#include "application/sync/mutation.hpp"
#include "crypto/content.hpp"
#include "mutation_detail.hpp"
#include "mutation_fault_test.hpp"
#include "platform/durability.hpp"
#include "platform/metadata.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>

namespace kasumi::application::sync::mutation {

using detail::make_error;
using detail::missing;
using detail::rollback_candidate_path;
using detail::read_status;
using detail::remove_temporary_file;
using detail::resolve_local_path;

namespace {

constexpr std::uint32_t no_backup_slot =
    std::numeric_limits<std::uint32_t>::max();

std::expected<std::filesystem::path, MutationError>
backup_path(const platform::Workspace& workspace,
            const transaction::OperationProgress& progress,
            const std::filesystem::path& path,
            std::size_t operation_index) {
    if (workspace.root.empty() || progress.backup_slot == no_backup_slot) {
        return std::unexpected(make_error(MutationErrorCode::InvalidOperation,
                                          "invalid backup slot",
                                          path,
                                          operation_index));
    }
    const auto result =
        platform::workspace_file(workspace, progress.backup_slot, ".backup");
    if (result.empty()) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "invalid backup path",
                                          path,
                                          operation_index));
    }
    return result;
}

std::expected<void, MutationError>
validate_workspace(const platform::Workspace& workspace,
                   std::size_t operation_index) {
    if (workspace.root.empty()) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "empty workspace",
                                          workspace.root,
                                          operation_index));
    }
    std::error_code error;
    const auto status = std::filesystem::symlink_status(workspace.root, error);
    if (error == std::errc::no_such_file_or_directory) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "workspace does not exist",
                                          workspace.root,
                                          operation_index));
    }
    if (error) {
        return std::unexpected(
            make_error(MutationErrorCode::LocalIo,
                       "failed to query workspace: " + error.message(),
                       workspace.root,
                       operation_index));
    }
    if (std::filesystem::is_symlink(status) ||
        !std::filesystem::is_directory(status)) {
        return std::unexpected(make_error(MutationErrorCode::UnsafePath,
                                          "invalid workspace",
                                          workspace.root,
                                          operation_index));
    }
    auto secured = platform::private_storage::protect_directory(workspace.root);
    if (!secured) {
        return std::unexpected(make_error(MutationErrorCode::UnsafePath,
                                          secured.error(),
                                          workspace.root,
                                          operation_index));
    }
    return {};
}

std::expected<std::string, MutationError>
file_hash(const std::filesystem::path& path, std::size_t operation_index) {
    auto hash = crypto::content::hash_file(path);
    if (!hash) {
        return std::unexpected(make_error(
            MutationErrorCode::LocalIo, hash.error(), path, operation_index));
    }
    return hash_hex(*hash);
}

std::expected<void, MutationError>
validate_backup(const std::filesystem::path& backup,
                std::string_view expected_hash,
                std::size_t operation_index) {
    auto status = read_status(backup, operation_index);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (missing(*status) || std::filesystem::is_symlink(*status) ||
        !std::filesystem::is_regular_file(*status)) {
        return std::unexpected(make_error(MutationErrorCode::IntegrityMismatch,
                                          "backup is missing or invalid",
                                          backup,
                                          operation_index));
    }
    auto secured = platform::private_storage::protect_file(backup);
    if (!secured) {
        return std::unexpected(make_error(MutationErrorCode::UnsafePath,
                                          secured.error(),
                                          backup,
                                          operation_index));
    }
    platform::perf_trace::count("mutation backup hash calls");
    auto actual = file_hash(backup, operation_index);
    if (!actual) {
        return std::unexpected(actual.error());
    }
    if (*actual != expected_hash) {
        return std::unexpected(make_error(MutationErrorCode::IntegrityMismatch,
                                          "backup hash mismatch",
                                          backup,
                                          operation_index));
    }
    return {};
}

std::expected<void, MutationError>
make_backup_durable(const std::filesystem::path& backup,
                    std::size_t operation_index) {
    auto synced = platform::durability::sync_file(backup);
    if (!synced) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          synced.error(),
                                          backup,
                                          operation_index));
    }
    auto parent_synced = platform::durability::sync_parent_directory(backup);
    if (!parent_synced) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          parent_synced.error(),
                                          backup,
                                          operation_index));
    }
    return {};
}

std::expected<void, MutationError>
create_backup(const std::filesystem::path& source,
              const std::filesystem::path& backup,
              std::string_view expected_hash,
              std::size_t operation_index) {
    auto status = read_status(backup, operation_index);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (!missing(*status)) {
        auto validated =
            validate_backup(backup, expected_hash, operation_index);
        if (!validated)
            return validated;
        return make_backup_durable(backup, operation_index);
    }

    const auto source_mtime = platform::metadata::last_write_time(source);
    if (!source_mtime) {
        return std::unexpected(
            make_error(MutationErrorCode::LocalIo,
                       "failed to read backup mtime: " + source_mtime.error(),
                       source,
                       operation_index));
    }
    std::error_code error;
    if (!std::filesystem::copy_file(
            source, backup, std::filesystem::copy_options::none, error) ||
        error) {
        if (error == std::errc::file_exists) {
            auto validated =
                validate_backup(backup, expected_hash, operation_index);
            if (!validated)
                return validated;
            return make_backup_durable(backup, operation_index);
        }
        return std::unexpected(
            make_error(MutationErrorCode::LocalIo,
                       error ? "failed to create backup: " + error.message()
                             : "failed to create backup",
                       backup,
                       operation_index));
    }

    auto secured = platform::private_storage::protect_file(backup);
    if (!secured) {
        remove_temporary_file(backup);
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          secured.error(),
                                          backup,
                                          operation_index));
    }

    auto backup_metadata =
        platform::metadata::set_last_write_time(backup, *source_mtime);
    if (!backup_metadata) {
        remove_temporary_file(backup);
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "failed to preserve backup mtime: " +
                                              backup_metadata.error(),
                                          backup,
                                          operation_index));
    }

    auto verified = validate_backup(backup, expected_hash, operation_index);
    if (!verified) {
        remove_temporary_file(backup);
        return verified;
    }
    auto durable = make_backup_durable(backup, operation_index);
    if (!durable) {
        remove_temporary_file(backup);
        return durable;
    }
    return {};
}

std::expected<void, MutationError>
validate_progress(const Operation& operation,
                  const transaction::OperationProgress& progress,
                  std::size_t operation_index) {
    if (!transaction::valid(progress.state)) {
        return std::unexpected(make_error(MutationErrorCode::InvalidOperation,
                                          "invalid progress state",
                                          operation.path,
                                          operation_index));
    }
    if (progress.state == transaction::OperationState::Pending &&
        (progress.had_original || !progress.previous_hash.empty())) {
        return std::unexpected(
            make_error(MutationErrorCode::InvalidOperation,
                       "Pending progress contains residual data",
                       operation.path,
                       operation_index));
    }
    const auto valid_hash = [](std::string_view value) {
        return !value.empty() && hash_from_hex(value).has_value();
    };
    const auto require_slot = [&] {
        return progress.backup_slot != no_backup_slot;
    };
    const auto require_file_hash = [&] {
        return progress.had_original ? valid_hash(progress.previous_hash)
                                     : progress.previous_hash.empty();
    };
    switch (operation.action) {
        case Action::Upload:
        case Action::CreateRemoteDirectory:
        case Action::DeleteRemote:
        case Action::DeleteRemoteDirectory:
            if (progress.backup_slot != no_backup_slot ||
                progress.had_original || !progress.previous_hash.empty()) {
                return std::unexpected(
                    make_error(MutationErrorCode::InvalidOperation,
                               "remote operation contains local progress",
                               operation.path,
                               operation_index));
            }
            break;
        case Action::Download:
        case Action::DeleteLocal:
            if (!require_slot() || !require_file_hash()) {
                return std::unexpected(
                    make_error(MutationErrorCode::InvalidOperation,
                               "invalid local file progress",
                               operation.path,
                               operation_index));
            }
            break;
        case Action::RenameLocal:
            if (!require_slot() ||
                (progress.state != transaction::OperationState::Pending &&
                 !valid_hash(progress.previous_hash))) {
                return std::unexpected(
                    make_error(MutationErrorCode::InvalidOperation,
                               "invalid rename progress",
                               operation.path,
                               operation_index));
            }
            break;
        case Action::CreateLocalDirectory:
        case Action::DeleteLocalDirectory:
            if (!require_slot() || !progress.previous_hash.empty()) {
                return std::unexpected(
                    make_error(MutationErrorCode::InvalidOperation,
                               "invalid local directory progress",
                               operation.path,
                               operation_index));
            }
            break;
        case Action::Count:
            return std::unexpected(
                make_error(MutationErrorCode::InvalidOperation,
                           "count action is not transactional",
                           operation.path,
                           operation_index));
    }
    return {};
}

PreparationResult
prepare_file_progress(std::size_t operation_index,
                      const std::filesystem::path& path,
                      const platform::Workspace& workspace,
                      const transaction::OperationProgress& current,
                      bool allow_missing) {
    auto progress = current;
    auto status = read_status(path, operation_index);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (std::filesystem::is_symlink(*status)) {
        return std::unexpected(make_error(MutationErrorCode::UnsafePath,
                                          "local path is a symlink",
                                          path,
                                          operation_index));
    }
    if (missing(*status)) {
        if (!allow_missing) {
            return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                              "local file does not exist",
                                              path,
                                              operation_index));
        }
        progress.had_original = false;
        progress.previous_hash.clear();
        progress.state = transaction::OperationState::BackupCreated;
        return progress;
    }
    if (!std::filesystem::is_regular_file(*status)) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "local path is not a regular file",
                       path,
                       operation_index));
    }

    auto actual = file_hash(path, operation_index);
    if (!actual) {
        return std::unexpected(actual.error());
    }
    progress.had_original = true;
    progress.previous_hash = *actual;
    auto backup = backup_path(workspace, progress, path, operation_index);
    if (!backup) {
        return std::unexpected(backup.error());
    }
    auto created =
        create_backup(path, *backup, progress.previous_hash, operation_index);
    if (!created) {
        return std::unexpected(created.error());
    }
    progress.state = transaction::OperationState::BackupCreated;
    return progress;
}

std::expected<std::string, MutationError>
current_file_hash(const std::filesystem::path& path,
                  const std::filesystem::file_status& status,
                  std::size_t operation_index) {
    if (missing(status)) {
        return std::string{};
    }
    if (std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "unexpected local object during rollback",
                       path,
                       operation_index));
    }
    platform::perf_trace::count("mutation destination hash calls");
    return file_hash(path, operation_index);
}

std::expected<void, MutationError>
remove_file_if_hash(const std::filesystem::path& path,
                    std::string_view expected_hash,
                    std::size_t operation_index) {
    auto status = read_status(path, operation_index);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (missing(*status)) {
        return {};
    }
    if (std::filesystem::is_symlink(*status) ||
        !std::filesystem::is_regular_file(*status)) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "unexpected local object during rollback",
                       path,
                       operation_index));
    }
    auto actual = file_hash(path, operation_index);
    if (!actual) {
        return std::unexpected(actual.error());
    }
    if (*actual != expected_hash) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "local file was externally modified",
                       path,
                       operation_index));
    }
    mutation_fault_test::hit("before_remove_file_if_hash", path);
    std::error_code error;
    if (!std::filesystem::remove(path, error) || error) {
        return std::unexpected(make_error(
            MutationErrorCode::LocalIo,
            error ? error.message() : "file disappeared during rollback",
            path,
            operation_index));
    }
    auto synced = platform::durability::sync_parent_directory(path);
    if (!synced) {
        return std::unexpected(make_error(
            MutationErrorCode::LocalIo, synced.error(), path, operation_index));
    }
    return {};
}

std::expected<void, MutationError>
restore_backup(const std::filesystem::path& backup,
               const std::filesystem::path& destination,
               std::string_view expected_hash,
               std::size_t operation_index,
               std::string_view expected_current_hash = {},
               std::string_view transaction_id = {}) {
    auto valid_backup = validate_backup(backup, expected_hash, operation_index);
    if (!valid_backup) {
        return std::unexpected(valid_backup.error());
    }
    const auto backup_mtime = platform::metadata::last_write_time(backup);
    if (!backup_mtime) {
        return std::unexpected(
            make_error(MutationErrorCode::LocalIo,
                       "failed to read backup mtime: " + backup_mtime.error(),
                       backup,
                       operation_index));
    }
    const auto parent = destination.parent_path();
    auto parent_status = read_status(parent, operation_index);
    if (!parent_status) {
        return std::unexpected(parent_status.error());
    }
    if (std::filesystem::is_symlink(*parent_status) ||
        !std::filesystem::is_directory(*parent_status)) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "invalid restore directory",
                       parent,
                       operation_index));
    }
    auto destination_status = read_status(destination, operation_index);
    if (!destination_status) {
        return std::unexpected(destination_status.error());
    }
    if (std::filesystem::is_symlink(*destination_status) ||
        (!missing(*destination_status) &&
         !std::filesystem::is_regular_file(*destination_status))) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "restore destination is an unexpected object",
                       destination,
                       operation_index));
    }

    const auto candidate = rollback_candidate_path(
        destination, transaction_id, operation_index);
    auto candidate_status = read_status(candidate, operation_index);
    if (!candidate_status) {
        return std::unexpected(candidate_status.error());
    }
    if (missing(*candidate_status)) {
        std::error_code error;
        if (!std::filesystem::copy_file(
                backup, candidate, std::filesystem::copy_options::none, error) ||
            error) {
            remove_temporary_file(candidate);
            return std::unexpected(
                make_error(MutationErrorCode::LocalIo,
                           error ? error.message() : "failed to copy backup",
                           candidate,
                           operation_index));
        }
        mutation_fault_test::hit("after_rollback_candidate_copy", candidate);
    }
    auto candidate_valid =
        validate_backup(candidate, expected_hash, operation_index);
    if (!candidate_valid)
        return std::unexpected(candidate_valid.error());
    auto synced = platform::durability::sync_file(candidate);
    if (!synced) {
        remove_temporary_file(candidate);
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          synced.error(),
                                          candidate,
                                          operation_index));
    }
    auto current_status = read_status(destination, operation_index);
    if (!current_status) {
        remove_temporary_file(candidate);
        return std::unexpected(current_status.error());
    }
    auto current =
        current_file_hash(destination, *current_status, operation_index);
    if (!current) {
        remove_temporary_file(candidate);
        return std::unexpected(current.error());
    }
    if (*current != expected_current_hash) {
        remove_temporary_file(candidate);
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "rollback destination changed while staging backup",
                       destination,
                       operation_index));
    }
    if (expected_current_hash.empty()) {
        mutation_fault_test::hit("before_restore_install", destination);
        auto installed = platform::durability::install_without_overwrite(
            candidate, destination);
        if (!installed) {
            remove_temporary_file(candidate);
            return std::unexpected(
                make_error(installed.error() == std::errc::file_exists
                               ? MutationErrorCode::DestinationConflict
                               : MutationErrorCode::LocalIo,
                           "conditional rollback install failed: " +
                               installed.error().message(),
                           destination,
                           operation_index));
        }
    } else {
        mutation_fault_test::hit("before_restore_replace", destination);
        auto installed =
            platform::durability::replace_atomically(candidate, destination);
        if (!installed) {
            remove_temporary_file(candidate);
            return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                              "failed to replace rollback target: " +
                                                  installed.error(),
                                              destination,
                                              operation_index));
        }
    }
    auto destination_metadata =
        platform::metadata::set_last_write_time(destination, *backup_mtime);
    if (!destination_metadata) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "failed to restore file mtime: " +
                                              destination_metadata.error(),
                                          destination,
                                          operation_index));
    }
    auto parent_synced =
        platform::durability::sync_parent_directory(destination);
    if (!parent_synced) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          parent_synced.error(),
                                          destination,
                                          operation_index));
    }
    mutation_fault_test::hit("after_restore_complete", destination);
    return {};
}

std::expected<void, MutationError>
rollback_file_operation(const Operation& operation,
                        std::size_t operation_index,
                        const std::filesystem::path& local_root,
                        const platform::Workspace& workspace,
                        const transaction::OperationProgress& progress,
                        const DestinationPrecondition* condition) {
    auto path = resolve_local_path(local_root, operation.path, operation_index);
    if (!path) {
        return std::unexpected(path.error());
    }
    auto backup = backup_path(workspace, progress, *path, operation_index);
    if (progress.had_original && !backup) {
        return std::unexpected(backup.error());
    }
    if (condition && condition->backup) {
        auto transferred =
            backup_path(workspace, *condition->backup, *path, operation_index);
        if (!transferred)
            return std::unexpected(transferred.error());
        auto verified = validate_backup(
            *transferred, condition->backup->previous_hash, operation_index);
        if (!verified)
            return verified;
    }

    if (operation.action == Action::RenameLocal) {
        auto destination =
            resolve_local_path(local_root, operation.alt_path, operation_index);
        if (!destination) {
            return std::unexpected(destination.error());
        }
        auto source_status = read_status(*path, operation_index);
        auto destination_status = read_status(*destination, operation_index);
        if (!source_status)
            return std::unexpected(source_status.error());
        if (!destination_status)
            return std::unexpected(destination_status.error());
        if (std::filesystem::is_symlink(*source_status) ||
            std::filesystem::is_symlink(*destination_status)) {
            return std::unexpected(
                make_error(MutationErrorCode::DestinationConflict,
                           "rename contains symlink during rollback",
                           operation.path,
                           operation_index));
        }
        if (!progress.had_original) {
            return {};
        }
        auto valid_backup =
            validate_backup(*backup, progress.previous_hash, operation_index);
        if (!valid_backup) {
            if (valid_backup.error().code ==
                MutationErrorCode::IntegrityMismatch) {
                return std::unexpected(
                    make_error(MutationErrorCode::DestinationConflict,
                               valid_backup.error().detail,
                               valid_backup.error().path,
                               operation_index));
            }
            return std::unexpected(valid_backup.error());
        }
        const auto source_hash =
            current_file_hash(*path, *source_status, operation_index);
        const auto destination_hash = current_file_hash(
            *destination, *destination_status, operation_index);
        if (!source_hash || !destination_hash) {
            return std::unexpected(!source_hash ? source_hash.error()
                                                : destination_hash.error());
        }
        const bool rename_applied = source_hash->empty() &&
                                    *destination_hash == progress.previous_hash;
        if (progress.state != transaction::OperationState::Applied &&
            !rename_applied &&
            !(*source_hash == progress.previous_hash &&
              destination_hash->empty())) {
            return std::unexpected(
                make_error(MutationErrorCode::DestinationConflict,
                           "rename effect is not confirmed",
                           operation.path,
                           operation_index));
        }
        if (*source_hash == progress.previous_hash &&
            destination_hash->empty()) {
            return {};
        }
        if (*source_hash == progress.previous_hash &&
            *destination_hash == progress.previous_hash) {
            return remove_file_if_hash(
                *destination, progress.previous_hash, operation_index);
        }
        if (source_hash->empty() &&
            *destination_hash == progress.previous_hash) {
            auto restored = restore_backup(*backup,
                                           *path,
                                           progress.previous_hash,
                                           operation_index,
                                           {},
                                           workspace.root.filename().string());
            if (!restored)
                return restored;
            return remove_file_if_hash(
                *destination, progress.previous_hash, operation_index);
        }
        if (source_hash->empty() && destination_hash->empty()) {
            return restore_backup(*backup,
                                  *path,
                                  progress.previous_hash,
                                  operation_index,
                                  {},
                                  workspace.root.filename().string());
        }
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "rename was externally modified",
                       operation.path,
                       operation_index));
    }

    auto status = read_status(*path, operation_index);
    if (!status)
        return std::unexpected(status.error());
    if (std::filesystem::is_symlink(*status)) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "local path is a symlink during rollback",
                       *path,
                       operation_index));
    }

    if (operation.action == Action::Download ||
        operation.action == Action::DeleteLocal) {
        const auto tx_id = workspace.root.filename().string();

        if (progress.had_original) {
            auto actual = current_file_hash(*path, *status, operation_index);
            if (!actual)
                return std::unexpected(actual.error());
            if (condition && *actual == condition->hash &&
                (progress.state != transaction::OperationState::Applied ||
                 condition->backup))
                return {};
            if (*actual == progress.previous_hash)
                return {};
            // Before Applied, matching bytes are equivalent, not proof of authorship.
            if (operation.action == Action::Download &&
                ((progress.state == transaction::OperationState::Applied &&
                  (actual->empty() || *actual == operation.hash)) ||
                 (progress.state != transaction::OperationState::Applied &&
                  *actual == operation.hash))) {
                return restore_backup(*backup,
                                      *path,
                                      progress.previous_hash,
                                      operation_index,
                                      *actual,
                                      tx_id);
            }
            if ((progress.state == transaction::OperationState::Applied ||
                 progress.state == transaction::OperationState::BackupCreated) &&
                operation.action == Action::DeleteLocal && actual->empty()) {
                return restore_backup(*backup,
                                      *path,
                                      progress.previous_hash,
                                      operation_index,
                                      {},
                                      tx_id);
            }
            return std::unexpected(
                make_error(MutationErrorCode::DestinationConflict,
                           "local file was externally modified",
                           *path,
                           operation_index));
        }
        if (operation.action == Action::Download ||
            operation.action == Action::DeleteLocal) {
            auto actual = current_file_hash(*path, *status, operation_index);
            if (!actual)
                return std::unexpected(actual.error());
            // A no-op download leaves the rename's file for its own rollback.
            if (condition && *actual == condition->hash &&
                (progress.state != transaction::OperationState::Applied ||
                 condition->backup))
                return {};
            if (actual->empty())
                return {};
            if ((progress.state == transaction::OperationState::Applied ||
                 progress.state == transaction::OperationState::BackupCreated) &&
                operation.action == Action::Download &&
                *actual == operation.hash) {
                return remove_file_if_hash(
                    *path, operation.hash, operation_index);
            }
            return std::unexpected(
                make_error(MutationErrorCode::DestinationConflict,
                           "file created during transaction was modified",
                           *path,
                           operation_index));
        }
        return {};
    }
    return {};
}

PreparationResult
prepare_operation_impl(const Operation& operation,
                       std::size_t operation_index,
                       const std::filesystem::path& local_root,
                       const platform::Workspace& workspace,
                       const transaction::OperationProgress& current_progress,
                       std::span<const Operation> plan_operations = {}) {
    if (operation_index == std::numeric_limits<std::size_t>::max() ||
        !is_valid_action(operation.action) || !has_safe_paths(operation)) {
        return std::unexpected(make_error(MutationErrorCode::InvalidOperation,
                                          "invalid operation or index",
                                          operation.path,
                                          operation_index));
    }
    auto workspace_valid = validate_workspace(workspace, operation_index);
    if (!workspace_valid)
        return std::unexpected(workspace_valid.error());
    auto progress_valid =
        validate_progress(operation, current_progress, operation_index);
    if (!progress_valid)
        return std::unexpected(progress_valid.error());
    if (current_progress.state != transaction::OperationState::Pending) {
        const bool requires_file_backup =
            current_progress.had_original &&
            (operation.action == Action::Download ||
             operation.action == Action::DeleteLocal ||
             operation.action == Action::RenameLocal);
        if (requires_file_backup) {
            auto backup = backup_path(
                workspace, current_progress, operation.path, operation_index);
            if (!backup)
                return std::unexpected(backup.error());
            auto checked = validate_backup(
                *backup, current_progress.previous_hash, operation_index);
            if (!checked)
                return std::unexpected(checked.error());
        }
        return current_progress;
    }

    if (!is_local_mutation(operation.action)) {
        auto result = current_progress;
        result.state = transaction::OperationState::Prepared;
        result.backup_slot = no_backup_slot;
        result.had_original = false;
        result.previous_hash.clear();
        return result;
    }
    if (current_progress.backup_slot == no_backup_slot) {
        return std::unexpected(make_error(MutationErrorCode::InvalidOperation,
                                          "local operation without backup slot",
                                          operation.path,
                                          operation_index));
    }

    if (operation.action == Action::RenameLocal) {
        auto source = resolve_local_path(
            local_root, operation.path, operation_index, plan_operations);
        auto destination = resolve_local_path(
            local_root, operation.alt_path, operation_index, plan_operations);
        if (!source)
            return std::unexpected(source.error());
        if (!destination)
            return std::unexpected(destination.error());
        auto source_status = read_status(*source, operation_index);
        auto destination_status = read_status(*destination, operation_index);
        if (!source_status)
            return std::unexpected(source_status.error());
        if (!destination_status)
            return std::unexpected(destination_status.error());
        if (std::filesystem::is_symlink(*source_status) ||
            std::filesystem::is_symlink(*destination_status)) {
            return std::unexpected(make_error(MutationErrorCode::UnsafePath,
                                              "rename does not accept symlink",
                                              operation.path,
                                              operation_index));
        }
        const bool source_missing = missing(*source_status);
        const bool destination_missing = missing(*destination_status);
        auto result = current_progress;
        result.state = transaction::OperationState::BackupCreated;
        if (!source_missing && destination_missing) {
            if (!std::filesystem::is_regular_file(*source_status)) {
                return std::unexpected(
                    make_error(MutationErrorCode::DestinationConflict,
                               "rename source is not a regular file",
                               *source,
                               operation_index));
            }
            auto actual = file_hash(*source, operation_index);
            if (!actual)
                return std::unexpected(actual.error());
            if (!operation.hash.empty() && *actual != operation.hash) {
                return std::unexpected(
                    make_error(MutationErrorCode::IntegrityMismatch,
                               "rename source does not match expected hash",
                               *source,
                               operation_index));
            }
            result.had_original = true;
            result.previous_hash = *actual;
            auto backup =
                backup_path(workspace, result, *source, operation_index);
            if (!backup)
                return std::unexpected(backup.error());
            auto created =
                create_backup(*source, *backup, *actual, operation_index);
            if (!created)
                return std::unexpected(created.error());
            return result;
        }
        if (source_missing && !destination_missing &&
            std::filesystem::is_regular_file(*destination_status)) {
            auto actual = file_hash(*destination, operation_index);
            if (!actual)
                return std::unexpected(actual.error());
            if (!operation.hash.empty() && *actual != operation.hash) {
                return std::unexpected(make_error(
                    MutationErrorCode::IntegrityMismatch,
                    "rename destination does not match expected hash",
                    *destination,
                    operation_index));
            }
            result.had_original = false;
            result.previous_hash = *actual;
            return result;
        }
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "initial rename state is ambiguous",
                       operation.path,
                       operation_index));
    }

    auto path = resolve_local_path(
        local_root, operation.path, operation_index, plan_operations);
    if (!path)
        return std::unexpected(path.error());
    if (operation.action == Action::CreateLocalDirectory ||
        operation.action == Action::DeleteLocalDirectory) {
        auto status = read_status(*path, operation_index);
        if (!status)
            return std::unexpected(status.error());
        if (std::filesystem::is_symlink(*status)) {
            return std::unexpected(make_error(MutationErrorCode::UnsafePath,
                                              "local directory is a symlink",
                                              *path,
                                              operation_index));
        }
        bool source_of_preceding_rename = false;
        if (operation.action == Action::CreateLocalDirectory) {
            for (std::size_t i = 0;
                 i < operation_index && i < plan_operations.size();
                 ++i) {
                if (plan_operations[i].action == Action::RenameLocal &&
                    plan_operations[i].path == operation.path) {
                    source_of_preceding_rename = true;
                    break;
                }
            }
        }
        if (!missing(*status) && !std::filesystem::is_directory(*status) &&
            !source_of_preceding_rename) {
            return std::unexpected(
                make_error(MutationErrorCode::DestinationConflict,
                           "local object is not a directory",
                           *path,
                           operation_index));
        }
        auto result = current_progress;
        result.had_original = !missing(*status) && !source_of_preceding_rename;
        result.previous_hash.clear();
        result.state = transaction::OperationState::BackupCreated;
        return result;
    }
    return prepare_file_progress(
        operation_index, *path, workspace, current_progress, true);
}

std::expected<void, MutationError>
rollback_operation_impl(const Operation& operation,
                        std::size_t operation_index,
                        const std::filesystem::path& local_root,
                        const platform::Workspace& workspace,
                        const transaction::OperationProgress& progress,
                        const DestinationPrecondition* condition) {
    if (operation_index == std::numeric_limits<std::size_t>::max() ||
        !is_valid_action(operation.action) || !has_safe_paths(operation)) {
        return std::unexpected(make_error(MutationErrorCode::InvalidOperation,
                                          "invalid operation or index",
                                          operation.path,
                                          operation_index));
    }
    auto valid_progress =
        validate_progress(operation, progress, operation_index);
    if (!valid_progress)
        return std::unexpected(valid_progress.error());
    if (!is_local_mutation(operation.action) ||
        progress.state == transaction::OperationState::Pending ||
        progress.state == transaction::OperationState::Prepared) {
        return {};
    }
    auto workspace_valid = validate_workspace(workspace, operation_index);
    if (!workspace_valid)
        return std::unexpected(workspace_valid.error());

    if (operation.action == Action::Download) {
        auto destination =
            resolve_local_path(local_root, operation.path, operation_index);
        if (!destination)
            return std::unexpected(destination.error());
        const auto candidate = detail::download_candidate_path(
            *destination, workspace, operation_index);
        auto status = read_status(candidate, operation_index);
        if (!status)
            return std::unexpected(status.error());
        if (!missing(*status)) {
            if (std::filesystem::is_symlink(*status) ||
                !std::filesystem::is_regular_file(*status)) {
                return std::unexpected(
                    make_error(MutationErrorCode::DestinationConflict,
                               "download candidate is not a regular file",
                               candidate,
                               operation_index));
            }
            std::error_code error;
            if (!std::filesystem::remove(candidate, error) || error) {
                return std::unexpected(
                    make_error(MutationErrorCode::LocalIo,
                               error ? error.message()
                                     : "failed to remove download candidate",
                               candidate,
                               operation_index));
            }
            auto synced =
                platform::durability::sync_parent_directory(candidate);
            if (!synced)
                return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                                  synced.error(),
                                                  candidate,
                                                  operation_index));
        }
    }

    if (operation.action == Action::CreateLocalDirectory) {
        if (progress.had_original)
            return {};
        auto path =
            resolve_local_path(local_root, operation.path, operation_index);
        if (!path)
            return std::unexpected(path.error());
        auto status = read_status(*path, operation_index);
        if (!status)
            return std::unexpected(status.error());
        if (missing(*status))
            return {};
        if (std::filesystem::is_symlink(*status) ||
            !std::filesystem::is_directory(*status)) {
            return std::unexpected(
                make_error(MutationErrorCode::DestinationConflict,
                           "created object is not a regular directory",
                           *path,
                           operation_index));
        }
        std::error_code error;
        std::filesystem::directory_iterator iterator(*path, error);
        if (error || iterator != std::filesystem::directory_iterator{}) {
            return std::unexpected(
                make_error(MutationErrorCode::DestinationConflict,
                           "created directory is not empty",
                           *path,
                           operation_index));
        }
        if (!std::filesystem::remove(*path, error) || error) {
            return std::unexpected(make_error(
                MutationErrorCode::LocalIo,
                error ? error.message() : "failed to remove directory",
                *path,
                operation_index));
        }
        return {};
    }
    if (operation.action == Action::DeleteLocalDirectory) {
        if (!progress.had_original)
            return {};
        auto path =
            resolve_local_path(local_root, operation.path, operation_index);
        if (!path)
            return std::unexpected(path.error());
        auto status = read_status(*path, operation_index);
        if (!status)
            return std::unexpected(status.error());
        if (!missing(*status)) {
            if (std::filesystem::is_symlink(*status) ||
                !std::filesystem::is_directory(*status)) {
                return std::unexpected(
                    make_error(MutationErrorCode::DestinationConflict,
                               "restored object is not a regular directory",
                               *path,
                               operation_index));
            }
            return {};
        }
        std::error_code error;
        if (!std::filesystem::create_directory(*path, error) || error) {
            return std::unexpected(make_error(
                MutationErrorCode::LocalIo,
                error ? error.message() : "failed to recreate directory",
                *path,
                operation_index));
        }
        return {};
    }
    return rollback_file_operation(
        operation, operation_index, local_root, workspace, progress, condition);
}

} // namespace

MutationResult detail::validate_prepared_operation(
    const Operation& operation,
    std::size_t operation_index,
    const std::filesystem::path& destination,
    const platform::Workspace& workspace,
    const transaction::OperationProgress& progress) {
    auto valid = validate_progress(operation, progress, operation_index);
    if (!valid)
        return valid;
    if (operation_index == std::numeric_limits<std::size_t>::max() ||
        (operation.action != Action::Download &&
         operation.action != Action::DeleteLocal) ||
        progress.state < transaction::OperationState::Prepared) {
        return std::unexpected(make_error(MutationErrorCode::InvalidOperation,
                                          "destination lacks prepared progress",
                                          destination,
                                          operation_index));
    }
    auto workspace_valid = validate_workspace(workspace, operation_index);
    if (!workspace_valid)
        return workspace_valid;
    auto backup =
        backup_path(workspace, progress, destination, operation_index);
    if (!backup)
        return std::unexpected(backup.error());
    auto backup_status = read_status(*backup, operation_index);
    if (!backup_status)
        return std::unexpected(backup_status.error());
    if (progress.had_original &&
        !std::filesystem::is_regular_file(*backup_status))
        return std::unexpected(make_error(MutationErrorCode::IntegrityMismatch,
                                          "backup is missing or invalid",
                                          *backup,
                                          operation_index));
    if (!progress.had_original && !missing(*backup_status))
        return std::unexpected(make_error(MutationErrorCode::InvalidOperation,
                                          "absence progress contains a backup",
                                          destination,
                                          operation_index));
    return {};
}

MutationResult detail::validate_prepared_destination(
    const Operation& operation,
    std::size_t operation_index,
    const std::filesystem::path& destination,
    const platform::Workspace& workspace,
    const transaction::OperationProgress& progress,
    const DestinationPrecondition* condition) {
    auto valid = validate_prepared_operation(
        operation, operation_index, destination, workspace, progress);
    if (!valid)
        return valid;
    if (progress.had_original) {
        auto backup =
            backup_path(workspace, progress, destination, operation_index);
        if (!backup)
            return std::unexpected(backup.error());
        auto backup_valid =
            validate_backup(*backup, progress.previous_hash, operation_index);
        if (!backup_valid)
            return backup_valid;
    }
    if (condition && condition->backup) {
        auto backup = backup_path(
            workspace, *condition->backup, destination, operation_index);
        if (!backup)
            return std::unexpected(backup.error());
        auto verified = validate_backup(
            *backup, condition->backup->previous_hash, operation_index);
        if (!verified)
            return verified;
    }
    auto status = read_status(destination, operation_index);
    if (!status)
        return std::unexpected(status.error());
    if (std::filesystem::is_symlink(*status))
        return std::unexpected(
            make_error(MutationErrorCode::UnsafePath,
                       "prepared destination became a symlink",
                       destination,
                       operation_index));
    auto actual = current_file_hash(destination, *status, operation_index);
    if (!actual)
        return std::unexpected(actual.error());
    const auto expected =
        progress.state == transaction::OperationState::Applied
            ? (operation.action == Action::Download ? operation.hash
                                                    : std::string{})
            : (condition ? condition->hash : progress.previous_hash);
    if (*actual != expected) {
        return std::unexpected(make_error(
            MutationErrorCode::DestinationConflict,
            expected.empty()  ? "destination created after preparation"
            : actual->empty() ? "prepared destination is absent"
                              : "destination differs from prepared state",
            destination,
            operation_index));
    }
    return {};
}

std::vector<std::size_t>
detail::destination_dependencies(std::span<const Operation> operations) {
    const auto none = std::numeric_limits<std::size_t>::max();
    std::vector<std::size_t> result(operations.size(), none);
    std::unordered_map<std::filesystem::path, std::size_t> renamed;
    for (std::size_t index = 0; index < operations.size(); ++index) {
        const auto& operation = operations[index];
        if (operation.action == Action::RenameLocal) {
            renamed[operation.path] = index;
            renamed[operation.alt_path] = index;
        } else if (operation.action == Action::Download ||
                   operation.action == Action::DeleteLocal) {
            const auto found = renamed.find(operation.path);
            if (found != renamed.end()) {
                result[index] = found->second;
                platform::perf_trace::count("destination dependency links");
            }
        }
    }
    platform::perf_trace::count("destination dependency entries",
                                operations.size());
    return result;
}

std::expected<std::optional<DestinationPrecondition>, MutationError>
detail::effective_destination(const transaction::Record& record,
                              std::size_t index,
                              std::span<const std::size_t> dependencies) {
    if (index >= record.plan.operations.size() ||
        record.progress.size() != record.plan.operations.size() ||
        dependencies.size() != record.plan.operations.size())
        return std::unexpected(
            make_error(MutationErrorCode::InvalidOperation,
                       "invalid destination dependency index",
                       {},
                       index));
    const auto preceding = dependencies[index];
    if (preceding == std::numeric_limits<std::size_t>::max())
        return std::nullopt;
    const auto& operation = record.plan.operations[index];
    if (preceding >= index)
        return std::unexpected(
            make_error(MutationErrorCode::InvalidOperation,
                       "destination dependency is not earlier",
                       operation.path,
                       index));
    const auto& rename = record.plan.operations[preceding];
    const auto& previous = record.progress[preceding];
    const auto& progress = record.progress[index];
    auto valid = validate_progress(operation, progress, index);
    if (!valid)
        return std::unexpected(valid.error());
    valid = validate_progress(rename, previous, preceding);
    if (!valid)
        return std::unexpected(valid.error());
    if (rename.action != Action::RenameLocal ||
        (operation.action != Action::Download &&
         operation.action != Action::DeleteLocal) ||
        previous.state != transaction::OperationState::Applied ||
        !previous.had_original ||
        (!rename.hash.empty() && rename.hash != previous.previous_hash))
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "preceding original rename is not confirmed",
                       operation.path,
                       index));
    const bool vacated = rename.path == operation.path;
    const bool matches =
        vacated ? progress.had_original &&
                      progress.previous_hash == previous.previous_hash
                : rename.alt_path == operation.path && !progress.had_original &&
                      progress.previous_hash.empty();
    if (!matches)
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "rename does not match prepared destination",
                       operation.path,
                       index));
    return DestinationPrecondition{
        .hash = vacated ? std::string{} : previous.previous_hash,
        .backup = vacated ? std::nullopt : std::optional{previous}};
}

MutationResult detail::validate_prepared_rename(
    const Operation& operation,
    std::size_t index,
    const std::filesystem::path& source,
    const std::filesystem::path& destination,
    const platform::Workspace& workspace,
    const transaction::OperationProgress& progress) {
    // An unprepared pending operation has no authority over a following path.
    if (progress.state == transaction::OperationState::Pending &&
        !progress.had_original && progress.previous_hash.empty())
        return {};
    auto valid = validate_progress(operation, progress, index);
    if (!valid)
        return valid;
    if (!operation.hash.empty() && operation.hash != progress.previous_hash)
        return std::unexpected(make_error(MutationErrorCode::InvalidOperation,
                                          "rename progress does not match plan",
                                          operation.path,
                                          index));
    valid = validate_workspace(workspace, index);
    if (!valid)
        return valid;
    if (progress.had_original) {
        auto backup = backup_path(workspace, progress, source, index);
        if (!backup)
            return std::unexpected(backup.error());
        valid = validate_backup(*backup, progress.previous_hash, index);
        if (!valid)
            return valid;
    }
    const auto source_status = read_status(source, index);
    const auto destination_status = read_status(destination, index);
    if (!source_status || !destination_status)
        return std::unexpected(!source_status ? source_status.error()
                                              : destination_status.error());
    auto source_hash = current_file_hash(source, *source_status, index);
    auto destination_hash =
        current_file_hash(destination, *destination_status, index);
    if (!source_hash || !destination_hash)
        return std::unexpected(!source_hash ? source_hash.error()
                                            : destination_hash.error());
    const bool at_destination =
        source_hash->empty() && *destination_hash == progress.previous_hash;
    const bool at_source = *source_hash == progress.previous_hash &&
                           destination_hash->empty();
    const bool matches = progress.state == transaction::OperationState::Applied ||
                                 !progress.had_original
                             ? at_destination
                             : at_source ||
                                   (progress.state ==
                                        transaction::OperationState::BackupCreated &&
                                    at_destination);
    if (!matches)
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "rename differs from prepared state",
                       operation.path,
                       index));
    return {};
}

PreparationResult
prepare_operation(const Operation& operation,
                  std::size_t operation_index,
                  const std::filesystem::path& local_root,
                  const platform::Workspace& workspace,
                  const transaction::OperationProgress& current_progress,
                  std::span<const Operation> plan_operations) {
    return prepare_operation_impl(operation,
                                  operation_index,
                                  local_root,
                                  workspace,
                                  current_progress,
                                  plan_operations);
}

std::expected<void, MutationError>
rollback_operation(const Operation& operation,
                   std::size_t operation_index,
                   const std::filesystem::path& local_root,
                   const platform::Workspace& workspace,
                   const transaction::OperationProgress& progress,
                   const DestinationPrecondition* condition) {
    return rollback_operation_impl(
        operation, operation_index, local_root, workspace, progress, condition);
}

} // namespace kasumi::application::sync::mutation
