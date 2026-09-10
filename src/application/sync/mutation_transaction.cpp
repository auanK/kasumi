#include "application/sync/mutation.hpp"
#include "crypto/content.hpp"
#include "mutation_detail.hpp"
#include "platform/durability.hpp"
#include "platform/metadata.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>

namespace kasumi::application::sync::mutation {

using detail::make_error;
using detail::missing;
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
                                          "slot de backup inválido",
                                          path,
                                          operation_index));
    }
    const auto result =
        platform::workspace_file(workspace, progress.backup_slot, ".backup");
    if (result.empty()) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "caminho de backup inválido",
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
                                          "workspace vazio",
                                          workspace.root,
                                          operation_index));
    }
    std::error_code error;
    const auto status = std::filesystem::symlink_status(workspace.root, error);
    if (error == std::errc::no_such_file_or_directory) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "workspace não existe",
                                          workspace.root,
                                          operation_index));
    }
    if (error) {
        return std::unexpected(make_error(
            MutationErrorCode::LocalIo,
            "não foi possível consultar o workspace: " + error.message(),
            workspace.root,
            operation_index));
    }
    if (std::filesystem::is_symlink(status) ||
        !std::filesystem::is_directory(status)) {
        return std::unexpected(make_error(MutationErrorCode::UnsafePath,
                                          "workspace inválido",
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
                                          "backup ausente ou inválido",
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
    auto actual = file_hash(backup, operation_index);
    if (!actual) {
        return std::unexpected(actual.error());
    }
    if (*actual != expected_hash) {
        return std::unexpected(make_error(MutationErrorCode::IntegrityMismatch,
                                          "hash do backup não corresponde",
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

    std::error_code error;
    const auto source_mtime = std::filesystem::last_write_time(source, error);
    if (error) {
        return std::unexpected(make_error(
            MutationErrorCode::LocalIo,
            "não foi possível ler o mtime do backup: " + error.message(),
            source,
            operation_index));
    }
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
        return std::unexpected(make_error(
            MutationErrorCode::LocalIo,
            error ? "não foi possível criar backup: " + error.message()
                  : "não foi possível criar backup",
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
        platform::metadata::set_last_write_time(backup, source_mtime);
    if (!backup_metadata) {
        remove_temporary_file(backup);
        return std::unexpected(
            make_error(MutationErrorCode::LocalIo,
                       "não foi possível preservar o mtime do backup: " +
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
                                          "estado de progresso inválido",
                                          operation.path,
                                          operation_index));
    }
    if (progress.state == transaction::OperationState::Pending &&
        (progress.had_original || !progress.previous_hash.empty())) {
        return std::unexpected(
            make_error(MutationErrorCode::InvalidOperation,
                       "progresso Pending possui dados residuais",
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
                               "operação remota possui progresso local",
                               operation.path,
                               operation_index));
            }
            break;
        case Action::Download:
        case Action::DeleteLocal:
            if (!require_slot() || !require_file_hash()) {
                return std::unexpected(
                    make_error(MutationErrorCode::InvalidOperation,
                               "progresso de arquivo local inválido",
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
                               "progresso de rename inválido",
                               operation.path,
                               operation_index));
            }
            break;
        case Action::CreateLocalDirectory:
        case Action::DeleteLocalDirectory:
            if (!require_slot() || !progress.previous_hash.empty()) {
                return std::unexpected(
                    make_error(MutationErrorCode::InvalidOperation,
                               "progresso de diretório local inválido",
                               operation.path,
                               operation_index));
            }
            break;
        case Action::Count:
            return std::unexpected(
                make_error(MutationErrorCode::InvalidOperation,
                           "ação de contagem não é transacional",
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
                                          "caminho local é um symlink",
                                          path,
                                          operation_index));
    }
    if (missing(*status)) {
        if (!allow_missing) {
            return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                              "arquivo local não existe",
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
                       "caminho local não é um arquivo regular",
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
                       "objeto local inesperado durante rollback",
                       path,
                       operation_index));
    }
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
                       "objeto local inesperado durante rollback",
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
                       "arquivo local foi alterado externamente",
                       path,
                       operation_index));
    }
    std::error_code error;
    if (!std::filesystem::remove(path, error) || error) {
        return std::unexpected(make_error(
            MutationErrorCode::LocalIo,
            error ? error.message() : "arquivo não pôde ser removido",
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
               std::size_t operation_index) {
    auto valid_backup = validate_backup(backup, expected_hash, operation_index);
    if (!valid_backup) {
        return std::unexpected(valid_backup.error());
    }
    std::error_code backup_mtime_error;
    const auto backup_mtime =
        std::filesystem::last_write_time(backup, backup_mtime_error);
    if (backup_mtime_error) {
        return std::unexpected(
            make_error(MutationErrorCode::LocalIo,
                       "não foi possível ler o mtime do backup: " +
                           backup_mtime_error.message(),
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
                       "diretório de restauração inválido",
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
                       "destino da restauração é um objeto inesperado",
                       destination,
                       operation_index));
    }

    auto id = platform::random::hex_id();
    if (!id) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          id.error(),
                                          destination,
                                          operation_index));
    }
    const auto candidate = platform::path::temporary_sibling_path(
        destination, ".", ".kasumi-rollback-" + *id);
    auto candidate_status = read_status(candidate, operation_index);
    if (!candidate_status) {
        return std::unexpected(candidate_status.error());
    }
    if (!missing(*candidate_status)) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "candidato de restauração já existe",
                       candidate,
                       operation_index));
    }

    std::error_code error;
    if (!std::filesystem::copy_file(
            backup, candidate, std::filesystem::copy_options::none, error) ||
        error) {
        remove_temporary_file(candidate);
        return std::unexpected(make_error(
            MutationErrorCode::LocalIo,
            error ? error.message() : "não foi possível copiar o backup",
            candidate,
            operation_index));
    }
    auto candidate_valid =
        validate_backup(candidate, expected_hash, operation_index);
    if (!candidate_valid) {
        remove_temporary_file(candidate);
        return std::unexpected(candidate_valid.error());
    }
    auto synced = platform::durability::sync_file(candidate);
    if (!synced) {
        remove_temporary_file(candidate);
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          synced.error(),
                                          candidate,
                                          operation_index));
    }
    auto replaced =
        platform::durability::replace_atomically(candidate, destination);
    if (!replaced) {
        remove_temporary_file(candidate);
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          replaced.error(),
                                          destination,
                                          operation_index));
    }
    auto destination_metadata =
        platform::metadata::set_last_write_time(destination, backup_mtime);
    if (!destination_metadata) {
        return std::unexpected(
            make_error(MutationErrorCode::LocalIo,
                       "não foi possível restaurar o mtime do arquivo: " +
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
    return {};
}

std::expected<void, MutationError>
rollback_file_operation(const Operation& operation,
                        std::size_t operation_index,
                        const std::filesystem::path& local_root,
                        const platform::Workspace& workspace,
                        const transaction::OperationProgress& progress) {
    auto path = resolve_local_path(local_root, operation.path, operation_index);
    if (!path) {
        return std::unexpected(path.error());
    }
    auto backup = backup_path(workspace, progress, *path, operation_index);
    if (progress.had_original && !backup) {
        return std::unexpected(backup.error());
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
                           "rename contém symlink durante rollback",
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
            auto restored = restore_backup(
                *backup, *path, progress.previous_hash, operation_index);
            if (!restored)
                return restored;
            return remove_file_if_hash(
                *destination, progress.previous_hash, operation_index);
        }
        if (source_hash->empty() && destination_hash->empty()) {
            return restore_backup(
                *backup, *path, progress.previous_hash, operation_index);
        }
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "rename foi alterado externamente",
                       operation.path,
                       operation_index));
    }

    auto status = read_status(*path, operation_index);
    if (!status)
        return std::unexpected(status.error());
    if (std::filesystem::is_symlink(*status)) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "caminho local é um symlink durante rollback",
                       *path,
                       operation_index));
    }

    if (operation.action == Action::Download ||
        operation.action == Action::DeleteLocal) {
        if (progress.had_original) {
            auto actual = current_file_hash(*path, *status, operation_index);
            if (!actual)
                return std::unexpected(actual.error());
            if (*actual == progress.previous_hash)
                return {};
            if (operation.action == Action::Download &&
                (actual->empty() || *actual == operation.hash)) {
                return restore_backup(
                    *backup, *path, progress.previous_hash, operation_index);
            }
            if (operation.action == Action::DeleteLocal && actual->empty()) {
                return restore_backup(
                    *backup, *path, progress.previous_hash, operation_index);
            }
            return std::unexpected(
                make_error(MutationErrorCode::DestinationConflict,
                           "arquivo local foi alterado externamente",
                           *path,
                           operation_index));
        }
        if (operation.action == Action::Download) {
            auto actual = current_file_hash(*path, *status, operation_index);
            if (!actual)
                return std::unexpected(actual.error());
            if (actual->empty())
                return {};
            if (*actual == operation.hash) {
                return remove_file_if_hash(
                    *path, operation.hash, operation_index);
            }
            return std::unexpected(
                make_error(MutationErrorCode::DestinationConflict,
                           "arquivo criado durante a transação foi alterado",
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
                       const transaction::OperationProgress& current_progress) {
    if (operation_index == std::numeric_limits<std::size_t>::max() ||
        !is_valid_action(operation.action) || !has_safe_paths(operation)) {
        return std::unexpected(make_error(MutationErrorCode::InvalidOperation,
                                          "operação ou índice inválido",
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
                                          "operação local sem slot de backup",
                                          operation.path,
                                          operation_index));
    }

    if (operation.action == Action::RenameLocal) {
        auto source =
            resolve_local_path(local_root, operation.path, operation_index);
        auto destination =
            resolve_local_path(local_root, operation.alt_path, operation_index);
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
                                              "rename não aceita symlink",
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
                               "origem do rename não é arquivo regular",
                               *source,
                               operation_index));
            }
            auto actual = file_hash(*source, operation_index);
            if (!actual)
                return std::unexpected(actual.error());
            if (!operation.hash.empty() && *actual != operation.hash) {
                return std::unexpected(make_error(
                    MutationErrorCode::IntegrityMismatch,
                    "origem do rename não corresponde ao hash esperado",
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
                    "destino do rename não corresponde ao hash esperado",
                    *destination,
                    operation_index));
            }
            result.had_original = false;
            result.previous_hash = *actual;
            return result;
        }
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "estado inicial do rename é ambíguo",
                       operation.path,
                       operation_index));
    }

    auto path = resolve_local_path(local_root, operation.path, operation_index);
    if (!path)
        return std::unexpected(path.error());
    if (operation.action == Action::CreateLocalDirectory ||
        operation.action == Action::DeleteLocalDirectory) {
        auto status = read_status(*path, operation_index);
        if (!status)
            return std::unexpected(status.error());
        if (std::filesystem::is_symlink(*status)) {
            return std::unexpected(make_error(MutationErrorCode::UnsafePath,
                                              "diretório local é um symlink",
                                              *path,
                                              operation_index));
        }
        if (!missing(*status) && !std::filesystem::is_directory(*status)) {
            return std::unexpected(
                make_error(MutationErrorCode::DestinationConflict,
                           "objeto local não é diretório",
                           *path,
                           operation_index));
        }
        auto result = current_progress;
        result.had_original = !missing(*status);
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
                        const transaction::OperationProgress& progress) {
    if (operation_index == std::numeric_limits<std::size_t>::max() ||
        !is_valid_action(operation.action) || !has_safe_paths(operation)) {
        return std::unexpected(make_error(MutationErrorCode::InvalidOperation,
                                          "operação ou índice inválido",
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
                           "objeto criado não é diretório regular",
                           *path,
                           operation_index));
        }
        std::error_code error;
        std::filesystem::directory_iterator iterator(*path, error);
        if (error || iterator != std::filesystem::directory_iterator{}) {
            return std::unexpected(
                make_error(MutationErrorCode::DestinationConflict,
                           "diretório criado não está vazio",
                           *path,
                           operation_index));
        }
        if (!std::filesystem::remove(*path, error) || error) {
            return std::unexpected(make_error(
                MutationErrorCode::LocalIo,
                error ? error.message() : "não foi possível remover diretório",
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
                               "objeto restaurado não é diretório regular",
                               *path,
                               operation_index));
            }
            return {};
        }
        std::error_code error;
        if (!std::filesystem::create_directory(*path, error) || error) {
            return std::unexpected(make_error(
                MutationErrorCode::LocalIo,
                error ? error.message() : "não foi possível recriar diretório",
                *path,
                operation_index));
        }
        return {};
    }
    return rollback_file_operation(
        operation, operation_index, local_root, workspace, progress);
}

} // namespace

PreparationResult
prepare_operation(const Operation& operation,
                  std::size_t operation_index,
                  const std::filesystem::path& local_root,
                  const platform::Workspace& workspace,
                  const transaction::OperationProgress& current_progress) {
    return prepare_operation_impl(
        operation, operation_index, local_root, workspace, current_progress);
}

std::expected<void, MutationError>
rollback_operation(const Operation& operation,
                   std::size_t operation_index,
                   const std::filesystem::path& local_root,
                   const platform::Workspace& workspace,
                   const transaction::OperationProgress& progress) {
    return rollback_operation_impl(
        operation, operation_index, local_root, workspace, progress);
}

} // namespace kasumi::application::sync::mutation
