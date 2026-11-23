#include "application/sync/coordinator.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/mutation.hpp"
#include "application/sync/mutation_detail.hpp"
#include "application/sync/publication.hpp"
#include "coordinator_detail.hpp"
#include "core/hasher.hpp"
#include "core/transaction/types.hpp"
#include "crypto/key_derivation.hpp"
#include "journal_fault_test.hpp"
#include "platform/durability.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "platform/workspace.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <utility>
#include <vector>

namespace kasumi::application::sync::coordinator::detail {

Error make_error(ErrorCode code,
                 std::string detail,
                 std::optional<std::size_t> operation_index) {
    return Error{.code = code,
                 .detail = std::move(detail),
                 .operation_index = operation_index};
}

Error journal_error(std::string detail) {
    return make_error(ErrorCode::JournalFailure, std::move(detail));
}

Error indeterminate_publication(const publication::Error& error,
                                std::string_view operation) {
    return make_error(ErrorCode::RecoveryIndeterminate,
                      "failed to determine " + std::string{operation} + ": " +
                          error.detail);
}

Error mutation_error(const mutation::MutationError& error) {
    return make_error(error.code ==
                              mutation::MutationErrorCode::RemoteContentMissing
                          ? ErrorCode::RemoteContentMissing
                          : ErrorCode::MutationFailure,
                      mutation::describe(error),
                      error.operation_index);
}

Error publication_error(const publication::Error& error) {
    return make_error(ErrorCode::PublicationFailure, error.detail);
}

bool missing(std::filesystem::file_status status) noexcept {
    return status.type() == std::filesystem::file_type::not_found;
}

Error workspace_error(std::string_view operation,
                      const std::filesystem::path& path,
                      std::string detail) {
    return make_error(ErrorCode::WorkspaceFailure,
                      std::string{operation} + " '" +
                          platform::path::to_utf8(path) +
                          "': " + std::move(detail));
}

std::expected<std::filesystem::file_status, Error>
read_status(const std::filesystem::path& path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error == std::errc::no_such_file_or_directory ||
        error == std::errc::not_a_directory) {
        return std::filesystem::file_status{
            std::filesystem::file_type::not_found};
    }
    if (error) {
        return std::unexpected(workspace_error(
            "failed to inspect path in file system", path, error.message()));
    }
    return status;
}

std::expected<void, Error>
require_physical_directory(std::filesystem::file_status status,
                           const std::filesystem::path& path,
                           std::string_view error_title) {
    if (std::filesystem::is_symlink(status) ||
        !std::filesystem::is_directory(status)) {
        return std::unexpected(workspace_error(
            error_title, path, "expected a physical directory"));
    }
    return {};
}

std::unexpected<Error> fail_after_rollback(std::expected<void, Error> rolled,
                                           Error original) {
    if (!rolled) {
        return std::unexpected(std::move(rolled.error()));
    }
    return std::unexpected(std::move(original));
}

std::expected<std::filesystem::path, Error>
profile_directory(const runtime::RuntimeData& runtime_data) {
    const auto profile = runtime_data.database_path.parent_path();
    if (profile.empty() || profile == "." || profile == "..") {
        return std::unexpected(
            make_error(ErrorCode::InvalidInput, "invalid profile directory"));
    }
    return profile.lexically_normal();
}

std::expected<std::filesystem::path, Error>
transactions_directory(const std::filesystem::path& profile, bool create) {
    auto status = read_status(profile);
    if (!status || missing(*status) || std::filesystem::is_symlink(*status) ||
        !std::filesystem::is_directory(*status)) {
        if (!status) {
            return std::unexpected(status.error());
        }
        return std::unexpected(
            workspace_error("invalid profile directory",
                            profile,
                            "expected a physical directory"));
    }
    const auto directory = profile / ".transactions";
    status = read_status(directory);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (missing(*status)) {
        if (!create) {
            return directory;
        }
        auto created = platform::private_storage::create_directory(directory);
        if (!created) {
            return std::unexpected(
                workspace_error("failed to create transactions directory",
                                directory,
                                created.error()));
        }
        return directory;
    }
    if (auto valid = require_physical_directory(
            *status, directory, "invalid transactions directory");
        !valid) {
        return std::unexpected(valid.error());
    }
    auto secured = platform::private_storage::protect_directory(directory);
    if (!secured) {
        return std::unexpected(workspace_error(
            "invalid transactions directory", directory, secured.error()));
    }
    return directory;
}

namespace {

constexpr std::string_view workspace_owner_file = ".kasumi-workspace-owner";
constexpr std::string_view workspace_owner_sidecar_prefix =
    ".kasumi-workspace-owner-";
constexpr std::string_view workspace_quarantine_prefix = ".kasumi-cleanup-";

std::filesystem::path
workspace_owner_sidecar(const std::filesystem::path& directory,
                        std::string_view id) {
    return directory /
           platform::path::from_utf8(
               std::string{workspace_owner_sidecar_prefix} + std::string{id});
}

std::optional<std::string>
transaction_id_from_owner_sidecar(std::string_view name) {
    if (!name.starts_with(workspace_owner_sidecar_prefix)) {
        return std::nullopt;
    }
    const auto id = name.substr(workspace_owner_sidecar_prefix.size());
    if (!transaction::valid_transaction_id(id)) {
        return std::nullopt;
    }
    return std::string{id};
}

std::optional<std::string>
transaction_id_from_quarantine(std::string_view name) {
    if (!name.starts_with(workspace_quarantine_prefix)) {
        return std::nullopt;
    }
    const auto suffix = name.substr(workspace_quarantine_prefix.size());
    if (suffix.size() <= 33 || suffix[32] != '-') {
        return std::nullopt;
    }
    const auto id = suffix.substr(0, 32);
    if (!transaction::valid_transaction_id(id)) {
        return std::nullopt;
    }
    return std::string{id};
}

std::string workspace_owner_payload(
    std::string_view id,
    const platform::private_storage::DirectoryIdentity& identity) {
    return "kasumi-transaction-workspace-v1\n" + std::string{id} + "\n" +
           std::to_string(identity.volume_or_dev) + "\n" +
           std::to_string(identity.file_id_low) + "\n" +
           std::to_string(identity.file_id_high) + "\n";
}

std::string
workspace_owner_mac(std::string_view payload,
                    std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    const auto bytes = std::span{
        reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size()};
    return hash_hex(crypto::derive_identifier(
        key, crypto::IdentifierPurpose::Namespace, bytes));
}

std::optional<std::uint64_t> parse_workspace_id(std::string_view text) {
    std::uint64_t value = 0;
    const auto [end, error] =
        std::from_chars(text.data(), text.data() + text.size(), value);
    if (text.empty() || error != std::errc{} ||
        end != text.data() + text.size()) {
        return std::nullopt;
    }
    return value;
}

std::expected<void, Error> write_workspace_owner(
    const std::filesystem::path& marker,
    std::string_view id,
    const platform::private_storage::DirectoryIdentity& identity,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    const auto payload = workspace_owner_payload(id, identity);
    const auto text = payload + workspace_owner_mac(payload, key) + "\n";
    auto written = platform::private_storage::write_atomically(marker, text);
    if (!written) {
        return std::unexpected(
            workspace_error("failed to persist transaction workspace ownership",
                            marker,
                            written.error()));
    }
    return {};
}

template <typename Fn>
std::expected<void, Error>
for_each_transaction_entry(const std::filesystem::path& directory, Fn&& fn) {
    std::error_code error;
    std::filesystem::directory_iterator entry(directory, error), end;
    if (error) {
        return std::unexpected(
            workspace_error("failed to enumerate transaction workspaces",
                            directory,
                            error.message()));
    }
    while (entry != end) {
        const auto candidate = entry->path().lexically_normal();
        if (auto ok =
                fn(candidate, platform::path::to_utf8(candidate.filename()));
            !ok) {
            return std::unexpected(ok.error());
        }
        entry.increment(error);
        if (error) {
            return std::unexpected(
                workspace_error("failed to enumerate transaction workspaces",
                                directory,
                                error.message()));
        }
    }
    return {};
}

std::expected<std::optional<platform::private_storage::DirectoryIdentity>,
              Error>
read_workspace_owner_marker(
    const std::filesystem::path& marker,
    std::string_view id,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(marker, error);
    if (error == std::errc::no_such_file_or_directory ||
        status.type() == std::filesystem::file_type::not_found) {
        return std::optional<platform::private_storage::DirectoryIdentity>{};
    }
    if (error) {
        return std::unexpected(workspace_error(
            "failed to inspect transaction workspace owner marker",
            marker,
            error.message()));
    }
    if (std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        return std::unexpected(
            workspace_error("invalid transaction workspace owner marker",
                            marker,
                            "expected a regular file"));
    }
    const auto size = std::filesystem::file_size(marker, error);
    if (error || size > 256) {
        return std::unexpected(workspace_error(
            "invalid transaction workspace owner marker",
            marker,
            error ? error.message() : "marker exceeds size limit"));
    }
    std::ifstream input(marker, std::ios::binary);
    const std::string text{std::istreambuf_iterator<char>{input}, {}};
    if (input.bad()) {
        return std::unexpected(
            workspace_error("failed to read transaction workspace owner marker",
                            marker,
                            "read failed"));
    }
    std::array<std::string_view, 6> lines{};
    std::string_view remaining{text};
    for (auto& line : lines) {
        const auto newline = remaining.find('\n');
        if (newline == std::string_view::npos) {
            return std::unexpected(
                workspace_error("invalid transaction workspace owner marker",
                                marker,
                                "malformed marker"));
        }
        line = remaining.substr(0, newline);
        remaining.remove_prefix(newline + 1);
    }
    if (!remaining.empty() || lines[0] != "kasumi-transaction-workspace-v1" ||
        lines[1] != id) {
        return std::unexpected(
            workspace_error("invalid transaction workspace owner marker",
                            marker,
                            "operation identifier or format mismatch"));
    }
    const auto volume = parse_workspace_id(lines[2]);
    const auto low = parse_workspace_id(lines[3]);
    const auto high = parse_workspace_id(lines[4]);
    if (!volume || !low || !high) {
        return std::unexpected(
            workspace_error("invalid transaction workspace owner marker",
                            marker,
                            "invalid directory identity"));
    }
    platform::private_storage::DirectoryIdentity identity{.volume_or_dev =
                                                              *volume,
                                                          .file_id_low = *low,
                                                          .file_id_high = *high,
                                                          .valid = true};
    const auto payload = workspace_owner_payload(id, identity);
    if (lines[5] != workspace_owner_mac(payload, key)) {
        return std::unexpected(
            workspace_error("invalid transaction workspace owner marker",
                            marker,
                            "authentication mismatch"));
    }
    return std::optional{identity};
}

std::expected<std::optional<platform::private_storage::DirectoryIdentity>,
              Error>
read_workspace_owner(const std::filesystem::path& root,
                     std::string_view id,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    const auto internal =
        read_workspace_owner_marker(root / workspace_owner_file, id, key);
    if (!internal) {
        return std::unexpected(internal.error());
    }
    const auto sidecar = read_workspace_owner_marker(
        workspace_owner_sidecar(root.parent_path(), id), id, key);
    if (!sidecar) {
        return std::unexpected(sidecar.error());
    }
    if (*internal && *sidecar && **internal != **sidecar) {
        return std::unexpected(
            workspace_error("invalid transaction workspace owner marker",
                            workspace_owner_sidecar(root.parent_path(), id),
                            "internal and durable ownership proofs disagree"));
    }
    const auto owner = *internal ? *internal : *sidecar;
    if (owner &&
        platform::private_storage::query_directory_identity(root) != *owner) {
        return std::unexpected(
            workspace_error("invalid transaction workspace owner marker",
                            root / workspace_owner_file,
                            "directory identity mismatch"));
    }
    return owner;
}

std::expected<void, Error> retire_workspace_owner(
    const std::filesystem::path& sidecar,
    std::string_view id,
    const platform::private_storage::DirectoryIdentity& identity,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    auto owner = read_workspace_owner_marker(sidecar, id, key);
    if (!owner) {
        return std::unexpected(owner.error());
    }
    if (!*owner) {
        return {};
    }
    if (!identity.valid || **owner != identity) {
        return std::unexpected(
            workspace_error("invalid transaction workspace owner marker",
                            sidecar,
                            "saved directory identity mismatch"));
    }
    std::error_code error;
    std::filesystem::remove(sidecar, error);
    if (error) {
        return std::unexpected(workspace_error(
            "failed to remove transaction workspace ownership proof",
            sidecar,
            error.message()));
    }
    auto synced = platform::durability::sync_parent_directory(sidecar);
    if (!synced) {
        return std::unexpected(workspace_error(
            "failed to sync transaction workspace ownership proof",
            sidecar.parent_path(),
            synced.error()));
    }
    return {};
}

std::expected<void, Error> rollback_operations_in_workspace(
    transaction::Record& record,
    const std::optional<platform::Workspace>& workspace,
    const std::filesystem::path& local_root,
    bool local_mutations_only) {
    if (has_local_rollback_work(record) && !workspace) {
        return std::unexpected(make_error(
            ErrorCode::RecoveryConflict,
            "transaction workspace missing while local rollback is required"));
    }
    if (!workspace) {
        return {};
    }
    const auto dependencies =
        mutation::detail::destination_dependencies(record.plan.operations);
    std::vector<std::size_t> order(record.plan.operations.size());
    std::iota(order.begin(), order.end(), std::size_t{0});
    order_local_type_changes(local_type_changes(record.plan.operations), order);
    for (const auto operation_index : order | std::views::reverse) {
        const auto& operation = record.plan.operations[operation_index];
        auto& progress = record.progress[operation_index];
        if ((local_mutations_only && !is_local_mutation(operation.action)) ||
            (progress.state < transaction::OperationState::BackupCreated &&
             !(operation.action == Action::CopyLocal &&
               progress.state == transaction::OperationState::Prepared))) {
            continue;
        }
        auto condition = mutation::detail::effective_destination(
            record, operation_index, dependencies);
        if (!condition) {
            return std::unexpected(
                make_error(ErrorCode::RecoveryConflict,
                           mutation::describe(condition.error()),
                           operation_index));
        }
        auto rolled =
            mutation::rollback_operation(operation,
                                         operation_index,
                                         local_root,
                                         *workspace,
                                         progress,
                                         *condition ? &**condition : nullptr);
        if (!rolled) {
            return std::unexpected(make_error(
                ErrorCode::RecoveryConflict,
                std::string{local_mutations_only ? "rollback local failed: "
                                                 : "rollback failed: "} +
                    mutation::describe(rolled.error()),
                operation_index));
        }
        if (local_mutations_only) {
            progress.state = transaction::OperationState::Prepared;
        }
    }
    return {};
}

} // namespace

std::expected<platform::Workspace, Error> create_transaction_workspace(
    const std::filesystem::path& profile,
    std::string_view id,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    if (!transaction::valid_transaction_id(id)) {
        return std::unexpected(make_error(ErrorCode::WorkspaceFailure,
                                          "invalid transaction identifier"));
    }
    auto directory = transactions_directory(profile, true);
    if (!directory) {
        return std::unexpected(directory.error());
    }
    const auto root = *directory / platform::path::from_utf8(id);
    auto status = read_status(root);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (!missing(*status)) {
        if (auto valid = require_physical_directory(
                *status, root, "invalid transaction workspace");
            !valid) {
            return std::unexpected(valid.error());
        }
        auto opened = open_transaction_workspace(profile, id, key);
        if (!opened) {
            return std::unexpected(opened.error());
        }
        if (!*opened || !(**opened).identity.valid) {
            return std::unexpected(workspace_error(
                "transaction workspace ownership is unavailable",
                root,
                "preserving existing directory"));
        }
        return **opened;
    }
    auto pending = open_transaction_workspace(profile, id, key);
    if (!pending) {
        return std::unexpected(pending.error());
    }
    if (*pending) {
        return std::unexpected(
            workspace_error("transaction workspace cleanup is pending",
                            (**pending).root,
                            "preserving existing ownership proof"));
    }
    auto created = platform::create_workspace_at(root);
    if (!created) {
        return std::unexpected(workspace_error(
            "failed to create transaction workspace", root, created.error()));
    }
    auto owner = write_workspace_owner(
        created->root / workspace_owner_file, id, created->identity, key);
    if (!owner) {
        auto cleanup = platform::remove_workspace(*created);
        if (!cleanup) {
            return std::unexpected(workspace_error(
                "failed to create transaction workspace ownership proof",
                root,
                owner.error().detail + "; cleanup failed: " + cleanup.error()));
        }
        return std::unexpected(owner.error());
    }
    return *created;
}

std::expected<std::optional<platform::Workspace>, Error>
open_transaction_workspace(
    const std::filesystem::path& profile,
    std::string_view id,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    if (!transaction::valid_transaction_id(id)) {
        return std::unexpected(make_error(ErrorCode::WorkspaceFailure,
                                          "invalid transaction identifier"));
    }
    auto directory = transactions_directory(profile, false);
    if (!directory) {
        return std::unexpected(directory.error());
    }
    const auto root = *directory / platform::path::from_utf8(id);
    auto status = read_status(root);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (!missing(*status)) {
        if (auto valid = require_physical_directory(
                *status, root, "invalid transaction workspace");
            !valid) {
            return std::unexpected(valid.error());
        }
    }

    std::optional<platform::Workspace> quarantined;
    auto directory_status = read_status(*directory);
    if (!directory_status) {
        return std::unexpected(directory_status.error());
    }
    if (!missing(*directory_status)) {
        if (auto valid =
                require_physical_directory(*directory_status,
                                           *directory,
                                           "invalid transactions directory");
            !valid) {
            return std::unexpected(valid.error());
        }
        if (auto visited = for_each_transaction_entry(
                *directory,
                [&](const std::filesystem::path& candidate,
                    const std::string& name) -> std::expected<void, Error> {
                    const auto quarantined_id =
                        transaction_id_from_quarantine(name);
                    if (!quarantined_id || *quarantined_id != id) {
                        return {};
                    }
                    auto candidate_status = read_status(candidate);
                    if (!candidate_status) {
                        return std::unexpected(candidate_status.error());
                    }
                    if (auto valid = require_physical_directory(
                            *candidate_status,
                            candidate,
                            "invalid quarantined transaction workspace");
                        !valid) {
                        return valid;
                    }
                    auto identity = read_workspace_owner(candidate, id, key);
                    if (!identity) {
                        return std::unexpected(identity.error());
                    }
                    if (!*identity || quarantined) {
                        return std::unexpected(workspace_error(
                            "ambiguous quarantined transaction workspace",
                            candidate,
                            "ownership proof is missing or duplicated"));
                    }
                    quarantined = platform::Workspace{.root = candidate,
                                                      .identity = **identity};
                    return {};
                });
            !visited) {
            return std::unexpected(visited.error());
        }
    }
    if (quarantined) {
        if (!missing(*status)) {
            return std::unexpected(workspace_error(
                "multiple transaction workspaces exist",
                root,
                "preserving the journal and all workspace paths"));
        }
        return quarantined;
    }
    if (missing(*status)) {
        auto owner = read_workspace_owner_marker(
            workspace_owner_sidecar(*directory, id), id, key);
        if (!owner) {
            return std::unexpected(owner.error());
        }
        if (!*owner) {
            return std::optional<platform::Workspace>{};
        }
        return std::optional<platform::Workspace>{
            platform::Workspace{.root = root, .identity = **owner}};
    }
    const auto current_identity =
        platform::private_storage::query_directory_identity(root);
    if (!current_identity.valid) {
        return std::unexpected(
            workspace_error("invalid transaction workspace",
                            root,
                            "expected a physical directory"));
    }
    auto identity = read_workspace_owner(root, id, key);
    if (!identity) {
        return std::unexpected(identity.error());
    }
    return std::optional<platform::Workspace>{platform::Workspace{
        .root = root,
        .identity = identity->value_or(
            platform::private_storage::DirectoryIdentity{})}};
}

std::expected<void, Error> remove_transaction_workspace(
    const std::optional<platform::Workspace>& workspace,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    if (!workspace || workspace->root.empty()) {
        return {};
    }
    auto id = platform::path::to_utf8(workspace->root.filename());
    if (!transaction::valid_transaction_id(id)) {
        const auto quarantined_id = transaction_id_from_quarantine(id);
        if (!quarantined_id) {
            return std::unexpected(
                workspace_error("invalid transaction workspace path",
                                workspace->root,
                                "operation identifier is unavailable"));
        }
        id = *quarantined_id;
    }
    const auto sidecar =
        workspace_owner_sidecar(workspace->root.parent_path(), id);
    auto status = read_status(workspace->root);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (missing(*status)) {
        auto synced =
            platform::durability::sync_parent_directory(workspace->root);
        if (!synced) {
            return std::unexpected(workspace_error(
                "failed to sync parent directory of transaction workspace",
                workspace->root.parent_path(),
                synced.error()));
        }
        return retire_workspace_owner(sidecar, id, workspace->identity, key);
    }
    if (auto valid = require_physical_directory(
            *status, workspace->root, "invalid transaction workspace");
        !valid) {
        return valid;
    }
    if (!workspace->identity.valid) {
        return std::unexpected(
            workspace_error("transaction workspace ownership is unavailable",
                            workspace->root,
                            "preserving existing directory"));
    }
    auto owner = read_workspace_owner(workspace->root, id, key);
    if (!owner) {
        return std::unexpected(owner.error());
    }
    if (!*owner || **owner != workspace->identity) {
        return std::unexpected(
            workspace_error("transaction workspace ownership is unavailable",
                            workspace->root,
                            "preserving existing directory"));
    }
    auto durable_owner = read_workspace_owner_marker(sidecar, id, key);
    if (!durable_owner) {
        return std::unexpected(durable_owner.error());
    }
    if (!*durable_owner) {
        auto saved =
            write_workspace_owner(sidecar, id, workspace->identity, key);
        if (!saved) {
            return std::unexpected(saved.error());
        }
    } else if (**durable_owner != workspace->identity) {
        return std::unexpected(
            workspace_error("invalid transaction workspace owner marker",
                            sidecar,
                            "saved directory identity mismatch"));
    }
    auto removed = platform::remove_workspace(*workspace);
    if (!removed) {
        return std::unexpected(
            workspace_error("failed to remove transaction workspace",
                            workspace->root,
                            removed.error()));
    }
    auto synced = platform::durability::sync_parent_directory(workspace->root);
    if (!synced) {
        return std::unexpected(
            workspace_error("failed to sync parent directory of "
                            "transaction workspace",
                            workspace->root.parent_path(),
                            synced.error()));
    }
    return retire_workspace_owner(sidecar, id, workspace->identity, key);
}

std::expected<void, Error>
finish_transaction_cleanup(const journal::Paths& paths,
                           const std::optional<platform::Workspace>& workspace,
                           std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                           journal::Session* session) {
    if (workspace && !workspace->identity.valid) {
        auto status = read_status(workspace->root);
        if (!status) {
            return std::unexpected(status.error());
        }
        if (!missing(*status)) {
            auto cleared = journal::clear(paths, key, session);
            if (!cleared) {
                return std::unexpected(journal_error(cleared.error()));
            }
            return std::unexpected(workspace_error(
                "transaction completed with workspace preserved",
                workspace->root,
                "ownership proof is unavailable"));
        }
    }
    auto removed = remove_transaction_workspace(workspace, key);
    if (!removed) {
        return std::unexpected(removed.error());
    }
    auto cleared = journal::clear(paths, key, session);
    if (!cleared) {
        return std::unexpected(journal_error(cleared.error()));
    }
    return {};
}

std::expected<void, Error>
cleanup_orphan_workspaces(const std::filesystem::path& profile,
                          std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    auto directory = transactions_directory(profile, false);
    if (!directory) {
        return std::unexpected(directory.error());
    }
    auto status = read_status(*directory);
    if (!status) {
        return std::unexpected(status.error());
    }
    if (missing(*status)) {
        return {};
    }
    if (auto valid = require_physical_directory(
            *status, *directory, "invalid transactions directory");
        !valid) {
        return valid;
    }

    std::vector<std::string> candidates;
    if (auto visited = for_each_transaction_entry(
            *directory,
            [&](const std::filesystem::path& candidate,
                const std::string& name) -> std::expected<void, Error> {
                if (transaction::valid_transaction_id(name)) {
                    if (candidate.parent_path() !=
                        directory->lexically_normal()) {
                        return std::unexpected(workspace_error(
                            "unsafe transaction workspace path",
                            candidate,
                            "path escapes transactions directory"));
                    }
                    candidates.push_back(name);
                } else if (const auto quarantine_id =
                               transaction_id_from_quarantine(name)) {
                    candidates.push_back(*quarantine_id);
                } else if (const auto owner_id =
                               transaction_id_from_owner_sidecar(name)) {
                    candidates.push_back(*owner_id);
                }
                return {};
            });
        !visited) {
        return std::unexpected(visited.error());
    }
    std::ranges::sort(candidates);
    candidates.erase(std::unique(candidates.begin(), candidates.end()),
                     candidates.end());
    for (const auto& id : candidates) {
        auto workspace = open_transaction_workspace(profile, id, key);
        if (!workspace) {
            return std::unexpected(workspace.error());
        }
        if (!*workspace || !(**workspace).identity.valid) {
            continue;
        }
        auto removed = remove_transaction_workspace(**workspace, key);
        if (!removed) {
            return std::unexpected(removed.error());
        }
    }
    return {};
}

std::expected<journal::Paths, Error>
make_journal_paths(const runtime::RuntimeData& runtime_data) {
    auto profile = profile_directory(runtime_data);
    if (!profile) {
        return std::unexpected(profile.error());
    }
    auto paths = journal::make_paths(*profile);
    if (!paths) {
        return std::unexpected(journal_error(paths.error()));
    }
    return *paths;
}

std::expected<void, Error>
save_record(const journal::Paths& paths,
            const transaction::Record& record,
            std::span<const std::uint8_t, crypto::KEY_SIZE> key,
            journal::SaveMode mode,
            journal::Session* session) {
    auto saved = journal::save(paths, record, key, mode, session);
    if (!saved) {
        return std::unexpected(journal_error(saved.error()));
    }
    journal_fault_test::hit(
        "saved", &record, static_cast<std::size_t>(record.phase));
    return {};
}

transaction::Record
make_upload_batch_checkpoint(const transaction::Record& original,
                             const mutation::StagedUploadBatch& batch) {
    transaction::Record checkpoint = original;
    for (const auto& obj : batch.objects) {
        for (std::size_t index : obj.operation_indices) {
            checkpoint.progress[index].state =
                transaction::OperationState::Applied;
        }
    }
    return checkpoint;
}

std::expected<void, Error>
checkpoint_upload_batch(const journal::Paths& paths,
                        transaction::Record& record,
                        const mutation::StagedUploadBatch& batch,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        journal::Session* session) {
    auto checkpoint = make_upload_batch_checkpoint(record, batch);
    auto saved = save_record(
        paths, checkpoint, key, journal::SaveMode::Advance, session);
    if (!saved) {
        return std::unexpected(saved.error());
    }

    record = std::move(checkpoint);

    return {};
}

bool has_local_rollback_work(const transaction::Record& record) noexcept {
    for (std::size_t index = 0; index < record.plan.operations.size();
         ++index) {
        if (is_local_mutation(record.plan.operations[index].action) &&
            (record.progress[index].state >=
                 transaction::OperationState::BackupCreated ||
             (record.plan.operations[index].action == Action::CopyLocal &&
              record.progress[index].state ==
                  transaction::OperationState::Prepared))) {
            return true;
        }
    }
    return false;
}

std::vector<TypeChangeStep>
local_type_changes(std::span<const transaction::Operation> operations) {
    std::unordered_set<std::filesystem::path> deleted_files;
    std::unordered_set<std::filesystem::path> deleted_directories;
    for (const auto& operation : operations) {
        if (operation.action == Action::DeleteLocal) {
            deleted_files.insert(operation.path);
        } else if (operation.action == Action::DeleteLocalDirectory) {
            deleted_directories.insert(operation.path);
        }
    }
    std::unordered_set<std::filesystem::path> to_file;
    std::unordered_set<std::filesystem::path> to_directory;
    for (const auto& operation : operations) {
        if (operation.action == Action::Download &&
            deleted_directories.contains(operation.path)) {
            to_file.insert(operation.path);
        } else if (operation.action == Action::CreateLocalDirectory &&
                   deleted_files.contains(operation.path)) {
            to_directory.insert(operation.path);
        }
    }
    std::vector<TypeChangeStep> steps(operations.size(),
                                      TypeChangeStep::Unrelated);
    if (to_file.empty() && to_directory.empty()) {
        return steps;
    }
    const auto inside = [](const auto& roots, std::filesystem::path path) {
        for (; !path.empty(); path = path.parent_path()) {
            if (roots.contains(path)) {
                return true;
            }
        }
        return false;
    };
    for (std::size_t index = 0; index < operations.size(); ++index) {
        const auto& operation = operations[index];
        const auto& path = operation.path;
        if ((operation.action == Action::DeleteLocal ||
             operation.action == Action::DeleteIgnoredLocalFile) &&
            (to_directory.contains(path) || inside(to_file, path))) {
            steps[index] = TypeChangeStep::RemoveFile;
        } else if (operation.action == Action::DeleteLocalDirectory &&
                   inside(to_file, path)) {
            steps[index] = TypeChangeStep::RemoveDirectory;
        } else if ((operation.action == Action::Download ||
                    operation.action == Action::CreateLocalDirectory) &&
                   (to_file.contains(path) || inside(to_directory, path))) {
            steps[index] = TypeChangeStep::Install;
        }
    }
    return steps;
}

void order_local_type_changes(std::span<const TypeChangeStep> steps,
                              std::vector<std::size_t>& order) {
    const auto first = std::stable_partition(
        order.begin(), order.end(), [&](std::size_t index) {
            return steps[index] == TypeChangeStep::Unrelated;
        });
    const auto first_directory =
        std::stable_partition(first, order.end(), [&](std::size_t index) {
            return steps[index] == TypeChangeStep::RemoveFile;
        });
    std::stable_partition(first_directory, order.end(), [&](std::size_t index) {
        return steps[index] == TypeChangeStep::RemoveDirectory;
    });
}

std::expected<void, Error>
prepare_type_change_install(transaction::Record& record,
                            std::size_t index,
                            const std::filesystem::path& root,
                            const platform::Workspace& workspace) {
    auto& progress = record.progress[index];
    auto prepared = mutation::prepare_operation(
        record.plan.operations[index], index, root, workspace, progress);
    if (!prepared) {
        return std::unexpected(make_error(ErrorCode::MutationFailure,
                                          mutation::describe(prepared.error()),
                                          index));
    }
    if (prepared->had_original) {
        return std::unexpected(
            make_error(ErrorCode::ConcurrentModification,
                       "replacement destination appeared during sync",
                       index));
    }
    progress = std::move(*prepared);
    return {};
}

std::vector<std::size_t>
next_upload_batch_chunk(std::span<const std::size_t> pending_uploads,
                        std::size_t& cursor,
                        std::span<const transaction::Operation> operations) {
    std::vector<std::size_t> chunk;
    std::uint64_t chunk_bytes = 0;
    while (cursor + chunk.size() < pending_uploads.size() &&
           chunk.size() < upload_batch_max_items &&
           (chunk.empty() ||
            chunk_bytes +
                    operations[pending_uploads[cursor + chunk.size()]].size <=
                upload_batch_max_bytes)) {
        const auto op_index = pending_uploads[cursor + chunk.size()];
        chunk_bytes += operations[op_index].size;
        chunk.push_back(op_index);
    }
    cursor += chunk.size();
    return chunk;
}

std::expected<void, Error>
rollback_transaction(const journal::Paths& paths,
                     transaction::Record& record,
                     const std::optional<platform::Workspace>& workspace,
                     const std::filesystem::path& local_root,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                     journal::Session* session) {
    if (auto rolled = rollback_operations_in_workspace(
            record, workspace, local_root, false);
        !rolled) {
        return rolled;
    }
    record.phase = transaction::Phase::Started;
    record.commit_id.clear();
    record.ciphertext_id.clear();
    record.parent_ids.clear();
    record.marker_id.clear();
    record.epoch_vault_id.clear();
    record.epoch_id.clear();
    record.epoch_issued_at = 0;
    record.epoch_min_history_depth = 0;
    record.epoch_min_history_age_hours = 0;
    for (auto& progress : record.progress) {
        progress.previous_hash.clear();
        progress.state = transaction::OperationState::Pending;
        progress.had_original = false;
    }
    auto saved =
        save_record(paths, record, key, journal::SaveMode::Rollback, session);
    if (!saved) {
        return std::unexpected(saved.error());
    }
    journal_fault_test::hit("rollback-reset-saved", &record);
    return finish_transaction_cleanup(paths, workspace, key, session);
}

std::expected<void, Error>
rollback_local_mutations(transaction::Record& record,
                         const std::optional<platform::Workspace>& workspace,
                         const std::filesystem::path& local_root) {
    if (auto rolled = rollback_operations_in_workspace(
            record, workspace, local_root, true);
        !rolled) {
        return rolled;
    }
    record.phase = transaction::Phase::FilesStaged;
    return {};
}

std::expected<void, Error> save_state_checked(
    const std::filesystem::path& database_path,
    const state_storage::StoredState& state,
    const std::optional<state_storage::AcceptedCommitMeta>& accepted_meta) {
    if (!state_storage::initialize(database_path)) {
        return std::unexpected(
            make_error(ErrorCode::DatabaseFailure, "failed to save state.db"));
    }
    const bool saved =
        accepted_meta.has_value()
            ? state_storage::save_state(database_path, state, *accepted_meta)
            : state_storage::save_state(database_path, state);
    if (!saved) {
        return std::unexpected(
            make_error(ErrorCode::DatabaseFailure, "failed to save state.db"));
    }
    return {};
}

} // namespace kasumi::application::sync::coordinator::detail
