#include "application/sync/coordinator.hpp"

#include "application/concurrency.hpp"
#include "application/history_storage/content_reachability.hpp"
#include "application/history_storage/epoch.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/observation/scanner.hpp"
#include "application/progress.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/metadata.hpp"
#include "application/sync/mutation.hpp"
#include "application/sync/mutation_batch.hpp"
#include "application/sync/mutation_detail.hpp"
#include "application/sync/mutation_fault_test.hpp"
#include "application/sync/publication.hpp"
#include "coordinator_detail.hpp"
#include "core/hasher.hpp"
#include "core/history.hpp"
#include "core/reconciliation/plan.hpp"
#include "core/transaction/types.hpp"
#include "crypto/content.hpp"
#include "crypto/key_derivation.hpp"
#include "crypto/pack.hpp"
#include "crypto/secure_memory.hpp"
#include "journal_fault_test.hpp"
#include "platform/cancellation.hpp"
#include "platform/clock.hpp"
#include "platform/durability.hpp"
#include "platform/metadata.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"
#include "platform/workspace.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <array>
#include <blake3.h>
#include <charconv>
#include <condition_variable>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <limits>
#include <mutex>
#include <numeric>
#include <optional>
#include <ranges>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace kasumi::application::sync::coordinator {
namespace detail {

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

std::expected<std::optional<platform::private_storage::DirectoryIdentity>,
              Error>
read_workspace_owner(const std::filesystem::path& directory,
                     std::string_view id,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key);

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

history_storage::epoch::Epoch genesis_epoch(const transaction::Record& record) {
    return {
        .vault_id = record.epoch_vault_id,
        .sequence = 0,
        .issued_at = record.epoch_issued_at,
        .policy = {.min_history_depth = record.epoch_min_history_depth,
                   .min_history_age_hours = record.epoch_min_history_age_hours},
        .anchors = {{.commit_id = record.commit_id, .height = 0}},
        .previous_epoch_id = {}};
}

std::expected<history_storage::epoch::SealedEpoch, Error>
seal_transaction_epoch(transaction::Record& record,
                       const history_storage::epoch::Epoch& epoch,
                       std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                       std::string_view mismatch_message) {
    auto sealed = history_storage::epoch::seal(epoch, key);
    if (!sealed) {
        return std::unexpected(
            make_error(ErrorCode::PublicationFailure, sealed.error().detail));
    }
    if (!record.epoch_id.empty() &&
        record.epoch_id != sealed->reference.epoch_id) {
        return std::unexpected(make_error(ErrorCode::RecoveryConflict,
                                          std::string(mismatch_message)));
    }
    record.epoch_id = sealed->reference.epoch_id;
    return *sealed;
}

std::expected<history_storage::epoch::SealedEpoch, Error>
prepare_genesis_epoch(transaction::Record& record,
                      history_storage::epoch::RetentionPolicy policy,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    if (record.plan.target_generation != 0 || !record.parent_ids.empty()) {
        return std::unexpected(
            make_error(ErrorCode::InvalidInput, "commit is not genesis"));
    }
    if (record.epoch_vault_id.empty()) {
        auto vault_id = platform::random::hex_id(HASH_SIZE);
        auto issued_at = platform::clock::unix_seconds();
        if (!vault_id || !issued_at) {
            return std::unexpected(
                make_error(ErrorCode::WorkspaceFailure,
                           vault_id ? issued_at.error() : vault_id.error()));
        }
        record.epoch_vault_id = std::move(*vault_id);
        record.epoch_issued_at = *issued_at;
        record.epoch_min_history_depth = policy.min_history_depth;
        record.epoch_min_history_age_hours = policy.min_history_age_hours;
    }
    return seal_transaction_epoch(
        record, genesis_epoch(record), key, "journal genesis Epoch mismatch");
}

std::expected<history_storage::epoch::SealedEpoch, Error>
prepare_pruning_epoch(transaction::Record& record,
                      history_storage::epoch::RetentionPolicy policy,
                      const history_storage::epoch::EpochPlan& plan,
                      const std::string& previous_vault_id,
                      std::uint64_t previous_sequence,
                      const std::string& previous_epoch_id,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    if (previous_sequence == std::numeric_limits<std::uint64_t>::max()) {
        return std::unexpected(
            make_error(ErrorCode::InvalidInput,
                       "Epoch sequence cannot advance beyond uint64 maximum"));
    }
    if (record.epoch_vault_id.empty()) {
        record.epoch_vault_id = previous_vault_id;
        auto issued_at = platform::clock::unix_seconds();
        if (!issued_at) {
            return std::unexpected(
                make_error(ErrorCode::WorkspaceFailure, issued_at.error()));
        }
        record.epoch_issued_at = *issued_at;
        record.epoch_min_history_depth = policy.min_history_depth;
        record.epoch_min_history_age_hours = policy.min_history_age_hours;
    }
    history_storage::epoch::Epoch epoch = {.vault_id = previous_vault_id,
                                           .sequence = previous_sequence + 1,
                                           .issued_at = record.epoch_issued_at,
                                           .policy = policy,
                                           .anchors = plan.anchors,
                                           .previous_epoch_id =
                                               previous_epoch_id};
    return seal_transaction_epoch(record, epoch, key, "journal Epoch mismatch");
}

static std::expected<std::optional<history_storage::epoch::Reference>, Error>
epoch_reference_for_state(
    const reconciliation::StorageState& observed,
    const std::optional<history_storage::epoch::Reference>&
        verified_new_epoch) {
    // state.db stores only the last authenticated Epoch; the identity in the
    // journal represents progress and may still name an unaccepted
    // candidate.
    if (verified_new_epoch) {
        return verified_new_epoch;
    }
    if (observed.epoch_id.empty()) {
        return std::optional<history_storage::epoch::Reference>{};
    }
    return history_storage::epoch::Reference{
        .sequence = observed.epoch_sequence, .epoch_id = observed.epoch_id};
}

std::expected<void, Error>
validate_epoch_policy_presence(const reconciliation::StorageState& observed) {
    if (observed.epoch_id.empty()) {
        if (!observed.epoch_vault_id.empty() || observed.epoch_sequence != 0 ||
            observed.epoch_policy) {
            return std::unexpected(make_error(
                ErrorCode::InvalidInput,
                "partial Epoch state without authenticated identity"));
        }
        return {};
    }
    if (!history::valid_commit_id(observed.epoch_id) ||
        !history::valid_commit_id(observed.epoch_vault_id) ||
        !observed.epoch_policy ||
        observed.epoch_policy->min_history_depth == 0 ||
        observed.epoch_policy->min_history_depth >
            history::maximum_graph_depth ||
        observed.epoch_policy->min_history_age_hours == 0) {
        return std::unexpected(
            make_error(ErrorCode::InvalidInput,
                       "authenticated Epoch state is structurally invalid"));
    }
    return {};
}

std::expected<void, Error> publish_and_verify_epoch(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const std::filesystem::path& workspace_dir,
    const journal::Paths& paths,
    transaction::Record& record,
    const history_storage::epoch::Epoch& expected_epoch,
    const history_storage::epoch::SealedEpoch& sealed_epoch,
    std::string_view epoch_kind,
    ErrorCode publish_error_code,
    ErrorCode verify_error_code,
    journal::Session* session) {
    auto verify_epoch = [&]() {
        return history_storage::epoch::verify(storage,
                                              expected_epoch,
                                              sealed_epoch.reference,
                                              key,
                                              workspace_dir);
    };
    const auto save_phase =
        [&](transaction::Phase phase) -> std::expected<void, Error> {
        record.phase = phase;
        return save_record(
            paths, record, key, journal::SaveMode::Advance, session);
    };
    if (record.phase < transaction::Phase::EpochUploaded) {
        if (auto published = history_storage::epoch::publish(
                storage, key, sealed_epoch, workspace_dir);
            !published && !verify_epoch()) {
            return std::unexpected(
                make_error(publish_error_code,
                           "failed to publish " + std::string(epoch_kind) +
                               " Epoch: " + published.error().detail));
        }
        if (auto saved = save_phase(transaction::Phase::EpochUploaded);
            !saved) {
            return std::unexpected(saved.error());
        }
    }
    if (auto verified = verify_epoch(); !verified) {
        return std::unexpected(
            make_error(verify_error_code,
                       "failed to verify " + std::string(epoch_kind) +
                           " Epoch: " + verified.error().detail));
    }
    return save_phase(transaction::Phase::EpochVerified);
}

std::expected<history_storage::epoch::RetentionPolicy, Error>
authenticated_epoch_policy(const reconciliation::StorageState& observed) {
    if (observed.epoch_id.empty() || observed.epoch_vault_id.empty() ||
        !observed.epoch_policy) {
        return std::unexpected(
            detail::make_error(ErrorCode::InvalidInput,
                               "authenticated remote Epoch policy is missing"));
    }
    if (observed.epoch_policy->min_history_depth == 0 ||
        observed.epoch_policy->min_history_depth >
            history::maximum_graph_depth ||
        observed.epoch_policy->min_history_age_hours == 0) {
        return std::unexpected(
            detail::make_error(ErrorCode::InvalidInput,
                               "authenticated remote Epoch policy is invalid"));
    }
    return history_storage::epoch::RetentionPolicy{
        .min_history_depth = observed.epoch_policy->min_history_depth,
        .min_history_age_hours = observed.epoch_policy->min_history_age_hours};
}

bool same_epoch_frontier(
    std::span<const reconciliation::EpochAnchor> accepted,
    std::span<const history_storage::epoch::Anchor> planned) noexcept {
    return std::ranges::equal(
        accepted, planned, [](const auto& left, const auto& right) {
            return left.commit_id == right.commit_id &&
                   left.height == right.height;
        });
}

using RoundedTimestamps = std::unordered_map<std::string, std::int64_t>;

bool same_materialized_head_rows(const std::vector<NodeRow>& expected_rows,
                                 const std::vector<NodeRow>& actual_rows,
                                 const Snapshot& observed_local_tree,
                                 const RoundedTimestamps& rounded) noexcept {
    if (expected_rows.size() != actual_rows.size()) {
        return false;
    }
    for (std::size_t i = 0; i < expected_rows.size(); ++i) {
        const auto& exp = expected_rows[i];
        const auto& act = actual_rows[i];
        if (exp.path != act.path || exp.is_directory != act.is_directory) {
            return false;
        }
        if (!exp.is_directory) {
            if (exp.size != act.size || exp.hash != act.hash) {
                return false;
            }
        }
        if (const auto written = rounded.find(exp.path);
            written != rounded.end()) {
            if (!platform::metadata::filesystem_equivalent(written->second,
                                                           act.mtime)) {
                return false;
            }
            continue;
        }
        if (exp.mtime == 0 ||
            platform::metadata::filesystem_equivalent(exp.mtime, act.mtime)) {
            continue;
        }
        if (exp.mtime != act.mtime) {
            const auto* obs = find_row(observed_local_tree, act.path);
            const bool pre_existing_equivalent =
                obs != nullptr && !obs->is_directory && !exp.is_directory &&
                obs->hash == exp.hash && obs->size == exp.size &&
                act.hash == exp.hash && act.size == exp.size &&
                obs->mtime != exp.mtime;
            if (!pre_existing_equivalent) {
                return false;
            }
        }
    }
    return true;
}

bool same_materialized_row(const NodeRow& expected,
                           const NodeRow& actual,
                           const RoundedTimestamps& rounded) noexcept {
    const auto written = rounded.find(expected.path);
    const auto mtime =
        written == rounded.end() ? expected.mtime : written->second;
    return expected.path == actual.path && expected.hash == actual.hash &&
           expected.size == actual.size &&
           (expected.mtime == 0 ||
            platform::metadata::filesystem_equivalent(mtime, actual.mtime)) &&
           expected.is_directory == actual.is_directory;
}

bool same_materialized_rows(std::span<const NodeRow> expected,
                            std::span<const NodeRow> actual,
                            const RoundedTimestamps& rounded) noexcept {
    return expected.size() == actual.size() &&
           std::ranges::equal(
               expected, actual, [&](const auto& exp, const auto& act) {
                   return same_materialized_row(exp, act, rounded);
               });
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

std::expected<void, UploadBatchError> transfer_and_verify_upload_batch(
    const mutation::StagedUploadBatch& batch,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const platform::Workspace& workspace,
    std::size_t parallelism,
    ProgressMeter* meter,
    const std::filesystem::path* item,
    std::string_view progress_identifier) {
    const auto* single = progress_identifier.empty() ? item : nullptr;
    if (meter)
        meter->phase(Activity::Uploading, batch.objects.size(), 0, single);
    transport::TransportProgressCallback progress;
    if (meter && item && !progress_identifier.empty() && meter->observing()) {
        progress = [meter, item](const auto& event) {
            meter->transfer_item(*item, event.item);
        };
    }
    auto transferred = mutation::transfer_upload_batch(
        batch,
        storage,
        parallelism,
        progress ? progress_identifier : std::string_view{},
        progress);
    const bool transfer_unknown =
        !transferred && transferred.error().code ==
                            mutation::MutationErrorCode::RemoteResultUnknown;
    if (!transferred && !transfer_unknown) {
        return std::unexpected(UploadBatchError{
            .transport_after_unknown_transfer = false,
            .mutation = std::move(transferred.error()),
        });
    }
    if (meter)
        meter->phase(Activity::Verifying, batch.objects.size(), 0, single);
    auto verified = mutation::verify_upload_batch(
        batch, storage, key, workspace, parallelism, meter);
    if (!verified) {
        return std::unexpected(UploadBatchError{
            .transport_after_unknown_transfer =
                transfer_unknown &&
                verified.error().code ==
                    mutation::MutationErrorCode::TransportFailure,
            .mutation = std::move(verified.error()),
        });
    }
    return {};
}

std::expected<bool, Error>
verify_existing_content(transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        std::string_view identifier,
                        std::string_view plaintext_hash,
                        std::optional<std::uint64_t> size,
                        const platform::Workspace& workspace,
                        std::size_t operation_index,
                        bool is_pack) {
    const auto checked = history_storage::audit_content_object(storage,
                                                               key,
                                                               identifier,
                                                               plaintext_hash,
                                                               size,
                                                               workspace.root,
                                                               operation_index,
                                                               is_pack);
    if (!checked) {
        return std::unexpected(
            make_error(ErrorCode::ObservationFailure,
                       "could not authenticate existing content: " +
                           checked.error().detail,
                       operation_index));
    }
    return checked->state == history_storage::ContentObjectState::Present;
}

std::expected<void, Error>
save_state_checked(const std::filesystem::path& database_path,
                   const state_storage::StoredState& state) {
    if (!state_storage::initialize(database_path) ||
        !state_storage::save_state(database_path, state)) {
        return std::unexpected(
            make_error(ErrorCode::DatabaseFailure, "failed to save state.db"));
    }
    return {};
}

} // namespace detail

namespace {

Error mutation_error(const mutation::MutationError& error) {
    return detail::make_error(
        error.code == mutation::MutationErrorCode::RemoteContentMissing
            ? ErrorCode::RemoteContentMissing
            : ErrorCode::MutationFailure,
        mutation::describe(error),
        error.operation_index);
}

Error publication_error(const publication::Error& error) {
    return detail::make_error(ErrorCode::PublicationFailure, error.detail);
}

struct CommitTimeDecision {
    std::int64_t created_at = 0;
    bool pruning_time_safe = true;
};

std::expected<CommitTimeDecision, Error>
choose_commit_time(const reconciliation::StorageState& storage,
                   std::int64_t local_now) {
    if (local_now <= 0) {
        return std::unexpected(detail::make_error(
            ErrorCode::PublicationFailure, "invalid local commit timestamp"));
    }
    if (!storage.history_present) {
        return CommitTimeDecision{.created_at = local_now,
                                  .pruning_time_safe = true};
    }
    if (storage.logical_heads.empty()) {
        return std::unexpected(detail::make_error(
            ErrorCode::InvalidInput, "history has no logical heads"));
    }

    std::int64_t newest_parent = 0;
    for (const auto& head : storage.logical_heads) {
        const auto found = std::ranges::find(
            storage.reachable_commits, head, &history::LoadedCommit::id);
        if (found == storage.reachable_commits.end()) {
            return std::unexpected(detail::make_error(
                ErrorCode::InvalidInput,
                "logical head is missing from reachable commits"));
        }
        newest_parent = std::max(newest_parent, found->commit.created_at);
    }

    return CommitTimeDecision{.created_at = std::max(local_now, newest_parent),
                              .pruning_time_safe = newest_parent <= local_now};
}

} // namespace

namespace {

struct ContentWorkResult {
    std::size_t index = 0;
    std::optional<mutation::MutationError> error;
};

struct ContentWorkItem {
    std::size_t index = 0;
    transaction::OperationProgress progress;
    std::optional<mutation::DestinationPrecondition> destination;
    mutation::DownloadCacheMode cache_mode = mutation::DownloadCacheMode::None;
};

struct ContentWindowState {
    std::mutex mutex;
    std::condition_variable_any changed;
    std::vector<std::optional<ContentWorkItem>> tasks;
    std::vector<std::optional<ContentWorkResult>> completions;
};

void run_content_worker(std::stop_token stop,
                        std::size_t slot,
                        ContentWindowState& state,
                        const transaction::Record& record,
                        const std::filesystem::path& local_root,
                        transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        const platform::Workspace& workspace) {
    while (!stop.stop_requested()) {
        ContentWorkItem task;
        {
            std::unique_lock lock(state.mutex);
            if (!state.changed.wait(lock, stop, [&] {
                    return state.tasks[slot].has_value();
                })) {
                return;
            }
            task = std::move(*state.tasks[slot]);
            state.tasks[slot].reset();
        }

        const auto index = task.index;
        ContentWorkResult result{.index = index, .error = std::nullopt};
        try {
            auto applied = mutation::apply_operation(
                record.plan.operations[index],
                index,
                local_root,
                storage,
                key,
                workspace,
                task.progress,
                task.cache_mode,
                task.destination ? &*task.destination : nullptr);
            if (!applied) {
                result.error = applied.error();
            }
        } catch (const std::exception& exception) {
            result.error = mutation::MutationError{
                .code = mutation::MutationErrorCode::LocalIo,
                .detail =
                    std::string{"content worker failed: "} + exception.what(),
                .path = record.plan.operations[index].path,
                .operation_index = index};
        } catch (...) {
            result.error = mutation::MutationError{
                .code = mutation::MutationErrorCode::LocalIo,
                .detail = "content worker failed",
                .path = record.plan.operations[index].path,
                .operation_index = index};
        }

        {
            std::lock_guard lock(state.mutex);
            state.completions[slot] = std::move(result);
        }
        state.changed.notify_all();
    }
}

std::expected<std::optional<std::pair<std::size_t, mutation::MutationError>>,
              Error>
run_content_window(
    std::span<const std::size_t> indices,
    std::size_t parallelism,
    transaction::Record& record,
    const journal::Paths& paths,
    const std::filesystem::path& local_root,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const platform::Workspace& workspace,
    std::span<const std::optional<mutation::DestinationPrecondition>>
        destinations,
    std::span<const mutation::DownloadCacheMode> cache_modes,
    journal::Session* session,
    ProgressMeter* meter) {
    const auto worker_count = std::min(parallelism, indices.size());
    ContentWindowState state;
    state.tasks.resize(worker_count);
    state.completions.resize(worker_count);
    std::vector<std::jthread> workers;
    try {
        workers.reserve(worker_count);
        for (std::size_t slot = 0; slot < worker_count; ++slot) {
            workers.emplace_back(run_content_worker,
                                 slot,
                                 std::ref(state),
                                 std::cref(record),
                                 std::cref(local_root),
                                 std::ref(storage),
                                 key,
                                 std::cref(workspace));
        }
    } catch (const std::exception& exception) {
        return std::unexpected(detail::make_error(
            ErrorCode::MutationFailure,
            std::string{"failed to start content worker: "} + exception.what(),
            indices.front()));
    }

    std::size_t next = 0;
    std::size_t outstanding = 0;
    const auto admit = [&](std::size_t slot) {
        {
            std::lock_guard lock(state.mutex);
            const auto pos = next++;
            const auto index = indices[pos];
            const auto mode = pos < cache_modes.size()
                                  ? cache_modes[pos]
                                  : mutation::DownloadCacheMode::None;
            state.tasks[slot] = ContentWorkItem{
                index, record.progress[index], destinations[index], mode};
            ++outstanding;
        }
        state.changed.notify_all();
    };
    for (std::size_t slot = 0; slot < worker_count; ++slot) {
        admit(slot);
    }

    std::optional<std::pair<std::size_t, mutation::MutationError>> failure;
    std::optional<Error> checkpoint_failure;
    std::vector<std::pair<std::size_t, ContentWorkResult>> batch;
    batch.reserve(worker_count);
    while (outstanding != 0) {
        batch.clear();
        {
            std::unique_lock lock(state.mutex);
            state.changed.wait(lock, [&] {
                return std::ranges::any_of(state.completions,
                                           [](const auto& item) {
                                               return item.has_value();
                                           });
            });
            for (std::size_t slot = 0; slot < worker_count; ++slot) {
                if (state.completions[slot].has_value()) {
                    batch.emplace_back(slot, std::move(*state.completions[slot]));
                    state.completions[slot].reset();
                }
            }
        }
        outstanding -= batch.size();

        std::size_t applied = 0;
        for (auto& [slot, result] : batch) {
            static_cast<void>(slot);
            if (result.error) {
                if (!failure || result.index < failure->first) {
                    failure = std::pair{result.index, std::move(*result.error)};
                }
            } else {
                record.progress[result.index].state =
                    transaction::OperationState::Applied;
                ++applied;
            }
        }
        if (applied != 0) {
            auto saved = detail::save_record(
                paths, record, key, journal::SaveMode::Advance, session);
            if (!saved && !checkpoint_failure) {
                checkpoint_failure = saved.error();
            } else if (saved && !checkpoint_failure && meter) {
                meter->applied(applied);
            }
        }

        if (!failure && !checkpoint_failure) {
            for (const auto& [slot, result] : batch) {
                static_cast<void>(result);
                if (next < indices.size()) {
                    admit(slot);
                }
            }
        }
    }

    if (checkpoint_failure) {
        return std::unexpected(std::move(*checkpoint_failure));
    }
    return failure;
}

bool same_operation(const kasumi::Operation& left,
                    const kasumi::Operation& right) noexcept {
    return left.action == right.action && left.path == right.path &&
           left.hash == right.hash && left.alt_path == right.alt_path &&
           left.size == right.size &&
           left.exclusive_destination == right.exclusive_destination &&
           left.expected_source_identity == right.expected_source_identity;
}

bool same_plan(const SyncPlan& left, const SyncPlan& right) noexcept {
    if (left.target_generation != right.target_generation ||
        left.offsets != right.offsets ||
        left.operations.size() != right.operations.size()) {
        return false;
    }
    return std::ranges::equal(
        left.operations, right.operations, same_operation);
}

bool is_storage_repair_operation(const reconciliation::Input& input,
                                 const reconciliation::Result& result,
                                 const kasumi::Operation& operation) noexcept {
    if (!result.requires_storage_repair || operation.action != Action::Upload ||
        !input.storage.history_present) {
        return false;
    }
    const auto expected_hash = hash_from_hex(operation.hash);
    const auto row = find_row(input.storage.tree,
                              platform::path::to_logical_utf8(operation.path));
    return expected_hash.has_value() && row != nullptr && !row->is_directory &&
           row->hash == *expected_hash && row->size == operation.size;
}

std::vector<bool> required_content_uploads(const reconciliation::Input& input,
                                           const reconciliation::Result& result,
                                           const SyncPlan& plan) {
    std::unordered_set<std::string> available;
    if (input.storage.history_present) {
        for (const auto& row : input.storage.tree.rows) {
            if (!row.is_directory &&
                !result.missing_objects.contains(row.hash)) {
                available.insert(hash_hex(row.hash) + ':' +
                                 std::to_string(row.size));
            }
        }
    }

    std::vector<bool> required(plan.operations.size(), true);
    for (std::size_t index = 0; index < plan.operations.size(); ++index) {
        const auto& operation = plan.operations[index];
        if (operation.action != Action::Upload) {
            continue;
        }
        auto content_identity =
            operation.hash + ':' + std::to_string(operation.size);
        if (input.verified_remote_content_objects.contains(content_identity) ||
            input.trusted_remote_content_objects.contains(content_identity)) {
            available.insert(std::move(content_identity));
            required[index] = false;
            continue;
        }
        required[index] = available.insert(std::move(content_identity)).second;
    }
    return required;
}

struct PlannedSmallUpload {
    Hash hash{};
    std::uint32_t size = 0;
    std::size_t op_index = 0;
};

struct PlannedPack {
    Hash pack_hash{};
    std::string pack_identifier;
    std::vector<PlannedSmallUpload> blobs;
    std::vector<std::size_t> operation_indices;
};

constexpr std::size_t pack_upload_window_size = std::min(
    detail::upload_batch_max_items,
    static_cast<std::size_t>(detail::upload_batch_max_bytes /
                             crypto::pack::MAXIMUM_PACK_PLAINTEXT_SIZE));

struct PlannedChunkUpload {
    Hash file_hash{};
    std::uint64_t file_size = 0;
    std::size_t primary_op_index = 0;
    std::vector<crypto::pack::FastCdcChunk> chunks;
    std::vector<std::size_t> operation_indices;
};

template <typename Chunk>
std::span<const Chunk> next_chunk_window(std::span<const Chunk> pending) {
    constexpr std::size_t max_items = 64;
    std::size_t count = 0;
    std::uint64_t bytes = 0;
    for (const auto& chunk :
         pending.first(std::min(max_items, pending.size()))) {
        if (count != 0 && bytes + chunk.size > detail::upload_batch_max_bytes) {
            break;
        }
        ++count;
        bytes += chunk.size;
    }
    return pending.first(count);
}

struct UploadLayoutPlan {
    history::StorageManifest target_manifest;
    std::vector<PlannedPack> packs;
    std::vector<PlannedChunkUpload> chunked_uploads;
    std::unordered_map<Hash, std::size_t, decltype(&hash_key)> pack_by_hash{
        0, hash_key};
    std::unordered_map<Hash, std::size_t, decltype(&hash_key)> chunked_by_hash{
        0, hash_key};
};

std::filesystem::path
resolve_pre_mutation_source_path(const std::filesystem::path& local_root,
                                 const kasumi::Operation& operation,
                                 const Hash& expected_hash,
                                 const Snapshot& observed_local_tree,
                                 std::size_t op_index) {
    auto resolved =
        mutation::detail::resolve_local_path(local_root, operation.path, op_index);
    if (resolved) {
        std::error_code ec;
        const auto status = std::filesystem::symlink_status(*resolved, ec);
        if (!ec && !std::filesystem::is_symlink(status) &&
            !platform::private_storage::is_reparse_or_symlink(*resolved) &&
            std::filesystem::is_regular_file(status)) {
            return *resolved;
        }
    }
    for (const auto& row : observed_local_tree.rows) {
        if (!row.is_directory && row.hash == expected_hash &&
            row.size == operation.size) {
            auto candidate = mutation::detail::resolve_local_path(
                local_root, platform::path::from_utf8(row.path), op_index);
            if (candidate) {
                return *candidate;
            }
        }
    }
    return resolved ? *resolved : (local_root / operation.path);
}

using RepairOperations =
    std::unordered_map<Hash, std::vector<std::size_t>, decltype(&hash_key)>;

std::expected<void, Error>
plan_manifest_repairs(UploadLayoutPlan& layout,
                      const history::StorageManifest& manifest,
                      const transaction::Record& record,
                      const RepairOperations& repair_ops_by_hash,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    HashSet handled_packs{0, hash_key};
    std::optional<std::size_t> incomplete_pack;
    for (const auto& [op_hash, indices] : repair_ops_by_hash) {
        if (const auto* chunked =
                history::find_chunked_file(manifest, op_hash)) {
            PlannedChunkUpload upload{
                .file_hash = chunked->file_hash,
                .file_size = chunked->file_size,
                .primary_op_index = indices.front(),
                .chunks = {},
                .operation_indices = indices,
            };
            upload.chunks.reserve(chunked->chunks.size());
            std::uint64_t offset = 0;
            for (const auto& c : chunked->chunks) {
                upload.chunks.push_back(crypto::pack::FastCdcChunk{
                    .hash = c.hash,
                    .offset = offset,
                    .size = c.size,
                });
                offset += c.size;
            }
            layout.chunked_uploads.push_back(std::move(upload));
        } else if (const auto* packed =
                       history::find_packed_blob(manifest, op_hash)) {
            if (!handled_packs.insert(packed->pack_hash).second) {
                continue;
            }
            PlannedPack pack{.pack_hash = packed->pack_hash,
                             .pack_identifier = crypto::pack_identifier(
                                 key, packed->pack_hash),
                             .blobs = {},
                             .operation_indices = {}};
            std::vector<crypto::pack::PackMemberDescriptor> descriptors;
            bool complete = true;
            auto first_pack_operation = indices.front();
            for (const auto& entry : manifest.packed_blobs) {
                if (entry.pack_hash != packed->pack_hash) {
                    continue;
                }
                const auto found = repair_ops_by_hash.find(entry.blob_hash);
                if (found == repair_ops_by_hash.end()) {
                    complete = false;
                    continue;
                }
                const auto op_index = found->second.front();
                first_pack_operation = std::min(first_pack_operation, op_index);
                if (record.plan.operations[op_index].size != entry.size) {
                    complete = false;
                    continue;
                }
                descriptors.push_back(
                    {entry.blob_hash, static_cast<std::uint32_t>(entry.size)});
                pack.blobs.push_back(PlannedSmallUpload{
                    .hash = entry.blob_hash,
                    .size = static_cast<std::uint32_t>(entry.size),
                    .op_index = op_index,
                });
                pack.operation_indices.insert(pack.operation_indices.end(),
                                              found->second.begin(),
                                              found->second.end());
            }
            if (complete && crypto::pack::compute_pack_hash(descriptors) ==
                                packed->pack_hash) {
                std::ranges::sort(pack.operation_indices);
                layout.packs.push_back(std::move(pack));
            } else {
                incomplete_pack =
                    std::min(incomplete_pack.value_or(first_pack_operation),
                             first_pack_operation);
            }
        }
    }
    if (incomplete_pack) {
        return std::unexpected(detail::make_error(
            ErrorCode::MutationFailure,
            "cannot reconstruct the original absent pack from local sources",
            incomplete_pack));
    }
    return {};
}

std::expected<UploadLayoutPlan, Error>
build_upload_layout_plan(const runtime::RuntimeData& runtime_data,
                         const transport::Transport& storage,
                         std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                         const reconciliation::Input& observed_input,
                         const reconciliation::Result& reconciliation_result,
                         const transaction::Record& record,
                         const std::vector<bool>& content_upload_required,
                         bool enable_micro_packs) {
    UploadLayoutPlan layout;

    const auto& observed_manifest = observed_input.storage.storage_manifest;
    const auto& missing = reconciliation_result.missing_objects;
    RepairOperations repair_ops_by_hash{0, hash_key};
    if (!observed_manifest.empty() && !missing.empty()) {
        for (std::size_t index = 0; index < record.plan.operations.size();
             ++index) {
            const auto& op = record.plan.operations[index];
            if (op.action == Action::Upload && content_upload_required[index]) {
                if (const auto h = hash_from_hex(op.hash);
                    h && missing.contains(*h)) {
                    repair_ops_by_hash[*h].push_back(index);
                }
            }
        }
    }

    const auto& ref_tree = record.publication_required
                               ? reconciliation_result.candidate_shared_tree
                               : observed_input.storage.tree;
    std::unordered_map<Hash, std::uint64_t, decltype(&hash_key)> live_files{
        0, hash_key};
    live_files.reserve(ref_tree.rows.size());
    for (const auto& row : ref_tree.rows) {
        if (row.is_directory) {
            continue;
        }
        if (missing.contains(row.hash)) {
            if (record.publication_required &&
                history::find_packed_blob(observed_manifest, row.hash) &&
                !repair_ops_by_hash.contains(row.hash)) {
                return std::unexpected(detail::make_error(
                    ErrorCode::MutationFailure,
                    "cannot replace an absent pack without a local source for " +
                        row.path));
            }
        } else if (row.path != ".kasumiignore") {
            live_files.emplace(row.hash, row.size);
        }
    }

    for (const auto& entry : observed_input.storage.storage_manifest.packed_blobs) {
        const auto found = live_files.find(entry.blob_hash);
        if (found != live_files.end() && found->second == entry.size) {
            layout.target_manifest.packed_blobs.push_back(entry);
        }
    }
    for (const auto& entry :
         observed_input.storage.storage_manifest.chunked_files) {
        const auto found = live_files.find(entry.file_hash);
        if (found != live_files.end() && found->second == entry.file_size) {
            layout.target_manifest.chunked_files.push_back(entry);
        }
    }

    if (record.publication_required && enable_micro_packs) {
        std::vector<PlannedSmallUpload> small_candidates;
        HashSet seen_upload{0, hash_key};
        for (std::size_t index = 0; index < record.plan.operations.size();
             ++index) {
            const auto& op = record.plan.operations[index];
            if (op.action != Action::Upload || !content_upload_required[index] ||
                platform::path::to_logical_utf8(op.path) == ".kasumiignore") {
                continue;
            }
            const auto op_hash = hash_from_hex(op.hash);
            if (!op_hash || !seen_upload.insert(*op_hash).second) {
                continue;
            }
            if (history::find_packed_blob(layout.target_manifest, *op_hash) ||
                history::find_chunked_file(layout.target_manifest, *op_hash)) {
                continue;
            }

            if (op.size > crypto::pack::FASTCDC_FILE_THRESHOLD) {
                layout.chunked_uploads.push_back(PlannedChunkUpload{
                    .file_hash = *op_hash,
                    .file_size = op.size,
                    .primary_op_index = index,
                    .chunks = {},
                    .operation_indices = {index},
                });
            } else if (op.size <= crypto::pack::MAX_MICRO_PACK_BLOB_SIZE) {
                small_candidates.push_back(PlannedSmallUpload{
                    .hash = *op_hash,
                    .size = static_cast<std::uint32_t>(op.size),
                    .op_index = index,
                });
            }
        }

        auto& chunked = layout.chunked_uploads;
        if (!chunked.empty()) {
            std::vector<std::optional<Error>> errors(chunked.size());
            const auto started = platform::perf_trace::begin();
            application::parallel_for_indexed(
                chunked.size(),
                application::content_concurrency(),
                [&](std::size_t slot) {
                    auto& job = chunked[slot];
                    const auto index = job.primary_op_index;
                    const auto src = resolve_pre_mutation_source_path(
                        runtime_data.local_dir,
                        record.plan.operations[index],
                        job.file_hash,
                        observed_input.local_tree,
                        index);
                    auto cdc = crypto::pack::chunk_file_fastcdc(
                        src,
                        crypto::pack::fastcdc_profile_for_size(job.file_size));
                    if (!cdc) {
                        errors[slot] = detail::make_error(
                            ErrorCode::ConcurrentModification,
                            "failed to chunk upload source: " + cdc.error(),
                            index);
                    } else if (cdc->file_hash != job.file_hash ||
                               cdc->file_size != job.file_size ||
                               cdc->chunks.empty() ||
                               cdc->chunks.size() >
                                   history::maximum_chunks_per_file) {
                        errors[slot] = detail::make_error(
                            ErrorCode::ConcurrentModification,
                            "large upload source changed before publication",
                            index);
                    } else {
                        job.chunks = std::move(cdc->chunks);
                    }
                });
            platform::perf_trace::finish("sync/fastcdc-layout", started);

            for (std::size_t slot = 0; slot < chunked.size(); ++slot) {
                if (errors[slot]) {
                    return std::unexpected(std::move(*errors[slot]));
                }
                const auto& job = chunked[slot];
                history::ChunkedFileEntry entry{.file_hash = job.file_hash,
                                                .file_size = job.file_size,
                                                .chunks = {}};
                entry.chunks.reserve(job.chunks.size());
                for (const auto& chunk : job.chunks) {
                    entry.chunks.push_back(
                        {.hash = chunk.hash, .size = chunk.size});
                }
                layout.target_manifest.chunked_files.push_back(
                    std::move(entry));
            }
        }

        std::ranges::sort(small_candidates, {}, &PlannedSmallUpload::hash);
        const std::size_t min_pack_blobs =
            (storage.storage.physical_hash_batch != nullptr) ? 2U : 16U;
        if (small_candidates.size() >= min_pack_blobs) {
            std::size_t cursor = 0;
            while (cursor < small_candidates.size()) {
                std::uint64_t bin_bytes = 0;
                std::size_t end = cursor;
                while (end < small_candidates.size() &&
                       (end - cursor) < crypto::pack::MAXIMUM_PACK_MEMBERS &&
                       (end == cursor ||
                        bin_bytes + small_candidates[end].size <=
                            crypto::pack::TARGET_MICRO_PACK_SIZE)) {
                    bin_bytes += small_candidates[end].size;
                    ++end;
                }
                if (end - cursor >= 2) {
                    std::vector<crypto::pack::PackMemberDescriptor> descriptors;
                    descriptors.reserve(end - cursor);
                    PlannedPack pack;
                    pack.blobs.reserve(end - cursor);
                    pack.operation_indices.reserve(end - cursor);
                    for (std::size_t k = cursor; k < end; ++k) {
                        descriptors.push_back(
                            crypto::pack::PackMemberDescriptor{
                                .hash = small_candidates[k].hash,
                                .size = small_candidates[k].size,
                            });
                        pack.blobs.push_back(small_candidates[k]);
                        pack.operation_indices.push_back(
                            small_candidates[k].op_index);
                    }
                    std::ranges::sort(pack.operation_indices);
                    if (const auto pack_hash =
                            crypto::pack::compute_pack_hash(descriptors)) {
                        pack.pack_hash = *pack_hash;
                        pack.pack_identifier =
                            crypto::pack_identifier(key, *pack_hash);
                        for (const auto& d : descriptors) {
                            layout.target_manifest.packed_blobs.push_back(
                                history::PackedBlobEntry{
                                    .blob_hash = d.hash,
                                    .size = d.size,
                                    .pack_hash = *pack_hash,
                                });
                        }
                        layout.packs.push_back(std::move(pack));
                    }
                }
                cursor = end;
            }
        }
    } else if (!record.publication_required &&
               reconciliation_result.requires_storage_repair &&
               !observed_input.storage.storage_manifest.empty()) {
        if (auto planned = plan_manifest_repairs(
                layout, observed_manifest, record, repair_ops_by_hash, key);
            !planned) {
            return std::unexpected(planned.error());
        }
    }

    std::ranges::sort(
        layout.target_manifest.packed_blobs, {}, &history::PackedBlobEntry::blob_hash);
    std::ranges::sort(layout.target_manifest.chunked_files,
                      {},
                      &history::ChunkedFileEntry::file_hash);

    for (std::size_t i = 0; i < layout.packs.size(); ++i) {
        for (const auto op_idx : layout.packs[i].operation_indices) {
            if (const auto h =
                    hash_from_hex(record.plan.operations[op_idx].hash)) {
                layout.pack_by_hash.emplace(*h, i);
            }
        }
    }
    for (std::size_t i = 0; i < layout.chunked_uploads.size(); ++i) {
        layout.chunked_by_hash.emplace(layout.chunked_uploads[i].file_hash, i);
    }
    return layout;
}

std::expected<void, detail::UploadBatchError>
execute_packed_upload_batch(std::span<const PlannedPack* const> packs,
                            const transaction::Record& record,
                            const std::filesystem::path& local_root,
                            transport::Transport& storage,
                            std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                            const platform::Workspace& workspace,
                            std::size_t parallelism,
                            ProgressMeter* meter) {
    if (packs.empty()) {
        return {};
    }
    if (meter)
        meter->phase(Activity::Staging, packs.size());
    const auto first_op = packs.front()->operation_indices.front();
    auto staging = platform::create_workspace("pack-upload-batch");
    if (!staging) {
        return std::unexpected(detail::UploadBatchError{
            .transport_after_unknown_transfer = false,
            .mutation = mutation::MutationError{
                .code = mutation::MutationErrorCode::LocalIo,
                .detail = staging.error(),
                .path = local_root,
                .operation_index = first_op,
            }});
    }
    mutation::StagedUploadBatch batch;
    batch.root = staging->root;
    batch.objects.resize(packs.size());
    detail::ScopedUploadBatchCleanup cleanup{batch};

    std::vector<std::optional<mutation::MutationError>> stage_errors(
        packs.size());
    application::parallel_for_indexed(
        packs.size(),
        std::min<std::size_t>(parallelism, packs.size()),
        [&](std::size_t i) {
            const auto& pack = *packs[i];
            std::vector<crypto::pack::PackMemberSource> sources;
            sources.reserve(pack.blobs.size());
            for (const auto& blob : pack.blobs) {
                auto resolved = mutation::detail::resolve_local_path(
                    local_root,
                    record.plan.operations[blob.op_index].path,
                    blob.op_index);
                if (!resolved) {
                    stage_errors[i] = resolved.error();
                    return;
                }
                sources.push_back(crypto::pack::PackMemberSource{
                    .hash = blob.hash,
                    .size = blob.size,
                    .source_path = std::move(*resolved),
                });
            }
            const auto dest = batch.root / pack.pack_identifier;
            auto res =
                crypto::pack::write_encrypted_pack(sources, dest, key);
            if (!res || res->pack_hash != pack.pack_hash) {
                stage_errors[i] = mutation::MutationError{
                    .code = mutation::MutationErrorCode::IntegrityMismatch,
                    .detail = res ? "staged pack identifier mismatch" : res.error(),
                    .path = local_root,
                    .operation_index = pack.operation_indices.front(),
                };
                return;
            }
            if (meter) {
                meter->record_staged(dest, res->pack_plaintext_size);
            }
            batch.objects[i] = mutation::StagedUploadObject{
                .identifier = pack.pack_identifier,
                .plaintext_hash = hash_hex(res->pack_hash),
                .plaintext_size = res->pack_plaintext_size,
                .ciphertext_sha256 = std::move(res->ciphertext_sha256),
                .operation_indices = pack.operation_indices,
                .is_pack = true,
            };
        });

    std::optional<mutation::MutationError> lowest_err;
    for (const auto& err : stage_errors) {
        if (err &&
            (!lowest_err || err->operation_index < lowest_err->operation_index)) {
            lowest_err = *err;
        }
    }
    if (lowest_err) {
        return std::unexpected(detail::UploadBatchError{
            .transport_after_unknown_transfer = false,
            .mutation = std::move(*lowest_err),
        });
    }

    auto transferred = detail::transfer_and_verify_upload_batch(
        batch, storage, key, workspace, parallelism, meter);
    if (!transferred) {
        if (!transferred.error().transport_after_unknown_transfer) {
            return transferred;
        }
        cleanup.dismissed = true;
        static_cast<void>(mutation::cleanup_upload_batch(batch));
        return transferred;
    }
    cleanup.dismissed = true;
    static_cast<void>(mutation::cleanup_upload_batch(batch));
    return {};
}

std::expected<void, detail::UploadBatchError> execute_chunked_upload_batch(
    std::span<const PlannedChunkUpload* const> uploads,
    const transaction::Record& record,
    const history::StorageManifest& live_manifest,
    const HashSet& missing_files,
    const HashSet& invalid_chunks,
    const std::filesystem::path& local_root,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const platform::Workspace& workspace,
    std::size_t parallelism,
    ProgressMeter* meter) {
    if (uploads.empty()) {
        return {};
    }

    HashSet known_live_chunks{0, hash_key};
    for (const auto& entry : live_manifest.chunked_files) {
        if (!missing_files.contains(entry.file_hash)) {
            for (const auto& c : entry.chunks) {
                if (!invalid_chunks.contains(c.hash)) {
                    known_live_chunks.insert(c.hash);
                }
            }
        }
    }

    struct PendingChunkWork {
        Hash chunk_hash{};
        std::string chunk_id;
        std::string chunk_hex;
        std::uint64_t offset = 0;
        std::uint32_t size = 0;
        std::filesystem::path source_path;
        std::size_t operation_index = 0;
    };

    std::vector<PendingChunkWork> unique_chunks;
    HashSet seen_chunks{0, hash_key};
    std::vector<std::string> candidate_present_ids;

    for (const auto* upload : uploads) {
        const auto op_idx = upload->primary_op_index;
        auto resolved = mutation::detail::resolve_local_path(
            local_root, record.plan.operations[op_idx].path, op_idx);
        if (!resolved) {
            return std::unexpected(detail::UploadBatchError{
                .transport_after_unknown_transfer = false,
                .mutation = resolved.error(),
            });
        }
        for (const auto& chunk : upload->chunks) {
            if (!seen_chunks.insert(chunk.hash).second) {
                continue;
            }
            auto id = crypto::content_identifier(key, chunk.hash);
            candidate_present_ids.push_back(id);
            unique_chunks.push_back(PendingChunkWork{
                .chunk_hash = chunk.hash,
                .chunk_id = std::move(id),
                .chunk_hex = hash_hex(chunk.hash),
                .offset = chunk.offset,
                .size = chunk.size,
                .source_path = *resolved,
                .operation_index = op_idx,
            });
        }
    }

    std::unordered_set<std::string> present_chunk_ids;
    if (!candidate_present_ids.empty()) {
        std::ranges::sort(candidate_present_ids);
        candidate_present_ids.erase(
            std::ranges::unique(candidate_present_ids).begin(),
            candidate_present_ids.end());
        bool probed = false;
        if (candidate_present_ids.size() >= 8U &&
            storage.storage.list != nullptr) {
            if (auto listed = transport::list(storage)) {
                const std::unordered_set<std::string> remote_set(
                    listed->begin(), listed->end());
                for (const auto& id : candidate_present_ids) {
                    if (remote_set.contains(id)) {
                        present_chunk_ids.insert(id);
                    }
                }
                probed = true;
            }
        }
        if (!probed && storage.storage.control_read_batch != nullptr) {
            transport::ControlReadBatchRequest req;
            req.presence_identifiers = candidate_present_ids;
            auto batch = transport::control_read_batch(storage, req);
            if (batch &&
                batch->presences.size() == candidate_present_ids.size()) {
                for (std::size_t i = 0; i < candidate_present_ids.size(); ++i) {
                    if (batch->presences[i] == transport::Presence::Present) {
                        present_chunk_ids.insert(candidate_present_ids[i]);
                    }
                }
                probed = true;
            }
        }
        if (!probed && storage.storage.presence != nullptr) {
            for (const auto& cid : candidate_present_ids) {
                if (auto res = transport::presence(storage, cid);
                    res && *res == transport::Presence::Present) {
                    present_chunk_ids.insert(cid);
                }
            }
        }
    }

    {
        std::vector<const PendingChunkWork*> orphan_candidates;
        for (const auto& chunk : unique_chunks) {
            if (present_chunk_ids.contains(chunk.chunk_id) &&
                !known_live_chunks.contains(chunk.chunk_hash)) {
                orphan_candidates.push_back(&chunk);
            }
        }
        if (!orphan_candidates.empty()) {
            if (meter)
                meter->phase(Activity::Verifying, orphan_candidates.size());
            std::vector<std::uint8_t> verified(orphan_candidates.size());
            application::parallel_for_indexed(
                orphan_candidates.size(), parallelism, [&](std::size_t i) {
                    const auto& chunk = *orphan_candidates[i];
                    const auto audit =
                        history_storage::audit_content_object(storage,
                                                              key,
                                                              chunk.chunk_id,
                                                              chunk.chunk_hex,
                                                              chunk.size,
                                                              workspace.root,
                                                              i);
                    if (audit &&
                        audit->state ==
                            history_storage::ContentObjectState::Present) {
                        verified[i] = 1;
                    }
                    if (meter)
                        ProgressMeter::add(meter->work);
                });
            for (std::size_t i = 0; i < orphan_candidates.size(); ++i) {
                if (!verified[i]) {
                    present_chunk_ids.erase(orphan_candidates[i]->chunk_id);
                }
            }
        }
    }

    std::vector<PendingChunkWork> to_upload;
    to_upload.reserve(unique_chunks.size());
    for (auto& chunk : unique_chunks) {
        if (!present_chunk_ids.contains(chunk.chunk_id)) {
            to_upload.push_back(std::move(chunk));
        } else if (meter) {
            ProgressMeter::add(meter->bytes_reused, chunk.size);
        }
    }
    if (to_upload.empty()) {
        return {};
    }

    for (std::span<const PendingChunkWork> pending{to_upload};
         !pending.empty();) {
        const auto window = next_chunk_window(pending);
        pending = pending.subspan(window.size());
        const auto first_op = window.front().operation_index;
        if (platform::cancellation::requested()) {
            return std::unexpected(detail::UploadBatchError{
                .transport_after_unknown_transfer = false,
                .mutation = mutation::detail::make_error(
                    mutation::MutationErrorCode::TransportFailure,
                    "FastCDC upload cancelled",
                    local_root,
                    first_op),
            });
        }
        if (meter)
            meter->phase(Activity::Staging, window.size());
        auto staging = platform::create_workspace("chunk-upload-batch");
        if (!staging) {
            return std::unexpected(detail::UploadBatchError{
                .transport_after_unknown_transfer = false,
                .mutation = mutation::MutationError{
                    .code = mutation::MutationErrorCode::LocalIo,
                    .detail = staging.error(),
                    .path = local_root,
                    .operation_index = first_op,
                }});
        }

        mutation::StagedUploadBatch batch;
        batch.root = staging->root;
        batch.objects.resize(window.size());
        detail::ScopedUploadBatchCleanup cleanup{batch};

        std::vector<std::optional<mutation::MutationError>> stage_errors(
            window.size());
        application::parallel_for_indexed(
            window.size(),
            std::min<std::size_t>(parallelism, window.size()),
            [&](std::size_t i) {
                const auto& chunk = window[i];
                std::string detail_err;
                const auto dest = batch.root / chunk.chunk_id;
                auto enc = crypto::pack::encrypt_file_slice_with_hashes(
                    chunk.source_path,
                    chunk.offset,
                    chunk.size,
                    chunk.chunk_hash,
                    dest,
                    key,
                    &detail_err);
                if (!enc) {
                    stage_errors[i] = mutation::MutationError{
                        .code = mutation::MutationErrorCode::IntegrityMismatch,
                        .detail =
                            detail_err.empty()
                                ? "failed to encrypt FastCDC chunk slice"
                                : std::move(detail_err),
                        .path = chunk.source_path,
                        .operation_index = chunk.operation_index,
                    };
                    return;
                }
                if (meter) {
                    meter->record_staged(dest, chunk.size);
                }
                batch.objects[i] = mutation::StagedUploadObject{
                    .identifier = chunk.chunk_id,
                    .plaintext_hash = chunk.chunk_hex,
                    .plaintext_size = chunk.size,
                    .ciphertext_sha256 = std::move(enc->ciphertext_sha256),
                    .operation_indices = {chunk.operation_index},
                    .is_pack = false,
                };
            });

        std::optional<mutation::MutationError> lowest_err;
        for (const auto& err : stage_errors) {
            if (err &&
                (!lowest_err ||
                 err->operation_index < lowest_err->operation_index)) {
                lowest_err = *err;
            }
        }
        if (lowest_err) {
            return std::unexpected(detail::UploadBatchError{
                .transport_after_unknown_transfer = false,
                .mutation = std::move(*lowest_err),
            });
        }

        const auto* item =
            uploads.size() == 1 &&
                    uploads.front()->operation_indices.size() == 1 &&
                    window.size() == to_upload.size()
                ? &record.plan.operations[first_op].path
                : nullptr;
        auto transferred = detail::transfer_and_verify_upload_batch(
            batch, storage, key, workspace, parallelism, meter, item);
        if (!transferred) {
            if (!transferred.error().transport_after_unknown_transfer) {
                return transferred;
            }
            cleanup.dismissed = true;
            static_cast<void>(mutation::cleanup_upload_batch(batch));
            return transferred;
        }
        cleanup.dismissed = true;
        static_cast<void>(mutation::cleanup_upload_batch(batch));
    }
    return {};
}

} // namespace

std::expected<void, Error> detail::resume_manifest_repairs(
    const journal::Paths& paths,
    transaction::Record& record,
    const history::StorageManifest& manifest,
    const std::filesystem::path& local_root,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const platform::Workspace& workspace) {
    if (manifest.empty()) {
        return {};
    }

    RepairOperations repairs{0, hash_key};
    for (std::size_t index = 0; index < record.plan.operations.size();
         ++index) {
        const auto& operation = record.plan.operations[index];
        if (operation.action == Action::Upload) {
            if (const auto hash = hash_from_hex(operation.hash);
                hash && (history::find_packed_blob(manifest, *hash) ||
                         history::find_chunked_file(manifest, *hash))) {
                repairs[*hash].push_back(index);
            }
        }
    }
    if (repairs.empty()) {
        return {};
    }

    UploadLayoutPlan pending;
    if (auto planned =
            plan_manifest_repairs(pending, manifest, record, repairs, key);
        !planned) {
        return planned;
    }
    std::vector<const PlannedPack*> packs;
    for (const auto& pack : pending.packs) {
        const auto verified =
            verify_existing_content(storage,
                                    key,
                                    pack.pack_identifier,
                                    hash_hex(pack.pack_hash),
                                    std::nullopt,
                                    workspace,
                                    pack.operation_indices.front(),
                                    true);
        if (!verified) {
            return std::unexpected(verified.error());
        }
        if (!*verified) {
            packs.push_back(&pack);
        }
    }
    const auto parallelism = application::content_concurrency();
    for (std::span<const PlannedPack* const> remaining{packs};
         !remaining.empty();) {
        const auto window = remaining.first(
            std::min(remaining.size(), pack_upload_window_size));
        if (auto result = execute_packed_upload_batch(window,
                                                      record,
                                                      local_root,
                                                      storage,
                                                      key,
                                                      workspace,
                                                      parallelism,
                                                      nullptr);
            !result) {
            return std::unexpected(mutation_error(result.error().mutation));
        }
        for (const auto* pack : window) {
            for (const auto index : pack->operation_indices) {
                record.progress[index].state =
                    transaction::OperationState::Applied;
            }
        }
        if (auto checkpoint = save_record(paths, record, key); !checkpoint) {
            return checkpoint;
        }
        remaining = remaining.subspan(window.size());
    }

    std::vector<const PlannedChunkUpload*> chunks;
    for (const auto& upload : pending.chunked_uploads) {
        chunks.push_back(&upload);
    }
    const HashSet none{0, hash_key};
    // A repair checkpoint may have been written by a client that used loose
    // objects.
    if (auto result = execute_chunked_upload_batch(chunks,
                                                   record,
                                                   history::StorageManifest{},
                                                   none,
                                                   none,
                                                   local_root,
                                                   storage,
                                                   key,
                                                   workspace,
                                                   parallelism,
                                                   nullptr);
        !result) {
        return std::unexpected(mutation_error(result.error().mutation));
    }

    for (const auto& [hash, indices] : repairs) {
        for (const auto index : indices) {
            record.progress[index].state = transaction::OperationState::Applied;
        }
    }
    return save_record(paths, record, key);
}

namespace {

bool batch_fetch_objects(transport::Transport& storage,
                         const std::filesystem::path& dir,
                         const std::vector<std::string>& ids,
                         std::size_t transfers = 0) {
    if (ids.size() >= 2 && storage.storage.get_batch != nullptr) {
        transport::GetBatch req;
        req.destination_root = dir;
        req.identifiers = ids;
        req.max_parallel_transfers = transfers;
        if (transport::get_batch(storage, req)) {
            return true;
        }
    }
    return false;
}

bool seed_source_matches(const detail::ChunkSource& seed,
                         std::uint32_t expected_size) noexcept {
    namespace ps = platform::private_storage;
    return seed.size == expected_size &&
           !ps::is_reparse_or_symlink(seed.source_path) &&
           ps::query_file_identity(seed.source_path) == seed.identity;
}

void maybe_seed_local_fastcdc_source(const history::ChunkedFileEntry& entry,
                                     const std::filesystem::path& cand,
                                     detail::ChunkDownloadSession& session) {
    namespace ps = platform::private_storage;
    const auto key_path = platform::path::to_utf8(cand);
    if (key_path.empty() || session.seeded_paths.contains(key_path)) {
        return;
    }
    std::error_code ec;
    const auto st = std::filesystem::symlink_status(cand, ec);
    if (ec || std::filesystem::is_symlink(st) ||
        !std::filesystem::is_regular_file(st) ||
        ps::is_reparse_or_symlink(cand)) {
        return;
    }
    const auto fsize = std::filesystem::file_size(cand, ec);
    if (ec || fsize < crypto::pack::FASTCDC_MIN_CHUNK) {
        return;
    }
    const auto id = ps::query_file_identity(cand);
    if (!id.valid) {
        return;
    }
    session.seeded_paths.insert(key_path);
    auto cdc = crypto::pack::chunk_file_fastcdc(
        cand, crypto::pack::fastcdc_profile_for_size(entry.file_size));
    if (!cdc) {
        return;
    }
    const auto post_id = ps::query_file_identity(cand);
    if (!post_id.valid || !(post_id == id)) {
        return;
    }
    for (const auto& sc : cdc->chunks) {
        session.local_seeds.try_emplace(sc.hash,
                                        detail::ChunkSource{
                                            .source_path = cand,
                                            .identity = id,
                                            .offset = sc.offset,
                                            .size = sc.size,
                                        });
    }
}

template <typename AppendFn>
bool stream_verified_seed_slice(const detail::ChunkSource& seed,
                                const history::ChunkSlice& chunk,
                                std::vector<std::uint8_t>& copy_buf,
                                AppendFn&& append) {
    namespace ps = platform::private_storage;
    if (!seed_source_matches(seed, chunk.size)) {
        return false;
    }
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    crypto::secure_memory::WipeGuard wipe_hasher{hasher};
    const auto streamed = ps::stream_regular_file(
        seed.source_path,
        copy_buf,
        [&](std::span<const std::uint8_t> slab) {
            blake3_hasher_update(&hasher, slab.data(), slab.size());
            return append(slab);
        },
        std::nullopt,
        ps::FileSlice{seed.offset, seed.size});
    if (!seed_source_matches(seed, chunk.size) || !streamed) {
        return false;
    }
    Hash digest{};
    blake3_hasher_finalize(&hasher,
                           reinterpret_cast<std::uint8_t*>(digest.data()),
                           digest.size());
    return digest == chunk.hash;
}

} // namespace

mutation::MutationResult detail::apply_chunked_download(
    const history::ChunkedFileEntry& entry,
    const kasumi::Operation& operation,
    std::size_t operation_index,
    const std::filesystem::path& local_root,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const platform::Workspace& workspace,
    std::size_t parallelism,
    const transaction::OperationProgress& progress,
    const mutation::DestinationPrecondition* destination_condition,
    ChunkDownloadSession& session,
    ProgressMeter* meter) {
    namespace ps = platform::private_storage;
    if (!session.directories_ready) {
        session.chunk_dl_dir = workspace.root / "chunk-dl";
        if (auto ok = ps::ensure_directory(session.chunk_dl_dir); !ok) {
            return std::unexpected(mutation::detail::make_error(
                mutation::MutationErrorCode::LocalIo,
                ok.error(),
                session.chunk_dl_dir,
                operation_index));
        }
        session.directories_ready = true;
    }

    struct InstalledSlice {
        Hash hash{};
        std::uint64_t offset = 0;
        std::uint32_t size = 0;
    };
    std::vector<InstalledSlice> installed_slices;
    installed_slices.reserve(entry.chunks.size());
    std::optional<std::filesystem::path> resolved_destination;

    auto installed = mutation::apply_streamed_download(
        operation,
        operation_index,
        local_root,
        workspace,
        progress,
        destination_condition,
        [&](const std::filesystem::path& candidate_path,
            const std::filesystem::path& destination_path,
            const std::filesystem::path* backup_path)
            -> mutation::MutationResult {
            resolved_destination = destination_path;
            const auto fail = [&](mutation::MutationErrorCode code,
                                  std::string reason) {
                return std::unexpected(mutation::detail::make_error(
                    code, std::move(reason), candidate_path, operation_index));
            };

            if (backup_path != nullptr && !backup_path->empty()) {
                maybe_seed_local_fastcdc_source(entry, *backup_path, session);
            }
            maybe_seed_local_fastcdc_source(entry, destination_path, session);

            auto private_out = ps::create_private_file(candidate_path);
            if (!private_out) {
                return fail(mutation::MutationErrorCode::LocalIo,
                            "failed to create staged FastCDC download file: " +
                                private_out.error().message);
            }
            struct OutputCleanup {
                ps::PrivateOutputFile* file = nullptr;
                bool dismissed = false;
                ~OutputCleanup() noexcept {
                    if (!dismissed && file != nullptr) {
                        static_cast<void>(
                            ps::remove_private_file_if_owned(*file));
                    }
                }
            } out_cleanup{&*private_out, false};

            std::vector<std::uint8_t> copy_buf(256U * 1024U);
            crypto::secure_memory::WipeGuard wipe_buffer{copy_buf};
            blake3_hasher file_hash;
            blake3_hasher_init(&file_hash);
            crypto::secure_memory::WipeGuard wipe_hash{file_hash};
            bool write_failed = false;
            auto append = [&](std::span<const std::uint8_t> slab) {
                if (!ps::write_private_file(
                        *private_out, slab.data(), slab.size())) {
                    write_failed = true;
                    return false;
                }
                blake3_hasher_update(&file_hash, slab.data(), slab.size());
                return true;
            };

            std::unordered_map<Hash,
                               std::pair<std::uint64_t, std::uint32_t>,
                               ChunkHashKey>
                current_file_slices;
            std::uint64_t offset = 0;
            for (std::span<const history::ChunkSlice> pending{entry.chunks};
                 !pending.empty();) {
                const auto window = next_chunk_window(pending);
                pending = pending.subspan(window.size());
                if (platform::cancellation::requested()) {
                    return fail(mutation::MutationErrorCode::TransportFailure,
                                "FastCDC download cancelled");
                }

                HashSet scheduled{0, hash_key};
                std::vector<const history::ChunkSlice*> fetch;
                std::vector<std::string> ids;
                for (const auto& chunk : window) {
                    if (current_file_slices.contains(chunk.hash)) {
                        continue;
                    }
                    if (const auto local_it =
                            session.local_seeds.find(chunk.hash);
                        local_it != session.local_seeds.end()) {
                        if (seed_source_matches(local_it->second, chunk.size)) {
                            continue;
                        }
                        session.local_seeds.erase(local_it);
                    }
                    if (const auto prior_it =
                            session.downloaded_slices.find(chunk.hash);
                        prior_it != session.downloaded_slices.end()) {
                        if (seed_source_matches(prior_it->second, chunk.size)) {
                            continue;
                        }
                        session.downloaded_slices.erase(prior_it);
                    }
                    if (scheduled.insert(chunk.hash).second) {
                        fetch.push_back(&chunk);
                        ids.push_back(
                            crypto::content_identifier(key, chunk.hash));
                    }
                }

                struct WindowDlCleanup {
                    const std::filesystem::path& dir;
                    const std::vector<std::string>& ids;
                    ~WindowDlCleanup() noexcept {
                        std::error_code ignored;
                        for (const auto& id : ids) {
                            std::filesystem::remove(dir / id, ignored);
                        }
                    }
                } dl_cleanup{session.chunk_dl_dir, ids};

                if (!fetch.empty()) {
                    if (meter)
                        meter->phase(
                            Activity::Downloading,
                            fetch.size(),
                            0,
                            window.size() == entry.chunks.size()
                                ? &operation.path
                                : nullptr);
                    batch_fetch_objects(
                        storage, session.chunk_dl_dir, ids, parallelism);
                    if (platform::cancellation::requested()) {
                        return fail(
                            mutation::MutationErrorCode::TransportFailure,
                            "FastCDC download cancelled");
                    }

                    std::vector<std::optional<mutation::MutationError>> errors(
                        fetch.size());
                    application::parallel_for_indexed(
                        fetch.size(), parallelism, [&](std::size_t i) {
                            const auto enc = session.chunk_dl_dir / ids[i];
                            std::error_code status_error;
                            const auto status = std::filesystem::symlink_status(
                                enc, status_error);
                            const bool absent =
                                status_error ==
                                    std::errc::no_such_file_or_directory ||
                                (!status_error &&
                                 status.type() ==
                                     std::filesystem::file_type::not_found);
                            if (absent) {
                                auto fetched =
                                    transport::get(storage, ids[i], enc);
                                if (!fetched) {
                                    errors[i] = mutation::detail::make_error(
                                        fetched.error().code ==
                                                transport::ErrorCode::
                                                    ObjectNotFound
                                            ? mutation::MutationErrorCode::
                                                  RemoteContentMissing
                                            : mutation::MutationErrorCode::
                                                  TransportFailure,
                                        transport::describe(fetched.error()),
                                        operation.path,
                                        operation_index);
                                    return;
                                }
                            } else if (status_error ||
                                       !std::filesystem::is_regular_file(
                                           status) ||
                                       ps::is_reparse_or_symlink(enc)) {
                                errors[i] = mutation::detail::make_error(
                                    mutation::MutationErrorCode::LocalIo,
                                    status_error
                                        ? status_error.message()
                                        : "downloaded chunk is not a regular "
                                          "file",
                                    enc,
                                    operation_index);
                                return;
                            }
                        });
                    for (auto& error : errors) {
                        if (error) {
                            return std::unexpected(std::move(*error));
                        }
                    }
                }

                if (meter)
                    meter->phase(Activity::Installing, window.size());
                mutation_fault_test::hit("fastcdc_chunks_ready",
                                         session.chunk_dl_dir);
                for (const auto& chunk : window) {
                    if (const auto local_it =
                            session.local_seeds.find(chunk.hash);
                        local_it != session.local_seeds.end()) {
                        if (!stream_verified_seed_slice(
                                local_it->second, chunk, copy_buf, append)) {
                            return fail(
                                mutation::MutationErrorCode::IntegrityMismatch,
                                "local FastCDC seed changed or could not be "
                                "staged");
                        }
                        if (meter)
                            ProgressMeter::add(meter->bytes_reused, chunk.size);
                    } else if (const auto cur_it =
                                   current_file_slices.find(chunk.hash);
                               cur_it != current_file_slices.end()) {
                        const ChunkSource intra{
                            .source_path = candidate_path,
                            .identity = private_out->identity,
                            .offset = cur_it->second.first,
                            .size = cur_it->second.second,
                        };
                        if (!stream_verified_seed_slice(
                                intra, chunk, copy_buf, append)) {
                            return fail(
                                mutation::MutationErrorCode::IntegrityMismatch,
                                "previously staged FastCDC chunk changed");
                        }
                    } else if (const auto prior_it =
                                   session.downloaded_slices.find(chunk.hash);
                               prior_it != session.downloaded_slices.end()) {
                        if (!stream_verified_seed_slice(
                                prior_it->second, chunk, copy_buf, append)) {
                            return fail(
                                mutation::MutationErrorCode::IntegrityMismatch,
                                "previously staged FastCDC chunk changed");
                        }
                    } else {
                        const auto enc = session.chunk_dl_dir /
                                         crypto::content_identifier(
                                             key, chunk.hash);
                        write_failed = false;
                        const bool decrypted = crypto::decrypt_file_to_sink(
                            enc,
                            key,
                            append,
                            crypto::FilePurpose::Content,
                            chunk.size,
                            &chunk.hash);
                        std::error_code ec;
                        std::filesystem::remove(enc, ec);
                        if (!decrypted) {
                            return fail(
                                write_failed
                                    ? mutation::MutationErrorCode::LocalIo
                                    : mutation::MutationErrorCode::
                                          CryptoFailure,
                                write_failed
                                    ? "failed to write FastCDC chunk to "
                                      "destination"
                                    : "FastCDC chunk failed authentication");
                        }
                        if (ec) {
                            return fail(
                                mutation::MutationErrorCode::LocalIo,
                                "failed to remove encrypted FastCDC chunk: " +
                                    ec.message());
                        }
                    }
                    current_file_slices.try_emplace(
                        chunk.hash, offset, chunk.size);
                    installed_slices.push_back(InstalledSlice{
                        .hash = chunk.hash,
                        .offset = offset,
                        .size = chunk.size,
                    });
                    offset += chunk.size;
                    if (meter)
                        ProgressMeter::add(meter->work);
                }
            }

            ps::close_private_file(*private_out);
            out_cleanup.dismissed = true;
            Hash digest{};
            blake3_hasher_finalize(
                &file_hash,
                reinterpret_cast<std::uint8_t*>(digest.data()),
                digest.size());
            if (offset != entry.file_size || digest != entry.file_hash) {
                return fail(mutation::MutationErrorCode::IntegrityMismatch,
                            "reassembled FastCDC file failed verification");
            }
            mutation_fault_test::hit("fastcdc_file_ready", candidate_path);
            return {};
        });
    if (!installed) {
        return installed;
    }
    if (resolved_destination) {
        const auto installed_id =
            ps::query_file_identity(*resolved_destination);
        if (installed_id.valid) {
            for (const auto& slice : installed_slices) {
                session.downloaded_slices.try_emplace(
                    slice.hash,
                    ChunkSource{
                        .source_path = *resolved_destination,
                        .identity = installed_id,
                        .offset = slice.offset,
                        .size = slice.size,
                    });
            }
        }
    }
    return {};
}

std::expected<std::optional<mutation::MutationError>, Error>
detail::apply_packed_downloads(
    const history::StorageManifest& manifest,
    std::span<const std::size_t> op_indices,
    transaction::Record& record,
    const std::filesystem::path& local_root,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const platform::Workspace& workspace,
    std::span<const std::optional<mutation::DestinationPrecondition>>
        destinations,
    std::size_t parallelism,
    const CheckpointCallback& checkpoint,
    const AppliedOpsCallback& on_applied,
    ProgressMeter* meter) {
    if (manifest.empty() || op_indices.empty()) {
        return std::optional<mutation::MutationError>{};
    }

    struct PackDownloadJob {
        Hash pack_hash{};
        std::string identifier;
        std::size_t first_op_index = 0;
        std::uint64_t size = 0;
        std::vector<std::size_t> op_indices;
    };

    std::vector<PackDownloadJob> pack_jobs;
    std::unordered_map<Hash, std::size_t, decltype(&hash_key)>
        pack_index_by_hash{0, hash_key};
    HashSet seen_blobs{0, hash_key};

    for (const auto op_idx : op_indices) {
        if (record.progress[op_idx].state ==
            transaction::OperationState::Applied) {
            continue;
        }
        const auto& op = record.plan.operations[op_idx];
        if (op.action != Action::Download) {
            continue;
        }
        const auto h = hash_from_hex(op.hash);
        if (!h) {
            continue;
        }
        const auto* packed = history::find_packed_blob(manifest, *h);
        if (!packed) {
            continue;
        }
        auto [it, inserted] =
            pack_index_by_hash.emplace(packed->pack_hash, pack_jobs.size());
        if (inserted) {
            pack_jobs.push_back(PackDownloadJob{
                .pack_hash = packed->pack_hash,
                .identifier = crypto::pack_identifier(key, packed->pack_hash),
                .first_op_index = op_idx,
            });
        }
        auto& job = pack_jobs[it->second];
        job.first_op_index = std::min(job.first_op_index, op_idx);
        job.op_indices.push_back(op_idx);
        if (seen_blobs.insert(*h).second) {
            job.size += packed->size;
        }
    }

    if (pack_jobs.empty()) {
        return std::optional<mutation::MutationError>{};
    }

    const auto dl_dir = workspace.root / "pack-dl";
    if (auto ok = platform::private_storage::ensure_directory(dl_dir); !ok) {
        return std::optional<mutation::MutationError>{
            mutation::detail::make_error(mutation::MutationErrorCode::LocalIo,
                                         ok.error(),
                                         dl_dir,
                                         pack_jobs.front().first_op_index)};
    }

    const auto concurrency = std::max<std::size_t>(1, parallelism);
    for (std::span<const PackDownloadJob> pending{pack_jobs};
         !pending.empty();) {
        const auto window = next_chunk_window(pending);
        pending = pending.subspan(window.size());
        if (platform::cancellation::requested()) {
            const auto first_op = window.front().first_op_index;
            return std::optional<mutation::MutationError>{
                mutation::detail::make_error(
                    mutation::MutationErrorCode::TransportFailure,
                    "Micro-Pack download cancelled",
                    record.plan.operations[first_op].path,
                    first_op)};
        }

        std::vector<std::string> ids;
        ids.reserve(window.size());
        for (const auto& p : window) {
            ids.push_back(p.identifier);
        }
        if (meter) {
            meter->phase(Activity::Downloading, ids.size());
        }
        const bool batch_ok =
            batch_fetch_objects(storage, dl_dir, ids, concurrency);
        if (platform::cancellation::requested()) {
            const auto first_op = window.front().first_op_index;
            return std::optional<mutation::MutationError>{
                mutation::detail::make_error(
                    mutation::MutationErrorCode::TransportFailure,
                    "Micro-Pack download cancelled",
                    record.plan.operations[first_op].path,
                    first_op)};
        }
        if (meter && batch_ok) {
            meter->phase(Activity::Installing, window.size());
        }

        std::vector<std::optional<mutation::MutationError>> errors(
            window.size());
        std::vector<std::vector<std::size_t>> installed(window.size());
        application::parallel_for_indexed(
            window.size(),
            std::min<std::size_t>(concurrency, window.size()),
            [&](std::size_t i) {
                const auto& job = window[i];
                const auto enc_path = dl_dir / job.identifier;
                std::error_code status_error;
                const auto status =
                    std::filesystem::symlink_status(enc_path, status_error);
                const bool absent =
                    status_error == std::errc::no_such_file_or_directory ||
                    (!status_error &&
                     status.type() == std::filesystem::file_type::not_found);
                if (absent) {
                    auto fetched =
                        transport::get(storage, job.identifier, enc_path);
                    if (!fetched) {
                        errors[i] = mutation::detail::make_error(
                            fetched.error().code ==
                                    transport::ErrorCode::ObjectNotFound
                                ? mutation::MutationErrorCode::
                                      RemoteContentMissing
                                : mutation::MutationErrorCode::TransportFailure,
                            transport::describe(fetched.error()),
                            record.plan.operations[job.first_op_index].path,
                            job.first_op_index);
                        return;
                    }
                } else if (status_error ||
                           !std::filesystem::is_regular_file(status) ||
                           platform::private_storage::is_reparse_or_symlink(
                               enc_path)) {
                    errors[i] = mutation::detail::make_error(
                        mutation::MutationErrorCode::LocalIo,
                        status_error ? status_error.message()
                                     : "downloaded pack is not a regular file",
                        enc_path,
                        job.first_op_index);
                    return;
                }
                auto verified = crypto::pack::load_verified_pack(
                    enc_path, key, job.pack_hash);
                std::error_code ignored;
                std::filesystem::remove(enc_path, ignored);
                if (!verified) {
                    errors[i] = mutation::detail::make_error(
                        mutation::MutationErrorCode::CryptoFailure,
                        "Micro-Pack authentication/extraction failed: " +
                            verified.error(),
                        record.plan.operations[job.first_op_index].path,
                        job.first_op_index);
                    return;
                }
                for (const auto op_idx : job.op_indices) {
                    const auto& op = record.plan.operations[op_idx];
                    const auto blob_hash = hash_from_hex(op.hash);
                    const auto member =
                        blob_hash ? verified->member_bytes(*blob_hash)
                                  : std::nullopt;
                    if (!member) {
                        errors[i] = mutation::detail::make_error(
                            mutation::MutationErrorCode::IntegrityMismatch,
                            "blob missing from authenticated Micro-Pack: " +
                                op.hash,
                            op.path,
                            op_idx);
                        return;
                    }
                    const auto* condition =
                        op_idx < destinations.size() && destinations[op_idx]
                            ? &*destinations[op_idx]
                            : nullptr;
                    auto applied = mutation::apply_preverified_bytes_download(
                        op,
                        op_idx,
                        local_root,
                        *member,
                        workspace,
                        record.progress[op_idx],
                        condition);
                    if (!applied) {
                        errors[i] = std::move(applied.error());
                        return;
                    }
                    installed[i].push_back(op_idx);
                }
                if (meter && batch_ok) {
                    ProgressMeter::add(meter->work);
                }
            });

        std::vector<std::size_t> applied_in_window;
        for (const auto& ops : installed) {
            applied_in_window.insert(
                applied_in_window.end(), ops.begin(), ops.end());
        }
        if (!applied_in_window.empty()) {
            for (const auto op_idx : applied_in_window) {
                record.progress[op_idx].state =
                    transaction::OperationState::Applied;
            }
            if (checkpoint) {
                if (auto saved = checkpoint(); !saved) {
                    return std::unexpected(saved.error());
                }
            }
            if (on_applied) {
                on_applied(applied_in_window);
            }
        }

        std::optional<mutation::MutationError> first_err;
        for (const auto& e : errors) {
            if (e && (!first_err ||
                      e->operation_index < first_err->operation_index)) {
                first_err = *e;
            }
        }
        if (first_err) {
            return first_err;
        }
    }

    return std::optional<mutation::MutationError>{};
}

namespace {

std::expected<std::vector<bool>, Error>
uploads_to_replay(const transaction::Record& record,
                  const history::StorageManifest& target_manifest,
                  const std::vector<bool>& content_upload_required,
                  transport::Transport& storage,
                  std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                  const platform::Workspace& workspace,
                  HashSet& invalid_chunks) {
    std::vector<bool> replay(record.progress.size());
    struct CheckedObject {
        bool verified;
        std::optional<std::uint64_t> size;
    };
    std::unordered_map<std::string, CheckedObject> checked_objects;
    for (std::size_t i = 0; i < record.progress.size(); ++i) {
        const auto& op = record.plan.operations[i];
        if (op.action != Action::Upload || !content_upload_required[i] ||
            record.progress[i].state != transaction::OperationState::Applied) {
            continue;
        }
        const auto hash = hash_from_hex(op.hash);
        if (!hash) {
            return std::unexpected(
                detail::make_error(ErrorCode::RecoveryConflict,
                                   "invalid checkpointed upload hash",
                                   i));
        }
        const auto verify = [&](const Hash& object_hash,
                                std::optional<std::uint64_t> size)
            -> std::expected<bool, Error> {
            const auto identifier =
                size ? crypto::content_identifier(key, object_hash)
                     : crypto::pack_identifier(key, object_hash);
            if (const auto prior = checked_objects.find(identifier);
                prior != checked_objects.end()) {
                return prior->second.verified && prior->second.size == size;
            }
            auto verified =
                detail::verify_existing_content(storage,
                                                key,
                                                identifier,
                                                hash_hex(object_hash),
                                                size,
                                                workspace,
                                                i,
                                                !size);
            if (verified) {
                checked_objects.emplace(identifier,
                                        CheckedObject{*verified, size});
            }
            return verified;
        };
        if (const auto* chunked =
                history::find_chunked_file(target_manifest, *hash)) {
            for (const auto& chunk : chunked->chunks) {
                auto verified = verify(chunk.hash, chunk.size);
                if (!verified) {
                    return std::unexpected(verified.error());
                }
                if (!*verified) {
                    invalid_chunks.insert(chunk.hash);
                    replay[i] = true;
                }
            }
        } else {
            const auto* pack =
                history::find_packed_blob(target_manifest, *hash);
            auto verified = pack ? verify(pack->pack_hash, std::nullopt)
                                 : verify(*hash, op.size);
            if (!verified) {
                return std::unexpected(verified.error());
            }
            replay[i] = !*verified;
        }
    }
    return replay;
}

std::expected<detail::RoundedTimestamps, Error>
restore_transaction_metadata(const Snapshot& expected_tree,
                             const Snapshot& observed_tree,
                             const transaction::Record& record,
                             const std::filesystem::path& local_dir) {
    auto operation_paths = ::kasumi::application::sync::metadata_restore_paths(
        record, expected_tree);
    if (!operation_paths) {
        return std::unexpected(detail::make_error(ErrorCode::MutationFailure,
                                                  operation_paths.error()));
    }
    auto paths = ::kasumi::application::sync::metadata_restore_paths(
        record, expected_tree, &observed_tree);
    if (!paths) {
        return std::unexpected(
            detail::make_error(ErrorCode::MutationFailure, paths.error()));
    }
    detail::RoundedTimestamps rounded;
    for (const auto& path_name : *paths) {
        const auto* row = find_row(expected_tree, path_name);
        if (row == nullptr) {
            continue;
        }
        std::error_code error;
        auto path = row->path.empty()
                        ? local_dir
                        : local_dir / platform::path::from_utf8(row->path);
        const auto status = std::filesystem::symlink_status(path, error);
        if (error) {
            return std::unexpected(detail::make_error(
                ErrorCode::MutationFailure,
                "failed to restore materialized timestamp for " + path_name +
                    ": " + error.message()));
        }
        if (std::filesystem::is_symlink(status) ||
            (row->is_directory ? !std::filesystem::is_directory(status)
                               : !std::filesystem::is_regular_file(status))) {
            return std::unexpected(detail::make_error(
                ErrorCode::MutationFailure,
                "failed to restore materialized timestamp for " + path_name +
                    ": unexpected file system type"));
        }
        const auto observed_only =
            std::ranges::find(*operation_paths, path_name) ==
            operation_paths->end();
        if (observed_only) {
            const auto* observed = find_row(observed_tree, path_name);
            const auto current = platform::metadata::last_write_time(path);
            if (!current) {
                return std::unexpected(detail::make_error(
                    ErrorCode::MutationFailure,
                    "failed to confirm observed timestamp for " + path_name +
                        ": " + current.error()));
            }
            const auto current_ns =
                ::kasumi::platform::metadata::unix_nanoseconds(*current);
            if (observed == nullptr || !current_ns ||
                !platform::metadata::filesystem_equivalent(*current_ns,
                                                           observed->mtime)) {
                return std::unexpected(detail::make_error(
                    ErrorCode::ConcurrentModification,
                    "entry modified after observation: " + path_name));
            }
        }
        if (row->mtime == 0) {
            // Canonical history uses default mtime as an unspecified sentinel.
            continue;
        }
        const auto native_mtime =
            ::kasumi::platform::metadata::file_time_from_unix_nanoseconds(
                row->mtime);
        if (!native_mtime) {
            return std::unexpected(detail::make_error(
                ErrorCode::MutationFailure,
                "failed to restore materialized timestamp for " + path_name +
                    ": timestamp is out of range"));
        }
        auto written = ::kasumi::platform::metadata::set_last_write_time(
            path, *native_mtime);
        if (!written) {
            return std::unexpected(detail::make_error(
                ErrorCode::MutationFailure,
                "failed to restore materialized timestamp for " + path_name +
                    ": " + written.error()));
        }
        const auto materialized =
            platform::metadata::unix_nanoseconds(*written);
        if (!materialized) {
            return std::unexpected(detail::make_error(
                ErrorCode::MutationFailure,
                "materialized timestamp is out of range for " + path_name));
        }
        if (!platform::metadata::filesystem_equivalent(row->mtime,
                                                       *materialized)) {
            rounded.emplace(path_name, *materialized);
        }
    }
    return rounded;
}

bool same_result(const reconciliation::Result& left,
                 const reconciliation::Result& right) noexcept {
    return same_plan(left.plan, right.plan) &&
           left.missing_objects == right.missing_objects &&
           std::ranges::equal(left.pending_storage_rows,
                              right.pending_storage_rows) &&
           std::ranges::equal(left.pending_materializations,
                              right.pending_materializations) &&
           left.missing_content_paths_without_local_source ==
               right.missing_content_paths_without_local_source &&
           left.observed_storage_generation ==
               right.observed_storage_generation &&
           left.target_generation == right.target_generation &&
           left.recovering_missing_history ==
               right.recovering_missing_history &&
           left.has_conflicts == right.has_conflicts &&
           left.requires_local_mutation == right.requires_local_mutation &&
           left.requires_storage_repair == right.requires_storage_repair &&
           left.candidate_shared_tree == right.candidate_shared_tree &&
           left.shared_tree_changed == right.shared_tree_changed &&
           left.requires_publication == right.requires_publication &&
           left.requires_state_commit == right.requires_state_commit;
}

std::expected<void, Error>
validate_execution_composition(const reconciliation::Input& input,
                               const reconciliation::Result& result) {
    auto expected = reconciliation::reconcile(input);
    if (!expected) {
        return std::unexpected(detail::make_error(
            ErrorCode::CompositionMismatch,
            "input cannot reproduce result: " + expected.error().detail));
    }
    if (!same_result(*expected, result)) {
        return std::unexpected(
            detail::make_error(ErrorCode::CompositionMismatch,
                               "reconciliation input and result do not match"));
    }
    return {};
}

} // namespace

std::string describe(const Error& error) {
    static constexpr std::array<std::pair<ErrorCode, std::string_view>, 13>
        names{{
            {ErrorCode::InvalidInput, "invalid_input"},
            {ErrorCode::JournalFailure, "journal_failure"},
            {ErrorCode::WorkspaceFailure, "workspace_failure"},
            {ErrorCode::MutationFailure, "mutation_failure"},
            {ErrorCode::RemoteContentMissing, "remote_content_missing"},
            {ErrorCode::PublicationFailure, "publication_failure"},
            {ErrorCode::DatabaseFailure, "database_failure"},
            {ErrorCode::CompositionMismatch, "composition_mismatch"},
            {ErrorCode::ObservationFailure, "observation_failure"},
            {ErrorCode::ConcurrentModification, "concurrent_modification"},
            {ErrorCode::RecoveryIndeterminate, "recovery_indeterminate"},
            {ErrorCode::RecoveryConflict, "recovery_conflict"},
            {ErrorCode::RecoveryRequired, "recovery_required"},
        }};
    const auto it = std::ranges::find(
        names, error.code, &std::pair<ErrorCode, std::string_view>::first);
    std::string result{it != names.end() ? it->second : "coordinator_error"};
    if (error.operation_index) {
        result += " operation " + std::to_string(*error.operation_index);
    }
    if (!error.detail.empty()) {
        result += ": " + error.detail;
    }
    return result;
}

std::expected<void, Error>
discard_staged_handoff(std::optional<StagedExecutionHandoff>& staged,
                       std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    if (!staged) {
        return {};
    }
    auto workspace = std::move(staged->workspace);
    staged.reset();
    return detail::remove_transaction_workspace(workspace, key);
}

std::expected<void, Error>
execute(const runtime::RuntimeData& runtime_data,
        transport::Transport& storage,
        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
        const reconciliation::Input& observed_input,
        const reconciliation::Result& reconciliation_result,
        observation::LocalObservationSession* session,
        StagedExecutionHandoff* staged_handoff,
        bool enable_micro_packs) {
    auto* meter = session ? session->progress : nullptr;
    struct StagedHandoffGuard {
        StagedExecutionHandoff* handoff = nullptr;
        std::span<const std::uint8_t, crypto::KEY_SIZE> key;
        ~StagedHandoffGuard() noexcept {
            if (handoff != nullptr && handoff->workspace.has_value()) {
                static_cast<void>(detail::remove_transaction_workspace(
                    handoff->workspace, key));
                handoff->workspace.reset();
            }
        }
    } handoff_guard{staged_handoff, key};

    if (runtime_data.local_dir.empty() || runtime_data.database_path.empty() ||
        !transport::valid(storage) ||
        !reconciliation::has_safe_paths(reconciliation_result.plan)) {
        return std::unexpected(detail::make_error(ErrorCode::InvalidInput,
                                                  "invalid transaction input"));
    }

    auto composition =
        validate_execution_composition(observed_input, reconciliation_result);
    if (!composition) {
        return std::unexpected(composition.error());
    }
    auto epoch_policy_presence =
        detail::validate_epoch_policy_presence(observed_input.storage);
    if (!epoch_policy_presence) {
        return std::unexpected(epoch_policy_presence.error());
    }

    auto paths = detail::make_journal_paths(runtime_data);
    if (!paths) {
        return std::unexpected(paths.error());
    }
    journal::Session journal_session;
    auto existing = journal::load(*paths, key, &journal_session);
    if (!existing) {
        return std::unexpected(detail::journal_error(existing.error()));
    }
    auto profile = detail::profile_directory(runtime_data);
    if (!profile) {
        return std::unexpected(profile.error());
    }
    std::string observed_head_id;
    if (reconciliation_result.requires_publication) {
        if (observed_input.base_state_present) {
            observed_head_id = observed_input.base_commit_id;
        }
    } else {
        if (observed_input.storage.logical_heads.size() != 1) {
            return std::unexpected(detail::make_error(
                ErrorCode::InvalidInput,
                "local-only execution requires exactly one logical head"));
        }
        observed_head_id = observed_input.storage.logical_heads.front();
    }
    std::vector<std::string> observed_pending_paths;
    observed_pending_paths.reserve(
        observed_input.pending_materializations.size());
    for (const auto& row : observed_input.pending_materializations) {
        observed_pending_paths.push_back(row.path);
    }
    std::vector<std::string> pending_paths;
    pending_paths.reserve(
        reconciliation_result.pending_materializations.size());
    for (const auto& row : reconciliation_result.pending_materializations) {
        pending_paths.push_back(row.path);
    }
    const auto observed_base_id = observed_input.base_state_present
                                      ? observed_input.base_commit_id
                                      : std::string{};

    std::optional<transaction::Record> record_storage;
    std::optional<platform::Workspace> handoff_workspace;
    std::vector<transaction::OperationProgress> handoff_progress;
    if (*existing) {
        if ((*existing)->publication_required ==
                reconciliation_result.requires_publication &&
            (*existing)->local_generation == observed_input.local_generation &&
            (*existing)->storage_generation ==
                observed_input.storage.generation &&
            (*existing)->observed_base_id == observed_base_id &&
            (*existing)->observed_pending_paths == observed_pending_paths &&
            (*existing)->pending_paths == pending_paths &&
            std::ranges::equal((*existing)->plan.operations,
                               reconciliation_result.plan.operations,
                               same_operation)) {
            record_storage = std::move(**existing);
        } else {
            auto& stale = **existing;
            if (!stale.publication_required ||
                stale.phase >= transaction::Phase::CommitPrepared ||
                detail::has_local_rollback_work(stale)) {
                return std::unexpected(detail::make_error(
                    ErrorCode::RecoveryRequired, "pending transaction exists"));
            }
            auto stale_workspace = detail::open_transaction_workspace(
                *profile, stale.operation_id, key);
            if (!stale_workspace) {
                return std::unexpected(stale_workspace.error());
            }
            // The new plan was observed before any mutation from this record.
            if (auto discarded =
                    detail::rollback_transaction(*paths,
                                                 stale,
                                                 *stale_workspace,
                                                 runtime_data.local_dir,
                                                 key);
                !discarded) {
                return discarded;
            }
            journal_session.invalidate();
            existing->reset();
        }
    }
    if (!record_storage) {
        auto record =
            journal::create_record(observed_input.local_generation,
                                   observed_input.storage.generation,
                                   reconciliation_result.plan,
                                   reconciliation_result.requires_publication,
                                   std::move(observed_head_id));
        if (!record) {
            return std::unexpected(detail::journal_error(record.error()));
        }
        record_storage = std::move(*record);
        record_storage->observed_base_id = observed_base_id;
        record_storage->observed_pending_paths =
            std::move(observed_pending_paths);
        record_storage->pending_paths = std::move(pending_paths);
        if (staged_handoff != nullptr &&
            staged_handoff->workspace.has_value() &&
            staged_handoff->progress.size() ==
                record_storage->plan.operations.size()) {
            record_storage->operation_id =
                std::move(staged_handoff->operation_id);
            handoff_workspace = std::move(staged_handoff->workspace);
            staged_handoff->workspace.reset();
            handoff_progress = std::move(staged_handoff->progress);
        }
    }
    auto& record = record_storage;
    const auto save_active_record = [&](journal::SaveMode mode =
                                            journal::SaveMode::Advance) {
        return detail::save_record(
            *paths, *record, key, mode, &journal_session);
    };
    const auto advance_phase =
        [&](transaction::Phase phase) -> std::expected<void, Error> {
        record->phase = phase;
        return save_active_record();
    };
    const auto content_upload_required = required_content_uploads(
        observed_input, reconciliation_result, record->plan);
    if (meter) {
        for (std::size_t i = 0; i < record->plan.operations.size(); ++i) {
            const auto& op = record->plan.operations[i];
            if (op.action == Action::Upload && !content_upload_required[i]) {
                ProgressMeter::add(meter->bytes_reused, op.size);
            }
        }
    }

    auto saved = save_active_record();
    if (!saved) {
        if (handoff_workspace.has_value()) {
            static_cast<void>(
                detail::remove_transaction_workspace(handoff_workspace, key));
        }
        return std::unexpected(saved.error());
    }
    std::expected<platform::Workspace, Error> workspace =
        handoff_workspace.has_value()
            ? std::expected<platform::Workspace, Error>{std::move(
                  *handoff_workspace)}
            : detail::create_transaction_workspace(
                  *profile, record->operation_id, key);
    if (!workspace) {
        return std::unexpected(workspace.error());
    }
    std::optional<platform::Workspace> transaction_workspace{*workspace};
    const auto rollback_local = [&]() {
        return detail::rollback_transaction(*paths,
                                            *record,
                                            transaction_workspace,
                                            runtime_data.local_dir,
                                            key);
    };
    const auto rollback_terminal = [&]() {
        return detail::rollback_transaction(*paths,
                                            *record,
                                            transaction_workspace,
                                            runtime_data.local_dir,
                                            key,
                                            &journal_session);
    };
    const auto fail_terminal = [&](Error original) {
        return detail::fail_after_rollback(rollback_terminal(),
                                           std::move(original));
    };

    const bool use_handoff_progress =
        handoff_progress.size() == record->plan.operations.size();
    const auto type_changes =
        detail::local_type_changes(record->plan.operations);
    for (std::size_t index = 0; index < record->plan.operations.size();
         ++index) {
        const auto& current_progress =
            use_handoff_progress ? handoff_progress[index]
                                 : record->progress[index];
        if (type_changes[index] == detail::TypeChangeStep::Install &&
            current_progress.state == transaction::OperationState::Pending) {
            continue;
        }
        auto prepared =
            mutation::prepare_operation(record->plan.operations[index],
                                        index,
                                        runtime_data.local_dir,
                                        *workspace,
                                        current_progress,
                                        record->plan.operations);
        if (!prepared) {
            return detail::fail_after_rollback(
                rollback_local(), mutation_error(prepared.error()));
        }
        record->progress[index] = *prepared;
        journal_fault_test::hit("prepared", &*record, index);
    }
    journal_fault_test::hit("before-FilesStaged", &*record);
    // A resumed CommitPrepared record must keep its publication identity valid.
    if (record->phase < transaction::Phase::FilesStaged) {
        record->phase = transaction::Phase::FilesStaged;
    }
    saved = save_active_record();
    if (!saved)
        return std::unexpected(saved.error());

    if (meter &&
        std::ranges::any_of(record->plan.operations, [](const auto& operation) {
            return operation.action == Action::Upload;
        })) {
        meter->phase(Activity::Staging);
    }
    auto layout_plan = build_upload_layout_plan(runtime_data,
                                                storage,
                                                key,
                                                observed_input,
                                                reconciliation_result,
                                                *record,
                                                content_upload_required,
                                                enable_micro_packs);
    if (!layout_plan) {
        return fail_terminal(layout_plan.error());
    }
    HashSet invalid_chunks{0, hash_key};
    std::vector<bool> replay_uploads(record->progress.size());
    if (*existing && record->publication_required) {
        auto replay = uploads_to_replay(*record,
                                        layout_plan->target_manifest,
                                        content_upload_required,
                                        storage,
                                        key,
                                        *workspace,
                                        invalid_chunks);
        if (!replay) {
            return std::unexpected(replay.error());
        }
        replay_uploads = std::move(*replay);
    }

    std::optional<publication::PreparedCommit> prepared_commit;
    std::optional<CommitTimeDecision> commit_time;
    // Destroyed first: waits for the task before destroying prepared_commit.
    std::future<publication::PublishObjectResult> commit_publication;
    if (record->publication_required) {
        const auto local_now = platform::clock::unix_seconds();
        if (!local_now || *local_now <= 0) {
            return fail_terminal(detail::make_error(
                ErrorCode::PublicationFailure,
                local_now ? "invalid local commit timestamp"
                          : "failed to read local commit timestamp: " +
                                local_now.error()));
        }
        auto chosen_time =
            choose_commit_time(observed_input.storage, *local_now);
        if (!chosen_time) {
            return fail_terminal(chosen_time.error());
        }
        commit_time.emplace(*chosen_time);
        auto prepared = publication::prepare_commit(
            reconciliation_result.candidate_shared_tree,
            observed_input.storage.history_present,
            observed_input.storage.generation,
            observed_input.storage.logical_heads,
            commit_time->created_at,
            key,
            layout_plan->target_manifest);
        if (!prepared) {
            return fail_terminal(publication_error(prepared.error()));
        }
        prepared_commit.emplace(std::move(*prepared));

        const auto publication_workspace =
            runtime_data.database_path.parent_path();
        try {
            commit_publication = std::async(
                std::launch::async,
                [&storage,
                 key,
                 layout = history_storage::derive_remote_layout(key),
                 publication_workspace,
                 prepared = &*prepared_commit]() {
                    auto published = publication::publish_commit_object(
                        storage, layout, key, *prepared, publication_workspace);
                    if (!published)
                        return published;
                    auto verified = publication::verify_commit_object(
                        storage,
                        layout,
                        key,
                        *prepared,
                        published->head,
                        publication_workspace,
                        published->physical_hash);
                    if (!verified) {
                        return publication::PublishObjectResult{
                            std::unexpected(verified.error())};
                    }
                    return published;
                });
        } catch (const std::exception& exception) {
            return fail_terminal(detail::make_error(
                ErrorCode::PublicationFailure,
                std::string{"failed to start commit upload: "} +
                    exception.what()));
        }
    }

    std::vector<std::size_t> apply_order;
    apply_order.reserve(record->plan.operations.size());
    std::vector<bool> in_apply_order(record->plan.operations.size(), false);
    if (!record->publication_required &&
        reconciliation_result.requires_storage_repair) {
        for (std::size_t index = 0; index < record->plan.operations.size();
             ++index) {
            if (content_upload_required[index] &&
                is_storage_repair_operation(observed_input,
                                            reconciliation_result,
                                            record->plan.operations[index])) {
                apply_order.push_back(index);
                in_apply_order[index] = true;
            }
        }
    }
    std::vector<std::size_t> remaining_operations;
    remaining_operations.reserve(record->plan.operations.size());
    for (std::size_t index = 0; index < record->plan.operations.size();
         ++index) {
        if (!content_upload_required[index] ||
            (record->progress[index].state ==
                 transaction::OperationState::Applied &&
             !replay_uploads[index])) {
            record->progress[index].state =
                transaction::OperationState::Applied;
            continue;
        }
        if (!in_apply_order[index]) {
            remaining_operations.push_back(index);
        }
    }
    detail::order_local_copies(record->plan.operations, remaining_operations);
    std::stable_partition(remaining_operations.begin(),
                          remaining_operations.end(),
                          [&](std::size_t index) {
                              return record->plan.operations[index].action !=
                                     Action::DeleteLocalDirectory;
                          });
    detail::order_local_type_changes(type_changes, remaining_operations);
    for (const auto index : remaining_operations) {
        apply_order.push_back(index);
    }

    std::vector<bool> awaiting_apply_progress;
    if (meter) {
        awaiting_apply_progress.resize(record->plan.operations.size());
        for (const auto index : apply_order) {
            awaiting_apply_progress[index] = true;
        }
        meter->applied(record->plan.operations.size() - apply_order.size());
    }
    const auto report_applied = [&](std::span<const std::size_t> indices) {
        if (meter) {
            std::size_t completed = 0;
            for (const auto index : indices) {
                if (awaiting_apply_progress[index]) {
                    awaiting_apply_progress[index] = false;
                    ++completed;
                }
            }
            meter->applied(completed);
        }
    };

    const auto mark_applied =
        [&](std::size_t index) -> std::expected<void, Error> {
        record->progress[index].state = transaction::OperationState::Applied;
        if (record->plan.operations[index].action == Action::MoveLocal ||
            record->plan.operations[index].action == Action::CopyLocal ||
            is_logical_mutation(record->plan.operations[index].action)) {
            return {};
        }
        return save_active_record();
    };

    const auto has_applied_uploads = [&]() noexcept {
        for (std::size_t current = 0; current < record->plan.operations.size();
             ++current) {
            if (record->plan.operations[current].action == Action::Upload &&
                record->progress[current].state ==
                    transaction::OperationState::Applied) {
                return true;
            }
        }
        return false;
    };

    const auto fail_mutation = [&](std::size_t index,
                                   const mutation::MutationError& failure)
        -> std::expected<void, Error> {
        for (std::size_t current = index;
             current < record->plan.operations.size();
             ++current) {
            if (record->plan.operations[current].action == Action::MoveLocal &&
                record->progress[current].state ==
                    transaction::OperationState::BackupCreated) {
                record->progress[current].state =
                    transaction::OperationState::Prepared;
            }
        }
        if (failure.code == mutation::MutationErrorCode::DestinationConflict) {
            // Keep completed peers; the next Sync reobserves the tree.
            for (std::size_t current = 0;
                 current < record->plan.operations.size();
                 ++current) {
                if (is_local_mutation(
                        record->plan.operations[current].action) &&
                    !(record->plan.operations[current].action ==
                          Action::MoveLocal &&
                      current < index &&
                      record->progress[current].state ==
                          transaction::OperationState::Applied)) {
                    record->progress[current].state =
                        transaction::OperationState::Prepared;
                }
            }
            return detail::fail_after_rollback(
                rollback_local(),
                detail::make_error(
                    ErrorCode::ConcurrentModification,
                    "local destination changed before mutation; completed "
                    "local "
                    "effects were retained and the transaction was cleared; "
                    "reobserve and retry: " +
                        mutation::describe(failure),
                    index));
        }
        if (failure.code == mutation::MutationErrorCode::RemoteContentMissing) {
            return detail::fail_after_rollback(rollback_local(),
                                               mutation_error(failure));
        }
        if (!record->publication_required &&
            is_storage_repair_operation(observed_input,
                                        reconciliation_result,
                                        record->plan.operations[index])) {
            return std::unexpected(mutation_error(failure));
        }
        if (record->publication_required &&
            record->phase <= transaction::Phase::CommitPrepared &&
            has_applied_uploads()) {
            if (transaction_workspace) {
                std::error_code ec;
                std::filesystem::remove_all(
                    transaction_workspace->root / "upload-batches", ec);
            }
            return std::unexpected(mutation_error(failure));
        }
        return detail::fail_after_rollback(rollback_local(),
                                           mutation_error(failure));
    };

    const auto parallelism = application::content_concurrency();
    const auto dependencies =
        mutation::detail::destination_dependencies(record->plan.operations);
    std::vector<std::optional<mutation::DestinationPrecondition>> destinations(
        record->plan.operations.size());
    const auto prepare_destination =
        [&](std::size_t index) -> std::expected<void, Error> {
        if (type_changes[index] == detail::TypeChangeStep::Install &&
            record->progress[index].state ==
                transaction::OperationState::Pending) {
            auto prepared = detail::prepare_type_change_install(
                *record, index, runtime_data.local_dir, *workspace);
            if (!prepared) {
                return fail_terminal(prepared.error());
            }
            if (auto checkpoint = save_active_record(); !checkpoint) {
                return checkpoint;
            }
        }
        auto condition = mutation::detail::effective_destination(
            *record, index, dependencies);
        if (!condition)
            return std::unexpected(
                detail::make_error(ErrorCode::RecoveryConflict,
                                   mutation::describe(condition.error()),
                                   index));
        destinations[index] = std::move(*condition);
        return {};
    };
    std::unordered_map<std::string, std::size_t> download_counts;
    for (const auto index : apply_order) {
        const auto& operation = record->plan.operations[index];
        if (operation.action == Action::Download) {
            ++download_counts[operation.hash + ':' +
                              std::to_string(operation.size)];
        }
    }
    std::unordered_set<std::string> populated_downloads;
    detail::ChunkDownloadSession chunk_session;
    for (std::size_t position = 0; position < apply_order.size();) {
        const auto first = apply_order[position];
        const auto& first_operation = record->plan.operations[first];
        const bool is_content_install =
            first_operation.action == Action::Download ||
            first_operation.action == Action::CopyLocal;
        if (auto prepared = prepare_destination(first); !prepared)
            return std::unexpected(prepared.error());
        if (first_operation.action == Action::Download) {
            std::size_t end = position + 1;
            while (end < apply_order.size() &&
                   record->plan.operations[apply_order[end]].action ==
                       Action::Download) {
                ++end;
            }
            for (std::size_t i = position + 1; i < end; ++i) {
                if (auto prepared = prepare_destination(apply_order[i]);
                    !prepared) {
                    return std::unexpected(prepared.error());
                }
            }

            std::vector<std::size_t> packed_indices;
            std::vector<std::size_t> chunked_indices;
            std::vector<std::size_t> loose_indices;
            const auto& manifest = observed_input.storage.storage_manifest;
            for (std::size_t i = position; i < end; ++i) {
                const auto op_idx = apply_order[i];
                if (manifest.empty()) {
                    loose_indices.push_back(op_idx);
                    continue;
                }
                const auto h =
                    hash_from_hex(record->plan.operations[op_idx].hash);
                if (h && history::find_packed_blob(manifest, *h) != nullptr) {
                    packed_indices.push_back(op_idx);
                } else if (h &&
                           history::find_chunked_file(manifest, *h) !=
                               nullptr) {
                    chunked_indices.push_back(op_idx);
                } else {
                    loose_indices.push_back(op_idx);
                }
            }

            if (!packed_indices.empty()) {
                auto packed_result = detail::apply_packed_downloads(
                    manifest,
                    packed_indices,
                    *record,
                    runtime_data.local_dir,
                    storage,
                    key,
                    *workspace,
                    destinations,
                    parallelism,
                    [&]() -> std::expected<void, Error> {
                        return save_active_record();
                    },
                    [&](std::span<const std::size_t> applied) {
                        report_applied(applied);
                    },
                    meter);
                if (!packed_result) {
                    return std::unexpected(packed_result.error());
                }
                if (*packed_result) {
                    return fail_mutation((*packed_result)->operation_index,
                                         **packed_result);
                }
            }

            for (const auto op_idx : chunked_indices) {
                const auto& op = record->plan.operations[op_idx];
                const auto h = hash_from_hex(op.hash);
                const auto* chunked =
                    h ? history::find_chunked_file(manifest, *h) : nullptr;
                if (!chunked) {
                    continue;
                }
                auto applied = detail::apply_chunked_download(
                    *chunked,
                    op,
                    op_idx,
                    runtime_data.local_dir,
                    storage,
                    key,
                    *workspace,
                    parallelism,
                    record->progress[op_idx],
                    destinations[op_idx] ? &*destinations[op_idx] : nullptr,
                    chunk_session,
                    meter);
                if (!applied) {
                    return fail_mutation(op_idx, applied.error());
                }
                auto marked = mark_applied(op_idx);
                if (!marked) {
                    return std::unexpected(marked.error());
                }
                report_applied({&op_idx, 1});
            }

            for (std::size_t loose_pos = 0; loose_pos < loose_indices.size();) {
                std::unordered_set<std::string> window_keys;
                std::vector<mutation::DownloadCacheMode> window_modes;
                std::vector<std::string> populated_in_window;
                std::size_t batch_end = loose_pos;
                while (batch_end < loose_indices.size()) {
                    const auto& operation =
                        record->plan.operations[loose_indices[batch_end]];
                    auto content_key =
                        operation.hash + ':' + std::to_string(operation.size);
                    if (populated_downloads.contains(content_key) ||
                        window_keys.contains(content_key)) {
                        break;
                    }
                    const bool multi = download_counts[content_key] > 1;
                    window_modes.push_back(
                        multi ? mutation::DownloadCacheMode::Populate
                              : mutation::DownloadCacheMode::None);
                    window_keys.insert(content_key);
                    if (multi) {
                        populated_in_window.push_back(std::move(content_key));
                    }
                    ++batch_end;
                }
                if (batch_end > loose_pos + 1) {
                    const auto window_span =
                        std::span<const std::size_t>{loose_indices}.subspan(
                            loose_pos, batch_end - loose_pos);
                    if (meter)
                        meter->phase(Activity::Downloading, window_span.size());
                    auto failure = run_content_window(window_span,
                                                      parallelism,
                                                      *record,
                                                      *paths,
                                                      runtime_data.local_dir,
                                                      storage,
                                                      key,
                                                      *workspace,
                                                      destinations,
                                                      window_modes,
                                                      &journal_session,
                                                      meter);
                    if (!failure) {
                        return std::unexpected(failure.error());
                    }
                    if (*failure) {
                        return fail_mutation((*failure)->first,
                                             (*failure)->second);
                    }
                    for (auto& content_key : populated_in_window) {
                        populated_downloads.insert(std::move(content_key));
                    }
                    if (meter)
                        ProgressMeter::add(meter->work, window_span.size());
                    loose_pos = batch_end;
                    continue;
                }
                const auto op_idx = loose_indices[loose_pos];
                const auto& operation = record->plan.operations[op_idx];
                const auto content_key =
                    operation.hash + ':' + std::to_string(operation.size);
                auto download_cache = mutation::DownloadCacheMode::None;
                if (download_counts[content_key] > 1) {
                    download_cache =
                        populated_downloads.insert(content_key).second
                            ? mutation::DownloadCacheMode::Populate
                            : mutation::DownloadCacheMode::Reuse;
                }
                if (meter) {
                    const bool needs_download =
                        download_cache != mutation::DownloadCacheMode::Reuse;
                    meter->phase(needs_download ? Activity::Downloading
                                                : Activity::Installing,
                                 1,
                                 0,
                                 &operation.path);
                }
                auto applied = mutation::apply_operation(
                    operation,
                    op_idx,
                    runtime_data.local_dir,
                    storage,
                    key,
                    *workspace,
                    record->progress[op_idx],
                    download_cache,
                    destinations[op_idx] ? &*destinations[op_idx] : nullptr);
                if (!applied) {
                    return fail_mutation(op_idx, applied.error());
                }
                auto marked = mark_applied(op_idx);
                if (!marked) {
                    return std::unexpected(marked.error());
                }
                if (meter)
                    ProgressMeter::add(meter->work);
                report_applied({&op_idx, 1});
                ++loose_pos;
            }

            position = end;
            continue;
        }
        if (record->plan.operations[first].action != Action::Upload) {
            const auto& operation = first_operation;
            auto download_cache = mutation::DownloadCacheMode::None;
            if (operation.action == Action::Download) {
                const auto content_key =
                    operation.hash + ':' + std::to_string(operation.size);
                if (download_counts[content_key] > 1) {
                    download_cache =
                        populated_downloads.insert(content_key).second
                            ? mutation::DownloadCacheMode::Populate
                            : mutation::DownloadCacheMode::Reuse;
                }
            }
            if (meter && is_content_install) {
                const bool needs_download =
                    operation.action == Action::Download &&
                    download_cache != mutation::DownloadCacheMode::Reuse;
                meter->phase(needs_download ? Activity::Downloading
                                            : Activity::Installing,
                             1,
                             0,
                             &operation.path);
            }
            auto applied = mutation::apply_operation(
                record->plan.operations[first],
                first,
                runtime_data.local_dir,
                storage,
                key,
                *workspace,
                record->progress[first],
                download_cache,
                destinations[first] ? &*destinations[first] : nullptr);
            if (!applied) {
                return fail_mutation(first, applied.error());
            }
            auto marked = mark_applied(first);
            if (!marked) {
                return std::unexpected(marked.error());
            }
            if (meter && is_content_install)
                ProgressMeter::add(meter->work);
            report_applied({&first, 1});
            ++position;
            continue;
        }

        std::size_t end = position;
        std::vector<std::size_t> pending_uploads;
        while (end < apply_order.size() &&
               record->plan.operations[apply_order[end]].action ==
                   Action::Upload) {
            const auto op_index = apply_order[end];
            if (record->progress[op_index].state !=
                    transaction::OperationState::Applied ||
                replay_uploads[op_index]) {
                pending_uploads.push_back(op_index);
            }
            ++end;
        }

        std::vector<const PlannedPack*> planned_packs_pending;
        std::unordered_set<std::size_t> pack_seen;
        std::vector<const PlannedChunkUpload*> planned_chunks_pending;
        std::unordered_set<std::size_t> chunk_seen;
        std::vector<std::size_t> loose_pending_uploads;
        loose_pending_uploads.reserve(pending_uploads.size());

        for (const auto op_index : pending_uploads) {
            const auto h = hash_from_hex(record->plan.operations[op_index].hash);
            if (h) {
                if (const auto it = layout_plan->pack_by_hash.find(*h);
                    it != layout_plan->pack_by_hash.end()) {
                    if (pack_seen.insert(it->second).second) {
                        planned_packs_pending.push_back(
                            &layout_plan->packs[it->second]);
                    }
                    continue;
                }
                if (const auto it = layout_plan->chunked_by_hash.find(*h);
                    it != layout_plan->chunked_by_hash.end()) {
                    if (chunk_seen.insert(it->second).second) {
                        planned_chunks_pending.push_back(
                            &layout_plan->chunked_uploads[it->second]);
                    }
                    continue;
                }
            }
            loose_pending_uploads.push_back(op_index);
        }

        for (std::span<const PlannedPack* const> remaining{
                 planned_packs_pending};
             !remaining.empty();) {
            const auto window = remaining.first(
                std::min(remaining.size(), pack_upload_window_size));
            if (auto pack_ok =
                    execute_packed_upload_batch(window,
                                                *record,
                                                runtime_data.local_dir,
                                                storage,
                                                key,
                                                *workspace,
                                                parallelism,
                                                meter);
                !pack_ok) {
                if (pack_ok.error().transport_after_unknown_transfer) {
                    return std::unexpected(
                        mutation_error(pack_ok.error().mutation));
                }
                return fail_mutation(pack_ok.error().mutation.operation_index,
                                     pack_ok.error().mutation);
            }
            for (const auto* pack : window) {
                for (const auto op_idx : pack->operation_indices) {
                    record->progress[op_idx].state =
                        transaction::OperationState::Applied;
                }
            }
            if (auto saved_pack = save_active_record(); !saved_pack) {
                return std::unexpected(saved_pack.error());
            }
            for (const auto* pack : window) {
                report_applied(pack->operation_indices);
            }
            remaining = remaining.subspan(window.size());
        }

        if (!planned_chunks_pending.empty()) {
            if (auto chunk_ok = execute_chunked_upload_batch(
                    planned_chunks_pending,
                    *record,
                    observed_input.storage.storage_manifest,
                    reconciliation_result.missing_objects,
                    invalid_chunks,
                    runtime_data.local_dir,
                    storage,
                    key,
                    *workspace,
                    parallelism,
                    meter);
                !chunk_ok) {
                if (chunk_ok.error().transport_after_unknown_transfer) {
                    return std::unexpected(
                        mutation_error(chunk_ok.error().mutation));
                }
                return fail_mutation(chunk_ok.error().mutation.operation_index,
                                     chunk_ok.error().mutation);
            }
            for (const auto* cu : planned_chunks_pending) {
                for (const auto op_idx : cu->operation_indices) {
                    record->progress[op_idx].state =
                        transaction::OperationState::Applied;
                }
            }
            if (auto saved_chunk = save_active_record(); !saved_chunk) {
                return std::unexpected(saved_chunk.error());
            }
            for (const auto* upload : planned_chunks_pending) {
                report_applied(upload->operation_indices);
            }
        }

        for (std::size_t chunk_start = 0;
             chunk_start < loose_pending_uploads.size();) {
            const auto chunk = detail::next_upload_batch_chunk(
                loose_pending_uploads, chunk_start, record->plan.operations);

            auto staged_batch = mutation::stage_upload_batch(
                chunk, *record, runtime_data.local_dir, key, *workspace, meter);

            if (!staged_batch) {
                return fail_mutation(staged_batch.error().operation_index,
                                     staged_batch.error());
            }

            detail::ScopedUploadBatchCleanup batch_cleanup{*staged_batch};

            const auto& first_object = staged_batch->objects.front();
            const auto* item =
                first_object.operation_indices.size() == 1
                    ? &record->plan
                           .operations[first_object.operation_indices.front()]
                           .path
                    : nullptr;
            const std::string_view progress_id = item && chunk.size() > 1
                                                     ? first_object.identifier
                                                     : std::string_view{};
            if (auto batch_ok =
                    detail::transfer_and_verify_upload_batch(*staged_batch,
                                                             storage,
                                                             key,
                                                             *workspace,
                                                             parallelism,
                                                             meter,
                                                             item,
                                                             progress_id);
                !batch_ok) {
                if (batch_ok.error().transport_after_unknown_transfer) {
                    return std::unexpected(
                        mutation_error(batch_ok.error().mutation));
                }
                return fail_mutation(batch_ok.error().mutation.operation_index,
                                     batch_ok.error().mutation);
            }

            auto checkpointed = detail::checkpoint_upload_batch(
                *paths, *record, *staged_batch, key, &journal_session);

            if (!checkpointed) {
                return std::unexpected(checkpointed.error());
            }
            report_applied(chunk);

            batch_cleanup.dismissed = true;
            auto cleaned = mutation::cleanup_upload_batch(*staged_batch);

            if (!cleaned) {
                return std::unexpected(mutation_error(cleaned.error()));
            }
        }

        report_applied(
            std::span{apply_order}.subspan(position, end - position));
        position = end;
    }
    if (record->phase < transaction::Phase::LocalChangesApplied) {
        record->phase = transaction::Phase::LocalChangesApplied;
    }
    saved = save_active_record();
    if (!saved)
        return std::unexpected(saved.error());

    mutation_fault_test::hit("after-MoveLocal-consolidated-checkpoint");

    if (meter) {
        meter->phase(Activity::Verifying);
    }
    const auto& expected_tree =
        record->publication_required
            ? reconciliation_result.candidate_shared_tree
            : observed_input.storage.tree;
    auto timestamps = restore_transaction_metadata(expected_tree,
                                                   observed_input.local_tree,
                                                   *record,
                                                   runtime_data.local_dir);
    if (!timestamps) {
        return fail_terminal(timestamps.error());
    }

    auto scanned = observation::collect_local_observation(
        runtime_data.local_dir, session, observed_input.ignore_list);
    if (!scanned) {
        return fail_terminal(detail::make_error(ErrorCode::MutationFailure,
                                                "local scan failed"));
    }
    // Identifies new files or directories created locally and concurrently
    // during sync.
    std::unordered_set<std::string> concurrent_new_paths;
    std::unordered_set<std::string> affected_ancestor_dirs;
    for (const auto& row : scanned->snapshot.rows) {
        if (!row.path.empty() &&
            find_row(observed_input.local_tree, row.path) == nullptr &&
            find_row(reconciliation_result.candidate_shared_tree, row.path) ==
                nullptr) {
            concurrent_new_paths.insert(row.path);
            for (auto parent = row_parent(row.path); !parent.empty();
                 parent = row_parent(parent)) {
                affected_ancestor_dirs.emplace(parent);
            }
            affected_ancestor_dirs.insert("");
        }
    }

    Snapshot validation_local_tree;
    if (concurrent_new_paths.empty()) {
        validation_local_tree = std::move(scanned->snapshot);
    } else {
        validation_local_tree.rows.reserve(scanned->snapshot.rows.size());
        for (auto& row : scanned->snapshot.rows) {
            if (concurrent_new_paths.contains(row.path)) {
                continue;
            }
            if (row.is_directory && affected_ancestor_dirs.contains(row.path)) {
                const auto* expected_dir = find_row(
                    reconciliation_result.candidate_shared_tree, row.path);
                if (expected_dir != nullptr) {
                    const auto written = timestamps->find(row.path);
                    row.mtime = written == timestamps->end()
                                    ? expected_dir->mtime
                                    : written->second;
                }
            }
            validation_local_tree.rows.push_back(std::move(row));
        }
        finalize_snapshot(validation_local_tree);
    }

    auto publication_tree = reconciliation::build_publication_tree(
        std::move(validation_local_tree),
        reconciliation_result.pending_storage_rows,
        reconciliation_result.candidate_shared_tree,
        scanned->physical_evidence);
    if (!publication_tree) {
        return fail_terminal(detail::make_error(
            ErrorCode::PublicationFailure, publication_tree.error().detail));
    }

    if (record->publication_required &&
        !detail::same_materialized_rows(
            reconciliation_result.candidate_shared_tree.rows,
            publication_tree->rows,
            *timestamps)) {
        return fail_terminal(detail::make_error(
            ErrorCode::CompositionMismatch,
            "materialized tree does not match reconciled candidate tree"));
    }

    if (!record->publication_required) {
        const auto found =
            std::ranges::find(observed_input.storage.reachable_commits,
                              record->observed_head_id,
                              &history::LoadedCommit::id);
        if (found == observed_input.storage.reachable_commits.end() ||
            found->commit.height != observed_input.storage.generation ||
            found->commit.tree != observed_input.storage.tree ||
            !detail::same_materialized_head_rows(found->commit.tree.rows,
                                                 publication_tree->rows,
                                                 observed_input.local_tree,
                                                 *timestamps)) {
            return fail_terminal(detail::make_error(
                ErrorCode::CompositionMismatch,
                "local materialization diverges from observed head"));
        }
        std::string ff_ciphertext_id = record->ciphertext_id;
        if (ff_ciphertext_id.empty()) {
            auto it = std::ranges::find(observed_input.storage.marked_heads,
                                        found->id);
            if (it != observed_input.storage.marked_heads.end()) {
                const auto layout = history_storage::derive_remote_layout(key);
                for (const auto& identifier :
                     observed_input.storage.marked_head_identifiers) {
                    const auto parsed = history_storage::parse_marker_object(
                        layout, identifier);
                    if (parsed && parsed->commit_id == found->id) {
                        ff_ciphertext_id = parsed->ciphertext_id;
                        break;
                    }
                }
            }
        }
        if (meter) {
            meter->notify(SyncProgress{.stage = SyncStage::Finalizing});
        }
        if (auto saved_state = detail::save_state_checked(
                runtime_data.database_path,
                state_storage::StoredState{
                    .tree = found->commit.tree,
                    .height = found->commit.height,
                    .commit_id = found->id,
                    .ciphertext_id = ff_ciphertext_id,
                    .epoch_id = observed_input.storage.epoch_id,
                    .epoch_sequence = observed_input.storage.epoch_sequence,
                    .pending_materializations =
                        reconciliation_result.pending_materializations,
                    .storage_manifest = found->commit.storage});
            !saved_state) {
            auto rolled = rollback_terminal();
            if (!rolled) {
                return std::unexpected(detail::make_error(
                    ErrorCode::RecoveryConflict,
                    saved_state.error().detail +
                        "; rollback failed: " + rolled.error().detail));
            }
            return std::unexpected(saved_state.error());
        }
        if (auto saved_phase =
                advance_phase(transaction::Phase::DatabaseCommitted);
            !saved_phase) {
            return std::unexpected(saved_phase.error());
        }
        if (auto saved_phase =
                advance_phase(transaction::Phase::CleanupCompleted);
            !saved_phase) {
            return std::unexpected(saved_phase.error());
        }
        return detail::finish_transaction_cleanup(
            *paths, transaction_workspace, key, &journal_session);
    }

    if (!prepared_commit || !commit_publication.valid()) {
        return fail_terminal(detail::make_error(
            ErrorCode::PublicationFailure,
            "speculative commit publication was not initialized"));
    }
    if (meter) {
        meter->notify(SyncProgress{.stage = SyncStage::Publishing});
    }
    record->commit_id = prepared_commit->commit_id;
    record->parent_ids = prepared_commit->commit.parents;
    if (auto saved_phase = advance_phase(transaction::Phase::CommitPrepared);
        !saved_phase) {
        return std::unexpected(saved_phase.error());
    }

    publication::PublishObjectResult published;
    try {
        published = commit_publication.get();
    } catch (const std::exception& exception) {
        return fail_terminal(
            detail::make_error(ErrorCode::PublicationFailure,
                               std::string{"commit publication task failed: "} +
                                   exception.what()));
    }
    if (!published) {
        return fail_terminal(publication_error(published.error()));
    }
    record->ciphertext_id = published->head.ciphertext_id;
    record->marker_id = published->marker_id;
    if (auto saved_phase = advance_phase(transaction::Phase::CommitUploaded);
        !saved_phase) {
        return std::unexpected(saved_phase.error());
    }
    if (auto saved_phase = advance_phase(transaction::Phase::CommitVerified);
        !saved_phase) {
        return std::unexpected(saved_phase.error());
    }

    const auto layout = history_storage::derive_remote_layout(key);
    const auto confirm_head_marker =
        [&](const publication::Error& failed,
            std::string_view stage) -> std::expected<void, Error> {
        auto inspected = publication::inspect_head_marker(
            storage,
            layout,
            published->head,
            runtime_data.database_path.parent_path());
        if (!inspected) {
            return std::unexpected(
                detail::indeterminate_publication(inspected.error(), stage));
        }
        if (*inspected != publication::HeadMarkerState::Valid) {
            return fail_terminal(publication_error(failed));
        }
        return {};
    };
    auto marker_published = publication::publish_head_marker(
        storage,
        layout,
        published->head,
        runtime_data.database_path.parent_path());
    if (!marker_published) {
        if (auto ok = confirm_head_marker(marker_published.error(),
                                          "head marker publication");
            !ok) {
            return std::unexpected(ok.error());
        }
    }
    if (auto saved_phase = advance_phase(transaction::Phase::HeadPublished);
        !saved_phase) {
        return std::unexpected(saved_phase.error());
    }

    auto head_verified = publication::verify_head_marker(
        storage,
        layout,
        published->head,
        runtime_data.database_path.parent_path(),
        marker_published ? marker_published->physical_hash
                         : std::string_view{});
    if (!head_verified) {
        if (head_verified.error().code ==
            publication::ErrorCode::VerificationFailure) {
            return fail_terminal(publication_error(head_verified.error()));
        }
        if (auto ok = confirm_head_marker(head_verified.error(),
                                          "head marker verification");
            !ok) {
            return std::unexpected(ok.error());
        }
    }
    if (auto saved_phase = advance_phase(transaction::Phase::HeadVerified);
        !saved_phase) {
        return std::unexpected(saved_phase.error());
    }

    std::optional<history_storage::epoch::Reference> verified_new_epoch;
    const auto publish_epoch =
        [&](const history_storage::epoch::Epoch& expected_epoch,
            const history_storage::epoch::SealedEpoch& sealed_epoch,
            std::string_view epoch_kind) -> std::expected<void, Error> {
        if (auto ok = detail::publish_and_verify_epoch(
                storage,
                key,
                runtime_data.database_path.parent_path(),
                *paths,
                *record,
                expected_epoch,
                sealed_epoch,
                epoch_kind,
                ErrorCode::PublicationFailure,
                ErrorCode::PublicationFailure,
                &journal_session);
            !ok) {
            return ok;
        }
        verified_new_epoch = sealed_epoch.reference;
        return {};
    };

    if (prepared_commit->commit.parents.empty()) {
        history_storage::epoch::RetentionPolicy policy{
            .min_history_depth = runtime_data.min_history_depth,
            .min_history_age_hours = runtime_data.min_history_age_hours};
        auto epoch = detail::prepare_genesis_epoch(*record, policy, key);
        if (!epoch) {
            return std::unexpected(epoch.error());
        }
        if (auto saved_phase = advance_phase(transaction::Phase::EpochPrepared);
            !saved_phase) {
            return std::unexpected(saved_phase.error());
        }
        if (auto published_epoch = publish_epoch(
                detail::genesis_epoch(*record), *epoch, "genesis");
            !published_epoch) {
            return std::unexpected(published_epoch.error());
        }
    } else if (!observed_input.storage.epoch_id.empty()) {
        auto policy =
            detail::authenticated_epoch_policy(observed_input.storage);
        if (!policy) {
            return std::unexpected(policy.error());
        }

        std::vector<history::LoadedCommit> current_dag =
            observed_input.storage.reachable_commits;
        current_dag.push_back(
            history::LoadedCommit{.id = prepared_commit->commit_id,
                                  .commit = prepared_commit->commit});

        if (commit_time->pruning_time_safe) {
            auto plan =
                history_storage::epoch::plan_pruning(current_dag, *policy);
            if (plan &&
                !detail::same_epoch_frontier(
                    observed_input.storage.epoch_anchors, plan->anchors)) {
                auto epoch = detail::prepare_pruning_epoch(
                    *record,
                    *policy,
                    *plan,
                    observed_input.storage.epoch_vault_id,
                    observed_input.storage.epoch_sequence,
                    observed_input.storage.epoch_id,
                    key);
                if (!epoch) {
                    return std::unexpected(epoch.error());
                }

                const history_storage::epoch::Epoch expected_epoch{
                    .vault_id = observed_input.storage.epoch_vault_id,
                    .sequence = epoch->reference.sequence,
                    .issued_at = record->epoch_issued_at,
                    .policy = *policy,
                    .anchors = plan->anchors,
                    .previous_epoch_id = observed_input.storage.epoch_id};

                if (auto published_epoch =
                        publish_epoch(expected_epoch, *epoch, "pruning");
                    !published_epoch) {
                    return std::unexpected(published_epoch.error());
                }
            }
        }
    }

    auto epoch_reference = detail::epoch_reference_for_state(
        observed_input.storage, verified_new_epoch);
    if (!epoch_reference) {
        return std::unexpected(epoch_reference.error());
    }
    if (meter) {
        meter->notify(SyncProgress{.stage = SyncStage::Finalizing});
    }
    if (auto saved_state = detail::save_state_checked(
            runtime_data.database_path,
            state_storage::StoredState{
                .tree = prepared_commit->commit.tree,
                .height = prepared_commit->commit.height,
                .commit_id = prepared_commit->commit_id,
                .ciphertext_id = published->head.ciphertext_id,
                .epoch_id = *epoch_reference ? (**epoch_reference).epoch_id
                                             : std::string{},
                .epoch_sequence =
                    *epoch_reference ? (**epoch_reference).sequence : 0,
                .pending_materializations =
                    reconciliation_result.pending_materializations,
                .storage_manifest = prepared_commit->commit.storage});
        !saved_state) {
        return std::unexpected(saved_state.error());
    }
    if (auto saved_phase = advance_phase(transaction::Phase::DatabaseCommitted);
        !saved_phase) {
        return std::unexpected(saved_phase.error());
    }

    auto observed_cleanup_ids = prepared_commit->commit.parents;
    observed_cleanup_ids.insert(
        observed_cleanup_ids.end(),
        observed_input.storage.ancestral_marked_heads.begin(),
        observed_input.storage.ancestral_marked_heads.end());
    auto post_prune = publication::prune_observed_parent_markers(
        storage,
        layout,
        observed_cleanup_ids,
        observed_input.storage.marked_head_identifiers);
    if (!post_prune) {
        return std::unexpected(detail::indeterminate_publication(
            post_prune.error(), "marker pruning"));
    }
    if (auto saved_phase = advance_phase(transaction::Phase::CleanupCompleted);
        !saved_phase) {
        return std::unexpected(saved_phase.error());
    }
    return detail::finish_transaction_cleanup(
        *paths, transaction_workspace, key, &journal_session);
}

} // namespace kasumi::application::sync::coordinator
