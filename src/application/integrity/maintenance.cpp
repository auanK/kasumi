#include "application/integrity/maintenance.hpp"

#include "application/history_storage/content_reachability.hpp"
#include "application/history_storage/detail.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/observation/state.hpp"
#include "core/maintenance.hpp"
#include "crypto/content.hpp"
#include "platform/clock.hpp"
#include "platform/path.hpp"
#include "platform/workspace.hpp"

#include <algorithm>
#include <exception>
#include <filesystem>
#include <iterator>
#include <limits>
#include <ranges>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace kasumi::application::integrity {

namespace {

using KeySpan = std::span<const std::uint8_t, crypto::KEY_SIZE>;

enum class AuditState {
    Healthy,
    Missing,
    Corrupt
};

struct GarbageCollectionSnapshot {
    std::vector<std::string> logical_heads;
    std::vector<std::string> reachable_commits;
    std::vector<std::string> required_commit_objects;
    std::vector<std::string> reachable_content;
    std::vector<std::string> candidates;
    std::vector<std::string> physical_namespace;
};

Error make_error(ErrorCode code,
                 std::string detail,
                 std::optional<std::string> object = std::nullopt) {
    return Error{
        .code = code,
        .detail = std::move(detail),
        .object_identifier = std::move(object),
    };
}

Error transport_error(const transport::Error& error,
                      std::string identifier = {}) {
    return make_error(ErrorCode::TransportFailure,
                      transport::describe(error),
                      identifier.empty()
                          ? std::nullopt
                          : std::optional<std::string>{std::move(identifier)});
}

Error history_storage_error(const history_storage::Error& error) {
    ErrorCode code = ErrorCode::IntegrityFailure;
    switch (error.code) {
        case history_storage::ErrorCode::TransportFailure:
            code = ErrorCode::TransportFailure;
            break;
        case history_storage::ErrorCode::WorkspaceFailure:
            code = ErrorCode::WorkspaceFailure;
            break;
        case history_storage::ErrorCode::CryptoFailure:
            code = ErrorCode::CryptoFailure;
            break;
        default:
            break;
    }
    return make_error(code, error.detail);
}

Error protocol_error(
    const history_storage::maintenance_protocol::Error& error) {
    using ProtocolErrorCode = history_storage::maintenance_protocol::ErrorCode;
    ErrorCode code = ErrorCode::IntegrityFailure;
    switch (error.code) {
        case ProtocolErrorCode::WorkspaceFailure:
            code = ErrorCode::WorkspaceFailure;
            break;
        case ProtocolErrorCode::TransportFailure:
            code = ErrorCode::TransportFailure;
            break;
        case ProtocolErrorCode::Blocked:
            code = ErrorCode::ConcurrentChange;
            break;
        default:
            break;
    }
    return make_error(code, error.detail);
}

bool not_found(const std::error_code& error) noexcept {
    return error == std::errc::no_such_file_or_directory;
}

std::vector<std::string>
physical_identifiers(const reconciliation::StorageState& state) {
    return {state.object_identifiers.begin(), state.object_identifiers.end()};
}

std::expected<kasumi::maintenance::Inventory, Error>
analyze_inventory(const Snapshot& history_tree,
                  const Snapshot& local_tree,
                  const reconciliation::StorageState& storage_state) {
    auto physical = physical_identifiers(storage_state);
    auto analyzed = kasumi::maintenance::analyze(
        history_tree, local_tree, std::span<const std::string>{physical});
    if (!analyzed) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure, analyzed.error().detail));
    }
    return std::move(*analyzed);
}

std::string list_detail(std::string_view prefix,
                        const std::vector<std::string>& values) {
    constexpr std::size_t limit = 20;
    const auto displayed = std::min(values.size(), limit);
    std::string result{prefix};
    for (std::size_t index = 0; index < displayed; ++index) {
        result += index == 0 ? "" : ", ";
        result += values[index];
    }
    if (values.size() > limit) {
        result += "; e mais ";
        result += std::to_string(values.size() - limit);
    }
    return result;
}

std::string path_detail(const std::vector<std::filesystem::path>& paths) {
    constexpr std::size_t limit = 20;
    const auto displayed = std::min(paths.size(), limit);
    std::string result =
        "objetos referenciados ausentes ou corrompidos; reparo do fsck "
        "indisponível nesta etapa (caminhos: ";
    for (std::size_t index = 0; index < displayed; ++index) {
        if (index != 0) {
            result += ", ";
        }
        result += platform::path::to_utf8(paths[index]);
    }
    if (paths.size() > limit) {
        result += "; e mais ";
        result += std::to_string(paths.size() - limit);
    }
    result += ')';
    return result;
}

std::filesystem::path
maintenance_workspace_root(const runtime::RuntimeData& runtime_data) {
    auto root = runtime_data.database_path.parent_path();
    std::error_code error;
    if (root.empty() || !std::filesystem::exists(root, error)) {
        root = runtime_data.local_dir.parent_path();
    }
    return root;
}

std::expected<void, Error> validate_history_inventory(
    const history_storage::ReachabilityInventory& inventory) {
    if (inventory.logical_heads.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure, "remote history absent"));
    }
    if (!inventory.unknown_history_objects.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("unknown history objects: ",
                                   inventory.unknown_history_objects)));
    }
    if (!inventory.missing_parent_ids.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("commits pais ausentes: ",
                                   inventory.missing_parent_ids)));
    }
    if (!inventory.invalid_parent_ids.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("invalid parent commits: ",
                                   inventory.invalid_parent_ids)));
    }

    std::vector<std::string> invalid_markers;
    for (const auto& marker : inventory.markers) {
        if (marker.state != history_storage::ReachabilityMarkerState::Valid) {
            invalid_markers.push_back(marker.identifier);
        }
    }
    if (!invalid_markers.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("invalid or unstable head markers: ",
                                   invalid_markers)));
    }

    std::vector<std::string> invalid_commits;
    for (const auto& commit : inventory.commits) {
        if (!commit.valid &&
            std::ranges::any_of(commit.variants, [](const auto& variant) {
                return !variant.identifier.empty();
            })) {
            invalid_commits.push_back(commit.commit_id);
        }
    }
    if (!invalid_commits.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("invalid commits: ", invalid_commits)));
    }
    return {};
}

std::expected<void, Error> validate_content_inventory(
    const history_storage::ContentReachabilityInventory& inventory) {
    if (!inventory.unknown_storage_objects.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("unknown physical identifiers: ",
                                   inventory.unknown_storage_objects)));
    }

    std::vector<std::string> damaged;
    for (const auto& content : inventory.contents) {
        if (content.reachable &&
            content.state != history_storage::ContentObjectState::Present) {
            damaged.push_back(content.content_id);
        }
    }
    if (!damaged.empty()) {
        return std::unexpected(make_error(
            ErrorCode::IntegrityFailure,
            list_detail("reachable contents missing or corrupted: ", damaged)));
    }
    return {};
}

std::expected<GarbageCollectionSnapshot, Error>
collect_garbage_collection_snapshot(
    transport::Transport& storage,
    KeySpan key,
    const std::filesystem::path& workspace_root) {
    auto listing = transport::list(storage);
    if (!listing) {
        return std::unexpected(transport_error(listing.error()));
    }
    std::ranges::sort(*listing);

    auto history = history_storage::inventory_reachability(
        storage, key, *listing, workspace_root);
    if (!history) {
        return std::unexpected(history_storage_error(history.error()));
    }
    if (auto valid = validate_history_inventory(*history); !valid) {
        return std::unexpected(valid.error());
    }

    auto content = history_storage::inventory_content_reachability(
        storage, key, *listing, *history, workspace_root, false);
    if (!content) {
        return std::unexpected(history_storage_error(content.error()));
    }
    if (auto valid = validate_content_inventory(*content); !valid) {
        return std::unexpected(valid.error());
    }

    GarbageCollectionSnapshot result{
        .logical_heads = history->logical_heads,
        .reachable_commits = history->reachable_commits,
        .required_commit_objects = {},
        .reachable_content = content->reachable_content_ids,
        .candidates = {},
        .physical_namespace = std::move(*listing),
    };

    std::vector<std::string> marked_commits;
    for (const auto& marker : history->markers) {
        if (marker.state != history_storage::ReachabilityMarkerState::Valid ||
            !marker.reference) {
            continue;
        }
        marked_commits.push_back(marker.reference->commit_id);
        result.required_commit_objects.push_back(
            history_storage::detail::commit_object(*marker.reference));
    }
    std::ranges::sort(marked_commits);
    marked_commits.erase(std::ranges::unique(marked_commits).begin(),
                         marked_commits.end());

    for (const auto& commit : history->commits) {
        if (!commit.reachable ||
            std::ranges::binary_search(marked_commits, commit.commit_id)) {
            continue;
        }
        const auto variant =
            std::ranges::find_if(commit.variants, [](const auto& candidate) {
                return !candidate.identifier.empty() &&
                       candidate.state ==
                           history_storage::detail::VariantState::Valid;
            });
        if (variant != commit.variants.end()) {
            result.required_commit_objects.push_back(variant->identifier);
        }
    }
    std::ranges::sort(result.required_commit_objects);
    result.required_commit_objects.erase(
        std::ranges::unique(result.required_commit_objects).begin(),
        result.required_commit_objects.end());

    for (const auto& commit : history->commits) {
        for (const auto& variant : commit.variants) {
            if (!variant.identifier.empty() &&
                !std::ranges::binary_search(result.required_commit_objects,
                                            variant.identifier)) {
                result.candidates.push_back(variant.identifier);
            }
        }
    }
    std::ranges::sort(result.candidates);
    result.candidates.erase(std::ranges::unique(result.candidates).begin(),
                            result.candidates.end());
    result.candidates.insert(result.candidates.end(),
                             content->orphan_content_ids.begin(),
                             content->orphan_content_ids.end());
    std::ranges::sort(result.candidates);
    result.candidates.erase(std::ranges::unique(result.candidates).begin(),
                            result.candidates.end());
    return result;
}

bool same_reachable_state(const GarbageCollectionSnapshot& left,
                          const GarbageCollectionSnapshot& right) noexcept {
    return left.logical_heads == right.logical_heads &&
           left.reachable_commits == right.reachable_commits &&
           left.required_commit_objects == right.required_commit_objects &&
           left.reachable_content == right.reachable_content &&
           left.candidates == right.candidates &&
           left.physical_namespace == right.physical_namespace;
}

const history_storage::maintenance_protocol::QuarantineEntry* find_quarantined(
    const std::vector<history_storage::maintenance_protocol::QuarantineEntry>&
        entries,
    std::string_view original_identifier) {
    const auto found =
        std::ranges::lower_bound(entries,
                                 original_identifier,
                                 {},
                                 &history_storage::maintenance_protocol::
                                     QuarantineEntry::original_identifier);
    return found != entries.end() &&
                   found->original_identifier == original_identifier
               ? &*found
               : nullptr;
}

std::expected<void, Error> restore_quarantined_object(
    transport::Transport& storage,
    const history_storage::maintenance_protocol::QuarantineEntry& entry,
    const std::filesystem::path& workspace_root,
    history_storage::maintenance_protocol::RegistrationState& barrier) {
    auto verified =
        history_storage::maintenance_protocol::verify_registration(barrier);
    if (!verified) {
        return std::unexpected(protocol_error(verified.error()));
    }
    auto copied = history_storage::maintenance_protocol::copy_verified(
        storage,
        entry.quarantine_identifier,
        entry.original_identifier,
        workspace_root);
    if (!copied) {
        return std::unexpected(protocol_error(copied.error()));
    }
    return {};
}

std::expected<std::size_t, Error> restore_reachable_quarantine(
    transport::Transport& storage,
    KeySpan key,
    const std::filesystem::path& workspace_root,
    history_storage::maintenance_protocol::RegistrationState& barrier,
    const std::vector<history_storage::maintenance_protocol::QuarantineEntry>&
        entries) {
    if (entries.empty()) {
        return 0;
    }
    std::size_t restored = 0;
    auto listing = transport::list(storage);
    if (!listing) {
        return std::unexpected(transport_error(listing.error()));
    }
    std::ranges::sort(*listing);

    bool marker_restored = false;
    for (const auto& identifier : *listing) {
        const auto reference = history_storage::parse_marker_object(identifier);
        if (!reference) {
            continue;
        }
        const auto original =
            history_storage::detail::commit_object(*reference);
        const auto* quarantined = find_quarantined(entries, original);
        if (!quarantined) {
            continue;
        }
        if (!std::ranges::binary_search(*listing, original)) {
            auto restored_object = restore_quarantined_object(
                storage, *quarantined, workspace_root, barrier);
            if (!restored_object) {
                return std::unexpected(restored_object.error());
            }
            ++restored;
            marker_restored = true;
        }
    }
    if (marker_restored) {
        listing = transport::list(storage);
        if (!listing) {
            return std::unexpected(transport_error(listing.error()));
        }
        std::ranges::sort(*listing);
    }

    for (std::size_t pass = 0; pass <= entries.size(); ++pass) {
        auto history = history_storage::inventory_reachability(
            storage, key, *listing, workspace_root);
        if (!history) {
            return std::unexpected(history_storage_error(history.error()));
        }
        std::vector<std::string> unavailable = history->missing_parent_ids;
        unavailable.insert(unavailable.end(),
                           history->invalid_parent_ids.begin(),
                           history->invalid_parent_ids.end());
        std::ranges::sort(unavailable);
        unavailable.erase(std::ranges::unique(unavailable).begin(),
                          unavailable.end());
        bool changed = false;
        for (const auto& entry : entries) {
            const auto reference = history_storage::detail::parse_commit_object(
                entry.original_identifier);
            if (!reference || !std::ranges::binary_search(
                                  unavailable, reference->commit_id)) {
                continue;
            }
            auto restored_object = restore_quarantined_object(
                storage, entry, workspace_root, barrier);
            if (!restored_object) {
                return std::unexpected(restored_object.error());
            }
            ++restored;
            changed = true;
        }
        if (changed) {
            listing = transport::list(storage);
            if (!listing) {
                return std::unexpected(transport_error(listing.error()));
            }
            std::ranges::sort(*listing);
            continue;
        }
        if (auto valid = validate_history_inventory(*history); !valid) {
            return std::unexpected(valid.error());
        }
        auto content = history_storage::inventory_content_reachability(
            storage, key, *listing, *history, workspace_root, false);
        if (!content) {
            return std::unexpected(history_storage_error(content.error()));
        }
        for (const auto& item : content->contents) {
            if (!item.reachable ||
                item.state == history_storage::ContentObjectState::Present) {
                continue;
            }
            const auto* quarantined =
                find_quarantined(entries, item.content_id);
            if (!quarantined) {
                continue;
            }
            auto restored_object = restore_quarantined_object(
                storage, *quarantined, workspace_root, barrier);
            if (!restored_object) {
                return std::unexpected(restored_object.error());
            }
            ++restored;
        }
        return restored;
    }
    return std::unexpected(
        make_error(ErrorCode::IntegrityFailure,
                   "quarantine restoration did not stabilize"));
}

bool quarantine_is_reachable(
    const history_storage::maintenance_protocol::QuarantineEntry& entry,
    const GarbageCollectionSnapshot& snapshot) {
    if (const auto content = hash_from_hex(entry.original_identifier);
        content && hash_hex(*content) == entry.original_identifier) {
        return std::ranges::binary_search(snapshot.reachable_content,
                                          entry.original_identifier);
    }
    const auto reference =
        history_storage::detail::parse_commit_object(entry.original_identifier);
    return !reference ||
           std::ranges::binary_search(snapshot.required_commit_objects,
                                      entry.original_identifier);
}

std::expected<void, Error> initialize_quarantine_metadata(
    transport::Transport& storage,
    KeySpan key,
    const std::filesystem::path& workspace_root,
    std::int64_t now,
    history_storage::maintenance_protocol::RegistrationState& barrier,
    std::vector<history_storage::maintenance_protocol::QuarantineEntry>&
        entries) {
    for (auto& entry : entries) {
        if (entry.quarantined_at) {
            continue;
        }
        auto owned =
            history_storage::maintenance_protocol::verify_registration(barrier);
        if (!owned) {
            return std::unexpected(protocol_error(owned.error()));
        }
        auto recorded =
            history_storage::maintenance_protocol::record_quarantine(
                storage, entry.quarantine_identifier, now, key, workspace_root);
        if (!recorded) {
            return std::unexpected(protocol_error(recorded.error()));
        }
        entry = std::move(*recorded);
    }
    return {};
}

std::expected<std::size_t, Error> purge_expired_quarantine(
    transport::Transport& storage,
    const std::filesystem::path& workspace_root,
    std::int64_t now,
    const GarbageCollectionSnapshot& snapshot,
    history_storage::maintenance_protocol::RegistrationState& barrier,
    const std::vector<history_storage::maintenance_protocol::QuarantineEntry>&
        entries) {
    std::size_t purged = 0;
    for (const auto& entry : entries) {
        if (history_storage::maintenance_protocol::is_epoch_object(
                entry.original_identifier) ||
            !entry.quarantined_at || now < *entry.quarantined_at ||
            now - *entry.quarantined_at <
                history_storage::maintenance_protocol::
                    quarantine_retention_seconds ||
            quarantine_is_reachable(entry, snapshot)) {
            continue;
        }
        auto original = transport::presence(storage, entry.original_identifier);
        if (!original) {
            return std::unexpected(
                transport_error(original.error(), entry.original_identifier));
        }
        if (*original == transport::Presence::Present) {
            continue;
        }
        auto verified =
            history_storage::maintenance_protocol::verify_quarantine(
                storage, entry, workspace_root);
        if (!verified) {
            return std::unexpected(protocol_error(verified.error()));
        }
        if (!*verified) {
            return std::unexpected(
                make_error(ErrorCode::IntegrityFailure,
                           "quarantine object does not match metadata",
                           entry.quarantine_identifier));
        }
        auto owned =
            history_storage::maintenance_protocol::verify_registration(barrier);
        if (!owned) {
            return std::unexpected(protocol_error(owned.error()));
        }
        auto metadata_removed =
            transport::remove(storage, entry.metadata_identifier);
        if (!metadata_removed) {
            return std::unexpected(transport_error(metadata_removed.error(),
                                                   entry.metadata_identifier));
        }
        if (*metadata_removed != transport::Removal::Removed) {
            return std::unexpected(
                make_error(ErrorCode::ConcurrentChange,
                           "quarantine metadata disappeared during purge",
                           entry.metadata_identifier));
        }
        owned =
            history_storage::maintenance_protocol::verify_registration(barrier);
        if (!owned) {
            return std::unexpected(protocol_error(owned.error()));
        }
        auto object_removed =
            transport::remove(storage, entry.quarantine_identifier);
        if (!object_removed) {
            return std::unexpected(transport_error(
                object_removed.error(), entry.quarantine_identifier));
        }
        if (*object_removed != transport::Removal::Removed) {
            return std::unexpected(
                make_error(ErrorCode::ConcurrentChange,
                           "quarantine object disappeared during purge",
                           entry.quarantine_identifier));
        }
        ++purged;
    }
    return purged;
}

std::expected<void, Error>
prepare_workspace_file(const std::filesystem::path& path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (not_found(error) ||
        status.type() == std::filesystem::file_type::not_found) {
        return {};
    }
    if (error) {
        return std::unexpected(
            make_error(ErrorCode::WorkspaceFailure,
                       "could not inspect temporary file: " + error.message()));
    }
    if (std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        return std::unexpected(make_error(ErrorCode::WorkspaceFailure,
                                          "temporary file has invalid type"));
    }
    std::filesystem::remove(path, error);
    if (error) {
        return std::unexpected(
            make_error(ErrorCode::WorkspaceFailure,
                       "could not clean temporary file: " + error.message()));
    }
    return {};
}

std::expected<void, Error>
require_regular_file(const std::filesystem::path& path,
                     ErrorCode failure_code,
                     std::string detail) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error) {
        return std::unexpected(make_error(
            failure_code, std::move(detail) + ": " + error.message()));
    }
    if (status.type() == std::filesystem::file_type::not_found ||
        std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        return std::unexpected(make_error(failure_code, std::move(detail)));
    }
    return {};
}

std::expected<void, Error>
remove_temporary_file(const std::filesystem::path& path) {
    std::error_code error;
    std::filesystem::remove(path, error);
    if (error) {
        return std::unexpected(make_error(
            ErrorCode::WorkspaceFailure,
            "não foi possível remover temporário: " + error.message()));
    }
    return {};
}

std::expected<void, Error> verify_content(const std::filesystem::path& path,
                                          std::string_view identifier,
                                          std::uint64_t expected_size,
                                          ErrorCode io_failure) {
    auto regular = require_regular_file(
        path, io_failure, "file is not regular for verification");
    if (!regular) {
        return regular;
    }
    std::error_code error;
    const auto actual_size = std::filesystem::file_size(path, error);
    if (error) {
        return std::unexpected(make_error(
            io_failure, "could not read file size: " + error.message()));
    }
    if (actual_size != expected_size) {
        return std::unexpected(make_error(
            ErrorCode::IntegrityFailure, "object size does not match history"));
    }
    auto actual_hash = crypto::content::hash_file(path);
    if (!actual_hash) {
        return std::unexpected(make_error(io_failure, actual_hash.error()));
    }
    if (hash_hex(*actual_hash) != identifier) {
        return std::unexpected(make_error(
            ErrorCode::IntegrityFailure, "object hash does not match history"));
    }
    return {};
}

std::expected<AuditState, Error>
audit_object(transport::Transport& storage,
             KeySpan key,
             const kasumi::maintenance::ObjectReference& reference,
             const platform::Workspace& workspace,
             std::size_t index) {
    const auto plaintext_hash = hash_from_hex(reference.identifier);
    if (!plaintext_hash) {
        return std::unexpected(make_error(ErrorCode::IntegrityFailure,
                                          "invalid content identifier"));
    }
    const auto remote_identifier =
        crypto::content_identifier(key, *plaintext_hash);
    const auto encrypted =
        platform::workspace_file(workspace, index, ".audit.enc");
    const auto plaintext =
        platform::workspace_file(workspace, index, ".audit.plain");
    auto prepared = prepare_workspace_file(encrypted);
    if (!prepared)
        return std::unexpected(prepared.error());
    prepared = prepare_workspace_file(plaintext);
    if (!prepared)
        return std::unexpected(prepared.error());

    auto downloaded = transport::get(storage, remote_identifier, encrypted);
    if (!downloaded) {
        auto removed = remove_temporary_file(encrypted);
        if (!removed)
            return std::unexpected(removed.error());
        removed = remove_temporary_file(plaintext);
        if (!removed)
            return std::unexpected(removed.error());
        if (downloaded.error().code == transport::ErrorCode::ObjectNotFound) {
            return AuditState::Missing;
        }
        return std::unexpected(
            transport_error(downloaded.error(), reference.identifier));
    }

    auto regular = require_regular_file(
        encrypted, ErrorCode::WorkspaceFailure, "invalid temporary download");
    if (!regular)
        return std::unexpected(regular.error());

    AuditState result = AuditState::Healthy;
    if (!crypto::decrypt_file(encrypted, plaintext, key)) {
        result = AuditState::Corrupt;
    } else {
        auto verified = verify_content(plaintext,
                                       reference.identifier,
                                       reference.size,
                                       ErrorCode::WorkspaceFailure);
        if (!verified) {
            if (verified.error().code != ErrorCode::IntegrityFailure) {
                return std::unexpected(verified.error());
            }
            result = AuditState::Corrupt;
        }
    }
    auto removed = remove_temporary_file(encrypted);
    if (!removed)
        return std::unexpected(removed.error());
    removed = remove_temporary_file(plaintext);
    if (!removed)
        return std::unexpected(removed.error());
    return result;
}

} // namespace

std::string describe(const Error& error) {
    std::string result;
    switch (error.code) {
        case ErrorCode::InvalidInput:
            result = "invalid_input";
            break;
        case ErrorCode::StateFailure:
            result = "state_failure";
            break;
        case ErrorCode::WorkspaceFailure:
            result = "workspace_failure";
            break;
        case ErrorCode::TransportFailure:
            result = "transport_failure";
            break;
        case ErrorCode::CryptoFailure:
            result = "crypto_failure";
            break;
        case ErrorCode::IntegrityFailure:
            result = "integrity_failure";
            break;
        case ErrorCode::Unrecoverable:
            result = "unrecoverable";
            break;
        case ErrorCode::ConcurrentChange:
            result = "concurrent_change";
            break;
    }
    if (error.object_identifier) {
        result += " no objeto ";
        result += *error.object_identifier;
    }
    if (!error.detail.empty()) {
        result += ": ";
        result += error.detail;
    }
    return result;
}

std::expected<FsckResult, Error> fsck(const runtime::RuntimeData& runtime_data,
                                      transport::Transport& storage,
                                      KeySpan key) {
    if (runtime_data.local_dir.empty() || !transport::valid(storage)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidInput, "invalid fsck context"));
    }
    const auto history_workspace = maintenance_workspace_root(runtime_data);
    auto storage_state = observation::collect_storage_state(
        storage, key, history_workspace, true);
    if (!storage_state) {
        return std::unexpected(
            make_error(ErrorCode::StateFailure, storage_state.error()));
    }
    if (!storage_state->history_present) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure, "remote history absent"));
    }
    auto listing = transport::list(storage);
    if (!listing) {
        return std::unexpected(transport_error(listing.error()));
    }
    std::vector<std::string> unknown_storage_identifiers;
    for (const auto& identifier : *listing) {
        if (identifier.starts_with("history/") ||
            kasumi::hash_from_hex(identifier).has_value()) {
            continue;
        }
        unknown_storage_identifiers.push_back(identifier);
    }
    if (!unknown_storage_identifiers.empty()) {
        std::ranges::sort(unknown_storage_identifiers);
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("unknown physical identifiers: ",
                                   unknown_storage_identifiers)));
    }
    auto local_tree = observation::collect_local_tree(runtime_data.local_dir);
    if (!local_tree) {
        return std::unexpected(
            make_error(ErrorCode::StateFailure, local_tree.error()));
    }
    auto inventory =
        analyze_inventory(storage_state->tree, *local_tree, *storage_state);
    if (!inventory)
        return std::unexpected(inventory.error());
    if (!inventory->unknown_identifiers.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("unknown physical identifiers: ",
                                   inventory->unknown_identifiers)));
    }

    auto workspace = platform::create_workspace("fsck");
    if (!workspace) {
        return std::unexpected(
            make_error(ErrorCode::WorkspaceFailure, workspace.error()));
    }
    auto result = [&]() -> std::expected<FsckResult, Error> {
        try {
            FsckResult fsck_result{
                .checked_objects = inventory->referenced_objects.size(),
            };
            std::vector<std::filesystem::path> unrecoverable;
            for (std::size_t index = 0;
                 index < inventory->referenced_objects.size();
                 ++index) {
                const auto& reference = inventory->referenced_objects[index];
                auto audited =
                    audit_object(storage, key, reference, *workspace, index);
                if (!audited)
                    return std::unexpected(audited.error());
                if (*audited == AuditState::Healthy)
                    continue;
                unrecoverable.insert(unrecoverable.end(),
                                     reference.referenced_paths.begin(),
                                     reference.referenced_paths.end());
            }
            std::ranges::sort(unrecoverable, {}, [](const auto& path) {
                return platform::path::to_logical_utf8(path);
            });
            unrecoverable.erase(std::ranges::unique(unrecoverable).begin(),
                                unrecoverable.end());
            if (!unrecoverable.empty()) {
                return std::unexpected(make_error(ErrorCode::Unrecoverable,
                                                  path_detail(unrecoverable)));
            }
            return fsck_result;
        } catch (const std::exception& exception) {
            return std::unexpected(
                make_error(ErrorCode::StateFailure, exception.what()));
        }
    }();
    platform::cleanup_workspace(*workspace);
    return result;
}

std::expected<GarbageCollectResult, Error>
garbage_collect(const runtime::RuntimeData& runtime_data,
                transport::Transport& storage,
                KeySpan key) {
    if (runtime_data.local_dir.empty() || runtime_data.database_path.empty() ||
        !transport::valid(storage)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidInput, "invalid GC context"));
    }

    try {
        const auto workspace_root = maintenance_workspace_root(runtime_data);
        auto barrier = history_storage::maintenance_protocol::establish_barrier(
            storage, workspace_root);
        if (!barrier) {
            return std::unexpected(protocol_error(barrier.error()));
        }
        auto outcome = [&]() -> std::expected<GarbageCollectResult, Error> {
            try {
                for (int observation = 0; observation < 2; ++observation) {
                    auto writers =
                        history_storage::maintenance_protocol::active_writers(
                            storage);
                    if (!writers) {
                        return std::unexpected(protocol_error(writers.error()));
                    }
                    if (!writers->empty()) {
                        return std::unexpected(make_error(
                            ErrorCode::ConcurrentChange,
                            list_detail("active or abandoned writers: ",
                                        *writers)));
                    }
                    auto owned = history_storage::maintenance_protocol::
                        verify_registration(*barrier);
                    if (!owned) {
                        return std::unexpected(protocol_error(owned.error()));
                    }
                }

                auto online = history_storage::maintenance_protocol::
                    supports_online_collection(storage, workspace_root);
                if (!online) {
                    return std::unexpected(protocol_error(online.error()));
                }
                if (!*online) {
                    auto analyzed = collect_garbage_collection_snapshot(
                        storage, key, workspace_root);
                    if (!analyzed) {
                        return std::unexpected(analyzed.error());
                    }
                    return GarbageCollectResult{
                        .candidate_objects = analyzed->candidates.size(),
                        .analysis_only = true,
                    };
                }

                auto now = platform::clock::unix_seconds();
                if (!now) {
                    return std::unexpected(
                        make_error(ErrorCode::StateFailure, now.error()));
                }

                auto quarantine =
                    history_storage::maintenance_protocol::inventory_quarantine(
                        storage, key, workspace_root);
                if (!quarantine) {
                    return std::unexpected(protocol_error(quarantine.error()));
                }
                auto restored = restore_reachable_quarantine(
                    storage, key, workspace_root, *barrier, *quarantine);
                if (!restored) {
                    return std::unexpected(restored.error());
                }
                auto metadata = initialize_quarantine_metadata(
                    storage, key, workspace_root, *now, *barrier, *quarantine);
                if (!metadata) {
                    return std::unexpected(metadata.error());
                }

                auto first = collect_garbage_collection_snapshot(
                    storage, key, workspace_root);
                if (!first) {
                    return std::unexpected(first.error());
                }
                auto confirmed = collect_garbage_collection_snapshot(
                    storage, key, workspace_root);
                if (!confirmed) {
                    return std::unexpected(confirmed.error());
                }
                if (!same_reachable_state(*first, *confirmed)) {
                    return std::unexpected(make_error(
                        ErrorCode::ConcurrentChange,
                        "reachability or inventory changed during GC"));
                }

                GarbageCollectResult result{
                    .candidate_objects = confirmed->candidates.size(),
                    .restored_objects = *restored,
                };
                auto final_listing = transport::list(storage);
                if (!final_listing) {
                    return std::unexpected(
                        transport_error(final_listing.error()));
                }
                std::ranges::sort(*final_listing);
                if (*final_listing != confirmed->physical_namespace) {
                    return std::unexpected(make_error(
                        ErrorCode::ConcurrentChange,
                        "remote storage changed prior to destructive phase"));
                }
                auto purged = purge_expired_quarantine(storage,
                                                       workspace_root,
                                                       *now,
                                                       *confirmed,
                                                       *barrier,
                                                       *quarantine);
                if (!purged) {
                    return std::unexpected(purged.error());
                }
                result.purged_objects = *purged;
                for (const auto& identifier : confirmed->candidates) {
                    if (history_storage::maintenance_protocol::is_epoch_object(
                            identifier)) {
                        return std::unexpected(make_error(
                            ErrorCode::IntegrityFailure,
                            "epoch candidate blocked from quarantine",
                            identifier));
                    }
                    auto owned = history_storage::maintenance_protocol::
                        verify_registration(*barrier);
                    if (!owned) {
                        return std::unexpected(protocol_error(owned.error()));
                    }
                    auto quarantine_identifier = history_storage::
                        maintenance_protocol::quarantine_identifier(identifier);
                    if (!quarantine_identifier) {
                        return std::unexpected(
                            make_error(ErrorCode::IntegrityFailure,
                                       "candidate cannot be quarantined",
                                       identifier));
                    }
                    auto copied =
                        history_storage::maintenance_protocol::copy_verified(
                            storage,
                            identifier,
                            *quarantine_identifier,
                            workspace_root);
                    if (!copied) {
                        return std::unexpected(protocol_error(copied.error()));
                    }
                    auto recorded = history_storage::maintenance_protocol::
                        record_quarantine(storage,
                                          *quarantine_identifier,
                                          *now,
                                          key,
                                          workspace_root,
                                          *copied);
                    if (!recorded) {
                        return std::unexpected(
                            protocol_error(recorded.error()));
                    }
                    owned = history_storage::maintenance_protocol::
                        verify_registration(*barrier);
                    if (!owned) {
                        return std::unexpected(protocol_error(owned.error()));
                    }
                    auto removed = transport::remove(storage, identifier);
                    if (!removed) {
                        return std::unexpected(
                            transport_error(removed.error(), identifier));
                    }
                    if (*removed == transport::Removal::Removed) {
                        ++result.quarantined_objects;
                    }
                }
                return result;
            } catch (const std::exception& exception) {
                return std::unexpected(
                    make_error(ErrorCode::StateFailure, exception.what()));
            }
        }();
        auto released =
            history_storage::maintenance_protocol::release_registration(
                *barrier);
        if (!outcome) {
            return outcome;
        }
        if (!released) {
            return std::unexpected(protocol_error(released.error()));
        }
        return outcome;
    } catch (const std::exception& exception) {
        return std::unexpected(
            make_error(ErrorCode::StateFailure, exception.what()));
    }
}

} // namespace kasumi::application::integrity
