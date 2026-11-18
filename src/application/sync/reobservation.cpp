#include "application/sync/reobservation.hpp"

#include "application/observation/file_metadata.hpp"
#include "application/observation/state.hpp"
#include "application/sync/coordinator_detail.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/mutation.hpp"
#include "application/sync/mutation_fault_test.hpp"
#include "core/reconciliation/plan.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/key_derivation.hpp"
#include "platform/metadata.hpp"
#include "platform/path.hpp"
#include "platform/workspace.hpp"

#include <algorithm>
#include <cstddef>
#include <exception>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace kasumi::application::sync::coordinator::reobservation {
namespace {

inline constexpr std::size_t maximum_observation_attempts = 3;

bool same_snapshot(const Snapshot& left, const Snapshot& right) noexcept {
    if (left.rows.size() != right.rows.size()) {
        return false;
    }
    for (std::size_t index = 0; index < left.rows.size(); ++index) {
        const auto& a = left.rows[index];
        const auto& b = right.rows[index];
        if (a.path != b.path || a.hash != b.hash || a.size != b.size ||
            (!a.is_directory && a.mtime != b.mtime) ||
            a.is_directory != b.is_directory) {
            return false;
        }
    }
    return true;
}

std::vector<std::string> normalized_ids(const std::vector<std::string>& ids) {
    auto result = ids;
    std::ranges::sort(result);
    result.erase(std::ranges::unique(result).begin(), result.end());
    return result;
}

bool same_storage(const reconciliation::StorageState& left,
                  const reconciliation::StorageState& right) {
    return same_snapshot(left.tree, right.tree) &&
           normalized_ids(left.logical_heads) ==
               normalized_ids(right.logical_heads) &&
           normalized_ids(left.marked_head_identifiers) ==
               normalized_ids(right.marked_head_identifiers) &&
           left.history_present == right.history_present &&
           left.epoch_vault_id == right.epoch_vault_id &&
           left.epoch_id == right.epoch_id &&
           left.epoch_sequence == right.epoch_sequence &&
           left.epoch_policy == right.epoch_policy &&
           left.epoch_anchors == right.epoch_anchors &&
           left.generation == right.generation &&
           left.history_has_conflicts == right.history_has_conflicts &&
           left.storage_manifest == right.storage_manifest &&
           normalized_ids(left.reachable_commit_ids) ==
               normalized_ids(right.reachable_commit_ids);
}

bool same_rows(std::span<const NodeRow> left,
               std::span<const NodeRow> right) noexcept {
    return left.size() == right.size() && std::ranges::equal(left, right);
}

std::expected<bool, Error>
verify_existing_content(transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        const Hash& hash,
                        std::uint64_t size,
                        const platform::Workspace& workspace,
                        std::size_t index) {
    const auto encrypted =
        platform::workspace_file(workspace, index, ".initial.enc");
    const auto plaintext =
        platform::workspace_file(workspace, index, ".initial.plain");
    struct TempFileCleanup {
        const std::filesystem::path& encrypted;
        const std::filesystem::path& plaintext;
        ~TempFileCleanup() noexcept {
            std::error_code ignored;
            std::filesystem::remove(encrypted, ignored);
            std::filesystem::remove(plaintext, ignored);
        }
    } temp_cleanup{encrypted, plaintext};
    const auto identifier = crypto::content_identifier(key, hash);
    auto downloaded = transport::get(storage, identifier, encrypted);
    if (!downloaded) {
        if (downloaded.error().code == transport::ErrorCode::ObjectNotFound) {
            return false;
        }
        return std::unexpected(
            detail::make_error(ErrorCode::ObservationFailure,
                               transport::describe(downloaded.error())));
    }
    if (!crypto::decrypt_file(encrypted, plaintext, key)) {
        return false;
    }
    std::error_code error;
    const auto status = std::filesystem::symlink_status(plaintext, error);
    if (error) {
        return std::unexpected(detail::make_error(
            ErrorCode::ObservationFailure,
            "could not inspect downloaded Content: " + error.message()));
    }
    if (!std::filesystem::is_regular_file(status)) {
        return false;
    }
    const auto actual_size = std::filesystem::file_size(plaintext, error);
    if (error) {
        return std::unexpected(detail::make_error(
            ErrorCode::ObservationFailure,
            "could not read downloaded Content size: " + error.message()));
    }
    if (actual_size != size) {
        return false;
    }
    const auto actual_hash = crypto::content::hash_file(plaintext);
    if (!actual_hash) {
        return std::unexpected(detail::make_error(ErrorCode::ObservationFailure,
                                                  actual_hash.error()));
    }
    return *actual_hash == hash;
}

std::expected<void, Error> observe_content_availability(
    reconciliation::Input& input,
    const reconciliation::Result& result,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    std::span<const Hash> confirmed_missing,
    bool allow_unreferenced_content_reuse,
    bool trust_existing_content = false,
    const std::unordered_set<std::string>* initial_content_identifiers =
        nullptr) {
    HashSet hashes{0, hash_key};
    std::unordered_map<Hash, std::uint64_t, decltype(&hash_key)> upload_sizes{
        0, hash_key};
    std::unordered_set<std::string> upload_identities;
    std::unordered_map<std::string, std::size_t> relocated_delete_counts;
    if (input.base_state_present && input.storage.history_present &&
        !allow_unreferenced_content_reuse) {
        for (const auto& base_row : input.base_tree.rows) {
            if (base_row.is_directory) {
                continue;
            }
            const auto* remote_row =
                find_row(input.storage.tree, base_row.path);
            const auto* candidate_row =
                find_row(result.candidate_shared_tree, base_row.path);
            if (remote_row != nullptr && !remote_row->is_directory &&
                remote_row->hash == base_row.hash &&
                remote_row->size == base_row.size &&
                !input.known_missing_content_objects.contains(
                    remote_row->hash) &&
                (candidate_row == nullptr || candidate_row->is_directory ||
                 candidate_row->hash != base_row.hash ||
                 candidate_row->size != base_row.size)) {
                ++relocated_delete_counts[hash_hex(remote_row->hash) + ':' +
                                          std::to_string(remote_row->size)];
            }
        }
    }
    const auto add_hash = [&](const Hash& hash) {
        hashes.insert(hash);
    };

    for (const auto& candidate : sync_plan_operations(result.plan)) {
        if (candidate.action == Action::Upload) {
            if (const auto hash = hash_from_hex(candidate.hash)) {
                if (allow_unreferenced_content_reuse) {
                    upload_sizes.emplace(*hash, candidate.size);
                    add_hash(*hash);
                } else {
                    const auto identity =
                        hash_hex(*hash) + ':' + std::to_string(candidate.size);
                    if (const auto relocated =
                            relocated_delete_counts.find(identity);
                        relocated != relocated_delete_counts.end() &&
                        relocated->second > 0) {
                        --relocated->second;
                    } else {
                        upload_identities.insert(identity);
                    }
                }
            }
        } else if (candidate.action == Action::Download ||
                   candidate.action == Action::CopyLocal) {
            if (const auto hash = hash_from_hex(candidate.hash)) {
                add_hash(*hash);
            }
        }
    }
    input.verified_remote_content_objects.clear();
    input.trusted_remote_content_objects.clear();

    // Probe a known object only when an Upload would be elided because another
    // accepted row already references the same Content identity.
    if (input.storage.history_present && !upload_identities.empty()) {
        for (const auto& row : input.storage.tree.rows) {
            if (!row.is_directory &&
                upload_identities.contains(hash_hex(row.hash) + ':' +
                                           std::to_string(row.size))) {
                add_hash(row.hash);
            }
        }
    }
    const auto add_relevant_pending = [&](std::span<const NodeRow> rows) {
        for (const auto& row : rows) {
            if (const auto* remote = find_row(input.storage.tree, row.path);
                remote != nullptr && !remote->is_directory &&
                remote->hash == row.hash && remote->size == row.size) {
                const auto* local = find_row(input.local_tree, row.path);
                if (local == nullptr ||
                    (!local->is_directory && local->hash == row.hash)) {
                    add_hash(remote->hash);
                }
            }
        }
    };
    add_relevant_pending(input.pending_materializations);
    add_relevant_pending(input.pending_deletion_authority);
    add_relevant_pending(result.pending_materializations);
    add_relevant_pending(result.pending_storage_rows);

    if (allow_unreferenced_content_reuse && trust_existing_content &&
        initial_content_identifiers != nullptr &&
        !input.audit_storage_objects) {
        for (auto it = upload_sizes.begin(); it != upload_sizes.end();) {
            const auto identifier = crypto::content_identifier(key, it->first);
            if (initial_content_identifiers->contains(identifier)) {
                input.trusted_remote_content_objects.insert(
                    hash_hex(it->first) + ':' + std::to_string(it->second));
                hashes.erase(it->first);
                it = upload_sizes.erase(it);
            } else {
                ++it;
            }
        }
    }

    if (hashes.empty()) {
        input.known_missing_content_objects.clear();
        input.known_missing_content_objects.insert(confirmed_missing.begin(),
                                                   confirmed_missing.end());
        return {};
    }
    platform::Workspace reuse_workspace;
    struct WorkspaceCleanup {
        platform::Workspace& workspace;
        ~WorkspaceCleanup() {
            platform::cleanup_workspace(workspace);
        }
    } cleanup{reuse_workspace};
    struct LogicalProbe {
        Hash hash{};
        std::vector<std::string> physical_ids;
    };
    std::vector<LogicalProbe> logical_probes;
    logical_probes.reserve(hashes.size());
    std::vector<std::string> requested_physical;
    requested_physical.reserve(hashes.size());
    bool has_chunked_probe = false;
    for (const auto& hash : hashes) {
        LogicalProbe probe{.hash = hash, .physical_ids = {}};
        if (const auto* packed = history::find_packed_blob(
                input.storage.storage_manifest, hash)) {
            probe.physical_ids.push_back(
                crypto::pack_identifier(key, packed->pack_hash));
        } else if (const auto* chunked = history::find_chunked_file(
                       input.storage.storage_manifest, hash)) {
            has_chunked_probe = true;
            probe.physical_ids.reserve(chunked->chunks.size());
            for (const auto& chunk : chunked->chunks) {
                probe.physical_ids.push_back(
                    crypto::content_identifier(key, chunk.hash));
            }
        } else {
            probe.physical_ids.push_back(crypto::content_identifier(key, hash));
        }
        for (const auto& phys : probe.physical_ids) {
            requested_physical.push_back(phys);
        }
        logical_probes.push_back(std::move(probe));
    }
    std::ranges::sort(requested_physical);
    requested_physical.erase(std::ranges::unique(requested_physical).begin(),
                             requested_physical.end());

    std::vector<transport::Presence> presences;
    bool probed = false;
    if (has_chunked_probe && requested_physical.size() >= 8U &&
        storage.storage.list != nullptr) {
        if (auto listed = transport::list(storage)) {
            const std::unordered_set<std::string> remote_set(listed->begin(),
                                                             listed->end());
            presences.reserve(requested_physical.size());
            for (const auto& id : requested_physical) {
                presences.push_back(remote_set.contains(id)
                                        ? transport::Presence::Present
                                        : transport::Presence::Absent);
            }
            probed = true;
        }
    }
    if (!probed && storage.storage.control_read_batch != nullptr) {
        transport::ControlReadBatchRequest request;
        request.presence_identifiers = requested_physical;
        auto batch = transport::control_read_batch(storage, request);
        if (batch) {
            if (batch->presences.size() != requested_physical.size()) {
                return std::unexpected(detail::make_error(
                    ErrorCode::ObservationFailure,
                    "presence batch returned an invalid result count"));
            }
            presences = std::move(batch->presences);
            probed = true;
        } else if (batch.error().code != transport::ErrorCode::Unsupported) {
            return std::unexpected(
                detail::make_error(ErrorCode::ObservationFailure,
                                   transport::describe(batch.error())));
        }
    }
    if (!probed) {
        if (storage.storage.presence == nullptr) {
            return std::unexpected(detail::make_error(
                ErrorCode::ObservationFailure,
                "transport cannot verify required content availability"));
        }
        presences.reserve(requested_physical.size());
        for (const auto& identifier : requested_physical) {
            auto observed = transport::presence(storage, identifier);
            if (!observed) {
                return std::unexpected(
                    detail::make_error(ErrorCode::ObservationFailure,
                                       transport::describe(observed.error())));
            }
            presences.push_back(*observed);
        }
    }

    std::unordered_map<std::string_view, bool> physical_present;
    physical_present.reserve(requested_physical.size());
    for (std::size_t i = 0; i < requested_physical.size(); ++i) {
        physical_present.emplace(
            requested_physical[i],
            presences[i] == transport::Presence::Present);
    }

    const bool inventory_available = input.audit_storage_objects;
    std::vector<Hash> missing;
    HashSet absent_packs{0, hash_key};
    missing.reserve(logical_probes.size());
    for (std::size_t index = 0; index < logical_probes.size(); ++index) {
        const auto& [hash, phys_ids] = logical_probes[index];
        const bool present =
            std::ranges::all_of(phys_ids, [&](const std::string& phys_id) {
                return physical_present.at(phys_id);
            });
        if (inventory_available) {
            const bool listed =
                std::ranges::all_of(
                    phys_ids,
                    [&](const std::string& phys_id) {
                        return input.storage.object_identifiers.contains(
                            phys_id);
                    }) ||
                input.storage.object_identifiers.contains(hash_hex(hash));
            if (listed != present) {
                return std::unexpected(detail::make_error(
                    ErrorCode::ObservationFailure,
                    "content availability disagreement for " +
                        phys_ids.front() + ": LIST says " +
                        (listed ? "present" : "absent") + ", PRESENCE says " +
                        (present ? "present" : "absent")));
            }
        }
        const auto upload_it = upload_sizes.find(hash);
        if (allow_unreferenced_content_reuse && present &&
            upload_it != upload_sizes.end()) {
            const auto identity =
                hash_hex(hash) + ':' + std::to_string(upload_it->second);
            if (trust_existing_content) {
                input.trusted_remote_content_objects.insert(identity);
                continue;
            }
            if (reuse_workspace.root.empty()) {
                auto created =
                    platform::create_workspace("sync-initial-content");
                if (!created) {
                    return std::unexpected(detail::make_error(
                        ErrorCode::ObservationFailure, created.error()));
                }
                reuse_workspace = std::move(*created);
            }
            const auto verified = verify_existing_content(
                storage, key, hash, upload_it->second, reuse_workspace, index);
            if (!verified) {
                return std::unexpected(verified.error());
            }
            if (*verified) {
                input.verified_remote_content_objects.insert(identity);
                continue;
            }
        }
        if (!present) {
            if (const auto* packed = history::find_packed_blob(
                    input.storage.storage_manifest, hash)) {
                absent_packs.insert(packed->pack_hash);
            }
        }
        if (!present || upload_it != upload_sizes.end()) {
            missing.push_back(hash);
        }
    }
    if (!absent_packs.empty()) {
        for (const auto& member : input.storage.storage_manifest.packed_blobs) {
            if (absent_packs.contains(member.pack_hash)) {
                missing.push_back(member.blob_hash);
            }
        }
    }
    // Replace the set only after every requested identifier has been
    // classified successfully; an error or disagreement leaves the input
    // unchanged for the caller's fail-closed path.
    input.known_missing_content_objects.clear();
    input.known_missing_content_objects.insert(confirmed_missing.begin(),
                                               confirmed_missing.end());
    input.known_missing_content_objects.insert(missing.begin(), missing.end());
    return {};
}

std::expected<void, Error>
stage_attempt(const runtime::RuntimeData& runtime_data,
              const reconciliation::Input& input,
              const reconciliation::Result& result,
              const std::filesystem::path& profile,
              std::span<const std::uint8_t, crypto::KEY_SIZE> key,
              std::optional<platform::Workspace>& workspace,
              std::string& out_operation_id,
              std::vector<transaction::OperationProgress>& out_progress) {
    auto record = journal::create_record(
        input.local_generation,
        input.storage.generation,
        result.plan,
        result.requires_publication,
        result.requires_publication ? std::string{}
                                    : input.storage.logical_heads.front());
    if (!record) {
        return std::unexpected(detail::journal_error(record.error()));
    }
    auto created = detail::create_transaction_workspace(
        profile, record->operation_id, key);
    if (!created) {
        return std::unexpected(created.error());
    }
    workspace = *created;

    for (std::size_t index = 0; index < record->plan.operations.size();
         ++index) {
        auto prepared =
            mutation::prepare_operation(record->plan.operations[index],
                                        index,
                                        runtime_data.local_dir,
                                        *workspace,
                                        record->progress[index],
                                        record->plan.operations);
        if (!prepared) {
            return std::unexpected(
                detail::make_error(ErrorCode::MutationFailure,
                                   mutation::describe(prepared.error()),
                                   index));
        }
        record->progress[index] = *prepared;
    }
    out_operation_id = std::move(record->operation_id);
    out_progress = std::move(record->progress);
    return {};
}

} // namespace

bool same_observation(const reconciliation::Input& left,
                      const reconciliation::Input& right) noexcept {
    return same_snapshot(left.local_tree, right.local_tree) &&
           same_rows(left.pending_materializations,
                     right.pending_materializations) &&
           same_rows(left.pending_deletion_authority,
                     right.pending_deletion_authority) &&
           left.known_missing_content_objects ==
               right.known_missing_content_objects &&
           left.verified_remote_content_objects ==
               right.verified_remote_content_objects &&
           left.trusted_remote_content_objects ==
               right.trusted_remote_content_objects &&
           same_snapshot(left.base_tree, right.base_tree) &&
           left.base_commit_id == right.base_commit_id &&
           left.base_state_present == right.base_state_present &&
           left.local_generation == right.local_generation &&
           left.audit_storage_objects == right.audit_storage_objects &&
           left.ignore_list == right.ignore_list &&
           same_storage(left.storage, right.storage);
}

std::expected<bool, coordinator::Error> verify_destructive_local_operations(
    const runtime::RuntimeData& runtime_data,
    reconciliation::Input& input,
    const reconciliation::Result& result,
    observation::LocalObservationSession* session) {
    bool modified = false;
    for (const auto& op : sync_plan_operations(result.plan)) {
        if (op.action != Action::DeleteLocal && op.action != Action::Download &&
            op.action != Action::RenameLocal &&
            op.action != Action::MoveLocal && op.action != Action::CopyLocal) {
            continue;
        }

        const auto verify_target = [&](const std::filesystem::path& rel_path,
                                       bool is_destination)
            -> std::expected<void, coordinator::Error> {
            if (rel_path.empty()) {
                return {};
            }
            const auto local_path = runtime_data.local_dir / rel_path;
            const auto logical_path = platform::path::to_logical_utf8(rel_path);

            auto pre_meta = observation::cache::read_file_metadata(
                local_path, logical_path);
            if (!pre_meta) {
                if (pre_meta.error().code ==
                    observation::cache::FileMetadataErrorCode::NotFound) {
                    if (is_destination) {
                        return {};
                    }
                    auto* local_row = find_row(input.local_tree, logical_path);
                    if (local_row != nullptr) {
                        return std::unexpected(detail::make_error(
                            ErrorCode::ObservationFailure,
                            "destructive target disappeared concurrently: " +
                                local_path.string()));
                    }
                    if (op.action == Action::Download) {
                        return {};
                    }
                    return std::unexpected(detail::make_error(
                        ErrorCode::ObservationFailure,
                        "destructive target missing from snapshot: " +
                            local_path.string()));
                }
                return std::unexpected(detail::make_error(
                    ErrorCode::ObservationFailure,
                    "failed to read metadata for destructive target: " +
                        pre_meta.error().message));
            }

            auto* local_row = find_row(input.local_tree, logical_path);
            if (is_destination || local_row == nullptr) {
                return std::unexpected(detail::make_error(
                    ErrorCode::ObservationFailure,
                    is_destination
                        ? "rename destination already exists: " +
                              local_path.string()
                        : "destructive destination already exists: " +
                              local_path.string()));
            }

            if (local_row->is_directory || !*pre_meta) {
                return std::unexpected(detail::make_error(
                    ErrorCode::ObservationFailure,
                    "destructive target replaced by non-regular file: " +
                        local_path.string()));
            }

            auto actual_hash = crypto::content::hash_file(local_path);
            if (!actual_hash) {
                return std::unexpected(detail::make_error(
                    ErrorCode::ObservationFailure,
                    "failed to compute hash for destructive target: " +
                        local_path.string()));
            }

            auto post_meta = observation::cache::read_file_metadata(
                local_path, logical_path);
            if (!post_meta || !*post_meta ||
                (*pre_meta)->size != (*post_meta)->size ||
                (*pre_meta)->mtime_nanoseconds !=
                    (*post_meta)->mtime_nanoseconds ||
                (*pre_meta)->identity != (*post_meta)->identity) {
                return std::unexpected(
                    detail::make_error(ErrorCode::ObservationFailure,
                                       "file changed while being read"));
            }

            if (local_row->hash != *actual_hash) {
                local_row->hash = *actual_hash;
                local_row->size = (*post_meta)->size;
                local_row->mtime = (*post_meta)->mtime_nanoseconds;
                if (session != nullptr) {
                    std::erase_if(session->cache, [&](const auto& row) {
                        return row.path == logical_path;
                    });
                    session->cache_dirty = true;
                }
                modified = true;
            }
            return {};
        };

        auto verified_source = verify_target(op.path, false);
        if (!verified_source) {
            return std::unexpected(verified_source.error());
        }
        if ((op.action == Action::RenameLocal ||
             op.action == Action::MoveLocal ||
             op.action == Action::CopyLocal) &&
            !op.alt_path.empty()) {
            auto verified_dest = verify_target(op.alt_path, true);
            if (!verified_dest) {
                return std::unexpected(verified_dest.error());
            }
        }
    }
    return modified;
}

std::expected<reconciliation::Result, coordinator::Error>
refresh_content_availability(
    reconciliation::Input& input,
    const reconciliation::Result& reconciliation_result,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    std::span<const Hash> confirmed_missing,
    bool allow_unreferenced_content_reuse,
    bool trust_existing_content,
    const std::unordered_set<std::string>* initial_content_identifiers) {
    auto availability =
        observe_content_availability(input,
                                     reconciliation_result,
                                     storage,
                                     key,
                                     confirmed_missing,
                                     allow_unreferenced_content_reuse,
                                     trust_existing_content,
                                     initial_content_identifiers);
    if (!availability) {
        return std::unexpected(availability.error());
    }
    auto available_result = reconciliation::reconcile(input);
    if (!available_result) {
        return std::unexpected(detail::make_error(
            ErrorCode::ObservationFailure, available_result.error().detail));
    }
    return std::move(*available_result);
}

std::expected<StableExecution, coordinator::Error>
stabilize(const runtime::RuntimeData& runtime_data,
          transport::Transport& storage,
          std::span<const std::uint8_t, crypto::KEY_SIZE> key,
          reconciliation::Input observed_input,
          reconciliation::Result reconciliation_result,
          observation::LocalObservationSession* session,
          std::span<const Hash> confirmed_missing,
          bool content_availability_is_current,
          bool allow_unreferenced_content_reuse,
          bool trust_existing_content,
          const std::unordered_set<std::string>* initial_content_identifiers,
          bool retain_staged_workspace) {
    const auto no_work = [](const reconciliation::Result& candidate) {
        return !candidate.requires_publication &&
               !candidate.requires_local_mutation &&
               !candidate.requires_storage_repair &&
               !candidate.requires_state_commit;
    };
    const auto concurrent_trust_error = []() {
        return detail::make_error(
            ErrorCode::ConcurrentModification,
            "remote history was published concurrently during initial sync "
            "with --trust-existing-content; operation was rejected to prevent "
            "unverified content reuse");
    };
    const auto reconcile_and_refresh =
        [&](reconciliation::Input& target,
            bool allow_reuse) -> std::expected<reconciliation::Result, Error> {
        auto recalculated = reconciliation::reconcile(target);
        if (!recalculated) {
            return std::unexpected(detail::make_error(
                ErrorCode::ObservationFailure, recalculated.error().detail));
        }
        return refresh_content_availability(target,
                                            *recalculated,
                                            storage,
                                            key,
                                            confirmed_missing,
                                            allow_reuse,
                                            trust_existing_content,
                                            initial_content_identifiers);
    };

    if (trust_existing_content && observed_input.storage.history_present) {
        return std::unexpected(concurrent_trust_error());
    }

    if (!content_availability_is_current) {
        auto available =
            refresh_content_availability(observed_input,
                                         reconciliation_result,
                                         storage,
                                         key,
                                         confirmed_missing,
                                         allow_unreferenced_content_reuse,
                                         trust_existing_content,
                                         initial_content_identifiers);
        if (!available) {
            return std::unexpected(available.error());
        }
        reconciliation_result = std::move(*available);
    }

    if (no_work(reconciliation_result)) {
        return StableExecution{.input = std::move(observed_input),
                               .result = std::move(reconciliation_result)};
    }

    auto profile = detail::profile_directory(runtime_data);
    if (!profile) {
        return std::unexpected(profile.error());
    }

    auto input = std::move(observed_input);
    auto result = std::move(reconciliation_result);
    for (std::size_t attempt = 0; attempt < maximum_observation_attempts;
         ++attempt) {
        std::size_t verification_pass = 0;
        while (true) {
            auto verification = verify_destructive_local_operations(
                runtime_data, input, result, session);
            if (!verification) {
                return std::unexpected(verification.error());
            }
            if (!*verification) {
                break;
            }
            ++verification_pass;
            if (verification_pass >= maximum_observation_attempts) {
                return std::unexpected(detail::make_error(
                    ErrorCode::ConcurrentModification,
                    "state changed repeatedly before publication"));
            }
            auto refreshed =
                reconcile_and_refresh(input, allow_unreferenced_content_reuse);
            if (!refreshed) {
                return std::unexpected(refreshed.error());
            }
            result = std::move(*refreshed);
            if (no_work(result)) {
                return StableExecution{.input = std::move(input),
                                       .result = std::move(result)};
            }
        }

        std::optional<platform::Workspace> workspace;
        std::string staged_operation_id;
        std::vector<transaction::OperationProgress> staged_progress;
        const auto fail_with_cleanup =
            [&](Error err) -> std::expected<StableExecution, Error> {
            if (auto removed =
                    detail::remove_transaction_workspace(workspace, key);
                !removed) {
                return std::unexpected(removed.error());
            }
            return std::unexpected(std::move(err));
        };
        if (!result.plan.operations.empty()) {
            auto staged = stage_attempt(runtime_data,
                                        input,
                                        result,
                                        *profile,
                                        key,
                                        workspace,
                                        staged_operation_id,
                                        staged_progress);
            if (!staged) {
                return fail_with_cleanup(staged.error());
            }
        }

        auto observed = observation::collect_reconciliation_input(
            runtime_data,
            storage,
            key,
            input.audit_storage_objects,
            input.storage.marked_head_identifiers,
            session);
        if (!observed) {
            if (observed.error().code ==
                    reconciliation::ErrorCode::InvalidLocalTree &&
                observed.error().detail.ends_with(
                    "file changed while being read")) {
                if (auto removed =
                        detail::remove_transaction_workspace(workspace, key);
                    !removed) {
                    return std::unexpected(removed.error());
                }
                if (attempt + 1 == maximum_observation_attempts) {
                    return std::unexpected(detail::make_error(
                        ErrorCode::ConcurrentModification,
                        "state changed repeatedly before publication"));
                }
                continue;
            }
            return fail_with_cleanup(detail::make_error(
                ErrorCode::ObservationFailure, observed.error().detail));
        }
        if (trust_existing_content && observed->storage.history_present) {
            return fail_with_cleanup(concurrent_trust_error());
        }
        observed->pending_deletion_authority = input.pending_deletion_authority;
        mutation_fault_test::hit("before_final_local_observation",
                                 runtime_data.local_dir);
        auto local_after_storage = observation::collect_local_observation(
            runtime_data.local_dir, session, observed->ignore_list);
        if (!local_after_storage) {
            return fail_with_cleanup(detail::make_error(
                ErrorCode::ObservationFailure, local_after_storage.error()));
        }
        if (!same_snapshot(observed->local_tree,
                           local_after_storage->snapshot) ||
            observed->local_physical_evidence !=
                local_after_storage->physical_evidence) {
            observed->local_tree = std::move(local_after_storage->snapshot);
            observed->local_physical_evidence =
                std::move(local_after_storage->physical_evidence);
        }
        auto refreshed =
            reconcile_and_refresh(*observed,
                                  allow_unreferenced_content_reuse &&
                                      !observed->storage.history_present);
        if (!refreshed) {
            return fail_with_cleanup(refreshed.error());
        }
        if (same_observation(input, *observed)) {
            if (retain_staged_workspace && workspace.has_value()) {
                return StableExecution{
                    .input = std::move(*observed),
                    .result = std::move(*refreshed),
                    .staged = StagedExecutionHandoff{
                        .operation_id = std::move(staged_operation_id),
                        .progress = std::move(staged_progress),
                        .workspace = std::move(workspace)}};
            }
            if (auto removed =
                    detail::remove_transaction_workspace(workspace, key);
                !removed) {
                return std::unexpected(removed.error());
            }
            return StableExecution{.input = std::move(*observed),
                                   .result = std::move(*refreshed)};
        }
        if (auto removed = detail::remove_transaction_workspace(workspace, key);
            !removed) {
            return std::unexpected(removed.error());
        }

        if (attempt + 1 == maximum_observation_attempts) {
            return std::unexpected(detail::make_error(
                ErrorCode::ConcurrentModification,
                "state changed repeatedly before publication"));
        }
        input = std::move(*observed);
        result = std::move(*refreshed);
    }

    return std::unexpected(
        detail::make_error(ErrorCode::ConcurrentModification,
                           "state changed repeatedly before publication"));
}

} // namespace kasumi::application::sync::coordinator::reobservation
