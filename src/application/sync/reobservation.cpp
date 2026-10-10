#include "application/sync/reobservation.hpp"

#include "application/observation/file_metadata.hpp"
#include "application/observation/state.hpp"
#include "application/sync/coordinator_detail.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/mutation.hpp"
#include "core/reconciliation/plan.hpp"
#include "crypto/content.hpp"
#include "crypto/key_derivation.hpp"
#include "platform/metadata.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"

#include <algorithm>
#include <cstddef>
#include <exception>
#include <filesystem>
#include <string>
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
           normalized_ids(left.reachable_commit_ids) ==
               normalized_ids(right.reachable_commit_ids);
}

bool same_rows(std::span<const NodeRow> left,
               std::span<const NodeRow> right) noexcept {
    return left.size() == right.size() && std::ranges::equal(left, right);
}

std::expected<void, Error> observe_content_availability(
    reconciliation::Input& input,
    const reconciliation::Result& result,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    std::span<const Hash> confirmed_missing) {
    HashSet hashes{0, hash_key};
    const auto add_hash = [&](const Hash& hash) {
        hashes.insert(hash);
    };
    for (const auto& operation : sync_plan_operations(result.plan)) {
        if (operation.action == Action::Download) {
            if (const auto hash = hash_from_hex(operation.hash)) {
                add_hash(*hash);
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

    input.known_missing_content_objects.clear();
    input.known_missing_content_objects.insert(confirmed_missing.begin(),
                                               confirmed_missing.end());
    if (hashes.empty()) {
        return {};
    }
    std::vector<std::pair<Hash, std::string>> requested;
    requested.reserve(hashes.size());
    for (const auto& hash : hashes) {
        requested.emplace_back(hash, crypto::content_identifier(key, hash));
    }
    std::ranges::sort(requested, {}, [](const auto& item) {
        return item.second;
    });
    platform::perf_trace::count("sync content presence requests",
                                requested.size());

    std::vector<transport::Presence> presences;
    if (storage.storage.control_read_batch != nullptr) {
        transport::ControlReadBatchRequest request;
        request.presence_identifiers.reserve(requested.size());
        for (const auto& [hash, identifier] : requested) {
            request.presence_identifiers.push_back(identifier);
        }
        auto batch = transport::control_read_batch(storage, request);
        if (batch) {
            if (batch->presences.size() != requested.size()) {
                return std::unexpected(detail::make_error(
                    ErrorCode::ObservationFailure,
                    "presence batch returned an invalid result count"));
            }
            presences = std::move(batch->presences);
        } else if (batch.error().code != transport::ErrorCode::Unsupported) {
            return std::unexpected(
                detail::make_error(ErrorCode::ObservationFailure,
                                   transport::describe(batch.error())));
        }
    }
    if (presences.empty() && storage.storage.presence != nullptr) {
        presences.reserve(requested.size());
        for (const auto& [hash, identifier] : requested) {
            auto observed = transport::presence(storage, identifier);
            if (!observed) {
                if (observed.error().code ==
                    transport::ErrorCode::Unsupported) {
                    presences.clear();
                    break;
                }
                return std::unexpected(
                    detail::make_error(ErrorCode::ObservationFailure,
                                       transport::describe(observed.error())));
            }
            presences.push_back(*observed);
        }
    }
    if (presences.empty()) {
        return {}; // No probe capability: the verified GET remains
                   // authoritative.
    }
    for (std::size_t index = 0; index < requested.size(); ++index) {
        if (presences[index] == transport::Presence::Absent) {
            input.known_missing_content_objects.insert(requested[index].first);
        }
    }
    return {};
}

std::expected<void, Error>
stage_attempt(const runtime::RuntimeData& runtime_data,
              const reconciliation::Input& input,
              const reconciliation::Result& result,
              const std::filesystem::path& profile,
              std::optional<platform::Workspace>& workspace) {
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
    auto created =
        detail::create_transaction_workspace(profile, record->operation_id);
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
           same_snapshot(left.base_tree, right.base_tree) &&
           left.base_commit_id == right.base_commit_id &&
           left.base_state_present == right.base_state_present &&
           left.local_generation == right.local_generation &&
           left.audit_storage_objects == right.audit_storage_objects &&
           left.ignore_list == right.ignore_list &&
           same_storage(left.storage, right.storage);
}

std::expected<bool, coordinator::Error>
verify_destructive_local_operations(
    const runtime::RuntimeData& runtime_data,
    reconciliation::Input& input,
    const reconciliation::Result& result,
    observation::LocalObservationSession* session) {
    bool modified = false;
    for (const auto& op : sync_plan_operations(result.plan)) {
        if (op.action != Action::DeleteLocal &&
            op.action != Action::Download &&
            op.action != Action::RenameLocal) {
            continue;
        }

        const auto verify_target = [&](const std::filesystem::path& rel_path)
            -> std::expected<void, coordinator::Error> {
            if (rel_path.empty()) {
                return {};
            }
            const auto local_path = runtime_data.local_dir / rel_path;
            const auto logical_path = platform::path::to_logical_utf8(rel_path);

            auto pre_meta =
                observation::cache::read_file_metadata(local_path, logical_path);
            if (!pre_meta) {
                if (pre_meta.error().code ==
                    observation::cache::FileMetadataErrorCode::NotFound) {
                    return {};
                }
                return std::unexpected(detail::make_error(
                    ErrorCode::ObservationFailure,
                    "failed to read metadata for destructive target: " +
                        pre_meta.error().message));
            }
            if (!*pre_meta) {
                return {};
            }

            auto* local_row = find_row(input.local_tree, logical_path);
            if (local_row == nullptr || local_row->is_directory) {
                return {};
            }

            auto actual_hash = crypto::content::hash_file(local_path);
            if (!actual_hash) {
                return std::unexpected(detail::make_error(
                    ErrorCode::ObservationFailure,
                    "failed to compute hash for destructive target: " +
                        local_path.string()));
            }

            auto post_meta =
                observation::cache::read_file_metadata(local_path, logical_path);
            if (!post_meta || !*post_meta ||
                (*pre_meta)->size != (*post_meta)->size ||
                (*pre_meta)->mtime_nanoseconds !=
                    (*post_meta)->mtime_nanoseconds ||
                (*pre_meta)->identity != (*post_meta)->identity) {
                return std::unexpected(detail::make_error(
                    ErrorCode::ObservationFailure,
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

        auto verified_source = verify_target(op.path);
        if (!verified_source) {
            return std::unexpected(verified_source.error());
        }
        if (op.action == Action::RenameLocal && !op.alt_path.empty()) {
            auto verified_dest = verify_target(op.alt_path);
            if (!verified_dest) {
                return std::unexpected(verified_dest.error());
            }
        }
    }
    return modified;
}

std::expected<StableExecution, coordinator::Error>
stabilize(const runtime::RuntimeData& runtime_data,
          transport::Transport& storage,
          std::span<const std::uint8_t, crypto::KEY_SIZE> key,
          reconciliation::Input observed_input,
          reconciliation::Result reconciliation_result,
          observation::LocalObservationSession* session,
          std::span<const Hash> confirmed_missing) {
    auto availability = observe_content_availability(
        observed_input, reconciliation_result, storage, key, confirmed_missing);
    if (!availability) {
        return std::unexpected(availability.error());
    }
    auto available_result = reconciliation::reconcile(observed_input);
    if (!available_result) {
        return std::unexpected(detail::make_error(
            ErrorCode::ObservationFailure, available_result.error().detail));
    }
    reconciliation_result = std::move(*available_result);

    if (!reconciliation_result.requires_publication &&
        !reconciliation_result.requires_local_mutation &&
        !reconciliation_result.requires_storage_repair &&
        !reconciliation_result.requires_state_commit) {
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
            auto recalculated = reconciliation::reconcile(input);
            if (!recalculated) {
                return std::unexpected(detail::make_error(
                    ErrorCode::ObservationFailure, recalculated.error().detail));
            }
            auto reobserved_availability = observe_content_availability(
                input, *recalculated, storage, key, confirmed_missing);
            if (!reobserved_availability) {
                return std::unexpected(reobserved_availability.error());
            }
            recalculated = reconciliation::reconcile(input);
            if (!recalculated) {
                return std::unexpected(detail::make_error(
                    ErrorCode::ObservationFailure, recalculated.error().detail));
            }
            result = std::move(*recalculated);
            if (!result.requires_publication &&
                !result.requires_local_mutation &&
                !result.requires_storage_repair &&
                !result.requires_state_commit) {
                return StableExecution{.input = std::move(input),
                                       .result = std::move(result)};
            }
        }

        std::optional<platform::Workspace> workspace;
        if (!result.plan.operations.empty()) {
            auto staged =
                stage_attempt(runtime_data, input, result, *profile, workspace);
            if (!staged) {
                auto removed = detail::remove_transaction_workspace(workspace);
                if (!removed) {
                    return std::unexpected(removed.error());
                }
                return std::unexpected(staged.error());
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
            auto removed = detail::remove_transaction_workspace(workspace);
            if (!removed) {
                return std::unexpected(removed.error());
            }
            if (observed.error().code ==
                    reconciliation::ErrorCode::InvalidLocalTree &&
                observed.error().detail.ends_with(
                    "file changed while being read")) {
                if (attempt + 1 == maximum_observation_attempts) {
                    return std::unexpected(detail::make_error(
                        ErrorCode::ConcurrentModification,
                        "state changed repeatedly before publication"));
                }
                continue;
            }
            return std::unexpected(detail::make_error(
                ErrorCode::ObservationFailure, observed.error().detail));
        }
        observed->pending_deletion_authority = input.pending_deletion_authority;
        auto local_after_storage = observation::collect_local_tree(
            runtime_data.local_dir, session, observed->ignore_list);
        if (!local_after_storage) {
            auto removed = detail::remove_transaction_workspace(workspace);
            if (!removed) {
                return std::unexpected(removed.error());
            }
            return std::unexpected(detail::make_error(
                ErrorCode::ObservationFailure, local_after_storage.error()));
        }
        if (!same_snapshot(observed->local_tree, *local_after_storage)) {
            observed->local_tree = std::move(*local_after_storage);
        }
        auto recalculated = reconciliation::reconcile(*observed);
        if (!recalculated) {
            auto removed = detail::remove_transaction_workspace(workspace);
            if (!removed) {
                return std::unexpected(removed.error());
            }
            return std::unexpected(detail::make_error(
                ErrorCode::ObservationFailure, recalculated.error().detail));
        }
        auto reobserved_availability = observe_content_availability(
            *observed, *recalculated, storage, key, confirmed_missing);
        if (!reobserved_availability) {
            auto removed = detail::remove_transaction_workspace(workspace);
            if (!removed) {
                return std::unexpected(removed.error());
            }
            return std::unexpected(reobserved_availability.error());
        }
        recalculated = reconciliation::reconcile(*observed);
        if (!recalculated) {
            auto removed = detail::remove_transaction_workspace(workspace);
            if (!removed) {
                return std::unexpected(removed.error());
            }
            return std::unexpected(detail::make_error(
                ErrorCode::ObservationFailure, recalculated.error().detail));
        }
        if (same_observation(input, *observed)) {
            auto removed = detail::remove_transaction_workspace(workspace);
            if (!removed) {
                return std::unexpected(removed.error());
            }
            return StableExecution{.input = std::move(*observed),
                                   .result = std::move(*recalculated)};
        }

        auto removed = detail::remove_transaction_workspace(workspace);
        if (!removed) {
            return std::unexpected(removed.error());
        }
        if (attempt + 1 == maximum_observation_attempts) {
            return std::unexpected(detail::make_error(
                ErrorCode::ConcurrentModification,
                "state changed repeatedly before publication"));
        }
        input = std::move(*observed);
        result = std::move(*recalculated);
    }

    return std::unexpected(
        detail::make_error(ErrorCode::ConcurrentModification,
                           "state changed repeatedly before publication"));
}

} // namespace kasumi::application::sync::coordinator::reobservation
