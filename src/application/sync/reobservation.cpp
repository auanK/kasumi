#include "application/sync/reobservation.hpp"

#include "application/observation/state.hpp"
#include "application/sync/coordinator_detail.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/mutation.hpp"
#include "core/reconciliation/plan.hpp"

#include <algorithm>
#include <cstddef>
#include <exception>
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
                                        record->progress[index]);
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
           same_snapshot(left.base_tree, right.base_tree) &&
           left.base_commit_id == right.base_commit_id &&
           left.base_state_present == right.base_state_present &&
           left.local_generation == right.local_generation &&
           left.audit_storage_objects == right.audit_storage_objects &&
           same_storage(left.storage, right.storage);
}

std::expected<StableExecution, coordinator::Error>
stabilize(const runtime::RuntimeData& runtime_data,
          transport::Transport& storage,
          std::span<const std::uint8_t, crypto::KEY_SIZE> key,
          reconciliation::Input observed_input,
          reconciliation::Result reconciliation_result,
          observation::LocalObservationSession* session) {
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
            return std::unexpected(detail::make_error(
                ErrorCode::ObservationFailure, observed.error().detail));
        }
        auto local_after_storage =
            observation::collect_local_tree(runtime_data.local_dir, session);
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
        if (recalculated->unrecoverable_paths.empty() &&
            same_observation(input, *observed)) {
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
                "estado mudou repetidamente antes da publicação"));
        }
        input = std::move(*observed);
        result = std::move(*recalculated);
        if (!result.unrecoverable_paths.empty()) {
            return std::unexpected(detail::make_error(
                ErrorCode::ObservationFailure,
                "a observação encontrou caminhos irrecuperáveis"));
        }
    }

    return std::unexpected(
        detail::make_error(ErrorCode::ConcurrentModification,
                           "estado mudou repetidamente antes da publicação"));
}

} // namespace kasumi::application::sync::coordinator::reobservation
