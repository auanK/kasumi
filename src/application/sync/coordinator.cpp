#include "application/sync/coordinator.hpp"

#include "application/concurrency.hpp"
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
#include "crypto/pack.hpp"
#include "journal_fault_test.hpp"
#include "platform/cancellation.hpp"
#include "platform/clock.hpp"
#include "platform/metadata.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "platform/random.hpp"
#include "platform/workspace.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <array>
#include <condition_variable>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <functional>
#include <future>
#include <limits>
#include <mutex>
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

} // namespace detail

namespace {

using detail::mutation_error;
using detail::publication_error;

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
                        std::stop_token op_stop,
                        std::optional<std::size_t> concurrency_override,
                        std::size_t slot,
                        ContentWindowState& state,
                        const transaction::Record& record,
                        const std::filesystem::path& local_root,
                        transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        const platform::Workspace& workspace) {
    const platform::cancellation::ScopedStopToken stop_scope{op_stop};
    const application::ScopedContentConcurrency concurrency_scope{
        concurrency_override};
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
    const auto op_stop = platform::cancellation::current_stop_token();
    const auto concurrency_override =
        application::current_content_concurrency_override();
    std::vector<std::jthread> workers;
    try {
        workers.reserve(worker_count);
        for (std::size_t slot = 0; slot < worker_count; ++slot) {
            workers.emplace_back(run_content_worker,
                                 op_stop,
                                 concurrency_override,
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
                    batch.emplace_back(slot,
                                       std::move(*state.completions[slot]));
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
                record_progress_applied(*meter, applied);
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
        if (input.verified_remote_content_objects.contains(content_identity)) {
            available.insert(std::move(content_identity));
            required[index] = false;
            continue;
        }
        required[index] = available.insert(std::move(content_identity)).second;
    }
    return required;
}

using detail::build_upload_layout_plan;
using detail::execute_chunked_upload_batch;
using detail::execute_packed_upload_batch;
using detail::next_chunk_window;
using detail::pack_upload_window_size;
using detail::PlannedChunkUpload;
using detail::PlannedPack;
using detail::UploadLayoutPlan;

} // namespace

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
check_empty_local_deletion_guard(const std::filesystem::path& local_dir,
                                 const reconciliation::Input& input,
                                 const reconciliation::Result& result) {
    if (!input.base_state_present || input.base_tree.rows.size() <= 5U ||
        input.local_tree.rows.size() > 1U) {
        return {};
    }
    std::error_code dir_ec;
    std::filesystem::directory_iterator dir_it(local_dir, dir_ec);
    const bool physically_empty =
        !dir_ec && dir_it == std::filesystem::directory_iterator{};
    const auto ops = sync_plan_operations(result.plan);
    const bool all_remote_deletes =
        !ops.empty() && std::ranges::all_of(ops, [](const auto& op) {
            return op.action == Action::DeleteRemote ||
                   op.action == Action::DeleteRemoteDirectory;
        });
    if (physically_empty && all_remote_deletes) {
        return std::unexpected(Error{
            .code = ErrorCode::ObservationFailure,
            .detail = std::format(
                "refusing to delete all {} remote entries because local "
                "directory '{}' is completely empty (verify mounted storage "
                "or pass --allow-empty-local to propagate deletions)",
                input.base_tree.rows.size() - 1U,
                platform::path::to_utf8(local_dir)),
            .empty_local_blocked = true,
        });
    }
    return {};
}

std::expected<void, Error>
execute(const runtime::RuntimeData& runtime_data,
        transport::Transport& storage,
        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
        const reconciliation::Input& observed_input,
        const reconciliation::Result& reconciliation_result,
        observation::LocalObservationSession* session,
        StagedExecutionHandoff* staged_handoff,
        bool enable_micro_packs,
        history::CommitAuthorship authorship,
        std::string* accepted_commit_id,
        bool enforce_empty_local_guard,
        EpochAdvancementPolicy epoch_advancement) {
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

    if (enforce_empty_local_guard) {
        if (auto guarded = check_empty_local_deletion_guard(
                runtime_data.local_dir, observed_input, reconciliation_result);
            !guarded) {
            return std::unexpected(guarded.error());
        }
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
            journal::invalidate_session(journal_session);
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
                progress_add(meter->bytes_reused, op.size);
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
        const auto& current_progress = use_handoff_progress
                                           ? handoff_progress[index]
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
        begin_progress_phase(*meter, Activity::Staging);
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
            layout_plan->target_manifest,
            std::move(authorship));
        if (!prepared) {
            return fail_terminal(publication_error(prepared.error()));
        }
        prepared_commit.emplace(std::move(*prepared));

        const auto publication_workspace =
            runtime_data.database_path.parent_path();
        try {
            const auto op_stop = platform::cancellation::current_stop_token();
            commit_publication = std::async(
                std::launch::async,
                [&storage,
                 key,
                 layout = history_storage::derive_remote_layout(key),
                 publication_workspace,
                 op_stop,
                 prepared = &*prepared_commit]() {
                    const platform::cancellation::ScopedStopToken stop_scope{
                        op_stop};
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
        record_progress_applied(
            *meter, record->plan.operations.size() - apply_order.size());
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
            record_progress_applied(*meter, completed);
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
                if (history::is_storage_manifest_empty(manifest)) {
                    loose_indices.push_back(op_idx);
                    continue;
                }
                const auto h =
                    hash_from_hex(record->plan.operations[op_idx].hash);
                if (h && history::find_packed_blob(manifest, *h) != nullptr) {
                    packed_indices.push_back(op_idx);
                } else if (h && history::find_chunked_file(manifest, *h) !=
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
                        begin_progress_phase(
                            *meter, Activity::Downloading, window_span.size());
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
                        progress_add(meter->work, window_span.size());
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
                    begin_progress_phase(*meter,
                                         needs_download ? Activity::Downloading
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
                    progress_add(meter->work);
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
                begin_progress_phase(*meter,
                                     needs_download ? Activity::Downloading
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
                progress_add(meter->work);
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
            const auto h =
                hash_from_hex(record->plan.operations[op_index].hash);
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
        begin_progress_phase(*meter, Activity::Verifying);
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
            notify_progress(*meter,
                            SyncProgress{.stage = SyncStage::Finalizing});
        }
        std::optional<state_storage::AcceptedCommitMeta> accepted_meta;
        if (found->commit.created_at > 0 ||
            history::has_commit_authorship(found->commit.authorship) ||
            !observed_input.base_state_present ||
            found->id != observed_input.base_commit_id) {
            accepted_meta = publication::make_accepted_commit_meta(
                found->id, found->commit);
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
                    .storage_manifest = found->commit.storage},
                accepted_meta);
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
        if (accepted_commit_id != nullptr) {
            *accepted_commit_id = found->id;
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
        notify_progress(*meter, SyncProgress{.stage = SyncStage::Publishing});
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

        if (epoch_advancement == EpochAdvancementPolicy::ExclusivePublisher &&
            commit_time->pruning_time_safe) {
            std::vector<history::LoadedCommit> current_dag =
                observed_input.storage.reachable_commits;
            current_dag.push_back(
                history::LoadedCommit{.id = prepared_commit->commit_id,
                                      .commit = prepared_commit->commit});

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
        notify_progress(*meter, SyncProgress{.stage = SyncStage::Finalizing});
    }
    const auto accepted_meta = publication::make_accepted_commit_meta(
        prepared_commit->commit_id, prepared_commit->commit);
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
                .storage_manifest = prepared_commit->commit.storage},
            accepted_meta);
        !saved_state) {
        return std::unexpected(saved_state.error());
    }
    if (accepted_commit_id != nullptr) {
        *accepted_commit_id = prepared_commit->commit_id;
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
