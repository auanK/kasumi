#include "application/execute.hpp"

#include "application/history_storage/activity.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/profile.hpp"
#include "application/use_cases/context.hpp"
#include "platform/cancellation.hpp"
#include "platform/clock.hpp"
#include "platform/perf_trace.hpp"
#include "platform/random.hpp"
#include "platform/workspace.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace kasumi::application {
namespace detail {

std::expected<Response, Error> run_sync(OperationContext& context);
std::expected<Response, Error> run_plan(OperationContext& context);
std::expected<Response, Error> run_fsck(OperationContext& context);
std::expected<Response, Error> run_garbage_collect(OperationContext& context);
std::expected<Response, Error> run_resolve_missing(OperationContext& context);
std::expected<Response, Error> run_remove_writer(OperationContext& context);
std::expected<Response, Error> run_remove_barrier(OperationContext& context);
std::expected<Response, Error> run_repack(OperationContext& context);

std::expected<Response, Error> dispatch(OperationContext& context) {
    switch (context.operation) {
        case Operation::Sync:
            return run_sync(context);
        case Operation::Preview:
        case Operation::Status:
            return run_plan(context);
        case Operation::Fsck:
            return run_fsck(context);
        case Operation::GarbageCollect:
            return run_garbage_collect(context);
        case Operation::ResolveMissing:
            return run_resolve_missing(context);
        case Operation::RemoveWriter:
            return run_remove_writer(context);
        case Operation::RemoveBarrier:
            return run_remove_barrier(context);
        case Operation::Repack:
            return run_repack(context);
    }
    std::unreachable();
}

} // namespace detail

namespace {

bool is_remote_activity_operation(Operation operation) noexcept {
    switch (operation) {
        case Operation::Fsck:
        case Operation::GarbageCollect:
        case Operation::RemoveWriter:
        case Operation::RemoveBarrier:
            return true;
        case Operation::Sync:
        case Operation::Preview:
        case Operation::Status:
        case Operation::ResolveMissing:
        case Operation::Repack:
            return false;
    }
    return false;
}

state_storage::LocalOperationKind to_local_op(Operation operation) noexcept {
    using K = state_storage::LocalOperationKind;
    switch (operation) {
        case Operation::Sync:
        case Operation::Preview:
        case Operation::Status:
            return K::Sync;
        case Operation::Fsck:
            return K::Fsck;
        case Operation::GarbageCollect:
            return K::GarbageCollect;
        case Operation::Repack:
            return K::Repack;
        case Operation::ResolveMissing:
            return K::ResolveMissing;
        case Operation::RemoveWriter:
            return K::RemoveWriter;
        case Operation::RemoveBarrier:
            return K::RemoveBarrier;
    }
    return K::Sync;
}

history_storage::activity::ActivityOperation
to_activity_op(Operation operation) noexcept {
    using AO = history_storage::activity::ActivityOperation;
    switch (operation) {
        case Operation::Fsck:
            return AO::Fsck;
        case Operation::GarbageCollect:
            return AO::GarbageCollect;
        case Operation::RemoveWriter:
            return AO::RemoveWriter;
        case Operation::RemoveBarrier:
            return AO::RemoveBarrier;
        default:
            return AO::Fsck;
    }
}

state_storage::LocalExecutionStatus
outcome_to_local_status(history_storage::activity::ActivityOutcome outcome) noexcept {
    using AO = history_storage::activity::ActivityOutcome;
    using LS = state_storage::LocalExecutionStatus;
    switch (outcome) {
        case AO::Succeeded:
            return LS::Succeeded;
        case AO::IssuesFound:
            return LS::IssuesFound;
        case AO::Blocked:
            return LS::Blocked;
        case AO::Cancelled:
            return LS::Cancelled;
        case AO::Failed:
            return LS::Failed;
        case AO::Uncertain:
            return LS::Uncertain;
    }
    return LS::Failed;
}

std::string sync_stage_label(std::optional<SyncStage> stage) {
    if (!stage) {
        return {};
    }
    switch (*stage) {
        case SyncStage::Observing:
            return "observing";
        case SyncStage::Calculating:
            return "calculating";
        case SyncStage::Applying:
            return "applying";
        case SyncStage::Publishing:
            return "publishing";
        case SyncStage::Finalizing:
            return "finalizing";
    }
    return {};
}

bool db_ready_for_tracking(const std::filesystem::path& database_path) noexcept {
    if (database_path.empty()) {
        return false;
    }
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(database_path, ec);
    return !ec && std::filesystem::is_regular_file(status) &&
           state_storage::validate(database_path);
}

state_storage::CachedRemoteActivity
to_cached_activity(const history_storage::activity::ActivityRecord& record,
                   std::int64_t cached_at) {
    std::string machine_hex;
    static constexpr char kHex[] = "0123456789abcdef";
    machine_hex.reserve(record.machine_id.size() * 2U);
    for (const auto byte : record.machine_id) {
        machine_hex.push_back(kHex[(byte >> 4U) & 0x0FU]);
        machine_hex.push_back(kHex[byte & 0x0FU]);
    }
    return state_storage::CachedRemoteActivity{
        .event_id = record.event_id,
        .operation = static_cast<std::uint8_t>(record.operation),
        .outcome = static_cast<std::uint8_t>(record.outcome),
        .machine_id_hex = std::move(machine_hex),
        .machine_name = record.machine_name,
        .started_at = record.started_at,
        .finished_at = record.finished_at,
        .duration_ms = record.duration_ms,
        .metric_primary = record.metric_primary,
        .metric_secondary = record.metric_secondary,
        .metric_bytes = record.metric_bytes,
        .flags = record.flags,
        .stage = record.stage,
        .detail = record.detail,
        .cached_at = cached_at,
    };
}

} // namespace

std::expected<Response, Error> execute(ExecutionInput input) {
    platform::perf_trace::reset();
    const auto total_trace = platform::perf_trace::begin();
    detail::OperationContext context{};
    const bool track_operation =
        input.request.operation != Operation::Status &&
        input.request.operation != Operation::Preview &&
        !((input.request.operation == Operation::Repack ||
           input.request.operation == Operation::GarbageCollect) &&
          input.request.dry_run);
    std::expected<Response, Error> result =
        std::unexpected(Error{.operation = input.request.operation,
                              .code = ErrorCode::RuntimeFailure,
                              .detail = "uninitialized execution"});
    try {
        auto prepared = detail::prepare_operation(input, context);
        if (!prepared) {
            result = std::unexpected(prepared.error());
        } else if (!track_operation) {
            result = detail::dispatch(context);
        } else {
            const auto steady_started = std::chrono::steady_clock::now();
            const auto started_at =
                platform::clock::unix_seconds().value_or(0);
            auto eid = platform::random::hex_id(16);
            const std::string execution_id =
                (eid && !eid->empty())
                    ? std::move(*eid)
                    : ("exec-" + std::to_string(started_at));
            state_storage::LocalExecutionRecord record{
                .execution_id = execution_id,
                .operation = to_local_op(context.operation),
                .machine_id_hex = context.machine_identity
                                      ? context.machine_identity->id_hex
                                      : std::string{},
                .machine_name = context.machine_identity
                                    ? context.machine_identity->name
                                    : std::string{},
                .started_at = started_at,
                .status = state_storage::LocalExecutionStatus::InProgress,
                .remote_publish_state =
                    is_remote_activity_operation(context.operation)
                        ? state_storage::RemotePublishState::Pending
                        : state_storage::RemotePublishState::NotApplicable,
            };

            bool start_recorded = false;
            if (context.operation == Operation::Sync) {
                context.on_sync_mutation_start = [&]() {
                    if (db_ready_for_tracking(context.runtime.database_path)) {
                        start_recorded = state_storage::record_execution_start(
                            context.runtime.database_path, record);
                    }
                };
            } else if (db_ready_for_tracking(context.runtime.database_path)) {
                start_recorded = state_storage::record_execution_start(
                    context.runtime.database_path, record);
            }

            result = detail::dispatch(context);

            const auto finished_at =
                platform::clock::unix_seconds().value_or(started_at);
            const auto elapsed_ms =
                static_cast<std::uint64_t>(std::max<std::int64_t>(
                    0,
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - steady_started)
                        .count()));
            record.finished_at = finished_at;
            record.duration_ms = elapsed_ms;
            record.recovered = context.recovered_transaction;

            using LS = state_storage::LocalExecutionStatus;
            if (is_remote_activity_operation(context.operation)) {
                history_storage::activity::ActivityRecord act{
                    .event_id = execution_id,
                    .operation = to_activity_op(context.operation),
                    .machine_id = context.machine_identity
                                      ? context.machine_identity->id
                                      : std::array<std::uint8_t, 16>{},
                    .machine_name = record.machine_name,
                    .started_at = started_at,
                    .finished_at = finished_at,
                    .duration_ms = elapsed_ms,
                };
                if (result) {
                    act.outcome =
                        history_storage::activity::ActivityOutcome::Succeeded;
                    if (const auto* fc =
                            std::get_if<FsckCompleted>(&result->data)) {
                        act.metric_primary = fc->checked_objects;
                        act.metric_bytes = fc->wire_download_bytes;
                    } else if (const auto* gcc =
                                   std::get_if<GarbageCollectCompleted>(
                                       &result->data)) {
                        act.metric_primary = gcc->candidate_objects;
                        act.metric_secondary = gcc->removed_objects;
                        if (gcc->analysis_only) {
                            act.flags |= history_storage::activity::
                                flag_analysis_only;
                        }
                    } else if (const auto* rwc =
                                   std::get_if<ManualWriterRemovalCompleted>(
                                       &result->data)) {
                        act.detail = history_storage::activity::sanitize_text(
                            rwc->identifier,
                            history_storage::activity::maximum_detail_bytes);
                    } else if (const auto* rbc =
                                   std::get_if<ManualBarrierRemovalCompleted>(
                                       &result->data)) {
                        act.metric_primary = rbc->active_writers_count;
                        if (rbc->outcome ==
                            BarrierRemovalOutcome::AlreadyAbsent) {
                            act.flags |= history_storage::activity::
                                flag_barrier_already_absent;
                        }
                    }
                } else {
                    act.outcome =
                        context.maintenance_failure_outcome.value_or(
                            history_storage::activity::ActivityOutcome::Failed);
                    act.metric_primary = context.maintenance_metric_primary;
                    act.metric_secondary = context.maintenance_metric_secondary;
                    act.flags = context.maintenance_flags;
                    act.stage = history_storage::activity::sanitize_text(
                        context.maintenance_failure_stage,
                        history_storage::activity::maximum_stage_bytes);
                    act.detail = history_storage::activity::sanitize_text(
                        context.maintenance_failure_detail.empty()
                            ? result.error().detail
                            : context.maintenance_failure_detail,
                        history_storage::activity::maximum_detail_bytes);
                }

                record.status = outcome_to_local_status(act.outcome);
                record.stage = act.stage;
                record.detail = act.detail;
                record.summary_a = act.metric_primary;
                record.summary_b = act.metric_secondary;
                record.summary_bytes = act.metric_bytes;
                record.flags = act.flags;

                if (result.has_value() || context.remote_observed) {
                    const auto layout =
                        history_storage::derive_remote_layout(context.key);
                    bool published = false;
                    std::string pub_error;
                    if (auto ws = platform::create_workspace("kasumi-activity");
                        ws) {
                        auto pub = history_storage::activity::publish(
                            context.storage, layout, context.key, act, ws->root);
                        platform::cleanup_workspace(*ws);
                        if (pub) {
                            published = true;
                        } else {
                            pub_error = pub.error().detail;
                        }
                    } else {
                        pub_error = ws.error();
                    }
                    if (published) {
                        record.remote_publish_state =
                            state_storage::RemotePublishState::Published;
                        if (db_ready_for_tracking(
                                context.runtime.database_path)) {
                            std::vector<state_storage::CachedRemoteActivity>
                                updated_cache;
                            if (context.operation ==
                                    Operation::GarbageCollect &&
                                result.has_value()) {
                                updated_cache.reserve(
                                    context.gc_kept_activities.size() + 1U);
                                for (const auto& kept :
                                     context.gc_kept_activities) {
                                    updated_cache.push_back(to_cached_activity(
                                        kept.record, finished_at));
                                }
                            } else if (auto existing =
                                           state_storage::load_local_activity(
                                               context.runtime.database_path);
                                       existing) {
                                updated_cache = std::move(
                                    existing->cached_remote_activities);
                            }
                            updated_cache.push_back(
                                to_cached_activity(act, finished_at));
                            static_cast<void>(
                                state_storage::save_remote_activity_cache(
                                    context.runtime.database_path,
                                    updated_cache));
                        }
                    } else {
                        record.remote_publish_state =
                            state_storage::RemotePublishState::Pending;
                        if (result.has_value()) {
                            result->activity_publish_warning =
                                std::move(pub_error);
                        }
                    }
                } else {
                    record.remote_publish_state =
                        state_storage::RemotePublishState::NotApplicable;
                }
            } else {
                record.remote_publish_state =
                    state_storage::RemotePublishState::NotApplicable;
                if (result) {
                    if (const auto* sc =
                            std::get_if<SyncCompleted>(&result->data)) {
                        const bool had_changes =
                            sc->published || sc->uploaded > 0 ||
                            sc->downloaded > 0 || sc->removed > 0 ||
                            sc->renamed > 0 || sc->created_dirs > 0 ||
                            sc->removed_dirs > 0;
                        record.status =
                            sc->partial
                                ? LS::Partial
                                : (!had_changes
                                       ? LS::SucceededNoChanges
                                       : (!sc->published
                                              ? LS::SucceededDownloadedOnly
                                              : LS::Succeeded));
                        record.summary_a = sc->uploaded;
                        record.summary_b = sc->downloaded;
                        record.summary_c = sc->removed + sc->renamed;
                        record.summary_bytes =
                            sc->upload_bytes + sc->download_bytes;
                        record.flags = sc->published ? 1U : 0U;
                        record.commit_id = context.accepted_commit_id;
                    } else if (const auto* rc =
                                   std::get_if<RepackCompleted>(&result->data)) {
                        record.status = rc->published
                                            ? LS::Succeeded
                                            : LS::SucceededNoChanges;
                        record.summary_a = rc->repacked_blobs;
                        record.summary_b = rc->new_packs;
                        record.summary_bytes = rc->repacked_plaintext_bytes;
                        record.flags = rc->published ? 1U : 0U;
                        record.commit_id = rc->published_commit_id;
                    } else if (const auto* rmc =
                                   std::get_if<ResolveMissingCompleted>(
                                       &result->data)) {
                        record.status = rmc->published
                                            ? LS::Succeeded
                                            : LS::SucceededNoChanges;
                        record.summary_a = rmc->resolved_count;
                        record.flags = rmc->published ? 1U : 0U;
                        record.commit_id = context.accepted_commit_id;
                    }
                } else {
                    const auto& err = result.error();
                    if (err.code == ErrorCode::InventoryAuditFailure &&
                        err.sync_completed.has_value()) {
                        const auto& sc = *err.sync_completed;
                        record.status = LS::Failed;
                        record.stage = "audit";
                        record.detail = history_storage::activity::sanitize_text(
                            err.detail,
                            history_storage::activity::maximum_detail_bytes);
                        record.summary_a = sc.uploaded;
                        record.summary_b = sc.downloaded;
                        record.summary_c = sc.removed + sc.renamed;
                        record.summary_bytes =
                            sc.upload_bytes + sc.download_bytes;
                        record.flags =
                            (sc.published ? 1U : 0U) |
                            profile_execution_flag_audit_failed_after_sync;
                        record.commit_id = context.accepted_commit_id;
                    } else {
                        record.status = platform::cancellation::requested()
                                            ? LS::Cancelled
                                            : LS::Failed;
                        record.stage = sync_stage_label(err.stage);
                        record.detail = history_storage::activity::sanitize_text(
                            err.detail,
                            history_storage::activity::maximum_detail_bytes);
                    }
                }
            }

            if (db_ready_for_tracking(context.runtime.database_path)) {
                if (start_recorded) {
                    static_cast<void>(state_storage::record_execution_finish(
                        context.runtime.database_path, record));
                } else {
                    static_cast<void>(state_storage::record_execution_complete(
                        context.runtime.database_path, record));
                }
            }
        }
    } catch (...) {
        result = std::unexpected(Error{
            .operation = context.operation,
            .code = ErrorCode::RuntimeFailure,
            .detail = "application orchestration exception",
            .runtime = context.summary.local_dir.empty() &&
                               context.summary.remote_dir.empty()
                           ? std::nullopt
                           : std::optional<RuntimeSummary>{context.summary},
        });
    }

    context.storage = {};
    detail::wipe_operation(context);
    wipe_credentials(input.credentials);
    platform::perf_trace::finish("total sync", total_trace);
    platform::perf_trace::report(result ? "success" : "error");
    return result;
}

} // namespace kasumi::application
