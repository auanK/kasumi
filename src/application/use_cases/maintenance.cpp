#include "application/integrity/maintenance.hpp"

#include "application/concurrency.hpp"
#include "application/detail.hpp"
#include "application/history_storage/activity.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/repack.hpp"
#include "application/progress.hpp"
#include "application/sync/coordinator.hpp"
#include "application/use_cases/context.hpp"
#include "core/history.hpp"
#include "platform/cancellation.hpp"

#include <optional>
#include <string>
#include <utility>

namespace kasumi::application::detail {
namespace {

template <typename Callback, typename Progress, typename Stage>
Callback make_progress_callback(const OperationContext& context,
                                Stage initial_stage,
                                std::optional<Progress>& last_progress) {
    Callback callback{};
    if (context.on_progress) {
        callback = [&context,
                    &last_progress](const Progress& progress) noexcept {
            last_progress = progress;
            try {
                context.on_progress(progress);
            } catch (...) {
                // Progress is observational and must not alter the operation.
            }
        };
        callback(Progress{.stage = initial_stage});
    }
    return callback;
}

template <typename Callback, typename Progress, typename Stage, typename RunFn>
std::expected<Response, Error>
run_with_recovery(OperationContext& context,
                  Stage initial_stage,
                  std::optional<Progress>& last_progress,
                  RunFn&& fn) {
    const auto failure_code = context.operation == Operation::Fsck
                                  ? ErrorCode::FsckFailure
                                  : ErrorCode::GarbageCollectionFailure;
    auto callback = make_progress_callback<Callback, Progress>(
        context, initial_stage, last_progress);
    const auto recovery = sync::coordinator::recover_if_needed(
        context.runtime, context.storage, context.key);
    if (!recovery) {
        return std::unexpected(
            make_error(context,
                       failure_code,
                       sync::coordinator::describe(recovery.error())));
    }
    if (context.operation == Operation::GarbageCollect &&
        *recovery == sync::coordinator::RecoveryResult::ResumableTransaction) {
        context.maintenance_failure_outcome =
            history_storage::activity::ActivityOutcome::Blocked;
        context.maintenance_failure_stage = "preparing";
        context.maintenance_failure_detail =
            "complete the interrupted upload with sync before garbage "
            "collection";
        return fail_app(context,
                        failure_code,
                        context.maintenance_failure_detail);
    }
    auto res = fn(std::move(callback));
    if (!res) {
        const auto described = integrity::describe(res.error());
        const auto& err = res.error();
        if (context.operation == Operation::Fsck) {
            using IE = integrity::ErrorCode;
            using AO = history_storage::activity::ActivityOutcome;
            switch (err.code) {
                case IE::IntegrityFailure:
                case IE::Unrecoverable:
                    context.remote_observed = true;
                    context.maintenance_failure_outcome = AO::IssuesFound;
                    context.maintenance_failure_stage = "auditing";
                    break;
                case IE::ConcurrentChange:
                    context.remote_observed = true;
                    context.maintenance_failure_outcome = AO::Blocked;
                    context.maintenance_failure_stage = "auditing";
                    break;
                case IE::TransportFailure:
                case IE::CryptoFailure:
                    context.remote_observed = true;
                    context.maintenance_failure_outcome = AO::Failed;
                    context.maintenance_failure_stage = "auditing";
                    break;
                case IE::StateFailure:
                    if (platform::cancellation::requested()) {
                        context.remote_observed = true;
                        context.maintenance_failure_outcome = AO::Cancelled;
                    } else {
                        context.maintenance_failure_outcome = AO::Failed;
                    }
                    context.maintenance_failure_stage = "auditing";
                    break;
                case IE::InvalidInput:
                case IE::WorkspaceFailure:
                    context.maintenance_failure_outcome = AO::Failed;
                    context.maintenance_failure_stage = "preparing";
                    break;
            }
            context.maintenance_failure_detail = described;
        } else {
            using IE = integrity::ErrorCode;
            using AO = history_storage::activity::ActivityOutcome;
            const auto& gc = err.garbage_collection;
            context.remote_observed =
                gc.has_value() || err.code == IE::ConcurrentChange ||
                err.code == IE::IntegrityFailure;
            if (gc.has_value()) {
                context.maintenance_metric_primary = gc->candidate_objects;
                context.maintenance_metric_secondary = gc->confirmed_removed;
                if (gc->barrier_cleanup_error.has_value()) {
                    context.maintenance_flags |=
                        history_storage::activity::flag_barrier_release_failed;
                }
                if (gc->mutation_state ==
                    GarbageCollectMutationState::Uncertain) {
                    context.maintenance_flags |=
                        history_storage::activity::flag_mutation_uncertain;
                }
                switch (gc->stage) {
                    case GarbageCollectStage::Preparing:
                        context.maintenance_failure_stage = "preparing";
                        break;
                    case GarbageCollectStage::Analyzing:
                        context.maintenance_failure_stage = "analyzing";
                        break;
                    case GarbageCollectStage::Applying:
                        context.maintenance_failure_stage = "applying";
                        break;
                    case GarbageCollectStage::Finalizing:
                        context.maintenance_failure_stage = "finalizing";
                        break;
                }
            } else {
                context.maintenance_failure_stage = "preparing";
            }
            if (gc.has_value() &&
                gc->mutation_state == GarbageCollectMutationState::Uncertain) {
                context.maintenance_failure_outcome = AO::Uncertain;
            } else if (platform::cancellation::requested()) {
                context.maintenance_failure_outcome = AO::Cancelled;
            } else if (err.code == IE::ConcurrentChange) {
                context.maintenance_failure_outcome = AO::Blocked;
            } else if (err.code == IE::IntegrityFailure) {
                context.maintenance_failure_outcome = AO::IssuesFound;
            } else {
                context.maintenance_failure_outcome = AO::Failed;
            }
            context.maintenance_failure_detail = described;
        }
        auto error = make_error(context, failure_code, described);
        error.garbage_collection = err.garbage_collection;
        return std::unexpected(std::move(error));
    }
    return make_response(context, std::move(*res));
}

} // namespace

std::expected<Response, Error> run_fsck(OperationContext& context) {
    std::optional<FsckProgress> last_progress;
    return run_with_recovery<integrity::FsckProgressCallback>(
        context,
        FsckStage::Preparing,
        last_progress,
        [&](integrity::FsckProgressCallback cb)
            -> std::expected<ResponseData, integrity::Error> {
            auto checked = integrity::fsck(context.runtime,
                                           context.storage,
                                           context.key,
                                           content_concurrency(),
                                           std::move(cb));
            if (!checked) {
                return std::unexpected(std::move(checked.error()));
            }
            context.remote_observed = true;
            return FsckCompleted{
                .checked_objects = checked->checked_objects,
                .checked_plaintext_bytes =
                    last_progress ? last_progress->completed_plaintext_bytes
                                  : std::nullopt,
                .wire_download_bytes =
                    last_progress ? last_progress->wire_download_bytes : 0,
                .physical_objects_downloaded =
                    last_progress ? last_progress->physical_objects_downloaded
                                  : 0,
                .files_reassembled =
                    last_progress ? last_progress->files_reassembled : 0,
            };
        });
}

std::expected<Response, Error> run_garbage_collect(OperationContext& context) {
    std::optional<GarbageCollectProgress> last_progress;
    return run_with_recovery<integrity::GarbageCollectProgressCallback>(
        context,
        GarbageCollectStage::Preparing,
        last_progress,
        [&](integrity::GarbageCollectProgressCallback cb)
            -> std::expected<ResponseData, integrity::Error> {
            auto collected = integrity::garbage_collect(
                context.runtime, context.storage, context.key, std::move(cb));
            if (!collected) {
                return std::unexpected(std::move(collected.error()));
            }
            context.remote_observed = true;
            context.gc_kept_activities = std::move(collected->kept_activities);
            return GarbageCollectCompleted{
                .candidate_objects = collected->candidate_objects,
                .analysis_only = collected->analysis_only,
                .removed_objects = collected->removed_objects,
                .removal_elapsed = collected->removal_elapsed,
            };
        });
}

std::expected<Response, Error> run_remove_barrier(OperationContext& context) {
    const auto layout = history_storage::derive_remote_layout(context.key);
    auto removed = history_storage::maintenance_protocol::remove_barrier(
        context.storage, layout, maintenance_workspace_root(context.runtime));
    if (!removed) {
        const auto& err = removed.error();
        const auto stage = err.stage.has_value()
                               ? static_cast<BarrierRemovalStage>(*err.stage)
                               : BarrierRemovalStage::CheckingPresence;
        const auto mutation_state =
            err.mutation_state.has_value()
                ? static_cast<BarrierRemovalMutationState>(*err.mutation_state)
                : BarrierRemovalMutationState::NotAttempted;

        using P = history_storage::maintenance_protocol::ErrorCode;
        using AO = history_storage::activity::ActivityOutcome;
        context.remote_observed =
            err.code != P::InvalidInput &&
            stage != BarrierRemovalStage::CheckingPresence;
        switch (stage) {
            case BarrierRemovalStage::CheckingPresence:
                context.maintenance_failure_stage = "checking-presence";
                break;
            case BarrierRemovalStage::DownloadingPayload:
                context.maintenance_failure_stage = "downloading-payload";
                break;
            case BarrierRemovalStage::ValidatingPayload:
                context.maintenance_failure_stage = "validating-payload";
                break;
            case BarrierRemovalStage::CheckingWriters:
                context.maintenance_failure_stage = "checking-writers";
                break;
            case BarrierRemovalStage::VerifyingPhysicalIdentity:
                context.maintenance_failure_stage = "verifying-identity";
                break;
            case BarrierRemovalStage::Removing:
                context.maintenance_failure_stage = "removing";
                break;
            case BarrierRemovalStage::ConfirmingAbsence:
                context.maintenance_failure_stage = "confirming-absence";
                break;
        }
        if (mutation_state == BarrierRemovalMutationState::Uncertain) {
            context.maintenance_flags |=
                history_storage::activity::flag_mutation_uncertain;
            context.maintenance_failure_outcome = AO::Uncertain;
        } else if (platform::cancellation::requested()) {
            context.maintenance_failure_outcome = AO::Cancelled;
        } else if (err.code == P::Blocked) {
            context.maintenance_failure_outcome = AO::Blocked;
        } else {
            context.maintenance_failure_outcome = AO::Failed;
        }
        context.maintenance_failure_detail = err.detail;

        return std::unexpected(Error{
            .operation = context.operation,
            .code = ErrorCode::BarrierRemovalFailure,
            .detail = err.detail,
            .runtime = context.summary,
            .barrier_removal =
                BarrierRemovalFailure{
                    .barrier_identifier =
                        err.identifier.value_or(layout.barrier_identifier),
                    .stage = stage,
                    .mutation_state = mutation_state,
                    .transport_error = err.transport_failure,
                },
        });
    }
    context.remote_observed = true;
    const auto outcome =
        (removed->outcome ==
         history_storage::maintenance_protocol::BarrierRemovalOutcome::Removed)
            ? BarrierRemovalOutcome::Removed
            : BarrierRemovalOutcome::AlreadyAbsent;
    return make_response(
        context,
        ManualBarrierRemovalCompleted{
            .identifier = layout.barrier_identifier,
            .outcome = outcome,
            .active_writers_count = removed->active_writers_count,
        });
}

std::expected<Response, Error> run_remove_writer(OperationContext& context) {
    const auto layout = history_storage::derive_remote_layout(context.key);
    auto removed = history_storage::maintenance_protocol::remove_writer(
        context.storage, layout, context.writer_identifier);
    if (!removed) {
        using P = history_storage::maintenance_protocol::ErrorCode;
        using AO = history_storage::activity::ActivityOutcome;
        const auto& err = removed.error();
        context.remote_observed =
            err.code != P::WorkspaceFailure &&
            !(err.code == P::InvalidInput &&
              !history_storage::valid_writer_identifier(
                  layout, context.writer_identifier));
        context.maintenance_failure_stage = "removing-writer";
        context.maintenance_failure_detail = err.detail;
        context.maintenance_failure_outcome =
            platform::cancellation::requested() ? AO::Cancelled
            : err.code == P::Blocked            ? AO::Blocked
                                                : AO::Failed;
        return fail_app(
            context, ErrorCode::WriterRemovalFailure, err.detail);
    }
    context.remote_observed = true;
    return make_response(
        context,
        ManualWriterRemovalCompleted{.identifier = context.writer_identifier});
}

std::expected<Response, Error> run_repack(OperationContext& context) {
    ProgressMeter meter(context.on_progress, context.storage);
    integrity::repack::Options options{};
    options.policy.reclaim_large_dirty_packs = context.reclaim_dirty;
    options.dry_run = context.dry_run;
    options.max_parallelism = content_concurrency();
    if (!context.dry_run && context.machine_identity) {
        options.authorship = make_commit_authorship(
            history::CommitOriginOperation::Repack, *context.machine_identity);
    }

    auto res = integrity::repack::execute(
        context.runtime, context.storage, context.key, options, &meter);
    if (!res) {
        return fail_app(
            context, ErrorCode::RepackFailure, integrity::describe(res.error()));
    }
    return make_response(
        context,
        RepackCompleted{
            .dry_run = res->dry_run,
            .actionable = res->plan.actionable,
            .published = res->published,
            .live_small_blobs = res->plan.live_small_blobs,
            .existing_packs = res->plan.existing_packs,
            .healthy_packs_kept = res->plan.healthy_packs_kept,
            .dirty_packs_detected = res->plan.dirty_packs_detected,
            .loose_small_blobs_detected = res->plan.loose_small_blobs_detected,
            .source_loose_blobs = res->plan.source_loose_blobs,
            .source_clean_packs = res->plan.source_clean_packs,
            .source_dirty_packs = res->plan.source_dirty_packs,
            .new_packs = res->plan.new_packs.size(),
            .repacked_blobs = res->plan.repacked_blobs,
            .repacked_plaintext_bytes = res->plan.repacked_plaintext_bytes,
            .published_commit_id = std::move(res->published_commit_id),
            .published_height = res->published_height,
            .pruned_markers = res->pruned_markers,
            .wire_upload_bytes = res->wire_upload_bytes,
            .physical_objects_uploaded = res->physical_objects_uploaded,
            .duration = res->duration,
        });
}

} // namespace kasumi::application::detail
