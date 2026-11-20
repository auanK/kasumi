#include "application/integrity/maintenance.hpp"

#include "application/concurrency.hpp"
#include "application/detail.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/repack.hpp"
#include "application/progress.hpp"
#include "application/sync/coordinator.hpp"
#include "application/use_cases/context.hpp"

#include <optional>

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
        return fail_app(context,
                        failure_code,
                        "complete the interrupted upload with sync before "
                        "garbage collection");
    }
    auto res = fn(std::move(callback));
    if (!res) {
        auto error =
            make_error(context, failure_code, integrity::describe(res.error()));
        error.garbage_collection = res.error().garbage_collection;
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
        return fail_app(
            context, ErrorCode::WriterRemovalFailure, removed.error().detail);
    }
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
