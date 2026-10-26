#include "application/integrity/maintenance.hpp"

#include "application/concurrency.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/sync/coordinator.hpp"
#include "application/use_cases/context.hpp"
#include "application/use_cases/error_mapping.hpp"

#include <optional>

namespace kasumi::application::detail {
namespace {

std::expected<Response, Error> run_fsck_operation(OperationContext& context) {
    std::optional<FsckProgress> last_fsck_progress;
    integrity::FsckProgressCallback fsck_progress{};
    if (context.on_progress) {
        fsck_progress = [&context, &last_fsck_progress](
                            const FsckProgress& progress) noexcept {
            last_fsck_progress = progress;
            try {
                context.on_progress(progress);
            } catch (...) {
                // Progress is observational and must not alter the operation.
            }
        };
        fsck_progress(FsckProgress{.stage = FsckStage::Preparing});
    }

    auto recovery = sync::coordinator::recover_if_needed(
        context.runtime, context.storage, context.key);
    if (!recovery) {
        return std::unexpected(maintenance_recovery_error(
            context.operation, recovery.error(), context.summary));
    }

    auto checked = integrity::fsck(context.runtime,
                                   context.storage,
                                   context.key,
                                   content_concurrency(),
                                   std::move(fsck_progress));
    if (!checked) {
        return std::unexpected(maintenance_error(
            context.operation, checked.error(), context.summary));
    }
    return Response{
        .operation = context.operation,
        .runtime = context.summary,
        .data = FsckCompleted{
            .checked_objects = checked->checked_objects,
            .checked_plaintext_bytes =
                last_fsck_progress
                    ? last_fsck_progress->completed_plaintext_bytes
                    : std::nullopt,
        }};
}

std::expected<Response, Error>
run_garbage_collect_operation(OperationContext& context) {
    std::optional<GarbageCollectProgress> last_progress;
    integrity::GarbageCollectProgressCallback gc_progress{};
    if (context.on_progress) {
        gc_progress = [&context, &last_progress](
                          const GarbageCollectProgress& progress) noexcept {
            last_progress = progress;
            try {
                context.on_progress(progress);
            } catch (...) {
                // Progress is observational and must not alter the operation.
            }
        };
        gc_progress(
            GarbageCollectProgress{.stage = GarbageCollectStage::Preparing});
    }

    auto recovery = sync::coordinator::recover_if_needed(
        context.runtime, context.storage, context.key);
    if (!recovery) {
        return std::unexpected(maintenance_recovery_error(
            context.operation, recovery.error(), context.summary));
    }

    auto collected = integrity::garbage_collect(
        context.runtime, context.storage, context.key, std::move(gc_progress));
    if (!collected) {
        return std::unexpected(maintenance_error(
            context.operation, collected.error(), context.summary));
    }
    return Response{.operation = context.operation,
                    .runtime = context.summary,
                    .data = GarbageCollectCompleted{
                        .candidate_objects = collected->candidate_objects,
                        .analysis_only = collected->analysis_only,
                        .removed_objects = collected->removed_objects,
                    }};
}

} // namespace

std::expected<Response, Error> run_fsck(OperationContext& context) {
    return run_fsck_operation(context);
}

std::expected<Response, Error> run_garbage_collect(OperationContext& context) {
    return run_garbage_collect_operation(context);
}

std::expected<Response, Error> run_remove_barrier(OperationContext& context) {
    const auto layout = history_storage::derive_remote_layout(context.key);
    auto workspace_root = context.runtime.database_path.parent_path();
    std::error_code ec;
    if (workspace_root.empty() || !std::filesystem::exists(workspace_root, ec)) {
        workspace_root = context.runtime.local_dir.parent_path();
    }
    if (workspace_root.empty() || !std::filesystem::exists(workspace_root, ec)) {
        workspace_root = std::filesystem::temp_directory_path();
    }
    auto removed = history_storage::maintenance_protocol::remove_barrier(
        context.storage, layout, workspace_root);
    if (!removed) {
        const auto& err = removed.error();
        const auto stage = err.stage.has_value()
            ? static_cast<BarrierRemovalStage>(*err.stage)
            : BarrierRemovalStage::CheckingPresence;
        const auto mutation_state = err.mutation_state.has_value()
            ? static_cast<BarrierRemovalMutationState>(*err.mutation_state)
            : BarrierRemovalMutationState::NotAttempted;

        return std::unexpected(Error{
            .operation = context.operation,
            .code = ErrorCode::BarrierRemovalFailure,
            .detail = err.detail,
            .runtime = context.summary,
            .barrier_removal = BarrierRemovalFailure{
                .barrier_identifier = err.identifier.value_or(layout.barrier_identifier),
                .stage = stage,
                .mutation_state = mutation_state,
                .transport_error = err.transport_failure,
            },
        });
    }
    const auto outcome = (removed->outcome ==
                          history_storage::maintenance_protocol::
                              BarrierRemovalOutcome::Removed)
                             ? BarrierRemovalOutcome::Removed
                             : BarrierRemovalOutcome::AlreadyAbsent;
    return Response{
        .operation = context.operation,
        .runtime = context.summary,
        .data = ManualBarrierRemovalCompleted{
            .identifier = layout.barrier_identifier,
            .outcome = outcome,
            .active_writers_count = removed->active_writers_count,
        },
    };
}

std::expected<Response, Error> run_remove_writer(OperationContext& context) {
    const auto layout = history_storage::derive_remote_layout(context.key);
    auto removed = history_storage::maintenance_protocol::remove_writer(
        context.storage, layout, context.writer_identifier);
    if (!removed) {
        return std::unexpected(Error{
            .operation = context.operation,
            .code = ErrorCode::WriterRemovalFailure,
            .detail = removed.error().detail,
            .runtime = context.summary,
        });
    }
    return Response{.operation = context.operation,
                    .runtime = context.summary,
                    .data = ManualWriterRemovalCompleted{
                        .identifier = context.writer_identifier}};
}

} // namespace kasumi::application::detail
