#include "application/concurrency.hpp"
#include "application/integrity/maintenance.hpp"

#include "application/sync/coordinator.hpp"
#include "application/use_cases/context.hpp"
#include "application/use_cases/error_mapping.hpp"

#include <optional>

namespace kasumi::application::detail {
namespace {

std::expected<Response, Error> run_maintenance(OperationContext& context,
                                               bool fsck) {
    std::optional<FsckProgress> last_fsck_progress;
    integrity::FsckProgressCallback fsck_progress{};
    if (fsck && context.on_progress) {
        fsck_progress = [&context, &last_fsck_progress](const FsckProgress& progress) noexcept {
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

    if (fsck) {
        auto checked = integrity::fsck(context.runtime, context.storage, context.key,
                                        content_concurrency(),
                                        std::move(fsck_progress));
        if (!checked) {
            return std::unexpected(maintenance_error(
                context.operation, checked.error(), context.summary));
        }
        return Response{.operation = context.operation,
                        .runtime = context.summary,
                        .data = FsckCompleted{
                            .checked_objects = checked->checked_objects,
                            .checked_plaintext_bytes = last_fsck_progress
                                                         ? last_fsck_progress->completed_plaintext_bytes
                                                         : std::nullopt,
                        }};
    }

    integrity::GarbageCollectProgressCallback gc_progress{};
    if (context.on_progress) {
        gc_progress = [&context](const GarbageCollectProgress& p) {
            context.on_progress(p);
        };
    }

    auto collected = integrity::garbage_collect(
        context.runtime, context.storage, context.key,
        8, 8, 8, std::move(gc_progress));
    if (!collected) {
        return std::unexpected(maintenance_error(
            context.operation, collected.error(), context.summary));
    }
    return Response{.operation = context.operation,
                    .runtime = context.summary,
                    .data = GarbageCollectCompleted{
                        .candidate_objects = collected->candidate_objects,
                        .quarantined_objects = collected->quarantined_objects,
                        .restored_objects = collected->restored_objects,
                        .purged_objects = collected->purged_objects,
                        .analysis_only = collected->analysis_only}};
}

} // namespace

std::expected<Response, Error> run_fsck(OperationContext& context) {
    return run_maintenance(context, true);
}

std::expected<Response, Error> run_garbage_collect(OperationContext& context) {
    return run_maintenance(context, false);
}

} // namespace kasumi::application::detail
