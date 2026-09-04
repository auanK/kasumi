#include "application/integrity/maintenance.hpp"

#include "application/sync/coordinator.hpp"
#include "application/use_cases/context.hpp"
#include "application/use_cases/error_mapping.hpp"

namespace kasumi::application::detail {
namespace {

std::expected<Response, Error> run_maintenance(OperationContext& context,
                                               bool fsck) {
    auto recovery = sync::coordinator::recover_if_needed(
        context.runtime, context.storage, context.key);
    if (!recovery) {
        return std::unexpected(maintenance_recovery_error(
            context.operation, recovery.error(), context.summary));
    }

    if (fsck) {
        auto checked =
            integrity::fsck(context.runtime, context.storage, context.key);
        if (!checked) {
            return std::unexpected(maintenance_error(
                context.operation, checked.error(), context.summary));
        }
        return Response{.operation = context.operation,
                        .runtime = context.summary,
                        .data = FsckCompleted{}};
    }

    auto collected = integrity::garbage_collect(
        context.runtime, context.storage, context.key);
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
