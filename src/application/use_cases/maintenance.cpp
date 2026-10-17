#include "application/integrity/maintenance.hpp"

#include "application/concurrency.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/sync/coordinator.hpp"
#include "application/use_cases/context.hpp"
#include "application/use_cases/error_mapping.hpp"

#include <optional>

namespace kasumi::application::detail {

std::expected<Response, Error> run_fsck(OperationContext& context) {
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
