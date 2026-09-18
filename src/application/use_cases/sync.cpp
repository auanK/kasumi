#include "application/history_storage/maintenance_protocol.hpp"
#include "application/observation/state.hpp"
#include "application/sync/coordinator.hpp"
#include "application/sync/coordinator_detail.hpp"
#include "application/sync/reobservation.hpp"
#include "application/use_cases/context.hpp"
#include "application/use_cases/error_mapping.hpp"
#include "application/use_cases/plan_support.hpp"
#include "core/reconciliation/plan.hpp"
#include "platform/perf_trace.hpp"
#include "state_storage/database.hpp"

#include <chrono>
#include <exception>
#include <optional>
#include <utility>

namespace kasumi::application::detail {

namespace {

void save_observation_checkpoint(
    const runtime::RuntimeData& runtime,
    const observation::LocalObservationSession& session,
    bool local_tree_is_authoritative) {
    if (!local_tree_is_authoritative) {
        return;
    }
    if (!session.checkpoint || !session.last_snapshot ||
        session.last_snapshot->rows.empty()) {
        return;
    }
    auto checkpoint = *session.checkpoint;
    checkpoint.tree_root_hash = session.last_snapshot->rows.front().hash;
    checkpoint.row_count = session.last_snapshot->rows.size();
    checkpoint.directory_file_references = session.directory_file_references;
    checkpoint.lineage_complete = session.lineage_complete;
    if (auto current =
            state_storage::load_observation_checkpoint(runtime.database_path);
        current && *current &&
        (*current)->tree_root_hash == checkpoint.tree_root_hash &&
        (*current)->row_count == checkpoint.row_count &&
        (*current)->journal.kind == checkpoint.journal.kind &&
        (*current)->journal.volume_serial == checkpoint.journal.volume_serial &&
        (*current)->journal.journal_id == checkpoint.journal.journal_id &&
        (*current)->journal.next_usn == checkpoint.journal.next_usn &&
        (*current)->journal.root_file_reference ==
            checkpoint.journal.root_file_reference &&
        (*current)->lineage_complete == checkpoint.lineage_complete &&
        (*current)->directory_file_references ==
            checkpoint.directory_file_references) {
        platform::perf_trace::count("checkpoint save avoided");
        return;
    }
    static_cast<void>(state_storage::save_observation_checkpoint(
        runtime.database_path, checkpoint));
}

SyncCompleted compute_sync_summary(const reconciliation::Result& result) {
    SyncCompleted summary;
    summary.total = static_cast<std::uint32_t>(sync_plan_size(result.plan));
    summary.published = result.requires_publication;

    for (const auto& op : sync_plan_operations(result.plan)) {
        switch (op.action) {
            case Action::Upload:
                ++summary.uploaded;
                summary.upload_bytes += op.size;
                break;
            case Action::Download:
                ++summary.downloaded;
                summary.download_bytes += op.size;
                break;
            case Action::DeleteLocal:
            case Action::DeleteRemote:
                ++summary.removed;
                break;
            case Action::RenameLocal:
                ++summary.renamed;
                break;
            case Action::CreateLocalDirectory:
            case Action::CreateRemoteDirectory:
                ++summary.created_dirs;
                break;
            case Action::DeleteLocalDirectory:
            case Action::DeleteRemoteDirectory:
                ++summary.removed_dirs;
                break;
            case Action::Count:
                break;
        }
    }
    return summary;
}

} // namespace

std::expected<Response, Error> run_sync(OperationContext& context) {
    const auto sync_start = std::chrono::steady_clock::now();
    platform::perf_trace::maximum(
        "configured content concurrency",
        sync::coordinator::detail::content_concurrency());
    const auto recovery_trace = platform::perf_trace::begin();
    auto recovery = sync::coordinator::recover_if_needed(
        context.runtime, context.storage, context.key);
    platform::perf_trace::finish("transaction recovery", recovery_trace);
    if (!recovery) {
        auto err = transaction_error(
            context.operation, recovery.error(), context.summary);
        err.stage = SyncStage::Observing;
        return std::unexpected(err);
    }

    observation::LocalObservationSession observation_session;
    observation_session.database_path = context.runtime.database_path;
    std::optional<history_storage::maintenance_protocol::RegistrationResult>
        eager_writer;
    history_storage::maintenance_protocol::RegistrationState writer;
    SyncStage current_stage = SyncStage::Observing;
    auto outcome = [&]() -> std::expected<Response, Error> {
        try {
            current_stage = SyncStage::Observing;
            if (context.on_progress) {
                context.on_progress(
                    SyncProgress{.stage = SyncStage::Observing});
            }
            const auto observation_trace = platform::perf_trace::begin();
            auto collected = observation::collect_reconciliation_input(
                context.runtime,
                context.storage,
                context.key,
                false,
                {},
                &observation_session,
                [&] {
                    const auto writer_trace = platform::perf_trace::begin();
                    eager_writer.emplace(
                        history_storage::maintenance_protocol::register_writer(
                            context.storage,
                            context.runtime.database_path.parent_path()));
                    platform::perf_trace::finish("writer registration",
                                                 writer_trace);
                });
            platform::perf_trace::finish("initial observation",
                                         observation_trace);
            if (!collected) {
                auto err = plan_error(context.operation,
                                      collected.error().detail,
                                      context.summary);
                err.stage = SyncStage::Observing;
                return std::unexpected(err);
            }

            current_stage = SyncStage::Calculating;
            if (context.on_progress) {
                context.on_progress(
                    SyncProgress{.stage = SyncStage::Calculating});
            }
            const auto reconciliation_trace = platform::perf_trace::begin();
            auto reconciled = reconciliation::reconcile(*collected);
            platform::perf_trace::finish("reconciliation",
                                         reconciliation_trace);
            if (!reconciled) {
                auto err = plan_error(
                    context.operation,
                    describe_reconciliation_error(reconciled.error()),
                    context.summary);
                err.stage = SyncStage::Calculating;
                return std::unexpected(err);
            }

            if (!reconciled->unrecoverable_paths.empty()) {
                auto err =
                    synchronization_error(context.operation,
                                          describe_unrecoverable_paths(
                                              reconciled->unrecoverable_paths),
                                          context.summary);
                err.stage = SyncStage::Calculating;
                return std::unexpected(err);
            }

            const bool remote_write_required =
                reconciled->requires_publication ||
                reconciled->requires_storage_repair;
            const bool active_sync = remote_write_required ||
                                     reconciled->requires_local_mutation ||
                                     reconciled->requires_state_commit;
            if (eager_writer) {
                if (!*eager_writer) {
                    auto err =
                        synchronization_error(context.operation,
                                              eager_writer->error().detail,
                                              context.summary);
                    err.stage = SyncStage::Calculating;
                    return std::unexpected(err);
                }
                writer = std::move(**eager_writer);
                (**eager_writer).storage = nullptr;
            }
            if (remote_write_required && !collected->storage.history_present) {
                const auto initialize_trace = platform::perf_trace::begin();
                auto initialized = transport::initialize(context.storage);
                platform::perf_trace::finish("remote initialize",
                                             initialize_trace);
                if (!initialized) {
                    auto err = synchronization_error(
                        context.operation,
                        transport::describe(initialized.error()),
                        context.summary);
                    err.stage = SyncStage::Calculating;
                    return std::unexpected(err);
                }
            }
            if (active_sync &&
                !history_storage::maintenance_protocol::registration_active(
                    writer)) {
                const auto writer_trace = platform::perf_trace::begin();
                auto registered =
                    history_storage::maintenance_protocol::register_writer(
                        context.storage,
                        context.runtime.database_path.parent_path());
                platform::perf_trace::finish("writer registration",
                                             writer_trace);
                if (!registered) {
                    auto err = synchronization_error(context.operation,
                                                     registered.error().detail,
                                                     context.summary);
                    err.stage = SyncStage::Calculating;
                    return std::unexpected(err);
                }
                writer = std::move(*registered);
            }

            const auto reobservation_trace = platform::perf_trace::begin();
            auto stable = sync::coordinator::reobservation::stabilize(
                context.runtime,
                context.storage,
                context.key,
                std::move(*collected),
                std::move(*reconciled),
                &observation_session);
            platform::perf_trace::finish("reobservation", reobservation_trace);
            if (!stable) {
                auto err = transaction_error(
                    context.operation, stable.error(), context.summary);
                err.stage = SyncStage::Calculating;
                return std::unexpected(err);
            }

            auto summary = compute_sync_summary(stable->result);
            if (context.on_progress) {
                context.on_progress(SyncProgress{
                    .stage = SyncStage::Calculating,
                    .summary = summary,
                    .total_items = summary.total,
                });
            }

            if (!stable->result.requires_publication &&
                !stable->result.requires_local_mutation &&
                !stable->result.requires_storage_repair &&
                !stable->result.requires_state_commit) {
                const auto finalization_trace = platform::perf_trace::begin();
                if (observation_session.cache_dirty) {
                    static_cast<void>(state_storage::save_file_cache_delta(
                        context.runtime.database_path,
                        observation_session.cache));
                } else {
                    platform::perf_trace::count("file cache save avoided");
                }
                save_observation_checkpoint(
                    context.runtime, observation_session, true);
                platform::perf_trace::finish("finalization",
                                             finalization_trace);
                summary.duration =
                    std::chrono::steady_clock::now() - sync_start;
                return Response{.operation = context.operation,
                                .runtime = context.summary,
                                .data = summary};
            }

            current_stage = SyncStage::Applying;
            if (context.on_progress) {
                context.on_progress(SyncProgress{
                    .stage = SyncStage::Applying,
                    .total_items = summary.total,
                });
            }

            const auto execution_trace = platform::perf_trace::begin();
            auto synchronized =
                sync::coordinator::execute(context.runtime,
                                           context.storage,
                                           context.key,
                                           stable->input,
                                           stable->result,
                                           &observation_session);
            platform::perf_trace::finish("transaction execution",
                                         execution_trace);
            if (!synchronized) {
                const auto fail_stage =
                    synchronized.error().code ==
                            sync::coordinator::ErrorCode::PublicationFailure
                        ? SyncStage::Publishing
                        : SyncStage::Applying;
                auto err = transaction_error(
                    context.operation, synchronized.error(), context.summary);
                err.stage = fail_stage;
                return std::unexpected(err);
            }

            if (summary.published) {
                current_stage = SyncStage::Publishing;
                if (context.on_progress) {
                    context.on_progress(SyncProgress{
                        .stage = SyncStage::Publishing,
                    });
                }
            }

            current_stage = SyncStage::Finalizing;
            if (context.on_progress) {
                context.on_progress(SyncProgress{
                    .stage = SyncStage::Finalizing,
                });
            }

            const auto finalization_trace = platform::perf_trace::begin();
            if (observation_session.cache_dirty) {
                static_cast<void>(state_storage::save_file_cache_delta(
                    context.runtime.database_path, observation_session.cache));
            } else {
                platform::perf_trace::count("file cache save avoided");
            }
            // Execution ends with a final scan of the materialized
            // state.
            save_observation_checkpoint(
                context.runtime, observation_session, true);
            platform::perf_trace::finish("finalization", finalization_trace);
            summary.duration = std::chrono::steady_clock::now() - sync_start;
            return Response{.operation = context.operation,
                            .runtime = context.summary,
                            .data = summary};
        } catch (const std::exception& exception) {
            auto err = synchronization_error(
                context.operation, exception.what(), context.summary);
            err.stage = current_stage;
            return std::unexpected(err);
        }
    }();
    auto* pending =
        history_storage::maintenance_protocol::registration_active(writer)
            ? &writer
        : eager_writer && *eager_writer &&
                history_storage::maintenance_protocol::registration_active(
                    **eager_writer)
            ? &**eager_writer
            : nullptr;
    if (pending != nullptr) {
        const auto release_trace = platform::perf_trace::begin();
        auto released =
            history_storage::maintenance_protocol::release_registration(
                *pending);
        platform::perf_trace::finish("writer release", release_trace);
        if (outcome && !released) {
            auto err = synchronization_error(
                context.operation, released.error().detail, context.summary);
            err.stage = SyncStage::Finalizing;
            return std::unexpected(err);
        }
    }
    return outcome;
}

} // namespace kasumi::application::detail
