#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/observation/state.hpp"
#include "application/sync/coordinator.hpp"
#include "application/sync/coordinator_detail.hpp"
#include "application/sync/reobservation.hpp"
#include "application/use_cases/context.hpp"
#include "application/use_cases/error_mapping.hpp"
#include "application/use_cases/plan_support.hpp"
#include "core/hasher.hpp"
#include "core/reconciliation/plan.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "state_storage/database.hpp"

#include <chrono>
#include <exception>
#include <optional>
#include <utility>

namespace kasumi::application::detail {

namespace {

SyncCompleted compute_sync_summary(const reconciliation::Result& result) {
    SyncCompleted summary;
    summary.total = static_cast<std::uint32_t>(sync_plan_size(result.plan));
    summary.published = result.requires_publication;
    summary.pending =
        static_cast<std::uint32_t>(result.pending_materializations.size());
    summary.partial = !result.pending_materializations.empty();
    for (const auto& row : result.pending_materializations) {
        summary.pending_paths.push_back(platform::path::from_utf8(row.path));
    }

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
            const auto layout =
                history_storage::derive_remote_layout(context.key);
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
                            layout,
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
                        layout,
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
            std::vector<Hash> confirmed_missing;
            std::expected<void, sync::coordinator::Error> synchronized;
            for (std::size_t attempt = 0; attempt < 3; ++attempt) {
                synchronized = sync::coordinator::execute(context.runtime,
                                                          context.storage,
                                                          context.key,
                                                          stable->input,
                                                          stable->result,
                                                          &observation_session);
                if (synchronized ||
                    synchronized.error().code !=
                        sync::coordinator::ErrorCode::RemoteContentMissing) {
                    break;
                }
                if (attempt + 1 == 3) {
                    synchronized = std::unexpected(sync::coordinator::Error{
                        .code = sync::coordinator::ErrorCode::
                            ConcurrentModification,
                        .detail = "content availability changed repeatedly"});
                    break;
                }

                const auto operations =
                    sync_plan_operations(stable->result.plan);
                const auto index = synchronized.error().operation_index;
                if (!index || *index >= operations.size()) {
                    break;
                }
                const auto missing_hash =
                    hash_from_hex(operations[*index].hash);
                if (!missing_hash) {
                    break;
                }
                confirmed_missing.push_back(*missing_hash);

                current_stage = SyncStage::Calculating;
                if (context.on_progress) {
                    context.on_progress(
                        SyncProgress{.stage = SyncStage::Calculating});
                }
                auto refreshed = observation::collect_reconciliation_input(
                    context.runtime,
                    context.storage,
                    context.key,
                    false,
                    stable->input.storage.marked_head_identifiers,
                    &observation_session);
                if (!refreshed) {
                    auto err = plan_error(context.operation,
                                          refreshed.error().detail,
                                          context.summary);
                    err.stage = SyncStage::Observing;
                    return std::unexpected(err);
                }
                refreshed->known_missing_content_objects.insert(
                    confirmed_missing.begin(), confirmed_missing.end());
                auto replanned = reconciliation::reconcile(*refreshed);
                if (!replanned) {
                    auto err = plan_error(
                        context.operation,
                        describe_reconciliation_error(replanned.error()),
                        context.summary);
                    err.stage = SyncStage::Calculating;
                    return std::unexpected(err);
                }
                auto restabilized = sync::coordinator::reobservation::stabilize(
                    context.runtime,
                    context.storage,
                    context.key,
                    std::move(*refreshed),
                    std::move(*replanned),
                    &observation_session,
                    confirmed_missing);
                if (!restabilized) {
                    auto err = transaction_error(context.operation,
                                                 restabilized.error(),
                                                 context.summary);
                    err.stage = SyncStage::Calculating;
                    return std::unexpected(err);
                }
                stable = std::move(restabilized);
                summary = compute_sync_summary(stable->result);
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
                    synchronized = {};
                    break;
                }
                current_stage = SyncStage::Applying;
                if (context.on_progress) {
                    context.on_progress(SyncProgress{
                        .stage = SyncStage::Applying,
                        .total_items = summary.total,
                    });
                }
            }
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
