#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/inspection/inspect.hpp"
#include "application/observation/state.hpp"
#include "application/sync/coordinator.hpp"
#include "application/sync/coordinator_detail.hpp"
#include "application/sync/journal_fault_test.hpp"
#include "application/sync/reobservation.hpp"
#include "application/use_cases/context.hpp"
#include "application/use_cases/error_mapping.hpp"
#include "application/use_cases/plan_support.hpp"
#include "core/hasher.hpp"
#include "core/reconciliation/plan.hpp"
#include "platform/path.hpp"
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
            case Action::DeleteIgnoredLocalFile:
            case Action::DeleteRemote:
                ++summary.removed;
                break;
            case Action::RenameLocal:
            case Action::MoveLocal:
                ++summary.renamed;
                break;
            case Action::CopyLocal:
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
    const auto with_stage = [](SyncStage stage, Error err) {
        err.stage = stage;
        return std::unexpected(std::move(err));
    };
    const auto plan_fail = [&](SyncStage stage, std::string detail) {
        return with_stage(
            stage,
            plan_error(context.operation, std::move(detail), context.summary));
    };
    const auto tx_fail = [&](SyncStage stage,
                             const sync::coordinator::Error& error) {
        return with_stage(
            stage,
            transaction_error(context.operation, error, context.summary));
    };
    const auto sync_fail = [&](SyncStage stage, std::string detail) {
        return with_stage(stage,
                          synchronization_error(context.operation,
                                                std::move(detail),
                                                context.summary));
    };

    auto recovery = sync::coordinator::recover_if_needed(
        context.runtime, context.storage, context.key);
    if (!recovery) {
        return tx_fail(SyncStage::Observing, recovery.error());
    }
    sync::journal_fault_test::hit(
        "recovery", nullptr, static_cast<std::size_t>(*recovery));
    sync::journal_fault_test::hit("recovered");

    observation::LocalObservationSession observation_session;
    observation_session.database_path = context.runtime.database_path;
    std::optional<history_storage::maintenance_protocol::RegistrationResult>
        eager_writer;
    history_storage::maintenance_protocol::RegistrationState writer;
    SyncStage current_stage = SyncStage::Observing;
    const auto notify_stage = [&](SyncStage stage,
                                  SyncCompleted summary_arg = {},
                                  std::uint32_t total_items = 0) {
        current_stage = stage;
        if (context.on_progress) {
            context.on_progress(SyncProgress{
                .stage = stage,
                .summary = std::move(summary_arg),
                .total_items = total_items,
            });
        }
    };
    auto outcome = [&]() -> std::expected<Response, Error> {
        try {
            const auto layout =
                history_storage::derive_remote_layout(context.key);
            SyncCompleted summary;
            std::optional<sync::coordinator::reobservation::StableExecution>
                stable;
            bool allow_unreferenced_content_reuse = false;

            const auto finish_summary = [&] {
                if (observation_session.cache_dirty) {
                    static_cast<void>(state_storage::save_file_cache_delta(
                        context.runtime.database_path,
                        observation_session.cache));
                }
                summary.duration =
                    std::chrono::steady_clock::now() - sync_start;
                return Response{.operation = context.operation,
                                .runtime = context.summary,
                                .data = summary};
            };

            const auto update_progress_after_stabilize = [&]() {
                summary = compute_sync_summary(stable->result);
                summary.trusted_content_reused = static_cast<std::uint32_t>(
                    stable->input.trusted_remote_content_objects.size());
                notify_stage(SyncStage::Calculating, summary, summary.total);
                return !stable->result.requires_publication &&
                       !stable->result.requires_local_mutation &&
                       !stable->result.requires_storage_repair &&
                       !stable->result.requires_state_commit;
            };

            const auto prepare_pass =
                [&](bool initial_pass,
                    std::span<const std::string> marked_heads,
                    std::span<const Hash> confirmed_missing)
                -> std::expected<void, Error> {
                if (initial_pass) {
                    notify_stage(SyncStage::Observing);
                } else {
                    notify_stage(SyncStage::Calculating);
                }
                auto collected = observation::collect_reconciliation_input(
                    context.runtime,
                    context.storage,
                    context.key,
                    false,
                    marked_heads,
                    &observation_session,
                    initial_pass ? std::function<void()>{[&] {
                        eager_writer.emplace(
                            history_storage::maintenance_protocol::
                                register_writer(context.storage,
                                                layout,
                                                context.runtime.database_path
                                                    .parent_path()));
                    }}
                                 : std::function<void()>{});
                if (!collected) {
                    return plan_fail(SyncStage::Observing,
                                     collected.error().detail);
                }
                if (initial_pass) {
                    if (context.trust_existing_content &&
                        collected->storage.history_present) {
                        return plan_fail(
                            SyncStage::Observing,
                            "remote history was published concurrently "
                            "during initial sync with "
                            "--trust-existing-content; operation was "
                            "rejected to prevent unverified content reuse");
                    }
                    if (context.initial_sync &&
                        context.has_remote_history_objects &&
                        !collected->storage.history_present) {
                        return plan_fail(
                            SyncStage::Observing,
                            "remote history contains head markers but no "
                            "valid authenticated history could be observed");
                    }
                    notify_stage(SyncStage::Calculating);
                } else {
                    collected->known_missing_content_objects.insert(
                        confirmed_missing.begin(), confirmed_missing.end());
                }

                auto reconciled = reconciliation::reconcile(*collected);
                if (!reconciled) {
                    return plan_fail(
                        SyncStage::Calculating,
                        describe_reconciliation_error(reconciled.error()));
                }

                if (initial_pass) {
                    allow_unreferenced_content_reuse =
                        context.initial_sync &&
                        !collected->storage.history_present;
                    auto available = sync::coordinator::reobservation::
                        refresh_content_availability(
                            *collected,
                            *reconciled,
                            context.storage,
                            context.key,
                            {},
                            allow_unreferenced_content_reuse,
                            context.trust_existing_content,
                            &context.initial_content_identifiers);
                    if (!available) {
                        return tx_fail(SyncStage::Calculating,
                                       available.error());
                    }
                    reconciled = std::move(*available);

                    const bool remote_write_required =
                        reconciled->requires_publication ||
                        reconciled->requires_storage_repair;
                    const bool active_sync =
                        remote_write_required ||
                        reconciled->requires_local_mutation ||
                        reconciled->requires_state_commit;
                    if (eager_writer) {
                        if (!*eager_writer) {
                            return sync_fail(SyncStage::Calculating,
                                             eager_writer->error().detail);
                        }
                        writer = std::move(**eager_writer);
                        (**eager_writer).storage = nullptr;
                    }
                    if (remote_write_required &&
                        !collected->storage.history_present) {
                        if (auto initialized =
                                transport::initialize(context.storage);
                            !initialized) {
                            return sync_fail(
                                SyncStage::Calculating,
                                transport::describe(initialized.error()));
                        }
                    }
                    if (active_sync && !history_storage::maintenance_protocol::
                                           registration_active(writer)) {
                        auto registered = history_storage::
                            maintenance_protocol::register_writer(
                                context.storage,
                                layout,
                                context.runtime.database_path.parent_path());
                        if (!registered) {
                            return sync_fail(SyncStage::Calculating,
                                             registered.error().detail);
                        }
                        writer = std::move(*registered);
                    }
                }

                auto stabilized = sync::coordinator::reobservation::stabilize(
                    context.runtime,
                    context.storage,
                    context.key,
                    std::move(*collected),
                    std::move(*reconciled),
                    &observation_session,
                    confirmed_missing,
                    initial_pass,
                    allow_unreferenced_content_reuse,
                    context.trust_existing_content,
                    &context.initial_content_identifiers);
                if (!stabilized) {
                    return tx_fail(SyncStage::Calculating, stabilized.error());
                }
                stable = std::move(*stabilized);
                return {};
            };

            if (auto first = prepare_pass(true, {}, {}); !first) {
                return std::unexpected(first.error());
            }
            if (update_progress_after_stabilize()) {
                return finish_summary();
            }

            notify_stage(SyncStage::Applying, {}, summary.total);

            std::vector<Hash> confirmed_missing;
            std::expected<void, sync::coordinator::Error> synchronized;
            for (std::size_t attempt = 0; attempt < 3; ++attempt) {
                auto admission = history_storage::maintenance_protocol::
                    verify_writer_admission(writer, layout);
                if (!admission) {
                    synchronized = std::unexpected(sync::coordinator::Error{
                        .code = admission.error().code ==
                                        history_storage::maintenance_protocol::
                                            ErrorCode::Blocked
                                    ? sync::coordinator::ErrorCode::
                                          ConcurrentModification
                                    : sync::coordinator::ErrorCode::
                                          ObservationFailure,
                        .detail = admission.error().detail,
                    });
                    break;
                }
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

                if (auto retry = prepare_pass(
                        false,
                        stable->input.storage.marked_head_identifiers,
                        confirmed_missing);
                    !retry) {
                    return std::unexpected(retry.error());
                }
                if (update_progress_after_stabilize()) {
                    synchronized = {};
                    break;
                }
                notify_stage(SyncStage::Applying, {}, summary.total);
            }
            if (!synchronized) {
                const auto fail_stage =
                    synchronized.error().code ==
                            sync::coordinator::ErrorCode::PublicationFailure
                        ? SyncStage::Publishing
                        : SyncStage::Applying;
                return tx_fail(fail_stage, synchronized.error());
            }

            if (summary.published) {
                notify_stage(SyncStage::Publishing);
            }

            notify_stage(SyncStage::Finalizing);
            return finish_summary();
        } catch (const std::exception& exception) {
            return sync_fail(current_stage, exception.what());
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
        auto released =
            history_storage::maintenance_protocol::release_registration(
                *pending);
        if (outcome && !released) {
            return sync_fail(SyncStage::Finalizing, released.error().detail);
        }
    }
    if (outcome && context.audit_inventory) {
        const auto* summary = std::get_if<SyncCompleted>(&outcome->data);
        if (summary == nullptr) {
            return std::unexpected(Error{
                .operation = context.operation,
                .code = ErrorCode::InventoryAuditFailure,
                .detail = "sync completed without a synchronization summary",
                .runtime = context.summary,
            });
        }
        const auto audit = audit_remote_inventory(context.storage, context.key);
        if (!audit) {
            return std::unexpected(Error{
                .operation = context.operation,
                .code = ErrorCode::InventoryAuditFailure,
                .detail = audit.error(),
                .runtime = context.summary,
                .sync_completed = *summary,
            });
        }
        outcome->inventory_audit = *audit;
    }
    return outcome;
}

} // namespace kasumi::application::detail
