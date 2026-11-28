#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/inspection/inspect.hpp"
#include "application/observation/state.hpp"
#include "application/progress.hpp"
#include "application/sync/coordinator.hpp"
#include "application/sync/coordinator_detail.hpp"
#include "application/sync/journal_fault_test.hpp"
#include "application/sync/reobservation.hpp"
#include "application/use_cases/context.hpp"
#include "application/use_cases/plan_support.hpp"
#include "core/hasher.hpp"
#include "core/reconciliation/plan.hpp"
#include "platform/path.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <chrono>
#include <exception>
#include <filesystem>
#include <format>
#include <optional>
#include <utility>

namespace kasumi::application::detail {

namespace {

SyncCompleted compute_sync_summary(const reconciliation::Result& result) {
    SyncCompleted summary;
    summary.total = static_cast<std::uint32_t>(sync_plan_size(result.plan));
    summary.repaired = result.repair_uploads;
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
                ++summary.copied;
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
    ProgressMeter meter(context.on_progress, context.storage);
    const auto sync_start = std::chrono::steady_clock::now();

    auto recovery = sync::coordinator::recover_if_needed(
        context.runtime, context.storage, context.key);
    if (!recovery) {
        return fail_app(context,
                        ErrorCode::SynchronizationFailure,
                        sync::coordinator::describe(recovery.error()),
                        SyncStage::Observing);
    }
    sync::journal_fault_test::hit(
        "recovery", nullptr, static_cast<std::size_t>(*recovery));
    sync::journal_fault_test::hit("recovered");
    context.recovered_transaction =
        (*recovery != sync::coordinator::RecoveryResult::NoJournal);

    observation::LocalObservationSession local_session;
    observation::LocalObservationSession* active_session = &local_session;
    if (context.warm_observation != nullptr) {
        active_session = context.warm_observation;
        if (!observation::warm_session_db_matches(
                *active_session, context.runtime.database_path)) {
            *active_session = observation::LocalObservationSession{};
            active_session->database_path = context.runtime.database_path;
        }
    } else {
        local_session.database_path = context.runtime.database_path;
    }
    struct WarmSessionProgressGuard {
        observation::LocalObservationSession* session;
        ~WarmSessionProgressGuard() noexcept {
            if (session != nullptr) {
                session->progress = nullptr;
            }
        }
    } session_progress_guard{active_session};
    active_session->progress = &meter;
    std::optional<history_storage::maintenance_protocol::RegistrationResult>
        eager_writer;
    history_storage::maintenance_protocol::RegistrationState writer;
    SyncStage current_stage = SyncStage::Observing;
    const auto notify_stage = [&](SyncStage stage,
                                  std::optional<SyncCompleted> summary_arg =
                                      std::nullopt,
                                  std::uint32_t total_items = 0) {
        current_stage = stage;
        notify_progress(meter,
                        SyncProgress{
                            .stage = stage,
                            .summary = std::move(summary_arg),
                            .total_items = total_items,
                        });
        if (stage == SyncStage::Observing) {
            begin_progress_phase(meter, Activity::Scanning);
        }
    };
    auto outcome = [&]() -> std::expected<Response, Error> {
        try {
            const auto layout =
                history_storage::derive_remote_layout(context.key);
            SyncCompleted summary;
            std::optional<sync::coordinator::reobservation::StableExecution>
                stable;
            struct StagedHandoffGuard {
                std::optional<
                    sync::coordinator::reobservation::StableExecution>& stable;
                std::span<const std::uint8_t, crypto::KEY_SIZE> key;
                ~StagedHandoffGuard() noexcept {
                    if (stable) {
                        static_cast<void>(
                            sync::coordinator::discard_staged_handoff(
                                stable->staged, key));
                    }
                }
            } staged_guard{stable, context.key};
            bool allow_unreferenced_content_reuse = false;

            const auto finish_summary = [&] {
                if (active_session->cache_dirty) {
                    if (state_storage::save_file_cache_delta(
                            context.runtime.database_path,
                            active_session->cache)) {
                        active_session->cache_dirty = false;
                    }
                }
                summary.wire_upload_bytes = meter.wire.upload.bytes.load();
                summary.wire_download_bytes = meter.wire.download.bytes.load();
                summary.physical_objects_uploaded =
                    meter.wire.upload.objects.load();
                summary.physical_objects_downloaded =
                    meter.wire.download.objects.load();
                summary.local_delta_reused_bytes = meter.bytes_reused.load();
                summary.duration =
                    std::chrono::steady_clock::now() - sync_start;
                return make_response(context, summary);
            };

            const auto update_progress_after_stabilize = [&]() {
                summary = compute_sync_summary(stable->result);
                notify_stage(SyncStage::Calculating, summary, summary.total);
                return !stable->result.requires_publication &&
                       !stable->result.requires_local_mutation &&
                       !stable->result.requires_storage_repair &&
                       !stable->result.requires_state_commit;
            };

            const bool enforce_empty_local_guard =
                *recovery == sync::coordinator::RecoveryResult::NoJournal &&
                !context.initial_sync && !context.repair &&
                !context.allow_empty_local;

            const auto prepare_pass =
                [&](bool initial_pass,
                    std::span<const std::string> marked_heads,
                    std::span<const Hash> confirmed_missing)
                -> std::expected<void, Error> {
                if (initial_pass) {
                    notify_stage(SyncStage::Observing);
                }
                auto collected = observation::collect_reconciliation_input(
                    context.runtime,
                    context.storage,
                    context.key,
                    false,
                    marked_heads,
                    active_session,
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
                    return fail_app(context,
                                    ErrorCode::PlanFailure,
                                    collected.error().detail,
                                    SyncStage::Observing);
                }
                if (initial_pass) {
                    if (context.initial_sync &&
                        context.has_remote_history_objects &&
                        !collected->storage.history_present) {
                        return fail_app(
                            context,
                            ErrorCode::PlanFailure,
                            "remote history contains head markers but no "
                            "valid authenticated history could be observed",
                            SyncStage::Observing);
                    }
                    notify_stage(SyncStage::Calculating);
                } else {
                    collected->known_missing_content_objects.insert(
                        confirmed_missing.begin(), confirmed_missing.end());
                }

                begin_progress_phase(meter, Activity::ComparingSnapshots);
                auto reconciled = reconciliation::reconcile(*collected);
                if (!reconciled) {
                    return fail_app(
                        context,
                        ErrorCode::PlanFailure,
                        describe_reconciliation_error(reconciled.error()),
                        SyncStage::Calculating);
                }

                if (enforce_empty_local_guard) {
                    if (auto guarded = sync::coordinator::
                            check_empty_local_deletion_guard(
                                context.runtime.local_dir,
                                *collected,
                                *reconciled);
                        !guarded) {
                        auto err = make_error(context,
                                              ErrorCode::SynchronizationFailure,
                                              guarded.error().detail,
                                              SyncStage::Calculating);
                        err.empty_local_blocked =
                            guarded.error().empty_local_blocked;
                        return std::unexpected(std::move(err));
                    }
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
                            &meter,
                            context.repair);
                    if (!available) {
                        return fail_app(
                            context,
                            ErrorCode::SynchronizationFailure,
                            sync::coordinator::describe(available.error()),
                            SyncStage::Calculating);
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
                            return fail_app(context,
                                            ErrorCode::SynchronizationFailure,
                                            eager_writer->error().detail,
                                            SyncStage::Calculating);
                        }
                        writer = std::move(**eager_writer);
                        (**eager_writer).storage = nullptr;
                    }
                    const bool initialize_storage =
                        remote_write_required &&
                        !collected->storage.history_present;
                    const bool register_writer =
                        active_sync && !history_storage::maintenance_protocol::
                                           registration_active(writer);
                    if (initialize_storage || register_writer) {
                        begin_progress_phase(meter, Activity::PreparingRemote);
                    }
                    if (initialize_storage) {
                        if (auto initialized =
                                transport::initialize(context.storage);
                            !initialized) {
                            return fail_app(
                                context,
                                ErrorCode::SynchronizationFailure,
                                transport::describe(initialized.error()),
                                SyncStage::Calculating);
                        }
                    }
                    if (register_writer) {
                        auto registered = history_storage::
                            maintenance_protocol::register_writer(
                                context.storage,
                                layout,
                                context.runtime.database_path.parent_path());
                        if (!registered) {
                            return fail_app(context,
                                            ErrorCode::SynchronizationFailure,
                                            registered.error().detail,
                                            SyncStage::Calculating);
                        }
                        writer = std::move(*registered);
                    }
                }

                if (stable) {
                    if (auto discarded =
                            sync::coordinator::discard_staged_handoff(
                                stable->staged, context.key);
                        !discarded) {
                        return fail_app(context,
                                        ErrorCode::SynchronizationFailure,
                                        discarded.error().detail,
                                        SyncStage::Calculating);
                    }
                }
                auto stabilized = sync::coordinator::reobservation::stabilize(
                    context.runtime,
                    context.storage,
                    context.key,
                    std::move(*collected),
                    std::move(*reconciled),
                    active_session,
                    confirmed_missing,
                    initial_pass,
                    allow_unreferenced_content_reuse,
                    true,
                    context.repair,
                    enforce_empty_local_guard);
                if (!stabilized) {
                    if (stabilized.error().empty_local_blocked) {
                        auto err = make_error(context,
                                              ErrorCode::SynchronizationFailure,
                                              stabilized.error().detail,
                                              SyncStage::Calculating);
                        err.empty_local_blocked = true;
                        return std::unexpected(std::move(err));
                    }
                    return fail_app(
                        context,
                        ErrorCode::SynchronizationFailure,
                        sync::coordinator::describe(stabilized.error()),
                        SyncStage::Calculating);
                }
                stable = std::move(*stabilized);
                return {};
            };

            if (auto first = prepare_pass(true, {}, {}); !first) {
                return std::unexpected(first.error());
            }
            if (update_progress_after_stabilize()) {
                context.accepted_commit_id = stable->input.base_commit_id;
                return finish_summary();
            }
            if (auto space = check_sync_disk_space(
                    context.runtime.local_dir,
                    context.runtime.database_path.parent_path(),
                    stable->result.plan);
                !space) {
                auto err = make_error(context,
                                      ErrorCode::SynchronizationFailure,
                                      space.error(),
                                      SyncStage::Calculating);
                err.insufficient_disk_space = true;
                return std::unexpected(std::move(err));
            }

            notify_stage(SyncStage::Applying, {}, summary.total);

            std::vector<Hash> confirmed_missing;
            std::expected<void, sync::coordinator::Error> synchronized;
            for (std::size_t attempt = 0; attempt < 3; ++attempt) {
                begin_progress_phase(meter, Activity::PreparingRemote);
                auto admission = history_storage::maintenance_protocol::
                    verify_writer_admission(
                        writer,
                        layout,
                        stable->result.requires_publication &&
                                !stable->input.storage.history_present
                            ? std::optional{history_storage::
                                                maintenance_protocol::
                                                    GenesisAdmission{}}
                            : std::nullopt);
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
                if (!context.sync_mutated) {
                    context.sync_mutated = true;
                    if (context.on_sync_mutation_start) {
                        context.on_sync_mutation_start();
                    }
                }
                history::CommitAuthorship authorship;
                if (context.machine_identity) {
                    authorship = make_commit_authorship(
                        history::CommitOriginOperation::Sync,
                        *context.machine_identity);
                }
                synchronized = sync::coordinator::execute(
                    context.runtime,
                    context.storage,
                    context.key,
                    stable->input,
                    stable->result,
                    active_session,
                    stable->staged ? &*stable->staged : nullptr,
                    true,
                    std::move(authorship),
                    &context.accepted_commit_id,
                    enforce_empty_local_guard);
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
                notify_stage(SyncStage::Calculating);
                begin_progress_phase(meter,
                                     Activity::Reobserving,
                                     std::nullopt,
                                     static_cast<unsigned>(attempt + 2));

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
                if (auto space = check_sync_disk_space(
                        context.runtime.local_dir,
                        context.runtime.database_path.parent_path(),
                        stable->result.plan);
                    !space) {
                    auto err = make_error(context,
                                          ErrorCode::SynchronizationFailure,
                                          space.error(),
                                          SyncStage::Calculating);
                    err.insufficient_disk_space = true;
                    return std::unexpected(std::move(err));
                }
                notify_stage(SyncStage::Applying, {}, summary.total);
            }
            if (!synchronized) {
                if (synchronized.error().empty_local_blocked) {
                    auto err = make_error(context,
                                          ErrorCode::SynchronizationFailure,
                                          synchronized.error().detail,
                                          SyncStage::Calculating);
                    err.empty_local_blocked = true;
                    return std::unexpected(std::move(err));
                }
                const auto fail_stage =
                    synchronized.error().code ==
                            sync::coordinator::ErrorCode::PublicationFailure
                        ? SyncStage::Publishing
                        : SyncStage::Applying;
                return fail_app(
                    context,
                    ErrorCode::SynchronizationFailure,
                    sync::coordinator::describe(synchronized.error()),
                    fail_stage);
            }

            return finish_summary();
        } catch (const std::exception& exception) {
            return fail_app(context,
                            ErrorCode::SynchronizationFailure,
                            exception.what(),
                            current_stage);
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
            return fail_app(context,
                            ErrorCode::SynchronizationFailure,
                            released.error().detail,
                            SyncStage::Finalizing);
        }
    }
    if (outcome && context.audit_inventory) {
        const auto* summary = std::get_if<SyncCompleted>(&outcome->data);
        if (summary == nullptr) {
            return fail_app(context,
                            ErrorCode::InventoryAuditFailure,
                            "sync completed without a synchronization summary");
        }
        begin_progress_phase(meter, Activity::Auditing);
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
