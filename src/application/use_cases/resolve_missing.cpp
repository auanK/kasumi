#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/observation/state.hpp"
#include "application/progress.hpp"
#include "application/sync/coordinator.hpp"
#include "application/sync/coordinator_detail.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/reobservation.hpp"
#include "application/use_cases/context.hpp"
#include "application/use_cases/plan_support.hpp"
#include "core/reconciliation/plan.hpp"
#include "platform/path.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <unordered_set>
#include <utility>
#include <vector>

namespace kasumi::application::detail {

std::expected<Response, Error> run_resolve_missing(OperationContext& context) {
    ProgressMeter meter(context.on_progress, context.storage);
    meter.notify(SyncProgress{.stage = SyncStage::Observing});
    meter.phase(Activity::Scanning);
    if (context.dry_run) {
        const auto journal_paths = sync::journal::make_paths(
            context.runtime.database_path.parent_path());
        if (!journal_paths) {
            return fail_app(context,
                            ErrorCode::SynchronizationFailure,
                            "cannot inspect local transaction journal: " +
                                journal_paths.error());
        }
        const auto journal_state =
            sync::journal::inspect(*journal_paths, context.key);
        if (journal_state != sync::journal::InspectionResult::Absent) {
            return fail_app(
                context,
                ErrorCode::SynchronizationFailure,
                "pending or invalid local transaction journal exists; complete "
                "recovery with sync before resolve-missing --dry-run");
        }
    } else {
        auto recovered = sync::coordinator::recover_if_needed(
            context.runtime, context.storage, context.key);
        if (!recovered) {
            return std::unexpected(
                make_error(context,
                           ErrorCode::SynchronizationFailure,
                           sync::coordinator::describe(recovered.error())));
        }
    }

    auto state = state_storage::load_state(context.runtime.database_path);
    if (!state || !*state) {
        return fail_app(context,
                        ErrorCode::RuntimeFailure,
                        "failed to load accepted state");
    }

    if ((*state)->pending_materializations.empty()) {
        return make_response(context,
                             ResolveMissingCompleted{
                                 .resolved_count = 0,
                                 .resolved_paths = {},
                                 .published = false,
                                 .dry_run = context.dry_run,
                             });
    }

    const auto authority = (*state)->pending_materializations;

    observation::LocalObservationSession session;
    session.progress = &meter;
    auto collected = observation::collect_reconciliation_input(
        context.runtime, context.storage, context.key, false, {}, &session);
    if (!collected) {
        return std::unexpected(make_error(
            context, ErrorCode::PlanFailure, collected.error().detail));
    }

    collected->pending_deletion_authority = authority;

    meter.notify(SyncProgress{.stage = SyncStage::Calculating});
    meter.phase(Activity::ComparingSnapshots);
    auto reconciled = reconciliation::reconcile(*collected);
    if (!reconciled) {
        return std::unexpected(
            make_error(context,
                       ErrorCode::PlanFailure,
                       describe_reconciliation_error(reconciled.error())));
    }

    auto stable =
        sync::coordinator::reobservation::stabilize(context.runtime,
                                                    context.storage,
                                                    context.key,
                                                    std::move(*collected),
                                                    std::move(*reconciled),
                                                    &session,
                                                    {},
                                                    false,
                                                    false,
                                                    true);
    if (!stable) {
        return std::unexpected(
            make_error(context,
                       ErrorCode::SynchronizationFailure,
                       sync::coordinator::describe(stable.error())));
    }
    struct StagedHandoffGuard {
        std::optional<sync::coordinator::StagedExecutionHandoff>& staged;
        std::span<const std::uint8_t, crypto::KEY_SIZE> key;
        ~StagedHandoffGuard() noexcept {
            static_cast<void>(
                sync::coordinator::discard_staged_handoff(staged, key));
        }
    } staged_guard{stable->staged, context.key};

    meter.phase(Activity::PreparingPlan);
    std::unordered_set<std::string> eligible_paths;
    for (const auto& auth_row : authority) {
        const auto pending =
            std::ranges::find(stable->input.pending_materializations, auth_row);
        if (pending == stable->input.pending_materializations.end()) {
            continue;
        }
        const auto* remote =
            find_row(stable->input.storage.tree, auth_row.path);
        const bool has_local_source = std::ranges::any_of(
            stable->input.local_tree.rows, [&](const NodeRow& r) {
                return !r.is_directory && r.hash == auth_row.hash;
            });
        if (remote != nullptr && !remote->is_directory &&
            remote->hash == auth_row.hash && remote->size == auth_row.size &&
            find_row(stable->input.local_tree, auth_row.path) == nullptr &&
            !has_local_source &&
            stable->result.missing_objects.contains(auth_row.hash)) {
            eligible_paths.insert(auth_row.path);
        }
    }

    std::vector<std::string> resolved_paths;
    for (const auto& op : sync_plan_operations(stable->result.plan)) {
        const auto op_path = platform::path::to_logical_utf8(op.path);
        if (op.action != Action::DeleteRemote ||
            !eligible_paths.contains(op_path) ||
            std::ranges::find(resolved_paths, op_path) !=
                resolved_paths.end()) {
            return std::unexpected(Error{
                .operation = context.operation,
                .code = ErrorCode::RecoveryFailure,
                .detail =
                    std::string(
                        "plan contains unauthorized sync operations: action=") +
                    std::to_string(static_cast<int>(op.action)) +
                    " path=" + op_path,
                .runtime = context.summary,
            });
        }
        resolved_paths.push_back(op_path);
    }

    auto expected_tree = stable->input.storage.tree;
    std::erase_if(expected_tree.rows, [&](const NodeRow& row) {
        return std::ranges::find(resolved_paths, row.path) !=
               resolved_paths.end();
    });
    finalize_snapshot(expected_tree);
    if (stable->result.requires_local_mutation ||
        stable->result.requires_storage_repair ||
        expected_tree != stable->result.candidate_shared_tree) {
        return fail_app(context,
                        ErrorCode::RecoveryFailure,
                        "plan contains unrelated logical mutations");
    }

    if (context.dry_run || resolved_paths.empty()) {
        return make_response(context,
                             ResolveMissingCompleted{
                                 .resolved_count = resolved_paths.size(),
                                 .resolved_paths = std::move(resolved_paths),
                                 .published = false,
                                 .dry_run = context.dry_run,
                             });
    }

    history_storage::maintenance_protocol::RegistrationState writer;
    struct WriterGuard {
        history_storage::maintenance_protocol::RegistrationState& state;
        ~WriterGuard() noexcept {
            try {
                static_cast<void>(
                    history_storage::maintenance_protocol::release_registration(
                        state));
            } catch (...) {
            }
        }
    } writer_guard{writer};
    if (stable->result.requires_publication) {
        meter.phase(Activity::PreparingRemote);
        const auto layout = history_storage::derive_remote_layout(context.key);
        auto registered =
            history_storage::maintenance_protocol::register_writer(
                context.storage,
                layout,
                context.runtime.database_path.parent_path());
        if (!registered) {
            return std::unexpected(make_error(context,
                                              ErrorCode::SynchronizationFailure,
                                              registered.error().detail));
        }
        writer = std::move(*registered);
    }

    meter.notify(SyncProgress{
        .stage = SyncStage::Applying,
        .total_items =
            static_cast<std::uint32_t>(sync_plan_size(stable->result.plan)),
    });
    history::CommitAuthorship authorship;
    if (context.machine_identity) {
        authorship = make_commit_authorship(
            history::CommitOriginOperation::ResolveMissing,
            *context.machine_identity);
    }
    auto synchronized = sync::coordinator::execute(
        context.runtime,
        context.storage,
        context.key,
        stable->input,
        stable->result,
        &session,
        stable->staged ? &*stable->staged : nullptr,
        false,
        std::move(authorship),
        &context.accepted_commit_id);

    if (history_storage::maintenance_protocol::registration_active(writer)) {
        auto released =
            history_storage::maintenance_protocol::release_registration(writer);
        if (synchronized && !released) {
            return std::unexpected(make_error(context,
                                              ErrorCode::SynchronizationFailure,
                                              released.error().detail));
        }
    }

    if (!synchronized) {
        return std::unexpected(
            make_error(context,
                       ErrorCode::SynchronizationFailure,
                       sync::coordinator::describe(synchronized.error())));
    }

    return make_response(context,
                         ResolveMissingCompleted{
                             .resolved_count = resolved_paths.size(),
                             .resolved_paths = std::move(resolved_paths),
                             .published = stable->result.requires_publication,
                         });
}

} // namespace kasumi::application::detail
