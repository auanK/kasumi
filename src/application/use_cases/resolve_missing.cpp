#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/observation/state.hpp"
#include "application/sync/coordinator.hpp"
#include "application/sync/coordinator_detail.hpp"
#include "application/sync/reobservation.hpp"
#include "application/use_cases/context.hpp"
#include "application/use_cases/error_mapping.hpp"
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
    auto recovered = sync::coordinator::recover_if_needed(
        context.runtime, context.storage, context.key);
    if (!recovered) {
        return std::unexpected(transaction_error(
            context.operation, recovered.error(), context.summary));
    }

    auto state = state_storage::load_state(context.runtime.database_path);
    if (!state || !*state) {
        return std::unexpected(Error{
            .operation = context.operation,
            .code = ErrorCode::RuntimeFailure,
            .detail = "failed to load accepted state",
            .runtime = context.summary,
        });
    }

    if ((*state)->pending_materializations.empty()) {
        return Response{
            .operation = context.operation,
            .runtime = context.summary,
            .data = ResolveMissingCompleted{
                .resolved_count = 0,
                .resolved_paths = {},
                .published = false,
            },
        };
    }

    const auto authority = (*state)->pending_materializations;

    observation::LocalObservationSession session;
    auto collected = observation::collect_reconciliation_input(
        context.runtime,
        context.storage,
        context.key,
        false,
        {},
        &session);
    if (!collected) {
        return std::unexpected(plan_error(
            context.operation, collected.error().detail, context.summary));
    }

    collected->pending_deletion_authority = authority;

    auto reconciled = reconciliation::reconcile(*collected);
    if (!reconciled) {
        return std::unexpected(plan_error(
            context.operation,
            describe_reconciliation_error(reconciled.error()),
            context.summary));
    }


    auto stable = sync::coordinator::reobservation::stabilize(
        context.runtime,
        context.storage,
        context.key,
        std::move(*collected),
        std::move(*reconciled),
        &session);
    if (!stable) {
        return std::unexpected(transaction_error(
            context.operation, stable.error(), context.summary));
    }

    std::unordered_set<std::string> eligible_paths;
    for (const auto& auth_row : authority) {
        const auto pending = std::ranges::find(
            stable->input.pending_materializations, auth_row);
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
            std::ranges::find(resolved_paths, op_path) != resolved_paths.end()) {
            return std::unexpected(Error{
                .operation = context.operation,
                .code = ErrorCode::RecoveryFailure,
                .detail = std::string("plan contains unauthorized sync operations: action=") +
                          std::to_string(static_cast<int>(op.action)) + " path=" + op_path,
                .runtime = context.summary,
            });
        }
        resolved_paths.push_back(op_path);
    }

    auto expected_tree = stable->input.storage.tree;
    std::erase_if(expected_tree.rows, [&](const NodeRow& row) {
        return std::ranges::find(resolved_paths, row.path) != resolved_paths.end();
    });
    finalize_snapshot(expected_tree);
    if (stable->result.requires_local_mutation ||
        stable->result.requires_storage_repair ||
        expected_tree != stable->result.candidate_shared_tree) {
        return std::unexpected(Error{
            .operation = context.operation,
            .code = ErrorCode::RecoveryFailure,
            .detail = "plan contains unrelated logical mutations",
            .runtime = context.summary,
        });
    }


    if (resolved_paths.empty()) {
        return Response{
            .operation = context.operation,
            .runtime = context.summary,
            .data = ResolveMissingCompleted{
                .resolved_count = 0,
                .resolved_paths = {},
                .published = false,
            },
        };
    }

    history_storage::maintenance_protocol::RegistrationState writer;
    if (stable->result.requires_publication) {
        const auto layout = history_storage::derive_remote_layout(context.key);
        auto registered = history_storage::maintenance_protocol::register_writer(
            context.storage,
            layout,
            context.runtime.database_path.parent_path());
        if (!registered) {
            return std::unexpected(synchronization_error(
                context.operation,
                registered.error().detail,
                context.summary));
        }
        writer = std::move(*registered);
    }

    const auto execute_outcome = [&]() -> std::expected<void, Error> {
        auto synchronized = sync::coordinator::execute(
            context.runtime,
            context.storage,
            context.key,
            stable->input,
            stable->result,
            &session);
        if (!synchronized) {
            return std::unexpected(transaction_error(
                context.operation,
                synchronized.error(),
                context.summary));
        }
        return {};
    }();

    if (history_storage::maintenance_protocol::registration_active(writer)) {
        auto released =
            history_storage::maintenance_protocol::release_registration(writer);
        if (execute_outcome && !released) {
            return std::unexpected(synchronization_error(
                context.operation,
                released.error().detail,
                context.summary));
        }
    }

    if (!execute_outcome) {
        return std::unexpected(execute_outcome.error());
    }

    return Response{
        .operation = context.operation,
        .runtime = context.summary,
        .data = ResolveMissingCompleted{
            .resolved_count = resolved_paths.size(),
            .resolved_paths = std::move(resolved_paths),
            .published = stable->result.requires_publication,
        },
    };
}

} // namespace kasumi::application::detail
