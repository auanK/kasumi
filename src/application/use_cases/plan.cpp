#include "core/reconciliation/plan.hpp"

#include "application/observation/state.hpp"
#include "application/use_cases/context.hpp"
#include "application/use_cases/error_mapping.hpp"
#include "application/use_cases/plan_support.hpp"
#include "core/operation.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <filesystem>
#include <span>
#include <string>
#include <utility>

namespace kasumi::application::detail {
namespace {

std::expected<PlanAction, std::string>
core_action_to_plan_action(Action action) {
    static_assert(
        static_cast<std::size_t>(PlanAction::RenameLocal) ==
            action_index(Action::RenameLocal) &&
        static_cast<std::size_t>(PlanAction::Upload) ==
            action_index(Action::Upload) &&
        static_cast<std::size_t>(PlanAction::CreateLocalDirectory) ==
            action_index(Action::CreateLocalDirectory) &&
        static_cast<std::size_t>(PlanAction::CreateRemoteDirectory) ==
            action_index(Action::CreateRemoteDirectory) &&
        static_cast<std::size_t>(PlanAction::MoveLocal) ==
            action_index(Action::MoveLocal) &&
        static_cast<std::size_t>(PlanAction::Download) ==
            action_index(Action::Download) &&
        static_cast<std::size_t>(PlanAction::DeleteLocal) ==
            action_index(Action::DeleteLocal) &&
        static_cast<std::size_t>(PlanAction::DeleteLocalDirectory) ==
            action_index(Action::DeleteLocalDirectory) &&
        static_cast<std::size_t>(PlanAction::DeleteRemote) ==
            action_index(Action::DeleteRemote) &&
        static_cast<std::size_t>(PlanAction::DeleteRemoteDirectory) ==
            action_index(Action::DeleteRemoteDirectory) &&
        static_cast<std::size_t>(PlanAction::CopyLocal) ==
            action_index(Action::CopyLocal) &&
        static_cast<std::size_t>(PlanAction::DeleteIgnoredLocalFile) ==
            action_index(Action::DeleteIgnoredLocalFile) &&
        PLAN_ACTION_COUNT == ActionCount);
    if (!is_valid_action(action)) {
        return std::unexpected("count action is not a valid plan");
    }
    return static_cast<PlanAction>(action_index(action));
}

std::expected<PlanReport, std::string>
reconciliation_to_report(const reconciliation::Input& input,
                         const reconciliation::Result& result) {
    PlanReport report;
    report.target_generation = result.plan.target_generation;
    report.has_conflicts = result.has_conflicts;
    for (const auto& row : input.pending_materializations) {
        const auto* candidate =
            find_row(result.candidate_shared_tree, row.path);
        if (find_row(input.local_tree, row.path) == nullptr &&
            candidate != nullptr && !candidate->is_directory &&
            candidate->hash == row.hash && candidate->size == row.size) {
            report.pending_paths.push_back(platform::path::from_utf8(row.path));
        }
    }
    for (const auto& row : result.pending_materializations) {
        report.pending_paths.push_back(platform::path::from_utf8(row.path));
    }
    std::ranges::sort(report.pending_paths);
    report.pending_paths.erase(
        std::ranges::unique(report.pending_paths).begin(),
        report.pending_paths.end());

    for (const auto& operation : sync_plan_operations(result.plan)) {
        auto action = core_action_to_plan_action(operation.action);
        if (!action) {
            return std::unexpected(action.error());
        }
        if (*action == PlanAction::Upload) {
            report.upload_bytes += operation.size;
        } else if (*action == PlanAction::Download) {
            report.download_bytes += operation.size;
        }

        const auto index = static_cast<std::size_t>(*action);
        if (index < report.action_counts.size()) {
            ++report.action_counts[index];
        }
        report.items.push_back(PlanItem{.action = *action,
                                        .path = operation.path,
                                        .alternative_path = operation.alt_path,
                                        .size = operation.size});
    }
    return report;
}

} // namespace

std::string describe_reconciliation_error(const reconciliation::Error& error) {
    std::string detail = error.detail;
    if (!error.paths.empty()) {
        detail += " (paths: ";
        for (std::size_t index = 0; index < error.paths.size(); ++index) {
            if (index != 0) {
                detail += ", ";
            }
            detail += platform::path::to_utf8(error.paths[index]);
        }
        detail += ')';
    }
    return detail;
}

std::expected<Response, Error> run_plan(OperationContext& context) {
    if (context.on_progress) {
        context.on_progress(SyncProgress{
            .stage = SyncStage::Observing,
        });
    }

    observation::LocalObservationSession observation_session;
    observation_session.database_path = context.runtime.database_path;

    auto collected =
        observation::collect_reconciliation_input(context.runtime,
                                                  context.storage,
                                                  context.key,
                                                  false,
                                                  {},
                                                  &observation_session);
    if (!collected) {
        auto err = plan_error(
            context.operation, collected.error().detail, context.summary);
        err.stage = SyncStage::Observing;
        return std::unexpected(err);
    }

    if (context.on_progress) {
        context.on_progress(SyncProgress{
            .stage = SyncStage::Calculating,
        });
    }

    auto reconciled = reconciliation::reconcile(*collected);
    if (!reconciled) {
        auto err = plan_error(context.operation,
                              describe_reconciliation_error(reconciled.error()),
                              context.summary);
        err.stage = SyncStage::Calculating;
        return std::unexpected(err);
    }

    auto report = reconciliation_to_report(*collected, *reconciled);
    if (!report) {
        auto err =
            plan_error(context.operation, report.error(), context.summary);
        err.stage = SyncStage::Calculating;
        return std::unexpected(err);
    }
    return Response{.operation = context.operation,
                    .runtime = context.summary,
                    .data = std::move(*report)};
}

} // namespace kasumi::application::detail
