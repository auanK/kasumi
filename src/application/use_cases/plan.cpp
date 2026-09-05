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
    switch (action) {
        case Action::RenameLocal:
            return PlanAction::RenameLocal;
        case Action::Upload:
            return PlanAction::Upload;
        case Action::CreateLocalDirectory:
            return PlanAction::CreateLocalDirectory;
        case Action::CreateRemoteDirectory:
            return PlanAction::CreateRemoteDirectory;
        case Action::Download:
            return PlanAction::Download;
        case Action::DeleteLocal:
            return PlanAction::DeleteLocal;
        case Action::DeleteLocalDirectory:
            return PlanAction::DeleteLocalDirectory;
        case Action::DeleteRemote:
            return PlanAction::DeleteRemote;
        case Action::DeleteRemoteDirectory:
            return PlanAction::DeleteRemoteDirectory;
        case Action::Count:
            return std::unexpected("ação de contagem não é um plano válido");
    }
    std::unreachable();
}

std::expected<PlanReport, std::string>
reconciliation_to_report(const reconciliation::Result& result) {
    PlanReport report;
    report.target_generation = result.plan.target_generation;
    report.has_conflicts = result.has_conflicts;

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
        detail += " (caminhos: ";
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

std::string
describe_unrecoverable_paths(std::span<const std::filesystem::path> paths) {
    constexpr std::size_t path_limit = 20;
    const auto displayed = std::min(paths.size(), path_limit);
    std::string detail =
        "objetos remotos ausentes sem fonte local recuperável (caminhos: ";
    for (std::size_t index = 0; index < displayed; ++index) {
        if (index != 0) {
            detail += ", ";
        }
        detail += platform::path::to_utf8(paths[index]);
    }
    if (paths.size() > path_limit) {
        detail += "; e mais ";
        detail += std::to_string(paths.size() - path_limit);
    }
    detail += ')';
    return detail;
}

std::expected<Response, Error> run_plan(OperationContext& context) {
    auto collected = observation::collect_reconciliation_input(
        context.runtime, context.storage, context.key, false);
    if (!collected) {
        return std::unexpected(plan_error(
            context.operation, collected.error().detail, context.summary));
    }

    auto reconciled = reconciliation::reconcile(*collected);
    if (!reconciled) {
        return std::unexpected(
            plan_error(context.operation,
                       describe_reconciliation_error(reconciled.error()),
                       context.summary));
    }

    auto report = reconciliation_to_report(*reconciled);
    if (!report) {
        return std::unexpected(
            plan_error(context.operation, report.error(), context.summary));
    }
    return Response{.operation = context.operation,
                    .runtime = context.summary,
                    .data = std::move(*report)};
}

} // namespace kasumi::application::detail
