#include "provider_certification_support.hpp"
#include "provider_target_config.hpp"

#include "platform/path.hpp"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

namespace {

using namespace kasumi::operational::provider_certification;

std::expected<void, std::string> write_json(const std::filesystem::path& path,
                                           const nlohmann::json& value) {
    std::error_code error;
    if (!path.parent_path().empty()) {
        std::filesystem::create_directories(path.parent_path(), error);
    }
    if (error) {
        return std::unexpected("could not create report directory");
    }
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        return std::unexpected("could not open report output");
    }
    output << value.dump(2) << '\n';
    if (!output) {
        return std::unexpected("could not write report output");
    }
    return {};
}

std::expected<Report, std::string>
read_report(const std::filesystem::path& path) {
    try {
        std::ifstream input(path, std::ios::binary);
        if (!input) {
            return std::unexpected("could not open input report");
        }
        const auto json = nlohmann::json::parse(input);
        Report report;
        report.schema_version = json.at("schema_version").get<int>();
        report.provider_id = json.at("provider_id").get<std::string>();
        report.transport = json.at("transport").get<std::string>();
        report.status = json.at("status").get<std::string>();
        report.cleanup = json.at("cleanup").get<std::string>();
        for (const auto& item : json.at("capabilities")) {
            const auto status = item.at("status").get<std::string>();
            CapabilityStatus parsed = CapabilityStatus::Unsupported;
            if (status == "Supported") {
                parsed = CapabilityStatus::Supported;
            } else if (status == "Failed") {
                parsed = CapabilityStatus::Failed;
            } else if (status != "Unsupported") {
                return std::unexpected("input report has an invalid capability status");
            }
            report.capabilities.push_back(
                {.name = item.at("name").get<std::string>(),
                 .status = parsed});
        }
        for (const auto& item : json.at("scenarios")) {
            const auto status = item.at("status").get<std::string>();
            ScenarioStatus parsed = ScenarioStatus::NotRun;
            if (status == "Pass") {
                parsed = ScenarioStatus::Pass;
            } else if (status == "Fail") {
                parsed = ScenarioStatus::Fail;
            } else if (status == "Blocked") {
                parsed = ScenarioStatus::Blocked;
            } else if (status != "NotRun") {
                return std::unexpected("input report has an invalid scenario status");
            }
            report.scenarios.push_back(
                {.name = item.at("name").get<std::string>(),
                 .status = parsed});
        }
        return report;
    } catch (const std::exception&) {
        return std::unexpected("input report is invalid");
    }
}

void finish_cleanup(ProviderTarget& target,
                    Report& report,
                    bool preserve_on_failure) {
    auto cleanup_scenario = std::ranges::find(
        report.scenarios, std::string{"cleanup"}, &Scenario::name);
    if (report.status == "FAIL" && preserve_on_failure) {
        report.cleanup = "PRESERVED_ON_FAILURE";
        cleanup_scenario->status = ScenarioStatus::Blocked;
        cleanup_scenario->diagnostics.emplace_back(
            "preserved by request after certification failure");
        return;
    }

    std::expected<void, std::string> cleanup = std::unexpected(
        "target ownership information is unavailable");
    if (target.transport == "Local" && target.local_ownership) {
        cleanup = cleanup_local_target(*target.local_ownership);
    } else if (target.transport == "Rclone") {
        cleanup = cleanup_rclone_target(target);
    }
    report.cleanup = cleanup ? "CLEANED" : "FAILED";
    cleanup_scenario->status = cleanup ? ScenarioStatus::Pass
                                      : ScenarioStatus::Fail;
    if (!cleanup) {
        report.diagnostics.push_back(cleanup.error());
        cleanup_scenario->diagnostics.push_back(cleanup.error());
    }
}

} // namespace

int main(int argc, char** argv) {
    auto local_parent = std::filesystem::temp_directory_path();
    auto output_path = std::filesystem::current_path() /
                       "benchmark-results/phase41-multi-backend-certification/"
                       "local-certification.json";
    std::vector<std::string_view> arguments;
    arguments.reserve(static_cast<std::size_t>(argc));
    for (int index = 0; index < argc; ++index) {
        arguments.emplace_back(argv[index]);
    }
    auto target_selection =
        kasumi::operational::provider_target_config::
            parse_target_selection_arguments(arguments);
    if (!target_selection) {
        std::cerr << target_selection.error() << '\n';
        return 2;
    }

    const std::string target_kind = target_selection->target_kind;
    bool preserve_on_failure = false;
    bool aggregate_only = false;
    bool output_explicit = false;
    std::vector<std::filesystem::path> input_reports;

    for (int index = 1; index < argc; ++index) {
        const std::string argument{argv[index]};
        if (argument == "--target" || argument == "--config" ||
            argument == "--target-id") {
            ++index;
        } else if ((argument == "--local-parent" ||
                    argument == "--local-root") &&
            index + 1 < argc) {
            local_parent = argv[++index];
        } else if (argument == "--output" && index + 1 < argc) {
            output_path = argv[++index];
            output_explicit = true;
        } else if (argument == "--preserve-evidence-on-failure") {
            preserve_on_failure = true;
        } else if (argument == "--aggregate") {
            aggregate_only = true;
        } else if (aggregate_only && !argument.starts_with('-')) {
            input_reports.emplace_back(argument);
        } else {
            std::cerr << "unsupported argument: " << argument << '\n';
            return 2;
        }
    }

    if (aggregate_only) {
        if (input_reports.empty()) {
            std::cerr << "--aggregate requires at least one report path\n";
            return 2;
        }
        std::vector<Report> reports;
        for (const auto& path : input_reports) {
            auto report = read_report(path);
            if (!report) {
                std::cerr << report.error() << '\n';
                return 2;
            }
            reports.push_back(std::move(*report));
        }
        const auto matrix = aggregate_reports(reports);
        auto written = write_json(output_path, matrix);
        if (!written) {
            std::cerr << written.error() << '\n';
            return 2;
        }
        std::cout << matrix.dump(2) << '\n';
        return matrix.at("status") == "PASS" ? 0 : 1;
    }

    auto selected_live_target =
        kasumi::operational::provider_target_config::resolve_target(
            *target_selection);
    if (!selected_live_target) {
        std::cerr << selected_live_target.error() << '\n';
        return 2;
    }

    std::expected<ProviderTarget, std::string> target =
        std::unexpected("unsupported target; choose local or rclone");
    if (target_kind == "local") {
        auto local = create_local_target(local_parent);
        if (!local) {
            std::cerr << local.error() << '\n';
            return 2;
        }
        target = ProviderTarget{
            .provider_id = "local-filesystem",
            .transport = "Local",
            .locator = kasumi::platform::path::to_utf8(local->root / "remote"),
            .workspace_root = local->root,
            .local_ownership = std::move(*local),
        };
    } else if (target_kind == "rclone") {
        if (!selected_live_target->has_value()) {
            std::cerr << "Rclone target was not selected\n";
            return 2;
        }
        target = create_rclone_target(
            (*selected_live_target)->provider_id,
            (*selected_live_target)->remote,
            (*selected_live_target)->authorized_parent);
        if (!target) {
            std::cerr << target.error() << '\n';
            return 2;
        }
        if (!output_explicit) {
            output_path = std::filesystem::current_path() /
                          std::filesystem::path{
                              "benchmark-results/phase41-multi-backend-certification/"} /
                          (target->provider_id + "-certification.json");
        }
    } else {
        std::cerr << "unsupported target: " << target_kind << '\n';
        return 2;
    }

    const auto absolute_output = std::filesystem::absolute(output_path)
                                     .lexically_normal();
    const auto output_relative =
        absolute_output.lexically_relative(target->workspace_root);
    if (!output_relative.empty() && output_relative != "." &&
        !output_relative.is_absolute() && !output_relative.has_root_name() &&
        !output_relative.has_root_directory() &&
        *output_relative.begin() != "..") {
        if (target->local_ownership) {
            (void)cleanup_local_target(*target->local_ownership);
        } else if (target->transport == "Rclone") {
            (void)cleanup_rclone_target(*target);
        }
        std::cerr << "report output must be outside the target workspace\n";
        return 2;
    }

    auto report = run_certification(*target);
    finish_cleanup(*target, report, preserve_on_failure);
    report.status = derive_status(report);
    auto written = write_json(output_path, to_json(report));
    if (!written) {
        std::cerr << written.error() << '\n';
        return 2;
    }
    std::cout << to_json(report).dump(2) << '\n';
    return report.status == "PASS" ? 0 : 1;
}
