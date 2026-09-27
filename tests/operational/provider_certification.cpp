#include "provider_certification_support.hpp"

#include <fstream>
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    auto parent = std::filesystem::temp_directory_path();
    auto output_path = std::filesystem::current_path() /
                       "benchmark-results/phase40-provider-certification/"
                       "local-certification.json";
    bool preserve_on_failure = false;
    for (int index = 1; index < argc; ++index) {
        const std::string argument{argv[index]};
        if (argument == "--local-root" && index + 1 < argc) {
            parent = argv[++index];
        } else if (argument == "--output" && index + 1 < argc) {
            output_path = argv[++index];
        } else if (argument == "--preserve-evidence-on-failure") {
            preserve_on_failure = true;
        } else {
            std::cerr << "unsupported argument: " << argument << '\n';
            return 2;
        }
    }

    auto target =
        kasumi::operational::provider_certification::create_local_target(
            parent);
    if (!target) {
        std::cerr << target.error() << '\n';
        return 2;
    }
    const auto absolute_output =
        std::filesystem::absolute(output_path).lexically_normal();
    const auto output_relative =
        absolute_output.lexically_relative(target->root);
    if (!output_relative.empty() && output_relative != "." &&
        !output_relative.is_absolute() && !output_relative.has_root_name() &&
        !output_relative.has_root_directory() &&
        *output_relative.begin() != "..") {
        auto cleanup =
            kasumi::operational::provider_certification::cleanup_local_target(
                *target);
        std::cerr << "report output must be outside the owned target\n";
        return cleanup ? 2 : 1;
    }
    auto report =
        kasumi::operational::provider_certification::run_local_certification(
            target->root);
    if (report.status == "FAIL" && preserve_on_failure) {
        report.cleanup = "PRESERVED_ON_FAILURE";
        report.diagnostics.emplace_back("evidence preserved at target_root");
        report.scenarios.push_back(
            {.name = "cleanup",
             .status = kasumi::operational::provider_certification::
                 ScenarioStatus::Blocked,
             .diagnostics = {
                 "preserved by request after certification failure"}});
    } else {
        auto cleanup =
            kasumi::operational::provider_certification::cleanup_local_target(
                *target);
        report.cleanup = cleanup ? "CLEANED" : "FAILED";
        report.scenarios.push_back(
            {.name = "cleanup",
             .status = cleanup ? kasumi::operational::provider_certification::
                                     ScenarioStatus::Pass
                               : kasumi::operational::provider_certification::
                                     ScenarioStatus::Fail});
        if (!cleanup) {
            report.diagnostics.push_back(cleanup.error());
        }
    }
    report.status =
        kasumi::operational::provider_certification::derive_status(report);

    std::error_code error;
    if (!output_path.parent_path().empty()) {
        std::filesystem::create_directories(output_path.parent_path(), error);
    }
    if (error) {
        std::cerr << "could not create report directory: " << error.message()
                  << '\n';
        return 2;
    }
    std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
    if (!output) {
        std::cerr << "could not open certification report path\n";
        return 2;
    }
    output << kasumi::operational::provider_certification::to_json(report).dump(
                  2)
           << '\n';
    if (!output) {
        std::cerr << "could not write certification report\n";
        return 2;
    }
    std::cout
        << kasumi::operational::provider_certification::to_json(report).dump(2)
        << '\n';
    return report.status == "PASS" ? 0 : 1;
}
