#include "gc_live_runner_support.hpp"

#include <iostream>
#include <span>
#include <string_view>
#include <vector>

namespace {

namespace runner = kasumi::operational::gc_live_runner;

void print_usage(std::ostream& output) {
    output << "Usage: kasumi_gc_live_smoke --remote <kasumi:integration-tests> "
              "[--rclone-config <config-file>] --output <new-local-json> --execute-live-gc "
              "[--preserve-evidence-on-failure]\n\n"
              "Guarded live GC collection runner for Kasumi.\n"
              "This operational tool executes exactly ONE complete garbage collection sequence:\n"
              "  1. Validates the authorized parent (kasumi:integration-tests)\n"
              "  2. Probes a newly-generated unique child namespace (PRE_INITIALIZE == UNUSED)\n"
              "  3. Initializes the child namespace and verifies POST_INITIALIZE is empty\n"
              "  4. Establishes an operational ownership marker with exact readback verification\n"
              "  5. Writes synthetic test objects (1 reachable content + commit, 1 orphan candidate)\n"
              "  6. Captures and verifies pre-GC inventory\n"
              "  7. Invokes one real garbage_collect() call without retries\n"
              "  8. Verifies all post-collection invariants (quarantine verified, source removed, metadata valid)\n"
              "  9. Cleans only owned objects when ownership marker is re-verified\n\n"
              "MUTATION SAFETY:\n"
              "  --execute-live-gc is REQUIRED to authorize mutations within the generated child.\n"
              "  Without this flag, no network requests or remote writes occur.\n";
}

int execute(const runner::SmokeArguments& arguments) {
    runner::RcloneConfigEnvironment restore_environment;

    auto prepared = runner::prepare_cli_paths(
        arguments.remote, arguments.output, arguments.rclone_config, "kasumi-gc-smoke-scratch");
    if (!prepared) {
        std::cerr << prepared.error() << '\n';
        return 2;
    }

    runner::RunnerOptions options{
        .remote_parent = arguments.remote,
        .rclone_config = arguments.rclone_config,
        .output_path = prepared->output_path,
        .local_scratch = prepared->scratch_root,
        .execute_live_gc = arguments.execute_live_gc,
        .preserve_evidence_on_failure = arguments.preserve_evidence_on_failure,
    };

    std::cout << "Starting guarded live GC runner against: " << arguments.remote << '\n';
    std::cout.flush();

    auto report = runner::run(options);

    std::cout << "Stage reached: " << runner::stage_name(report.stage_reached) << '\n';
    std::cout << "Status: " << report.status << '\n';
    if (!report.error_message.empty()) {
        std::cout << "Message: " << report.error_message << '\n';
    }
    std::cout.flush();

    return report.status == "PASS" ? 0 : 1;
}

} // namespace

int main(int argc, char** argv) {
    std::vector<std::string_view> args;
    args.reserve(static_cast<std::size_t>(argc));
    for (int i = 0; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }

    const auto arguments = runner::parse_smoke_arguments(args);
    if (!arguments) {
        if (arguments.error() == "help") {
            print_usage(std::cout);
            return 0;
        }
        std::cerr << arguments.error() << "\n\n";
        print_usage(std::cerr);
        return 2;
    }
    return execute(*arguments);
}
