#include "gc_live_runner_support.hpp"

#include <chrono>
#include <fstream>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

namespace {

namespace runner = kasumi::operational::gc_live_runner;

void print_usage(std::ostream& output) {
    output << "Usage: kasumi_gc_live_benchmark --remote <kasumi:integration-tests> \\\n"
              "         --output <new-local-json> --mode <native|fallback> \\\n"
              "         --payload-bytes <bytes> --execute-live-benchmark \\\n"
              "         [--rclone-config <config-file>] [--preserve-evidence-on-failure]\n\n"
              "Controlled live GC remote copy benchmark runner for Kasumi.\n"
              "This operational tool executes exactly ONE complete garbage collection sequence\n"
              "under a new owned child namespace and measures client-side latency metrics:\n"
              "  --remote: authorized remote parent (strictly kasumi:integration-tests)\n"
              "  --output: path for writing the benchmark JSON report\n"
              "  --mode: copy mode ('native' for transport::copy or 'fallback' for GET/PUT)\n"
              "  --payload-bytes: synthetic candidate size in bytes (1 to 67108864 [64 MiB], default 8 MiB)\n"
              "  --execute-live-benchmark: required authorization gate to perform live operations\n"
              "  --preserve-evidence-on-failure: retain child namespace if errors occur (default true)\n";
}

int execute(const runner::BenchmarkArguments& arguments) {
    runner::RcloneConfigEnvironment restore_environment;

    auto prepared = runner::prepare_cli_paths(
        arguments.remote, arguments.output, arguments.rclone_config, "kasumi-gc-benchmark-scratch");
    if (!prepared) {
        std::cerr << prepared.error() << '\n';
        return 2;
    }

    runner::RunnerOptions options{
        .remote_parent = arguments.remote,
        .rclone_config = arguments.rclone_config,
        .output_path = prepared->output_path,
        .local_scratch = prepared->scratch_root,
        .execute_live_gc = arguments.execute_live_benchmark,
        .preserve_evidence_on_failure = arguments.preserve_evidence_on_failure,
        .copy_mode = arguments.mode,
        .candidate_payload_bytes = arguments.payload_bytes,
    };

    std::cout << "Starting live GC benchmark ["
              << (arguments.mode == runner::CopyMode::Native ? "native" : "fallback")
              << ", " << arguments.payload_bytes << " bytes] against: " << arguments.remote << '\n';
    std::cout.flush();

    const auto process_start = std::chrono::steady_clock::now();
    auto report = runner::run(options);
    const auto process_end = std::chrono::steady_clock::now();

    report.phase = "GC_LIVE_BENCHMARK";
    report.benchmark.process_wall_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(process_end - process_start).count());

    std::cout << "Stage reached: " << runner::stage_name(report.stage_reached) << '\n';
    std::cout << "Status: " << report.status << '\n';
    std::cout << "Process wall time: " << report.benchmark.process_wall_ms << " ms\n";
    std::cout << "GC total time: " << report.benchmark.gc_total_us << " us\n";
    std::cout << "Candidate verified copy time: " << report.benchmark.gc_candidate_verified_copy_us << " us\n";
    if (!report.error_message.empty()) {
        std::cout << "Message: " << report.error_message << '\n';
    }
    std::cout.flush();

    auto report_json = runner::to_json(report);
    std::ofstream stream(prepared->output_path, std::ios::binary | std::ios::trunc);
    if (stream) {
        stream << report_json.dump(2) << '\n';
    }

    return report.status == "PASS" ? 0 : 1;
}

} // namespace

int main(int argc, char** argv) {
    std::vector<std::string_view> args;
    args.reserve(static_cast<std::size_t>(argc));
    for (int i = 0; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }

    const auto arguments = runner::parse_benchmark_arguments(args);
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
