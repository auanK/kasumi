#include "gc_live_runner_support.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace {

namespace runner = kasumi::operational::gc_live_runner;

struct RcloneConfigEnvironment {
    std::optional<std::string> previous;

    RcloneConfigEnvironment() {
        if (const char* value = std::getenv("RCLONE_CONFIG"); value != nullptr) {
            previous = value;
        }
    }

    ~RcloneConfigEnvironment() {
#ifdef _WIN32
        _putenv_s("RCLONE_CONFIG", previous ? previous->c_str() : "");
#else
        if (previous) {
            setenv("RCLONE_CONFIG", previous->c_str(), 1);
        } else {
            unsetenv("RCLONE_CONFIG");
        }
#endif
    }
};

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
    if (!runner::is_authorized_live_parent(arguments.remote)) {
        std::cerr << "Remote parent must be exactly 'kasumi:integration-tests'; no remote request made.\n";
        return 2;
    }

    std::error_code fs_error;
    auto output = std::filesystem::absolute(arguments.output, fs_error);
    if (fs_error) {
        std::cerr << "Invalid local report path.\n";
        return 2;
    }
    if (std::filesystem::exists(output, fs_error) || fs_error) {
        std::cerr << "Output must be a new local file.\n";
        return 2;
    }
    const auto output_parent = output.parent_path();
    if (!std::filesystem::is_directory(output_parent, fs_error) || fs_error) {
        std::cerr << "Output parent directory must already exist.\n";
        return 2;
    }

    if (arguments.rclone_config) {
        fs_error.clear();
        const auto status = std::filesystem::symlink_status(*arguments.rclone_config, fs_error);
        if (fs_error || std::filesystem::is_symlink(status) || !std::filesystem::is_regular_file(status)) {
            std::cerr << "rclone config must be a regular local file.\n";
            return 2;
        }
    }

    RcloneConfigEnvironment restore_environment;
    if (arguments.rclone_config) {
        const auto config = std::filesystem::absolute(*arguments.rclone_config, fs_error);
        if (fs_error) {
            std::cerr << "could not resolve rclone config path.\n";
            return 2;
        }
#ifdef _WIN32
        if (_putenv_s("RCLONE_CONFIG", config.string().c_str()) != 0) {
#else
        if (setenv("RCLONE_CONFIG", config.string().c_str(), 1) != 0) {
#endif
            std::cerr << "could not set RCLONE_CONFIG environment variable.\n";
            return 2;
        }
    }

    const auto scratch_root = output_parent / "kasumi-gc-benchmark-scratch";
    std::filesystem::create_directories(scratch_root, fs_error);
    if (fs_error) {
        std::cerr << "could not create scratch directory.\n";
        return 2;
    }

    runner::RunnerOptions options{
        .remote_parent = arguments.remote,
        .rclone_config = arguments.rclone_config,
        .output_path = output,
        .local_scratch = scratch_root,
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
    std::ofstream stream(output, std::ios::binary | std::ios::trunc);
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
