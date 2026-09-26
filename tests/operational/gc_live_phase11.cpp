#include "gc_live_phase11_support.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace phase11 = kasumi::operational::phase11;

struct CliArgs {
    std::string remote = "kasumi:integration-tests";
    std::optional<std::filesystem::path> rclone_config;
    std::filesystem::path output;
    std::filesystem::path scratch;
    phase11::BenchmarkMode mode = phase11::BenchmarkMode::Batch;
    std::size_t candidate_count = 8;
    std::size_t payload_bytes = 4096;
    bool capability_test = false;
    bool execute_live = false;
    bool help_requested = false;
};

void print_usage(std::ostream& out) {
    out << "Usage: kasumi_gc_live_phase11 [options]\n\n"
        << "Phase 11 Controlled Live Remote GC Batch Gain Benchmark\n\n"
        << "Options:\n"
        << "  --remote <kasumi:integration-tests>     Authorized remote parent\n"
        << "  --output <path>                         Path to save output JSON\n"
        << "  --mode <individual|batch>               Benchmark mode (default: batch)\n"
        << "  --candidates <N>                        Candidate count (default: 8)\n"
        << "  --payload-bytes <bytes>                 Payload bytes per object (default: 4096)\n"
        << "  --capability-test                       Run Phase 3 batch capability test only\n"
        << "  --execute-live                          Required authorization gate for live operations\n"
        << "  --rclone-config <path>                  Optional rclone config file path\n"
        << "  --local-scratch <path>                  Optional local scratch folder\n"
        << "  --help, -h                              Show this help\n";
}

std::optional<CliArgs> parse_args(std::span<std::string_view> args) {
    CliArgs result;
    for (std::size_t i = 1; i < args.size(); ++i) {
        const auto arg = args[i];
        if (arg == "--help" || arg == "-h") {
            print_usage(std::cout);
            result.help_requested = true;
            return result;
        } else if (arg == "--capability-test") {
            result.capability_test = true;
        } else if (arg == "--execute-live") {
            result.execute_live = true;
        } else if (arg == "--remote") {
            if (++i >= args.size()) return std::nullopt;
            result.remote = std::string{args[i]};
        } else if (arg == "--output") {
            if (++i >= args.size()) return std::nullopt;
            result.output = std::filesystem::path{args[i]};
        } else if (arg == "--local-scratch") {
            if (++i >= args.size()) return std::nullopt;
            result.scratch = std::filesystem::path{args[i]};
        } else if (arg == "--mode") {
            if (++i >= args.size()) return std::nullopt;
            if (args[i] == "individual") {
                result.mode = phase11::BenchmarkMode::Individual;
            } else if (args[i] == "batch") {
                result.mode = phase11::BenchmarkMode::Batch;
            } else {
                std::cerr << "Invalid mode: " << args[i] << '\n';
                return std::nullopt;
            }
        } else if (arg == "--candidates") {
            if (++i >= args.size()) return std::nullopt;
            result.candidate_count = static_cast<std::size_t>(std::stoul(std::string{args[i]}));
        } else if (arg == "--payload-bytes") {
            if (++i >= args.size()) return std::nullopt;
            result.payload_bytes = static_cast<std::size_t>(std::stoul(std::string{args[i]}));
        } else if (arg == "--rclone-config") {
            if (++i >= args.size()) return std::nullopt;
            result.rclone_config = std::filesystem::path{args[i]};
        } else {
            std::cerr << "Unknown argument: " << arg << '\n';
            return std::nullopt;
        }
    }
    return result;
}

} // namespace

int main(int argc, char** argv) {
    std::vector<std::string_view> args;
    args.reserve(static_cast<std::size_t>(argc));
    for (int i = 0; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }

    const auto parsed = parse_args(args);
    if (!parsed) {
        return 1;
    }
    if (parsed->help_requested) {
        return 0;
    }

    phase11::Phase11Config config{
        .remote_parent = parsed->remote,
        .rclone_config = parsed->rclone_config,
        .output_path = parsed->output,
        .local_scratch = parsed->scratch.empty() ? (std::filesystem::current_path() / "phase11_scratch") : parsed->scratch,
        .execute_live = parsed->execute_live,
        .candidate_count = parsed->candidate_count,
        .payload_bytes = parsed->payload_bytes,
        .mode = parsed->mode,
        .explicit_child = std::nullopt,
        .explicit_token = std::nullopt,
        .preflight_timeout = std::chrono::minutes{2}
    };

    if (parsed->capability_test) {
        std::cout << "Running Phase 3 Capability Test against " << config.remote_parent << "...\n";
        phase11::Phase11RunReport report;
        const auto status = phase11::run_capability_test(config, report);
        std::cout << "Capability test status: " << phase11::capability_status_name(status) << '\n';
        std::cout << "Report status: " << report.status << '\n';
        if (!report.error_message.empty()) {
            std::cout << "Error: " << report.error_message << '\n';
        }
        std::cout << "Wall clock: " << report.timings_ms.total_wall_ms << " ms\n";
        std::cout << "RC requests: " << report.rc_requests.total << '\n';
        return (status == phase11::CapabilityStatus::Supported || status == phase11::CapabilityStatus::Unsupported) ? 0 : 1;
    }

    std::cout << "Running Phase 11 Benchmark Trial: N=" << config.candidate_count
              << ", mode=" << phase11::mode_name(config.mode)
              << ", payload=" << config.payload_bytes << " bytes against " << config.remote_parent << "...\n";

    const auto report = phase11::run_benchmark_trial(config);
    std::cout << "Trial status: " << report.status << '\n';
    if (!report.error_message.empty()) {
        std::cout << "Error: " << report.error_message << '\n';
    }
    std::cout << "Wall clock: " << report.timings_ms.total_wall_ms << " ms\n";
    std::cout << "Native copies: " << report.kasumi_operations.native_copy_successes << "/" << report.kasumi_operations.native_copy_attempts << '\n';
    std::cout << "Batch hash calls: " << report.kasumi_operations.batch_hash_calls << '\n';
    std::cout << "Individual dest hashes: " << report.kasumi_operations.individual_destination_hashes << '\n';
    std::cout << "RC requests: " << report.rc_requests.total << '\n';
    std::cout << "Removals: " << report.kasumi_operations.removals << '\n';
    std::cout << "Cleanup: " << report.cleanup.result << " (" << report.cleanup.objects_removed << " objects removed)\n";

    return report.status == "PASS" ? 0 : 1;
}
