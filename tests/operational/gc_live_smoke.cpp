#include "gc_live_runner_support.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

namespace {

namespace runner = kasumi::operational::gc_live_runner;

struct Arguments {
    std::string remote;
    std::optional<std::filesystem::path> rclone_config;
    std::filesystem::path output;
    bool execute_live_gc = false;
    bool preserve_evidence_on_failure = true;
};

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

std::expected<Arguments, std::string> parse_arguments(int argc, char** argv) {
    Arguments result;
    for (int index = 1; index < argc; ++index) {
        const std::string_view option{argv[index]};
        if (option == "--help" || option == "-h") {
            return std::unexpected("help");
        }
        if (option == "--execute-live-gc") {
            result.execute_live_gc = true;
            continue;
        }
        if (option == "--preserve-evidence-on-failure") {
            result.preserve_evidence_on_failure = true;
            continue;
        }
        if (index + 1 >= argc) {
            return std::unexpected("missing value for " + std::string{option});
        }
        const std::string value{argv[++index]};
        if (option == "--remote" && result.remote.empty()) {
            result.remote = value;
        } else if (option == "--rclone-config" && !result.rclone_config) {
            result.rclone_config = std::filesystem::path{value};
        } else if (option == "--output" && result.output.empty()) {
            result.output = std::filesystem::path{value};
        } else {
            return std::unexpected("unknown or duplicate option: " + std::string{option});
        }
    }

    if (result.remote.empty() || result.output.empty()) {
        return std::unexpected("--remote and --output are required");
    }
    if (!result.execute_live_gc) {
        return std::unexpected("--execute-live-gc is required to execute live GC collection");
    }
    return result;
}

int execute(const Arguments& arguments) {
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

    // Local scratch directory
    const auto scratch_root = output_parent / "kasumi-gc-smoke-scratch";
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

    // Write final report
    auto report_json = runner::to_json(report);
    std::ofstream stream(output, std::ios::binary | std::ios::trunc);
    if (stream) {
        stream << report_json.dump(2) << '\n';
    }

    return report.status == "PASS" ? 0 : 1;
}

} // namespace

int main(int argc, char** argv) {
    const auto arguments = parse_arguments(argc, argv);
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
