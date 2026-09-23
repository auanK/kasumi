#include "gc_live_preflight_support.hpp"

#include "platform/random.hpp"
#include "transport/transport.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace {

namespace smoke = kasumi::operational::remote_copy_smoke;
namespace gc_live = kasumi::operational::gc_live_preflight;
namespace transport = kasumi::transport;

struct Arguments {
    std::string remote;
    std::optional<std::filesystem::path> rclone_config;
    std::filesystem::path output;
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

std::expected<Arguments, std::string> parse_arguments(int argc, char** argv) {
    Arguments result;
    for (int index = 1; index < argc; ++index) {
        const std::string_view option{argv[index]};
        if (option == "--help" || option == "-h") {
            return std::unexpected("help");
        }
        if (index + 1 >= argc) {
            return std::unexpected("missing value for " + std::string{option});
        }
        const std::string value{argv[++index]};
        if (option == "--remote" && result.remote.empty()) {
            result.remote = value;
        } else if (option == "--rclone-config" &&
                   !result.rclone_config) {
            result.rclone_config = std::filesystem::path{value};
        } else if (option == "--output" && result.output.empty()) {
            result.output = std::filesystem::path{value};
        } else {
            return std::unexpected("unknown or duplicate option: " +
                                   std::string{option});
        }
    }
    if (result.remote.empty() || result.output.empty()) {
        return std::unexpected("--remote and --output are required");
    }
    return result;
}

bool write_report(const std::filesystem::path& output,
                  const nlohmann::json& report) {
    std::ofstream stream(output, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return false;
    }
    stream << report.dump(2) << '\n';
    return static_cast<bool>(stream);
}

void print_usage(std::ostream& output) {
    output << "Usage: kasumi_gc_live_preflight --remote "
              "<rclone-remote:dedicated-test-parent> "
              "[--rclone-config <config-file>] --output <new-local-json>\n"
              "This command only probes and classifies a generated child; "
              "it does not initialize, write, clean up, or run GC.\n";
}

int execute(const Arguments& arguments) {
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

    nlohmann::json report{
        {"schema_version", 1},
        {"phase", "PRE_INITIALIZE_ONLY"},
        {"status", "REFUSED"},
        {"remote_parent", arguments.remote},
        {"effective_namespace", nullptr},
        {"parent_validation",
         {{"result", "NOT_RUN"},
          {"entry_count", nullptr},
          {"error_category", nullptr},
          {"native_code", nullptr},
          {"error_message", nullptr}}},
        {"pre_initialize", nullptr},
        {"post_initialize", nullptr},
        {"ownership", "NOT_ATTEMPTED"},
        {"cleanup", "NOT_ATTEMPTED"},
        {"gc_called", false},
    };

    const auto parent = smoke::parse_remote_parent(arguments.remote);
    if (!parent) {
        report["parent_validation"]["error_category"] = "invalid_identifier";
        report["parent_validation"]["error_message"] = parent.error();
        write_report(output, report);
        std::cerr << "Remote parent was rejected; no remote request made.\n";
        return 2;
    }

    if (arguments.rclone_config) {
        fs_error.clear();
        const auto status = std::filesystem::symlink_status(
            *arguments.rclone_config, fs_error);
        if (fs_error || std::filesystem::is_symlink(status) ||
            !std::filesystem::is_regular_file(status)) {
            report["parent_validation"]["error_category"] = "invalid_context";
            report["parent_validation"]["error_message"] =
                "rclone config must be a regular local file";
            write_report(output, report);
            std::cerr << "Rclone config path was rejected.\n";
            return 2;
        }
    }

    RcloneConfigEnvironment restore_environment;
    if (arguments.rclone_config) {
        const auto config = std::filesystem::absolute(*arguments.rclone_config,
                                                      fs_error);
        if (fs_error) {
            report["parent_validation"]["error_category"] = "invalid_context";
            report["parent_validation"]["error_message"] =
                "could not resolve rclone config path";
            write_report(output, report);
            return 2;
        }
#ifdef _WIN32
        if (_putenv_s("RCLONE_CONFIG", config.string().c_str()) != 0) {
#else
        if (setenv("RCLONE_CONFIG", config.string().c_str(), 1) != 0) {
#endif
            report["parent_validation"]["error_category"] = "invalid_context";
            report["parent_validation"]["error_message"] =
                "could not set RCLONE_CONFIG";
            write_report(output, report);
            return 2;
        }
    }

    const auto nonce = kasumi::platform::random::hex_id();
    if (!nonce) {
        report["parent_validation"]["error_category"] = "io";
        report["parent_validation"]["error_message"] = nonce.error();
        write_report(output, report);
        return 2;
    }
    const auto child = gc_live::child_namespace(*nonce);
    if (!child) {
        report["parent_validation"]["error_category"] = "invalid_identifier";
        report["parent_validation"]["error_message"] = child.error();
        write_report(output, report);
        return 2;
    }
    const auto location = gc_live::child_location(*parent, *child);
    if (!location) {
        report["parent_validation"]["error_category"] = "invalid_identifier";
        report["parent_validation"]["error_message"] = location.error();
        write_report(output, report);
        return 2;
    }

    auto parent_storage = transport::open_transport(parent->location);
    if (!parent_storage) {
        report["parent_validation"]["result"] = "FAILED";
        report["parent_validation"]["error_category"] =
            transport::error_code_name(parent_storage.error().code);
        report["parent_validation"]["native_code"] =
            parent_storage.error().native_code;
        report["parent_validation"]["error_message"] =
            "transport open failed; message omitted to avoid leaking RC diagnostics";
        write_report(output, report);
        return 1;
    }
    const auto parent_listing = transport::list(*parent_storage);
    if (!parent_listing) {
        report["parent_validation"]["result"] = "FAILED";
        report["parent_validation"]["error_category"] =
            transport::error_code_name(parent_listing.error().code);
        report["parent_validation"]["native_code"] =
            parent_listing.error().native_code;
        report["parent_validation"]["error_message"] =
            "parent listing failed; raw diagnostics are captured only for the child probe";
        write_report(output, report);
        return 1;
    }
    report["parent_validation"]["result"] = "SUCCESS";
    report["parent_validation"]["entry_count"] = parent_listing->size();

    report["effective_namespace"] = *location;
    std::cout << "Effective GC-live child namespace: " << *location << '\n';
    std::cout.flush();

    auto observation = gc_live::observe_pre_initialize(
        *parent_storage, *parent, *child);
    const auto classification =
        gc_live::classify_pre_initialize(observation, *parent, *child);
    report["pre_initialize"] = gc_live::to_json(observation, classification);
    report["status"] = classification.disposition ==
                               gc_live::ChildDisposition::Unused
                           ? "CANDIDATE_UNUSED"
                           : classification.disposition ==
                                     gc_live::ChildDisposition::Existing
                                 ? "EXISTING"
                                 : "REFUSED";
    if (!write_report(output, report)) {
        std::cerr << "Could not write local JSON report.\n";
        return 2;
    }
    return classification.disposition == gc_live::ChildDisposition::Unused
               ? 0
               : 1;
}

} // namespace

int main(int argc, char** argv) {
    const auto arguments = parse_arguments(argc, argv);
    if (!arguments) {
        if (arguments.error() == "help") {
            print_usage(std::cout);
            return 0;
        }
        std::cerr << arguments.error() << '\n';
        print_usage(std::cerr);
        return 2;
    }
    return execute(*arguments);
}
