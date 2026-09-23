#include "remote_copy_smoke_support.hpp"

#include "platform/random.hpp"
#include "transport/transport.hpp"
#include "../../src/transport/rclone/detail.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace {

namespace smoke = kasumi::operational::remote_copy_smoke;
namespace transport = kasumi::transport;
namespace rclone_detail = kasumi::transport::rclone_detail;

constexpr std::string_view payload =
    "Kasumi real-remote same-storage copy smoke test\n"
    "Synthetic data only; no vault or production profile is used.\n";

struct Arguments {
    std::string remote;
    std::optional<std::filesystem::path> rclone_config;
    std::filesystem::path output;
};

struct EnvironmentValue {
    std::optional<std::string> previous;

    explicit EnvironmentValue(const char* name) {
        if (const char* value = std::getenv(name); value != nullptr) {
            previous = value;
        }
    }

    ~EnvironmentValue() {
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

struct ScratchDirectory {
    std::filesystem::path path;

    ScratchDirectory() = default;
    explicit ScratchDirectory(std::filesystem::path value)
        : path(std::move(value)) {}
    ScratchDirectory(const ScratchDirectory&) = delete;
    ScratchDirectory& operator=(const ScratchDirectory&) = delete;
    ScratchDirectory(ScratchDirectory&& other) noexcept
        : path(std::exchange(other.path, {})) {}
    ScratchDirectory& operator=(ScratchDirectory&& other) noexcept {
        if (this != &other) {
            if (!path.empty()) {
                std::error_code ignored;
                std::filesystem::remove_all(path, ignored);
            }
            path = std::exchange(other.path, {});
        }
        return *this;
    }

    ~ScratchDirectory() {
        if (!path.empty()) {
            std::error_code ignored;
            std::filesystem::remove_all(path, ignored);
        }
    }
};

void record_skipped(nlohmann::json& records,
                    std::string name) {
    records.push_back(smoke::to_json(smoke::OperationRecord{
        .name = std::move(name), .result = "SKIPPED"}));
}

template <typename Function>
auto run_operation(nlohmann::json& records,
                   std::string name,
                   Function&& function) {
    const auto started = std::chrono::steady_clock::now();
    auto result = std::forward<Function>(function)();
    const auto elapsed = std::chrono::duration<double, std::milli>(
                             std::chrono::steady_clock::now() - started)
                             .count();
    smoke::OperationRecord record{
        .name = std::move(name),
        .result = result ? "SUCCESS" : "FAILED",
        .elapsed_ms = elapsed,
    };
    if (!result) {
        record.error_category = result.error().code;
        record.error_message = result.error().message;
        if (result.error().code == transport::ErrorCode::Unsupported) {
            record.result = "UNSUPPORTED";
        }
    }
    records.push_back(smoke::to_json(record));
    return result;
}

void fail_operation(nlohmann::json& records,
                    std::string name,
                    transport::ErrorCode code,
                    std::string message) {
    records.push_back(smoke::to_json(smoke::OperationRecord{
        .name = std::move(name),
        .result = code == transport::ErrorCode::Unsupported ? "UNSUPPORTED"
                                                            : "FAILED",
        .error_category = code,
        .error_message = std::move(message),
    }));
}

bool valid_sha256(std::string_view hash);

std::vector<smoke::ReadinessAttempt> probe_readiness(
    transport::Transport& storage,
    std::string_view identifier,
    std::string_view operation_prefix,
    nlohmann::json& operations) {
    const auto started = std::chrono::steady_clock::now();
    const auto schedule = smoke::readiness_schedule();
    std::vector<smoke::ReadinessAttempt> attempts;
    attempts.reserve(schedule.size());

    for (std::size_t index = 0; index < schedule.size(); ++index) {
        std::this_thread::sleep_until(started + schedule[index]);
        smoke::ReadinessAttempt attempt{
            .attempt_index = index + 1,
            .elapsed_since_reference =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - started),
        };

        auto presence = run_operation(
            operations,
            std::string{operation_prefix} + "_presence_attempt_" +
                std::to_string(attempt.attempt_index),
            [&] { return transport::presence(storage, identifier); });
        if (!presence) {
            attempt.presence = smoke::ReadinessPresence::Failed;
            attempt.presence_error = presence.error().code;
            attempt.presence_error_message = presence.error().message;
        } else {
            attempt.presence = *presence == transport::Presence::Present
                                   ? smoke::ReadinessPresence::Present
                                   : smoke::ReadinessPresence::Absent;
        }

        auto physical_hash = run_operation(
            operations,
            std::string{operation_prefix} + "_physical_hash_attempt_" +
                std::to_string(attempt.attempt_index),
            [&] { return transport::physical_hash(storage, identifier, "sha256"); });
        if (!physical_hash) {
            attempt.physical_hash_error = physical_hash.error().code;
            attempt.physical_hash_error_message = physical_hash.error().message;
            if (physical_hash.error().code == transport::ErrorCode::ObjectNotFound) {
                attempt.physical_hash = smoke::ReadinessHash::ObjectNotFound;
            } else if (physical_hash.error().code == transport::ErrorCode::Unsupported) {
                attempt.physical_hash = smoke::ReadinessHash::Unsupported;
            } else {
                attempt.physical_hash = smoke::ReadinessHash::Failed;
            }
        } else if (!valid_sha256(*physical_hash)) {
            attempt.physical_hash = smoke::ReadinessHash::Invalid;
            attempt.physical_hash_error = transport::ErrorCode::ProtocolFailure;
            attempt.physical_hash_error_message =
                "physical_hash returned an invalid SHA-256";
            fail_operation(operations,
                           std::string{operation_prefix} +
                               "_validate_sha256_attempt_" +
                               std::to_string(attempt.attempt_index),
                           transport::ErrorCode::ProtocolFailure,
                           attempt.physical_hash_error_message);
        } else {
            attempt.physical_hash = smoke::ReadinessHash::Valid;
            attempt.sha256 = *physical_hash;
        }

        const bool stop = attempt.presence == smoke::ReadinessPresence::Failed ||
                          attempt.physical_hash !=
                              smoke::ReadinessHash::ObjectNotFound;
        attempts.push_back(std::move(attempt));
        if (stop) {
            break;
        }
    }
    return attempts;
}

nlohmann::json readiness_report(
    const std::vector<smoke::ReadinessAttempt>& attempts,
    smoke::ReadinessClassification classification,
    std::string_view elapsed_field) {
    nlohmann::json attempt_reports = nlohmann::json::array();
    for (const auto& attempt : attempts) {
        auto value = smoke::to_json(attempt);
        value[std::string{elapsed_field}] =
            value.at("elapsed_since_reference_ms");
        value.erase("elapsed_since_reference_ms");
        attempt_reports.push_back(std::move(value));
    }
    return nlohmann::json{
        {"classification",
         smoke::readiness_classification_name(classification)},
        {"attempts", std::move(attempt_reports)},
    };
}

void replace_all(std::string& value,
                 std::string_view secret,
                 std::string_view replacement) {
    if (secret.empty()) {
        return;
    }
    std::size_t position = 0;
    while ((position = value.find(secret, position)) != std::string::npos) {
        value.replace(position, secret.size(), replacement);
        position += replacement.size();
    }
}

nlohmann::json diagnostic_hashsumfile(
    rclone_detail::State& state,
    nlohmann::json& operations,
    std::string_view form_name,
    std::string fs,
    std::string remote) {
    constexpr std::size_t maximum_response_size = 64 * 1024;
    const nlohmann::json request{{"fs", fs},
                                 {"remote", remote},
                                 {"hashType", "SHA-256"}};
    const auto started = std::chrono::steady_clock::now();
    const auto response = rclone_detail::post_rc_read_only(
        state,
        "operations/hashsumfile",
        request.dump(),
        maximum_response_size,
        std::chrono::seconds{5});
    const auto elapsed = std::chrono::duration<double, std::milli>(
                             std::chrono::steady_clock::now() - started)
                             .count();

    nlohmann::json result{{"method", "operations/hashsumfile"},
                          {"request", request},
                          {"result", response ? "SUCCESS" : "FAILED"},
                          {"elapsed_ms", elapsed},
                          {"error_category", nullptr},
                          {"error_native_code", nullptr},
                          {"error_message", ""}};
    if (response) {
        try {
            result["response"] = nlohmann::json::parse(*response);
        } catch (const nlohmann::json::exception&) {
            result["result"] = "FAILED";
            result["response_text"] = *response;
            result["error_category"] = "protocol_failure";
            result["error_message"] = "RC response was not valid JSON";
        }
    } else {
        auto message = response.error().message;
        replace_all(message, state.username, "<redacted>");
        replace_all(message, state.password, "<redacted>");
        result["error_category"] =
            transport::error_code_name(response.error().code);
        result["error_native_code"] = response.error().native_code;
        result["error_message"] = std::move(message);
    }

    const auto operation_name = "diagnostic_hashsumfile_" +
                                std::string{form_name};
    smoke::OperationRecord operation{
        .name = operation_name,
        .result = result.at("result").get<std::string>(),
        .elapsed_ms = elapsed,
    };
    if (!response) {
        operation.error_category = response.error().code;
        operation.error_message = result.at("error_message").get<std::string>();
    }
    operations.push_back(smoke::to_json(operation));
    return result;
}

nlohmann::json compare_hashsumfile_path_forms(
    transport::Transport& storage,
    nlohmann::json& operations,
    const smoke::RemoteParent& parent,
    std::string_view child) {
    auto* state = static_cast<rclone_detail::State*>(storage.state.get());
    if (state == nullptr) {
        return nlohmann::json{
            {"result", "FAILED"},
            {"error", "rclone session state is unavailable"},
        };
    }
    const auto remote_root = parent.directory + "/" + std::string{child};
    const auto root_fs = state->configuration.remote_name + ":";
    auto form_a = diagnostic_hashsumfile(
        *state,
        operations,
        "form_a",
        root_fs,
        remote_root + "/source.bin");
    auto form_b = diagnostic_hashsumfile(
        *state,
        operations,
        "form_b",
        root_fs + remote_root,
        "source.bin");
    const bool identical = form_a.at("result") == form_b.at("result") &&
                           form_a.value("response", nlohmann::json{}) ==
                               form_b.value("response", nlohmann::json{}) &&
                           form_a.value("error_category", nlohmann::json{}) ==
                               form_b.value("error_category", nlohmann::json{}) &&
                           form_a.value("error_message", nlohmann::json{}) ==
                               form_b.value("error_message", nlohmann::json{});
    return nlohmann::json{
        {"method", "operations/hashsumfile"},
        {"hashType", "SHA-256"},
        {"forms_behavior_identical", identical},
        {"form_a_current_kasumi_form", std::move(form_a)},
        {"form_b_rooted_fs_form", std::move(form_b)},
    };
}

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
        if (option == "--remote") {
            result.remote = value;
        } else if (option == "--rclone-config") {
            result.rclone_config = std::filesystem::path{value};
        } else if (option == "--output") {
            result.output = std::filesystem::path{value};
        } else {
            return std::unexpected("unknown option: " + std::string{option});
        }
    }
    if (result.remote.empty() || result.output.empty()) {
        return std::unexpected("--remote and --output are required");
    }
    return result;
}

void print_usage(std::ostream& output) {
    output << "Usage: kasumi_remote_copy_smoke --remote <remote:path/test-parent> "
              "[--rclone-config <config-file>] --output <local-json-file>\n"
              "The remote must be a dedicated, non-root test parent.\n";
}

std::expected<ScratchDirectory, std::string> make_scratch_directory() {
    const auto temp = std::filesystem::temp_directory_path();
    for (int attempt = 0; attempt != 8; ++attempt) {
        const auto nonce = kasumi::platform::random::hex_id();
        if (!nonce) {
            return std::unexpected(nonce.error());
        }
        const auto candidate = temp / ("kasumi-copy-smoke-" + *nonce);
        std::error_code error;
        if (std::filesystem::create_directory(candidate, error)) {
            return ScratchDirectory{candidate};
        }
        if (error && error != std::errc::file_exists) {
            return std::unexpected("cannot create local scratch directory");
        }
    }
    return std::unexpected("could not allocate a unique local scratch directory");
}

std::expected<void, std::string>
write_file(const std::filesystem::path& path, std::string_view bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (!output) {
        return std::unexpected("failed to write local synthetic file");
    }
    return {};
}

std::expected<std::string, std::string>
read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::unexpected("failed to read downloaded synthetic file");
    }
    std::string bytes{std::istreambuf_iterator<char>{input}, {}};
    if (input.bad()) {
        return std::unexpected("failed while reading downloaded synthetic file");
    }
    return bytes;
}

bool valid_sha256(std::string_view hash) {
    return hash.size() == 64 &&
           std::all_of(hash.begin(), hash.end(), [](unsigned char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f') ||
                      (character >= 'A' && character <= 'F');
           });
}

void write_report(const std::filesystem::path& output,
                  const nlohmann::json& report) {
    if (output.empty()) {
        return;
    }
    std::ofstream stream(output, std::ios::binary | std::ios::trunc);
    if (!stream) {
        std::cerr << "Could not write JSON report: " << output.string() << '\n';
        return;
    }
    stream << report.dump(2) << '\n';
}

int execute(const Arguments& arguments) {
    nlohmann::json report{
        {"schema_version", 1},
        {"status", "FAILED"},
        {"remote_parent", arguments.remote},
        {"effective_namespace", nullptr},
        {"copy_path", "not_attempted"},
        {"native_copy_result", "NOT_ATTEMPTED"},
        {"fallback_result", "NOT_USED"},
        {"source_sha256", nullptr},
        {"destination_sha256", nullptr},
        {"hashes_match", false},
        {"sha256_verification", "not_attempted"},
        {"exact_byte_verification", "NOT_ATTEMPTED"},
        {"provider_side_copy", "NOT_MEASURED"},
        {"operations", nlohmann::json::array()},
        {"metrics",
         {{"rc_request_counts", "NOT_MEASURED"},
          {"client_payload_transfer_bytes", "NOT_MEASURED"},
          {"native_copy", "not_attempted"}}},
        {"diagnostics",
         {{"source_readiness", nullptr},
          {"destination_readiness", nullptr},
          {"source_hash_rc_path_forms", nullptr}}},
        {"cleanup",
         {{"result", "not_attempted"},
          {"detail", ""},
          {"removed_objects", 0},
          {"error_category", nullptr},
          {"namespace_directory_may_remain", true}}},
    };
    auto& records = report["operations"];
    bool failed = false;
    smoke::CopySmokeOutcome outcome;
    bool owned_child = false;
    bool ownership_ambiguous = false;
    std::string child;
    std::string owner_token;

    const auto parsed_parent = smoke::parse_remote_parent(arguments.remote);
    if (!parsed_parent) {
        fail_operation(records,
                       "validate_remote_parent",
                       transport::ErrorCode::InvalidIdentifier,
                       parsed_parent.error());
        report["cleanup"]["result"] = "not_needed";
        write_report(arguments.output, report);
        return 2;
    }

    if (arguments.rclone_config) {
        std::error_code error;
        if (!std::filesystem::is_regular_file(*arguments.rclone_config, error) ||
            error) {
            fail_operation(records,
                           "validate_rclone_config",
                           transport::ErrorCode::InvalidContext,
                           "rclone config must be an existing local regular file");
            report["cleanup"]["result"] = "not_needed";
            write_report(arguments.output, report);
            return 2;
        }
    }
    EnvironmentValue previous_config{"RCLONE_CONFIG"};
    if (arguments.rclone_config) {
        const auto config_path = std::filesystem::absolute(
            *arguments.rclone_config);
#ifdef _WIN32
        if (_putenv_s("RCLONE_CONFIG", config_path.string().c_str()) != 0) {
#else
        if (setenv("RCLONE_CONFIG", config_path.string().c_str(), 1) != 0) {
#endif
            fail_operation(records,
                           "configure_rclone_config",
                           transport::ErrorCode::InvalidContext,
                           "could not set RCLONE_CONFIG");
            report["cleanup"]["result"] = "not_needed";
            write_report(arguments.output, report);
            return 2;
        }
    }

    const auto nonce = kasumi::platform::random::hex_id();
    if (!nonce) {
        fail_operation(records,
                       "generate_child_namespace",
                       transport::ErrorCode::Io,
                       nonce.error());
        report["cleanup"]["result"] = "not_needed";
        write_report(arguments.output, report);
        return 2;
    }
    const auto generated_child = smoke::child_namespace(*nonce);
    if (!generated_child) {
        fail_operation(records,
                       "generate_child_namespace",
                       transport::ErrorCode::InvalidIdentifier,
                       generated_child.error());
        report["cleanup"]["result"] = "not_needed";
        write_report(arguments.output, report);
        return 2;
    }
    child = *generated_child;
    const auto scoped_location = smoke::child_location(*parsed_parent, child);
    if (!scoped_location) {
        fail_operation(records,
                       "validate_child_namespace",
                       transport::ErrorCode::InvalidIdentifier,
                       scoped_location.error());
        report["cleanup"]["result"] = "not_needed";
        write_report(arguments.output, report);
        return 2;
    }

    auto parent_result = run_operation(records, "open_remote_parent", [&] {
        return transport::open_transport(parsed_parent->location);
    });
    if (!parent_result) {
        failed = true;
    }
    if (parent_result) {
        auto parent_listing = run_operation(records, "validate_remote_parent", [&] {
            return transport::list(*parent_result);
        });
        if (!parent_listing) {
            failed = true;
        } else {
            auto unused = run_operation(records, "check_child_is_unused", [&] {
                return smoke::require_unused_child(*parent_result, child);
            });
            if (!unused) {
                failed = true;
            }
        }
    }
    if (failed) {
        report["cleanup"]["result"] = "not_needed";
        write_report(arguments.output, report);
        return 1;
    }

    const auto effective_namespace = *scoped_location;
    report["effective_namespace"] = effective_namespace;
    std::cout << "Effective test namespace: " << effective_namespace << '\n';
    std::cout.flush();

    auto scratch_result = make_scratch_directory();
    if (!scratch_result) {
        fail_operation(records,
                       "create_local_scratch",
                       transport::ErrorCode::Io,
                       scratch_result.error());
        report["cleanup"]["result"] = "not_needed";
        write_report(arguments.output, report);
        return 1;
    }
    ScratchDirectory scratch = std::move(*scratch_result);
    const auto source_path = scratch.path / "source.bin";
    const auto destination_path = scratch.path / "destination.bin";
    const auto marker_path = scratch.path / "owner.marker";
    owner_token = *nonce + "-kasumi-copy-smoke-owner";
    if (!write_file(source_path, payload) || !write_file(marker_path, owner_token)) {
        fail_operation(records,
                       "prepare_synthetic_files",
                       transport::ErrorCode::Io,
                       "could not prepare local synthetic data");
        report["cleanup"]["result"] = "not_needed";
        write_report(arguments.output, report);
        return 1;
    }

    auto child_result = run_operation(records, "open_child_transport", [&] {
        return transport::open_transport(*scoped_location);
    });
    if (!child_result) {
        failed = true;
        report["cleanup"]["result"] = "not_needed";
    } else {
        auto initialized = run_operation(records, "initialize_child_namespace", [&] {
            return transport::initialize(*child_result);
        });
        if (!initialized) {
            failed = true;
            ownership_ambiguous = true;
            report["cleanup"]["result"] = "refused";
            report["cleanup"]["detail"] =
                "initialization may have created the child; no owner marker exists";
        } else {
            auto empty_child = run_operation(records, "list_initialized_child", [&] {
                return transport::list(*child_result);
            });
            if (!empty_child || !empty_child->empty()) {
                if (empty_child && !empty_child->empty()) {
                    fail_operation(records,
                                   "verify_child_is_empty",
                                   transport::ErrorCode::InvalidIdentifier,
                                   "generated child is unexpectedly non-empty");
                }
                failed = true;
                ownership_ambiguous = true;
                report["cleanup"]["result"] = "refused";
                report["cleanup"]["detail"] =
                    "child contents are not owned by this run";
            } else {
                auto owner_put = run_operation(records, "write_owner_marker", [&] {
                    return transport::put(*child_result, marker_path, "owner.marker");
                });
                if (!owner_put) {
                    failed = true;
                    ownership_ambiguous = true;
                    report["cleanup"]["result"] = "refused";
                    report["cleanup"]["detail"] =
                        "owner-marker write may have completed; ownership is ambiguous";
                } else {
                    owned_child = true;
                    auto source_put = run_operation(records, "put_source", [&] {
                        return transport::put(*child_result, source_path, "source.bin");
                    });
                    if (!source_put) {
                        failed = true;
                    } else {
                        const auto source_attempts = probe_readiness(
                            *child_result,
                            "source.bin",
                            "source_readiness",
                            records);
                        const auto source_classification =
                            smoke::classify_readiness(
                                source_attempts, std::chrono::seconds{8});
                        report["diagnostics"]["source_readiness"] =
                            readiness_report(source_attempts,
                                             source_classification,
                                             "elapsed_since_put_ms");
                        std::optional<std::string> source_hash;
                        if (source_classification ==
                                smoke::ReadinessClassification::Ready ||
                            source_classification ==
                                smoke::ReadinessClassification::ReadyAfterDelay) {
                            const auto ready = std::find_if(
                                source_attempts.begin(),
                                source_attempts.end(),
                                [](const auto& attempt) {
                                    return attempt.physical_hash ==
                                           smoke::ReadinessHash::Valid;
                                });
                            if (ready != source_attempts.end()) {
                                source_hash = ready->sha256;
                                outcome.source_hash_valid = true;
                                report["source_sha256"] = *source_hash;
                                report["sha256_verification"] = "source_available";
                            }
                        } else if (source_classification ==
                                   smoke::ReadinessClassification::Unsupported) {
                            outcome.source_hash_unsupported = true;
                            report["sha256_verification"] = "UNSUPPORTED";
                        } else {
                            failed = true;
                            report["sha256_verification"] = "FAILED";
                            if (source_classification ==
                                smoke::ReadinessClassification::
                                    FailedContradictoryVisibility) {
                                report["diagnostics"]["source_hash_rc_path_forms"] =
                                    compare_hashsumfile_path_forms(
                                        *child_result,
                                        records,
                                        *parsed_parent,
                                        child);
                            }
                        }

                        const bool source_ready = source_hash.has_value();
                        if (!source_ready) {
                            record_skipped(records, "copy_source_to_destination");
                            record_skipped(records,
                                           "destination_physical_hash_sha256");
                            record_skipped(records, "get_destination");
                        } else {
                            auto copied = run_operation(
                                records,
                                "copy_source_to_destination",
                                [&] {
                                    return transport::copy(
                                        *child_result,
                                        "source.bin",
                                        "destination.bin");
                                });
                            if (copied) {
                                outcome.native_copy_succeeded = true;
                                report["copy_path"] = "native";
                                report["native_copy_result"] = "SUPPORTED";
                                report["metrics"]["native_copy"] = true;
                            } else if (copied.error().code ==
                                       transport::ErrorCode::Unsupported) {
                                outcome.copy_unsupported = true;
                                report["copy_path"] = "native_unsupported";
                                report["native_copy_result"] = "UNSUPPORTED";
                                report["metrics"]["native_copy"] = false;
                            } else {
                                report["copy_path"] = "native_failed";
                                report["native_copy_result"] = "FAILED";
                                report["metrics"]["native_copy"] =
                                    "attempted_failed";
                                failed = true;
                            }

                            if (outcome.native_copy_succeeded) {
                                const auto destination_attempts = probe_readiness(
                                    *child_result,
                                    "destination.bin",
                                    "destination_readiness",
                                    records);
                                const auto destination_classification =
                                    smoke::classify_readiness(
                                        destination_attempts,
                                        std::chrono::seconds{8});
                                report["diagnostics"]["destination_readiness"] =
                                    readiness_report(
                                        destination_attempts,
                                        destination_classification,
                                        "elapsed_since_copy_ms");

                                std::optional<std::string> destination_hash;
                                if (destination_classification ==
                                        smoke::ReadinessClassification::Ready ||
                                    destination_classification ==
                                        smoke::ReadinessClassification::
                                            ReadyAfterDelay) {
                                    const auto ready = std::find_if(
                                        destination_attempts.begin(),
                                        destination_attempts.end(),
                                        [](const auto& attempt) {
                                            return attempt.physical_hash ==
                                                   smoke::ReadinessHash::Valid;
                                        });
                                    if (ready != destination_attempts.end()) {
                                        destination_hash = ready->sha256;
                                        outcome.destination_hash_valid = true;
                                        report["destination_sha256"] =
                                            *destination_hash;
                                        if (*destination_hash != *source_hash) {
                                            fail_operation(
                                                records,
                                                "compare_physical_sha256",
                                                transport::ErrorCode::
                                                    ProtocolFailure,
                                                "source and destination SHA-256 differ");
                                            failed = true;
                                            report["sha256_verification"] =
                                                "FAILED";
                                        } else {
                                            outcome.hashes_match = true;
                                            report["hashes_match"] = true;
                                            report["sha256_verification"] =
                                                "VERIFIED";
                                        }
                                    }
                                } else if (destination_classification ==
                                           smoke::ReadinessClassification::
                                               Unsupported) {
                                    outcome.destination_hash_unsupported = true;
                                    report["sha256_verification"] =
                                        "UNSUPPORTED";
                                } else {
                                    failed = true;
                                    report["sha256_verification"] = "FAILED";
                                }

                                if (destination_hash) {
                                    auto destination_get = run_operation(
                                        records,
                                        "get_destination",
                                        [&] {
                                            return transport::get(
                                                *child_result,
                                                "destination.bin",
                                                destination_path);
                                        });
                                    if (!destination_get) {
                                        failed = true;
                                        report["exact_byte_verification"] =
                                            "FAILED";
                                    } else {
                                        auto destination_bytes =
                                            read_file(destination_path);
                                        if (!destination_bytes ||
                                            *destination_bytes != payload) {
                                            fail_operation(
                                                records,
                                                "verify_destination_bytes",
                                                transport::ErrorCode::
                                                    ProtocolFailure,
                                                "downloaded destination differs from synthetic payload");
                                            failed = true;
                                            report["exact_byte_verification"] =
                                                "FAILED";
                                        } else {
                                            outcome.destination_bytes_match =
                                                true;
                                            report["exact_byte_verification"] =
                                                "VERIFIED";
                                            records.push_back(smoke::to_json(
                                                smoke::OperationRecord{
                                                    .name =
                                                        "verify_destination_bytes",
                                                    .result = "SUCCESS"}));
                                        }
                                    }
                                } else {
                                    record_skipped(records, "get_destination");
                                }
                            } else {
                                record_skipped(
                                    records,
                                    "destination_physical_hash_sha256");
                                record_skipped(records, "get_destination");
                            }
                        }

                        auto source_presence = run_operation(
                            records, "query_source_presence", [&] {
                                return transport::presence(*child_result,
                                                           "source.bin");
                            });
                        if (!source_presence) {
                            failed = true;
                        } else if (*source_presence !=
                                   transport::Presence::Present) {
                            fail_operation(records,
                                           "verify_source_remains",
                                           transport::ErrorCode::ObjectNotFound,
                                           "copy removed the source object");
                            failed = true;
                        } else {
                            outcome.source_remains = true;
                            records.push_back(smoke::to_json(
                                smoke::OperationRecord{
                                    .name = "verify_source_remains",
                                    .result = "SUCCESS"}));
                        }
                    }
                }
            }
        }
    }

    if (child_result && owned_child) {
        const auto cleanup_started = std::chrono::steady_clock::now();
        const auto cleanup = smoke::cleanup_owned_child(
            *child_result,
            child,
            owner_token,
            {child + "/source.bin", child + "/destination.bin"},
            scratch.path);
        const auto cleanup_elapsed = std::chrono::duration<double, std::milli>(
                                         std::chrono::steady_clock::now() -
                                         cleanup_started)
                                         .count();
        smoke::OperationRecord cleanup_operation{
            .name = "cleanup_owned_objects",
            .result = cleanup.result == "removed" ? "SUCCESS" : "FAILED",
            .elapsed_ms = cleanup_elapsed,
            .error_category = cleanup.error_category,
            .error_message = cleanup.detail,
        };
        records.push_back(smoke::to_json(cleanup_operation));
        report["cleanup"] = smoke::to_json(cleanup);
        report["cleanup"]["namespace_directory_may_remain"] = true;
        if (cleanup.result != "removed") {
            failed = true;
            report["cleanup"]["exact_namespace_to_inspect"] = effective_namespace;
        } else {
            outcome.cleanup_succeeded = true;
        }
    } else if (ownership_ambiguous) {
        report["cleanup"]["exact_namespace_to_inspect"] = effective_namespace;
    } else if (!owned_child) {
        report["cleanup"]["result"] = "not_needed";
    }

    outcome.required_operation_failed = failed;
    const auto status = smoke::classify(outcome);
    report["status"] = std::string{smoke::status_name(status)};
    write_report(arguments.output, report);
    return status == smoke::SmokeStatus::Pass
               ? 0
               : (status == smoke::SmokeStatus::Unsupported ? 3 : 1);
}

} // namespace

int main(int argc, char** argv) {
    auto arguments = parse_arguments(argc, argv);
    if (!arguments) {
        if (arguments.error() == "help") {
            print_usage(std::cout);
            return 0;
        }
        print_usage(std::cerr);
        std::cerr << arguments.error() << '\n';
        return 2;
    }
    return execute(*arguments);
}
