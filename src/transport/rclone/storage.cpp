#include "../detail.hpp"
#include "detail.hpp"
#include "platform/cancellation.hpp"
#include "platform/path.hpp"
#include "platform/random.hpp"
#include "platform/workspace.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_set>
#include <utility>
#include <vector>

namespace kasumi::transport::rclone_detail {
namespace {

constexpr std::size_t maximum_response_size = 64 * 1024;
constexpr std::size_t maximum_list_response_size = 64 * 1024 * 1024;
constexpr std::size_t maximum_check_response_size = 64 * 1024 * 1024;
constexpr auto quick_timeout = std::chrono::seconds{30};
// Drive DELETE calls show 5-20 s tails; 120 s avoids ambiguous client timeouts.
constexpr auto remove_timeout = std::chrono::seconds{120};
constexpr auto control_read_deadline = std::chrono::minutes{2};
constexpr auto transfer_timeout = std::chrono::minutes{30};

using detail::make_error;

Error invalid_context_error() {
    return make_error(ErrorCode::InvalidContext, "RC session is not ready");
}

Error invalid_identifier_error() {
    return make_error(ErrorCode::InvalidIdentifier,
                      "invalid object identifier");
}

Error filesystem_error(const std::error_code& error) {
    return make_error(ErrorCode::Io, error.message(), error.value());
}

bool valid_identifier(std::string_view identifier) noexcept {
    return detail::valid_relative_identifier(identifier, false);
}

bool valid_sha256(std::string_view value) noexcept {
    return value.size() == 64 && std::ranges::all_of(value, [](char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f') ||
                      (character >= 'A' && character <= 'F');
           });
}

bool valid_batch_identifier(std::string_view identifier) noexcept {
    return identifier.find_first_of("\r\n") == std::string_view::npos &&
           detail::valid_relative_identifier(identifier, true);
}

std::string ascii_lower(std::string value) {
    std::ranges::transform(value, value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

nlohmann::json stat_opt(bool files_only,
                        std::optional<bool> recurse = std::nullopt,
                        bool no_mod_time = true) {
    nlohmann::json opt{
        {"filesOnly", files_only},
        {"noModTime", no_mod_time},
        {"noMimeType", true},
    };
    if (recurse.has_value()) {
        opt["recurse"] = *recurse;
    }
    return opt;
}

PresenceResult parse_stat_presence(const nlohmann::json& item,
                                   std::string_view invalid_message,
                                   std::string_view directory_message) {
    if (item.is_null()) {
        return Presence::Absent;
    }
    if (!item.is_object() ||
        (item.contains("IsDir") && !item.at("IsDir").is_boolean())) {
        return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                          std::string{invalid_message}));
    }
    if (item.value("IsDir", false)) {
        return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                          std::string{directory_message}));
    }
    return Presence::Present;
}

std::expected<State*, Error>
require_ready(void* context,
              std::optional<std::string_view> identifier = std::nullopt) {
    auto* state = static_cast<State*>(context);
    if (state == nullptr || !state->ready ||
        state->configuration.remote_name.empty()) {
        return std::unexpected(invalid_context_error());
    }
    if (identifier && !valid_identifier(*identifier)) {
        return std::unexpected(invalid_identifier_error());
    }
    return state;
}

std::string join_remote_path(std::string_view root, std::string_view suffix) {
    while (root.ends_with('/')) {
        root.remove_suffix(1);
    }
    while (suffix.starts_with('/')) {
        suffix.remove_prefix(1);
    }
    while (suffix.ends_with('/')) {
        suffix.remove_suffix(1);
    }
    if (root.empty()) {
        return std::string{suffix};
    }
    if (suffix.empty()) {
        return std::string{root};
    }
    return std::string{root} + "/" + std::string{suffix};
}

std::string rooted_remote_fs(const State& state) {
    return state.configuration.remote_name + ":" +
           state.configuration.remote_root;
}

std::expected<nlohmann::json, Error>
request_json(State& state,
             std::string_view endpoint,
             const nlohmann::json& request,
             std::size_t response_limit,
             std::chrono::milliseconds read_timeout,
             bool retry_transient_reads = false,
             bool honour_cancellation = true) {
    const auto body = request.dump();
    const auto response =
        retry_transient_reads
            ? post_rc_read_only(
                  state, endpoint, body, response_limit, read_timeout)
            : post_rc(state,
                      endpoint,
                      body,
                      response_limit,
                      read_timeout,
                      honour_cancellation);
    if (!response) {
        return std::unexpected(response.error());
    }

    try {
        return nlohmann::json::parse(*response);
    } catch (const std::exception&) {
        return std::unexpected(make_error(
            ErrorCode::ProtocolFailure,
            std::string{"invalid "} + std::string{endpoint} + " response"));
    }
}

std::expected<nlohmann::json, Error>
request_read_json(State& state,
                  std::string_view endpoint,
                  const nlohmann::json& request,
                  std::size_t response_limit,
                  std::chrono::milliseconds deadline) {
    return request_json(
        state, endpoint, request, response_limit, deadline, true);
}

std::expected<std::vector<std::string>, Error>
check_entries(const nlohmann::json& response,
              std::string_view name,
              const std::unordered_set<std::string>& expected,
              std::unordered_set<std::string>& seen) {
    if (!response.contains(name) || !response.at(name).is_array()) {
        return std::unexpected(make_error(
            ErrorCode::ProtocolFailure,
            "operations/check response missing list " + std::string{name}));
    }

    std::vector<std::string> entries;
    for (const auto& item : response.at(name)) {
        if (!item.is_string()) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "operations/check response contains invalid entry"));
        }
        auto identifier = item.get<std::string>();
        if (!expected.contains(identifier) || !seen.insert(identifier).second) {
            return std::unexpected(make_error(
                ErrorCode::ProtocolFailure,
                "operations/check response contains unexpected identifier"));
        }
        entries.push_back(std::move(identifier));
    }
    return entries;
}

bool unsupported_endpoint(const Error& error,
                          std::string_view endpoint) noexcept {
    return error.code == ErrorCode::ProtocolFailure &&
           error.native_code == 404 &&
           (error.message.contains("method not found") ||
            (error.message.contains("couldn't find method") &&
             error.message.contains(endpoint)));
}

bool unsupported_hash(const Error& error) noexcept {
    return error.message.contains("hash type not supported") ||
           error.message.contains("hash type is not supported") ||
           error.message.contains("unsupported hash type") ||
           error.message.contains("unknown hash type");
}

std::expected<nlohmann::json, Error>
run_job_batch(State& state,
              const nlohmann::json& inputs,
              std::size_t concurrency,
              std::size_t response_limit,
              std::chrono::milliseconds timeout,
              bool read_only) {
    nlohmann::json request{
        {"inputs", inputs},
        {"concurrency", concurrency},
    };
    auto response = request_json(
        state, "job/batch", request, response_limit, timeout, read_only);
    if (!response) {
        if (unsupported_endpoint(response.error(), "job/batch")) {
            return std::unexpected(
                make_error(ErrorCode::Unsupported,
                           "rclone does not support job/batch",
                           response.error().native_code));
        }
        auto error = response.error();
        if (!read_only && error.code == ErrorCode::ProtocolFailure &&
            error.native_code == 0) {
            error.code = ErrorCode::BackendUnavailable;
        }
        return std::unexpected(std::move(error));
    }
    return response;
}

std::expected<int, Error>
parse_job_batch_status(const nlohmann::json& status_json,
                       std::string_view operation_name) {
    if (!status_json.is_number_integer()) {
        return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                          std::string("invalid ") +
                                              std::string(operation_name) +
                                              " job/batch result status"));
    }
    const auto in_range = [](auto value) noexcept {
        return value >= 100 && value <= 599;
    };
    if (status_json.is_number_unsigned()) {
        if (const auto val = status_json.get<std::uint64_t>(); in_range(val)) {
            return static_cast<int>(val);
        }
    } else if (const auto val = status_json.get<std::int64_t>();
               in_range(val)) {
        return static_cast<int>(val);
    }
    return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                      std::string("out-of-range ") +
                                          std::string(operation_name) +
                                          " job/batch result status"));
}

std::expected<std::filesystem::path, Error>
absolute_path(const std::filesystem::path& path) {
    std::error_code error;
    auto absolute = std::filesystem::absolute(path, error);
    if (error) {
        return std::unexpected(filesystem_error(error));
    }
    return absolute;
}

Result ensure_parent_directory(const std::filesystem::path& path) {
    const auto parent = path.parent_path();
    if (parent.empty()) {
        return std::unexpected(make_error(
            ErrorCode::InvalidContext, "local path has no parent directory"));
    }

    std::error_code error;
    std::filesystem::create_directories(parent, error);
    if (error) {
        return std::unexpected(filesystem_error(error));
    }
    return {};
}

Result require_regular_source(const std::filesystem::path& source) {
    std::error_code error;
    const bool regular = std::filesystem::is_regular_file(source, error);
    if (error) {
        if (error == std::errc::no_such_file_or_directory) {
            return std::unexpected(make_error(ErrorCode::ObjectNotFound,
                                              "source file does not exist"));
        }
        return std::unexpected(filesystem_error(error));
    }
    if (!regular) {
        return std::unexpected(make_error(ErrorCode::ObjectNotFound,
                                          "source file does not exist"));
    }
    return {};
}

std::expected<nlohmann::json, Error>
stat_remote(State& state, std::string_view remote, bool files_only = true) {
    return request_read_json(state,
                             "operations/stat",
                             nlohmann::json{
                                 {"fs", rooted_remote_fs(state)},
                                 {"remote", remote},
                                 {"opt", stat_opt(files_only)},
                             },
                             maximum_response_size,
                             control_read_deadline);
}

bool missing_object(std::string_view message) noexcept {
    return message == "object not found" || message == "directory not found" ||
           message.ends_with(": object not found") ||
           message.ends_with(": directory not found");
}

bool not_found(const Error& error) noexcept {
    return error.code == ErrorCode::ObjectNotFound ||
           (error.code == ErrorCode::ProtocolFailure &&
            (error.native_code == 404 ||
             error.message.contains("not found"))) ||
           (error.code == ErrorCode::BackendUnavailable &&
            error.native_code == 500 && missing_object(error.message));
}

struct SplitLocalPath {
    std::filesystem::path absolute;
    std::string parent;
    std::string name;
};

std::expected<SplitLocalPath, Error>
split_local_path(const std::filesystem::path& path,
                 std::string_view invalid_message) {
    const auto absolute = absolute_path(path);
    if (!absolute) {
        return std::unexpected(absolute.error());
    }
    auto name = platform::path::to_utf8(absolute->filename());
    auto parent = platform::path::to_utf8(absolute->parent_path());
    if (name.empty() || parent.empty()) {
        return std::unexpected(make_error(ErrorCode::InvalidContext,
                                          std::string{invalid_message}));
    }
    return SplitLocalPath{
        .absolute = *absolute,
        .parent = std::move(parent),
        .name = std::move(name),
    };
}

std::optional<std::uint64_t> nonnegative_integer(const nlohmann::json& object,
                                                 std::string_view key) {
    const auto it = object.find(key);
    if (it == object.end()) {
        return std::nullopt;
    }
    if (it->is_number_unsigned()) {
        return it->get<std::uint64_t>();
    }
    if (it->is_number_integer()) {
        const auto value = it->get<std::int64_t>();
        if (value >= 0) {
            return static_cast<std::uint64_t>(value);
        }
    }
    return std::nullopt;
}

std::optional<double> transfer_speed(const nlohmann::json& object) {
    const auto it = object.find("speed");
    if (it != object.end() && it->is_number()) {
        const auto value = it->get<double>();
        if (std::isfinite(value) && value >= 0.0) {
            return value;
        }
    }
    return std::nullopt;
}

Result validate_finished_job(const State& state, const nlohmann::json& result) {
    const auto success = result.find("success");
    const auto error = result.find("error");
    if (success == result.end() || !success->is_boolean() ||
        (error != result.end() && !error->is_string())) {
        return std::unexpected(make_error(ErrorCode::BackendUnavailable,
                                          "invalid job/status result"));
    }
    if (!success->get<bool>() ||
        (error != result.end() &&
         !error->get_ref<const std::string&>().empty())) {
        const std::string_view message =
            error != result.end()
                ? std::string_view{error->get_ref<const std::string&>()}
                : std::string_view{};
        const bool missing = missing_object(message);
        return std::unexpected(make_error(
            missing ? ErrorCode::ObjectNotFound : ErrorCode::BackendUnavailable,
            rc_error_detail(state, message, "rclone transfer job failed"),
            missing ? 404 : 0));
    }
    return {};
}

std::optional<TransferItemProgress> transfer_item(const nlohmann::json& stats,
                                                  std::string_view identifier) {
    const auto transferring = stats.find("transferring");
    if (transferring == stats.end() || !transferring->is_array()) {
        return std::nullopt;
    }
    for (const auto& item : *transferring) {
        const auto name = item.find("name");
        if (name != item.end() && name->is_string() &&
            name->get_ref<const std::string&>() == identifier) {
            const auto bytes = nonnegative_integer(item, "bytes");
            const auto total = nonnegative_integer(item, "size");
            if (bytes && total && *total > 0 && *bytes <= *total) {
                return TransferItemProgress{*bytes, *total};
            }
        }
    }
    return std::nullopt;
}

Result run_copy(State& state,
                std::string_view endpoint,
                nlohmann::json payload,
                const TransportProgressCallback& callback,
                bool read_only = false,
                std::string_view progress_identifier = {}) {
    if (!callback) {
        const auto copied = request_json(state,
                                         endpoint,
                                         payload,
                                         maximum_response_size,
                                         transfer_timeout,
                                         read_only);
        if (!copied) {
            auto error = copied.error();
            if (error.code == ErrorCode::ProtocolFailure &&
                error.native_code == 0) {
                error.code = ErrorCode::BackendUnavailable;
            }
            return std::unexpected(std::move(error));
        }
        return {};
    }

    if (platform::cancellation::requested()) {
        return std::unexpected(
            make_error(ErrorCode::Cancelled, "transfer cancelled"));
    }
    static std::atomic<std::uint64_t> sequence{0};
    const auto group =
        "kasumi-xfer-" +
        std::to_string(sequence.fetch_add(1, std::memory_order_relaxed));
    payload["_async"] = true;
    payload["_group"] = group;
    using namespace std::chrono_literals;
    const auto submitted = request_json(
        state, endpoint, payload, maximum_response_size, 5s, false, false);
    if (!submitted) {
        auto error = submitted.error();
        if (error.code == ErrorCode::ProtocolFailure &&
            error.native_code == 0) {
            error.code = ErrorCode::BackendUnavailable;
        }
        return std::unexpected(std::move(error));
    }
    if (submitted->is_object() && !submitted->contains("jobid")) {
        // A synchronous RC response is already the completion of this copy.
        if (submitted->contains("success")) {
            return validate_finished_job(state, *submitted);
        }
        if (submitted->empty()) {
            return {};
        }
    }
    const auto job_id = nonnegative_integer(*submitted, "jobid");
    if (!job_id) {
        return std::unexpected(
            make_error(ErrorCode::BackendUnavailable, "invalid async job id"));
    }

    const nlohmann::json job{{"jobid", *job_id}};
    struct JobCleanup {
        State& state;
        const nlohmann::json& job;
        std::string_view group;
        bool running = true;
        bool cleanup_needed = true;
        ~JobCleanup() noexcept {
            if (!std::exchange(cleanup_needed, false)) {
                return;
            }
            try {
                if (running) {
                    (void)post_rc(state,
                                  "job/stop",
                                  job.dump(),
                                  maximum_response_size,
                                  1s,
                                  false);
                    const auto deadline = std::chrono::steady_clock::now() + 2s;
                    while (std::chrono::steady_clock::now() < deadline) {
                        const auto status = request_json(state,
                                                         "job/status",
                                                         job,
                                                         maximum_response_size,
                                                         500ms,
                                                         false,
                                                         false);
                        if (status) {
                            const auto finished = status->find("finished");
                            if (finished != status->end() &&
                                finished->is_boolean() &&
                                finished->get<bool>()) {
                                running = false;
                                break;
                            }
                        } else if (status.error().message.ends_with(
                                       ": job not found")) {
                            running = false;
                            break;
                        }
                        std::this_thread::sleep_for(50ms);
                    }
                }
                if (!running) {
                    (void)post_rc(state,
                                  "core/stats-delete",
                                  nlohmann::json{{"group", group}}.dump(),
                                  maximum_response_size,
                                  1s,
                                  false);
                }
            } catch (...) {
            }
        }
    } cleanup{state, job, group};

    const auto finish_cleanup = [&]() noexcept {
        if (!std::exchange(cleanup.cleanup_needed, false)) {
            return !cleanup.running;
        }
        try {
            if (cleanup.running) {
                (void)post_rc(cleanup.state,
                              "job/stop",
                              cleanup.job.dump(),
                              maximum_response_size,
                              1s,
                              false);
                const auto deadline = std::chrono::steady_clock::now() + 2s;
                while (std::chrono::steady_clock::now() < deadline) {
                    const auto status = request_json(cleanup.state,
                                                     "job/status",
                                                     cleanup.job,
                                                     maximum_response_size,
                                                     500ms,
                                                     false,
                                                     false);
                    if (status) {
                        const auto finished = status->find("finished");
                        if (finished != status->end() &&
                            finished->is_boolean() && finished->get<bool>()) {
                            cleanup.running = false;
                            break;
                        }
                    } else if (status.error().message.ends_with(
                                   ": job not found")) {
                        cleanup.running = false;
                        break;
                    }
                    std::this_thread::sleep_for(50ms);
                }
            }
            if (!cleanup.running) {
                (void)post_rc(cleanup.state,
                              "core/stats-delete",
                              nlohmann::json{{"group", cleanup.group}}.dump(),
                              maximum_response_size,
                              1s,
                              false);
            }
        } catch (...) {
        }
        return !cleanup.running;
    };

    const auto fail = [&](Error error) -> Result {
        if (!finish_cleanup()) {
            error.message += "; rclone job termination could not be confirmed";
        }
        return std::unexpected(std::move(error));
    };

    TransferProgress latest;
    const auto deadline = std::chrono::steady_clock::now() + transfer_timeout;
    for (;;) {
        if (platform::cancellation::requested()) {
            return fail(make_error(ErrorCode::Cancelled, "transfer cancelled"));
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now());
        if (remaining <= 0ms) {
            return fail(
                make_error(ErrorCode::Timeout, "transfer job timed out"));
        }
        const auto status = request_read_json(state,
                                              "job/status",
                                              job,
                                              maximum_response_size,
                                              std::min(remaining, 5000ms));
        if (!status) {
            auto error = status.error();
            if (!mutation_result_is_ambiguous(error)) {
                error.code = ErrorCode::BackendUnavailable;
            }
            return fail(std::move(error));
        }
        const auto finished = status->find("finished");
        if (finished == status->end() || !finished->is_boolean()) {
            return fail(make_error(ErrorCode::BackendUnavailable,
                                   "invalid job/status response"));
        }
        const bool done = finished->get<bool>();
        if (done) {
            cleanup.running = false;
            if (auto valid = validate_finished_job(state, *status); !valid) {
                return valid;
            }
        }
        const auto stats = request_json(
            state,
            "core/stats",
            {{"group", group}, {"short", progress_identifier.empty() || done}},
            maximum_response_size,
            2s);
        bool sampled = false;
        if (stats) {
            if (const auto bytes = nonnegative_integer(*stats, "bytes")) {
                sampled = true;
                latest.bytes_transferred =
                    std::max(latest.bytes_transferred, *bytes);
                latest.total_bytes = nonnegative_integer(*stats, "totalBytes");
                const auto objects =
                    nonnegative_integer(*stats, "transfers").value_or(0);
                const auto total =
                    nonnegative_integer(*stats, "totalTransfers");
                constexpr auto limit =
                    (std::numeric_limits<std::size_t>::max)();
                if (objects <= limit) {
                    latest.objects_completed =
                        std::max(latest.objects_completed,
                                 static_cast<std::size_t>(objects));
                }
                if (total && *total <= limit) {
                    latest.total_objects = static_cast<std::size_t>(*total);
                }
                latest.bytes_per_second = transfer_speed(*stats);
                latest.eta_seconds = nonnegative_integer(*stats, "eta");
                latest.item = progress_identifier.empty() || done
                                  ? std::nullopt
                                  : transfer_item(*stats, progress_identifier);
                if (done) {
                    latest.total_bytes = latest.bytes_transferred;
                    latest.total_objects = latest.objects_completed;
                    latest.eta_seconds = 0;
                }
                report_transfer(callback, latest);
            }
        }
        if (done) {
            if (!sampled && (latest.total_bytes || latest.bytes_transferred)) {
                latest.total_bytes.reset();
                latest.item.reset();
                latest.eta_seconds = 0;
                report_transfer(callback, latest);
            }
            return {};
        }
        for (int tick = 0; tick < 10 && !platform::cancellation::requested();
             ++tick) {
            std::this_thread::sleep_for(25ms);
        }
    }
}

Result copyfile_object(State& state,
                       std::string_view src_fs,
                       std::string_view src_remote,
                       std::string_view dst_fs,
                       std::string_view dst_remote,
                       bool no_check_destination,
                       std::string_view not_found_message,
                       const TransportProgressCallback& callback) {
    nlohmann::json payload{{"srcFs", std::string{src_fs}},
                           {"srcRemote", std::string{src_remote}},
                           {"dstFs", std::string{dst_fs}},
                           {"dstRemote", std::string{dst_remote}}};
    // Downloads must replace stale bytes even when size and mtime match.
    payload["_config"] = {
        {no_check_destination ? "NoCheckDest" : "IgnoreTimes", true}};
    const auto copied =
        run_copy(state, "operations/copyfile", std::move(payload), callback);
    if (!copied) {
        if (!not_found_message.empty() && not_found(copied.error())) {
            return std::unexpected(make_error(ErrorCode::ObjectNotFound,
                                              std::string{not_found_message}));
        }
        return std::unexpected(copied.error());
    }
    return {};
}

PresenceResult rclone_presence(void* context, std::string_view identifier);

Result rclone_initialize(void* context) {
    auto state = require_ready(context);
    if (!state) {
        return std::unexpected(state.error());
    }

    const auto created = request_json(
        **state,
        "operations/mkdir",
        nlohmann::json{{"fs", rooted_remote_fs(**state)}, {"remote", ""}},
        maximum_response_size,
        quick_timeout);
    if (!created) {
        return std::unexpected(created.error());
    }
    return {};
}

Result rclone_put_progress(void* context,
                           const std::filesystem::path& source,
                           std::string_view identifier,
                           const TransportProgressCallback& callback) {
    auto state = require_ready(context, identifier);
    if (!state) {
        return std::unexpected(state.error());
    }

    const auto local = split_local_path(source, "invalid source file");
    if (!local) {
        return std::unexpected(local.error());
    }
    if (const auto source_file = require_regular_source(local->absolute);
        !source_file) {
        return source_file;
    }

    return copyfile_object(**state,
                           local->parent,
                           local->name,
                           rooted_remote_fs(**state),
                           identifier,
                           true,
                           {},
                           callback);
}

Result sync_copy_batch(State& state,
                       std::string_view src_fs,
                       std::string_view dst_fs,
                       std::span<const std::string> identifiers,
                       std::size_t max_parallel_transfers,
                       nlohmann::json base_config,
                       bool read_only,
                       const TransportProgressCallback& callback,
                       std::string_view progress_identifier = {}) {
    nlohmann::json include_rules = nlohmann::json::array();
    for (const auto& identifier : identifiers) {
        // Reject rclone filter glob/brace metacharacters so an identifier
        // cannot expand an IncludeRule beyond its exact relative path.
        if (!valid_identifier(identifier) ||
            identifier.find_first_of("*?[]{}") != std::string::npos) {
            return std::unexpected(invalid_identifier_error());
        }
        include_rules.push_back("/" + identifier);
    }
    nlohmann::json payload = {
        {"srcFs", std::string{src_fs}},
        {"dstFs", std::string{dst_fs}},
        {"createEmptySrcDirs", false},
        {"_filter", {{"IncludeRule", include_rules}}},
    };
    if (max_parallel_transfers > 0) {
        base_config["Transfers"] = max_parallel_transfers;
    }
    if (!base_config.empty()) {
        payload["_config"] = std::move(base_config);
    }
    return run_copy(state,
                    "sync/copy",
                    std::move(payload),
                    callback,
                    read_only,
                    progress_identifier);
}

Result rclone_put_batch(void* context, const PutBatch& batch) {
    auto state = require_ready(context);
    if (!state) {
        return std::unexpected(state.error());
    }
    if (batch.identifiers.empty()) {
        return {};
    }
    const auto absolute_source = absolute_path(batch.source_root);
    if (!absolute_source) {
        return std::unexpected(absolute_source.error());
    }
    return sync_copy_batch(**state,
                           platform::path::to_utf8(*absolute_source),
                           rooted_remote_fs(**state),
                           batch.identifiers,
                           batch.max_parallel_transfers,
                           {{"NoTraverse", true},
                            {"NoUpdateModTime", true},
                            {"NoCheckDest", true}},
                           false,
                           batch.on_progress,
                           batch.progress_identifier);
}

Result rclone_get_progress(void* context,
                           std::string_view identifier,
                           const std::filesystem::path& destination,
                           const TransportProgressCallback& callback) {
    auto state = require_ready(context, identifier);
    if (!state) {
        return std::unexpected(state.error());
    }

    const auto local =
        split_local_path(destination, "invalid local destination");
    if (!local) {
        return std::unexpected(local.error());
    }
    std::error_code error;
    const auto pre_status =
        std::filesystem::symlink_status(local->absolute, error);
    if (error && error != std::errc::no_such_file_or_directory) {
        return std::unexpected(filesystem_error(error));
    }
    if (std::filesystem::is_symlink(pre_status) ||
        std::filesystem::is_directory(pre_status)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidContext,
                       "local destination cannot be a symlink or directory"));
    }
    if (const auto parent = ensure_parent_directory(local->absolute); !parent) {
        return parent;
    }

    if (const auto copied = copyfile_object(**state,
                                            rooted_remote_fs(**state),
                                            identifier,
                                            local->parent,
                                            local->name,
                                            false,
                                            "remote object does not exist",
                                            callback);
        !copied) {
        return copied;
    }

    error.clear();
    const auto post_status =
        std::filesystem::symlink_status(local->absolute, error);
    if (error) {
        return std::unexpected(filesystem_error(error));
    }
    if (std::filesystem::is_symlink(post_status) ||
        !std::filesystem::is_regular_file(post_status)) {
        return std::unexpected(
            make_error(ErrorCode::ProtocolFailure,
                       "local destination did not become regular file"));
    }
    return {};
}

Result rclone_get_batch(void* context, const GetBatch& batch) {
    auto state = require_ready(context);
    if (!state) {
        return std::unexpected(state.error());
    }
    if (!batch.source_prefix.empty() &&
        !valid_identifier(batch.source_prefix)) {
        return std::unexpected(invalid_identifier_error());
    }
    if (batch.identifiers.empty()) {
        return {};
    }
    const auto absolute_destination = absolute_path(batch.destination_root);
    if (!absolute_destination) {
        return std::unexpected(absolute_destination.error());
    }
    const auto check_destination = [&](std::string_view id) -> PresenceResult {
        auto current = *absolute_destination;
        const auto relative = platform::path::from_utf8(id);
        for (auto component = relative.begin();; ++component) {
            const bool last = component == relative.end();
            std::error_code error;
            const auto status = std::filesystem::symlink_status(current, error);
            if (error == std::errc::no_such_file_or_directory ||
                (!error &&
                 status.type() == std::filesystem::file_type::not_found)) {
                return Presence::Absent;
            }
            if (error) {
                return std::unexpected(filesystem_error(error));
            }
            if (platform::private_storage::is_reparse_or_symlink(current) ||
                !(last ? std::filesystem::is_regular_file(status)
                       : std::filesystem::is_directory(status))) {
                return std::unexpected(
                    make_error(ErrorCode::InvalidContext,
                               "batch destination has an invalid entry"));
            }
            if (last) {
                return Presence::Present;
            }
            current /= *component;
        }
    };

    bool contains_existing = false;
    for (const auto& id : batch.identifiers) {
        if (!valid_identifier(id) || id.find_first_of("*?[]{}") != id.npos) {
            return std::unexpected(invalid_identifier_error());
        }
        const auto present = check_destination(id);
        if (!present) {
            return std::unexpected(present.error());
        }
        contains_existing |= *present == Presence::Present;
    }
    if (contains_existing) {
        // A preexisting file cannot prove that an IncludeRule matched remotely.
        for (const auto& id : batch.identifiers) {
            const auto source = join_remote_path(batch.source_prefix, id);
            if (auto copied = rclone_get_progress(
                    context,
                    source,
                    *absolute_destination / platform::path::from_utf8(id),
                    {});
                !copied) {
                return copied;
            }
        }
        return {};
    }

    auto scratch = platform::create_workspace("rclone-get-batch");
    if (!scratch) {
        return std::unexpected(make_error(ErrorCode::Io, scratch.error()));
    }
    struct ScratchCleanup {
        const platform::Workspace& workspace;
        ~ScratchCleanup() noexcept {
            platform::cleanup_workspace(workspace);
        }
    } cleanup{*scratch};
    const auto files = scratch->root / "files";
    {
        std::ofstream file_list(files, std::ios::binary);
        if (!file_list) {
            return std::unexpected(
                make_error(ErrorCode::Io, "failed to create batch file list"));
        }
        for (const auto& id : batch.identifiers) {
            file_list << id << '\n';
        }
        file_list.close();
        if (!file_list) {
            return std::unexpected(
                make_error(ErrorCode::Io, "failed to write batch file list"));
        }
    }

    nlohmann::json config = {
        {"NoTraverse", true},
        {"NoUpdateModTime", true},
        {"NoCheckDest", true},
    };
    if (batch.max_parallel_transfers > 0) {
        config["Transfers"] = batch.max_parallel_transfers;
    }
    nlohmann::json payload = {
        {"srcFs",
         batch.source_prefix.empty()
             ? rooted_remote_fs(**state)
             : join_remote_path(rooted_remote_fs(**state),
                                batch.source_prefix)},
        {"dstFs", platform::path::to_utf8(*absolute_destination)},
        {"createEmptySrcDirs", false},
        {"_filter", {{"FilesFromRaw", {platform::path::to_utf8(files)}}}},
        {"_config", std::move(config)},
    };
    auto copied = run_copy(
        **state, "sync/copy", std::move(payload), batch.on_progress, true);
    platform::cleanup_workspace(*scratch);
    if (!copied) {
        return copied;
    }
    for (const auto& id : batch.identifiers) {
        const auto present = check_destination(id);
        if (!present) {
            return std::unexpected(present.error());
        }
        if (*present == Presence::Absent) {
            return std::unexpected(
                make_error(ErrorCode::ObjectNotFound,
                           "rclone did not download requested object: " + id));
        }
    }
    return {};
}

Result rclone_put(void* context,
                  const std::filesystem::path& source,
                  std::string_view identifier) {
    return rclone_put_progress(context, source, identifier, {});
}

Result rclone_get(void* context,
                  std::string_view identifier,
                  const std::filesystem::path& destination) {
    return rclone_get_progress(context, identifier, destination, {});
}

std::optional<int> parse_fixed_uint(std::string_view text,
                                    std::size_t pos,
                                    std::size_t digits) noexcept {
    if (pos + digits > text.size()) {
        return std::nullopt;
    }
    int value = 0;
    for (std::size_t i = 0; i < digits; ++i) {
        const char ch = text[pos + i];
        if (ch < '0' || ch > '9') {
            return std::nullopt;
        }
        value = value * 10 + (ch - '0');
    }
    return value;
}

std::optional<std::int64_t>
parse_rfc3339_utc_seconds(std::string_view text) noexcept {
    // Minimum RFC3339 form: YYYY-MM-DDTHH:MM:SSZ
    if (text.size() < 20 || text[4] != '-' || text[7] != '-' ||
        (text[10] != 'T' && text[10] != 't') || text[13] != ':' ||
        text[16] != ':') {
        return std::nullopt;
    }
    const auto year = parse_fixed_uint(text, 0, 4);
    const auto month = parse_fixed_uint(text, 5, 2);
    const auto day = parse_fixed_uint(text, 8, 2);
    const auto hour = parse_fixed_uint(text, 11, 2);
    const auto minute = parse_fixed_uint(text, 14, 2);
    const auto second = parse_fixed_uint(text, 17, 2);
    if (!year || !month || !day || !hour || !minute || !second ||
        *year < 1970 || *year > 9999 || *month < 1 || *month > 12 ||
        *hour < 0 || *hour > 23 || *minute < 0 || *minute > 59 || *second < 0 ||
        *second > 59) {
        return std::nullopt;
    }
    static constexpr std::array<int, 12> days_per_month{
        31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const bool is_leap =
        (*year % 4 == 0) && (*year % 100 != 0 || *year % 400 == 0);
    const int max_day = days_per_month[static_cast<std::size_t>(*month - 1)] +
                        ((*month == 2 && is_leap) ? 1 : 0);
    if (*day < 1 || *day > max_day) {
        return std::nullopt;
    }

    std::size_t pos = 19;
    if (pos < text.size() && text[pos] == '.') {
        ++pos;
        if (pos >= text.size() || text[pos] < '0' || text[pos] > '9') {
            return std::nullopt;
        }
        while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') {
            ++pos;
        }
    }
    if (pos >= text.size()) {
        return std::nullopt;
    }

    std::int64_t tz_offset_seconds = 0;
    if (text[pos] == 'Z' || text[pos] == 'z') {
        if (pos + 1 != text.size()) {
            return std::nullopt;
        }
    } else if (text[pos] == '+' || text[pos] == '-') {
        const std::int64_t sign = text[pos] == '+' ? 1 : -1;
        ++pos;
        const auto tz_hour = parse_fixed_uint(text, pos, 2);
        if (!tz_hour || *tz_hour > 23) {
            return std::nullopt;
        }
        pos += 2;
        if (pos < text.size() && text[pos] == ':') {
            ++pos;
        }
        const auto tz_min = parse_fixed_uint(text, pos, 2);
        if (!tz_min || *tz_min > 59 || pos + 2 != text.size()) {
            return std::nullopt;
        }
        tz_offset_seconds =
            sign * (static_cast<std::int64_t>(*tz_hour) * 3600LL +
                    static_cast<std::int64_t>(*tz_min) * 60LL);
    } else {
        return std::nullopt;
    }

    std::int64_t civil_year = *year;
    const auto m = static_cast<unsigned>(*month);
    const auto d = static_cast<unsigned>(*day);
    civil_year -= m <= 2 ? 1 : 0;
    const std::int64_t era =
        (civil_year >= 0 ? civil_year : civil_year - 399) / 400;
    const auto yoe = static_cast<unsigned>(civil_year - era * 400);
    const unsigned doy =
        (153U * (m + (m > 2 ? static_cast<unsigned>(-3) : 9U)) + 2U) / 5U + d -
        1U;
    const unsigned doe = yoe * 365U + yoe / 4U - yoe / 100U + doy;
    const std::int64_t days =
        era * 146097LL + static_cast<std::int64_t>(doe) - 719468LL;
    const std::int64_t utc =
        days * 86400LL + static_cast<std::int64_t>(*hour) * 3600LL +
        static_cast<std::int64_t>(*minute) * 60LL +
        static_cast<std::int64_t>(*second) - tz_offset_seconds;
    return utc >= 0 ? std::optional<std::int64_t>{utc} : std::nullopt;
}

template <typename Fn>
std::expected<void, Error>
parse_list_entries_json(const nlohmann::json& response,
                        std::string_view remote_prefix,
                        Fn&& on_entry) {
    if (!response.is_object() || !response.contains("list") ||
        !response["list"].is_array()) {
        return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                          "invalid operations/list response"));
    }

    std::unordered_set<std::string> seen;
    for (const auto& item : response["list"]) {
        if (!item.is_object() || !item.contains("Path") ||
            !item["Path"].is_string()) {
            return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                              "invalid operations/list item"));
        }
        auto identifier = item["Path"].get<std::string>();
        if (!remote_prefix.empty()) {
            const auto prefix = std::string{remote_prefix} + "/";
            if (identifier.starts_with(prefix)) {
                identifier.erase(0, prefix.size());
            }
        }
        if (!valid_identifier(identifier)) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "operations/list returned invalid Path"));
        }
        if (!seen.insert(identifier).second) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "remote returned duplicate identifiers"));
        }
        on_entry(item, std::move(identifier));
    }
    return {};
}

ListingResult parse_list_response_json(const nlohmann::json& response,
                                       std::string_view remote_prefix = {}) {
    std::vector<std::string> identifiers;
    if (auto parsed = parse_list_entries_json(
            response,
            remote_prefix,
            [&](const nlohmann::json&, std::string identifier) {
                identifiers.push_back(std::move(identifier));
            });
        !parsed) {
        return std::unexpected(parsed.error());
    }
    std::ranges::sort(identifiers);
    return identifiers;
}

MetadataListingResult
parse_list_metadata_response_json(const nlohmann::json& response) {
    std::vector<ObjectMetadata> entries;
    if (auto parsed = parse_list_entries_json(
            response,
            {},
            [&](const nlohmann::json& item, std::string identifier) {
                ObjectMetadata meta{.identifier = std::move(identifier)};
                meta.size = nonnegative_integer(item, "Size");
                if (const auto mod = item.find("ModTime");
                    mod != item.end() && mod->is_string()) {
                    meta.modified_at_unix = parse_rfc3339_utc_seconds(
                        mod->get_ref<const std::string&>());
                }
                entries.push_back(std::move(meta));
            });
        !parsed) {
        return std::unexpected(parsed.error());
    }
    std::ranges::sort(entries, {}, &ObjectMetadata::identifier);
    return entries;
}

PresenceResult rclone_presence(void* context, std::string_view identifier) {
    auto state = require_ready(context, identifier);
    if (!state) {
        return std::unexpected(state.error());
    }

    const auto response = stat_remote(**state, identifier);
    if (!response) {
        if (not_found(response.error())) {
            return Presence::Absent;
        }
        return std::unexpected(response.error());
    }
    if (!response->is_object() || !response->contains("item")) {
        return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                          "invalid operations/stat response"));
    }
    return parse_stat_presence((*response)["item"],
                               "invalid operations/stat response",
                               "remote object is a directory");
}

std::expected<nlohmann::json, Error>
fetch_remote_listing_json(void* context,
                          std::optional<std::string_view> prefix,
                          bool include_mod_time) {
    auto state = require_ready(context);
    if (!state) {
        return std::unexpected(state.error());
    }
    if (prefix && !valid_identifier(*prefix)) {
        return std::unexpected(invalid_identifier_error());
    }
    const std::string_view effective_prefix =
        prefix.value_or(std::string_view{});
    nlohmann::json list_request{
        {"fs", rooted_remote_fs(**state)},
        {"remote", effective_prefix},
        {"opt", stat_opt(true, effective_prefix.empty(), !include_mod_time)},
    };
    if (effective_prefix.empty()) {
        list_request["_config"] = {{"FastList", true}};
    }
    const auto response = request_read_json(**state,
                                            "operations/list",
                                            list_request,
                                            maximum_list_response_size,
                                            control_read_deadline);
    if (!response) {
        if (not_found(response.error())) {
            return std::unexpected(
                make_error(ErrorCode::StorageNotFound,
                           "remote objects directory does not exist"));
        }
        return std::unexpected(response.error());
    }
    return *response;
}

ListingResult
list_remote_objects(void* context,
                    std::optional<std::string_view> prefix = std::nullopt) {
    const auto response = fetch_remote_listing_json(context, prefix, false);
    if (!response) {
        return std::unexpected(response.error());
    }
    return parse_list_response_json(*response,
                                    prefix.value_or(std::string_view{}));
}

ListingResult rclone_list(void* context) {
    return list_remote_objects(context);
}

MetadataListingResult rclone_list_metadata(void* context) {
    const auto response =
        fetch_remote_listing_json(context, std::nullopt, true);
    if (!response) {
        return std::unexpected(response.error());
    }
    return parse_list_metadata_response_json(*response);
}

ListingResult rclone_list_prefix(void* context, std::string_view prefix) {
    return list_remote_objects(context, prefix);
}

std::expected<std::string, Error> rclone_physical_hash(
    void* context, std::string_view identifier, std::string_view algorithm) {
    auto state = require_ready(context, identifier);
    if (!state) {
        return std::unexpected(state.error());
    }
    if (algorithm != "sha256" ||
        (*state)->sha256_unsupported.load(std::memory_order_relaxed)) {
        return std::unexpected(
            make_error(ErrorCode::Unsupported,
                       "rclone backend does not expose algorithm"));
    }

    const auto response =
        request_read_json(**state,
                          "operations/hashsumfile",
                          nlohmann::json{{"fs", rooted_remote_fs(**state)},
                                         {"remote", identifier},
                                         {"hashType", "SHA-256"}},
                          maximum_response_size,
                          control_read_deadline);
    if (!response) {
        if (response.error().code == ErrorCode::ProtocolFailure &&
            response.error().native_code == 404 &&
            response.error().message.find(
                "couldn't find method \"operations/hashsumfile\"") !=
                std::string::npos) {
            return std::unexpected(
                make_error(ErrorCode::Unsupported,
                           "rclone does not support operations/hashsumfile",
                           response.error().native_code));
        }
        if (not_found(response.error())) {
            return std::unexpected(make_error(ErrorCode::ObjectNotFound,
                                              "remote object does not exist"));
        }
        const bool hash_missing = unsupported_hash(response.error());
        if (hash_missing || response.error().code == ErrorCode::Unsupported ||
            response.error().native_code == 501) {
            if (hash_missing) {
                (*state)->sha256_unsupported.store(true,
                                                   std::memory_order_relaxed);
            }
            return std::unexpected(
                make_error(ErrorCode::Unsupported,
                           "rclone backend does not expose algorithm",
                           response.error().native_code));
        }
        return std::unexpected(response.error());
    }
    if (!response->is_object() || !response->contains("hash") ||
        !response->at("hash").is_string() || !response->contains("hashType") ||
        !response->at("hashType").is_string()) {
        return std::unexpected(
            make_error(ErrorCode::ProtocolFailure,
                       "rclone returned a malformed physical hash response"));
    }
    const auto returned_algorithm = response->at("hashType").get<std::string>();
    if (returned_algorithm != "sha256" && returned_algorithm != "SHA-256") {
        return std::unexpected(
            make_error(ErrorCode::ProtocolFailure,
                       "rclone returned a different physical hash algorithm"));
    }
    auto digest = response->at("hash").get<std::string>();
    if (!valid_sha256(digest)) {
        return std::unexpected(
            make_error(ErrorCode::ProtocolFailure,
                       "rclone returned a malformed SHA-256 digest"));
    }
    return ascii_lower(std::move(digest));
}

PhysicalHashBatchResult parse_physical_hash_batch_response_json(
    const nlohmann::json& response, const PhysicalHashBatchRequest& request) {
    if (!response.is_object() || !response.contains("success") ||
        !response.at("success").is_boolean() ||
        !response.contains("hashType") ||
        !response.at("hashType").is_string()) {
        return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                          "invalid operations/check response"));
    }

    if (ascii_lower(response.at("hashType").get<std::string>()) != "sha256") {
        return std::unexpected(
            make_error(ErrorCode::ProtocolFailure,
                       "operations/check returned unexpected algorithm"));
    }

    std::unordered_set<std::string> expected;
    for (const auto& object : request.objects) {
        if (!expected.insert(object.identifier).second) {
            return std::unexpected(
                make_error(ErrorCode::InvalidIdentifier,
                           "duplicate identifiers in physical hash request"));
        }
    }

    std::unordered_set<std::string> seen;
    PhysicalHashBatchReport report;
    for (const auto& [name, destination] :
         {std::pair{"match", &report.matched},
          std::pair{"differ", &report.mismatched},
          std::pair{"missingOnDst", &report.missing},
          std::pair{"error", &report.errors}}) {
        auto entries = check_entries(response, name, expected, seen);
        if (!entries) {
            return std::unexpected(entries.error());
        }
        *destination = std::move(*entries);
    }

    const bool success = response.at("success").get<bool>();
    const bool has_failures = !report.mismatched.empty() ||
                              !report.missing.empty() || !report.errors.empty();
    if (seen.size() != expected.size() ||
        (success &&
         (has_failures || report.matched.size() != expected.size())) ||
        (!success && !has_failures)) {
        return std::unexpected(
            make_error(ErrorCode::ProtocolFailure,
                       "inconsistent operations/check response"));
    }

    return report;
}

PhysicalHashBatchResult
rclone_physical_hash_batch(void* context,
                           const PhysicalHashBatchRequest& request) {
    auto state = require_ready(context);
    if (!state) {
        return std::unexpected(state.error());
    }
    if (ascii_lower(request.algorithm) != "sha256" ||
        (*state)->sha256_unsupported.load(std::memory_order_relaxed)) {
        return std::unexpected(
            make_error(ErrorCode::Unsupported,
                       "rclone backend does not expose algorithm for batch"));
    }

    std::unordered_set<std::string> identifiers;
    std::vector<PhysicalHashExpectation> expectations;
    expectations.reserve(request.objects.size());
    for (const auto& object : request.objects) {
        if (!valid_batch_identifier(object.identifier) ||
            !identifiers.insert(object.identifier).second) {
            return std::unexpected(invalid_identifier_error());
        }
        if (!valid_sha256(object.expected_hash)) {
            return std::unexpected(
                make_error(ErrorCode::InvalidIdentifier,
                           "expected hash is not valid SHA-256"));
        }
        expectations.push_back(object);
    }

    auto root = absolute_path(request.scratch_root);
    if (!root) {
        return std::unexpected(root.error());
    }
    std::error_code status_error;
    const auto root_status =
        std::filesystem::symlink_status(*root, status_error);
    if (status_error || !std::filesystem::is_directory(root_status) ||
        platform::private_storage::is_reparse_or_symlink(*root)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidContext,
                       "scratch_root is not a real local directory"));
    }

    std::ranges::sort(expectations, {}, &PhysicalHashExpectation::identifier);
    const auto nonce = platform::random::hex_id(8);
    if (!nonce) {
        return std::unexpected(make_error(ErrorCode::Io, nonce.error()));
    }
    auto scratch = platform::create_workspace_at(
        *root / (".kasumi-batch-verify-" + *nonce));
    if (!scratch) {
        return std::unexpected(make_error(ErrorCode::Io, scratch.error()));
    }
    struct ScratchCleanup {
        const platform::Workspace& workspace;
        ~ScratchCleanup() {
            platform::cleanup_workspace(workspace);
        }
    } cleanup{*scratch};
    const auto manifest = scratch->root / "manifest.sha256";
    const auto files = scratch->root / "files";

    {
        std::ofstream output(manifest, std::ios::binary);
        if (!output) {
            return std::unexpected(make_error(
                ErrorCode::Io, "failed to create verification manifest"));
        }
        std::ofstream file_list(files, std::ios::binary);
        if (!file_list) {
            return std::unexpected(make_error(
                ErrorCode::Io, "failed to create verification file list"));
        }
        for (const auto& object : expectations) {
            output << object.expected_hash << "  " << object.identifier << '\n';
            file_list << object.identifier << '\n';
        }
        output.close();
        file_list.close();
        if (!output || !file_list) {
            return std::unexpected(make_error(
                ErrorCode::Io,
                "failed to write verification manifest or file list"));
        }
    }

    const auto manifest_parent = platform::path::to_utf8(scratch->root);
    const auto response = request_read_json(
        **state,
        "operations/check",
        nlohmann::json{
            {"dstFs", rooted_remote_fs(**state)},
            {"checkFileHash", "SHA-256"},
            {"checkFileFs", manifest_parent},
            {"checkFileRemote", platform::path::to_utf8(manifest.filename())},
            {"oneWay", true},
            {"missingOnSrc", false},
            {"missingOnDst", true},
            {"match", true},
            {"differ", true},
            {"error", true},
            {"_config", {{"NoTraverse", true}}},
            // Restrict names: oneWay alone still scans the remote.
            {"_filter", {{"FilesFromRaw", {platform::path::to_utf8(files)}}}},
        },
        maximum_check_response_size,
        transfer_timeout);
    if (!response) {
        const bool hash_missing = unsupported_hash(response.error());
        if (unsupported_endpoint(response.error(), "operations/check") ||
            hash_missing || response.error().code == ErrorCode::Unsupported ||
            response.error().native_code == 501) {
            if (hash_missing) {
                (*state)->sha256_unsupported.store(true,
                                                   std::memory_order_relaxed);
            }
            return std::unexpected(
                make_error(ErrorCode::Unsupported,
                           "rclone does not support operations/check",
                           response.error().native_code));
        }
        return std::unexpected(response.error());
    }

    if (auto removed = platform::remove_workspace(*scratch); !removed) {
        return std::unexpected(make_error(ErrorCode::Io, removed.error()));
    }
    scratch->root.clear();

    return parse_physical_hash_batch_response_json(*response, request);
}

struct JobBatchItemStatus {
    int status{200};
    bool has_error{false};
    std::string error_message;
};

bool is_job_batch_item_not_found(const JobBatchItemStatus& item) noexcept {
    return item.status == 404 ||
           (item.status == 500 && missing_object(item.error_message));
}

std::expected<JobBatchItemStatus, Error>
parse_job_batch_item_status(const nlohmann::json& item,
                            std::string_view operation_name,
                            bool require_nonempty_error_with_status) {
    JobBatchItemStatus parsed;
    if (item.contains("status")) {
        auto parsed_status =
            parse_job_batch_status(item.at("status"), operation_name);
        if (!parsed_status) {
            return std::unexpected(parsed_status.error());
        }
        parsed.status = *parsed_status;
    }
    if (item.contains("error")) {
        if (!item.at("error").is_string()) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           require_nonempty_error_with_status
                               ? "invalid job/batch subcommand error"
                               : "invalid remove job/batch error result"));
        }
        parsed.has_error = true;
        parsed.error_message = item.at("error").get<std::string>();
        if (require_nonempty_error_with_status &&
            (parsed.error_message.empty() || !item.contains("status"))) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "invalid job/batch subcommand error"));
        }
    }
    return parsed;
}

ControlReadBatchResponse
parse_control_read_batch_response_json(const nlohmann::json& response,
                                       const ControlReadBatchRequest& request) {
    const auto expected_size =
        request.list_prefixes.size() + request.presence_identifiers.size();
    if (!response.is_object() || !response.contains("results") ||
        !response.at("results").is_array() ||
        response.at("results").size() != expected_size) {
        return std::unexpected(make_error(
            ErrorCode::ProtocolFailure, "invalid control job/batch response"));
    }

    const auto missing =
        [](const nlohmann::json& item) -> std::expected<bool, Error> {
        if (!item.is_object()) {
            return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                              "invalid job/batch result"));
        }
        const auto parsed = parse_job_batch_item_status(item, "control", true);
        if (!parsed) {
            return std::unexpected(parsed.error());
        }
        if (parsed->status >= 500) {
            return std::unexpected(make_error(ErrorCode::BackendUnavailable,
                                              "job/batch subcommand failed",
                                              parsed->status));
        }
        if (parsed->has_error) {
            if (parsed->status == 404) {
                return true;
            }
            return std::unexpected(make_error(
                ErrorCode::ProtocolFailure,
                "job/batch subcommand failed; remote detail omitted"));
        }
        if (parsed->status < 200 || parsed->status >= 300) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "job/batch subcommand status indicates failure"));
        }
        return false;
    };

    ControlReadBatchResult result;
    result.listings.reserve(request.list_prefixes.size());
    result.presences.reserve(request.presence_identifiers.size());
    for (std::size_t index = 0; index < request.list_prefixes.size(); ++index) {
        const auto& item = response.at("results").at(index);
        auto absent = missing(item);
        if (!absent) {
            return std::unexpected(absent.error());
        }
        if (*absent) {
            if (item.contains("list") &&
                (!item.at("list").is_array() || !item.at("list").empty())) {
                return std::unexpected(
                    make_error(ErrorCode::ProtocolFailure,
                               "contradictory 404 job/batch result"));
            }
            result.listings.emplace_back();
            continue;
        }
        auto listing =
            parse_list_response_json(item, request.list_prefixes[index]);
        if (!listing) {
            return std::unexpected(listing.error());
        }
        result.listings.push_back(std::move(*listing));
    }

    for (std::size_t offset = 0; offset < request.presence_identifiers.size();
         ++offset) {
        const auto& item =
            response.at("results").at(request.list_prefixes.size() + offset);
        const auto& expected_identifier = request.presence_identifiers[offset];

        if (item.contains("input") && item.at("input").is_object() &&
            item.at("input").contains("remote") &&
            item.at("input").at("remote").is_string() &&
            item.at("input").at("remote").get_ref<const std::string&>() !=
                expected_identifier) {
            return std::unexpected(make_error(
                ErrorCode::ProtocolFailure,
                "job/batch result input does not match expected position"));
        }

        auto absent = missing(item);
        if (!absent) {
            return std::unexpected(absent.error());
        }
        if (*absent) {
            if (item.contains("item") && !item.at("item").is_null()) {
                return std::unexpected(
                    make_error(ErrorCode::ProtocolFailure,
                               "contradictory 404 job/batch result"));
            }
            result.presences.push_back(Presence::Absent);
            continue;
        }
        if (!item.contains("item")) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "invalid operations/stat response in job/batch"));
        }
        auto presence =
            parse_stat_presence(item.at("item"),
                                "invalid operations/stat response in job/batch",
                                "remote control object is a directory");
        if (!presence) {
            return std::unexpected(presence.error());
        }
        result.presences.push_back(*presence);
    }
    return result;
}

ControlReadBatchResponse
execute_single_control_read_batch(State& state,
                                  const ControlReadBatchRequest& request,
                                  std::size_t concurrency) {
    nlohmann::json inputs = nlohmann::json::array();
    for (const auto& prefix : request.list_prefixes) {
        inputs.push_back(nlohmann::json{{"_path", "operations/list"},
                                        {"fs", rooted_remote_fs(state)},
                                        {"remote", prefix},
                                        {"opt", stat_opt(true, false)}});
    }
    for (const auto& identifier : request.presence_identifiers) {
        inputs.push_back(nlohmann::json{{"_path", "operations/stat"},
                                        {"fs", rooted_remote_fs(state)},
                                        {"remote", identifier},
                                        {"opt", stat_opt(true)}});
    }

    const auto response = run_job_batch(state,
                                        inputs,
                                        concurrency,
                                        maximum_list_response_size,
                                        control_read_deadline,
                                        true);
    if (!response) {
        return std::unexpected(response.error());
    }
    return parse_control_read_batch_response_json(*response, request);
}

ControlReadBatchResponse
rclone_control_read_batch(void* context,
                          const ControlReadBatchRequest& request) {
    auto state = require_ready(context);
    if (!state) {
        return std::unexpected(state.error());
    }

    constexpr std::size_t control_presence_concurrency = 8;
    constexpr std::size_t max_presence_batch_chunk_size = 128;

    // Admission depends on the ordering LIST writers -> STAT barrier;
    // rclone executes inputs sequentially when concurrency <= 1.
    if (!request.list_prefixes.empty() &&
        request.presence_identifiers.size() <= max_presence_batch_chunk_size) {
        return execute_single_control_read_batch(**state, request, 1);
    }

    if (request.list_prefixes.empty() && request.presence_identifiers.empty()) {
        return ControlReadBatchResult{};
    }

    ControlReadBatchResult aggregated;
    if (!request.list_prefixes.empty()) {
        ControlReadBatchRequest list_req;
        list_req.list_prefixes = request.list_prefixes;
        auto list_res = execute_single_control_read_batch(**state, list_req, 1);
        if (!list_res) {
            return std::unexpected(list_res.error());
        }
        aggregated.listings = std::move(list_res->listings);
    }
    aggregated.presences.reserve(request.presence_identifiers.size());

    for (std::size_t offset = 0; offset < request.presence_identifiers.size();
         offset += max_presence_batch_chunk_size) {
        const auto count =
            std::min(max_presence_batch_chunk_size,
                     request.presence_identifiers.size() - offset);
        ControlReadBatchRequest chunk_req;
        chunk_req.presence_identifiers.assign(
            request.presence_identifiers.begin() +
                static_cast<std::ptrdiff_t>(offset),
            request.presence_identifiers.begin() +
                static_cast<std::ptrdiff_t>(offset + count));

        auto chunk_res = execute_single_control_read_batch(
            **state, chunk_req, control_presence_concurrency);
        if (!chunk_res) {
            return std::unexpected(chunk_res.error());
        }
        aggregated.presences.insert(aggregated.presences.end(),
                                    chunk_res->presences.begin(),
                                    chunk_res->presences.end());
    }

    return aggregated;
}

RemovalResult rclone_remove(void* context, std::string_view identifier) {
    auto state = require_ready(context, identifier);
    if (!state) {
        return std::unexpected(state.error());
    }

    const auto deleted =
        request_json(**state,
                     "operations/deletefile",
                     nlohmann::json{{"fs", rooted_remote_fs(**state)},
                                    {"remote", std::string{identifier}}},
                     maximum_response_size,
                     remove_timeout);
    if (!deleted) {
        if (not_found(deleted.error())) {
            return Removal::AlreadyAbsent;
        }
        return std::unexpected(deleted.error());
    }
    return Removal::Removed;
}

RemoveBatchResult rclone_remove_batch(void* context, const RemoveBatch& batch) {
    auto state = require_ready(context);
    if (!state) {
        return std::unexpected(state.error());
    }
    if (batch.items.empty()) {
        return RemoveBatchReport{};
    }
    if (batch.concurrency == 0) {
        return std::unexpected(
            make_error(ErrorCode::InvalidContext,
                       "remove batch concurrency must be positive"));
    }

    nlohmann::json all_inputs = nlohmann::json::array();
    std::unordered_map<std::string, std::size_t> remote_to_index;
    remote_to_index.reserve(batch.items.size());
    for (std::size_t index = 0; index < batch.items.size(); ++index) {
        const auto& identifier = batch.items[index].identifier;
        if (!valid_identifier(identifier) ||
            !remote_to_index.emplace(std::string{identifier}, index).second) {
            return std::unexpected(invalid_identifier_error());
        }
        all_inputs.push_back(nlohmann::json{
            {"_path", "operations/deletefile"},
            {"fs", rooted_remote_fs(**state)},
            {"remote", identifier},
        });
    }

    constexpr std::size_t maximum_remove_response_size = 1024U * 1024U;
    std::vector<std::size_t> response_cost;
    response_cost.reserve(all_inputs.size());
    for (const auto& entry : all_inputs) {
        // rclone echoes the whole input and adds the result and error fields.
        const auto bytes = entry.dump().size() + 512U;
        if (bytes > maximum_remove_response_size - 64U) {
            return std::unexpected(invalid_identifier_error());
        }
        response_cost.push_back(bytes);
    }
    RemoveBatchReport report;
    report.items.resize(batch.items.size());
    for (std::size_t index = 0; index < batch.items.size(); ++index) {
        report.items[index].identifier = batch.items[index].identifier;
    }

    std::vector<bool> matched(batch.items.size(), false);
    const auto uncertain_report = [](std::string message) {
        return std::unexpected(
            make_error(ErrorCode::BackendUnavailable, std::move(message)));
    };
    std::size_t chunk_begin = 0;
    while (chunk_begin < batch.items.size()) {
        nlohmann::json chunk_inputs = nlohmann::json::array();
        std::size_t chunk_bytes = 64;
        std::size_t chunk_end = chunk_begin;
        while (chunk_end < batch.items.size()) {
            const auto& entry = all_inputs[chunk_end];
            const auto entry_bytes = response_cost[chunk_end];
            if (!chunk_inputs.empty() &&
                chunk_bytes + entry_bytes > maximum_response_size) {
                break;
            }
            chunk_inputs.push_back(entry);
            chunk_bytes += entry_bytes;
            ++chunk_end;
        }
        const std::size_t chunk_count = chunk_end - chunk_begin;
        const auto response = run_job_batch(**state,
                                            chunk_inputs,
                                            batch.concurrency,
                                            maximum_remove_response_size,
                                            transfer_timeout,
                                            false);
        if (!response) {
            if (chunk_begin != 0 &&
                !mutation_result_is_ambiguous(response.error())) {
                return uncertain_report(response.error().message);
            }
            return std::unexpected(response.error());
        }
        if (!response->is_object() || response->contains("error") ||
            !response->contains("results") ||
            !response->at("results").is_array() ||
            response->at("results").size() != chunk_count) {
            return uncertain_report(
                "invalid or incomplete remove job/batch response");
        }

        for (std::size_t local_idx = 0; local_idx < chunk_count; ++local_idx) {
            const auto& result = response->at("results").at(local_idx);
            if (!result.is_object()) {
                return uncertain_report("invalid remove job/batch subresult");
            }
            if (result.contains("path") &&
                (!result.at("path").is_string() ||
                 result.at("path") != "operations/deletefile")) {
                return uncertain_report(
                    "remove job/batch result path does not match input");
            }

            std::size_t target_index = chunk_begin + local_idx;
            if (result.contains("input")) {
                const auto& input_echo = result.at("input");
                if (!input_echo.is_object() || !input_echo.contains("remote") ||
                    !input_echo.at("remote").is_string()) {
                    return uncertain_report(
                        "remove job/batch result input does not match request");
                }
                const auto remote_echo =
                    input_echo.at("remote").get<std::string>();
                auto it = remote_to_index.find(remote_echo);
                if (it == remote_to_index.end() || it->second < chunk_begin ||
                    it->second >= chunk_end) {
                    return uncertain_report(
                        "unknown identifier in remove job/batch result");
                }
                target_index = it->second;
            }

            if (matched[target_index]) {
                return uncertain_report(
                    "duplicate item in remove job/batch response");
            }
            matched[target_index] = true;

            const auto parsed =
                parse_job_batch_item_status(result, "remove", false);
            if (!parsed) {
                return uncertain_report(parsed.error().message);
            }
            if (is_job_batch_item_not_found(*parsed)) {
                report.items[target_index].result = Removal::AlreadyAbsent;
            } else if (parsed->status >= 200 && parsed->status < 300 &&
                       !parsed->has_error) {
                report.items[target_index].result = Removal::Removed;
            } else {
                report.items[target_index].result = std::unexpected(make_error(
                    parsed->status >= 500 ? ErrorCode::BackendUnavailable
                                          : ErrorCode::ProtocolFailure,
                    rc_error_detail(
                        **state, parsed->error_message, "remote remove failed"),
                    parsed->status));
            }
        }
        chunk_begin = chunk_end;
    }

    for (bool m : matched) {
        if (!m) {
            return uncertain_report(
                "missing item in remove job/batch response");
        }
    }

    return report;
}

template <typename Fn>
auto parse_json_response(std::string_view response_body,
                         std::string_view error_message,
                         Fn fn) {
    try {
        return fn(nlohmann::json::parse(response_body));
    } catch (const std::exception&) {
        return decltype(fn(nlohmann::json{})){std::unexpected(make_error(
            ErrorCode::ProtocolFailure, std::string{error_message}))};
    }
}

} // namespace

ControlReadBatchResponse
parse_control_read_batch_response(std::string_view response_body,
                                  const ControlReadBatchRequest& request) {
    return parse_json_response(
        response_body,
        "invalid control job/batch response",
        [&](const auto& j) {
            return parse_control_read_batch_response_json(j, request);
        });
}

PhysicalHashBatchResult
parse_physical_hash_batch_response(std::string_view response_body,
                                   const PhysicalHashBatchRequest& request) {
    return parse_json_response(
        response_body, "invalid operations/check response", [&](const auto& j) {
            return parse_physical_hash_batch_response_json(j, request);
        });
}

ListingResult parse_list_response(std::string_view response_body) {
    return parse_json_response(
        response_body, "invalid operations/list response", [](const auto& j) {
            return parse_list_response_json(j);
        });
}

MetadataListingResult
parse_list_metadata_response(std::string_view response_body) {
    return parse_json_response(response_body,
                               "invalid operations/list metadata response",
                               [](const auto& j) {
                                   return parse_list_metadata_response_json(j);
                               });
}

namespace {

Result rclone_health_check(void* context) {
    auto state = require_ready(context);
    if (!state) {
        return std::unexpected(state.error());
    }
    return check_rc_health(**state);
}

} // namespace

StorageOperations make_storage_operations() noexcept {
    return StorageOperations{
        .initialize = rclone_initialize,
        .put = rclone_put,
        .put_batch = rclone_put_batch,
        .get = rclone_get,
        .get_batch = rclone_get_batch,
        .presence = rclone_presence,
        .list = rclone_list,
        .list_metadata = rclone_list_metadata,
        .list_prefix = rclone_list_prefix,
        .physical_hash = rclone_physical_hash,
        .physical_hash_batch = rclone_physical_hash_batch,
        .control_read_batch = rclone_control_read_batch,
        .remove = rclone_remove,
        .remove_batch = rclone_remove_batch,
        .health_check = rclone_health_check,
        .physical_hash_batch_min_objects = 6,
        .put_with_progress = rclone_put_progress,
        .get_with_progress = rclone_get_progress,
    };
}

} // namespace kasumi::transport::rclone_detail
