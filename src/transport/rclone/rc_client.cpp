#include "detail.hpp"
#include "platform/cancellation.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <format>
#include <httplib.h>
#include <limits>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace kasumi::transport::rclone_detail {
namespace {

constexpr std::size_t maximum_response_size = 64 * 1024;
constexpr std::size_t maximum_rc_payload_size = 64U * 1024U * 1024U;
constexpr auto default_read_timeout = std::chrono::seconds{5};
constexpr auto read_retry_delay = std::chrono::milliseconds{75};
constexpr int maximum_read_attempts = 2;

std::chrono::milliseconds artificial_latency() noexcept {
    static const auto value = [] {
        const char* setting = std::getenv("KASUMI_PERF_RC_DELAY_MS");
        unsigned milliseconds = 0;
        if (setting == nullptr) {
            return std::chrono::milliseconds{0};
        }
        const std::string_view text{setting};
        const auto parsed = std::from_chars(
            text.data(), text.data() + text.size(), milliseconds);
        return parsed.ec == std::errc{} &&
                       parsed.ptr == text.data() + text.size() &&
                       milliseconds <= 10'000
                   ? std::chrono::milliseconds{milliseconds}
                   : std::chrono::milliseconds{0};
    }();
    return value;
}

using detail::make_error;

std::expected<std::string, Error>
post_rc_impl(State& state,
             std::string_view endpoint,
             std::string_view request_body,
             std::size_t response_limit,
             std::chrono::milliseconds read_timeout,
             int attempt,
             int attempts);

Error with_request_context(const State& state,
                           Error error,
                           std::string_view endpoint,
                           std::chrono::steady_clock::time_point started,
                           int attempt,
                           int attempts) {
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);
    error.message = std::format(
        "endpoint={}, duration={} ms, RC attempt={}/{}, rclone={}: {}",
        endpoint,
        elapsed.count(),
        attempt,
        attempts,
        platform::path::to_utf8(state.configuration.executable),
        error.message);
    return error;
}

bool drain_finished(const State& state) {
    return state.drain_future.valid() &&
           state.drain_future.wait_for(std::chrono::milliseconds(0)) ==
               std::future_status::ready;
}

std::expected<std::string, Error>
post_rc_impl(State& state,
             std::string_view path_suffix,
             std::string_view request_body,
             std::size_t response_limit,
             std::chrono::milliseconds read_timeout,
             int attempt,
             int attempts) {
    if (path_suffix.empty() || path_suffix.front() == '/' ||
        path_suffix.find("..") != std::string_view::npos ||
        path_suffix.find_first_of("?#") != std::string_view::npos) {
        return std::unexpected(
            make_error(ErrorCode::ProtocolFailure, "invalid RC endpoint"));
    }
    const std::string path = state.base_url + "/" + std::string{path_suffix};
    httplib::Client client("127.0.0.1", state.port);
    client.set_basic_auth(state.username, state.password);
    client.set_connection_timeout(std::chrono::seconds(1));
    client.set_read_timeout(read_timeout);
    client.set_write_timeout(std::chrono::seconds(5));
    client.set_follow_location(false);
    client.set_payload_max_length(maximum_rc_payload_size);
    std::this_thread::sleep_for(artificial_latency());
    const auto started = std::chrono::steady_clock::now();
    std::mutex watcher_mutex;
    std::condition_variable watcher_wakeup;
    std::jthread watcher([&](std::stop_token stop) {
        std::stop_callback wake_on_stop(stop, [&] {
            watcher_wakeup.notify_all();
        });
        std::unique_lock watcher_lock(watcher_mutex);
        bool reported = false;
        while (!stop.stop_requested()) {
            if (platform::cancellation::requested()) {
                client.stop();
                return;
            }
            if (!reported && state.report_status &&
                std::chrono::steady_clock::now() - started >=
                    std::chrono::seconds{1}) {
                const auto operation = path_suffix == "operations/list"
                                           ? "remote LIST"
                                           : "remote response";
                state.report_status(std::format(
                    "[Network] waiting for {} (RC attempt {}/{}, endpoint={})",
                    operation,
                    attempt,
                    attempts,
                    path_suffix));
                reported = true;
            }
            watcher_wakeup.wait_for(watcher_lock,
                                    std::chrono::milliseconds{50});
        }
    });
    const auto trace = platform::perf_trace::begin();
    const auto response =
        client.Post(path, std::string{request_body}, "application/json");
    watcher.request_stop();
    if (trace.active) {
        platform::perf_trace::finish(
            std::string{"rc/"} + std::string{path_suffix}, trace);
    }
    if (platform::cancellation::requested()) {
        return std::unexpected(
            make_error(ErrorCode::Cancelled, "operation cancelled by user"));
    }
    if (!response) {
        return std::unexpected(
            make_error(ErrorCode::Io,
                       std::string{"RC HTTP failure: "} +
                           httplib::to_string(response.error()),
                       static_cast<int>(response.error())));
    }
    if (response->body.size() > response_limit) {
        return std::unexpected(make_error(
            ErrorCode::ProtocolFailure,
            "RC response exceeds limit",
            static_cast<int>(std::min(
                response->body.size(),
                static_cast<std::size_t>((std::numeric_limits<int>::max)())))));
    }
    if (response->status == 401 || response->status == 403) {
        return std::unexpected(make_error(ErrorCode::PermissionDenied,
                                          "RC authentication rejected",
                                          response->status));
    }
    if (response->status < 200 || response->status >= 300) {
        std::string detail = "unexpected RC HTTP status; body omitted";
        try {
            const auto json = nlohmann::json::parse(response->body);
            if (json.contains("error") && json["error"].is_string()) {
                detail = json["error"].get<std::string>();
            }
        } catch (...) {
        }
        return std::unexpected(
            make_error(ErrorCode::ProtocolFailure, detail, response->status));
    }
    return response->body;
}

bool transient_read_failure(const Error& error) noexcept {
    return error.code == ErrorCode::Io || error.code == ErrorCode::Timeout;
}

std::expected<void, Error> validate_rc_handshake(State& state, int child_pid) {
    const auto response = post_rc(
        state, "core/pid", "{}", maximum_response_size, default_read_timeout);
    if (!response) {
        return std::unexpected(response.error());
    }
    try {
        const auto json = nlohmann::json::parse(*response);
        if (!json.is_object() || !json.contains("pid") ||
            !json["pid"].is_number_integer() || json["pid"] <= 0) {
            return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                              "invalid core/pid response"));
        }
        if (json["pid"] != child_pid) {
            return std::unexpected(
                make_error(ErrorCode::ProtocolFailure,
                           "RC PID does not match started process"));
        }
    } catch (const std::exception&) {
        return std::unexpected(make_error(
            ErrorCode::ProtocolFailure, "invalid core/pid JSON; body omitted"));
    }
    return {};
}

std::expected<void, Error> wait_for_rc_readiness(State& state, int child_pid) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (std::chrono::steady_clock::now() < deadline) {
        if (drain_finished(state)) {
            return std::unexpected(
                make_error(ErrorCode::ProcessFailure,
                           "rclone process drain finished during startup"));
        }
        const auto handshake = validate_rc_handshake(state, child_pid);
        if (handshake) {
            return {};
        }
        if (handshake.error().code == ErrorCode::PermissionDenied ||
            handshake.error().code == ErrorCode::ProtocolFailure ||
            handshake.error().code == ErrorCode::Cancelled) {
            return std::unexpected(handshake.error());
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(75));
    }
    return std::unexpected(make_error(
        ErrorCode::Timeout, "timed out waiting for rclone readiness"));
}

} // namespace

std::expected<std::string, Error>
post_rc(State& state,
        std::string_view endpoint,
        std::string_view request_body,
        std::size_t response_limit,
        std::chrono::milliseconds read_timeout) {
    const auto started = std::chrono::steady_clock::now();
    auto result = post_rc_impl(
        state, endpoint, request_body, response_limit, read_timeout, 1, 1);
    if (!result) {
        return std::unexpected(with_request_context(
            state, std::move(result.error()), endpoint, started, 1, 1));
    }
    return result;
}

std::expected<std::string, Error>
post_rc_read_only(State& state,
                  std::string_view endpoint,
                  std::string_view request_body,
                  std::size_t response_limit,
                  std::chrono::milliseconds deadline) {
    const auto started = std::chrono::steady_clock::now();
    const auto expires_at = std::chrono::steady_clock::now() + deadline;
    Error last_error;
    for (int attempt = 0; attempt < maximum_read_attempts; ++attempt) {
        const auto contextualize = [&](Error err) {
            return with_request_context(state,
                                        std::move(err),
                                        endpoint,
                                        started,
                                        attempt + 1,
                                        maximum_read_attempts);
        };
        if (platform::cancellation::requested()) {
            return std::unexpected(contextualize(make_error(
                ErrorCode::Cancelled, "operation cancelled by user")));
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= expires_at) {
            return std::unexpected(contextualize(
                make_error(ErrorCode::Timeout, "RC read deadline exceeded")));
        }
        const auto remaining =
            std::max(std::chrono::milliseconds{1},
                     std::chrono::duration_cast<std::chrono::milliseconds>(
                         expires_at - now));
        auto result = post_rc_impl(state,
                                   endpoint,
                                   request_body,
                                   response_limit,
                                   remaining,
                                   attempt + 1,
                                   maximum_read_attempts);
        if (!result) {
            result = std::unexpected(contextualize(std::move(result.error())));
        }
        if (result || !transient_read_failure(result.error())) {
            return result;
        }
        last_error = std::move(result.error());
        if (attempt + 1 == maximum_read_attempts) {
            break;
        }
        const auto retry_at = std::chrono::steady_clock::now();
        if (retry_at + read_retry_delay >= expires_at) {
            return std::unexpected(contextualize(
                make_error(ErrorCode::Timeout, "RC read deadline exceeded")));
        }
        std::this_thread::sleep_for(read_retry_delay);
    }
    return std::unexpected(std::move(last_error));
}

std::expected<void, Error> establish_rc_connection(State& state,
                                                   int child_pid) {
    const auto ready = wait_for_rc_readiness(state, child_pid);
    if (!ready) {
        return std::unexpected(ready.error());
    }
    state.ready = true;
    return {};
}

bool request_core_quit_best_effort(State& state) noexcept {
    if (!state.ready) {
        return false;
    }
    bool acknowledged = false;
    try {
        acknowledged = post_rc(state,
                               "core/quit",
                               "{}",
                               maximum_response_size,
                               default_read_timeout)
                           .has_value();
    } catch (...) {
    }
    state.ready = false;
    return acknowledged;
}

} // namespace kasumi::transport::rclone_detail
