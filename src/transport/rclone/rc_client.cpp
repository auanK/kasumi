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
#ifndef CPPHTTPLIB_EXPECT_100_THRESHOLD
#define CPPHTTPLIB_EXPECT_100_THRESHOLD (64U * 1024U * 1024U)
#endif
#include <httplib.h>
#include <limits>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace kasumi::transport::rclone_detail {
namespace {

constexpr std::size_t maximum_response_size = 64 * 1024;
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
             int attempts,
             bool honour_cancellation = true);

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

constexpr std::size_t maximum_pooled_clients = 16;
constexpr auto idle_client_ttl = std::chrono::seconds{20};

struct PooledClient {
    std::unique_ptr<httplib::Client> client;
    std::chrono::steady_clock::time_point last_used{};
};

struct InFlightRequest {
    httplib::Client* client = nullptr;
    std::chrono::steady_clock::time_point started{};
    std::string endpoint;
    int attempt = 1;
    int attempts = 1;
    std::function<void(std::string_view)> report_status;
    bool reported = false;
};

} // namespace

std::string rc_error_detail(const State& state,
                            std::string_view message,
                            std::string_view fallback) {
    const auto contains = [&](std::string_view secret) {
        return !secret.empty() && message.contains(secret);
    };
    if (message.empty() || message.size() > 2048 || contains(state.username) ||
        contains(state.password) || contains(state.base_url) ||
        contains("KASUMI_") || contains("access_token") ||
        contains("refresh_token") || contains("Authorization:")) {
        return std::string{fallback};
    }
    std::string cleaned{message};
    std::ranges::replace_if(
        cleaned,
        [](unsigned char byte) {
            return byte < 0x20 || byte == 0x7f;
        },
        ' ');
    return cleaned;
}

struct RcRuntime {
    std::mutex pool_mutex;
    std::vector<PooledClient> idle_clients;
    std::mutex watcher_mutex;
    std::condition_variable watcher_cv;
    std::vector<InFlightRequest*> active_requests;
    bool stop_watcher = false;
    std::jthread watcher_thread;
};

namespace {

void watcher_loop(RcRuntime& runtime) {
    std::unique_lock lock(runtime.watcher_mutex);
    while (!runtime.stop_watcher) {
        if (runtime.active_requests.empty()) {
            runtime.watcher_cv.wait(lock, [&] {
                return runtime.stop_watcher || !runtime.active_requests.empty();
            });
            continue;
        }
        if (platform::cancellation::requested()) {
            for (auto* request : runtime.active_requests) {
                if (request->client != nullptr) {
                    request->client->stop();
                }
            }
            runtime.watcher_cv.wait_for(lock, std::chrono::milliseconds{25});
            continue;
        }
        const auto now = std::chrono::steady_clock::now();
        struct PendingNotice {
            std::function<void(std::string_view)> callback;
            std::string message;
        };
        std::vector<PendingNotice> notices;
        for (auto* request : runtime.active_requests) {
            if (!request->reported && request->report_status &&
                now - request->started >= std::chrono::seconds{1}) {
                const auto operation = request->endpoint == "operations/list"
                                           ? "remote LIST"
                                           : "remote response";
                notices.push_back(PendingNotice{
                    .callback = request->report_status,
                    .message = std::format(
                        "[Network] waiting for {} (RC attempt {}/{}, endpoint={})",
                        operation,
                        request->attempt,
                        request->attempts,
                        request->endpoint),
                });
                request->reported = true;
            }
        }
        if (!notices.empty()) {
            lock.unlock();
            for (const auto& notice : notices) {
                notice.callback(notice.message);
            }
            lock.lock();
            continue;
        }
        runtime.watcher_cv.wait_for(lock, std::chrono::milliseconds{50});
    }
}

RcRuntime& ensure_rc_runtime(State& state) {
    std::call_once(state.rc_runtime_once, [&] {
        auto runtime = std::make_unique<RcRuntime>();
        auto* raw = runtime.get();
        runtime->watcher_thread = std::jthread([raw] {
            watcher_loop(*raw);
        });
        state.rc_runtime.reset(runtime.release());
    });
    return *state.rc_runtime;
}

std::unique_ptr<httplib::Client> acquire_client(State& state,
                                                RcRuntime& runtime) {
    const auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard lock(runtime.pool_mutex);
        while (!runtime.idle_clients.empty()) {
            auto entry = std::move(runtime.idle_clients.back());
            runtime.idle_clients.pop_back();
            if (entry.client &&
                now - entry.last_used < idle_client_ttl &&
                entry.client->is_socket_open()) {
                return std::move(entry.client);
            }
        }
    }
    auto client = std::make_unique<httplib::Client>("127.0.0.1", state.port);
    client->set_basic_auth(state.username, state.password);
    client->set_connection_timeout(std::chrono::seconds(1));
    client->set_write_timeout(std::chrono::seconds(5));
    client->set_follow_location(false);
    client->set_keep_alive(true);
    client->set_tcp_nodelay(true);
    return client;
}

void release_client(RcRuntime& runtime,
                    std::unique_ptr<httplib::Client> client) {
    if (!client || !client->is_socket_open()) {
        return;
    }
    std::lock_guard lock(runtime.pool_mutex);
    if (runtime.idle_clients.size() < maximum_pooled_clients) {
        runtime.idle_clients.push_back(PooledClient{
            .client = std::move(client),
            .last_used = std::chrono::steady_clock::now(),
        });
    }
}

} // namespace

void destroy_rc_runtime(RcRuntime* runtime) noexcept {
    if (runtime == nullptr) {
        return;
    }
    {
        std::lock_guard lock(runtime->watcher_mutex);
        runtime->stop_watcher = true;
        for (auto* request : runtime->active_requests) {
            if (request->client != nullptr) {
                request->client->stop();
            }
        }
    }
    runtime->watcher_cv.notify_all();
    runtime->watcher_thread = std::jthread{};
    {
        std::lock_guard lock(runtime->pool_mutex);
        runtime->idle_clients.clear();
    }
    delete runtime;
}

void stop_rc_runtime(State& state) noexcept {
    state.rc_runtime.reset();
}

namespace {

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
             int attempts,
             bool honour_cancellation) {
    if (path_suffix.empty() || path_suffix.front() == '/' ||
        path_suffix.find("..") != std::string_view::npos ||
        path_suffix.find_first_of("?#") != std::string_view::npos) {
        return std::unexpected(
            make_error(ErrorCode::ProtocolFailure, "invalid RC endpoint"));
    }
    const std::string path = state.base_url + "/" + std::string{path_suffix};
    auto& runtime = ensure_rc_runtime(state);
    auto client = acquire_client(state, runtime);
    client->set_read_timeout(read_timeout);
    std::this_thread::sleep_for(artificial_latency());
    const auto started = std::chrono::steady_clock::now();
    InFlightRequest in_flight{
        .client = client.get(),
        .started = started,
        .endpoint = std::string{path_suffix},
        .attempt = attempt,
        .attempts = attempts,
        .report_status = state.report_status,
    };
    if (honour_cancellation) {
        std::lock_guard lock(runtime.watcher_mutex);
        runtime.active_requests.push_back(&in_flight);
    }
    runtime.watcher_cv.notify_one();

    struct RequestGuard {
        RcRuntime& runtime;
        InFlightRequest* entry;
        void unregister() noexcept {
            if (entry != nullptr) {
                std::lock_guard lock(runtime.watcher_mutex);
                std::erase(runtime.active_requests, entry);
                entry = nullptr;
            }
        }
        ~RequestGuard() noexcept {
            unregister();
        }
    } request_guard{runtime, honour_cancellation ? &in_flight : nullptr};

    const auto trace = platform::perf_trace::begin();
    std::string body;
    bool oversized = false;
    httplib::Request request;
    request.method = "POST";
    request.path = path;
    request.body = request_body;
    request.set_header("Content-Type", "application/json");
    request.response_handler = [&](const httplib::Response& headers) {
        oversized =
            headers.get_header_value_u64("Content-Length") > response_limit;
        return !oversized;
    };
    request.content_receiver =
        [&](const char* bytes, std::size_t count, auto, auto) {
            oversized = count > response_limit - body.size();
            if (!oversized) {
                body.append(bytes, count);
            }
            return !oversized;
        };
    const auto response = client->send(request);
    request_guard.unregister();
    if (trace.active) {
        platform::perf_trace::finish(
            std::string{"rc/"} + std::string{path_suffix}, trace);
    }
    if (honour_cancellation && platform::cancellation::requested()) {
        return std::unexpected(
            make_error(ErrorCode::Cancelled, "operation cancelled by user"));
    }
    if (oversized) {
        return std::unexpected(make_error(ErrorCode::ProtocolFailure,
                                          "RC response exceeds limit of " +
                                              std::to_string(response_limit) +
                                              " bytes"));
    }
    if (!response) {
        return std::unexpected(
            make_error(ErrorCode::Io,
                       std::string{"RC HTTP failure: "} +
                           httplib::to_string(response.error()),
                       static_cast<int>(response.error())));
    }
    const bool server_closed =
        response->get_header_value("Connection") == "close";
    if (!server_closed) {
        release_client(runtime, std::move(client));
    }
    if (response->status == 401 || response->status == 403) {
        return std::unexpected(make_error(ErrorCode::PermissionDenied,
                                          "RC authentication rejected",
                                          response->status));
    }
    if (response->status < 200 || response->status >= 300) {
        std::string detail = "unexpected RC HTTP status; body omitted";
        try {
            const auto json = nlohmann::json::parse(body);
            if (json.contains("error") && json["error"].is_string()) {
                detail = rc_error_detail(
                    state, json["error"].get_ref<const std::string&>(), detail);
            }
        } catch (...) {
        }
        const auto code = response->status >= 500 && response->status <= 599
                              ? ErrorCode::BackendUnavailable
                              : ErrorCode::ProtocolFailure;
        return std::unexpected(
            make_error(code, std::move(detail), response->status));
    }
    return body;
}

bool transient_read_failure(const Error& error) noexcept {
    return error.code == ErrorCode::Io || error.code == ErrorCode::Timeout ||
           (error.code == ErrorCode::BackendUnavailable &&
            (error.native_code == 502 || error.native_code == 503 ||
             error.native_code == 504));
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
        std::chrono::milliseconds read_timeout,
        bool honour_cancellation) {
    const auto started = std::chrono::steady_clock::now();
    auto result = post_rc_impl(state,
                               endpoint,
                               request_body,
                               response_limit,
                               read_timeout,
                               1,
                               1,
                               honour_cancellation);
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
            if (last_error.code == ErrorCode::BackendUnavailable) {
                return std::unexpected(std::move(last_error));
            }
            return std::unexpected(contextualize(
                make_error(ErrorCode::Timeout, "RC read deadline exceeded")));
        }
        std::this_thread::sleep_for(read_retry_delay);
    }
    return std::unexpected(std::move(last_error));
}

std::expected<void, Error> verify_rclone_version(State& state) {
    const auto response = post_rc(
        state, "core/version", "{}", maximum_response_size, default_read_timeout);
    if (!response) {
        return std::unexpected(response.error());
    }
    try {
        const auto json = nlohmann::json::parse(*response);
        std::optional<RcloneVersion> parsed;
        if (json.contains("decomposed") && json["decomposed"].is_array() &&
            json["decomposed"].size() >= 3 &&
            json["decomposed"][0].is_number_integer() &&
            json["decomposed"][1].is_number_integer() &&
            json["decomposed"][2].is_number_integer()) {
            const int major = json["decomposed"][0].get<int>();
            const int minor = json["decomposed"][1].get<int>();
            const int patch = json["decomposed"][2].get<int>();
            if (major >= 0 && minor >= 0 && patch >= 0) {
                std::string raw =
                    (json.contains("version") && json["version"].is_string())
                        ? json["version"].get<std::string>()
                        : std::format("v{}.{}.{}", major, minor, patch);
                parsed = RcloneVersion{
                    .major = major,
                    .minor = minor,
                    .patch = patch,
                    .raw = std::move(raw),
                };
            }
        } else if (json.contains("version") && json["version"].is_string()) {
            parsed = parse_rclone_version(
                json["version"].get_ref<const std::string&>());
        }
        if (!parsed) {
            return std::unexpected(make_error(
                ErrorCode::ProtocolFailure, "invalid core/version response"));
        }
        if (!meets_minimum_rclone_version(*parsed)) {
            return std::unexpected(make_error(
                ErrorCode::BackendUnavailable,
                std::format("unsupported rclone version {} (minimum required: "
                            "v{}.{}.{})",
                            parsed->raw,
                            minimum_rclone_major,
                            minimum_rclone_minor,
                            minimum_rclone_patch)));
        }
    } catch (const std::exception&) {
        return std::unexpected(make_error(
            ErrorCode::ProtocolFailure,
            "invalid core/version JSON; body omitted"));
    }
    return {};
}

std::expected<void, Error> establish_rc_connection(State& state,
                                                   int child_pid) {
    const auto ready = wait_for_rc_readiness(state, child_pid);
    if (!ready) {
        return std::unexpected(ready.error());
    }
    const auto version = verify_rclone_version(state);
    if (!version) {
        return std::unexpected(version.error());
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
                               std::chrono::seconds{2},
                               false)
                           .has_value();
    } catch (...) {
    }
    state.ready = false;
    return acknowledged;
}

} // namespace kasumi::transport::rclone_detail
