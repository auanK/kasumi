#include "application/daemon/profile_state.hpp"
#include "application/daemon/session_state.hpp"
#include "application/daemon/web_http.hpp"
#include "application/daemon/web_profile_json.hpp"
#include "application/daemon/web_routes.hpp"
#include "application/daemon/web_static.hpp"
#include "crypto/secure_memory.hpp"
#include "platform/profile_lock.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <httplib.h>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace kasumi::application::daemon_detail {
namespace {

std::string_view error_code_string(DaemonErrorCode code) noexcept {
    switch (code) {
        case DaemonErrorCode::AlreadyRunning:
            return "daemon_already_running";
        case DaemonErrorCode::NotRunning:
            return "daemon_not_running";
        case DaemonErrorCode::ProfileNotFound:
            return "profile_not_found";
        case DaemonErrorCode::InvalidCredential:
            return "credentials_invalid";
        case DaemonErrorCode::LockBusy:
            return "lock_busy";
        case DaemonErrorCode::IpcFailure:
            return "ipc_failure";
        case DaemonErrorCode::ConfigFailure:
            return "config_failure";
        case DaemonErrorCode::StorageFailure:
            return "storage_failure";
        case DaemonErrorCode::Unsupported:
            return "unsupported";
        case DaemonErrorCode::Timeout:
            return "timeout";
    }
    return "ipc_failure";
}

void set_ipc_error(httplib::Response& res,
                   int status,
                   DaemonErrorCode code,
                   std::string_view detail) {
    res.status = status;
    res.set_content(
        nlohmann::json{{"code", std::string{error_code_string(code)}},
                       {"error", std::string{detail}}}
            .dump(),
        "application/json");
}

Credentials web_credentials(DaemonSessionState& state, std::string_view name) {
    std::lock_guard lock(state.mutex);
    const auto slot = find_profile_slot(state.profiles, name);
    if (slot && state.profiles.cold[*slot].config.key_storage ==
                    runtime::KeyStorage::Memory) {
        MasterKeyBytes key;
        if (platform::read_secure_key(state.key_arena, name, key.bytes))
            return key;
    }
    return NoCredentials{};
}

void track_internal_profile_lock(DaemonSessionState& state,
                                 std::string_view name,
                                 bool active) {
    std::lock_guard lock(state.mutex);
    const std::string key(name);
    auto& count = state.internal_lock_counts[key];
    if (active) {
        ++count;
    } else if (count > 0 && --count == 0) {
        state.internal_lock_counts.erase(key);
    }
}

struct WarmTransportLease {
    transport::Transport transport;
    std::optional<std::uint64_t> generation;
};

WarmTransportLease borrow_warm_transport(DaemonSessionState& state,
                                         std::string_view name,
                                         const runtime::ProfileData& config) {
    WarmTransportLease lease;
    std::lock_guard lock(state.mutex);
    if (auto slot = find_profile_slot(state.profiles, name)) {
        const auto& cfg = state.profiles.cold[*slot].config;
        if (!state.profiles.hot[*slot].in_flight &&
            cfg.remote_dir == config.remote_dir &&
            cfg.local_dir == config.local_dir &&
            cfg.rclone_config == config.rclone_config &&
            cfg.bandwidth_limit == config.bandwidth_limit) {
            lease.generation = state.profiles.hot[*slot].config_generation;
            auto& cache = state.profiles.warm[*slot].warm_transport;
            if (cache) {
                lease.transport = std::move(*cache);
                cache.reset();
            }
        }
    }
    return lease;
}

void return_warm_transport(DaemonSessionState& state,
                           std::string_view name,
                           std::optional<std::uint64_t> generation,
                           transport::Transport returned) {
    if (!generation || !transport::valid(returned))
        return;
    std::lock_guard lock(state.mutex);
    auto slot = find_profile_slot(state.profiles, name);
    if (slot && state.profiles.hot[*slot].config_generation == *generation &&
        !state.profiles.hot[*slot].in_flight &&
        !state.profiles.warm[*slot].warm_transport) {
        state.profiles.warm[*slot].warm_transport = std::move(returned);
        state.profiles.warm[*slot].warm_transport_last_used =
            std::chrono::steady_clock::now();
    }
}

std::expected<InspectionResponse, InspectionError>
inspect_web_request(DaemonSessionState& state, InspectionRequest request) {
    const auto name = request.profile_name;
    if (!runtime::is_valid_profile_name(name))
        throw daemon_detail::HttpError{400, "invalid profile name"};
    const bool writes =
        request.operation == InspectionOperation::RemoteRestore &&
        !request.dry_run;
    auto inspect_profile = [&] {
        auto config = runtime::load_profile(
            state.environment.app_data_dir / "config.toml", name);
        if (!config)
            throw daemon_detail::HttpError{404, "profile unavailable"};
        auto lease = borrow_warm_transport(state, name, *config);
        auto result = inspect({.request = std::move(request),
                               .credentials = web_credentials(state, name),
                               .environment = state.environment,
                               .stop_token = state.master_stop.get_token(),
                               .transport_cache = &lease.transport});
        if (result) {
            return_warm_transport(
                state, name, lease.generation, std::move(lease.transport));
        }
        return result;
    };
    if (writes) {
        daemon_detail::InternalProfileLockGuard lock_guard(
            [&state](std::string_view n, bool active) {
                track_internal_profile_lock(state, n, active);
            },
            name);
        return daemon_detail::with_profile_lock(
            state.environment, name, inspect_profile);
    }
    return inspect_profile();
}

std::expected<std::shared_ptr<RemoteDownloadSession>, InspectionError>
open_web_download(DaemonSessionState& state, InspectionRequest request) {
    const auto name = request.profile_name;
    if (!runtime::is_valid_profile_name(name))
        throw daemon_detail::HttpError{400, "invalid profile name"};
    auto config = runtime::load_profile(
        state.environment.app_data_dir / "config.toml", name);
    if (!config)
        throw daemon_detail::HttpError{404, "profile unavailable"};
    auto lease = borrow_warm_transport(state, name, *config);
    auto opened = open_remote_download({
        .request = std::move(request),
        .credentials = web_credentials(state, name),
        .environment = state.environment,
        .stop_token = state.master_stop.get_token(),
        .transport_cache =
            transport::valid(lease.transport) ? &lease.transport : nullptr,
    });
    if (!opened)
        return std::unexpected(opened.error());
    const auto generation = lease.generation;
    return std::shared_ptr<RemoteDownloadSession>(
        new RemoteDownloadSession(std::move(*opened)),
        [&state, name, generation](RemoteDownloadSession* ptr) {
            if (!ptr)
                return;
            if (auto returned = take_remote_download_transport(*ptr);
                returned && transport::valid(*returned) &&
                transport::check_health(*returned)) {
                return_warm_transport(
                    state, name, generation, std::move(*returned));
            }
            delete ptr;
        });
}

std::uint64_t parse_http_count(std::string_view text) {
    std::uint64_t count{};
    const auto [end, ec] =
        std::from_chars(text.data(), text.data() + text.size(), count);
    if (ec != std::errc{} || end != text.data() + text.size())
        throw daemon_detail::HttpError{400, "invalid count"};
    return count;
}

std::set<std::string>
probe_external_locked_profiles(DaemonSessionState& state) {
    std::vector<std::string> candidates;
    {
        std::lock_guard lock(state.mutex);
        if (!state.running)
            return {};
        candidates.reserve(state.profiles.names.size());
        for (std::size_t i = 0; i < state.profiles.names.size(); ++i) {
            if (state.profiles.hot[i].in_flight)
                continue;
            const auto& name = state.profiles.names[i];
            const auto it = state.internal_lock_counts.find(name);
            if (it != state.internal_lock_counts.end() && it->second > 0)
                continue;
            candidates.push_back(name);
        }
    }
    const auto active_jobs =
        daemon_detail::active_job_operations(state.web_jobs);
    std::set<std::string> external;
    for (const auto& name : candidates) {
        const bool has_job =
            std::ranges::any_of(active_jobs, [&](const auto& pair) {
                return pair.first == name;
            });
        if (has_job)
            continue;
        if (const auto op =
                daemon_detail::detect_held_profile_operation(state, name);
            op && *op == "external") {
            external.insert(name);
        }
    }
    return external;
}

void register_stream(httplib::Server& server,
                     DaemonSessionState& state,
                     const daemon_detail::WebContext& ctx) {
    using daemon_detail::Json;
    server.Get(
        "/v1/logs", daemon_detail::json_route([&state](const auto& req) {
            DaemonLogQuery query;
            if (req.has_param("profile"))
                query.profile_name = req.get_param_value("profile");
            if (req.has_param("lines"))
                query.max_lines = std::clamp<std::uint64_t>(
                    parse_http_count(req.get_param_value("lines")), 1, 1000);
            const auto full =
                req.has_param("full") ? req.get_param_value("full") : "true";
            if (full != "true" && full != "false")
                throw daemon_detail::HttpError{400, "invalid full flag"};
            auto logs = events_session_state(state, query);
            if (!logs)
                throw daemon_detail::HttpError{503, "daemon unavailable"};
            Json rows = logs->events;
            if (full == "false")
                for (auto& row : rows)
                    row.erase("detail");
            return Json{{"events", std::move(rows)},
                        {"latest_seq", logs->latest_seq}};
        }));
    server.Get(
        "/v1/events/stream",
        [&state, ctx](const httplib::Request& req, httplib::Response& res) {
            auto since =
                req.has_header("Last-Event-ID")
                    ? parse_http_count(req.get_header_value("Last-Event-ID"))
                : req.has_param("since")
                    ? parse_http_count(req.get_param_value("since"))
                    : 0;
            if (state.web_jobs.streams.fetch_add(1) >= 4) {
                --state.web_jobs.streams;
                throw daemon_detail::HttpError{429, "too many live streams"};
            }
            auto slot = std::shared_ptr<std::atomic_uint>(
                &state.web_jobs.streams, [](auto* n) {
                    --*n;
                });
            const bool ipc = req.has_header("X-Kasumi-Daemon-Token");
            auto cookie = daemon_detail::session_cookie(req);
            res.set_header("X-Accel-Buffering", "no");
            res.set_chunked_content_provider(
                "text/event-stream",
                [ctx,
                 &state,
                 slot,
                 cookie,
                 ipc,
                 since,
                 last_rev = std::uint64_t{0},
                 last_external = std::set<std::string>{}](
                    std::size_t offset, httplib::DataSink& sink) mutable {
                    bool send_status = (offset == 0);
                    bool send_logs = (offset == 0);
                    bool external_changed = false;
                    if (offset > 0) {
                        bool woke = false;
                        for (int tick = 0; tick < 14; ++tick) {
                            if (ctx.stop.stop_requested() ||
                                !sink.is_writable() ||
                                (!ipc && !daemon_detail::web_session_active(
                                             state.web_auth, cookie))) {
                                sink.done();
                                return true;
                            }
                            {
                                std::unique_lock lock(state.mutex);
                                woke = state.cv.wait_for(
                                    lock, std::chrono::seconds(1), [&] {
                                        return state.stop_requested ||
                                               state.latest_event_seq.load(
                                                   std::memory_order_acquire) >
                                                   since ||
                                               state.status_revision.load(
                                                   std::memory_order_acquire) !=
                                                   last_rev;
                                    });
                            }
                            if (woke)
                                break;
                            if (probe_external_locked_profiles(state) !=
                                last_external) {
                                external_changed = true;
                                woke = true;
                                break;
                            }
                        }
                        if (ctx.stop.stop_requested() || !sink.is_writable() ||
                            (!ipc && !daemon_detail::web_session_active(
                                         state.web_auth, cookie))) {
                            sink.done();
                            return true;
                        }
                        if (!woke) {
                            static constexpr std::string_view kKeepalive =
                                ": keepalive\n\n";
                            return sink.write(kKeepalive.data(),
                                              kKeepalive.size());
                        }
                        send_logs = state.latest_event_seq.load(
                                        std::memory_order_acquire) > since;
                        send_status =
                            external_changed ||
                            state.status_revision.load(
                                std::memory_order_acquire) != last_rev;
                    }
                    if (ctx.stop.stop_requested() ||
                        (!ipc && !daemon_detail::web_session_active(
                                     state.web_auth, cookie))) {
                        sink.done();
                        return true;
                    }
                    std::string frame;
                    if (send_logs) {
                        std::vector<DaemonEvent> events;
                        {
                            std::lock_guard lock(state.event_log_mutex);
                            for (const auto& ev : state.event_ring)
                                if (ev.seq > since)
                                    events.push_back(ev);
                        }
                        for (const auto& ev : events) {
                            frame +=
                                "id: " + std::to_string(ev.seq) +
                                "\nevent: log\ndata: " +
                                Json(ev).dump(-1,
                                              ' ',
                                              false,
                                              Json::error_handler_t::replace) +
                                "\n\n";
                            since = ev.seq;
                        }
                    }
                    if (send_status) {
                        const auto rev = state.status_revision.load(
                            std::memory_order_acquire);
                        auto status = status_session_state(state, std::nullopt);
                        if (!status) {
                            sink.done();
                            return true;
                        }
                        Json snapshot{
                            {"daemon_instance", status->daemon_instance},
                            {"kasumi_version", status->kasumi_version},
                            {"machine_name", status->machine_name},
                            {"profiles", status->profiles},
                            {"uptime_seconds", status->uptime_seconds},
                            {"jobs",
                             daemon_detail::job_snapshot(state.web_jobs)}};
                        frame += "event: status\ndata: " +
                                 snapshot.dump(-1,
                                               ' ',
                                               false,
                                               Json::error_handler_t::replace) +
                                 "\n\n";
                        last_rev = rev;
                        last_external.clear();
                        for (const auto& p : status->profiles) {
                            if (p.busy && p.active_operation == "external")
                                last_external.insert(p.name);
                        }
                    }
                    if (frame.empty()) {
                        static constexpr std::string_view kKeepalive =
                            ": keepalive\n\n";
                        return sink.write(kKeepalive.data(), kKeepalive.size());
                    }
                    return sink.write(frame.data(), frame.size());
                });
        });
}

void register_daemon_routes(httplib::Server& server,
                            DaemonSessionState& state) {
    server.set_payload_max_length(1024U * 1024U);
    server.set_read_timeout(5, 0);
    server.set_write_timeout(5, 0);
    server.set_keep_alive_max_count(32);
    daemon_detail::WebContext ctx{
        .environment = state.environment,
        .stop = state.master_stop.get_token(),
        .credentials =
            [&state](auto name) {
                return web_credentials(state, name);
            },
        .status =
            [&state] {
                auto status = status_session_state(state, std::nullopt);
                if (!status)
                    throw daemon_detail::HttpError{503, "daemon unavailable"};
                return std::move(*status);
            },
        .reload =
            [&state] {
                if (!reload_session_state(state))
                    throw daemon_detail::HttpError{500,
                                                   "cannot reload profiles"};
            },
        .track_internal_lock =
            [&state](std::string_view name, bool active) {
                track_internal_profile_lock(state, name, active);
            },
        .inspect =
            [&state](InspectionRequest request) {
                return inspect_web_request(state, std::move(request));
            },
        .open_download =
            [&state](InspectionRequest request) {
                return open_web_download(state, std::move(request));
            }};
    daemon_detail::register_profile_routes(server, ctx);
    daemon_detail::register_remote_routes(server, ctx);
    daemon_detail::register_local_routes(server, ctx);
    daemon_detail::register_job_routes(server, ctx, state.web_jobs, [&state] {
        notify_daemon_status_change(state);
    });
    register_stream(server, state, ctx);
    server.Get("/v1/status",
               [&state](const httplib::Request& req, httplib::Response& res) {
                   std::optional<std::string_view> profile_arg;
                   std::string profile_storage;
                   if (req.has_param("profile")) {
                       profile_storage = req.get_param_value("profile");
                       if (!profile_storage.empty()) {
                           profile_arg = profile_storage;
                       }
                   }
                   auto report = status_session_state(state, profile_arg);
                   if (!report) {
                       set_ipc_error(res,
                                     report.error().code ==
                                             DaemonErrorCode::ProfileNotFound
                                         ? 404
                                         : 400,
                                     report.error().code,
                                     report.error().detail);
                       return;
                   }
                   nlohmann::json body{
                       {"running", report->running},
                       {"api_version", report->api_version},
                       {"kasumi_version", report->kasumi_version},
                       {"machine_name", report->machine_name},
                       {"secure_pages_locked", report->secure_pages_locked},
                       {"pid", report->pid},
                       {"started_at_unix", report->started_at_unix},
                       {"daemon_instance", report->daemon_instance},
                       {"uptime_seconds", report->uptime_seconds},
                       {"ipc_port", report->ipc_port},
                       {"web_port", report->web_port},
                       {"autostart", report->autostart},
                       {"profiles", nlohmann::json(report->profiles)},
                   };
                   res.set_content(body.dump(), "application/json");
               });

    server.Get(
        "/v1/events",
        [&state](const httplib::Request& req, httplib::Response& res) {
            DaemonLogQuery query;
            if (req.has_param("profile")) {
                auto p = req.get_param_value("profile");
                if (!p.empty()) {
                    query.profile_name = std::move(p);
                }
            }
            if (req.has_param("since")) {
                try {
                    query.since_seq = std::stoull(req.get_param_value("since"));
                } catch (...) {
                    set_ipc_error(res,
                                  400,
                                  DaemonErrorCode::ConfigFailure,
                                  "invalid since sequence");
                    return;
                }
            }
            if (req.has_param("limit")) {
                try {
                    query.max_lines = static_cast<std::size_t>(
                        std::stoull(req.get_param_value("limit")));
                } catch (...) {
                    set_ipc_error(res,
                                  400,
                                  DaemonErrorCode::ConfigFailure,
                                  "invalid limit parameter");
                    return;
                }
            }
            const auto report = events_session_state(state, query);
            if (!report) {
                set_ipc_error(
                    res, 400, report.error().code, report.error().detail);
                return;
            }
            nlohmann::json evs = nlohmann::json::array();
            for (const auto& ev : report->events) {
                evs.push_back({
                    {"seq", ev.seq},
                    {"ts", ev.timestamp_unix},
                    {"profile", ev.profile_name},
                    {"kind", ev.kind},
                    {"detail", ev.detail},
                });
            }
            res.set_content(
                nlohmann::json{
                    {"log_path", report->log_path},
                    {"latest_seq", report->latest_seq},
                    {"events", std::move(evs)},
                }
                    .dump(),
                "application/json");
        });

    server.Post(
        "/v1/autostart", daemon_detail::json_route([&state](const auto& req) {
            const bool enabled = daemon_detail::parse_body(req)
                                     ->at("enabled")
                                     .template get<bool>();
            std::lock_guard autostart_lock(state.autostart_mutex);
            auto result = enabled ? install_daemon_autostart()
                                  : uninstall_daemon_autostart();
            if (!result)
                throw daemon_detail::HttpError{500, result.error().detail};
            std::lock_guard lock(state.mutex);
            state.cached_autostart = *result;
            return *result;
        }));

    server.Get("/v1/web/config",
               daemon_detail::json_route([&state](const auto&) {
                   const auto cfg = read_web_listener_config(state.environment);
                   if (!cfg)
                       throw daemon_detail::HttpError{400, cfg.error().detail};
                   std::uint16_t active_port = 0;
                   {
                       std::lock_guard lock(state.mutex);
                       active_port = state.web_port;
                   }
                   return nlohmann::json{
                       {"bind", cfg->bind},
                       {"port", cfg->port},
                       {"active_port", active_port},
                       {"allowed_hosts", cfg->allowed_hosts},
                       {"skip_host_check", cfg->skip_host_check},
                   };
               }));

    server.Patch(
        "/v1/web/config", daemon_detail::json_route([&state](const auto& req) {
            const auto current = read_web_listener_config(state.environment);
            if (!current)
                throw daemon_detail::HttpError{400, current.error().detail};
            const auto body = daemon_detail::parse_body(req);
            WebListenerConfig next = *current;
            if (body->contains("bind"))
                next.bind = (*body)["bind"].template get<std::string>();
            if (body->contains("port"))
                next.port = (*body)["port"].template get<int>();
            if (body->contains("allowed_hosts"))
                next.allowed_hosts =
                    (*body)["allowed_hosts"]
                        .template get<std::vector<std::string>>();
            if (body->contains("skip_host_check"))
                next.skip_host_check =
                    (*body)["skip_host_check"].template get<bool>();
            const auto saved =
                write_web_listener_config(state.environment, next);
            if (!saved) {
                throw daemon_detail::HttpError{400, saved.error().detail};
            }
            return nlohmann::json{
                {"bind", saved->bind},
                {"port", saved->port},
                {"allowed_hosts", saved->allowed_hosts},
                {"skip_host_check", saved->skip_host_check},
                {"restart_required", true},
            };
        }));

    server.Get("/v1/web/config",
               daemon_detail::json_route([&state](const auto&) {
                   const auto cfg = read_web_listener_config(state.environment);
                   if (!cfg)
                       throw daemon_detail::HttpError{400, cfg.error().detail};
                   std::uint16_t active_port = 0;
                   {
                       std::lock_guard lock(state.mutex);
                       active_port = state.web_port;
                   }
                   return nlohmann::json{
                       {"bind", cfg->bind},
                       {"port", cfg->port},
                       {"active_port", active_port},
                       {"allowed_hosts", cfg->allowed_hosts},
                       {"skip_host_check", cfg->skip_host_check},
                   };
               }));

    server.Patch(
        "/v1/web/config", daemon_detail::json_route([&state](const auto& req) {
            const auto current = read_web_listener_config(state.environment);
            if (!current)
                throw daemon_detail::HttpError{400, current.error().detail};
            const auto body = daemon_detail::parse_body(req);
            WebListenerConfig next = *current;
            if (body->contains("bind"))
                next.bind = (*body)["bind"].template get<std::string>();
            if (body->contains("port"))
                next.port = (*body)["port"].template get<int>();
            if (body->contains("allowed_hosts"))
                next.allowed_hosts =
                    (*body)["allowed_hosts"]
                        .template get<std::vector<std::string>>();
            if (body->contains("skip_host_check"))
                next.skip_host_check =
                    (*body)["skip_host_check"].template get<bool>();
            const auto saved =
                write_web_listener_config(state.environment, next);
            if (!saved) {
                throw daemon_detail::HttpError{400, saved.error().detail};
            }
            return nlohmann::json{
                {"bind", saved->bind},
                {"port", saved->port},
                {"allowed_hosts", saved->allowed_hosts},
                {"skip_host_check", saved->skip_host_check},
                {"restart_required", true},
            };
        }));

    server.Post("/v1/stop",
                [&state](const httplib::Request&, httplib::Response& res) {
                    res.set_content(R"({"stopping":true})", "application/json");
                    request_stop_internal(state);
                });

    server.Post("/v1/reload",
                [&state](const httplib::Request&, httplib::Response& res) {
                    const auto reloaded = reload_session_state(state);
                    if (!reloaded) {
                        set_ipc_error(res,
                                      400,
                                      reloaded.error().code,
                                      reloaded.error().detail);
                        return;
                    }
                    res.set_content(R"({"reloaded":true})", "application/json");
                });

    server.Post(
        "/v1/sync",
        [&state](const httplib::Request& req, httplib::Response& res) {
            std::optional<std::string> profile_name;
            bool wait = false;
            try {
                if (!req.body.empty()) {
                    const auto j = daemon_detail::parse_body(req);
                    if (j->contains("profile") && (*j)["profile"].is_string()) {
                        auto p = (*j)["profile"].template get<std::string>();
                        if (!p.empty()) {
                            profile_name = std::move(p);
                        }
                    }
                    wait = j->value("wait", false);
                }
            } catch (const daemon_detail::HttpError& err) {
                set_ipc_error(
                    res, err.status, DaemonErrorCode::IpcFailure, err.message);
                return;
            } catch (...) {
                set_ipc_error(
                    res, 400, DaemonErrorCode::IpcFailure, "invalid JSON body");
                return;
            }
            const auto triggered = trigger_sync_session_state(
                state,
                profile_name ? std::optional<std::string_view>{*profile_name}
                             : std::nullopt,
                wait);
            if (!triggered) {
                set_ipc_error(res,
                              triggered.error().code ==
                                      DaemonErrorCode::ProfileNotFound
                                  ? 404
                                  : 400,
                              triggered.error().code,
                              triggered.error().detail);
                return;
            }
            nlohmann::json failures = nlohmann::json::array();
            for (const auto& [pname, err] : triggered->failures) {
                failures.push_back({{"profile", pname}, {"detail", err}});
            }
            res.set_content(nlohmann::json{{"profiles", triggered->profiles},
                                           {"completed", triggered->completed},
                                           {"failures", std::move(failures)}}
                                .dump(),
                            "application/json");
        });

    auto handle_profile_action = [&state](const httplib::Request& req,
                                          httplib::Response& res,
                                          int action_kind) {
        std::string profile_name;
        try {
            const auto j = daemon_detail::parse_body(req);
            profile_name = j->value("profile", std::string{});
        } catch (const daemon_detail::HttpError& err) {
            set_ipc_error(
                res, err.status, DaemonErrorCode::IpcFailure, err.message);
            return;
        } catch (...) {
            set_ipc_error(
                res, 400, DaemonErrorCode::IpcFailure, "invalid JSON body");
            return;
        }
        if (profile_name.empty()) {
            set_ipc_error(res,
                          400,
                          DaemonErrorCode::ConfigFailure,
                          "profile is required");
            return;
        }
        std::expected<void, DaemonError> outcome;
        if (action_kind == 0) {
            outcome = pause_session_state(state, profile_name);
        } else if (action_kind == 1) {
            outcome = resume_session_state(state, profile_name);
        } else if (action_kind == 2) {
            outcome = lock_session_state(state, profile_name);
        } else {
            outcome = cancel_session_state(state, profile_name);
        }
        if (!outcome) {
            const int status =
                outcome.error().code == DaemonErrorCode::ProfileNotFound
                    ? 404
                    : (outcome.error().code == DaemonErrorCode::LockBusy ? 409
                                                                         : 400);
            set_ipc_error(
                res, status, outcome.error().code, outcome.error().detail);
            return;
        }
        res.set_content(R"({"ok":true})", "application/json");
    };

    server.Post("/v1/pause",
                [handle_profile_action](const auto& req, auto& res) {
                    handle_profile_action(req, res, 0);
                });
    server.Post("/v1/resume",
                [handle_profile_action](const auto& req, auto& res) {
                    handle_profile_action(req, res, 1);
                });
    server.Post("/v1/lock",
                [handle_profile_action](const auto& req, auto& res) {
                    handle_profile_action(req, res, 2);
                });
    server.Post("/v1/cancel",
                [handle_profile_action](const auto& req, auto& res) {
                    handle_profile_action(req, res, 3);
                });

    server.Post(
        "/v1/unlock",
        [&state](const httplib::Request& req, httplib::Response& res) {
            if (!req.has_header("X-Kasumi-Daemon-Token")) {
                auto body = daemon_detail::parse_body(req);
                auto unlocked = unlock_session_state(
                    state,
                    body->at("profile").get<std::string>(),
                    daemon_detail::credential_input(*body));
                if (!unlocked) {
                    set_ipc_error(res,
                                  400,
                                  unlocked.error().code,
                                  unlocked.error().detail);
                    return;
                }
                res.set_content(R"({"unlocked":true})", "application/json");
                return;
            }
            std::string profile_name;
            daemon_detail::SealedUnlockPayload sealed;
            try {
                const auto j = daemon_detail::parse_body(req);
                profile_name = j->value("profile", std::string{});
                sealed.nonce_hex = j->value("nonce", std::string{});
                sealed.mac_hex = j->value("mac", std::string{});
                sealed.ciphertext_hex = j->value("ciphertext", std::string{});
            } catch (const daemon_detail::HttpError& err) {
                set_ipc_error(
                    res, err.status, DaemonErrorCode::IpcFailure, err.message);
                return;
            } catch (...) {
                set_ipc_error(res,
                              400,
                              DaemonErrorCode::IpcFailure,
                              "invalid unlock JSON");
                return;
            }
            auto opened = daemon_detail::open_key_payload(
                state.ipc_key, sealed, profile_name);
            if (!opened) {
                set_ipc_error(res,
                              403,
                              DaemonErrorCode::InvalidCredential,
                              opened.error());
                return;
            }
            MasterKeyBytes key_bytes{*opened};
            crypto::secure_memory::wipe(opened->data(), opened->size());
            const auto unlocked =
                unlock_session_state(state, profile_name, std::move(key_bytes));
            if (!unlocked) {
                const int status =
                    unlocked.error().code == DaemonErrorCode::ProfileNotFound
                        ? 404
                        : (unlocked.error().code ==
                                   DaemonErrorCode::InvalidCredential
                               ? 401
                               : 400);
                set_ipc_error(res,
                              status,
                              unlocked.error().code,
                              unlocked.error().detail);
                return;
            }
            res.set_content(R"({"unlocked":true})", "application/json");
        });
}

} // namespace

std::expected<void, DaemonError> start_ipc_server(DaemonSessionState& state) {
    auto config = daemon_detail::initialize_web_auth(
        state.web_auth, state.environment.app_data_dir);
    if (!config)
        return std::unexpected(
            DaemonError{DaemonErrorCode::ConfigFailure, config.error()});
    auto server = std::make_unique<httplib::Server>();
    register_daemon_routes(*server, state);
    const int bound_port = server->bind_to_any_port("127.0.0.1");
    if (bound_port <= 0 || bound_port > 65535) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::IpcFailure,
            .detail = "failed to bind local daemon IPC loopback socket",
        });
    }
    state.ipc_port = static_cast<std::uint16_t>(bound_port);
    state.web_port = state.ipc_port;
    const bool separate = config->port != 0 || config->bind != "127.0.0.1";
    daemon_detail::install_web_security(state.web_auth,
                                        *server,
                                        separate ? daemon_detail::WebListener{}
                                                 : *config,
                                        bound_port,
                                        state.auth_token,
                                        true,
                                        !separate);
    if (!separate) {
        daemon_detail::register_web_static_routes(*server);
    }
    state.ipc_server = std::move(server);
    auto* raw_srv = state.ipc_server.get();
    state.ipc_thread = std::thread([raw_srv] {
        raw_srv->listen_after_bind();
    });
    state.ipc_server->wait_until_ready();
    if (separate) {
        auto web = std::make_unique<httplib::Server>();
        register_daemon_routes(*web, state);
        int port = config->port;
        if (port == 0)
            port = web->bind_to_any_port(config->bind);
        else if (!web->bind_to_port(config->bind, port))
            port = -1;
        if (port <= 0)
            return std::unexpected(
                DaemonError{DaemonErrorCode::IpcFailure,
                            std::format("cannot bind web API on {}:{}",
                                        config->bind,
                                        config->port)});
        daemon_detail::install_web_security(
            state.web_auth, *web, *config, port, state.auth_token, false, true);
        daemon_detail::register_web_static_routes(*web);
        {
            std::lock_guard lock(state.mutex);
            state.web_port = static_cast<std::uint16_t>(port);
        }
        state.web_server = std::move(web);
        state.web_thread = std::thread([srv = state.web_server.get()] {
            srv->listen_after_bind();
        });
        state.web_server->wait_until_ready();
    }
    return {};
}

} // namespace kasumi::application::daemon_detail
