#pragma once

#include "application/daemon.hpp"
#include "application/daemon/ipc_security.hpp"

#include <chrono>
#include <filesystem>
#include <httplib.h>
#include <map>
#include <mutex>
#include <optional>

namespace kasumi::application::daemon_detail {

using WebListener = WebListenerConfig;

using WebClock = std::chrono::steady_clock;
struct WebSession {
    std::array<std::uint8_t, kTokenSize> csrf{};
    WebClock::time_point expires;
    WebClock::time_point idle;
    WebClock::time_point last_persisted{};
};
struct LoginAttempts {
    unsigned failures{};
    WebClock::time_point next{};
    bool in_flight = false;
};
struct WebAuth {
    std::mutex mutex;
    std::filesystem::path dir;
    WebListener listener;
    std::string username = "admin";
    std::string salt;
    std::array<std::uint8_t, kTokenSize> hash{};
    std::array<std::uint8_t, kTokenSize> bootstrap{};
    std::map<std::string, WebSession, std::less<>> sessions;
    std::map<std::string, LoginAttempts> attempts;
    unsigned active_derivations = 0;
};
std::expected<WebListener, std::string>
initialize_web_auth(WebAuth& auth, const std::filesystem::path& dir);
void install_web_security(WebAuth& auth,
                          httplib::Server& server,
                          const WebListener& listener,
                          int port,
                          std::span<const std::uint8_t, kTokenSize> ipc_token,
                          bool ipc,
                          bool browser);
bool web_session_active(WebAuth& auth, std::string_view cookie);

std::string session_cookie(const httplib::Request& req);

} // namespace kasumi::application::daemon_detail
