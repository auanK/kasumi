#include "application/daemon/web_auth.hpp"

#include "application/daemon.hpp"
#include "application/daemon/web_http.hpp"
#include "crypto/secure_memory.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"
#include "runtime/vault.hpp"

#include <algorithm>
#include <charconv>
#include <monocypher.h>
#include <nlohmann/json.hpp>

namespace kasumi::application::daemon_detail {
namespace {
using namespace std::chrono_literals;
using json = nlohmann::json;
using crypto::secure_memory::WipeGuard;

constexpr std::size_t max_web_password_size = 1024;
constexpr auto kSessionIdleTtl = std::chrono::hours{24 * 7};
constexpr auto kSessionMaxTtl = std::chrono::hours{24 * 30};
constexpr std::int64_t kCookieMaxAgeSeconds = 30LL * 24LL * 60LL * 60LL;
constexpr auto kSessionPersistInterval = 1h;
constexpr std::size_t kMaxSessions = 256;

bool valid_web_username(std::string_view username) noexcept {
    return username.size() <= 256 &&
           username.find_first_not_of(' ') != std::string_view::npos &&
           std::ranges::none_of(username, [](unsigned char ch) {
               return ch < 0x20 || ch == 0x7f;
           });
}

bool valid_new_web_password(std::string_view password) noexcept {
    return password.size() <= max_web_password_size &&
           static_cast<std::size_t>(
               std::ranges::count_if(password, [](unsigned char ch) {
                   return (ch & 0xc0U) != 0x80U;
               })) >= runtime::vault::MINIMUM_WEB_PASSWORD_SIZE;
}

bool is_loopback_bind(std::string_view bind) noexcept {
    return bind == "127.0.0.1" || bind == "::1";
}

bool is_wildcard_bind(std::string_view bind) noexcept {
    return bind == "0.0.0.0" || bind == "::";
}

bool is_ipv4_literal(std::string_view value) noexcept {
    if (value.empty() || value.size() > 15)
        return false;
    int parts = 0;
    std::size_t pos = 0;
    while (pos <= value.size()) {
        const std::size_t dot = value.find('.', pos);
        const auto part = dot == std::string_view::npos
                              ? value.substr(pos)
                              : value.substr(pos, dot - pos);
        if (part.empty() || part.size() > 3)
            return false;
        if (part.size() > 1 && part.front() == '0')
            return false;
        int octet = -1;
        const auto [end, ec] =
            std::from_chars(part.data(), part.data() + part.size(), octet);
        if (ec != std::errc{} || end != part.data() + part.size() ||
            octet < 0 || octet > 255)
            return false;
        ++parts;
        if (dot == std::string_view::npos)
            break;
        pos = dot + 1;
        if (pos == value.size())
            return false;
    }
    return parts == 4;
}

bool is_ipv6_literal(std::string_view value) noexcept {
    if (value.size() < 2 || value.size() > 45 ||
        value.find(':') == std::string_view::npos)
        return false;
    if (value.find("::") != value.rfind("::"))
        return false;
    for (const char ch : value) {
        const auto uc = static_cast<unsigned char>(ch);
        const bool is_hex = (uc >= '0' && uc <= '9') ||
                            (uc >= 'a' && uc <= 'f') ||
                            (uc >= 'A' && uc <= 'F');
        if (!is_hex && ch != ':' && ch != '.')
            return false;
    }
    return true;
}

bool is_valid_bind_address(std::string_view bind) noexcept {
    return is_ipv4_literal(bind) || is_ipv6_literal(bind);
}

bool is_valid_allowed_host(std::string_view entry) noexcept {
    if (entry.empty() || entry.size() > 256)
        return false;
    return std::ranges::none_of(entry, [](unsigned char ch) {
        return ch <= 0x20 || ch == 0x7f || ch == '/' || ch == '\\';
    });
}

bool is_ip_literal_host(std::string_view host_part) noexcept {
    if (is_ipv4_literal(host_part))
        return true;
    return host_part.size() >= 4 && host_part.front() == '[' &&
           host_part.back() == ']' &&
           is_ipv6_literal(host_part.substr(1, host_part.size() - 2));
}

std::pair<std::string_view, std::string_view>
split_host_header(std::string_view host) noexcept {
    if (host.starts_with('[')) {
        const auto close = host.find(']');
        if (close == std::string_view::npos)
            return {{}, {}};
        const auto base = host.substr(0, close + 1);
        const auto rest = host.substr(close + 1);
        if (rest.empty())
            return {base, {}};
        if (rest.starts_with(':') && rest.size() > 1)
            return {base, rest.substr(1)};
        return {{}, {}};
    }
    const auto first = host.find(':');
    if (first == std::string_view::npos)
        return {host, {}};
    if (host.find(':', first + 1) != std::string_view::npos || first == 0 ||
        first + 1 == host.size())
        return {{}, {}};
    return {host.substr(0, first), host.substr(first + 1)};
}

std::string_view unbracket(std::string_view host_base) noexcept {
    if (host_base.size() >= 2 && host_base.front() == '[' &&
        host_base.back() == ']')
        return host_base.substr(1, host_base.size() - 2);
    return host_base;
}

bool host_allowed(const WebListener& listener,
                  std::string_view host,
                  int port) {
    if (host.empty() || host.size() > 320 ||
        std::ranges::any_of(host, [](unsigned char ch) {
            return ch <= 0x20 || ch == 0x7f;
        }))
        return false;
    if (listener.skip_host_check)
        return true;
    const std::string port_text = std::to_string(port);
    if (host == "127.0.0.1:" + port_text || host == "localhost:" + port_text ||
        host == "[::1]:" + port_text)
        return true;
    const auto [host_base, host_port] = split_host_header(host);
    for (const auto& entry : listener.allowed_hosts) {
        if (entry == host || entry + ":" + port_text == host)
            return true;
        if (entry.starts_with("*.") && entry.size() > 2 && !host_base.empty()) {
            const std::string_view suffix = std::string_view{entry}.substr(1);
            if (host_base.size() > suffix.size() &&
                host_base.ends_with(suffix) &&
                (host_port.empty() || host_port == port_text))
                return true;
        }
    }
    const bool valid_port =
        host_port == port_text || (port == 80 && host_port.empty());
    if (valid_port && !host_base.empty() && is_ip_literal_host(host_base)) {
        if (is_wildcard_bind(listener.bind) ||
            unbracket(host_base) == listener.bind)
            return true;
    }
    return false;
}

std::string session_token_hash(std::string_view token) {
    std::array<std::uint8_t, kTokenSize> digest{};
    crypto_blake2b(digest.data(),
                   digest.size(),
                   reinterpret_cast<const std::uint8_t*>(token.data()),
                   token.size());
    auto encoded = encode_hex(digest);
    crypto::secure_memory::wipe(digest.data(), digest.size());
    return encoded;
}

void reply(httplib::Response& res, int status, const json& value) {
    res.status = status;
    res.set_content(value.dump(), "application/json");
}

bool proxy_https(const httplib::Request& req) {
    return (req.remote_addr == "127.0.0.1" || req.remote_addr == "::1") &&
           req.get_header_value_count("X-Forwarded-Proto") == 1 &&
           req.get_header_value("X-Forwarded-Proto") == "https";
}

bool same_origin(const httplib::Request& req, const std::string& host) {
    const std::string origin =
        (proxy_https(req) ? "https://" : "http://") + host;
    if (req.has_header("Origin")) {
        return req.get_header_value_count("Origin") == 1 &&
               req.get_header_value("Origin") == origin;
    }
    return req.get_header_value_count("Referer") == 1 &&
           req.get_header_value("Referer").starts_with(origin + "/");
}

std::expected<json, std::string>
read_optional(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) && !ec)
        return json(nullptr);
    auto input = platform::private_storage::open_regular_file(path);
    if (!input || input->size > 16384)
        return std::unexpected("cannot read web configuration");
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(input->size));
    WipeGuard wipe(bytes);
    if (!platform::private_storage::read_regular_file_exact(*input, bytes))
        return std::unexpected("cannot read web configuration");
    auto parsed = json::parse(bytes, nullptr, false);
    if (!parsed.is_object())
        return std::unexpected("invalid web configuration");
    return parsed;
}

std::expected<WebListener, std::string> parse_web_listener(const json& config) {
    WebListener listener;
    if (config.is_null())
        return listener;
    try {
        listener.bind = config.value("bind", listener.bind);
        const auto port =
            config.value("port", static_cast<std::int64_t>(listener.port));
        if (port < 0 || port > 65535 || !is_valid_bind_address(listener.bind))
            return std::unexpected("invalid web listener");
        listener.port = static_cast<int>(port);
        listener.allowed_hosts =
            config.value("allowed_hosts", listener.allowed_hosts);
        for (const auto& host : listener.allowed_hosts) {
            if (!is_valid_allowed_host(host))
                return std::unexpected("invalid allowed host entry");
        }
        listener.skip_host_check =
            config.value("skip_host_check", listener.skip_host_check);
    } catch (const json::exception&) {
        return std::unexpected("invalid web configuration");
    }
    return listener;
}

void persist_sessions(WebAuth& auth) {
    if (auth.dir.empty() || auth.salt.empty())
        return;
    const auto mono_now = WebClock::now();
    std::erase_if(auth.sessions, [&](const auto& entry) {
        return mono_now >= entry.second.expires ||
               mono_now >= entry.second.idle;
    });
    const auto wall_now_s =
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count();
    json items = json::array();
    for (const auto& [hash, session] : auth.sessions) {
        if (hash.size() != kTokenSize * 2)
            continue;
        const auto exp_s = std::chrono::duration_cast<std::chrono::seconds>(
                               session.expires - mono_now)
                               .count();
        const auto idle_s = std::chrono::duration_cast<std::chrono::seconds>(
                                session.idle - mono_now)
                                .count();
        if (exp_s <= 0 || idle_s <= 0)
            continue;
        items.push_back(json{{"hash", hash},
                             {"csrf", encode_hex(session.csrf)},
                             {"expires_unix", wall_now_s + exp_s},
                             {"idle_unix", wall_now_s + idle_s}});
    }
    const auto serialized = json{
        {"version", 1},
        {"salt", auth.salt},
        {"sessions",
         std::move(items)}}.dump();
    static_cast<void>(platform::private_storage::write_atomically(
        auth.dir / "web-sessions.json", serialized));
}

void load_persisted_sessions(WebAuth& auth) {
    if (auth.dir.empty() || auth.salt.empty())
        return;
    auto persisted = read_optional(auth.dir / "web-sessions.json");
    if (!persisted || persisted->is_null())
        return;
    try {
        if (persisted->value("version", 0) != 1 ||
            persisted->value("salt", std::string{}) != auth.salt ||
            !persisted->contains("sessions") ||
            !(*persisted)["sessions"].is_array())
            return;
        const auto wall_now_s =
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count();
        const auto mono_now = WebClock::now();
        for (const auto& item : (*persisted)["sessions"]) {
            if (!item.is_object() || auth.sessions.size() >= kMaxSessions)
                break;
            const auto hash = item.value("hash", std::string{});
            const auto csrf_hex = item.value("csrf", std::string{});
            const auto exp_unix = item.value("expires_unix", std::int64_t{0});
            const auto idle_unix = item.value("idle_unix", std::int64_t{0});
            auto hash_bytes = decode_hex(hash, kTokenSize);
            auto csrf_bytes = decode_hex(csrf_hex, kTokenSize);
            if (!hash_bytes || !csrf_bytes ||
                csrf_bytes->size() != kTokenSize || exp_unix <= wall_now_s ||
                idle_unix <= wall_now_s)
                continue;
            std::array<std::uint8_t, kTokenSize> csrf{};
            std::copy_n(csrf_bytes->begin(), kTokenSize, csrf.begin());
            crypto::secure_memory::wipe(csrf_bytes->data(), csrf_bytes->size());
            const auto exp_rem =
                (std::min)(std::chrono::seconds{exp_unix - wall_now_s},
                           std::chrono::duration_cast<std::chrono::seconds>(
                               kSessionMaxTtl));
            const auto idle_rem =
                (std::min)(std::chrono::seconds{idle_unix - wall_now_s},
                           std::chrono::duration_cast<std::chrono::seconds>(
                               kSessionIdleTtl));
            auth.sessions.emplace(hash,
                                  WebSession{.csrf = csrf,
                                             .expires = mono_now + exp_rem,
                                             .idle = mono_now + idle_rem,
                                             .last_persisted = mono_now});
        }
    } catch (const json::exception&) {
        return;
    }
}

} // namespace

std::string session_cookie(const httplib::Request& req) {
    if (req.get_header_value_count("Cookie") != 1)
        return {};
    const auto header = req.get_header_value("Cookie");
    std::string_view rest(header);
    std::string result;
    while (!rest.empty()) {
        const auto end = rest.find(';');
        auto part = rest.substr(0, end);
        while (part.starts_with(' '))
            part.remove_prefix(1);
        if (part.starts_with("kasumi_session=")) {
            part.remove_prefix(15);
            if (part.size() != 64 || !result.empty())
                return {};
            result = part;
        }
        if (end == std::string_view::npos)
            break;
        rest.remove_prefix(end + 1);
    }
    return result;
}

std::expected<WebListener, std::string>
initialize_web_auth(WebAuth& auth, const std::filesystem::path& dir) {
    auth.dir = dir;
    auto config = read_optional(dir / "web.json");
    auto verifier = read_optional(dir / "web-password.json");
    if (!config || !verifier)
        return std::unexpected("invalid web configuration or password file");
    auto listener = parse_web_listener(*config);
    if (!listener)
        return std::unexpected(listener.error());
    try {
        if (!verifier->is_null()) {
            auth.username = verifier->value("username", std::string{"admin"});
            auth.salt = verifier->at("salt").get<std::string>();
            auto decoded = runtime::vault::decode_hex(
                verifier->at("hash").get_ref<const std::string&>());
            if (!decoded || !decode_hex(auth.salt, 32) ||
                !valid_web_username(auth.username))
                return std::unexpected("invalid web password file");
            auth.hash = *decoded;
            crypto::secure_memory::wipe(decoded->data(), decoded->size());
        }
    } catch (const json::exception&) {
        return std::unexpected("invalid web configuration or password file");
    }
    if (auth.salt.empty()) {
        if (!is_loopback_bind(listener->bind))
            return std::unexpected(
                "configure a web password before binding outside loopback");
        if (!platform::random::fill_bytes(auth.bootstrap))
            return std::unexpected("cannot generate web bootstrap token");
        auto token = encode_hex(auth.bootstrap);
        WipeGuard wipe(token);
        if (!platform::private_storage::write_atomically(
                dir / "web-bootstrap.token", token))
            return std::unexpected("cannot write web bootstrap token");
    } else {
        load_persisted_sessions(auth);
    }
    auth.listener = *listener;
    return *listener;
}

static WebSession* lookup(WebAuth& auth, std::string_view cookie) {
    if (cookie.empty())
        return nullptr;
    auto it = auth.sessions.find(cookie);
    if (it == auth.sessions.end() && cookie.size() == kTokenSize * 2)
        it = auth.sessions.find(session_token_hash(cookie));
    if (it == auth.sessions.end())
        return nullptr;
    const auto now = WebClock::now();
    if (now >= it->second.expires || now >= it->second.idle) {
        auth.sessions.erase(it);
        return nullptr;
    }
    return &it->second;
}

bool web_session_active(WebAuth& auth, std::string_view cookie) {
    std::lock_guard lock(auth.mutex);
    return lookup(auth, cookie) != nullptr;
}

namespace {

bool verify_csrf(const httplib::Request& req, const WebSession& session) {
    return req.get_header_value_count("X-CSRF-Token") == 1 &&
           constant_time_verify_hex_token(req.get_header_value("X-CSRF-Token"),
                                          session.csrf);
}

bool password_matches(std::string_view password,
                      std::string_view salt,
                      std::span<const std::uint8_t, kTokenSize> hash) {
    if (salt.empty())
        return false;
    auto calculated =
        runtime::vault::derive_web_password_verifier(password, salt);
    if (!calculated)
        return false;
    WipeGuard wipe(*calculated);
    return crypto_verify32(calculated->data(), hash.data()) == 0;
}

void authentication_busy(httplib::Response& res) {
    res.set_header("Retry-After", "1");
    reply(res, 429, {{"error", "try again later"}});
}

// Release the session mutex across expensive work. Limit aggregate Argon2id
// memory use across login and password changes, and admit only one login per
// IP.
constexpr unsigned max_active_derivations = 2;
auto reserve_derivation(WebAuth& auth,
                        std::unique_lock<std::mutex>& lock,
                        LoginAttempts* attempt = nullptr) {
    auto release = [&lock, attempt](WebAuth* state) {
        if (!lock.owns_lock())
            lock.lock();
        --state->active_derivations;
        if (attempt)
            attempt->in_flight = false;
    };
    ++auth.active_derivations;
    if (attempt)
        attempt->in_flight = true;
    return std::unique_ptr<WebAuth, decltype(release)>(&auth, release);
}

std::string_view auth_field(const json& body, const char* name) {
    const auto it = body.find(name);
    return it != body.end() && it->is_string()
               ? std::string_view(it->get_ref<const std::string&>())
               : std::string_view{};
}

void change_password(WebAuth& auth,
                     std::unique_lock<std::mutex>& lock,
                     const httplib::Request& req,
                     httplib::Response& res,
                     const json& body,
                     std::string_view cookie,
                     const std::string& cookie_flags) {
    const auto permitted = [&] {
        if (auth.salt.empty()) {
            return constant_time_verify_hex_token(
                auth_field(body, "bootstrap_token"), auth.bootstrap);
        }
        const auto* session = lookup(auth, cookie);
        return session && verify_csrf(req, *session);
    };
    if (!permitted()) {
        reply(res, 403, {{"error", "forbidden"}});
        return;
    }
    if (auth.active_derivations >= max_active_derivations) {
        authentication_busy(res);
        return;
    }

    const auto username_field = body.find("username");
    if (username_field != body.end() &&
        !valid_web_username(auth_field(body, "username"))) {
        reply(res, 400, {{"error", "invalid Web UI username"}});
        return;
    }
    auto username = username_field == body.end()
                        ? auth.username
                        : std::string{auth_field(body, "username")};
    const auto password = auth_field(body, "password");
    if (!valid_new_web_password(password)) {
        reply(res,
              400,
              {{"error",
                "web password requires 8 characters and at most 1024 bytes"}});
        return;
    }
    const auto previous_salt = auth.salt;
    auto previous_hash = auth.hash;
    WipeGuard wipe_previous(previous_hash);
    auto reservation = reserve_derivation(auth, lock);
    lock.unlock();
    if (!previous_salt.empty() &&
        !password_matches(auth_field(body, "current_password"),
                          previous_salt,
                          previous_hash)) {
        reply(res, 403, {{"error", "forbidden"}});
        return;
    }
    auto salt = platform::random::hex_id(32);
    if (!salt) {
        reply(res, 500, {{"error", "random source unavailable"}});
        return;
    }
    auto key = runtime::vault::derive_web_password_verifier(password, *salt);
    if (!key) {
        reply(res, 503, {{"error", "cannot derive password verifier"}});
        return;
    }
    WipeGuard wipe(*key);
    auto encoded = encode_hex(*key);
    WipeGuard wipe_encoded(encoded);
    auto verifier =
        json{{"username", username}, {"salt", *salt}, {"hash", encoded}};
    auto serialized = verifier.dump();
    WipeGuard wipe_serialized(serialized);
    scrub_json(&verifier);

    lock.lock();
    reservation.reset();
    // Another password change or logout may have won while we derived the key.
    if (auth.salt != previous_salt || !permitted()) {
        reply(res, 403, {{"error", "forbidden"}});
        return;
    }
    if (!platform::private_storage::write_atomically(
            auth.dir / "web-password.json", serialized)) {
        reply(res, 500, {{"error", "cannot store web password"}});
        return;
    }
    auth.salt = std::move(*salt);
    auth.username = std::move(username);
    auth.hash = *key;
    auth.sessions.clear();
    crypto::secure_memory::wipe(auth.bootstrap.data(), auth.bootstrap.size());
    std::error_code ec;
    std::filesystem::remove(auth.dir / "web-bootstrap.token", ec);
    std::filesystem::remove(auth.dir / "web-sessions.json", ec);
    res.set_header("Set-Cookie", "kasumi_session=; Max-Age=0" + cookie_flags);
    reply(res, 200, {{"configured", true}});
}

void change_username(WebAuth& auth,
                     std::unique_lock<std::mutex>& lock,
                     const httplib::Request& req,
                     httplib::Response& res,
                     const json& body,
                     std::string_view cookie) {
    const auto* session = lookup(auth, cookie);
    if (!session || !verify_csrf(req, *session) || auth.salt.empty()) {
        reply(res, 403, {{"error", "forbidden"}});
        return;
    }
    if (auth.active_derivations >= max_active_derivations) {
        authentication_busy(res);
        return;
    }
    const auto username_field = body.find("username");
    const auto username_view = auth_field(body, "username");
    if (username_field == body.end() || !valid_web_username(username_view)) {
        reply(res, 400, {{"error", "invalid Web UI username"}});
        return;
    }
    std::string username{username_view};
    const auto previous_salt = auth.salt;
    auto previous_hash = auth.hash;
    WipeGuard wipe_previous(previous_hash);
    auto reservation = reserve_derivation(auth, lock);
    lock.unlock();
    if (!password_matches(auth_field(body, "current_password"),
                          previous_salt,
                          previous_hash)) {
        reply(res, 403, {{"error", "forbidden"}});
        return;
    }
    auto encoded = encode_hex(previous_hash);
    WipeGuard wipe_encoded(encoded);
    auto verifier = json{
        {"username", username}, {"salt", previous_salt}, {"hash", encoded}};
    auto serialized = verifier.dump();
    WipeGuard wipe_serialized(serialized);
    scrub_json(&verifier);

    lock.lock();
    reservation.reset();
    const auto* active_session = lookup(auth, cookie);
    if (auth.salt != previous_salt || !active_session ||
        !verify_csrf(req, *active_session)) {
        reply(res, 403, {{"error", "forbidden"}});
        return;
    }
    if (!platform::private_storage::write_atomically(
            auth.dir / "web-password.json", serialized)) {
        reply(res, 500, {{"error", "cannot store web username"}});
        return;
    }
    auth.username = std::move(username);
    reply(res, 200, {{"username", auth.username}});
}

void login(WebAuth& auth,
           std::unique_lock<std::mutex>& lock,
           const httplib::Request& req,
           httplib::Response& res,
           const json& body,
           const std::string& cookie_flags) {
    const auto admitted_at = WebClock::now();
    std::erase_if(auth.attempts, [&](const auto& entry) {
        return !entry.second.in_flight &&
               entry.second.next + 10min < admitted_at;
    });
    if (auth.active_derivations >= max_active_derivations ||
        (auth.attempts.size() >= 4096 &&
         !auth.attempts.contains(req.remote_addr))) {
        authentication_busy(res);
        return;
    }
    auto& attempt = auth.attempts[req.remote_addr];
    if (attempt.in_flight || admitted_at < attempt.next) {
        authentication_busy(res);
        return;
    }
    const auto salt = auth.salt;
    const auto username = auth.username;
    auto hash = auth.hash;
    WipeGuard wipe(hash);
    auto reservation = reserve_derivation(auth, lock, &attempt);
    lock.unlock();
    const bool password_valid =
        password_matches(auth_field(body, "password"), salt, hash);
    const bool matched =
        password_valid && auth_field(body, "username") == username;
    lock.lock();
    reservation.reset();

    const auto now = WebClock::now();
    if (!matched || salt != auth.salt) {
        attempt.failures = std::min(attempt.failures + 1, 8U);
        attempt.next = now + std::chrono::seconds(1U << (attempt.failures - 1));
        reply(res, 401, {{"error", "invalid credentials"}});
        return;
    }
    auth.attempts.erase(req.remote_addr);
    std::erase_if(auth.sessions, [&](const auto& entry) {
        return now >= entry.second.expires || now >= entry.second.idle;
    });
    WebSession session{.expires = now + kSessionMaxTtl,
                       .idle = now + kSessionIdleTtl,
                       .last_persisted = now};
    auto id = platform::random::hex_id(kTokenSize);
    if (!id || !platform::random::fill_bytes(session.csrf) ||
        auth.sessions.size() >= kMaxSessions) {
        reply(res, 503, {{"error", "cannot open session"}});
        return;
    }
    auto session_key = session_token_hash(*id);
    auth.sessions.emplace(session_key, session);
    persist_sessions(auth);
    res.set_header("Set-Cookie",
                   "kasumi_session=" + *id + "; Max-Age=" +
                       std::to_string(kCookieMaxAgeSeconds) + cookie_flags);
    reply(res,
          200,
          {{"authenticated", true}, {"csrf_token", encode_hex(session.csrf)}});
}

void authenticate(WebAuth& auth,
                  const httplib::Request& req,
                  httplib::Response& res) {
    const auto cookie = session_cookie(req);
    std::unique_lock lock(auth.mutex);
    if (req.path == "/v1/auth/status") {
        const auto* session = lookup(auth, cookie);
        json info{{"configured", !auth.salt.empty()},
                  {"authenticated", session != nullptr}};
        if (session) {
            info["csrf_token"] = encode_hex(session->csrf);
            info["username"] = auth.username;
        }
        reply(res, 200, info);
        return;
    }
    const std::string flags =
        std::string("; Path=/; HttpOnly; SameSite=Strict") +
        (proxy_https(req) ? "; Secure" : "");
    if (req.path == "/v1/auth/logout") {
        if (!cookie.empty()) {
            auth.sessions.erase(std::string{cookie});
            if (cookie.size() == kTokenSize * 2)
                auth.sessions.erase(session_token_hash(cookie));
            persist_sessions(auth);
        }
        res.set_header("Set-Cookie", "kasumi_session=; Max-Age=0" + flags);
        reply(res, 200, {{"authenticated", false}});
        return;
    }
    lock.unlock();
    auto body = parse_body(req);
    lock.lock();
    if (req.path == "/v1/auth/password")
        change_password(auth, lock, req, res, *body, cookie, flags);
    else if (req.path == "/v1/auth/username")
        change_username(auth, lock, req, res, *body, cookie);
    else
        login(auth, lock, req, res, *body, flags);
}

bool valid_mutation_content_type(const httplib::Request& req) {
    // The routing guard runs before cpp-httplib reads the body. Only a
    // request explicitly framed as empty may omit Content-Type.
    if (!req.has_header("Content-Type")) {
        return !req.has_header("Transfer-Encoding") &&
               req.get_header_value_count("Content-Length") == 1 &&
               req.get_header_value("Content-Length") == "0";
    }
    const auto type = req.get_header_value("Content-Type");
    return req.get_header_value_count("Content-Type") == 1 &&
           httplib::detail::case_ignore::equal(
               httplib::detail::trim_copy(type.substr(0, type.find(';'))),
               "application/json");
}

bool is_safe_static_path(std::string_view path) noexcept {
    if (path.empty() || path.front() != '/' || path.size() > 512)
        return false;
    if (path.find("..") != std::string_view::npos ||
        path.find("//") != std::string_view::npos ||
        path.find('\\') != std::string_view::npos)
        return false;
    for (const char raw_ch : path) {
        const auto ch = static_cast<unsigned char>(raw_ch);
        if (ch < 0x20 || ch == 0x7f)
            return false;
    }
    return path != "/v1" && !path.starts_with("/v1/");
}

} // namespace

void install_web_security(WebAuth& auth,
                          httplib::Server& server,
                          const WebListener& listener,
                          int port,
                          std::span<const std::uint8_t, kTokenSize> ipc_token,
                          bool ipc,
                          bool browser) {
    using Result = httplib::Server::HandlerResponse;
    server.set_default_headers({{"Content-Security-Policy",
                                 "default-src 'self'; object-src 'none'; "
                                 "frame-ancestors 'none'; base-uri 'none'"},
                                {"X-Content-Type-Options", "nosniff"},
                                {"Cache-Control", "no-store"},
                                {"Referrer-Policy", "no-referrer"}});
    server.set_pre_routing_handler(
        [&auth, listener, port, ipc_token, ipc, browser](
            const httplib::Request& req, httplib::Response& res) {
            auto deny = [&] {
                reply(res,
                      403,
                      {{"code", "invalid_credential"}, {"error", "forbidden"}});
                return Result::Handled;
            };
            const bool write = req.method != "GET" && req.method != "HEAD";
            const auto check_body = [&] {
                const bool is_icon_upload =
                    req.method == "POST" &&
                    req.path.starts_with("/v1/profiles/") &&
                    req.path.ends_with("/icon");
                if (!is_icon_upload) {
                    std::size_t content_len = req.body.size();
                    if (req.has_header("Content-Length")) {
                        const auto raw_len =
                            req.get_header_value("Content-Length");
                        std::size_t parsed = 0;
                        const auto [end, ec] =
                            std::from_chars(raw_len.data(),
                                            raw_len.data() + raw_len.size(),
                                            parsed);
                        if (ec == std::errc{} &&
                            end == raw_len.data() + raw_len.size()) {
                            content_len = (std::max)(content_len, parsed);
                        }
                    }
                    if (content_len > 65536U) {
                        reply(res, 413, {{"error", "payload too large"}});
                        return Result::Handled;
                    }
                }
                if (write && !valid_mutation_content_type(req)) {
                    reply(res, 415, {{"error", "expected application/json"}});
                    return Result::Handled;
                }
                return Result::Unhandled;
            };
            if (req.has_header("X-Kasumi-Daemon-Token")) {
                if (ipc &&
                    validate_ipc_request_headers(
                        req, static_cast<std::uint16_t>(port), ipc_token))
                    return check_body();
                return deny();
            }
            if (!browser)
                return deny();
            const auto host = req.get_header_value("Host");
            if (req.get_header_value_count("Host") != 1 ||
                !host_allowed(listener, host, port))
                return deny();
            if (write && !same_origin(req, host))
                return deny();
            if (check_body() == Result::Handled)
                return Result::Handled;
            if (!write && is_safe_static_path(req.path))
                return Result::Unhandled;
            if ((!write && req.path == "/v1/auth/status") ||
                (req.method == "POST" && (req.path == "/v1/auth/login" ||
                                          req.path == "/v1/auth/password")))
                return Result::Unhandled;
            std::lock_guard lock(auth.mutex);
            auto* s = lookup(auth, session_cookie(req));
            if (!s || (write && !verify_csrf(req, *s)))
                return deny();
            const auto now = WebClock::now();
            s->idle = now + kSessionIdleTtl;
            if (now - s->last_persisted >= kSessionPersistInterval) {
                s->last_persisted = now;
                persist_sessions(auth);
            }
            return Result::Unhandled;
        });
    server.set_post_routing_handler(
        [](const httplib::Request& req, httplib::Response&) {
            // cpp-httplib owns a mutable Request until dispatch and response
            // writing finish.
            auto& bytes = const_cast<std::string&>(req.body);
            crypto::secure_memory::wipe(bytes.data(), bytes.size());
        });
    server.set_exception_handler(
        [](const auto&, auto& res, std::exception_ptr exception) {
            try {
                std::rethrow_exception(exception);
            } catch (const HttpError& err) {
                Json body{{"error", err.message}};
                if (!err.code.empty())
                    body["code"] = err.code;
                if (!err.active_operation.empty())
                    body["active_operation"] = err.active_operation;
                reply(res, err.status, std::move(body));
            } catch (const json::exception&) {
                reply(res, 400, {{"error", "invalid request field"}});
            } catch (...) {
                reply(res, 500, {{"error", "internal error"}});
            }
        });
    const auto handle = [&auth](const auto& req, auto& res) {
        authenticate(auth, req, res);
    };
    server.Get("/v1/auth/status", handle);
    server.Post("/v1/auth/login", handle);
    server.Post("/v1/auth/password", handle);
    server.Post("/v1/auth/username", handle);
    server.Post("/v1/auth/logout", handle);
}

} // namespace kasumi::application::daemon_detail

namespace kasumi::application {

std::expected<void, DaemonError>
set_web_password(const ExecutionEnvironment& environment,
                 std::string_view password,
                 std::optional<std::string_view> username) {
    using crypto::secure_memory::WipeGuard;
    using daemon_detail::encode_hex;
    using json = nlohmann::json;

    if (!daemon_detail::valid_new_web_password(password)) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::InvalidCredential,
            .detail =
                "web password requires 8 characters and at most 1024 bytes",
        });
    }
    std::error_code dir_ec;
    std::filesystem::create_directories(environment.app_data_dir, dir_ec);
    if (dir_ec) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::StorageFailure,
            .detail =
                "cannot create application data directory: " + dir_ec.message(),
        });
    }
    std::string account = "admin";
    if (username) {
        account = *username;
    } else {
        auto previous = daemon_detail::read_optional(environment.app_data_dir /
                                                     "web-password.json");
        if (!previous) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::StorageFailure,
                .detail = previous.error(),
            });
        }
        if (previous->is_object())
            account = daemon_detail::auth_field(*previous, "username").empty()
                          ? "admin"
                          : std::string{daemon_detail::auth_field(*previous,
                                                                  "username")};
        daemon_detail::scrub_json(&*previous);
    }
    if (!daemon_detail::valid_web_username(account)) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::InvalidCredential,
            .detail = "invalid Web UI username",
        });
    }
    auto salt = platform::random::hex_id(32);
    if (!salt) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::StorageFailure,
            .detail = "random source unavailable",
        });
    }
    WipeGuard wipe_salt(*salt);
    auto key = runtime::vault::derive_web_password_verifier(password, *salt);
    if (!key) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::InvalidCredential,
            .detail = "cannot derive password verifier",
        });
    }
    WipeGuard wipe(*key);
    auto encoded = encode_hex(*key);
    WipeGuard wipe_encoded(encoded);
    auto verifier =
        json{{"username", account}, {"salt", *salt}, {"hash", encoded}};
    auto serialized = verifier.dump();
    WipeGuard wipe_serialized(serialized);
    daemon_detail::scrub_json(&verifier);

    if (!platform::private_storage::write_atomically(
            environment.app_data_dir / "web-password.json", serialized)) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::StorageFailure,
            .detail = "cannot store web password",
        });
    }
    std::error_code ec;
    std::filesystem::remove(environment.app_data_dir / "web-bootstrap.token",
                            ec);
    std::filesystem::remove(environment.app_data_dir / "web-sessions.json", ec);
    return {};
}

std::expected<WebListenerConfig, DaemonError>
read_web_listener_config(const ExecutionEnvironment& environment) {
    auto config =
        daemon_detail::read_optional(environment.app_data_dir / "web.json");
    if (!config) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::ConfigFailure,
            .detail = config.error(),
        });
    }
    auto parsed = daemon_detail::parse_web_listener(*config);
    if (!parsed) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::ConfigFailure,
            .detail = parsed.error(),
        });
    }
    return *parsed;
}

std::expected<WebListenerConfig, DaemonError>
write_web_listener_config(const ExecutionEnvironment& environment,
                          const WebListenerConfig& config) {
    using json = nlohmann::json;
    if (config.port < 0 || config.port > 65535 ||
        !daemon_detail::is_valid_bind_address(config.bind)) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::ConfigFailure,
            .detail = "invalid web listener bind address or port",
        });
    }
    for (const auto& host : config.allowed_hosts) {
        if (!daemon_detail::is_valid_allowed_host(host)) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::ConfigFailure,
                .detail = "invalid allowed host entry",
            });
        }
    }
    if (!daemon_detail::is_loopback_bind(config.bind)) {
        auto verifier = daemon_detail::read_optional(environment.app_data_dir /
                                                     "web-password.json");
        if (!verifier || verifier->is_null()) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::InvalidCredential,
                .detail =
                    "configure a web password before binding outside loopback",
            });
        }
    }
    std::error_code dir_ec;
    std::filesystem::create_directories(environment.app_data_dir, dir_ec);
    if (dir_ec) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::StorageFailure,
            .detail =
                "cannot create application data directory: " + dir_ec.message(),
        });
    }
    const auto serialized = json{{"bind", config.bind},
                                 {"port", config.port},
                                 {"allowed_hosts", config.allowed_hosts},
                                 {"skip_host_check", config.skip_host_check}}
                                .dump(2) +
                            "\n";
    if (!platform::private_storage::write_atomically(
            environment.app_data_dir / "web.json", serialized)) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::StorageFailure,
            .detail = "cannot store web listener configuration",
        });
    }
    return config;
}

} // namespace kasumi::application
