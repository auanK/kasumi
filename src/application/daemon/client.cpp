#include "application/daemon.hpp"
#include "application/daemon/defaults.hpp"
#include "application/daemon/error_classification.hpp"
#include "application/daemon/event_log.hpp"
#include "application/daemon/ipc_security.hpp"
#include "application/detail.hpp"
#include "application/use_cases/context.hpp"
#include "platform/autostart.hpp"
#include "platform/machine.hpp"
#include "platform/path.hpp"
#include "platform/profile_lock.hpp"
#include "runtime/paths.hpp"
#include "runtime/profile.hpp"
#include "runtime/resolver.hpp"
#include "runtime/vault.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <exception>
#include <expected>
#include <filesystem>
#include <format>
#include <httplib.h>
#include <monocypher.h>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifndef KASUMI_VERSION
#define KASUMI_VERSION "0.26.0"
#endif

namespace kasumi::application {
namespace {

using daemon_detail::kDaemonApiVersion;
using daemon_detail::kDefaultSyncIntervalSeconds;

std::optional<DaemonErrorCode>
parse_error_code_string(std::string_view s) noexcept {
    if (s == "daemon_already_running") {
        return DaemonErrorCode::AlreadyRunning;
    }
    if (s == "daemon_not_running") {
        return DaemonErrorCode::NotRunning;
    }
    if (s == "profile_not_found") {
        return DaemonErrorCode::ProfileNotFound;
    }
    if (s == "credentials_invalid") {
        return DaemonErrorCode::InvalidCredential;
    }
    if (s == "lock_busy") {
        return DaemonErrorCode::LockBusy;
    }
    if (s == "ipc_failure") {
        return DaemonErrorCode::IpcFailure;
    }
    if (s == "config_failure") {
        return DaemonErrorCode::ConfigFailure;
    }
    if (s == "storage_failure") {
        return DaemonErrorCode::StorageFailure;
    }
    if (s == "unsupported") {
        return DaemonErrorCode::Unsupported;
    }
    if (s == "timeout") {
        return DaemonErrorCode::Timeout;
    }
    return std::nullopt;
}

DaemonAutostartStatus to_app_autostart(const platform::AutostartStatus& src) {
    return DaemonAutostartStatus{
        .supported = src.supported,
        .installed = src.installed,
        .systemd_enabled = src.systemd_enabled,
        .method = src.method,
        .location = src.location,
        .command = src.command,
        .detail = src.detail,
    };
}

ExecutionEnvironment normalize_env(const ExecutionEnvironment& env) {
    return env.app_data_dir.empty() ? default_execution_environment() : env;
}

struct IpcClientSession {
    httplib::Client client;
    daemon_detail::DaemonControlMetadata meta;
    ~IpcClientSession() noexcept {
        daemon_detail::wipe_control_metadata(meta);
    }
    IpcClientSession(httplib::Client c, daemon_detail::DaemonControlMetadata m)
        : client(std::move(c)), meta(std::move(m)) {
    }
    IpcClientSession(const IpcClientSession&) = delete;
    IpcClientSession& operator=(const IpcClientSession&) = delete;
    IpcClientSession(IpcClientSession&&) noexcept = default;
    IpcClientSession& operator=(IpcClientSession&&) noexcept = default;
};

std::expected<IpcClientSession, DaemonError>
open_ipc_client(const ExecutionEnvironment& env, int read_timeout_sec = 10) {
    const auto normalized = normalize_env(env);
    if (!is_daemon_running(normalized)) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::NotRunning,
            .detail = "daemon is not running",
        });
    }
    auto meta = daemon_detail::read_control_metadata(
        daemon_detail::daemon_control_path(normalized.app_data_dir));
    if (!meta) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::IpcFailure,
            .detail = meta.error(),
        });
    }
    httplib::Client client("127.0.0.1", meta->port);
    client.set_connection_timeout(std::chrono::seconds(2));
    client.set_read_timeout(read_timeout_sec, 0);
    client.set_write_timeout(5, 0);
    client.set_default_headers({
        {"Host", "127.0.0.1:" + std::to_string(meta->port)},
        {"X-Kasumi-Daemon-Token", meta->auth_token_hex},
    });
    return IpcClientSession{std::move(client), std::move(*meta)};
}

DaemonError parse_ipc_http_error(int status, const std::string& body) {
    std::string detail = "daemon IPC error (" + std::to_string(status) + ")";
    std::optional<DaemonErrorCode> parsed_code;
    try {
        const auto j = nlohmann::json::parse(body);
        if (j.contains("error") && j["error"].is_string()) {
            detail = j["error"].get<std::string>();
        }
        if (j.contains("code") && j["code"].is_string()) {
            parsed_code = parse_error_code_string(j["code"].get<std::string>());
        }
    } catch (...) {
    }
    DaemonErrorCode code = parsed_code.value_or(DaemonErrorCode::IpcFailure);
    if (!parsed_code.has_value()) {
        if (status == 404) {
            code = DaemonErrorCode::ProfileNotFound;
        } else if (status == 401 || status == 403) {
            code = DaemonErrorCode::InvalidCredential;
        } else if (status == 409) {
            code = DaemonErrorCode::LockBusy;
        } else if (status == 400) {
            code = DaemonErrorCode::ConfigFailure;
        }
    }
    return DaemonError{.code = code, .detail = std::move(detail)};
}

std::string url_encode_query(std::string_view input) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    for (const char raw : input) {
        const auto ch = static_cast<unsigned char>(raw);
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || ch == '-' || ch == '_') {
            out.push_back(raw);
        } else {
            out.push_back('%');
            out.push_back(kHex[(ch >> 4U) & 0x0FU]);
            out.push_back(kHex[ch & 0x0FU]);
        }
    }
    return out;
}

DaemonProfileState parse_profile_state(std::string_view s) noexcept {
    if (s == "pending_debounce") {
        return DaemonProfileState::PendingDebounce;
    }
    if (s == "running_sync") {
        return DaemonProfileState::RunningSync;
    }
    if (s == "paused") {
        return DaemonProfileState::Paused;
    }
    if (s == "locked") {
        return DaemonProfileState::Locked;
    }
    if (s == "backoff") {
        return DaemonProfileState::Backoff;
    }
    if (s == "needs_attention") {
        return DaemonProfileState::NeedsAttention;
    }
    return DaemonProfileState::Idle;
}

KeyStorage parse_app_key_storage(std::string_view s) noexcept {
    if (s == "file") {
        return KeyStorage::File;
    }
    if (s == "memory") {
        return KeyStorage::Memory;
    }
    return KeyStorage::Vault;
}

template <typename T>
std::optional<T> optional_field(const nlohmann::json& obj, const char* key) {
    if (!obj.contains(key) || obj[key].is_null()) {
        return std::nullopt;
    }
    return obj[key].get<T>();
}

DaemonStatusReport
build_offline_status_report(const ExecutionEnvironment& env,
                            std::optional<std::string_view> profile_name) {
    DaemonStatusReport report{
        .running = false,
        .api_version = kDaemonApiVersion,
        .kasumi_version = KASUMI_VERSION,
        .machine_name = platform::machine::host_name(),
    };
    if (const auto autostart = platform::query_user_autostart()) {
        report.autostart = to_app_autostart(*autostart);
    }
    if (const auto profs = list_profiles(env)) {
        for (const auto& p : *profs) {
            if (profile_name && p.name != *profile_name) {
                continue;
            }
            report.profiles.push_back(DaemonProfileStatus{
                .name = p.name,
                .key_storage = p.key_storage,
                .state = p.paused ? DaemonProfileState::Paused
                                  : (p.key_storage == KeyStorage::Memory
                                         ? DaemonProfileState::Locked
                                         : DaemonProfileState::Idle),
                .paused = p.paused,
                .locked = p.key_storage == KeyStorage::Memory,
                .watch_enabled = p.watch_enabled.value_or(true),
                .sync_interval_seconds = p.sync_interval_seconds.value_or(
                    kDefaultSyncIntervalSeconds),
                .local_dir = platform::path::to_utf8(p.local_dir),
                .remote_dir = p.remote_dir,
            });
        }
    }
    return report;
}

bool has_os_process_exited(std::uint64_t pid) noexcept {
    if (pid == 0) {
        return true;
    }
#if defined(_WIN32)
    if (pid == static_cast<std::uint64_t>(GetCurrentProcessId())) {
        return true;
    }
    HANDLE hp = OpenProcess(SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
    if (hp == nullptr) {
        return true;
    }
    const DWORD wait_rc = WaitForSingleObject(hp, 50);
    CloseHandle(hp);
    return wait_rc == WAIT_OBJECT_0 || wait_rc == WAIT_FAILED;
#else
    if (pid == static_cast<std::uint64_t>(::getpid())) {
        return true;
    }
    return ::kill(static_cast<pid_t>(pid), 0) != 0 && errno == ESRCH;
#endif
}

#if defined(_WIN32)
std::wstring quote_windows_cli_arg(std::wstring_view arg) {
    std::wstring out;
    out.push_back(L'"');
    std::size_t backslashes = 0;
    for (const wchar_t ch : arg) {
        if (ch == L'\\') {
            ++backslashes;
        } else if (ch == L'"') {
            out.append(backslashes * 2U + 1U, L'\\');
            out.push_back(L'"');
            backslashes = 0;
        } else {
            out.append(backslashes, L'\\');
            backslashes = 0;
            out.push_back(ch);
        }
    }
    out.append(backslashes * 2U, L'\\');
    out.push_back(L'"');
    return out;
}

std::vector<wchar_t> build_sanitized_windows_env(
    const std::optional<std::filesystem::path>& appdata_override) {
    wchar_t* raw_env = GetEnvironmentStringsW();
    if (raw_env == nullptr) {
        return {};
    }
    struct EnvStringsGuard {
        wchar_t* ptr;
        ~EnvStringsGuard() noexcept {
            if (ptr != nullptr) {
                FreeEnvironmentStringsW(ptr);
            }
        }
    } env_guard{raw_env};

    auto equals_ci = [](std::wstring_view a, std::wstring_view b) noexcept {
        if (a.size() != b.size()) {
            return false;
        }
        for (std::size_t i = 0; i < a.size(); ++i) {
            wchar_t ca = a[i];
            wchar_t cb = b[i];
            if (ca >= L'a' && ca <= L'z') {
                ca = static_cast<wchar_t>(ca - (L'a' - L'A'));
            }
            if (cb >= L'a' && cb <= L'z') {
                cb = static_cast<wchar_t>(cb - (L'a' - L'A'));
            }
            if (ca != cb) {
                return false;
            }
        }
        return true;
    };

    std::vector<std::wstring> entries;
    for (const wchar_t* cur = raw_env; *cur != L'\0';) {
        const std::size_t len = std::wcslen(cur);
        std::wstring_view entry{cur, len};
        cur += len + 1U;
        const std::size_t eq = entry.find(L'=', 1U);
        const std::wstring_view name = eq == std::wstring_view::npos
                                           ? std::wstring_view{}
                                           : entry.substr(0, eq);
        if (equals_ci(name, L"KASUMI_MASTER_KEY") ||
            equals_ci(name, L"KASUMI_PASSWORD") ||
            equals_ci(name, L"KASUMI_PASSWORD2")) {
            continue;
        }
        if (appdata_override && equals_ci(name, L"APPDATA")) {
            continue;
        }
        entries.emplace_back(entry);
    }
    if (appdata_override) {
        entries.push_back(L"APPDATA=" + appdata_override->wstring());
    }
    std::ranges::sort(
        entries, [](const std::wstring& a, const std::wstring& b) {
            const auto ka = a.substr(0, a.find(L'=', 1U));
            const auto kb = b.substr(0, b.find(L'=', 1U));
            return _wcsnicmp(ka.c_str(),
                             kb.c_str(),
                             std::min(ka.size(), kb.size())) < 0 ||
                   (_wcsnicmp(ka.c_str(),
                              kb.c_str(),
                              std::min(ka.size(), kb.size())) == 0 &&
                    ka.size() < kb.size());
        });

    std::vector<wchar_t> block;
    for (const auto& entry : entries) {
        block.insert(block.end(), entry.begin(), entry.end());
        block.push_back(L'\0');
    }
    block.push_back(L'\0');
    return block;
}
#endif

} // namespace

bool is_daemon_running(const ExecutionEnvironment& environment) noexcept {
    const auto normalized = normalize_env(environment);
    return platform::is_profile_lock_held(
        daemon_detail::daemon_lock_path(normalized.app_data_dir));
}

std::expected<DaemonStatusReport, DaemonError>
query_daemon_status(const ExecutionEnvironment& environment,
                    std::optional<std::string_view> profile_name) {
    const auto normalized = normalize_env(environment);
    if (!is_daemon_running(normalized)) {
        if (profile_name) {
            const auto profs = list_profiles(normalized);
            if (!profs || std::ranges::none_of(*profs, [&](const Profile& p) {
                    return p.name == *profile_name;
                })) {
                return std::unexpected(DaemonError{
                    .code = DaemonErrorCode::ProfileNotFound,
                    .detail =
                        "profile not found: " + std::string{*profile_name},
                });
            }
        }
        return build_offline_status_report(normalized, profile_name);
    }

    auto conn = open_ipc_client(normalized);
    if (!conn) {
        return std::unexpected(conn.error());
    }
    std::string path = "/v1/status";
    if (profile_name && !profile_name->empty()) {
        path += "?profile=" + url_encode_query(*profile_name);
    }
    const auto res = conn->client.Get(path);
    if (!res) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::IpcFailure,
            .detail = "failed to query daemon IPC endpoint",
        });
    }
    if (res->status != 200) {
        return std::unexpected(parse_ipc_http_error(res->status, res->body));
    }
    try {
        const auto doc = nlohmann::json::parse(res->body);
        DaemonStatusReport report{
            .running = doc.value("running", true),
            .api_version = doc.value("api_version", kDaemonApiVersion),
            .kasumi_version = doc.value("kasumi_version", std::string{}),
            .machine_name = doc.value("machine_name", std::string{}),
            .secure_pages_locked = doc.value("secure_pages_locked", false),
            .pid = doc.value("pid", std::uint64_t{0}),
            .started_at_unix = doc.value("started_at_unix", std::int64_t{0}),
            .uptime_seconds = doc.value("uptime_seconds", std::uint64_t{0}),
            .ipc_port = doc.value("ipc_port", std::uint16_t{0}),
            .web_port =
                doc.value("web_port", doc.value("ipc_port", std::uint16_t{0})),
        };
        if (doc.contains("autostart") && doc["autostart"].is_object()) {
            const auto& a = doc["autostart"];
            report.autostart = DaemonAutostartStatus{
                .supported = a.value("supported", true),
                .installed = a.value("installed", false),
                .systemd_enabled = a.value("systemd_enabled", false),
                .method = a.value("method", std::string{}),
                .location = a.value("location", std::string{}),
                .command = a.value("command", std::string{}),
                .detail = a.value("detail", std::string{}),
            };
        }
        if (doc.contains("profiles") && doc["profiles"].is_array()) {
            for (const auto& p : doc["profiles"]) {
                report.profiles.push_back(DaemonProfileStatus{
                    .name = p.value("name", std::string{}),
                    .key_storage = parse_app_key_storage(
                        p.value("key_storage", std::string{"vault"})),
                    .state = parse_profile_state(
                        p.value("state", std::string{"idle"})),
                    .paused = p.value("paused", false),
                    .locked = p.value("locked", false),
                    .watch_enabled = p.value("watch_enabled", true),
                    .watcher_active = p.value("watcher_active", false),
                    .watcher_degraded = p.value("watcher_degraded", false),
                    .warm_transport_active =
                        p.value("warm_transport_active", false),
                    .warm_cache_entries =
                        p.value("warm_cache_entries", std::size_t{0}),
                    .sync_interval_seconds = p.value(
                        "sync_interval_seconds", kDefaultSyncIntervalSeconds),
                    .local_dir = p.value("local_dir", std::string{}),
                    .remote_dir = p.value("remote_dir", std::string{}),
                    .dirty_paths_count =
                        p.value("dirty_paths_count", std::size_t{0}),
                    .active_stage = p.value("active_stage", std::string{}),
                    .active_item_path =
                        p.value("active_item_path", std::string{}),
                    .active_item_bytes =
                        optional_field<std::uint64_t>(p, "active_item_bytes"),
                    .active_item_total_bytes = optional_field<std::uint64_t>(
                        p, "active_item_total_bytes"),
                    .active_objects =
                        p.value("active_objects", std::uint64_t{0}),
                    .active_total_objects = optional_field<std::uint64_t>(
                        p, "active_total_objects"),
                    .active_bytes = p.value("active_bytes", std::uint64_t{0}),
                    .active_total_bytes =
                        optional_field<std::uint64_t>(p, "active_total_bytes"),
                    .sync_phase = p.value("sync_phase", std::string{}),
                    .sync_applied_items =
                        optional_field<std::uint32_t>(p, "sync_applied_items"),
                    .sync_total_items =
                        optional_field<std::uint32_t>(p, "sync_total_items"),
                    .active_bytes_per_second =
                        optional_field<double>(p, "active_bytes_per_second"),
                    .last_sync_started_at =
                        optional_field<std::int64_t>(p, "last_sync_started_at"),
                    .last_sync_finished_at = optional_field<std::int64_t>(
                        p, "last_sync_finished_at"),
                    .last_checked_at =
                        optional_field<std::int64_t>(p, "last_checked_at"),
                    .next_sync_at =
                        optional_field<std::int64_t>(p, "next_sync_at"),
                    .backoff_until_unix =
                        optional_field<std::int64_t>(p, "backoff_until_unix"),
                    .backoff_seconds =
                        p.value("backoff_seconds", std::uint32_t{0}),
                    .consecutive_failures =
                        p.value("consecutive_failures", std::uint32_t{0}),
                    .sync_runs = p.value("sync_runs", std::uint64_t{0}),
                    .fast_noop_polls =
                        p.value("fast_noop_polls", std::uint64_t{0}),
                    .last_outcome = p.value("last_outcome", std::string{}),
                    .last_error = p.value("last_error", std::string{}),
                });
            }
        }
        return report;
    } catch (const std::exception&) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::IpcFailure,
            .detail = "invalid status JSON from daemon",
        });
    }
}

std::expected<DaemonLogsReport, DaemonError>
query_daemon_events(const ExecutionEnvironment& environment,
                    const DaemonLogQuery& query) {
    const auto normalized = normalize_env(environment);
    if (!is_daemon_running(normalized)) {
        return daemon_detail::merge_daemon_log_events(
            normalized.app_data_dir, nullptr, query);
    }
    auto conn = open_ipc_client(normalized);
    if (!conn) {
        return daemon_detail::merge_daemon_log_events(
            normalized.app_data_dir, nullptr, query);
    }
    const std::size_t limit =
        query.max_lines == 0 ? 100U
                             : std::min<std::size_t>(query.max_lines, 1000U);
    std::string path =
        std::format("/v1/events?since={}&limit={}", query.since_seq, limit);
    if (query.profile_name && !query.profile_name->empty()) {
        path += "&profile=" + url_encode_query(*query.profile_name);
    }
    const auto res = conn->client.Get(path);
    if (!res) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::IpcFailure,
            .detail = "failed to query daemon events",
        });
    }
    if (res->status != 200) {
        return std::unexpected(parse_ipc_http_error(res->status, res->body));
    }
    try {
        const auto doc = nlohmann::json::parse(res->body);
        DaemonLogsReport report{
            .log_path = doc.value("log_path", std::string{}),
            .latest_seq = doc.value("latest_seq", std::uint64_t{0}),
        };
        if (doc.contains("events") && doc["events"].is_array()) {
            for (const auto& item : doc["events"]) {
                report.events.push_back(DaemonEvent{
                    .seq = item.value("seq", std::uint64_t{0}),
                    .timestamp_unix = item.value("ts", std::int64_t{0}),
                    .profile_name = item.value("profile", std::string{}),
                    .kind = item.value("kind", std::string{}),
                    .detail = item.value("detail", std::string{}),
                });
            }
        }
        return report;
    } catch (const std::exception&) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::IpcFailure,
            .detail = "invalid events JSON from daemon",
        });
    }
}

std::expected<void, DaemonError>
stop_running_daemon(const ExecutionEnvironment& environment) {
    const auto normalized = normalize_env(environment);
    std::uint64_t daemon_pid = 0;
    {
        auto conn = open_ipc_client(normalized);
        if (!conn) {
            return std::unexpected(conn.error());
        }
        daemon_pid = conn->meta.pid;
        const auto res =
            conn->client.Post("/v1/stop", "{}", "application/json");
        if (!res) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::IpcFailure,
                .detail = "failed to send stop command to daemon",
            });
        }
        if (res->status != 200) {
            return std::unexpected(
                parse_ipc_http_error(res->status, res->body));
        }
    }
    // Wait up to 10 seconds for daemon.lock release AND full OS process exit so
    // temp directories and files are never still open when stop returns.
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{10};
    while (std::chrono::steady_clock::now() < deadline) {
        if (!is_daemon_running(normalized) &&
            has_os_process_exited(daemon_pid)) {
            return {};
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{25});
    }
    return std::unexpected(DaemonError{
        .code = DaemonErrorCode::Timeout,
        .detail = "daemon acknowledged stop but is still shutting down",
    });
}

std::expected<DaemonSyncTriggerReport, DaemonError>
trigger_daemon_sync(const ExecutionEnvironment& environment,
                    std::optional<std::string_view> profile_name,
                    bool wait) {
    const auto normalized = normalize_env(environment);
    auto conn = open_ipc_client(normalized, wait ? 300 : 10);
    if (!conn) {
        return std::unexpected(conn.error());
    }
    nlohmann::json payload{{"wait", wait}};
    if (profile_name && !profile_name->empty()) {
        payload["profile"] = std::string{*profile_name};
    }
    const auto res =
        conn->client.Post("/v1/sync", payload.dump(), "application/json");
    if (!res) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::IpcFailure,
            .detail = "failed to trigger daemon sync",
        });
    }
    if (res->status != 200) {
        return std::unexpected(parse_ipc_http_error(res->status, res->body));
    }
    try {
        const auto doc = nlohmann::json::parse(res->body);
        DaemonSyncTriggerReport report{
            .completed = doc.value("completed", false),
        };
        if (doc.contains("profiles") && doc["profiles"].is_array()) {
            for (const auto& item : doc["profiles"]) {
                if (item.is_string()) {
                    report.profiles.push_back(item.get<std::string>());
                }
            }
        }
        if (doc.contains("failures") && doc["failures"].is_array()) {
            for (const auto& item : doc["failures"]) {
                report.failures.emplace_back(
                    item.value("profile", std::string{}),
                    item.value("detail", std::string{}));
            }
        }
        return report;
    } catch (const std::exception&) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::IpcFailure,
            .detail = "invalid sync trigger response from daemon",
        });
    }
}

namespace {

std::expected<void, DaemonError>
post_profile_ipc(const ExecutionEnvironment& environment,
                 std::string_view endpoint,
                 std::string_view profile_name) {
    auto conn = open_ipc_client(environment);
    if (!conn) {
        return std::unexpected(conn.error());
    }
    const auto res = conn->client.Post(
        std::string{endpoint},
        nlohmann::json{{"profile", std::string{profile_name}}}.dump(),
        "application/json");
    if (!res) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::IpcFailure,
            .detail = "failed to contact daemon IPC endpoint",
        });
    }
    if (res->status != 200) {
        return std::unexpected(parse_ipc_http_error(res->status, res->body));
    }
    return {};
}

std::expected<void, DaemonError>
set_offline_profile_paused(const ExecutionEnvironment& environment,
                           std::string_view profile_name,
                           bool paused) {
    if (auto updated = set_profile_paused(environment, profile_name, paused);
        !updated) {
        return std::unexpected(DaemonError{
            .code = daemon_detail::map_profile_pause_error_code(
                updated.error().code),
            .detail = updated.error().detail,
        });
    }
    return {};
}

} // namespace

std::expected<void, DaemonError>
cancel_daemon_profile(const ExecutionEnvironment& environment,
                      std::string_view profile_name) {
    return post_profile_ipc(
        normalize_env(environment), "/v1/cancel", profile_name);
}

std::expected<void, DaemonError>
pause_daemon_profile(const ExecutionEnvironment& environment,
                     std::string_view profile_name) {
    const auto normalized = normalize_env(environment);
    if (!is_daemon_running(normalized)) {
        return set_offline_profile_paused(normalized, profile_name, true);
    }
    return post_profile_ipc(normalized, "/v1/pause", profile_name);
}

std::expected<void, DaemonError>
resume_daemon_profile(const ExecutionEnvironment& environment,
                      std::string_view profile_name) {
    const auto normalized = normalize_env(environment);
    if (!is_daemon_running(normalized)) {
        return set_offline_profile_paused(normalized, profile_name, false);
    }
    return post_profile_ipc(normalized, "/v1/resume", profile_name);
}

std::expected<void, DaemonError>
unlock_daemon_profile(const ExecutionEnvironment& environment,
                      std::string_view profile_name,
                      ProfileCredentials credentials) {
    struct CredsGuard {
        ProfileCredentials& creds;
        ~CredsGuard() noexcept {
            wipe_credentials(creds);
        }
    } creds_guard{credentials};

    const auto normalized = normalize_env(environment);
    auto conn = open_ipc_client(normalized, 30);
    if (!conn) {
        return std::unexpected(conn.error());
    }

    auto key_bytes_vec = daemon_detail::decode_hex(conn->meta.ipc_key_hex,
                                                   daemon_detail::kTokenSize);
    if (!key_bytes_vec) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::IpcFailure,
            .detail = key_bytes_vec.error(),
        });
    }
    detail::WipedBytes<daemon_detail::kTokenSize> ipc_key;
    std::memcpy(
        ipc_key.data.data(), key_bytes_vec->data(), ipc_key.data.size());
    crypto_wipe(key_bytes_vec->data(), key_bytes_vec->size());

    const auto rt = runtime::resolve(normalized.app_data_dir,
                                     profile_name,
                                     runtime::AccessMode::ReadOnly,
                                     false);
    if (!rt) {
        return std::unexpected(DaemonError{
            .code = rt.error().code == runtime::ErrorCode::ProfileNotFound
                        ? DaemonErrorCode::ProfileNotFound
                        : DaemonErrorCode::ConfigFailure,
            .detail = rt.error().detail,
        });
    }

    Credentials generic_creds = NoCredentials{};
    if (const auto* hex = std::get_if<MasterKeyHex>(&credentials)) {
        generic_creds = MasterKeyHex{hex->value};
    } else if (const auto* bytes = std::get_if<MasterKeyBytes>(&credentials)) {
        generic_creds = MasterKeyBytes{bytes->bytes};
    } else if (const auto* pair = std::get_if<PasswordPair>(&credentials)) {
        generic_creds = PasswordPair{pair->password, pair->salt_password};
    }
    struct GenericGuard {
        Credentials& creds;
        ~GenericGuard() noexcept {
            wipe_credentials(creds);
        }
    } generic_guard{generic_creds};

    detail::WipedBytes<runtime::vault::KEY_SIZE> candidate;
    const auto resolved_key = detail::resolve_vault_key<DaemonError>(
        generic_creds,
        *rt,
        candidate.data,
        detail::VaultKeyPolicy<DaemonError>{
            .read_only = true,
            .missing_code = DaemonErrorCode::InvalidCredential,
            .mismatch_code = DaemonErrorCode::InvalidCredential,
            .io_code = DaemonErrorCode::StorageFailure,
            .credential_code = DaemonErrorCode::InvalidCredential,
            .missing_detail = "credentials are required",
        },
        [](DaemonErrorCode code, std::string detail) {
            return DaemonError{.code = code, .detail = std::move(detail)};
        });
    if (!resolved_key) {
        return std::unexpected(resolved_key.error());
    }

    const auto sealed = daemon_detail::seal_key_payload(
        ipc_key.data, candidate.data, profile_name);
    if (!sealed) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::IpcFailure,
            .detail = sealed.error(),
        });
    }
    const nlohmann::json body{
        {"profile", std::string{profile_name}},
        {"nonce", sealed->nonce_hex},
        {"mac", sealed->mac_hex},
        {"ciphertext", sealed->ciphertext_hex},
    };
    const auto res =
        conn->client.Post("/v1/unlock", body.dump(), "application/json");
    if (!res) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::IpcFailure,
            .detail = "failed to send unlock command to daemon",
        });
    }
    if (res->status != 200) {
        return std::unexpected(parse_ipc_http_error(res->status, res->body));
    }
    return {};
}

std::expected<void, DaemonError>
lock_daemon_profile(const ExecutionEnvironment& environment,
                    std::string_view profile_name) {
    return post_profile_ipc(
        normalize_env(environment), "/v1/lock", profile_name);
}

std::expected<void, DaemonError>
reload_running_daemon(const ExecutionEnvironment& environment) {
    auto conn = open_ipc_client(normalize_env(environment));
    if (!conn) {
        return std::unexpected(conn.error());
    }
    const auto res = conn->client.Post("/v1/reload", "{}", "application/json");
    if (!res) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::IpcFailure,
            .detail = "failed to reload running daemon",
        });
    }
    if (res->status != 200) {
        return std::unexpected(parse_ipc_http_error(res->status, res->body));
    }
    return {};
}

std::expected<DaemonStatusReport, DaemonError>
spawn_background_daemon(const ExecutionEnvironment& environment,
                        const std::optional<std::filesystem::path>& log_file) {
    const auto normalized = normalize_env(environment);
    if (is_daemon_running(normalized)) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::AlreadyRunning,
            .detail = "daemon is already running",
        });
    }
    const auto exe = platform::current_executable_path();
    if (!exe) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::StorageFailure,
            .detail = exe.error(),
        });
    }

    std::optional<std::filesystem::path> parent_dir_override;
    if (normalized.app_data_dir.filename() == "kasumi" &&
        !normalized.app_data_dir.parent_path().empty()) {
        parent_dir_override = normalized.app_data_dir.parent_path();
    }

#if defined(_WIN32)
    std::wstring cmd = quote_windows_cli_arg(exe->wstring()) + L" daemon run";
    if (log_file && !log_file->empty()) {
        cmd += L" --log-file " + quote_windows_cli_arg(log_file->wstring());
    }
    std::wstring mutable_cmd = cmd;
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE nul_in = CreateFileW(L"NUL",
                                GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                &sa,
                                OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL,
                                nullptr);
    HANDLE nul_out = CreateFileW(L"NUL",
                                 GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 &sa,
                                 OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL,
                                 nullptr);

    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput =
        nul_in != INVALID_HANDLE_VALUE ? nul_in : nullptr;
    si.StartupInfo.hStdOutput =
        nul_out != INVALID_HANDLE_VALUE ? nul_out : nullptr;
    si.StartupInfo.hStdError =
        nul_out != INVALID_HANDLE_VALUE ? nul_out : nullptr;

    HANDLE inherit_handles[2]{};
    DWORD inherit_count = 0;
    if (nul_in != INVALID_HANDLE_VALUE) {
        inherit_handles[inherit_count++] = nul_in;
    }
    if (nul_out != INVALID_HANDLE_VALUE) {
        inherit_handles[inherit_count++] = nul_out;
    }

    std::vector<unsigned char> attr_buf;
    bool attr_list_ready = false;
    if (inherit_count > 0) {
        SIZE_T attr_size = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
        if (attr_size > 0) {
            attr_buf.resize(attr_size);
            si.lpAttributeList =
                reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_buf.data());
            if (InitializeProcThreadAttributeList(
                    si.lpAttributeList, 1, 0, &attr_size) &&
                UpdateProcThreadAttribute(si.lpAttributeList,
                                          0,
                                          PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                          inherit_handles,
                                          static_cast<SIZE_T>(inherit_count) *
                                              sizeof(HANDLE),
                                          nullptr,
                                          nullptr)) {
                attr_list_ready = true;
            }
        }
    }

    auto env_block = build_sanitized_windows_env(parent_dir_override);
    std::error_code cwd_ec;
    auto neutral_cwd = std::filesystem::temp_directory_path(cwd_ec);
    if (cwd_ec || neutral_cwd.empty()) {
        neutral_cwd = exe->parent_path();
    }

    PROCESS_INFORMATION pi{};
    const DWORD creation_flags =
        DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW |
        CREATE_UNICODE_ENVIRONMENT |
        (attr_list_ready ? EXTENDED_STARTUPINFO_PRESENT : 0UL);
    const BOOL ok =
        CreateProcessW(exe->c_str(),
                       mutable_cmd.data(),
                       nullptr,
                       nullptr,
                       attr_list_ready ? TRUE : FALSE,
                       creation_flags,
                       env_block.empty() ? nullptr : env_block.data(),
                       neutral_cwd.empty() ? nullptr : neutral_cwd.c_str(),
                       &si.StartupInfo,
                       &pi);
    const DWORD last_error = ok ? 0 : GetLastError();
    if (attr_list_ready) {
        DeleteProcThreadAttributeList(si.lpAttributeList);
    }
    if (nul_in != INVALID_HANDLE_VALUE) {
        CloseHandle(nul_in);
    }
    if (nul_out != INVALID_HANDLE_VALUE) {
        CloseHandle(nul_out);
    }
    if (!ok) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::StorageFailure,
            .detail = "CreateProcessW failed (" +
                      std::to_string(static_cast<unsigned long>(last_error)) +
                      ")",
        });
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
#else
    const pid_t pid = ::fork();
    if (pid < 0) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::StorageFailure,
            .detail = "fork failed with errno " + std::to_string(errno),
        });
    }
    if (pid == 0) {
        static_cast<void>(::setsid());
        const pid_t grand = ::fork();
        if (grand < 0) {
            ::_exit(127);
        }
        if (grand > 0) {
            ::_exit(0);
        }
        if (::chdir("/") != 0) {
        }
        static_cast<void>(::unsetenv("KASUMI_MASTER_KEY"));
        static_cast<void>(::unsetenv("KASUMI_PASSWORD"));
        static_cast<void>(::unsetenv("KASUMI_PASSWORD2"));
        if (parent_dir_override) {
            const std::string xdg_utf8 =
                platform::path::to_utf8(*parent_dir_override);
            static_cast<void>(::setenv("XDG_CONFIG_HOME", xdg_utf8.c_str(), 1));
        }
        const int devnull = ::open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            static_cast<void>(::dup2(devnull, STDIN_FILENO));
            static_cast<void>(::dup2(devnull, STDOUT_FILENO));
            static_cast<void>(::dup2(devnull, STDERR_FILENO));
            if (devnull > 2) {
                static_cast<void>(::close(devnull));
            }
        }
        const std::string exe_utf8 = platform::path::to_utf8(*exe);
        std::string log_utf8;
        std::vector<char*> argv{
            const_cast<char*>(exe_utf8.c_str()),
            const_cast<char*>("daemon"),
            const_cast<char*>("run"),
        };
        if (log_file && !log_file->empty()) {
            log_utf8 = platform::path::to_utf8(*log_file);
            argv.push_back(const_cast<char*>("--log-file"));
            argv.push_back(const_cast<char*>(log_utf8.c_str()));
        }
        argv.push_back(nullptr);
        ::execv(exe_utf8.c_str(), argv.data());
        ::_exit(127);
    }
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::StorageFailure,
            .detail = "background daemon launcher exited unexpectedly",
        });
    }
#endif

    // Poll briefly until the detached daemon acquires its lock and opens IPC.
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{10};
    while (std::chrono::steady_clock::now() < deadline) {
        if (is_daemon_running(normalized)) {
            auto st = query_daemon_status(normalized);
            if (st && st->running) {
                return *st;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{30});
    }
    return std::unexpected(DaemonError{
        .code = DaemonErrorCode::Timeout,
        .detail = "timed out waiting for background daemon startup",
    });
}

std::expected<DaemonAutostartStatus, DaemonError> install_daemon_autostart() {
    const auto exe = platform::current_executable_path();
    if (!exe) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::StorageFailure,
            .detail = exe.error(),
        });
    }
    const auto installed = platform::install_user_autostart(*exe);
    if (!installed) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::StorageFailure,
            .detail = installed.error(),
        });
    }
    return to_app_autostart(*installed);
}

std::expected<DaemonAutostartStatus, DaemonError> uninstall_daemon_autostart() {
    const auto removed = platform::uninstall_user_autostart();
    if (!removed) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::StorageFailure,
            .detail = removed.error(),
        });
    }
    return to_app_autostart(*removed);
}

std::expected<DaemonAutostartStatus, DaemonError> query_daemon_autostart() {
    const auto queried = platform::query_user_autostart();
    if (!queried) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::StorageFailure,
            .detail = queried.error(),
        });
    }
    return to_app_autostart(*queried);
}

} // namespace kasumi::application
