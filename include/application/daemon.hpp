#ifndef KASUMI_APPLICATION_DAEMON_HPP
#define KASUMI_APPLICATION_DAEMON_HPP

#include "application/credentials.hpp"
#include "application/environment.hpp"
#include "application/profile.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kasumi::application {

enum class DaemonProfileState : std::uint8_t {
    Idle,
    PendingDebounce,
    RunningSync,
    Paused,
    Locked,
    Backoff,
    NeedsAttention,
};

std::string_view to_string(DaemonProfileState state) noexcept;

enum class DaemonErrorCode : std::uint8_t {
    AlreadyRunning,
    NotRunning,
    ProfileNotFound,
    InvalidCredential,
    LockBusy,
    IpcFailure,
    ConfigFailure,
    StorageFailure,
    Unsupported,
    Timeout,
};

struct DaemonError {
    DaemonErrorCode code = DaemonErrorCode::IpcFailure;
    std::string detail;
};

struct DaemonEvent {
    std::uint64_t seq = 0;
    std::int64_t timestamp_unix = 0;
    std::string profile_name;
    std::string kind;
    std::string detail;
};

using DaemonEventCallback = std::function<void(const DaemonEvent&)>;

struct DaemonOptions {
    std::chrono::milliseconds watch_debounce{std::chrono::seconds{3}};
    std::chrono::milliseconds watch_max_wait{std::chrono::seconds{30}};
    std::chrono::milliseconds warm_transport_idle_ttl{std::chrono::minutes{15}};
    std::chrono::milliseconds full_scan_verification_interval{
        std::chrono::minutes{30}};
    std::chrono::milliseconds config_poll_interval{std::chrono::seconds{2}};
    std::chrono::milliseconds startup_stagger{std::chrono::seconds{3}};
    std::size_t max_parallel_profiles = 4;
    std::size_t max_parallel_per_remote = 2;
    bool enable_ipc_server = true;
    DaemonEventCallback on_event{};
};

struct DaemonAutostartStatus {
    bool supported = true;
    bool installed = false;
    bool systemd_enabled = false;
    std::string method;
    std::string location;
    std::string command;
    std::string detail;
};

struct DaemonProfileStatus {
    std::string name;
    KeyStorage key_storage = KeyStorage::Vault;
    DaemonProfileState state = DaemonProfileState::Idle;
    bool paused = false;
    bool locked = false;
    bool watch_enabled = true;
    bool watcher_active = false;
    bool watcher_degraded = false;
    bool warm_transport_active = false;
    std::size_t warm_cache_entries = 0;
    std::uint32_t sync_interval_seconds = 300;
    std::string local_dir;
    std::string remote_dir;
    std::size_t dirty_paths_count = 0;
    std::string active_stage;
    std::string active_item_path;
    std::optional<std::uint64_t> active_item_bytes = std::nullopt;
    std::optional<std::uint64_t> active_item_total_bytes = std::nullopt;
    std::uint64_t active_objects = 0;
    std::optional<std::uint64_t> active_total_objects = std::nullopt;
    std::uint64_t active_bytes = 0;
    std::optional<std::uint64_t> active_total_bytes = std::nullopt;
    std::string sync_phase{};
    std::optional<std::uint32_t> sync_applied_items = std::nullopt;
    std::optional<std::uint32_t> sync_total_items = std::nullopt;
    std::optional<double> active_bytes_per_second = std::nullopt;
    std::optional<std::int64_t> last_sync_started_at = std::nullopt;
    std::optional<std::int64_t> last_sync_finished_at = std::nullopt;
    std::optional<std::int64_t> last_checked_at = std::nullopt;
    std::optional<std::int64_t> next_sync_at = std::nullopt;
    std::optional<std::int64_t> backoff_until_unix = std::nullopt;
    std::uint32_t backoff_seconds = 0;
    std::uint32_t consecutive_failures = 0;
    std::uint64_t sync_runs = 0;
    std::uint64_t fast_noop_polls = 0;
    std::string last_outcome;
    std::string last_error;
    bool busy = false;
    std::string active_operation;
};

struct DaemonStatusReport {
    bool running = false;
    std::uint32_t api_version = 1;
    std::string kasumi_version;
    std::string machine_name;
    bool secure_pages_locked = false;
    std::uint64_t pid = 0;
    std::int64_t started_at_unix = 0;
    std::string daemon_instance;
    std::uint64_t uptime_seconds = 0;
    std::uint16_t ipc_port = 0;
    std::uint16_t web_port = 0;
    DaemonAutostartStatus autostart;
    std::vector<DaemonProfileStatus> profiles;
};

struct DaemonLogQuery {
    std::optional<std::string> profile_name = std::nullopt;
    std::size_t max_lines = 100;
    std::uint64_t since_seq = 0;
};

struct DaemonLogsReport {
    std::string log_path;
    std::uint64_t latest_seq = 0;
    std::vector<DaemonEvent> events;
};

struct DaemonSyncTriggerReport {
    std::vector<std::string> profiles;
    bool completed = false;
    std::vector<std::pair<std::string, std::string>> failures;
};

struct DaemonSessionState;
void destroy_daemon_session(DaemonSessionState* state) noexcept;

// Continuous multi-profile daemon session handle managed by free functions
// so both `kasumi daemon run` and embedded hosts share the same DoD engine.
struct DaemonSession {
    std::unique_ptr<DaemonSessionState, void (*)(DaemonSessionState*) noexcept>
        state{nullptr, &destroy_daemon_session};
};

std::expected<DaemonSession, DaemonError>
start_daemon_session(ExecutionEnvironment environment,
                     DaemonOptions options = {});

std::expected<void, DaemonError> run_daemon(ExecutionEnvironment environment,
                                            DaemonOptions options,
                                            std::stop_token stop_token);

void request_daemon_session_stop(DaemonSession& session) noexcept;
void stop_daemon_session(DaemonSession& session) noexcept;
[[nodiscard]] bool
is_daemon_session_running(const DaemonSession& session) noexcept;

std::expected<DaemonStatusReport, DaemonError> query_daemon_session_status(
    DaemonSession& session,
    std::optional<std::string_view> profile_name = std::nullopt);

std::expected<DaemonSyncTriggerReport, DaemonError> trigger_daemon_session_sync(
    DaemonSession& session,
    std::optional<std::string_view> profile_name = std::nullopt,
    bool wait = false);

std::expected<void, DaemonError>
pause_daemon_session_profile(DaemonSession& session,
                             std::string_view profile_name);

std::expected<void, DaemonError>
resume_daemon_session_profile(DaemonSession& session,
                              std::string_view profile_name);

std::expected<void, DaemonError>
unlock_daemon_session_profile(DaemonSession& session,
                              std::string_view profile_name,
                              ProfileCredentials credentials);

std::expected<void, DaemonError>
lock_daemon_session_profile(DaemonSession& session,
                            std::string_view profile_name);

std::expected<void, DaemonError>
reload_daemon_session_profiles(DaemonSession& session);

std::expected<DaemonLogsReport, DaemonError>
query_daemon_session_events(DaemonSession& session,
                            const DaemonLogQuery& query = {});

std::expected<void, DaemonError>
cancel_daemon_session_profile(DaemonSession& session,
                              std::string_view profile_name);

// Local IPC & process management client APIs.
bool is_daemon_running(const ExecutionEnvironment& environment) noexcept;

std::expected<DaemonStatusReport, DaemonError> query_daemon_status(
    const ExecutionEnvironment& environment,
    std::optional<std::string_view> profile_name = std::nullopt);

std::expected<DaemonLogsReport, DaemonError>
query_daemon_events(const ExecutionEnvironment& environment,
                    const DaemonLogQuery& query = {});

std::expected<void, DaemonError>
cancel_daemon_profile(const ExecutionEnvironment& environment,
                      std::string_view profile_name);

std::expected<void, DaemonError>
stop_running_daemon(const ExecutionEnvironment& environment);

std::expected<DaemonSyncTriggerReport, DaemonError>
trigger_daemon_sync(const ExecutionEnvironment& environment,
                    std::optional<std::string_view> profile_name = std::nullopt,
                    bool wait = false);

std::expected<void, DaemonError>
pause_daemon_profile(const ExecutionEnvironment& environment,
                     std::string_view profile_name);

std::expected<void, DaemonError>
resume_daemon_profile(const ExecutionEnvironment& environment,
                      std::string_view profile_name);

std::expected<void, DaemonError>
unlock_daemon_profile(const ExecutionEnvironment& environment,
                      std::string_view profile_name,
                      ProfileCredentials credentials);

std::expected<void, DaemonError>
lock_daemon_profile(const ExecutionEnvironment& environment,
                    std::string_view profile_name);

std::expected<void, DaemonError>
reload_running_daemon(const ExecutionEnvironment& environment);

std::expected<DaemonStatusReport, DaemonError> spawn_background_daemon(
    const ExecutionEnvironment& environment,
    const std::optional<std::filesystem::path>& log_file = std::nullopt);

std::expected<DaemonAutostartStatus, DaemonError> install_daemon_autostart();
std::expected<DaemonAutostartStatus, DaemonError> uninstall_daemon_autostart();
std::expected<DaemonAutostartStatus, DaemonError> query_daemon_autostart();

// Writes a salted Argon2id verifier to web-password.json (minimum 8
// characters). and removes any pending web-bootstrap.token.
std::expected<void, DaemonError>
set_web_password(const ExecutionEnvironment& environment,
                 std::string_view password,
                 std::optional<std::string_view> username = std::nullopt);

struct WebListenerConfig {
    std::string bind = "127.0.0.1";
    int port = 3137;
    std::vector<std::string> allowed_hosts;
    bool skip_host_check = false;
};

std::expected<WebListenerConfig, DaemonError>
read_web_listener_config(const ExecutionEnvironment& environment);

std::expected<WebListenerConfig, DaemonError>
write_web_listener_config(const ExecutionEnvironment& environment,
                          const WebListenerConfig& config);

} // namespace kasumi::application

#endif
