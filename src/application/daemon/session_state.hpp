#ifndef KASUMI_APPLICATION_DAEMON_SESSION_STATE_HPP
#define KASUMI_APPLICATION_DAEMON_SESSION_STATE_HPP

#include "application/daemon.hpp"
#include "application/daemon/defaults.hpp"
#include "application/daemon/ipc_security.hpp"
#include "application/daemon/web_auth.hpp"
#include "application/daemon/web_jobs.hpp"
#include "application/observation/state.hpp"
#include "core/ignore.hpp"
#include "platform/directory_watcher.hpp"
#include "platform/private_storage.hpp"
#include "platform/profile_lock.hpp"
#include "platform/secure_page.hpp"
#include "runtime/profile.hpp"
#include "transport/transport.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace kasumi::application {
namespace daemon_detail {

struct WatcherContext {
    std::mutex mutex;
    DaemonSessionState* owner = nullptr;
    std::string profile_name;
    ignore::IgnoreList ignore_rules;
    bool detached = false;
};

// Hot scheduling & state flags packed tightly for contiguous scheduler scans.
struct ProfileHotSchedule {
    bool paused = false;
    bool locked = false;
    bool needs_attention = false;
    bool dirty = false;
    bool overflow = false;
    bool watcher_healthy = false;
    bool watcher_baseline_established = false;
    bool immediate_sync_requested = false;
    bool in_flight = false;
    bool watch_enabled = true;

    std::uint32_t sync_interval_seconds = kDefaultSyncIntervalSeconds;
    std::uint32_t backoff_seconds = 0;
    std::uint32_t consecutive_failures = 0;

    std::uint64_t config_generation = 0;
    std::uint64_t watch_epoch = 0;
    std::uint64_t completed_generation = 0;

    std::optional<std::chrono::steady_clock::time_point> first_dirty_at;
    std::optional<std::chrono::steady_clock::time_point> last_dirty_at;
    std::chrono::steady_clock::time_point next_sync_at{};
    std::chrono::steady_clock::time_point last_full_verify_at{};
    std::chrono::steady_clock::time_point backoff_until{};
    std::uint32_t vault_recheck_attempts = 0;
    std::chrono::steady_clock::time_point next_vault_recheck_at{};
};

// Telemetry & status counters surfaced cleanly on /v1/status queries.
struct ProfileTelemetryRow {
    std::string active_item_path;
    std::optional<std::uint64_t> active_item_bytes = std::nullopt;
    std::optional<std::uint64_t> active_item_total_bytes = std::nullopt;
    std::string active_stage;
    std::uint64_t active_objects = 0;
    std::optional<std::uint64_t> active_total_objects;
    std::uint64_t active_bytes = 0;
    std::optional<std::uint64_t> active_total_bytes;
    std::string sync_phase;
    std::optional<std::uint32_t> sync_applied_items;
    std::optional<std::uint32_t> sync_total_items;
    std::optional<double> active_bytes_per_second;
    std::chrono::steady_clock::time_point rate_sample_at{};
    std::uint64_t rate_activity_id = 0;
    std::uint64_t rate_sample_bytes = 0;

    std::optional<std::int64_t> last_sync_started_at;
    std::optional<std::int64_t> last_sync_finished_at;
    std::optional<std::int64_t> last_checked_at;
    std::uint64_t sync_runs = 0;
    std::uint64_t fast_noop_polls = 0;
    std::string last_outcome;
    std::string last_error;
};

// Cold configuration, paths, dirty sets, and filesystem metadata stamps.
struct ProfileColdMeta {
    runtime::ProfileData config;
    std::filesystem::path database_path;
    std::filesystem::path key_path;
    std::unordered_set<std::string> dirty_paths;

    ignore::IgnoreList ignore_rules;
    bool ignore_has_negation = false;
    bool ignore_file_present = false;
    observation::DatabaseMetadataStamp ignore_stamp{};
    platform::private_storage::DirectoryIdentity local_dir_identity{};
    observation::DatabaseMetadataStamp external_db_stamp{};
    bool has_external_db_stamp = false;
    observation::DatabaseMetadataStamp key_file_stamp{};
};

// Warm long-lived handles & observation caches retained across sync cycles.
struct ProfileWarmSlot {
    std::shared_ptr<WatcherContext> watcher_ctx;
    platform::DirectoryWatcher watcher;
    std::optional<transport::Transport> warm_transport;
    std::chrono::steady_clock::time_point warm_transport_last_used{};
    observation::LocalObservationSession warm_observation;
    std::unique_ptr<std::stop_source> task_stop_source;
};

// Sorted Hot/Cold Structure-of-Arrays (SoA) table over all managed profiles.
struct ProfileTable {
    std::vector<std::string> names;
    std::vector<ProfileHotSchedule> hot;
    std::vector<ProfileTelemetryRow> telemetry;
    std::vector<ProfileColdMeta> cold;
    std::vector<ProfileWarmSlot> warm;
};

struct WorkerSlot {
    std::thread thread;
    std::shared_ptr<std::atomic_bool> finished;
};

} // namespace daemon_detail

struct DaemonSessionState {
    mutable std::mutex mutex;
    mutable std::mutex event_log_mutex;
    std::mutex cleanup_mutex;
    std::condition_variable cv;
    bool cleaned_up = false;

    ExecutionEnvironment environment;
    DaemonOptions options;
    std::intptr_t daemon_lock = platform::invalid_profile_lock;
    std::uint64_t pid = 0;
    std::int64_t started_at_unix = 0;
    std::string daemon_instance;
    std::chrono::steady_clock::time_point started_at_steady{};
    std::atomic<std::uint64_t> status_revision{1};
    std::atomic<std::uint64_t> latest_event_seq{0};
    std::uint16_t ipc_port = 0;
    std::uint16_t web_port = 0;
    std::array<std::uint8_t, daemon_detail::kTokenSize> auth_token{};
    std::array<std::uint8_t, daemon_detail::kTokenSize> ipc_key{};

    bool running = false;
    bool stop_requested = false;
    std::stop_source master_stop;

    platform::SecureKeyArena key_arena;
    daemon_detail::ProfileTable profiles;
    observation::DatabaseMetadataStamp config_stamp{};
    bool has_config_stamp = false;
    std::mutex autostart_mutex;
    DaemonAutostartStatus cached_autostart{};

    std::uint64_t next_event_seq = 1;
    std::deque<DaemonEvent> event_ring;

    platform::DirectoryWatcher config_watcher;
    std::atomic_bool config_dirty{false};

    std::unique_ptr<httplib::Server> ipc_server;
    std::thread ipc_thread;
    daemon_detail::WebAuth web_auth;
    daemon_detail::WebJobs web_jobs;
    std::unordered_map<std::string, std::size_t> internal_lock_counts;
    std::unique_ptr<httplib::Server> web_server;
    std::thread web_thread;
    std::thread scheduler_thread;
    std::vector<daemon_detail::WorkerSlot> workers;
    std::size_t active_workers = 0;
};

namespace daemon_detail {

std::int64_t current_unix_seconds() noexcept;
inline void notify_daemon_status_change(DaemonSessionState& state) noexcept {
    state.status_revision.fetch_add(1, std::memory_order_release);
    state.cv.notify_all();
}
std::optional<std::string> detect_held_profile_operation(
    DaemonSessionState& state, std::string_view profile_name);
void cleanup_daemon_resources(DaemonSessionState& state,
                              bool join_scheduler) noexcept;
void scheduler_loop(DaemonSessionState& state);

void request_stop_internal(DaemonSessionState& state) noexcept;

std::expected<DaemonStatusReport, DaemonError>
status_session_state(DaemonSessionState& state,
                     std::optional<std::string_view> profile_name);

std::expected<void, DaemonError>
reload_session_state(DaemonSessionState& state);

std::expected<DaemonSyncTriggerReport, DaemonError>
trigger_sync_session_state(DaemonSessionState& state,
                           std::optional<std::string_view> profile_name,
                           bool wait);

std::expected<void, DaemonError>
pause_session_state(DaemonSessionState& state, std::string_view profile_name);

std::expected<void, DaemonError>
resume_session_state(DaemonSessionState& state, std::string_view profile_name);

std::expected<void, DaemonError>
unlock_session_state(DaemonSessionState& state,
                     std::string_view profile_name,
                     ProfileCredentials credentials);

std::expected<void, DaemonError>
lock_session_state(DaemonSessionState& state, std::string_view profile_name);

std::expected<DaemonLogsReport, DaemonError>
events_session_state(DaemonSessionState& state, const DaemonLogQuery& query);

std::expected<void, DaemonError>
cancel_session_state(DaemonSessionState& state, std::string_view profile_name);

std::expected<void, DaemonError> start_ipc_server(DaemonSessionState& state);

} // namespace daemon_detail
} // namespace kasumi::application

#endif
