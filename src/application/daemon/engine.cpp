#include "application/daemon.hpp"
#include "application/daemon/error_classification.hpp"
#include "application/daemon/fast_poll.hpp"
#include "application/daemon/ipc_security.hpp"
#include "application/detail.hpp"
#include "application/execute.hpp"
#include "application/observation/file_metadata.hpp"
#include "application/observation/state.hpp"
#include "application/use_cases/context.hpp"
#include "core/ignore.hpp"
#include "crypto/secure_memory.hpp"
#include "platform/autostart.hpp"
#include "platform/clock.hpp"
#include "platform/directory_watcher.hpp"
#include "platform/machine.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "platform/profile_lock.hpp"
#include "platform/random.hpp"
#include "platform/secure_page.hpp"
#include "runtime/paths.hpp"
#include "runtime/profile.hpp"
#include "runtime/resolver.hpp"
#include "runtime/vault.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <filesystem>
#include <format>
#include <fstream>
#include <httplib.h>
#include <memory>
#include <monocypher.h>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_set>
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

std::string_view to_string(DaemonProfileState state) noexcept {
    switch (state) {
        case DaemonProfileState::Idle:
            return "idle";
        case DaemonProfileState::PendingDebounce:
            return "pending_debounce";
        case DaemonProfileState::RunningSync:
            return "running_sync";
        case DaemonProfileState::RunningGc:
            return "running_gc";
        case DaemonProfileState::Paused:
            return "paused";
        case DaemonProfileState::Locked:
            return "locked";
        case DaemonProfileState::Backoff:
            return "backoff";
        case DaemonProfileState::NeedsAttention:
            return "needs_attention";
    }
    return "idle";
}

namespace {

constexpr std::uint32_t kDefaultSyncIntervalSeconds = 300U;
constexpr std::uint32_t kDefaultGcIntervalHours = 0U;
constexpr std::uint32_t kDaemonApiVersion = 1U;
constexpr std::size_t kMaxEventRingSize = 512U;
constexpr std::uint64_t kMaxDaemonLogBytes = 2ULL * 1024ULL * 1024ULL;
constexpr std::size_t kMaxTrackedDirtyPaths = 4096U;
constexpr std::uint32_t kMinBackoffSeconds = 5U;
constexpr std::uint32_t kMaxBackoffSeconds = 600U;

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

std::int64_t current_unix_seconds() noexcept {
    return platform::clock::unix_seconds().value_or(0);
}

std::int64_t
steady_to_unix_estimate(std::chrono::steady_clock::time_point target,
                        std::chrono::steady_clock::time_point now_steady,
                        std::int64_t now_unix) noexcept {
    const auto delta =
        std::chrono::duration_cast<std::chrono::seconds>(target - now_steady);
    return now_unix + delta.count();
}

bool contains_case_insensitive(std::string_view haystack,
                               std::string_view needle) noexcept {
    if (needle.empty() || haystack.size() < needle.size()) {
        return false;
    }
    const auto it = std::ranges::search(haystack, needle, [](char a, char b) {
        const auto lower = [](char c) noexcept {
            return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A'))
                                          : c;
        };
        return lower(a) == lower(b);
    });
    return !it.empty();
}

} // namespace

namespace daemon_detail {

bool is_concurrent_local_mutation_error(const Error& error) noexcept {
    return contains_case_insensitive(error.detail, "concurrent_modification") ||
           contains_case_insensitive(
               error.detail,
               "materialized tree does not match reconciled candidate tree") ||
           contains_case_insensitive(
               error.detail,
               "local materialization diverges from observed head");
}

bool is_transient_sync_error(const Error& error) noexcept {
    if (error.lock_busy || error.remote_busy) {
        return true;
    }
    if (error.empty_local_blocked || error.insufficient_disk_space) {
        return false;
    }
    if (error.code == ErrorCode::CredentialFailure ||
        error.code == ErrorCode::CredentialsRequired ||
        error.code == ErrorCode::InvalidProfile ||
        error.code == ErrorCode::ProfileNotFound) {
        return false;
    }
    if (is_concurrent_local_mutation_error(error)) {
        return true;
    }
    if (contains_case_insensitive(error.detail, "remote_busy") ||
        contains_case_insensitive(error.detail, "blocked by active") ||
        contains_case_insensitive(error.detail, "another execution") ||
        contains_case_insensitive(error.detail, "timeout") ||
        contains_case_insensitive(error.detail, "timed out") ||
        contains_case_insensitive(error.detail, "unreachable") ||
        contains_case_insensitive(error.detail, "connection") ||
        contains_case_insensitive(error.detail, "transport") ||
        contains_case_insensitive(error.detail, "backend") ||
        contains_case_insensitive(error.detail, "network")) {
        return true;
    }
    if (contains_case_insensitive(error.detail, "composition_mismatch") ||
        contains_case_insensitive(error.detail, "initial sync") ||
        contains_case_insensitive(error.detail, "unauthenticated") ||
        contains_case_insensitive(error.detail, "corrupt") ||
        contains_case_insensitive(error.detail, "does not match") ||
        contains_case_insensitive(error.detail, "do not match") ||
        contains_case_insensitive(error.detail, "regression") ||
        contains_case_insensitive(error.detail,
                                  "requires absent local state")) {
        return false;
    }
    return error.code == ErrorCode::SynchronizationFailure ||
           error.code == ErrorCode::PlanFailure;
}

} // namespace daemon_detail

namespace {

std::uint32_t
compute_jittered_backoff_seconds(std::uint32_t consecutive_failures) noexcept {
    const std::uint32_t shift =
        std::min<std::uint32_t>(consecutive_failures, 8U);
    const std::uint32_t base = std::min<std::uint32_t>(
        kMaxBackoffSeconds, kMinBackoffSeconds << shift);
    std::array<std::uint8_t, 1> rnd{};
    if (!platform::random::fill_bytes(rnd)) {
        return base;
    }
    // Jitter within [85%, 115%] to avoid thundering-herd retries.
    const std::int32_t pct = 85 + static_cast<std::int32_t>(rnd[0] % 31U);
    return std::max<std::uint32_t>(
        kMinBackoffSeconds,
        static_cast<std::uint32_t>((static_cast<std::uint64_t>(base) *
                                    static_cast<std::uint64_t>(pct)) /
                                   100ULL));
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

observation::DatabaseMetadataStamp
capture_ignore_stamp(const std::filesystem::path& local_dir,
                     bool& ignore_present) {
    ignore_present = false;
    const auto path = local_dir / ".kasumiignore";
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(path, ec);
    if (ec || std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        return observation::DatabaseMetadataStamp{};
    }
    ignore_present = true;
    const auto utf8 = platform::path::to_utf8(path);
    const auto meta = observation::cache::read_file_metadata(path, utf8);
    if (!meta || !meta->has_value() || !(*meta)->identity.has_value()) {
        return observation::DatabaseMetadataStamp{.present = true};
    }
    const auto& m = **meta;
    return observation::DatabaseMetadataStamp{
        .present = true,
        .size = m.size,
        .mtime_ns = m.mtime_nanoseconds,
        .volume = m.identity->volume,
        .file_low = m.identity->file_low,
        .file_high = m.identity->file_high,
    };
}

std::string format_sync_outcome(const SyncCompleted& completed) {
    return std::format("up={}, down={}, rm={}, mv={}",
                       completed.uploaded,
                       completed.downloaded,
                       completed.removed,
                       completed.renamed);
}

std::string activity_stage_label(Activity activity) {
    switch (activity) {
        case Activity::Scanning:
            return "scanning";
        case Activity::Staging:
            return "staging";
        case Activity::Uploading:
            return "uploading";
        case Activity::Downloading:
            return "downloading";
        case Activity::Verifying:
            return "verifying";
        case Activity::Installing:
            return "installing";
        case Activity::Reobserving:
            return "reobserving";
        case Activity::Listing:
            return "listing";
        case Activity::Authenticating:
            return "authenticating";
        case Activity::Auditing:
            return "auditing";
        case Activity::Removing:
            return "removing";
        case Activity::ComparingSnapshots:
            return "comparing";
        case Activity::CheckingRemoteContent:
            return "checking_remote";
        case Activity::PreparingPlan:
            return "planning";
        case Activity::PreparingRemote:
            return "preparing_remote";
        case Activity::CheckingControls:
            return "checking_controls";
        case Activity::EstablishingBarrier:
            return "establishing_barrier";
        case Activity::ProbingConsistency:
            return "probing_consistency";
        case Activity::AnalyzingReachability:
            return "analyzing_reachability";
        case Activity::LoadingActivities:
            return "loading_activities";
        case Activity::ReleasingBarrier:
            return "releasing_barrier";
    }
    return "running";
}

} // namespace

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
    bool active_gc = false;
    bool watch_enabled = true;

    std::uint32_t sync_interval_seconds = kDefaultSyncIntervalSeconds;
    std::uint32_t gc_interval_hours = kDefaultGcIntervalHours;
    std::uint32_t backoff_seconds = 0;
    std::uint32_t consecutive_failures = 0;

    std::uint64_t config_generation = 0;
    std::uint64_t watch_epoch = 0;
    std::uint64_t completed_generation = 0;

    std::optional<std::chrono::steady_clock::time_point> first_dirty_at;
    std::optional<std::chrono::steady_clock::time_point> last_dirty_at;
    std::chrono::steady_clock::time_point next_sync_at{};
    std::chrono::steady_clock::time_point next_gc_at{};
    std::chrono::steady_clock::time_point last_full_verify_at{};
    std::chrono::steady_clock::time_point backoff_until{};
    std::uint32_t vault_recheck_attempts = 0;
    std::chrono::steady_clock::time_point next_vault_recheck_at{};
};

constexpr std::chrono::seconds
next_vault_recheck_delay(std::uint32_t attempts) noexcept {
    constexpr std::array<int, 5> kDelaysSeconds{{3, 5, 10, 15, 30}};
    const std::size_t idx =
        std::min<std::size_t>(attempts, kDelaysSeconds.size() - 1U);
    return std::chrono::seconds{kDelaysSeconds[idx]};
}

// Telemetry & status counters surfaced cleanly on /v1/status queries.
struct ProfileTelemetryRow {
    std::string active_stage;
    std::uint64_t active_objects = 0;
    std::optional<std::uint64_t> active_total_objects;
    std::uint64_t active_bytes = 0;
    std::optional<std::uint64_t> active_total_bytes;

    std::optional<std::int64_t> last_sync_started_at;
    std::optional<std::int64_t> last_sync_finished_at;
    std::optional<std::int64_t> last_checked_at;
    std::uint64_t sync_runs = 0;
    std::uint64_t fast_noop_polls = 0;
    std::uint64_t gc_runs = 0;
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
    std::chrono::steady_clock::time_point started_at_steady{};
    std::uint16_t ipc_port = 0;
    std::array<std::uint8_t, daemon_detail::kTokenSize> auth_token{};
    std::array<std::uint8_t, daemon_detail::kTokenSize> ipc_key{};

    bool running = false;
    bool stop_requested = false;
    std::stop_source master_stop;

    platform::SecureKeyArena key_arena;
    ProfileTable profiles;
    observation::DatabaseMetadataStamp config_stamp{};
    bool has_config_stamp = false;
    DaemonAutostartStatus cached_autostart{};

    std::uint64_t next_event_seq = 1;
    std::deque<DaemonEvent> event_ring;

    platform::DirectoryWatcher config_watcher;
    std::atomic_bool config_dirty{false};

    std::unique_ptr<httplib::Server> ipc_server;
    std::thread ipc_thread;
    std::thread scheduler_thread;
    std::vector<WorkerSlot> workers;
    std::size_t active_workers = 0;
};

namespace {

std::optional<std::size_t> find_profile_slot(const ProfileTable& table,
                                             std::string_view name) noexcept {
    const auto it = std::ranges::lower_bound(table.names, name);
    if (it == table.names.end() || *it != name) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(it - table.names.begin());
}

void insert_profile_slot(ProfileTable& table,
                         std::string name,
                         ProfileHotSchedule hot,
                         ProfileTelemetryRow telemetry,
                         ProfileColdMeta cold,
                         ProfileWarmSlot warm) {
    const auto it = std::ranges::lower_bound(table.names, name);
    const auto pos = static_cast<std::ptrdiff_t>(it - table.names.begin());
    const std::size_t next_cap = table.names.size() + 1U;
    table.names.reserve(next_cap);
    table.hot.reserve(next_cap);
    table.telemetry.reserve(next_cap);
    table.cold.reserve(next_cap);
    table.warm.reserve(next_cap);

    table.names.insert(table.names.begin() + pos, std::move(name));
    table.hot.insert(table.hot.begin() + pos, std::move(hot));
    table.telemetry.insert(table.telemetry.begin() + pos, std::move(telemetry));
    table.cold.insert(table.cold.begin() + pos, std::move(cold));
    table.warm.insert(table.warm.begin() + pos, std::move(warm));
}

void erase_profile_slot(ProfileTable& table, std::size_t idx) noexcept {
    const auto offset = static_cast<std::ptrdiff_t>(idx);
    table.names.erase(table.names.begin() + offset);
    table.hot.erase(table.hot.begin() + offset);
    table.telemetry.erase(table.telemetry.begin() + offset);
    table.cold.erase(table.cold.begin() + offset);
    table.warm.erase(table.warm.begin() + offset);
}

void clear_active_telemetry(ProfileTelemetryRow& telemetry) noexcept {
    telemetry.active_stage.clear();
    telemetry.active_objects = 0;
    telemetry.active_total_objects.reset();
    telemetry.active_bytes = 0;
    telemetry.active_total_bytes.reset();
}

std::filesystem::path
daemon_log_path(const std::filesystem::path& app_data_dir) {
    return app_data_dir / "daemon.log";
}

std::filesystem::path
daemon_rotated_log_path(const std::filesystem::path& app_data_dir) {
    return app_data_dir / "daemon.log.1";
}

bool safe_regular_or_absent(const std::filesystem::path& path,
                            std::uint64_t* out_size = nullptr) noexcept {
    std::error_code ec;
    const auto st = std::filesystem::symlink_status(path, ec);
    if (ec == std::errc::no_such_file_or_directory ||
        (!ec && st.type() == std::filesystem::file_type::not_found)) {
        if (out_size != nullptr) {
            *out_size = 0;
        }
        return true;
    }
    if (ec || std::filesystem::is_symlink(st) ||
        !std::filesystem::is_regular_file(st)) {
        return false;
    }
    if (out_size != nullptr) {
        const auto sz = std::filesystem::file_size(path, ec);
        *out_size = ec ? 0ULL : static_cast<std::uint64_t>(sz);
    }
    return true;
}

void append_daemon_log_line_best_effort(
    const std::filesystem::path& app_data_dir, const DaemonEvent& ev) noexcept {
    if (app_data_dir.empty()) {
        return;
    }
    try {
        if (!platform::private_storage::ensure_directory(app_data_dir)) {
            return;
        }
        const auto primary = daemon_log_path(app_data_dir);
        const auto rotated = daemon_rotated_log_path(app_data_dir);
        std::uint64_t cur_size = 0;
        if (!safe_regular_or_absent(primary, &cur_size) ||
            !safe_regular_or_absent(rotated)) {
            return;
        }
        if (cur_size >= kMaxDaemonLogBytes) {
            std::error_code ec;
            std::filesystem::remove(rotated, ec);
            ec.clear();
            std::filesystem::rename(primary, rotated, ec);
            if (!ec) {
                static_cast<void>(
                    platform::private_storage::protect_file(rotated));
            }
        }
        const bool existed = std::filesystem::exists(primary);
        if (!existed) {
            if (!platform::private_storage::create_file(primary)) {
                return;
            }
        }
        nlohmann::json row{
            {"seq", ev.seq},
            {"ts", ev.timestamp_unix},
            {"profile", ev.profile_name},
            {"kind", ev.kind},
            {"detail", ev.detail},
        };
        std::ofstream out(primary, std::ios::binary | std::ios::app);
        if (out) {
            out << row.dump() << '\n';
            out.flush();
        }
        if (!existed) {
            static_cast<void>(platform::private_storage::protect_file(primary));
        }
    } catch (...) {
    }
}

void read_log_file_into(const std::filesystem::path& path,
                        std::vector<DaemonEvent>& out,
                        std::uint64_t& max_seq) {
    std::error_code ec;
    const auto st = std::filesystem::symlink_status(path, ec);
    if (ec || std::filesystem::is_symlink(st) ||
        !std::filesystem::is_regular_file(st)) {
        return;
    }
    std::string content;
    std::array<std::uint8_t, 8192> buf{};
    const auto streamed = platform::private_storage::stream_regular_file(
        path, buf, [&](std::span<const std::uint8_t> chunk) {
            if (content.size() + chunk.size() > 4ULL * 1024ULL * 1024ULL) {
                return false;
            }
            content.append(reinterpret_cast<const char*>(chunk.data()),
                           chunk.size());
            return true;
        });
    if (!streamed) {
        return;
    }
    std::size_t pos = 0;
    while (pos < content.size()) {
        const std::size_t nl = content.find('\n', pos);
        const std::size_t end = nl == std::string::npos ? content.size() : nl;
        std::string_view line{content.data() + pos, end - pos};
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }
        pos = (nl == std::string::npos) ? content.size() : nl + 1U;
        if (line.empty()) {
            continue;
        }
        try {
            const auto j = nlohmann::json::parse(line);
            if (!j.is_object()) {
                continue;
            }
            DaemonEvent ev{
                .seq = j.value("seq", std::uint64_t{0}),
                .timestamp_unix = j.value("ts", std::int64_t{0}),
                .profile_name = j.value("profile", std::string{}),
                .kind = j.value("kind", std::string{}),
                .detail = j.value("detail", std::string{}),
            };
            if (ev.seq > max_seq) {
                max_seq = ev.seq;
            }
            out.push_back(std::move(ev));
        } catch (...) {
        }
    }
}

void emit_daemon_event(DaemonSessionState& state,
                       std::string profile_name,
                       std::string kind,
                       std::string detail,
                       bool persist_to_log = true) noexcept {
    DaemonEvent ev{
        .timestamp_unix = current_unix_seconds(),
        .profile_name = std::move(profile_name),
        .kind = std::move(kind),
        .detail = std::move(detail),
    };
    DaemonEventCallback cb;
    try {
        std::filesystem::path app_dir;
        {
            std::lock_guard lock(state.event_log_mutex);
            ev.seq = state.next_event_seq++;
            state.event_ring.push_back(ev);
            while (state.event_ring.size() > kMaxEventRingSize) {
                state.event_ring.pop_front();
            }
            if (persist_to_log) {
                append_daemon_log_line_best_effort(
                    state.environment.app_data_dir, ev);
            }
        }
        cb = state.options.on_event;
    } catch (...) {
        return;
    }
    if (cb) {
        try {
            cb(ev);
        } catch (...) {
        }
    }
}

observation::DatabaseMetadataStamp
read_file_stamp(const std::filesystem::path& path) {
    std::error_code ec;
    const auto st = std::filesystem::symlink_status(path, ec);
    if (ec || st.type() == std::filesystem::file_type::not_found) {
        return {};
    }
    const auto utf8 = platform::path::to_utf8(path);
    const auto meta = observation::cache::read_file_metadata(path, utf8);
    if (!meta || !meta->has_value() || !(*meta)->identity.has_value()) {
        return {.present = true};
    }
    const auto& m = **meta;
    return observation::DatabaseMetadataStamp{
        .present = true,
        .size = m.size,
        .mtime_ns = m.mtime_nanoseconds,
        .volume = m.identity->volume,
        .file_low = m.identity->file_low,
        .file_high = m.identity->file_high,
    };
}

void refresh_ignore_state(ProfileColdMeta& cold, ProfileWarmSlot& warm) {
    cold.ignore_stamp =
        capture_ignore_stamp(cold.config.local_dir, cold.ignore_file_present);
    if (cold.ignore_file_present) {
        cold.ignore_rules =
            ignore::load_ignore_list(cold.config.local_dir / ".kasumiignore");
        cold.ignore_has_negation = std::ranges::any_of(
            cold.ignore_rules.rules, &ignore::IgnoreRule::negated);
    } else {
        cold.ignore_rules = {};
        cold.ignore_has_negation = false;
    }
    if (warm.watcher_ctx) {
        std::lock_guard lock(warm.watcher_ctx->mutex);
        warm.watcher_ctx->ignore_rules = cold.ignore_rules;
    }
}

void handle_watch_event(DaemonSessionState& state,
                        std::string_view profile_name,
                        const platform::WatchEvent& ev) noexcept {
    bool ignore_reloaded = false;
    ignore::IgnoreList updated_ignore;
    if (!ev.overflow && !ev.root_invalidated &&
        ignore::is_kasumiignore_path(ev.relative_path)) {
        std::filesystem::path local_dir;
        {
            std::lock_guard lock(state.mutex);
            if (const auto slot =
                    find_profile_slot(state.profiles, profile_name)) {
                local_dir = state.profiles.cold[*slot].config.local_dir;
            }
        }
        if (!local_dir.empty()) {
            updated_ignore =
                ignore::load_ignore_list(local_dir / ".kasumiignore");
            ignore_reloaded = true;
        }
    }

    bool wake_scheduler = false;
    bool should_emit_overflow = false;
    {
        std::lock_guard lock(state.mutex);
        const auto slot = find_profile_slot(state.profiles, profile_name);
        if (!slot) {
            return;
        }
        auto& hot = state.profiles.hot[*slot];
        auto& cold = state.profiles.cold[*slot];
        auto& warm = state.profiles.warm[*slot];
        if (ignore_reloaded) {
            cold.ignore_rules = updated_ignore;
            cold.ignore_has_negation = std::ranges::any_of(
                updated_ignore.rules, &ignore::IgnoreRule::negated);
            cold.ignore_stamp = capture_ignore_stamp(cold.config.local_dir,
                                                     cold.ignore_file_present);
            if (warm.watcher_ctx) {
                std::lock_guard ctx_lock(warm.watcher_ctx->mutex);
                warm.watcher_ctx->ignore_rules = updated_ignore;
            }
        }

        const auto now = std::chrono::steady_clock::now();
        ++hot.watch_epoch;
        if (ev.overflow || ev.root_invalidated) {
            hot.overflow = true;
            hot.dirty = true;
            hot.watcher_baseline_established = false;
            if (ev.root_invalidated) {
                hot.watcher_healthy = false;
            }
            if (!hot.first_dirty_at) {
                hot.first_dirty_at = now;
            }
            hot.last_dirty_at = now;
            wake_scheduler = true;
            should_emit_overflow = true;
        } else {
            hot.dirty = true;
            if (cold.dirty_paths.size() < kMaxTrackedDirtyPaths) {
                cold.dirty_paths.insert(ev.relative_path);
            } else {
                hot.overflow = true;
            }
            if (!hot.first_dirty_at) {
                hot.first_dirty_at = now;
            }
            hot.last_dirty_at = now;
            wake_scheduler = true;
        }
    }
    if (should_emit_overflow) {
        emit_daemon_event(
            state,
            std::string{profile_name},
            ev.root_invalidated ? "watch_root_invalidated" : "watch_overflow",
            ev.root_invalidated
                ? "watched root moved, removed, or unavailable"
                : "watcher event queue overflowed; full scan scheduled");
    }
    if (wake_scheduler) {
        state.cv.notify_all();
    }
}

void ensure_watcher_started_unlocked(DaemonSessionState& state,
                                     std::string_view profile_name) {
    platform::DirectoryWatcher old_watcher;
    std::shared_ptr<WatcherContext> old_ctx;
    std::filesystem::path local_dir;

    {
        std::lock_guard lock(state.mutex);
        const auto slot = find_profile_slot(state.profiles, profile_name);
        if (!slot) {
            return;
        }
        auto& hot = state.profiles.hot[*slot];
        auto& cold = state.profiles.cold[*slot];
        auto& warm = state.profiles.warm[*slot];
        if (hot.paused || !hot.watch_enabled) {
            old_watcher = std::move(warm.watcher);
            old_ctx = std::move(warm.watcher_ctx);
            hot.watcher_healthy = false;
            hot.watcher_baseline_established = false;
        } else if (platform::directory_watcher_healthy(warm.watcher)) {
            hot.watcher_healthy = true;
            return;
        } else {
            old_watcher = std::move(warm.watcher);
            old_ctx = std::move(warm.watcher_ctx);
            hot.watcher_healthy = false;
            local_dir = cold.config.local_dir;
        }
    }

    if (old_ctx) {
        std::lock_guard ctx_lock(old_ctx->mutex);
        old_ctx->detached = true;
    }
    platform::stop_directory_watcher(old_watcher);
    if (local_dir.empty()) {
        return;
    }

    bool ignore_present = false;
    const auto ignore_stamp = capture_ignore_stamp(local_dir, ignore_present);
    ignore::IgnoreList ignore_rules;
    bool ignore_has_negation = false;
    if (ignore_present) {
        ignore_rules = ignore::load_ignore_list(local_dir / ".kasumiignore");
        ignore_has_negation = std::ranges::any_of(ignore_rules.rules,
                                                  &ignore::IgnoreRule::negated);
    }
    const auto local_dir_id =
        platform::private_storage::query_directory_identity(local_dir);
    if (!local_dir_id.valid) {
        std::lock_guard lock(state.mutex);
        if (const auto slot = find_profile_slot(state.profiles, profile_name)) {
            auto& hot = state.profiles.hot[*slot];
            auto& cold = state.profiles.cold[*slot];
            cold.ignore_stamp = ignore_stamp;
            cold.ignore_file_present = ignore_present;
            cold.ignore_rules = std::move(ignore_rules);
            cold.ignore_has_negation = ignore_has_negation;
            cold.local_dir_identity = local_dir_id;
            hot.watcher_healthy = false;
            hot.watcher_baseline_established = false;
        }
        return;
    }

    auto ctx = std::make_shared<WatcherContext>();
    ctx->owner = &state;
    ctx->profile_name = std::string{profile_name};
    ctx->ignore_rules = ignore_rules;

    platform::IgnoreDirectoryFilter skip_dir;
    if (!ignore_has_negation) {
        skip_dir = [ctx](std::string_view rel_dir) {
            if (ignore::is_reserved_internal(rel_dir)) {
                return true;
            }
            std::lock_guard lock(ctx->mutex);
            return ignore::is_ignored(rel_dir, ctx->ignore_rules, true);
        };
    } else {
        skip_dir = [](std::string_view rel_dir) {
            return ignore::is_reserved_internal(rel_dir);
        };
    }

    auto started = platform::start_directory_watcher(
        local_dir,
        [ctx](const platform::WatchEvent& ev) {
            DaemonSessionState* owner_ptr = nullptr;
            std::string pname;
            {
                std::lock_guard lock(ctx->mutex);
                if (ctx->detached || ctx->owner == nullptr) {
                    return;
                }
                if (!ev.overflow && !ev.root_invalidated) {
                    if (ev.relative_path.empty() ||
                        ignore::is_reserved_internal(ev.relative_path)) {
                        return;
                    }
                    if (!ignore::is_kasumiignore_path(ev.relative_path) &&
                        ignore::is_ignored(ev.relative_path,
                                           ctx->ignore_rules,
                                           ev.is_directory)) {
                        return;
                    }
                }
                owner_ptr = ctx->owner;
                pname = ctx->profile_name;
            }
            handle_watch_event(*owner_ptr, pname, ev);
        },
        std::move(skip_dir));

    bool keep_watcher = false;
    {
        std::lock_guard lock(state.mutex);
        if (const auto slot = find_profile_slot(state.profiles, profile_name)) {
            auto& hot = state.profiles.hot[*slot];
            auto& cold = state.profiles.cold[*slot];
            auto& warm = state.profiles.warm[*slot];
            if (!hot.paused && hot.watch_enabled &&
                cold.config.local_dir == local_dir) {
                cold.ignore_stamp = ignore_stamp;
                cold.ignore_file_present = ignore_present;
                cold.ignore_rules = std::move(ignore_rules);
                cold.ignore_has_negation = ignore_has_negation;
                cold.local_dir_identity = local_dir_id;
                if (started &&
                    !platform::directory_watcher_valid(warm.watcher)) {
                    warm.watcher_ctx = ctx;
                    warm.watcher = std::move(*started);
                    hot.watcher_healthy =
                        platform::directory_watcher_healthy(warm.watcher);
                    keep_watcher = true;
                } else if (!started) {
                    hot.watcher_healthy = false;
                    hot.watcher_baseline_established = false;
                }
            }
        }
    }
    if (started && !keep_watcher) {
        {
            std::lock_guard ctx_lock(ctx->mutex);
            ctx->detached = true;
        }
        platform::stop_directory_watcher(*started);
    }
}

bool db_schema_valid(const std::filesystem::path& db_path) {
    return state_storage::validate(db_path);
}

bool db_initialized_and_has_state(const std::filesystem::path& db_path) {
    if (!state_storage::validate(db_path)) {
        return false;
    }
    const auto loaded = state_storage::load_state(db_path);
    return loaded && loaded->has_value() && !(*loaded)->commit_id.empty();
}

std::chrono::steady_clock::time_point
compute_initial_next_gc_at(const ExecutionEnvironment& env,
                           std::string_view profile_name,
                           std::uint32_t gc_hrs,
                           std::chrono::steady_clock::time_point now_steady,
                           std::int64_t now_unix) {
    if (gc_hrs == 0U) {
        return (std::chrono::steady_clock::time_point::max)();
    }
    const auto interval_sec = static_cast<std::int64_t>(gc_hrs) * 3600LL;
    std::optional<std::int64_t> last_gc_unix;
    const auto act = inspect_profile_activity(env, profile_name);
    for (const auto& e : act.recent_executions) {
        if (e.operation == ProfileOperationKind::GarbageCollect &&
            (e.status == ProfileExecutionStatus::Succeeded ||
             e.status == ProfileExecutionStatus::SucceededNoChanges)) {
            const auto ts = e.finished_at.value_or(e.started_at);
            if (!last_gc_unix || ts > *last_gc_unix) {
                last_gc_unix = ts;
            }
        }
    }
    if (!last_gc_unix || *last_gc_unix <= 0 || now_unix <= 0) {
        return now_steady + std::chrono::hours{gc_hrs};
    }
    const auto elapsed = now_unix - *last_gc_unix;
    if (elapsed >= interval_sec) {
        return now_steady + std::chrono::seconds{10};
    }
    if (elapsed > 0) {
        return now_steady + std::chrono::seconds{interval_sec - elapsed};
    }
    return now_steady + std::chrono::hours{gc_hrs};
}

bool refresh_key_status_for_slot(DaemonSessionState& state,
                                 std::size_t slot,
                                 bool force_recheck) {
    const auto& name = state.profiles.names[slot];
    auto& hot = state.profiles.hot[slot];
    auto& telemetry = state.profiles.telemetry[slot];
    auto& cold = state.profiles.cold[slot];
    auto& warm = state.profiles.warm[slot];
    if (cold.config.key_storage == runtime::KeyStorage::Memory) {
        cold.key_file_stamp = {};
        hot.locked = !platform::contains_secure_key(state.key_arena, name);
        return false;
    }
    const auto new_key_stamp =
        cold.config.key_storage == runtime::KeyStorage::File
            ? read_file_stamp(cold.key_path)
            : observation::DatabaseMetadataStamp{};
    const bool stamp_changed = cold.key_file_stamp != new_key_stamp;
    cold.key_file_stamp = new_key_stamp;

    const bool has_arena = platform::contains_secure_key(state.key_arena, name);
    if (has_arena && !force_recheck && !stamp_changed) {
        hot.locked = false;
        return false;
    }

    // Resolve stored key from OS vault or file into RAM arena.
    std::expected<runtime::vault::KeyBytes, runtime::Error> stored =
        std::unexpected(runtime::Error{
            .code = runtime::ErrorCode::KeyNotFound,
            .detail = "missing",
        });
    if (cold.config.key_storage == runtime::KeyStorage::Vault) {
        stored = runtime::vault::read_vault(cold.key_path);
    } else {
        stored = runtime::vault::read_only(cold.key_path);
    }
    if (stored) {
        hot.vault_recheck_attempts = 0;
        hot.next_vault_recheck_at = {};
        detail::WipedBytes<runtime::vault::KEY_SIZE> existing_bytes;
        const bool had_existing = platform::read_secure_key(
            state.key_arena, name, existing_bytes.data);
        const bool changed =
            had_existing &&
            crypto_verify32(existing_bytes.data.data(), stored->data()) != 0;
        if (!had_existing || changed) {
            const bool was_locked = hot.locked;
            if (platform::store_secure_key(state.key_arena, name, *stored)) {
                hot.locked = false;
                hot.needs_attention = false;
                telemetry.last_error.clear();
                if (changed) {
                    ++hot.config_generation;
                    warm.warm_observation = {.database_path =
                                                 cold.database_path};
                    if (warm.task_stop_source) {
                        warm.task_stop_source->request_stop();
                    }
                    hot.next_sync_at = std::chrono::steady_clock::now();
                } else if (was_locked) {
                    hot.next_sync_at = std::chrono::steady_clock::now();
                }
            }
        } else {
            hot.locked = false;
            hot.needs_attention = false;
            telemetry.last_error.clear();
        }
        crypto::secure_memory::wipe(stored->data(), stored->size());
        return changed;
    }

    if (has_arena) {
        platform::erase_secure_key(state.key_arena, name);
        ++hot.config_generation;
        warm.warm_observation = {.database_path = cold.database_path};
    }
    hot.locked = true;
    hot.needs_attention = true;
    telemetry.last_error = stored.error().detail;
    if (cold.config.key_storage == runtime::KeyStorage::Vault) {
        hot.next_vault_recheck_at =
            std::chrono::steady_clock::now() +
            next_vault_recheck_delay(hot.vault_recheck_attempts);
        if (hot.vault_recheck_attempts < 4U) {
            ++hot.vault_recheck_attempts;
        }
    } else {
        hot.vault_recheck_attempts = 0;
        hot.next_vault_recheck_at = {};
    }
    return has_arena;
}

std::expected<void, DaemonError>
sync_profiles_from_disk_locked(DaemonSessionState& state,
                               std::unique_lock<std::mutex>& lock,
                               bool force_key_recheck = false) {
    const auto cfg_path = state.environment.app_data_dir / "config.toml";
    const auto cfg_stamp = read_file_stamp(cfg_path);
    auto loaded = runtime::load_profiles(cfg_path);
    if (!loaded) {
        if (loaded.error().code == runtime::ErrorCode::ConfigNotFound) {
            loaded = std::vector<runtime::ProfileData>{};
        } else {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::ConfigFailure,
                .detail = loaded.error().detail,
            });
        }
    }

    state.config_stamp = cfg_stamp;
    state.has_config_stamp = true;

    std::vector<runtime::ProfileData> disk_profiles = std::move(*loaded);
    std::ranges::sort(disk_profiles, {}, &runtime::ProfileData::name);
    const auto has_disk_profile = [&](std::string_view name) {
        return std::ranges::binary_search(
            disk_profiles, name, {}, &runtime::ProfileData::name);
    };

    std::vector<platform::DirectoryWatcher> watchers_to_stop;
    std::vector<std::shared_ptr<WatcherContext>> ctx_to_detach;
    std::vector<std::optional<transport::Transport>> transports_to_close;

    // 1. Remove deleted profiles cleanly across all SoA arrays.
    for (std::size_t i = state.profiles.names.size(); i > 0; --i) {
        const std::size_t idx = i - 1U;
        if (!has_disk_profile(state.profiles.names[idx])) {
            auto& hot = state.profiles.hot[idx];
            auto& warm = state.profiles.warm[idx];
            if (hot.in_flight) {
                // Cancel active task first; defer erasure until next reload.
                if (warm.task_stop_source) {
                    warm.task_stop_source->request_stop();
                }
                hot.paused = true;
                continue;
            }
            if (warm.watcher_ctx) {
                ctx_to_detach.push_back(std::move(warm.watcher_ctx));
            }
            if (platform::directory_watcher_valid(warm.watcher)) {
                watchers_to_stop.push_back(std::move(warm.watcher));
            }
            if (warm.warm_transport) {
                transports_to_close.push_back(std::move(warm.warm_transport));
                warm.warm_transport.reset();
            }
            platform::erase_secure_key(state.key_arena,
                                       state.profiles.names[idx]);
            erase_profile_slot(state.profiles, idx);
        }
    }

    const auto now_steady = std::chrono::steady_clock::now();
    const auto now_unix = current_unix_seconds();
    // 2. Add new profiles or update changed settings.
    for (const auto& cfg : disk_profiles) {
        const auto paths = runtime::resolve_profile_paths(
            state.environment.app_data_dir, cfg.name);
        if (!paths) {
            continue;
        }
        const auto existing = find_profile_slot(state.profiles, cfg.name);
        if (!existing) {
            const auto sync_sec =
                cfg.sync_interval_seconds.value_or(kDefaultSyncIntervalSeconds);
            const auto gc_hrs =
                cfg.gc_interval_hours.value_or(kDefaultGcIntervalHours);
            ProfileHotSchedule hot{
                .paused = cfg.paused,
                .watch_enabled = cfg.watch_enabled.value_or(true),
                .sync_interval_seconds = sync_sec,
                .gc_interval_hours = gc_hrs,
                .next_sync_at =
                    sync_sec > 0
                        ? (now_steady + std::chrono::seconds{2})
                        : (std::chrono::steady_clock::time_point::max)(),
                .next_gc_at = compute_initial_next_gc_at(
                    state.environment, cfg.name, gc_hrs, now_steady, now_unix),
                .last_full_verify_at = now_steady,
            };
            ProfileColdMeta cold{
                .config = cfg,
                .database_path = paths->database_path,
                .key_path = paths->key_path,
            };
            ProfileWarmSlot warm;
            warm.warm_observation.database_path = paths->database_path;

            insert_profile_slot(state.profiles,
                                cfg.name,
                                std::move(hot),
                                ProfileTelemetryRow{},
                                std::move(cold),
                                std::move(warm));
            if (const auto slot = find_profile_slot(state.profiles, cfg.name)) {
                static_cast<void>(
                    refresh_key_status_for_slot(state, *slot, true));
            }
        } else {
            const std::size_t idx = *existing;
            auto& hot = state.profiles.hot[idx];
            auto& telemetry = state.profiles.telemetry[idx];
            auto& cold = state.profiles.cold[idx];
            auto& warm = state.profiles.warm[idx];

            const bool transport_changed =
                cold.config.remote_dir != cfg.remote_dir ||
                cold.config.rclone_config != cfg.rclone_config ||
                cold.config.bandwidth_limit != cfg.bandwidth_limit ||
                cold.config.local_dir != cfg.local_dir;
            const bool key_mode_changed =
                cold.config.key_storage != cfg.key_storage;
            const bool watch_changed =
                cold.config.local_dir != cfg.local_dir ||
                hot.watch_enabled != cfg.watch_enabled.value_or(true) ||
                hot.paused != cfg.paused;
            const bool sync_interval_changed =
                cold.config.sync_interval_seconds != cfg.sync_interval_seconds;
            const bool gc_interval_changed =
                cold.config.gc_interval_hours != cfg.gc_interval_hours;
            const bool unpaused = hot.paused && !cfg.paused;

            cold.config = cfg;
            hot.paused = cfg.paused;
            hot.watch_enabled = cfg.watch_enabled.value_or(true);
            hot.sync_interval_seconds =
                cfg.sync_interval_seconds.value_or(kDefaultSyncIntervalSeconds);
            hot.gc_interval_hours =
                cfg.gc_interval_hours.value_or(kDefaultGcIntervalHours);

            if (key_mode_changed) {
                platform::erase_secure_key(state.key_arena, cfg.name);
                cold.key_file_stamp = {};
            }
            const bool key_changed =
                !hot.in_flight &&
                refresh_key_status_for_slot(
                    state, idx, key_mode_changed || force_key_recheck);
            if (transport_changed || key_mode_changed || key_changed) {
                ++hot.config_generation;
                if (!hot.in_flight) {
                    warm.warm_observation = {.database_path =
                                                 cold.database_path};
                }
            }
            if (transport_changed || key_mode_changed || key_changed ||
                hot.paused) {
                if (warm.task_stop_source) {
                    warm.task_stop_source->request_stop();
                }
                if (warm.warm_transport && !hot.in_flight) {
                    transports_to_close.push_back(
                        std::move(warm.warm_transport));
                    warm.warm_transport.reset();
                }
                if (hot.paused && !hot.in_flight) {
                    clear_active_telemetry(telemetry);
                }
                if (transport_changed) {
                    hot.needs_attention = false;
                    hot.consecutive_failures = 0;
                    hot.backoff_seconds = 0;
                    hot.backoff_until = {};
                    telemetry.last_error.clear();
                }
            }
            if (watch_changed || transport_changed) {
                hot.watcher_baseline_established = false;
                if (warm.watcher_ctx) {
                    ctx_to_detach.push_back(std::move(warm.watcher_ctx));
                }
                if (platform::directory_watcher_valid(warm.watcher)) {
                    watchers_to_stop.push_back(std::move(warm.watcher));
                }
                hot.watcher_healthy = false;
            }
            if (sync_interval_changed || unpaused) {
                hot.next_sync_at =
                    hot.sync_interval_seconds > 0
                        ? (unpaused ? now_steady
                                    : now_steady +
                                          std::chrono::seconds{
                                              hot.sync_interval_seconds})
                        : (std::chrono::steady_clock::time_point::max)();
            }
            if (gc_interval_changed || unpaused) {
                hot.next_gc_at =
                    compute_initial_next_gc_at(state.environment,
                                               cfg.name,
                                               hot.gc_interval_hours,
                                               now_steady,
                                               now_unix);
            }
        }
    }

    // Release lock before shutting down watchers / transports, then start any
    // missing watchers safely.
    lock.unlock();
    for (auto& ctx : ctx_to_detach) {
        std::lock_guard ctx_lock(ctx->mutex);
        ctx->detached = true;
    }
    watchers_to_stop.clear();
    transports_to_close.clear();
    lock.lock();

    // Check external db.sqlite changes (e.g. CLI ran `--initial` or `sync`)
    // to auto-heal NeedsAttention cleanly, and collect missing watchers.
    std::vector<std::string> watchers_needed;
    for (std::size_t idx = 0; idx < state.profiles.names.size(); ++idx) {
        const std::string& name = state.profiles.names[idx];
        auto& hot = state.profiles.hot[idx];
        auto& telemetry = state.profiles.telemetry[idx];
        auto& cold = state.profiles.cold[idx];
        auto& warm = state.profiles.warm[idx];

        const auto db_stamp = read_file_stamp(cold.database_path);
        if (hot.needs_attention && cold.has_external_db_stamp &&
            db_stamp != cold.external_db_stamp) {
            hot.needs_attention = false;
            hot.consecutive_failures = 0;
            hot.backoff_seconds = 0;
            hot.backoff_until = {};
            telemetry.last_error.clear();
            hot.next_sync_at = now_steady;
        }
        cold.external_db_stamp = db_stamp;
        cold.has_external_db_stamp = db_stamp.present;

        if (!hot.paused && hot.watch_enabled &&
            !platform::directory_watcher_healthy(warm.watcher)) {
            watchers_needed.push_back(name);
        }
    }

    if (!watchers_needed.empty()) {
        lock.unlock();
        for (const auto& name : watchers_needed) {
            ensure_watcher_started_unlocked(state, name);
        }
        lock.lock();
    }

    return {};
}

DaemonStatusReport
build_status_locked(const DaemonSessionState& state,
                    std::optional<std::string_view> filter_profile) {
    const auto now_steady = std::chrono::steady_clock::now();
    const auto now_unix = current_unix_seconds();
    const auto uptime =
        now_steady >= state.started_at_steady
            ? static_cast<std::uint64_t>(
                  std::chrono::duration_cast<std::chrono::seconds>(
                      now_steady - state.started_at_steady)
                      .count())
            : 0ULL;

    DaemonStatusReport report{
        .running = state.running,
        .api_version = kDaemonApiVersion,
        .kasumi_version = KASUMI_VERSION,
        .secure_pages_locked =
            platform::secure_key_arena_all_pages_locked(state.key_arena),
        .pid = state.pid,
        .started_at_unix = state.started_at_unix,
        .uptime_seconds = uptime,
        .ipc_port = state.ipc_port,
        .autostart = state.cached_autostart,
    };

    for (std::size_t i = 0; i < state.profiles.names.size(); ++i) {
        const auto& name = state.profiles.names[i];
        if (filter_profile && name != *filter_profile) {
            continue;
        }
        const auto& hot = state.profiles.hot[i];
        const auto& telemetry = state.profiles.telemetry[i];
        const auto& cold = state.profiles.cold[i];
        const auto& warm = state.profiles.warm[i];
        const bool in_backoff =
            hot.backoff_seconds > 0 && hot.backoff_until > now_steady;
        std::uint32_t remaining_backoff_seconds = 0U;
        std::optional<std::int64_t> backoff_until_unix;
        if (in_backoff) {
            const auto rem = std::chrono::duration_cast<std::chrono::seconds>(
                hot.backoff_until - now_steady);
            remaining_backoff_seconds = static_cast<std::uint32_t>(
                std::max<std::int64_t>(1, rem.count()));
            backoff_until_unix = steady_to_unix_estimate(
                hot.backoff_until, now_steady, now_unix);
        }

        DaemonProfileState pstate = DaemonProfileState::Idle;
        if (hot.paused) {
            pstate = DaemonProfileState::Paused;
        } else if (hot.in_flight) {
            pstate = hot.active_gc ? DaemonProfileState::RunningGc
                                   : DaemonProfileState::RunningSync;
        } else if (hot.locked) {
            pstate = DaemonProfileState::Locked;
        } else if (hot.needs_attention) {
            pstate = DaemonProfileState::NeedsAttention;
        } else if (in_backoff) {
            pstate = DaemonProfileState::Backoff;
        } else if (hot.dirty) {
            pstate = DaemonProfileState::PendingDebounce;
        }

        std::optional<std::int64_t> next_sync_unix;
        if (!hot.paused && !hot.locked && !hot.needs_attention &&
            hot.sync_interval_seconds > 0 &&
            hot.next_sync_at != std::chrono::steady_clock::time_point::max()) {
            next_sync_unix =
                steady_to_unix_estimate(hot.next_sync_at, now_steady, now_unix);
        }
        std::optional<std::int64_t> next_gc_unix;
        if (!hot.paused && !hot.locked && !hot.needs_attention &&
            hot.gc_interval_hours > 0 &&
            hot.next_gc_at != std::chrono::steady_clock::time_point::max()) {
            next_gc_unix =
                steady_to_unix_estimate(hot.next_gc_at, now_steady, now_unix);
        }

        report.profiles.push_back(DaemonProfileStatus{
            .name = name,
            .key_storage = static_cast<KeyStorage>(cold.config.key_storage),
            .state = pstate,
            .paused = hot.paused,
            .locked = hot.locked,
            .watch_enabled = hot.watch_enabled,
            .watcher_active = platform::directory_watcher_valid(warm.watcher) &&
                              hot.watcher_healthy,
            .watcher_degraded =
                hot.watch_enabled && !hot.paused && !hot.watcher_healthy,
            .warm_transport_active = warm.warm_transport.has_value(),
            .warm_cache_entries = warm.warm_observation.cache.size(),
            .sync_interval_seconds = hot.sync_interval_seconds,
            .gc_interval_hours = hot.gc_interval_hours,
            .local_dir = platform::path::to_utf8(cold.config.local_dir),
            .remote_dir = cold.config.remote_dir,
            .dirty_paths_count = cold.dirty_paths.size(),
            .active_stage = telemetry.active_stage,
            .active_objects = telemetry.active_objects,
            .active_total_objects = telemetry.active_total_objects,
            .active_bytes = telemetry.active_bytes,
            .active_total_bytes = telemetry.active_total_bytes,
            .last_sync_started_at = telemetry.last_sync_started_at,
            .last_sync_finished_at = telemetry.last_sync_finished_at,
            .last_checked_at = telemetry.last_checked_at,
            .next_sync_at = next_sync_unix,
            .next_gc_at = next_gc_unix,
            .backoff_until_unix = backoff_until_unix,
            .backoff_seconds = remaining_backoff_seconds,
            .consecutive_failures = hot.consecutive_failures,
            .sync_runs = telemetry.sync_runs,
            .fast_noop_polls = telemetry.fast_noop_polls,
            .gc_runs = telemetry.gc_runs,
            .last_outcome = telemetry.last_outcome,
            .last_error = telemetry.last_error,
        });
    }
    return report;
}

void finish_fast_noop(DaemonSessionState& state,
                      const std::string& profile_name,
                      std::uint64_t task_config_gen,
                      std::optional<transport::Transport>& borrowed_owner,
                      observation::LocalObservationSession& warm_obs) {
    const auto now_steady = std::chrono::steady_clock::now();
    const auto now_unix = current_unix_seconds();
    std::optional<transport::Transport> discard_transport;
    {
        std::lock_guard lock(state.mutex);
        if (const auto slot = find_profile_slot(state.profiles, profile_name)) {
            auto& hot = state.profiles.hot[*slot];
            auto& telemetry = state.profiles.telemetry[*slot];
            auto& warm = state.profiles.warm[*slot];
            if (hot.config_generation == task_config_gen && !hot.paused &&
                !hot.locked) {
                warm.warm_observation = std::move(warm_obs);
                if (borrowed_owner) {
                    warm.warm_transport = std::move(borrowed_owner);
                    warm.warm_transport_last_used = now_steady;
                }
            } else {
                discard_transport = std::move(borrowed_owner);
            }
            hot.in_flight = false;
            hot.active_gc = false;
            clear_active_telemetry(telemetry);
            warm.task_stop_source.reset();
            telemetry.last_checked_at = now_unix;
            hot.consecutive_failures = 0;
            hot.backoff_seconds = 0;
            hot.backoff_until = {};
            telemetry.last_error.clear();
            telemetry.last_outcome = "fast_noop";
            ++telemetry.fast_noop_polls;
            ++hot.completed_generation;
            hot.next_sync_at =
                hot.sync_interval_seconds > 0
                    ? (now_steady +
                       std::chrono::seconds{hot.sync_interval_seconds})
                    : (std::chrono::steady_clock::time_point::max)();
        }
    }
    discard_transport.reset();
    emit_daemon_event(state,
                      profile_name,
                      "fast_noop",
                      "remote unchanged (fast poll)",
                      false);
    state.cv.notify_all();
}

void finish_gc_success(DaemonSessionState& state,
                       const std::string& profile_name,
                       std::uint64_t task_config_gen,
                       std::optional<transport::Transport>& borrowed_owner,
                       observation::LocalObservationSession& warm_obs,
                       const std::string& detail) {
    const auto now_steady = std::chrono::steady_clock::now();
    const auto now_unix = current_unix_seconds();
    std::optional<transport::Transport> discard_transport;
    {
        std::lock_guard lock(state.mutex);
        if (const auto slot = find_profile_slot(state.profiles, profile_name)) {
            auto& hot = state.profiles.hot[*slot];
            auto& telemetry = state.profiles.telemetry[*slot];
            auto& warm = state.profiles.warm[*slot];
            if (hot.config_generation == task_config_gen && !hot.paused &&
                !hot.locked) {
                warm.warm_observation = std::move(warm_obs);
                if (borrowed_owner) {
                    warm.warm_transport = std::move(borrowed_owner);
                    warm.warm_transport_last_used = now_steady;
                }
            } else {
                discard_transport = std::move(borrowed_owner);
            }
            hot.in_flight = false;
            hot.active_gc = false;
            clear_active_telemetry(telemetry);
            warm.task_stop_source.reset();
            telemetry.last_checked_at = now_unix;
            telemetry.last_outcome = detail;
            telemetry.last_error.clear();
            ++telemetry.gc_runs;
            ++hot.completed_generation;
            hot.next_gc_at =
                hot.gc_interval_hours > 0
                    ? (now_steady + std::chrono::hours{hot.gc_interval_hours})
                    : (std::chrono::steady_clock::time_point::max)();
        }
    }
    discard_transport.reset();
    state.cv.notify_all();
}

void finish_sync_success(DaemonSessionState& state,
                         const std::string& profile_name,
                         std::uint64_t task_config_gen,
                         std::optional<transport::Transport>& borrowed_owner,
                         observation::LocalObservationSession& warm_obs,
                         std::unordered_set<std::string> remaining_dirty,
                         bool remaining_overflow,
                         const WatcherContext* watcher_ctx_before,
                         bool watcher_healthy_before,
                         const std::string& outcome) {
    const auto now_steady = std::chrono::steady_clock::now();
    const auto now_unix = current_unix_seconds();
    std::optional<transport::Transport> discard_transport;
    {
        std::lock_guard lock(state.mutex);
        if (const auto slot = find_profile_slot(state.profiles, profile_name)) {
            auto& hot = state.profiles.hot[*slot];
            auto& telemetry = state.profiles.telemetry[*slot];
            auto& cold = state.profiles.cold[*slot];
            auto& warm = state.profiles.warm[*slot];
            if (hot.config_generation == task_config_gen && !hot.paused &&
                !hot.locked) {
                warm.warm_observation = std::move(warm_obs);
                if (borrowed_owner) {
                    warm.warm_transport = std::move(borrowed_owner);
                    warm.warm_transport_last_used = now_steady;
                }
            } else {
                discard_transport = std::move(borrowed_owner);
            }
            refresh_ignore_state(cold, warm);
            cold.local_dir_identity =
                platform::private_storage::query_directory_identity(
                    cold.config.local_dir);
            const auto db_stamp = read_file_stamp(cold.database_path);
            cold.external_db_stamp = db_stamp;
            cold.has_external_db_stamp = db_stamp.present;

            hot.in_flight = false;
            hot.active_gc = false;
            clear_active_telemetry(telemetry);
            warm.task_stop_source.reset();
            telemetry.last_sync_finished_at = now_unix;
            telemetry.last_checked_at = now_unix;
            hot.last_full_verify_at = now_steady;
            hot.consecutive_failures = 0;
            hot.backoff_seconds = 0;
            hot.backoff_until = {};
            hot.needs_attention = false;
            telemetry.last_error.clear();
            telemetry.last_outcome = outcome;
            ++telemetry.sync_runs;
            ++hot.completed_generation;

            if (remaining_dirty.empty() && !remaining_overflow) {
                hot.dirty = false;
                hot.overflow = false;
                cold.dirty_paths.clear();
                hot.first_dirty_at.reset();
                hot.last_dirty_at.reset();
                hot.watcher_baseline_established =
                    watcher_healthy_before && watcher_ctx_before != nullptr &&
                    warm.watcher_ctx.get() == watcher_ctx_before &&
                    platform::directory_watcher_valid(warm.watcher) &&
                    hot.watcher_healthy;
            } else {
                hot.dirty = true;
                hot.overflow = remaining_overflow;
                cold.dirty_paths = std::move(remaining_dirty);
                hot.first_dirty_at = now_steady;
                hot.last_dirty_at = now_steady;
            }

            hot.next_sync_at =
                hot.sync_interval_seconds > 0
                    ? (now_steady +
                       std::chrono::seconds{hot.sync_interval_seconds})
                    : (std::chrono::steady_clock::time_point::max)();
        }
    }
    discard_transport.reset();
    state.cv.notify_all();
}

void finish_task_state(DaemonSessionState& state,
                       const std::string& profile_name,
                       std::uint64_t task_config_gen,
                       std::optional<transport::Transport>& borrowed_owner,
                       observation::LocalObservationSession& warm_obs,
                       bool count_failure,
                       bool set_needs_attention,
                       bool set_locked,
                       bool set_backoff,
                       const std::string& error_detail,
                       const std::string& outcome) {
    const auto now_steady = std::chrono::steady_clock::now();
    const auto now_unix = current_unix_seconds();
    std::string event_kind;
    std::optional<transport::Transport> discard_transport;
    {
        std::lock_guard lock(state.mutex);
        if (const auto slot = find_profile_slot(state.profiles, profile_name)) {
            auto& hot = state.profiles.hot[*slot];
            auto& telemetry = state.profiles.telemetry[*slot];
            auto& cold = state.profiles.cold[*slot];
            auto& warm = state.profiles.warm[*slot];
            if (hot.config_generation == task_config_gen && !set_locked &&
                !hot.paused && !hot.locked) {
                warm.warm_observation = std::move(warm_obs);
                if (borrowed_owner) {
                    warm.warm_transport = std::move(borrowed_owner);
                    warm.warm_transport_last_used = now_steady;
                }
            } else {
                discard_transport = std::move(borrowed_owner);
            }
            hot.in_flight = false;
            hot.active_gc = false;
            clear_active_telemetry(telemetry);
            warm.task_stop_source.reset();
            telemetry.last_checked_at = now_unix;
            telemetry.last_error = error_detail;
            if (!outcome.empty()) {
                telemetry.last_outcome = outcome;
            }
            ++hot.completed_generation;

            if (set_locked) {
                platform::erase_secure_key(state.key_arena, profile_name);
                hot.locked = true;
                event_kind = "locked";
            }
            if (set_needs_attention) {
                hot.needs_attention = true;
                hot.dirty = false;
                cold.dirty_paths.clear();
                hot.overflow = false;
                hot.first_dirty_at.reset();
                hot.last_dirty_at.reset();
                event_kind = "needs_attention";
                const auto db_stamp = read_file_stamp(cold.database_path);
                cold.external_db_stamp = db_stamp;
                cold.has_external_db_stamp = db_stamp.present;
            } else if (set_backoff) {
                if (count_failure) {
                    ++hot.consecutive_failures;
                }
                hot.backoff_seconds =
                    compute_jittered_backoff_seconds(hot.consecutive_failures);
                hot.backoff_until =
                    now_steady + std::chrono::seconds{hot.backoff_seconds};
                event_kind = "backoff";
            }
        }
    }
    discard_transport.reset();
    if (!event_kind.empty()) {
        emit_daemon_event(state, profile_name, event_kind, error_detail);
    }
    state.cv.notify_all();
}

void run_profile_task(DaemonSessionState& state,
                      const std::string& profile_name,
                      bool run_gc,
                      bool from_timer_poll,
                      bool manual_trigger) {
    runtime::ProfileData cfg;
    std::filesystem::path db_path;
    std::filesystem::path key_path;
    std::optional<transport::Transport> borrowed_owner;
    observation::LocalObservationSession warm_obs;
    std::uint64_t task_config_gen = 0;
    bool can_try_fast_poll = false;
    bool ignore_present = false;
    observation::DatabaseMetadataStamp ignore_stamp{};
    platform::private_storage::DirectoryIdentity watched_dir_id{};
    std::stop_source task_stop;

    {
        std::lock_guard lock(state.mutex);
        const auto slot = find_profile_slot(state.profiles, profile_name);
        if (!slot) {
            return;
        }
        auto& hot = state.profiles.hot[*slot];
        auto& telemetry = state.profiles.telemetry[*slot];
        auto& cold = state.profiles.cold[*slot];
        auto& warm = state.profiles.warm[*slot];
        warm.task_stop_source = std::make_unique<std::stop_source>();
        task_stop = *warm.task_stop_source;
        task_config_gen = hot.config_generation;
        cfg = cold.config;
        db_path = cold.database_path;
        key_path = cold.key_path;

        if (warm.warm_transport) {
            borrowed_owner = std::move(warm.warm_transport);
            warm.warm_transport.reset();
        }
        warm_obs = std::move(warm.warm_observation);
        warm.warm_observation = {};

        const auto now = std::chrono::steady_clock::now();
        can_try_fast_poll =
            !run_gc && !manual_trigger && from_timer_poll && !hot.dirty &&
            !hot.overflow && platform::directory_watcher_valid(warm.watcher) &&
            hot.watcher_healthy && hot.watcher_baseline_established &&
            (now - hot.last_full_verify_at <
             state.options.full_scan_verification_interval);
        ignore_present = cold.ignore_file_present;
        ignore_stamp = cold.ignore_stamp;
        watched_dir_id = cold.local_dir_identity;
        telemetry.active_stage = run_gc ? "gc" : "checking";
        telemetry.active_objects = 0;
        telemetry.active_total_objects.reset();
        telemetry.active_bytes = 0;
        telemetry.active_total_bytes.reset();
    }

    // Combined stop callback forwards daemon master_stop to task_stop.
    std::stop_callback master_forward(state.master_stop.get_token(),
                                      [&]() noexcept {
                                          task_stop.request_stop();
                                      });

    // Verify local_dir root identity hasn't changed (e.g. moved/recreated).
    // If identity changed while watcher seemed healthy, restart the watcher.
    if (watched_dir_id.valid) {
        const auto current_dir_id =
            platform::private_storage::query_directory_identity(cfg.local_dir);
        if (current_dir_id != watched_dir_id) {
            can_try_fast_poll = false;
            {
                std::lock_guard lock(state.mutex);
                if (const auto slot =
                        find_profile_slot(state.profiles, profile_name)) {
                    auto& hot = state.profiles.hot[*slot];
                    hot.watcher_healthy = false;
                    hot.watcher_baseline_established = false;
                }
            }
            ensure_watcher_started_unlocked(state, profile_name);
        }
    }

    // Ensure master key bytes exist in OS-pinned RAM arena.
    detail::WipedBytes<runtime::vault::KEY_SIZE> clear_key;
    if (!platform::read_secure_key(
            state.key_arena, profile_name, clear_key.data)) {
        if (cfg.key_storage == runtime::KeyStorage::Memory) {
            finish_task_state(state,
                              profile_name,
                              task_config_gen,
                              borrowed_owner,
                              warm_obs,
                              false,
                              false,
                              true,
                              false,
                              "profile key is locked in memory",
                              "");
            return;
        }
        const auto resolved = cfg.key_storage == runtime::KeyStorage::Vault
                                  ? runtime::vault::read_vault(key_path)
                                  : runtime::vault::read_only(key_path);
        if (!resolved) {
            finish_task_state(state,
                              profile_name,
                              task_config_gen,
                              borrowed_owner,
                              warm_obs,
                              false,
                              true,
                              true,
                              false,
                              resolved.error().detail,
                              "");
            return;
        }
        clear_key.data = *resolved;
        static_cast<void>(platform::store_secure_key(
            state.key_arena, profile_name, clear_key.data));
    }

    // Ensure warm transport exists & passes health check.
    bool opened_new_transport = false;
    if (borrowed_owner) {
        const auto health = transport::check_health(*borrowed_owner);
        if (!health) {
            borrowed_owner.reset();
        }
    }
    if (!borrowed_owner) {
        auto opened = transport::open_transport(
            cfg.remote_dir,
            transport::TransportOptions{
                .forbidden_executable_root = cfg.local_dir,
                .rclone_config = cfg.rclone_config,
                .bandwidth_limit = cfg.bandwidth_limit,
            });
        if (opened) {
            borrowed_owner = std::move(*opened);
            opened_new_transport = true;
        } else {
            const auto msg = transport::describe(opened.error());
            finish_task_state(state,
                              profile_name,
                              task_config_gen,
                              borrowed_owner,
                              warm_obs,
                              false,
                              false,
                              false,
                              true,
                              msg,
                              "");
            return;
        }
    }
    if (opened_new_transport) {
        emit_daemon_event(state,
                          profile_name,
                          "warm_transport_opened",
                          "warm rclone transport session ready");
    }

    // Check if fast no-op poll proves both local & remote are unchanged.
    const auto resolved_runtime =
        runtime::resolve(state.environment.app_data_dir,
                         profile_name,
                         runtime::AccessMode::ReadOnly,
                         false);
    if (can_try_fast_poll && resolved_runtime && !task_stop.stop_requested()) {
        const auto fast =
            daemon_detail::try_fast_remote_noop_poll(state.environment,
                                                     profile_name,
                                                     *resolved_runtime,
                                                     *borrowed_owner,
                                                     clear_key.data,
                                                     warm_obs,
                                                     ignore_present,
                                                     ignore_stamp);
        if (fast.profile_locked) {
            finish_task_state(state,
                              profile_name,
                              task_config_gen,
                              borrowed_owner,
                              warm_obs,
                              false,
                              false,
                              false,
                              true,
                              fast.reason,
                              "");
            return;
        }
        if (fast.verdict == daemon_detail::FastPollVerdict::NoChanges) {
            bool still_clean = false;
            {
                std::lock_guard lock(state.mutex);
                if (const auto slot =
                        find_profile_slot(state.profiles, profile_name)) {
                    const auto& hot = state.profiles.hot[*slot];
                    still_clean = !hot.dirty && !hot.overflow && !hot.locked &&
                                  !hot.paused && hot.watcher_healthy &&
                                  hot.watcher_baseline_established &&
                                  hot.config_generation == task_config_gen &&
                                  !task_stop.stop_requested();
                }
            }
            if (still_clean) {
                finish_fast_noop(state,
                                 profile_name,
                                 task_config_gen,
                                 borrowed_owner,
                                 warm_obs);
                return;
            }
        }
        if (fast.transport_error) {
            borrowed_owner.reset();
            finish_task_state(state,
                              profile_name,
                              task_config_gen,
                              borrowed_owner,
                              warm_obs,
                              false,
                              false,
                              false,
                              true,
                              fast.reason,
                              "");
            return;
        }
    }

    // Before full sync: fail-closed with clean NeedsAttention if db.sqlite is
    // missing or invalid and requires `--initial`.
    if (!run_gc && !db_schema_valid(db_path)) {
        finish_task_state(state,
                          profile_name,
                          task_config_gen,
                          borrowed_owner,
                          warm_obs,
                          false,
                          true,
                          false,
                          false,
                          "profile requires initial sync ('kasumi sync " +
                              profile_name + " --initial')",
                          "");
        return;
    }

    // Snapshot watcher state right when profile-<name>.lock is acquired inside
    // execute_warm, BEFORE local scan reads files.
    const WatcherContext* watcher_ctx_before = nullptr;
    bool watcher_healthy_before = false;
    std::unordered_set<std::string> dirty_snapshot;
    bool had_overflow_snapshot = false;

    detail::WarmExecutionContext warm_ctx{
        .borrowed_transport = borrowed_owner ? &*borrowed_owner : nullptr,
        .warm_observation = &warm_obs,
        .on_lock_acquired =
            [&]() {
                std::lock_guard lock(state.mutex);
                if (const auto slot =
                        find_profile_slot(state.profiles, profile_name)) {
                    auto& hot = state.profiles.hot[*slot];
                    auto& telemetry = state.profiles.telemetry[*slot];
                    auto& cold = state.profiles.cold[*slot];
                    auto& warm = state.profiles.warm[*slot];
                    watcher_ctx_before = warm.watcher_ctx.get();
                    watcher_healthy_before =
                        platform::directory_watcher_valid(warm.watcher) &&
                        hot.watcher_healthy;
                    dirty_snapshot = cold.dirty_paths;
                    had_overflow_snapshot = hot.overflow;
                    cold.dirty_paths.clear();
                    hot.overflow = false;
                    telemetry.last_sync_started_at = current_unix_seconds();
                }
            },
        .origin_daemon = true,
    };

    const ExecutionInput exec_input{
        .request =
            Request{
                .operation =
                    run_gc ? Operation::GarbageCollect : Operation::Sync,
                .profile_name = profile_name,
                .bandwidth_limit = cfg.bandwidth_limit,
                .transfer_concurrency = cfg.transfer_concurrency,
            },
        .credentials = MasterKeyBytes{clear_key.data},
        .environment = state.environment,
        .on_progress =
            [&](const ExecutionProgress& progress) {
                std::lock_guard lock(state.mutex);
                const auto slot =
                    find_profile_slot(state.profiles, profile_name);
                if (!slot) {
                    return;
                }
                auto& telemetry = state.profiles.telemetry[*slot];
                if (const auto* act =
                        std::get_if<ActivityProgress>(&progress)) {
                    telemetry.active_stage =
                        activity_stage_label(act->activity);
                    telemetry.active_objects = act->objects;
                    telemetry.active_total_objects = act->total_objects;
                    telemetry.active_bytes = act->bytes;
                    telemetry.active_total_bytes = act->total_bytes;
                } else if (const auto* sp =
                               std::get_if<SyncProgress>(&progress)) {
                    switch (sp->stage) {
                        case SyncStage::Observing:
                            telemetry.active_stage = "observing";
                            break;
                        case SyncStage::Calculating:
                            telemetry.active_stage = "calculating";
                            break;
                        case SyncStage::Applying:
                            telemetry.active_stage = "applying";
                            break;
                        case SyncStage::Publishing:
                            telemetry.active_stage = "publishing";
                            break;
                        case SyncStage::Finalizing:
                            telemetry.active_stage = "finalizing";
                            break;
                    }
                } else if (const auto* gp =
                               std::get_if<GarbageCollectProgress>(&progress)) {
                    switch (gp->stage) {
                        case GarbageCollectStage::Preparing:
                            telemetry.active_stage = "gc_preparing";
                            break;
                        case GarbageCollectStage::Analyzing:
                            telemetry.active_stage = "gc_analyzing";
                            break;
                        case GarbageCollectStage::Applying:
                            telemetry.active_stage = "gc_applying";
                            break;
                        case GarbageCollectStage::Finalizing:
                            telemetry.active_stage = "gc_finalizing";
                            break;
                    }
                }
            },
        .stop_token = task_stop.get_token(),
    };

    const auto exec_started = std::chrono::steady_clock::now();
    auto res = detail::execute_warm(exec_input, warm_ctx);

    if (res) {
        if (run_gc) {
            const auto* gc_done =
                std::get_if<GarbageCollectCompleted>(&res->data);
            const std::string detail =
                gc_done ? std::format("removed {} objects ({} bytes)",
                                      gc_done->removed_objects,
                                      gc_done->removed_bytes)
                        : std::string{"gc completed"};
            finish_gc_success(state,
                              profile_name,
                              task_config_gen,
                              borrowed_owner,
                              warm_obs,
                              detail);
            emit_daemon_event(state, profile_name, "gc_completed", detail);
            return;
        }

        const auto* sync_done = std::get_if<SyncCompleted>(&res->data);
        const std::string outcome =
            sync_done ? format_sync_outcome(*sync_done) : std::string{"ok"};

        // Cache + committed-tree self-mutation pruning so daemon downloads and
        // deletions do not retrigger redundant sync cycles while preserving
        // concurrent user edits (including newly created files not yet in the
        // published commit tree).
        std::unordered_set<std::string> remaining_dirty;
        bool remaining_overflow = false;
        {
            std::lock_guard lock(state.mutex);
            if (const auto slot =
                    find_profile_slot(state.profiles, profile_name)) {
                auto& hot = state.profiles.hot[*slot];
                auto& cold = state.profiles.cold[*slot];
                remaining_dirty = std::move(cold.dirty_paths);
                remaining_overflow = hot.overflow;
                cold.dirty_paths.clear();
                hot.overflow = false;
            }
        }

        if (!remaining_dirty.empty() && !remaining_overflow) {
            if (!std::ranges::is_sorted(
                    warm_obs.cache, {}, &state_storage::FileCacheRow::path)) {
                std::ranges::sort(
                    warm_obs.cache, {}, &state_storage::FileCacheRow::path);
            }
            std::optional<state_storage::StoredState> stored_state;
            bool loaded_stored = false;
            auto ensure_stored_state = [&]() {
                if (!loaded_stored) {
                    loaded_stored = true;
                    auto s = state_storage::load_state(db_path);
                    if (s && s->has_value()) {
                        stored_state = std::move(**s);
                    }
                }
            };
            auto is_pending_path = [&](std::string_view rel) {
                if (!stored_state) {
                    return false;
                }
                return std::ranges::any_of(
                    stored_state->pending_materializations,
                    [&](const NodeRow& row) {
                        return row.path == rel;
                    });
            };

            for (auto it = remaining_dirty.begin();
                 it != remaining_dirty.end();) {
                const auto& rel = *it;
                const auto phys =
                    cfg.local_dir / platform::path::from_utf8(rel);
                bool matched_synced_state = false;
                const auto cache_it = std::ranges::lower_bound(
                    warm_obs.cache,
                    rel,
                    {},
                    &state_storage::FileCacheRow::path);
                if (cache_it != warm_obs.cache.end() && cache_it->path == rel) {
                    const auto meta =
                        observation::cache::read_file_metadata(phys, rel);
                    if (meta && meta->has_value() &&
                        (*meta)->identity.has_value()) {
                        const auto& c = *cache_it;
                        const auto& m = **meta;
                        if (m.size == c.size &&
                            m.mtime_nanoseconds == c.mtime_nanoseconds &&
                            m.identity->volume == c.volume &&
                            m.identity->file_low == c.file_low &&
                            m.identity->file_high == c.file_high) {
                            ensure_stored_state();
                            if (stored_state) {
                                const auto* row =
                                    find_row(stored_state->tree, rel);
                                matched_synced_state = row != nullptr &&
                                                       !row->is_directory &&
                                                       row->hash == c.hash &&
                                                       row->size == c.size &&
                                                       !is_pending_path(rel);
                            }
                        }
                    }
                } else {
                    std::error_code ec;
                    const auto st = std::filesystem::symlink_status(phys, ec);
                    if (ec == std::errc::no_such_file_or_directory ||
                        (!ec &&
                         st.type() == std::filesystem::file_type::not_found)) {
                        ensure_stored_state();
                        matched_synced_state =
                            stored_state &&
                            find_row(stored_state->tree, rel) == nullptr;
                    } else if (!ec && std::filesystem::is_directory(st)) {
                        ensure_stored_state();
                        if (stored_state) {
                            const auto* row = find_row(stored_state->tree, rel);
                            matched_synced_state =
                                row != nullptr && row->is_directory;
                        }
                    }
                }

                if (matched_synced_state) {
                    it = remaining_dirty.erase(it);
                } else {
                    ++it;
                }
            }
        }

        finish_sync_success(state,
                            profile_name,
                            task_config_gen,
                            borrowed_owner,
                            warm_obs,
                            std::move(remaining_dirty),
                            remaining_overflow,
                            watcher_ctx_before,
                            watcher_healthy_before,
                            outcome);
        const double exec_seconds =
            std::chrono::duration<double>(std::chrono::steady_clock::now() -
                                          exec_started)
                .count();
        emit_daemon_event(state,
                          profile_name,
                          "sync_completed",
                          std::format("{} ({:.1f} s)", outcome, exec_seconds));
        return;
    }

    // Sync or GC failed: check if warm transport should be discarded and
    // classify transient backoff vs permanent NeedsAttention.
    const auto& err = res.error();
    const bool cancelled =
        task_stop.stop_requested() || state.master_stop.stop_requested();
    if (cancelled) {
        if (borrowed_owner && !transport::check_health(*borrowed_owner)) {
            borrowed_owner.reset();
        }
        std::optional<transport::Transport> discard_transport;
        {
            std::lock_guard lock(state.mutex);
            if (const auto slot =
                    find_profile_slot(state.profiles, profile_name)) {
                auto& hot = state.profiles.hot[*slot];
                auto& telemetry = state.profiles.telemetry[*slot];
                auto& cold = state.profiles.cold[*slot];
                auto& warm = state.profiles.warm[*slot];
                if (hot.config_generation == task_config_gen && !hot.paused &&
                    !hot.locked) {
                    warm.warm_observation = std::move(warm_obs);
                    if (borrowed_owner) {
                        warm.warm_transport = std::move(borrowed_owner);
                        warm.warm_transport_last_used =
                            std::chrono::steady_clock::now();
                    }
                } else {
                    discard_transport = std::move(borrowed_owner);
                }
                cold.dirty_paths.insert(dirty_snapshot.begin(),
                                        dirty_snapshot.end());
                hot.overflow = hot.overflow || had_overflow_snapshot;
                hot.in_flight = false;
                hot.active_gc = false;
                clear_active_telemetry(telemetry);
                warm.task_stop_source.reset();
                ++hot.completed_generation;
                telemetry.last_error = err.detail;
            }
        }
        discard_transport.reset();
        state.cv.notify_all();
        return;
    }

    const bool local_mutation_race =
        daemon_detail::is_concurrent_local_mutation_error(err);
    if (borrowed_owner && ((!local_mutation_race &&
                            daemon_detail::is_transient_sync_error(err)) ||
                           !transport::check_health(*borrowed_owner))) {
        borrowed_owner.reset();
    }
    const bool transient = daemon_detail::is_transient_sync_error(err);
    const bool lock_only = ((err.code == ErrorCode::CredentialFailure ||
                             err.code == ErrorCode::CredentialsRequired) &&
                            cfg.key_storage == runtime::KeyStorage::Memory);
    if (run_gc) {
        // Transient GC contention waits for next window instead of
        // NeedsAttention.
        std::optional<transport::Transport> discard_transport;
        {
            std::lock_guard lock(state.mutex);
            if (const auto slot =
                    find_profile_slot(state.profiles, profile_name)) {
                auto& hot = state.profiles.hot[*slot];
                auto& telemetry = state.profiles.telemetry[*slot];
                auto& warm = state.profiles.warm[*slot];
                if (hot.config_generation == task_config_gen && !hot.paused &&
                    !hot.locked) {
                    warm.warm_observation = std::move(warm_obs);
                    if (borrowed_owner) {
                        warm.warm_transport = std::move(borrowed_owner);
                        warm.warm_transport_last_used =
                            std::chrono::steady_clock::now();
                    }
                } else {
                    discard_transport = std::move(borrowed_owner);
                }
                hot.in_flight = false;
                hot.active_gc = false;
                clear_active_telemetry(telemetry);
                warm.task_stop_source.reset();
                ++hot.completed_generation;
                telemetry.last_error = err.detail;
                telemetry.last_outcome = "gc_deferred";
                hot.next_gc_at =
                    transient
                        ? std::chrono::steady_clock::now() +
                              std::chrono::minutes{15}
                        : (hot.gc_interval_hours > 0
                               ? std::chrono::steady_clock::now() +
                                     std::chrono::hours{hot.gc_interval_hours}
                               : (std::chrono::steady_clock::time_point::
                                      max)());
            }
        }
        discard_transport.reset();
        state.cv.notify_all();
        return;
    }

    // Restore any dirty snapshot before recording failure state.
    {
        std::lock_guard lock(state.mutex);
        if (const auto slot = find_profile_slot(state.profiles, profile_name)) {
            auto& hot = state.profiles.hot[*slot];
            auto& cold = state.profiles.cold[*slot];
            cold.dirty_paths.insert(dirty_snapshot.begin(),
                                    dirty_snapshot.end());
            hot.overflow = hot.overflow || had_overflow_snapshot;
            if (!cold.dirty_paths.empty() || hot.overflow) {
                hot.dirty = true;
            }
        }
    }
    finish_task_state(state,
                      profile_name,
                      task_config_gen,
                      borrowed_owner,
                      warm_obs,
                      true,
                      !transient && !lock_only,
                      lock_only,
                      transient,
                      err.detail,
                      "failed");
}

void reap_finished_workers_locked(DaemonSessionState& state) {
    for (auto it = state.workers.begin(); it != state.workers.end();) {
        if (it->finished->load(std::memory_order_acquire)) {
            if (it->thread.joinable()) {
                it->thread.join();
            }
            it = state.workers.erase(it);
        } else {
            ++it;
        }
    }
}

void request_stop_internal(DaemonSessionState& state) noexcept {
    {
        std::lock_guard lock(state.mutex);
        state.stop_requested = true;
        state.master_stop.request_stop();
        for (auto& warm : state.profiles.warm) {
            if (warm.task_stop_source) {
                warm.task_stop_source->request_stop();
            }
        }
    }
    state.cv.notify_all();
}

void cleanup_daemon_resources(DaemonSessionState& state,
                              bool join_scheduler) noexcept {
    if (join_scheduler && state.scheduler_thread.joinable() &&
        state.scheduler_thread.get_id() != std::this_thread::get_id()) {
        state.scheduler_thread.join();
    }
    std::lock_guard cleanup_lock(state.cleanup_mutex);
    if (state.cleaned_up) {
        return;
    }

    if (state.ipc_server) {
        state.ipc_server->stop();
    }
    if (state.ipc_thread.joinable() &&
        state.ipc_thread.get_id() != std::this_thread::get_id()) {
        state.ipc_thread.join();
    }
    state.ipc_server.reset();

    std::vector<WorkerSlot> remaining_workers;
    {
        std::lock_guard lock(state.mutex);
        remaining_workers = std::move(state.workers);
    }
    for (auto& w : remaining_workers) {
        if (w.thread.joinable()) {
            w.thread.join();
        }
    }

    platform::stop_directory_watcher(state.config_watcher);

    bool was_running = false;
    ProfileTable moved_profiles;
    ExecutionEnvironment env_copy;
    {
        std::lock_guard lock(state.mutex);
        was_running = state.running;
        env_copy = state.environment;
        for (auto& warm : state.profiles.warm) {
            if (warm.watcher_ctx) {
                std::lock_guard ctx_lock(warm.watcher_ctx->mutex);
                warm.watcher_ctx->detached = true;
            }
        }
        moved_profiles = std::move(state.profiles);
        state.active_workers = 0;
        state.ipc_port = 0;
        state.running = false;
    }
    moved_profiles = {};
    platform::clear_secure_key_arena(state.key_arena);
    crypto::secure_memory::wipe(state.auth_token.data(),
                                state.auth_token.size());
    crypto::secure_memory::wipe(state.ipc_key.data(), state.ipc_key.size());

    if (!env_copy.app_data_dir.empty()) {
        daemon_detail::remove_control_metadata_best_effort(
            daemon_detail::daemon_control_path(env_copy.app_data_dir));
    }
    platform::release_profile_lock(state.daemon_lock);
    state.cleaned_up = true;
    if (was_running) {
        emit_daemon_event(state, "", "stopped", "daemon engine stopped");
    }
}

void scheduler_loop(DaemonSessionState& state) {
    std::unique_lock lock(state.mutex);
    auto last_config_poll = std::chrono::steady_clock::now();

    while (!state.stop_requested) {
        reap_finished_workers_locked(state);
        const auto now = std::chrono::steady_clock::now();

        // 1. Check config.toml reload on watcher trigger or file metadata
        // stamp change, and check key.bin/db.sqlite stamps without redundant
        // TOML re-parses when idle.
        const bool dirty_flagged =
            state.config_dirty.exchange(false, std::memory_order_acq_rel);
        const bool poll_due =
            now - last_config_poll >= state.options.config_poll_interval;
        if (dirty_flagged || poll_due) {
            last_config_poll = now;
            const auto cfg_stamp =
                read_file_stamp(state.environment.app_data_dir / "config.toml");
            if (!state.has_config_stamp || dirty_flagged ||
                cfg_stamp != state.config_stamp) {
                static_cast<void>(sync_profiles_from_disk_locked(state, lock));
            } else {
                const auto now_steady = std::chrono::steady_clock::now();
                std::vector<std::string> watchers_needed;
                for (std::size_t idx = 0; idx < state.profiles.names.size();
                     ++idx) {
                    auto& hot = state.profiles.hot[idx];
                    auto& telemetry = state.profiles.telemetry[idx];
                    auto& cold = state.profiles.cold[idx];
                    auto& warm = state.profiles.warm[idx];

                    if (!hot.in_flight &&
                        cold.config.key_storage == runtime::KeyStorage::File) {
                        const auto key_stamp = read_file_stamp(cold.key_path);
                        if (key_stamp != cold.key_file_stamp) {
                            if (refresh_key_status_for_slot(state, idx, true)) {
                                ++hot.config_generation;
                                warm.warm_observation = {
                                    .database_path = cold.database_path};
                                if (warm.warm_transport) {
                                    warm.warm_transport.reset();
                                }
                            }
                        }
                    }

                    const auto db_stamp = read_file_stamp(cold.database_path);
                    if (hot.needs_attention && cold.has_external_db_stamp &&
                        db_stamp != cold.external_db_stamp) {
                        hot.needs_attention = false;
                        hot.consecutive_failures = 0;
                        hot.backoff_seconds = 0;
                        hot.backoff_until = {};
                        telemetry.last_error.clear();
                        hot.next_sync_at = now_steady;
                    }
                    cold.external_db_stamp = db_stamp;
                    cold.has_external_db_stamp = db_stamp.present;

                    if (!hot.paused && hot.watch_enabled &&
                        !platform::directory_watcher_healthy(warm.watcher)) {
                        watchers_needed.push_back(state.profiles.names[idx]);
                    }
                }
                if (!watchers_needed.empty()) {
                    lock.unlock();
                    for (const auto& name : watchers_needed) {
                        ensure_watcher_started_unlocked(state, name);
                    }
                    lock.lock();
                }
            }
        }

        // 2. Evict idle warm transports past TTL.
        std::vector<std::optional<transport::Transport>> expired_transports;
        std::vector<std::string> expired_names;
        for (std::size_t idx = 0; idx < state.profiles.names.size(); ++idx) {
            const auto& hot = state.profiles.hot[idx];
            auto& warm = state.profiles.warm[idx];
            if (!hot.in_flight && warm.warm_transport &&
                now - warm.warm_transport_last_used >=
                    state.options.warm_transport_idle_ttl) {
                expired_transports.push_back(std::move(warm.warm_transport));
                warm.warm_transport.reset();
                expired_names.push_back(state.profiles.names[idx]);
            }
        }
        if (!expired_transports.empty()) {
            lock.unlock();
            expired_transports.clear();
            for (const auto& name : expired_names) {
                emit_daemon_event(state,
                                  name,
                                  "warm_transport_evicted",
                                  "evicted idle warm transport session");
            }
            lock.lock();
        }

        // 2b. Re-check locked OS vault profiles (e.g. keyring unlocked after
        // systemd/autostart boot) outside the scheduler mutex.
        struct VaultRecheckCandidate {
            std::string name;
            std::filesystem::path key_path;
            std::uint64_t config_generation = 0;
        };
        std::vector<VaultRecheckCandidate> vault_candidates;
        for (std::size_t idx = 0; idx < state.profiles.names.size(); ++idx) {
            const auto& hot = state.profiles.hot[idx];
            const auto& cold = state.profiles.cold[idx];
            if (!hot.in_flight && !hot.paused && hot.locked &&
                cold.config.key_storage == runtime::KeyStorage::Vault &&
                hot.next_vault_recheck_at !=
                    std::chrono::steady_clock::time_point{} &&
                now >= hot.next_vault_recheck_at) {
                vault_candidates.push_back(VaultRecheckCandidate{
                    .name = state.profiles.names[idx],
                    .key_path = cold.key_path,
                    .config_generation = hot.config_generation,
                });
            }
        }
        if (!vault_candidates.empty()) {
            lock.unlock();
            std::vector<
                std::expected<runtime::vault::KeyBytes, runtime::Error>>
                vault_results;
            vault_results.reserve(vault_candidates.size());
            for (const auto& cand : vault_candidates) {
                vault_results.push_back(runtime::vault::read_vault(cand.key_path));
            }
            std::vector<std::string> unlocked_names;
            {
                lock.lock();
                const auto check_now = std::chrono::steady_clock::now();
                for (std::size_t i = 0; i < vault_candidates.size(); ++i) {
                    const auto& cand = vault_candidates[i];
                    auto& res = vault_results[i];
                    const auto slot =
                        find_profile_slot(state.profiles, cand.name);
                    if (!slot) {
                        if (res) {
                            crypto::secure_memory::wipe(res->data(), res->size());
                        }
                        continue;
                    }
                    auto& hot = state.profiles.hot[*slot];
                    auto& telemetry = state.profiles.telemetry[*slot];
                    const auto& cold = state.profiles.cold[*slot];
                    if (hot.config_generation != cand.config_generation ||
                        hot.in_flight || hot.paused || !hot.locked ||
                        cold.config.key_storage != runtime::KeyStorage::Vault) {
                        if (res) {
                            crypto::secure_memory::wipe(res->data(), res->size());
                        }
                        continue;
                    }
                    if (res) {
                        const auto stored_ok = platform::store_secure_key(
                            state.key_arena, cand.name, *res);
                        crypto::secure_memory::wipe(res->data(), res->size());
                        if (stored_ok) {
                            hot.locked = false;
                            hot.needs_attention = false;
                            hot.vault_recheck_attempts = 0;
                            hot.next_vault_recheck_at = {};
                            telemetry.last_error.clear();
                            hot.next_sync_at = check_now;
                            unlocked_names.push_back(cand.name);
                        }
                    } else {
                        telemetry.last_error = res.error().detail;
                        hot.next_vault_recheck_at =
                            check_now + next_vault_recheck_delay(
                                            hot.vault_recheck_attempts);
                        if (hot.vault_recheck_attempts < 4U) {
                            ++hot.vault_recheck_attempts;
                        }
                    }
                }
            }
            if (!unlocked_names.empty()) {
                lock.unlock();
                for (const auto& unlocked_name : unlocked_names) {
                    emit_daemon_event(state,
                                      unlocked_name,
                                      "unlocked",
                                      "profile key loaded from OS vault");
                }
                lock.lock();
            }
        }

        // 3. Scan hot SoA scheduling array contiguously up to
        // max_parallel_profiles.
        struct ScheduledJob {
            std::string name;
            bool run_gc = false;
            bool from_timer = false;
            bool manual = false;
        };
        std::vector<ScheduledJob> jobs;
        auto next_wake = now + state.options.config_poll_interval;

        for (std::size_t idx = 0; idx < state.profiles.hot.size(); ++idx) {
            auto& hot = state.profiles.hot[idx];
            const auto& cold = state.profiles.cold[idx];
            if (hot.locked && !hot.paused && !hot.in_flight &&
                cold.config.key_storage == runtime::KeyStorage::Vault &&
                hot.next_vault_recheck_at !=
                    std::chrono::steady_clock::time_point{}) {
                next_wake = std::min(next_wake, hot.next_vault_recheck_at);
            }
            if (hot.in_flight || hot.paused || hot.locked ||
                hot.needs_attention) {
                continue;
            }
            const auto& name = state.profiles.names[idx];
            if (hot.immediate_sync_requested) {
                if (state.active_workers + jobs.size() <
                    state.options.max_parallel_profiles) {
                    hot.immediate_sync_requested = false;
                    hot.in_flight = true;
                    hot.active_gc = false;
                    jobs.push_back(ScheduledJob{
                        .name = name,
                        .run_gc = false,
                        .from_timer = false,
                        .manual = true,
                    });
                }
                continue;
            }
            if (hot.backoff_seconds > 0 && hot.backoff_until > now) {
                next_wake = std::min(next_wake, hot.backoff_until);
                continue;
            }

            // Evaluate debounced watcher changes.
            if (hot.dirty && hot.last_dirty_at && hot.first_dirty_at) {
                const auto quiet_due =
                    *hot.last_dirty_at + state.options.watch_debounce;
                const auto max_due =
                    *hot.first_dirty_at + state.options.watch_max_wait;
                const auto due = std::min(quiet_due, max_due);
                if (now >= due) {
                    if (state.active_workers + jobs.size() <
                        state.options.max_parallel_profiles) {
                        hot.in_flight = true;
                        hot.active_gc = false;
                        jobs.push_back(ScheduledJob{
                            .name = name,
                            .run_gc = false,
                            .from_timer = false,
                            .manual = false,
                        });
                    }
                    continue;
                }
                next_wake = std::min(next_wake, due);
            }

            // Evaluate periodic poll timer.
            if (hot.sync_interval_seconds > 0 && now >= hot.next_sync_at) {
                if (state.active_workers + jobs.size() <
                    state.options.max_parallel_profiles) {
                    hot.in_flight = true;
                    hot.active_gc = false;
                    jobs.push_back(ScheduledJob{
                        .name = name,
                        .run_gc = false,
                        .from_timer = true,
                        .manual = false,
                    });
                }
                continue;
            }
            if (hot.sync_interval_seconds > 0 &&
                hot.next_sync_at <
                    std::chrono::steady_clock::time_point::max()) {
                next_wake = std::min(next_wake, hot.next_sync_at);
            }

            // Evaluate periodic cooperative GC timer.
            if (hot.gc_interval_hours > 0 && now >= hot.next_gc_at) {
                if (state.active_workers + jobs.size() <
                    state.options.max_parallel_profiles) {
                    hot.in_flight = true;
                    hot.active_gc = true;
                    jobs.push_back(ScheduledJob{
                        .name = name,
                        .run_gc = true,
                        .from_timer = true,
                        .manual = false,
                    });
                }
                continue;
            }
            if (hot.gc_interval_hours > 0 &&
                hot.next_gc_at < std::chrono::steady_clock::time_point::max()) {
                next_wake = std::min(next_wake, hot.next_gc_at);
            }
        }

        // Launch selected jobs on tracked worker threads.
        for (const auto& job : jobs) {
            auto finished_flag = std::make_shared<std::atomic_bool>(false);
            ++state.active_workers;
            try {
                std::thread t([&state, job, finished_flag] {
                    run_profile_task(state,
                                     job.name,
                                     job.run_gc,
                                     job.from_timer,
                                     job.manual);
                    {
                        std::lock_guard g(state.mutex);
                        if (state.active_workers > 0) {
                            --state.active_workers;
                        }
                    }
                    finished_flag->store(true, std::memory_order_release);
                    state.cv.notify_all();
                });
                state.workers.push_back(WorkerSlot{
                    .thread = std::move(t),
                    .finished = std::move(finished_flag),
                });
            } catch (const std::system_error&) {
                if (state.active_workers > 0) {
                    --state.active_workers;
                }
                if (const auto slot =
                        find_profile_slot(state.profiles, job.name)) {
                    auto& hot = state.profiles.hot[*slot];
                    hot.in_flight = false;
                    hot.active_gc = false;
                    if (job.manual) {
                        hot.immediate_sync_requested = true;
                    }
                }
            }
        }

        if (state.stop_requested) {
            break;
        }
        state.cv.wait_until(lock, next_wake, [&] {
            return state.stop_requested;
        });
    }
    lock.unlock();
    cleanup_daemon_resources(state, false);
    state.cv.notify_all();
}

std::expected<DaemonStatusReport, DaemonError>
status_session_state(DaemonSessionState& state,
                     std::optional<std::string_view> profile_name) {
    std::lock_guard lock(state.mutex);
    if (!state.running) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::NotRunning,
            .detail = "daemon engine is not running",
        });
    }
    if (profile_name &&
        !find_profile_slot(state.profiles, *profile_name).has_value()) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::ProfileNotFound,
            .detail = "profile not found: " + std::string{*profile_name},
        });
    }
    return build_status_locked(state, profile_name);
}

DaemonErrorCode map_profile_pause_error_code(ProfileErrorCode code) noexcept {
    switch (code) {
        case ProfileErrorCode::LockFailure:
            return DaemonErrorCode::LockBusy;
        case ProfileErrorCode::NotFound:
            return DaemonErrorCode::ProfileNotFound;
        default:
            return DaemonErrorCode::ConfigFailure;
    }
}

std::expected<void, DaemonError>
reload_session_state(DaemonSessionState& state) {
    DaemonAutostartStatus refreshed_autostart;
    bool has_autostart = false;
    if (const auto as = platform::query_user_autostart()) {
        refreshed_autostart = to_app_autostart(*as);
        has_autostart = true;
    }
    std::expected<void, DaemonError> res;
    {
        std::unique_lock lock(state.mutex);
        if (!state.running) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::NotRunning,
                .detail = "daemon engine is not running",
            });
        }
        if (has_autostart) {
            state.cached_autostart = std::move(refreshed_autostart);
        }
        res = sync_profiles_from_disk_locked(state, lock, true);
    }
    state.cv.notify_all();
    if (res) {
        emit_daemon_event(state, "", "reloaded", "configuration reloaded");
    }
    return res;
}

std::expected<DaemonSyncTriggerReport, DaemonError>
trigger_sync_session_state(DaemonSessionState& state,
                           std::optional<std::string_view> profile_name,
                           bool wait) {
    struct Target {
        std::string name;
        std::uint64_t target_generation = 0;
    };
    std::vector<Target> targets;
    {
        std::unique_lock lock(state.mutex);
        if (!state.running) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::NotRunning,
                .detail = "daemon engine is not running",
            });
        }
        static_cast<void>(sync_profiles_from_disk_locked(state, lock, true));
        if (profile_name) {
            const auto slot = find_profile_slot(state.profiles, *profile_name);
            if (!slot) {
                return std::unexpected(DaemonError{
                    .code = DaemonErrorCode::ProfileNotFound,
                    .detail =
                        "profile not found: " + std::string{*profile_name},
                });
            }
            auto& hot = state.profiles.hot[*slot];
            auto& telemetry = state.profiles.telemetry[*slot];
            if (hot.paused) {
                return std::unexpected(DaemonError{
                    .code = DaemonErrorCode::ConfigFailure,
                    .detail = "profile is paused; resume it before syncing",
                });
            }
            if (hot.locked) {
                return std::unexpected(DaemonError{
                    .code = DaemonErrorCode::InvalidCredential,
                    .detail = "profile is locked; unlock it before syncing",
                });
            }
            hot.needs_attention = false;
            hot.backoff_seconds = 0;
            hot.backoff_until = {};
            telemetry.last_error.clear();
            hot.immediate_sync_requested = true;
            targets.push_back(Target{
                .name = state.profiles.names[*slot],
                .target_generation =
                    hot.completed_generation + (hot.in_flight ? 2U : 1U),
            });
        } else {
            for (std::size_t idx = 0; idx < state.profiles.names.size();
                 ++idx) {
                auto& hot = state.profiles.hot[idx];
                auto& telemetry = state.profiles.telemetry[idx];
                if (hot.paused || hot.locked) {
                    continue;
                }
                hot.needs_attention = false;
                hot.backoff_seconds = 0;
                hot.backoff_until = {};
                telemetry.last_error.clear();
                hot.immediate_sync_requested = true;
                targets.push_back(Target{
                    .name = state.profiles.names[idx],
                    .target_generation =
                        hot.completed_generation + (hot.in_flight ? 2U : 1U),
                });
            }
        }
    }
    state.cv.notify_all();

    DaemonSyncTriggerReport report;
    for (const auto& t : targets) {
        report.profiles.push_back(t.name);
    }
    if (!wait || targets.empty()) {
        report.completed = !wait ? false : true;
        return report;
    }

    std::unique_lock lock(state.mutex);
    state.cv.wait(lock, [&] {
        if (!state.running || state.stop_requested) {
            return true;
        }
        for (const auto& t : targets) {
            const auto slot = find_profile_slot(state.profiles, t.name);
            if (!slot) {
                continue;
            }
            const auto& hot = state.profiles.hot[*slot];
            if (hot.immediate_sync_requested || hot.in_flight ||
                hot.completed_generation < t.target_generation) {
                return false;
            }
        }
        return true;
    });
    if (!state.running || state.stop_requested) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::NotRunning,
            .detail = "daemon stopped before triggered sync completed",
        });
    }
    report.completed = true;
    for (const auto& t : targets) {
        if (const auto slot = find_profile_slot(state.profiles, t.name)) {
            if (!state.profiles.telemetry[*slot].last_error.empty()) {
                report.failures.emplace_back(
                    t.name, state.profiles.telemetry[*slot].last_error);
            }
        }
    }
    return report;
}

std::expected<void, DaemonError>
pause_session_state(DaemonSessionState& state, std::string_view profile_name) {
    platform::DirectoryWatcher watcher_to_stop;
    std::shared_ptr<WatcherContext> ctx_to_detach;
    std::optional<transport::Transport> transport_to_close;
    ExecutionEnvironment env_copy;
    {
        std::unique_lock lock(state.mutex);
        if (!state.running) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::NotRunning,
                .detail = "daemon engine is not running",
            });
        }
        const auto slot = find_profile_slot(state.profiles, profile_name);
        if (!slot) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::ProfileNotFound,
                .detail = "profile not found: " + std::string{profile_name},
            });
        }
        env_copy = state.environment;
        lock.unlock();

        if (auto saved = set_profile_paused(env_copy, profile_name, true);
            !saved) {
            return std::unexpected(DaemonError{
                .code = map_profile_pause_error_code(saved.error().code),
                .detail = saved.error().detail,
            });
        }

        lock.lock();
        if (const auto re_slot =
                find_profile_slot(state.profiles, profile_name)) {
            auto& hot = state.profiles.hot[*re_slot];
            auto& telemetry = state.profiles.telemetry[*re_slot];
            auto& cold = state.profiles.cold[*re_slot];
            auto& warm = state.profiles.warm[*re_slot];
            hot.paused = true;
            cold.config.paused = true;
            if (warm.task_stop_source) {
                warm.task_stop_source->request_stop();
            }
            if (!hot.in_flight) {
                clear_active_telemetry(telemetry);
            }
            ctx_to_detach = std::move(warm.watcher_ctx);
            watcher_to_stop = std::move(warm.watcher);
            hot.watcher_healthy = false;
            hot.watcher_baseline_established = false;
            if (!hot.in_flight && warm.warm_transport) {
                transport_to_close = std::move(warm.warm_transport);
                warm.warm_transport.reset();
            }
        }
        state.config_stamp =
            read_file_stamp(env_copy.app_data_dir / "config.toml");
        state.has_config_stamp = true;
    }
    if (ctx_to_detach) {
        std::lock_guard ctx_lock(ctx_to_detach->mutex);
        ctx_to_detach->detached = true;
    }
    platform::stop_directory_watcher(watcher_to_stop);
    transport_to_close.reset();

    emit_daemon_event(
        state, std::string{profile_name}, "paused", "profile paused");
    state.cv.notify_all();
    return {};
}

std::expected<void, DaemonError>
resume_session_state(DaemonSessionState& state, std::string_view profile_name) {
    ExecutionEnvironment env_copy;
    {
        std::unique_lock lock(state.mutex);
        if (!state.running) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::NotRunning,
                .detail = "daemon engine is not running",
            });
        }
        const auto slot = find_profile_slot(state.profiles, profile_name);
        if (!slot) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::ProfileNotFound,
                .detail = "profile not found: " + std::string{profile_name},
            });
        }
        env_copy = state.environment;
        lock.unlock();

        if (auto saved = set_profile_paused(env_copy, profile_name, false);
            !saved) {
            return std::unexpected(DaemonError{
                .code = map_profile_pause_error_code(saved.error().code),
                .detail = saved.error().detail,
            });
        }

        lock.lock();
        if (const auto re_slot =
                find_profile_slot(state.profiles, profile_name)) {
            auto& hot = state.profiles.hot[*re_slot];
            auto& telemetry = state.profiles.telemetry[*re_slot];
            auto& cold = state.profiles.cold[*re_slot];
            hot.paused = false;
            cold.config.paused = false;
            hot.needs_attention = false;
            hot.backoff_seconds = 0;
            hot.backoff_until = {};
            telemetry.last_error.clear();
            hot.next_sync_at = std::chrono::steady_clock::now();
            if (hot.gc_interval_hours > 0) {
                hot.next_gc_at =
                    compute_initial_next_gc_at(env_copy,
                                               profile_name,
                                               hot.gc_interval_hours,
                                               hot.next_sync_at,
                                               current_unix_seconds());
            }
        }
        state.config_stamp =
            read_file_stamp(env_copy.app_data_dir / "config.toml");
        state.has_config_stamp = true;
    }
    ensure_watcher_started_unlocked(state, profile_name);
    emit_daemon_event(
        state, std::string{profile_name}, "resumed", "profile resumed");
    state.cv.notify_all();
    return {};
}

std::expected<void, DaemonError>
unlock_session_state(DaemonSessionState& state,
                     std::string_view profile_name,
                     ProfileCredentials credentials) {
    struct CredsGuard {
        ProfileCredentials& creds;
        ~CredsGuard() noexcept {
            wipe_credentials(creds);
        }
    } creds_guard{credentials};

    std::filesystem::path db_path;
    runtime::KeyStorage key_storage = runtime::KeyStorage::Vault;
    ExecutionEnvironment env_copy;
    std::stop_token master_token;
    {
        std::unique_lock lock(state.mutex);
        if (!state.running) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::NotRunning,
                .detail = "daemon engine is not running",
            });
        }
        static_cast<void>(sync_profiles_from_disk_locked(state, lock));
        const auto slot = find_profile_slot(state.profiles, profile_name);
        if (!slot) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::ProfileNotFound,
                .detail = "profile not found: " + std::string{profile_name},
            });
        }
        db_path = state.profiles.cold[*slot].database_path;
        key_storage = state.profiles.cold[*slot].config.key_storage;
        env_copy = state.environment;
        master_token = state.master_stop.get_token();
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

    const auto rt = runtime::resolve(env_copy.app_data_dir,
                                     profile_name,
                                     runtime::AccessMode::ReadOnly,
                                     false);
    if (!rt) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::ProfileNotFound,
            .detail = rt.error().detail,
        });
    }

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

    if (key_storage == runtime::KeyStorage::Memory) {
        const auto conn =
            test_profile_connection(env_copy,
                                    profile_name,
                                    MasterKeyBytes{candidate.data},
                                    master_token);
        if (!conn) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::InvalidCredential,
                .detail = conn.error().detail,
            });
        }
        if (conn->vault_state == RemoteVaultState::TransportFailure) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::StorageFailure,
                .detail = conn->detail.empty()
                              ? "remote unreachable while verifying credentials"
                              : conn->detail,
            });
        }
        if (conn->vault_state ==
            RemoteVaultState::KeyMismatchOrInvalidHistory) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::InvalidCredential,
                .detail = conn->detail,
            });
        }
        if (conn->vault_state == RemoteVaultState::EmptyReadyForInit &&
            db_initialized_and_has_state(db_path)) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::InvalidCredential,
                .detail = "credentials do not match remote vault history",
            });
        }
    }

    if (auto stored = platform::store_secure_key(
            state.key_arena, profile_name, candidate.data);
        !stored) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::StorageFailure,
            .detail = stored.error(),
        });
    }

    {
        std::lock_guard lock(state.mutex);
        if (const auto slot = find_profile_slot(state.profiles, profile_name)) {
            auto& hot = state.profiles.hot[*slot];
            auto& telemetry = state.profiles.telemetry[*slot];
            hot.locked = false;
            hot.needs_attention = false;
            hot.backoff_seconds = 0;
            hot.backoff_until = {};
            telemetry.last_error.clear();
            hot.next_sync_at = std::chrono::steady_clock::now();
        }
    }
    emit_daemon_event(
        state, std::string{profile_name}, "unlocked", "profile key unlocked");
    state.cv.notify_all();
    return {};
}

std::expected<void, DaemonError>
lock_session_state(DaemonSessionState& state, std::string_view profile_name) {
    std::optional<transport::Transport> transport_to_close;
    {
        std::unique_lock lock(state.mutex);
        if (!state.running) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::NotRunning,
                .detail = "daemon engine is not running",
            });
        }
        const auto slot = find_profile_slot(state.profiles, profile_name);
        if (!slot) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::ProfileNotFound,
                .detail = "profile not found: " + std::string{profile_name},
            });
        }
        auto& hot = state.profiles.hot[*slot];
        auto& telemetry = state.profiles.telemetry[*slot];
        auto& cold = state.profiles.cold[*slot];
        auto& warm = state.profiles.warm[*slot];
        if (warm.task_stop_source) {
            warm.task_stop_source->request_stop();
        }
        platform::erase_secure_key(state.key_arena, profile_name);
        hot.locked = true;
        hot.dirty = false;
        cold.dirty_paths.clear();
        hot.overflow = false;
        hot.first_dirty_at.reset();
        hot.last_dirty_at.reset();
        ++hot.config_generation;
        if (!hot.in_flight) {
            clear_active_telemetry(telemetry);
        }
        if (!hot.in_flight && warm.warm_transport) {
            transport_to_close = std::move(warm.warm_transport);
            warm.warm_transport.reset();
        }
        warm.warm_observation.history_reads = {};
    }
    transport_to_close.reset();
    emit_daemon_event(
        state, std::string{profile_name}, "locked", "profile key locked");
    state.cv.notify_all();
    return {};
}

DaemonLogsReport
merge_daemon_log_events(const std::filesystem::path& app_data_dir,
                        const std::deque<DaemonEvent>* live_ring,
                        const DaemonLogQuery& query) {
    std::vector<DaemonEvent> raw;
    std::uint64_t disk_max_seq = 0;
    if (!app_data_dir.empty()) {
        read_log_file_into(
            daemon_rotated_log_path(app_data_dir), raw, disk_max_seq);
        read_log_file_into(daemon_log_path(app_data_dir), raw, disk_max_seq);
    }
    std::uint64_t latest_seq = disk_max_seq;
    if (live_ring != nullptr) {
        for (const auto& ev : *live_ring) {
            if (ev.seq > disk_max_seq) {
                raw.push_back(ev);
                if (ev.seq > latest_seq) {
                    latest_seq = ev.seq;
                }
            }
        }
    }

    std::vector<DaemonEvent> filtered;
    filtered.reserve(raw.size());
    for (auto& ev : raw) {
        if (ev.seq <= query.since_seq) {
            continue;
        }
        if (query.profile_name && !query.profile_name->empty() &&
            ev.profile_name != *query.profile_name) {
            continue;
        }
        filtered.push_back(std::move(ev));
    }

    const std::size_t max_lines =
        query.max_lines == 0 ? 100U
                             : std::min<std::size_t>(query.max_lines, 1000U);
    if (filtered.size() > max_lines) {
        filtered.erase(filtered.begin(),
                       filtered.end() - static_cast<std::ptrdiff_t>(max_lines));
    }

    return DaemonLogsReport{
        .log_path = app_data_dir.empty() ? std::string{}
                                         : platform::path::to_utf8(
                                               daemon_log_path(app_data_dir)),
        .latest_seq = latest_seq,
        .events = std::move(filtered),
    };
}

std::expected<DaemonLogsReport, DaemonError>
events_session_state(DaemonSessionState& state, const DaemonLogQuery& query) {
    std::filesystem::path app_dir;
    {
        std::lock_guard lock(state.mutex);
        if (!state.running) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::NotRunning,
                .detail = "daemon engine is not running",
            });
        }
        app_dir = state.environment.app_data_dir;
    }
    std::lock_guard log_lock(state.event_log_mutex);
    return merge_daemon_log_events(app_dir, &state.event_ring, query);
}

std::expected<void, DaemonError>
cancel_session_state(DaemonSessionState& state, std::string_view profile_name) {
    {
        std::lock_guard lock(state.mutex);
        if (!state.running) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::NotRunning,
                .detail = "daemon engine is not running",
            });
        }
        const auto slot = find_profile_slot(state.profiles, profile_name);
        if (!slot) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::ProfileNotFound,
                .detail = "profile not found: " + std::string{profile_name},
            });
        }
        auto& warm = state.profiles.warm[*slot];
        if (warm.task_stop_source) {
            warm.task_stop_source->request_stop();
        }
    }
    emit_daemon_event(state,
                      std::string{profile_name},
                      "cancelled",
                      "profile sync cancelled");
    state.cv.notify_all();
    return {};
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

std::expected<void, DaemonError> start_ipc_server(DaemonSessionState& state) {
    auto server = std::make_unique<httplib::Server>();
    server->set_payload_max_length(16384U);
    server->set_read_timeout(5, 0);
    server->set_write_timeout(5, 0);
    server->set_keep_alive_max_count(32);

    auto auth_guard = [&state](const httplib::Request& req,
                               httplib::Response& res) -> bool {
        if (!daemon_detail::validate_ipc_request_headers(
                req, state.ipc_port, state.auth_token)) {
            set_ipc_error(
                res, 403, DaemonErrorCode::InvalidCredential, "forbidden");
            return false;
        }
        return true;
    };

    server->Get(
        "/v1/status",
        [&state, auth_guard](const httplib::Request& req,
                             httplib::Response& res) {
            if (!auth_guard(req, res)) {
                return;
            }
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
            nlohmann::json profiles_json = nlohmann::json::array();
            for (const auto& p : report->profiles) {
                nlohmann::json obj{
                    {"name", p.name},
                    {"key_storage",
                     std::string{application::to_string(p.key_storage)}},
                    {"state", std::string{to_string(p.state)}},
                    {"paused", p.paused},
                    {"locked", p.locked},
                    {"watch_enabled", p.watch_enabled},
                    {"watcher_active", p.watcher_active},
                    {"watcher_degraded", p.watcher_degraded},
                    {"warm_transport_active", p.warm_transport_active},
                    {"warm_cache_entries", p.warm_cache_entries},
                    {"sync_interval_seconds", p.sync_interval_seconds},
                    {"gc_interval_hours", p.gc_interval_hours},
                    {"local_dir", p.local_dir},
                    {"remote_dir", p.remote_dir},
                    {"dirty_paths_count", p.dirty_paths_count},
                    {"active_stage", p.active_stage},
                    {"active_objects", p.active_objects},
                    {"active_total_objects",
                     p.active_total_objects
                         ? nlohmann::json(*p.active_total_objects)
                         : nlohmann::json(nullptr)},
                    {"active_bytes", p.active_bytes},
                    {"active_total_bytes",
                     p.active_total_bytes
                         ? nlohmann::json(*p.active_total_bytes)
                         : nlohmann::json(nullptr)},
                    {"last_sync_started_at",
                     p.last_sync_started_at
                         ? nlohmann::json(*p.last_sync_started_at)
                         : nlohmann::json(nullptr)},
                    {"last_sync_finished_at",
                     p.last_sync_finished_at
                         ? nlohmann::json(*p.last_sync_finished_at)
                         : nlohmann::json(nullptr)},
                    {"last_checked_at",
                     p.last_checked_at ? nlohmann::json(*p.last_checked_at)
                                       : nlohmann::json(nullptr)},
                    {"next_sync_at",
                     p.next_sync_at ? nlohmann::json(*p.next_sync_at)
                                    : nlohmann::json(nullptr)},
                    {"next_gc_at",
                     p.next_gc_at ? nlohmann::json(*p.next_gc_at)
                                  : nlohmann::json(nullptr)},
                    {"backoff_until_unix",
                     p.backoff_until_unix
                         ? nlohmann::json(*p.backoff_until_unix)
                         : nlohmann::json(nullptr)},
                    {"backoff_seconds", p.backoff_seconds},
                    {"consecutive_failures", p.consecutive_failures},
                    {"sync_runs", p.sync_runs},
                    {"fast_noop_polls", p.fast_noop_polls},
                    {"gc_runs", p.gc_runs},
                    {"last_outcome", p.last_outcome},
                    {"last_error", p.last_error},
                };
                profiles_json.push_back(std::move(obj));
            }
            nlohmann::json body{
                {"running", report->running},
                {"api_version", report->api_version},
                {"kasumi_version", report->kasumi_version},
                {"secure_pages_locked", report->secure_pages_locked},
                {"pid", report->pid},
                {"started_at_unix", report->started_at_unix},
                {"uptime_seconds", report->uptime_seconds},
                {"ipc_port", report->ipc_port},
                {"autostart",
                 {{"supported", report->autostart.supported},
                  {"installed", report->autostart.installed},
                  {"systemd_enabled", report->autostart.systemd_enabled},
                  {"method", report->autostart.method},
                  {"location", report->autostart.location},
                  {"command", report->autostart.command},
                  {"detail", report->autostart.detail}}},
                {"profiles", std::move(profiles_json)},
            };
            res.set_content(body.dump(), "application/json");
        });

    server->Get(
        "/v1/events",
        [&state, auth_guard](const httplib::Request& req,
                             httplib::Response& res) {
            if (!auth_guard(req, res)) {
                return;
            }
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

    server->Post("/v1/stop",
                 [&state, auth_guard](const httplib::Request& req,
                                      httplib::Response& res) {
                     if (!auth_guard(req, res)) {
                         return;
                     }
                     res.set_content(R"({"stopping":true})",
                                     "application/json");
                     request_stop_internal(state);
                 });

    server->Post(
        "/v1/reload",
        [&state, auth_guard](const httplib::Request& req,
                             httplib::Response& res) {
            if (!auth_guard(req, res)) {
                return;
            }
            const auto reloaded = reload_session_state(state);
            if (!reloaded) {
                set_ipc_error(
                    res, 400, reloaded.error().code, reloaded.error().detail);
                return;
            }
            res.set_content(R"({"reloaded":true})", "application/json");
        });

    server->Post(
        "/v1/sync",
        [&state, auth_guard](const httplib::Request& req,
                             httplib::Response& res) {
            if (!auth_guard(req, res)) {
                return;
            }
            std::optional<std::string> profile_name;
            bool wait = false;
            try {
                if (!req.body.empty()) {
                    const auto j = nlohmann::json::parse(req.body);
                    if (j.contains("profile") && j["profile"].is_string()) {
                        auto p = j["profile"].get<std::string>();
                        if (!p.empty()) {
                            profile_name = std::move(p);
                        }
                    }
                    wait = j.value("wait", false);
                }
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

    auto handle_profile_action = [&state,
                                  auth_guard](const httplib::Request& req,
                                              httplib::Response& res,
                                              int action_kind) {
        if (!auth_guard(req, res)) {
            return;
        }
        std::string profile_name;
        try {
            const auto j = nlohmann::json::parse(req.body);
            profile_name = j.value("profile", std::string{});
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

    server->Post("/v1/pause",
                 [handle_profile_action](const auto& req, auto& res) {
                     handle_profile_action(req, res, 0);
                 });
    server->Post("/v1/resume",
                 [handle_profile_action](const auto& req, auto& res) {
                     handle_profile_action(req, res, 1);
                 });
    server->Post("/v1/lock",
                 [handle_profile_action](const auto& req, auto& res) {
                     handle_profile_action(req, res, 2);
                 });
    server->Post("/v1/cancel",
                 [handle_profile_action](const auto& req, auto& res) {
                     handle_profile_action(req, res, 3);
                 });

    server->Post(
        "/v1/unlock",
        [&state, auth_guard](const httplib::Request& req,
                             httplib::Response& res) {
            if (!auth_guard(req, res)) {
                return;
            }
            std::string profile_name;
            daemon_detail::SealedUnlockPayload sealed;
            try {
                const auto j = nlohmann::json::parse(req.body);
                profile_name = j.value("profile", std::string{});
                sealed.nonce_hex = j.value("nonce", std::string{});
                sealed.mac_hex = j.value("mac", std::string{});
                sealed.ciphertext_hex = j.value("ciphertext", std::string{});
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

    const int bound_port = server->bind_to_any_port("127.0.0.1");
    if (bound_port <= 0 || bound_port > 65535) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::IpcFailure,
            .detail = "failed to bind local daemon IPC loopback socket",
        });
    }
    state.ipc_port = static_cast<std::uint16_t>(bound_port);
    state.ipc_server = std::move(server);
    auto* raw_srv = state.ipc_server.get();
    state.ipc_thread = std::thread([raw_srv] {
        raw_srv->listen_after_bind();
    });
    return {};
}

void stop_session_state(DaemonSessionState& state) noexcept {
    request_stop_internal(state);
    cleanup_daemon_resources(state, true);
    state.cv.notify_all();
}

std::expected<void, DaemonError> start_session_state(DaemonSessionState& state,
                                                     ExecutionEnvironment env,
                                                     DaemonOptions opts) {
    {
        std::lock_guard lock(state.mutex);
        if (state.running) {
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::AlreadyRunning,
                .detail = "daemon engine is already running",
            });
        }
    }

    if (env.app_data_dir.empty()) {
        env = default_execution_environment();
    }
    if (auto created =
            platform::private_storage::ensure_directory(env.app_data_dir);
        !created) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::StorageFailure,
            .detail = created.error(),
        });
    }

    const auto lock_path = daemon_detail::daemon_lock_path(env.app_data_dir);
    auto acquired = platform::acquire_profile_lock(lock_path);
    if (!acquired) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::AlreadyRunning,
            .detail = acquired.error(),
        });
    }
    const auto control_path =
        daemon_detail::daemon_control_path(env.app_data_dir);
    // Clear any stale control file left behind by a crashed daemon before
    // binding IPC so clients cannot target dead ephemeral ports.
    daemon_detail::remove_control_metadata_best_effort(control_path);

    DaemonAutostartStatus initial_autostart;
    if (const auto as = platform::query_user_autostart()) {
        initial_autostart = to_app_autostart(*as);
    }

    if (!platform::random::fill_bytes(state.auth_token) ||
        !platform::random::fill_bytes(state.ipc_key)) {
        platform::release_profile_lock(*acquired);
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::StorageFailure,
            .detail = "failed to generate ephemeral daemon IPC keys",
        });
    }

    {
        std::unique_lock lock(state.mutex);
        state.environment = env;
        state.options = std::move(opts);
        if (state.options.max_parallel_profiles == 0) {
            state.options.max_parallel_profiles = 1;
        }
        state.daemon_lock = *acquired;
        state.pid = platform::machine::current_process_id();
        state.started_at_unix = current_unix_seconds();
        state.started_at_steady = std::chrono::steady_clock::now();
        state.ipc_port = 0;
        state.stop_requested = false;
        state.cleaned_up = false;
        state.master_stop = std::stop_source{};
        state.key_arena = platform::create_secure_key_arena();
        state.cached_autostart = std::move(initial_autostart);
        state.running = true;

        if (auto loaded = sync_profiles_from_disk_locked(state, lock);
            !loaded) {
            state.running = false;
            platform::release_profile_lock(state.daemon_lock);
            return std::unexpected(loaded.error());
        }
    }

    if (auto cfg_watch = platform::start_directory_watcher(
            state.environment.app_data_dir,
            [&state](const platform::WatchEvent& ev) {
                if (ev.overflow || ev.relative_path == "config.toml") {
                    state.config_dirty.store(true, std::memory_order_release);
                    state.cv.notify_all();
                }
            },
            [](std::string_view) {
                return true;
            },
            false);
        cfg_watch) {
        state.config_watcher = std::move(*cfg_watch);
    }

    if (state.options.enable_ipc_server) {
        if (auto ipc_res = start_ipc_server(state); !ipc_res) {
            stop_session_state(state);
            return std::unexpected(ipc_res.error());
        }
        auto control_meta = daemon_detail::DaemonControlMetadata{
            .api_version = kDaemonApiVersion,
            .kasumi_version = KASUMI_VERSION,
            .pid = state.pid,
            .port = state.ipc_port,
            .started_at_unix = state.started_at_unix,
            .auth_token_hex = daemon_detail::encode_hex(state.auth_token),
            .ipc_key_hex = daemon_detail::encode_hex(state.ipc_key),
        };
        const auto wrote =
            daemon_detail::write_control_metadata(control_path, control_meta);
        daemon_detail::wipe_control_metadata(control_meta);
        if (!wrote) {
            stop_session_state(state);
            return std::unexpected(DaemonError{
                .code = DaemonErrorCode::StorageFailure,
                .detail = wrote.error(),
            });
        }
    }

    state.scheduler_thread = std::thread([&state] {
        scheduler_loop(state);
    });
    emit_daemon_event(state, "", "started", "daemon engine started");
    return {};
}

} // namespace

void destroy_daemon_session(DaemonSessionState* state) noexcept {
    if (state == nullptr) {
        return;
    }
    stop_session_state(*state);
    delete state;
}

std::expected<DaemonSession, DaemonError>
start_daemon_session(ExecutionEnvironment environment, DaemonOptions options) {
    std::unique_ptr<DaemonSessionState, void (*)(DaemonSessionState*) noexcept>
        state_holder{new DaemonSessionState{}, &destroy_daemon_session};
    if (auto started = start_session_state(
            *state_holder, std::move(environment), std::move(options));
        !started) {
        return std::unexpected(started.error());
    }
    return DaemonSession{.state = std::move(state_holder)};
}

std::expected<void, DaemonError> run_daemon(ExecutionEnvironment environment,
                                            DaemonOptions options,
                                            std::stop_token stop_token) {
    auto session =
        start_daemon_session(std::move(environment), std::move(options));
    if (!session) {
        return std::unexpected(session.error());
    }
    std::stop_callback stop_cb(stop_token, [&session]() noexcept {
        request_daemon_session_stop(*session);
    });
    auto& state = *session->state;
    {
        std::unique_lock lock(state.mutex);
        state.cv.wait(lock, [&] {
            return !state.running || state.stop_requested ||
                   stop_token.stop_requested();
        });
    }
    stop_daemon_session(*session);
    return {};
}

void request_daemon_session_stop(DaemonSession& session) noexcept {
    if (session.state) {
        request_stop_internal(*session.state);
    }
}

void stop_daemon_session(DaemonSession& session) noexcept {
    if (session.state) {
        stop_session_state(*session.state);
    }
}

bool is_daemon_session_running(const DaemonSession& session) noexcept {
    if (!session.state) {
        return false;
    }
    std::lock_guard lock(session.state->mutex);
    return session.state->running;
}

std::expected<DaemonStatusReport, DaemonError>
query_daemon_session_status(DaemonSession& session,
                            std::optional<std::string_view> profile_name) {
    if (!session.state) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::NotRunning,
            .detail = "daemon session is closed",
        });
    }
    return status_session_state(*session.state, profile_name);
}

std::expected<DaemonSyncTriggerReport, DaemonError>
trigger_daemon_session_sync(DaemonSession& session,
                            std::optional<std::string_view> profile_name,
                            bool wait) {
    if (!session.state) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::NotRunning,
            .detail = "daemon session is closed",
        });
    }
    return trigger_sync_session_state(*session.state, profile_name, wait);
}

std::expected<void, DaemonError>
pause_daemon_session_profile(DaemonSession& session,
                             std::string_view profile_name) {
    if (!session.state) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::NotRunning,
            .detail = "daemon session is closed",
        });
    }
    return pause_session_state(*session.state, profile_name);
}

std::expected<void, DaemonError>
resume_daemon_session_profile(DaemonSession& session,
                              std::string_view profile_name) {
    if (!session.state) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::NotRunning,
            .detail = "daemon session is closed",
        });
    }
    return resume_session_state(*session.state, profile_name);
}

std::expected<void, DaemonError>
unlock_daemon_session_profile(DaemonSession& session,
                              std::string_view profile_name,
                              ProfileCredentials credentials) {
    if (!session.state) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::NotRunning,
            .detail = "daemon session is closed",
        });
    }
    return unlock_session_state(
        *session.state, profile_name, std::move(credentials));
}

std::expected<void, DaemonError>
lock_daemon_session_profile(DaemonSession& session,
                            std::string_view profile_name) {
    if (!session.state) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::NotRunning,
            .detail = "daemon session is closed",
        });
    }
    return lock_session_state(*session.state, profile_name);
}

std::expected<void, DaemonError>
reload_daemon_session_profiles(DaemonSession& session) {
    if (!session.state) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::NotRunning,
            .detail = "daemon session is closed",
        });
    }
    return reload_session_state(*session.state);
}

std::expected<DaemonLogsReport, DaemonError>
query_daemon_session_events(DaemonSession& session,
                            const DaemonLogQuery& query) {
    if (!session.state) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::NotRunning,
            .detail = "daemon session is closed",
        });
    }
    return events_session_state(*session.state, query);
}

std::expected<void, DaemonError>
cancel_daemon_session_profile(DaemonSession& session,
                              std::string_view profile_name) {
    if (!session.state) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::NotRunning,
            .detail = "daemon session is closed",
        });
    }
    return cancel_session_state(*session.state, profile_name);
}

// ============================================================================
// Client IPC, Background Spawner & Autostart Facades
// ============================================================================

namespace {

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
    if (s == "running_gc") {
        return DaemonProfileState::RunningGc;
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
                .gc_interval_hours =
                    p.gc_interval_hours.value_or(kDefaultGcIntervalHours),
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
            .secure_pages_locked = doc.value("secure_pages_locked", false),
            .pid = doc.value("pid", std::uint64_t{0}),
            .started_at_unix = doc.value("started_at_unix", std::int64_t{0}),
            .uptime_seconds = doc.value("uptime_seconds", std::uint64_t{0}),
            .ipc_port = doc.value("ipc_port", std::uint16_t{0}),
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
                    .gc_interval_hours =
                        p.value("gc_interval_hours", kDefaultGcIntervalHours),
                    .local_dir = p.value("local_dir", std::string{}),
                    .remote_dir = p.value("remote_dir", std::string{}),
                    .dirty_paths_count =
                        p.value("dirty_paths_count", std::size_t{0}),
                    .active_stage = p.value("active_stage", std::string{}),
                    .active_objects =
                        p.value("active_objects", std::uint64_t{0}),
                    .active_total_objects = optional_field<std::uint64_t>(
                        p, "active_total_objects"),
                    .active_bytes = p.value("active_bytes", std::uint64_t{0}),
                    .active_total_bytes =
                        optional_field<std::uint64_t>(p, "active_total_bytes"),
                    .last_sync_started_at =
                        optional_field<std::int64_t>(p, "last_sync_started_at"),
                    .last_sync_finished_at = optional_field<std::int64_t>(
                        p, "last_sync_finished_at"),
                    .last_checked_at =
                        optional_field<std::int64_t>(p, "last_checked_at"),
                    .next_sync_at =
                        optional_field<std::int64_t>(p, "next_sync_at"),
                    .next_gc_at = optional_field<std::int64_t>(p, "next_gc_at"),
                    .backoff_until_unix =
                        optional_field<std::int64_t>(p, "backoff_until_unix"),
                    .backoff_seconds =
                        p.value("backoff_seconds", std::uint32_t{0}),
                    .consecutive_failures =
                        p.value("consecutive_failures", std::uint32_t{0}),
                    .sync_runs = p.value("sync_runs", std::uint64_t{0}),
                    .fast_noop_polls =
                        p.value("fast_noop_polls", std::uint64_t{0}),
                    .gc_runs = p.value("gc_runs", std::uint64_t{0}),
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
        return merge_daemon_log_events(normalized.app_data_dir, nullptr, query);
    }
    auto conn = open_ipc_client(normalized);
    if (!conn) {
        return merge_daemon_log_events(normalized.app_data_dir, nullptr, query);
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
            .code = map_profile_pause_error_code(updated.error().code),
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
