#include "application/daemon.hpp"
#include "application/daemon/defaults.hpp"
#include "application/daemon/error_classification.hpp"
#include "application/daemon/event_log.hpp"
#include "application/daemon/ipc_security.hpp"
#include "application/daemon/profile_state.hpp"
#include "application/daemon/session_state.hpp"
#include "application/detail.hpp"
#include "application/use_cases/context.hpp"
#include "crypto/secure_memory.hpp"
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
#include <httplib.h>
#include <memory>
#include <mutex>
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

using daemon_detail::current_unix_seconds;
using daemon_detail::kDaemonApiVersion;
using daemon_detail::WatcherContext;

std::int64_t
steady_to_unix_estimate(std::chrono::steady_clock::time_point target,
                        std::chrono::steady_clock::time_point now_steady,
                        std::int64_t now_unix) noexcept {
    const auto delta =
        std::chrono::duration_cast<std::chrono::seconds>(target - now_steady);
    return now_unix + delta.count();
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
        .machine_name = platform::machine::host_name(),
        .secure_pages_locked =
            platform::secure_key_arena_all_pages_locked(state.key_arena),
        .pid = state.pid,
        .started_at_unix = state.started_at_unix,
        .daemon_instance = state.daemon_instance,
        .uptime_seconds = uptime,
        .ipc_port = state.ipc_port,
        .web_port = state.web_port,
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
            pstate = DaemonProfileState::RunningSync;
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
            .local_dir = platform::path::to_utf8(cold.config.local_dir),
            .remote_dir = cold.config.remote_dir,
            .dirty_paths_count = cold.dirty_paths.size(),
            .active_stage = telemetry.active_stage,
            .active_item_path = telemetry.active_item_path,
            .active_item_bytes = telemetry.active_item_bytes,
            .active_item_total_bytes = telemetry.active_item_total_bytes,
            .active_objects = telemetry.active_objects,
            .active_total_objects = telemetry.active_total_objects,
            .active_bytes = telemetry.active_bytes,
            .active_total_bytes = telemetry.active_total_bytes,
            .sync_phase = telemetry.sync_phase,
            .sync_applied_items = telemetry.sync_applied_items,
            .sync_total_items = telemetry.sync_total_items,
            .active_bytes_per_second = telemetry.active_bytes_per_second,
            .last_sync_started_at = telemetry.last_sync_started_at,
            .last_sync_finished_at = telemetry.last_sync_finished_at,
            .last_checked_at = telemetry.last_checked_at,
            .next_sync_at = next_sync_unix,
            .backoff_until_unix = backoff_until_unix,
            .backoff_seconds = remaining_backoff_seconds,
            .consecutive_failures = hot.consecutive_failures,
            .sync_runs = telemetry.sync_runs,
            .fast_noop_polls = telemetry.fast_noop_polls,
            .last_outcome = telemetry.last_outcome,
            .last_error = telemetry.last_error,
            .busy = hot.in_flight,
            .active_operation = hot.in_flight ? std::string{"sync"}
                                              : std::string{},
        });
    }
    return report;
}

} // namespace

namespace daemon_detail {

std::int64_t current_unix_seconds() noexcept {
    return platform::clock::unix_seconds().value_or(0);
}

std::optional<std::string> detect_held_profile_operation(
    DaemonSessionState& state, std::string_view profile_name) {
    std::filesystem::path app_data_dir;
    {
        std::lock_guard lock(state.mutex);
        if (!state.running)
            return std::nullopt;
        app_data_dir = state.environment.app_data_dir;
    }
    const auto lock_path =
        app_data_dir / ("profile-" + std::string{profile_name} + ".lock");
    if (!platform::is_profile_lock_held(lock_path))
        return std::nullopt;

    // Re-check daemon-internal state after observing the OS lock so we
    // never misclassify our own background scheduler/web operations as an
    // external CLI process due to a lock-free window between reads.
    bool internal_in_flight = false;
    bool internal_web_locked = false;
    {
        std::lock_guard lock(state.mutex);
        if (const auto slot =
                find_profile_slot(state.profiles, profile_name)) {
            internal_in_flight = state.profiles.hot[*slot].in_flight;
        }
        const auto lock_it =
            state.internal_lock_counts.find(std::string{profile_name});
        internal_web_locked = lock_it != state.internal_lock_counts.end() &&
                              lock_it->second > 0;
    }
    if (internal_in_flight)
        return std::string{"sync"};
    const auto current_jobs = active_job_operations(state.web_jobs);
    const auto current_job =
        std::ranges::find_if(current_jobs, [&](const auto& pair) {
            return pair.first == profile_name;
        });
    if (current_job != current_jobs.end())
        return current_job->second;
    if (internal_web_locked)
        return std::nullopt;
    return std::string{"external"};
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

    if (state.web_server)
        state.web_server->stop();
    if (state.web_thread.joinable())
        state.web_thread.join();
    state.web_server.reset();
    if (state.ipc_server) {
        state.ipc_server->stop();
    }
    if (state.ipc_thread.joinable() &&
        state.ipc_thread.get_id() != std::this_thread::get_id()) {
        state.ipc_thread.join();
    }
    state.ipc_server.reset();
    daemon_detail::join_web_jobs(state.web_jobs);

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
        state.web_port = 0;
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
    if (was_running) {
        emit_daemon_event(state, "", "stopped", "daemon engine stopped");
    }
    platform::release_profile_lock(state.daemon_lock);
    state.cleaned_up = true;
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
    notify_daemon_status_change(state);
}

std::expected<DaemonStatusReport, DaemonError>
status_session_state(DaemonSessionState& state,
                     std::optional<std::string_view> profile_name) {
    DaemonStatusReport report;
    {
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
        report = build_status_locked(state, profile_name);
    }
    const auto active_jobs = active_job_operations(state.web_jobs);
    for (auto& profile : report.profiles) {
        if (profile.busy)
            continue;
        const auto job_it = std::ranges::find_if(
            active_jobs, [&](const auto& pair) {
                return pair.first == profile.name;
            });
        if (job_it != active_jobs.end()) {
            profile.busy = true;
            profile.active_operation = job_it->second;
            continue;
        }
        if (auto detected = detect_held_profile_operation(state, profile.name)) {
            profile.busy = true;
            profile.active_operation = std::move(*detected);
        }
    }
    return report;
}

std::expected<void, DaemonError>
reload_session_state(DaemonSessionState& state) {
    std::unique_lock autostart_lock(state.autostart_mutex);
    DaemonAutostartStatus refreshed_autostart;
    bool has_autostart = false;
    if (const auto as = query_daemon_autostart()) {
        refreshed_autostart = *as;
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
        autostart_lock.unlock();
        res = sync_profiles_from_disk_locked(state, lock, true);
    }
    notify_daemon_status_change(state);
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
    notify_daemon_status_change(state);

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
    notify_daemon_status_change(state);
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
        }
        state.config_stamp =
            read_file_stamp(env_copy.app_data_dir / "config.toml");
        state.has_config_stamp = true;
    }
    ensure_watcher_started_unlocked(state, profile_name);
    emit_daemon_event(
        state, std::string{profile_name}, "resumed", "profile resumed");
    notify_daemon_status_change(state);
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
    notify_daemon_status_change(state);
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
        if (warm.commit_cache) {
            history_storage::clear_memory_cache(*warm.commit_cache);
        }
        if (warm.thumbnail_cache) {
            daemon_detail::clear_remote_thumbnail_cache(*warm.thumbnail_cache);
        }
    }
    transport_to_close.reset();
    emit_daemon_event(
        state, std::string{profile_name}, "locked", "profile key locked");
    notify_daemon_status_change(state);
    return {};
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
    return daemon_detail::merge_daemon_log_events(
        app_dir, &state.event_ring, query);
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
    notify_daemon_status_change(state);
    return {};
}

} // namespace daemon_detail

namespace {

void stop_session_state(DaemonSessionState& state) noexcept {
    daemon_detail::request_stop_internal(state);
    daemon_detail::cleanup_daemon_resources(state, true);
    daemon_detail::notify_daemon_status_change(state);
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
    const auto previous_event_seq =
        daemon_detail::merge_daemon_log_events(
            env.app_data_dir, nullptr, DaemonLogQuery{.max_lines = 1U})
            .latest_seq;

    DaemonAutostartStatus initial_autostart;
    if (const auto as = query_daemon_autostart()) {
        initial_autostart = *as;
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
        state.daemon_instance = std::to_string(state.pid) + "-" +
                                std::to_string(state.started_at_unix);
        state.started_at_steady = std::chrono::steady_clock::now();
        state.ipc_port = 0;
        state.web_port = 0;
        state.next_event_seq = previous_event_seq + 1U;
        state.latest_event_seq.store(previous_event_seq,
                                     std::memory_order_release);
        state.status_revision.store(1, std::memory_order_release);
        state.stop_requested = false;
        state.cleaned_up = false;
        state.master_stop = std::stop_source{};
        state.key_arena = platform::create_secure_key_arena();
        state.cached_autostart = std::move(initial_autostart);
        state.running = true;

        if (auto loaded =
                daemon_detail::sync_profiles_from_disk_locked(state, lock);
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
                    daemon_detail::notify_daemon_status_change(state);
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
        if (auto ipc_res = daemon_detail::start_ipc_server(state); !ipc_res) {
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
        daemon_detail::scheduler_loop(state);
    });
    daemon_detail::emit_daemon_event(
        state, "", "started", "daemon engine started");
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
        daemon_detail::request_stop_internal(*session.state);
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
    return daemon_detail::status_session_state(*session.state, profile_name);
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
    return daemon_detail::trigger_sync_session_state(
        *session.state, profile_name, wait);
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
    return daemon_detail::pause_session_state(*session.state, profile_name);
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
    return daemon_detail::resume_session_state(*session.state, profile_name);
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
    return daemon_detail::unlock_session_state(
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
    return daemon_detail::lock_session_state(*session.state, profile_name);
}

std::expected<void, DaemonError>
reload_daemon_session_profiles(DaemonSession& session) {
    if (!session.state) {
        return std::unexpected(DaemonError{
            .code = DaemonErrorCode::NotRunning,
            .detail = "daemon session is closed",
        });
    }
    return daemon_detail::reload_session_state(*session.state);
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
    return daemon_detail::events_session_state(*session.state, query);
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
    return daemon_detail::cancel_session_state(*session.state, profile_name);
}

} // namespace kasumi::application
