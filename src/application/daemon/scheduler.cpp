#include "application/daemon/error_classification.hpp"
#include "application/daemon/event_log.hpp"
#include "application/daemon/fast_poll.hpp"
#include "application/daemon/profile_state.hpp"
#include "application/daemon/session_state.hpp"
#include "application/daemon/web_jobs.hpp"
#include "application/detail.hpp"
#include "application/execute.hpp"
#include "application/observation/file_metadata.hpp"
#include "application/use_cases/context.hpp"
#include "crypto/secure_memory.hpp"
#include "platform/path.hpp"
#include "platform/random.hpp"
#include "runtime/paths.hpp"
#include "runtime/resolver.hpp"
#include "runtime/vault.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <format>
#include <mutex>
#include <utility>

namespace kasumi::application::daemon_detail {
namespace {

constexpr std::uint32_t kMinBackoffSeconds = 5U;
constexpr std::uint32_t kMaxBackoffSeconds = 600U;

std::mutex post_sync_prune_hook_mutex;
testing::PostSyncPruneHook active_post_sync_prune_hook{};
std::atomic<bool> has_post_sync_prune_hook{false};

void merge_dirty_paths_locked(ProfileHotSchedule& hot,
                              ProfileColdMeta& cold,
                              const std::unordered_set<std::string>& incoming,
                              bool incoming_overflow) {
    hot.overflow = hot.overflow || incoming_overflow;
    if (hot.overflow) {
        return;
    }
    for (const auto& path : incoming) {
        if (cold.dirty_paths.contains(path)) {
            continue;
        }
        if (cold.dirty_paths.size() >= kMaxTrackedDirtyPaths) {
            hot.overflow = true;
            return;
        }
        cold.dirty_paths.insert(path);
    }
}

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

std::string format_sync_outcome(const SyncCompleted& completed) {
    if (completed.copied > 0) {
        return std::format("up={}, down={}, rm={}, mv={}, cp={}",
                           completed.uploaded,
                           completed.downloaded,
                           completed.removed,
                           completed.renamed,
                           completed.copied);
    }
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

void stash_or_discard_warm_state(
    ProfileHotSchedule& hot,
    const ProfileColdMeta& cold,
    ProfileWarmSlot& warm,
    std::uint64_t task_config_gen,
    bool eligible,
    std::optional<transport::Transport>& borrowed_owner,
    const std::optional<detail::TransportBinding>& borrowed_binding,
    observation::LocalObservationSession& warm_obs,
    std::chrono::steady_clock::time_point now_steady,
    std::optional<transport::Transport>& discard_transport) {
    if (eligible && hot.config_generation == task_config_gen && !hot.paused &&
        !hot.locked) {
        if (warm_obs.database_path == cold.database_path) {
            warm.warm_observation = std::move(warm_obs);
        } else {
            warm.warm_observation = {.database_path = cold.database_path};
        }
        if (borrowed_owner && borrowed_binding &&
            *borrowed_binding == detail::make_transport_binding(cold.config)) {
            warm.warm_transport = std::move(borrowed_owner);
            warm.warm_transport_binding = *borrowed_binding;
            warm.warm_transport_last_used = now_steady;
        } else {
            discard_transport = std::move(borrowed_owner);
            warm.warm_transport_binding.reset();
        }
    } else {
        discard_transport = std::move(borrowed_owner);
    }
}

void finish_fast_noop(
    DaemonSessionState& state,
    const std::string& profile_name,
    std::uint64_t task_config_gen,
    std::optional<transport::Transport>& borrowed_owner,
    const std::optional<detail::TransportBinding>& borrowed_binding,
    observation::LocalObservationSession& warm_obs) {
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
            stash_or_discard_warm_state(hot,
                                        cold,
                                        warm,
                                        task_config_gen,
                                        true,
                                        borrowed_owner,
                                        borrowed_binding,
                                        warm_obs,
                                        now_steady,
                                        discard_transport);
            const auto db_stamp = read_file_stamp(cold.database_path);
            cold.external_db_stamp = db_stamp;
            cold.has_external_db_stamp = db_stamp.present;
            hot.in_flight = false;
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
    notify_daemon_status_change(state);
}

void finish_sync_success(
    DaemonSessionState& state,
    const std::string& profile_name,
    std::uint64_t task_config_gen,
    std::optional<transport::Transport>& borrowed_owner,
    const std::optional<detail::TransportBinding>& borrowed_binding,
    observation::LocalObservationSession& warm_obs,
    const std::unordered_set<std::string>& remaining_dirty,
    bool remaining_overflow,
    std::uint64_t consumed_watch_epoch,
    const WatcherContext* watcher_ctx_before,
    bool watcher_healthy_before,
    const std::string& outcome,
    std::optional<testing::PostSyncPruneSnapshot>* post_snapshot_out =
        nullptr) {
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
            stash_or_discard_warm_state(hot,
                                        cold,
                                        warm,
                                        task_config_gen,
                                        true,
                                        borrowed_owner,
                                        borrowed_binding,
                                        warm_obs,
                                        now_steady,
                                        discard_transport);
            refresh_ignore_state(cold, warm);
            cold.local_dir_identity =
                platform::private_storage::query_directory_identity(
                    cold.config.local_dir);
            const auto db_stamp = read_file_stamp(cold.database_path);
            cold.external_db_stamp = db_stamp;
            cold.has_external_db_stamp = db_stamp.present;

            hot.in_flight = false;
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

            const bool watcher_changed_since_drain =
                (hot.watch_epoch != consumed_watch_epoch);
            merge_dirty_paths_locked(
                hot, cold, remaining_dirty, remaining_overflow);
            const bool has_pending_dirty = !cold.dirty_paths.empty() ||
                                           hot.overflow ||
                                           watcher_changed_since_drain;
            if (!has_pending_dirty) {
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
                if (watcher_changed_since_drain && cold.dirty_paths.empty() &&
                    !hot.overflow) {
                    hot.overflow = true;
                }
                hot.dirty = true;
                hot.watcher_baseline_established = false;
                if (!hot.first_dirty_at) {
                    hot.first_dirty_at = now_steady;
                }
                if (!hot.last_dirty_at) {
                    hot.last_dirty_at = now_steady;
                }
            }

            hot.next_sync_at =
                hot.sync_interval_seconds > 0
                    ? (now_steady +
                       std::chrono::seconds{hot.sync_interval_seconds})
                    : (std::chrono::steady_clock::time_point::max)();

            if (post_snapshot_out != nullptr &&
                testing::post_sync_prune_hook_active()) {
                *post_snapshot_out = testing::PostSyncPruneSnapshot{
                    .dirty = hot.dirty,
                    .overflow = hot.overflow,
                    .watcher_baseline_established =
                        hot.watcher_baseline_established,
                    .has_dirty_timestamps = hot.first_dirty_at.has_value() &&
                                            hot.last_dirty_at.has_value(),
                    .sync_runs = telemetry.sync_runs,
                    .dirty_paths = cold.dirty_paths,
                };
            }
        }
    }
    discard_transport.reset();
    notify_daemon_status_change(state);
}

void finish_task_state(
    DaemonSessionState& state,
    const std::string& profile_name,
    std::uint64_t task_config_gen,
    std::optional<transport::Transport>& borrowed_owner,
    const std::optional<detail::TransportBinding>& borrowed_binding,
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
            stash_or_discard_warm_state(hot,
                                        cold,
                                        warm,
                                        task_config_gen,
                                        !set_locked,
                                        borrowed_owner,
                                        borrowed_binding,
                                        warm_obs,
                                        now_steady,
                                        discard_transport);
            hot.in_flight = false;
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
    notify_daemon_status_change(state);
}

void run_profile_task(DaemonSessionState& state,
                      const std::string& profile_name,
                      bool from_timer_poll,
                      bool manual_trigger) {
    runtime::ProfileData cfg;
    std::filesystem::path db_path;
    std::filesystem::path key_path;
    std::optional<transport::Transport> borrowed_owner;
    std::optional<detail::TransportBinding> borrowed_binding;
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
            borrowed_binding = std::move(warm.warm_transport_binding);
            warm.warm_transport.reset();
            warm.warm_transport_binding.reset();
        }
        warm_obs = std::move(warm.warm_observation);
        warm.warm_observation = {};

        const auto now = std::chrono::steady_clock::now();
        can_try_fast_poll =
            !manual_trigger && from_timer_poll && !hot.dirty && !hot.overflow &&
            platform::directory_watcher_valid(warm.watcher) &&
            hot.watcher_healthy && hot.watcher_baseline_established &&
            (now - hot.last_full_verify_at <
             state.options.full_scan_verification_interval);
        ignore_present = cold.ignore_file_present;
        ignore_stamp = cold.ignore_stamp;
        watched_dir_id = cold.local_dir_identity;
        clear_active_telemetry(telemetry);
        telemetry.active_stage = "checking";
        telemetry.sync_phase = "observing";
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
                              borrowed_binding,
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
                              borrowed_binding,
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

    const auto expected_binding = detail::make_transport_binding(cfg);
    if (borrowed_owner &&
        (!borrowed_binding || *borrowed_binding != expected_binding)) {
        borrowed_owner.reset();
        borrowed_binding.reset();
        warm_obs = {.database_path = db_path};
    }

    // Ensure warm transport exists & passes health check.
    bool opened_new_transport = false;
    if (borrowed_owner) {
        const auto health = transport::check_health(*borrowed_owner);
        if (!health) {
            borrowed_owner.reset();
            borrowed_binding.reset();
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
            borrowed_binding = expected_binding;
            opened_new_transport = true;
        } else {
            const auto msg = transport::describe(opened.error());
            finish_task_state(state,
                              profile_name,
                              task_config_gen,
                              borrowed_owner,
                              borrowed_binding,
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
        const auto fast = daemon_detail::try_fast_remote_noop_poll(
            state.environment,
            profile_name,
            *resolved_runtime,
            *borrowed_owner,
            *borrowed_binding,
            clear_key.data,
            warm_obs,
            ignore_present,
            ignore_stamp);
        if (fast.config_changed) {
            borrowed_owner.reset();
            borrowed_binding.reset();
            warm_obs = {.database_path = db_path};
            state.config_dirty.store(true, std::memory_order_release);
            const auto updated = runtime::resolve(state.environment.app_data_dir,
                                                  profile_name,
                                                  runtime::AccessMode::ReadOnly,
                                                  false);
            if (!updated || updated->paused) {
                finish_task_state(state,
                                  profile_name,
                                  task_config_gen,
                                  borrowed_owner,
                                  borrowed_binding,
                                  warm_obs,
                                  false,
                                  false,
                                  false,
                                  false,
                                  fast.reason,
                                  "");
                return;
            }
            db_path = updated->database_path;
            key_path = updated->key_path;
        }
        if (fast.profile_locked) {
            finish_task_state(state,
                              profile_name,
                              task_config_gen,
                              borrowed_owner,
                              borrowed_binding,
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
                                 borrowed_binding,
                                 warm_obs);
                return;
            }
        }
        if (fast.transport_error) {
            borrowed_owner.reset();
            borrowed_binding.reset();
            finish_task_state(state,
                              profile_name,
                              task_config_gen,
                              borrowed_owner,
                              borrowed_binding,
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
    if (!db_schema_valid(db_path)) {
        finish_task_state(state,
                          profile_name,
                          task_config_gen,
                          borrowed_owner,
                          borrowed_binding,
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
        .borrowed_transport_binding = borrowed_binding,
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
                .operation = Operation::Sync,
                .profile_name = profile_name,
            },
        .credentials = MasterKeyBytes{clear_key.data},
        .environment = state.environment,
        .on_progress =
            [&](const ExecutionProgress& progress) {
                {
                    std::lock_guard lock(state.mutex);
                    const auto slot =
                        find_profile_slot(state.profiles, profile_name);
                    if (!slot) {
                        return;
                    }
                    auto& telemetry = state.profiles.telemetry[*slot];
                    if (const auto* act =
                            std::get_if<ActivityProgress>(&progress)) {
                        const auto now = std::chrono::steady_clock::now();
                        if (telemetry.rate_sample_at ==
                                std::chrono::steady_clock::time_point{} ||
                            telemetry.rate_activity_id != act->stage_id ||
                            act->bytes < telemetry.rate_sample_bytes) {
                            telemetry.active_bytes_per_second.reset();
                            telemetry.rate_activity_id = act->stage_id;
                            telemetry.rate_sample_at = now;
                            telemetry.rate_sample_bytes = act->bytes;
                        } else if (const auto elapsed =
                                       std::chrono::duration<double>(
                                           now - telemetry.rate_sample_at)
                                           .count();
                                   elapsed >= 0.25) {
                            const auto bytes =
                                act->bytes - telemetry.rate_sample_bytes;
                            telemetry.active_bytes_per_second =
                                static_cast<double>(bytes) / elapsed;
                            telemetry.rate_sample_at = now;
                            telemetry.rate_sample_bytes = act->bytes;
                        }
                        telemetry.active_item_path =
                            platform::path::to_utf8(act->item_path);
                        telemetry.active_item_bytes = act->item_bytes;
                        telemetry.active_item_total_bytes =
                            act->item_total_bytes;
                        if (act->activity == Activity::Scanning &&
                            act->observing_remote &&
                            act->total_objects.has_value() &&
                            act->objects >= *act->total_objects) {
                            telemetry.active_stage = "listing";
                            telemetry.active_objects = 0;
                            telemetry.active_total_objects.reset();
                            telemetry.active_bytes = 0;
                            telemetry.active_total_bytes.reset();
                            telemetry.active_bytes_per_second.reset();
                        } else {
                            telemetry.active_stage =
                                activity_stage_label(act->activity);
                            telemetry.active_objects = act->objects;
                            telemetry.active_total_objects = act->total_objects;
                            telemetry.active_bytes = act->bytes;
                            telemetry.active_total_bytes = act->total_bytes;
                        }
                    } else if (const auto* sp =
                                   std::get_if<SyncProgress>(&progress)) {
                        std::string_view phase;
                        switch (sp->stage) {
                            case SyncStage::Observing:
                                phase = "observing";
                                break;
                            case SyncStage::Calculating:
                                phase = "calculating";
                                break;
                            case SyncStage::Applying:
                                phase = "applying";
                                break;
                            case SyncStage::Publishing:
                                phase = "publishing";
                                break;
                            case SyncStage::Finalizing:
                                phase = "finalizing";
                                break;
                        }
                        if (phase != telemetry.sync_phase) {
                            clear_active_telemetry(telemetry);
                            telemetry.sync_phase = phase;
                        }
                        telemetry.active_stage = phase;
                        if (sp->total_items > 0)
                            telemetry.sync_total_items = sp->total_items;
                        if (sp->applied_items)
                            telemetry.sync_applied_items = sp->applied_items;
                    }
                }
                notify_daemon_status_change(state);
            },
        .stop_token = task_stop.get_token(),
    };

    const auto exec_started = std::chrono::steady_clock::now();
    auto res = detail::execute_warm(exec_input, warm_ctx);
    if (warm_ctx.borrowed_transport_rejected) {
        borrowed_owner.reset();
        borrowed_binding.reset();
        state.config_dirty.store(true, std::memory_order_release);
    }

    if (res) {
        const auto* sync_done = std::get_if<SyncCompleted>(&res->data);
        const std::string outcome =
            sync_done ? format_sync_outcome(*sync_done) : std::string{"ok"};

        // Cache + committed-tree self-mutation pruning so daemon downloads and
        // deletions do not retrigger redundant sync cycles while preserving
        // concurrent user edits (including newly created files not yet in the
        // published commit tree).
        std::unordered_set<std::string> remaining_dirty;
        bool remaining_overflow = false;
        std::uint64_t consumed_watch_epoch = 0;
        {
            std::lock_guard lock(state.mutex);
            if (const auto slot =
                    find_profile_slot(state.profiles, profile_name)) {
                auto& hot = state.profiles.hot[*slot];
                auto& cold = state.profiles.cold[*slot];
                remaining_dirty = std::move(cold.dirty_paths);
                remaining_overflow = hot.overflow;
                consumed_watch_epoch = hot.watch_epoch;
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

        testing::invoke_post_sync_prune_hook(
            state,
            profile_name,
            testing::PostSyncPruneStage::BeforeFinishSyncSuccess);
        std::optional<testing::PostSyncPruneSnapshot> post_snapshot;
        finish_sync_success(state,
                            profile_name,
                            task_config_gen,
                            borrowed_owner,
                            borrowed_binding,
                            warm_obs,
                            remaining_dirty,
                            remaining_overflow,
                            consumed_watch_epoch,
                            watcher_ctx_before,
                            watcher_healthy_before,
                            outcome,
                            &post_snapshot);
        testing::invoke_post_sync_prune_hook(
            state,
            profile_name,
            testing::PostSyncPruneStage::AfterFinishSyncSuccess,
            post_snapshot ? &*post_snapshot : nullptr);
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
            borrowed_binding.reset();
        }
        const auto now_cancelled = std::chrono::steady_clock::now();
        std::optional<transport::Transport> discard_transport;
        {
            std::lock_guard lock(state.mutex);
            if (const auto slot =
                    find_profile_slot(state.profiles, profile_name)) {
                auto& hot = state.profiles.hot[*slot];
                auto& telemetry = state.profiles.telemetry[*slot];
                auto& cold = state.profiles.cold[*slot];
                auto& warm = state.profiles.warm[*slot];
                stash_or_discard_warm_state(hot,
                                            cold,
                                            warm,
                                            task_config_gen,
                                            true,
                                            borrowed_owner,
                                            borrowed_binding,
                                            warm_obs,
                                            now_cancelled,
                                            discard_transport);
                merge_dirty_paths_locked(
                    hot, cold, dirty_snapshot, had_overflow_snapshot);
                if (!cold.dirty_paths.empty() || hot.overflow) {
                    hot.dirty = true;
                    hot.watcher_baseline_established = false;
                    if (!hot.first_dirty_at) {
                        hot.first_dirty_at = now_cancelled;
                    }
                    if (!hot.last_dirty_at) {
                        hot.last_dirty_at = now_cancelled;
                    }
                }
                hot.in_flight = false;
                clear_active_telemetry(telemetry);
                warm.task_stop_source.reset();
                ++hot.completed_generation;
                telemetry.last_error = err.detail;
            }
        }
        discard_transport.reset();
        notify_daemon_status_change(state);
        return;
    }

    const bool local_mutation_race =
        daemon_detail::is_concurrent_local_mutation_error(err);
    if (borrowed_owner && ((!local_mutation_race &&
                            daemon_detail::is_transient_sync_error(err)) ||
                           !transport::check_health(*borrowed_owner))) {
        borrowed_owner.reset();
        borrowed_binding.reset();
    }
    const bool transient = daemon_detail::is_transient_sync_error(err);
    const bool lock_only = ((err.code == ErrorCode::CredentialFailure ||
                             err.code == ErrorCode::CredentialsRequired) &&
                            cfg.key_storage == runtime::KeyStorage::Memory);

    // Restore any dirty snapshot before recording failure state.
    {
        const auto now_restore = std::chrono::steady_clock::now();
        std::lock_guard lock(state.mutex);
        if (const auto slot = find_profile_slot(state.profiles, profile_name)) {
            auto& hot = state.profiles.hot[*slot];
            auto& cold = state.profiles.cold[*slot];
            merge_dirty_paths_locked(
                hot, cold, dirty_snapshot, had_overflow_snapshot);
            if (!cold.dirty_paths.empty() || hot.overflow) {
                hot.dirty = true;
                hot.watcher_baseline_established = false;
                if (!hot.first_dirty_at) {
                    hot.first_dirty_at = now_restore;
                }
                if (!hot.last_dirty_at) {
                    hot.last_dirty_at = now_restore;
                }
            }
        }
    }
    finish_task_state(state,
                      profile_name,
                      task_config_gen,
                      borrowed_owner,
                      borrowed_binding,
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

} // namespace

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
                                    warm.warm_transport_binding.reset();
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
                warm.warm_transport_binding.reset();
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
            std::vector<std::expected<runtime::vault::KeyBytes, runtime::Error>>
                vault_results;
            vault_results.reserve(vault_candidates.size());
            for (const auto& cand : vault_candidates) {
                vault_results.push_back(
                    runtime::vault::read_vault(cand.key_path));
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
                            crypto::secure_memory::wipe(res->data(),
                                                        res->size());
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
                            crypto::secure_memory::wipe(res->data(),
                                                        res->size());
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
        // max_parallel_profiles and max_parallel_per_remote.
        lock.unlock();
        const auto active_web_jobs = active_job_operations(state.web_jobs);
        lock.lock();
        if (state.stop_requested) {
            break;
        }
        struct ScheduledJob {
            std::string name;
            std::optional<std::string> rclone_remote;
            bool from_timer = false;
            bool manual = false;
        };
        std::vector<ScheduledJob> jobs;
        auto can_launch_job = [&](std::string_view remote_dir) -> bool {
            if (state.active_workers + jobs.size() >=
                state.options.max_parallel_profiles) {
                return false;
            }
            const auto remote =
                daemon_detail::extract_rclone_remote_name(remote_dir);
            if (!remote || state.options.max_parallel_per_remote == 0U) {
                return true;
            }
            std::size_t active_on_remote = 0U;
            for (std::size_t i = 0; i < state.profiles.hot.size(); ++i) {
                if (state.profiles.hot[i].in_flight &&
                    daemon_detail::extract_rclone_remote_name(
                        state.profiles.cold[i].config.remote_dir) == remote) {
                    ++active_on_remote;
                }
            }
            for (const auto& queued : jobs) {
                if (queued.rclone_remote && *queued.rclone_remote == *remote) {
                    ++active_on_remote;
                }
            }
            return active_on_remote < state.options.max_parallel_per_remote;
        };
        auto next_wake = now + state.options.config_poll_interval;

        bool aborted_any_immediate = false;
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
                if (!hot.in_flight && hot.immediate_sync_requested) {
                    const std::string_view reason =
                        hot.paused
                            ? "profile paused before sync started"
                            : (hot.locked
                                   ? "profile locked before sync started"
                                   : "profile requires attention before sync");
                    abort_pending_immediate_sync_locked(hot, reason);
                    aborted_any_immediate = true;
                }
                continue;
            }
            const auto& name = state.profiles.names[idx];
            if (std::ranges::any_of(active_web_jobs, [&](const auto& pair) {
                    return pair.first == name;
                })) {
                continue;
            }
            const auto remote_name = daemon_detail::extract_rclone_remote_name(
                cold.config.remote_dir);
            if (hot.immediate_sync_requested) {
                if (can_launch_job(cold.config.remote_dir)) {
                    hot.immediate_sync_requested = false;
                    hot.in_flight = true;
                    jobs.push_back(ScheduledJob{
                        .name = name,
                        .rclone_remote =
                            remote_name
                                ? std::optional<std::string>{*remote_name}
                                : std::nullopt,
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
                    if (can_launch_job(cold.config.remote_dir)) {
                        hot.in_flight = true;
                        jobs.push_back(ScheduledJob{
                            .name = name,
                            .rclone_remote =
                                remote_name
                                    ? std::optional<std::string>{*remote_name}
                                    : std::nullopt,
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
                if (can_launch_job(cold.config.remote_dir)) {
                    hot.in_flight = true;
                    jobs.push_back(ScheduledJob{
                        .name = name,
                        .rclone_remote =
                            remote_name
                                ? std::optional<std::string>{*remote_name}
                                : std::nullopt,
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
        }

        // Launch selected jobs on tracked worker threads.
        for (const auto& job : jobs) {
            auto finished_flag = std::make_shared<std::atomic_bool>(false);
            ++state.active_workers;
            try {
                std::thread t([&state, job, finished_flag] {
                    run_profile_task(
                        state, job.name, job.from_timer, job.manual);
                    {
                        std::lock_guard g(state.mutex);
                        if (state.active_workers > 0) {
                            --state.active_workers;
                        }
                    }
                    finished_flag->store(true, std::memory_order_release);
                    notify_daemon_status_change(state);
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
                    if (job.manual) {
                        hot.immediate_sync_requested = true;
                    }
                }
            }
        }

        if (state.stop_requested) {
            break;
        }
        if (aborted_any_immediate) {
            state.cv.notify_all();
        }
        state.cv.wait_until(lock, next_wake);
    }
    lock.unlock();
    cleanup_daemon_resources(state, false);
    notify_daemon_status_change(state);
}

namespace testing {

ScopedPostSyncPruneHook::ScopedPostSyncPruneHook(PostSyncPruneHook hook) {
    std::lock_guard lock(post_sync_prune_hook_mutex);
    previous = std::exchange(active_post_sync_prune_hook, std::move(hook));
    has_post_sync_prune_hook.store(
        static_cast<bool>(active_post_sync_prune_hook),
        std::memory_order_release);
}

ScopedPostSyncPruneHook::~ScopedPostSyncPruneHook() noexcept {
    std::lock_guard lock(post_sync_prune_hook_mutex);
    active_post_sync_prune_hook = std::move(previous);
    has_post_sync_prune_hook.store(
        static_cast<bool>(active_post_sync_prune_hook),
        std::memory_order_release);
}

bool post_sync_prune_hook_active() noexcept {
    return has_post_sync_prune_hook.load(std::memory_order_acquire);
}

void invoke_post_sync_prune_hook(DaemonSessionState& state,
                                 std::string_view profile_name,
                                 PostSyncPruneStage stage,
                                 const PostSyncPruneSnapshot* snapshot) {
    if (!has_post_sync_prune_hook.load(std::memory_order_acquire)) {
        return;
    }
    PostSyncPruneHook hook;
    {
        std::lock_guard lock(post_sync_prune_hook_mutex);
        hook = active_post_sync_prune_hook;
    }
    if (hook) {
        hook(state, profile_name, stage, snapshot);
    }
}

} // namespace testing

} // namespace kasumi::application::daemon_detail
