#include "application/daemon/profile_state.hpp"

#include "application/daemon/event_log.hpp"
#include "application/detail.hpp"
#include "application/observation/file_metadata.hpp"
#include "crypto/secure_memory.hpp"
#include "platform/path.hpp"
#include "runtime/paths.hpp"
#include "runtime/vault.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <array>
#include <monocypher.h>
#include <system_error>
#include <utility>

namespace kasumi::application::daemon_detail {
namespace {

constexpr std::size_t kMaxTrackedDirtyPaths = 4096U;

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
        notify_daemon_status_change(state);
    }
}

} // namespace

std::optional<std::size_t> find_profile_slot(const ProfileTable& table,
                                             std::string_view name) noexcept {
    const auto it = std::ranges::lower_bound(table.names, name);
    if (it == table.names.end() || *it != name) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(it - table.names.begin());
}

std::chrono::seconds next_vault_recheck_delay(std::uint32_t attempts) noexcept {
    constexpr std::array<int, 5> kDelaysSeconds{{3, 5, 10, 15, 30}};
    const std::size_t idx =
        std::min<std::size_t>(attempts, kDelaysSeconds.size() - 1U);
    return std::chrono::seconds{kDelaysSeconds[idx]};
}

void clear_active_telemetry(ProfileTelemetryRow& telemetry) noexcept {
    telemetry.active_stage.clear();
    telemetry.active_item_path.clear();
    telemetry.active_item_bytes.reset();
    telemetry.active_item_total_bytes.reset();
    telemetry.active_objects = 0;
    telemetry.active_total_objects.reset();
    telemetry.active_bytes = 0;
    telemetry.active_total_bytes.reset();
    telemetry.sync_phase.clear();
    telemetry.sync_applied_items.reset();
    telemetry.sync_total_items.reset();
    telemetry.active_bytes_per_second.reset();
    telemetry.rate_sample_at = {};
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
                               bool force_key_recheck) {
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
            if (warm.commit_cache) {
                history_storage::clear_memory_cache(*warm.commit_cache);
            }
            if (warm.thumbnail_cache) {
                clear_remote_thumbnail_cache(*warm.thumbnail_cache);
            }
            platform::erase_secure_key(state.key_arena,
                                       state.profiles.names[idx]);
            erase_profile_slot(state.profiles, idx);
        }
    }

    const auto now_steady = std::chrono::steady_clock::now();
    std::size_t startup_index = 0;
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
            const auto stagger = state.options.startup_stagger *
                                 static_cast<std::int64_t>(startup_index);
            ++startup_index;
            ProfileHotSchedule hot{
                .paused = cfg.paused,
                .watch_enabled = cfg.watch_enabled.value_or(true),
                .sync_interval_seconds = sync_sec,
                .next_sync_at =
                    sync_sec > 0
                        ? (now_steady + std::chrono::seconds{2} + stagger)
                        : (std::chrono::steady_clock::time_point::max)(),
                .last_full_verify_at = now_steady,
            };
            ProfileColdMeta cold{
                .config = cfg,
                .database_path = paths->database_path,
                .key_path = paths->key_path,
            };
            ProfileWarmSlot warm;
            warm.warm_observation.database_path = paths->database_path;
            warm.commit_cache =
                std::make_shared<history_storage::CommitCache>();
            warm.commit_cache->disk_cache_root =
                state.environment.app_data_dir / "cache" / "commits";
            warm.thumbnail_cache = std::make_shared<RemoteThumbnailCache>();

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
            const bool unpaused = hot.paused && !cfg.paused;

            cold.config = cfg;
            hot.paused = cfg.paused;
            hot.watch_enabled = cfg.watch_enabled.value_or(true);
            hot.sync_interval_seconds =
                cfg.sync_interval_seconds.value_or(kDefaultSyncIntervalSeconds);

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
                if (warm.commit_cache) {
                    history_storage::clear_memory_cache(*warm.commit_cache);
                }
                if (warm.thumbnail_cache) {
                    clear_remote_thumbnail_cache(*warm.thumbnail_cache);
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

} // namespace kasumi::application::daemon_detail
