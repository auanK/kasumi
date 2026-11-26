#ifndef KASUMI_APPLICATION_DAEMON_PROFILE_STATE_HPP
#define KASUMI_APPLICATION_DAEMON_PROFILE_STATE_HPP

#include "application/daemon/session_state.hpp"

namespace kasumi::application::daemon_detail {

std::optional<std::size_t> find_profile_slot(const ProfileTable& table,
                                             std::string_view name) noexcept;

std::chrono::seconds next_vault_recheck_delay(std::uint32_t attempts) noexcept;

void clear_active_telemetry(ProfileTelemetryRow& telemetry) noexcept;

observation::DatabaseMetadataStamp
read_file_stamp(const std::filesystem::path& path);

void refresh_ignore_state(ProfileColdMeta& cold, ProfileWarmSlot& warm);

void ensure_watcher_started_unlocked(DaemonSessionState& state,
                                     std::string_view profile_name);

bool db_schema_valid(const std::filesystem::path& db_path);
bool db_initialized_and_has_state(const std::filesystem::path& db_path);

bool refresh_key_status_for_slot(DaemonSessionState& state,
                                 std::size_t idx,
                                 bool force_probe);

std::expected<void, DaemonError>
sync_profiles_from_disk_locked(DaemonSessionState& state,
                               std::unique_lock<std::mutex>& lock,
                               bool force_key_recheck = false);

} // namespace kasumi::application::daemon_detail

#endif
