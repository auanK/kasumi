#ifndef KASUMI_CLI_JSON_PRESENTER_HPP
#define KASUMI_CLI_JSON_PRESENTER_HPP

#include "application/daemon.hpp"
#include "application/inspection/result.hpp"
#include "application/profile.hpp"
#include "application/result.hpp"

#include <chrono>
#include <filesystem>
#include <optional>
#include <string_view>
#include <vector>

namespace kasumi::cli {

struct ScopedJsonLogFile {
    std::optional<std::filesystem::path> path;
    const std::filesystem::path* previous = nullptr;

    explicit ScopedJsonLogFile(std::optional<std::filesystem::path> log_path);
    ~ScopedJsonLogFile() noexcept;

    ScopedJsonLogFile(const ScopedJsonLogFile&) = delete;
    ScopedJsonLogFile& operator=(const ScopedJsonLogFile&) = delete;
};

int present_json_io_error(std::string_view command,
                          std::string_view profile_name,
                          std::string_view detail);

std::string_view json_error_code(const application::Error& error) noexcept;
std::string_view
json_error_code(const application::InspectionError& error) noexcept;
std::string_view json_error_code(application::ProfileErrorCode code) noexcept;
std::string_view json_error_code(application::DaemonErrorCode code) noexcept;

int present_json_parse_error(std::string_view command, std::string_view detail);

int present_json_cancellation(std::string_view command,
                              std::string_view profile_name = {});

int present_json_list(const std::vector<application::Profile>& profiles);

int present_json_show(const application::Profile& profile,
                      application::ProfileLocalState state,
                      application::ProfileLocalProblem problem,
                      const application::ProfileActivityReport& activity,
                      bool full,
                      const std::optional<application::DaemonProfileStatus>&
                          daemon_profile = std::nullopt);

int present_json_diagnostics(const application::DiagnosticsReport& report,
                             std::string_view version,
                             std::string_view requested_profile,
                             std::chrono::nanoseconds duration);

int present_json_conflicts(const application::LocalConflictsReport& report,
                           std::chrono::nanoseconds duration);

int present_json_conflict_resolved(
    const application::ResolveConflictReport& report,
    std::chrono::nanoseconds duration);

int present_json_profile_action(std::string_view command,
                                const application::Profile* profile,
                                std::string_view profile_name,
                                std::string_view summary,
                                bool needs_key,
                                std::chrono::nanoseconds duration);

int present_json_key_updated(std::string_view profile_name,
                             bool replaced,
                             bool unchanged,
                             std::chrono::nanoseconds duration);

int present_json_profile_test(
    const application::ProfileConnectionReport& report,
    std::chrono::nanoseconds duration);

int present_json_ignore_check(const application::IgnoreCheckReport& report,
                              std::chrono::nanoseconds duration);

int present_json_ignore_init(const application::IgnoreInitReport& report,
                             std::chrono::nanoseconds duration);

int present_json_credentials_required(
    std::string_view command,
    std::string_view profile_name,
    std::string_view detail,
    std::chrono::nanoseconds duration = std::chrono::nanoseconds{0});

int present_json_profile_error(
    std::string_view command,
    std::string_view profile_name,
    const application::ProfileError& error,
    std::optional<std::chrono::nanoseconds> duration = std::nullopt);

int present_json_confirmation_required(
    std::string_view profile_name,
    const application::ResolveMissingCompleted& preview,
    std::chrono::nanoseconds duration);

int present_json(std::string_view profile_name,
                 const application::Response& response,
                 std::chrono::nanoseconds duration,
                 bool full = false);

int present_json(std::string_view profile_name,
                 const application::Error& error,
                 std::chrono::nanoseconds duration);

int present_json(std::string_view profile_name,
                 const application::InspectionResponse& response,
                 std::chrono::nanoseconds duration,
                 bool full = false);

int present_json(std::string_view profile_name,
                 const application::InspectionError& error,
                 std::chrono::nanoseconds duration);

int present_json_daemon_status(
    std::string_view command,
    const application::DaemonStatusReport& report,
    std::chrono::nanoseconds duration,
    std::optional<std::string_view> profile_name = std::nullopt);

int present_json_daemon_sync(const application::DaemonSyncTriggerReport& report,
                             std::optional<std::string_view> profile_name,
                             bool wait,
                             std::chrono::nanoseconds duration);

int present_json_daemon_autostart(
    std::string_view command,
    const application::DaemonAutostartStatus& status,
    std::chrono::nanoseconds duration);

int present_json_daemon_action(std::string_view command,
                               std::string_view profile_name,
                               std::string_view summary,
                               std::chrono::nanoseconds duration);

int present_json_daemon_logs(const application::DaemonLogsReport& report,
                             std::optional<std::string_view> profile_name,
                             std::chrono::nanoseconds duration);

void append_json_daemon_event(const std::filesystem::path& path,
                              const application::DaemonEvent& event);

int present_json_daemon_error(std::string_view command,
                              std::string_view profile_name,
                              const application::DaemonError& error,
                              std::chrono::nanoseconds duration);

} // namespace kasumi::cli

#endif
