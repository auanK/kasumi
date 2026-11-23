#ifndef KASUMI_CLI_JSON_PRESENTER_HPP
#define KASUMI_CLI_JSON_PRESENTER_HPP

#include "application/inspection/result.hpp"
#include "application/profile.hpp"
#include "application/result.hpp"

#include <chrono>
#include <filesystem>
#include <optional>
#include <string_view>
#include <vector>

namespace kasumi::cli {

class ScopedJsonLogFile {
public:
    explicit ScopedJsonLogFile(std::optional<std::filesystem::path> path);
    ~ScopedJsonLogFile() noexcept;

    ScopedJsonLogFile(const ScopedJsonLogFile&) = delete;
    ScopedJsonLogFile& operator=(const ScopedJsonLogFile&) = delete;

private:
    std::optional<std::filesystem::path> path_;
    const std::filesystem::path* previous_ = nullptr;
};

int present_json_io_error(std::string_view command,
                          std::string_view profile_name,
                          std::string_view detail);

std::string_view json_error_code(const application::Error& error) noexcept;
std::string_view
json_error_code(const application::InspectionError& error) noexcept;
std::string_view json_error_code(application::ProfileErrorCode code) noexcept;

int present_json_parse_error(std::string_view command, std::string_view detail);

int present_json_cancellation(std::string_view command,
                              std::string_view profile_name = {});

int present_json_list(const std::vector<application::Profile>& profiles);

int present_json_show(const application::Profile& profile,
                      application::ProfileLocalState state,
                      application::ProfileLocalProblem problem,
                      const application::ProfileActivityReport& activity,
                      bool full);

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

} // namespace kasumi::cli

#endif
