#ifndef KASUMI_CLI_JSON_PRESENTER_HPP
#define KASUMI_CLI_JSON_PRESENTER_HPP

#include "application/inspection/result.hpp"
#include "application/profile.hpp"
#include "application/result.hpp"

#include <chrono>
#include <string_view>
#include <vector>

namespace kasumi::cli {

int present_json_parse_error(std::string_view command,
                             std::string_view detail);

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

int present_json_profile_error(std::string_view command,
                               std::string_view profile_name,
                               const application::ProfileError& error);

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
