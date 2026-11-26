#ifndef KASUMI_APPLICATION_DAEMON_EVENT_LOG_HPP
#define KASUMI_APPLICATION_DAEMON_EVENT_LOG_HPP

#include "application/daemon.hpp"

#include <deque>
#include <filesystem>

namespace kasumi::application::daemon_detail {

void emit_daemon_event(DaemonSessionState& state,
                       std::string profile_name,
                       std::string kind,
                       std::string detail,
                       bool persist_to_log = true) noexcept;

void append_daemon_log_line_best_effort(
    const std::filesystem::path& app_data_dir,
    const DaemonEvent& event) noexcept;

DaemonLogsReport
merge_daemon_log_events(const std::filesystem::path& app_data_dir,
                        const std::deque<DaemonEvent>* live_ring,
                        const DaemonLogQuery& query);

} // namespace kasumi::application::daemon_detail

#endif
