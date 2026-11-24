#ifndef KASUMI_CLI_PRESENTER_HPP
#define KASUMI_CLI_PRESENTER_HPP

#include "application/daemon.hpp"
#include "application/execute.hpp"
#include "application/inspection/result.hpp"
#include "application/profile.hpp"
#include "application/result.hpp"
#include "platform/terminal.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::cli {

struct OverviewProfileRow {
    application::Profile profile;
    application::ProfileLocalState local_state =
        application::ProfileLocalState::Initialized;
    application::ProfileLocalProblem local_problem =
        application::ProfileLocalProblem::None;
    application::ProfileActivityReport activity;
    std::size_t conflict_count = 0;
    std::optional<application::DaemonProfileStatus> daemon_profile;
};

int present_help(std::string_view topic, bool all = false);
int present_parse_error(std::string_view topic);

struct FsckProgressDisplayState {
    std::optional<application::FsckStage> last_stage;
    std::optional<unsigned> last_object_percent;
    bool empty_inventory_reported = false;
};

struct GarbageCollectProgressDisplayState {
    std::optional<application::GarbageCollectStage> last_stage;
    std::optional<std::size_t> last_listed_objects;
    std::optional<std::size_t> last_candidate_count;
};

struct TransferMetricsState {
    std::uint64_t base_objects = 0;
    std::uint64_t base_total_objects = 0;
    std::uint64_t base_bytes = 0;
    std::uint64_t base_total_bytes = 0;
    std::uint64_t last_objects = 0;
    std::uint64_t last_total_objects = 0;
    std::uint64_t last_bytes = 0;
    std::uint64_t last_total_bytes = 0;
    std::uint64_t last_stage_id = 0;
    double rate = 0;
    std::optional<double> min_rate;
    std::optional<double> max_rate;
    std::chrono::steady_clock::time_point started{};
    std::chrono::steady_clock::time_point last_sample{};
    std::uint64_t last_sample_bytes = 0;
    bool active = false;
    bool completed_reported = false;
    std::optional<application::ActivityProgress> last_event;
    std::string last_extra;
};

struct ProgressDisplay {
    explicit ProgressDisplay(
        platform::Terminal terminal_value = platform::stdout_terminal(),
        bool full_value = false)
        : terminal(terminal_value), full(full_value) {
    }
    ~ProgressDisplay();

    platform::Terminal terminal;
    bool full = false;
    bool indented = false;
    bool in_applying = false;
    std::optional<application::SyncProgress> apply_progress;
    std::optional<unsigned> plain_milestone;
    FsckProgressDisplayState fsck;
    GarbageCollectProgressDisplayState gc;
    TransferMetricsState upload_state;
    TransferMetricsState download_state;
    std::optional<application::Activity> activity;
    std::uint64_t stage_id = 0;
    std::size_t rendered_width = 0;
    bool rendered_detail = false;
    std::uint64_t last_value = 0;
    std::uint64_t last_objects = 0;
    double rate = 0;
    bool was_complete = false;
    std::optional<application::ActivityProgress> last_event;
    std::string last_extra;
    bool rendered_last = true;
    std::chrono::steady_clock::time_point started =
        std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point last_render{};
};

void update_progress_display(
    ProgressDisplay& display,
    const application::ExecutionProgress& progress,
    application::Operation operation = application::Operation::Sync);
void show_progress_display(ProgressDisplay& display,
                           const application::ActivityProgress& progress,
                           std::string_view extra = {});
void heartbeat_progress_display(ProgressDisplay& display) noexcept;
void finish_progress_display(ProgressDisplay& display,
                             bool keep = false) noexcept;

std::string format_eta(std::uint64_t seconds);

// Formats a byte count into a human-readable representation.
std::string format_size(std::uint64_t bytes);

// Formats a duration into a human-readable representation.
std::string format_duration(std::chrono::nanoseconds duration);
void present_duration(std::chrono::nanoseconds duration);

// Formats a concise, language-independent operational summary string.
std::string format_compact_summary(const application::SyncCompleted& sync);
std::string format_compact_summary(const application::Response& response);
std::string
format_compact_summary(const application::DiagnosticsReport& report);
std::string
format_compact_summary(const application::LocalConflictsReport& report);
std::string
format_compact_summary(const application::ResolveConflictReport& report);
std::string
format_compact_summary(const application::InspectionResponse& response);
std::string
format_compact_summary(const application::DaemonStatusReport& report);
std::string
format_compact_summary(const application::DaemonAutostartStatus& status);

// Displays cancellation message and returns 130.
int present_cancellation(
    application::Operation operation = application::Operation::Sync);

// Displays a synchronization or plan progress event.
void present(const application::SyncProgress& progress,
             application::Operation operation = application::Operation::Sync);

// Displays a garbage collection progress event.
void present(const application::GarbageCollectProgress& progress,
             GarbageCollectProgressDisplayState& state);

// Displays an FSCK stage and throttled unique-object progress.
void present(const application::FsckProgress& progress,
             FsckProgressDisplayState& state);

// Displays success and returns 0. When quiet is true and exit code is 0,
// suppresses non-error status stdout while preserving stderr warnings.
int present(const application::Response& response,
            bool full = false,
            bool quiet = false);

// Displays local environment and profile diagnostics and returns 0.
int present(const application::DiagnosticsReport& report,
            std::string_view version,
            bool quiet = false);

// Displays local conflict artifacts for a profile and returns 0.
int present(const application::LocalConflictsReport& report,
            bool quiet = false);

// Displays resolved local conflict result for a profile and returns 0.
int present(const application::ResolveConflictReport& report,
            bool quiet = false);

// Displays `.kasumiignore` rule evaluation results and returns 0.
int present(const application::IgnoreCheckReport& report, bool quiet = false);

// Displays `.kasumiignore` initialization template or result and returns 0.
int present(const application::IgnoreInitReport& report, bool quiet = false);

// Displays the result of a remote inspection and returns 0.
int present(const application::InspectionResponse& response, bool full = false);

// Displays the error and returns 1.
int present(const application::Error& error);

// Displays the error of a remote inspection and returns 1.
int present(const application::InspectionError& error);

// Displays consolidated daemon + profile overview (for bare `kasumi`).
int present_overview(const application::DaemonStatusReport& daemon,
                     const std::vector<OverviewProfileRow>& rows,
                     bool full = false,
                     bool quiet = false);

// Displays daemon status, sync triggers, autostart status, logs, and errors.
int present(const application::DaemonStatusReport& report,
            bool full = false,
            bool quiet = false);
int present(const application::DaemonAutostartStatus& status,
            bool quiet = false);
int present(const application::DaemonSyncTriggerReport& report,
            bool wait,
            bool quiet = false);
bool is_noisy_daemon_event(const application::DaemonEvent& event) noexcept;
void print_daemon_event_line(const application::DaemonEvent& event);
int present(const application::DaemonLogsReport& report,
            bool full = false,
            bool quiet = false);
int present(const application::DaemonError& error);
std::string_view
execution_status_label(application::ProfileExecutionStatus status);
std::string_view overview_problem_message(
    application::ProfileLocalProblem problem);

void print_ok_line(std::string_view message);
void print_warning_line(std::string_view message);
void print_error_line(std::string_view message);
std::string sanitize_terminal_text(std::string_view text);

// Shared formatting helpers for execution and activity traceability.
std::string format_machine_label(std::string_view name,
                                 std::string_view id_hex,
                                 bool show_id,
                                 bool full_id = false);
std::string_view commit_origin_label(std::uint8_t origin_op);
std::string_view activity_operation_label(std::uint8_t op);
std::string_view activity_outcome_label(std::uint8_t outcome);
std::string format_activity_metrics(std::uint8_t op,
                                    std::uint64_t primary,
                                    std::uint64_t secondary,
                                    std::uint64_t bytes,
                                    std::uint32_t flags);
std::string format_activity_flags(std::uint32_t flags);

} // namespace kasumi::cli

#endif
