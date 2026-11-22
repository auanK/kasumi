#ifndef KASUMI_CLI_PRESENTER_HPP
#define KASUMI_CLI_PRESENTER_HPP

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

namespace kasumi::cli {

int present_help(std::string_view topic);
int present_parse_error(std::string_view topic);

struct FsckProgressDisplayState {
    std::optional<application::FsckStage> last_stage;
    std::optional<unsigned> last_object_percent;
    bool empty_inventory_reported = false;
};

struct GarbageCollectProgressDisplayState {
    std::optional<application::GarbageCollectStage> last_stage;
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

class ProgressDisplay {
public:
    explicit ProgressDisplay(
        platform::Terminal terminal = platform::stdout_terminal(),
        bool full = false)
        : terminal_(terminal), full_(full) {
    }
    ~ProgressDisplay();
    void
    update(const application::ExecutionProgress& progress,
           application::Operation operation = application::Operation::Sync);
    void show(const application::ActivityProgress& progress,
              std::string_view extra = {});
    void heartbeat() noexcept;
    void finish(bool keep = false) noexcept;

private:
    void clear_line() noexcept;
    void render_line(std::string_view line, std::string_view detail = {});
    std::string applying_line() const;
    void render_event(const application::ActivityProgress& event,
                      std::string_view extra,
                      bool force_complete = false);
    void flush_transfer(TransferMetricsState& state) noexcept;

    platform::Terminal terminal_;
    bool full_ = false;
    bool indented_ = false;
    bool in_applying_ = false;
    std::optional<application::SyncProgress> apply_progress_;
    std::optional<unsigned> plain_milestone_;
    FsckProgressDisplayState fsck_;
    GarbageCollectProgressDisplayState gc_;
    TransferMetricsState upload_state_;
    TransferMetricsState download_state_;
    std::optional<application::Activity> activity_;
    std::uint64_t stage_id_ = 0;
    std::size_t rendered_width_ = 0;
    bool rendered_detail_ = false;
    std::uint64_t last_value_ = 0;
    std::uint64_t last_objects_ = 0;
    double rate_ = 0;
    bool was_complete_ = false;
    std::optional<application::ActivityProgress> last_event_;
    std::string last_extra_;
    bool rendered_last_ = true;
    std::chrono::steady_clock::time_point started_ =
        std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point last_render_{};
};

std::string format_eta(std::uint64_t seconds);

// Formats a byte count into a human-readable representation.
std::string format_size(std::uint64_t bytes);

// Formats a duration into a human-readable representation.
std::string format_duration(std::chrono::nanoseconds duration);
void present_duration(std::chrono::nanoseconds duration);

// Formats a concise, language-independent operational summary string.
std::string format_compact_summary(const application::SyncCompleted& sync);
std::string format_compact_summary(const application::Response& response);
std::string format_compact_summary(const application::DiagnosticsReport& report);
std::string
format_compact_summary(const application::InspectionResponse& response);

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

// Displays the result of a remote inspection and returns 0.
int present(const application::InspectionResponse& response, bool full = false);

// Displays the error and returns 1.
int present(const application::Error& error);

// Displays the error of a remote inspection and returns 1.
int present(const application::InspectionError& error);

void print_ok_line(std::string_view message);
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
