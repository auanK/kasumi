#ifndef KASUMI_CLI_PRESENTER_HPP
#define KASUMI_CLI_PRESENTER_HPP

#include "application/execute.hpp"
#include "application/inspection/result.hpp"
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

class ProgressDisplay {
public:
    explicit ProgressDisplay(
        platform::Terminal terminal = platform::stdout_terminal())
        : terminal_(terminal) {
    }
    ~ProgressDisplay();
    void
    update(const application::ExecutionProgress& progress,
           application::Operation operation = application::Operation::Sync);
    void show(const application::ActivityProgress& progress,
              std::string_view extra = {});
    void finish(bool keep = false) noexcept;

private:
    platform::Terminal terminal_;
    FsckProgressDisplayState fsck_;
    GarbageCollectProgressDisplayState gc_;
    std::optional<application::Activity> activity_;
    std::uint64_t stage_id_ = 0;
    std::size_t rendered_width_ = 0;
    std::uint64_t last_value_ = 0;
    double rate_ = 0;
    bool was_complete_ = false;
    std::chrono::steady_clock::time_point started_{};
    std::chrono::steady_clock::time_point last_render_{};
};

std::string format_eta(std::uint64_t seconds);

// Formats a byte count into a human-readable representation.
std::string format_size(std::uint64_t bytes);

// Formats a duration into a human-readable representation.
std::string format_duration(std::chrono::nanoseconds duration);
void present_duration(std::chrono::nanoseconds duration);

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

// Displays success and returns 0.
int present(const application::Response& response, bool full = false);

// Displays the result of a remote inspection and returns 0.
int present(const application::InspectionResponse& response);

// Displays the error and returns 1.
int present(const application::Error& error);

// Displays the error of a remote inspection and returns 1.
int present(const application::InspectionError& error);

void print_ok_line(std::string_view message);
void print_error_line(std::string_view message);
std::string sanitize_terminal_text(std::string_view text);

} // namespace kasumi::cli

#endif
