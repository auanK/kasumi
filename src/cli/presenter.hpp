#ifndef KASUMI_CLI_PRESENTER_HPP
#define KASUMI_CLI_PRESENTER_HPP

#include "application/execute.hpp"
#include "application/inspection/result.hpp"
#include "application/result.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace kasumi::cli {

struct FsckProgressDisplayState {
    std::optional<application::FsckStage> last_stage;
    std::optional<unsigned> last_object_percent;
    bool empty_inventory_reported = false;
};

// Formats a byte count into a human-readable representation.
std::string format_size(std::uint64_t bytes);

// Formats a duration into a human-readable representation.
std::string format_duration(std::chrono::nanoseconds duration);

// Displays cancellation message and returns 130.
int present_cancellation(
    application::Operation operation = application::Operation::Sync);

// Displays a synchronization or plan progress event.
void present(const application::SyncProgress& progress,
             application::Operation operation = application::Operation::Sync);

// Displays a garbage collection progress event.
void present(const application::GarbageCollectProgress& progress);

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

} // namespace kasumi::cli

#endif
