#ifndef KASUMI_CLI_PRESENTER_HPP
#define KASUMI_CLI_PRESENTER_HPP

#include "application/execute.hpp"
#include "application/inspection/result.hpp"
#include "application/result.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace kasumi::cli {

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
