#ifndef KASUMI_APPLICATION_EXECUTE_HPP
#define KASUMI_APPLICATION_EXECUTE_HPP

#include "application/credentials.hpp"
#include "application/environment.hpp"
#include "application/request.hpp"
#include "application/result.hpp"

#include <expected>
#include <functional>
#include <optional>

namespace kasumi::application {

// Progress notification for high-level synchronization phases.
struct SyncProgress {
    SyncStage stage = SyncStage::Observing;
    std::optional<SyncCompleted> summary = std::nullopt;
    std::uint32_t completed_items = 0;
    std::uint32_t total_items = 0;
};

// Callback type for receiving synchronization progress updates.
using SyncProgressCallback = std::function<void(const SyncProgress&)>;

// Inputs required for an execution.
struct ExecutionInput {
    Request request;
    Credentials credentials;
    ExecutionEnvironment environment;
    SyncProgressCallback on_progress{};
};

// Executes the requested operation.
std::expected<Response, Error> execute(ExecutionInput input);

} // namespace kasumi::application

#endif
