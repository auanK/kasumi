#ifndef KASUMI_APPLICATION_EXECUTE_HPP
#define KASUMI_APPLICATION_EXECUTE_HPP

#include "application/credentials.hpp"
#include "application/environment.hpp"
#include "application/request.hpp"
#include "application/result.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <variant>

namespace kasumi::application {

// Progress notification for high-level synchronization phases.
struct SyncProgress {
    SyncStage stage = SyncStage::Observing;
    std::optional<SyncCompleted> summary = std::nullopt;
    std::uint32_t completed_items = 0;
    std::uint32_t total_items = 0;
};

// High-level stages for recoverable garbage collection.
enum class GarbageCollectStage {
    Preparing,
    CheckingQuarantine,
    Analyzing,
    Applying,
    Finalizing,
};

// Progress notification for high-level garbage collection phases.
struct GarbageCollectProgress {
    GarbageCollectStage stage = GarbageCollectStage::Preparing;
    std::optional<std::size_t> candidate_count = std::nullopt;
};

// Progress notification for a read-only integrity audit.
enum class FsckStage {
    Preparing,
    Observing,
    Analyzing,
    AuditingContent,
    Finalizing,
};

struct FsckProgress {
    FsckStage stage = FsckStage::Preparing;
    std::size_t completed_objects = 0;
    std::optional<std::size_t> total_objects = std::nullopt;
    std::optional<std::uint64_t> completed_plaintext_bytes = 0;
    std::optional<std::uint64_t> total_plaintext_bytes = std::nullopt;
};

// Unified progress notification for application executions.
using ExecutionProgress =
    std::variant<SyncProgress, GarbageCollectProgress, FsckProgress>;

// Callback type for receiving execution progress updates.
using ProgressCallback = std::function<void(const ExecutionProgress&)>;

// Backward-compatible alias for synchronization progress updates.
using SyncProgressCallback = ProgressCallback;

// Inputs required for an execution.
struct ExecutionInput {
    Request request;
    Credentials credentials;
    ExecutionEnvironment environment;
    ProgressCallback on_progress{};
};

// Executes the requested operation.
std::expected<Response, Error> execute(ExecutionInput input);

} // namespace kasumi::application

#endif
