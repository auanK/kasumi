#ifndef KASUMI_APPLICATION_EXECUTE_HPP
#define KASUMI_APPLICATION_EXECUTE_HPP

#include "application/credentials.hpp"
#include "application/environment.hpp"
#include "application/request.hpp"
#include "application/result.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <optional>
#include <variant>

namespace kasumi::application {

enum class Activity {
    Scanning,
    Staging,
    Uploading,
    Downloading,
    Verifying,
    Installing,
    Reobserving,
    Listing,
    Authenticating,
    Auditing,
    Removing,
    ComparingSnapshots,
    CheckingRemoteContent,
    PreparingPlan,
    PreparingRemote,
};

// Cumulative counters for the current activity, sampled outside worker threads.
struct ActivityProgress {
    Activity activity = Activity::Scanning;
    std::uint64_t bytes = 0;
    std::optional<std::uint64_t> total_bytes = std::nullopt;
    std::uint64_t objects = 0;
    std::optional<std::uint64_t> total_objects = std::nullopt;
    std::uint64_t cache_hits = 0;
    std::uint64_t files_hashed = 0;
    std::uint64_t bytes_reused = 0;
    std::optional<std::uint64_t> staged_bytes = std::nullopt;
    unsigned attempt = 0;
    bool observing_remote = false;
    std::uint64_t stage_id = 0;
    std::filesystem::path item_path{};
    std::optional<std::uint64_t> item_bytes = std::nullopt;
    std::optional<std::uint64_t> item_total_bytes = std::nullopt;
};

// Progress notification for high-level synchronization phases.
struct SyncProgress {
    SyncStage stage = SyncStage::Observing;
    std::optional<SyncCompleted> summary = std::nullopt;
    std::uint32_t total_items = 0;
    std::optional<std::uint32_t> applied_items = std::nullopt;
};

// Progress notification for high-level garbage collection phases.
struct GarbageCollectProgress {
    GarbageCollectStage stage = GarbageCollectStage::Preparing;
    std::optional<std::size_t> candidate_count = std::nullopt;
    std::size_t removed_objects = 0;
    std::chrono::nanoseconds removal_elapsed{};
    std::optional<std::size_t> listed_objects = std::nullopt;
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
    std::uint64_t wire_download_bytes = 0;
    std::optional<std::uint64_t> total_wire_bytes = std::nullopt;
    std::uint64_t physical_objects_downloaded = 0;
    std::uint64_t files_reassembled = 0;
};

// Unified progress notification for application executions.
using ExecutionProgress = std::variant<SyncProgress,
                                       GarbageCollectProgress,
                                       FsckProgress,
                                       ActivityProgress>;

// Callback type for receiving execution progress updates.
using ProgressCallback = std::function<void(const ExecutionProgress&)>;

inline void report_progress(const ProgressCallback& callback,
                            const ExecutionProgress& progress) noexcept {
    if (callback) {
        try {
            callback(progress);
        } catch (...) {
        }
    }
}

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
