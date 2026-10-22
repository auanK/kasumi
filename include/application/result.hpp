#ifndef KASUMI_APPLICATION_RESULT_HPP
#define KASUMI_APPLICATION_RESULT_HPP

#include "application/request.hpp"
#include "transport/types.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace kasumi::application {

// Paths used during execution.
struct RuntimeSummary {
    std::filesystem::path local_dir;
    std::string remote_dir;
};

// Possible actions in a synchronization plan.
enum class PlanAction {
    RenameLocal,
    Upload,
    CreateLocalDirectory,
    CreateRemoteDirectory,
    Download,
    DeleteLocal,
    DeleteLocalDirectory,
    DeleteRemote,
    DeleteRemoteDirectory,
    Count
};

// Number of valid actions.
inline constexpr std::size_t PLAN_ACTION_COUNT =
    static_cast<std::size_t>(PlanAction::Count);

// Item displayed in a synchronization plan.
struct PlanItem {
    PlanAction action = PlanAction::Upload;
    std::filesystem::path path;
    // Destination of RenameLocal; path is the source.
    std::filesystem::path alternative_path;
    std::uint64_t size = 0;
};

// Computed plan for Preview or Status, without execution.
struct PlanReport {
    // Expected generation following synchronization.
    std::uint64_t target_generation = 0;
    // Counts indexed by PlanAction.
    std::array<std::uint32_t, PLAN_ACTION_COUNT> action_counts{};
    std::uint64_t upload_bytes = 0;
    std::uint64_t download_bytes = 0;
    bool has_conflicts = false;
    std::vector<PlanItem> items;
    std::vector<std::filesystem::path> pending_paths;
};

// High-level phases of synchronization execution.
enum class SyncStage {
    Observing,
    Calculating,
    Applying,
    Publishing,
    Finalizing,
};

// Indicates completed synchronization with summary counts.
struct SyncCompleted {
    std::uint32_t total = 0;
    std::uint32_t uploaded = 0;
    std::uint32_t downloaded = 0;
    std::uint32_t removed = 0;
    std::uint32_t renamed = 0;
    std::uint32_t created_dirs = 0;
    std::uint32_t removed_dirs = 0;

    std::uint64_t upload_bytes = 0;
    std::uint64_t download_bytes = 0;

    bool published = false;
    std::uint32_t pending = 0;
    std::vector<std::filesystem::path> pending_paths;
    bool partial = false;
    std::optional<std::chrono::nanoseconds> duration = std::nullopt;
};

// Summary of a completed integrity check.
struct FsckCompleted {
    std::size_t checked_objects = 0;
    std::optional<std::uint64_t> checked_plaintext_bytes = std::nullopt;
};

// High-level stages for garbage collection.
enum class GarbageCollectStage {
    Preparing,
    Analyzing,
    Applying,
    Finalizing,
};

// State of the mutation associated with a garbage-collection failure.
enum class GarbageCollectMutationState {
    NotAttempted,
    Confirmed,
    Uncertain,
};

// Diagnostic context for a garbage-collection failure. confirmed_removed counts
// REMOVE operations acknowledged by the transport, not an independent physical
// audit; an ambiguous mutation remains Uncertain.
struct GarbageCollectFailure {
    std::size_t candidate_objects = 0;
    std::size_t confirmed_removed = 0;
    std::optional<std::string> failed_identifier;
    GarbageCollectStage stage = GarbageCollectStage::Preparing;
    GarbageCollectMutationState mutation_state =
        GarbageCollectMutationState::NotAttempted;
    std::optional<transport::Error> transport_error;
    bool barrier_release_attempted = false;
    bool barrier_release_confirmed = false;
    std::optional<std::string> barrier_cleanup_error;
    std::optional<transport::Error> barrier_cleanup_transport_error;
};

// Result of completed garbage collection.
struct GarbageCollectCompleted {
    std::size_t candidate_objects = 0;
    bool analysis_only = false;
    std::size_t removed_objects = 0;
};

// Result of resolving unavailable pending materializations as logical
// deletions.
struct ResolveMissingCompleted {
    std::size_t resolved_count = 0;
    std::vector<std::string> resolved_paths;
    bool published = false;
};

struct ManualWriterRemovalCompleted {
    std::string identifier;
};

// Possible payload variants for a successful response.
using ResponseData = std::variant<SyncCompleted,
                                  PlanReport,
                                  FsckCompleted,
                                  GarbageCollectCompleted,
                                  ResolveMissingCompleted,
                                  ManualWriterRemovalCompleted>;

// Successful operation response.
struct Response {
    Operation operation = Operation::Sync;
    // Resolved runtime paths, when available.
    std::optional<RuntimeSummary> runtime;
    // Payload variant corresponding to operation.
    ResponseData data;
};

// Application failure categories.
enum class ErrorCode {
    InvalidProfile,
    ProfileNotFound,
    RuntimeFailure,
    CredentialsRequired,
    CredentialFailure,
    PlanFailure,
    FsckFailure,
    GarbageCollectionFailure,
    WriterRemovalFailure,
    SynchronizationFailure,
    RecoveryFailure
};

// Error returned by the application.
struct Error {
    Operation operation = Operation::Sync;
    ErrorCode code = ErrorCode::RuntimeFailure;
    std::string detail;
    std::optional<RuntimeSummary> runtime;
    std::optional<SyncStage> stage = std::nullopt;
    // Present when garbage collection failed after acquiring execution context
    // sufficient to report candidate and cleanup diagnostics.
    std::optional<GarbageCollectFailure> garbage_collection;
};

} // namespace kasumi::application

#endif
