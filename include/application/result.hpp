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
    MoveLocal,
    Download,
    DeleteLocal,
    DeleteLocalDirectory,
    DeleteRemote,
    DeleteRemoteDirectory,
    CopyLocal,
    DeleteIgnoredLocalFile,
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
    std::uint32_t repaired = 0;

    std::uint64_t upload_bytes = 0;
    std::uint64_t download_bytes = 0;

    bool published = false;
    std::uint32_t pending = 0;
    std::vector<std::filesystem::path> pending_paths;
    bool partial = false;
    std::optional<std::chrono::nanoseconds> duration = std::nullopt;
    std::uint64_t wire_upload_bytes = 0;
    std::uint64_t wire_download_bytes = 0;
    std::uint64_t local_delta_reused_bytes = 0;
    std::uint64_t physical_objects_uploaded = 0;
    std::uint64_t physical_objects_downloaded = 0;
};

// Structural inventory summary collected after an explicitly audited Sync.
struct InventoryAuditReport {
    std::size_t referenced_content = 0;
    std::size_t present_content = 0;
    std::size_t missing_content = 0;
    std::size_t orphan_content = 0;
    std::size_t unknown_objects = 0;
};

// Summary of a completed integrity check.
struct FsckCompleted {
    std::size_t checked_objects = 0;
    std::optional<std::uint64_t> checked_plaintext_bytes = std::nullopt;
    std::uint64_t wire_download_bytes = 0;
    std::uint64_t physical_objects_downloaded = 0;
    std::uint64_t files_reassembled = 0;
};

// High-level stages for garbage collection.
enum class GarbageCollectStage {
    Preparing,
    Analyzing,
    Applying,
    Finalizing,
};

// NotAttempted means no REMOVE call; errors after a call remain Uncertain
// because transport error categories do not guarantee absence of remote
// effects.
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
    bool dry_run = false;
    std::size_t candidate_content_objects = 0;
    std::size_t candidate_commit_variants = 0;
    std::size_t candidate_activities = 0;
    std::size_t removed_objects = 0;
    std::chrono::nanoseconds removal_elapsed{};
};

// Result of resolving unavailable pending materializations as logical
// deletions.
struct ResolveMissingCompleted {
    std::size_t resolved_count = 0;
    std::vector<std::string> resolved_paths;
    bool published = false;
    bool dry_run = false;
};

struct ManualWriterRemovalCompleted {
    std::string identifier;
};

enum class BarrierRemovalOutcome : std::uint8_t {
    Removed,
    AlreadyAbsent,
};

struct ManualBarrierRemovalCompleted {
    std::string identifier;
    BarrierRemovalOutcome outcome = BarrierRemovalOutcome::Removed;
    std::size_t active_writers_count = 0;
};

// Stage of the manual barrier removal operation.
enum class BarrierRemovalStage : std::uint8_t {
    CheckingPresence,
    DownloadingPayload,
    ValidatingPayload,
    CheckingWriters,
    VerifyingPhysicalIdentity,
    Removing,
    ConfirmingAbsence,
};

// NotAttempted means no REMOVE call; Confirmed requires verified absence.
// An attempted REMOVE with an unproven outcome remains Uncertain.
enum class BarrierRemovalMutationState : std::uint8_t {
    NotAttempted,
    Confirmed,
    Uncertain,
};

// Diagnostic context for a barrier-removal failure.
struct BarrierRemovalFailure {
    std::string barrier_identifier;
    BarrierRemovalStage stage = BarrierRemovalStage::CheckingPresence;
    BarrierRemovalMutationState mutation_state =
        BarrierRemovalMutationState::NotAttempted;
    std::optional<transport::Error> transport_error;
};

// Summary of a completed Micro-Pack repack execution or dry-run.
struct RepackCompleted {
    bool dry_run = false;
    bool actionable = false;
    bool published = false;
    std::size_t live_small_blobs = 0;
    std::size_t existing_packs = 0;
    std::size_t healthy_packs_kept = 0;
    std::size_t dirty_packs_detected = 0;
    std::size_t loose_small_blobs_detected = 0;
    std::size_t source_loose_blobs = 0;
    std::size_t source_clean_packs = 0;
    std::size_t source_dirty_packs = 0;
    std::size_t new_packs = 0;
    std::size_t repacked_blobs = 0;
    std::uint64_t repacked_plaintext_bytes = 0;
    std::string published_commit_id;
    std::uint64_t published_height = 0;
    std::size_t pruned_markers = 0;
    std::uint64_t wire_upload_bytes = 0;
    std::uint64_t physical_objects_uploaded = 0;
    std::chrono::nanoseconds duration{};
};

// Possible payload variants for a successful response.
using ResponseData = std::variant<SyncCompleted,
                                  PlanReport,
                                  FsckCompleted,
                                  GarbageCollectCompleted,
                                  ResolveMissingCompleted,
                                  ManualWriterRemovalCompleted,
                                  ManualBarrierRemovalCompleted,
                                  RepackCompleted>;

// Successful operation response.
struct Response {
    Operation operation = Operation::Sync;
    // Resolved runtime paths, when available.
    std::optional<RuntimeSummary> runtime;
    // Payload variant corresponding to operation.
    ResponseData data;
    std::optional<InventoryAuditReport> inventory_audit;
    // Set when a remote operational activity record could not be published
    // after the main operation completed.
    std::optional<std::string> activity_publish_warning;
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
    BarrierRemovalFailure,
    SynchronizationFailure,
    RecoveryFailure,
    InventoryAuditFailure,
    RepackFailure
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
    // Present when manual barrier removal failed.
    std::optional<BarrierRemovalFailure> barrier_removal;
    // Sync succeeded before a subsequent inventory audit failed.
    std::optional<SyncCompleted> sync_completed;
    bool lock_busy = false;
    bool insufficient_disk_space = false;
};

} // namespace kasumi::application

#endif
