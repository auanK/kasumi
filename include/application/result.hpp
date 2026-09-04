#ifndef KASUMI_APPLICATION_RESULT_HPP
#define KASUMI_APPLICATION_RESULT_HPP

#include "application/request.hpp"

#include <array>
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
};

// Indicates completed synchronization.
struct SyncCompleted {};

// Indicates completed integrity check.
struct FsckCompleted {};

// Result of completed recoverable garbage collection.
struct GarbageCollectCompleted {
    std::size_t candidate_objects = 0;
    std::size_t quarantined_objects = 0;
    std::size_t restored_objects = 0;
    std::size_t purged_objects = 0;
    bool analysis_only = false;
};

// Possible payload variants for a successful response.
using ResponseData = std::
    variant<SyncCompleted, PlanReport, FsckCompleted, GarbageCollectCompleted>;

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
    SynchronizationFailure
};

// Error returned by the application.
struct Error {
    Operation operation = Operation::Sync;
    ErrorCode code = ErrorCode::RuntimeFailure;
    std::string detail;
    std::optional<RuntimeSummary> runtime;
};

} // namespace kasumi::application

#endif
