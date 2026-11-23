#ifndef KASUMI_APPLICATION_PROFILE_HPP
#define KASUMI_APPLICATION_PROFILE_HPP

#include "application/credentials.hpp"
#include "application/environment.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::application {

enum class KeyStorage {
    Vault,
    File,
    Memory,
};

// Configuration for a synchronization profile.
struct Profile {
    std::string name;
    // Local synchronized directory.
    std::filesystem::path local_dir;
    // Local or remote rclone destination.
    std::string remote_dir;
    // Retention policy.
    std::uint32_t min_history_depth = 5;
    std::uint32_t min_history_age_hours = 6;
    // Key storage mechanism.
    KeyStorage key_storage = KeyStorage::Vault;
};

std::string_view to_string(KeyStorage storage) noexcept;

// Possible failures in profile management.
enum class ProfileErrorCode {
    InvalidName,
    InvalidPath,
    AlreadyExists,
    NotFound,
    ConfigFailure,
    CredentialFailure,
    StorageFailure,
    LockFailure
};

// Error encountered while managing a profile.
struct ProfileError {
    ProfileErrorCode code = ProfileErrorCode::ConfigFailure;
    std::string detail;
};

enum class ProfileField {
    Name,
    LocalPath,
    RemotePath
};
std::expected<void, ProfileError>
validate_profile_field(ProfileField field, std::string_view value);

// Lists configured profiles.
std::expected<std::vector<Profile>, ProfileError>
list_profiles(const ExecutionEnvironment& environment);

// Creates the profile and persists its local key.
std::expected<void, ProfileError>
create_profile(const ExecutionEnvironment& environment,
               Profile profile,
               ProfileCredentials credentials);

// Updates profile directories and retention policy.
std::expected<void, ProfileError>
update_profile(const ExecutionEnvironment& environment, Profile profile);

// Derives or decodes credentials and saves them to the profile's key storage.
// Succeeds without rewriting when the stored key already matches. If a
// different valid key is already stored and allow_replace is false, fails with
// ProfileErrorCode::AlreadyExists without modifying the stored key.
std::expected<void, ProfileError>
set_profile_key(const ExecutionEnvironment& environment,
                std::string_view profile_name,
                ProfileCredentials credentials,
                bool allow_replace = false);

// Removes configuration, key, and state; preserves synchronized directory.
std::expected<void, ProfileError>
delete_profile(const ExecutionEnvironment& environment,
               std::string_view profile_name);

// Renames configuration and moves local key and state.
std::expected<void, ProfileError>
rename_profile(const ExecutionEnvironment& environment,
               std::string_view current_name,
               std::string_view new_name);

// Clones an existing profile configuration and cryptographic identity
// into a new profile with independent local state storage.
// Does not access remote storage, does not synchronize.
std::expected<void, ProfileError>
clone_profile(const ExecutionEnvironment& environment,
              std::string_view source_profile_name,
              std::string_view destination_profile_name);

// Local state of a profile based exclusively on local infrastructure and
// database evidence.
enum class ProfileLocalState {
    Initialized,
    Ready,
    Pending,
    Running,
    Problem
};

enum class ProfileLocalProblem {
    None,
    InvalidName,
    Paths,
    Directory,
    Key,
    Database,
    Lock,
    Sidecar,
    Journal,
    Workspace,
    Snapshot,
    Cleanup,
    Count
};

// Inspects the local state of a profile based exclusively on local evidence.
// Does not access remote storage, does not initialize SQLite, does not create
// files.
// If supplied, problem receives the first detected issue, or None on success.
ProfileLocalState
inspect_profile_local_state(const ExecutionEnvironment& environment,
                            std::string_view profile_name,
                            ProfileLocalProblem* problem = nullptr);

// Returns a canonical string representation for the profile local state.
std::string_view to_string(ProfileLocalState state) noexcept;

enum class ProfileOperationKind : std::uint8_t {
    Sync = 1,
    Fsck = 2,
    GarbageCollect = 3,
    Repack = 4,
    ResolveMissing = 5,
    RemoveWriter = 6,
    RemoveBarrier = 7,
};

// Returns a canonical CLI-aligned label for a recorded profile operation.
std::string_view to_string(ProfileOperationKind operation) noexcept;

enum class ProfileExecutionStatus : std::uint8_t {
    InProgress = 1,
    Succeeded = 2,
    SucceededNoChanges = 3,
    SucceededDownloadedOnly = 4,
    SucceededPartial = 5,
    IssuesFound = 6,
    Blocked = 7,
    Cancelled = 8,
    Failed = 9,
    Uncertain = 10,
    Interrupted = 11,
};

enum class ProfileRemotePublishState : std::uint8_t {
    NotApplicable = 0,
    Published = 1,
    Pending = 2,
};

inline constexpr std::uint32_t profile_execution_flag_audit_failed_after_sync =
    1U << 8;

struct ProfileExecutionSummary {
    std::string execution_id;
    ProfileOperationKind operation = ProfileOperationKind::Sync;
    std::string machine_id_hex;
    std::string machine_name;
    std::int64_t started_at = 0;
    std::optional<std::int64_t> finished_at;
    std::uint64_t duration_ms = 0;
    ProfileExecutionStatus status = ProfileExecutionStatus::Succeeded;
    bool recovered = false;
    std::string stage;
    std::string detail;
    std::string commit_id;
    std::uint64_t summary_a = 0;
    std::uint64_t summary_b = 0;
    std::uint64_t summary_c = 0;
    std::uint64_t summary_bytes = 0;
    std::uint32_t flags = 0;
    ProfileRemotePublishState remote_publish_state =
        ProfileRemotePublishState::NotApplicable;
};

struct ProfileCommitAuthorship {
    std::string commit_id;
    std::uint64_t height = 0;
    std::int64_t created_at = 0;
    std::uint8_t origin_operation = 0;
    std::string machine_id_hex;
    std::string machine_name;
    std::int64_t accepted_at = 0;
};

struct ProfileCachedRemoteActivity {
    std::string event_id;
    std::uint8_t operation = 0;
    std::uint8_t outcome = 0;
    std::string machine_id_hex;
    std::string machine_name;
    std::int64_t started_at = 0;
    std::int64_t finished_at = 0;
    std::uint64_t duration_ms = 0;
    std::uint64_t metric_primary = 0;
    std::uint64_t metric_secondary = 0;
    std::uint64_t metric_bytes = 0;
    std::uint32_t flags = 0;
    std::string stage;
    std::string detail;
    std::int64_t cached_at = 0;
};

struct ProfileActivityReport {
    bool database_present = false;
    std::optional<ProfileCommitAuthorship> accepted_commit;
    std::optional<ProfileExecutionSummary> last_attempt;
    std::optional<ProfileExecutionSummary> last_complete_sync;
    std::vector<ProfileExecutionSummary> recent_executions;
    std::vector<ProfileCachedRemoteActivity> cached_remote_activities;
};

// Inspects offline local traceability and cached remote activity for a
// profile without accessing remote storage, initializing SQLite, or
// creating lock files.
ProfileActivityReport
inspect_profile_activity(const ExecutionEnvironment& environment,
                         std::string_view profile_name);

// Returns the active operation label when activity shows an InProgress attempt.
std::optional<std::string_view>
active_profile_operation(const ProfileActivityReport& activity) noexcept;

struct DiagnosticsRcloneInfo {
    bool found = false;
    std::filesystem::path executable;
    std::string version;
    std::string minimum_version;
    bool meets_minimum = false;
    std::string detail;
};

struct ProfileDiagnostic {
    Profile profile;
    ProfileLocalState local_state = ProfileLocalState::Problem;
    ProfileLocalProblem local_problem = ProfileLocalProblem::None;
    bool local_dir_exists = false;
    bool local_dir_writable = false;
    std::optional<std::uint64_t> local_free_bytes;
    std::optional<std::uint64_t> local_capacity_bytes;
    bool uses_rclone = false;
    bool lock_active = false;
    bool journal_present = false;
    bool key_accessible = false;
    bool healthy = false;
    std::string detail;
    ProfileActivityReport activity;
};

struct DiagnosticsReport {
    std::string os_name;
    std::filesystem::path app_data_dir;
    std::filesystem::path config_path;
    bool config_exists = false;
    std::optional<std::uint64_t> app_data_free_bytes;
    DiagnosticsRcloneInfo rclone;
    std::vector<ProfileDiagnostic> profiles;
    bool overall_ok = true;
};

// Inspects local environment, rclone toolchain, and profile health without
// modifying state, exposing secrets, or contacting remote storage.
std::expected<DiagnosticsReport, ProfileError>
collect_diagnostics(const ExecutionEnvironment& environment,
                    std::string_view profile_name = {});

struct RcloneRemotesInfo {
    bool available = false;
    std::vector<std::string> remotes;
    std::string detail;
};

// Queries configured local rclone remote names without contacting remote
// storage.
RcloneRemotesInfo discover_rclone_remotes(
    const std::filesystem::path& forbidden_executable_root = {});

enum class ConflictOrigin : std::uint8_t {
    Local,
    Remote,
    BranchCommit,
};

struct LocalConflictArtifact {
    std::string path;
    ConflictOrigin origin = ConflictOrigin::Local;
    std::string origin_tag;
    std::uint64_t size = 0;
    std::int64_t modified_at = 0;
};

struct LocalConflictGroup {
    std::string canonical_path;
    bool canonical_exists = false;
    std::uint64_t canonical_size = 0;
    std::int64_t canonical_modified_at = 0;
    std::vector<LocalConflictArtifact> artifacts;
};

struct LocalConflictsReport {
    std::string profile_name;
    std::filesystem::path local_dir;
    std::size_t total_artifacts = 0;
    std::vector<LocalConflictGroup> groups;
};

// Scans a profile's synchronized folder read-only (respecting .kasumiignore
// and skipping symlinks) for preserved `.kasumiconflict_*` artifacts.
std::expected<LocalConflictsReport, ProfileError>
list_local_conflicts(const ExecutionEnvironment& environment,
                     std::string_view profile_name);

enum class ConflictResolutionChoice : std::uint8_t {
    KeepCanonical,
    KeepArtifact,
};

struct ResolveConflictRequest {
    std::string profile_name;
    std::string canonical_path;
    ConflictResolutionChoice choice = ConflictResolutionChoice::KeepCanonical;
    std::string artifact_selector;
    bool dry_run = false;
};

struct ResolveConflictReport {
    std::string profile_name;
    std::string canonical_path;
    ConflictResolutionChoice choice = ConflictResolutionChoice::KeepCanonical;
    std::optional<std::string> selected_artifact;
    bool dry_run = false;
    std::vector<std::string> removed_artifacts;
};

// Resolves one preserved conflict group by keeping either the canonical file or
// one named `.kasumiconflict_*` artifact, atomically promoting the chosen file
// before deleting any conflict artifacts in the group.
std::expected<ResolveConflictReport, ProfileError>
resolve_local_conflict(const ExecutionEnvironment& environment,
                       const ResolveConflictRequest& request);

} // namespace kasumi::application

#endif
