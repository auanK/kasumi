#ifndef KASUMI_APPLICATION_INSPECTION_RESULT_HPP
#define KASUMI_APPLICATION_INSPECTION_RESULT_HPP

#include "application/inspection/request.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace kasumi::application {

struct RemoteHeadInfo {
    std::string commit_id;
    std::uint64_t height = 0;
    std::int64_t created_at = 0;
    std::vector<std::string> parent_ids;
    std::string root_hash;
    std::uint64_t file_count = 0;
    std::uint64_t directory_count = 0;
    std::uint64_t total_bytes = 0;
};

struct RemoteHeadsReport {
    bool history_present = false;
    std::uint64_t observed_height = 0;
    std::size_t physical_marker_count = 0;
    std::size_t ancestral_marker_count = 0;
    std::vector<RemoteHeadInfo> heads;
};

enum class RemoteTreeEntryType : std::uint8_t {
    File,
    Directory,
};

struct RemoteTreeEntry {
    std::string path;
    RemoteTreeEntryType type = RemoteTreeEntryType::File;
    std::string logical_hash;
    std::uint64_t size = 0;
};

struct RemoteTreeReport {
    bool history_present = false;
    std::string commit_id;
    std::uint64_t height = 0;
    std::int64_t created_at = 0;
    std::string root_hash;
    std::uint64_t total_bytes = 0;
    std::uint64_t file_count = 0;
    std::uint64_t directory_count = 0;
    std::vector<RemoteTreeEntry> entries;
};

struct RemoteCommitInfo {
    std::string commit_id;
    std::uint64_t height = 0;
    std::int64_t created_at = 0;
    std::vector<std::string> parent_ids;
    bool logical_head = false;
    bool physically_marked = false;
    bool ancestral_marked = false;
    std::string root_hash;
    std::uint64_t total_bytes = 0;
    std::uint64_t entry_count = 0;
};

struct RemoteCommitsReport {
    bool history_present = false;
    std::uint64_t observed_height = 0;
    std::vector<std::string> logical_head_ids;
    std::vector<RemoteCommitInfo> commits;
};

struct RemoteSummaryReport {
    bool history_present = false;
    std::uint64_t observed_height = 0;
    std::size_t reachable_commit_count = 0;
    std::size_t logical_head_count = 0;
    bool has_conflicts = false;
    std::size_t missing_content_count = 0;
    std::size_t orphan_content_count = 0;
    std::size_t active_writer_count = 0;
};

struct RemoteStatReport {
    std::uint64_t observed_height = 0;
    bool has_conflicts = false;
    std::string path;
    RemoteTreeEntryType type = RemoteTreeEntryType::File;
    std::string logical_hash;
    std::uint64_t size = 0;
    std::int64_t modified_at_unix_nanoseconds = 0;
};

enum class RemoteCommitVariantState : std::uint8_t {
    Valid,
    InvalidCiphertext,
    InvalidCommit,
};

struct RemoteCommitVariantInfo {
    std::string ciphertext_id;
    std::string object_identifier;
    RemoteCommitVariantState state = RemoteCommitVariantState::Valid;
};

struct RemoteCommitReport {
    RemoteCommitInfo commit;
    std::vector<RemoteCommitVariantInfo> variants;
};

struct RemoteFileReport {
    std::string path;
    std::string destination_path;
    std::string logical_hash;
    std::string content_id;
    std::uint64_t size = 0;
};

struct RemoteEpochAnchorInfo {
    std::string commit_id;
    std::uint64_t height = 0;
};

struct RemoteEpochInfo {
    std::string vault_id;
    std::uint64_t sequence = 0;
    std::string epoch_id;
    std::int64_t issued_at = 0;
    std::uint32_t min_history_depth = 0;
    std::uint32_t min_history_age_hours = 0;
    std::vector<RemoteEpochAnchorInfo> anchors;
    std::string previous_epoch_id;
    std::string next_epoch_id;
};

struct RemoteEpochsReport {
    std::vector<RemoteEpochInfo> epochs;
};

struct RemoteEpochReport {
    RemoteEpochInfo epoch;
};

enum class RemoteContentState : std::uint8_t {
    Present,
    Missing,
    Orphan,
    Valid,
    Invalid,
};

struct RemoteContentInfo {
    std::string content_id;
    std::string logical_hash;
    std::uint64_t size = 0;
    std::vector<std::string> paths;
    bool referenced = false;
    bool physically_present = false;
    bool current_tree = false;
    RemoteContentState state = RemoteContentState::Present;
};

struct RemoteContentsReport {
    bool audited = false;
    std::size_t referenced_count = 0;
    std::size_t physical_count = 0;
    std::size_t missing_count = 0;
    std::size_t orphan_count = 0;
    std::size_t valid_count = 0;
    std::size_t invalid_count = 0;
    std::vector<RemoteContentInfo> contents;
};

struct RemoteContentReport {
    RemoteContentInfo content;
};

enum class RemoteMarkerState : std::uint8_t {
    LogicalHead,
    Ancestral,
    InvalidPath,
    Missing,
    InvalidMarker,
    MissingCommit,
    InvalidCiphertext,
    InvalidCommit,
};

struct RemoteMarkerInfo {
    std::string object_identifier;
    std::string commit_id;
    std::string ciphertext_id;
    RemoteMarkerState state = RemoteMarkerState::InvalidPath;
};

struct RemoteMarkersReport {
    std::size_t logical_count = 0;
    std::size_t ancestral_count = 0;
    std::size_t invalid_count = 0;
    std::vector<RemoteMarkerInfo> markers;
};

enum class RemoteObjectCategory : std::uint8_t {
    Content,
    CommitVariant,
    HeadMarker,
    Epoch,
    Writer,
    Barrier,
    Quarantine,
    RetentionMetadata,
    Protocol,
    Unknown,
};

struct RemoteObjectInfo {
    std::string identifier;
    RemoteObjectCategory category = RemoteObjectCategory::Unknown;
    bool structurally_valid = false;
    std::string relation;
};

struct RemoteObjectsReport {
    std::size_t unknown_count = 0;
    std::vector<RemoteObjectInfo> objects;
};

enum class RemoteOrphanKind : std::uint8_t {
    Commit,
    CommitVariant,
    RedundantVariant,
    InvalidVariant,
    Content,
    ProtectedEpoch,
    Unknown,
};

struct RemoteOrphanInfo {
    std::string identifier;
    RemoteOrphanKind kind = RemoteOrphanKind::Unknown;
    bool removal_candidate = false;
};

struct RemoteOrphansReport {
    bool diagnostic_only = true;
    std::vector<RemoteOrphanInfo> objects;
};

struct RemoteQuarantineInfo {
    std::string original_identifier;
    std::string quarantine_identifier;
    std::string metadata_identifier;
    std::string category;
    bool metadata_authenticated = false;
    std::int64_t quarantined_at = 0;
    bool retention_elapsed = false;
};

struct RemoteQuarantineReport {
    std::vector<RemoteQuarantineInfo> entries;
};

enum class RemoteWriterState : std::uint8_t {
    Indeterminate,
    Invalid,
};

struct RemoteWriterInfo {
    std::string identifier;
    RemoteWriterState state = RemoteWriterState::Indeterminate;
};

struct RemoteWritersReport {
    bool barrier_present = false;
    bool maintenance_blocked = false;
    bool protocol_consistent = true;
    std::vector<RemoteWriterInfo> writers;
};

enum class RemoteHealthState : std::uint8_t {
    Healthy,
    Degraded,
    Critical,
};

struct RemoteHealthReport {
    RemoteHealthState state = RemoteHealthState::Healthy;
    std::size_t marker_count = 0;
    std::size_t reachable_commit_count = 0;
    std::size_t orphan_count = 0;
    std::size_t missing_content_count = 0;
    std::size_t invalid_content_count = 0;
    std::size_t writer_count = 0;
    std::size_t quarantine_count = 0;
    std::size_t unknown_object_count = 0;
    std::vector<std::string> reasons;
};

using InspectionPayload = std::variant<RemoteHeadsReport,
                                       RemoteTreeReport,
                                       RemoteCommitsReport,
                                       RemoteSummaryReport,
                                       RemoteStatReport,
                                       RemoteCommitReport,
                                       RemoteFileReport,
                                       RemoteEpochsReport,
                                       RemoteEpochReport,
                                       RemoteContentsReport,
                                       RemoteContentReport,
                                       RemoteMarkersReport,
                                       RemoteObjectsReport,
                                       RemoteOrphansReport,
                                       RemoteQuarantineReport,
                                       RemoteWritersReport,
                                       RemoteHealthReport>;

struct InspectionResponse {
    InspectionOperation operation = InspectionOperation::RemoteHeads;
    InspectionPayload payload = RemoteHeadsReport{};
};

enum class InspectionErrorCode {
    InvalidRequest,
    InvalidProfile,
    ProfileNotFound,
    RuntimeFailure,
    CredentialsRequired,
    CredentialFailure,
    RemoteObservationFailure,
    HeadSelectionRequired,
    RemoteHeadNotFound,
    RemotePathNotFound,
    RemoteCommitNotFound,
    RemotePathIsDirectory,
    RemoteContentNotFound,
    RemoteContentInvalid,
    DestinationFailure,
    RemoteEpochNotFound,
};

struct InspectionError {
    InspectionOperation operation = InspectionOperation::RemoteHeads;
    InspectionErrorCode code = InspectionErrorCode::RuntimeFailure;
    std::string detail;
    std::vector<std::string> candidate_ids;
};

} // namespace kasumi::application

#endif
