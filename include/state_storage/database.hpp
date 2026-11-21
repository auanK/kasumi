#ifndef KASUMI_STATE_STORAGE_DATABASE_HPP
#define KASUMI_STATE_STORAGE_DATABASE_HPP

#include "core/history.hpp"
#include "core/node.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace kasumi::state_storage {

inline constexpr std::size_t max_local_execution_history = 50;
inline constexpr std::size_t max_cached_remote_activity = 256;

// Persisted synchronized state for a profile.
struct StoredState {
    Snapshot tree;
    std::uint64_t height = 0;
    std::string commit_id;
    std::string ciphertext_id;
    // Latest Epoch certificate accepted locally.
    std::string epoch_id;
    std::uint64_t epoch_sequence = 0;
    // Logical files accepted but not yet materialized locally.
    std::vector<NodeRow> pending_materializations;
    // Physical packing/chunking layout persisted with the accepted commit.
    history::StorageManifest storage_manifest;
};

// Persisted entry for safe reuse of the local hash.
struct FileCacheRow {
    std::string path;
    Hash hash{};
    std::uint64_t size = 0;
    std::int64_t mtime_nanoseconds = 0;
    std::uint64_t volume = 0;
    std::uint64_t file_low = 0;
    std::uint64_t file_high = 0;

    bool operator==(const FileCacheRow&) const = default;
};

enum class LocalOperationKind : std::uint8_t {
    Sync = 1,
    Repack = 2,
    ResolveMissing = 3,
    Fsck = 4,
    GarbageCollect = 5,
    RemoveWriter = 6,
    RemoveBarrier = 7,
};

enum class LocalExecutionStatus : std::uint8_t {
    InProgress = 0,
    Succeeded = 1,
    SucceededNoChanges = 2,
    SucceededDownloadedOnly = 3,
    Partial = 4,
    IssuesFound = 5,
    Blocked = 6,
    Cancelled = 7,
    Failed = 8,
    Uncertain = 9,
};

enum class RemotePublishState : std::uint8_t {
    NotApplicable = 0,
    Published = 1,
    Pending = 2,
};

struct LocalExecutionRecord {
    std::string execution_id;
    LocalOperationKind operation = LocalOperationKind::Sync;
    std::string machine_id_hex;
    std::string machine_name;
    std::int64_t started_at = 0;
    std::optional<std::int64_t> finished_at;
    std::uint64_t duration_ms = 0;
    LocalExecutionStatus status = LocalExecutionStatus::InProgress;
    bool recovered = false;
    std::string stage;
    std::string detail;
    std::string commit_id;
    std::uint64_t summary_a = 0;
    std::uint64_t summary_b = 0;
    std::uint64_t summary_c = 0;
    std::uint64_t summary_bytes = 0;
    std::uint32_t flags = 0;
    RemotePublishState remote_publish_state =
        RemotePublishState::NotApplicable;

    bool operator==(const LocalExecutionRecord&) const = default;
};

struct AcceptedCommitMeta {
    std::string commit_id;
    std::uint64_t height = 0;
    std::int64_t created_at = 0;
    history::CommitOriginOperation origin_operation =
        history::CommitOriginOperation::Unknown;
    std::string machine_id_hex;
    std::string machine_name;
    std::int64_t accepted_at = 0;

    bool operator==(const AcceptedCommitMeta&) const = default;
};

struct CachedRemoteActivity {
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

    bool operator==(const CachedRemoteActivity&) const = default;
};

struct LocalActivitySnapshot {
    std::vector<LocalExecutionRecord> executions;
    std::optional<AcceptedCommitMeta> accepted_commit;
    std::vector<CachedRemoteActivity> cached_remote_activities;
};

// Creates or validates the canonical v2 database schema.
bool initialize(const std::filesystem::path& database_path);

// Validates an existing v2 database schema without modifying it.
bool validate(const std::filesystem::path& database_path);

// Loads the state or returns nullopt when it does not exist yet.
std::expected<std::optional<StoredState>, std::string>
load_state(const std::filesystem::path& database_path);

// Validates and replaces the state within a transaction; preserves Epoch if
// omitted.
bool save_state(const std::filesystem::path& database_path,
                const StoredState& state);

// Validates and replaces the state and accepted commit authorship atomically
// within a single transaction; preserves Epoch if omitted.
bool save_state(const std::filesystem::path& database_path,
                const StoredState& state,
                const AcceptedCommitMeta& accepted_meta);

// Loads the cache or returns empty when it does not exist yet.
std::expected<std::vector<FileCacheRow>, std::string>
load_file_cache(const std::filesystem::path& database_path);

// Synchronizes the persisted cache with the provided set.
bool save_file_cache_delta(const std::filesystem::path& database_path,
                           std::span<const FileCacheRow> rows);

// Records an InProgress execution row before remote/local mutations begin.
bool record_execution_start(const std::filesystem::path& database_path,
                            const LocalExecutionRecord& record);

// Finalizes an existing execution row (or inserts if absent) and prunes old
// finished rows beyond max_local_execution_history.
bool record_execution_finish(const std::filesystem::path& database_path,
                             const LocalExecutionRecord& record);

// Records a completed execution in a single SQLite transaction.
bool record_execution_complete(const std::filesystem::path& database_path,
                               const LocalExecutionRecord& record);

// Persists declared authorship and creation timestamp for the accepted commit.
bool save_accepted_commit_meta(const std::filesystem::path& database_path,
                               const AcceptedCommitMeta& meta);

// Replaces the cached snapshot of remote operational activity records.
bool save_remote_activity_cache(
    const std::filesystem::path& database_path,
    std::span<const CachedRemoteActivity> entries);

// Loads auxiliary local execution history, accepted commit authorship, and
// cached remote activities read-only (returns empty when DB is absent).
std::expected<LocalActivitySnapshot, std::string>
load_local_activity(const std::filesystem::path& database_path);

} // namespace kasumi::state_storage

#endif
