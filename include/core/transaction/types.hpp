#ifndef KASUMI_TRANSACTION_TYPES_HPP
#define KASUMI_TRANSACTION_TYPES_HPP

#include "../operation.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::transaction {

// Size of random transaction identifier in bytes.
inline constexpr std::size_t transaction_id_byte_count = 16;

// Hexadecimal length of transaction identifier.
inline constexpr std::size_t transaction_id_hex_size =
    transaction_id_byte_count * 2;

// Persisted phases of transactional execution.
enum class Phase : std::uint8_t {
    // Record created, preparation not yet complete.
    Started = 0,
    // Operations prepared and necessary backups created.
    FilesStaged = 1,
    // Plan mutations and transfers completed.
    LocalChangesApplied = 2,
    // Canonical commit created locally.
    CommitPrepared = 3,
    // Encrypted commit object uploaded.
    CommitUploaded = 4,
    // Remote commit object verified.
    CommitVerified = 5,
    // New head marker published.
    HeadPublished = 6,
    // Remote head marker verified.
    HeadVerified = 7,
    // Canonical genesis Epoch created locally.
    EpochPrepared = 8,
    // Remote genesis Epoch object uploaded.
    EpochUploaded = 9,
    // Remote genesis Epoch object verified.
    EpochVerified = 10,
    // New base persisted in local database.
    DatabaseCommitted = 11,
    // Markers processed; local artifacts pending cleanup.
    CleanupCompleted = 12
};

// Persisted stages of operation progress.
enum class OperationState : std::uint8_t {
    // Operation not yet prepared.
    Pending = 0,
    // Preconditions verified without effects applied.
    Prepared = 1,
    // State required for rollback preserved.
    BackupCreated = 2,
    // Operation effect completed.
    Applied = 3
};

// Elementary operation stored in transaction record.
using Operation = kasumi::Operation;

// Persisted progress of an operation.
struct OperationProgress {
    // Previous hash used to verify backup or resumption.
    std::string previous_hash;
    // Rollback slot; maximum marks operation without local mutation.
    std::uint32_t backup_slot = std::numeric_limits<std::uint32_t>::max();
    // Last durable stage completed for the operation.
    OperationState state = OperationState::Pending;
    // Indicates path existed prior to transaction.
    bool had_original = false;
};

// Persisted state for transaction recovery.
struct Record {
    // Hexadecimal ID of transaction and its temporary directory.
    std::string operation_id;
    // Last durable phase completed.
    Phase phase = Phase::Started;
    // Indicates whether execution must publish a new commit.
    bool publication_required = true;
    // Pinned logical head for non-publishing execution.
    std::string observed_head_id;
    // Local base height at transaction start.
    std::uint64_t local_generation = 0;
    // Observed remote height at transaction start.
    std::uint64_t storage_generation = 0;
    // Prepared commit ID for publication.
    std::string commit_id;
    // Physical ID of published encrypted commit.
    std::string ciphertext_id;
    // Canonical parent IDs of prepared commit.
    std::vector<std::string> parent_ids;
    // Physical identifier of marker associated with commit.
    std::string marker_id;
    // Stable vault identity created with genesis Epoch.
    std::string epoch_vault_id;
    // Authenticated ID of genesis Epoch.
    std::string epoch_id;
    // Canonical timestamp of genesis Epoch.
    std::int64_t epoch_issued_at = 0;
    // Authenticated policy used to seal prepared Epoch.
    std::uint32_t epoch_min_history_depth = 0;
    std::uint32_t epoch_min_history_age_hours = 0;
    // Immutable plan executed by transaction.
    SyncPlan plan;
    // Mapped 1:1 with plan.operations.
    std::vector<OperationProgress> progress;
};

// Indicates whether phase belongs to persisted format.
bool valid(Phase phase) noexcept;

// Indicates whether state belongs to persisted format.
bool valid(OperationState state) noexcept;

// Validates structural invariants of the record.
bool valid(const Record& record) noexcept;

// Accepts lowercase hexadecimal transaction ID of expected size.
bool valid_transaction_id(std::string_view value) noexcept;

// Validates inputs and constructs a record in Started phase.
std::expected<Record, std::string>
make_record(std::string transaction_id,
            std::uint64_t local_generation,
            std::uint64_t storage_generation,
            SyncPlan plan,
            bool publication_required = true,
            std::string observed_head_id = {});

} // namespace kasumi::transaction

#endif
