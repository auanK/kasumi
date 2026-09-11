#ifndef KASUMI_RECONCILIATION_TYPES_HPP
#define KASUMI_RECONCILIATION_TYPES_HPP

#include "core/hasher.hpp"
#include "core/history.hpp"
#include "core/ignore.hpp"
#include "core/node.hpp"
#include "core/operation.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace kasumi::reconciliation {

// Failure categories when reconciling local, base, and remote states.
enum class ErrorCode {
    InvalidLocalTree,
    InvalidExecutedTree,
    InvalidBaseTree,
    InvalidStorageTree,
    // Persisted base does not match the commit identifying it.
    InvalidLocalBaseState,
    StorageGenerationOverflow,
    // Local base is no longer reachable in remote history.
    StorageHistoryRegression,
    // Persisted local base exists, but no remote history found.
    MissingStorageHistory,
    // Plan or candidate tree violates safety invariants.
    UnsafePlan
};

// Reconciliation error, including involved paths when applicable.
struct Error {
    // Failure category.
    ErrorCode code = ErrorCode::InvalidLocalTree;

    // Human-readable failure description.
    std::string detail;

    // Paths associated with the failure.
    std::vector<std::filesystem::path> paths;
};

// Authenticated policy snapshot observed in the remote Epoch.
struct EpochRetentionPolicy {
    std::uint32_t min_history_depth = 0;
    std::uint32_t min_history_age_hours = 0;

    bool operator==(const EpochRetentionPolicy&) const = default;
};

// Authenticated frontier anchor observed in the remote Epoch.
struct EpochAnchor {
    std::string commit_id;
    std::uint64_t height = 0;

    bool operator==(const EpochAnchor&) const = default;
};

// Remote state observed and validated prior to reconciliation.
struct StorageState {
    // Tree resulting from remote history resolution.
    Snapshot tree;

    // IDs of physical objects observed in storage.
    std::unordered_set<std::string> object_identifiers;

    // Commits required to validate and resolve observed heads.
    std::vector<history::LoadedCommit> reachable_commits;
    // IDs of reachable commits.
    std::vector<std::string> reachable_commit_ids;
    // Commit IDs extracted from valid markers.
    std::vector<std::string> marked_heads;
    // Physical identifiers of valid markers.
    std::vector<std::string> marked_head_identifiers;
    // Marked heads that are not ancestors of another head.
    std::vector<std::string> logical_heads;
    // Ancestral marked heads eligible for pruning.
    std::vector<std::string> ancestral_marked_heads;

    // Authenticated remote Epoch accepted during observation.
    std::string epoch_vault_id;
    std::string epoch_id;
    std::uint64_t epoch_sequence = 0;
    std::optional<EpochRetentionPolicy> epoch_policy;
    std::vector<EpochAnchor> epoch_anchors;

    // Maximum height among resolved logical heads.
    std::uint64_t generation = 0;

    // Indicates that valid remote history was observed.
    bool history_present = false;
    // Indicates conflicts preserved when resolving multiple heads.
    bool history_has_conflicts = false;
};

// Immutable inputs used to compute a reconciliation.
struct Input {
    // Current snapshot of the local directory.
    Snapshot local_tree;

    // Last shared tree persisted locally.
    Snapshot base_tree;

    // ID of the persisted local base.
    std::string base_commit_id;
    // Ciphertext identifier corresponding to the base.
    std::string base_ciphertext_id;
    // Indicates that base_tree, base_commit_id, and local_generation are valid.
    bool base_state_present = false;

    // Remote state observed for this execution.
    StorageState storage;

    // Height of the persisted local base.
    std::uint64_t local_generation = 0;

    // Also audits physical presence of objects.
    bool audit_storage_objects = false;

    // Ignore rules observed for local synchronization.
    ignore::IgnoreList ignore_list;
};

// Computed plan and decisions required to execute it safely.
struct Result {
    // Ordered operations that reconcile observed states.
    SyncPlan plan;

    // Objects referenced by remote but physically missing.
    HashSet missing_objects{0, hash_key};

    // Remote rows whose physical objects are missing.
    std::vector<NodeRow> pending_storage_rows;

    // Missing remote paths without a compatible local source.
    std::vector<std::filesystem::path> unrecoverable_paths;

    // Remote generation used in computation.
    std::uint64_t observed_storage_generation = 0;

    // Generation that execution must produce or preserve.
    std::uint64_t target_generation = 0;

    // Indicates bootstrap because no remote history was observed.
    bool recovering_missing_history = false;

    // Indicates conflicts in history or computed plan.
    bool has_conflicts = false;

    // Indicates that the plan mutates the local file system.
    bool requires_local_mutation = false;

    // Indicates that missing physical objects can be republished.
    bool requires_storage_repair = false;

    // Predicted shared tree after applying logical plan.
    Snapshot candidate_shared_tree;

    // Indicates difference between candidate tree and observed remote tree.
    bool shared_tree_changed = false;

    // Indicates that execution must publish a new commit.
    bool requires_publication = false;

    // Indicates that persisted local base must be updated.
    bool requires_state_commit = false;
};

// Result of reconciliation computation.
using ReconcileResult = std::expected<Result, Error>;

} // namespace kasumi::reconciliation

#endif
