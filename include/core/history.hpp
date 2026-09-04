#ifndef KASUMI_CORE_HISTORY_HPP
#define KASUMI_CORE_HISTORY_HPP

#include "core/hasher.hpp"
#include "core/node.hpp"

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::history {

// Defensive limits for untrusted remote history.
inline constexpr std::size_t maximum_parent_count = 32;
inline constexpr std::size_t maximum_loaded_commit_count = 4096;
inline constexpr std::size_t maximum_marked_head_count = 64;
inline constexpr std::size_t maximum_graph_depth = 4096;
inline constexpr std::uint64_t maximum_commit_plaintext_size =
    64ULL * 1024ULL * 1024ULL;

// Failure categories when validating, encoding, or resolving history.
enum class ErrorCode {
    InvalidCommit,
    InvalidCommitId,
    InvalidParent,
    InvalidSnapshot,
    InvalidEncoding,
    UnsupportedVersion,
    DuplicateCommit,
    MissingParent,
    Cycle,
    HeightMismatch,
    InvalidHead,
    NoCommonAncestor,
    // More than one common ancestor base at maximum height.
    AmbiguousMergeBase,
    // Merge would produce a structurally invalid snapshot.
    UnsafeMerge,
    LimitExceeded,
};

// Error produced by history operations.
struct Error {
    // Failure category.
    ErrorCode code = ErrorCode::InvalidCommit;
    // Human-readable failure description.
    std::string detail;
};

// Versioned state with its position in the history DAG.
struct Commit {
    // Height in the DAG; ordinary commits use max parent height plus one.
    std::uint64_t height = 0;
    // Creation timestamp in Unix seconds.
    std::int64_t created_at = 0;
    // Canonical IDs of direct parents, sorted without duplicates.
    std::vector<std::string> parents;
    // Complete snapshot published by the commit.
    Snapshot tree;
};

// Commit associated with the ID used by the graph.
struct LoadedCommit {
    // Canonical commit ID.
    std::string id;
    // Decoded commit payload.
    Commit commit;
};

// Resulting state from validating and merging logical heads.
struct Resolution {
    // Resolved or merged snapshot.
    Snapshot tree;
    // Maximum height among resolved heads.
    std::uint64_t height = 0;
    // Marked heads that are not ancestors of another head.
    std::vector<std::string> heads;
    // Indicates that merge preserved conflicting versions.
    bool has_conflicts = false;
};

// Result of creating or decoding a commit.
using CommitResult = std::expected<Commit, Error>;

// Result of canonical commit serialization.
using BytesResult = std::expected<std::vector<std::uint8_t>, Error>;

// String result produced by history operations.
using StringResult = std::expected<std::string, Error>;

// Result of history graph resolution.
using ResolutionResult = std::expected<Resolution, Error>;

// Accepts only canonical IDs with 64 lowercase hexadecimal digits.
bool valid_commit_id(std::string_view id) noexcept;

// Validates and constructs a commit, ordering its parents.
CommitResult make_commit(std::uint64_t height,
                         std::vector<std::string> parents,
                         Snapshot tree,
                         std::int64_t created_at = 0);

// Creates a parentless bootstrap commit to start history with tree.
CommitResult make_bootstrap(Snapshot tree, std::uint64_t height, std::int64_t created_at = 0);

// Creates an initial empty bootstrap commit at height zero.
CommitResult make_empty_bootstrap(std::int64_t created_at = 0);

// Serializes in canonical wire format.
BytesResult serialize(const Commit& commit);

// Decodes and validates untrusted data.
CommitResult deserialize(std::span<const std::uint8_t> bytes);

// Computes ID over canonical serialization of the commit.
StringResult compute_id(const Commit& commit);

// Computes ID directly over canonical bytes.
StringResult compute_id(std::span<const std::uint8_t> canonical_bytes);

// Validates the graph and resolves all heads.
ResolutionResult resolve(std::span<const LoadedCommit> commits,
                         std::span<const std::string> marked_heads);

// Resolves commits whose IDs have already been authenticated by cryptography.
ResolutionResult resolve_authenticated(
    std::span<const LoadedCommit> commits,
    std::span<const std::string> marked_heads);

// Resolves a truncated graph whose root is the trusted anchor.
ResolutionResult resolve_from_anchor(std::span<const LoadedCommit> commits,
                                     std::span<const std::string> marked_heads,
                                     std::string_view trusted_anchor_id);

// Resolves a truncated graph with externally authenticated IDs.
ResolutionResult resolve_from_anchor_authenticated(
    std::span<const LoadedCommit> commits,
    std::span<const std::string> marked_heads,
    std::string_view trusted_anchor_id);

// Resolves a truncated graph at one or more authenticated roots.
ResolutionResult resolve_from_frontier_authenticated(
    std::span<const LoadedCommit> commits,
    std::span<const std::string> marked_heads,
    std::span<const std::string> trusted_anchor_ids);

} // namespace kasumi::history

#endif
