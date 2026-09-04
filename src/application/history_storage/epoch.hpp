#ifndef KASUMI_APPLICATION_HISTORY_STORAGE_EPOCH_HPP
#define KASUMI_APPLICATION_HISTORY_STORAGE_EPOCH_HPP

#include "core/history.hpp"
#include "crypto/key_derivation.hpp"
#include "transport/transport.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::application::history_storage::epoch {

inline constexpr std::uint32_t default_min_history_depth = 5;
inline constexpr std::uint32_t default_min_history_age_hours = 6;
inline constexpr std::size_t maximum_anchor_count = 64;
inline constexpr std::size_t maximum_encoded_size = 16U * 1024U;

struct RetentionPolicy {
    std::uint32_t min_history_depth = default_min_history_depth;
    std::uint32_t min_history_age_hours = default_min_history_age_hours;

    bool operator==(const RetentionPolicy&) const = default;
};

struct Anchor {
    std::string commit_id;
    std::uint64_t height = 0;

    bool operator==(const Anchor&) const = default;
};

struct Epoch {
    std::string vault_id;
    std::uint64_t sequence = 0;
    std::int64_t issued_at = 0;
    RetentionPolicy policy;
    std::vector<Anchor> anchors;
    std::string previous_epoch_id;

    bool operator==(const Epoch&) const = default;
};

struct Reference {
    std::uint64_t sequence = 0;
    std::string epoch_id;

    bool operator==(const Reference&) const = default;
};

struct SealedEpoch {
    Reference reference;
    std::vector<std::uint8_t> bytes;
};

struct VerifiedEpoch {
    Reference reference;
    Epoch value;

    bool operator==(const VerifiedEpoch&) const = default;
};

struct NoPrune {
    std::string reason;
    bool operator==(const NoPrune&) const = default;
};

struct EpochPlan {
    std::vector<Anchor> anchors;
    std::vector<std::string> prunable_commits;
    bool operator==(const EpochPlan&) const = default;
};

using PruneResult = std::expected<EpochPlan, NoPrune>;

PruneResult plan_pruning(std::span<const kasumi::history::LoadedCommit> commits,
                         const RetentionPolicy& policy);

enum class ErrorCode {
    InvalidInput,
    LimitExceeded,
    InvalidEncoding,
    UnsupportedVersion,
    AuthenticationFailure,
    Conflict,
    NotFound,
    TransportFailure,
    WorkspaceFailure,
    VerificationFailure,
};

struct Error {
    ErrorCode code = ErrorCode::InvalidInput;
    std::string detail;
};

using BytesResult = std::expected<std::vector<std::uint8_t>, Error>;
using LatestResult = std::expected<std::optional<VerifiedEpoch>, Error>;
using ChainResult = std::expected<std::vector<VerifiedEpoch>, Error>;

// Encodes canonical v1 content without cryptographic protection.
BytesResult encode(const Epoch& value);

// Decodes only canonical v1 content and rejects trailing bytes.
std::expected<Epoch, Error> decode(std::span<const std::uint8_t> bytes);

// Produces the confidential, authenticated envelope used by the immutable object.
std::expected<SealedEpoch, Error>
seal(const Epoch& value,
     std::span<const std::uint8_t, crypto::KEY_SIZE> master_key);

// Authenticates, decrypts, and confirms that content and naming match.
std::expected<VerifiedEpoch, Error>
open(std::span<const std::uint8_t> bytes,
     const Reference& reference,
     std::span<const std::uint8_t, crypto::KEY_SIZE> master_key);

// history/epochs/v1/<fixed-width decimal sequence>-<epoch ID>.epoch
std::expected<std::string, Error> object_identifier(const Reference& reference);
std::expected<Reference, Error>
parse_object_identifier(std::string_view identifier);

// Validates a contiguous authenticated chain, rejects forks/gaps, and returns the
// latest Epoch.
std::expected<VerifiedEpoch, Error>
select_latest(std::span<const VerifiedEpoch> epochs);

// Publishes the immutable object at the identifier derived from its content.
std::expected<void, Error> publish(transport::Transport& storage,
                                   const SealedEpoch& sealed,
                                   const std::filesystem::path& workspace_root);

// Downloads, authenticates, and compares the remote object against the expected Epoch.
std::expected<void, Error>
verify(transport::Transport& storage,
       const Epoch& expected,
       const Reference& reference,
       std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
       const std::filesystem::path& workspace_root);

// Discovers, authenticates, and deterministically selects the latest remote Epoch.
LatestResult
load_latest(transport::Transport& storage,
            std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
            const std::filesystem::path& workspace_root);

// Reuses an already observed complete listing.
LatestResult
load_latest(transport::Transport& storage,
            std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
            const std::filesystem::path& workspace_root,
            std::span<const std::string> identifiers);

// Discovers the latest Epoch and authenticates its ancestry up to the
// exact checkpoint, or the entire chain when there is no checkpoint.
LatestResult
load_latest(transport::Transport& storage,
            std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
            const std::filesystem::path& workspace_root,
            std::optional<Reference> trusted_ancestor);

// Incremental variant using an already observed listing.
LatestResult
load_latest(transport::Transport& storage,
            std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
            const std::filesystem::path& workspace_root,
            std::span<const std::string> identifiers,
            std::optional<Reference> trusted_ancestor);

// Discovers and authenticates the full remote chain, from genesis to the current Epoch.
ChainResult
load_chain(transport::Transport& storage,
           std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
           const std::filesystem::path& workspace_root);

ChainResult
load_chain(transport::Transport& storage,
           std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
           const std::filesystem::path& workspace_root,
           std::span<const std::string> identifiers);

// Discovers and authenticates exactly the Epoch identified by the journal.
LatestResult
load_by_id(transport::Transport& storage,
           std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
           const std::filesystem::path& workspace_root,
           std::string_view epoch_id);

} // namespace kasumi::application::history_storage::epoch

#endif
