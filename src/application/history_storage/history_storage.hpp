#ifndef KASUMI_APPLICATION_HISTORY_STORAGE_HISTORY_STORAGE_HPP
#define KASUMI_APPLICATION_HISTORY_STORAGE_HISTORY_STORAGE_HPP

#include "application/history_storage/epoch.hpp"
#include "core/history.hpp"
#include "crypto/file_crypto.hpp"
#include "transport/transport.hpp"

#include <compare>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <tuple>
#include <vector>

namespace kasumi::application::history_storage {

// Binds a canonical commit to its published encrypted variant.
struct HeadReference {
    // BLAKE3 of the canonical commit bytes.
    std::string commit_id;
    // BLAKE3 of the encrypted object.
    std::string ciphertext_id;
};

// Compares the two identifiers.
inline bool operator==(const HeadReference& left,
                       const HeadReference& right) noexcept {
    return std::tie(left.commit_id, left.ciphertext_id) ==
           std::tie(right.commit_id, right.ciphertext_id);
}

// Orders by commit, then by encrypted variant.
inline std::strong_ordering operator<=>(const HeadReference& left,
                                        const HeadReference& right) noexcept {
    return std::tie(left.commit_id, left.ciphertext_id) <=>
           std::tie(right.commit_id, right.ciphertext_id);
}

// Validates both hexadecimal identifiers.
bool valid(const HeadReference& reference) noexcept;

// Builds the remote identifier for a marker.
std::string marker_object(const HeadReference& reference);

// Extracts a reference from a marker identifier.
std::optional<HeadReference> parse_marker_object(std::string_view identifier);

// Possible failures in history storage.
enum class ErrorCode {
    InvalidInput,
    InvalidIdentifier,
    InvalidMarker,
    InvalidCommit,
    InvalidCiphertext,
    CryptoFailure,
    TransportFailure,
    MissingCommit,
    LimitExceeded,
    VerificationFailure,
    InconsistentInventory,
    WorkspaceFailure,
};

// Failure produced by history storage.
struct Error {
    ErrorCode code = ErrorCode::InvalidInput;
    std::string detail;
};

// Result of marker encoding.
using MarkerResult = std::expected<std::vector<std::uint8_t>, Error>;

// Encodes a reference into the canonical marker format.
MarkerResult encode_marker(const HeadReference& reference);
// Decodes and validates a remote marker.
std::expected<HeadReference, Error>
decode_marker(std::span<const std::uint8_t> bytes);

// Published commit and its encrypted variant.
struct PublishedCommit {
    HeadReference head;
    // Indicates reuse of an already valid variant.
    bool reused_existing_ciphertext = false;
};

// Count of removed markers.
struct RemovedMarkers {
    std::size_t removed = 0;
};

// Result of marker removal.
using RemoveMarkersResult = std::expected<RemovedMarkers, Error>;

// Validated history loaded from storage.
struct LoadedHistory {
    std::vector<history::LoadedCommit> commits;
    // Physical variants authenticated during this load.
    std::vector<HeadReference> authenticated_commit_variants;
    std::vector<std::string> marked_heads;
    // Physical identifiers of valid markers.
    std::vector<std::string> marked_head_identifiers;
    // Authenticated frontier used to terminate traversal.
    std::vector<std::string> trusted_anchor_ids;
    // Authenticated remote Epoch accepted during load.
    std::optional<epoch::VerifiedEpoch> epoch;
};

enum class PhysicalCommitVariantState : std::uint8_t {
    InvalidCiphertext,
    InvalidCommit,
    Valid,
};

struct PhysicalCommitVariant {
    HeadReference reference;
    std::string identifier;
    PhysicalCommitVariantState state =
        PhysicalCommitVariantState::InvalidCiphertext;
};

using InspectCommitVariantsResult =
    std::expected<std::vector<PhysicalCommitVariant>, Error>;

// Lists and authenticates only the physical variants of the selected commit.
InspectCommitVariantsResult inspect_commit_variants(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    std::string_view commit_id,
    const std::filesystem::path& workspace_root,
    std::optional<HeadReference> authenticated_variant = std::nullopt);

// Validated local anchor to shorten history reading.
struct KnownHistoryAnchor {
    std::string commit_id;
    std::uint64_t height = 0;
    Snapshot tree;
};

// Local trust used to detect rollback and, without a remote Epoch, shorten
// traversal via an already validated base.
struct KnownHistoryFrontier {
    std::vector<KnownHistoryAnchor> anchors;
    std::optional<epoch::Reference> accepted_epoch;
};

// Result of publishing a commit.
using PublishResult = std::expected<PublishedCommit, Error>;
// Result of loading history.
using LoadResult = std::expected<LoadedHistory, Error>;

// Publishes, verifies, and marks a commit as head.
PublishResult
publish_commit(transport::Transport& storage,
               std::span<const std::uint8_t, crypto::KEY_SIZE> key,
               const history::Commit& commit,
               const std::filesystem::path& workspace_root);

// Loads and validates all remote history.
LoadResult load_history(transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        const std::filesystem::path& workspace_root);

// Loads from an already observed listing.
LoadResult load_history(transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        const std::filesystem::path& workspace_root,
                        std::span<const std::string> identifiers);

// Loads using a validated local anchor.
LoadResult load_history(transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        const std::filesystem::path& workspace_root,
                        const KnownHistoryFrontier& frontier);

// Loads heads and discovers ancestors on demand.
LoadResult load_history_scoped(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const std::filesystem::path& workspace_root,
    const KnownHistoryFrontier* frontier = nullptr,
    std::span<const std::string> trusted_marker_identifiers = {});

// Combines the observed listing with a local anchor.
LoadResult load_history(transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        const std::filesystem::path& workspace_root,
                        std::span<const std::string> identifiers,
                        const KnownHistoryFrontier& frontier);

// Removes all marker variants for the given commits.
RemoveMarkersResult
remove_marker_variants(transport::Transport& storage,
                       std::span<const std::string> commit_ids);

// Removes variants using an already observed listing.
RemoveMarkersResult
remove_marker_variants(transport::Transport& storage,
                       std::span<const std::string> commit_ids,
                       std::span<const std::string> identifiers);

} // namespace kasumi::application::history_storage

#endif
