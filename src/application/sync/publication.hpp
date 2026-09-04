#ifndef KASUMI_APPLICATION_SYNC_PUBLICATION_HPP
#define KASUMI_APPLICATION_SYNC_PUBLICATION_HPP

#include "application/history_storage/history_storage.hpp"
#include "application/history_storage/publication.hpp"
#include "core/history.hpp"
#include "crypto/file_crypto.hpp"
#include "transport/transport.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace kasumi::application::sync::publication {

// Failure categories when publishing history.
enum class ErrorCode {
    InvalidInput,
    InvalidCommit,
    HistoryStorageFailure,
    ObservationFailure,
    TransportFailure,
    WorkspaceFailure,
    LimitExceeded,
    VerificationFailure,
};

// Detailed publication failure.
struct Error {
    ErrorCode code = ErrorCode::InvalidInput;
    std::string detail;
};

// Commit and identifier used in publication.
struct PreparedCommit {
    history::Commit commit;
    std::string commit_id;
};

// Count of removed markers.
struct PruneResult {
    std::size_t removed_markers = 0;
};

// Types used by publication stages.
using PrepareResult = std::expected<PreparedCommit, Error>;
using PublishResult = std::expected<history_storage::PublishedCommit, Error>;
using PublishObjectResult =
    std::expected<history_storage::PublishedCommitObject, Error>;
using PublishHeadResult =
    std::expected<history_storage::PublishedHeadMarker, Error>;
using HeadMarkerState = history_storage::HeadMarkerState;
using HeadMarkerInspection = std::expected<HeadMarkerState, Error>;
using ReachableResult =
    std::expected<std::optional<history::LoadedCommit>, Error>;
using PruneMarkersResult = std::expected<PruneResult, Error>;

// Assembles and validates the next history commit.
PrepareResult
prepare_commit(Snapshot tree,
               bool history_present,
               std::uint64_t observed_height,
               std::span<const std::string> logical_heads,
               std::int64_t created_at,
               std::span<const std::uint8_t, crypto::KEY_SIZE> key);

// Publishes only the encrypted commit object.
PublishObjectResult
publish_commit_object(transport::Transport& storage,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                      const PreparedCommit& prepared,
                      const std::filesystem::path& workspace_root);

// Confirms integrity of the published object.
std::expected<void, Error>
verify_commit_object(transport::Transport& storage,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                     const PreparedCommit& prepared,
                     const history_storage::HeadReference& reference,
                     const std::filesystem::path& workspace_root,
                     std::string_view local_physical_hash = {});

// Publishes the marker that makes the commit visible.
PublishHeadResult
publish_head_marker(transport::Transport& storage,
                    const history_storage::HeadReference& reference,
                    const std::filesystem::path& workspace_root);

// Confirms integrity of the published marker.
std::expected<void, Error>
verify_head_marker(transport::Transport& storage,
                   const history_storage::HeadReference& reference,
                   const std::filesystem::path& workspace_root,
                   std::string_view local_physical_hash = {});

// Inspects the current state of a marker.
HeadMarkerInspection
inspect_head_marker(transport::Transport& storage,
                    const history_storage::HeadReference& reference,
                    const std::filesystem::path& workspace_root);

// Publishes the commit object and its marker.
PublishResult
publish_commit(transport::Transport& storage,
               std::span<const std::uint8_t, crypto::KEY_SIZE> key,
               const PreparedCommit& prepared,
               const std::filesystem::path& workspace_root);

// Finds and validates a reachable commit by identifier.
ReachableResult
find_reachable_commit(transport::Transport& storage,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                      const std::filesystem::path& workspace_root,
                      std::string_view commit_id);

// Prunes markers that now point to ancestors.
PruneMarkersResult prune_current_ancestral_markers(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const std::filesystem::path& workspace_root);

// Prunes only markers present in the plan's observation.
PruneMarkersResult prune_observed_parent_markers(
    transport::Transport& storage,
    std::span<const std::string> parent_ids,
    std::span<const std::string> observed_marker_identifiers);

// Queries remote head commit identifiers from storage.
using history_storage::list_remote_head_commit_ids;

} // namespace kasumi::application::sync::publication

#endif
