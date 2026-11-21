#ifndef KASUMI_APPLICATION_SYNC_PUBLICATION_HPP
#define KASUMI_APPLICATION_SYNC_PUBLICATION_HPP

#include "application/history_storage/history_storage.hpp"
#include "application/history_storage/publication.hpp"
#include "core/history.hpp"
#include "crypto/file_crypto.hpp"
#include "state_storage/database.hpp"
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

// Types used by publication stages (aliased to history_storage errors).
using ErrorCode = history_storage::ErrorCode;
using Error = history_storage::Error;

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
using history_storage::HeadMarkerInspection;
using history_storage::HeadMarkerState;
using history_storage::PublishHeadResult;
using history_storage::PublishObjectResult;
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
               std::span<const std::uint8_t, crypto::KEY_SIZE> key,
               history::StorageManifest storage = {},
               history::CommitAuthorship authorship = {});

// Builds an AcceptedCommitMeta record from a validated commit (unauthored
// commits yield CommitOriginOperation::Unknown and empty machine identity).
state_storage::AcceptedCommitMeta
make_accepted_commit_meta(std::string_view commit_id,
                          const history::Commit& commit);

// Publishes only the encrypted commit object.
PublishObjectResult
publish_commit_object(transport::Transport& storage,
                      const history_storage::RemoteLayout& layout,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                      const PreparedCommit& prepared,
                      const std::filesystem::path& workspace_root);
PublishObjectResult
publish_commit_object(transport::Transport& storage,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                      const PreparedCommit& prepared,
                      const std::filesystem::path& workspace_root);

// Confirms integrity of the published object.
std::expected<void, Error>
verify_commit_object(transport::Transport& storage,
                     const history_storage::RemoteLayout& layout,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                     const PreparedCommit& prepared,
                     const history_storage::HeadReference& reference,
                     const std::filesystem::path& workspace_root,
                     std::string_view local_physical_hash = {});
std::expected<void, Error>
verify_commit_object(transport::Transport& storage,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                     const PreparedCommit& prepared,
                     const history_storage::HeadReference& reference,
                     const std::filesystem::path& workspace_root,
                     std::string_view local_physical_hash = {});

// Publishes the marker that makes the commit visible.
inline PublishHeadResult
publish_head_marker(transport::Transport& storage,
                    const history_storage::RemoteLayout& layout,
                    const history_storage::HeadReference& reference,
                    const std::filesystem::path& workspace_root) {
    return history_storage::publish_head_marker_scoped(
        storage, layout, reference, workspace_root);
}

using history_storage::inspect_head_marker;
using history_storage::list_remote_head_commit_ids;
using history_storage::verify_head_marker;

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
    const history_storage::RemoteLayout& layout,
    std::span<const std::string> parent_ids,
    std::span<const std::string> observed_marker_identifiers);

} // namespace kasumi::application::sync::publication

#endif
