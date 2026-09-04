#ifndef KASUMI_APPLICATION_HISTORY_STORAGE_PUBLICATION_HPP
#define KASUMI_APPLICATION_HISTORY_STORAGE_PUBLICATION_HPP

#include "application/history_storage/history_storage.hpp"

#include <expected>
#include <string>
#include <vector>

namespace kasumi::application::history_storage {

// Published or reused commit object.
struct PublishedCommitObject {
    HeadReference head;
    // Identifier of the corresponding marker.
    std::string marker_id;
    // SHA-256 of the new object; empty when reused.
    std::string physical_hash;
    // Indicates reuse of an already valid variant.
    bool reused_existing_ciphertext = false;
};

// Published or already existing head marker.
struct PublishedHeadMarker {
    std::string marker_id;
    // SHA-256 of the new marker; empty when already existed.
    std::string physical_hash;
};

// Observed state of a head marker.
enum class HeadMarkerState {
    Absent,
    Valid,
    Invalid,
};

// Result of publishing a commit object.
using PublishObjectResult = std::expected<PublishedCommitObject, Error>;
// Result of publishing a marker.
using PublishHeadResult = std::expected<PublishedHeadMarker, Error>;
// Result of inspecting a marker.
using HeadMarkerInspection = std::expected<HeadMarkerState, Error>;

// Publishes or reuses the encrypted commit variant.
PublishObjectResult
publish_commit_object(transport::Transport& storage,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                      const history::Commit& commit,
                      const std::filesystem::path& workspace_root);

// Scoped variant avoids inventorying the entire remote storage.
PublishObjectResult publish_commit_object_scoped(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const history::Commit& commit,
    const std::filesystem::path& workspace_root);

// Confirms the physical hash or downloads and validates the commit.
std::expected<void, Error>
verify_commit_object(transport::Transport& storage,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                     const history::Commit& commit,
                     const HeadReference& reference,
                     const std::filesystem::path& workspace_root,
                     std::string_view local_physical_hash = {});

// Publishes the marker after validating remote inventory.
PublishHeadResult
publish_head_marker(transport::Transport& storage,
                    const HeadReference& reference,
                    const std::filesystem::path& workspace_root);

// Publishes the marker without inventorying the entire remote storage.
PublishHeadResult
publish_head_marker_scoped(transport::Transport& storage,
                           const HeadReference& reference,
                           const std::filesystem::path& workspace_root);

// Confirms the physical hash or downloads and validates the marker.
std::expected<void, Error>
verify_head_marker(transport::Transport& storage,
                   const HeadReference& reference,
                   const std::filesystem::path& workspace_root,
                   std::string_view local_physical_hash = {});

// Classifies presence and validity of the marker.
HeadMarkerInspection
inspect_head_marker(transport::Transport& storage,
                    const HeadReference& reference,
                    const std::filesystem::path& workspace_root);

// Builds the remote identifier for the marker.
std::string marker_identifier(const HeadReference& reference);

// Queries remote head commit identifiers from storage.
std::expected<std::vector<std::string>, Error>
list_remote_head_commit_ids(transport::Transport& storage);

} // namespace kasumi::application::history_storage

#endif
