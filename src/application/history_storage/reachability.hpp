#ifndef KASUMI_APPLICATION_HISTORY_STORAGE_REACHABILITY_HPP
#define KASUMI_APPLICATION_HISTORY_STORAGE_REACHABILITY_HPP

#include "application/history_storage/detail.hpp"

#include <optional>

namespace kasumi::application::history_storage {

// Observed state of a head marker.
enum class ReachabilityMarkerState {
    InvalidPath,
    Missing,
    InvalidMarker,
    MissingCommit,
    InvalidCiphertext,
    InvalidCommit,
    Valid,
};

// State of an encrypted commit variant.
struct ReachabilityVariant {
    HeadReference reference;
    // Physical identifier; empty when the variant is absent.
    std::string identifier;
    detail::VariantState state = detail::VariantState::Missing;
};

// Inventoried commit and its physical variants.
struct ReachabilityCommit {
    std::string commit_id;
    bool valid = false;
    bool reachable = false;
    std::vector<std::string> parents;
    // Decoded commit when a valid variant exists.
    std::optional<history::Commit> tree;
    std::vector<ReachabilityVariant> variants;
};

// Inventoried remote marker.
struct ReachabilityMarker {
    std::string identifier;
    // Absent when the remote identifier is invalid.
    std::optional<HeadReference> reference;
    ReachabilityMarkerState state = ReachabilityMarkerState::InvalidPath;
};

// Reachability and integrity of history in an observation.
struct ReachabilityInventory {
    std::vector<std::string> logical_heads;
    std::vector<std::string> reachable_commits;
    // Valid commits with no path from any head.
    std::vector<std::string> orphan_commits;
    std::vector<std::string> missing_parent_ids;
    std::vector<std::string> invalid_parent_ids;
    std::vector<std::string> unknown_history_objects;
    std::vector<ReachabilityCommit> commits;
    std::vector<ReachabilityMarker> markers;
    std::vector<std::string> valid_epochs;
    std::vector<std::string> orphan_epochs;
};

// Result of the history reachability inventory.
using ReachabilityResult = std::expected<ReachabilityInventory, Error>;

// Inventories markers, commits, and reachability without removing objects.
ReachabilityResult
inventory_reachability(transport::Transport& storage,
                       std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                       const std::filesystem::path& workspace_root);

// Variant reusing an already captured physical listing.
ReachabilityResult
inventory_reachability(transport::Transport& storage,
                       std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                       std::span<const std::string> identifiers,
                       const std::filesystem::path& workspace_root);

// Also reuses the Epoch chain already authenticated in this observation.
ReachabilityResult
inventory_reachability(transport::Transport& storage,
                       std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                       std::span<const std::string> identifiers,
                       std::span<const epoch::VerifiedEpoch> verified_epochs,
                       const std::filesystem::path& workspace_root);

} // namespace kasumi::application::history_storage

#endif
