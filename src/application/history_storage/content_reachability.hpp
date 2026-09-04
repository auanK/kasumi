#ifndef KASUMI_APPLICATION_HISTORY_STORAGE_CONTENT_REACHABILITY_HPP
#define KASUMI_APPLICATION_HISTORY_STORAGE_CONTENT_REACHABILITY_HPP

#include "application/history_storage/reachability.hpp"

#include <compare>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <tuple>
#include <vector>

namespace kasumi::application::history_storage {

// Availability and integrity of a content object.
enum class ContentObjectState {
    Present,
    Missing,
    Corrupt,
};

// Usage of a content item by a reachable commit.
struct ContentReference {
    std::string commit_id;
    std::string path;
    std::uint64_t size = 0;
};

// Compares commit, path, and size.
inline bool operator==(const ContentReference& left,
                       const ContentReference& right) noexcept {
    return std::tie(left.commit_id, left.path, left.size) ==
           std::tie(right.commit_id, right.path, right.size);
}

// Orders by commit, path, and size.
inline std::strong_ordering
operator<=>(const ContentReference& left,
            const ContentReference& right) noexcept {
    return std::tie(left.commit_id, left.path, left.size) <=>
           std::tie(right.commit_id, right.path, right.size);
}

// State and references of a content object.
struct ContentEntry {
    std::string content_id;
    ContentObjectState state = ContentObjectState::Missing;
    bool reachable = false;
    std::vector<ContentReference> references;
};

// Reachability and integrity of content in an observation.
struct ContentReachabilityInventory {
    std::vector<std::string> reachable_content_ids;
    std::vector<std::string> missing_content_ids;
    std::vector<std::string> corrupt_content_ids;
    // Physical objects without references in reachable commits.
    std::vector<std::string> orphan_content_ids;
    std::vector<ContentEntry> contents;
    std::vector<std::string> unknown_storage_objects;
};

// Result of content reachability inventory.
using ContentReachabilityResult =
    std::expected<ContentReachabilityInventory, Error>;

// Audits referenced and orphan objects without removing them.
ContentReachabilityResult inventory_content_reachability(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const ReachabilityInventory& history_inventory,
    const std::filesystem::path& workspace_root);

// Variant reusing an already captured physical listing.
ContentReachabilityResult inventory_content_reachability(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    std::span<const std::string> identifiers,
    const ReachabilityInventory& history_inventory,
    const std::filesystem::path& workspace_root);

} // namespace kasumi::application::history_storage

#endif
