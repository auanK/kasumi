#ifndef KASUMI_APPLICATION_INTEGRITY_REPACK_PLANNER_HPP
#define KASUMI_APPLICATION_INTEGRITY_REPACK_PLANNER_HPP

#include "core/history.hpp"
#include "core/node.hpp"
#include "crypto/pack.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace kasumi::application::integrity::repack {

// Policy thresholds controlling when live small files and fragmented packs
// are consolidated into fresh Micro-Packs.
struct Policy {
    std::uint64_t max_blob_size = crypto::pack::MAX_MICRO_PACK_BLOB_SIZE;
    std::uint64_t target_pack_size = crypto::pack::TARGET_MICRO_PACK_SIZE;
    std::uint64_t underfilled_pack_threshold =
        crypto::pack::TARGET_MICRO_PACK_SIZE / 2ULL;
    std::size_t max_pack_members = crypto::pack::MAXIMUM_PACK_MEMBERS;
    std::size_t min_pack_members = 2U;
    bool reclaim_large_dirty_packs = false;
};

// A new Micro-Pack to be assembled from live local files and published.
struct PlannedPack {
    Hash pack_hash{};
    std::uint64_t plaintext_bytes = 0;
    std::vector<crypto::pack::PackMemberDescriptor> members;

    bool operator==(const PlannedPack&) const noexcept = default;
};

// Pure planning output describing pack consolidation without I/O or mutation.
struct Plan {
    bool actionable = false;
    std::size_t live_small_blobs = 0;
    std::size_t existing_packs = 0;
    std::size_t healthy_packs_kept = 0;
    std::size_t dirty_packs_detected = 0;
    std::size_t loose_small_blobs_detected = 0;
    std::size_t source_loose_blobs = 0;
    std::size_t source_clean_packs = 0;
    std::size_t source_dirty_packs = 0;
    std::size_t repacked_blobs = 0;
    std::uint64_t repacked_plaintext_bytes = 0;
    std::vector<Hash> replaced_pack_hashes;
    std::vector<PlannedPack> new_packs;
    history::StorageManifest target_manifest;
};

using PlanResult = std::expected<Plan, std::string>;

// Computes a deterministic Micro-Pack repack plan from live_tree and
// current_manifest without mutating remote storage or touching disk files.
PlanResult plan(const Snapshot& live_tree,
                const history::StorageManifest& current_manifest,
                const Policy& policy = {});

} // namespace kasumi::application::integrity::repack

#endif
