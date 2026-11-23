#include "application/integrity/repack_planner.hpp"

#include <algorithm>
#include <limits>
#include <optional>
#include <unordered_map>
#include <utility>

namespace kasumi::application::integrity::repack {
namespace {

enum class PackKind {
    Retained,
    DirtyUnderfilled,
    DirtyLarge,
    CleanUnderfilled,
};

struct ExistingPack {
    Hash pack_hash{};
    std::vector<history::PackedBlobEntry> entries;
    std::uint64_t live_bytes = 0;
    bool has_oversized_member = false;
    bool has_dead_blobs = false;
    PackKind kind = PackKind::Retained;
};

struct WorkingBin {
    std::uint64_t bytes = 0;
    std::vector<crypto::pack::PackMemberDescriptor> members;
};

std::expected<void, std::string> validate_policy(const Policy& policy) {
    if (policy.max_blob_size == 0 ||
        policy.max_blob_size > crypto::pack::MAX_MICRO_PACK_BLOB_SIZE) {
        return std::unexpected("repack max_blob_size is out of bounds");
    }
    if (policy.target_pack_size == 0 ||
        policy.target_pack_size > crypto::pack::MAXIMUM_PACK_PLAINTEXT_SIZE) {
        return std::unexpected("repack target_pack_size is out of bounds");
    }
    if (policy.underfilled_pack_threshold > policy.target_pack_size) {
        return std::unexpected(
            "repack underfilled_pack_threshold exceeds target_pack_size");
    }
    if (policy.max_pack_members < 2U ||
        policy.max_pack_members > crypto::pack::MAXIMUM_PACK_MEMBERS) {
        return std::unexpected("repack max_pack_members is out of bounds");
    }
    if (policy.min_pack_members < 2U ||
        policy.min_pack_members > policy.max_pack_members) {
        return std::unexpected("repack min_pack_members is out of bounds");
    }
    return {};
}

std::expected<void, std::string> checked_add_u64(std::uint64_t& sum,
                                                 std::uint64_t delta) {
    if (delta > std::numeric_limits<std::uint64_t>::max() - sum) {
        return std::unexpected("byte total overflows 64-bit unsigned limit");
    }
    sum += delta;
    return {};
}

} // namespace

PlanResult plan(const Snapshot& live_tree,
                const history::StorageManifest& current_manifest,
                const Policy& policy) {
    if (auto valid_pol = validate_policy(policy); !valid_pol) {
        return std::unexpected(valid_pol.error());
    }
    if (!valid_snapshot(live_tree, false)) {
        return std::unexpected("live tree snapshot is invalid");
    }

    std::unordered_map<Hash, std::uint64_t, decltype(&hash_key)> live_files{
        0, hash_key};
    live_files.reserve(live_tree.rows.size());
    for (const auto& row : live_tree.rows) {
        if (row.is_directory || row.path == ".kasumiignore") {
            continue;
        }
        auto [it, inserted] = live_files.emplace(row.hash, row.size);
        if (!inserted && it->second != row.size) {
            return std::unexpected(
                "live tree has conflicting sizes for the same content hash");
        }
    }

    if (current_manifest.packed_blobs.size() >
        history::maximum_packed_blob_entries) {
        return std::unexpected("packed_blobs exceeds maximum entry limit");
    }
    HashSet packed_hashes{0, hash_key};
    packed_hashes.reserve(current_manifest.packed_blobs.size());
    for (std::size_t i = 0; i < current_manifest.packed_blobs.size(); ++i) {
        const auto& entry = current_manifest.packed_blobs[i];
        if (i > 0 && !(current_manifest.packed_blobs[i - 1].blob_hash <
                       entry.blob_hash)) {
            return std::unexpected("packed_blobs not strictly sorted");
        }
        if (entry.size > history::maximum_packed_blob_size) {
            return std::unexpected("packed blob exceeds maximum size");
        }
        const auto found = live_files.find(entry.blob_hash);
        if (found == live_files.end() || found->second != entry.size) {
            return std::unexpected(
                "packed blob missing or size mismatch in live tree");
        }
        packed_hashes.insert(entry.blob_hash);
    }

    if (current_manifest.chunked_files.size() >
        history::maximum_chunked_file_entries) {
        return std::unexpected("chunked_files exceeds maximum entry limit");
    }
    HashSet chunked_hashes{0, hash_key};
    chunked_hashes.reserve(current_manifest.chunked_files.size());
    for (std::size_t i = 0; i < current_manifest.chunked_files.size(); ++i) {
        const auto& entry = current_manifest.chunked_files[i];
        if (i > 0 && !(current_manifest.chunked_files[i - 1].file_hash <
                       entry.file_hash)) {
            return std::unexpected("chunked_files not strictly sorted");
        }
        if (packed_hashes.contains(entry.file_hash)) {
            return std::unexpected(
                "content hash appears in both packed_blobs and chunked_files");
        }
        if (entry.chunks.empty()) {
            return std::unexpected("chunked file has empty chunk list");
        }
        const auto found = live_files.find(entry.file_hash);
        if (found == live_files.end() || found->second != entry.file_size) {
            return std::unexpected(
                "chunked file missing or size mismatch in live tree");
        }
        chunked_hashes.insert(entry.file_hash);
    }
    if (!history::valid_storage_manifest(current_manifest, live_tree)) {
        return std::unexpected("current storage manifest is invalid");
    }

    std::unordered_map<Hash, ExistingPack, decltype(&hash_key)> pack_map{
        0, hash_key};
    std::size_t packed_small_count = 0;
    for (const auto& entry : current_manifest.packed_blobs) {
        if (entry.size <= policy.max_blob_size) {
            ++packed_small_count;
        }
        auto [it, inserted] = pack_map.try_emplace(
            entry.pack_hash, ExistingPack{.pack_hash = entry.pack_hash});
        static_cast<void>(inserted);
        if (auto ok = checked_add_u64(it->second.live_bytes, entry.size); !ok) {
            return std::unexpected(ok.error());
        }
        if (entry.size > policy.max_blob_size) {
            it->second.has_oversized_member = true;
        }
        it->second.entries.push_back(entry);
    }

    std::vector<ExistingPack> packs;
    packs.reserve(pack_map.size());
    for (auto& [unused, group] : pack_map) {
        static_cast<void>(unused);
        packs.push_back(std::move(group));
    }
    std::ranges::sort(packs, {}, &ExistingPack::pack_hash);

    Plan result;
    result.existing_packs = packs.size();

    std::size_t dirty_underfilled_count = 0;
    std::size_t clean_underfilled_count = 0;

    for (auto& pack : packs) {
        if (pack.has_oversized_member) {
            pack.kind = PackKind::Retained;
            continue;
        }
        std::vector<crypto::pack::PackMemberDescriptor> descriptors;
        descriptors.reserve(pack.entries.size());
        for (const auto& entry : pack.entries) {
            descriptors.push_back(crypto::pack::PackMemberDescriptor{
                .hash = entry.blob_hash,
                .size = static_cast<std::uint32_t>(entry.size),
            });
        }
        // Comparing the canonical live-only pack hash against the remote
        // pack_hash detects dead members inside immutable packs with zero I/O.
        const auto live_only_hash =
            crypto::pack::compute_pack_hash(descriptors);
        pack.has_dead_blobs =
            !live_only_hash.has_value() || *live_only_hash != pack.pack_hash;
        if (pack.has_dead_blobs) {
            ++result.dirty_packs_detected;
            if (pack.live_bytes < policy.underfilled_pack_threshold) {
                pack.kind = PackKind::DirtyUnderfilled;
                ++dirty_underfilled_count;
            } else {
                pack.kind = PackKind::DirtyLarge;
            }
        } else if (pack.live_bytes < policy.underfilled_pack_threshold) {
            pack.kind = PackKind::CleanUnderfilled;
            ++clean_underfilled_count;
        } else {
            pack.kind = PackKind::Retained;
        }
    }

    std::vector<crypto::pack::PackMemberDescriptor> loose_small;
    for (const auto& [hash, size] : live_files) {
        if (size <= policy.max_blob_size && !packed_hashes.contains(hash) &&
            !chunked_hashes.contains(hash)) {
            loose_small.push_back(crypto::pack::PackMemberDescriptor{
                .hash = hash,
                .size = static_cast<std::uint32_t>(size),
            });
        }
    }
    std::ranges::sort(
        loose_small, {}, &crypto::pack::PackMemberDescriptor::hash);

    result.loose_small_blobs_detected = loose_small.size();
    result.live_small_blobs = loose_small.size() + packed_small_count;

    const auto make_noop = [&] {
        result.actionable = false;
        result.healthy_packs_kept = result.existing_packs;
        result.source_loose_blobs = 0;
        result.source_clean_packs = 0;
        result.source_dirty_packs = 0;
        result.repacked_blobs = 0;
        result.repacked_plaintext_bytes = 0;
        result.replaced_pack_hashes.clear();
        result.new_packs.clear();
        result.target_manifest = current_manifest;
        return result;
    };

    const bool include_clean_and_loose =
        (dirty_underfilled_count + clean_underfilled_count +
         loose_small.size()) >= 2U;

    std::vector<std::size_t> selected_dirty_indices;
    std::vector<std::size_t> selected_clean_indices;
    for (std::size_t i = 0; i < packs.size(); ++i) {
        const auto kind = packs[i].kind;
        if (kind == PackKind::DirtyUnderfilled ||
            (kind == PackKind::DirtyLarge &&
             policy.reclaim_large_dirty_packs)) {
            selected_dirty_indices.push_back(i);
        } else if (kind == PackKind::CleanUnderfilled &&
                   include_clean_and_loose) {
            selected_clean_indices.push_back(i);
        } else {
            packs[i].kind = PackKind::Retained;
        }
    }

    std::vector<crypto::pack::PackMemberDescriptor> selected_loose_blobs;
    if (include_clean_and_loose) {
        selected_loose_blobs = loose_small;
    }

    std::vector<crypto::pack::PackMemberDescriptor> candidates;
    candidates.reserve(selected_loose_blobs.size());
    for (const auto idx : selected_dirty_indices) {
        for (const auto& entry : packs[idx].entries) {
            candidates.push_back(crypto::pack::PackMemberDescriptor{
                .hash = entry.blob_hash,
                .size = static_cast<std::uint32_t>(entry.size),
            });
        }
    }
    for (const auto idx : selected_clean_indices) {
        for (const auto& entry : packs[idx].entries) {
            candidates.push_back(crypto::pack::PackMemberDescriptor{
                .hash = entry.blob_hash,
                .size = static_cast<std::uint32_t>(entry.size),
            });
        }
    }
    candidates.insert(candidates.end(),
                      selected_loose_blobs.begin(),
                      selected_loose_blobs.end());
    std::ranges::sort(
        candidates, {}, &crypto::pack::PackMemberDescriptor::hash);

    if (candidates.empty() || (selected_dirty_indices.empty() &&
                               candidates.size() < policy.min_pack_members)) {
        return make_noop();
    }

    std::vector<WorkingBin> bins;
    for (const auto& cand : candidates) {
        const bool start_new =
            bins.empty() ||
            bins.back().members.size() >= policy.max_pack_members ||
            (!bins.back().members.empty() &&
             bins.back().bytes + cand.size > policy.target_pack_size);
        if (start_new) {
            bins.push_back(WorkingBin{});
        }
        bins.back().members.push_back(cand);
        bins.back().bytes += cand.size;
    }

    if (bins.size() >= 2U && bins.back().members.size() == 1U) {
        auto& prev = bins[bins.size() - 2U];
        const auto tail = bins.back().members.front();
        if (prev.members.size() < policy.max_pack_members &&
            prev.bytes + tail.size <=
                crypto::pack::MAXIMUM_PACK_PLAINTEXT_SIZE) {
            prev.members.push_back(tail);
            prev.bytes += tail.size;
            bins.pop_back();
        }
    }

    std::unordered_map<Hash, std::size_t, decltype(&hash_key)>
        clean_pack_by_hash{0, hash_key};
    clean_pack_by_hash.reserve(selected_clean_indices.size());
    for (const auto idx : selected_clean_indices) {
        clean_pack_by_hash.emplace(packs[idx].pack_hash, idx);
    }

    std::vector<PlannedPack> formed_packs;
    formed_packs.reserve(bins.size());
    for (auto& bin : bins) {
        const auto pack_hash = crypto::pack::compute_pack_hash(bin.members);
        if (!pack_hash) {
            return std::unexpected(
                "failed to compute canonical pack hash for repack bin");
        }
        if (const auto identical = clean_pack_by_hash.find(*pack_hash);
            identical != clean_pack_by_hash.end()) {
            const auto pack_idx = identical->second;
            packs[pack_idx].kind = PackKind::Retained;
            std::erase(selected_clean_indices, pack_idx);
            clean_pack_by_hash.erase(identical);
            continue;
        }
        formed_packs.push_back(PlannedPack{
            .pack_hash = *pack_hash,
            .plaintext_bytes = bin.bytes,
            .members = std::move(bin.members),
        });
    }

    const std::size_t replaced_source_objects = selected_loose_blobs.size() +
                                                selected_clean_indices.size() +
                                                selected_dirty_indices.size();
    const bool beneficial = !formed_packs.empty() &&
                            (!selected_dirty_indices.empty() ||
                             formed_packs.size() < replaced_source_objects);
    if (!beneficial) {
        return make_noop();
    }

    history::StorageManifest target_manifest;
    target_manifest.chunked_files = current_manifest.chunked_files;
    for (const auto& pack : packs) {
        if (pack.kind != PackKind::Retained) {
            continue;
        }
        target_manifest.packed_blobs.insert(target_manifest.packed_blobs.end(),
                                            pack.entries.begin(),
                                            pack.entries.end());
    }

    std::size_t repacked_blob_count = 0;
    std::uint64_t repacked_bytes = 0;
    for (const auto& new_pack : formed_packs) {
        repacked_blob_count += new_pack.members.size();
        repacked_bytes += new_pack.plaintext_bytes;
        for (const auto& member : new_pack.members) {
            target_manifest.packed_blobs.push_back(history::PackedBlobEntry{
                .blob_hash = member.hash,
                .size = member.size,
                .pack_hash = new_pack.pack_hash,
            });
        }
    }
    if (target_manifest.packed_blobs.size() >
        history::maximum_packed_blob_entries) {
        return std::unexpected(
            "repacked storage manifest exceeds packed blob entry limit");
    }
    std::ranges::sort(
        target_manifest.packed_blobs, {}, &history::PackedBlobEntry::blob_hash);

    std::vector<Hash> replaced_hashes;
    replaced_hashes.reserve(selected_dirty_indices.size() +
                            selected_clean_indices.size());
    for (const auto idx : selected_dirty_indices) {
        replaced_hashes.push_back(packs[idx].pack_hash);
    }
    for (const auto idx : selected_clean_indices) {
        replaced_hashes.push_back(packs[idx].pack_hash);
    }
    std::ranges::sort(replaced_hashes);
    std::ranges::sort(formed_packs, {}, &PlannedPack::pack_hash);

    result.actionable = true;
    result.healthy_packs_kept = result.existing_packs - replaced_hashes.size();
    result.source_loose_blobs = selected_loose_blobs.size();
    result.source_clean_packs = selected_clean_indices.size();
    result.source_dirty_packs = selected_dirty_indices.size();
    result.repacked_blobs = repacked_blob_count;
    result.repacked_plaintext_bytes = repacked_bytes;
    result.replaced_pack_hashes = std::move(replaced_hashes);
    result.new_packs = std::move(formed_packs);
    result.target_manifest = std::move(target_manifest);
    return result;
}

} // namespace kasumi::application::integrity::repack
