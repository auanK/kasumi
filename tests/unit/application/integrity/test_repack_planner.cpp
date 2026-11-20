#include "application/integrity/repack_planner.hpp"

#include "core/hasher.hpp"
#include "core/history.hpp"
#include "core/node.hpp"
#include "crypto/pack.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace repack = kasumi::application::integrity::repack;
namespace history = kasumi::history;
namespace pack = kasumi::crypto::pack;

struct FileSpec {
    std::string path;
    kasumi::Hash hash{};
    std::uint64_t size = 0;
};

kasumi::Hash make_hash(std::string_view tag) {
    return kasumi::hasher::hash_string(tag);
}

// Builds a hash with controllable leading byte so tests can fix relative hash
// order deterministically while preserving uniqueness per tag.
kasumi::Hash make_ordered_hash(std::uint8_t prefix, std::string_view tag) {
    auto hash = kasumi::hasher::hash_string(tag);
    hash[0] = static_cast<std::byte>(prefix);
    return hash;
}

kasumi::Snapshot build_snapshot(const std::vector<FileSpec>& files,
                                std::vector<std::string> dirs = {}) {
    kasumi::Snapshot snapshot;
    snapshot.rows.push_back(kasumi::NodeRow{
        .path = "",
        .hash = {},
        .size = 0,
        .mtime = 1,
        .is_directory = true,
    });
    for (const auto& dir : dirs) {
        snapshot.rows.push_back(kasumi::NodeRow{
            .path = dir,
            .hash = {},
            .size = 0,
            .mtime = 1,
            .is_directory = true,
        });
    }
    for (const auto& file : files) {
        snapshot.rows.push_back(kasumi::NodeRow{
            .path = file.path,
            .hash = file.hash,
            .size = file.size,
            .mtime = 2,
            .is_directory = false,
        });
    }
    kasumi::finalize_snapshot(snapshot);
    return snapshot;
}

kasumi::Hash canonical_pack_hash(const std::vector<FileSpec>& members) {
    std::vector<pack::PackMemberDescriptor> descriptors;
    descriptors.reserve(members.size());
    for (const auto& member : members) {
        descriptors.push_back(pack::PackMemberDescriptor{
            .hash = member.hash,
            .size = static_cast<std::uint32_t>(member.size),
        });
    }
    std::ranges::sort(
        descriptors, {}, &pack::PackMemberDescriptor::hash);
    const auto computed = pack::compute_pack_hash(descriptors);
    EXPECT_TRUE(computed.has_value());
    return computed.value_or(kasumi::Hash{});
}

void append_pack_to_manifest(history::StorageManifest& manifest,
                             const std::vector<FileSpec>& live_members,
                             const kasumi::Hash& pack_hash) {
    for (const auto& member : live_members) {
        manifest.packed_blobs.push_back(history::PackedBlobEntry{
            .blob_hash = member.hash,
            .size = member.size,
            .pack_hash = pack_hash,
        });
    }
}

void finalize_manifest(history::StorageManifest& manifest) {
    std::ranges::sort(manifest.packed_blobs,
                      {},
                      &history::PackedBlobEntry::blob_hash);
    std::ranges::sort(manifest.chunked_files,
                      {},
                      &history::ChunkedFileEntry::file_hash);
}

TEST(RepackPlannerTest, EmptyOrAllHealthyVaultIsNoOp) {
    const auto empty_tree = build_snapshot({});
    const auto empty_plan = repack::plan(empty_tree, history::StorageManifest{});
    ASSERT_TRUE(empty_plan.has_value()) << empty_plan.error();
    EXPECT_FALSE(empty_plan->actionable);
    EXPECT_EQ(empty_plan->existing_packs, 0U);
    EXPECT_EQ(empty_plan->target_manifest, history::StorageManifest{});

    // Healthy pack (>= 2 MiB with no dead members), plus medium (> 256 KiB),
    // FastCDC chunked (> 8 MiB), and ignored rules file (.kasumiignore).
    std::vector<FileSpec> pack_members;
    pack_members.reserve(10);
    for (int i = 0; i < 10; ++i) {
        pack_members.push_back(FileSpec{
            .path = "small_" + std::to_string(i) + ".txt",
            .hash = make_hash("healthy_member_" + std::to_string(i)),
            .size = 240U * 1024U, // 10 * 240 KiB = 2.4 MiB >= 2 MiB threshold
        });
    }
    const auto healthy_pack_hash = canonical_pack_hash(pack_members);

    const FileSpec ignore_file{
        .path = ".kasumiignore",
        .hash = make_hash("ignore_rules"),
        .size = 128,
    };
    const FileSpec medium_file{
        .path = "medium.bin",
        .hash = make_hash("medium_blob"),
        .size = 512ULL * 1024ULL,
    };
    const std::uint64_t large_size = 9ULL * 1024ULL * 1024ULL;
    const FileSpec chunked_file{
        .path = "large.bin",
        .hash = make_hash("large_blob"),
        .size = large_size,
    };

    std::vector<FileSpec> all_files = pack_members;
    all_files.push_back(ignore_file);
    all_files.push_back(medium_file);
    all_files.push_back(chunked_file);
    const auto tree = build_snapshot(all_files);

    history::StorageManifest manifest;
    append_pack_to_manifest(manifest, pack_members, healthy_pack_hash);
    manifest.chunked_files.push_back(history::ChunkedFileEntry{
        .file_hash = chunked_file.hash,
        .file_size = large_size,
        .chunks =
            {
                {.hash = make_hash("chunk_1"), .size = 4U * 1024U * 1024U},
                {.hash = make_hash("chunk_2"), .size = 5U * 1024U * 1024U},
            },
    });
    finalize_manifest(manifest);

    const auto result = repack::plan(tree, manifest);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_FALSE(result->actionable);
    EXPECT_EQ(result->existing_packs, 1U);
    EXPECT_EQ(result->healthy_packs_kept, 1U);
    EXPECT_EQ(result->dirty_packs_detected, 0U);
    EXPECT_EQ(result->loose_small_blobs_detected, 0U);
    EXPECT_EQ(result->live_small_blobs, 10U);
    EXPECT_TRUE(result->new_packs.empty());
    EXPECT_TRUE(result->replaced_pack_hashes.empty());
    EXPECT_EQ(result->target_manifest, manifest);
}

TEST(RepackPlannerTest, SingleLooseSmallBlobIsNoOp) {
    const auto tree = build_snapshot({
        FileSpec{
            .path = "only.txt",
            .hash = make_hash("single_loose"),
            .size = 1024,
        },
        FileSpec{
            .path = ".kasumiignore",
            .hash = make_hash("ignore_file"),
            .size = 64,
        },
    });

    const auto result = repack::plan(tree, history::StorageManifest{});
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_FALSE(result->actionable);
    EXPECT_EQ(result->live_small_blobs, 1U);
    EXPECT_EQ(result->loose_small_blobs_detected, 1U);
    EXPECT_TRUE(result->new_packs.empty());
    EXPECT_EQ(result->target_manifest, history::StorageManifest{});
}

TEST(RepackPlannerTest, ConsolidatesMultipleLooseSmallBlobsIntoMicroPacks) {
    const FileSpec small_a{.path = "a.txt", .hash = make_ordered_hash(0x01, "a"), .size = 1000};
    const FileSpec small_b{.path = "b.txt", .hash = make_ordered_hash(0x02, "b"), .size = 2000};
    const FileSpec small_a_dup{.path = "dup_a.txt", .hash = small_a.hash, .size = 1000};
    const FileSpec ignore_file{.path = ".kasumiignore", .hash = make_ordered_hash(0x03, "ig"), .size = 120};
    const FileSpec medium_file{.path = "medium.dat", .hash = make_ordered_hash(0x04, "med"), .size = 300ULL * 1024ULL};
    const std::uint64_t large_size = 9ULL * 1024ULL * 1024ULL;
    const FileSpec large_file{.path = "large.dat", .hash = make_ordered_hash(0x05, "big"), .size = large_size};

    const auto tree = build_snapshot(
        {small_a, small_b, small_a_dup, ignore_file, medium_file, large_file});
    history::StorageManifest manifest;
    manifest.chunked_files.push_back(history::ChunkedFileEntry{
        .file_hash = large_file.hash,
        .file_size = large_size,
        .chunks =
            {
                {.hash = make_hash("c1"), .size = 4U * 1024U * 1024U},
                {.hash = make_hash("c2"), .size = 5U * 1024U * 1024U},
            },
    });
    finalize_manifest(manifest);

    const auto first = repack::plan(tree, manifest);
    ASSERT_TRUE(first.has_value()) << first.error();
    ASSERT_TRUE(first->actionable);
    EXPECT_EQ(first->live_small_blobs, 2U);
    EXPECT_EQ(first->loose_small_blobs_detected, 2U);
    EXPECT_EQ(first->source_loose_blobs, 2U);
    EXPECT_EQ(first->source_clean_packs, 0U);
    EXPECT_EQ(first->source_dirty_packs, 0U);
    EXPECT_EQ(first->repacked_blobs, 2U);
    EXPECT_EQ(first->repacked_plaintext_bytes, 3000ULL);
    ASSERT_EQ(first->new_packs.size(), 1U);
    EXPECT_EQ(first->new_packs[0].members.size(), 2U);
    EXPECT_TRUE(history::valid_storage_manifest(first->target_manifest, tree));
    EXPECT_NE(history::find_packed_blob(first->target_manifest, small_a.hash), nullptr);
    EXPECT_NE(history::find_packed_blob(first->target_manifest, small_b.hash), nullptr);
    EXPECT_EQ(history::find_packed_blob(first->target_manifest, ignore_file.hash), nullptr);
    EXPECT_EQ(history::find_packed_blob(first->target_manifest, medium_file.hash), nullptr);
    EXPECT_NE(history::find_chunked_file(first->target_manifest, large_file.hash), nullptr);

    // Second pass against target_manifest must be idempotent (no-op).
    const auto second = repack::plan(tree, first->target_manifest);
    ASSERT_TRUE(second.has_value()) << second.error();
    EXPECT_FALSE(second->actionable);
    EXPECT_EQ(second->target_manifest, first->target_manifest);
}

TEST(RepackPlannerTest, ConsolidatesMultipleCleanUnderfilledPacksIntoOne) {
    // Healthy pack (>= 2 MiB) that must stay untouched.
    std::vector<FileSpec> healthy_members;
    for (int i = 0; i < 10; ++i) {
        healthy_members.push_back(FileSpec{
            .path = "healthy/f_" + std::to_string(i),
            .hash = make_ordered_hash(0x10, "healthy_" + std::to_string(i)),
            .size = 220U * 1024U,
        });
    }
    const auto healthy_hash = canonical_pack_hash(healthy_members);

    // Three clean underfilled packs (each < 2 MiB, combined ~1.0 MiB).
    const std::vector<FileSpec> pack1{
        {.path = "p1/a", .hash = make_ordered_hash(0x20, "p1a"), .size = 150U * 1024U},
        {.path = "p1/b", .hash = make_ordered_hash(0x21, "p1b"), .size = 200U * 1024U},
    };
    const std::vector<FileSpec> pack2{
        {.path = "p2/a", .hash = make_ordered_hash(0x22, "p2a"), .size = 150U * 1024U},
        {.path = "p2/b", .hash = make_ordered_hash(0x23, "p2b"), .size = 200U * 1024U},
    };
    const std::vector<FileSpec> pack3{
        {.path = "p3/a", .hash = make_ordered_hash(0x24, "p3a"), .size = 150U * 1024U},
        {.path = "p3/b", .hash = make_ordered_hash(0x25, "p3b"), .size = 200U * 1024U},
    };

    const auto p1_hash = canonical_pack_hash(pack1);
    const auto p2_hash = canonical_pack_hash(pack2);
    const auto p3_hash = canonical_pack_hash(pack3);

    std::vector<FileSpec> all_files = healthy_members;
    all_files.insert(all_files.end(), pack1.begin(), pack1.end());
    all_files.insert(all_files.end(), pack2.begin(), pack2.end());
    all_files.insert(all_files.end(), pack3.begin(), pack3.end());
    const auto tree = build_snapshot(all_files, {"healthy", "p1", "p2", "p3"});

    history::StorageManifest manifest;
    append_pack_to_manifest(manifest, healthy_members, healthy_hash);
    append_pack_to_manifest(manifest, pack1, p1_hash);
    append_pack_to_manifest(manifest, pack2, p2_hash);
    append_pack_to_manifest(manifest, pack3, p3_hash);
    finalize_manifest(manifest);

    const auto result = repack::plan(tree, manifest);
    ASSERT_TRUE(result.has_value()) << result.error();
    ASSERT_TRUE(result->actionable);
    EXPECT_EQ(result->existing_packs, 4U);
    EXPECT_EQ(result->healthy_packs_kept, 1U);
    EXPECT_EQ(result->source_clean_packs, 3U);
    EXPECT_EQ(result->source_dirty_packs, 0U);
    EXPECT_EQ(result->new_packs.size(), 1U);
    EXPECT_EQ(result->repacked_blobs, 6U);
    EXPECT_EQ(result->replaced_pack_hashes.size(), 3U);
    EXPECT_TRUE(history::valid_storage_manifest(result->target_manifest, tree));

    // Healthy pack entries must keep the exact same remote pack hash.
    for (const auto& member : healthy_members) {
        const auto* entry =
            history::find_packed_blob(result->target_manifest, member.hash);
        ASSERT_NE(entry, nullptr);
        EXPECT_EQ(entry->pack_hash, healthy_hash);
    }

    // Second pass is a no-op (even though the merged pack is ~1.05 MiB, it is a
    // single clean underfilled pack with nothing else to coalesce with).
    const auto second = repack::plan(tree, result->target_manifest);
    ASSERT_TRUE(second.has_value()) << second.error();
    EXPECT_FALSE(second->actionable);
}

TEST(RepackPlannerTest, ReclaimsDirtyPackProvenByPackHashMismatch) {
    const FileSpec survivor{.path = "alive.txt", .hash = make_ordered_hash(0x30, "alive"), .size = 4096};
    const FileSpec dead_b{.path = "dead_b.txt", .hash = make_ordered_hash(0x31, "dead_b"), .size = 8192};
    const FileSpec dead_c{.path = "dead_c.txt", .hash = make_ordered_hash(0x32, "dead_c"), .size = 16384};
    const auto old_pack_hash = canonical_pack_hash({survivor, dead_b, dead_c});

    const auto tree = build_snapshot({survivor});
    history::StorageManifest manifest;
    append_pack_to_manifest(manifest, {survivor}, old_pack_hash);
    finalize_manifest(manifest);

    const auto result = repack::plan(tree, manifest);
    ASSERT_TRUE(result.has_value()) << result.error();
    ASSERT_TRUE(result->actionable);
    EXPECT_EQ(result->dirty_packs_detected, 1U);
    EXPECT_EQ(result->source_dirty_packs, 1U);
    EXPECT_EQ(result->source_clean_packs, 0U);
    EXPECT_EQ(result->healthy_packs_kept, 0U);
    ASSERT_EQ(result->new_packs.size(), 1U);
    EXPECT_NE(result->new_packs[0].pack_hash, old_pack_hash);
    EXPECT_EQ(result->new_packs[0].pack_hash, canonical_pack_hash({survivor}));
    EXPECT_EQ(result->replaced_pack_hashes, std::vector{old_pack_hash});
    EXPECT_TRUE(history::valid_storage_manifest(result->target_manifest, tree));

    // Re-running on target_manifest has no dead blobs and only 1 clean pack -> no-op.
    const auto second = repack::plan(tree, result->target_manifest);
    ASSERT_TRUE(second.has_value()) << second.error();
    EXPECT_FALSE(second->actionable);
    EXPECT_EQ(second->dirty_packs_detected, 0U);
}

TEST(RepackPlannerTest, SkipsLargeDirtyPackByDefaultAndReclaimsWhenPolicyEnablesIt) {
    // 10 live blobs totaling 2.5 MiB (>= 2 MiB threshold), plus 1 dead blob
    // included in the original pack hash.
    std::vector<FileSpec> large_dirty_live;
    for (int i = 0; i < 10; ++i) {
        large_dirty_live.push_back(FileSpec{
            .path = "large_dirty/f_" + std::to_string(i),
            .hash = make_ordered_hash(0x40, "ldl_" + std::to_string(i)),
            .size = 256U * 1024U,
        });
    }
    auto original_members = large_dirty_live;
    original_members.push_back(FileSpec{
        .path = "deleted.txt",
        .hash = make_ordered_hash(0x41, "dead_member"),
        .size = 64U * 1024U,
    });
    const auto large_dirty_hash = canonical_pack_hash(original_members);

    // One unrelated clean underfilled pack that must NOT be needlessly rewritten
    // when object count would not decrease.
    const std::vector<FileSpec> clean_small{
        {.path = "clean/one", .hash = make_ordered_hash(0x80, "c1"), .size = 1024},
        {.path = "clean/two", .hash = make_ordered_hash(0x81, "c2"), .size = 1024},
    };
    const auto clean_small_hash = canonical_pack_hash(clean_small);

    std::vector<FileSpec> all_files = large_dirty_live;
    all_files.insert(all_files.end(), clean_small.begin(), clean_small.end());
    const auto tree = build_snapshot(all_files, {"large_dirty", "clean"});

    history::StorageManifest manifest;
    append_pack_to_manifest(manifest, large_dirty_live, large_dirty_hash);
    append_pack_to_manifest(manifest, clean_small, clean_small_hash);
    finalize_manifest(manifest);

    // Default policy leaves the >= 2 MiB dirty pack alone.
    const auto default_plan = repack::plan(tree, manifest);
    ASSERT_TRUE(default_plan.has_value()) << default_plan.error();
    EXPECT_FALSE(default_plan->actionable);
    EXPECT_EQ(default_plan->dirty_packs_detected, 1U);
    EXPECT_EQ(default_plan->healthy_packs_kept, 2U);

    // Explicit policy reclaims the large dirty pack while keeping the clean
    // underfilled pack untouched.
    repack::Policy reclaim_policy;
    reclaim_policy.reclaim_large_dirty_packs = true;
    const auto reclaim_plan = repack::plan(tree, manifest, reclaim_policy);
    ASSERT_TRUE(reclaim_plan.has_value()) << reclaim_plan.error();
    ASSERT_TRUE(reclaim_plan->actionable);
    EXPECT_EQ(reclaim_plan->source_dirty_packs, 1U);
    EXPECT_EQ(reclaim_plan->source_clean_packs, 0U);
    EXPECT_EQ(reclaim_plan->healthy_packs_kept, 1U);
    EXPECT_EQ(reclaim_plan->replaced_pack_hashes, std::vector{large_dirty_hash});
    EXPECT_EQ(reclaim_plan->new_packs.size(), 1U);
    const auto* clean_entry =
        history::find_packed_blob(reclaim_plan->target_manifest, clean_small[0].hash);
    ASSERT_NE(clean_entry, nullptr);
    EXPECT_EQ(clean_entry->pack_hash, clean_small_hash);
}

TEST(RepackPlannerTest, MergesTrailingSingleBlobIntoPreviousPack) {
    // target_pack_size = 4 MiB. 16 blobs * 256 KiB = 4 MiB fill the first bin,
    // leaving 1 trailing 256 KiB blob that must merge into bin 0 (4.25 MiB <=
    // MAXIMUM_PACK_PLAINTEXT_SIZE of 16 MiB) instead of leaving a 1-member pack.
    std::vector<FileSpec> files;
    files.reserve(17);
    for (int i = 0; i < 17; ++i) {
        files.push_back(FileSpec{
            .path = "blob_" + std::to_string(i) + ".bin",
            .hash = make_ordered_hash(static_cast<std::uint8_t>(0x50 + i),
                                      "trail_" + std::to_string(i)),
            .size = 256U * 1024U,
        });
    }
    const auto tree = build_snapshot(files);

    const auto result = repack::plan(tree, history::StorageManifest{});
    ASSERT_TRUE(result.has_value()) << result.error();
    ASSERT_TRUE(result->actionable);
    ASSERT_EQ(result->new_packs.size(), 1U);
    EXPECT_EQ(result->new_packs[0].members.size(), 17U);
    EXPECT_EQ(result->new_packs[0].plaintext_bytes, 17ULL * 256ULL * 1024ULL);
    EXPECT_TRUE(history::valid_storage_manifest(result->target_manifest, tree));
}

TEST(RepackPlannerTest, NonReducingCleanPacksAreNoOp) {
    // Interleaved hashes across 2 clean packs of 300 KiB each under a 400 KiB
    // target_pack_size: bin-packing produces 2 new packs of 300 KiB each with
    // zero dirty packs reclaimed, so object count is not reduced -> no-op.
    const std::vector<FileSpec> pack1{
        {.path = "p1/a", .hash = make_ordered_hash(0x01, "nr1a"), .size = 150U * 1024U},
        {.path = "p1/b", .hash = make_ordered_hash(0x03, "nr1b"), .size = 150U * 1024U},
    };
    const std::vector<FileSpec> pack2{
        {.path = "p2/a", .hash = make_ordered_hash(0x02, "nr2a"), .size = 150U * 1024U},
        {.path = "p2/b", .hash = make_ordered_hash(0x04, "nr2b"), .size = 150U * 1024U},
    };

    const auto p1_hash = canonical_pack_hash(pack1);
    const auto p2_hash = canonical_pack_hash(pack2);

    std::vector<FileSpec> all_files = pack1;
    all_files.insert(all_files.end(), pack2.begin(), pack2.end());
    const auto tree = build_snapshot(all_files, {"p1", "p2"});

    history::StorageManifest manifest;
    append_pack_to_manifest(manifest, pack1, p1_hash);
    append_pack_to_manifest(manifest, pack2, p2_hash);
    finalize_manifest(manifest);

    repack::Policy custom;
    custom.target_pack_size = 400ULL * 1024ULL;
    custom.underfilled_pack_threshold = 400ULL * 1024ULL;

    const auto result = repack::plan(tree, manifest, custom);
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_FALSE(result->actionable);
    EXPECT_EQ(result->target_manifest, manifest);
}

TEST(RepackPlannerTest, RejectsInvalidInputs) {
    const auto valid_tree = build_snapshot({
        {.path = "a.txt", .hash = make_ordered_hash(0x10, "a"), .size = 10},
        {.path = "b.txt", .hash = make_ordered_hash(0x20, "b"), .size = 20},
    });

    // Invalid policy bounds.
    repack::Policy bad_policy;
    bad_policy.max_blob_size = 0;
    EXPECT_FALSE(repack::plan(valid_tree, {}, bad_policy).has_value());

    bad_policy = repack::Policy{};
    bad_policy.max_blob_size = pack::MAX_MICRO_PACK_BLOB_SIZE + 1;
    EXPECT_FALSE(repack::plan(valid_tree, {}, bad_policy).has_value());

    bad_policy = repack::Policy{};
    bad_policy.underfilled_pack_threshold = bad_policy.target_pack_size + 1;
    EXPECT_FALSE(repack::plan(valid_tree, {}, bad_policy).has_value());

    bad_policy = repack::Policy{};
    bad_policy.min_pack_members = 1;
    EXPECT_FALSE(repack::plan(valid_tree, {}, bad_policy).has_value());

    // Invalid snapshot (empty).
    EXPECT_FALSE(repack::plan(kasumi::Snapshot{}, {}).has_value());

    // Conflicting sizes for identical content hash in live tree.
    const auto same_hash = make_hash("conflict");
    const auto conflicting_tree = build_snapshot({
        {.path = "x.txt", .hash = same_hash, .size = 10},
        {.path = "y.txt", .hash = same_hash, .size = 20},
    });
    EXPECT_FALSE(repack::plan(conflicting_tree, {}).has_value());

    // Unsorted manifest packed_blobs.
    history::StorageManifest unsorted_manifest;
    const auto h1 = make_ordered_hash(0x10, "a");
    const auto h2 = make_ordered_hash(0x20, "b");
    unsorted_manifest.packed_blobs = {
        {.blob_hash = h2, .size = 20, .pack_hash = make_hash("p")},
        {.blob_hash = h1, .size = 10, .pack_hash = make_hash("p")},
    };
    EXPECT_FALSE(repack::plan(valid_tree, unsorted_manifest).has_value());

    // Manifest entry missing from live_tree.
    history::StorageManifest absent_manifest;
    absent_manifest.packed_blobs = {
        {.blob_hash = make_ordered_hash(0x99, "missing"),
         .size = 10,
         .pack_hash = make_hash("p")},
    };
    EXPECT_FALSE(repack::plan(valid_tree, absent_manifest).has_value());

    // Manifest size mismatch against live_tree.
    history::StorageManifest mismatch_manifest;
    mismatch_manifest.packed_blobs = {
        {.blob_hash = h1, .size = 999, .pack_hash = make_hash("p")},
    };
    EXPECT_FALSE(repack::plan(valid_tree, mismatch_manifest).has_value());

    // Overlap between packed_blobs and chunked_files.
    history::StorageManifest overlap_manifest;
    overlap_manifest.packed_blobs = {
        {.blob_hash = h1, .size = 10, .pack_hash = make_hash("p")},
    };
    overlap_manifest.chunked_files = {
        {.file_hash = h1, .file_size = 10, .chunks = {{.hash = h2, .size = 10}}},
    };
    EXPECT_FALSE(repack::plan(valid_tree, overlap_manifest).has_value());
}

TEST(RepackPlannerTest, PreservesZeroByteSmallFilesAndOversizedPackedBlobs) {
    const FileSpec empty_file{
        .path = "empty.txt",
        .hash = kasumi::hasher::hash_bytes(nullptr, 0),
        .size = 0,
    };
    const FileSpec tiny_file{
        .path = "tiny.txt",
        .hash = make_ordered_hash(0x70, "tiny"),
        .size = 128,
    };
    // Existing packed blob larger than a custom policy's max_blob_size (1 KiB).
    const FileSpec oversized_packed{
        .path = "oversized.dat",
        .hash = make_ordered_hash(0x71, "oversized"),
        .size = 4096,
    };
    const auto oversized_pack_hash = canonical_pack_hash({oversized_packed});

    const auto tree = build_snapshot({empty_file, tiny_file, oversized_packed});
    history::StorageManifest manifest;
    append_pack_to_manifest(manifest, {oversized_packed}, oversized_pack_hash);
    finalize_manifest(manifest);

    repack::Policy custom;
    custom.max_blob_size = 1024;
    custom.target_pack_size = 64ULL * 1024ULL;
    custom.underfilled_pack_threshold = 32ULL * 1024ULL;

    const auto result = repack::plan(tree, manifest, custom);
    ASSERT_TRUE(result.has_value()) << result.error();
    ASSERT_TRUE(result->actionable);
    EXPECT_EQ(result->live_small_blobs, 2U);
    EXPECT_EQ(result->loose_small_blobs_detected, 2U);
    EXPECT_EQ(result->healthy_packs_kept, 1U);
    EXPECT_TRUE(result->replaced_pack_hashes.empty());
    ASSERT_EQ(result->new_packs.size(), 1U);
    EXPECT_EQ(result->new_packs[0].members.size(), 2U);

    // The oversized packed entry must remain untouched in its original pack.
    const auto* retained_oversized =
        history::find_packed_blob(result->target_manifest, oversized_packed.hash);
    ASSERT_NE(retained_oversized, nullptr);
    EXPECT_EQ(retained_oversized->pack_hash, oversized_pack_hash);

    // Zero-byte and tiny loose files must be consolidated into the new pack.
    const auto* packed_empty =
        history::find_packed_blob(result->target_manifest, empty_file.hash);
    const auto* packed_tiny =
        history::find_packed_blob(result->target_manifest, tiny_file.hash);
    ASSERT_NE(packed_empty, nullptr);
    ASSERT_NE(packed_tiny, nullptr);
    EXPECT_EQ(packed_empty->pack_hash, result->new_packs[0].pack_hash);
    EXPECT_EQ(packed_tiny->pack_hash, result->new_packs[0].pack_hash);
    EXPECT_TRUE(history::valid_storage_manifest(result->target_manifest, tree));
}

} // namespace
