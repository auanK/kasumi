#include "application/observation/cache_contract.hpp"

#include <cstdint>
#include <limits>
#include <string>
#include <gtest/gtest.h>

namespace {

using kasumi::application::observation::cache::CacheReuseResult;
using kasumi::application::observation::cache::can_reuse_cached_hash;
using kasumi::application::observation::cache::describe_result;
using kasumi::application::observation::cache::EntryKind;
using kasumi::application::observation::cache::evaluate_cache_reuse;
using kasumi::application::observation::cache::FileIdentity;
using kasumi::application::observation::cache::FileMetadata;

FileMetadata make_valid_metadata() {
    return FileMetadata{
        .path = "documents/tax_return_2026.pdf",
        .kind = EntryKind::RegularFile,
        .size = 2048576,
        .mtime_nanoseconds = 1774000000123456789LL,
        .identity = FileIdentity{.volume = 0x12345678ULL, .file_low = 1001ULL, .file_high = 2002ULL},
        .is_valid = true,
    };
}

TEST(CacheContractTest, IdenticalMetadataAuthorizesHashReuse) {
    const auto cached = make_valid_metadata();
    const auto current = make_valid_metadata();

    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::Reusable);
    EXPECT_TRUE(can_reuse_cached_hash(cached, current));
    EXPECT_STREQ(describe_result(CacheReuseResult::Reusable), "Reusable");
}

TEST(CacheContractTest, DefaultConstructedStructsTriggerCacheMiss) {
    FileMetadata empty_cached{};
    FileMetadata empty_current{};

    EXPECT_FALSE(empty_cached.is_valid);
    EXPECT_FALSE(empty_current.is_valid);
    EXPECT_EQ(empty_cached.kind, EntryKind::Other);
    EXPECT_EQ(empty_current.kind, EntryKind::Other);
    EXPECT_FALSE(empty_cached.identity.has_value());
    EXPECT_FALSE(empty_current.identity.has_value());

    EXPECT_EQ(evaluate_cache_reuse(empty_cached, empty_current),
              CacheReuseResult::InvalidCachedEntry);
    EXPECT_FALSE(can_reuse_cached_hash(empty_cached, empty_current));
}

TEST(CacheContractTest, PartiallyInitializedStructsTriggerCacheMiss) {
    // Only path and is_valid set, kind is Other
    FileMetadata partial_cached{
        .path = "test.txt",
        .is_valid = true,
    };
    FileMetadata partial_current{
        .path = "test.txt",
        .is_valid = true,
    };

    EXPECT_EQ(evaluate_cache_reuse(partial_cached, partial_current),
              CacheReuseResult::NotRegularFile);
    EXPECT_FALSE(can_reuse_cached_hash(partial_cached, partial_current));

    // Kind set to RegularFile, but identity missing
    partial_cached.kind = EntryKind::RegularFile;
    partial_current.kind = EntryKind::RegularFile;
    EXPECT_EQ(evaluate_cache_reuse(partial_cached, partial_current),
              CacheReuseResult::MissingRequiredIdentity);
    EXPECT_FALSE(can_reuse_cached_hash(partial_cached, partial_current));
}

TEST(CacheContractTest, InvalidCacheEntryTriggersCacheMiss) {
    auto cached = make_valid_metadata();
    cached.is_valid = false;
    const auto current = make_valid_metadata();

    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::InvalidCachedEntry);
    EXPECT_FALSE(can_reuse_cached_hash(cached, current));
    EXPECT_STREQ(describe_result(CacheReuseResult::InvalidCachedEntry), "InvalidCachedEntry");
}

TEST(CacheContractTest, InvalidCurrentMetadataTriggersCacheMiss) {
    const auto cached = make_valid_metadata();
    auto current = make_valid_metadata();
    current.is_valid = false;

    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::InvalidCurrentMetadata);
    EXPECT_FALSE(can_reuse_cached_hash(cached, current));
    EXPECT_STREQ(describe_result(CacheReuseResult::InvalidCurrentMetadata), "InvalidCurrentMetadata");
}

TEST(CacheContractTest, NonRegularFileKindsTriggerCacheMiss) {
    const auto cached = make_valid_metadata();

    auto dir_current = make_valid_metadata();
    dir_current.kind = EntryKind::Directory;
    EXPECT_EQ(evaluate_cache_reuse(cached, dir_current), CacheReuseResult::NotRegularFile);
    EXPECT_FALSE(can_reuse_cached_hash(cached, dir_current));

    auto symlink_current = make_valid_metadata();
    symlink_current.kind = EntryKind::Symlink;
    EXPECT_EQ(evaluate_cache_reuse(cached, symlink_current), CacheReuseResult::NotRegularFile);
    EXPECT_FALSE(can_reuse_cached_hash(cached, symlink_current));

    auto other_current = make_valid_metadata();
    other_current.kind = EntryKind::Other;
    EXPECT_EQ(evaluate_cache_reuse(cached, other_current), CacheReuseResult::NotRegularFile);
    EXPECT_FALSE(can_reuse_cached_hash(cached, other_current));

    auto dir_cached = cached;
    dir_cached.kind = EntryKind::Directory;
    const auto regular_current = make_valid_metadata();
    EXPECT_EQ(evaluate_cache_reuse(dir_cached, regular_current), CacheReuseResult::NotRegularFile);
    EXPECT_FALSE(can_reuse_cached_hash(dir_cached, regular_current));
}

TEST(CacheContractTest, MissingIdentityInCacheTriggersCacheMiss) {
    auto cached = make_valid_metadata();
    cached.identity = std::nullopt;
    const auto current = make_valid_metadata();

    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::MissingRequiredIdentity);
    EXPECT_FALSE(can_reuse_cached_hash(cached, current));
    EXPECT_STREQ(describe_result(CacheReuseResult::MissingRequiredIdentity), "MissingRequiredIdentity");
}

TEST(CacheContractTest, MissingIdentityInCurrentTriggersCacheMiss) {
    const auto cached = make_valid_metadata();
    auto current = make_valid_metadata();
    current.identity = std::nullopt;

    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::MissingRequiredIdentity);
    EXPECT_FALSE(can_reuse_cached_hash(cached, current));
}

TEST(CacheContractTest, MissingIdentityInBothTriggersCacheMiss) {
    auto cached = make_valid_metadata();
    cached.identity = std::nullopt;
    auto current = make_valid_metadata();
    current.identity = std::nullopt;

    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::MissingRequiredIdentity);
    EXPECT_FALSE(can_reuse_cached_hash(cached, current));
}

TEST(CacheContractTest, Full192BitIdentityMatchingAuthorizesReuse) {
    auto cached = make_valid_metadata();
    cached.identity = FileIdentity{
        .volume = 0xABCDEF0123456789ULL,
        .file_low = 0x1122334455667788ULL,
        .file_high = 0x99AABBCCDDEEFF00ULL,
    };
    auto current = cached;

    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::Reusable);
    EXPECT_TRUE(can_reuse_cached_hash(cached, current));
}

TEST(CacheContractTest, VolumeIdentifierMutationTriggersCacheMiss) {
    const auto cached = make_valid_metadata();
    auto current = cached;
    current.identity->volume ^= 1ULL;

    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::IdentityMismatch);
    EXPECT_FALSE(can_reuse_cached_hash(cached, current));
    EXPECT_STREQ(describe_result(CacheReuseResult::IdentityMismatch), "IdentityMismatch");
}

TEST(CacheContractTest, FileLowIdentifierMutationTriggersCacheMiss) {
    const auto cached = make_valid_metadata();
    auto current = cached;
    current.identity->file_low ^= 1ULL;

    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::IdentityMismatch);
    EXPECT_FALSE(can_reuse_cached_hash(cached, current));
}

TEST(CacheContractTest, FileHighIdentifierMutationTriggersCacheMiss) {
    const auto cached = make_valid_metadata();
    auto current = cached;
    current.identity->file_high ^= 1ULL;

    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::IdentityMismatch);
    EXPECT_FALSE(can_reuse_cached_hash(cached, current));
}

TEST(CacheContractTest, ZeroComponentIdentityHandledAccurately) {
    // Identity with all components equal to 0
    auto cached = make_valid_metadata();
    cached.identity = FileIdentity{.volume = 0, .file_low = 0, .file_high = 0};
    auto current = cached;

    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::Reusable);
    EXPECT_TRUE(can_reuse_cached_hash(cached, current));

    // Changing one component away from 0 triggers miss
    current.identity->volume = 1;
    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::IdentityMismatch);
    EXPECT_FALSE(can_reuse_cached_hash(cached, current));

    current.identity->volume = 0;
    current.identity->file_low = 1;
    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::IdentityMismatch);
    EXPECT_FALSE(can_reuse_cached_hash(cached, current));

    current.identity->file_low = 0;
    current.identity->file_high = 1;
    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::IdentityMismatch);
    EXPECT_FALSE(can_reuse_cached_hash(cached, current));
}

TEST(CacheContractTest, PathMismatchTriggersCacheMiss) {
    const auto cached = make_valid_metadata();
    auto current = cached;
    current.path = "documents/other_file.pdf";

    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::PathMismatch);
    EXPECT_FALSE(can_reuse_cached_hash(cached, current));
    EXPECT_STREQ(describe_result(CacheReuseResult::PathMismatch), "PathMismatch");
}

TEST(CacheContractTest, EmptyPathTriggersCacheMiss) {
    auto cached = make_valid_metadata();
    auto current = cached;
    cached.path = "";
    current.path = "";

    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::PathMismatch);
    EXPECT_FALSE(can_reuse_cached_hash(cached, current));

    // One empty, one non-empty
    cached.path = "file.txt";
    current.path = "";
    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::PathMismatch);
    EXPECT_FALSE(can_reuse_cached_hash(cached, current));
}

TEST(CacheContractTest, SizeChangeTriggersCacheMiss) {
    const auto cached = make_valid_metadata();
    auto current = cached;
    current.size += 1;

    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::SizeMismatch);
    EXPECT_FALSE(can_reuse_cached_hash(cached, current));
    EXPECT_STREQ(describe_result(CacheReuseResult::SizeMismatch), "SizeMismatch");
}

TEST(CacheContractTest, MtimeChangeTriggersCacheMiss) {
    const auto cached = make_valid_metadata();
    auto current = cached;
    current.mtime_nanoseconds += 1000;

    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::MtimeMismatch);
    EXPECT_FALSE(can_reuse_cached_hash(cached, current));
    EXPECT_STREQ(describe_result(CacheReuseResult::MtimeMismatch), "MtimeMismatch");
}

TEST(CacheContractTest, SubsecondTimestampPrecisionDifferentiatesMutations) {
    auto cached = make_valid_metadata();
    cached.mtime_nanoseconds = 1700000000000000000LL; // Exactly on the second boundary
    auto current = cached;

    // 1 nanosecond mutation must be detected
    current.mtime_nanoseconds = 1700000000000000001LL;
    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::MtimeMismatch);
    EXPECT_FALSE(can_reuse_cached_hash(cached, current));

    // Microsecond-precision filesystem (ending in 000 ns)
    cached.mtime_nanoseconds = 1700000000123456000LL;
    current.mtime_nanoseconds = 1700000000123456000LL;
    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::Reusable);
    EXPECT_TRUE(can_reuse_cached_hash(cached, current));
}

TEST(CacheContractTest, NegativeTimestampHandledAccurately) {
    auto cached = make_valid_metadata();
    cached.mtime_nanoseconds = -1234567890123LL; // Before Unix Epoch 1970
    auto current = cached;

    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::Reusable);
    EXPECT_TRUE(can_reuse_cached_hash(cached, current));

    current.mtime_nanoseconds = -1234567890124LL;
    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::MtimeMismatch);
    EXPECT_FALSE(can_reuse_cached_hash(cached, current));
}

TEST(CacheContractTest, BoundaryTimestampsHandledAccurately) {
    auto cached = make_valid_metadata();
    cached.mtime_nanoseconds = std::numeric_limits<std::int64_t>::max();
    auto current = cached;

    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::Reusable);
    EXPECT_TRUE(can_reuse_cached_hash(cached, current));

    cached.mtime_nanoseconds = std::numeric_limits<std::int64_t>::min();
    current.mtime_nanoseconds = std::numeric_limits<std::int64_t>::min();
    EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::Reusable);
    EXPECT_TRUE(can_reuse_cached_hash(cached, current));
}

TEST(CacheContractTest, ZeroAndHugeSizesHandledWithoutOverflow) {
    // Zero size (empty file)
    auto cached_zero = make_valid_metadata();
    cached_zero.size = 0;
    auto current_zero = cached_zero;
    EXPECT_EQ(evaluate_cache_reuse(cached_zero, current_zero), CacheReuseResult::Reusable);
    EXPECT_TRUE(can_reuse_cached_hash(cached_zero, current_zero));

    // Huge size (100 GB)
    auto cached_huge = make_valid_metadata();
    cached_huge.size = 100ULL * 1024ULL * 1024ULL * 1024ULL;
    auto current_huge = cached_huge;
    EXPECT_EQ(evaluate_cache_reuse(cached_huge, current_huge), CacheReuseResult::Reusable);
    EXPECT_TRUE(can_reuse_cached_hash(cached_huge, current_huge));

    // Maximum uint64 size
    cached_huge.size = std::numeric_limits<std::uint64_t>::max();
    current_huge.size = std::numeric_limits<std::uint64_t>::max();
    EXPECT_EQ(evaluate_cache_reuse(cached_huge, current_huge), CacheReuseResult::Reusable);
    EXPECT_TRUE(can_reuse_cached_hash(cached_huge, current_huge));
}

TEST(CacheContractTest, LinuxSyntheticIdentityNormalizedAndEvaluated) {
    // Linux representation: volume = dev_t, file_low = ino_t, file_high = 0
    FileMetadata linux_cached{
        .path = "shared/code.cpp",
        .kind = EntryKind::RegularFile,
        .size = 4096,
        .mtime_nanoseconds = 1750000000000000000LL,
        .identity = FileIdentity{.volume = 2050ULL, .file_low = 1459201ULL, .file_high = 0ULL},
        .is_valid = true,
    };
    auto linux_current = linux_cached;

    EXPECT_EQ(evaluate_cache_reuse(linux_cached, linux_current), CacheReuseResult::Reusable);
    EXPECT_TRUE(can_reuse_cached_hash(linux_cached, linux_current));

    // Inode change triggers miss
    linux_current.identity->file_low = 1459202ULL;
    EXPECT_EQ(evaluate_cache_reuse(linux_cached, linux_current), CacheReuseResult::IdentityMismatch);
    EXPECT_FALSE(can_reuse_cached_hash(linux_cached, linux_current));
}

TEST(CacheContractTest, WindowsSyntheticIdentityNormalizedAndEvaluated) {
    // Windows representation: volume = VolumeSerialNumber, file_low/high = FILE_ID_128
    FileMetadata win_cached{
        .path = "shared/code.cpp",
        .kind = EntryKind::RegularFile,
        .size = 4096,
        .mtime_nanoseconds = 1750000000000000000LL,
        .identity = FileIdentity{
            .volume = 0x38472910ULL,
            .file_low = 0x000100000000002AULL,
            .file_high = 0x000200000000005FULL,
        },
        .is_valid = true,
    };
    auto win_current = win_cached;

    EXPECT_EQ(evaluate_cache_reuse(win_cached, win_current), CacheReuseResult::Reusable);
    EXPECT_TRUE(can_reuse_cached_hash(win_cached, win_current));

    // FileId high 64 bits change triggers miss
    win_current.identity->file_high = 0x0002000000000060ULL;
    EXPECT_EQ(evaluate_cache_reuse(win_cached, win_current), CacheReuseResult::IdentityMismatch);
    EXPECT_FALSE(can_reuse_cached_hash(win_cached, win_current));
}

TEST(CacheContractTest, EvaluationIsDeterministicAndIdempotent) {
    const auto cached = make_valid_metadata();
    const auto current = make_valid_metadata();

    for (int i = 0; i < 1000; ++i) {
        EXPECT_EQ(evaluate_cache_reuse(cached, current), CacheReuseResult::Reusable);
        EXPECT_TRUE(can_reuse_cached_hash(cached, current));
    }
}

} // namespace
