#include "application/observation/file_metadata.hpp"

#include <cstdint>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <gtest/gtest.h>

namespace {

namespace fs = std::filesystem;
using kasumi::application::observation::cache::describe_metadata_error;
using kasumi::application::observation::cache::EntryKind;
using kasumi::application::observation::cache::FileIdentity;
using kasumi::application::observation::cache::FileMetadata;
using kasumi::application::observation::cache::FileMetadataError;
using kasumi::application::observation::cache::FileMetadataErrorCode;
using kasumi::application::observation::cache::posix_timespec_to_unix_nanoseconds;
using kasumi::application::observation::cache::read_file_metadata;
using kasumi::application::observation::cache::windows_filetime_to_unix_nanoseconds;

// Helper RAII directory for tests
class TempDirFixture {
public:
    TempDirFixture() {
        const auto temp_base = fs::temp_directory_path();
        path_ = temp_base / ("kasumi_file_metadata_test_" + std::to_string(::getpid()) + "_" +
                             std::to_string(reinterpret_cast<std::uintptr_t>(this)));
        fs::create_directories(path_);
    }

    ~TempDirFixture() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }

    const fs::path& path() const noexcept {
        return path_;
    }

private:
    fs::path path_;
};

// ============================================================================
// 1. Pure Timestamp Conversion Tests
// ============================================================================

TEST(FileMetadataTimestampTest, PosixTimespecUnixEpoch) {
    const auto ns = posix_timespec_to_unix_nanoseconds(0, 0);
    ASSERT_TRUE(ns.has_value());
    EXPECT_EQ(*ns, 0);
}

TEST(FileMetadataTimestampTest, PosixTimespecPositiveDateWithSubsecond) {
    // 2026-03-20 12:00:00.123456789 UTC
    const auto ns = posix_timespec_to_unix_nanoseconds(1774008000, 123456789);
    ASSERT_TRUE(ns.has_value());
    EXPECT_EQ(*ns, 1774008000123456789LL);
}

TEST(FileMetadataTimestampTest, PosixTimespecBefore1970) {
    // 1969-12-31 23:59:59.500000000 UTC (-1s + 500ms = -500ms)
    const auto ns = posix_timespec_to_unix_nanoseconds(-1, 500000000);
    ASSERT_TRUE(ns.has_value());
    EXPECT_EQ(*ns, -500000000LL);

    // 1969-12-31 23:59:59.000000000 UTC (-1s)
    const auto ns_exact = posix_timespec_to_unix_nanoseconds(-1, 0);
    ASSERT_TRUE(ns_exact.has_value());
    EXPECT_EQ(*ns_exact, -1000000000LL);
}

TEST(FileMetadataTimestampTest, PosixTimespecInvalidNsecFraction) {
    // Negative nanoseconds fraction
    EXPECT_FALSE(posix_timespec_to_unix_nanoseconds(100, -1).has_value());

    // Nanoseconds >= 1'000'000'000
    EXPECT_FALSE(posix_timespec_to_unix_nanoseconds(100, 1000000000).has_value());
    EXPECT_FALSE(posix_timespec_to_unix_nanoseconds(100, 2000000000).has_value());
}

TEST(FileMetadataTimestampTest, PosixTimespecOverflowAndUnderflow) {
    constexpr std::int64_t kMaxSec = 9223372036LL;
    constexpr std::int64_t kMinSec = -9223372036LL;
    constexpr std::int64_t kMaxNsec = 854775807LL;

    // Max safe value -> INT64_MAX
    const auto max_safe = posix_timespec_to_unix_nanoseconds(kMaxSec, kMaxNsec);
    ASSERT_TRUE(max_safe.has_value());
    EXPECT_EQ(*max_safe, std::numeric_limits<std::int64_t>::max());

    // 1 nanosecond beyond INT64_MAX
    EXPECT_FALSE(posix_timespec_to_unix_nanoseconds(kMaxSec, kMaxNsec + 1).has_value());

    // 1 second beyond max safe seconds
    EXPECT_FALSE(posix_timespec_to_unix_nanoseconds(kMaxSec + 1, 0).has_value());

    // 1 second below min safe seconds
    EXPECT_FALSE(posix_timespec_to_unix_nanoseconds(kMinSec - 1, 0).has_value());
}

TEST(FileMetadataTimestampTest, WindowsFiletimeUnixEpoch) {
    // Unix Epoch in 100ns ticks = 116444736000000000
    constexpr std::int64_t kEpochTicks = 116444736000000000LL;
    const auto ns = windows_filetime_to_unix_nanoseconds(kEpochTicks);
    ASSERT_TRUE(ns.has_value());
    EXPECT_EQ(*ns, 0);
}

TEST(FileMetadataTimestampTest, WindowsFiletimePositiveDateWith100nsPrecision) {
    constexpr std::int64_t kEpochTicks = 116444736000000000LL;
    // 1 tick = 100 nanoseconds
    const auto ns_one_tick = windows_filetime_to_unix_nanoseconds(kEpochTicks + 1);
    ASSERT_TRUE(ns_one_tick.has_value());
    EXPECT_EQ(*ns_one_tick, 100);

    // 10'000'000 ticks = 1 second = 1'000'000'000 ns
    const auto ns_one_sec = windows_filetime_to_unix_nanoseconds(kEpochTicks + 10000000LL);
    ASSERT_TRUE(ns_one_sec.has_value());
    EXPECT_EQ(*ns_one_sec, 1000000000LL);
}

TEST(FileMetadataTimestampTest, WindowsFiletimeBefore1970) {
    constexpr std::int64_t kEpochTicks = 116444736000000000LL;
    // 1 tick before Unix Epoch
    const auto ns_before = windows_filetime_to_unix_nanoseconds(kEpochTicks - 1);
    ASSERT_TRUE(ns_before.has_value());
    EXPECT_EQ(*ns_before, -100LL);
}

TEST(FileMetadataTimestampTest, WindowsFiletimeYear1601OverflowsInt64Nanoseconds) {
    // Year 1601 (tick = 0) is ~369 years before 1970.
    // In int64 nanoseconds, maximum span is ~292 years.
    // Year 1601 cannot fit in int64 nanoseconds and must safely return nullopt.
    EXPECT_FALSE(windows_filetime_to_unix_nanoseconds(0).has_value());
}

TEST(FileMetadataTimestampTest, WindowsFiletimeOverflowAndUnderflow) {
    constexpr std::int64_t kEpochTicks = 116444736000000000LL;
    constexpr std::int64_t kMaxTicksSinceEpoch = 92233720368547758LL;
    constexpr std::int64_t kMinTicksSinceEpoch = -92233720368547758LL;

    const auto max_safe = windows_filetime_to_unix_nanoseconds(kEpochTicks + kMaxTicksSinceEpoch);
    ASSERT_TRUE(max_safe.has_value());
    EXPECT_EQ(*max_safe, 9223372036854775800LL);

    // 1 tick beyond max
    EXPECT_FALSE(windows_filetime_to_unix_nanoseconds(kEpochTicks + kMaxTicksSinceEpoch + 1).has_value());

    // Min safe
    const auto min_safe = windows_filetime_to_unix_nanoseconds(kEpochTicks + kMinTicksSinceEpoch);
    ASSERT_TRUE(min_safe.has_value());
    EXPECT_EQ(*min_safe, -9223372036854775800LL);

    // 1 tick below min
    EXPECT_FALSE(windows_filetime_to_unix_nanoseconds(kEpochTicks + kMinTicksSinceEpoch - 1).has_value());
}

// ============================================================================
// 2. Native Filesystem Tests (Linux / POSIX)
// ============================================================================

TEST(FileMetadataNativeTest, ExistingRegularFileReturnsValidMetadata) {
    TempDirFixture fixture;
    const auto file_path = fixture.path() / "sample.bin";
    const std::string content = "Kasumi Unified Observation Contract 2.2 Content";

    {
        std::ofstream ofs(file_path, std::ios::binary);
        ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
    }

    const std::string_view logical_path = "data/sample.bin";
    const auto result = read_file_metadata(file_path, logical_path);

    ASSERT_TRUE(result.has_value()) << "Failed with error: " << result.error().message;
    ASSERT_TRUE(result->has_value()) << "Expected regular file to produce metadata";

    const auto& meta = **result;
    EXPECT_TRUE(meta.is_valid);
    EXPECT_EQ(meta.path, logical_path);
    EXPECT_EQ(meta.kind, EntryKind::RegularFile);
    EXPECT_EQ(meta.size, content.size());
    ASSERT_TRUE(meta.identity.has_value());

    // Compare directly against lstat
    struct stat st{};
    ASSERT_EQ(::lstat(file_path.c_str(), &st), 0);
    EXPECT_EQ(meta.identity->volume, static_cast<std::uint64_t>(st.st_dev));
    EXPECT_EQ(meta.identity->file_low, static_cast<std::uint64_t>(st.st_ino));
    EXPECT_EQ(meta.identity->file_high, 0ULL);

    const auto expected_mtime = posix_timespec_to_unix_nanoseconds(st.st_mtim.tv_sec, st.st_mtim.tv_nsec);
    ASSERT_TRUE(expected_mtime.has_value());
    EXPECT_EQ(meta.mtime_nanoseconds, *expected_mtime);
}

TEST(FileMetadataNativeTest, EmptyRegularFileReturnsValidMetadata) {
    TempDirFixture fixture;
    const auto file_path = fixture.path() / "empty.txt";

    {
        std::ofstream ofs(file_path, std::ios::binary);
    }

    const auto result = read_file_metadata(file_path, "empty.txt");
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->has_value());

    const auto& meta = **result;
    EXPECT_TRUE(meta.is_valid);
    EXPECT_EQ(meta.size, 0ULL);
    EXPECT_EQ(meta.kind, EntryKind::RegularFile);
    EXPECT_TRUE(meta.identity.has_value());
}

TEST(FileMetadataNativeTest, LogicalPathPreservedWithoutAllocation) {
    TempDirFixture fixture;
    const auto file_path = fixture.path() / "test.txt";
    {
        std::ofstream ofs(file_path);
        ofs << "test";
    }

    const std::string logical_str = "deeply/nested/path/to/test.txt";
    const auto result = read_file_metadata(file_path, logical_str);
    ASSERT_TRUE(result.has_value() && result->has_value());

    EXPECT_EQ((**result).path.data(), logical_str.data());
    EXPECT_EQ((**result).path, logical_str);
}

TEST(FileMetadataNativeTest, NonExistentFileReturnsNotFoundError) {
    TempDirFixture fixture;
    const auto file_path = fixture.path() / "does_not_exist.bin";

    const auto result = read_file_metadata(file_path, "missing.bin");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FileMetadataErrorCode::NotFound);
    EXPECT_STREQ(describe_metadata_error(result.error().code), "NotFound");
}

TEST(FileMetadataNativeTest, DirectoryReturnsNulloptIneligible) {
    TempDirFixture fixture;
    const auto sub_dir = fixture.path() / "subdirectory";
    fs::create_directories(sub_dir);

    const auto result = read_file_metadata(sub_dir, "subdirectory");
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->has_value()) << "Directory must not produce regular file cache metadata";
}

TEST(FileMetadataNativeTest, SymlinkToRegularFileReturnsNulloptIneligible) {
    TempDirFixture fixture;
    const auto target_file = fixture.path() / "target.txt";
    const auto symlink_file = fixture.path() / "symlink.txt";

    {
        std::ofstream ofs(target_file);
        ofs << "target payload";
    }

    std::error_code ec;
    fs::create_symlink(target_file, symlink_file, ec);
    ASSERT_FALSE(ec) << ec.message();

    const auto result = read_file_metadata(symlink_file, "symlink.txt");
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->has_value())
        << "Symlink must not be followed and must be ineligible for regular file cache metadata";
}

TEST(FileMetadataNativeTest, DanglingSymlinkReturnsNulloptIneligible) {
    TempDirFixture fixture;
    const auto missing_target = fixture.path() / "missing_target.txt";
    const auto symlink_file = fixture.path() / "dangling_symlink.txt";

    std::error_code ec;
    fs::create_symlink(missing_target, symlink_file, ec);
    ASSERT_FALSE(ec) << ec.message();

    const auto result = read_file_metadata(symlink_file, "dangling.txt");
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->has_value())
        << "Dangling symlink must not report NotFound error; lstat sees the symlink entry";
}

TEST(FileMetadataNativeTest, FileSizeModificationReflectedInMetadata) {
    TempDirFixture fixture;
    const auto file_path = fixture.path() / "mutate_size.txt";

    {
        std::ofstream ofs(file_path, std::ios::binary);
        ofs << "Initial";
    }

    const auto meta1 = read_file_metadata(file_path, "file.txt");
    ASSERT_TRUE(meta1.has_value() && meta1->has_value());
    EXPECT_EQ((**meta1).size, 7ULL);

    {
        std::ofstream ofs(file_path, std::ios::binary | std::ios::app);
        ofs << " + Appended";
    }

    const auto meta2 = read_file_metadata(file_path, "file.txt");
    ASSERT_TRUE(meta2.has_value() && meta2->has_value());
    EXPECT_EQ((**meta2).size, 18ULL);
}

TEST(FileMetadataNativeTest, MtimeModificationReflectedInMetadata) {
    TempDirFixture fixture;
    const auto file_path = fixture.path() / "mutate_mtime.txt";

    {
        std::ofstream ofs(file_path);
        ofs << "Timestamp test";
    }

    // Explicitly set timestamp via utimensat
    struct timespec ts[2];
    ts[0].tv_sec = 1700000000;
    ts[0].tv_nsec = 100000000;
    ts[1].tv_sec = 1700000000;
    ts[1].tv_nsec = 200000000;
    ASSERT_EQ(::utimensat(AT_FDCWD, file_path.c_str(), ts, 0), 0);

    const auto meta1 = read_file_metadata(file_path, "file.txt");
    ASSERT_TRUE(meta1.has_value() && meta1->has_value());
    EXPECT_EQ((**meta1).mtime_nanoseconds, 1700000000200000000LL);

    // Modify mtime by 1 nanosecond
    ts[1].tv_nsec = 200000001;
    ASSERT_EQ(::utimensat(AT_FDCWD, file_path.c_str(), ts, 0), 0);

    const auto meta2 = read_file_metadata(file_path, "file.txt");
    ASSERT_TRUE(meta2.has_value() && meta2->has_value());
    EXPECT_EQ((**meta2).mtime_nanoseconds, 1700000000200000001LL);
}

TEST(FileMetadataNativeTest, AtomicReplacementChangesFileIdentity) {
    TempDirFixture fixture;
    const auto target_path = fixture.path() / "target.txt";
    const auto temp_path = fixture.path() / "temp.txt";

    {
        std::ofstream ofs(target_path);
        ofs << "Original";
    }

    const auto meta1 = read_file_metadata(target_path, "target.txt");
    ASSERT_TRUE(meta1.has_value() && meta1->has_value());
    const auto original_id = (**meta1).identity;
    ASSERT_TRUE(original_id.has_value());

    {
        std::ofstream ofs(temp_path);
        ofs << "Replaced";
    }

    // Atomic rename over target
    ASSERT_EQ(::rename(temp_path.c_str(), target_path.c_str()), 0);

    const auto meta2 = read_file_metadata(target_path, "target.txt");
    ASSERT_TRUE(meta2.has_value() && meta2->has_value());
    const auto new_id = (**meta2).identity;
    ASSERT_TRUE(new_id.has_value());

    // Inode must be different, capturing atomic replacement
    EXPECT_NE(original_id->file_low, new_id->file_low);
}

TEST(FileMetadataNativeTest, PermissionDeniedErrorDetected) {
    if (::geteuid() == 0) {
        GTEST_SKIP() << "Running as root bypasses filesystem permission checks";
    }

    TempDirFixture fixture;
    const auto restricted_dir = fixture.path() / "no_access_dir";
    fs::create_directories(restricted_dir);

    const auto file_path = restricted_dir / "secret.txt";
    {
        std::ofstream ofs(file_path);
        ofs << "secret";
    }

    // Remove execute permission on parent directory so lstat fails with EACCES
    ASSERT_EQ(::chmod(restricted_dir.c_str(), 0000), 0);

    const auto result = read_file_metadata(file_path, "secret.txt");

    // Restore permissions before asserts so cleanup succeeds
    ::chmod(restricted_dir.c_str(), 0755);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FileMetadataErrorCode::PermissionDenied);
}

} // namespace

