#include "application/observation/file_metadata.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <expected>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <gtest/gtest.h>
#include <gtest/gtest-spi.h>

#include "crypto/content.hpp"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <vector>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

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
        static std::atomic<std::uint64_t> counter{0};
        const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        const auto temp_base = fs::temp_directory_path();
        path_ = temp_base / ("kasumi_file_metadata_test_" + std::to_string(now) + "_" +
                             std::to_string(counter.fetch_add(1)) + "_" +
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
    constexpr std::int64_t kMaxNsec = 854775807LL;

    // Max safe value -> INT64_MAX
    const auto max_safe = posix_timespec_to_unix_nanoseconds(kMaxSec, kMaxNsec);
    ASSERT_TRUE(max_safe.has_value());
    EXPECT_EQ(*max_safe, std::numeric_limits<std::int64_t>::max());

    // 1 nanosecond beyond INT64_MAX
    EXPECT_FALSE(posix_timespec_to_unix_nanoseconds(kMaxSec, kMaxNsec + 1).has_value());

    // 1 second beyond max safe seconds
    EXPECT_FALSE(posix_timespec_to_unix_nanoseconds(kMaxSec + 1, 0).has_value());
}

TEST(FileMetadataTimestampTest, PosixTimespecInt64MinBoundary) {
    // sec = -9223372037, nsec = 145224192 is exactly INT64_MIN (-9223372036854775808)
    constexpr std::int64_t kExactSec = -9223372037LL;
    constexpr std::int64_t kExactNsec = 145224192LL;

    const auto exact_min = posix_timespec_to_unix_nanoseconds(kExactSec, kExactNsec);
    ASSERT_TRUE(exact_min.has_value());
    EXPECT_EQ(*exact_min, std::numeric_limits<std::int64_t>::min());

    // 1 nanosecond above INT64_MIN: must be accepted
    const auto one_above = posix_timespec_to_unix_nanoseconds(kExactSec, kExactNsec + 1);
    ASSERT_TRUE(one_above.has_value());
    EXPECT_EQ(*one_above, std::numeric_limits<std::int64_t>::min() + 1);

    // 1 nanosecond below INT64_MIN: must be rejected (underflow)
    const auto one_below = posix_timespec_to_unix_nanoseconds(kExactSec, kExactNsec - 1);
    EXPECT_FALSE(one_below.has_value());

    // 1 second below min safe seconds: must be rejected
    EXPECT_FALSE(posix_timespec_to_unix_nanoseconds(kExactSec - 1, 0).has_value());
}

TEST(FileMetadataTimestampTest, WindowsFiletimeUnixEpoch) {
    // Unix Epoch in 100ns ticks = 116444736000000000
    constexpr std::uint64_t kEpochTicks = 116444736000000000ULL;
    const auto ns = windows_filetime_to_unix_nanoseconds(kEpochTicks);
    ASSERT_TRUE(ns.has_value());
    EXPECT_EQ(*ns, 0);
}

TEST(FileMetadataTimestampTest, WindowsFiletimePositiveDateWith100nsPrecision) {
    constexpr std::uint64_t kEpochTicks = 116444736000000000ULL;
    // 1 tick = 100 nanoseconds
    const auto ns_one_tick = windows_filetime_to_unix_nanoseconds(kEpochTicks + 1ULL);
    ASSERT_TRUE(ns_one_tick.has_value());
    EXPECT_EQ(*ns_one_tick, 100);

    // 10'000'000 ticks = 1 second = 1'000'000'000 ns
    const auto ns_one_sec = windows_filetime_to_unix_nanoseconds(kEpochTicks + 10000000ULL);
    ASSERT_TRUE(ns_one_sec.has_value());
    EXPECT_EQ(*ns_one_sec, 1000000000LL);
}

TEST(FileMetadataTimestampTest, WindowsFiletimeBefore1970) {
    constexpr std::uint64_t kEpochTicks = 116444736000000000ULL;
    // 1 tick before Unix Epoch
    const auto ns_before = windows_filetime_to_unix_nanoseconds(kEpochTicks - 1ULL);
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
    constexpr std::uint64_t kEpochTicks = 116444736000000000ULL;
    constexpr std::uint64_t kMaxTicksSinceEpoch = 92233720368547758ULL;
    constexpr std::uint64_t kMinTicksSinceEpoch = 92233720368547758ULL;

    const auto max_safe = windows_filetime_to_unix_nanoseconds(kEpochTicks + kMaxTicksSinceEpoch);
    ASSERT_TRUE(max_safe.has_value());
    EXPECT_EQ(*max_safe, 9223372036854775800LL);

    // 1 tick beyond max
    EXPECT_FALSE(windows_filetime_to_unix_nanoseconds(kEpochTicks + kMaxTicksSinceEpoch + 1ULL).has_value());

    // Min safe
    const auto min_safe = windows_filetime_to_unix_nanoseconds(kEpochTicks - kMinTicksSinceEpoch);
    ASSERT_TRUE(min_safe.has_value());
    EXPECT_EQ(*min_safe, -9223372036854775800LL);

    // 1 tick below min
    EXPECT_FALSE(windows_filetime_to_unix_nanoseconds(kEpochTicks - kMinTicksSinceEpoch - 1ULL).has_value());
}

TEST(FileMetadataTimestampTest, WindowsFiletimeUint64Boundaries) {
    // UINT64_MAX would overflow signed int64 if cast implicitly
    EXPECT_FALSE(windows_filetime_to_unix_nanoseconds(
        std::numeric_limits<std::uint64_t>::max()).has_value());
    EXPECT_FALSE(windows_filetime_to_unix_nanoseconds(
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) + 1ULL).has_value());
}

// ============================================================================
// 2. Native Filesystem Tests (Linux / POSIX)
// ============================================================================

#if !defined(_WIN32)
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
    EXPECT_EQ(result.error().os_error, static_cast<std::uint32_t>(ENOENT));
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
    EXPECT_EQ(result.error().os_error, static_cast<std::uint32_t>(EACCES));
}
#endif // !defined(_WIN32)

#if defined(_WIN32)
// ============================================================================
// 3. Native Filesystem Tests (Windows / Win32)
// ============================================================================

TEST(FileMetadataWin32NativeTest, ExistingRegularFileReturnsValidMetadata) {
    TempDirFixture fixture;
    const auto file_path = fixture.path() / "sample.bin";
    const std::string content = "Windows Native Metadata Test Content";

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

    // Compare directly against native FILE_ID_INFO
    HANDLE hFile = ::CreateFileW(
        file_path.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr);
    ASSERT_NE(hFile, INVALID_HANDLE_VALUE);

    FILE_ID_INFO expected_id{};
    const BOOL id_ok = ::GetFileInformationByHandleEx(
        hFile, FileIdInfo, &expected_id, sizeof(expected_id));
    ::CloseHandle(hFile);
    ASSERT_TRUE(id_ok);

    std::uint64_t expected_low = 0;
    std::uint64_t expected_high = 0;
    std::memcpy(&expected_low, expected_id.FileId.Identifier, sizeof(std::uint64_t));
    std::memcpy(&expected_high, expected_id.FileId.Identifier + sizeof(std::uint64_t), sizeof(std::uint64_t));

    EXPECT_EQ(meta.identity->volume, expected_id.VolumeSerialNumber);
    EXPECT_EQ(meta.identity->file_low, expected_low);
    EXPECT_EQ(meta.identity->file_high, expected_high);
}

TEST(FileMetadataWin32NativeTest, EmptyRegularFileReturnsValidMetadata) {
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

TEST(FileMetadataWin32NativeTest, LogicalPathPreservedWithoutAllocation) {
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

TEST(FileMetadataWin32NativeTest, NonExistentFileReturnsNotFoundError) {
    TempDirFixture fixture;
    const auto file_path = fixture.path() / "does_not_exist.bin";

    const auto result = read_file_metadata(file_path, "missing.bin");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FileMetadataErrorCode::NotFound);
    EXPECT_EQ(result.error().os_error, static_cast<std::uint32_t>(ERROR_FILE_NOT_FOUND));
    EXPECT_STREQ(describe_metadata_error(result.error().code), "NotFound");
}

TEST(FileMetadataWin32NativeTest, DirectoryReturnsNulloptIneligible) {
    TempDirFixture fixture;
    const auto sub_dir = fixture.path() / "subdirectory";
    fs::create_directories(sub_dir);

    const auto result = read_file_metadata(sub_dir, "subdirectory");
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->has_value()) << "Directory must not produce regular file cache metadata";
}

TEST(FileMetadataWin32NativeTest, FileSizeModificationReflectedInMetadata) {
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

TEST(FileMetadataWin32NativeTest, MtimeModificationReflectedInMetadata) {
    TempDirFixture fixture;
    const auto file_path = fixture.path() / "mutate_mtime.txt";

    {
        std::ofstream ofs(file_path);
        ofs << "Timestamp test";
    }

    const auto meta1 = read_file_metadata(file_path, "file.txt");
    ASSERT_TRUE(meta1.has_value() && meta1->has_value());

    // Explicitly modify LastWriteTime using Win32 SetFileTime
    HANDLE hFile = ::CreateFileW(
        file_path.c_str(),
        FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    ASSERT_NE(hFile, INVALID_HANDLE_VALUE);

    FILETIME ft;
    ULARGE_INTEGER uli;
    uli.QuadPart = 133801248000000000ULL;
    ft.dwLowDateTime = uli.LowPart;
    ft.dwHighDateTime = uli.HighPart;
    const BOOL set_ok = ::SetFileTime(hFile, nullptr, nullptr, &ft);
    ::CloseHandle(hFile);
    ASSERT_TRUE(set_ok);

    const auto meta2 = read_file_metadata(file_path, "file.txt");
    ASSERT_TRUE(meta2.has_value() && meta2->has_value());
    const auto expected_ns = windows_filetime_to_unix_nanoseconds(uli.QuadPart);
    ASSERT_TRUE(expected_ns.has_value());
    EXPECT_EQ((**meta2).mtime_nanoseconds, *expected_ns);
}

TEST(FileMetadataWin32NativeTest, FileReplacementChangesIdentity) {
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

    // Atomic replacement using MoveFileExW
    ASSERT_TRUE(::MoveFileExW(temp_path.c_str(), target_path.c_str(), MOVEFILE_REPLACE_EXISTING));

    const auto meta2 = read_file_metadata(target_path, "target.txt");
    ASSERT_TRUE(meta2.has_value() && meta2->has_value());
    const auto new_id = (**meta2).identity;
    ASSERT_TRUE(new_id.has_value());

    // FileId on NTFS must change upon replacement
    EXPECT_TRUE(original_id->file_low != new_id->file_low || original_id->file_high != new_id->file_high);
}

TEST(FileMetadataWin32NativeTest, SymlinkOrReparsePointIneligible) {
    TempDirFixture fixture;
    const auto target_path = fixture.path() / "target.txt";
    const auto symlink_path = fixture.path() / "symlink.txt";

    {
        std::ofstream ofs(target_path);
        ofs << "target payload";
    }

    // Attempt to create symlink (SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE = 0x2)
    BOOLEAN created = ::CreateSymbolicLinkW(
        symlink_path.c_str(), target_path.c_str(), 0x2);
    if (!created) {
        created = ::CreateSymbolicLinkW(symlink_path.c_str(), target_path.c_str(), 0);
    }

    if (!created) {
        const DWORD err = ::GetLastError();
        if (err == ERROR_PRIVILEGE_NOT_HELD || err == ERROR_NOT_SUPPORTED || err == ERROR_INVALID_FUNCTION) {
            GTEST_SKIP() << "Creating symbolic links on Windows requires Developer Mode or SeCreateSymbolicLinkPrivilege (error " << err << ")";
        } else {
            FAIL() << "CreateSymbolicLinkW failed with unexpected error: " << err;
        }
    }

    const auto result = read_file_metadata(symlink_path, "symlink.txt");
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->has_value())
        << "Symlink/reparse point must not produce regular file cache metadata";
}

TEST(FileMetadataWin32NativeTest, SharingViolationOrAccessDeniedDetected) {
    TempDirFixture fixture;
    const auto file_path = fixture.path() / "locked.txt";

    {
        std::ofstream ofs(file_path);
        ofs << "locked content";
    }

    // Lock file with exclusive access (share mode 0)
    HANDLE hLock = ::CreateFileW(
        file_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0, // Exclusive: no sharing allowed
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    ASSERT_NE(hLock, INVALID_HANDLE_VALUE);

    // 1. Consulta de atributos com arquivo bloqueado:
    // FILE_READ_ATTRIBUTES succeeds because Windows NT share mode 0 only restricts
    // read/write data access, not attribute queries.
    const auto meta_result = read_file_metadata(file_path, "locked.txt");
    ASSERT_TRUE(meta_result.has_value());
    ASSERT_TRUE(meta_result->has_value());
    EXPECT_EQ(meta_result->value().size, 14U);

    // 2. Tentativa de leitura de conteúdo com arquivo bloqueado:
    // Fails with ERROR_SHARING_VIOLATION
    HANDLE hRead = ::CreateFileW(
        file_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    EXPECT_EQ(hRead, INVALID_HANDLE_VALUE);
    EXPECT_EQ(::GetLastError(), static_cast<DWORD>(ERROR_SHARING_VIOLATION));

    // 3. Calculo de BLAKE3 com arquivo bloqueado:
    // Cannot read content, so hashing fails
    const auto hash_result = kasumi::crypto::content::hash_file(file_path);
    EXPECT_FALSE(hash_result.has_value());

    // 4. Tentativa de mutacao destrutiva com arquivo bloqueado:
    // Fails with ERROR_SHARING_VIOLATION
    HANDLE hWrite = ::CreateFileW(
        file_path.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    EXPECT_EQ(hWrite, INVALID_HANDLE_VALUE);
    EXPECT_EQ(::GetLastError(), static_cast<DWORD>(ERROR_SHARING_VIOLATION));

    ::CloseHandle(hLock);
}

bool is_dacl_protected(const std::filesystem::path& path) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    const DWORD res = ::GetNamedSecurityInfoW(
        const_cast<LPWSTR>(path.c_str()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &sd);
    if (res != ERROR_SUCCESS || sd == nullptr) {
        return false;
    }
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    const BOOL ok = ::GetSecurityDescriptorControl(sd, &control, &revision);
    ::LocalFree(sd);
    return (ok != FALSE) && ((control & SE_DACL_PROTECTED) != 0);
}

// Queries whether a Win32 privilege is currently enabled in the process token
bool is_privilege_enabled(LPCWSTR privilege_name) {
    HANDLE token = NULL;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    LUID luid;
    if (!::LookupPrivilegeValueW(nullptr, privilege_name, &luid)) {
        ::CloseHandle(token);
        return false;
    }
    DWORD length = 0;
    ::GetTokenInformation(token, TokenPrivileges, nullptr, 0, &length);
    if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER || length == 0) {
        ::CloseHandle(token);
        return false;
    }
    std::vector<BYTE> buffer(length);
    if (!::GetTokenInformation(token, TokenPrivileges, buffer.data(), length, &length)) {
        ::CloseHandle(token);
        return false;
    }
    ::CloseHandle(token);
    const auto* privs = reinterpret_cast<const TOKEN_PRIVILEGES*>(buffer.data());
    for (DWORD i = 0; i < privs->PrivilegeCount; ++i) {
        if (privs->Privileges[i].Luid.LowPart == luid.LowPart &&
            privs->Privileges[i].Luid.HighPart == luid.HighPart) {
            return (privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
        }
    }
    return false;
}

// RAII guard ensuring a Win32 privilege (such as SeBackupPrivilege) is temporarily disabled
// during access control tests so DACLs are strictly enforced even in elevated environments
// (e.g. MSYS2 bash under runneradmin), and restored upon scope exit.
class ScopedPrivilegeDisable {
public:
    explicit ScopedPrivilegeDisable(LPCWSTR privilege_name)
        : privilege_name_(privilege_name) {
        HANDLE token = NULL;
        if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
            return;
        }
        LUID luid;
        if (!::LookupPrivilegeValueW(nullptr, privilege_name, &luid)) {
            ::CloseHandle(token);
            return;
        }
        DWORD length = 0;
        ::GetTokenInformation(token, TokenPrivileges, nullptr, 0, &length);
        if (::GetLastError() == ERROR_INSUFFICIENT_BUFFER && length > 0) {
            std::vector<BYTE> buffer(length);
            if (::GetTokenInformation(token, TokenPrivileges, buffer.data(), length, &length)) {
                const auto* privs = reinterpret_cast<const TOKEN_PRIVILEGES*>(buffer.data());
                for (DWORD i = 0; i < privs->PrivilegeCount; ++i) {
                    if (privs->Privileges[i].Luid.LowPart == luid.LowPart &&
                        privs->Privileges[i].Luid.HighPart == luid.HighPart) {
                        if ((privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0) {
                            was_enabled_ = true;
                            TOKEN_PRIVILEGES tp{};
                            tp.PrivilegeCount = 1;
                            tp.Privileges[0].Luid = luid;
                            tp.Privileges[0].Attributes = 0; // Disable
                            if (::AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr) &&
                                ::GetLastError() == ERROR_SUCCESS) {
                                adjusted_ = true;
                            }
                        }
                        break;
                    }
                }
            }
        }
        ::CloseHandle(token);
    }

    ~ScopedPrivilegeDisable() {
        if (!adjusted_ || !was_enabled_) {
            return;
        }
        HANDLE token = NULL;
        if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
            return;
        }
        LUID luid;
        if (::LookupPrivilegeValueW(nullptr, privilege_name_, &luid)) {
            TOKEN_PRIVILEGES tp{};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            ::AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        }
        ::CloseHandle(token);
    }

    ScopedPrivilegeDisable(const ScopedPrivilegeDisable&) = delete;
    ScopedPrivilegeDisable& operator=(const ScopedPrivilegeDisable&) = delete;
    ScopedPrivilegeDisable(ScopedPrivilegeDisable&&) = delete;
    ScopedPrivilegeDisable& operator=(ScopedPrivilegeDisable&&) = delete;

    bool was_enabled() const noexcept { return was_enabled_; }
    bool adjusted() const noexcept { return adjusted_; }

private:
    LPCWSTR privilege_name_;
    bool was_enabled_{false};
    bool adjusted_{false};
};

// RAII guard ensuring original DACL restoration even if an assertion fails
struct DaclRestoreGuard {
    std::wstring path;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    bool is_protected = false;
    bool restored = false;
    bool dismissed = false;

    DaclRestoreGuard(std::wstring p, PACL d, PSECURITY_DESCRIPTOR s, bool prot = false)
        : path(std::move(p)), dacl(d), sd(s), is_protected(prot) {}

    DaclRestoreGuard(const DaclRestoreGuard&) = delete;
    DaclRestoreGuard& operator=(const DaclRestoreGuard&) = delete;
    DaclRestoreGuard& operator=(DaclRestoreGuard&&) = delete;

    DaclRestoreGuard(DaclRestoreGuard&& other) noexcept
        : path(std::move(other.path)),
          dacl(other.dacl),
          sd(other.sd),
          is_protected(other.is_protected),
          restored(other.restored),
          dismissed(other.dismissed) {
        other.sd = nullptr;
        other.dacl = nullptr;
        other.restored = true;
        other.dismissed = true;
    }

    ~DaclRestoreGuard() noexcept {
        if (!restored && !dismissed) {
            const DWORD err = restore();
            if (err != ERROR_SUCCESS) {
                ADD_FAILURE() << "DaclRestoreGuard destructor failed to restore DACL for path '"
                              << std::filesystem::path(path).string()
                              << "'. Win32 error: " << err;
            }
        }
        if (sd != nullptr) {
            ::LocalFree(sd);
            sd = nullptr;
        }
    }

    void dismiss() noexcept {
        dismissed = true;
    }

    static std::expected<DaclRestoreGuard, DWORD> capture(const std::filesystem::path& file_path) {
        PACL orig_dacl = nullptr;
        PSECURITY_DESCRIPTOR orig_sd = nullptr;
        const DWORD res = ::GetNamedSecurityInfoW(
            const_cast<LPWSTR>(file_path.c_str()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            &orig_dacl,
            nullptr,
            &orig_sd);
        if (res != ERROR_SUCCESS) {
            return std::unexpected(res);
        }
        if (orig_sd == nullptr) {
            return std::unexpected(static_cast<DWORD>(ERROR_INVALID_SECURITY_DESCR));
        }

        SECURITY_DESCRIPTOR_CONTROL control = 0;
        DWORD revision = 0;
        if (!::GetSecurityDescriptorControl(orig_sd, &control, &revision)) {
            const DWORD err = ::GetLastError();
            ::LocalFree(orig_sd);
            return std::unexpected(err);
        }

        const bool prot = (control & SE_DACL_PROTECTED) != 0;
        return DaclRestoreGuard(file_path.wstring(), orig_dacl, orig_sd, prot);
    }

    DWORD restore() noexcept {
        if (restored) {
            return ERROR_SUCCESS;
        }
        const SECURITY_INFORMATION sec_info =
            DACL_SECURITY_INFORMATION |
            (is_protected ? PROTECTED_DACL_SECURITY_INFORMATION
                          : UNPROTECTED_DACL_SECURITY_INFORMATION);
        const DWORD err = ::SetNamedSecurityInfoW(
            const_cast<LPWSTR>(path.c_str()),
            SE_FILE_OBJECT,
            sec_info,
            nullptr,
            nullptr,
            dacl,
            nullptr);
        if (err == ERROR_SUCCESS) {
            restored = true;
        }
        return err;
    }
};

TEST(FileMetadataWin32NativeTest, AccessDeniedDetectedViaDacl) {
    TempDirFixture fixture;
    const auto file_path = fixture.path() / "denied.txt";
    {
        std::ofstream ofs(file_path);
        ofs << "secret content";
    }

    EXPECT_FALSE(is_dacl_protected(file_path));

    // 1. Capture original security descriptor and DACL
    auto guard_res = DaclRestoreGuard::capture(file_path);
    ASSERT_TRUE(guard_res.has_value());
    auto& guard = *guard_res;
    EXPECT_FALSE(guard.is_protected);

    // 2. Apply restrictive empty DACL denying access
    ACL empty_acl{};
    ASSERT_TRUE(::InitializeAcl(&empty_acl, sizeof(empty_acl), ACL_REVISION));
    const auto set_res = ::SetNamedSecurityInfoW(
        const_cast<LPWSTR>(file_path.c_str()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        &empty_acl,
        nullptr);
    ASSERT_EQ(set_res, ERROR_SUCCESS)
        << "SetNamedSecurityInfoW failed: " << ::GetLastError();

    EXPECT_TRUE(is_dacl_protected(file_path));

    // Direct open without backup semantics is always denied by the empty DACL
    HANDLE h_no_backup = ::CreateFileW(
        file_path.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    EXPECT_EQ(h_no_backup, INVALID_HANDLE_VALUE);
    EXPECT_EQ(::GetLastError(), static_cast<DWORD>(ERROR_ACCESS_DENIED));

    // 3. Confirm reading metadata fails with PermissionDenied / ERROR_ACCESS_DENIED
    // when backup privilege is disabled (ensures deterministic testing across all environments)
    {
        ScopedPrivilegeDisable no_backup(L"SeBackupPrivilege");
        const auto result = read_file_metadata(file_path, "denied.txt");
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code, FileMetadataErrorCode::PermissionDenied);
        EXPECT_EQ(result.error().os_error, static_cast<std::uint32_t>(ERROR_ACCESS_DENIED));
    }

    // 4. Restore original security state and verify result
    const auto restore_res = guard.restore();
    EXPECT_EQ(restore_res, ERROR_SUCCESS)
        << "Restoring DACL failed: " << ::GetLastError();
    EXPECT_TRUE(guard.restored);
    EXPECT_FALSE(is_dacl_protected(file_path));

    const auto restored_meta = read_file_metadata(file_path, "denied.txt");
    ASSERT_TRUE(restored_meta.has_value() && restored_meta->has_value());
    EXPECT_EQ((**restored_meta).size, 14ULL);
}

TEST(FileMetadataWin32NativeTest, AccessDeniedDetectedViaProtectedDacl) {
    TempDirFixture fixture;
    const auto file_path = fixture.path() / "denied_prot.txt";
    {
        std::ofstream ofs(file_path);
        ofs << "secret content";
    }

    // Set original file DACL to protected
    PACL initial_dacl = nullptr;
    PSECURITY_DESCRIPTOR initial_sd = nullptr;
    ASSERT_EQ(::GetNamedSecurityInfoW(
        const_cast<LPWSTR>(file_path.c_str()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr, nullptr, &initial_dacl, nullptr, &initial_sd), ERROR_SUCCESS);
    ASSERT_NE(initial_sd, nullptr);
    ASSERT_EQ(::SetNamedSecurityInfoW(
        const_cast<LPWSTR>(file_path.c_str()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, initial_dacl, nullptr), ERROR_SUCCESS);
    ::LocalFree(initial_sd);

    ASSERT_TRUE(is_dacl_protected(file_path));

    // 1. Capture original security descriptor and DACL
    auto guard_res = DaclRestoreGuard::capture(file_path);
    ASSERT_TRUE(guard_res.has_value());
    auto& guard = *guard_res;
    EXPECT_TRUE(guard.is_protected);

    // 2. Apply restrictive empty DACL denying access
    ACL empty_acl{};
    ASSERT_TRUE(::InitializeAcl(&empty_acl, sizeof(empty_acl), ACL_REVISION));
    ASSERT_EQ(::SetNamedSecurityInfoW(
        const_cast<LPWSTR>(file_path.c_str()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        &empty_acl,
        nullptr), ERROR_SUCCESS);

    // Direct open without backup semantics is always denied by the empty DACL
    HANDLE h_no_backup = ::CreateFileW(
        file_path.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    EXPECT_EQ(h_no_backup, INVALID_HANDLE_VALUE);
    EXPECT_EQ(::GetLastError(), static_cast<DWORD>(ERROR_ACCESS_DENIED));

    // 3. Confirm reading metadata fails with PermissionDenied
    // when backup privilege is disabled (ensures deterministic testing across all environments)
    {
        ScopedPrivilegeDisable no_backup(L"SeBackupPrivilege");
        const auto result = read_file_metadata(file_path, "denied_prot.txt");
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code, FileMetadataErrorCode::PermissionDenied);
        EXPECT_EQ(result.error().os_error, static_cast<std::uint32_t>(ERROR_ACCESS_DENIED));
    }

    // 4. Restore original security state and verify result
    const auto restore_res = guard.restore();
    EXPECT_EQ(restore_res, ERROR_SUCCESS);
    EXPECT_TRUE(guard.restored);

    // Protection against inheritance must be preserved
    EXPECT_TRUE(is_dacl_protected(file_path));

    const auto restored_meta = read_file_metadata(file_path, "denied_prot.txt");
    ASSERT_TRUE(restored_meta.has_value() && restored_meta->has_value());
    EXPECT_EQ((**restored_meta).size, 14ULL);
}

TEST(FileMetadataWin32NativeTest, DaclRestoreGuardFailureDoesNotMarkRestored) {
    TempDirFixture fixture;
    const auto non_existent = fixture.path() / "non_existent_file.txt";

    ACL empty_acl{};
    ASSERT_TRUE(::InitializeAcl(&empty_acl, sizeof(empty_acl), ACL_REVISION));

    DaclRestoreGuard guard{non_existent.wstring(), &empty_acl, nullptr, false};

    const auto restore_res = guard.restore();
    EXPECT_NE(restore_res, static_cast<DWORD>(ERROR_SUCCESS));
    EXPECT_FALSE(guard.restored);

    // Subsequent restore should still attempt and return error rather than false success
    const auto second_res = guard.restore();
    EXPECT_NE(second_res, static_cast<DWORD>(ERROR_SUCCESS));
    EXPECT_FALSE(guard.restored);

    // Intentional failure test: dismiss automatic destruction failure report
    guard.dismiss();
}

TEST(FileMetadataWin32NativeTest, DaclRestoreGuardMoveConstructorTransfersOwnership) {
    TempDirFixture fixture;
    const auto file_path = fixture.path() / "move_transfer.txt";
    {
        std::ofstream ofs(file_path);
        ofs << "move transfer payload";
    }

    auto guard_res = DaclRestoreGuard::capture(file_path);
    ASSERT_TRUE(guard_res.has_value());

    // Apply restrictive empty DACL
    ACL empty_acl{};
    ASSERT_TRUE(::InitializeAcl(&empty_acl, sizeof(empty_acl), ACL_REVISION));
    ASSERT_EQ(::SetNamedSecurityInfoW(
        const_cast<LPWSTR>(file_path.c_str()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, &empty_acl, nullptr), ERROR_SUCCESS);

    // Direct open without backup semantics is always denied by the empty DACL
    HANDLE h_no_backup = ::CreateFileW(
        file_path.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    EXPECT_EQ(h_no_backup, INVALID_HANDLE_VALUE);
    EXPECT_EQ(::GetLastError(), static_cast<DWORD>(ERROR_ACCESS_DENIED));

    {
        ScopedPrivilegeDisable no_backup(L"SeBackupPrivilege");
        EXPECT_FALSE(read_file_metadata(file_path, "move_transfer.txt").has_value());
    }

    {
        DaclRestoreGuard moved_guard = std::move(*guard_res);
        EXPECT_EQ(guard_res->sd, nullptr);
        EXPECT_TRUE(guard_res->restored);
        EXPECT_TRUE(guard_res->dismissed);
        EXPECT_NE(moved_guard.sd, nullptr);
        EXPECT_FALSE(moved_guard.restored);
        EXPECT_FALSE(moved_guard.dismissed);

        // Explicit restoration through moved guard
        EXPECT_EQ(moved_guard.restore(), ERROR_SUCCESS);
        EXPECT_TRUE(moved_guard.restored);
    }

    // Access restored
    const auto restored_meta = read_file_metadata(file_path, "move_transfer.txt");
    ASSERT_TRUE(restored_meta.has_value() && restored_meta->has_value());
    EXPECT_EQ((**restored_meta).size, 21ULL);
}

TEST(FileMetadataWin32NativeTest, DaclRestoreGuardDestructorRestoresOnScopeExit) {
    TempDirFixture fixture;
    const auto file_path = fixture.path() / "scope_exit.txt";
    {
        std::ofstream ofs(file_path);
        ofs << "scope exit test";
    }

    {
        auto guard_res = DaclRestoreGuard::capture(file_path);
        ASSERT_TRUE(guard_res.has_value());

        // Apply restrictive DACL
        ACL empty_acl{};
        ASSERT_TRUE(::InitializeAcl(&empty_acl, sizeof(empty_acl), ACL_REVISION));
        ASSERT_EQ(::SetNamedSecurityInfoW(
            const_cast<LPWSTR>(file_path.c_str()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &empty_acl, nullptr), ERROR_SUCCESS);

        // Direct open without backup semantics is always denied by the empty DACL
        HANDLE h_no_backup_scope = ::CreateFileW(
            file_path.c_str(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            nullptr);
        EXPECT_EQ(h_no_backup_scope, INVALID_HANDLE_VALUE);
        EXPECT_EQ(::GetLastError(), static_cast<DWORD>(ERROR_ACCESS_DENIED));

        {
            ScopedPrivilegeDisable no_backup(L"SeBackupPrivilege");
            EXPECT_FALSE(read_file_metadata(file_path, "scope_exit.txt").has_value());
        }
        // Do NOT call restore() explicitly; let destructor run
    }

    // After guard destruction, access must be restored
    const auto restored_meta = read_file_metadata(file_path, "scope_exit.txt");
    ASSERT_TRUE(restored_meta.has_value() && restored_meta->has_value());
    EXPECT_EQ((**restored_meta).size, 15ULL);
}

TEST(FileMetadataWin32NativeTest, DaclRestoreGuardMoveAssignmentIsDisabled) {
    // Problem A: Move assignment must be deleted to prevent resource leakage on unconfirmed cleanup
    EXPECT_FALSE(std::is_move_assignable_v<DaclRestoreGuard>);
    EXPECT_TRUE(std::is_move_constructible_v<DaclRestoreGuard>);
}

TEST(FileMetadataWin32NativeTest, DaclRestoreGuardDestructorReportsFailureWhenNotDismissed) {
    // Problem B: Destructor must report unexpected restoration failures via GoogleTest diagnostics
    TempDirFixture fixture;
    const auto non_existent = fixture.path() / "non_existent_fail.txt";

    ACL empty_acl{};
    ASSERT_TRUE(::InitializeAcl(&empty_acl, sizeof(empty_acl), ACL_REVISION));

    EXPECT_NONFATAL_FAILURE(([&]() {
        DaclRestoreGuard guard{non_existent.wstring(), &empty_acl, nullptr, false};
    }()), "DaclRestoreGuard destructor failed to restore DACL");
}

TEST(FileMetadataWin32NativeTest, RestrictiveDaclAccessBehaviorWithAndWithoutBackupPrivilege) {
    TempDirFixture fixture;
    const auto file_path = fixture.path() / "priv_behavior.txt";
    {
        std::ofstream ofs(file_path);
        ofs << "privilege behavior test";
    }

    auto guard_res = DaclRestoreGuard::capture(file_path);
    ASSERT_TRUE(guard_res.has_value());
    auto& guard = *guard_res;

    ACL empty_acl{};
    ASSERT_TRUE(::InitializeAcl(&empty_acl, sizeof(empty_acl), ACL_REVISION));
    ASSERT_EQ(::SetNamedSecurityInfoW(
        const_cast<LPWSTR>(file_path.c_str()),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr, nullptr, &empty_acl, nullptr), ERROR_SUCCESS);

    // 1. Direct open without backup semantics is always denied by the empty DACL
    HANDLE h_raw = ::CreateFileW(
        file_path.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    EXPECT_EQ(h_raw, INVALID_HANDLE_VALUE);
    EXPECT_EQ(::GetLastError(), static_cast<DWORD>(ERROR_ACCESS_DENIED));

    // 2. Open without backup semantics for GENERIC_READ is also denied
    HANDLE h_read = ::CreateFileW(
        file_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
    EXPECT_EQ(h_read, INVALID_HANDLE_VALUE);
    EXPECT_EQ(::GetLastError(), static_cast<DWORD>(ERROR_ACCESS_DENIED));

    // 3. With SeBackupPrivilege disabled, read_file_metadata fails with PermissionDenied
    {
        ScopedPrivilegeDisable no_backup(L"SeBackupPrivilege");
        const auto result = read_file_metadata(file_path, "priv_behavior.txt");
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code, FileMetadataErrorCode::PermissionDenied);
        EXPECT_EQ(result.error().os_error, static_cast<std::uint32_t>(ERROR_ACCESS_DENIED));
    }

    // 4. If environment has SeBackupPrivilege enabled, read_file_metadata legitimately succeeds
    if (is_privilege_enabled(L"SeBackupPrivilege")) {
        const auto backup_result = read_file_metadata(file_path, "priv_behavior.txt");
        ASSERT_TRUE(backup_result.has_value());
        ASSERT_TRUE(backup_result->has_value());
        EXPECT_EQ((**backup_result).size, 23ULL);
    }

    // 5. Restore original DACL and confirm full access is restored
    EXPECT_EQ(guard.restore(), ERROR_SUCCESS);
    EXPECT_TRUE(guard.restored);
    const auto final_meta = read_file_metadata(file_path, "priv_behavior.txt");
    ASSERT_TRUE(final_meta.has_value() && final_meta->has_value());
    EXPECT_EQ((**final_meta).size, 23ULL);
}
#endif // defined(_WIN32)

} // namespace

