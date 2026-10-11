#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/metadata.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <gtest/gtest.h>
#include <vector>

namespace {

std::filesystem::file_time_type timestamp(std::chrono::seconds offset) {
    const auto value = std::filesystem::file_time_type::clock::now() + offset;
    return std::filesystem::file_time_type{
        std::chrono::duration_cast<std::filesystem::file_time_type::duration>(
            std::chrono::time_point_cast<std::chrono::seconds>(value)
                .time_since_epoch())};
}

std::filesystem::file_time_type subsecond_timestamp() {
    using filetime_tick =
        std::chrono::duration<long long, std::ratio<1, 10000000>>;
    const auto base = std::chrono::time_point_cast<filetime_tick>(
        std::chrono::clock_cast<std::chrono::system_clock>(
            std::filesystem::file_time_type::clock::now()));
    const auto value =
        base.time_since_epoch() + std::chrono::duration_cast<filetime_tick>(
                                      std::chrono::nanoseconds{123456700});
    return std::chrono::clock_cast<std::chrono::file_clock>(
        std::chrono::sys_time<filetime_tick>{value});
}

void expect_written(const std::filesystem::path& path,
                    std::filesystem::file_time_type requested,
                    bool check_filesystem_readback = true) {
    const auto written =
        kasumi::platform::metadata::set_last_write_time(path, requested);
    ASSERT_TRUE(written.has_value()) << written.error();
    if (!check_filesystem_readback) {
        return;
    }
    const auto actual = kasumi::platform::metadata::last_write_time(path);
    ASSERT_TRUE(actual.has_value()) << actual.error();
    EXPECT_EQ(*actual, requested);
}

TEST(PlatformMetadataTest, WritesRegularFileAndConfirmsIt) {
    auto workspace =
        kasumi::test::make_temp_workspace("platform-metadata-file");
    const auto file = kasumi::test::workspace_path(workspace, "file.txt");
    kasumi::test::write_text(file, "content");
    expect_written(file, timestamp(std::chrono::hours{-1}));
    expect_written(file, timestamp(std::chrono::hours{1}));
}

TEST(PlatformMetadataTest, WritesEmptyDirectoryAndRoot) {
    auto workspace =
        kasumi::test::make_temp_workspace("platform-metadata-directory");
    const auto root = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(root));
    expect_written(root, timestamp(std::chrono::hours{-2}));
    expect_written(root, timestamp(std::chrono::hours{2}));
}

TEST(PlatformMetadataTest, WritesDirectoryWithContent) {
    auto workspace =
        kasumi::test::make_temp_workspace("platform-metadata-content");
    const auto directory = kasumi::test::workspace_path(workspace, "directory");
    ASSERT_TRUE(std::filesystem::create_directories(directory));
    kasumi::test::write_text(directory / "file.txt", "content");
    expect_written(directory, timestamp(std::chrono::hours{-1}));
}

TEST(PlatformMetadataTest, RejectsMissingPathAndSymlink) {
    auto workspace =
        kasumi::test::make_temp_workspace("platform-metadata-invalid");
    const auto missing = kasumi::test::workspace_path(workspace, "missing");
    const auto missing_result = kasumi::platform::metadata::set_last_write_time(
        missing, timestamp(std::chrono::hours{1}));
    EXPECT_FALSE(missing_result.has_value());

    const auto target = kasumi::test::workspace_path(workspace, "target");
    const auto link = kasumi::test::workspace_path(workspace, "link");
    kasumi::test::write_text(target, "target");
    std::error_code error;
    std::filesystem::create_symlink(target, link, error);
    if (error) {
        GTEST_SKIP() << "symbolic link creation not supported: "
                     << error.message();
    }
    const auto symlink_result = kasumi::platform::metadata::set_last_write_time(
        link, timestamp(std::chrono::hours{1}));
    EXPECT_FALSE(symlink_result.has_value());
}

TEST(PlatformMetadataTest, ConfirmsSubsecondFiletimeRoundTrip) {
    auto workspace =
        kasumi::test::make_temp_workspace("platform-metadata-subsecond");
    const auto file = kasumi::test::workspace_path(workspace, "file.txt");
    kasumi::test::write_text(file, "content");
    expect_written(file, subsecond_timestamp(), true);
}

TEST(PlatformMetadataTest, ConvertsCanonicalNanosecondsAtFilesystemBoundary) {
    auto workspace =
        kasumi::test::make_temp_workspace("platform-metadata-canonical-ns");
    const auto file = kasumi::test::workspace_path(workspace, "file.txt");
    kasumi::test::write_text(file, "content");

    constexpr std::int64_t canonical = 123456789;
    const auto native =
        kasumi::platform::metadata::file_time_from_unix_nanoseconds(canonical);
    ASSERT_TRUE(native.has_value());
    const auto observed = kasumi::platform::metadata::unix_nanoseconds(*native);
    ASSERT_TRUE(observed.has_value());
    using FileDuration = std::filesystem::file_time_type::duration;
    const auto expected = std::chrono::duration_cast<std::chrono::nanoseconds>(
                              std::chrono::duration_cast<FileDuration>(
                                  std::chrono::nanoseconds{canonical}))
                              .count();
    EXPECT_EQ(*observed, expected);
    EXPECT_TRUE(kasumi::platform::metadata::filesystem_equivalent(canonical,
                                                                  *observed));

    ASSERT_TRUE(kasumi::platform::metadata::set_last_write_time(file, *native));
    EXPECT_EQ(canonical, 123456789);
}

TEST(PlatformMetadataTest, ConvertsTheSameNativeTimestampDeterministically) {
    const auto native = std::filesystem::file_time_type::clock::now();
    const auto expected = kasumi::platform::metadata::unix_nanoseconds(native);
    ASSERT_TRUE(expected.has_value());
    for (int attempt = 0; attempt < 256; ++attempt) {
        EXPECT_EQ(kasumi::platform::metadata::unix_nanoseconds(native),
                  expected)
            << "attempt=" << attempt;
    }
}

TEST(PlatformMetadataTest, PreservesUnspecifiedNegativeAndChecksNativeRange) {
    const auto unspecified =
        kasumi::platform::metadata::file_time_from_unix_nanoseconds(0);
    ASSERT_TRUE(unspecified.has_value());
    EXPECT_EQ(*unspecified, std::filesystem::file_time_type{});
    EXPECT_EQ(kasumi::platform::metadata::unix_nanoseconds(*unspecified), 0);

    const auto negative =
        kasumi::platform::metadata::file_time_from_unix_nanoseconds(-123456789);
    ASSERT_TRUE(negative.has_value());
    EXPECT_EQ(kasumi::platform::metadata::unix_nanoseconds(*negative),
              std::chrono::duration_cast<std::chrono::nanoseconds>(
                  std::chrono::duration_cast<
                      std::filesystem::file_time_type::duration>(
                      std::chrono::nanoseconds{-123456789}))
                  .count());
    for (const auto native :
         {std::filesystem::file_time_type{
              std::filesystem::file_time_type::duration::min()},
          std::filesystem::file_time_type{
              std::filesystem::file_time_type::duration::max()}}) {
        const auto canonical =
            kasumi::platform::metadata::unix_nanoseconds(native);
        if (!canonical) {
            continue;
        }
        const auto restored =
            kasumi::platform::metadata::file_time_from_unix_nanoseconds(
                *canonical);
        ASSERT_TRUE(restored.has_value());
        EXPECT_EQ(kasumi::platform::metadata::unix_nanoseconds(*restored),
                  canonical);
    }
}

TEST(PlatformMetadataTest, FilesystemEquivalentSafeAcrossFullInt64Domain) {
    constexpr auto min_i64 = std::numeric_limits<std::int64_t>::min();
    constexpr auto max_i64 = std::numeric_limits<std::int64_t>::max();

    // Reflexivity
    EXPECT_TRUE(kasumi::platform::metadata::filesystem_equivalent(min_i64, min_i64));
    EXPECT_TRUE(kasumi::platform::metadata::filesystem_equivalent(max_i64, max_i64));
    EXPECT_TRUE(kasumi::platform::metadata::filesystem_equivalent(0, 0));
    EXPECT_TRUE(kasumi::platform::metadata::filesystem_equivalent(-1, -1));
    EXPECT_TRUE(kasumi::platform::metadata::filesystem_equivalent(-100, -100));

    // Symmetry
    const std::vector<std::pair<std::int64_t, std::int64_t>> pairs = {
        {min_i64, max_i64},
        {0, 99},
        {0, 100},
        {-1, -99},
        {-100, -1},
        {-101, -100},
        {-1, 0},
        {min_i64, 0},
        {max_i64, 0},
    };
    for (const auto& [a, b] : pairs) {
        EXPECT_EQ(kasumi::platform::metadata::filesystem_equivalent(a, b),
                  kasumi::platform::metadata::filesystem_equivalent(b, a))
            << "symmetry broken for a=" << a << ", b=" << b;
    }

    // Extremes
    EXPECT_FALSE(kasumi::platform::metadata::filesystem_equivalent(min_i64, max_i64));
    EXPECT_FALSE(kasumi::platform::metadata::filesystem_equivalent(min_i64, 0));
    EXPECT_FALSE(kasumi::platform::metadata::filesystem_equivalent(max_i64, 0));

#if defined(_WIN32)
    // 100ns tick quantum on Windows
    EXPECT_TRUE(kasumi::platform::metadata::filesystem_equivalent(0, 99));
    EXPECT_FALSE(kasumi::platform::metadata::filesystem_equivalent(0, 100));
    EXPECT_FALSE(kasumi::platform::metadata::filesystem_equivalent(99, 100));

    EXPECT_TRUE(kasumi::platform::metadata::filesystem_equivalent(-1, -99));
    EXPECT_TRUE(kasumi::platform::metadata::filesystem_equivalent(-100, -1));
    EXPECT_FALSE(kasumi::platform::metadata::filesystem_equivalent(-101, -100));
    EXPECT_FALSE(kasumi::platform::metadata::filesystem_equivalent(-101, -1));
    EXPECT_FALSE(kasumi::platform::metadata::filesystem_equivalent(-1, 0));
#endif
}

#if defined(_WIN32)
TEST(PlatformMetadataTest, WindowsFiletimeTicksBoundariesAndOverflow) {
    constexpr std::uint64_t unix_epoch_ticks = 116444736000000000ULL;

    // 1. Unix epoch (1970-01-01 00:00:00 UTC)
    const auto unix_epoch_ft =
        kasumi::platform::metadata::detail::from_windows_ticks(unix_epoch_ticks);
    ASSERT_TRUE(unix_epoch_ft.has_value()) << unix_epoch_ft.error();
    const auto epoch_ns = kasumi::platform::metadata::unix_nanoseconds(*unix_epoch_ft);
    ASSERT_TRUE(epoch_ns.has_value());
    EXPECT_EQ(*epoch_ns, 0);
    const auto roundtrip_epoch_ticks =
        kasumi::platform::metadata::detail::to_windows_ticks(*unix_epoch_ft);
    ASSERT_TRUE(roundtrip_epoch_ticks.has_value());
    EXPECT_EQ(*roundtrip_epoch_ticks, unix_epoch_ticks);

    // 2. Timestamps before Unix epoch (e.g. 1969-12-31 23:59:59 UTC, 1s before)
    const auto before_epoch_ticks = unix_epoch_ticks - 10000000ULL;
    const auto before_epoch_ft =
        kasumi::platform::metadata::detail::from_windows_ticks(before_epoch_ticks);
    ASSERT_TRUE(before_epoch_ft.has_value()) << before_epoch_ft.error();
    const auto before_epoch_ns =
        kasumi::platform::metadata::unix_nanoseconds(*before_epoch_ft);
    ASSERT_TRUE(before_epoch_ns.has_value());
    EXPECT_EQ(*before_epoch_ns, -1000000000LL);
    const auto roundtrip_before_ticks =
        kasumi::platform::metadata::detail::to_windows_ticks(*before_epoch_ft);
    ASSERT_TRUE(roundtrip_before_ticks.has_value());
    EXPECT_EQ(*roundtrip_before_ticks, before_epoch_ticks);

    // 3. Current timestamp with 100ns fraction
    const auto subsecond_ticks = unix_epoch_ticks + 12345678901234ULL;
    const auto subsecond_ft =
        kasumi::platform::metadata::detail::from_windows_ticks(subsecond_ticks);
    ASSERT_TRUE(subsecond_ft.has_value()) << subsecond_ft.error();
    const auto roundtrip_subsecond_ticks =
        kasumi::platform::metadata::detail::to_windows_ticks(*subsecond_ft);
    ASSERT_TRUE(roundtrip_subsecond_ticks.has_value());
    EXPECT_EQ(*roundtrip_subsecond_ticks, subsecond_ticks);

    // 4. Extreme values: UINT64_MAX must fail explicitly
    const auto max_u64_ft =
        kasumi::platform::metadata::detail::from_windows_ticks(
            std::numeric_limits<std::uint64_t>::max());
    EXPECT_FALSE(max_u64_ft.has_value());

    // 5. Value with bit 63 set (exceeds signed int64_t max) must fail
    const auto high_bit_ticks = 0x8000000000000000ULL;
    const auto high_bit_ft =
        kasumi::platform::metadata::detail::from_windows_ticks(high_bit_ticks);
    EXPECT_FALSE(high_bit_ft.has_value());

    // 6. Zero ticks (Jan 1, 1601 - outside representable nanoseconds)
    const auto zero_ft = kasumi::platform::metadata::detail::from_windows_ticks(0);
#if !defined(_MSC_VER)
    // In libstdc++, file_time_type has 1ns resolution; 1601 exceeds int64 nanoseconds
    EXPECT_FALSE(zero_ft.has_value());
#endif
}

TEST(PlatformMetadataTest, WindowsRoundTripsFilesAndDirectories) {
    auto workspace =
        kasumi::test::make_temp_workspace("platform-metadata-windows-range");
    const auto file = kasumi::test::workspace_path(workspace, "file.txt");
    const auto directory = kasumi::test::workspace_path(workspace, "directory");
    kasumi::test::write_text(file, "content");
    ASSERT_TRUE(std::filesystem::create_directory(directory));

    const std::vector offsets{std::chrono::duration_cast<std::chrono::seconds>(
                                  std::chrono::hours{-3}),
                              std::chrono::seconds{-1},
                              std::chrono::seconds{0},
                              std::chrono::seconds{1},
                              std::chrono::duration_cast<std::chrono::seconds>(
                                  std::chrono::hours{3})};
    for (const auto offset : offsets) {
        expect_written(file, timestamp(offset));
        expect_written(directory, timestamp(offset));
    }
}

TEST(PlatformMetadataTest, RejectsTimestampBeforeWindowsFiletimeEpoch) {
    auto workspace =
        kasumi::test::make_temp_workspace("platform-metadata-range");
    const auto file = kasumi::test::workspace_path(workspace, "file.txt");
    kasumi::test::write_text(file, "content");
    const auto before_epoch = std::chrono::clock_cast<std::chrono::file_clock>(
        std::chrono::sys_time<std::chrono::seconds>{
            std::chrono::seconds{-11644473601}});
    if (before_epoch.time_since_epoch() <
        std::chrono::duration_cast<std::chrono::seconds>(
            std::filesystem::file_time_type::duration::min())) {
        GTEST_SKIP() << "file_time_type cannot represent value before FILETIME";
    }
    const auto representable = std::filesystem::file_time_type{
        std::chrono::duration_cast<std::filesystem::file_time_type::duration>(
            before_epoch.time_since_epoch())};
    const auto result =
        kasumi::platform::metadata::set_last_write_time(file, representable);
    EXPECT_FALSE(result.has_value());
}
#endif

} // namespace
