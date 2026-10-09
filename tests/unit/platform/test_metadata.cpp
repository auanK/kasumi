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
    std::error_code error;
    const auto actual = std::filesystem::last_write_time(path, error);
    ASSERT_FALSE(error);
    EXPECT_EQ(actual, requested);
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
    expect_written(file, subsecond_timestamp(), false);
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

#if defined(_WIN32)
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
