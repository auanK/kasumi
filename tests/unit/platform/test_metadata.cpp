#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/metadata.hpp"

#include <chrono>
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
        GTEST_SKIP() << "criação de links simbólicos não suportada: "
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
        GTEST_SKIP() << "file_time_type não pode representar um valor anterior "
                        "ao FILETIME";
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
