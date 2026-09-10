#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"

#include <array>
#include <filesystem>
#include <gtest/gtest.h>
#include <string_view>

namespace {

namespace path = kasumi::platform::path;

TEST(PlatformPathTest, UnicodeRoundTripPreservesUtf8Bytes) {
    constexpr std::array<std::string_view, 9> names{"",
                                                    "高松灯",
                                                    "千早愛音",
                                                    "🌸",
                                                    "💝",
                                                    "𝑬𝒎𝒊𝒍𝒊𝒂",
                                                    "𓆩🌸𓆪",
                                                    "高松灯/カード💝.png",
                                                    "pasta-日本/usuário-☁.txt"};
    for (const auto name : names) {
        SCOPED_TRACE(name);
        const auto native = path::from_utf8(name);
        EXPECT_EQ(path::to_logical_utf8(native), name);
        EXPECT_EQ(path::from_utf8(path::to_utf8(native)), native);
    }

    const std::string_view bounded{"高松灯-extra"};
    EXPECT_EQ(path::to_utf8(path::from_utf8(bounded.substr(0, 9))), "高松灯");
}

TEST(PlatformPathTest, NativeUnicodeFilenameBecomesUtf8) {
#if defined(_WIN32)
    const std::filesystem::path native{L"高松灯\\千早愛音\\カード💝.png"};
    EXPECT_EQ(path::to_utf8(native), "高松灯\\千早愛音\\カード💝.png");
#else
    const std::filesystem::path native{"高松灯/千早愛音/カード💝.png"};
    EXPECT_EQ(path::to_utf8(native), "高松灯/千早愛音/カード💝.png");
#endif
    EXPECT_EQ(path::to_logical_utf8(native), "高松灯/千早愛音/カード💝.png");
    EXPECT_EQ(path::to_utf8(native.filename()), "カード💝.png");
}

TEST(PlatformPathTest, TemporarySiblingPreservesNativeUnicodeFilename) {
    const auto destination = path::from_utf8("高松灯/𓆩🌸𓆪-𝑬𝒎𝒊𝒍𝒊𝒂.txt");
    const auto temporary =
        path::temporary_sibling_path(destination, ".", ".kasumi-new-123");
    EXPECT_EQ(temporary.parent_path(), destination.parent_path());
    EXPECT_EQ(path::to_utf8(temporary.filename()),
              ".𓆩🌸𓆪-𝑬𝒎𝒊𝒍𝒊𝒂.txt.kasumi-new-123");
    EXPECT_EQ(path::temporary_sibling_path(destination, "", ""), destination);
}

TEST(PlatformPathTest, UnicodeFilesystemOperationsAndAtomicReplacement) {
    auto workspace = kasumi::test::make_temp_workspace("unicode-path");
    const auto directory = kasumi::test::workspace_root(workspace) /
                           path::from_utf8("高松灯/千早愛音🌸");
    std::filesystem::create_directories(directory);
    constexpr std::array<std::string_view, 4> names{
        "カード💝.png", "Karyl🌸.png", "𝑬𝒎𝒊𝒍𝒊𝒂.txt", "𓆩🌸𓆪.txt"};
    for (const auto name : names) {
        SCOPED_TRACE(name);
        const auto destination = directory / path::from_utf8(name);
        const auto written =
            kasumi::platform::private_storage::write_atomically(destination,
                                                                "initial");
        ASSERT_TRUE(written) << written.error();
        EXPECT_EQ(kasumi::test::read_text(destination), "initial");
        const auto replaced =
            kasumi::platform::private_storage::write_atomically(destination,
                                                                "updated");
        ASSERT_TRUE(replaced) << replaced.error();
        EXPECT_EQ(kasumi::test::read_text(destination), "updated");
        const auto moved =
            path::temporary_sibling_path(destination, ".", ".renamed");
        std::filesystem::rename(destination, moved);
        EXPECT_EQ(kasumi::test::read_text(moved), "updated");
        EXPECT_TRUE(std::filesystem::remove(moved));
    }
    EXPECT_TRUE(std::filesystem::is_empty(directory));
}

} // namespace
