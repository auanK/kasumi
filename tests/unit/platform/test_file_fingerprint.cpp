#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/file_fingerprint.hpp"

#include <gtest/gtest.h>

namespace {

TEST(FileFingerprintTest, RegularFileHasStableStrongIdentity) {
    auto workspace = kasumi::test::make_temp_workspace("fingerprint-stable");
    const auto file = kasumi::test::workspace_path(workspace, "file.txt");
    kasumi::test::write_text(file, "first");
    const auto before = kasumi::platform::regular_file_fingerprint(file);
    ASSERT_TRUE(before.has_value());
    const auto again = kasumi::platform::regular_file_fingerprint(file);
    ASSERT_TRUE(again.has_value());
    if (!*before) {
        EXPECT_FALSE(*again);
        return;
    }
    ASSERT_TRUE(*again);
    EXPECT_EQ((*again)->kind, (*before)->kind);
    EXPECT_EQ((*again)->value, (*before)->value);
}

TEST(FileFingerprintTest,
     DistinctExistingFilesHaveDistinctNativeIdentityWhenAvailable) {
    auto workspace = kasumi::test::make_temp_workspace("fingerprint-distinct");
    const auto first = kasumi::test::workspace_path(workspace, "first.txt");
    const auto second = kasumi::test::workspace_path(workspace, "second.txt");
    kasumi::test::write_text(first, "same content");
    kasumi::test::write_text(second, "same content");

    const auto first_fingerprint =
        kasumi::platform::regular_file_fingerprint(first);
    const auto second_fingerprint =
        kasumi::platform::regular_file_fingerprint(second);
    ASSERT_TRUE(first_fingerprint.has_value());
    ASSERT_TRUE(second_fingerprint.has_value());
    ASSERT_EQ(first_fingerprint->has_value(), second_fingerprint->has_value());
    if (!*first_fingerprint)
        return;

    ASSERT_TRUE(*second_fingerprint);
    EXPECT_EQ((*first_fingerprint)->kind, (*second_fingerprint)->kind);
    // ChangeTime is not a native identity guarantee.
    EXPECT_TRUE((*first_fingerprint)->value[0] !=
                    (*second_fingerprint)->value[0] ||
                (*first_fingerprint)->value[1] !=
                    (*second_fingerprint)->value[1] ||
                (*first_fingerprint)->value[2] !=
                    (*second_fingerprint)->value[2]);
}

TEST(FileFingerprintTest, DirectoriesAndMissingPathsDoNotBecomeCacheRows) {
    auto workspace = kasumi::test::make_temp_workspace("fingerprint-invalid");
    const auto directory = kasumi::test::workspace_path(workspace, "dir");
    ASSERT_TRUE(std::filesystem::create_directory(directory));
    const auto directory_result =
        kasumi::platform::regular_file_fingerprint(directory);
    ASSERT_TRUE(directory_result.has_value());
    EXPECT_FALSE(*directory_result);
    const auto missing = kasumi::platform::regular_file_fingerprint(
        kasumi::test::workspace_path(workspace, "missing"));
    EXPECT_FALSE(missing.has_value());
}

} // namespace
