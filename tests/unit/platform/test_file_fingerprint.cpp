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

TEST(FileFingerprintTest, ReplacementChangesIdentityEvidence) {
    auto workspace = kasumi::test::make_temp_workspace("fingerprint-change");
    const auto file = kasumi::test::workspace_path(workspace, "file.txt");
    kasumi::test::write_text(file, "first");
    const auto before = kasumi::platform::regular_file_fingerprint(file);
    ASSERT_TRUE(before.has_value());
    ASSERT_TRUE(std::filesystem::remove(file));
    kasumi::test::write_text(file, "second");
    const auto after = kasumi::platform::regular_file_fingerprint(file);
    ASSERT_TRUE(after.has_value());
    if (!*before) {
        EXPECT_FALSE(*after);
        return;
    }
    ASSERT_TRUE(*after);
    EXPECT_TRUE((*after)->kind != (*before)->kind ||
                (*after)->value != (*before)->value);
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
