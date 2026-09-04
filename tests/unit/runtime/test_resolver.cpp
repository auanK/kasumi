#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "runtime/resolver.hpp"
#include "runtime/vault.hpp"

#include <filesystem>
#include <gtest/gtest.h>

namespace {

using kasumi::test::TempWorkspace;

void write_config(const TempWorkspace& workspace, std::string_view remote) {
    kasumi::test::write_text(
        kasumi::test::workspace_path(workspace, "app/config.toml"),
        "[profiles.demo]\nlocal_dir = '" +
            kasumi::test::workspace_path(workspace, "local data").string() +
            "'\nremote_dir = '" + std::string(remote) +
            "'\nmin_history_depth = 5\nmin_history_age_hours = 6\n");
}

TEST(RuntimeResolverTest, ReadOnlyDoesNotCreateAnyProfileInfrastructure) {
    auto workspace = kasumi::test::make_temp_workspace("runtime-resolver-ro");
    std::filesystem::create_directories(
        kasumi::test::workspace_path(workspace, "app"));
    write_config(workspace, "remote:");
    const auto result =
        kasumi::runtime::resolve(kasumi::test::workspace_path(workspace, "app"),
                                 "demo",
                                 kasumi::runtime::AccessMode::ReadOnly);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->storage_location, "remote:");
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "app/profiles")));
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "local data")));
}

TEST(RuntimeResolverTest,
     ReadOnlyWithExistingProfileAndProtectionDisabledSucceeds) {
    auto workspace =
        kasumi::test::make_temp_workspace("runtime-resolver-existing-ro");
    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    std::filesystem::create_directories(app / "profiles/demo");
    write_config(workspace, remote.string());

    kasumi::runtime::vault::KeyBytes key{};
    key.fill(0x42);
    const auto key_path = app / "profiles/demo/key.bin";
    ASSERT_TRUE(kasumi::runtime::vault::write(key_path, key));
    const auto before = kasumi::test::snapshot_tree(app);

    const auto result = kasumi::runtime::resolve(
        app, "demo", kasumi::runtime::AccessMode::ReadOnly, false);

    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->storage_location, remote.string());
    EXPECT_EQ(result->key_path, key_path);
    EXPECT_EQ(result->database_path, app / "profiles/demo/db.sqlite");
    EXPECT_EQ(result->local_dir,
              kasumi::test::workspace_path(workspace, "local data"));
    EXPECT_EQ(kasumi::test::snapshot_tree(app), before);
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "local data")));
    EXPECT_FALSE(std::filesystem::exists(result->database_path));
}

TEST(RuntimeResolverTest, ReadWriteCreatesOnlyProfileAndLocalDirectories) {
    auto workspace = kasumi::test::make_temp_workspace("runtime-resolver-rw");
    std::filesystem::create_directories(
        kasumi::test::workspace_path(workspace, "app"));
    write_config(
        workspace,
        kasumi::test::workspace_path(workspace, "remote store").string());
    const auto result =
        kasumi::runtime::resolve(kasumi::test::workspace_path(workspace, "app"),
                                 "demo",
                                 kasumi::runtime::AccessMode::ReadWrite);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->storage_location,
              kasumi::test::workspace_path(workspace, "remote store").string());
    EXPECT_TRUE(std::filesystem::is_directory(result->local_dir));
    EXPECT_TRUE(
        std::filesystem::is_directory(result->database_path.parent_path()));
    EXPECT_FALSE(std::filesystem::exists(result->database_path));
    EXPECT_FALSE(std::filesystem::exists(result->key_path));
}

TEST(RuntimeResolverTest, InvalidProfileAndMissingConfigKeepRuntimeErrors) {
    auto workspace =
        kasumi::test::make_temp_workspace("runtime-resolver-errors");
    const auto missing =
        kasumi::runtime::resolve(kasumi::test::workspace_path(workspace, "app"),
                                 "demo",
                                 kasumi::runtime::AccessMode::ReadOnly);
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error().code, kasumi::runtime::ErrorCode::ConfigNotFound);

    std::filesystem::create_directories(
        kasumi::test::workspace_path(workspace, "app"));
    write_config(workspace, "relative");
    const auto invalid =
        kasumi::runtime::resolve(kasumi::test::workspace_path(workspace, "app"),
                                 "../escape",
                                 kasumi::runtime::AccessMode::ReadOnly);
    ASSERT_FALSE(invalid.has_value());
    EXPECT_EQ(invalid.error().code,
              kasumi::runtime::ErrorCode::InvalidProfileName);
}

TEST(RuntimeResolverTest, RejectsStoredRelativeLocalPath) {
    auto workspace =
        kasumi::test::make_temp_workspace("runtime-relative-local");
    const auto app = kasumi::test::workspace_path(workspace, "app");
    std::filesystem::create_directories(app);
    kasumi::test::write_text(
        app / "config.toml",
        "[profiles.demo]\nlocal_dir = 'relative'\nremote_dir = 'remote:root'\n"
        "min_history_depth = 5\nmin_history_age_hours = 6\n");

    const auto result = kasumi::runtime::resolve(
        app, "demo", kasumi::runtime::AccessMode::ReadWrite);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, kasumi::runtime::ErrorCode::ProfileInvalid);
}

} // namespace
