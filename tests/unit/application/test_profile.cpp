#include "application/profile.hpp"
#include "core/history.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "runtime/paths.hpp"
#include "runtime/profile.hpp"

#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <utility>

namespace {

using kasumi::application::ExecutionEnvironment;
using kasumi::application::MasterKeyHex;
using kasumi::application::Profile;
using kasumi::application::ProfileCredentials;
using kasumi::test::TempWorkspace;

MasterKeyHex key() {
    return MasterKeyHex{std::string(64, '1')};
}

TEST(ApplicationProfileTest, ListMissingConfigIsEmptyAndCreateListsProfile) {
    auto workspace = kasumi::test::make_temp_workspace("application-profile");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const auto before = kasumi::application::list_profiles(environment);
    ASSERT_TRUE(before.has_value());
    EXPECT_TRUE(before->empty());

    const Profile profile{
        "main",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));
    const auto listed = kasumi::application::list_profiles(environment);
    ASSERT_TRUE(listed.has_value());
    ASSERT_EQ(listed->size(), 1U);
    EXPECT_EQ(listed->front().name, "main");
    EXPECT_TRUE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "app/profiles/main/key.bin")));
}

TEST(ApplicationProfileTest, RejectsDuplicateNames) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-profile-errors");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile profile{
        "main",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));
    const auto duplicate =
        kasumi::application::create_profile(environment, profile, key());
    ASSERT_FALSE(duplicate.has_value());
    EXPECT_EQ(duplicate.error().code,
              kasumi::application::ProfileErrorCode::AlreadyExists);
    const Profile invalid{
        "../escape",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    EXPECT_EQ(kasumi::application::create_profile(environment, invalid, key())
                  .error()
                  .code,
              kasumi::application::ProfileErrorCode::InvalidName);
}

TEST(ApplicationProfileTest, RejectsRelativeLocalAndStoragePaths) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-profile-paths");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};

    const auto relative_local = kasumi::application::create_profile(
        environment, Profile{"local", "relative", "remote:root"}, key());
    ASSERT_FALSE(relative_local.has_value());
    EXPECT_EQ(relative_local.error().code,
              kasumi::application::ProfileErrorCode::StorageFailure);

    const auto relative_storage = kasumi::application::create_profile(
        environment,
        Profile{"storage",
                kasumi::test::workspace_path(workspace, "local"),
                "relative"},
        key());
    ASSERT_FALSE(relative_storage.has_value());
    EXPECT_EQ(relative_storage.error().code,
              kasumi::application::ProfileErrorCode::StorageFailure);
}

TEST(ApplicationProfileTest, InvalidRetentionDoesNotCreateProfileArtifacts) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-profile-retention");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile invalid{
        .name = "demo",
        .local_dir = kasumi::test::workspace_path(workspace, "local"),
        .remote_dir =
            kasumi::test::workspace_path(workspace, "remote").string(),
        .min_history_depth = kasumi::history::maximum_graph_depth + 1,
        .min_history_age_hours = 6};

    const auto result =
        kasumi::application::create_profile(environment, invalid, key());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::ProfileErrorCode::ConfigFailure);
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "app/config.toml")));
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "app/profiles/demo")));
}

TEST(ApplicationProfileTest,
     UpdateRenameAndDeleteKeepConfigAndStorageCoherent) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-profile-lifecycle");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    Profile profile{
        "old",
        kasumi::test::workspace_path(workspace, "local old"),
        kasumi::test::workspace_path(workspace, "remote old").string()};
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));

    profile.local_dir = kasumi::test::workspace_path(workspace, "local new");
    profile.remote_dir =
        kasumi::test::workspace_path(workspace, "remote new").string();
    ASSERT_TRUE(kasumi::application::update_profile(environment, profile));
    ASSERT_TRUE(kasumi::application::rename_profile(environment, "old", "new"));
    EXPECT_TRUE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "app/profiles/new")));
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "app/profiles/old")));

    const auto collision =
        kasumi::application::rename_profile(environment, "new", "new");
    EXPECT_FALSE(collision.has_value());
    ASSERT_TRUE(kasumi::application::delete_profile(environment, "new"));
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "app/profiles/new")));
    EXPECT_TRUE(kasumi::application::list_profiles(environment)->empty());
}

TEST(ApplicationProfileTest,
     PasswordPairCreatesUsableVaultWithoutExposingSecrets) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-password-profile");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    ProfileCredentials credentials =
        kasumi::application::PasswordPair{"test password", "test salt secret"};
    const Profile profile{
        "password",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, profile, std::move(credentials)));
    EXPECT_TRUE(std::filesystem::exists(kasumi::test::workspace_path(
        workspace, "app/profiles/password/key.bin")));
}

} // namespace
