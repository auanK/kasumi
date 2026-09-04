#include "application/profile.hpp"
#include "kasumi/test/temp_workspace.hpp"

#include <filesystem>
#include <gtest/gtest.h>
#include <string>

namespace {

TEST(RuntimeApplicationIntegrationTest, ProfileLifecycleCrossesPublicLayers) {
    auto workspace = kasumi::test::make_temp_workspace("runtime-application");
    const kasumi::application::ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const kasumi::application::Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment,
        profile,
        kasumi::application::MasterKeyHex{std::string(64, '3')}));
    const auto listed = kasumi::application::list_profiles(environment);
    ASSERT_TRUE(listed.has_value());
    ASSERT_EQ(listed->size(), 1U);
    EXPECT_EQ(listed->front().local_dir,
              kasumi::test::workspace_path(workspace, "local"));
    ASSERT_TRUE(
        kasumi::application::rename_profile(environment, "demo", "renamed"));
    EXPECT_TRUE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "app/profiles/renamed")));
    ASSERT_TRUE(kasumi::application::delete_profile(environment, "renamed"));
    EXPECT_TRUE(kasumi::application::list_profiles(environment)->empty());
}

} // namespace
