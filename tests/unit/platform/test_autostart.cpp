#include "kasumi/test/scoped_environment.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/autostart.hpp"

#include <filesystem>
#include <gtest/gtest.h>

namespace {

TEST(AutostartTest, CurrentExecutablePathIsAbsoluteAndExists) {
    const auto exe = kasumi::platform::current_executable_path();
    ASSERT_TRUE(exe.has_value()) << exe.error();
    EXPECT_TRUE(exe->is_absolute());
    EXPECT_TRUE(std::filesystem::exists(*exe));
}

TEST(AutostartTest, InstallQueryAndUninstallUseHermeticOverrideDirectory) {
    auto workspace = kasumi::test::make_temp_workspace("kasumi-autostart-");
    const auto override_dir =
        kasumi::test::workspace_path(workspace, "autostart");
    const auto env = kasumi::test::scoped_environment_variable(
        "KASUMI_AUTOSTART_DIR", override_dir.string());

    const auto exe = kasumi::platform::current_executable_path();
    ASSERT_TRUE(exe.has_value()) << exe.error();

    const auto before = kasumi::platform::query_user_autostart();
    ASSERT_TRUE(before.has_value()) << before.error();
    EXPECT_FALSE(before->installed);

    const auto installed = kasumi::platform::install_user_autostart(*exe);
    ASSERT_TRUE(installed.has_value()) << installed.error();
    EXPECT_TRUE(installed->installed);
    EXPECT_NE(installed->command.find("daemon run"), std::string::npos);

    const auto queried = kasumi::platform::query_user_autostart();
    ASSERT_TRUE(queried.has_value()) << queried.error();
    EXPECT_TRUE(queried->installed);
    EXPECT_NE(queried->command.find("daemon run"), std::string::npos);

    const auto removed = kasumi::platform::uninstall_user_autostart();
    ASSERT_TRUE(removed.has_value()) << removed.error();
    EXPECT_FALSE(removed->installed);

    const auto after = kasumi::platform::query_user_autostart();
    ASSERT_TRUE(after.has_value()) << after.error();
    EXPECT_FALSE(after->installed);
}

} // namespace
