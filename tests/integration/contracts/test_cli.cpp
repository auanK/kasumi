#include "application/profile.hpp"
#include "cli/app.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/scoped_environment.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/path.hpp"

#include <gtest/gtest.h>
#include <regex>
#include <string>
#include <vector>

TEST(CliIntegrationTest, PublicCommandsKeepTheirDomainResultsWithOneDuration) {
    auto workspace = kasumi::test::make_temp_workspace("cli-contract");
    const auto root = kasumi::test::workspace_root(workspace);
    const auto appdata =
        kasumi::test::scoped_environment_variable("APPDATA", root.string());
    const auto xdg = kasumi::test::scoped_environment_variable(
        "XDG_CONFIG_HOME", root.string());
    const auto language =
        kasumi::test::scoped_environment_variable("KASUMI_LANG", "en");
    const auto key = kasumi::test::scoped_environment_variable(
        "KASUMI_MASTER_KEY", std::nullopt);
    const kasumi::application::ExecutionEnvironment environment{root /
                                                                "kasumi"};
    const kasumi::application::Profile profile{
        "demo", root / "local", (root / "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment,
        profile,
        kasumi::application::MasterKeyHex{std::string(64, '7')}));
    kasumi::test::write_text(
        profile.local_dir / kasumi::platform::path::from_utf8("álbum-日本.txt"),
        "contents");

    const auto invoke = [](std::vector<std::string> arguments, int expected) {
        std::vector<char*> argv;
        for (auto& argument : arguments)
            argv.push_back(argument.data());
        testing::internal::CaptureStdout();
        testing::internal::CaptureStderr();
        const int code =
            kasumi::cli::run(static_cast<int>(argv.size()), argv.data());
        const auto out = testing::internal::GetCapturedStdout();
        const auto err = testing::internal::GetCapturedStderr();
        SCOPED_TRACE(testing::PrintToString(arguments) + "\n" + out + err);
        EXPECT_EQ(code, expected);
        EXPECT_TRUE(err.empty());
        EXPECT_TRUE(std::regex_search(
            out, std::regex(R"(Duration: [0-9]+\.[0-9]{3} s\r?\n)")));
        const auto first = out.find("Duration:");
        if (first != std::string::npos) {
            EXPECT_EQ(out.find("Duration:", first + 1), std::string::npos);
        }
    };

    for (const auto& tail : std::vector<std::vector<std::string>>{
             {"sync", "demo"},
             {"sync", "demo", "--dry-run"},
             {"status", "demo", "--full"},
             {"fsck", "demo"},
             {"gc", "demo"},
             {"resolve-missing", "demo"},
             {"remote", "summary", "demo"},
             {"remote", "heads", "demo"},
             {"remote", "tree", "demo"},
             {"remote", "commits", "demo"},
             {"remote", "stat", "demo", "álbum-日本.txt"},
             {"remote", "contents", "demo"},
             {"remote", "contents", "demo", "--audit"},
             {"remote", "epochs", "demo"},
             {"remote", "markers", "demo"},
             {"remote", "objects", "demo"},
             {"remote", "orphans", "demo"},
             {"remote", "writers", "demo"},
             {"remote", "health", "demo"},
             {"remote",
              "get",
              "demo",
              "álbum-日本.txt",
              (root / "download.txt").string()}}) {
        std::vector<std::string> arguments{"kasumi"};
        arguments.insert(arguments.end(), tail.begin(), tail.end());
        invoke(arguments, 0);
    }
    EXPECT_EQ(kasumi::test::read_text(root / "download.txt"), "contents");
    invoke({"kasumi", "remote", "stat", "demo", "missing.txt"}, 1);
    invoke({"kasumi", "fsck", "unknown"}, 1);
}
