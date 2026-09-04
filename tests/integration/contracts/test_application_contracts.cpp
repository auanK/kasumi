#include "application/execute.hpp"
#include "application/profile.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"

#include <filesystem>
#include <gtest/gtest.h>
#include <string>

namespace {

TEST(ApplicationContractTest,
     ProfileVaultExecuteAndReadOnlyPreviewCrossPublicBoundaries) {
    auto workspace =
        kasumi::test::make_temp_workspace("contract-application-boundary");
    const kasumi::application::ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const kasumi::application::Profile first{
        "first",
        kasumi::test::workspace_path(workspace, "client-a"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    const kasumi::application::Profile second{
        "second",
        kasumi::test::workspace_path(workspace, "client-b"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    const kasumi::application::MasterKeyHex key{std::string(64, '4')};
    ASSERT_TRUE(kasumi::application::create_profile(environment, first, key));
    ASSERT_TRUE(kasumi::application::create_profile(environment, second, key));
    kasumi::test::write_text(first.local_dir / "shared.txt",
                             "through application");

    auto sync = kasumi::application::execute(
        {{kasumi::application::Operation::Sync, "first"},
         kasumi::application::Credentials{kasumi::application::NoCredentials{}},
         environment});
    ASSERT_TRUE(sync.has_value()) << sync.error().detail;
    const auto second_sync = kasumi::application::execute(
        {{kasumi::application::Operation::Sync, "second"},
         kasumi::application::Credentials{kasumi::application::NoCredentials{}},
         environment});
    ASSERT_TRUE(second_sync.has_value()) << second_sync.error().detail;
    kasumi::test::write_text(first.local_dir / "shared.txt", "updated");
    ASSERT_TRUE(kasumi::application::execute(
                    {{kasumi::application::Operation::Sync, "first"},
                     kasumi::application::Credentials{
                         kasumi::application::NoCredentials{}},
                     environment})
                    .has_value());
    auto preview = kasumi::application::execute(
        {{kasumi::application::Operation::Preview, "second"},
         kasumi::application::Credentials{kasumi::application::NoCredentials{}},
         environment});
    ASSERT_TRUE(preview.has_value()) << preview.error().detail;
    ASSERT_TRUE(
        std::holds_alternative<kasumi::application::PlanReport>(preview->data));
    EXPECT_TRUE(std::filesystem::exists(kasumi::test::workspace_path(
        workspace, "app/profiles/second/db.sqlite")));
    ASSERT_TRUE(kasumi::application::execute(
                    {{kasumi::application::Operation::Sync, "second"},
                     kasumi::application::Credentials{
                         kasumi::application::NoCredentials{}},
                     environment})
                    .has_value());
    EXPECT_EQ(kasumi::test::read_text(second.local_dir / "shared.txt"),
              "updated");
}

TEST(ApplicationContractTest,
     WrongKeyDoesNotCrossHistoryOrTransactionBoundary) {
    auto workspace = kasumi::test::make_temp_workspace("contract-wrong-key");
    const kasumi::application::ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const kasumi::application::Profile profile{
        "secure",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment,
        profile,
        kasumi::application::MasterKeyHex{std::string(64, '5')}));
    kasumi::test::write_text(profile.local_dir / "secret.txt", "secret");
    ASSERT_TRUE(kasumi::application::execute(
                    {{kasumi::application::Operation::Sync, "secure"},
                     kasumi::application::Credentials{
                         kasumi::application::NoCredentials{}},
                     environment})
                    .has_value());
    const auto wrong = kasumi::application::execute(
        {{kasumi::application::Operation::Preview, "secure"},
         kasumi::application::Credentials{
             kasumi::application::MasterKeyHex{std::string(64, '6')}},
         environment});
    EXPECT_FALSE(wrong.has_value());
    EXPECT_TRUE(
        wrong.error().code == kasumi::application::ErrorCode::PlanFailure ||
        wrong.error().code == kasumi::application::ErrorCode::RuntimeFailure);
    EXPECT_EQ(kasumi::test::read_text(profile.local_dir / "secret.txt"),
              "secret");
}

} // namespace
