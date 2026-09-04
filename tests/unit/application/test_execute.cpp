#include "application/execute.hpp"
#include "application/profile.hpp"
#include "application/use_cases/context.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/profile_lock.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <string_view>

namespace {

using kasumi::application::Credentials;
using kasumi::application::ErrorCode;
using kasumi::application::ExecutionEnvironment;
using kasumi::application::MasterKeyHex;
using kasumi::application::NoCredentials;
using kasumi::application::Operation;
using kasumi::application::Profile;
using kasumi::application::Request;
using kasumi::application::RuntimeSummary;
using kasumi::test::TempWorkspace;

MasterKeyHex key() {
    return MasterKeyHex{std::string(64, '2')};
}

void write_profile(const TempWorkspace& workspace) {
    std::filesystem::create_directories(
        kasumi::test::workspace_path(workspace, "app"));
    kasumi::test::write_text(
        kasumi::test::workspace_path(workspace, "app/config.toml"),
        "[profiles.demo]\nlocal_dir = '" +
            kasumi::test::workspace_path(workspace, "local").string() +
            "'\nremote_dir = '" +
            kasumi::test::workspace_path(workspace, "remote").string() +
            "'\nmin_history_depth = 5\nmin_history_age_hours = 6\n");
}

RuntimeSummary summary() {
    return {.local_dir = "local", .remote_dir = "remote"};
}

TEST(ApplicationExecuteTest, MissingProfileMapsToPublicApplicationError) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-execute-missing");
    write_profile(workspace);
    const auto result = kasumi::application::execute(
        {Request{Operation::Status, "missing"},
         Credentials{NoCredentials{}},
         ExecutionEnvironment{kasumi::test::workspace_path(workspace, "app")}});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().operation, Operation::Status);
    EXPECT_EQ(result.error().code, ErrorCode::ProfileNotFound);
}

TEST(ApplicationExecuteTest, NoCredentialsUsesDifferentPublicCodesByOperation) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-execute-credentials");
    write_profile(workspace);
    const auto sync = kasumi::application::execute(
        {Request{Operation::Sync, "demo"},
         Credentials{NoCredentials{}},
         ExecutionEnvironment{kasumi::test::workspace_path(workspace, "app")}});
    ASSERT_FALSE(sync.has_value());
    EXPECT_EQ(sync.error().code, ErrorCode::CredentialFailure);

    const auto status = kasumi::application::execute(
        {Request{Operation::Status, "demo"},
         Credentials{NoCredentials{}},
         ExecutionEnvironment{kasumi::test::workspace_path(workspace, "app")}});
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, ErrorCode::CredentialFailure);
}

TEST(ApplicationExecuteTest,
     InvalidMasterKeyIsCredentialFailureAndCredentialsAreWiped) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-execute-key");
    write_profile(workspace);
    const auto result = kasumi::application::execute(
        {Request{Operation::Preview, "demo"},
         Credentials{MasterKeyHex{"invalid"}},
         ExecutionEnvironment{kasumi::test::workspace_path(workspace, "app")}});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().operation, Operation::Preview);
    EXPECT_EQ(result.error().code, ErrorCode::CredentialFailure);
}

TEST(ApplicationExecuteTest, ProvidedMasterKeyMustMatchProfileVault) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-execute-wrong-key");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, profile, MasterKeyHex{std::string(64, '5')}));

    const auto result = kasumi::application::execute(
        {Request{Operation::Preview, "demo"},
         Credentials{MasterKeyHex{std::string(64, '6')}},
         environment});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::RuntimeFailure);
}

TEST(ApplicationExecuteTest, ValidKeyCanReachReadOnlyApplicationBoundary) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-execute-valid");
    write_profile(workspace);
    std::filesystem::create_directories(
        kasumi::test::workspace_path(workspace, "local"));
    const auto result = kasumi::application::execute(
        {Request{Operation::Preview, "demo"},
         Credentials{key()},
         ExecutionEnvironment{kasumi::test::workspace_path(workspace, "app")}});
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->operation, Operation::Preview);
}

TEST(ApplicationExecuteTest,
     MalformedRetentionFailsBeforeKeyLockOrTransportPreparation) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-execute-retention");
    const auto app = kasumi::test::workspace_path(workspace, "app");
    std::filesystem::create_directories(app);
    kasumi::test::write_text(
        app / "config.toml",
        "[profiles.demo]\nlocal_dir = '" +
            kasumi::test::workspace_path(workspace, "local").string() +
            "'\nremote_dir = 'remote:root'\nmin_history_depth = 4097\n"
            "min_history_age_hours = 6\n");

    const auto result =
        kasumi::application::execute({Request{Operation::Preview, "demo"},
                                      Credentials{NoCredentials{}},
                                      ExecutionEnvironment{app}});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::RuntimeFailure);
    EXPECT_FALSE(std::filesystem::exists(app / "profiles"));
}

TEST(ApplicationExecuteTest, SyncPublicBoundaryRemainsSuccessful) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-sync-public");
    write_profile(workspace);
    ASSERT_TRUE(std::filesystem::create_directories(
        kasumi::test::workspace_path(workspace, "local")));

    const auto result = kasumi::application::execute(
        {Request{Operation::Sync, "demo"},
         Credentials{key()},
         ExecutionEnvironment{kasumi::test::workspace_path(workspace, "app")}});
    ASSERT_TRUE(result.has_value()) << result.error().detail;
}

TEST(ApplicationExecuteTest, ProfileLockRejectsOverlappingExecution) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-profile-lock");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    ASSERT_TRUE(std::filesystem::create_directories(profile.remote_dir));
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));

    auto acquired = kasumi::platform::acquire_profile_lock(
        environment.app_data_dir / "profile-demo.lock");
    ASSERT_TRUE(acquired.has_value()) << acquired.error();
    auto held = *acquired;

    const auto blocked = kasumi::application::execute(
        {Request{Operation::Status, "demo"}, Credentials{key()}, environment});
    ASSERT_FALSE(blocked.has_value());
    EXPECT_EQ(blocked.error().code, ErrorCode::RuntimeFailure);
    EXPECT_EQ(blocked.error().detail,
              "perfil já está em uso por outra execução");

    kasumi::platform::release_profile_lock(held);
    const auto allowed = kasumi::application::execute(
        {Request{Operation::Status, "demo"}, Credentials{key()}, environment});
    ASSERT_TRUE(allowed.has_value()) << allowed.error().detail;
}

TEST(ApplicationExecuteTest, WipeOperationIsIdempotentAndClearsKey) {
    kasumi::application::detail::OperationContext context{};
    std::fill(context.key.begin(), context.key.end(), 0xa5U);
    context.summary = summary();

    kasumi::application::detail::wipe_operation(context);
    EXPECT_TRUE(std::ranges::all_of(context.key, [](std::uint8_t value) {
        return value == 0;
    }));
    EXPECT_EQ(context.summary.remote_dir, "remote");

    kasumi::application::detail::wipe_operation(context);
    EXPECT_TRUE(std::ranges::all_of(context.key, [](std::uint8_t value) {
        return value == 0;
    }));
}

TEST(ApplicationExecuteTest,
     PrepareOperationWipesKeyWhenTransportOpeningFails) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-prepare-cleanup");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, profile, MasterKeyHex{std::string(64, '5')}));
    kasumi::test::write_text(
        kasumi::test::workspace_path(workspace, "app/config.toml"),
        "[profiles.demo]\nlocal_dir = '" + profile.local_dir.string() +
            "'\nremote_dir = 'rclone:'\nmin_history_depth = 5\n"
            "min_history_age_hours = 6\n");

    kasumi::application::detail::OperationContext context{};
    const auto prepared = kasumi::application::detail::prepare_operation(
        {Request{Operation::Preview, "demo"},
         Credentials{MasterKeyHex{std::string(64, '5')}},
         environment},
        context);

    ASSERT_FALSE(prepared.has_value());
    EXPECT_EQ(prepared.error().code, ErrorCode::RuntimeFailure);
    EXPECT_TRUE(std::ranges::all_of(context.key, [](std::uint8_t value) {
        return value == 0;
    }));
    kasumi::application::detail::wipe_operation(context);
}

} // namespace
