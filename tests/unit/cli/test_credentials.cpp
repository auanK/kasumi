#include "application/profile.hpp"
#include "cli/app.hpp"
#include "cli/credentials.hpp"
#include "cli/wizard.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/scoped_environment.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/cancellation.hpp"

#include <cstdio>
#include <gtest/gtest.h>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

TEST(CliCredentialsTest, ReadsSecretFromEnvironmentWithoutPrompt) {
    auto secret = kasumi::test::scoped_environment_variable(
        "KASUMI_TEST_SECRET", "secret-value");
    testing::internal::CaptureStdout();

    const auto result = kasumi::cli::credentials::read_secret(
        "KASUMI_TEST_SECRET", "prompt that must not appear");
    const auto output = testing::internal::GetCapturedStdout();

    EXPECT_EQ(result, "secret-value");
    EXPECT_TRUE(output.empty());
}

TEST(CliCredentialsTest, RepeatsPasswordAndSaltUntilConfirmed) {
    auto password = kasumi::test::scoped_environment_variable("KASUMI_PASSWORD",
                                                              std::nullopt);
    auto salt = kasumi::test::scoped_environment_variable("KASUMI_PASSWORD2",
                                                          std::nullopt);
    kasumi::platform::cancellation::reset();
    const std::vector<std::string> answers{
        "password",
        "wrong",
        "password",
        "password",
        "salt",
        "wrong",
        "salt",
        "salt",
    };
    std::size_t next = 0;
    testing::internal::CaptureStdout();

    const auto result =
        kasumi::cli::credentials::read_password_pair([&](const std::string&) {
            return answers.at(next++);
        });
    const auto output = testing::internal::GetCapturedStdout();

    EXPECT_EQ(result.password, "password");
    EXPECT_EQ(result.salt_password, "salt");
    EXPECT_EQ(next, answers.size());
    EXPECT_NE(output.find("Passwords do not match"), std::string::npos);
    EXPECT_NE(output.find("Password salt values do not match"),
              std::string::npos);
}

TEST(CliCredentialsTest, UsesPasswordSaltTerminologyInPrompts) {
    auto password = kasumi::test::scoped_environment_variable("KASUMI_PASSWORD",
                                                              std::nullopt);
    auto salt = kasumi::test::scoped_environment_variable("KASUMI_PASSWORD2",
                                                          std::nullopt);
    kasumi::platform::cancellation::reset();
    const std::vector<std::string> answers{
        "password-long", "password-long", "salt-password", "salt-password"};
    std::size_t next = 0;
    const auto result = kasumi::cli::credentials::read_password_pair(
        [&](const std::string& prompt) {
            EXPECT_TRUE(prompt == "Password: " || prompt == "Confirm password: " ||
                        prompt == "Password salt: " ||
                        prompt == "Confirm password salt: ");
            return answers.at(next++);
        });

    EXPECT_EQ(result.password, "password-long");
    EXPECT_EQ(result.salt_password, "salt-password");
    EXPECT_EQ(next, answers.size());
}

TEST(CliAppTest, PrintsSynchronizationProgressOnce) {
    auto workspace = kasumi::test::make_temp_workspace("cli-sync-progress");
#if defined(_WIN32)
    auto scoped_root = kasumi::test::scoped_environment_variable(
        "APPDATA", kasumi::test::workspace_path(workspace, "appdata").string());
#else
    auto scoped_root = kasumi::test::scoped_environment_variable(
        "XDG_CONFIG_HOME",
        kasumi::test::workspace_path(workspace, "config").string());
#endif
    char command[] = "kasumi";
    char operation[] = "sync";
    char profile[] = "missing";
    char* argv[] = {command, operation, profile};
    testing::internal::CaptureStdout();

    EXPECT_EQ(kasumi::cli::run(3, argv), 1);

    const auto output = testing::internal::GetCapturedStdout();
    std::size_t occurrences = 0;
    std::size_t position = 0;
    while ((position = output.find("Synchronizing...", position)) !=
           std::string::npos) {
        ++occurrences;
        position += std::string{"Synchronizing..."}.size();
    }
    EXPECT_EQ(occurrences, 1U);
    EXPECT_EQ(output.find("[Synchronizing]"), std::string::npos);
}

TEST(CliAppTest, PrintsMinimalHelpWithoutRuntimeAccess) {
    char command[] = "kasumi";
    char help[] = "help";
    char* argv[] = {command, help};
    testing::internal::CaptureStdout();

    EXPECT_EQ(kasumi::cli::run(2, argv), 0);

    const auto output = testing::internal::GetCapturedStdout();
    EXPECT_NE(output.find("kasumi sync <profile>"), std::string::npos);
    EXPECT_NE(output.find("kasumi remote contents --audit <profile>"),
              std::string::npos);
    EXPECT_NE(output.find("does not run GC"), std::string::npos);
    EXPECT_NE(output.find("health diagnostic"), std::string::npos);
}

TEST(CliAppTest, PrintsHelpInPortugueseWhenFlagProvided) {
    char command[] = "kasumi";
    char lang_flag[] = "--lang";
    char lang_val[] = "pt";
    char help[] = "help";
    char* argv[] = {command, lang_flag, lang_val, help};
    testing::internal::CaptureStdout();

    EXPECT_EQ(kasumi::cli::run(4, argv), 0);

    const auto output = testing::internal::GetCapturedStdout();
    EXPECT_NE(output.find("kasumi sync <perfil>"), std::string::npos);
    EXPECT_NE(output.find("não executa GC"), std::string::npos);
    EXPECT_NE(output.find("diagnóstico remoto completo"), std::string::npos);
}

TEST(CliWizardTest, RejectsDuplicateNameBeforeOtherPrompts) {
    auto workspace = kasumi::test::make_temp_workspace("cli-duplicate-profile");
    const kasumi::application::ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const kasumi::application::Profile profile{
        "existing",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string(),
    };
    ASSERT_TRUE(kasumi::application::create_profile(
        environment,
        profile,
        kasumi::application::MasterKeyHex{std::string(64, '1')}));
    std::istringstream input{"n\nexisting\nq\n"};
    auto* previous_input = std::cin.rdbuf(input.rdbuf());
    testing::internal::CaptureStdout();

    kasumi::cli::run_config_wizard(environment);

    std::fflush(stdout);
    const auto output = testing::internal::GetCapturedStdout();
    std::cin.rdbuf(previous_input);
    EXPECT_NE(output.find("The profile 'existing' already exists"), std::string::npos);
    EXPECT_EQ(output.find("Synchronized local path"), std::string::npos);
}

TEST(CliWizardTest, CreatesProfileWithHiddenRetentionDefaults) {
    auto workspace = kasumi::test::make_temp_workspace("cli-profile-defaults");
    const kasumi::application::ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    auto password = kasumi::test::scoped_environment_variable("KASUMI_PASSWORD",
                                                              "password-long");
    auto salt = kasumi::test::scoped_environment_variable("KASUMI_PASSWORD2",
                                                          "salt-password-long");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    std::istringstream input{"n\nnew-profile\n" + local.string() + "\n" +
                             remote.string() + "\nq\n"};
    auto* previous_input = std::cin.rdbuf(input.rdbuf());
    testing::internal::CaptureStdout();

    kasumi::cli::run_config_wizard(environment);

    const auto output = testing::internal::GetCapturedStdout();
    std::cin.rdbuf(previous_input);
    ASSERT_EQ(output.find("Profundidade mínima do histórico"),
              std::string::npos);
    ASSERT_EQ(output.find("Retenção mínima em horas"), std::string::npos);

    const auto profiles = kasumi::application::list_profiles(environment);
    ASSERT_TRUE(profiles.has_value());
    ASSERT_EQ(profiles->size(), 1U);
    EXPECT_EQ(profiles->front().min_history_depth, 5U);
    EXPECT_EQ(profiles->front().min_history_age_hours, 6U);

    const auto config =
        kasumi::test::workspace_path(workspace, "app/config.toml");
    const auto config_text = kasumi::test::read_text(config);
    EXPECT_NE(config_text.find("min_history_depth = 5"), std::string::npos);
    EXPECT_NE(config_text.find("min_history_age_hours = 6"), std::string::npos);
}

TEST(CliWizardTest, EditingProfilePreservesManualRetentionValues) {
    auto workspace = kasumi::test::make_temp_workspace("cli-profile-edit");
    const kasumi::application::ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const auto old_local = kasumi::test::workspace_path(workspace, "old-local");
    const auto new_local = kasumi::test::workspace_path(workspace, "new-local");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const kasumi::application::Profile profile{.name = "advanced",
                                               .local_dir = old_local,
                                               .remote_dir = remote.string(),
                                               .min_history_depth = 9,
                                               .min_history_age_hours = 18};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment,
        profile,
        kasumi::application::MasterKeyHex{std::string(64, '1')}));

    std::istringstream input{"e\nadvanced\n" + new_local.string() + "\n\nq\n"};
    auto* previous_input = std::cin.rdbuf(input.rdbuf());
    testing::internal::CaptureStdout();

    kasumi::cli::run_config_wizard(environment);

    const auto output = testing::internal::GetCapturedStdout();
    std::cin.rdbuf(previous_input);
    EXPECT_EQ(output.find("Política do histórico"), std::string::npos);
    EXPECT_EQ(output.find("Profundidade mínima"), std::string::npos);
    EXPECT_EQ(output.find("Retenção mínima"), std::string::npos);

    const auto profiles = kasumi::application::list_profiles(environment);
    ASSERT_TRUE(profiles.has_value());
    ASSERT_EQ(profiles->size(), 1U);
    EXPECT_EQ(profiles->front().local_dir, new_local);
    EXPECT_EQ(profiles->front().min_history_depth, 9U);
    EXPECT_EQ(profiles->front().min_history_age_hours, 18U);
}
