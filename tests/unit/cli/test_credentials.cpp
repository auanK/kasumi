#include "application/profile.hpp"
#include "cli/app.hpp"
#include "cli/credentials.hpp"
#include "cli/i18n.hpp"
#include "cli/wizard.hpp"
#include "core/hasher.hpp"
#include "core/node.hpp"
#include "kasumi/test/capture.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/scoped_environment.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/cancellation.hpp"
#include "runtime/paths.hpp"
#include "state_storage/database.hpp"

#include <cstdio>
#include <filesystem>
#include <gtest/gtest.h>
#include <initializer_list>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

std::string run_cli_out(std::initializer_list<const char*> arguments,
                        int expected_code) {
    std::vector<std::string> storage(arguments.begin(), arguments.end());
    std::vector<char*> argv;
    argv.reserve(storage.size());
    for (auto& value : storage) {
        argv.push_back(value.data());
    }
    return kasumi::test::capture_stdout([&] {
        EXPECT_EQ(kasumi::cli::run(static_cast<int>(argv.size()), argv.data()),
                  expected_code);
    });
}

std::string run_wizard_out(const kasumi::application::ExecutionEnvironment& env,
                           std::string_view stdin_text,
                           int* exit_code = nullptr) {
    kasumi::platform::cancellation::reset();
    std::istringstream input{std::string{stdin_text}};
    auto* previous_input = std::cin.rdbuf(input.rdbuf());
    std::string output = kasumi::test::capture_stdout([&] {
        const int result = kasumi::cli::run_config_wizard(env);
        std::fflush(stdout);
        if (exit_code != nullptr) {
            *exit_code = result;
        }
    });
    std::cin.rdbuf(previous_input);
    std::cin.clear();
    return output;
}

} // namespace

TEST(CliCredentialsTest, ReadsSecretFromEnvironmentWithoutPrompt) {
    auto secret = kasumi::test::scoped_environment_variable(
        "KASUMI_TEST_SECRET", "secret-value");
    std::string result;
    const auto output = kasumi::test::capture_stdout([&] {
        result = kasumi::cli::credentials::read_secret(
            "KASUMI_TEST_SECRET", "prompt that must not appear");
    });

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
        "tiny",
        "password-long",
        "wrong",
        "password-long",
        "password-long",
        "salt-password-long",
        "wrong",
        "salt-password-long",
        "salt-password-long",
    };
    std::size_t next = 0;
    kasumi::application::PasswordPair result;
    const auto output = kasumi::test::capture_stdout([&] {
        result = kasumi::cli::credentials::read_password_pair(
            [&](const std::string&) {
                return answers.at(next++);
            });
    });

    EXPECT_EQ(result.password, "password-long");
    EXPECT_EQ(result.salt_password, "salt-password-long");
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
    const std::vector<std::string> answers{"password-long",
                                           "password-long",
                                           "salt-password-long",
                                           "salt-password-long"};
    std::size_t next = 0;
    const auto result = kasumi::cli::credentials::read_password_pair(
        [&](const std::string& prompt) {
            EXPECT_TRUE(prompt == "Password: " ||
                        prompt == "Confirm password: " ||
                        prompt == "Password salt: " ||
                        prompt == "Confirm password salt: ");
            return answers.at(next++);
        });

    EXPECT_EQ(result.password, "password-long");
    EXPECT_EQ(result.salt_password, "salt-password-long");
    EXPECT_EQ(next, answers.size());
}

TEST(CliAppTest, PrintsSynchronizationProgressOnce) {
    auto workspace = kasumi::test::make_temp_workspace("cli-sync-progress");
    auto scoped_root = kasumi::test::scoped_config_home(
        kasumi::test::workspace_path(workspace, "config"));
    const auto output = run_cli_out({"kasumi", "sync", "missing"}, 1);
    const auto expected_starting = "Synchronizing \"missing\"...";
    std::size_t occurrences = 0;
    std::size_t position = 0;
    while ((position = output.find(expected_starting, position)) !=
           std::string::npos) {
        ++occurrences;
        position += std::string{expected_starting}.size();
    }
    EXPECT_EQ(occurrences, 1U);
    EXPECT_EQ(output.find("[Synchronizing]"), std::string::npos);
}

TEST(CliAppTest, PrintsMinimalHelpWithoutRuntimeAccess) {
    const auto output = run_cli_out({"kasumi", "--help"}, 0);
    EXPECT_NE(output.find("kasumi start"), std::string::npos);
    EXPECT_NE(output.find("kasumi logs"), std::string::npos);
    EXPECT_NE(output.find("--help --all"), std::string::npos);
    EXPECT_NE(output.find("--quiet"), std::string::npos);
    EXPECT_NE(output.find("--json"), std::string::npos);

    const auto full_output = run_cli_out({"kasumi", "--help", "--all"}, 0);
    EXPECT_NE(full_output.find("kasumi sync <profile>"), std::string::npos);
    EXPECT_NE(full_output.find("kasumi remote contents <profile> --audit"),
              std::string::npos);
    EXPECT_NE(full_output.find("does not run GC"), std::string::npos);
    EXPECT_NE(full_output.find("health diagnostic"), std::string::npos);
    EXPECT_NE(full_output.find(
                  "Analyze or run garbage collection on safe objects."),
              std::string::npos);
}

TEST(CliAppTest, PrintsHelpInPortugueseWhenFlagProvided) {
    const auto output = run_cli_out({"kasumi", "--lang", "pt", "--help"}, 0);
    EXPECT_NE(output.find("kasumi start"), std::string::npos);
    EXPECT_NE(output.find("kasumi logs"), std::string::npos);
    EXPECT_NE(output.find("--help --all"), std::string::npos);
    EXPECT_NE(output.find("--quiet"), std::string::npos);
    EXPECT_NE(output.find("--json"), std::string::npos);

    const auto full_output =
        run_cli_out({"kasumi", "--lang", "pt", "--help", "--all"}, 0);
    EXPECT_NE(full_output.find("kasumi sync <perfil>"), std::string::npos);
    EXPECT_NE(full_output.find("não executa GC"), std::string::npos);
    EXPECT_NE(full_output.find("diagnóstico remoto completo"),
              std::string::npos);
    EXPECT_NE(full_output.find(
                  "Analisa ou executa a coleta de lixo de objetos seguros."),
              std::string::npos);
    kasumi::cli::i18n::set_language(kasumi::cli::i18n::Language::English);
}

TEST(CliAppTest, PrintsPreviewStartingProgressOnce) {
    auto workspace = kasumi::test::make_temp_workspace("cli-app-preview");
    auto scoped_root = kasumi::test::scoped_config_home(
        kasumi::test::workspace_path(workspace, "config"));
    auto scoped_lang =
        kasumi::test::scoped_environment_variable("KASUMI_LANG", "en");
    const auto output =
        run_cli_out({"kasumi", "sync", "missing", "--dry-run"}, 1);
    const auto expected_starting =
        "Simulating synchronization of \"missing\"...";
    EXPECT_NE(output.find(expected_starting), std::string::npos);
    EXPECT_NE(output.find("[ERROR]"), std::string::npos);
}

TEST(CliAppTest, PrintsStatusStartingProgressOnce) {
    auto workspace = kasumi::test::make_temp_workspace("cli-app-status");
    auto scoped_root = kasumi::test::scoped_config_home(
        kasumi::test::workspace_path(workspace, "config"));
    auto scoped_lang =
        kasumi::test::scoped_environment_variable("KASUMI_LANG", "en");
    const auto output = run_cli_out({"kasumi", "status", "missing"}, 1);
    const auto expected_starting = "Checking status of \"missing\"...";
    EXPECT_NE(output.find(expected_starting), std::string::npos);
    EXPECT_NE(output.find("[ERROR]"), std::string::npos);
}

TEST(CliAppTest, AcceptsFullFlagOnStatusAndPreview) {
    auto workspace = kasumi::test::make_temp_workspace("cli-app-full-flag");
    auto scoped_root = kasumi::test::scoped_config_home(
        kasumi::test::workspace_path(workspace, "config"));
    auto scoped_lang =
        kasumi::test::scoped_environment_variable("KASUMI_LANG", "en");
    const auto output =
        run_cli_out({"kasumi", "status", "missing", "--full"}, 1);
    EXPECT_NE(output.find("Checking status of \"missing\"..."),
              std::string::npos);
    EXPECT_NE(output.find("[ERROR]"), std::string::npos);
}

TEST(CliAppTest, PrintsGarbageCollectStartingProgressOnce) {
    auto workspace = kasumi::test::make_temp_workspace("cli-gc-progress");
    auto scoped_root = kasumi::test::scoped_config_home(
        kasumi::test::workspace_path(workspace, "config"));
    const auto output = run_cli_out({"kasumi", "gc", "missing"}, 1);
    const auto expected_starting =
        "Running garbage collection for \"missing\"...";
    EXPECT_NE(output.find(expected_starting), std::string::npos);
}

TEST(CliAppTest, PrintsGarbageCollectStartingProgressInPortuguese) {
    auto workspace = kasumi::test::make_temp_workspace("cli-gc-progress-pt");
    auto scoped_root = kasumi::test::scoped_config_home(
        kasumi::test::workspace_path(workspace, "config"));
    const auto output =
        run_cli_out({"kasumi", "--lang", "pt-BR", "gc", "missing"}, 1);
    const auto expected_starting =
        "Executando coleta de lixo em \"missing\"...";
    EXPECT_NE(output.find(expected_starting), std::string::npos);
    kasumi::cli::i18n::set_language(kasumi::cli::i18n::Language::English);
}

TEST(CliAppTest, PrintsFsckStartingProgressOnce) {
    auto workspace = kasumi::test::make_temp_workspace("cli-fsck-progress");
    auto scoped_root = kasumi::test::scoped_config_home(
        kasumi::test::workspace_path(workspace, "config"));
    const auto output = run_cli_out({"kasumi", "fsck", "missing"}, 1);
    const std::string starting = "Auditing \"missing\"...";
    const auto first = output.find(starting);
    ASSERT_NE(first, std::string::npos);
    EXPECT_EQ(output.find(starting, first + starting.size()),
              std::string::npos);
    EXPECT_NE(output.find("[ERROR]"), std::string::npos);
}

TEST(CliAppTest, PrintsFsckStartingProgressInPortuguese) {
    auto workspace = kasumi::test::make_temp_workspace("cli-fsck-progress-pt");
    auto scoped_root = kasumi::test::scoped_config_home(
        kasumi::test::workspace_path(workspace, "config"));
    const auto output =
        run_cli_out({"kasumi", "--lang", "pt-BR", "fsck", "missing"}, 1);
    const std::string starting = "Auditando \"missing\"...";
    const auto first = output.find(starting);
    ASSERT_NE(first, std::string::npos);
    EXPECT_EQ(output.find(starting, first + starting.size()),
              std::string::npos);
    EXPECT_NE(output.find("[ERRO]"), std::string::npos);
    kasumi::cli::i18n::set_language(kasumi::cli::i18n::Language::English);
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
    const auto output = run_wizard_out(environment, "n\nexisting\n");
    EXPECT_NE(output.find("The profile 'existing' already exists"),
              std::string::npos);
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
    kasumi::cli::i18n::set_language(kasumi::cli::i18n::Language::Portuguese);
    const auto output = run_wizard_out(
        environment,
        "n\nbad/name\nnew-profile\nrelative\n" + local.string() +
            "\ngdrive:../invalid\n" + remote.string() + "\n\nq\n");
    kasumi::cli::i18n::set_language(kasumi::cli::i18n::Language::English);
    EXPECT_EQ(output.find("invalid profile name"), std::string::npos);
    EXPECT_EQ(output.find("local path must be absolute"), std::string::npos);
    EXPECT_NE(output.find("Destino inválido"), std::string::npos);
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

    const auto output = run_wizard_out(
        environment, "e\nadvanced\n" + new_local.string() + "\n\n\n\ny\nq\n");
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

TEST(CliWizardTest, ListsAllLocalStatesInBothLanguagesWithoutSideEffects) {
    auto workspace = kasumi::test::make_temp_workspace("cli-profile-states");
    const kasumi::application::ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const std::vector<std::string> names{
        "initialized", "ready", "pending", "problem"};
    for (const auto& name : names) {
        const auto local_dir = kasumi::test::workspace_path(workspace, name);
        ASSERT_TRUE(std::filesystem::create_directory(local_dir));
        const kasumi::application::Profile profile{
            .name = name,
            .local_dir = local_dir,
            .remote_dir = "unavailable:must-not-be-read",
            .key_storage = kasumi::application::KeyStorage::File};
        ASSERT_TRUE(kasumi::application::create_profile(
            environment,
            profile,
            kasumi::application::MasterKeyHex{std::string(64, '1')}));
    }

    kasumi::Snapshot tree{{
        {.path = "", .is_directory = true},
        {.path = "file.txt",
         .hash = kasumi::hasher::hash_string("wizard state"),
         .size = 12,
         .mtime = 1,
         .is_directory = false},
    }};
    kasumi::finalize_snapshot(tree);
    for (const auto& name : {std::string{"ready"}, std::string{"pending"}}) {
        const auto paths = kasumi::runtime::resolve_profile_paths(
            environment.app_data_dir, name);
        ASSERT_TRUE(paths.has_value());
        kasumi::state_storage::StoredState state{
            .tree = tree,
            .height = 1,
            .commit_id = std::string(64, 'a'),
            .ciphertext_id = {},
            .epoch_id = {},
            .epoch_sequence = 0,
            .pending_materializations = {},
        };
        if (name == "pending") {
            state.pending_materializations.push_back(tree.rows[1]);
        }
        ASSERT_TRUE(
            kasumi::state_storage::save_state(paths->database_path, state));
    }
    const auto problem_paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "problem");
    ASSERT_TRUE(problem_paths.has_value());
    ASSERT_TRUE(std::filesystem::remove(problem_paths->key_path));

    const auto before =
        kasumi::test::snapshot_tree(kasumi::test::workspace_root(workspace));
    const std::vector<std::pair<std::string, std::string>> displayed_states{
        {"initialized", "Initialized"},
        {"ready", "Ready"},
        {"pending", "Pending"},
        {"problem", "Problem"}};
    for (const auto language : {kasumi::cli::i18n::Language::English,
                                kasumi::cli::i18n::Language::Portuguese}) {
        kasumi::cli::i18n::set_language(language);
        int result = 0;
        const auto output = run_wizard_out(environment, "q\n", &result);

        EXPECT_EQ(result, 0);
        for (const auto& [name, state] : displayed_states) {
            const auto position = output.find(name);
            ASSERT_NE(position, std::string::npos) << output;
            std::istringstream row{output.substr(position)};
            std::string displayed_name, displayed_state;
            row >> displayed_name >> displayed_state;
            EXPECT_EQ(displayed_name, name);
            EXPECT_EQ(displayed_state, state);
        }
    }
    kasumi::cli::i18n::set_language(kasumi::cli::i18n::Language::English);
    EXPECT_EQ(
        before,
        kasumi::test::snapshot_tree(kasumi::test::workspace_root(workspace)));
}

TEST(CliWizardTest, ChangesProfileKeyStorageAndCleansPreviousKey) {
    auto workspace =
        kasumi::test::make_temp_workspace("cli-profile-key-storage");
    const kasumi::application::ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const kasumi::application::Profile profile{
        .name = "storage_demo",
        .local_dir = local,
        .remote_dir = remote.string(),
        .key_storage = kasumi::application::KeyStorage::File};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment,
        profile,
        kasumi::application::MasterKeyHex{std::string(64, '2')}));
    const auto paths = kasumi::runtime::resolve_profile_paths(
        environment.app_data_dir, "storage_demo");
    ASSERT_TRUE(paths.has_value());
    ASSERT_TRUE(std::filesystem::exists(paths->key_path));

    auto password = kasumi::test::scoped_environment_variable("KASUMI_PASSWORD",
                                                              "password-long");
    auto salt = kasumi::test::scoped_environment_variable("KASUMI_PASSWORD2",
                                                          "salt-password-long");

    const auto to_memory =
        run_wizard_out(environment, "s\nstorage_demo\ninvalid\nmemory\nq\n");
    EXPECT_NE(to_memory.find("Invalid key storage mode"), std::string::npos);
    EXPECT_NE(to_memory.find("set to 'memory'"), std::string::npos);
    EXPECT_FALSE(std::filesystem::exists(paths->key_path));

    auto profiles = kasumi::application::list_profiles(environment);
    ASSERT_TRUE(profiles.has_value());
    ASSERT_EQ(profiles->size(), 1U);
    EXPECT_EQ(profiles->front().key_storage,
              kasumi::application::KeyStorage::Memory);
    EXPECT_EQ(kasumi::application::inspect_profile_local_state(environment,
                                                               "storage_demo"),
              kasumi::application::ProfileLocalState::Initialized);

    const auto to_file =
        run_wizard_out(environment, "s\nstorage_demo\nfile\nq\n");
    EXPECT_NE(to_file.find("kasumi key storage_demo"), std::string::npos);
    EXPECT_EQ(kasumi::application::inspect_profile_local_state(environment,
                                                               "storage_demo"),
              kasumi::application::ProfileLocalState::Problem);

    const auto rekey = run_wizard_out(environment, "k\nstorage_demo\nq\n");
    EXPECT_NE(rekey.find("Key saved for profile 'storage_demo'"),
              std::string::npos);
    EXPECT_TRUE(std::filesystem::exists(paths->key_path));
    EXPECT_EQ(kasumi::application::inspect_profile_local_state(environment,
                                                               "storage_demo"),
              kasumi::application::ProfileLocalState::Initialized);
}
