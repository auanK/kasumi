#include "application/environment.hpp"
#include "application/history_storage/epoch.hpp"
#include "application/profile.hpp"
#include "cli/app.hpp"
#include "kasumi/test/history_storage.hpp"
#include "kasumi/test/scoped_environment.hpp"
#include "kasumi/test/temp_workspace.hpp"

#include <algorithm>
#include <filesystem>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <vector>

namespace {

std::string key_hex() {
    constexpr char digits[] = "0123456789abcdef";
    const auto key = test_key();
    std::string result;
    result.reserve(key.size() * 2);
    for (const auto byte : key) {
        result.push_back(digits[byte >> 4U]);
        result.push_back(digits[byte & 0x0fU]);
    }
    return result;
}

void write_profile(const kasumi::application::ExecutionEnvironment& environment,
                   const std::filesystem::path& local,
                   const std::filesystem::path& remote) {
    std::filesystem::create_directories(environment.app_data_dir);
    kasumi::test::write_text(environment.app_data_dir / "config.toml",
                             "[profiles.demo]\nlocal_dir = '" + local.string() +
                                 "'\nremote_dir = '" + remote.string() +
                                 "'\nmin_history_depth = 5\n"
                                 "min_history_age_hours = 6\n");
}

TEST(RemoteHeadsContractTest, RealCliCallsInspectionWithoutMutation) {
    auto remote = make_local_storage();
    auto app_workspace =
        kasumi::test::make_temp_workspace("remote-heads-cli-contract");

#if defined(_WIN32)
    auto app_root = kasumi::test::scoped_environment_variable(
        "APPDATA",
        kasumi::test::workspace_path(app_workspace, "appdata").string());
#else
    auto app_root = kasumi::test::scoped_environment_variable(
        "XDG_CONFIG_HOME",
        kasumi::test::workspace_path(app_workspace, "config").string());
#endif
    auto master_key = kasumi::test::scoped_environment_variable(
        "KASUMI_MASTER_KEY", key_hex());
    const auto environment =
        kasumi::application::default_execution_environment();
    const auto local = kasumi::test::workspace_path(app_workspace, "local");
    write_profile(environment,
                  local,
                  kasumi::test::workspace_path(remote.workspace, "storage"));

    const auto published =
        publish(remote, make_commit(0, {}, "file.txt", "contents").value());
    ASSERT_FALSE(published.head.commit_id.empty());
    const auto before = kasumi::transport::list(remote.transport);

    char command[] = "kasumi";
    char remote_command[] = "remote";
    char heads[] = "heads";
    char profile[] = "demo";
    char* argv[] = {command, remote_command, heads, profile};
    testing::internal::CaptureStdout();
    const auto exit_code = kasumi::cli::run(4, argv);
    const auto output = testing::internal::GetCapturedStdout();

    const auto after = kasumi::transport::list(remote.transport);
    EXPECT_EQ(exit_code, 0);
    EXPECT_TRUE(output.find("Heads remotas (1)") != std::string::npos ||
                output.find("Remote heads (1)") != std::string::npos);
    EXPECT_NE(output.find(published.head.commit_id), std::string::npos);
    EXPECT_EQ(output.find("Sincronizando..."), std::string::npos);
    EXPECT_EQ(output.find("Synchronizing..."), std::string::npos);
    ASSERT_TRUE(before.has_value());
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(*before, *after);
    EXPECT_FALSE(std::filesystem::exists(local));
    EXPECT_FALSE(
        std::filesystem::exists(environment.app_data_dir / "profiles"));
}

TEST(RemoteHeadsContractTest,
     RealProfileUsesPersistedKeyWithoutEnvironmentCredentials) {
    auto remote = make_local_storage();
    auto app_workspace =
        kasumi::test::make_temp_workspace("remote-heads-real-profile");

#if defined(_WIN32)
    auto app_root = kasumi::test::scoped_environment_variable(
        "APPDATA",
        kasumi::test::workspace_path(app_workspace, "appdata").string());
#else
    auto app_root = kasumi::test::scoped_environment_variable(
        "XDG_CONFIG_HOME",
        kasumi::test::workspace_path(app_workspace, "config").string());
#endif
    auto no_master_key = kasumi::test::scoped_environment_variable(
        "KASUMI_MASTER_KEY", std::nullopt);
    auto no_password = kasumi::test::scoped_environment_variable(
        "KASUMI_PASSWORD", std::nullopt);
    auto no_password_salt = kasumi::test::scoped_environment_variable(
        "KASUMI_PASSWORD2", std::nullopt);
    const auto environment =
        kasumi::application::default_execution_environment();
    std::filesystem::create_directories(environment.app_data_dir.parent_path());
    const auto local = kasumi::test::workspace_path(app_workspace, "local");
    const kasumi::application::Profile profile{
        .name = "demo",
        .local_dir = local,
        .remote_dir =
            kasumi::test::workspace_path(remote.workspace, "storage").string()};
    const auto created = kasumi::application::create_profile(
        environment, profile, kasumi::application::MasterKeyHex{key_hex()});
    ASSERT_TRUE(created) << created.error().detail;

    const auto config_path = environment.app_data_dir / "config.toml";
    const auto key_path = environment.app_data_dir / "profiles/demo/key.bin";
    const auto config_before = kasumi::test::read_binary(config_path);
    const auto key_before = kasumi::test::read_binary(key_path);
    const auto published =
        publish(remote, make_commit(0, {}, "file.txt", "contents").value());
    ASSERT_FALSE(published.head.commit_id.empty());
    const auto before = kasumi::transport::list(remote.transport);

    char command[] = "kasumi";
    char remote_command[] = "remote";
    char heads[] = "heads";
    char profile_name[] = "demo";
    char* argv[] = {command, remote_command, heads, profile_name};
    testing::internal::CaptureStdout();
    const auto exit_code = kasumi::cli::run(4, argv);
    const auto output = testing::internal::GetCapturedStdout();

    const auto after = kasumi::transport::list(remote.transport);
    EXPECT_EQ(exit_code, 0);
    EXPECT_TRUE(output.find("Heads remotas (1)") != std::string::npos ||
                output.find("Remote heads (1)") != std::string::npos);
    EXPECT_NE(output.find(published.head.commit_id), std::string::npos);
    EXPECT_EQ(output.find("The operation completed successfully"),
              std::string::npos);
    ASSERT_TRUE(before.has_value());
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(*before, *after);
    EXPECT_EQ(kasumi::test::read_binary(config_path), config_before);
    EXPECT_EQ(kasumi::test::read_binary(key_path), key_before);
    EXPECT_FALSE(std::filesystem::exists(local));
    EXPECT_FALSE(std::filesystem::exists(environment.app_data_dir /
                                         "profiles/demo/db.sqlite"));
}

TEST(RemoteHeadsContractTest,
     RealProfileRemoteTreeUsesPersistedKeyWithoutMutation) {
    auto remote = make_local_storage();
    auto app_workspace =
        kasumi::test::make_temp_workspace("remote-tree-real-profile");

#if defined(_WIN32)
    auto app_root = kasumi::test::scoped_environment_variable(
        "APPDATA",
        kasumi::test::workspace_path(app_workspace, "appdata").string());
#else
    auto app_root = kasumi::test::scoped_environment_variable(
        "XDG_CONFIG_HOME",
        kasumi::test::workspace_path(app_workspace, "config").string());
#endif
    auto no_master_key = kasumi::test::scoped_environment_variable(
        "KASUMI_MASTER_KEY", std::nullopt);
    auto no_password = kasumi::test::scoped_environment_variable(
        "KASUMI_PASSWORD", std::nullopt);
    auto no_password_salt = kasumi::test::scoped_environment_variable(
        "KASUMI_PASSWORD2", std::nullopt);
    const auto environment =
        kasumi::application::default_execution_environment();
    std::filesystem::create_directories(environment.app_data_dir.parent_path());
    const auto local = kasumi::test::workspace_path(app_workspace, "local");
    const kasumi::application::Profile profile{
        .name = "demo",
        .local_dir = local,
        .remote_dir =
            kasumi::test::workspace_path(remote.workspace, "storage").string()};
    const auto created = kasumi::application::create_profile(
        environment, profile, kasumi::application::MasterKeyHex{key_hex()});
    ASSERT_TRUE(created) << created.error().detail;

    const auto config_path = environment.app_data_dir / "config.toml";
    const auto key_path = environment.app_data_dir / "profiles/demo/key.bin";
    const auto config_before = kasumi::test::read_binary(config_path);
    const auto key_before = kasumi::test::read_binary(key_path);
    const auto published =
        publish(remote, make_commit(0, {}, "file.txt", "contents").value());
    ASSERT_FALSE(published.head.commit_id.empty());
    const auto before = kasumi::transport::list(remote.transport);

    char command[] = "kasumi";
    char remote_command[] = "remote";
    char tree[] = "tree";
    char profile_name[] = "demo";
    char* automatic_argv[] = {command, remote_command, tree, profile_name};
    testing::internal::CaptureStdout();
    const auto automatic_exit = kasumi::cli::run(4, automatic_argv);
    const auto automatic_output = testing::internal::GetCapturedStdout();

    char explicit_command[] = "kasumi";
    char explicit_remote[] = "remote";
    char explicit_tree[] = "tree";
    char explicit_profile[] = "demo";
    char head_option[] = "--head";
    char head_id[65]{};
    std::ranges::copy(published.head.commit_id, head_id);
    char* explicit_argv[] = {explicit_command,
                             explicit_remote,
                             explicit_tree,
                             explicit_profile,
                             head_option,
                             head_id};
    testing::internal::CaptureStdout();
    const auto explicit_exit = kasumi::cli::run(6, explicit_argv);
    const auto explicit_output = testing::internal::GetCapturedStdout();

    const auto after = kasumi::transport::list(remote.transport);
    EXPECT_EQ(automatic_exit, 0);
    EXPECT_EQ(explicit_exit, 0);
    EXPECT_NE(automatic_output.find("Head: " + published.head.commit_id),
              std::string::npos);
    EXPECT_NE(automatic_output.find("file.txt"), std::string::npos);
    EXPECT_NE(explicit_output.find("Head: " + published.head.commit_id),
              std::string::npos);
    ASSERT_TRUE(before.has_value());
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(*before, *after);
    EXPECT_EQ(kasumi::test::read_binary(config_path), config_before);
    EXPECT_EQ(kasumi::test::read_binary(key_path), key_before);
    EXPECT_FALSE(std::filesystem::exists(local));
    EXPECT_FALSE(std::filesystem::exists(environment.app_data_dir /
                                         "profiles/demo/db.sqlite"));
}

TEST(RemoteHeadsContractTest,
     RealProfileRemoteCommitsUsesPersistedKeyWithoutMutation) {
    auto remote = make_local_storage();
    auto app_workspace =
        kasumi::test::make_temp_workspace("remote-commits-real-profile");

#if defined(_WIN32)
    auto app_root = kasumi::test::scoped_environment_variable(
        "APPDATA",
        kasumi::test::workspace_path(app_workspace, "appdata").string());
#else
    auto app_root = kasumi::test::scoped_environment_variable(
        "XDG_CONFIG_HOME",
        kasumi::test::workspace_path(app_workspace, "config").string());
#endif
    auto no_master_key = kasumi::test::scoped_environment_variable(
        "KASUMI_MASTER_KEY", std::nullopt);
    auto no_password = kasumi::test::scoped_environment_variable(
        "KASUMI_PASSWORD", std::nullopt);
    auto no_password_salt = kasumi::test::scoped_environment_variable(
        "KASUMI_PASSWORD2", std::nullopt);
    const auto environment =
        kasumi::application::default_execution_environment();
    std::filesystem::create_directories(environment.app_data_dir.parent_path());
    const auto local = kasumi::test::workspace_path(app_workspace, "local");
    const kasumi::application::Profile profile{
        .name = "demo",
        .local_dir = local,
        .remote_dir =
            kasumi::test::workspace_path(remote.workspace, "storage").string()};
    const auto created = kasumi::application::create_profile(
        environment, profile, kasumi::application::MasterKeyHex{key_hex()});
    ASSERT_TRUE(created) << created.error().detail;

    const auto config_path = environment.app_data_dir / "config.toml";
    const auto key_path = environment.app_data_dir / "profiles/demo/key.bin";
    const auto config_before = kasumi::test::read_binary(config_path);
    const auto key_before = kasumi::test::read_binary(key_path);
    const auto c0 =
        publish(remote, make_commit(0, {}, "c0.txt", "zero").value());
    const auto c1 = publish(
        remote, make_commit(1, {c0.head.commit_id}, "c1.txt", "one").value());
    const auto c2 = publish(
        remote, make_commit(2, {c1.head.commit_id}, "c2.txt", "two").value());
    const auto before = kasumi::transport::list(remote.transport);

    char command[] = "kasumi";
    char remote_command[] = "remote";
    char commits[] = "commits";
    char profile_name[] = "demo";
    char* argv[] = {command, remote_command, commits, profile_name};
    testing::internal::CaptureStdout();
    const auto exit_code = kasumi::cli::run(4, argv);
    const auto output = testing::internal::GetCapturedStdout();

    const auto after = kasumi::transport::list(remote.transport);
    EXPECT_EQ(exit_code, 0);
    EXPECT_TRUE(output.find("Commits remotos (3)") != std::string::npos ||
                output.find("Remote commits (3)") != std::string::npos);
    EXPECT_NE(output.find(c2.head.commit_id), std::string::npos);
    EXPECT_NE(output.find(c1.head.commit_id), std::string::npos);
    EXPECT_NE(output.find(c0.head.commit_id), std::string::npos);
    EXPECT_NE(output.find("HEAD"), std::string::npos);
    EXPECT_EQ(output.find("Sincronizando..."), std::string::npos);
    EXPECT_EQ(output.find("Synchronizing..."), std::string::npos);
    ASSERT_TRUE(before.has_value());
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(*before, *after);
    EXPECT_EQ(kasumi::test::read_binary(config_path), config_before);
    EXPECT_EQ(kasumi::test::read_binary(key_path), key_before);
    EXPECT_FALSE(std::filesystem::exists(local));
    EXPECT_FALSE(std::filesystem::exists(environment.app_data_dir /
                                         "profiles/demo/db.sqlite"));
}

TEST(RemoteHeadsContractTest,
     RealProfileInspectionAndDownloadStayReadOnlyEndToEnd) {
    auto remote = make_local_storage();
    auto app_workspace =
        kasumi::test::make_temp_workspace("remote-details-real-profile");

#if defined(_WIN32)
    auto app_root = kasumi::test::scoped_environment_variable(
        "APPDATA",
        kasumi::test::workspace_path(app_workspace, "appdata").string());
#else
    auto app_root = kasumi::test::scoped_environment_variable(
        "XDG_CONFIG_HOME",
        kasumi::test::workspace_path(app_workspace, "config").string());
#endif
    auto no_master_key = kasumi::test::scoped_environment_variable(
        "KASUMI_MASTER_KEY", std::nullopt);
    auto no_password = kasumi::test::scoped_environment_variable(
        "KASUMI_PASSWORD", std::nullopt);
    auto no_password_salt = kasumi::test::scoped_environment_variable(
        "KASUMI_PASSWORD2", std::nullopt);
    const auto environment =
        kasumi::application::default_execution_environment();
    std::filesystem::create_directories(environment.app_data_dir.parent_path());
    const auto local = kasumi::test::workspace_path(app_workspace, "local");
    const kasumi::application::Profile profile{
        .name = "demo",
        .local_dir = local,
        .remote_dir =
            kasumi::test::workspace_path(remote.workspace, "storage").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, profile, kasumi::application::MasterKeyHex{key_hex()}));

    const auto config_path = environment.app_data_dir / "config.toml";
    const auto key_path = environment.app_data_dir / "profiles/demo/key.bin";
    const auto config_before = kasumi::test::read_binary(config_path);
    const auto key_before = kasumi::test::read_binary(key_path);
    const auto remote_commit =
        make_commit(0, {}, "file.txt", "contents").value();
    const auto published = publish(remote, remote_commit);
    const auto plaintext =
        kasumi::test::workspace_path(remote.workspace, "content.plain");
    const auto ciphertext =
        kasumi::test::workspace_path(remote.workspace, "content.enc");
    kasumi::test::write_text(plaintext, "contents");
    ASSERT_TRUE(
        kasumi::crypto::encrypt_file(plaintext,
                                     ciphertext,
                                     test_key(),
                                     kasumi::crypto::FilePurpose::Content));
    const auto content_id = kasumi::crypto::content_identifier(
        test_key(), remote_commit.tree.rows.back().hash);
    ASSERT_TRUE(
        kasumi::transport::put(remote.transport, ciphertext, content_id));
    const kasumi::application::history_storage::epoch::Epoch genesis{
        .vault_id = std::string(64, 'a'),
        .sequence = 0,
        .issued_at = 100,
        .anchors = {{.commit_id = published.head.commit_id, .height = 0}},
    };
    const auto sealed_epoch =
        kasumi::application::history_storage::epoch::seal(genesis, test_key());
    ASSERT_TRUE(sealed_epoch.has_value());
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        remote.transport,
        *sealed_epoch,
        kasumi::test::workspace_root(remote.workspace)));
    const auto before = kasumi::transport::list(remote.transport);
    const auto remote_root =
        kasumi::test::workspace_path(remote.workspace, "storage");
    const auto remote_bytes_before = kasumi::test::snapshot_tree(remote_root);

    char command[] = "kasumi";
    char remote_command[] = "remote";
    char profile_name[] = "demo";
    char summary[] = "summary";
    char* summary_argv[] = {command, remote_command, summary, profile_name};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::run(4, summary_argv), 0);
    const auto summary_output = testing::internal::GetCapturedStdout();

    char stat[] = "stat";
    char path[] = "file.txt";
    char* stat_argv[] = {command, remote_command, stat, profile_name, path};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::run(5, stat_argv), 0);
    const auto stat_output = testing::internal::GetCapturedStdout();

    char commit[] = "commit";
    char commit_id[65]{};
    std::ranges::copy(published.head.commit_id, commit_id);
    char* commit_argv[] = {
        command, remote_command, commit, profile_name, commit_id};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::run(5, commit_argv), 0);
    const auto commit_output = testing::internal::GetCapturedStdout();

    const auto destination =
        kasumi::test::workspace_path(app_workspace, "download/file.txt");
    std::filesystem::create_directories(destination.parent_path());
    char get[] = "get";
    char remote_path[] = "file.txt";
    auto destination_string = destination.string();
    char* get_argv[] = {command,
                        remote_command,
                        get,
                        profile_name,
                        remote_path,
                        destination_string.data()};
    testing::internal::CaptureStdout();
    const auto get_exit_code = kasumi::cli::run(6, get_argv);
    const auto get_output = testing::internal::GetCapturedStdout();
    EXPECT_EQ(get_exit_code, 0) << get_output;

    char epochs[] = "epochs";
    char* epochs_argv[] = {command, remote_command, epochs, profile_name};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::run(4, epochs_argv), 0);
    const auto epochs_output = testing::internal::GetCapturedStdout();

    char epoch[] = "epoch";
    char epoch_sequence[] = "0";
    char* epoch_argv[] = {
        command, remote_command, epoch, profile_name, epoch_sequence};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::run(5, epoch_argv), 0);
    const auto epoch_output = testing::internal::GetCapturedStdout();

    char contents[] = "contents";
    char* contents_argv[] = {command, remote_command, contents, profile_name};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::run(4, contents_argv), 0);
    const auto contents_output = testing::internal::GetCapturedStdout();

    char audit[] = "--audit";
    char* audit_argv[] = {
        command, remote_command, contents, audit, profile_name};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::run(5, audit_argv), 0);
    const auto audit_output = testing::internal::GetCapturedStdout();

    char content[] = "content";
    char content_identifier[65]{};
    std::ranges::copy(content_id, content_identifier);
    char* content_argv[] = {
        command, remote_command, content, profile_name, content_identifier};
    testing::internal::CaptureStdout();
    EXPECT_EQ(kasumi::cli::run(5, content_argv), 0);
    const auto content_output = testing::internal::GetCapturedStdout();

    const auto run_physical_inspection = [](std::string subcommand) {
        std::vector<std::string> arguments{
            "kasumi", "remote", std::move(subcommand), "demo"};
        std::vector<char*> argv;
        for (auto& argument : arguments) {
            argv.push_back(argument.data());
        }
        testing::internal::CaptureStdout();
        const auto exit_code =
            kasumi::cli::run(static_cast<int>(argv.size()), argv.data());
        auto output = testing::internal::GetCapturedStdout();
        EXPECT_EQ(exit_code, 0) << output;
        EXPECT_EQ(output.find("[Rede]"), std::string::npos);
        return output;
    };
    const auto markers_output = run_physical_inspection("markers");
    const auto objects_output = run_physical_inspection("objects");
    const auto orphans_output = run_physical_inspection("orphans");
    const auto quarantine_output = run_physical_inspection("quarantine");
    const auto writers_output = run_physical_inspection("writers");
    const auto health_output = run_physical_inspection("health");

    const auto after = kasumi::transport::list(remote.transport);
    const auto remote_bytes_after = kasumi::test::snapshot_tree(remote_root);
    EXPECT_TRUE(summary_output.find("Resumo remoto") != std::string::npos ||
                summary_output.find("Remote summary") != std::string::npos);
    EXPECT_TRUE(
        summary_output.find("Conteúdos ausentes: 0") != std::string::npos ||
        summary_output.find("Missing contents: 0") != std::string::npos ||
        summary_output.find("missing_content_count") != std::string::npos ||
        summary_output.find(": 0") != std::string::npos);
    EXPECT_TRUE(stat_output.find("Caminho: file.txt") != std::string::npos ||
                stat_output.find("Path: file.txt") != std::string::npos);
    EXPECT_NE(commit_output.find("Commit: " + published.head.commit_id),
              std::string::npos);
    EXPECT_TRUE(get_output.find("Arquivo remoto salvo") != std::string::npos ||
                get_output.find("Remote file saved") != std::string::npos);
    EXPECT_TRUE(get_output.find("Caminho: file.txt") != std::string::npos ||
                get_output.find("Path: file.txt") != std::string::npos);
    EXPECT_TRUE(epochs_output.find("Epochs remotos: 1") != std::string::npos ||
                epochs_output.find("Remote epochs: 1") != std::string::npos ||
                epochs_output.find("Epoch chain") != std::string::npos);
    EXPECT_TRUE(epoch_output.find("Sequência: 0") != std::string::npos ||
                epoch_output.find("Sequence: 0") != std::string::npos);
    EXPECT_TRUE(contents_output.find("Referenciados: 1") != std::string::npos ||
                contents_output.find("Referenced: 1") != std::string::npos ||
                contents_output.find("Remote contents") != std::string::npos);
    EXPECT_TRUE(audit_output.find("auditoria profunda") != std::string::npos ||
                audit_output.find("deep audit") != std::string::npos ||
                audit_output.find("Cryptographic audit") != std::string::npos);
    EXPECT_TRUE(audit_output.find("Válidos: 1") != std::string::npos ||
                audit_output.find("Valid: 1") != std::string::npos ||
                audit_output.find("Valid") != std::string::npos);
    EXPECT_NE(content_output.find("Content ID: " + content_id),
              std::string::npos);
    EXPECT_TRUE(markers_output.find("Markers físicos remotos: 1") !=
                    std::string::npos ||
                markers_output.find("Physical markers") != std::string::npos);
    EXPECT_TRUE(objects_output.find("Namespace físico remoto") !=
                    std::string::npos ||
                objects_output.find("Physical objects") != std::string::npos);
    EXPECT_TRUE(
        orphans_output.find("Objetos sem alcance: 0") != std::string::npos ||
        orphans_output.find("Orphan contents") != std::string::npos ||
        orphans_output.find("Unreachable objects: 0") != std::string::npos);
    EXPECT_TRUE(
        quarantine_output.find("Quarentena remota: 0") != std::string::npos ||
        quarantine_output.find("Quarantine state") != std::string::npos);
    EXPECT_TRUE(writers_output.find("Writers remotos: 0") !=
                    std::string::npos ||
                writers_output.find("Remote writers") != std::string::npos);
    EXPECT_TRUE(
        health_output.find("Saúde remota: saudável") != std::string::npos ||
        health_output.find("Remote health report") != std::string::npos ||
        health_output.find("healthy") != std::string::npos);
    EXPECT_EQ(summary_output.find("[Rede]"), std::string::npos);
    EXPECT_EQ(stat_output.find("[Rede]"), std::string::npos);
    EXPECT_EQ(commit_output.find("[Rede]"), std::string::npos);
    EXPECT_EQ(get_output.find("[Rede]"), std::string::npos);
    EXPECT_EQ(epochs_output.find("[Rede]"), std::string::npos);
    EXPECT_EQ(epoch_output.find("[Rede]"), std::string::npos);
    EXPECT_EQ(contents_output.find("[Rede]"), std::string::npos);
    EXPECT_EQ(audit_output.find("[Rede]"), std::string::npos);
    EXPECT_EQ(content_output.find("[Rede]"), std::string::npos);
    EXPECT_EQ(kasumi::test::read_text(destination), "contents");
    ASSERT_TRUE(before.has_value());
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(*before, *after);
    EXPECT_EQ(remote_bytes_after, remote_bytes_before);
    EXPECT_EQ(kasumi::test::read_binary(config_path), config_before);
    EXPECT_EQ(kasumi::test::read_binary(key_path), key_before);
    EXPECT_FALSE(std::filesystem::exists(local));
    EXPECT_FALSE(std::filesystem::exists(environment.app_data_dir /
                                         "profiles/demo/db.sqlite"));
}

} // namespace
