#include "application/environment.hpp"
#include "application/history_storage/epoch.hpp"
#include "application/profile.hpp"
#include "cli/app.hpp"
#include "kasumi/test/capture.hpp"
#include "kasumi/test/history_storage.hpp"
#include "kasumi/test/scoped_environment.hpp"
#include "kasumi/test/temp_workspace.hpp"

#include <algorithm>
#include <filesystem>
#include <gtest/gtest.h>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

void write_profile(const kasumi::application::ExecutionEnvironment& environment,
                   const std::filesystem::path& local,
                   const std::filesystem::path& remote) {
    std::filesystem::create_directories(environment.app_data_dir);
    kasumi::test::write_text(environment.app_data_dir / "config.toml",
                             "[profiles.demo]\nlocal_dir = '" + local.string() +
                                 "'\nremote_dir = '" + remote.string() +
                                 "'\nmin_history_depth = 5\n"
                                 "min_history_age_hours = 6\n"
                                 "key_storage = 'file'\n");
}

struct RemoteHeadsCliEnv {
    LocalStorage remote;
    kasumi::test::TempWorkspace app_workspace;
    kasumi::test::ScopedEnvironmentVariable app_root;
    kasumi::test::ScopedEnvironmentVariable master_key;
    kasumi::test::ScopedEnvironmentVariable no_password;
    kasumi::test::ScopedEnvironmentVariable no_password_salt;
    kasumi::application::ExecutionEnvironment environment;
    std::filesystem::path local;
    std::filesystem::path config_path;
    std::filesystem::path key_path;
    std::filesystem::path database_path;
    std::vector<std::byte> config_before;
    std::vector<std::byte> key_before;
    std::vector<std::byte> database_before;

    RemoteHeadsCliEnv(std::string_view name, bool create_persisted_profile)
        : remote(make_local_storage()),
          app_workspace(kasumi::test::make_temp_workspace(name)),
          app_root(kasumi::test::scoped_config_home(
              kasumi::test::workspace_path(app_workspace,
#if defined(_WIN32)
                                           "appdata"
#else
                                           "config"
#endif
                                           ))),
          master_key(kasumi::test::scoped_environment_variable(
              "KASUMI_MASTER_KEY",
              create_persisted_profile
                  ? std::optional<std::string>{}
                  : std::optional<std::string>{test_key_hex()})),
          no_password(kasumi::test::scoped_environment_variable(
              "KASUMI_PASSWORD", std::nullopt)),
          no_password_salt(kasumi::test::scoped_environment_variable(
              "KASUMI_PASSWORD2", std::nullopt)),
          environment(kasumi::application::default_execution_environment()),
          local(kasumi::test::workspace_path(app_workspace, "local")) {
        const auto storage_dir =
            kasumi::test::workspace_path(remote.workspace, "storage");
        if (create_persisted_profile) {
            std::filesystem::create_directories(
                environment.app_data_dir.parent_path());
            const kasumi::application::Profile profile{
                .name = "demo",
                .local_dir = local,
                .remote_dir = storage_dir.string(),
                .key_storage = kasumi::application::KeyStorage::File};
            const auto created = kasumi::application::create_profile(
                environment,
                profile,
                kasumi::application::MasterKeyHex{test_key_hex()});
            EXPECT_TRUE(created) << (created ? "" : created.error().detail);
            config_path = environment.app_data_dir / "config.toml";
            key_path = environment.app_data_dir / "profiles/demo/key.bin";
            database_path =
                environment.app_data_dir / "profiles/demo/db.sqlite";
            config_before = kasumi::test::read_binary(config_path);
            key_before = kasumi::test::read_binary(key_path);
            database_before = kasumi::test::read_binary(database_path);
        } else {
            write_profile(environment, local, storage_dir);
        }
    }

    void expect_profile_unchanged() const {
        EXPECT_EQ(kasumi::test::read_binary(config_path), config_before);
        EXPECT_EQ(kasumi::test::read_binary(key_path), key_before);
        EXPECT_EQ(kasumi::test::read_binary(database_path), database_before);
        EXPECT_FALSE(std::filesystem::exists(local));
    }
};

std::string run_cli(std::initializer_list<std::string_view> args,
                    int expected_exit = 0) {
    std::vector<std::string> owned;
    owned.reserve(args.size() + 1);
    owned.emplace_back("kasumi");
    for (const auto arg : args) {
        owned.emplace_back(arg);
    }
    std::vector<char*> argv;
    argv.reserve(owned.size());
    for (auto& s : owned) {
        argv.push_back(s.data());
    }
    int exit_code = -1;
    auto output = kasumi::test::capture_stdout([&] {
        exit_code =
            kasumi::cli::run(static_cast<int>(argv.size()), argv.data());
    });
    EXPECT_EQ(exit_code, expected_exit) << output;
    return output;
}

TEST(RemoteHeadsContractTest, RealCliCallsInspectionWithoutMutation) {
    RemoteHeadsCliEnv cli("remote-heads-cli-contract", false);
    const auto published =
        publish(cli.remote, make_commit(0, {}, "file.txt", "contents").value());
    ASSERT_FALSE(published.head.commit_id.empty());
    const auto before = kasumi::transport::list(cli.remote.transport);

    const auto output = run_cli({"remote", "heads", "demo"});

    const auto after = kasumi::transport::list(cli.remote.transport);
    EXPECT_TRUE(output.find("Heads remotas (1)") != std::string::npos ||
                output.find("Remote heads (1)") != std::string::npos);
    EXPECT_NE(output.find(published.head.commit_id), std::string::npos);
    EXPECT_EQ(output.find("Sincronizando..."), std::string::npos);
    EXPECT_EQ(output.find("Synchronizing..."), std::string::npos);
    ASSERT_TRUE(before.has_value());
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(*before, *after);
    EXPECT_FALSE(std::filesystem::exists(cli.local));
    EXPECT_FALSE(
        std::filesystem::exists(cli.environment.app_data_dir / "profiles"));
}

TEST(RemoteHeadsContractTest,
     RealProfileUsesPersistedKeyWithoutEnvironmentCredentials) {
    RemoteHeadsCliEnv cli("remote-heads-real-profile", true);
    const auto published =
        publish(cli.remote, make_commit(0, {}, "file.txt", "contents").value());
    ASSERT_FALSE(published.head.commit_id.empty());
    const auto before = kasumi::transport::list(cli.remote.transport);

    const auto output = run_cli({"remote", "heads", "demo"});

    const auto after = kasumi::transport::list(cli.remote.transport);
    EXPECT_TRUE(output.find("Heads remotas (1)") != std::string::npos ||
                output.find("Remote heads (1)") != std::string::npos);
    EXPECT_NE(output.find(published.head.commit_id), std::string::npos);
    EXPECT_EQ(output.find("The operation completed successfully"),
              std::string::npos);
    ASSERT_TRUE(before.has_value());
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(*before, *after);
    cli.expect_profile_unchanged();
}

TEST(RemoteHeadsContractTest,
     RealProfileRemoteTreeUsesPersistedKeyWithoutMutation) {
    RemoteHeadsCliEnv cli("remote-tree-real-profile", true);
    const auto published =
        publish(cli.remote, make_commit(0, {}, "file.txt", "contents").value());
    ASSERT_FALSE(published.head.commit_id.empty());
    const auto before = kasumi::transport::list(cli.remote.transport);

    const auto automatic_output = run_cli({"remote", "tree", "demo"});
    const auto explicit_output =
        run_cli({"remote", "tree", "demo", "--head", published.head.commit_id});

    const auto after = kasumi::transport::list(cli.remote.transport);
    EXPECT_NE(automatic_output.find("Head: " + published.head.commit_id),
              std::string::npos);
    EXPECT_NE(automatic_output.find("file.txt"), std::string::npos);
    EXPECT_NE(explicit_output.find("Head: " + published.head.commit_id),
              std::string::npos);
    ASSERT_TRUE(before.has_value());
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(*before, *after);
    cli.expect_profile_unchanged();
}

TEST(RemoteHeadsContractTest,
     RealProfileRemoteCommitsUsesPersistedKeyWithoutMutation) {
    RemoteHeadsCliEnv cli("remote-commits-real-profile", true);
    const auto c0 =
        publish(cli.remote, make_commit(0, {}, "c0.txt", "zero").value());
    const auto c1 =
        publish(cli.remote,
                make_commit(1, {c0.head.commit_id}, "c1.txt", "one").value());
    const auto c2 =
        publish(cli.remote,
                make_commit(2, {c1.head.commit_id}, "c2.txt", "two").value());
    const auto before = kasumi::transport::list(cli.remote.transport);

    const auto output = run_cli({"remote", "commits", "demo"});

    const auto after = kasumi::transport::list(cli.remote.transport);
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
    cli.expect_profile_unchanged();
}

TEST(RemoteHeadsContractTest,
     RealProfileInspectionAndDownloadStayReadOnlyEndToEnd) {
    RemoteHeadsCliEnv cli("remote-details-real-profile", true);
    const auto remote_commit =
        make_commit(0, {}, "file.txt", "contents").value();
    const auto published = publish(cli.remote, remote_commit);
    const auto plaintext =
        kasumi::test::workspace_path(cli.remote.workspace, "content.plain");
    const auto ciphertext =
        kasumi::test::workspace_path(cli.remote.workspace, "content.enc");
    kasumi::test::write_text(plaintext, "contents");
    ASSERT_TRUE(
        kasumi::crypto::encrypt_file(plaintext,
                                     ciphertext,
                                     test_key(),
                                     kasumi::crypto::FilePurpose::Content));
    const auto content_id = kasumi::crypto::content_identifier(
        test_key(), remote_commit.tree.rows.back().hash);
    ASSERT_TRUE(
        kasumi::transport::put(cli.remote.transport, ciphertext, content_id));
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
        cli.remote.transport,
        test_key(),
        *sealed_epoch,
        kasumi::test::workspace_root(cli.remote.workspace)));
    const auto before = kasumi::transport::list(cli.remote.transport);
    const auto remote_root =
        kasumi::test::workspace_path(cli.remote.workspace, "storage");
    const auto remote_bytes_before = kasumi::test::snapshot_tree(remote_root);

    const auto summary_output = run_cli({"remote", "summary", "demo"});
    const auto stat_output = run_cli({"remote", "stat", "demo", "file.txt"});
    const auto commit_output =
        run_cli({"remote", "commit", "demo", published.head.commit_id});

    const auto destination =
        kasumi::test::workspace_path(cli.app_workspace, "download/file.txt");
    std::filesystem::create_directories(destination.parent_path());
    const auto get_output =
        run_cli({"remote", "get", "demo", "file.txt", destination.string()});
    const auto epochs_output = run_cli({"remote", "epochs", "demo"});
    const auto epoch_output = run_cli({"remote", "epoch", "demo", "0"});
    const auto contents_output = run_cli({"remote", "contents", "demo"});
    const auto audit_output =
        run_cli({"remote", "contents", "demo", "--audit"});
    const auto content_output =
        run_cli({"remote", "content", "demo", content_id});

    const auto run_physical_inspection = [](std::string_view subcommand) {
        const auto output = run_cli({"remote", subcommand, "demo"});
        EXPECT_EQ(output.find("[Rede]"), std::string::npos);
        return output;
    };
    const auto markers_output = run_physical_inspection("markers");
    const auto objects_output = run_physical_inspection("objects");
    const auto orphans_output = run_physical_inspection("orphans");
    const auto writers_output = run_physical_inspection("writers");
    const auto health_output = run_physical_inspection("health");

    const auto after = kasumi::transport::list(cli.remote.transport);
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
                markers_output.find("Remote physical markers: 1") !=
                    std::string::npos ||
                markers_output.find("Physical markers") != std::string::npos);
    EXPECT_TRUE(
        objects_output.find("Namespace físico remoto") != std::string::npos ||
        objects_output.find("Remote physical namespace") != std::string::npos ||
        objects_output.find("Physical objects") != std::string::npos);
    EXPECT_TRUE(
        orphans_output.find("Objetos sem alcance: 0") != std::string::npos ||
        orphans_output.find("Orphan contents") != std::string::npos ||
        orphans_output.find("Unreachable objects: 0") != std::string::npos);
    EXPECT_TRUE(writers_output.find("Writers remotos: 0") !=
                    std::string::npos ||
                writers_output.find("Remote writers") != std::string::npos);
    EXPECT_TRUE(
        health_output.find("Saúde remota: saudável") != std::string::npos ||
        health_output.find("Remote health report") != std::string::npos ||
        health_output.find("healthy") != std::string::npos);
    for (const auto* out : {&summary_output,
                            &stat_output,
                            &commit_output,
                            &get_output,
                            &epochs_output,
                            &epoch_output,
                            &contents_output,
                            &audit_output,
                            &content_output}) {
        EXPECT_EQ(out->find("[Rede]"), std::string::npos);
    }
    EXPECT_EQ(kasumi::test::read_text(destination), "contents");
    ASSERT_TRUE(before.has_value());
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(*before, *after);
    EXPECT_EQ(remote_bytes_after, remote_bytes_before);
    cli.expect_profile_unchanged();
}

} // namespace
