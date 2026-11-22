#include "application/execute.hpp"
#include "application/history_storage/history_storage.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/profile.hpp"
#include "application/use_cases/context.hpp"
#include "core/hasher.hpp"
#include "core/history.hpp"
#include "core/node.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/profile_lock.hpp"
#include "platform/metadata.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace {

using kasumi::application::Credentials;
using kasumi::application::ErrorCode;
using kasumi::application::ExecutionEnvironment;
using kasumi::application::GarbageCollectCompleted;
using kasumi::application::MasterKeyHex;
using kasumi::application::NoCredentials;
using kasumi::application::Operation;
using kasumi::application::Profile;
using kasumi::application::RepackCompleted;
using kasumi::application::Request;
using kasumi::application::RuntimeSummary;
using kasumi::test::TempWorkspace;

MasterKeyHex key() {
    return MasterKeyHex{std::string(64, '2')};
}

void write_profile(const TempWorkspace& workspace) {
    std::filesystem::create_directories(
        kasumi::test::workspace_path(workspace, "app"));
    std::filesystem::create_directories(
        kasumi::test::workspace_path(workspace, "app/profiles/demo"));
    kasumi::test::write_text(
        kasumi::test::workspace_path(workspace, "app/config.toml"),
        "[profiles.demo]\nlocal_dir = '" +
            kasumi::test::workspace_path(workspace, "local").string() +
            "'\nremote_dir = '" +
            kasumi::test::workspace_path(workspace, "remote").string() +
            "'\nmin_history_depth = 5\nmin_history_age_hours = 6\n"
            "key_storage = 'file'\n");
    ASSERT_TRUE(kasumi::state_storage::initialize(kasumi::test::workspace_path(
        workspace, "app/profiles/demo/db.sqlite")));
}

RuntimeSummary summary() {
    return {.local_dir = "local", .remote_dir = "remote"};
}

std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> application_key() {
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> value{};
    value.fill(0x22U);
    return value;
}

std::string put_application_content(const TempWorkspace& workspace,
                                    kasumi::transport::Transport& transport,
                                    std::string_view contents,
                                    std::string_view suffix) {
    const auto key = application_key();
    const auto identifier = kasumi::crypto::content_identifier(
        key, kasumi::hasher::hash_string(contents));
    const auto plain =
        kasumi::test::workspace_path(workspace, std::string{suffix} + ".plain");
    const auto cipher = kasumi::test::workspace_path(
        workspace, std::string{suffix} + ".cipher");
    kasumi::test::write_text(plain, contents);
    EXPECT_TRUE(kasumi::crypto::encrypt_file(plain, cipher, key));
    EXPECT_TRUE(kasumi::transport::put(transport, cipher, identifier));
    return identifier;
}

void seed_remote_history(const TempWorkspace& workspace,
                         std::string& orphan_content) {
    const auto key = application_key();
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "remote").string());
    ASSERT_TRUE(opened.has_value()) << opened.error().message;
    ASSERT_TRUE(kasumi::transport::initialize(*opened));

    kasumi::Snapshot tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true},
                 kasumi::NodeRow{.path = "live.txt",
                                 .hash = kasumi::hasher::hash_string("live"),
                                 .size = 4,
                                 .is_directory = false}}};
    kasumi::finalize_snapshot(tree);
    const auto commit =
        kasumi::history::make_commit(0, {}, std::move(tree)).value();
    ASSERT_TRUE(kasumi::application::history_storage::publish_commit(
        *opened, key, commit, kasumi::test::workspace_root(workspace)));

    put_application_content(workspace, *opened, "live", "live-content");
    orphan_content =
        put_application_content(workspace, *opened, "orphan", "orphan-content");
}

auto execute_initial_sync(const ExecutionEnvironment& environment,
                          std::string profile_name = "demo") {
    return kasumi::application::execute(
        {Request{.operation = Operation::Sync,
                 .profile_name = std::move(profile_name),
                 .initial = true},
         Credentials{NoCredentials{}},
         environment});
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
     MissingProfileDatabaseIsRejectedWithoutReinitialization) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-execute-missing-db");
    write_profile(workspace);
    const auto database =
        kasumi::test::workspace_path(workspace, "app/profiles/demo/db.sqlite");
    ASSERT_TRUE(std::filesystem::remove(database));

    const auto result = kasumi::application::execute(
        {Request{Operation::Sync, "demo"},
         Credentials{key()},
         ExecutionEnvironment{kasumi::test::workspace_path(workspace, "app")}});

    ASSERT_FALSE(result.has_value());
    EXPECT_NE(result.error().detail.find("profile state database"),
              std::string::npos);
    EXPECT_FALSE(std::filesystem::exists(database));
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "remote")));
}

TEST(ApplicationExecuteTest,
     InitialSyncReusesProfileKeyAndCompatibleContentThenAllowsNormalSync) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-initial-sync");
    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const ExecutionEnvironment environment{app};
    const Profile profile{.name = "demo",
                          .local_dir = local,
                          .remote_dir = remote.string(),
                          .key_storage = kasumi::application::KeyStorage::File};
    ASSERT_TRUE(std::filesystem::create_directories(local));
    kasumi::test::write_text(local / "reused.txt", "reused-content");
    kasumi::test::write_text(local / "replaced.txt", "replaced-content");
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));

    const auto database = app / "profiles/demo/db.sqlite";
    const auto key_path = app / "profiles/demo/key.bin";
    const auto config_path = app / "config.toml";
    const auto key_before = kasumi::test::read_binary(key_path);
    const auto config_before = kasumi::test::read_text(config_path);
    ASSERT_TRUE(std::filesystem::create_directories(
        app / "profiles/demo/.transactions"));

    auto opened = kasumi::transport::open_transport(remote.string());
    ASSERT_TRUE(opened.has_value()) << opened.error().message;
    ASSERT_TRUE(kasumi::transport::initialize(*opened));
    const auto content_id = put_application_content(
        workspace, *opened, "reused-content", "preexisting-content");
    const auto content_before = kasumi::test::read_binary(remote / content_id);
    const auto replaced_id = kasumi::crypto::content_identifier(
        application_key(), kasumi::hasher::hash_string("replaced-content"));
    const auto corrupt_path =
        kasumi::test::workspace_path(workspace, "corrupt-content");
    kasumi::test::write_text(corrupt_path, "not encrypted Content");
    ASSERT_TRUE(kasumi::transport::put(*opened, corrupt_path, replaced_id));
    const auto corrupt_before = kasumi::test::read_binary(remote / replaced_id);
    ASSERT_TRUE(std::filesystem::remove(database));

    const auto initial = execute_initial_sync(environment);
    ASSERT_TRUE(initial.has_value()) << initial.error().detail;
    ASSERT_TRUE(kasumi::state_storage::validate(database));
    auto accepted = kasumi::state_storage::load_state(database);
    ASSERT_TRUE(accepted.has_value()) << accepted.error();
    ASSERT_TRUE(accepted->has_value());
    EXPECT_FALSE((**accepted).commit_id.empty());
    EXPECT_FALSE((**accepted).epoch_id.empty());
    EXPECT_EQ((**accepted).tree.rows.size(), 3U);
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(
            application_key());
    const kasumi::application::history_storage::HeadReference head{
        .commit_id = (**accepted).commit_id,
        .ciphertext_id = (**accepted).ciphertext_id,
    };
    const auto remote_ids = kasumi::transport::list(*opened);
    ASSERT_TRUE(remote_ids.has_value()) << remote_ids.error().message;
    EXPECT_NE(std::find(remote_ids->begin(),
                        remote_ids->end(),
                        kasumi::application::history_storage::commit_object(
                            layout, head)),
              remote_ids->end());
    EXPECT_NE(std::find(remote_ids->begin(),
                        remote_ids->end(),
                        kasumi::application::history_storage::marker_object(
                            layout, head)),
              remote_ids->end());
    EXPECT_NE(
        std::find(
            remote_ids->begin(),
            remote_ids->end(),
            kasumi::application::history_storage::epoch_object(
                layout, (**accepted).epoch_sequence, (**accepted).epoch_id)),
        remote_ids->end());
    EXPECT_EQ(kasumi::test::read_binary(key_path), key_before);
    EXPECT_EQ(kasumi::test::read_text(config_path), config_before);
    EXPECT_EQ(kasumi::test::read_binary(remote / content_id), content_before);
    EXPECT_NE(kasumi::test::read_binary(remote / replaced_id), corrupt_before);
    const auto replaced_plain =
        kasumi::test::workspace_path(workspace, "replaced-verified.txt");
    ASSERT_TRUE(kasumi::crypto::decrypt_file(
        remote / replaced_id, replaced_plain, application_key()));
    EXPECT_EQ(kasumi::test::read_text(replaced_plain), "replaced-content");

    const auto synchronized =
        kasumi::application::execute({Request{Operation::Sync, "demo"},
                                      Credentials{NoCredentials{}},
                                      environment});
    ASSERT_TRUE(synchronized.has_value()) << synchronized.error().detail;
}

TEST(ApplicationExecuteTest,
     InitialSyncEnrollsIntoExistingAuthenticatedRemoteVaultSuccessfully) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-initial-sync-enroll");
    const auto app_a = kasumi::test::workspace_path(workspace, "app_a");
    const auto local_a = kasumi::test::workspace_path(workspace, "local_a");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const ExecutionEnvironment env_a{app_a};
    const Profile profile_a{"demo", local_a, remote.string()};
    ASSERT_TRUE(std::filesystem::create_directories(local_a));
    kasumi::test::write_text(local_a / "file.txt", "remote-content-from-a");
    ASSERT_TRUE(kasumi::application::create_profile(env_a, profile_a, key()));
    const auto sync_a =
        kasumi::application::execute({Request{Operation::Sync, "demo"},
                                      Credentials{NoCredentials{}},
                                      env_a});
    ASSERT_TRUE(sync_a.has_value()) << sync_a.error().detail;

    // Client B has no SQLite database and an empty local directory
    const auto app_b = kasumi::test::workspace_path(workspace, "app_b");
    const auto local_b = kasumi::test::workspace_path(workspace, "local_b");
    const ExecutionEnvironment env_b{app_b};
    const Profile profile_b{"demo", local_b, remote.string()};
    ASSERT_TRUE(std::filesystem::create_directories(local_b));
    ASSERT_TRUE(kasumi::application::create_profile(env_b, profile_b, key()));
    const auto db_b = app_b / "profiles/demo/db.sqlite";
    ASSERT_TRUE(std::filesystem::remove(db_b));
    ASSERT_FALSE(std::filesystem::exists(db_b));

    // Client B joins with --initial
    const auto result = execute_initial_sync(env_b);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_TRUE(std::filesystem::exists(db_b));
    EXPECT_TRUE(kasumi::state_storage::validate(db_b));
    auto state_b = kasumi::state_storage::load_state(db_b);
    ASSERT_TRUE(state_b.has_value()) << state_b.error();
    ASSERT_TRUE(state_b->has_value());
    EXPECT_FALSE((**state_b).commit_id.empty());
    EXPECT_TRUE(std::filesystem::exists(local_b / "file.txt"));
    EXPECT_EQ(kasumi::test::read_text(local_b / "file.txt"),
              "remote-content-from-a");
}

TEST(ApplicationExecuteTest,
     InitialSyncEnrollsIntoExistingVaultWithAdditionalLocalFiles) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-initial-sync-add-files");
    const auto app_a = kasumi::test::workspace_path(workspace, "app_a");
    const auto local_a = kasumi::test::workspace_path(workspace, "local_a");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const ExecutionEnvironment env_a{app_a};
    const Profile profile_a{"demo", local_a, remote.string()};
    ASSERT_TRUE(std::filesystem::create_directories(local_a));
    kasumi::test::write_text(local_a / "from_a.txt", "content-from-a");
    ASSERT_TRUE(kasumi::application::create_profile(env_a, profile_a, key()));
    const auto sync_a =
        kasumi::application::execute({Request{Operation::Sync, "demo"},
                                      Credentials{NoCredentials{}},
                                      env_a});
    ASSERT_TRUE(sync_a.has_value()) << sync_a.error().detail;

    // Client B has no SQLite database and an extra local file
    const auto app_b = kasumi::test::workspace_path(workspace, "app_b");
    const auto local_b = kasumi::test::workspace_path(workspace, "local_b");
    const ExecutionEnvironment env_b{app_b};
    const Profile profile_b{"demo", local_b, remote.string()};
    ASSERT_TRUE(std::filesystem::create_directories(local_b));
    kasumi::test::write_text(local_b / "from_b.txt", "content-from-b");
    ASSERT_TRUE(kasumi::application::create_profile(env_b, profile_b, key()));
    const auto db_b = app_b / "profiles/demo/db.sqlite";
    ASSERT_TRUE(std::filesystem::remove(db_b));

    // Client B joins with --initial
    const auto result_b = execute_initial_sync(env_b);
    ASSERT_TRUE(result_b.has_value()) << result_b.error().detail;
    EXPECT_TRUE(std::filesystem::exists(local_b / "from_a.txt"));
    EXPECT_TRUE(std::filesystem::exists(local_b / "from_b.txt"));
    EXPECT_EQ(kasumi::test::read_text(local_b / "from_a.txt"),
              "content-from-a");
    EXPECT_EQ(kasumi::test::read_text(local_b / "from_b.txt"),
              "content-from-b");

    // Client A syncs normally and receives from_b.txt
    const auto sync_a2 =
        kasumi::application::execute({Request{Operation::Sync, "demo"},
                                      Credentials{NoCredentials{}},
                                      env_a});
    ASSERT_TRUE(sync_a2.has_value()) << sync_a2.error().detail;
    EXPECT_TRUE(std::filesystem::exists(local_a / "from_b.txt"));
    EXPECT_EQ(kasumi::test::read_text(local_a / "from_b.txt"),
              "content-from-b");
}

TEST(ApplicationExecuteTest,
     InitialSyncEnrollsIntoExistingVaultWithConflictingLocalFile) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-initial-sync-conflict");
    const auto app_a = kasumi::test::workspace_path(workspace, "app_a");
    const auto local_a = kasumi::test::workspace_path(workspace, "local_a");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const ExecutionEnvironment env_a{app_a};
    const Profile profile_a{"demo", local_a, remote.string()};
    ASSERT_TRUE(std::filesystem::create_directories(local_a));
    kasumi::test::write_text(local_a / "shared.txt", "content-version-a");
    ASSERT_TRUE(kasumi::application::create_profile(env_a, profile_a, key()));
    const auto sync_a =
        kasumi::application::execute({Request{Operation::Sync, "demo"},
                                      Credentials{NoCredentials{}},
                                      env_a});
    ASSERT_TRUE(sync_a.has_value()) << sync_a.error().detail;

    // Client B has conflicting shared.txt
    const auto app_b = kasumi::test::workspace_path(workspace, "app_b");
    const auto local_b = kasumi::test::workspace_path(workspace, "local_b");
    const ExecutionEnvironment env_b{app_b};
    const Profile profile_b{"demo", local_b, remote.string()};
    ASSERT_TRUE(std::filesystem::create_directories(local_b));
    kasumi::test::write_text(local_b / "shared.txt", "content-version-b");
    ASSERT_TRUE(kasumi::application::create_profile(env_b, profile_b, key()));
    const auto db_b = app_b / "profiles/demo/db.sqlite";
    ASSERT_TRUE(std::filesystem::remove(db_b));

    // Client B joins with --initial
    const auto result_b = execute_initial_sync(env_b);
    ASSERT_TRUE(result_b.has_value()) << result_b.error().detail;

    // Verify neither content was lost: local uncommitted version preserved,
    // remote version saved to conflict copy
    EXPECT_EQ(kasumi::test::read_text(local_b / "shared.txt"),
              "content-version-b");
    bool found_conflict_copy = false;
    for (const auto& entry : std::filesystem::directory_iterator(local_b)) {
        const auto filename = entry.path().filename().string();
        if (filename.starts_with("shared.conflict") ||
            filename.find("conflict") != std::string::npos) {
            found_conflict_copy = true;
            EXPECT_EQ(kasumi::test::read_text(entry.path()),
                      "content-version-a");
        }
    }
    EXPECT_TRUE(found_conflict_copy);
}

TEST(ApplicationExecuteTest,
     InitialSyncRejectsPartialRemoteHistoryWithoutCreatingDatabase) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-initial-sync-partial");
    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const ExecutionEnvironment environment{app};
    const Profile profile{.name = "demo",
                          .local_dir = local,
                          .remote_dir = remote.string(),
                          .key_storage = kasumi::application::KeyStorage::File};
    ASSERT_TRUE(std::filesystem::create_directories(local));
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));
    auto opened = kasumi::transport::open_transport(remote.string());
    ASSERT_TRUE(opened.has_value()) << opened.error().message;
    ASSERT_TRUE(kasumi::transport::initialize(*opened));
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(
            application_key());
    const auto partial_id = layout.history_prefix + "unknown-partial-object";
    const auto partial_path =
        kasumi::test::workspace_path(workspace, "partial-object");
    kasumi::test::write_text(partial_path, "partial protocol");
    ASSERT_TRUE(kasumi::transport::put(*opened, partial_path, partial_id));
    const auto before = kasumi::transport::list(*opened);
    ASSERT_TRUE(before.has_value()) << before.error().message;
    const auto database = app / "profiles/demo/db.sqlite";
    ASSERT_TRUE(std::filesystem::remove(database));

    const auto result = execute_initial_sync(environment);
    ASSERT_FALSE(result.has_value());
    EXPECT_FALSE(std::filesystem::exists(database));
    const auto after = kasumi::transport::list(*opened);
    ASSERT_TRUE(after.has_value()) << after.error().message;
    EXPECT_EQ(*after, *before);
}

TEST(ApplicationExecuteTest,
     InitialSyncRejectsPendingLocalTransactionEvidence) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-initial-sync-journal");
    const auto app = kasumi::test::workspace_path(workspace, "app");
    const ExecutionEnvironment environment{app};
    const Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));
    const auto database = app / "profiles/demo/db.sqlite";
    ASSERT_TRUE(std::filesystem::remove(database));
    const auto journal = app / "profiles/demo/transaction.bin.enc";
    ASSERT_TRUE(std::filesystem::create_directories(journal));
    kasumi::test::write_text(journal / "snapshot.enc", "unfinished");

    const auto result = execute_initial_sync(environment);
    ASSERT_FALSE(result.has_value());
    EXPECT_FALSE(std::filesystem::exists(database));
    EXPECT_TRUE(std::filesystem::exists(journal / "snapshot.enc"));

    std::error_code error;
    ASSERT_TRUE(std::filesystem::remove_all(journal, error) > 0U)
        << error.message();
    const auto workspace_evidence =
        app / "profiles/demo/.transactions/unfinished-workspace";
    ASSERT_TRUE(std::filesystem::create_directories(workspace_evidence));
    const auto workspace_retry = execute_initial_sync(environment);
    ASSERT_FALSE(workspace_retry.has_value());
    EXPECT_FALSE(std::filesystem::exists(database));
    EXPECT_TRUE(std::filesystem::exists(workspace_evidence));
}

TEST(ApplicationExecuteTest,
     FailedInitialSyncLeavesValidDatabaseForNormalSyncRecovery) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-initial-sync-recovery");
    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const ExecutionEnvironment environment{app};
    const Profile profile{.name = "demo",
                          .local_dir = local,
                          .remote_dir = remote.string(),
                          .key_storage = kasumi::application::KeyStorage::File};
    kasumi::test::write_text(local, "not a directory");
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));
    const auto database = app / "profiles/demo/db.sqlite";
    ASSERT_TRUE(std::filesystem::remove(database));

    const auto initial = execute_initial_sync(environment);
    ASSERT_FALSE(initial.has_value());
    ASSERT_TRUE(kasumi::state_storage::validate(database));
    auto empty = kasumi::state_storage::load_state(database);
    ASSERT_TRUE(empty.has_value()) << empty.error();
    EXPECT_FALSE(empty->has_value());

    ASSERT_TRUE(std::filesystem::remove(local));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    kasumi::test::write_text(local / "recovered.txt", "after-failure");
    const auto retry =
        kasumi::application::execute({Request{Operation::Sync, "demo"},
                                      Credentials{NoCredentials{}},
                                      environment});
    ASSERT_TRUE(retry.has_value()) << retry.error().detail;
    auto accepted = kasumi::state_storage::load_state(database);
    ASSERT_TRUE(accepted.has_value()) << accepted.error();
    ASSERT_TRUE(accepted->has_value());
    EXPECT_FALSE((**accepted).commit_id.empty());
}

TEST(ApplicationExecuteTest,
     InitialSyncRejectsAndPreservesExistingInvalidDatabase) {
    auto workspace = kasumi::test::make_temp_workspace(
        "application-initial-sync-corrupt-db");
    const auto app = kasumi::test::workspace_path(workspace, "app");
    const ExecutionEnvironment environment{app};
    const Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));
    const auto database = app / "profiles/demo/db.sqlite";
    const std::array<std::byte, 8> corrupt{std::byte{'n'},
                                           std::byte{'o'},
                                           std::byte{'t'},
                                           std::byte{'d'},
                                           std::byte{'b'},
                                           std::byte{'!'},
                                           std::byte{'!'},
                                           std::byte{'!'}};
    kasumi::test::write_binary(database, corrupt);
    const auto before = kasumi::test::read_binary(database);

    const auto result = execute_initial_sync(environment);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(kasumi::test::read_binary(database), before);
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
            "min_history_age_hours = 6\nkey_storage = 'file'\n");

    const auto result =
        kasumi::application::execute({Request{Operation::Preview, "demo"},
                                      Credentials{NoCredentials{}},
                                      ExecutionEnvironment{app}});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::RuntimeFailure);
    EXPECT_FALSE(std::filesystem::exists(app / "profiles"));
}

TEST(ApplicationExecuteTest, SyncCompletesItsPlanBeforeReportingPublication) {
    using kasumi::application::Activity;
    using kasumi::application::ActivityProgress;
    using kasumi::application::SyncCompleted;
    using kasumi::application::SyncProgress;
    using kasumi::application::SyncStage;

    auto workspace =
        kasumi::test::make_temp_workspace("application-sync-public");
    write_profile(workspace);
    ASSERT_TRUE(std::filesystem::create_directories(
        kasumi::test::workspace_path(workspace, "local/nested")));
    kasumi::test::write_text(
        kasumi::test::workspace_path(workspace, "local/nested/child.txt"),
        "child");
    kasumi::test::write_text(
        kasumi::test::workspace_path(workspace, "local/root.txt"), "root");

    std::vector<SyncProgress> progress;
    std::optional<ActivityProgress> preparation;
    std::uint64_t upload_stage = 0;
    std::uint64_t announced_upload_bytes = 0;
    const auto result = kasumi::application::execute(
        {Request{Operation::Sync, "demo"},
         Credentials{key()},
         ExecutionEnvironment{kasumi::test::workspace_path(workspace, "app")},
         [&](const auto& event) {
             if (const auto* sync = std::get_if<SyncProgress>(&event)) {
                 progress.push_back(*sync);
             } else if (const auto* activity =
                            std::get_if<ActivityProgress>(&event)) {
                 if (activity->activity == Activity::PreparingPlan) {
                     preparation = *activity;
                 } else if (activity->activity == Activity::Uploading &&
                            activity->stage_id != upload_stage) {
                     upload_stage = activity->stage_id;
                     EXPECT_EQ(activity->bytes, 0U);
                     EXPECT_GT(activity->total_bytes.value_or(0), 0U);
                     announced_upload_bytes +=
                         activity->total_bytes.value_or(0);
                 }
             }
         }});
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    const auto& completed = std::get<SyncCompleted>(result->data);
    ASSERT_TRUE(completed.published);
    ASSERT_GT(completed.total, 1U);
    ASSERT_TRUE(preparation);
    EXPECT_EQ(preparation->total_objects, completed.total);
    EXPECT_EQ(preparation->objects, completed.total);
    EXPECT_GT(completed.wire_upload_bytes, 0U);
    EXPECT_EQ(announced_upload_bytes, completed.wire_upload_bytes);
    std::uint32_t last_applied = 0;
    const auto publish = std::ranges::find(
        progress, SyncStage::Publishing, &SyncProgress::stage);
    ASSERT_NE(publish, progress.end());
    for (auto item = progress.begin(); item != publish; ++item) {
        if (item->stage == SyncStage::Applying) {
            EXPECT_EQ(item->total_items, completed.total);
            EXPECT_GE(item->applied_items.value_or(0), last_applied);
            last_applied = item->applied_items.value_or(0);
        }
    }
    EXPECT_EQ(last_applied, completed.total);
    EXPECT_NE(std::ranges::find(publish,
                                progress.end(),
                                SyncStage::Finalizing,
                                &SyncProgress::stage),
              progress.end());
}

TEST(ApplicationExecuteTest,
     GarbageCollectRunsThroughThePublicApplicationBoundary) {
    using kasumi::application::GarbageCollectProgress;
    using kasumi::application::GarbageCollectStage;
    auto workspace = kasumi::test::make_temp_workspace("application-gc-public");
    write_profile(workspace);
    ASSERT_TRUE(std::filesystem::create_directories(
        kasumi::test::workspace_path(workspace, "local")));
    std::string orphan_content;
    seed_remote_history(workspace, orphan_content);
    ASSERT_FALSE(orphan_content.empty());

    std::optional<std::size_t> listed;
    std::size_t confirmed = 0;
    const auto result = kasumi::application::execute(
        {Request{Operation::GarbageCollect, "demo"},
         Credentials{key()},
         ExecutionEnvironment{kasumi::test::workspace_path(workspace, "app")},
         [&](const auto& event) {
             if (const auto* progress =
                     std::get_if<GarbageCollectProgress>(&event)) {
                 if (progress->listed_objects) {
                     listed = progress->listed_objects;
                 }
                 if (progress->stage == GarbageCollectStage::Applying) {
                     confirmed = progress->removed_objects;
                 }
             }
         }});
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    const auto* completed = std::get_if<GarbageCollectCompleted>(&result->data);
    ASSERT_NE(completed, nullptr);
    EXPECT_EQ(completed->candidate_objects, 1U);
    EXPECT_EQ(completed->removed_objects, 1U);
    EXPECT_FALSE(completed->analysis_only);
    EXPECT_GT(listed.value_or(0), completed->candidate_objects);
    EXPECT_EQ(confirmed, completed->removed_objects);
    EXPECT_GT(completed->removal_elapsed.count(), 0);
}

// PARTIAL-R05: a candidate mutated after the single authenticated observation
// is no longer revalidated (cooperative exclusivity). The public partial
// diagnostic is exercised by a genuine REMOVE failure instead.
TEST(ApplicationExecuteTest,
     GarbageCollectPartialFailureKeepsPublicDiagnostics) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-gc-public-partial");
    write_profile(workspace);
    ASSERT_TRUE(std::filesystem::create_directories(
        kasumi::test::workspace_path(workspace, "local")));
    std::string orphan_content;
    seed_remote_history(workspace, orphan_content);
    ASSERT_FALSE(orphan_content.empty());

    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "remote").string());
    ASSERT_TRUE(opened.has_value()) << opened.error().message;
    ASSERT_TRUE(kasumi::transport::initialize(*opened));
    std::vector<std::string> identifiers{orphan_content};
    for (std::size_t index = 0; index < 99; ++index) {
        const auto contents = "public-partial-" + std::to_string(index);
        identifiers.push_back(
            put_application_content(workspace,
                                    *opened,
                                    contents,
                                    "public-partial-" + std::to_string(index)));
    }
    std::ranges::sort(identifiers);
    ASSERT_EQ(identifiers.size(), 100U);
    const auto target = identifiers[36];
    const auto target_path =
        kasumi::test::workspace_path(workspace, "remote") / target;
    bool corrupted = false;

    const auto result = kasumi::application::execute(
        {Request{Operation::GarbageCollect, "demo"},
         Credentials{key()},
         ExecutionEnvironment{kasumi::test::workspace_path(workspace, "app")},
         [&](const kasumi::application::ExecutionProgress& progress) {
             const auto* gc =
                 std::get_if<kasumi::application::GarbageCollectProgress>(
                     &progress);
             if (corrupted || gc == nullptr ||
                 gc->stage !=
                     kasumi::application::GarbageCollectStage::Applying ||
                 gc->removed_objects != 36U) {
                 return;
             }
             corrupted = true;
             const std::array<std::byte, 4> garbage{std::byte{0xde},
                                                    std::byte{0xad},
                                                    std::byte{0xbe},
                                                    std::byte{0xef}};
             try {
                 std::error_code ignored;
                 std::filesystem::remove(target_path, ignored);
                 std::filesystem::create_directories(target_path);
                 kasumi::test::write_binary(target_path / "blocker", garbage);
             } catch (...) {
             }
         }});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().operation, Operation::GarbageCollect);
    EXPECT_EQ(result.error().code, ErrorCode::GarbageCollectionFailure);
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_EQ(diagnostic.candidate_objects, 100U);
    EXPECT_EQ(diagnostic.confirmed_removed, 36U);
    EXPECT_EQ(diagnostic.failed_identifier, std::optional<std::string>{target});
    EXPECT_EQ(diagnostic.stage,
              kasumi::application::GarbageCollectStage::Applying);
    ASSERT_TRUE(diagnostic.transport_error.has_value());
    EXPECT_EQ(diagnostic.mutation_state,
              kasumi::application::GarbageCollectMutationState::Uncertain);
    EXPECT_TRUE(diagnostic.barrier_release_attempted);
    EXPECT_TRUE(diagnostic.barrier_release_confirmed);
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
              "profile is already in use by another execution");

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
            "min_history_age_hours = 6\nkey_storage = 'file'\n");

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

TEST(ApplicationExecuteTest, InitialSyncRejectsSymlinkAtDatabasePath) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-initial-sync-symlink");
    const auto app = kasumi::test::workspace_path(workspace, "app");
    const ExecutionEnvironment environment{app};
    const Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));
    const auto database = app / "profiles/demo/db.sqlite";
    const auto target = app / "profiles/demo/target.sqlite";
    ASSERT_TRUE(std::filesystem::remove(database));

    // Test 1: Dangling symlink
    std::error_code ec;
    std::filesystem::create_symlink(target, database, ec);
    if (ec) {
        GTEST_SKIP() << "Symlink creation not supported without elevation: "
                     << ec.message();
    }
    const auto dangling_result = execute_initial_sync(environment);
    EXPECT_FALSE(dangling_result.has_value());
    EXPECT_TRUE(
        std::filesystem::is_symlink(std::filesystem::symlink_status(database)));
    EXPECT_FALSE(std::filesystem::exists(target));

    // Test 2: Symlink pointing to a valid database
    ASSERT_TRUE(kasumi::state_storage::initialize(target));
    const auto valid_symlink_result = execute_initial_sync(environment);
    EXPECT_FALSE(valid_symlink_result.has_value());
    EXPECT_TRUE(
        std::filesystem::is_symlink(std::filesystem::symlink_status(database)));
}

TEST(ApplicationExecuteTest, InitialSyncRejectsDirectoryAtDatabasePath) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-initial-sync-dir-db");
    const auto app = kasumi::test::workspace_path(workspace, "app");
    const ExecutionEnvironment environment{app};
    const Profile profile{
        "demo",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(std::filesystem::create_directories(profile.local_dir));
    ASSERT_TRUE(
        kasumi::application::create_profile(environment, profile, key()));
    const auto database = app / "profiles/demo/db.sqlite";
    ASSERT_TRUE(std::filesystem::remove(database));
    ASSERT_TRUE(std::filesystem::create_directories(database));

    const auto result = execute_initial_sync(environment);
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(std::filesystem::is_directory(database));
}

TEST(ApplicationExecuteTest,
     InitialSyncRejectsCorruptHeadMarkerPayloadWithoutCreatingDatabase) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-initial-corrupt-head");
    const auto app_a = kasumi::test::workspace_path(workspace, "app_a");
    const auto local_a = kasumi::test::workspace_path(workspace, "local_a");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const ExecutionEnvironment env_a{app_a};
    const Profile profile_a{"demo", local_a, remote.string()};
    ASSERT_TRUE(std::filesystem::create_directories(local_a));
    kasumi::test::write_text(local_a / "file.txt", "content");
    ASSERT_TRUE(kasumi::application::create_profile(env_a, profile_a, key()));
    ASSERT_TRUE(kasumi::application::execute({Request{Operation::Sync, "demo"},
                                              Credentials{NoCredentials{}},
                                              env_a}));

    // Find head marker on remote and corrupt its contents
    auto opened = kasumi::transport::open_transport(remote.string());
    ASSERT_TRUE(opened.has_value());
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(
            application_key());
    const auto list = kasumi::transport::list(*opened);
    ASSERT_TRUE(list.has_value());
    std::string head_marker_id;
    for (const auto& id : *list) {
        if (id.starts_with(layout.heads_prefix)) {
            head_marker_id = id;
            break;
        }
    }
    ASSERT_FALSE(head_marker_id.empty());
    kasumi::test::write_text(remote / head_marker_id, "corrupted-head-payload");

    // Client B attempts to join with --initial
    const auto app_b = kasumi::test::workspace_path(workspace, "app_b");
    const auto local_b = kasumi::test::workspace_path(workspace, "local_b");
    const ExecutionEnvironment env_b{app_b};
    const Profile profile_b{"demo", local_b, remote.string()};
    ASSERT_TRUE(std::filesystem::create_directories(local_b));
    ASSERT_TRUE(kasumi::application::create_profile(env_b, profile_b, key()));
    const auto db_b = app_b / "profiles/demo/db.sqlite";
    ASSERT_TRUE(std::filesystem::remove(db_b));

    const auto result = execute_initial_sync(env_b);
    ASSERT_FALSE(result.has_value());
    EXPECT_FALSE(std::filesystem::exists(db_b));
}

TEST(ApplicationExecuteTest,
     InitialSyncRejectsHeadReferencingMissingCommitWithoutCreatingDatabase) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-initial-missing-commit");
    const auto app_a = kasumi::test::workspace_path(workspace, "app_a");
    const auto local_a = kasumi::test::workspace_path(workspace, "local_a");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const ExecutionEnvironment env_a{app_a};
    const Profile profile_a{"demo", local_a, remote.string()};
    ASSERT_TRUE(std::filesystem::create_directories(local_a));
    kasumi::test::write_text(local_a / "file.txt", "content");
    ASSERT_TRUE(kasumi::application::create_profile(env_a, profile_a, key()));
    ASSERT_TRUE(kasumi::application::execute({Request{Operation::Sync, "demo"},
                                              Credentials{NoCredentials{}},
                                              env_a}));

    // Remove commit file from remote
    auto opened = kasumi::transport::open_transport(remote.string());
    ASSERT_TRUE(opened.has_value());
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(
            application_key());
    const auto list = kasumi::transport::list(*opened);
    ASSERT_TRUE(list.has_value());
    for (const auto& id : *list) {
        if (id.starts_with(layout.history_prefix) &&
            !id.starts_with(layout.heads_prefix) &&
            !id.starts_with(layout.epochs_prefix)) {
            ASSERT_TRUE(std::filesystem::remove(remote / id));
        }
    }

    // Client B attempts to join with --initial
    const auto app_b = kasumi::test::workspace_path(workspace, "app_b");
    const auto local_b = kasumi::test::workspace_path(workspace, "local_b");
    const ExecutionEnvironment env_b{app_b};
    const Profile profile_b{"demo", local_b, remote.string()};
    ASSERT_TRUE(std::filesystem::create_directories(local_b));
    ASSERT_TRUE(kasumi::application::create_profile(env_b, profile_b, key()));
    const auto db_b = app_b / "profiles/demo/db.sqlite";
    ASSERT_TRUE(std::filesystem::remove(db_b));

    const auto result = execute_initial_sync(env_b);
    ASSERT_FALSE(result.has_value());
    EXPECT_FALSE(std::filesystem::exists(db_b));
}

TEST(ApplicationExecuteTest,
     InitialSyncEnrollmentDoesNotAuditOrDownloadOrphanContent) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-enroll-no-orphan-audit");
    const auto app_a = kasumi::test::workspace_path(workspace, "app_a");
    const auto local_a = kasumi::test::workspace_path(workspace, "local_a");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const ExecutionEnvironment env_a{app_a};
    const Profile profile_a{"demo", local_a, remote.string()};
    ASSERT_TRUE(std::filesystem::create_directories(local_a));
    kasumi::test::write_text(local_a / "file_a.txt", "content-from-a");
    ASSERT_TRUE(kasumi::application::create_profile(env_a, profile_a, key()));
    ASSERT_TRUE(kasumi::application::execute({Request{Operation::Sync, "demo"},
                                              Credentials{NoCredentials{}},
                                              env_a}));

    // Place an orphan content on remote with corrupted content bytes
    // (If enrollment tried to audit/verify it, decryption/verification would
    // fail or crash)
    const std::string orphan_text = "orphan-content-that-matches-b";
    const auto orphan_hash = kasumi::hasher::hash_string(orphan_text);
    const auto orphan_id =
        kasumi::crypto::content_identifier(application_key(), orphan_hash);
    kasumi::test::write_text(remote / orphan_id,
                             "corrupted-ciphertext-for-orphan");

    // Client B enrolls with --initial, having a local file that matches the
    // orphan content
    const auto app_b = kasumi::test::workspace_path(workspace, "app_b");
    const auto local_b = kasumi::test::workspace_path(workspace, "local_b");
    const ExecutionEnvironment env_b{app_b};
    const Profile profile_b{"demo", local_b, remote.string()};
    ASSERT_TRUE(std::filesystem::create_directories(local_b));
    kasumi::test::write_text(local_b / "orphan_b.txt", orphan_text);
    ASSERT_TRUE(kasumi::application::create_profile(env_b, profile_b, key()));
    const auto db_b = app_b / "profiles/demo/db.sqlite";
    ASSERT_TRUE(std::filesystem::remove(db_b));

    // Enrollment must NOT speculatively audit the orphan content.
    // Instead it must treat orphan_b.txt as normal new local content and upload
    // it.
    const auto result = execute_initial_sync(env_b);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
}

TEST(ApplicationExecuteTest, RemoveBarrierRequiresConfirmAbandonedFlag) {
    auto workspace =
        kasumi::test::make_temp_workspace("exec-barrier-confirm-req");
    write_profile(workspace);
    const auto env =
        ExecutionEnvironment{kasumi::test::workspace_path(workspace, "app")};

    const auto result = kasumi::application::execute(
        {Request{.operation = Operation::RemoveBarrier,
                 .profile_name = "demo",
                 .confirm_abandoned = false},
         Credentials{key()},
         env});
    ASSERT_FALSE(result.has_value());
    EXPECT_NE(result.error().detail.find("--confirm-abandoned is required"),
              std::string::npos);
}

TEST(ApplicationExecuteTest, RemoveBarrierOperatesWithMissingLocalDatabase) {
    auto workspace =
        kasumi::test::make_temp_workspace("exec-barrier-missing-db");
    write_profile(workspace);
    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const auto env = ExecutionEnvironment{app};

    // Remove SQLite database to simulate corrupted/missing local db
    const auto db = app / "profiles/demo/db.sqlite";
    std::filesystem::remove(db);
    ASSERT_FALSE(std::filesystem::exists(db));

    // Place abandoned barrier in remote
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(
            application_key());
    const auto barrier_path = remote / layout.barrier_identifier;
    std::filesystem::create_directories(barrier_path.parent_path());
    kasumi::test::write_text(
        barrier_path, "kasumi-gc-v1:barrier:0123456789abcdef0123456789abcdef");

    const auto result = kasumi::application::execute(
        {Request{.operation = Operation::RemoveBarrier,
                 .profile_name = "demo",
                 .confirm_abandoned = true},
         Credentials{key()},
         env});
    ASSERT_TRUE(result.has_value()) << (result ? "" : result.error().detail);
    const auto* completed =
        std::get_if<kasumi::application::ManualBarrierRemovalCompleted>(
            &result->data);
    ASSERT_NE(completed, nullptr);
    EXPECT_EQ(completed->outcome,
              kasumi::application::BarrierRemovalOutcome::Removed);
    EXPECT_FALSE(std::filesystem::exists(barrier_path));
}

TEST(ApplicationExecuteTest, RemoveBarrierFailurePreservesDiagnosticContext) {
    auto workspace = kasumi::test::make_temp_workspace("exec-barrier-diag");
    write_profile(workspace);
    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const auto env = ExecutionEnvironment{app};

    // Place corrupt barrier on remote
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(
            application_key());
    const auto barrier_path = remote / layout.barrier_identifier;
    std::filesystem::create_directories(barrier_path.parent_path());
    kasumi::test::write_text(barrier_path, "corrupt-payload");

    const auto result = kasumi::application::execute(
        {Request{.operation = Operation::RemoveBarrier,
                 .profile_name = "demo",
                 .confirm_abandoned = true},
         Credentials{key()},
         env});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::ErrorCode::BarrierRemovalFailure);
    ASSERT_TRUE(result.error().barrier_removal.has_value());
    EXPECT_EQ(result.error().barrier_removal->barrier_identifier,
              layout.barrier_identifier);
    EXPECT_EQ(result.error().barrier_removal->stage,
              kasumi::application::BarrierRemovalStage::ValidatingPayload);
    EXPECT_EQ(result.error().barrier_removal->mutation_state,
              kasumi::application::BarrierRemovalMutationState::NotAttempted);
}

TEST(ApplicationExecuteTest,
     MemoryModeRequiresPasswordPairAndSwitchingStorageRequiresSetProfileKey) {
    auto workspace =
        kasumi::test::make_temp_workspace("exec-key-storage-modes");
    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const ExecutionEnvironment env{app};
    const Profile profile{.name = "demo",
                          .local_dir = local,
                          .remote_dir = remote.string(),
                          .key_storage =
                              kasumi::application::KeyStorage::Memory};
    ASSERT_TRUE(std::filesystem::create_directories(local));
    kasumi::test::write_text(local / "note.txt", "hello-memory");
    const kasumi::application::PasswordPair pass_pair{"memory-secret-pass",
                                                      "memory-secret-salt-16"};
    ASSERT_TRUE(kasumi::application::create_profile(env, profile, pass_pair));
    EXPECT_FALSE(std::filesystem::exists(app / "profiles/demo/key.bin"));

    const auto no_creds = kasumi::application::execute(
        {Request{.operation = Operation::Sync, .profile_name = "demo"},
         Credentials{NoCredentials{}},
         env});
    ASSERT_FALSE(no_creds.has_value());
    EXPECT_EQ(no_creds.error().code,
              kasumi::application::ErrorCode::CredentialFailure);

    const auto with_pass = kasumi::application::execute(
        {Request{.operation = Operation::Sync, .profile_name = "demo"},
         Credentials{pass_pair},
         env});
    ASSERT_TRUE(with_pass.has_value())
        << (with_pass ? "" : with_pass.error().detail);
    EXPECT_FALSE(std::filesystem::exists(app / "profiles/demo/key.bin"));

    // Switch config.toml key_storage to "file"; missing key must report error
    // until set_profile_key re-enters it.
    const auto config_path = app / "config.toml";
    auto config_text = kasumi::test::read_text(config_path);
    const auto dq = config_text.find("\"memory\"");
    const auto sq = config_text.find("'memory'");
    if (dq != std::string::npos) {
        config_text.replace(dq, 8, "\"file\"");
    } else {
        ASSERT_NE(sq, std::string::npos) << config_text;
        config_text.replace(sq, 8, "'file'");
    }
    kasumi::test::write_text(config_path, config_text);

    const auto missing_file = kasumi::application::execute(
        {Request{.operation = Operation::Status, .profile_name = "demo"},
         Credentials{NoCredentials{}},
         env});
    ASSERT_FALSE(missing_file.has_value());
    EXPECT_NE(missing_file.error().detail.find("kasumi key"),
              std::string::npos);

    ASSERT_TRUE(kasumi::application::set_profile_key(env, "demo", pass_pair));
    const auto restored = kasumi::application::execute(
        {Request{.operation = Operation::Status, .profile_name = "demo"},
         Credentials{NoCredentials{}},
         env});
    ASSERT_TRUE(restored.has_value())
        << (restored ? "" : restored.error().detail);
}

TEST(ApplicationExecuteTest, RepackRejectsInvalidFlagsOnOtherOperations) {
    auto workspace = kasumi::test::make_temp_workspace("exec-repack-flags");
    const ExecutionEnvironment env{
        kasumi::test::workspace_path(workspace, "app")};

    for (const auto& req : {
             Request{.operation = Operation::Sync,
                     .profile_name = "demo",
                     .dry_run = true},
             Request{.operation = Operation::Sync,
                     .profile_name = "demo",
                     .reclaim_dirty = true},
         }) {
        const auto res = kasumi::application::execute(
            {req, Credentials{NoCredentials{}}, env});
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error().code, ErrorCode::RuntimeFailure);
    }
}

TEST(ApplicationExecuteTest, RepackRunsDryRunAndPublishThroughPublicBoundary) {
    auto workspace = kasumi::test::make_temp_workspace("exec-repack-public");
    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const ExecutionEnvironment env{app};
    const Profile profile{.name = "demo",
                          .local_dir = local,
                          .remote_dir = remote.string(),
                          .key_storage =
                              kasumi::application::KeyStorage::File};
    ASSERT_TRUE(std::filesystem::create_directories(local));
    ASSERT_TRUE(std::filesystem::create_directories(remote));
    ASSERT_TRUE(kasumi::application::create_profile(env, profile, key()));

    const auto write_settled = [](const std::filesystem::path& path,
                                  std::string_view text) {
        kasumi::test::write_text(path, text);
        const auto settled = std::filesystem::file_time_type::clock::now() -
                             std::chrono::seconds{2};
        ASSERT_TRUE(
            kasumi::platform::metadata::set_last_write_time(path, settled));
    };

    write_settled(local / "alpha.txt", "first loose small file payload");
    const auto sync1 = kasumi::application::execute(
        {Request{.operation = Operation::Sync, .profile_name = "demo"},
         Credentials{NoCredentials{}},
         env});
    ASSERT_TRUE(sync1.has_value()) << sync1.error().detail;

    write_settled(local / "beta.txt", "second loose small file payload");
    const auto sync2 = kasumi::application::execute(
        {Request{.operation = Operation::Sync, .profile_name = "demo"},
         Credentials{NoCredentials{}},
         env});
    ASSERT_TRUE(sync2.has_value()) << sync2.error().detail;

    const auto dry = kasumi::application::execute(
        {Request{.operation = Operation::Repack,
                 .profile_name = "demo",
                 .dry_run = true},
         Credentials{NoCredentials{}},
         env});
    ASSERT_TRUE(dry.has_value()) << dry.error().detail;
    const auto* dry_data = std::get_if<RepackCompleted>(&dry->data);
    ASSERT_NE(dry_data, nullptr);
    EXPECT_TRUE(dry_data->dry_run);
    EXPECT_TRUE(dry_data->actionable);
    EXPECT_FALSE(dry_data->published);
    EXPECT_EQ(dry_data->source_loose_blobs, 2U);
    EXPECT_EQ(dry_data->new_packs, 1U);
    EXPECT_EQ(dry_data->repacked_blobs, 2U);
    EXPECT_EQ(dry_data->wire_upload_bytes, 0U);
    EXPECT_EQ(dry_data->physical_objects_uploaded, 0U);

    bool saw_activity = false;
    const auto run = kasumi::application::execute(
        {Request{.operation = Operation::Repack, .profile_name = "demo"},
         Credentials{NoCredentials{}},
         env,
         [&](const kasumi::application::ExecutionProgress& event) {
             if (std::holds_alternative<kasumi::application::ActivityProgress>(
                     event)) {
                 saw_activity = true;
             }
         }});
    ASSERT_TRUE(run.has_value()) << run.error().detail;
    const auto* run_data = std::get_if<RepackCompleted>(&run->data);
    ASSERT_NE(run_data, nullptr);
    EXPECT_FALSE(run_data->dry_run);
    EXPECT_TRUE(run_data->actionable);
    EXPECT_TRUE(run_data->published);
    EXPECT_EQ(run_data->new_packs, 1U);
    EXPECT_EQ(run_data->repacked_blobs, 2U);
    EXPECT_GT(run_data->wire_upload_bytes, 0U);
    EXPECT_GT(run_data->physical_objects_uploaded, 0U);
    EXPECT_FALSE(run_data->published_commit_id.empty());
    EXPECT_GE(run_data->published_height, 2U);
    EXPECT_TRUE(saw_activity);

    const auto noop = kasumi::application::execute(
        {Request{.operation = Operation::Repack, .profile_name = "demo"},
         Credentials{NoCredentials{}},
         env});
    ASSERT_TRUE(noop.has_value()) << noop.error().detail;
    const auto* noop_data = std::get_if<RepackCompleted>(&noop->data);
    ASSERT_NE(noop_data, nullptr);
    EXPECT_FALSE(noop_data->actionable);
    EXPECT_FALSE(noop_data->published);

    const auto checked = kasumi::application::execute(
        {Request{Operation::Fsck, "demo"},
         Credentials{NoCredentials{}},
         env});
    ASSERT_TRUE(checked.has_value()) << checked.error().detail;
}

TEST(ApplicationExecuteTest,
     MaintenanceAuditAndPostSyncAuditFailureTrackRemoteAndLocalActivity) {
    auto workspace = kasumi::test::make_temp_workspace("exec-activity-audit");
    write_profile(workspace);
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const ExecutionEnvironment env{
        kasumi::test::workspace_path(workspace, "app")};
    ASSERT_TRUE(std::filesystem::create_directories(local));
    kasumi::test::write_text(local / "item.txt", "audit-item");

    const auto sync1 = kasumi::application::execute(
        {Request{Operation::Sync, "demo"}, Credentials{key()}, env});
    ASSERT_TRUE(sync1.has_value()) << sync1.error().detail;

    // Plant a stray object inside the control namespace on remote -> Sync with
    // --audit-inventory succeeds on sync step then fails audit; recorded
    // distinctly in DB.
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(
            application_key());
    const auto stray_path = remote / (layout.gc_prefix + "stray-object");
    std::error_code dir_ec;
    std::filesystem::create_directories(stray_path.parent_path(), dir_ec);
    ASSERT_FALSE(dir_ec) << dir_ec.message();
    kasumi::test::write_text(stray_path, "foreign");
    const auto audit_sync = kasumi::application::execute(
        {Request{.operation = Operation::Sync,
                 .profile_name = "demo",
                 .audit_inventory = true},
         Credentials{key()},
         env});
    ASSERT_FALSE(audit_sync.has_value());
    EXPECT_EQ(audit_sync.error().code, ErrorCode::InventoryAuditFailure);
    EXPECT_TRUE(audit_sync.error().sync_completed.has_value());

    const auto activity = kasumi::application::inspect_profile_activity(
        env, "demo");
    ASSERT_TRUE(activity.last_attempt.has_value());
    EXPECT_EQ(activity.last_attempt->status,
              kasumi::application::ProfileExecutionStatus::Failed);
    EXPECT_EQ(activity.last_attempt->stage, "audit");
    EXPECT_NE(
        activity.last_attempt->flags &
            kasumi::application::profile_execution_flag_audit_failed_after_sync,
        0U);
    ASSERT_TRUE(activity.last_complete_sync.has_value());
    EXPECT_EQ(activity.last_complete_sync->status,
              kasumi::application::ProfileExecutionStatus::Succeeded);
}

TEST(ApplicationExecuteTest,
     BestEffortActivityPublishFailureSetsWarningAndPendingPublishState) {
    auto workspace =
        kasumi::test::make_temp_workspace("exec-activity-publish-warning");
    write_profile(workspace);
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const ExecutionEnvironment env{
        kasumi::test::workspace_path(workspace, "app")};
    auto opened = kasumi::transport::open_transport(remote.string());
    ASSERT_TRUE(opened.has_value()) << opened.error().message;
    ASSERT_TRUE(kasumi::transport::initialize(*opened));

    // A regular file named after the keyed activity root blocks creating
    // <activity_ns>/<v1_ns>/*.act while leaving barrier checks and
    // RemoveBarrier intact.
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(
            application_key());
    const auto act_root =
        layout.activity_prefix.substr(0, layout.activity_prefix.find('/'));
    kasumi::test::write_text(remote / act_root, "blocker");

    const auto res = kasumi::application::execute(
        {Request{.operation = Operation::RemoveBarrier,
                 .profile_name = "demo",
                 .confirm_abandoned = true},
         Credentials{key()},
         env});
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_TRUE(res->activity_publish_warning.has_value());

    const auto activity =
        kasumi::application::inspect_profile_activity(env, "demo");
    ASSERT_TRUE(activity.last_attempt.has_value());
    EXPECT_EQ(activity.last_attempt->operation,
              kasumi::application::ProfileOperationKind::RemoveBarrier);
    EXPECT_EQ(activity.last_attempt->status,
              kasumi::application::ProfileExecutionStatus::Succeeded);
    EXPECT_EQ(activity.last_attempt->remote_publish_state,
              kasumi::application::ProfileRemotePublishState::Pending);
}

TEST(ApplicationExecuteTest,
     GcDryRunAnalyzesCandidatesWithoutDeletingOrPublishingActivity) {
    auto workspace = kasumi::test::make_temp_workspace("exec-gc-dry-run");
    write_profile(workspace);
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const ExecutionEnvironment env{
        kasumi::test::workspace_path(workspace, "app")};
    ASSERT_TRUE(std::filesystem::create_directories(local));
    kasumi::test::write_text(local / "item.txt", "gc-dry-run-item");

    const auto sync1 = kasumi::application::execute(
        {Request{Operation::Sync, "demo"}, Credentials{key()}, env});
    ASSERT_TRUE(sync1.has_value()) << sync1.error().detail;

    auto opened = kasumi::transport::open_transport(remote.string());
    ASSERT_TRUE(opened.has_value()) << opened.error().message;
    const auto key_bytes = application_key();
    const auto orphan_id = kasumi::crypto::content_identifier(
        key_bytes, kasumi::hasher::hash_string("unreferenced-orphan-payload"));
    const auto orphan_src =
        kasumi::test::workspace_path(workspace, "orphan.bin");
    kasumi::test::write_text(orphan_src, "unreferenced-orphan-bytes");
    ASSERT_TRUE(kasumi::transport::put(*opened, orphan_src, orphan_id));

    const auto dry = kasumi::application::execute(
        {Request{.operation = Operation::GarbageCollect,
                 .profile_name = "demo",
                 .dry_run = true},
         Credentials{key()},
         env});
    ASSERT_TRUE(dry.has_value()) << dry.error().detail;
    const auto* gc = std::get_if<GarbageCollectCompleted>(&dry->data);
    ASSERT_NE(gc, nullptr);
    EXPECT_TRUE(gc->dry_run);
    EXPECT_FALSE(gc->analysis_only);
    EXPECT_EQ(gc->candidate_objects, 1U);
    EXPECT_EQ(gc->candidate_content_objects, 1U);
    EXPECT_EQ(gc->candidate_commit_variants, 0U);
    EXPECT_EQ(gc->candidate_activities, 0U);
    EXPECT_EQ(gc->removed_objects, 0U);

    // Orphan remains present, no barrier remains, and no activity was published.
    EXPECT_EQ(kasumi::transport::presence(*opened, orphan_id).value(),
              kasumi::transport::Presence::Present);
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(key_bytes);
    EXPECT_EQ(
        kasumi::transport::presence(*opened, layout.barrier_identifier).value(),
        kasumi::transport::Presence::Absent);
    const auto activity = kasumi::application::inspect_profile_activity(
        env, "demo");
    ASSERT_TRUE(activity.last_attempt.has_value());
    EXPECT_EQ(activity.last_attempt->operation,
              kasumi::application::ProfileOperationKind::Sync);

    // Real GC still removes the orphan afterward.
    const auto live_gc = kasumi::application::execute(
        {Request{Operation::GarbageCollect, "demo"}, Credentials{key()}, env});
    ASSERT_TRUE(live_gc.has_value()) << live_gc.error().detail;
    const auto* live_data = std::get_if<GarbageCollectCompleted>(&live_gc->data);
    ASSERT_NE(live_data, nullptr);
    EXPECT_FALSE(live_data->dry_run);
    EXPECT_EQ(live_data->removed_objects, 1U);
    EXPECT_EQ(kasumi::transport::presence(*opened, orphan_id).value(),
              kasumi::transport::Presence::Absent);
}

} // namespace
