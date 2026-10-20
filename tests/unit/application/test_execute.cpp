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
            "'\nmin_history_depth = 5\nmin_history_age_hours = 6\n");
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

void seed_remote_history(const TempWorkspace& workspace,
                         std::string& orphan_content) {
    const auto key = application_key();
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(key);
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
    const auto canonical = kasumi::history::serialize(commit).value();
    const auto plain = kasumi::test::workspace_path(workspace, "seed.plain");
    const auto cipher = kasumi::test::workspace_path(workspace, "seed.cipher");
    kasumi::test::write_binary(plain, std::as_bytes(std::span{canonical}));
    ASSERT_TRUE(kasumi::crypto::encrypt_file(
        plain, cipher, key, kasumi::crypto::FilePurpose::History));
    const auto hash = kasumi::crypto::content::hash_file(cipher).value();
    const kasumi::application::history_storage::HeadReference reference{
        .commit_id = kasumi::crypto::commit_identifier(key, canonical),
        .ciphertext_id = kasumi::hash_hex(hash)};
    ASSERT_TRUE(kasumi::transport::put(
        *opened,
        cipher,
        kasumi::application::history_storage::commit_object(layout,
                                                            reference)));
    const auto marker =
        kasumi::application::history_storage::encode_marker(reference).value();
    const auto marker_path =
        kasumi::test::workspace_path(workspace, "seed.head");
    kasumi::test::write_binary(marker_path, std::as_bytes(std::span{marker}));
    ASSERT_TRUE(kasumi::transport::put(
        *opened,
        marker_path,
        kasumi::application::history_storage::marker_object(layout,
                                                            reference)));

    const auto put_content = [&](std::string_view contents,
                                 std::string_view suffix) {
        const auto identifier = kasumi::crypto::content_identifier(
            key, kasumi::hasher::hash_string(contents));
        const auto content_plain = kasumi::test::workspace_path(
            workspace, std::string{suffix} + ".plain");
        const auto content_cipher = kasumi::test::workspace_path(
            workspace, std::string{suffix} + ".cipher");
        kasumi::test::write_text(content_plain, contents);
        EXPECT_TRUE(
            kasumi::crypto::encrypt_file(content_plain, content_cipher, key));
        EXPECT_TRUE(
            kasumi::transport::put(*opened, content_cipher, identifier));
        return identifier;
    };
    put_content("live", "live-content");
    orphan_content = put_content("orphan", "orphan-content");
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

TEST(ApplicationExecuteTest,
     GarbageCollectRunsThroughThePublicApplicationBoundary) {
    auto workspace = kasumi::test::make_temp_workspace("application-gc-public");
    write_profile(workspace);
    ASSERT_TRUE(std::filesystem::create_directories(
        kasumi::test::workspace_path(workspace, "local")));
    std::string orphan_content;
    seed_remote_history(workspace, orphan_content);
    ASSERT_FALSE(orphan_content.empty());

    const auto result = kasumi::application::execute(
        {Request{Operation::GarbageCollect, "demo"},
         Credentials{key()},
         ExecutionEnvironment{kasumi::test::workspace_path(workspace, "app")}});
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    const auto* completed = std::get_if<GarbageCollectCompleted>(&result->data);
    ASSERT_NE(completed, nullptr);
    EXPECT_EQ(completed->candidate_objects, 1U);
    EXPECT_EQ(completed->removed_objects, 1U);
    EXPECT_FALSE(completed->analysis_only);
}

// PARTIAL-R05
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
                 kasumi::test::write_binary(target_path, garbage);
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
    EXPECT_EQ(diagnostic.mutation_state,
              kasumi::application::GarbageCollectMutationState::NotAttempted);
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
