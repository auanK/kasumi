#include "application/sync/coordinator.hpp"
#include "application/sync/coordinator_detail.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/mutation.hpp"
#include "core/hasher.hpp"
#include "crypto/key_derivation.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"

#include <array>
#include <filesystem>
#include <gtest/gtest.h>
#include <monocypher.h>

namespace {

namespace sync = kasumi::application::sync;

TEST(JournalPreparationTest,
     StartedRecoversUncheckpointedPreparationOfEveryAction) {
    for (const std::size_t prepared_count : {0U, 1U, 5U, 9U}) {
        SCOPED_TRACE(prepared_count);
        auto owner =
            kasumi::test::make_temp_workspace("uncheckpointed-preparation");
        const auto profile = kasumi::test::workspace_path(owner, "profile");
        const auto local = kasumi::test::workspace_path(owner, "local");
        ASSERT_TRUE(std::filesystem::create_directories(profile));
        ASSERT_TRUE(std::filesystem::create_directories(local / "old-dir"));
        for (const auto* name :
             {"upload.txt", "download.txt", "delete.txt", "rename.txt"}) {
            kasumi::test::write_text(local / name, "ORIGINAL");
        }
        kasumi::test::write_text(local / "old-dir/keep.txt", "KEEP");
        const auto hash =
            kasumi::hash_hex(kasumi::hasher::hash_string("ORIGINAL"));
        auto record = sync::journal::create_record(
            0,
            0,
            kasumi::make_sync_plan(
                {
                    {.action = kasumi::Action::Upload,
                     .path = "upload.txt",
                     .hash = hash,
                     .size = 8},
                    {.action = kasumi::Action::Download,
                     .path = "download.txt",
                     .hash = hash,
                     .size = 8},
                    {.action = kasumi::Action::DeleteLocal,
                     .path = "delete.txt",
                     .hash = hash,
                     .size = 8},
                    {.action = kasumi::Action::RenameLocal,
                     .path = "rename.txt",
                     .hash = hash,
                     .alt_path = "renamed.txt",
                     .size = 8},
                    {.action = kasumi::Action::CreateLocalDirectory,
                     .path = "new-dir"},
                    {.action = kasumi::Action::DeleteLocalDirectory,
                     .path = "old-dir"},
                    {.action = kasumi::Action::CreateRemoteDirectory,
                     .path = "remote-dir"},
                    {.action = kasumi::Action::DeleteRemote,
                     .path = "remote.txt"},
                    {.action = kasumi::Action::DeleteRemoteDirectory,
                     .path = "old-remote-dir"},
                },
                0));
        ASSERT_TRUE(record) << record.error();
        const auto paths = sync::journal::make_paths(profile);
        ASSERT_TRUE(paths);
        const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
        ASSERT_TRUE(sync::journal::save(*paths, *record, key));
        const kasumi::platform::Workspace workspace{
            .root = profile / ".transactions" / record->operation_id};
        ASSERT_TRUE(std::filesystem::create_directories(workspace.root));
        for (std::size_t i = 0; i < prepared_count; ++i) {
            auto prepared =
                sync::mutation::prepare_operation(record->plan.operations[i],
                                                  i,
                                                  local,
                                                  workspace,
                                                  record->progress[i],
                                                  record->plan.operations);
            ASSERT_TRUE(prepared) << prepared.error().detail;
            record->progress[i] = *prepared;
        }
        auto durable = sync::journal::load(*paths, key);
        ASSERT_TRUE(durable && *durable);
        EXPECT_EQ((*durable)->phase, kasumi::transaction::Phase::Started);
        for (const auto& progress : (*durable)->progress) {
            EXPECT_EQ(progress.state,
                      kasumi::transaction::OperationState::Pending);
            EXPECT_FALSE(progress.had_original);
        }
        // A concurrent addition is outside the transaction's rollback
        // authority.
        kasumi::test::write_text(local / "concurrent.txt", "CONCURRENT");
        const kasumi::runtime::RuntimeData runtime{
            .local_dir = local,
            .database_path = profile / "state.db",
            .key_path = profile / "key.bin"};
        kasumi::transport::Transport unavailable{};
        auto recovered =
            sync::coordinator::recover_if_needed(runtime, unavailable, key);
        ASSERT_TRUE(recovered) << recovered.error().detail;
        EXPECT_EQ(*recovered, sync::coordinator::RecoveryResult::RolledBack);
        EXPECT_FALSE(std::filesystem::exists(paths->final_path));
        EXPECT_FALSE(std::filesystem::exists(workspace.root));
        EXPECT_FALSE(std::filesystem::exists(runtime.database_path));
        for (const auto* name :
             {"upload.txt", "download.txt", "delete.txt", "rename.txt"}) {
            EXPECT_EQ(kasumi::test::read_text(local / name), "ORIGINAL");
        }
        EXPECT_EQ(kasumi::test::read_text(local / "old-dir/keep.txt"), "KEEP");
        EXPECT_EQ(kasumi::test::read_text(local / "concurrent.txt"),
                  "CONCURRENT");
        EXPECT_FALSE(std::filesystem::exists(local / "new-dir"));
        EXPECT_FALSE(std::filesystem::exists(local / "renamed.txt"));
    }
}

TEST(JournalPreparationTest, PreparationFailureRollsBackMemoryOnlyBackups) {
    auto owner = kasumi::test::make_temp_workspace("preparation-failure");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    const auto local = kasumi::test::workspace_path(owner, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    kasumi::test::write_text(local / "file.txt", "ORIGINAL");
    ASSERT_TRUE(std::filesystem::create_directory(local / "invalid.txt"));
    const auto hash = kasumi::hash_hex(kasumi::hasher::hash_string("NEW"));
    auto record = sync::journal::create_record(
        0,
        0,
        kasumi::make_sync_plan(
            {
                {.action = kasumi::Action::Download,
                 .path = "file.txt",
                 .hash = hash,
                 .size = 3},
                {.action = kasumi::Action::Download,
                 .path = "invalid.txt",
                 .hash = hash,
                 .size = 3},
            },
            0));
    ASSERT_TRUE(record);
    const auto paths = sync::journal::make_paths(profile);
    ASSERT_TRUE(paths);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    ASSERT_TRUE(sync::journal::save(*paths, *record, key));
    const kasumi::platform::Workspace workspace{
        .root = profile / ".transactions" / record->operation_id};
    ASSERT_TRUE(std::filesystem::create_directories(workspace.root));
    auto prepared = sync::mutation::prepare_operation(
        record->plan.operations[0], 0, local, workspace, record->progress[0]);
    ASSERT_TRUE(prepared);
    record->progress[0] = *prepared;
    auto failed = sync::mutation::prepare_operation(
        record->plan.operations[1], 1, local, workspace, record->progress[1]);
    ASSERT_FALSE(failed);
    auto rolled = sync::coordinator::detail::rollback_transaction(
        *paths, *record, workspace, local, key);
    ASSERT_TRUE(rolled) << rolled.error().detail;
    EXPECT_EQ(kasumi::test::read_text(local / "file.txt"), "ORIGINAL");
    EXPECT_TRUE(std::filesystem::is_directory(local / "invalid.txt"));
    EXPECT_FALSE(std::filesystem::exists(paths->final_path));
}

TEST(JournalPreparationTest,
     AuthenticatedInvalidPayloadPreservesRecoveryAuthority) {
    auto owner =
        kasumi::test::make_temp_workspace("authenticated-invalid-journal");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    const auto local = kasumi::test::workspace_path(owner, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    kasumi::test::write_text(local / "confirmed.txt", "CONFIRMED");
    const auto paths = sync::journal::make_paths(profile);
    ASSERT_TRUE(paths);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    auto journal_key =
        kasumi::crypto::derive_key(key, kasumi::crypto::KeyPurpose::Journal);
    std::array<std::uint8_t, 53> encrypted{};
    encrypted[0] = 'K';
    encrypted[1] = 'T';
    encrypted[2] = 'X';
    encrypted[3] = '2';
    encrypted[4] = 1;
    const std::uint8_t invalid_payload = 255;
    crypto_aead_lock(encrypted.data() + 52,
                     encrypted.data() + 36,
                     journal_key.data(),
                     encrypted.data() + 12,
                     encrypted.data(),
                     12,
                     &invalid_payload,
                     1);
    crypto_wipe(journal_key.data(), journal_key.size());
    kasumi::test::write_binary(
        paths->final_path,
        std::vector<std::byte>{
            reinterpret_cast<const std::byte*>(encrypted.data()),
            reinterpret_cast<const std::byte*>(encrypted.data() +
                                               encrypted.size())});
    const auto before = kasumi::test::read_binary(paths->final_path);
    const auto loaded = sync::journal::load(*paths, key);
    ASSERT_FALSE(loaded);
    EXPECT_EQ(loaded.error().find("authentication failed"), std::string::npos);
    const kasumi::runtime::RuntimeData runtime{.local_dir = local,
                                               .database_path =
                                                   profile / "state.db",
                                               .key_path = profile / "key.bin"};
    kasumi::transport::Transport unavailable{};
    auto recovered =
        sync::coordinator::recover_if_needed(runtime, unavailable, key);
    ASSERT_FALSE(recovered);
    EXPECT_EQ(recovered.error().code,
              sync::coordinator::ErrorCode::JournalFailure);
    EXPECT_EQ(kasumi::test::read_binary(paths->final_path), before);
    EXPECT_EQ(kasumi::test::read_text(local / "confirmed.txt"), "CONFIRMED");
    EXPECT_FALSE(std::filesystem::exists(runtime.database_path));
}

} // namespace
