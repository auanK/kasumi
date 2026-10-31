#include "application/sync/coordinator.hpp"
#include "application/sync/coordinator_detail.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/mutation.hpp"
#include "core/hasher.hpp"
#include "core/wire.hpp"
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
        auto workspace =
            sync::coordinator::detail::create_transaction_workspace(
                profile, record->operation_id, key);
        ASSERT_TRUE(workspace) << workspace.error().detail;
        for (std::size_t i = 0; i < prepared_count; ++i) {
            auto prepared =
                sync::mutation::prepare_operation(record->plan.operations[i],
                                                  i,
                                                  local,
                                                  *workspace,
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
        EXPECT_FALSE(std::filesystem::exists(workspace->root));
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
    auto workspace = sync::coordinator::detail::create_transaction_workspace(
        profile, record->operation_id, key);
    ASSERT_TRUE(workspace) << workspace.error().detail;
    auto prepared = sync::mutation::prepare_operation(
        record->plan.operations[0], 0, local, *workspace, record->progress[0]);
    ASSERT_TRUE(prepared);
    record->progress[0] = *prepared;
    auto failed = sync::mutation::prepare_operation(
        record->plan.operations[1], 1, local, *workspace, record->progress[1]);
    ASSERT_FALSE(failed);
    auto rolled = sync::coordinator::detail::rollback_transaction(
        *paths, *record, *workspace, local, key);
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
    auto record =
        sync::journal::create_record(0, 0, kasumi::make_sync_plan({}, 0));
    ASSERT_TRUE(record);
    ASSERT_TRUE(sync::journal::save(*paths, *record, key));
    auto journal_key =
        kasumi::crypto::derive_key(key, kasumi::crypto::KeyPurpose::Journal);
    std::array<std::uint8_t, 53> encrypted{};
    encrypted[0] = 'K';
    encrypted[1] = 'T';
    encrypted[2] = 'X';
    encrypted[3] = '3';
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
    kasumi::test::write_binary(
        paths->final_path,
        std::vector<std::byte>{
            reinterpret_cast<const std::byte*>(encrypted.data()),
            reinterpret_cast<const std::byte*>(encrypted.data() +
                                               encrypted.size())});
    const auto confirmation_path =
        paths->final_path.parent_path() / "confirmed.enc";
    auto confirmation = kasumi::test::read_binary(confirmation_path);
    const auto hash =
        kasumi::hasher::hash_bytes(encrypted.data(), encrypted.size());
    std::copy(hash.begin(), hash.end(), confirmation.begin() + 4);
    std::copy(hash.begin(), hash.end(), confirmation.begin() + 52);
    auto* bytes = reinterpret_cast<std::uint8_t*>(confirmation.data());
    crypto_aead_lock(nullptr,
                     bytes + 108,
                     journal_key.data(),
                     bytes + 84,
                     bytes,
                     84,
                     nullptr,
                     0);
    crypto_wipe(journal_key.data(), journal_key.size());
    kasumi::test::write_binary(confirmation_path, confirmation);
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

TEST(JournalPreparationTest, IncompleteInitializationRetainsTemporaryArtifact) {
    auto owner = kasumi::test::make_temp_workspace("incomplete-initialization");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    const auto local = kasumi::test::workspace_path(owner, "local");
    std::filesystem::create_directories(profile);
    std::filesystem::create_directories(local);
    auto paths = sync::journal::make_paths(profile);
    ASSERT_TRUE(paths);
    const std::vector<std::byte> partial{
        std::byte{'K'}, std::byte{'T'}, std::byte{'X'}, std::byte{'3'}};
    kasumi::test::write_binary(paths->temporary_path, partial);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const kasumi::runtime::RuntimeData runtime{.local_dir = local,
                                               .database_path =
                                                   profile / "state.db",
                                               .key_path = profile / "key.bin"};
    kasumi::transport::Transport unavailable{};
    EXPECT_FALSE(
        sync::coordinator::recover_if_needed(runtime, unavailable, key));
    ASSERT_TRUE(std::filesystem::exists(paths->temporary_path));
    EXPECT_EQ(kasumi::test::read_binary(paths->temporary_path), partial);
}

TEST(JournalPreparationTest, RollbackRemovesInterruptedOwnedDownloadCandidate) {
    auto owner =
        kasumi::test::make_temp_workspace("interrupted-download-candidate");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    const auto local = kasumi::test::workspace_path(owner, "local");
    std::filesystem::create_directories(profile);
    std::filesystem::create_directories(local);
    auto record = sync::journal::create_record(
        0,
        0,
        kasumi::make_sync_plan(
            {{.action = kasumi::Action::CreateLocalDirectory,
              .path = "new-dir"},
             {.action = kasumi::Action::Download,
              .path = "new-dir/file",
              .hash = kasumi::hash_hex(kasumi::hasher::hash_string("COMPLETE")),
              .size = 8}},
            0));
    ASSERT_TRUE(record);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    auto workspace = sync::coordinator::detail::create_transaction_workspace(
        profile, record->operation_id, key);
    ASSERT_TRUE(workspace) << workspace.error().detail;
    record->phase = kasumi::transaction::Phase::FilesStaged;
    record->progress[0].state = kasumi::transaction::OperationState::Applied;
    record->progress[1].state =
        kasumi::transaction::OperationState::BackupCreated;
    auto paths = sync::journal::make_paths(profile);
    ASSERT_TRUE(paths);
    ASSERT_TRUE(sync::journal::save(*paths, *record, key));
    std::filesystem::create_directory(local / "new-dir");
    const auto candidate =
        local / "new-dir" / (".file.kasumi-new-" + record->operation_id + "-1");
    kasumi::test::write_text(candidate, "PARTIAL");
    const kasumi::runtime::RuntimeData runtime{.local_dir = local,
                                               .database_path =
                                                   profile / "state.db",
                                               .key_path = profile / "key.bin"};
    kasumi::transport::Transport unavailable{};
    auto recovered =
        sync::coordinator::recover_if_needed(runtime, unavailable, key);
    ASSERT_TRUE(recovered) << recovered.error().detail;
    EXPECT_FALSE(std::filesystem::exists(local / "new-dir"));
    EXPECT_FALSE(std::filesystem::exists(paths->final_path));
}

TEST(JournalPreparationTest, RollbackPreservesUnownedDownloadCandidate) {
    auto owner =
        kasumi::test::make_temp_workspace("interrupted-download-candidate");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    const auto local = kasumi::test::workspace_path(owner, "local");
    std::filesystem::create_directories(profile);
    std::filesystem::create_directories(local);
    auto record = sync::journal::create_record(
        0,
        0,
        kasumi::make_sync_plan(
            {{.action = kasumi::Action::CreateLocalDirectory,
              .path = "new-dir"},
             {.action = kasumi::Action::Download,
              .path = "new-dir/file",
              .hash = kasumi::hash_hex(kasumi::hasher::hash_string("COMPLETE")),
              .size = 8}},
            0));
    ASSERT_TRUE(record);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    auto workspace = sync::coordinator::detail::create_transaction_workspace(
        profile, record->operation_id, key);
    ASSERT_TRUE(workspace) << workspace.error().detail;
    record->phase = kasumi::transaction::Phase::FilesStaged;
    record->progress[0].state = kasumi::transaction::OperationState::Applied;
    record->progress[1].state =
        kasumi::transaction::OperationState::BackupCreated;
    auto paths = sync::journal::make_paths(profile);
    ASSERT_TRUE(paths);
    ASSERT_TRUE(sync::journal::save(*paths, *record, key));
    std::filesystem::create_directory(local / "new-dir");
    const auto candidate =
        local / "new-dir" /
        (".file.kasumi-new-" + record->operation_id + "-other");
    kasumi::test::write_text(candidate, "PARTIAL");
    const kasumi::runtime::RuntimeData runtime{.local_dir = local,
                                               .database_path =
                                                   profile / "state.db",
                                               .key_path = profile / "key.bin"};
    kasumi::transport::Transport unavailable{};
    auto recovered =
        sync::coordinator::recover_if_needed(runtime, unavailable, key);
    ASSERT_FALSE(recovered);
    EXPECT_EQ(kasumi::test::read_text(candidate), "PARTIAL");
    EXPECT_TRUE(std::filesystem::exists(paths->final_path));
}

TEST(JournalPreparationTest, RollbackPreservesUnexpectedDownloadCandidateType) {
    auto owner =
        kasumi::test::make_temp_workspace("interrupted-download-candidate");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    const auto local = kasumi::test::workspace_path(owner, "local");
    std::filesystem::create_directories(profile);
    std::filesystem::create_directories(local);
    auto record = sync::journal::create_record(
        0,
        0,
        kasumi::make_sync_plan(
            {{.action = kasumi::Action::CreateLocalDirectory,
              .path = "new-dir"},
             {.action = kasumi::Action::Download,
              .path = "new-dir/file",
              .hash = kasumi::hash_hex(kasumi::hasher::hash_string("COMPLETE")),
              .size = 8}},
            0));
    ASSERT_TRUE(record);
    const kasumi::platform::Workspace workspace{profile / ".transactions" /
                                                record->operation_id};
    std::filesystem::create_directories(workspace.root);
    record->phase = kasumi::transaction::Phase::FilesStaged;
    record->progress[0].state = kasumi::transaction::OperationState::Applied;
    record->progress[1].state =
        kasumi::transaction::OperationState::BackupCreated;
    auto paths = sync::journal::make_paths(profile);
    ASSERT_TRUE(paths);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    ASSERT_TRUE(sync::journal::save(*paths, *record, key));
    std::filesystem::create_directory(local / "new-dir");
    const auto candidate =
        local / "new-dir" / (".file.kasumi-new-" + record->operation_id + "-1");
    std::filesystem::create_directory(candidate);
    const kasumi::runtime::RuntimeData runtime{.local_dir = local,
                                               .database_path =
                                                   profile / "state.db",
                                               .key_path = profile / "key.bin"};
    kasumi::transport::Transport unavailable{};
    auto recovered =
        sync::coordinator::recover_if_needed(runtime, unavailable, key);
    ASSERT_FALSE(recovered);
    EXPECT_TRUE(std::filesystem::is_directory(candidate));
    EXPECT_TRUE(std::filesystem::exists(paths->final_path));
}

std::vector<std::byte>
build_legacy_v091_recovery_payload(std::string_view op_id,
                                   std::string_view download_path,
                                   std::string_view download_hash,
                                   std::string_view dl_prev_hash,
                                   std::string_view delete_path,
                                   std::string_view del_hash,
                                   std::string_view del_prev_hash) {
    wire::Writer writer;
    wire::write<std::uint8_t>(writer, 9);
    wire::write_string(writer, op_id);
    wire::write<std::uint8_t>(
        writer, static_cast<std::uint8_t>(kasumi::transaction::Phase::Started));
    wire::write<std::uint8_t>(writer, 1);
    wire::write_string(writer, "");
    wire::write_string(writer, "");
    wire::write<std::uint64_t>(writer, 0);
    wire::write<std::uint64_t>(writer, 0);
    wire::write<std::uint32_t>(writer, 0);
    wire::write<std::uint32_t>(writer, 0);
    wire::write<std::uint64_t>(writer, 0);
    wire::write_string(writer, "");
    wire::write_string(writer, "");
    wire::write_string(writer, "");
    wire::write_string(writer, "");
    wire::write_string(writer, "");
    wire::write<std::int64_t>(writer, 0);
    wire::write<std::uint32_t>(writer, 0);
    wire::write<std::uint32_t>(writer, 0);
    wire::write<std::uint32_t>(writer, 0);
    wire::write<std::uint32_t>(writer, 2);

    // Op 0: Historical Download (wire 4 in v0.9.1)
    wire::write<std::uint8_t>(writer, 4);
    wire::write_string(writer, download_path);
    wire::write_string(writer, "");
    wire::write_string(writer, download_hash);
    wire::write<std::uint64_t>(writer, 8);
    wire::write<std::uint8_t>(writer, 0);
    wire::write_string(writer, dl_prev_hash);
    wire::write<std::uint32_t>(writer, 0);
    wire::write<std::uint8_t>(
        writer,
        static_cast<std::uint8_t>(
            kasumi::transaction::OperationState::Applied));
    wire::write<std::uint8_t>(writer, 1);

    // Op 1: Historical DeleteLocal (wire 5 in v0.9.1)
    wire::write<std::uint8_t>(writer, 5);
    wire::write_string(writer, delete_path);
    wire::write_string(writer, "");
    wire::write_string(writer, del_hash);
    wire::write<std::uint64_t>(writer, 8);
    wire::write<std::uint8_t>(writer, 0);
    wire::write_string(writer, del_prev_hash);
    wire::write<std::uint32_t>(writer, 1);
    wire::write<std::uint8_t>(
        writer,
        static_cast<std::uint8_t>(
            kasumi::transaction::OperationState::Applied));
    wire::write<std::uint8_t>(writer, 1);

    return writer.buffer;
}

TEST(JournalPreparationTest,
     RecoversHistoricalV091JournalRecordThroughCoordinator) {
    auto owner = kasumi::test::make_temp_workspace("v091-historical-recovery");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    const auto local = kasumi::test::workspace_path(owner, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));

    const std::string op_id = "0123456789abcdef0123456789abcdef";
    const auto dl_new_content = "NEW_DOWNLOAD";
    const auto dl_old_content = "OLD_DOWNLOAD";
    const auto del_old_content = "OLD_DELETE";

    kasumi::test::write_text(local / "download.txt", dl_new_content);

    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    auto workspace = sync::coordinator::detail::create_transaction_workspace(
        profile, op_id, key);
    ASSERT_TRUE(workspace) << workspace.error().detail;
    kasumi::test::write_text(workspace->root / "0.backup", dl_old_content);
    kasumi::test::write_text(workspace->root / "1.backup", del_old_content);

    const auto dl_new_hash =
        kasumi::hash_hex(kasumi::hasher::hash_string(dl_new_content));
    const auto dl_old_hash =
        kasumi::hash_hex(kasumi::hasher::hash_string(dl_old_content));
    const auto del_old_hash =
        kasumi::hash_hex(kasumi::hasher::hash_string(del_old_content));

    const auto paths = sync::journal::make_paths(profile);
    ASSERT_TRUE(paths);
    auto init_record =
        sync::journal::create_record(0, 0, kasumi::make_sync_plan({}, 0));
    ASSERT_TRUE(init_record);
    ASSERT_TRUE(sync::journal::save(*paths, *init_record, key));

    const auto payload = build_legacy_v091_recovery_payload(op_id,
                                                            "download.txt",
                                                            dl_new_hash,
                                                            dl_old_hash,
                                                            "delete.txt",
                                                            del_old_hash,
                                                            del_old_hash);

    auto journal_key =
        kasumi::crypto::derive_key(key, kasumi::crypto::KeyPurpose::Journal);
    std::vector<std::uint8_t> encrypted(52 + payload.size());
    encrypted[0] = 'K';
    encrypted[1] = 'T';
    encrypted[2] = 'X';
    encrypted[3] = '3';
    const std::uint64_t payload_len = payload.size();
    std::memcpy(encrypted.data() + 4, &payload_len, sizeof(payload_len));
    crypto_aead_lock(encrypted.data() + 52,
                     encrypted.data() + 36,
                     journal_key.data(),
                     encrypted.data() + 12,
                     encrypted.data(),
                     12,
                     reinterpret_cast<const std::uint8_t*>(payload.data()),
                     payload.size());
    kasumi::test::write_binary(
        paths->final_path,
        std::vector<std::byte>{
            reinterpret_cast<const std::byte*>(encrypted.data()),
            reinterpret_cast<const std::byte*>(encrypted.data() +
                                               encrypted.size())});
    const auto confirmation_path =
        paths->final_path.parent_path() / "confirmed.enc";
    auto confirmation = kasumi::test::read_binary(confirmation_path);
    const auto hash =
        kasumi::hasher::hash_bytes(encrypted.data(), encrypted.size());
    std::copy(hash.begin(), hash.end(), confirmation.begin() + 4);
    std::copy(hash.begin(), hash.end(), confirmation.begin() + 52);
    auto* bytes = reinterpret_cast<std::uint8_t*>(confirmation.data());
    crypto_aead_lock(nullptr,
                     bytes + 108,
                     journal_key.data(),
                     bytes + 84,
                     bytes,
                     84,
                     nullptr,
                     0);
    crypto_wipe(journal_key.data(), journal_key.size());
    kasumi::test::write_binary(confirmation_path, confirmation);

    const kasumi::runtime::RuntimeData runtime{.local_dir = local,
                                               .database_path =
                                                   profile / "state.db",
                                               .key_path = profile / "key.bin"};
    kasumi::transport::Transport unavailable{};
    auto recovered =
        sync::coordinator::recover_if_needed(runtime, unavailable, key);
    ASSERT_TRUE(recovered) << (recovered ? "" : recovered.error().detail);
    EXPECT_EQ(*recovered, sync::coordinator::RecoveryResult::RolledBack);
    EXPECT_EQ(kasumi::test::read_text(local / "download.txt"), dl_old_content);
    EXPECT_EQ(kasumi::test::read_text(local / "delete.txt"), del_old_content);
    EXPECT_FALSE(std::filesystem::exists(paths->final_path));
    EXPECT_FALSE(std::filesystem::exists(workspace->root));
}

} // namespace
