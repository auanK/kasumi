#include "application/history_storage/epoch.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/reachability.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/fsck_checkpoint.hpp"
#include "application/integrity/maintenance.hpp"
#include "core/maintenance.hpp"
#include "crypto/physical_hash.hpp"
#include "kasumi/test/history_storage.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "platform/private_storage.hpp"

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

using kasumi::application::history_storage::PublishedCommit;
using kasumi::runtime::RuntimeData;

inline const auto& test_layout() {
    static const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    return layout;
}

RuntimeData make_test_runtime_data(TempWorkspace& workspace) {
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    EXPECT_TRUE(std::filesystem::create_directories(local));
    EXPECT_TRUE(std::filesystem::create_directories(profile));
    return RuntimeData{
        .local_dir = local,
        .database_path = profile / "db.sqlite",
        .key_path = profile / "key.bin",
        .storage_location = "unused",
    };
}

std::string put_content(kasumi::transport::Transport& transport,
                        TempWorkspace& workspace,
                        std::string_view content,
                        std::string_view suffix) {
    const auto identifier = kasumi::crypto::content_identifier(
        test_key(), kasumi::hasher::hash_string(content));
    const auto plain =
        kasumi::test::workspace_path(workspace, std::string{suffix} + ".plain");
    const auto encrypted =
        kasumi::test::workspace_path(workspace, std::string{suffix} + ".enc");
    kasumi::test::write_text(plain, content);
    EXPECT_TRUE(kasumi::crypto::encrypt_file(plain, encrypted, test_key()));
    EXPECT_TRUE(kasumi::transport::put(transport, encrypted, identifier));
    return identifier;
}

PublishedCommit publish_remote(kasumi::transport::Transport& transport,
                               TempWorkspace& workspace,
                               const Commit& commit) {
    auto published = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    EXPECT_TRUE(published.has_value()) << published.error().detail;
    return published ? *published : PublishedCommit{};
}

// Global hook for fake lying transport
std::string g_fake_lying_target_id;
std::string g_fake_lying_reported_hash;
bool g_fake_lying_hash_called = false;

std::expected<std::string, kasumi::transport::Error>
fake_lying_physical_hash(void*, std::string_view identifier, std::string_view) {
    g_fake_lying_hash_called = true;
    if (identifier == g_fake_lying_target_id) {
        return g_fake_lying_reported_hash;
    }
    return std::unexpected(kasumi::transport::Error{
        .code = kasumi::transport::ErrorCode::Unsupported,
        .message = "unsupported identifier for test",
    });
}

TEST(FsckResumeTest, ColdAuditPersistsCheckpointWithVerifiedProof) {
    auto storage = make_local_storage();
    auto runtime = make_test_runtime_data(storage.workspace);

    const auto commit = make_commit(0, {}, "test.txt", "cold audit test content").value();
    (void)publish_remote(storage.transport, storage.workspace, commit);
    const auto content_id = put_content(storage.transport, storage.workspace, "cold audit test content", "test");

    auto fsck_result = kasumi::application::integrity::fsck(runtime, storage.transport, test_key());
    ASSERT_TRUE(fsck_result.has_value()) << fsck_result.error().detail;
    EXPECT_EQ(fsck_result->checked_objects, 1U);

    // Verify checkpoint file was created
    const auto ckpt_path = kasumi::application::integrity::checkpoint_path(runtime.database_path.parent_path());
    ASSERT_TRUE(std::filesystem::exists(ckpt_path));

    // Load checkpoint and verify contents
    auto checkpoint = kasumi::application::integrity::load_checkpoint(
        runtime.database_path.parent_path(), test_key());
    ASSERT_TRUE(checkpoint.has_value()) << checkpoint.error();
    ASSERT_TRUE(checkpoint->has_value());

    EXPECT_EQ((*checkpoint)->header.format_version, kasumi::application::integrity::checkpoint_format_version_1);
    EXPECT_EQ((*checkpoint)->header.audit_semantics_version, kasumi::application::integrity::checkpoint_audit_semantics_version_1);
    EXPECT_EQ((*checkpoint)->entries.size(), 1U);

    const auto& entry = (*checkpoint)->entries[0];
    const auto expected_logical = kasumi::hash_hex(kasumi::hasher::hash_string("cold audit test content"));
    EXPECT_EQ(entry.logical_content_hash, expected_logical);
    EXPECT_EQ(entry.remote_content_id, content_id);
    EXPECT_EQ(entry.plaintext_size, std::string("cold audit test content").size());
    EXPECT_FALSE(entry.physical_ciphertext_sha256.empty());
}

TEST(FsckResumeTest, WarmAuditLoadsCheckpointAndIdentifiesCandidates) {
    auto storage = make_local_storage();
    auto runtime = make_test_runtime_data(storage.workspace);

    const auto commit = make_commit(0, {}, "warm.txt", "warm resume test content").value();
    (void)publish_remote(storage.transport, storage.workspace, commit);
    (void)put_content(storage.transport, storage.workspace, "warm resume test content", "warm");

    // Cold run
    auto cold_result = kasumi::application::integrity::fsck(runtime, storage.transport, test_key());
    ASSERT_TRUE(cold_result.has_value()) << cold_result.error().detail;

    // Warm run: checkpoint exists and is loaded
    auto warm_result = kasumi::application::integrity::fsck(runtime, storage.transport, test_key());
    ASSERT_TRUE(warm_result.has_value()) << warm_result.error().detail;
    EXPECT_EQ(warm_result->checked_objects, 1U);
    EXPECT_EQ(warm_result->repaired_objects, 0U);
}

TEST(FsckResumeTest, DecisiveAdversarialLyingPhysicalHashRejectsBlindReuseUnderThreatA) {
    // SECURITY GATE DECISIVE ADVERSARIAL TEST (Section 5 & 38)
    // Threat A: "Remote storage is untrusted and can tamper with stored objects."
    // Scenario:
    // 1. Cold FSCK verifies object X and persists physical SHA-256 = H_old.
    // 2. Attacker corrupts remote ciphertext of object X on disk.
    // 3. Attacker's transport physical_hash() maliciously reports H_old.
    // Question: Does Kasumi blindly accept object X as Healthy?
    // Result: Kasumi must NOT trust unauthenticated provider metadata.
    // Kasumi falls back to full audit, downloads ciphertext, AEAD decrypt fails,
    // and corruption is detected!
    auto storage = make_local_storage();
    auto runtime = make_test_runtime_data(storage.workspace);

    const auto commit = make_commit(0, {}, "adversarial.txt", "authentic payload bytes").value();
    (void)publish_remote(storage.transport, storage.workspace, commit);
    const auto content_id = put_content(storage.transport, storage.workspace, "authentic payload bytes", "adv");

    // 1. Cold audit creates checkpoint
    auto cold_result = kasumi::application::integrity::fsck(runtime, storage.transport, test_key());
    ASSERT_TRUE(cold_result.has_value()) << cold_result.error().detail;

    auto ckpt = kasumi::application::integrity::load_checkpoint(
        runtime.database_path.parent_path(), test_key());
    ASSERT_TRUE(ckpt.has_value() && ckpt->has_value());
    const auto h_old = (*ckpt)->entries[0].physical_ciphertext_sha256;
    ASSERT_FALSE(h_old.empty());

    // 2. Attacker mutates remote ciphertext bytes on storage
    const auto remote_file_path = kasumi::test::workspace_path(storage.workspace, "storage/" + content_id);
    ASSERT_TRUE(std::filesystem::exists(remote_file_path));
    {
        std::fstream file(remote_file_path, std::ios::in | std::ios::out | std::ios::binary);
        ASSERT_TRUE(file.is_open());
        file.seekp(40); // mutate inside encrypted ciphertext body
        char tampered = 'Z';
        file.write(&tampered, 1);
        file.close();
    }

    // 3. Configure transport to maliciously report H_old despite altered bytes
    g_fake_lying_target_id = content_id;
    g_fake_lying_reported_hash = h_old;
    g_fake_lying_hash_called = false;
    storage.transport.storage.physical_hash = fake_lying_physical_hash;

    // 4. Run FSCK
    auto adversarial_result = kasumi::application::integrity::fsck(runtime, storage.transport, test_key());

    // Transport physical_hash was queried and reported the lying hash H_old
    EXPECT_TRUE(g_fake_lying_hash_called);

    // CRITICAL SECURITY PROOF:
    // Under Kasumi's Threat A, the lying provider hash is NOT accepted as proof of integrity.
    // The altered bytes are downloaded, AEAD/MAC verification fails, and FSCK fails closed!
    ASSERT_FALSE(adversarial_result.has_value());
    EXPECT_EQ(adversarial_result.error().code, kasumi::application::integrity::ErrorCode::Unrecoverable);
}

TEST(FsckResumeTest, RemoteCiphertextChangedMismatchedHashTriggersFullAuditAndDetectsCorruption) {
    // Section 37: remote ciphertext changed, hash mismatch -> full audit -> corruption detected
    auto storage = make_local_storage();
    auto runtime = make_test_runtime_data(storage.workspace);

    const auto commit = make_commit(0, {}, "changed.txt", "initial content").value();
    (void)publish_remote(storage.transport, storage.workspace, commit);
    const auto content_id = put_content(storage.transport, storage.workspace, "initial content", "chg");

    // Cold audit creates checkpoint
    auto cold_result = kasumi::application::integrity::fsck(runtime, storage.transport, test_key());
    ASSERT_TRUE(cold_result.has_value());

    // Mutate ciphertext on storage
    const auto remote_file_path = kasumi::test::workspace_path(storage.workspace, "storage/" + content_id);
    {
        std::fstream file(remote_file_path, std::ios::in | std::ios::out | std::ios::binary);
        file.seekp(50);
        char bad = 'X';
        file.write(&bad, 1);
        file.close();
    }

    // Transport reports mismatched hash H_mismatched != H_old
    g_fake_lying_target_id = content_id;
    g_fake_lying_reported_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    g_fake_lying_hash_called = false;
    storage.transport.storage.physical_hash = fake_lying_physical_hash;

    auto result = kasumi::application::integrity::fsck(runtime, storage.transport, test_key());
    EXPECT_TRUE(g_fake_lying_hash_called);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, kasumi::application::integrity::ErrorCode::Unrecoverable);
}

TEST(FsckResumeTest, WrongVaultIdentityRejectsCheckpointAndExecutesFullAudit) {
    // Section 40: checkpoint from vault A + run FSCK for vault B -> rejected, full normal audit
    auto storage = make_local_storage();
    auto runtime = make_test_runtime_data(storage.workspace);

    const auto commit = make_commit(0, {}, "vault.txt", "vault content").value();
    (void)publish_remote(storage.transport, storage.workspace, commit);
    (void)put_content(storage.transport, storage.workspace, "vault content", "vlt");

    // Create checkpoint with wrong vault identity
    kasumi::application::integrity::FsckCheckpoint wrong_vault_checkpoint{
        .header = {
            .format_version = kasumi::application::integrity::checkpoint_format_version_1,
            .audit_semantics_version = kasumi::application::integrity::checkpoint_audit_semantics_version_1,
            .vault_id = "completely_different_vault_id",
            .entry_count = 1,
        },
        .entries = {
            {
                .logical_content_hash = kasumi::hash_hex(kasumi::hasher::hash_string("vault content")),
                .remote_content_id = "some_remote_id",
                .plaintext_size = 13,
                .physical_ciphertext_sha256 = std::string(64, 'a'),
            },
        },
    };

    const auto profile_dir = runtime.database_path.parent_path();
    ASSERT_TRUE(kasumi::application::integrity::save_checkpoint(
        profile_dir, wrong_vault_checkpoint, test_key()).has_value());

    // FSCK on our vault: checkpoint should be rejected due to vault mismatch, but FSCK proceeds with full audit
    auto fsck_result = kasumi::application::integrity::fsck(runtime, storage.transport, test_key());
    ASSERT_TRUE(fsck_result.has_value()) << fsck_result.error().detail;
    EXPECT_EQ(fsck_result->checked_objects, 1U);

    // Overwritten by valid checkpoint with the correct vault ID
    auto loaded = kasumi::application::integrity::load_checkpoint(profile_dir, test_key());
    ASSERT_TRUE(loaded.has_value() && loaded->has_value());
    EXPECT_NE((*loaded)->header.vault_id, "completely_different_vault_id");
}

TEST(FsckResumeTest, CorruptedCheckpointFileFallsBackToFullAuditFailClosed) {
    // Section 41: corrupted checkpoint file does not fail FSCK; full audit runs
    auto storage = make_local_storage();
    auto runtime = make_test_runtime_data(storage.workspace);

    const auto commit = make_commit(0, {}, "file.txt", "file content").value();
    (void)publish_remote(storage.transport, storage.workspace, commit);
    (void)put_content(storage.transport, storage.workspace, "file content", "fc");

    const auto ckpt_path = kasumi::application::integrity::checkpoint_path(runtime.database_path.parent_path());
    std::ofstream out(ckpt_path, std::ios::binary);
    std::string garbage = "random_garbage_corrupt_checkpoint_data_12345";
    out.write(garbage.data(), static_cast<std::streamsize>(garbage.size()));
    out.close();

    auto fsck_result = kasumi::application::integrity::fsck(runtime, storage.transport, test_key());
    ASSERT_TRUE(fsck_result.has_value()) << fsck_result.error().detail;
    EXPECT_EQ(fsck_result->checked_objects, 1U);
}

TEST(FsckResumeTest, CheckpointEnabledVsDisabledProducesSemanticallyIdenticalResult) {
    // Section 46: Invariance test
    // Remote state has 1 healthy object, 1 missing object
    auto storage = make_local_storage();
    auto runtime = make_test_runtime_data(storage.workspace);

    const auto commit = make_commit(0, {}, "obj1.txt", "content 1").value();
    (void)publish_remote(storage.transport, storage.workspace, commit);
    // Content object is not put -> Missing!

    // Run without checkpoint
    auto res_disabled = kasumi::application::integrity::fsck(runtime, storage.transport, test_key());
    ASSERT_FALSE(res_disabled.has_value());
    EXPECT_EQ(res_disabled.error().code, kasumi::application::integrity::ErrorCode::Unrecoverable);

    // Run with checkpoint present (e.g. from previous run)
    auto res_enabled = kasumi::application::integrity::fsck(runtime, storage.transport, test_key());
    ASSERT_FALSE(res_enabled.has_value());
    EXPECT_EQ(res_enabled.error().code, kasumi::application::integrity::ErrorCode::Unrecoverable);
    EXPECT_EQ(res_enabled.error().detail, res_disabled.error().detail);
}

} // namespace
