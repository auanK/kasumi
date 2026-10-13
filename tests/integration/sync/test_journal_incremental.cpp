#include "application/history_storage/publication.hpp"
#include "application/sync/coordinator.hpp"
#include "application/sync/coordinator_detail.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/mutation.hpp"
#include "core/hasher.hpp"
#include "core/reconciliation/plan.hpp"
#include "core/transaction/codec.hpp"
#include "core/wire.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/key_derivation.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/clock.hpp"
#include "platform/metadata.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "transport/transport.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <future>
#include <gtest/gtest.h>
#include <monocypher.h>
#include <string>
#include <vector>

namespace {

namespace sync = kasumi::application::sync;

kasumi::runtime::RuntimeData
make_runtime(const std::filesystem::path& profile,
             const std::filesystem::path& local,
             const std::filesystem::path& storage) {
    return {.local_dir = local,
            .database_path = profile / "state.db",
            .key_path = profile / "key.bin",
            .storage_location = kasumi::platform::path::to_utf8(storage)};
}

void add_storage_object(kasumi::transport::Transport& storage,
                        const std::filesystem::path& source,
                        const kasumi::Hash& hash) {
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto encrypted = kasumi::platform::path::temporary_sibling_path(
        source, "", ".encrypted");
    ASSERT_TRUE(kasumi::crypto::encrypt_file(source, encrypted, key));
    ASSERT_TRUE(kasumi::transport::put(
        storage, encrypted, kasumi::crypto::content_identifier(key, hash)));
}

kasumi::reconciliation::Input empty_publication_input() {
    kasumi::Snapshot local_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    kasumi::finalize_snapshot(local_tree);
    return {.local_tree = local_tree,
            .base_tree = {},
            .base_commit_id = {},
            .base_state_present = false,
            .storage = {.tree = {},
                        .object_identifiers = {},
                        .reachable_commits = {},
                        .reachable_commit_ids = {},
                        .marked_heads = {},
                        .marked_head_identifiers = {},
                        .logical_heads = {},
                        .ancestral_marked_heads = {},
                        .generation = 0,
                        .history_present = false,
                        .history_has_conflicts = false}};
}

void run_download_sync(std::size_t file_count,
                       std::uint64_t& written_bytes,
                       std::uint64_t& durable_saves) {
    auto workspace = kasumi::test::make_temp_workspace(
        "red-download-" + std::to_string(file_count));
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_dir = kasumi::test::workspace_path(workspace, "storage");
    const auto staging = kasumi::test::workspace_path(workspace, "staging");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    ASSERT_TRUE(std::filesystem::create_directories(storage_dir));
    ASSERT_TRUE(std::filesystem::create_directories(staging));

    auto storage = kasumi::transport::open_transport(storage_dir.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    auto input = empty_publication_input();
    const std::string content(1024, 'x'); // 1 KiB
    const auto content_hash = kasumi::hasher::hash_string(content);
    const auto staged_file = staging / "source.bin";
    kasumi::test::write_text(staged_file, content);
    add_storage_object(*storage, staged_file, content_hash);

    input.storage.tree.rows.push_back(
        kasumi::NodeRow{.path = "", .is_directory = true});
    for (std::size_t i = 0; i < file_count; ++i) {
        const auto filename = "file_" + std::to_string(i) + ".txt";
        input.storage.tree.rows.push_back(kasumi::NodeRow{
            .path = filename,
            .hash = content_hash,
            .size = content.size(),
            .mtime = 1000,
            .is_directory = false,
        });
    }
    kasumi::finalize_snapshot(input.storage.tree);
    input.base_tree = kasumi::Snapshot{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    kasumi::finalize_snapshot(input.base_tree);

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_EQ(result->plan.operations.size(), file_count);

    auto runtime_data = make_runtime(profile, local, storage_dir);
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    const auto executed = kasumi::application::sync::coordinator::execute(
        runtime_data, *storage, key, input, *result);
    ASSERT_TRUE(executed.has_value()) << executed.error().detail;

    written_bytes =
        kasumi::platform::perf_trace::get_count("journal written bytes total");
    durable_saves =
        kasumi::platform::perf_trace::get_count("journal durable saves");
    kasumi::platform::perf_trace::force_enable(false);
}

// RED A: Demonstrates that in 3.2A, total journal bytes grow quadratically
// O(N^2) across scales (100, 200, 400 files), whereas GREEN must achieve
// approximately linear growth.
TEST(JournalIncrementalRedTest, GrowthAcrossFileScalesIsLinearNotQuadratic) {
    std::uint64_t bytes_100 = 0;
    std::uint64_t saves_100 = 0;
    run_download_sync(100, bytes_100, saves_100);

    std::uint64_t bytes_200 = 0;
    std::uint64_t saves_200 = 0;
    run_download_sync(200, bytes_200, saves_200);

    std::uint64_t bytes_400 = 0;
    std::uint64_t saves_400 = 0;
    run_download_sync(400, bytes_400, saves_400);

    std::cout << "[RED A Metrics] 100 files: " << bytes_100 << " bytes, "
              << saves_100 << " saves\n";
    std::cout << "[RED A Metrics] 200 files: " << bytes_200 << " bytes, "
              << saves_200 << " saves\n";
    std::cout << "[RED A Metrics] 400 files: " << bytes_400 << " bytes, "
              << saves_400 << " saves\n";

    // Ratio 400 vs 100: For linear O(N), 4x files -> ~4x bytes.
    // In quadratic O(N^2) (3.2A), 4x files -> ~14x to 16x bytes!
    // GREEN condition requires ratio < 5.0x and bounded total bytes for 400
    // files (< 400 KB).
    const double ratio_400_to_100 =
        static_cast<double>(bytes_400) / static_cast<double>(bytes_100);
    std::cout << "[RED A Ratio] bytes_400 / bytes_100 = " << ratio_400_to_100
              << "\n";

    EXPECT_LT(ratio_400_to_100, 5.0);
    EXPECT_LT(bytes_400, 300'000ULL);
}

// RED B: Demonstrates that completing a single operation currently rewrites the
// entire plan (~50 KB for 400 operations) instead of an O(1) small delta (< 1
// KB).
TEST(JournalIncrementalRedTest, SingleOperationCompletionCostIsO1) {
    auto owner =
        kasumi::test::make_temp_workspace("single-completion-cost-test");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    ASSERT_TRUE(std::filesystem::create_directories(profile));

    constexpr std::size_t op_count = 400;
    std::vector<kasumi::Operation> operations;
    operations.reserve(op_count);
    const auto dummy_hash =
        kasumi::hash_hex(kasumi::hasher::hash_string("PAYLOAD"));
    for (std::size_t i = 0; i < op_count; ++i) {
        operations.push_back(kasumi::Operation{
            .action = kasumi::Action::Download,
            .path = "dir/sub/file_" + std::to_string(i) + ".dat",
            .hash = dummy_hash,
            .size = 1024,
        });
    }

    auto record = sync::journal::create_record(
        0, 0, kasumi::make_sync_plan(operations, 0));
    ASSERT_TRUE(record.has_value());

    const auto paths = sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    // Initial snapshot save
    ASSERT_TRUE(sync::journal::save(*paths, *record, key));

    // Now complete EXACTLY ONE operation:
    record->progress[42].state = kasumi::transaction::OperationState::Applied;

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    ASSERT_TRUE(sync::journal::save(*paths, *record, key));

    const auto delta_bytes =
        kasumi::platform::perf_trace::get_count("journal written bytes total");
    kasumi::platform::perf_trace::force_enable(false);

    std::cout << "[RED B Metric] Single op completion bytes written: "
              << delta_bytes << " bytes\n";

    // In 3.2A, delta_bytes is ~52,000 bytes (full plan rewrite).
    // In incremental journal (GREEN), delta_bytes is < 512 bytes (~94 to 110
    // bytes).
    EXPECT_LE(delta_bytes, 512ULL);
}

// RED C: Demonstrates that upload batch checkpointing currently rewrites the
// full plan on every batch, causing superlinear total bytes as batch count
// grows.
TEST(JournalIncrementalRedTest,
     UploadBatchCheckpointCostScalesLinearlyWithBatchCount) {
    auto run_batch_test = [](std::size_t batch_count,
                             std::size_t batch_size) -> std::uint64_t {
        const std::size_t total_ops = batch_count * batch_size;
        auto owner = kasumi::test::make_temp_workspace(
            "batch-cost-" + std::to_string(batch_count));
        const auto profile = kasumi::test::workspace_path(owner, "profile");
        std::filesystem::create_directories(profile);

        std::vector<kasumi::Operation> operations;
        operations.reserve(total_ops);
        const auto dummy_hash =
            kasumi::hash_hex(kasumi::hasher::hash_string("DATA"));
        for (std::size_t i = 0; i < total_ops; ++i) {
            operations.push_back(kasumi::Operation{
                .action = kasumi::Action::Upload,
                .path = "uploads/file_" + std::to_string(i) + ".bin",
                .hash = dummy_hash,
                .size = 2048,
            });
        }

        auto record = sync::journal::create_record(
            0, 0, kasumi::make_sync_plan(operations, 0));
        const auto paths = sync::journal::make_paths(profile);
        const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

        sync::journal::save(*paths, *record, key);

        kasumi::platform::perf_trace::force_enable(true);
        kasumi::platform::perf_trace::reset();

        for (std::size_t b = 0; b < batch_count; ++b) {
            for (std::size_t i = 0; i < batch_size; ++i) {
                record->progress[b * batch_size + i].state =
                    kasumi::transaction::OperationState::Applied;
            }
            sync::journal::save(*paths, *record, key);
        }

        const auto written = kasumi::platform::perf_trace::get_count(
            "journal written bytes total");
        kasumi::platform::perf_trace::force_enable(false);
        return written;
    };

    constexpr std::size_t batch_size = 10;
    const auto bytes_10_batches = run_batch_test(10, batch_size);
    const auto bytes_40_batches = run_batch_test(40, batch_size);

    std::cout << "[RED C Metrics] 10 batches (100 ops): " << bytes_10_batches
              << " bytes\n";
    std::cout << "[RED C Metrics] 40 batches (400 ops): " << bytes_40_batches
              << " bytes\n";

    const double ratio = static_cast<double>(bytes_40_batches) /
                         static_cast<double>(bytes_10_batches);
    std::cout << "[RED C Ratio] 40 batches / 10 batches = " << ratio << "\n";

    // For linear scaling of batch checkpoints, 4x batches should be ~4x bytes.
    // In 3.2A, 10 batches rewrite 100 ops (10 * 100 = 1,000 op records),
    // and 40 batches rewrite 400 ops (40 * 400 = 16,000 op records) -> 16x
    // growth!
    EXPECT_LT(ratio, 6.0);
}

// RED D: Verifies incremental recovery correctness and security invariants.
TEST(JournalIncrementalRedTest, IncrementalRecoveryStateReconstruction) {
    auto owner =
        kasumi::test::make_temp_workspace("recovery-reconstruction-test");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    ASSERT_TRUE(std::filesystem::create_directories(profile));

    constexpr std::size_t op_count = 50;
    std::vector<kasumi::Operation> operations;
    operations.reserve(op_count);
    const auto dummy_hash =
        kasumi::hash_hex(kasumi::hasher::hash_string("RECOVERY"));
    for (std::size_t i = 0; i < op_count; ++i) {
        operations.push_back(kasumi::Operation{
            .action = kasumi::Action::Download,
            .path = "rec/item_" + std::to_string(i) + ".txt",
            .hash = dummy_hash,
            .size = 512,
        });
    }

    auto record = sync::journal::create_record(
        1, 2, kasumi::make_sync_plan(operations, 3));
    ASSERT_TRUE(record.has_value());

    const auto paths = sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    // 1. Initial snapshot
    ASSERT_TRUE(sync::journal::save(*paths, *record, key));

    // 2. Advance phase to FilesStaged
    record->phase = kasumi::transaction::Phase::FilesStaged;
    ASSERT_TRUE(sync::journal::save(*paths, *record, key));

    // 3. Mark 20 operations as Applied
    for (std::size_t i = 0; i < 20; ++i) {
        record->progress[i].state =
            kasumi::transaction::OperationState::Applied;
        ASSERT_TRUE(sync::journal::save(*paths, *record, key));
    }

    // 4. Load from disk and verify exact state reconstruction
    auto loaded = sync::journal::load(*paths, key);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_EQ((*loaded)->operation_id, record->operation_id);
    EXPECT_EQ((*loaded)->phase, kasumi::transaction::Phase::FilesStaged);
    EXPECT_EQ((*loaded)->local_generation, 1ULL);
    EXPECT_EQ((*loaded)->storage_generation, 2ULL);
    EXPECT_EQ((*loaded)->plan.target_generation, 3ULL);
    EXPECT_EQ((*loaded)->plan.operations.size(), op_count);
    EXPECT_EQ((*loaded)->progress.size(), op_count);

    for (std::size_t i = 0; i < op_count; ++i) {
        if (i < 20) {
            EXPECT_EQ((*loaded)->progress[i].state,
                      kasumi::transaction::OperationState::Applied);
        } else {
            EXPECT_EQ((*loaded)->progress[i].state,
                      kasumi::transaction::OperationState::Pending);
        }
    }
}

TEST(JournalIncrementalAdversarialTest,
     MissingSnapshotWithLogPresentFailsClosed) {
    auto owner = kasumi::test::make_temp_workspace("missing-snapshot-with-log");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    ASSERT_TRUE(std::filesystem::create_directories(profile));

    std::vector<kasumi::Operation> operations{
        {.action = kasumi::Action::Download,
         .path = "a.txt",
         .hash = "abcd",
         .size = 10}};
    auto record = sync::journal::create_record(
        0, 0, kasumi::make_sync_plan(operations, 0));
    const auto paths = sync::journal::make_paths(profile);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    ASSERT_TRUE(sync::journal::save(*paths, *record, key));
    record->progress[0].state = kasumi::transaction::OperationState::Applied;
    ASSERT_TRUE(sync::journal::save(*paths, *record, key));
    ASSERT_TRUE(std::filesystem::exists(paths->log_path));

    // Delete snapshot
    std::filesystem::remove(paths->final_path);

    auto loaded = sync::journal::load(*paths, key);
    EXPECT_FALSE(loaded.has_value());
}

TEST(JournalIncrementalAdversarialTest, TruncatedLogAtHeaderFailsClosed) {
    auto owner = kasumi::test::make_temp_workspace("truncated-log-header");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    ASSERT_TRUE(std::filesystem::create_directories(profile));

    std::vector<kasumi::Operation> operations{
        {.action = kasumi::Action::Download,
         .path = "a.txt",
         .hash = "abcd",
         .size = 10},
        {.action = kasumi::Action::Download,
         .path = "b.txt",
         .hash = "abcd",
         .size = 10}};
    auto record = sync::journal::create_record(
        0, 0, kasumi::make_sync_plan(operations, 0));
    const auto paths = sync::journal::make_paths(profile);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    ASSERT_TRUE(sync::journal::save(*paths, *record, key));
    record->progress[0].state = kasumi::transaction::OperationState::Applied;
    ASSERT_TRUE(sync::journal::save(*paths, *record, key));
    record->progress[1].state = kasumi::transaction::OperationState::Applied;
    ASSERT_TRUE(sync::journal::save(*paths, *record, key));

    // Truncate last 10 bytes
    const auto size = std::filesystem::file_size(paths->log_path);
    std::filesystem::resize_file(paths->log_path, size - 10);

    auto loaded = sync::journal::load(*paths, key);
    EXPECT_FALSE(loaded.has_value());
}

TEST(JournalIncrementalAdversarialTest, CorruptedLogCiphertextFailsClosed) {
    auto owner = kasumi::test::make_temp_workspace("corrupted-log-ciphertext");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    ASSERT_TRUE(std::filesystem::create_directories(profile));

    std::vector<kasumi::Operation> operations{
        {.action = kasumi::Action::Download,
         .path = "a.txt",
         .hash = "abcd",
         .size = 10}};
    auto record = sync::journal::create_record(
        0, 0, kasumi::make_sync_plan(operations, 0));
    const auto paths = sync::journal::make_paths(profile);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    ASSERT_TRUE(sync::journal::save(*paths, *record, key));
    record->progress[0].state = kasumi::transaction::OperationState::Applied;
    ASSERT_TRUE(sync::journal::save(*paths, *record, key));

    // Corrupt last byte of log file
    auto bytes = kasumi::test::read_binary(paths->log_path);
    ASSERT_FALSE(bytes.empty());
    bytes.back() =
        static_cast<std::byte>(static_cast<uint8_t>(bytes.back()) ^ 0xffU);
    kasumi::test::write_binary(paths->log_path, bytes);

    auto loaded = sync::journal::load(*paths, key);
    EXPECT_FALSE(loaded.has_value());
}

TEST(JournalIncrementalAdversarialTest, BrokenHashChainFailsClosed) {
    auto owner = kasumi::test::make_temp_workspace("broken-hash-chain");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    ASSERT_TRUE(std::filesystem::create_directories(profile));

    std::vector<kasumi::Operation> operations{
        {.action = kasumi::Action::Download,
         .path = "a.txt",
         .hash = "abcd",
         .size = 10},
        {.action = kasumi::Action::Download,
         .path = "b.txt",
         .hash = "abcd",
         .size = 10}};
    auto record = sync::journal::create_record(
        0, 0, kasumi::make_sync_plan(operations, 0));
    const auto paths = sync::journal::make_paths(profile);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    ASSERT_TRUE(sync::journal::save(*paths, *record, key));
    record->progress[0].state = kasumi::transaction::OperationState::Applied;
    ASSERT_TRUE(sync::journal::save(*paths, *record, key));
    record->progress[1].state = kasumi::transaction::OperationState::Applied;
    ASSERT_TRUE(sync::journal::save(*paths, *record, key));

    // Flip byte in previous_hash field of the first record (offset 12..43)
    auto bytes = kasumi::test::read_binary(paths->log_path);
    ASSERT_GT(bytes.size(), 20U);
    bytes[15] = static_cast<std::byte>(static_cast<uint8_t>(bytes[15]) ^ 0x01U);
    kasumi::test::write_binary(paths->log_path, bytes);

    auto loaded = sync::journal::load(*paths, key);
    EXPECT_FALSE(loaded.has_value());
}

class JournalCorrectionTest : public ::testing::Test {
protected:
    decltype(kasumi::test::make_temp_workspace("journal-correction")) owner =
        kasumi::test::make_temp_workspace("journal-correction");
    std::filesystem::path profile =
        kasumi::test::workspace_path(owner, "profile");
    sync::journal::Paths paths;
    kasumi::transaction::Record record;
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    void SetUp() override {
        ASSERT_TRUE(std::filesystem::create_directories(profile));
        auto resolved = sync::journal::make_paths(profile);
        ASSERT_TRUE(resolved);
        paths = *resolved;
        auto created = sync::journal::create_record(
            1,
            1,
            kasumi::make_sync_plan({{.action = kasumi::Action::Download,
                                     .path = "one",
                                     .hash = "abcd",
                                     .size = 10},
                                    {.action = kasumi::Action::Download,
                                     .path = "two",
                                     .hash = "abcd",
                                     .size = 10}},
                                   2));
        ASSERT_TRUE(created);
        record = *created;
        ASSERT_TRUE(sync::journal::save(paths, record, key));
    }

    void expect_reload(const kasumi::transaction::Record& expected) {
        auto loaded = sync::journal::load(paths, key);
        ASSERT_TRUE(loaded) << loaded.error();
        ASSERT_TRUE(*loaded);
        EXPECT_EQ(kasumi::transaction::codec::encode(**loaded),
                  kasumi::transaction::codec::encode(expected));
    }

    void replace_authenticated_delta(std::span<const std::byte> payload) {
        auto log = kasumi::test::read_binary(paths.log_path);
        log.resize(88 + payload.size());
        auto* bytes = reinterpret_cast<std::uint8_t*>(log.data());
        auto write_u64 =
            [](std::uint8_t* output, std::uint64_t value, std::size_t size) {
                for (std::size_t i = 0; i < size; ++i)
                    output[i] = static_cast<std::uint8_t>(value >> (8 * i));
            };
        write_u64(bytes + 44, payload.size(), 4);
        auto journal_key = kasumi::crypto::derive_key(
            key, kasumi::crypto::KeyPurpose::Journal);
        kasumi::crypto::Key log_key{};
        constexpr std::string_view domain = "kasumi:journal:log:v3";
        crypto_blake2b_keyed(
            log_key.data(),
            log_key.size(),
            journal_key.data(),
            journal_key.size(),
            reinterpret_cast<const std::uint8_t*>(domain.data()),
            domain.size());
        std::vector<std::uint8_t> aad(bytes, bytes + 48);
        aad.insert(
            aad.end(), record.operation_id.begin(), record.operation_id.end());
        crypto_aead_lock(bytes + 88,
                         bytes + 72,
                         log_key.data(),
                         bytes + 48,
                         aad.data(),
                         aad.size(),
                         reinterpret_cast<const std::uint8_t*>(payload.data()),
                         payload.size());
        crypto_wipe(log_key.data(), log_key.size());
        kasumi::test::write_binary(paths.log_path, log);
        const auto path = paths.final_path.parent_path() / "confirmed.enc";
        auto confirmation = kasumi::test::read_binary(path);
        auto* tip = reinterpret_cast<std::uint8_t*>(confirmation.data());
        write_u64(tip + 36, log.size(), 8);
        const auto hash = kasumi::hasher::hash_bytes(bytes, log.size());
        std::copy(hash.begin(), hash.end(), confirmation.begin() + 52);
        crypto_aead_lock(nullptr,
                         tip + 108,
                         journal_key.data(),
                         tip + 84,
                         tip,
                         84,
                         nullptr,
                         0);
        crypto_wipe(journal_key.data(), journal_key.size());
        kasumi::test::write_binary(path, confirmation);
    }
};

TEST_F(JournalCorrectionTest,
       InterruptedUnconfirmedAppendPreservesConfirmedPrefix) {
    record.phase = kasumi::transaction::Phase::FilesStaged;
    ASSERT_TRUE(sync::journal::save(paths, record, key));
    const auto confirmed = kasumi::test::read_binary(paths.log_path);
    {
        std::ofstream output(paths.log_path, std::ios::binary | std::ios::app);
        output.write("KTXD", 4);
    }
    expect_reload(record);
    EXPECT_GT(std::filesystem::file_size(paths.log_path), confirmed.size());
}

TEST_F(JournalCorrectionTest, CompleteConfirmedSuffixRemovalFailsClosed) {
    record.phase = kasumi::transaction::Phase::FilesStaged;
    ASSERT_TRUE(sync::journal::save(paths, record, key));
    const auto prefix = std::filesystem::file_size(paths.log_path);
    record.progress[0].state = kasumi::transaction::OperationState::Applied;
    ASSERT_TRUE(sync::journal::save(paths, record, key));
    std::filesystem::resize_file(paths.log_path, prefix);
    EXPECT_FALSE(sync::journal::load(paths, key));
}

TEST_F(JournalCorrectionTest, RollbackRoundTripsEveryField) {
    record.phase = kasumi::transaction::Phase::EpochPrepared;
    record.commit_id = std::string(64, 'a');
    record.ciphertext_id = std::string(64, 'b');
    record.marker_id = kasumi::application::history_storage::marker_identifier(
        {.commit_id = record.commit_id, .ciphertext_id = record.ciphertext_id});
    record.parent_ids = {std::string(64, 'c')};
    record.epoch_vault_id = std::string(64, 'd');
    record.epoch_id = std::string(64, 'e');
    record.epoch_issued_at = 12;
    record.epoch_min_history_depth = 2;
    record.epoch_min_history_age_hours = 3;
    record.progress[0].state = kasumi::transaction::OperationState::Applied;
    record.progress[0].previous_hash = "previous";
    record.progress[0].had_original = true;
    record.observed_pending_paths = {"before"};
    record.pending_paths = {"after"};
    ASSERT_TRUE(kasumi::transaction::valid(record));
    auto saved = sync::journal::save(paths, record, key);
    ASSERT_TRUE(saved) << saved.error();
    expect_reload(record);
    record.phase = kasumi::transaction::Phase::Started;
    record.commit_id.clear();
    record.ciphertext_id.clear();
    record.marker_id.clear();
    record.parent_ids.clear();
    record.epoch_vault_id.clear();
    record.epoch_id.clear();
    record.epoch_issued_at = 0;
    record.epoch_min_history_depth = 0;
    record.epoch_min_history_age_hours = 0;
    record.progress[0].state = kasumi::transaction::OperationState::Pending;
    record.progress[0].previous_hash.clear();
    record.progress[0].had_original = false;
    record.pending_paths = {"restored"};
    ASSERT_TRUE(sync::journal::save(
        paths, record, key, sync::journal::SaveMode::Rollback));
    expect_reload(record);
}

TEST_F(JournalCorrectionTest, ChangedPlanCannotReuseSession) {
    const auto before = kasumi::test::read_binary(paths.final_path);
    record.plan.operations[0].path = "different";
    EXPECT_FALSE(sync::journal::save(paths, record, key));
    EXPECT_EQ(kasumi::test::read_binary(paths.final_path), before);
}

TEST_F(JournalCorrectionTest, ActiveGenerationCannotBeReplaced) {
    record.phase = kasumi::transaction::Phase::FilesStaged;
    ASSERT_TRUE(sync::journal::save(paths, record, key));
    const auto snapshot = kasumi::test::read_binary(paths.final_path);
    const auto log = kasumi::test::read_binary(paths.log_path);
    record.operation_id = std::string(32, 'f');
    EXPECT_FALSE(sync::journal::save(paths, record, key));
    EXPECT_EQ(kasumi::test::read_binary(paths.final_path), snapshot);
    EXPECT_EQ(kasumi::test::read_binary(paths.log_path), log);
}

TEST_F(JournalCorrectionTest, WrongKeyCannotReuseSession) {
    key[0] = 1;
    record.phase = kasumi::transaction::Phase::FilesStaged;
    EXPECT_FALSE(sync::journal::save(paths, record, key));
}

TEST_F(JournalCorrectionTest, IncompatibleSnapshotIsRejectedAndPreserved) {
    auto bytes = kasumi::test::read_binary(paths.final_path);
    bytes[3] = std::byte{'2'};
    kasumi::test::write_binary(paths.final_path, bytes);
    EXPECT_FALSE(sync::journal::load(paths, key));
    EXPECT_FALSE(sync::journal::save(paths, record, key));
    EXPECT_EQ(kasumi::test::read_binary(paths.final_path), bytes);
}

TEST_F(JournalCorrectionTest,
       CleanupRejectsMalformedArtifactBeforeRemovingAuthority) {
    const auto before = kasumi::test::read_binary(paths.final_path);
    std::filesystem::create_directory(paths.log_path);
    EXPECT_FALSE(sync::journal::clear(paths, key));
    EXPECT_TRUE(std::filesystem::exists(paths.final_path));
    EXPECT_EQ(kasumi::test::read_binary(paths.final_path), before);
}

TEST_F(JournalCorrectionTest, ExternalSnapshotReplacementCannotReuseSession) {
    auto other = sync::journal::make_paths(profile.parent_path() / "other");
    ASSERT_TRUE(other);
    std::filesystem::create_directory(profile.parent_path() / "other");
    ASSERT_TRUE(sync::journal::save(*other, record, key));
    auto swapped = kasumi::test::read_binary(other->final_path);
    kasumi::test::write_binary(paths.final_path, swapped);
    record.phase = kasumi::transaction::Phase::FilesStaged;
    EXPECT_FALSE(sync::journal::save(paths, record, key));
    EXPECT_FALSE(sync::journal::load(paths, key));
    EXPECT_EQ(kasumi::test::read_binary(paths.final_path), swapped);
}

TEST_F(JournalCorrectionTest, TruncationAtEveryCommittedByteFailsClosed) {
    record.phase = kasumi::transaction::Phase::FilesStaged;
    ASSERT_TRUE(sync::journal::save(paths, record, key));
    const auto bytes = kasumi::test::read_binary(paths.log_path);
    for (std::size_t size = 0; size < bytes.size(); ++size) {
        SCOPED_TRACE(size);
        kasumi::test::write_binary(
            paths.log_path,
            {bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(size)});
        EXPECT_FALSE(sync::journal::load(paths, key));
    }
    kasumi::test::write_binary(paths.log_path, bytes);
    expect_reload(record);
}

TEST_F(JournalCorrectionTest,
       TailIsRetainedOnLoadAndDurablyRemovedBeforeRetry) {
    record.phase = kasumi::transaction::Phase::FilesStaged;
    ASSERT_TRUE(sync::journal::save(paths, record, key));
    const auto size = std::filesystem::file_size(paths.log_path);
    {
        std::ofstream output(paths.log_path, std::ios::binary | std::ios::app);
        output << "unconfirmed";
    }
    expect_reload(record);
    EXPECT_GT(std::filesystem::file_size(paths.log_path), size);
    ASSERT_TRUE(sync::journal::save(paths, record, key));
    EXPECT_EQ(std::filesystem::file_size(paths.log_path), size);
    record.progress[1].state = kasumi::transaction::OperationState::Applied;
    ASSERT_TRUE(sync::journal::save(paths, record, key));
    expect_reload(record);
}

TEST_F(JournalCorrectionTest, ParentSyncFailureThenRetryAuthenticatesDisk) {
#ifdef _WIN32
    _putenv_s("KASUMI_TEST_JOURNAL_FAIL", "parent-sync");
#else
    setenv("KASUMI_TEST_JOURNAL_FAIL", "parent-sync", 1);
#endif
    record.phase = kasumi::transaction::Phase::FilesStaged;
    auto failed = sync::journal::save(paths, record, key);
#ifdef _WIN32
    _putenv_s("KASUMI_TEST_JOURNAL_FAIL", "");
#else
    unsetenv("KASUMI_TEST_JOURNAL_FAIL");
#endif
    if (failed)
        GTEST_SKIP() << "Fault injection requires dedicated build";
    ASSERT_TRUE(sync::journal::save(paths, record, key));
    expect_reload(record);
    record.progress[0].state = kasumi::transaction::OperationState::Applied;
    ASSERT_TRUE(sync::journal::save(paths, record, key));
    expect_reload(record);
}

TEST_F(JournalCorrectionTest, EveryDurabilityFailureAllowsVerifiedRetry) {
    const auto initial = record;
    auto inject = [](const char* point) {
#ifdef _WIN32
        _putenv_s("KASUMI_TEST_JOURNAL_FAIL", point);
#else
        if (*point)
            setenv("KASUMI_TEST_JOURNAL_FAIL", point, 1);
        else
            unsetenv("KASUMI_TEST_JOURNAL_FAIL");
#endif
    };
    for (const char* point :
         {"write", "flush", "close", "sync", "replace", "parent-sync"}) {
        SCOPED_TRACE(point);
        record.phase = kasumi::transaction::Phase::FilesStaged;
        inject(point);
        auto result = sync::journal::save(paths, record, key);
        inject("");
        if (result)
            GTEST_SKIP() << "Fault injection requires dedicated build";
        auto persisted = sync::journal::load(paths, key);
        ASSERT_TRUE(persisted) << persisted.error();
        ASSERT_TRUE(*persisted);
        EXPECT_TRUE((*persisted)->phase == initial.phase ||
                    (*persisted)->phase == record.phase);
        auto retried = sync::journal::save(paths, record, key);
        ASSERT_TRUE(retried) << retried.error();
        expect_reload(record);
        record.progress[0].state = kasumi::transaction::OperationState::Applied;
        ASSERT_TRUE(sync::journal::save(paths, record, key));
        expect_reload(record);
        record.phase = kasumi::transaction::Phase::Started;
        record.progress[0].state = kasumi::transaction::OperationState::Pending;
        ASSERT_TRUE(sync::journal::save(
            paths, record, key, sync::journal::SaveMode::Rollback));
        ASSERT_TRUE(sync::journal::clear(paths, key));
        record = initial;
        ASSERT_TRUE(sync::journal::save(paths, record, key));
    }
}

TEST_F(JournalCorrectionTest,
       AuthenticatedMalformedDeltasAreRejectedWithoutWrites) {
    record.phase = kasumi::transaction::Phase::FilesStaged;
    ASSERT_TRUE(sync::journal::save(paths, record, key));
    const auto original_log = kasumi::test::read_binary(paths.log_path);
    const auto tip_path = paths.final_path.parent_path() / "confirmed.enc";
    const auto original_tip = kasumi::test::read_binary(tip_path);
    std::vector<std::vector<std::byte>> payloads{
        {std::byte{0x80}},
        {std::byte{0x20}},
        {std::byte{0}},
        {std::byte{1}, std::byte{255}},
        {std::byte{1}, std::byte{4}},
        {std::byte{1}, std::byte{1}, std::byte{0}}};
    auto progress = [](std::uint32_t count,
                       std::uint32_t second_index,
                       std::uint8_t state,
                       std::uint32_t slot) {
        wire::Writer writer;
        wire::write<std::uint8_t>(writer, 2);
        wire::write<std::uint32_t>(writer, count);
        if (count <= 2)
            for (std::uint32_t i = 0; i < count; ++i) {
                wire::write<std::uint32_t>(writer, i == 0 ? 0 : second_index);
                wire::write<std::uint8_t>(writer, state);
                wire::write<std::uint32_t>(writer, slot);
                wire::write<std::uint8_t>(writer, 0);
                wire::write_string(writer, "");
            }
        return std::move(writer.buffer);
    };
    payloads.push_back(progress(0, 0, 3, 0));
    payloads.push_back(progress(0xffffffffU, 0, 3, 0));
    payloads.push_back(progress(2, 0, 3, 0));
    payloads.push_back(progress(2, 99, 3, 0));
    payloads.push_back(progress(1, 0, 255, 0));
    payloads.push_back(progress(1, 0, 3, 99));
    for (std::size_t index = 0; index < payloads.size(); ++index) {
        SCOPED_TRACE(index);
        kasumi::test::write_binary(paths.log_path, original_log);
        kasumi::test::write_binary(tip_path, original_tip);
        replace_authenticated_delta(payloads[index]);
        const auto before = kasumi::test::read_binary(paths.log_path);
        auto loaded = sync::journal::load(paths, key);
        ASSERT_FALSE(loaded);
        EXPECT_EQ(loaded.error().find("authentication failed"),
                  std::string::npos);
        EXPECT_EQ(kasumi::test::read_binary(paths.log_path), before);
    }
}

TEST_F(JournalCorrectionTest,
       ConcurrentStaleCheckpointsCannotLoseConfirmedProgress) {
    record.phase = kasumi::transaction::Phase::FilesStaged;
    ASSERT_TRUE(sync::journal::save(paths, record, key));
    auto first = record, second = record;
    first.progress[0].state = kasumi::transaction::OperationState::Applied;
    second.progress[1].state = kasumi::transaction::OperationState::Applied;
    auto a = std::async(std::launch::async, [&] {
        return sync::journal::save(paths, first, key);
    });
    auto b = std::async(std::launch::async, [&] {
        return sync::journal::save(paths, second, key);
    });
    const auto first_result = a.get(), second_result = b.get();
    EXPECT_NE(first_result.has_value(), second_result.has_value());
    expect_reload(first_result ? first : second);
}

TEST_F(JournalCorrectionTest, CleanupFailuresPreserveAuthorityAndAllowRetry) {
    for (const char* point : {"retire", "cleanup-parent-sync", "cleanup"}) {
        SCOPED_TRACE(point);
#ifdef _WIN32
        _putenv_s("KASUMI_TEST_JOURNAL_FAIL", point);
#else
        setenv("KASUMI_TEST_JOURNAL_FAIL", point, 1);
#endif
        auto cleared = sync::journal::clear(paths, key);
#ifdef _WIN32
        _putenv_s("KASUMI_TEST_JOURNAL_FAIL", "");
#else
        unsetenv("KASUMI_TEST_JOURNAL_FAIL");
#endif
        if (cleared)
            GTEST_SKIP() << "Fault injection requires dedicated build";
        auto active = paths.final_path.parent_path();
        const auto retired =
            active.parent_path() / "transaction.bin.enc.cleared";
        const auto authority =
            std::filesystem::exists(active) ? active : retired;
        EXPECT_TRUE(std::filesystem::exists(authority / "snapshot.enc"));
        EXPECT_TRUE(std::filesystem::exists(authority / "confirmed.enc"));
        ASSERT_TRUE(sync::journal::clear(paths, key));
        EXPECT_FALSE(std::filesystem::exists(active));
        EXPECT_FALSE(std::filesystem::exists(retired));
        ASSERT_TRUE(sync::journal::save(paths, record, key));
        expect_reload(record);
    }
}

TEST_F(JournalCorrectionTest, DuplicatedOrReorderedConfirmedRecordsFailClosed) {
    record.phase = kasumi::transaction::Phase::FilesStaged;
    ASSERT_TRUE(sync::journal::save(paths, record, key));
    const auto first = kasumi::test::read_binary(paths.log_path);
    record.progress[0].state = kasumi::transaction::OperationState::Applied;
    ASSERT_TRUE(sync::journal::save(paths, record, key));
    const auto original = kasumi::test::read_binary(paths.log_path);
    auto duplicated = first;
    duplicated.insert(duplicated.end(), original.begin(), original.end());
    kasumi::test::write_binary(paths.log_path, duplicated);
    EXPECT_FALSE(sync::journal::load(paths, key));
    std::vector<std::byte> reordered(
        original.begin() + static_cast<std::ptrdiff_t>(first.size()),
        original.end());
    reordered.insert(reordered.end(), first.begin(), first.end());
    kasumi::test::write_binary(paths.log_path, reordered);
    EXPECT_FALSE(sync::journal::load(paths, key));
    kasumi::test::write_binary(paths.log_path, original);
    expect_reload(record);
}

TEST_F(JournalCorrectionTest,
       TruncationFailurePreservesTailAndConfirmedPrefix) {
    {
        std::ofstream output(paths.log_path, std::ios::binary);
        output << "partial append";
    }
    record.phase = kasumi::transaction::Phase::FilesStaged;
#ifdef _WIN32
    _putenv_s("KASUMI_TEST_JOURNAL_FAIL", "rollback-truncate");
#else
    setenv("KASUMI_TEST_JOURNAL_FAIL", "rollback-truncate", 1);
#endif
    auto retried = sync::journal::save(paths, record, key);
#ifdef _WIN32
    _putenv_s("KASUMI_TEST_JOURNAL_FAIL", "");
#else
    unsetenv("KASUMI_TEST_JOURNAL_FAIL");
#endif
    if (retried)
        GTEST_SKIP() << "Fault injection requires dedicated build";
    EXPECT_EQ(kasumi::test::read_text(paths.log_path), "partial append");
    auto persisted = sync::journal::load(paths, key);
    ASSERT_TRUE(persisted && *persisted);
    EXPECT_EQ((*persisted)->phase, kasumi::transaction::Phase::Started);
    ASSERT_TRUE(sync::journal::save(paths, record, key));
    expect_reload(record);
}

TEST_F(JournalCorrectionTest,
       UnauthenticatedRetirementCannotEraseActiveAuthority) {
    record.phase = kasumi::transaction::Phase::FilesStaged;
    record.progress[0].state = kasumi::transaction::OperationState::Applied;
    ASSERT_TRUE(sync::journal::save(paths, record, key));
    const auto active = paths.final_path.parent_path();
    const auto retired = active.parent_path() / "transaction.bin.enc.cleared";
    std::filesystem::rename(active, retired);
    auto loaded = sync::journal::load(paths, key);
    EXPECT_FALSE(loaded);
    EXPECT_TRUE(std::filesystem::exists(retired / "snapshot.enc"));
    EXPECT_TRUE(std::filesystem::exists(retired / "transaction.log.enc"));
    EXPECT_TRUE(std::filesystem::exists(retired / "confirmed.enc"));
}

TEST_F(JournalCorrectionTest,
       ForeignRetirementProofCannotEraseRemainingAuthority) {
    record.phase = kasumi::transaction::Phase::FilesStaged;
    ASSERT_TRUE(sync::journal::save(paths, record, key));
    const auto other_profile = profile.parent_path() / "other-proof";
    std::filesystem::create_directory(other_profile);
    auto other = sync::journal::make_paths(other_profile);
    ASSERT_TRUE(other);
    auto empty =
        sync::journal::create_record(0, 0, kasumi::make_sync_plan({}, 0));
    ASSERT_TRUE(empty);
    ASSERT_TRUE(sync::journal::save(*other, *empty, key));
    auto proof = kasumi::test::read_binary(other->final_path.parent_path() /
                                           "confirmed.enc");
    proof[2] = std::byte{'Q'};
    auto journal_key =
        kasumi::crypto::derive_key(key, kasumi::crypto::KeyPurpose::Journal);
    auto* bytes = reinterpret_cast<std::uint8_t*>(proof.data());
    crypto_aead_lock(nullptr,
                     bytes + 108,
                     journal_key.data(),
                     bytes + 84,
                     bytes,
                     84,
                     nullptr,
                     0);
    crypto_wipe(journal_key.data(), journal_key.size());
    const auto active = paths.final_path.parent_path();
    const auto retired = active.parent_path() / "transaction.bin.enc.cleared";
    std::filesystem::rename(active, retired);
    kasumi::test::write_binary(retired / "retired.enc", proof);
    EXPECT_FALSE(sync::journal::load(paths, key));
    EXPECT_TRUE(std::filesystem::exists(retired / "snapshot.enc"));
    EXPECT_TRUE(std::filesystem::exists(retired / "transaction.log.enc"));
    EXPECT_TRUE(std::filesystem::exists(retired / "confirmed.enc"));
    std::filesystem::remove(retired / "snapshot.enc");
    std::filesystem::remove(retired / "confirmed.enc");
    EXPECT_FALSE(sync::journal::load(paths, key));
    EXPECT_TRUE(std::filesystem::exists(retired / "transaction.log.enc"));
}

TEST_F(JournalCorrectionTest,
       PartialCleanupRetainsAuthenticatedIntentUntilDataSync) {
#ifdef _WIN32
    _putenv_s("KASUMI_TEST_JOURNAL_FAIL", "cleanup-data-sync");
#else
    setenv("KASUMI_TEST_JOURNAL_FAIL", "cleanup-data-sync", 1);
#endif
    auto cleared = sync::journal::clear(paths, key);
#ifdef _WIN32
    _putenv_s("KASUMI_TEST_JOURNAL_FAIL", "");
#else
    unsetenv("KASUMI_TEST_JOURNAL_FAIL");
#endif
    if (cleared)
        GTEST_SKIP() << "Fault injection requires dedicated build";
    const auto retired = paths.final_path.parent_path().parent_path() /
                         "transaction.bin.enc.cleared";
    EXPECT_TRUE(std::filesystem::exists(retired / "retired.enc"));
    EXPECT_FALSE(std::filesystem::exists(retired / "snapshot.enc"));
    auto loaded = sync::journal::load(paths, key);
    ASSERT_TRUE(loaded) << loaded.error();
    EXPECT_FALSE(*loaded);
    EXPECT_FALSE(std::filesystem::exists(retired));
}

TEST_F(JournalCorrectionTest, PendingCountIsBoundedBeforeAllocation) {
    record.phase = kasumi::transaction::Phase::FilesStaged;
    ASSERT_TRUE(sync::journal::save(paths, record, key));
    const std::array<std::byte, 9> payload{std::byte{0x10},
                                           std::byte{0},
                                           std::byte{0},
                                           std::byte{0},
                                           std::byte{0},
                                           std::byte{0x41},
                                           std::byte{0x42},
                                           std::byte{0x0f},
                                           std::byte{0}};
    replace_authenticated_delta(payload);
    auto loaded = sync::journal::load(paths, key);
    ASSERT_FALSE(loaded);
    EXPECT_NE(loaded.error().find("invalid pending_paths count"),
              std::string::npos);
}

} // namespace
