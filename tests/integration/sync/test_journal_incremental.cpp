#include "application/history_storage/publication.hpp"
#include "application/history_storage/remote_layout.hpp"
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
#include "platform/durability.hpp"
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

const auto marker_layout = [] {
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    return kasumi::application::history_storage::derive_remote_layout(key);
}();

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
TEST(JournalIncrementalCheckpointTest, GrowthAcrossFileScalesIsLinearNotQuadratic) {
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
TEST(JournalIncrementalCheckpointTest, SingleOperationCompletionCostIsO1) {
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
TEST(JournalIncrementalCheckpointTest,
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

        const auto initial_save = sync::journal::save(*paths, *record, key);
        EXPECT_TRUE(initial_save);
        if (!initial_save) return std::uint64_t{0};

        kasumi::platform::perf_trace::force_enable(true);
        kasumi::platform::perf_trace::reset();

        for (std::size_t b = 0; b < batch_count; ++b) {
            for (std::size_t i = 0; i < batch_size; ++i) {
                record->progress[b * batch_size + i].state =
                    kasumi::transaction::OperationState::Applied;
            }
            const auto checkpoint = sync::journal::save(*paths, *record, key);
            EXPECT_TRUE(checkpoint);
            if (!checkpoint) {
                kasumi::platform::perf_trace::force_enable(false);
                return std::uint64_t{0};
            }
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
TEST(JournalIncrementalCheckpointTest, IncrementalRecoveryStateReconstruction) {
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
        marker_layout,
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

// =============================================================================
// Journal checkpoint and replay performance tests
// =============================================================================

TEST(JournalSessionOptimizationTest, CoordinatorDownloadReplayCountBounded) {
    auto workspace = kasumi::test::make_temp_workspace("opt-33b-download-100");
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
    const std::string content(1024, 'x');
    const auto content_hash = kasumi::hasher::hash_string(content);
    const auto staged_file = staging / "source.bin";
    kasumi::test::write_text(staged_file, content);
    add_storage_object(*storage, staged_file, content_hash);

    constexpr std::size_t file_count = 100;
    input.storage.tree.rows.push_back(
        kasumi::NodeRow{.path = "", .is_directory = true});
    for (std::size_t i = 0; i < file_count; ++i) {
        input.storage.tree.rows.push_back(kasumi::NodeRow{
            .path = "file_" + std::to_string(i) + ".txt",
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

    auto runtime_data = make_runtime(profile, local, storage_dir);
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    const auto executed = kasumi::application::sync::coordinator::execute(
        runtime_data, *storage, key, input, *result);
    ASSERT_TRUE(executed.has_value()) << executed.error().detail;

    const auto replay_count =
        kasumi::platform::perf_trace::get_count("journal replay");
    const auto replay_time_us =
        kasumi::platform::perf_trace::get_time("journal replay");
    const auto durable_saves =
        kasumi::platform::perf_trace::get_count("journal durable saves");
    kasumi::platform::perf_trace::force_enable(false);

    std::cout << "[3.3B Group A] 100 downloads: " << durable_saves
              << " durable saves, " << replay_count << " replays, "
              << replay_time_us << " us replay time\n";

    // 3.3B Invariant: Zero redundant replays during normal execution.
    EXPECT_LE(replay_count, 2ULL);
}

TEST(JournalSessionOptimizationTest, SequentialCheckpointsReplayCountBounded) {
    auto owner = kasumi::test::make_temp_workspace("opt-33b-seq-checkpoints");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    ASSERT_TRUE(std::filesystem::create_directories(profile));

    constexpr std::size_t op_count = 100;
    std::vector<kasumi::Operation> operations;
    operations.reserve(op_count);
    const auto dummy_hash =
        kasumi::hash_hex(kasumi::hasher::hash_string("PAYLOAD"));
    for (std::size_t i = 0; i < op_count; ++i) {
        operations.push_back(kasumi::Operation{
            .action = kasumi::Action::Download,
            .path = "file_" + std::to_string(i) + ".dat",
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

    sync::journal::Session session;
    ASSERT_TRUE(sync::journal::save(
        *paths, *record, key, sync::journal::SaveMode::Advance, &session));
    ASSERT_TRUE(session.is_valid());

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    for (std::size_t i = 0; i < op_count; ++i) {
        record->progress[i].state =
            kasumi::transaction::OperationState::Applied;
        ASSERT_TRUE(sync::journal::save(
            *paths, *record, key, sync::journal::SaveMode::Advance, &session));
    }

    const auto replay_count =
        kasumi::platform::perf_trace::get_count("journal replay");
    const auto replay_time_us =
        kasumi::platform::perf_trace::get_time("journal replay");
    kasumi::platform::perf_trace::force_enable(false);

    std::cout << "[3.3B Group A Micro] 100 checkpoints: " << replay_count
              << " replays, " << replay_time_us << " us\n";

    EXPECT_EQ(replay_count, 0ULL);
}

TEST(JournalSessionOptimizationTest,
     SingleCheckpointLatencyIndependentOfHistory) {
    auto owner = kasumi::test::make_temp_workspace("opt-33b-latency-growth");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    ASSERT_TRUE(std::filesystem::create_directories(profile));

    constexpr std::size_t op_count = 200;
    std::vector<kasumi::Operation> operations;
    operations.reserve(op_count);
    const auto dummy_hash =
        kasumi::hash_hex(kasumi::hasher::hash_string("BENCH"));
    for (std::size_t i = 0; i < op_count; ++i) {
        operations.push_back(kasumi::Operation{
            .action = kasumi::Action::Download,
            .path = "file_" + std::to_string(i) + ".dat",
            .hash = dummy_hash,
            .size = 512,
        });
    }

    auto record = sync::journal::create_record(
        0, 0, kasumi::make_sync_plan(operations, 0));
    ASSERT_TRUE(record.has_value());

    const auto paths = sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    sync::journal::Session session;
    ASSERT_TRUE(sync::journal::save(
        *paths, *record, key, sync::journal::SaveMode::Advance, &session));

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    for (std::size_t i = 0; i < 10; ++i) {
        record->progress[i].state =
            kasumi::transaction::OperationState::Applied;
        ASSERT_TRUE(sync::journal::save(
            *paths, *record, key, sync::journal::SaveMode::Advance, &session));
    }
    const auto early_replays =
        kasumi::platform::perf_trace::get_count("journal replay");

    for (std::size_t i = 10; i < 190; ++i) {
        record->progress[i].state =
            kasumi::transaction::OperationState::Applied;
        ASSERT_TRUE(sync::journal::save(
            *paths, *record, key, sync::journal::SaveMode::Advance, &session));
    }

    kasumi::platform::perf_trace::reset();
    for (std::size_t i = 190; i < 200; ++i) {
        record->progress[i].state =
            kasumi::transaction::OperationState::Applied;
        ASSERT_TRUE(sync::journal::save(
            *paths, *record, key, sync::journal::SaveMode::Advance, &session));
    }
    const auto late_replays =
        kasumi::platform::perf_trace::get_count("journal replay");
    kasumi::platform::perf_trace::force_enable(false);

    EXPECT_EQ(early_replays, 0ULL);
    EXPECT_EQ(late_replays, 0ULL);
}

TEST(JournalSessionOptimizationTest, SessionLifecycleTransitions) {
    auto owner = kasumi::test::make_temp_workspace("opt-33b-lifecycle");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    ASSERT_TRUE(std::filesystem::create_directories(profile));

    std::vector<kasumi::Operation> operations{kasumi::Operation{
        .action = kasumi::Action::Download,
        .path = "doc.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("DATA")),
        .size = 100,
    }};
    auto record = sync::journal::create_record(
        0, 0, kasumi::make_sync_plan(operations, 0));
    ASSERT_TRUE(record.has_value());
    const auto paths = sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    sync::journal::Session session;
    EXPECT_EQ(session.status(), sync::journal::SessionState::Uninitialized);
    EXPECT_FALSE(session.is_valid());

    ASSERT_TRUE(sync::journal::save(
        *paths, *record, key, sync::journal::SaveMode::Advance, &session));
    EXPECT_EQ(session.status(), sync::journal::SessionState::Confirmed);
    EXPECT_TRUE(session.is_valid());
    EXPECT_EQ(session.operation(), record->operation_id);
    EXPECT_EQ(session.confirmed()->local_generation, 0ULL);
    EXPECT_EQ(session.confirmed()->storage_generation, 0ULL);

    record->progress[0].state = kasumi::transaction::OperationState::Applied;
    ASSERT_TRUE(sync::journal::save(
        *paths, *record, key, sync::journal::SaveMode::Advance, &session));
    EXPECT_EQ(session.status(), sync::journal::SessionState::Confirmed);
    EXPECT_TRUE(session.is_valid());

    record->phase = kasumi::transaction::Phase::Started;
    record->progress[0].state = kasumi::transaction::OperationState::Pending;
    record->progress[0].had_original = false;
    record->progress[0].previous_hash.clear();
    ASSERT_TRUE(sync::journal::save(
        *paths, *record, key, sync::journal::SaveMode::Rollback, &session));
    EXPECT_EQ(session.status(), sync::journal::SessionState::Confirmed);

    ASSERT_TRUE(sync::journal::clear(*paths, key, &session));
    EXPECT_EQ(session.status(), sync::journal::SessionState::Retired);
    EXPECT_FALSE(session.is_valid());
}

TEST(JournalSessionOptimizationTest, IdentityMismatchRejection) {
    auto owner =
        kasumi::test::make_temp_workspace("opt-33b-identity-rejection");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    ASSERT_TRUE(std::filesystem::create_directories(profile));

    std::vector<kasumi::Operation> ops{kasumi::Operation{
        .action = kasumi::Action::Download,
        .path = "test.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("1")),
        .size = 10,
    }};
    auto record =
        sync::journal::create_record(0, 0, kasumi::make_sync_plan(ops, 0));
    ASSERT_TRUE(record.has_value());
    const auto paths = sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    sync::journal::Session session;
    ASSERT_TRUE(sync::journal::save(
        *paths, *record, key, sync::journal::SaveMode::Advance, &session));
    ASSERT_TRUE(session.is_valid());

    auto tampered_record = *record;
    tampered_record.operation_id = std::string(32, 'f');

    auto saved = sync::journal::save(*paths,
                                     tampered_record,
                                     key,
                                     sync::journal::SaveMode::Advance,
                                     &session);
    EXPECT_FALSE(saved);
    EXPECT_EQ(session.status(), sync::journal::SessionState::Invalid);
    EXPECT_FALSE(session.is_valid());
}

TEST(JournalSessionOptimizationTest, DiskAuthorityDivergenceFallback) {
    auto owner = kasumi::test::make_temp_workspace("opt-33b-disk-divergence");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    ASSERT_TRUE(std::filesystem::create_directories(profile));

    std::vector<kasumi::Operation> ops{
        kasumi::Operation{
            .action = kasumi::Action::Download,
            .path = "a.txt",
            .hash = kasumi::hash_hex(kasumi::hasher::hash_string("1")),
            .size = 10},
        kasumi::Operation{
            .action = kasumi::Action::Download,
            .path = "b.txt",
            .hash = kasumi::hash_hex(kasumi::hasher::hash_string("2")),
            .size = 20},
    };
    auto record =
        sync::journal::create_record(0, 0, kasumi::make_sync_plan(ops, 0));
    ASSERT_TRUE(record.has_value());
    const auto paths = sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    sync::journal::Session session;
    ASSERT_TRUE(sync::journal::save(
        *paths, *record, key, sync::journal::SaveMode::Advance, &session));

    record->progress[0].state = kasumi::transaction::OperationState::Applied;
    ASSERT_TRUE(sync::journal::save(
        *paths, *record, key, sync::journal::SaveMode::Advance, &session));

    const auto tip_file = paths->final_path.parent_path() / "confirmed.enc";
    ASSERT_TRUE(std::filesystem::exists(tip_file));
    auto tip_bytes = kasumi::test::read_binary(tip_file);
    tip_bytes.back() ^= std::byte{0xff};
    kasumi::test::write_binary(tip_file, tip_bytes);

    record->progress[1].state = kasumi::transaction::OperationState::Applied;
    auto result = sync::journal::save(
        *paths, *record, key, sync::journal::SaveMode::Advance, &session);
    EXPECT_FALSE(result);
    EXPECT_EQ(session.status(), sync::journal::SessionState::Invalid);
}

TEST(JournalSessionOptimizationTest, IdempotentCheckpoints) {
    auto owner = kasumi::test::make_temp_workspace("opt-33b-idempotent");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    ASSERT_TRUE(std::filesystem::create_directories(profile));

    std::vector<kasumi::Operation> ops{kasumi::Operation{
        .action = kasumi::Action::Download,
        .path = "same.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("0")),
        .size = 1,
    }};
    auto record =
        sync::journal::create_record(0, 0, kasumi::make_sync_plan(ops, 0));
    ASSERT_TRUE(record.has_value());
    const auto paths = sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    sync::journal::Session session;
    ASSERT_TRUE(sync::journal::save(
        *paths, *record, key, sync::journal::SaveMode::Advance, &session));

    const auto tip_bytes_before = session.confirmed_bytes();
    const auto tip_count_before = session.confirmed_count();

    ASSERT_TRUE(sync::journal::save(
        *paths, *record, key, sync::journal::SaveMode::Advance, &session));
    EXPECT_TRUE(session.is_valid());
    EXPECT_EQ(session.confirmed_bytes(), tip_bytes_before);
    EXPECT_EQ(session.confirmed_count(), tip_count_before);
}

TEST(JournalSessionOptimizationTest, RollbackUpdatesSession) {
    auto owner = kasumi::test::make_temp_workspace("opt-33b-rollback");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    ASSERT_TRUE(std::filesystem::create_directories(profile));

    std::vector<kasumi::Operation> ops{kasumi::Operation{
        .action = kasumi::Action::Download,
        .path = "rb.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("aaaa")),
        .size = 50,
    }};
    auto record =
        sync::journal::create_record(0, 0, kasumi::make_sync_plan(ops, 0));
    ASSERT_TRUE(record.has_value());
    const auto paths = sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    sync::journal::Session session;
    ASSERT_TRUE(sync::journal::save(
        *paths, *record, key, sync::journal::SaveMode::Advance, &session));

    record->phase = kasumi::transaction::Phase::FilesStaged;
    ASSERT_TRUE(sync::journal::save(
        *paths, *record, key, sync::journal::SaveMode::Advance, &session));
    EXPECT_EQ(session.confirmed()->phase,
              kasumi::transaction::Phase::FilesStaged);

    record->phase = kasumi::transaction::Phase::Started;
    record->progress[0].state = kasumi::transaction::OperationState::Pending;
    record->progress[0].had_original = false;
    record->progress[0].previous_hash.clear();
    ASSERT_TRUE(sync::journal::save(
        *paths, *record, key, sync::journal::SaveMode::Rollback, &session));
    EXPECT_TRUE(session.is_valid());
    EXPECT_EQ(session.confirmed()->phase, kasumi::transaction::Phase::Started);
}

TEST(JournalSessionOptimizationTest, IndependentSessionsIsolation) {
    auto owner1 = kasumi::test::make_temp_workspace("opt-33b-iso-1");
    auto owner2 = kasumi::test::make_temp_workspace("opt-33b-iso-2");
    const auto profile1 = kasumi::test::workspace_path(owner1, "profile");
    const auto profile2 = kasumi::test::workspace_path(owner2, "profile");
    ASSERT_TRUE(std::filesystem::create_directories(profile1));
    ASSERT_TRUE(std::filesystem::create_directories(profile2));

    const auto paths1 = sync::journal::make_paths(profile1);
    const auto paths2 = sync::journal::make_paths(profile2);
    ASSERT_TRUE(paths1.has_value());
    ASSERT_TRUE(paths2.has_value());
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    std::vector<kasumi::Operation> ops1{kasumi::Operation{
        .action = kasumi::Action::Download,
        .path = "1.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("1")),
        .size = 10}};
    std::vector<kasumi::Operation> ops2{kasumi::Operation{
        .action = kasumi::Action::Download,
        .path = "2.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("2")),
        .size = 20}};

    auto rec1 =
        sync::journal::create_record(0, 0, kasumi::make_sync_plan(ops1, 0));
    auto rec2 =
        sync::journal::create_record(0, 0, kasumi::make_sync_plan(ops2, 0));
    ASSERT_TRUE(rec1.has_value());
    ASSERT_TRUE(rec2.has_value());

    sync::journal::Session session1;
    sync::journal::Session session2;

    ASSERT_TRUE(sync::journal::save(
        *paths1, *rec1, key, sync::journal::SaveMode::Advance, &session1));
    ASSERT_TRUE(sync::journal::save(
        *paths2, *rec2, key, sync::journal::SaveMode::Advance, &session2));

    EXPECT_NE(session1.operation(), session2.operation());

    rec1->progress[0].state = kasumi::transaction::OperationState::Applied;
    ASSERT_TRUE(sync::journal::save(
        *paths1, *rec1, key, sync::journal::SaveMode::Advance, &session1));

    EXPECT_EQ(session1.confirmed()->progress[0].state,
              kasumi::transaction::OperationState::Applied);
    EXPECT_EQ(session2.confirmed()->progress[0].state,
              kasumi::transaction::OperationState::Pending);
}

TEST(JournalSessionOptimizationTest, RetirementLifecycle) {
    auto owner = kasumi::test::make_temp_workspace("opt-33b-retire");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    ASSERT_TRUE(std::filesystem::create_directories(profile));

    std::vector<kasumi::Operation> ops{kasumi::Operation{
        .action = kasumi::Action::Download,
        .path = "r.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("r")),
        .size = 5}};
    auto record =
        sync::journal::create_record(0, 0, kasumi::make_sync_plan(ops, 0));
    ASSERT_TRUE(record.has_value());
    const auto paths = sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    sync::journal::Session session;
    ASSERT_TRUE(sync::journal::save(
        *paths, *record, key, sync::journal::SaveMode::Advance, &session));
    EXPECT_TRUE(session.is_valid());

    ASSERT_TRUE(sync::journal::clear(*paths, key, &session));
    EXPECT_EQ(session.status(), sync::journal::SessionState::Retired);
    EXPECT_FALSE(session.is_valid());

    auto save_after_retire = sync::journal::save(
        *paths, *record, key, sync::journal::SaveMode::Advance, &session);
    EXPECT_FALSE(save_after_retire);
}

TEST(JournalSessionOptimizationTest, NullSessionUsesPersistedAuthority) {
    auto owner = kasumi::test::make_temp_workspace("journal-null-session");
    const auto profile = kasumi::test::workspace_path(owner, "profile");
    ASSERT_TRUE(std::filesystem::create_directories(profile));

    std::vector<kasumi::Operation> ops{kasumi::Operation{
        .action = kasumi::Action::Download,
        .path = "c.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("c")),
        .size = 12}};
    auto record =
        sync::journal::create_record(0, 0, kasumi::make_sync_plan(ops, 0));
    ASSERT_TRUE(record.has_value());
    const auto paths = sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    ASSERT_TRUE(sync::journal::save(
        *paths, *record, key, sync::journal::SaveMode::Advance, nullptr));

    record->progress[0].state = kasumi::transaction::OperationState::Applied;
    ASSERT_TRUE(sync::journal::save(
        *paths, *record, key, sync::journal::SaveMode::Advance, nullptr));

    auto loaded = sync::journal::load(*paths, key, nullptr);
    ASSERT_TRUE(loaded.has_value());
    ASSERT_TRUE(loaded->has_value());
    EXPECT_EQ((*loaded)->progress[0].state,
              kasumi::transaction::OperationState::Applied);

    record->phase = kasumi::transaction::Phase::Started;
    record->progress[0].state = kasumi::transaction::OperationState::Pending;
    record->progress[0].had_original = false;
    record->progress[0].previous_hash.clear();
    ASSERT_TRUE(sync::journal::save(
        *paths, *record, key, sync::journal::SaveMode::Rollback, nullptr));

    ASSERT_TRUE(sync::journal::clear(*paths, key, nullptr));
}

class JournalSessionDurabilityTest : public JournalCorrectionTest {
protected:
    sync::journal::Session session;
    void activate() {
        auto loaded = sync::journal::load(paths, key, &session);
        ASSERT_TRUE(loaded);
        ASSERT_TRUE(session.is_valid());
        record.phase = kasumi::transaction::Phase::FilesStaged;
        ASSERT_TRUE(sync::journal::save(
            paths, record, key, sync::journal::SaveMode::Advance, &session));
    }
};

TEST_F(JournalSessionDurabilityTest,
       ActiveSessionRejectsOversizedProgressStringBeforeWriting) {
    activate();
    const auto confirmed = kasumi::test::read_binary(
        paths.final_path.parent_path() / "confirmed.enc");
    const auto log = kasumi::test::read_binary(paths.log_path);
    auto requested = record;
    requested.progress[0].previous_hash.assign(4097, 'a');
    ASSERT_FALSE(kasumi::transaction::codec::validate(requested));
    EXPECT_FALSE(sync::journal::save(
        paths, requested, key, sync::journal::SaveMode::Advance, &session));
    EXPECT_FALSE(session.is_valid());
    EXPECT_EQ(kasumi::test::read_binary(paths.final_path.parent_path() /
                                        "confirmed.enc"),
              confirmed);
    EXPECT_EQ(kasumi::test::read_binary(paths.log_path), log);
    expect_reload(record);
}

TEST_F(JournalSessionDurabilityTest, UnknownSaveModeInvalidatesActiveSession) {
    activate();
    EXPECT_FALSE(sync::journal::save(paths,
                                     record,
                                     key,
                                     static_cast<sync::journal::SaveMode>(255),
                                     &session));
    EXPECT_FALSE(session.is_valid());
    expect_reload(record);
}

TEST_F(JournalSessionDurabilityTest, TruncatedConfirmedLogCannotBeAppendedFromCache) {
    activate();
    const auto tip_path = paths.final_path.parent_path() / "confirmed.enc";
    const auto tip = kasumi::test::read_binary(tip_path);
    std::filesystem::resize_file(paths.log_path, 1);
    const auto log = kasumi::test::read_binary(paths.log_path);
    record.progress[0].state = kasumi::transaction::OperationState::Applied;
    EXPECT_FALSE(sync::journal::save(
        paths, record, key, sync::journal::SaveMode::Advance, &session));
    EXPECT_FALSE(session.is_valid());
    EXPECT_EQ(kasumi::test::read_binary(tip_path), tip);
    EXPECT_EQ(kasumi::test::read_binary(paths.log_path), log);
    EXPECT_FALSE(sync::journal::load(paths, key));
}

TEST_F(JournalSessionDurabilityTest,
       SnapshotReplacementWithUnchangedTipInvalidatesCache) {
    activate();
    const auto original = kasumi::test::read_binary(paths.final_path);
    const auto fingerprint =
        kasumi::platform::regular_file_fingerprint(paths.final_path);
    ASSERT_TRUE(fingerprint);
    const auto tip_path = paths.final_path.parent_path() / "confirmed.enc";
    const auto tip = kasumi::test::read_binary(tip_path);
    const auto log = kasumi::test::read_binary(paths.log_path);
    auto bytes = original;
    ASSERT_FALSE(bytes.empty());
    bytes.back() ^= std::byte{1};
    // A separate file guarantees replacement without relying on ChangeTime.
    const auto replacement =
        paths.final_path.parent_path() / "snapshot-replacement-test.tmp";
    kasumi::test::write_binary(replacement, bytes);
    ASSERT_FALSE(std::filesystem::equivalent(paths.final_path, replacement));
    const auto replacement_fingerprint =
        kasumi::platform::regular_file_fingerprint(replacement);
    ASSERT_TRUE(replacement_fingerprint);
    const auto identity = [](const kasumi::platform::FileFingerprint& value) {
        return std::array{value.value[0], value.value[1], value.value[2]};
    };
    ASSERT_EQ(fingerprint->has_value(), replacement_fingerprint->has_value());
    if (*fingerprint && *replacement_fingerprint) {
        ASSERT_EQ((**fingerprint).kind, (**replacement_fingerprint).kind);
        ASSERT_NE(identity(**fingerprint), identity(**replacement_fingerprint));
    }
    const auto replaced = kasumi::platform::durability::replace_atomically(
        replacement, paths.final_path);
    ASSERT_TRUE(replaced) << replaced.error();
    ASSERT_FALSE(std::filesystem::exists(replacement));
    ASSERT_EQ(std::filesystem::file_size(paths.final_path), original.size());
    ASSERT_EQ(kasumi::test::read_binary(paths.final_path), bytes);
    ASSERT_NE(bytes, original);
    const auto replaced_fingerprint =
        kasumi::platform::regular_file_fingerprint(paths.final_path);
    ASSERT_TRUE(replaced_fingerprint);
    ASSERT_EQ(fingerprint->has_value(), replaced_fingerprint->has_value());
    if (*fingerprint && *replacement_fingerprint && *replaced_fingerprint) {
        ASSERT_NE(identity(**fingerprint), identity(**replaced_fingerprint));
        ASSERT_EQ(identity(**replacement_fingerprint),
                  identity(**replaced_fingerprint));
    }
    ASSERT_EQ(kasumi::test::read_binary(tip_path), tip);
    ASSERT_EQ(kasumi::test::read_binary(paths.log_path), log);
    record.progress[0].state = kasumi::transaction::OperationState::Applied;
    EXPECT_FALSE(sync::journal::save(
        paths, record, key, sync::journal::SaveMode::Advance, &session));
    EXPECT_FALSE(session.is_valid());
    EXPECT_EQ(kasumi::test::read_binary(tip_path), tip);
    EXPECT_EQ(kasumi::test::read_binary(paths.log_path), log);
    EXPECT_EQ(kasumi::test::read_binary(paths.final_path), bytes);
    EXPECT_FALSE(sync::journal::load(paths, key));
}

TEST_F(JournalSessionDurabilityTest, RetirementArtifactBlocksActiveSession) {
    activate();
    kasumi::test::write_text(paths.final_path.parent_path() / "retired.enc",
                             "incomplete retirement");
    const auto tip_path = paths.final_path.parent_path() / "confirmed.enc";
    const auto tip = kasumi::test::read_binary(tip_path);
    record.progress[0].state = kasumi::transaction::OperationState::Applied;
    EXPECT_FALSE(sync::journal::save(
        paths, record, key, sync::journal::SaveMode::Advance, &session));
    EXPECT_FALSE(session.is_valid());
    EXPECT_EQ(kasumi::test::read_binary(tip_path), tip);
}

class JournalInputValidationTest : public JournalSessionDurabilityTest,
                            public ::testing::WithParamInterface<std::string> {
};

TEST_P(JournalInputValidationTest, ActiveAndColdRejectSameInvalidRequest) {
    activate();
    const auto name = GetParam();
    if (name == "ProgressRegression") {
        record.progress[0].state = kasumi::transaction::OperationState::Applied;
        ASSERT_TRUE(sync::journal::save(
            paths, record, key, sync::journal::SaveMode::Advance, &session));
    }
    auto requested = record;
    if (name == "ProgressTooShort")
        requested.progress.pop_back();
    else if (name == "ProgressTooLong")
        requested.progress.push_back(requested.progress.back());
    else if (name == "InvalidPhase")
        requested.phase = static_cast<kasumi::transaction::Phase>(255);
    else if (name == "InvalidProgress")
        requested.progress[0].state =
            static_cast<kasumi::transaction::OperationState>(255);
    else if (name == "InvalidSlot")
        requested.progress[0].backup_slot =
            std::numeric_limits<std::uint32_t>::max();
    else if (name == "InvalidIndexBounds")
        requested.plan.offsets.back() =
            std::numeric_limits<std::uint32_t>::max();
    else if (name == "OversizedProgressString")
        requested.progress[0].previous_hash.assign(4097, 'a');
    else if (name == "OversizedPath")
        requested.plan.operations[0].path = std::string(4097, 'a');
    else if (name == "ChangedPath")
        requested.plan.operations[0].path = "different";
    else if (name == "ChangedAction")
        requested.plan.operations[0].action = kasumi::Action::Upload;
    else if (name == "ChangedHash")
        requested.plan.operations[0].hash = "invalid-hash";
    else if (name == "ChangedSize")
        ++requested.plan.operations[0].size;
    else if (name == "ChangedAlternatePath")
        requested.plan.operations[0].alt_path = "other";
    else if (name == "ChangedExclusiveDestination")
        requested.plan.operations[0].exclusive_destination = true;
    else if (name == "ChangedOperationId")
        requested.operation_id.assign(32, 'f');
    else if (name == "ChangedGenerations") {
        requested.local_generation = 2;
        requested.storage_generation = 2;
        requested.plan.target_generation = 3;
    } else if (name == "ChangedTargetGeneration")
        ++requested.plan.target_generation;
    else if (name == "ChangedObservedBase")
        requested.observed_base_id.assign(64, 'a');
    else if (name == "ChangedObservedHead")
        requested.observed_head_id.assign(64, 'a');
    else if (name == "ChangedPublicationRequirement")
        requested.publication_required = false;
    else if (name == "RequiredCommitMissing")
        requested.phase = kasumi::transaction::Phase::CommitPrepared;
    else if (name == "PublicationMismatch" || name == "OversizedMarker") {
        requested.phase = kasumi::transaction::Phase::CommitUploaded;
        requested.commit_id.assign(64, 'a');
        requested.ciphertext_id.assign(64, 'b');
        requested.parent_ids = {std::string(64, 'c')};
        requested.marker_id = name == "OversizedMarker"
                                  ? std::string(4097, 'x') + "/" +
                                        requested.commit_id + "-" +
                                        requested.ciphertext_id
                                  : "wrong";
    } else if (name == "DuplicateParents") {
        requested.phase = kasumi::transaction::Phase::CommitPrepared;
        requested.commit_id.assign(64, 'a');
        requested.parent_ids = {std::string(64, 'b'), std::string(64, 'b')};
    } else if (name == "InvalidPendingPaths")
        requested.pending_paths = {"../escape"};
    else if (name == "UnsortedPendingPaths")
        requested.pending_paths = {"b", "a"};
    else if (name == "InvalidEpoch")
        requested.phase = kasumi::transaction::Phase::EpochPrepared;
    else if (name == "PhaseRegression")
        requested.phase = kasumi::transaction::Phase::Started;
    else if (name == "ProgressRegression")
        requested.progress[0].state =
            kasumi::transaction::OperationState::Pending;
    else
        FAIL() << "unknown input case";
    const auto snapshot = kasumi::test::read_binary(paths.final_path);
    const auto log = kasumi::test::read_binary(paths.log_path);
    const auto tip_path = paths.final_path.parent_path() / "confirmed.enc";
    const auto tip = kasumi::test::read_binary(tip_path);
    EXPECT_FALSE(sync::journal::save(
        paths, requested, key, sync::journal::SaveMode::Advance, &session));
    EXPECT_FALSE(session.is_valid());
    EXPECT_FALSE(sync::journal::save(paths, requested, key));
    EXPECT_EQ(kasumi::test::read_binary(paths.final_path), snapshot);
    EXPECT_EQ(kasumi::test::read_binary(paths.log_path), log);
    EXPECT_EQ(kasumi::test::read_binary(tip_path), tip);
    expect_reload(record);
}

INSTANTIATE_TEST_SUITE_P(Validation,
                         JournalInputValidationTest,
                         ::testing::Values("ProgressTooShort",
                                           "ProgressTooLong",
                                           "InvalidPhase",
                                           "InvalidProgress",
                                           "InvalidSlot",
                                           "InvalidIndexBounds",
                                           "OversizedProgressString",
                                           "OversizedPath",
                                           "ChangedPath",
                                           "ChangedAction",
                                           "ChangedHash",
                                           "ChangedSize",
                                           "ChangedAlternatePath",
                                           "ChangedExclusiveDestination",
                                           "ChangedOperationId",
                                           "ChangedGenerations",
                                           "ChangedTargetGeneration",
                                           "ChangedObservedBase",
                                           "ChangedObservedHead",
                                           "ChangedPublicationRequirement",
                                           "RequiredCommitMissing",
                                           "PublicationMismatch",
                                           "OversizedMarker",
                                           "DuplicateParents",
                                           "InvalidPendingPaths",
                                           "UnsortedPendingPaths",
                                           "InvalidEpoch",
                                           "PhaseRegression",
                                           "ProgressRegression"),
                         [](const auto& parameter_info) {
                             return parameter_info.param;
                         });

TEST_F(JournalSessionDurabilityTest, ActiveSessionCannotMoveToAnotherProfile) {
    activate();
    const auto another = profile.parent_path() / "other-profile";
    std::filesystem::create_directory(another);
    auto other = sync::journal::make_paths(another);
    ASSERT_TRUE(other);
    EXPECT_FALSE(sync::journal::save(
        *other, record, key, sync::journal::SaveMode::Advance, &session));
    EXPECT_FALSE(session.is_valid());
    EXPECT_FALSE(std::filesystem::exists(other->final_path.parent_path()));
    expect_reload(record);
}

TEST_F(JournalSessionDurabilityTest,
       ConfirmedCacheMovesOnlyChangedFieldsAndNoopPreservesState) {
    activate();
    const auto* plan = session.confirmed()->plan.operations.data();
    const auto* progress = session.confirmed()->progress.data();
    record.progress[1].state = kasumi::transaction::OperationState::Applied;
    ASSERT_TRUE(sync::journal::save(
        paths, record, key, sync::journal::SaveMode::Advance, &session));
    EXPECT_EQ(session.confirmed()->plan.operations.data(), plan);
    EXPECT_EQ(session.confirmed()->progress.data(), progress);
    EXPECT_EQ(kasumi::transaction::codec::encode(*session.confirmed()),
              kasumi::transaction::codec::encode(record));
    const auto count = session.confirmed_count();
    ASSERT_TRUE(sync::journal::save(
        paths, record, key, sync::journal::SaveMode::Advance, &session));
    EXPECT_EQ(session.confirmed_count(), count);
    expect_reload(record);
}

TEST_F(JournalSessionDurabilityTest,
       FailureAfterConfirmationInvalidatesCacheAndRetryDoesNotDuplicate) {
    activate();
    record.progress[0].state = kasumi::transaction::OperationState::Applied;
#ifdef _WIN32
    _putenv_s("KASUMI_TEST_JOURNAL_FAIL", "session-update");
#else
    setenv("KASUMI_TEST_JOURNAL_FAIL", "session-update", 1);
#endif
    auto saved = sync::journal::save(
        paths, record, key, sync::journal::SaveMode::Advance, &session);
#ifdef _WIN32
    _putenv_s("KASUMI_TEST_JOURNAL_FAIL", "");
#else
    unsetenv("KASUMI_TEST_JOURNAL_FAIL");
#endif
    if (saved)
        GTEST_SKIP() << "Requires dedicated fault build";
    EXPECT_FALSE(session.is_valid());
    expect_reload(record);
    const auto log = kasumi::test::read_binary(paths.log_path);
    const auto tip_path = paths.final_path.parent_path() / "confirmed.enc";
    const auto tip = kasumi::test::read_binary(tip_path);
    ASSERT_TRUE(sync::journal::save(
        paths, record, key, sync::journal::SaveMode::Advance, &session));
    EXPECT_EQ(kasumi::test::read_binary(paths.log_path), log);
    EXPECT_EQ(kasumi::test::read_binary(tip_path), tip);
    EXPECT_EQ(kasumi::transaction::codec::encode(*session.confirmed()),
              kasumi::transaction::codec::encode(record));
}

TEST_F(JournalSessionDurabilityTest,
       EveryActiveSessionDurabilityFailureRequiresAuthenticatedRetry) {
    for (const auto* failure : {"write",
                                "flush",
                                "close",
                                "sync",
                                "replace",
                                "parent-sync",
                                "rollback-truncate"}) {
        SCOPED_TRACE(failure);
        activate();
        auto requested = record;
        requested.progress[0].state =
            kasumi::transaction::OperationState::Applied;
        if (std::string_view{failure} == "rollback-truncate") {
            std::ofstream extra(paths.log_path,
                                std::ios::binary | std::ios::app);
            extra << "unconfirmed";
        }
#ifdef _WIN32
        _putenv_s("KASUMI_TEST_JOURNAL_FAIL", failure);
#else
        setenv("KASUMI_TEST_JOURNAL_FAIL", failure, 1);
#endif
        auto saved = sync::journal::save(
            paths, requested, key, sync::journal::SaveMode::Advance, &session);
#ifdef _WIN32
        _putenv_s("KASUMI_TEST_JOURNAL_FAIL", "");
#else
        unsetenv("KASUMI_TEST_JOURNAL_FAIL");
#endif
        if (saved)
            GTEST_SKIP() << "Requires dedicated fault build";
        EXPECT_FALSE(session.is_valid());
        auto loaded = sync::journal::load(paths, key);
        ASSERT_TRUE(loaded);
        ASSERT_TRUE(*loaded);
        EXPECT_TRUE(kasumi::transaction::codec::encode(**loaded) ==
                        kasumi::transaction::codec::encode(record) ||
                    kasumi::transaction::codec::encode(**loaded) ==
                        kasumi::transaction::codec::encode(requested));
        ASSERT_TRUE(sync::journal::save(
            paths, requested, key, sync::journal::SaveMode::Advance, &session));
        expect_reload(requested);
        record = requested;
        record.progress[0].state = kasumi::transaction::OperationState::Pending;
        record.progress[1].state = kasumi::transaction::OperationState::Pending;
        record.phase = kasumi::transaction::Phase::Started;
        ASSERT_TRUE(sync::journal::save(
            paths, record, key, sync::journal::SaveMode::Rollback, &session));
    }
}

TEST_F(JournalSessionDurabilityTest,
       SharedSessionRejectsConcurrentStaleRecordAndAcceptsMergedProgress) {
    activate();
    auto a = record;
    auto b = record;
    a.progress[0].state = kasumi::transaction::OperationState::Applied;
    b.progress[1].state = kasumi::transaction::OperationState::Applied;
    auto first = std::async(std::launch::async, [&] {
        return sync::journal::save(
            paths, a, key, sync::journal::SaveMode::Advance, &session);
    });
    auto second = std::async(std::launch::async, [&] {
        return sync::journal::save(
            paths, b, key, sync::journal::SaveMode::Advance, &session);
    });
    const bool first_ok = first.get().has_value();
    const bool second_ok = second.get().has_value();
    EXPECT_NE(first_ok, second_ok);
    record.progress[0].state = record.progress[1].state =
        kasumi::transaction::OperationState::Applied;
    ASSERT_TRUE(sync::journal::save(
        paths, record, key, sync::journal::SaveMode::Advance, &session));
    expect_reload(record);
}

TEST_F(JournalSessionDurabilityTest,
       RetiredSessionCannotBeResurrectedByLoadOrInvalidation) {
    activate();
    record.phase = kasumi::transaction::Phase::Started;
    ASSERT_TRUE(sync::journal::save(
        paths, record, key, sync::journal::SaveMode::Rollback, &session));
    ASSERT_TRUE(sync::journal::clear(paths, key, &session));
    session.invalidate();
    EXPECT_EQ(session.status(), sync::journal::SessionState::Retired);
    EXPECT_FALSE(sync::journal::load(paths, key, &session));
    EXPECT_FALSE(sync::journal::save(
        paths, record, key, sync::journal::SaveMode::Advance, &session));
}

TEST_F(JournalSessionDurabilityTest, OversizedDeltaIsRejectedBeforeConfirmation) {
    activate();
    auto requested = record;
    for (std::size_t i = 0; i < 18000; ++i) {
        auto prefix = std::to_string(i);
        prefix.insert(0, 6 - prefix.size(), '0');
        std::string path = prefix;
        for (int component = 0; component < 15; ++component)
            path += "/" + std::string(250, 'a');
        requested.pending_paths.push_back(std::move(path));
    }
    ASSERT_TRUE(kasumi::transaction::codec::validate(requested));
    const auto tip_path = paths.final_path.parent_path() / "confirmed.enc";
    const auto tip = kasumi::test::read_binary(tip_path);
    const auto log = kasumi::test::read_binary(paths.log_path);
    EXPECT_FALSE(sync::journal::save(
        paths, requested, key, sync::journal::SaveMode::Advance, &session));
    EXPECT_FALSE(session.is_valid());
    EXPECT_EQ(kasumi::test::read_binary(tip_path), tip);
    EXPECT_EQ(kasumi::test::read_binary(paths.log_path), log);
    expect_reload(record);
}

TEST_F(JournalSessionDurabilityTest,
       WrongKeyAndOtherJournalPathsInvalidateWithoutWriting) {
    activate();
    auto wrong = key;
    wrong[0] = 1;
    EXPECT_FALSE(sync::journal::save(
        paths, record, wrong, sync::journal::SaveMode::Advance, &session));
    EXPECT_FALSE(session.is_valid());
    expect_reload(record);
    for (int index = 0; index < 3; ++index) {
        activate();
        auto changed = paths;
        if (index == 0)
            changed.final_path = profile / "foreign";
        if (index == 1)
            changed.temporary_path = profile / "foreign";
        if (index == 2)
            changed.log_path = profile / "foreign";
        EXPECT_FALSE(sync::journal::save(
            changed, record, key, sync::journal::SaveMode::Advance, &session));
        EXPECT_FALSE(session.is_valid());
        expect_reload(record);
    }
}

TEST_F(JournalSessionDurabilityTest, RollbackWithSessionRoundTripsEveryMutableField) {
    auto loaded = sync::journal::load(paths, key, &session);
    ASSERT_TRUE(loaded);
    record.phase = kasumi::transaction::Phase::EpochPrepared;
    record.progress[0].state = record.progress[1].state =
        kasumi::transaction::OperationState::Applied;
    record.commit_id.assign(64, 'a');
    record.ciphertext_id.assign(64, 'b');
    record.parent_ids = {std::string(64, 'c')};
    record.marker_id = kasumi::application::history_storage::marker_identifier(
        marker_layout,
        {.commit_id = record.commit_id, .ciphertext_id = record.ciphertext_id});
    record.epoch_vault_id.assign(64, 'd');
    record.epoch_id.assign(64, 'e');
    record.epoch_issued_at = 1;
    record.epoch_min_history_depth = 1;
    record.epoch_min_history_age_hours = 1;
    record.observed_pending_paths = {"before"};
    record.pending_paths = {"after"};
    ASSERT_TRUE(sync::journal::save(
        paths, record, key, sync::journal::SaveMode::Advance, &session));
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
    record.observed_pending_paths.clear();
    record.pending_paths.clear();
    record.progress[0].state = record.progress[1].state =
        kasumi::transaction::OperationState::Pending;
    ASSERT_TRUE(sync::journal::save(
        paths, record, key, sync::journal::SaveMode::Rollback, &session));
    EXPECT_EQ(kasumi::transaction::codec::encode(*session.confirmed()),
              kasumi::transaction::codec::encode(record));
    expect_reload(record);
}

TEST_F(JournalSessionDurabilityTest, RequestedRecordCannotAliasOwnedConfirmedCache) {
    activate();
    const auto* aliased = session.confirmed();
    ASSERT_NE(aliased, nullptr);
    EXPECT_FALSE(sync::journal::save(
        paths, *aliased, key, sync::journal::SaveMode::Advance, &session));
    EXPECT_FALSE(session.is_valid());
    expect_reload(record);
}

} // namespace
