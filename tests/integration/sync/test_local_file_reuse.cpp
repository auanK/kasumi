#include "application/history_storage/publication.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/observation/scanner.hpp"
#include "application/sync/coordinator.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/mutation.hpp"
#include "application/sync/mutation_detail.hpp"
#include "application/sync/mutation_fault_test.hpp"
#include "application/sync/publication.hpp"
#include "application/use_cases/context.hpp"
#include "core/hasher.hpp"
#include "core/operation.hpp"
#include "core/reconciliation/plan.hpp"
#include "core/transaction/types.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/clock.hpp"
#include "platform/durability.hpp"
#include "platform/metadata.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "platform/workspace.hpp"
#include "runtime/resolver.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <array>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::application::detail {
std::expected<Response, Error> run_fsck(OperationContext& context);
std::expected<Response, Error> run_sync(OperationContext& context);
}

namespace {

struct ClientNode {
    std::filesystem::path root;
    std::filesystem::path profile;
    std::filesystem::path local;
    kasumi::runtime::RuntimeData runtime;
};

ClientNode make_client(const std::filesystem::path& base,
                       std::string_view name,
                       const std::filesystem::path& storage_path) {
    const auto root = base / name;
    const auto profile = root / "profile";
    const auto local = root / "local";
    std::filesystem::create_directories(profile);
    std::filesystem::create_directories(local);
    kasumi::runtime::RuntimeData runtime{
        .local_dir = local,
        .database_path = profile / "state.db",
        .key_path = profile / "key.bin",
        .storage_location = kasumi::platform::path::to_utf8(storage_path)};
    return ClientNode{
        .root = root, .profile = profile, .local = local, .runtime = runtime};
}

std::expected<kasumi::application::Response, kasumi::application::Error>
sync_client(ClientNode& client,
            const std::filesystem::path& storage_path,
            const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE>& key) {
    auto storage = kasumi::transport::open_transport(storage_path.string());
    if (!storage) {
        return std::unexpected(kasumi::application::Error{
            .code = kasumi::application::ErrorCode::SynchronizationFailure,
            .detail = "failed to open storage"});
    }
    if (!kasumi::transport::initialize(*storage)) {
        return std::unexpected(kasumi::application::Error{
            .code = kasumi::application::ErrorCode::SynchronizationFailure,
            .detail = "failed to initialize storage"});
    }
    kasumi::application::detail::OperationContext context{};
    context.operation = kasumi::application::Operation::Sync;
    context.runtime = client.runtime;
    context.summary = {
        .local_dir = client.local,
        .remote_dir = kasumi::platform::path::to_utf8(storage_path)};
    context.key = key;
    context.storage = std::move(*storage);
    return kasumi::application::detail::run_sync(context);
}

std::expected<kasumi::application::Response, kasumi::application::Error>
fsck_client(ClientNode& client,
            const std::filesystem::path& storage_path,
            const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE>& key) {
    auto storage = kasumi::transport::open_transport(storage_path.string());
    if (!storage) {
        return std::unexpected(kasumi::application::Error{
            .code = kasumi::application::ErrorCode::SynchronizationFailure,
            .detail = "failed to open storage"});
    }
    kasumi::application::detail::OperationContext context{};
    context.operation = kasumi::application::Operation::Fsck;
    context.runtime = client.runtime;
    context.summary = {
        .local_dir = client.local,
        .remote_dir = kasumi::platform::path::to_utf8(storage_path)};
    context.key = key;
    context.storage = std::move(*storage);
    return kasumi::application::detail::run_fsck(context);
}

// 8.1 Pure directory rename:
// Initial: Old/a.bin H1, Old/b.bin H2, Old/c.bin H3
// Target:  New/a.bin H1, New/b.bin H2, New/c.bin H3
// Expected: 3 file-level local moves, 0 Content GETs on B, Old absent, New present
TEST(LocalFileReuseTest, PureDirectoryRenamePerformsZeroContentGets) {
    auto workspace =
        kasumi::test::make_temp_workspace("pure-rename-zero-gets");
    const auto root = kasumi::test::workspace_root(workspace);
    const auto storage_path = root / "storage";
    std::filesystem::create_directories(storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    auto client_a = make_client(root, "client_a", storage_path);
    auto client_b = make_client(root, "client_b", storage_path);

    // Initial files on A:
    const auto old_dir_a = client_a.local / "Old";
    std::filesystem::create_directories(old_dir_a);
    kasumi::test::write_text(old_dir_a / "a.bin", "CONTENT_ALPHA_12345");
    kasumi::test::write_text(old_dir_a / "b.bin", "CONTENT_BETA_67890123");
    kasumi::test::write_text(old_dir_a / "c.bin", "CONTENT_GAMMA_456789012345");

    // A publishes initial tree:
    auto res_a1 = sync_client(client_a, storage_path, key);
    ASSERT_TRUE(res_a1.has_value()) << res_a1.error().detail;

    // B syncs initial tree:
    auto res_b1 = sync_client(client_b, storage_path, key);
    ASSERT_TRUE(res_b1.has_value()) << res_b1.error().detail;
    EXPECT_TRUE(std::filesystem::exists(client_b.local / "Old" / "a.bin"));
    EXPECT_TRUE(std::filesystem::exists(client_b.local / "Old" / "b.bin"));
    EXPECT_TRUE(std::filesystem::exists(client_b.local / "Old" / "c.bin"));

    // A renames Old -> New:
    std::filesystem::rename(client_a.local / "Old", client_a.local / "New");
    auto res_a2 = sync_client(client_a, storage_path, key);
    ASSERT_TRUE(res_a2.has_value()) << res_a2.error().detail;

    // B syncs rename: measure Content GETs!
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    auto res_b2 = sync_client(client_b, storage_path, key);
    ASSERT_TRUE(res_b2.has_value()) << res_b2.error().detail;

    // PRIMARY RED ASSERTION: 0 Content GETs expected!
    const auto gets =
        kasumi::platform::perf_trace::get_count("rc/get_content");
    EXPECT_EQ(gets, 0U) << "Physical Content GETs must be 0 for pure rename";

    // Correct final filesystem on B:
    EXPECT_FALSE(std::filesystem::exists(client_b.local / "Old"));
    EXPECT_TRUE(std::filesystem::exists(client_b.local / "New" / "a.bin"));
    EXPECT_TRUE(std::filesystem::exists(client_b.local / "New" / "b.bin"));
    EXPECT_TRUE(std::filesystem::exists(client_b.local / "New" / "c.bin"));
    EXPECT_EQ(kasumi::test::read_text(client_b.local / "New" / "a.bin"),
              "CONTENT_ALPHA_12345");
    EXPECT_EQ(kasumi::test::read_text(client_b.local / "New" / "b.bin"),
              "CONTENT_BETA_67890123");
    EXPECT_EQ(kasumi::test::read_text(client_b.local / "New" / "c.bin"),
              "CONTENT_GAMMA_456789012345");

    // Stable follow-up no-op:
    kasumi::platform::perf_trace::reset();
    auto res_b3 = sync_client(client_b, storage_path, key);
    ASSERT_TRUE(res_b3.has_value()) << res_b3.error().detail;
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("rc/get_content"), 0U);
}

// 8.2 Rename plus newly created files:
// Initial: Old/a.bin H1, Old/b.bin H2
// Target:  New/a.bin H1, New/b.bin H2, New/c.bin H3, New/d.bin H4
// Expected: 2 safe local moves, 2 Content GETs
TEST(LocalFileReuseTest, RenamePlusAdditionsDownloadsOnlyNewFiles) {
    auto workspace =
        kasumi::test::make_temp_workspace("rename-additions");
    const auto root = kasumi::test::workspace_root(workspace);
    const auto storage_path = root / "storage";
    std::filesystem::create_directories(storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    auto client_a = make_client(root, "client_a", storage_path);
    auto client_b = make_client(root, "client_b", storage_path);

    std::filesystem::create_directories(client_a.local / "Old");
    kasumi::test::write_text(client_a.local / "Old" / "a.bin", "ALPHA_UNIQUE_1");
    kasumi::test::write_text(client_a.local / "Old" / "b.bin", "BETA_UNIQUE_2");

    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());
    ASSERT_TRUE(sync_client(client_b, storage_path, key).has_value());

    // Rename Old -> New, and add c.bin and d.bin:
    std::filesystem::rename(client_a.local / "Old", client_a.local / "New");
    kasumi::test::write_text(client_a.local / "New" / "c.bin", "GAMMA_NEW_3");
    kasumi::test::write_text(client_a.local / "New" / "d.bin", "DELTA_NEW_4");

    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    auto res_b = sync_client(client_b, storage_path, key);
    ASSERT_TRUE(res_b.has_value()) << res_b.error().detail;

    // RED ASSERTION: exactly 2 Content GETs (for the 2 newly created files)
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("rc/get_content"), 2U);
    EXPECT_TRUE(std::filesystem::exists(client_b.local / "New" / "a.bin"));
    EXPECT_TRUE(std::filesystem::exists(client_b.local / "New" / "b.bin"));
    EXPECT_TRUE(std::filesystem::exists(client_b.local / "New" / "c.bin"));
    EXPECT_TRUE(std::filesystem::exists(client_b.local / "New" / "d.bin"));
}

// 8.3 Rename plus modified file:
// Initial: Old/a.bin H1, Old/b.bin H2
// Target:  New/a.bin H1, New/b.bin H3
// Expected: a.bin local move, b.bin authenticated Download (1 GET)
TEST(LocalFileReuseTest, RenamePlusModifiedFileDownloadsOnlyModifiedFile) {
    auto workspace =
        kasumi::test::make_temp_workspace("rename-modified");
    const auto root = kasumi::test::workspace_root(workspace);
    const auto storage_path = root / "storage";
    std::filesystem::create_directories(storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    auto client_a = make_client(root, "client_a", storage_path);
    auto client_b = make_client(root, "client_b", storage_path);

    std::filesystem::create_directories(client_a.local / "Old");
    kasumi::test::write_text(client_a.local / "Old" / "a.bin", "UNCHANGED_CONTENT");
    kasumi::test::write_text(client_a.local / "Old" / "b.bin", "ORIGINAL_B");

    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());
    ASSERT_TRUE(sync_client(client_b, storage_path, key).has_value());

    std::filesystem::rename(client_a.local / "Old", client_a.local / "New");
    kasumi::test::write_text(client_a.local / "New" / "b.bin", "MODIFIED_B_NEW_DATA");

    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    auto res_b = sync_client(client_b, storage_path, key);
    ASSERT_TRUE(res_b.has_value()) << res_b.error().detail;

    // RED ASSERTION: 1 Content GET (b.bin downloaded, a.bin moved locally)
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("rc/get_content"), 1U);
    EXPECT_EQ(kasumi::test::read_text(client_b.local / "New" / "a.bin"),
              "UNCHANGED_CONTENT");
    EXPECT_EQ(kasumi::test::read_text(client_b.local / "New" / "b.bin"),
              "MODIFIED_B_NEW_DATA");
}

// 8.5 Duplicate contents:
// Old/a.bin H1, Old/b.bin H1 -> New/x.bin H1, New/y.bin H1
// Expected: each path exists with correct content, source never double-consumed, 0 GETs
TEST(LocalFileReuseTest, DuplicateContentDeterministicSourceAllocation) {
    auto workspace =
        kasumi::test::make_temp_workspace("duplicate-content-reuse");
    const auto root = kasumi::test::workspace_root(workspace);
    const auto storage_path = root / "storage";
    std::filesystem::create_directories(storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    auto client_a = make_client(root, "client_a", storage_path);
    auto client_b = make_client(root, "client_b", storage_path);

    std::filesystem::create_directories(client_a.local / "Old");
    kasumi::test::write_text(client_a.local / "Old" / "a.bin", "IDENTICAL_BYTES_XYZ");
    kasumi::test::write_text(client_a.local / "Old" / "b.bin", "IDENTICAL_BYTES_XYZ");

    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());
    ASSERT_TRUE(sync_client(client_b, storage_path, key).has_value());

    std::filesystem::rename(client_a.local / "Old", client_a.local / "New");
    std::filesystem::rename(client_a.local / "New" / "a.bin", client_a.local / "New" / "x.bin");
    std::filesystem::rename(client_a.local / "New" / "b.bin", client_a.local / "New" / "y.bin");

    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    auto res_b = sync_client(client_b, storage_path, key);
    ASSERT_TRUE(res_b.has_value()) << res_b.error().detail;

    // RED ASSERTION: 0 Content GETs (both satisfied by native moves of the 2 duplicate sources)
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("rc/get_content"), 0U);
    EXPECT_EQ(kasumi::test::read_text(client_b.local / "New" / "x.bin"),
              "IDENTICAL_BYTES_XYZ");
    EXPECT_EQ(kasumi::test::read_text(client_b.local / "New" / "y.bin"),
              "IDENTICAL_BYTES_XYZ");
}

// 8.6 Local independent edit on B:
// B modifies Old/a.bin before sync.
// Expected: modified data is preserved, unauthorized deletion prevented.
TEST(LocalFileReuseTest, LocalIndependentEditPreservesUserModification) {
    auto workspace =
        kasumi::test::make_temp_workspace("independent-edit-preserve");
    const auto root = kasumi::test::workspace_root(workspace);
    const auto storage_path = root / "storage";
    std::filesystem::create_directories(storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    auto client_a = make_client(root, "client_a", storage_path);
    auto client_b = make_client(root, "client_b", storage_path);

    std::filesystem::create_directories(client_a.local / "Old");
    kasumi::test::write_text(client_a.local / "Old" / "a.bin", "ORIGINAL_VERSION");

    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());
    ASSERT_TRUE(sync_client(client_b, storage_path, key).has_value());

    // A renames Old -> New:
    std::filesystem::rename(client_a.local / "Old", client_a.local / "New");
    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());

    // User on B modifies Old/a.bin before sync:
    kasumi::test::write_text(client_b.local / "Old" / "a.bin", "USER_MODIFIED_WORK");

    auto res_b = sync_client(client_b, storage_path, key);
    ASSERT_TRUE(res_b.has_value()) << res_b.error().detail;

    // User's modified work must NOT be lost:
    bool user_work_found = false;
    for (const auto& entry :
         std::filesystem::recursive_directory_iterator(client_b.local)) {
        if (entry.is_regular_file() &&
            kasumi::test::read_text(entry.path()) == "USER_MODIFIED_WORK") {
            user_work_found = true;
            break;
        }
    }
    EXPECT_TRUE(user_work_found) << "Independent edit on B must be preserved";
    EXPECT_TRUE(std::filesystem::exists(client_b.local / "New" / "a.bin"));
    EXPECT_EQ(kasumi::test::read_text(client_b.local / "New" / "a.bin"),
              "ORIGINAL_VERSION");
}


// 8.8 Source modified after observation:
TEST(LocalFileReuseTest, SourceModifiedAfterObservationFailsSafely) {
    auto workspace =
        kasumi::test::make_temp_workspace("source-modified-safeguard");
    const auto root = kasumi::test::workspace_root(workspace);
    const auto storage_path = root / "storage";
    std::filesystem::create_directories(storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    auto client_a = make_client(root, "client_a", storage_path);
    auto client_b = make_client(root, "client_b", storage_path);

    std::filesystem::create_directories(client_a.local / "Old");
    kasumi::test::write_text(client_a.local / "Old" / "file.txt", "INITIAL_DATA");
    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());
    ASSERT_TRUE(sync_client(client_b, storage_path, key).has_value());

    std::filesystem::rename(client_a.local / "Old", client_a.local / "New");
    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());

    bool hook_hit = false;
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path& path) {
            if (point == "before_local_reuse_verify") {
                hook_hit = true;
                kasumi::test::write_text(path, "TAMPERED_EXTERNALLY");
            }
        });

    auto res_b = sync_client(client_b, storage_path, key);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    EXPECT_TRUE(hook_hit);
    EXPECT_FALSE(res_b.has_value());
    EXPECT_EQ(kasumi::test::read_text(client_b.local / "Old" / "file.txt"),
              "TAMPERED_EXTERNALLY");
}

// 8.7 Local source removed after observation:
TEST(LocalFileReuseTest, SourceRemovedAfterObservationFailsSafely) {
    auto workspace =
        kasumi::test::make_temp_workspace("source-removed-safeguard");
    const auto root = kasumi::test::workspace_root(workspace);
    const auto storage_path = root / "storage";
    std::filesystem::create_directories(storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    auto client_a = make_client(root, "client_a", storage_path);
    auto client_b = make_client(root, "client_b", storage_path);

    std::filesystem::create_directories(client_a.local / "Old");
    kasumi::test::write_text(client_a.local / "Old" / "file.txt", "INITIAL_DATA");
    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());
    ASSERT_TRUE(sync_client(client_b, storage_path, key).has_value());

    std::filesystem::rename(client_a.local / "Old", client_a.local / "New");
    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());

    bool hook_hit = false;
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path& path) {
            if (point == "before_local_reuse_move") {
                hook_hit = true;
                std::filesystem::remove(path);
            }
        });

    auto res_b = sync_client(client_b, storage_path, key);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    EXPECT_TRUE(hook_hit);
    EXPECT_FALSE(res_b.has_value());
}

// 8.9 Destination collision prevents overwrite:
TEST(LocalFileReuseTest, DestinationConflictPreventsOverwrite) {
    auto workspace =
        kasumi::test::make_temp_workspace("dest-conflict-safeguard");
    const auto root = kasumi::test::workspace_root(workspace);
    const auto storage_path = root / "storage";
    std::filesystem::create_directories(storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    auto client_a = make_client(root, "client_a", storage_path);
    auto client_b = make_client(root, "client_b", storage_path);

    std::filesystem::create_directories(client_a.local / "Old");
    kasumi::test::write_text(client_a.local / "Old" / "file.txt", "INITIAL_DATA");
    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());
    ASSERT_TRUE(sync_client(client_b, storage_path, key).has_value());

    std::filesystem::rename(client_a.local / "Old", client_a.local / "New");
    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());

    bool hook_hit = false;
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path& /*path*/) {
            if (point == "before_local_reuse_move") {
                hook_hit = true;
                std::filesystem::create_directories(client_b.local / "New");
                kasumi::test::write_text(client_b.local / "New" / "file.txt", "COLLIDING_DESTINATION");
            }
        });

    auto res_b = sync_client(client_b, storage_path, key);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    EXPECT_TRUE(hook_hit);
    EXPECT_FALSE(res_b.has_value());
    EXPECT_EQ(kasumi::test::read_text(client_b.local / "New" / "file.txt"),
              "COLLIDING_DESTINATION");
}

// 8.10 Occupied download destination uses normal replacement instead of local reuse:
TEST(LocalFileReuseTest, OccupiedDownloadDestinationUsesNormalReplacement) {
    auto workspace =
        kasumi::test::make_temp_workspace("occupied-dest-replacement");
    const auto root = kasumi::test::workspace_root(workspace);
    const auto storage_path = root / "storage";
    std::filesystem::create_directories(storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    auto client_a = make_client(root, "client_a", storage_path);
    auto client_b = make_client(root, "client_b", storage_path);

    std::filesystem::create_directories(client_a.local / "Old");
    std::filesystem::create_directories(client_a.local / "Target");
    kasumi::test::write_text(client_a.local / "Old" / "a.bin", "PAYLOAD_H1_REPLACEMENT");
    kasumi::test::write_text(client_a.local / "Target" / "file.bin", "PAYLOAD_H2_INITIAL_TARGET");

    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());
    ASSERT_TRUE(sync_client(client_b, storage_path, key).has_value());
    ASSERT_TRUE(std::filesystem::exists(client_b.local / "Old" / "a.bin"));
    ASSERT_TRUE(std::filesystem::exists(client_b.local / "Target" / "file.bin"));

    // Client A deletes Old/a.bin and updates Target/file.bin to have H1:
    std::filesystem::remove_all(client_a.local / "Old");
    kasumi::test::write_text(client_a.local / "Target" / "file.bin", "PAYLOAD_H1_REPLACEMENT");
    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());

    // Client B syncs: Target/file.bin is occupied locally, so it must use normal
    // download replacement rather than failing with a local reuse conflict.
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();
    auto res_b = sync_client(client_b, storage_path, key);
    ASSERT_TRUE(res_b.has_value()) << res_b.error().detail;

    EXPECT_FALSE(std::filesystem::exists(client_b.local / "Old" / "a.bin"));
    ASSERT_TRUE(std::filesystem::exists(client_b.local / "Target" / "file.bin"));
    EXPECT_EQ(kasumi::test::read_text(client_b.local / "Target" / "file.bin"),
              "PAYLOAD_H1_REPLACEMENT");
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("local reuse moves applied"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("rc/get_content"), 1U);

    auto audited = fsck_client(client_b, storage_path, key);
    ASSERT_TRUE(audited.has_value()) << audited.error().detail;
}

// 8.11 Multi-file duplicate content with occupied and vacant destinations:
TEST(LocalFileReuseTest, DuplicateContentWithOccupiedAndVacantDestinations) {
    auto workspace =
        kasumi::test::make_temp_workspace("duplicate-occupied-and-vacant");
    const auto root = kasumi::test::workspace_root(workspace);
    const auto storage_path = root / "storage";
    std::filesystem::create_directories(storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    auto client_a = make_client(root, "client_a", storage_path);
    auto client_b = make_client(root, "client_b", storage_path);

    std::filesystem::create_directories(client_a.local / "Old");
    std::filesystem::create_directories(client_a.local / "Occupied");
    kasumi::test::write_text(client_a.local / "Old" / "s1.bin", "SHARED_DUP_HASH_H1");
    kasumi::test::write_text(client_a.local / "Old" / "s2.bin", "SHARED_DUP_HASH_H1");
    kasumi::test::write_text(client_a.local / "Occupied" / "dest.bin", "PRIOR_OCCUPIED_H2");

    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());
    ASSERT_TRUE(sync_client(client_b, storage_path, key).has_value());

    // Client A removes Old/{s1,s2}.bin, creates Vacant/dest.bin with H1,
    // and updates Occupied/dest.bin to H1:
    std::filesystem::remove_all(client_a.local / "Old");
    std::filesystem::create_directories(client_a.local / "Vacant");
    kasumi::test::write_text(client_a.local / "Vacant" / "dest.bin", "SHARED_DUP_HASH_H1");
    kasumi::test::write_text(client_a.local / "Occupied" / "dest.bin", "SHARED_DUP_HASH_H1");
    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();
    auto res_b = sync_client(client_b, storage_path, key);
    ASSERT_TRUE(res_b.has_value()) << res_b.error().detail;

    // Vacant/dest.bin reuses one local source (1 local move), while Occupied/dest.bin
    // uses normal download replacement (1 Content GET).
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("local reuse moves applied"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("rc/get_content"), 1U);
    EXPECT_FALSE(std::filesystem::exists(client_b.local / "Old" / "s1.bin"));
    EXPECT_FALSE(std::filesystem::exists(client_b.local / "Old" / "s2.bin"));
    EXPECT_EQ(kasumi::test::read_text(client_b.local / "Vacant" / "dest.bin"),
              "SHARED_DUP_HASH_H1");
    EXPECT_EQ(kasumi::test::read_text(client_b.local / "Occupied" / "dest.bin"),
              "SHARED_DUP_HASH_H1");

    auto audited = fsck_client(client_b, storage_path, key);
    ASSERT_TRUE(audited.has_value()) << audited.error().detail;
}

// 8.12 Rollback after first reuse move when second operation fails:
TEST(LocalFileReuseTest,
     MultiFileRollbackAfterFirstMoveRestoresSourceAndRemovesMovedDestination) {
    auto workspace =
        kasumi::test::make_temp_workspace("multi-file-rollback-after-move");
    const auto root = kasumi::test::workspace_root(workspace);
    const auto storage_path = root / "storage";
    std::filesystem::create_directories(storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    auto client_a = make_client(root, "client_a", storage_path);
    auto client_b = make_client(root, "client_b", storage_path);

    std::filesystem::create_directories(client_a.local / "Old");
    kasumi::test::write_text(client_a.local / "Old" / "a.bin", "FIRST_MOVED_PAYLOAD");
    kasumi::test::write_text(client_a.local / "Old" / "b.bin", "SECOND_FAILING_PAYLOAD");
    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());
    ASSERT_TRUE(sync_client(client_b, storage_path, key).has_value());

    std::filesystem::rename(client_a.local / "Old", client_a.local / "New");
    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());

    // After Old/a.bin is moved to New/a.bin, cause Old/b.bin to fail before move
    // by removing Old/b.bin right at before_local_reuse_move for b.bin:
    bool first_moved = false;
    bool second_faulted = false;
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path& path) {
            if (point == "after_local_reuse_move" &&
                path.filename() == "a.bin") {
                first_moved = std::filesystem::exists(client_b.local / "New" / "a.bin") &&
                              !std::filesystem::exists(client_b.local / "Old" / "a.bin");
            }
            if (point == "before_local_reuse_move" &&
                path.filename() == "b.bin") {
                second_faulted = true;
                std::filesystem::remove(path);
            }
        });

    auto res_b = sync_client(client_b, storage_path, key);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    EXPECT_TRUE(first_moved);
    EXPECT_TRUE(second_faulted);
    EXPECT_FALSE(res_b.has_value());

    // Rollback must have restored Old/a.bin and Old/b.bin from backup and removed New/a.bin!
    EXPECT_TRUE(std::filesystem::exists(client_b.local / "Old" / "a.bin"));
    EXPECT_EQ(kasumi::test::read_text(client_b.local / "Old" / "a.bin"),
              "FIRST_MOVED_PAYLOAD");
    EXPECT_TRUE(std::filesystem::exists(client_b.local / "Old" / "b.bin"));
    EXPECT_EQ(kasumi::test::read_text(client_b.local / "Old" / "b.bin"),
              "SECOND_FAILING_PAYLOAD");
    EXPECT_FALSE(std::filesystem::exists(client_b.local / "New" / "a.bin"));
    EXPECT_FALSE(std::filesystem::exists(client_b.local / "New" / "b.bin"));

    // Repeated recover_if_needed() calls must be idempotent no-ops:
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::application::sync::coordinator::recover_if_needed(
                    client_b.runtime, *storage, key)
                    .has_value());
    ASSERT_TRUE(kasumi::application::sync::coordinator::recover_if_needed(
                    client_b.runtime, *storage, key)
                    .has_value());

    // Subsequent clean sync succeeds with 0 Content GETs:
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();
    auto res_b_retry = sync_client(client_b, storage_path, key);
    ASSERT_TRUE(res_b_retry.has_value()) << res_b_retry.error().detail;
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("rc/get_content"), 0U);
    EXPECT_TRUE(std::filesystem::exists(client_b.local / "New" / "a.bin"));
    EXPECT_TRUE(std::filesystem::exists(client_b.local / "New" / "b.bin"));
    EXPECT_FALSE(std::filesystem::exists(client_b.local / "Old"));
}

// 8.13 Corrupt or missing source backup before move fails closed without moving source:
TEST(LocalFileReuseTest, CorruptOrMissingSourceBackupBeforeMoveFailsClosed) {
    auto workspace =
        kasumi::test::make_temp_workspace("corrupt-backup-before-move");
    const auto root = kasumi::test::workspace_root(workspace);
    const auto storage_path = root / "storage";
    std::filesystem::create_directories(storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    auto client_a = make_client(root, "client_a", storage_path);
    auto client_b = make_client(root, "client_b", storage_path);

    std::filesystem::create_directories(client_a.local / "Old");
    kasumi::test::write_text(client_a.local / "Old" / "a.bin", "PROTECTED_BY_BACKUP");
    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());
    ASSERT_TRUE(sync_client(client_b, storage_path, key).has_value());

    std::filesystem::rename(client_a.local / "Old", client_a.local / "New");
    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());

    bool corrupted_backup = false;
    bool move_attempted = false;
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path& /*path*/) {
            if (point == "before_local_reuse_verify") {
                for (const auto& entry :
                     std::filesystem::recursive_directory_iterator(
                         client_b.profile / ".transactions")) {
                    if (entry.is_regular_file() &&
                        entry.path().extension() == ".backup") {
                        kasumi::test::write_text(entry.path(),
                                                 "CORRUPTED_BACKUP_BYTES");
                        corrupted_backup = true;
                    }
                }
            }
            if (point == "before_local_reuse_move") {
                move_attempted = true;
            }
        });

    auto res_b = sync_client(client_b, storage_path, key);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    // Must fail closed BEFORE moving Old/a.bin:
    EXPECT_TRUE(corrupted_backup);
    EXPECT_FALSE(res_b.has_value());
    EXPECT_FALSE(move_attempted);
    EXPECT_TRUE(std::filesystem::exists(client_b.local / "Old" / "a.bin"));
    EXPECT_EQ(kasumi::test::read_text(client_b.local / "Old" / "a.bin"),
              "PROTECTED_BY_BACKUP");
    EXPECT_FALSE(std::filesystem::exists(client_b.local / "New" / "a.bin"));
}

// 8.14 Corrupt source backup during rollback fails closed and preserves moved file:
TEST(LocalFileReuseTest, CorruptSourceBackupDuringRollbackFailsClosed) {
    auto workspace =
        kasumi::test::make_temp_workspace("corrupt-backup-during-rollback");
    const auto root = kasumi::test::workspace_root(workspace);
    const auto storage_path = root / "storage";
    std::filesystem::create_directories(storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    auto client_a = make_client(root, "client_a", storage_path);
    auto client_b = make_client(root, "client_b", storage_path);

    std::filesystem::create_directories(client_a.local / "Old");
    kasumi::test::write_text(client_a.local / "Old" / "a.bin", "ORIGINAL_FOR_ROLLBACK");
    kasumi::test::write_text(client_a.local / "Old" / "b.bin", "SECOND_FILE_TRIGGERS_ROLLBACK");
    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());
    ASSERT_TRUE(sync_client(client_b, storage_path, key).has_value());

    std::filesystem::rename(client_a.local / "Old", client_a.local / "New");
    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());

    bool corrupted_after_move = false;
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path& path) {
            if (point == "after_local_reuse_move" &&
                path.filename() == "a.bin") {
                for (const auto& entry :
                     std::filesystem::recursive_directory_iterator(
                         client_b.profile / ".transactions")) {
                    if (entry.is_regular_file() &&
                        entry.path().extension() == ".backup" &&
                        kasumi::test::read_text(entry.path()) ==
                            "ORIGINAL_FOR_ROLLBACK") {
                        kasumi::test::write_text(entry.path(),
                                                 "CORRUPTED_AFTER_MOVE");
                        corrupted_after_move = true;
                    }
                }
            }
            if (point == "before_local_reuse_move" &&
                path.filename() == "b.bin") {
                std::filesystem::remove(path);
            }
        });

    auto res_b = sync_client(client_b, storage_path, key);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    // Rollback must fail closed and NOT delete New/a.bin when Old/a.bin could not be restored:
    EXPECT_TRUE(corrupted_after_move);
    EXPECT_FALSE(res_b.has_value());
    EXPECT_TRUE(std::filesystem::exists(client_b.local / "New" / "a.bin"));
    EXPECT_EQ(kasumi::test::read_text(client_b.local / "New" / "a.bin"),
              "ORIGINAL_FOR_ROLLBACK");
}

// 8.15 External modification at destination or recreated source during rollback is preserved:
TEST(LocalFileReuseTest,
     ExternalModificationAtDestinationOrSourceDuringRollbackPreservesUserData) {
    auto workspace =
        kasumi::test::make_temp_workspace("external-mod-during-rollback");
    const auto root = kasumi::test::workspace_root(workspace);
    const auto storage_path = root / "storage";
    std::filesystem::create_directories(storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    auto client_a = make_client(root, "client_a", storage_path);
    auto client_b = make_client(root, "client_b", storage_path);

    std::filesystem::create_directories(client_a.local / "Old");
    kasumi::test::write_text(client_a.local / "Old" / "a.bin", "MOVED_CONTENT_V1");
    kasumi::test::write_text(client_a.local / "Old" / "b.bin", "SECOND_CONTENT_V1");
    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());
    ASSERT_TRUE(sync_client(client_b, storage_path, key).has_value());

    std::filesystem::rename(client_a.local / "Old", client_a.local / "New");
    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());

    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path& path) {
            if (point == "after_local_reuse_move" &&
                path.filename() == "a.bin") {
                kasumi::test::write_text(client_b.local / "New" / "a.bin",
                                         "USER_EDITED_AT_NEW_PATH");
            }
            if (point == "before_local_reuse_move" &&
                path.filename() == "b.bin") {
                std::filesystem::remove(path);
            }
        });

    auto res_b = sync_client(client_b, storage_path, key);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    EXPECT_FALSE(res_b.has_value());
    // Both the user edit at New/a.bin AND the restored Old/a.bin are preserved:
    EXPECT_EQ(kasumi::test::read_text(client_b.local / "New" / "a.bin"),
              "USER_EDITED_AT_NEW_PATH");
    EXPECT_EQ(kasumi::test::read_text(client_b.local / "Old" / "a.bin"),
              "MOVED_CONTENT_V1");
}

// 8.16 Malformed plan defense: unpaired or duplicate local-reuse alt_path fails closed:
TEST(LocalFileReuseTest, MalformedPlanWithUnpairedOrDuplicateLocalReuseFailsClosed) {
    auto workspace =
        kasumi::test::make_temp_workspace("malformed-local-reuse-plan");
    const auto root = kasumi::test::workspace_root(workspace);
    const auto storage_path = root / "storage";
    std::filesystem::create_directories(storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage).has_value());

    const auto hash = kasumi::hash_hex(kasumi::hasher::hash_string("UNPAIRED_SOURCE_DATA"));
    const auto other_hash = kasumi::hash_hex(kasumi::hasher::hash_string("DIFFERENT_SOURCE_DATA"));

    // Case 1: Download with alt_path and NO matching DeleteLocal in the plan.
    {
        auto client = make_client(root, "case1_unpaired", storage_path);
        std::filesystem::create_directories(client.local / "Old");
        std::filesystem::create_directories(client.local / "New");
        kasumi::test::write_text(client.local / "Old" / "a.bin", "UNPAIRED_SOURCE_DATA");

        const kasumi::platform::Workspace tx_workspace{client.profile / "tx1"};
        std::filesystem::create_directories(tx_workspace.root);

        kasumi::transaction::Record record{};
        record.operation_id = "0123456789abcdef0123456789abcdef";
        record.phase = kasumi::transaction::Phase::FilesStaged;
        record.plan.operations = {
            kasumi::Operation{.action = kasumi::Action::Download,
                              .path = "New/a.bin",
                              .hash = hash,
                              .alt_path = "Old/a.bin",
                              .size = 20,
                              .exclusive_destination = false},
        };
        record.plan.offsets.fill(1);
        record.plan.offsets[0] = 0;
        record.plan.offsets[1] = 0;

        EXPECT_FALSE(kasumi::reconciliation::has_safe_paths(record.plan))
            << "has_safe_paths must reject Download with unpaired alt_path";

        auto deps = kasumi::application::sync::mutation::detail::destination_dependencies(
            record.plan.operations);
        EXPECT_TRUE(deps.empty())
            << "destination_dependencies must reject Download with unpaired alt_path";

        auto prepared = kasumi::application::sync::mutation::prepare_operation(
            record.plan.operations[0],
            0,
            client.local,
            tx_workspace,
            {.backup_slot = 0},
            record.plan.operations);
        ASSERT_TRUE(prepared.has_value());
        auto applied = kasumi::application::sync::mutation::apply_operation(
            record.plan.operations[0], 0, client.local, *storage, key, tx_workspace, *prepared);
        EXPECT_FALSE(applied.has_value())
            << "apply_operation must reject local-reuse Download without verified source backup precondition";
        EXPECT_TRUE(std::filesystem::exists(client.local / "Old" / "a.bin"));
        EXPECT_FALSE(std::filesystem::exists(client.local / "New" / "a.bin"));
    }

    // Case 2: Two Downloads claiming the same single DeleteLocal alt_path.
    {
        kasumi::SyncPlan plan{};
        plan.operations = {
            kasumi::Operation{.action = kasumi::Action::Download,
                              .path = "New1/a.bin",
                              .hash = hash,
                              .alt_path = "Old/a.bin",
                              .size = 20,
                              .exclusive_destination = false},
            kasumi::Operation{.action = kasumi::Action::Download,
                              .path = "New2/a.bin",
                              .hash = hash,
                              .alt_path = "Old/a.bin",
                              .size = 20,
                              .exclusive_destination = false},
            kasumi::Operation{.action = kasumi::Action::DeleteLocal,
                              .path = "Old/a.bin"},
        };
        EXPECT_FALSE(kasumi::reconciliation::has_safe_paths(plan))
            << "has_safe_paths must reject duplicate local-reuse alt_path consumers";
        auto deps = kasumi::application::sync::mutation::detail::destination_dependencies(
            plan.operations);
        EXPECT_TRUE(deps.empty())
            << "destination_dependencies must reject duplicate local-reuse consumers of a single DeleteLocal";
    }

    // Case 3: Self-referencing alt_path == path.
    {
        kasumi::SyncPlan plan{};
        plan.operations = {
            kasumi::Operation{.action = kasumi::Action::Download,
                              .path = "Old/a.bin",
                              .hash = hash,
                              .alt_path = "Old/a.bin",
                              .size = 20,
                              .exclusive_destination = false},
            kasumi::Operation{.action = kasumi::Action::DeleteLocal,
                              .path = "Old/a.bin"},
        };
        EXPECT_FALSE(kasumi::reconciliation::has_safe_paths(plan))
            << "has_safe_paths must reject self-referencing alt_path == path";
        auto deps = kasumi::application::sync::mutation::detail::destination_dependencies(
            plan.operations);
        EXPECT_TRUE(deps.empty())
            << "destination_dependencies must reject self-referencing alt_path == path";
    }

    // Case 4: Paired DeleteLocal backup hash mismatches Download hash.
    {
        kasumi::transaction::Record record{};
        record.operation_id = "fedcba9876543210fedcba9876543210";
        record.phase = kasumi::transaction::Phase::FilesStaged;
        record.plan.operations = {
            kasumi::Operation{.action = kasumi::Action::Download,
                              .path = "New/a.bin",
                              .hash = hash,
                              .alt_path = "Old/a.bin",
                              .size = 20,
                              .exclusive_destination = false},
            kasumi::Operation{.action = kasumi::Action::DeleteLocal,
                              .path = "Old/a.bin"},
        };
        record.progress = {
            kasumi::transaction::OperationProgress{
                .previous_hash = {},
                .backup_slot = 0,
                .state = kasumi::transaction::OperationState::BackupCreated,
                .had_original = false},
            kasumi::transaction::OperationProgress{
                .previous_hash = other_hash,
                .backup_slot = 1,
                .state = kasumi::transaction::OperationState::BackupCreated,
                .had_original = true},
        };
        auto deps = kasumi::application::sync::mutation::detail::destination_dependencies(
            record.plan.operations);
        ASSERT_FALSE(deps.empty());
        auto eff_dl = kasumi::application::sync::mutation::detail::effective_destination(
            record, 0, deps);
        EXPECT_FALSE(eff_dl.has_value())
            << "effective_destination on Download must reject mismatched DeleteLocal previous_hash";
        auto eff_del = kasumi::application::sync::mutation::detail::effective_destination(
            record, 1, deps);
        EXPECT_FALSE(eff_del.has_value())
            << "effective_destination on DeleteLocal must reject mismatched DeleteLocal previous_hash";
    }
}

// 8.17 Fast-path normal Sync (no-op, upload-only, download-only, delete-only):
TEST(LocalFileReuseTest, NormalSyncFastPathPerformsZeroLocalReuseMoves) {
    auto workspace =
        kasumi::test::make_temp_workspace("normal-sync-fast-path");
    const auto root = kasumi::test::workspace_root(workspace);
    const auto storage_path = root / "storage";
    std::filesystem::create_directories(storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    auto client_a = make_client(root, "client_a", storage_path);
    auto client_b = make_client(root, "client_b", storage_path);

    // 1. Upload-only on A:
    std::filesystem::create_directories(client_a.local / "Docs");
    kasumi::test::write_text(client_a.local / "Docs" / "one.txt", "DOC_ONE");
    kasumi::test::write_text(client_a.local / "Docs" / "two.txt", "DOC_TWO");

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();
    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("local reuse candidates matched"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("local reuse moves applied"), 0U);

    // 2. Download-only on B:
    kasumi::platform::perf_trace::reset();
    ASSERT_TRUE(sync_client(client_b, storage_path, key).has_value());
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("local reuse candidates matched"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("local reuse moves applied"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("rc/get_content"), 2U);

    // 3. No-op on B:
    kasumi::platform::perf_trace::reset();
    ASSERT_TRUE(sync_client(client_b, storage_path, key).has_value());
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("local reuse candidates matched"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("local reuse moves applied"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("rc/get_content"), 0U);

    // 4. Delete-only (A deletes one.txt, B syncs):
    std::filesystem::remove(client_a.local / "Docs" / "one.txt");
    ASSERT_TRUE(sync_client(client_a, storage_path, key).has_value());
    kasumi::platform::perf_trace::reset();
    ASSERT_TRUE(sync_client(client_b, storage_path, key).has_value());
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("local reuse candidates matched"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("local reuse moves applied"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("rc/get_content"), 0U);
    EXPECT_FALSE(std::filesystem::exists(client_b.local / "Docs" / "one.txt"));
    EXPECT_TRUE(std::filesystem::exists(client_b.local / "Docs" / "two.txt"));

    auto audited = fsck_client(client_b, storage_path, key);
    ASSERT_TRUE(audited.has_value()) << audited.error().detail;
}

} // namespace

