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

} // namespace

