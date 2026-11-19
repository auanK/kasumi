#include "application/execute.hpp"
#include "application/profile.hpp"
#include "application/observation/state.hpp"
#include "core/reconciliation/plan.hpp"
#include "platform/metadata.hpp"
#include "platform/perf_trace.hpp"
#include "runtime/resolver.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"

#include <chrono>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <vector>

namespace {

using kasumi::application::Credentials;
using kasumi::application::ExecutionEnvironment;
using kasumi::application::MasterKeyHex;
using kasumi::application::Operation;
using kasumi::application::PlanAction;
using kasumi::application::PlanReport;
using kasumi::application::Request;
using kasumi::test::TempWorkspace;

MasterKeyHex test_key() {
    return MasterKeyHex{std::string(64, '4')};
}

void setup_test_profile(const TempWorkspace& workspace, int file_count = 5) {
    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");

    std::filesystem::create_directories(app);
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(remote);

    kasumi::test::write_text(
        app / "config.toml",
        "[profiles.demo]\nlocal_dir = '" + local.string() + "'\n"
        "remote_dir = '" + remote.string() + "'\n"
        "min_history_depth = 5\nmin_history_age_hours = 6\n"
        "key_storage = 'file'\n");
    std::filesystem::create_directories(app / "profiles" / "demo");
    ASSERT_TRUE(kasumi::state_storage::initialize(
        app / "profiles" / "demo" / "db.sqlite"));

    // Give the warm scan files outside the scanner's recent-write window.
    const auto mtime =
        std::filesystem::file_time_type::clock::now() - std::chrono::seconds{1};
    for (int i = 1; i <= file_count; ++i) {
        const auto file = local / ("file_" + std::to_string(i) + ".txt");
        kasumi::test::write_text(
            file,
            "Payload content for test file " + std::to_string(i) + " with some bytes.");
        ASSERT_TRUE(kasumi::platform::metadata::set_last_write_time(file, mtime));
    }
}

void init_transport(const TempWorkspace& workspace) {
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "remote").string());
    ASSERT_TRUE(opened.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*opened));
}

// Helper to count files in directory recursively
std::size_t count_files_recursively(const std::filesystem::path& dir) {
    std::size_t count = 0;
    std::error_code ec;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(dir, ec)) {
        if (entry.is_regular_file()) {
            ++count;
        }
    }
    return count;
}

TEST(PlanCacheObservationTest, StatusReusesStrongFingerprintsOnWarmNoOp) {
    auto workspace = kasumi::test::make_temp_workspace("plan-cache-status-noop");
    setup_test_profile(workspace, 5);
    init_transport(workspace);

    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto db_path = app / "profiles" / "demo" / "db.sqlite";
    const ExecutionEnvironment env{app};
    const Credentials creds{test_key()};

    // 1. Initial sync to populate state and warm the cache
    auto initial_sync = kasumi::application::execute({Request{Operation::Sync, "demo"}, creds, env});
    ASSERT_TRUE(initial_sync.has_value()) << initial_sync.error().detail;

    // Verify cache in db.sqlite is loaded and contains 5 rows
    auto cache_rows = kasumi::state_storage::load_file_cache(db_path);
    ASSERT_TRUE(cache_rows.has_value());
    ASSERT_EQ(cache_rows->size(), 5U);

    const auto db_size_before = std::filesystem::file_size(db_path);
    const auto remote_files_before = count_files_recursively(kasumi::test::workspace_path(workspace, "remote"));

    // 2. Execute Status
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    auto status_res = kasumi::application::execute({Request{Operation::Status, "demo"}, creds, env});
    ASSERT_TRUE(status_res.has_value()) << status_res.error().detail;
    EXPECT_EQ(status_res->operation, Operation::Status);

    // Plan report must indicate 0 actions needed (clean no-op)
    const auto& report = std::get<PlanReport>(status_res->data);
    EXPECT_EQ(report.action_counts[static_cast<std::size_t>(PlanAction::Upload)], 0U);
    EXPECT_EQ(report.action_counts[static_cast<std::size_t>(PlanAction::Download)], 0U);
    EXPECT_EQ(report.action_counts[static_cast<std::size_t>(PlanAction::DeleteRemote)], 0U);

    // Cache metrics: All 5 files must hit the cache with zero hash calculations
    const auto hits = kasumi::platform::perf_trace::get_count("local hash cache hits");
    const auto misses = kasumi::platform::perf_trace::get_count("local hash cache misses");
    const auto hash_calls = kasumi::platform::perf_trace::get_count("local hash file calls");
    const auto hash_bytes = kasumi::platform::perf_trace::get_count("local hash bytes");

    kasumi::platform::perf_trace::force_enable(false);

    EXPECT_EQ(hits, 5U);
    EXPECT_EQ(misses, 0U);
    EXPECT_EQ(hash_calls, 0U);
    EXPECT_EQ(hash_bytes, 0U);

    // Verification of zero side-effects
    EXPECT_EQ(std::filesystem::file_size(db_path), db_size_before);
    EXPECT_EQ(count_files_recursively(kasumi::test::workspace_path(workspace, "remote")), remote_files_before);
}

TEST(PlanCacheObservationTest, PreviewDryRunReusesStrongFingerprintsOnWarmNoOp) {
    auto workspace = kasumi::test::make_temp_workspace("plan-cache-preview-noop");
    setup_test_profile(workspace, 5);
    init_transport(workspace);

    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto db_path = app / "profiles" / "demo" / "db.sqlite";
    const ExecutionEnvironment env{app};
    const Credentials creds{test_key()};

    // 1. Initial sync
    auto initial_sync = kasumi::application::execute({Request{Operation::Sync, "demo"}, creds, env});
    ASSERT_TRUE(initial_sync.has_value()) << initial_sync.error().detail;

    const auto db_size_before = std::filesystem::file_size(db_path);
    const auto remote_files_before = count_files_recursively(kasumi::test::workspace_path(workspace, "remote"));

    // 2. Execute Preview (sync --dry-run)
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    auto preview_res = kasumi::application::execute({Request{Operation::Preview, "demo"}, creds, env});
    ASSERT_TRUE(preview_res.has_value()) << preview_res.error().detail;
    EXPECT_EQ(preview_res->operation, Operation::Preview);

    const auto& report = std::get<PlanReport>(preview_res->data);
    EXPECT_EQ(report.action_counts[static_cast<std::size_t>(PlanAction::Upload)], 0U);
    EXPECT_EQ(report.action_counts[static_cast<std::size_t>(PlanAction::Download)], 0U);

    const auto hits = kasumi::platform::perf_trace::get_count("local hash cache hits");
    const auto misses = kasumi::platform::perf_trace::get_count("local hash cache misses");
    const auto hash_calls = kasumi::platform::perf_trace::get_count("local hash file calls");
    const auto hash_bytes = kasumi::platform::perf_trace::get_count("local hash bytes");

    kasumi::platform::perf_trace::force_enable(false);

    EXPECT_EQ(hits, 5U);
    EXPECT_EQ(misses, 0U);
    EXPECT_EQ(hash_calls, 0U);
    EXPECT_EQ(hash_bytes, 0U);

    // Verification of zero side-effects
    EXPECT_EQ(std::filesystem::file_size(db_path), db_size_before);
    EXPECT_EQ(count_files_recursively(kasumi::test::workspace_path(workspace, "remote")), remote_files_before);
}

TEST(PlanCacheObservationTest, ModifiedFileRehashesOnlyModifiedEntry) {
    auto workspace = kasumi::test::make_temp_workspace("plan-cache-modified");
    setup_test_profile(workspace, 5);
    init_transport(workspace);

    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const ExecutionEnvironment env{app};
    const Credentials creds{test_key()};

    // 1. Initial sync
    ASSERT_TRUE(kasumi::application::execute({Request{Operation::Sync, "demo"}, creds, env}).has_value());

    // 2. Modify only file_3.txt
    kasumi::test::write_text(local / "file_3.txt", "Modified content with different hash and size!");

    // 3. Execute Status
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    auto status_res = kasumi::application::execute({Request{Operation::Status, "demo"}, creds, env});
    ASSERT_TRUE(status_res.has_value());

    const auto& report = std::get<PlanReport>(status_res->data);
    EXPECT_EQ(report.action_counts[static_cast<std::size_t>(PlanAction::Upload)], 1U);

    const auto hits = kasumi::platform::perf_trace::get_count("local hash cache hits");
    const auto misses = kasumi::platform::perf_trace::get_count("local hash cache misses");
    const auto hash_calls = kasumi::platform::perf_trace::get_count("local hash file calls");

    kasumi::platform::perf_trace::force_enable(false);

    EXPECT_EQ(hits, 4U);
    EXPECT_EQ(misses, 1U);
    EXPECT_EQ(hash_calls, 1U);
}

TEST(PlanCacheObservationTest, MissingDatabaseIsRejectedWithoutRecreation) {
    auto workspace = kasumi::test::make_temp_workspace("plan-cache-no-db");
    setup_test_profile(workspace, 3);
    init_transport(workspace);

    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto db_path = app / "profiles" / "demo" / "db.sqlite";
    const ExecutionEnvironment env{app};
    const Credentials creds{test_key()};
    ASSERT_TRUE(std::filesystem::remove(db_path));
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    const auto remote_before = kasumi::test::snapshot_tree(remote);

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    auto status_res = kasumi::application::execute({Request{Operation::Status, "demo"}, creds, env});
    EXPECT_FALSE(status_res.has_value());
    EXPECT_FALSE(std::filesystem::exists(db_path));
    EXPECT_EQ(kasumi::test::snapshot_tree(remote), remote_before);

    kasumi::platform::perf_trace::force_enable(false);
}

TEST(PlanCacheObservationTest, PlanEquivalenceBetweenCacheAndFullHash) {
    auto workspace = kasumi::test::make_temp_workspace("plan-cache-equivalence");
    setup_test_profile(workspace, 4);
    init_transport(workspace);

    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const ExecutionEnvironment env{app};
    const Credentials creds{test_key()};

    // 1. Initial sync
    ASSERT_TRUE(kasumi::application::execute({Request{Operation::Sync, "demo"}, creds, env}).has_value());

    // 2. Perform various edits: modify file 1, add file 5, remove file 2
    kasumi::test::write_text(local / "file_1.txt", "New content 1");
    kasumi::test::write_text(local / "file_5.txt", "Brand new file 5");
    std::filesystem::remove(local / "file_2.txt");

    // Execute Status and Preview
    auto status_res = kasumi::application::execute({Request{Operation::Status, "demo"}, creds, env});
    auto preview_res = kasumi::application::execute({Request{Operation::Preview, "demo"}, creds, env});

    ASSERT_TRUE(status_res.has_value());
    ASSERT_TRUE(preview_res.has_value());

    const auto& status_report = std::get<PlanReport>(status_res->data);
    const auto& preview_report = std::get<PlanReport>(preview_res->data);

    // Structural equivalence between Status and Preview
    EXPECT_EQ(status_report.action_counts, preview_report.action_counts);
    EXPECT_EQ(status_report.upload_bytes, preview_report.upload_bytes);
    EXPECT_EQ(status_report.items.size(), preview_report.items.size());
    for (std::size_t i = 0; i < status_report.items.size(); ++i) {
        EXPECT_EQ(status_report.items[i].action, preview_report.items[i].action);
        EXPECT_EQ(status_report.items[i].path, preview_report.items[i].path);
        EXPECT_EQ(status_report.items[i].size, preview_report.items[i].size);
    }
}

TEST(PlanCacheObservationTest, RepeatedStatusExecutionsDoNotMutateProfileOrDegrade) {
    auto workspace = kasumi::test::make_temp_workspace("plan-cache-repeated");
    setup_test_profile(workspace, 3);
    init_transport(workspace);

    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto db_path = app / "profiles" / "demo" / "db.sqlite";
    const ExecutionEnvironment env{app};
    const Credentials creds{test_key()};

    ASSERT_TRUE(kasumi::application::execute({Request{Operation::Sync, "demo"}, creds, env}).has_value());

    const auto db_mtime_before = std::filesystem::last_write_time(db_path);
    const auto db_size_before = std::filesystem::file_size(db_path);

    for (int run = 0; run < 5; ++run) {
        kasumi::platform::perf_trace::force_enable(true);
        kasumi::platform::perf_trace::reset();

        auto res = kasumi::application::execute({Request{Operation::Status, "demo"}, creds, env});
        ASSERT_TRUE(res.has_value());

        EXPECT_EQ(kasumi::platform::perf_trace::get_count("local hash cache hits"), 3U);
        EXPECT_EQ(kasumi::platform::perf_trace::get_count("local hash file calls"), 0U);

        kasumi::platform::perf_trace::force_enable(false);

        EXPECT_EQ(std::filesystem::file_size(db_path), db_size_before);
        EXPECT_EQ(std::filesystem::last_write_time(db_path), db_mtime_before);
    }
}

TEST(PlanCacheObservationTest, NewFileAddedHitsCacheForExistingAndHashesNewFile) {
    auto workspace = kasumi::test::make_temp_workspace("plan-cache-new-file");
    setup_test_profile(workspace, 3);
    init_transport(workspace);

    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const ExecutionEnvironment env{app};
    const Credentials creds{test_key()};

    ASSERT_TRUE(kasumi::application::execute({Request{Operation::Sync, "demo"}, creds, env}).has_value());

    // Add a brand new file
    kasumi::test::write_text(local / "brand_new.txt", "Brand new content not in cache");

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    auto status_res = kasumi::application::execute({Request{Operation::Status, "demo"}, creds, env});
    ASSERT_TRUE(status_res.has_value());

    const auto& report = std::get<PlanReport>(status_res->data);
    EXPECT_EQ(report.action_counts[static_cast<std::size_t>(PlanAction::Upload)], 1U);

    // 3 existing files hit cache, 1 new file is hashed
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("local hash cache hits"), 3U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("local hash cache misses"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("local hash file calls"), 1U);

    kasumi::platform::perf_trace::force_enable(false);
}

TEST(PlanCacheObservationTest, DeletedFilePlannedForDeletionWithoutAffectingRemainingCache) {
    auto workspace = kasumi::test::make_temp_workspace("plan-cache-del-file");
    setup_test_profile(workspace, 4);
    init_transport(workspace);

    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const ExecutionEnvironment env{app};
    const Credentials creds{test_key()};

    ASSERT_TRUE(kasumi::application::execute({Request{Operation::Sync, "demo"}, creds, env}).has_value());

    // Delete file_2.txt
    std::filesystem::remove(local / "file_2.txt");

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    auto status_res = kasumi::application::execute({Request{Operation::Status, "demo"}, creds, env});
    ASSERT_TRUE(status_res.has_value());

    const auto& report = std::get<PlanReport>(status_res->data);
    EXPECT_EQ(report.action_counts[static_cast<std::size_t>(PlanAction::DeleteRemote)], 1U);
    EXPECT_EQ(report.action_counts[static_cast<std::size_t>(PlanAction::Upload)], 0U);

    // Remaining 3 files all hit cache
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("local hash cache hits"), 3U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("local hash file calls"), 0U);

    kasumi::platform::perf_trace::force_enable(false);
}

TEST(PlanCacheObservationTest, IgnoreListChangePreventsIgnoredFilesFromBeingPlanned) {
    auto workspace = kasumi::test::make_temp_workspace("plan-cache-ignore-change");
    setup_test_profile(workspace, 3);
    init_transport(workspace);

    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const ExecutionEnvironment env{app};
    const Credentials creds{test_key()};

    ASSERT_TRUE(kasumi::application::execute({Request{Operation::Sync, "demo"}, creds, env}).has_value());

    // Add .kasumiignore ignoring file_2.txt and file_3.txt
    kasumi::test::write_text(local / ".kasumiignore", "file_2.txt\nfile_3.txt\n");

    auto status_res = kasumi::application::execute({Request{Operation::Status, "demo"}, creds, env});
    ASSERT_TRUE(status_res.has_value());

    const auto& report = std::get<PlanReport>(status_res->data);
    // Ignored files that already existed in remote should be planned for remote deletion
    EXPECT_EQ(report.action_counts[static_cast<std::size_t>(PlanAction::DeleteRemote)], 2U);
}

TEST(PlanCacheObservationTest, ReadOnlyDatabaseFileAllowsCacheReuseWithoutError) {
    auto workspace = kasumi::test::make_temp_workspace("plan-cache-ro-db");
    setup_test_profile(workspace, 3);
    init_transport(workspace);

    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto db_path = app / "profiles" / "demo" / "db.sqlite";
    const ExecutionEnvironment env{app};
    const Credentials creds{test_key()};

    ASSERT_TRUE(kasumi::application::execute({Request{Operation::Sync, "demo"}, creds, env}).has_value());

    // Make db.sqlite read-only at filesystem level
    std::filesystem::permissions(
        db_path,
        std::filesystem::perms::owner_read | std::filesystem::perms::group_read | std::filesystem::perms::others_read,
        std::filesystem::perm_options::replace);

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    auto status_res = kasumi::application::execute({Request{Operation::Status, "demo"}, creds, env});
    ASSERT_TRUE(status_res.has_value());

    EXPECT_EQ(kasumi::platform::perf_trace::get_count("local hash cache hits"), 3U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("local hash file calls"), 0U);

    kasumi::platform::perf_trace::force_enable(false);

    // Restore write permissions for workspace cleanup
    std::filesystem::permissions(
        db_path,
        std::filesystem::perms::all,
        std::filesystem::perm_options::replace);
}

TEST(PlanCacheObservationTest, TimestampModificationForcesRehash) {
    auto workspace = kasumi::test::make_temp_workspace("plan-cache-mtime");
    setup_test_profile(workspace, 2);
    init_transport(workspace);

    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const ExecutionEnvironment env{app};
    const Credentials creds{test_key()};

    ASSERT_TRUE(kasumi::application::execute({Request{Operation::Sync, "demo"}, creds, env}).has_value());

    // Update last_write_time of file_1.txt without changing content
    const auto target_file = local / "file_1.txt";
    const auto current_time = std::filesystem::last_write_time(target_file);
    std::filesystem::last_write_time(target_file, current_time + std::chrono::hours(24));

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    auto status_res = kasumi::application::execute({Request{Operation::Status, "demo"}, creds, env});
    ASSERT_TRUE(status_res.has_value());

    // file_1 was rehashed because mtime changed; file_2 hit cache
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("local hash cache hits"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("local hash cache misses"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("local hash file calls"), 1U);

    kasumi::platform::perf_trace::force_enable(false);
}

TEST(PlanCacheObservationTest,
     IgnoredOnlyDirectoryAndPathOrderInversionStayNoOpWithoutEagerWriterOrDirtyCache) {
    auto workspace =
        kasumi::test::make_temp_workspace("plan-cache-ignored-dir-noop");
    const auto app = kasumi::test::workspace_path(workspace, "app");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");

    std::filesystem::create_directories(app);
    std::filesystem::create_directories(local / "docs");
    std::filesystem::create_directories(local / "__history");
    std::filesystem::create_directories(remote);

    kasumi::test::write_text(
        app / "config.toml",
        "[profiles.demo]\nlocal_dir = '" + local.string() + "'\n"
        "remote_dir = '" + remote.string() + "'\n"
        "min_history_depth = 5\nmin_history_age_hours = 6\n"
        "key_storage = 'file'\n");
    std::filesystem::create_directories(app / "profiles" / "demo");
    ASSERT_TRUE(kasumi::state_storage::initialize(
        app / "profiles" / "demo" / "db.sqlite"));

    const auto mtime =
        std::filesystem::file_time_type::clock::now() - std::chrono::seconds{2};
    for (const auto& [rel, body] :
         std::vector<std::pair<std::string, std::string>>{
             {".kasumiignore", "*~\n"},
             {"docs.md", "top-level doc"},
             {"docs/sub.md", "nested doc"},
             {"__history/backup.1~", "ignored backup"},
         }) {
        const auto file = local / rel;
        kasumi::test::write_text(file, body);
        ASSERT_TRUE(kasumi::platform::metadata::set_last_write_time(file, mtime));
    }

    init_transport(workspace);
    const ExecutionEnvironment env{app};
    const Credentials creds{test_key()};
    ASSERT_TRUE(
        kasumi::application::execute({Request{Operation::Sync, "demo"}, creds, env})
            .has_value());

    auto runtime_data = kasumi::runtime::resolve(
        app, "demo", kasumi::runtime::AccessMode::ReadOnly);
    ASSERT_TRUE(runtime_data.has_value());
    auto storage = kasumi::transport::open_transport(
        runtime_data->storage_location, runtime_data->local_dir);
    ASSERT_TRUE(storage.has_value());
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    key.fill(0x44);

    // On a no-op with an ignored-only directory and SQLite-vs-path_less
    // ordering inversion ("docs.md" vs "docs/sub.md"), eager writer must not
    // trigger and file_cache must not be marked dirty.
    kasumi::application::observation::LocalObservationSession session;
    session.database_path = runtime_data->database_path;
    bool proven_local_change = false;
    auto collected = kasumi::application::observation::collect_reconciliation_input(
        *runtime_data,
        *storage,
        key,
        false,
        {},
        &session,
        [&] { proven_local_change = true; });
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_FALSE(proven_local_change);
    EXPECT_FALSE(session.cache_dirty);

    auto reconciled = kasumi::reconciliation::reconcile(*collected);
    ASSERT_TRUE(reconciled.has_value());
    EXPECT_FALSE(reconciled->requires_publication);
    EXPECT_FALSE(reconciled->requires_local_mutation);
    EXPECT_FALSE(reconciled->requires_storage_repair);
    EXPECT_FALSE(reconciled->requires_state_commit);

    // Modifying a managed file still triggers eager writer detection.
    const auto edited = local / "docs.md";
    kasumi::test::write_text(edited, "edited doc");
    ASSERT_TRUE(kasumi::platform::metadata::set_last_write_time(
        edited, mtime + std::chrono::seconds{1}));
    kasumi::application::observation::LocalObservationSession edited_session;
    edited_session.database_path = runtime_data->database_path;
    bool edited_proven_change = false;
    auto edited_collected =
        kasumi::application::observation::collect_reconciliation_input(
            *runtime_data,
            *storage,
            key,
            false,
            {},
            &edited_session,
            [&] { edited_proven_change = true; });
    ASSERT_TRUE(edited_collected.has_value());
    EXPECT_TRUE(edited_proven_change);
}

} // namespace

