#include "application/history_storage/publication.hpp"
#include "application/observation/scanner.hpp"
#include "application/observation/state.hpp"
#include "application/sync/coordinator.hpp"
#include "application/sync/publication.hpp"
#include "application/sync/reobservation.hpp"
#include "core/hasher.hpp"
#include "core/node.hpp"
#include "core/operation.hpp"
#include "core/reconciliation/plan.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/physical_hash.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/path.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <array>
#include <filesystem>
#include <gtest/gtest.h>

namespace {

void add_storage_payload(kasumi::transport::Transport& storage,
                         const std::filesystem::path& source,
                         const kasumi::Hash& hash) {
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto encrypted = kasumi::platform::path::temporary_sibling_path(
        source, "", ".encrypted");
    ASSERT_TRUE(kasumi::crypto::encrypt_file(source, encrypted, key));
    ASSERT_TRUE(kasumi::transport::put(
        storage, encrypted, kasumi::crypto::content_identifier(key, hash)));
}

kasumi::runtime::RuntimeData make_runtime_data(const std::filesystem::path& profile,
                                              const std::filesystem::path& local,
                                              const std::filesystem::path& storage) {
    return kasumi::runtime::RuntimeData{
        .local_dir = local,
        .database_path = profile / "state.db",
        .key_path = profile / "key.bin",
        .storage_location = storage.string()};
}

TEST(ReobservationSafeguardTest, DestructiveSafeguardSetsCacheDirtyUponEviction) {
    auto workspace = kasumi::test::make_temp_workspace("safeguard-dirty-flag");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path = kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto local_file = local / "file.txt";

    kasumi::test::write_text(local_file, "AAAA");
    const auto initial_scan = kasumi::application::observation::scanner::scan_result(
        local, {}, kasumi::application::observation::scanner::ScanPolicy::ReuseStrongFingerprint);
    ASSERT_TRUE(initial_scan.has_value());
    const auto old_mtime = std::filesystem::last_write_time(local_file);

    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto runtime_data = make_runtime_data(profile, local, storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto hash_a = kasumi::hasher::hash_string("AAAA");
    const auto hash_b = kasumi::hasher::hash_string("BBBB");

    const kasumi::Snapshot base_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true},
                 kasumi::NodeRow{.path = "file.txt", .hash = hash_a, .size = 4}}};

    const auto prepared_base =
        kasumi::application::sync::publication::prepare_commit(
            base_tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared_base.has_value());
    const auto published_base =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_base, profile);
    ASSERT_TRUE(published_base.has_value());

    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        kasumi::state_storage::StoredState{
            .tree = base_tree,
            .height = prepared_base->commit.height,
            .commit_id = published_base->head.commit_id,
            .ciphertext_id = published_base->head.ciphertext_id,
        }));

    kasumi::Snapshot remote_tree = base_tree;
    kasumi::find_row(remote_tree, "file.txt")->hash = hash_b;
    const std::array base_parents{published_base->head.commit_id};
    const auto prepared_remote =
        kasumi::application::sync::publication::prepare_commit(
            remote_tree, true, prepared_base->commit.height,
            base_parents, 101, key);
    ASSERT_TRUE(prepared_remote.has_value());
    const auto published_remote =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_remote, profile);
    ASSERT_TRUE(published_remote.has_value());

    const auto remote_payload = kasumi::test::workspace_path(workspace, "payload.bin");
    kasumi::test::write_text(remote_payload, "BBBB");
    add_storage_payload(*storage, remote_payload, hash_b);

    // Modify local file to "BBBB" with same size and restored mtime
    kasumi::test::write_text(local_file, "BBBB");
    std::filesystem::last_write_time(local_file, old_mtime);

    kasumi::application::observation::LocalObservationSession session{};
    session.cache = initial_scan->cache;
    session.cache_dirty = false;

    auto observed = kasumi::application::observation::collect_reconciliation_input(
        runtime_data, *storage, key, false, {}, &session);
    ASSERT_TRUE(observed.has_value());
    auto result = kasumi::reconciliation::reconcile(*observed);
    ASSERT_TRUE(result.has_value());

    // Explicitly clear dirty flag before stabilize to verify that safeguard invalidation sets it
    session.cache_dirty = false;

    const auto stable = kasumi::application::sync::coordinator::reobservation::stabilize(
        runtime_data, *storage, key, *observed, *result, &session);
    ASSERT_TRUE(stable.has_value()) << stable.error().detail;

    // Cache dirty flag MUST be set so that the eviction is persisted to SQLite!
    EXPECT_TRUE(session.cache_dirty);
}

TEST(ReobservationSafeguardTest, DestructiveSafeguardFailsClosedWhenHashFails) {
    auto workspace = kasumi::test::make_temp_workspace("safeguard-hash-fail");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path = kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto local_file = local / "file.txt";

    kasumi::test::write_text(local_file, "AAAA");
    const auto initial_scan = kasumi::application::observation::scanner::scan_result(
        local, {}, kasumi::application::observation::scanner::ScanPolicy::ReuseStrongFingerprint);
    ASSERT_TRUE(initial_scan.has_value());

    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto runtime_data = make_runtime_data(profile, local, storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto hash_a = kasumi::hasher::hash_string("AAAA");
    const auto hash_c = kasumi::hasher::hash_string("CCCC");

    const kasumi::Snapshot base_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true},
                 kasumi::NodeRow{.path = "file.txt", .hash = hash_a, .size = 4}}};

    const auto prepared_base =
        kasumi::application::sync::publication::prepare_commit(
            base_tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared_base.has_value());
    const auto published_base =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_base, profile);
    ASSERT_TRUE(published_base.has_value());

    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        kasumi::state_storage::StoredState{
            .tree = base_tree,
            .height = prepared_base->commit.height,
            .commit_id = published_base->head.commit_id,
            .ciphertext_id = published_base->head.ciphertext_id,
        }));

    kasumi::Snapshot remote_tree = base_tree;
    kasumi::find_row(remote_tree, "file.txt")->hash = hash_c;
    const std::array base_parents{published_base->head.commit_id};
    const auto prepared_remote =
        kasumi::application::sync::publication::prepare_commit(
            remote_tree, true, prepared_base->commit.height,
            base_parents, 101, key);
    ASSERT_TRUE(prepared_remote.has_value());
    const auto published_remote =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_remote, profile);
    ASSERT_TRUE(published_remote.has_value());

    const auto remote_payload = kasumi::test::workspace_path(workspace, "payload.bin");
    kasumi::test::write_text(remote_payload, "CCCC");
    add_storage_payload(*storage, remote_payload, hash_c);

    kasumi::application::observation::LocalObservationSession session{};
    session.cache = initial_scan->cache;

    auto observed = kasumi::application::observation::collect_reconciliation_input(
        runtime_data, *storage, key, false, {}, &session);
    ASSERT_TRUE(observed.has_value());
    auto result = kasumi::reconciliation::reconcile(*observed);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->plan.operations.front().action, kasumi::Action::Download);

    // Make local_file completely unreadable
    std::filesystem::permissions(local_file, std::filesystem::perms::none);

    const auto stable = kasumi::application::sync::coordinator::reobservation::stabilize(
        runtime_data, *storage, key, *observed, *result, &session);

    // Restore permissions for clean workspace cleanup
    std::filesystem::permissions(local_file, std::filesystem::perms::all);

    // Safeguard MUST fail closed when local file cannot be hashed
    ASSERT_FALSE(stable.has_value());
    EXPECT_EQ(stable.error().code,
              kasumi::application::sync::coordinator::ErrorCode::ObservationFailure);
}

TEST(ReobservationSafeguardTest, DestructiveSafeguardEvictionPersistsAcrossSessionsInDatabase) {
    auto workspace = kasumi::test::make_temp_workspace("safeguard-persist-eviction");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path = kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto local_file = local / "file.txt";

    kasumi::test::write_text(local_file, "AAAA");
    const auto initial_scan = kasumi::application::observation::scanner::scan_result(
        local, {}, kasumi::application::observation::scanner::ScanPolicy::ReuseStrongFingerprint);
    ASSERT_TRUE(initial_scan.has_value());
    const auto old_mtime = std::filesystem::last_write_time(local_file);

    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto runtime_data = make_runtime_data(profile, local, storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto hash_a = kasumi::hasher::hash_string("AAAA");
    const auto hash_b = kasumi::hasher::hash_string("BBBB");

    const kasumi::Snapshot base_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true},
                 kasumi::NodeRow{.path = "file.txt", .hash = hash_a, .size = 4}}};

    const auto prepared_base =
        kasumi::application::sync::publication::prepare_commit(
            base_tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared_base.has_value());
    const auto published_base =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_base, profile);
    ASSERT_TRUE(published_base.has_value());

    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        kasumi::state_storage::StoredState{
            .tree = base_tree,
            .height = prepared_base->commit.height,
            .commit_id = published_base->head.commit_id,
            .ciphertext_id = published_base->head.ciphertext_id,
        }));

    ASSERT_TRUE(kasumi::state_storage::save_file_cache_delta(
        runtime_data.database_path, initial_scan->cache));

    kasumi::application::observation::LocalObservationSession session_1{};
    session_1.database_path = runtime_data.database_path;
    auto tree_1 = kasumi::application::observation::collect_local_tree(local, &session_1);
    ASSERT_TRUE(tree_1.has_value());
    ASSERT_EQ(session_1.cache.size(), 1u);
    EXPECT_EQ(session_1.cache.front().path, "file.txt");
    EXPECT_EQ(session_1.cache.front().hash, hash_a);

    kasumi::Snapshot remote_tree = base_tree;
    kasumi::find_row(remote_tree, "file.txt")->hash = hash_b;
    const std::array base_parents{published_base->head.commit_id};
    const auto prepared_remote =
        kasumi::application::sync::publication::prepare_commit(
            remote_tree, true, prepared_base->commit.height,
            base_parents, 101, key);
    ASSERT_TRUE(prepared_remote.has_value());
    const auto published_remote =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_remote, profile);
    ASSERT_TRUE(published_remote.has_value());

    const auto remote_payload = kasumi::test::workspace_path(workspace, "payload.bin");
    kasumi::test::write_text(remote_payload, "BBBB");
    add_storage_payload(*storage, remote_payload, hash_b);

    kasumi::test::write_text(local_file, "BBBB");
    std::filesystem::last_write_time(local_file, old_mtime);

    auto observed = kasumi::application::observation::collect_reconciliation_input(
        runtime_data, *storage, key, false, {}, &session_1);
    ASSERT_TRUE(observed.has_value());
    auto result = kasumi::reconciliation::reconcile(*observed);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->plan.operations.front().action, kasumi::Action::Download);

    session_1.cache_dirty = false;

    const auto stable = kasumi::application::sync::coordinator::reobservation::stabilize(
        runtime_data, *storage, key, *observed, *result, &session_1);
    ASSERT_TRUE(stable.has_value()) << stable.error().detail;

    EXPECT_TRUE(session_1.cache_dirty);
    auto it_mem = std::ranges::find_if(session_1.cache, [](const auto& r) {
        return r.path == "file.txt";
    });
    EXPECT_EQ(it_mem, session_1.cache.end());

    ASSERT_TRUE(kasumi::state_storage::save_file_cache_delta(
        runtime_data.database_path, session_1.cache));

    auto loaded = kasumi::state_storage::load_file_cache(runtime_data.database_path);
    ASSERT_TRUE(loaded.has_value());
    auto it_db = std::ranges::find_if(*loaded, [](const auto& r) {
        return r.path == "file.txt";
    });
    EXPECT_EQ(it_db, loaded->end());

    kasumi::application::observation::LocalObservationSession session_2{};
    session_2.database_path = runtime_data.database_path;

    kasumi::test::write_text(local_file, "CCCC");
    std::filesystem::last_write_time(local_file, old_mtime);

    auto tree_2 = kasumi::application::observation::collect_local_tree(local, &session_2);
    ASSERT_TRUE(tree_2.has_value());
    const auto* row_2 = kasumi::find_row(*tree_2, "file.txt");
    ASSERT_NE(row_2, nullptr);
    EXPECT_EQ(row_2->hash, kasumi::hasher::hash_string("CCCC"));
}

TEST(ReobservationSafeguardTest, DestructiveSafeguardProtectsRenameLocal) {
    auto workspace = kasumi::test::make_temp_workspace("safeguard-rename-local");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path = kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto local_file = local / "file.txt";

    const auto hash_base = kasumi::hasher::hash_string("BASE");
    const auto hash_b = kasumi::hasher::hash_string("BBBB");
    const auto hash_c = kasumi::hasher::hash_string("CCCC");
    const auto hash_d = kasumi::hasher::hash_string("DDDD");

    const kasumi::Snapshot base_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true},
                 kasumi::NodeRow{.path = "file.txt", .hash = hash_base, .size = 4, .mtime = 100}}};

    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto runtime_data = make_runtime_data(profile, local, storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto prepared_base =
        kasumi::application::sync::publication::prepare_commit(
            base_tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared_base.has_value());
    const auto published_base =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_base, profile);
    ASSERT_TRUE(published_base.has_value());

    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        kasumi::state_storage::StoredState{
            .tree = base_tree,
            .height = prepared_base->commit.height,
            .commit_id = published_base->head.commit_id,
            .ciphertext_id = published_base->head.ciphertext_id,
        }));

    kasumi::Snapshot remote_tree = base_tree;
    auto* remote_row = kasumi::find_row(remote_tree, "file.txt");
    remote_row->hash = hash_c;
    remote_row->mtime = std::numeric_limits<kasumi::TimestampNs>::max();
    const std::array base_parents{published_base->head.commit_id};
    const auto prepared_remote =
        kasumi::application::sync::publication::prepare_commit(
            remote_tree, true, prepared_base->commit.height,
            base_parents, 101, key);
    ASSERT_TRUE(prepared_remote.has_value());
    const auto published_remote =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_remote, profile);
    ASSERT_TRUE(published_remote.has_value());

    const auto remote_payload = kasumi::test::workspace_path(workspace, "payload_c.bin");
    kasumi::test::write_text(remote_payload, "CCCC");
    add_storage_payload(*storage, remote_payload, hash_c);

    kasumi::test::write_text(local_file, "BBBB");
    const auto local_mtime = std::filesystem::last_write_time(local_file);

    const auto initial_scan = kasumi::application::observation::scanner::scan_result(
        local, {}, kasumi::application::observation::scanner::ScanPolicy::ReuseStrongFingerprint);
    ASSERT_TRUE(initial_scan.has_value());
    EXPECT_EQ(initial_scan->snapshot.rows.back().hash, hash_b);

    kasumi::application::observation::LocalObservationSession session{};
    session.cache = initial_scan->cache;

    auto observed = kasumi::application::observation::collect_reconciliation_input(
        runtime_data, *storage, key, false, {}, &session);
    ASSERT_TRUE(observed.has_value());
    auto* observed_local = kasumi::find_row(observed->local_tree, "file.txt");
    ASSERT_NE(observed_local, nullptr);
    observed_local->mtime = 150;

    auto result = kasumi::reconciliation::reconcile(*observed);
    ASSERT_TRUE(result.has_value());

    auto rename_op = std::ranges::find_if(result->plan.operations, [](const auto& op) {
        return op.action == kasumi::Action::RenameLocal;
    });
    ASSERT_NE(rename_op, result->plan.operations.end());
    EXPECT_EQ(rename_op->path, "file.txt");
    EXPECT_EQ(rename_op->alt_path, "file.txt.kasumiconflict_local");

    kasumi::test::write_text(local_file, "DDDD");
    std::filesystem::last_write_time(local_file, local_mtime);

    const auto stable = kasumi::application::sync::coordinator::reobservation::stabilize(
        runtime_data, *storage, key, *observed, *result, &session);
    ASSERT_TRUE(stable.has_value()) << stable.error().detail;

    const auto* row = kasumi::find_row(stable->input.local_tree, "file.txt");
    ASSERT_NE(row, nullptr);
    EXPECT_EQ(row->hash, hash_d);

    auto recalculated_rename = std::ranges::find_if(
        stable->result.plan.operations,
        [](const auto& op) { return op.action == kasumi::Action::RenameLocal; });
    ASSERT_NE(recalculated_rename, stable->result.plan.operations.end());
    EXPECT_EQ(recalculated_rename->path, "file.txt");
    EXPECT_EQ(recalculated_rename->alt_path, "file.txt.kasumiconflict_local");

    auto conflict_upload = std::ranges::find_if(
        stable->result.plan.operations,
        [&](const auto& op) {
            return op.action == kasumi::Action::Upload &&
                   op.path == "file.txt.kasumiconflict_local";
        });
    ASSERT_NE(conflict_upload, stable->result.plan.operations.end());
    EXPECT_EQ(conflict_upload->hash, kasumi::hash_hex(hash_d));

    EXPECT_EQ(kasumi::test::read_text(local_file), "DDDD");
}

TEST(ReobservationSafeguardTest, DestructiveSafeguardFailsClosedWhenRenameDestinationExists) {
    auto workspace = kasumi::test::make_temp_workspace("safeguard-rename-dest-exists");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path = kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto local_file = local / "file.txt";

    const auto hash_base = kasumi::hasher::hash_string("BASE");
    const auto hash_c = kasumi::hasher::hash_string("CCCC");

    const kasumi::Snapshot base_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true},
                 kasumi::NodeRow{.path = "file.txt", .hash = hash_base, .size = 4, .mtime = 100}}};

    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto runtime_data = make_runtime_data(profile, local, storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto prepared_base =
        kasumi::application::sync::publication::prepare_commit(
            base_tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared_base.has_value());
    const auto published_base =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_base, profile);
    ASSERT_TRUE(published_base.has_value());

    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        kasumi::state_storage::StoredState{
            .tree = base_tree,
            .height = prepared_base->commit.height,
            .commit_id = published_base->head.commit_id,
            .ciphertext_id = published_base->head.ciphertext_id,
        }));

    kasumi::Snapshot remote_tree = base_tree;
    auto* remote_row = kasumi::find_row(remote_tree, "file.txt");
    remote_row->hash = hash_c;
    remote_row->mtime = std::numeric_limits<kasumi::TimestampNs>::max();
    const std::array base_parents{published_base->head.commit_id};
    const auto prepared_remote =
        kasumi::application::sync::publication::prepare_commit(
            remote_tree, true, prepared_base->commit.height,
            base_parents, 101, key);
    ASSERT_TRUE(prepared_remote.has_value());
    const auto published_remote =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_remote, profile);
    ASSERT_TRUE(published_remote.has_value());

    const auto remote_payload = kasumi::test::workspace_path(workspace, "payload_c.bin");
    kasumi::test::write_text(remote_payload, "CCCC");
    add_storage_payload(*storage, remote_payload, hash_c);

    kasumi::test::write_text(local_file, "BBBB");

    const auto initial_scan = kasumi::application::observation::scanner::scan_result(
        local, {}, kasumi::application::observation::scanner::ScanPolicy::ReuseStrongFingerprint);
    ASSERT_TRUE(initial_scan.has_value());

    kasumi::application::observation::LocalObservationSession session{};
    session.cache = initial_scan->cache;

    auto observed = kasumi::application::observation::collect_reconciliation_input(
        runtime_data, *storage, key, false, {}, &session);
    ASSERT_TRUE(observed.has_value());
    auto* observed_local = kasumi::find_row(observed->local_tree, "file.txt");
    ASSERT_NE(observed_local, nullptr);
    observed_local->mtime = 150;

    auto result = kasumi::reconciliation::reconcile(*observed);
    ASSERT_TRUE(result.has_value());

    auto rename_op = std::ranges::find_if(result->plan.operations, [](const auto& op) {
        return op.action == kasumi::Action::RenameLocal;
    });
    ASSERT_NE(rename_op, result->plan.operations.end());
    EXPECT_EQ(rename_op->path, "file.txt");
    EXPECT_EQ(rename_op->alt_path, "file.txt.kasumiconflict_local");

    // Concurrently create destination file
    kasumi::test::write_text(local / "file.txt.kasumiconflict_local", "DEST_COLLISION");

    const auto stable = kasumi::application::sync::coordinator::reobservation::stabilize(
        runtime_data, *storage, key, *observed, *result, &session);
    ASSERT_FALSE(stable.has_value());
    EXPECT_EQ(stable.error().code,
              kasumi::application::sync::coordinator::ErrorCode::ObservationFailure);
}

TEST(ReobservationSafeguardTest, DestructiveSafeguardFailsClosedWhenRenameSourceDisappears) {
    auto workspace = kasumi::test::make_temp_workspace("safeguard-rename-src-disappears");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path = kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto local_file = local / "file.txt";

    const auto hash_base = kasumi::hasher::hash_string("BASE");
    const auto hash_c = kasumi::hasher::hash_string("CCCC");

    const kasumi::Snapshot base_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true},
                 kasumi::NodeRow{.path = "file.txt", .hash = hash_base, .size = 4, .mtime = 100}}};

    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto runtime_data = make_runtime_data(profile, local, storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto prepared_base =
        kasumi::application::sync::publication::prepare_commit(
            base_tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared_base.has_value());
    const auto published_base =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_base, profile);
    ASSERT_TRUE(published_base.has_value());

    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        kasumi::state_storage::StoredState{
            .tree = base_tree,
            .height = prepared_base->commit.height,
            .commit_id = published_base->head.commit_id,
            .ciphertext_id = published_base->head.ciphertext_id,
        }));

    kasumi::Snapshot remote_tree = base_tree;
    auto* remote_row = kasumi::find_row(remote_tree, "file.txt");
    remote_row->hash = hash_c;
    remote_row->mtime = std::numeric_limits<kasumi::TimestampNs>::max();
    const std::array base_parents{published_base->head.commit_id};
    const auto prepared_remote =
        kasumi::application::sync::publication::prepare_commit(
            remote_tree, true, prepared_base->commit.height,
            base_parents, 101, key);
    ASSERT_TRUE(prepared_remote.has_value());
    const auto published_remote =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_remote, profile);
    ASSERT_TRUE(published_remote.has_value());

    const auto remote_payload = kasumi::test::workspace_path(workspace, "payload_c.bin");
    kasumi::test::write_text(remote_payload, "CCCC");
    add_storage_payload(*storage, remote_payload, hash_c);

    kasumi::test::write_text(local_file, "BBBB");

    const auto initial_scan = kasumi::application::observation::scanner::scan_result(
        local, {}, kasumi::application::observation::scanner::ScanPolicy::ReuseStrongFingerprint);
    ASSERT_TRUE(initial_scan.has_value());

    kasumi::application::observation::LocalObservationSession session{};
    session.cache = initial_scan->cache;

    auto observed = kasumi::application::observation::collect_reconciliation_input(
        runtime_data, *storage, key, false, {}, &session);
    ASSERT_TRUE(observed.has_value());
    auto* observed_local = kasumi::find_row(observed->local_tree, "file.txt");
    ASSERT_NE(observed_local, nullptr);
    observed_local->mtime = 150;

    auto result = kasumi::reconciliation::reconcile(*observed);
    ASSERT_TRUE(result.has_value());

    // Concurrently remove source file before stabilize
    std::filesystem::remove(local_file);

    const auto stable = kasumi::application::sync::coordinator::reobservation::stabilize(
        runtime_data, *storage, key, *observed, *result, &session);
    ASSERT_FALSE(stable.has_value());
    EXPECT_EQ(stable.error().code,
              kasumi::application::sync::coordinator::ErrorCode::ObservationFailure);
}

TEST(ReobservationSafeguardTest, DestructiveSafeguardFailsClosedWhenRenameSourceReplacedByDirectory) {
    auto workspace = kasumi::test::make_temp_workspace("safeguard-rename-src-dir");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path = kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto local_file = local / "file.txt";

    const auto hash_base = kasumi::hasher::hash_string("BASE");
    const auto hash_c = kasumi::hasher::hash_string("CCCC");

    const kasumi::Snapshot base_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true},
                 kasumi::NodeRow{.path = "file.txt", .hash = hash_base, .size = 4, .mtime = 100}}};

    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto runtime_data = make_runtime_data(profile, local, storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto prepared_base =
        kasumi::application::sync::publication::prepare_commit(
            base_tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared_base.has_value());
    const auto published_base =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_base, profile);
    ASSERT_TRUE(published_base.has_value());

    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        kasumi::state_storage::StoredState{
            .tree = base_tree,
            .height = prepared_base->commit.height,
            .commit_id = published_base->head.commit_id,
            .ciphertext_id = published_base->head.ciphertext_id,
        }));

    kasumi::Snapshot remote_tree = base_tree;
    auto* remote_row = kasumi::find_row(remote_tree, "file.txt");
    remote_row->hash = hash_c;
    remote_row->mtime = std::numeric_limits<kasumi::TimestampNs>::max();
    const std::array base_parents{published_base->head.commit_id};
    const auto prepared_remote =
        kasumi::application::sync::publication::prepare_commit(
            remote_tree, true, prepared_base->commit.height,
            base_parents, 101, key);
    ASSERT_TRUE(prepared_remote.has_value());
    const auto published_remote =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_remote, profile);
    ASSERT_TRUE(published_remote.has_value());

    const auto remote_payload = kasumi::test::workspace_path(workspace, "payload_c.bin");
    kasumi::test::write_text(remote_payload, "CCCC");
    add_storage_payload(*storage, remote_payload, hash_c);

    kasumi::test::write_text(local_file, "BBBB");

    const auto initial_scan = kasumi::application::observation::scanner::scan_result(
        local, {}, kasumi::application::observation::scanner::ScanPolicy::ReuseStrongFingerprint);
    ASSERT_TRUE(initial_scan.has_value());

    kasumi::application::observation::LocalObservationSession session{};
    session.cache = initial_scan->cache;

    auto observed = kasumi::application::observation::collect_reconciliation_input(
        runtime_data, *storage, key, false, {}, &session);
    ASSERT_TRUE(observed.has_value());
    auto* observed_local = kasumi::find_row(observed->local_tree, "file.txt");
    ASSERT_NE(observed_local, nullptr);
    observed_local->mtime = 150;

    auto result = kasumi::reconciliation::reconcile(*observed);
    ASSERT_TRUE(result.has_value());

    // Concurrently replace source file with a directory before stabilize
    std::filesystem::remove(local_file);
    ASSERT_TRUE(std::filesystem::create_directory(local_file));

    const auto stable = kasumi::application::sync::coordinator::reobservation::stabilize(
        runtime_data, *storage, key, *observed, *result, &session);
    ASSERT_FALSE(stable.has_value());
    EXPECT_EQ(stable.error().code,
              kasumi::application::sync::coordinator::ErrorCode::ObservationFailure);
}

TEST(ReobservationSafeguardTest, DestructiveSafeguardFailsClosedWhenDownloadTargetDisappears) {
    auto workspace = kasumi::test::make_temp_workspace("safeguard-dl-disappears");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path = kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto local_file = local / "file.txt";

    kasumi::test::write_text(local_file, "AAAA");
    const auto initial_scan = kasumi::application::observation::scanner::scan_result(
        local, {}, kasumi::application::observation::scanner::ScanPolicy::ReuseStrongFingerprint);
    ASSERT_TRUE(initial_scan.has_value());

    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto runtime_data = make_runtime_data(profile, local, storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto hash_a = kasumi::hasher::hash_string("AAAA");
    const auto hash_c = kasumi::hasher::hash_string("CCCC");

    const kasumi::Snapshot base_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true},
                 kasumi::NodeRow{.path = "file.txt", .hash = hash_a, .size = 4}}};

    const auto prepared_base =
        kasumi::application::sync::publication::prepare_commit(
            base_tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared_base.has_value());
    const auto published_base =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_base, profile);
    ASSERT_TRUE(published_base.has_value());

    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        kasumi::state_storage::StoredState{
            .tree = base_tree,
            .height = prepared_base->commit.height,
            .commit_id = published_base->head.commit_id,
            .ciphertext_id = published_base->head.ciphertext_id,
        }));

    kasumi::Snapshot remote_tree = base_tree;
    kasumi::find_row(remote_tree, "file.txt")->hash = hash_c;
    const std::array base_parents{published_base->head.commit_id};
    const auto prepared_remote =
        kasumi::application::sync::publication::prepare_commit(
            remote_tree, true, prepared_base->commit.height,
            base_parents, 101, key);
    ASSERT_TRUE(prepared_remote.has_value());
    const auto published_remote =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_remote, profile);
    ASSERT_TRUE(published_remote.has_value());

    const auto remote_payload = kasumi::test::workspace_path(workspace, "payload.bin");
    kasumi::test::write_text(remote_payload, "CCCC");
    add_storage_payload(*storage, remote_payload, hash_c);

    kasumi::application::observation::LocalObservationSession session{};
    session.cache = initial_scan->cache;

    auto observed = kasumi::application::observation::collect_reconciliation_input(
        runtime_data, *storage, key, false, {}, &session);
    ASSERT_TRUE(observed.has_value());
    auto result = kasumi::reconciliation::reconcile(*observed);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->plan.operations.front().action, kasumi::Action::Download);

    // Concurrently remove file.txt on disk before stabilize
    std::filesystem::remove(local_file);

    const auto stable = kasumi::application::sync::coordinator::reobservation::stabilize(
        runtime_data, *storage, key, *observed, *result, &session);
    ASSERT_FALSE(stable.has_value());
    EXPECT_EQ(stable.error().code,
              kasumi::application::sync::coordinator::ErrorCode::ObservationFailure);
}

TEST(ReobservationSafeguardTest, DestructiveSafeguardFailsClosedWhenDownloadTargetReplacedByDirectory) {
    auto workspace = kasumi::test::make_temp_workspace("safeguard-dl-replaced-dir");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path = kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto local_file = local / "file.txt";

    kasumi::test::write_text(local_file, "AAAA");
    const auto initial_scan = kasumi::application::observation::scanner::scan_result(
        local, {}, kasumi::application::observation::scanner::ScanPolicy::ReuseStrongFingerprint);
    ASSERT_TRUE(initial_scan.has_value());

    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto runtime_data = make_runtime_data(profile, local, storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto hash_a = kasumi::hasher::hash_string("AAAA");
    const auto hash_c = kasumi::hasher::hash_string("CCCC");

    const kasumi::Snapshot base_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true},
                 kasumi::NodeRow{.path = "file.txt", .hash = hash_a, .size = 4}}};

    const auto prepared_base =
        kasumi::application::sync::publication::prepare_commit(
            base_tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared_base.has_value());
    const auto published_base =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_base, profile);
    ASSERT_TRUE(published_base.has_value());

    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        kasumi::state_storage::StoredState{
            .tree = base_tree,
            .height = prepared_base->commit.height,
            .commit_id = published_base->head.commit_id,
            .ciphertext_id = published_base->head.ciphertext_id,
        }));

    kasumi::Snapshot remote_tree = base_tree;
    kasumi::find_row(remote_tree, "file.txt")->hash = hash_c;
    const std::array base_parents{published_base->head.commit_id};
    const auto prepared_remote =
        kasumi::application::sync::publication::prepare_commit(
            remote_tree, true, prepared_base->commit.height,
            base_parents, 101, key);
    ASSERT_TRUE(prepared_remote.has_value());
    const auto published_remote =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_remote, profile);
    ASSERT_TRUE(published_remote.has_value());

    const auto remote_payload = kasumi::test::workspace_path(workspace, "payload.bin");
    kasumi::test::write_text(remote_payload, "CCCC");
    add_storage_payload(*storage, remote_payload, hash_c);

    kasumi::application::observation::LocalObservationSession session{};
    session.cache = initial_scan->cache;

    auto observed = kasumi::application::observation::collect_reconciliation_input(
        runtime_data, *storage, key, false, {}, &session);
    ASSERT_TRUE(observed.has_value());
    auto result = kasumi::reconciliation::reconcile(*observed);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->plan.operations.front().action, kasumi::Action::Download);

    // Concurrently replace file.txt on disk with directory before stabilize
    std::filesystem::remove(local_file);
    ASSERT_TRUE(std::filesystem::create_directory(local_file));

    const auto stable = kasumi::application::sync::coordinator::reobservation::stabilize(
        runtime_data, *storage, key, *observed, *result, &session);
    ASSERT_FALSE(stable.has_value());
    EXPECT_EQ(stable.error().code,
              kasumi::application::sync::coordinator::ErrorCode::ObservationFailure);
}

TEST(ReobservationSafeguardTest, DestructiveSafeguardFailsClosedWhenDeleteTargetDisappears) {
    auto workspace = kasumi::test::make_temp_workspace("safeguard-del-disappears");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path = kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto local_file = local / "file.txt";

    kasumi::test::write_text(local_file, "AAAA");
    const auto initial_scan = kasumi::application::observation::scanner::scan_result(
        local, {}, kasumi::application::observation::scanner::ScanPolicy::ReuseStrongFingerprint);
    ASSERT_TRUE(initial_scan.has_value());

    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto runtime_data = make_runtime_data(profile, local, storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto hash_a = kasumi::hasher::hash_string("AAAA");

    const kasumi::Snapshot base_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true},
                 kasumi::NodeRow{.path = "file.txt", .hash = hash_a, .size = 4}}};

    const auto prepared_base =
        kasumi::application::sync::publication::prepare_commit(
            base_tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared_base.has_value());
    const auto published_base =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_base, profile);
    ASSERT_TRUE(published_base.has_value());

    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        kasumi::state_storage::StoredState{
            .tree = base_tree,
            .height = prepared_base->commit.height,
            .commit_id = published_base->head.commit_id,
            .ciphertext_id = published_base->head.ciphertext_id,
        }));

    // Remote deletes file.txt
    const kasumi::Snapshot remote_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    const std::array base_parents{published_base->head.commit_id};
    const auto prepared_remote =
        kasumi::application::sync::publication::prepare_commit(
            remote_tree, true, prepared_base->commit.height,
            base_parents, 101, key);
    ASSERT_TRUE(prepared_remote.has_value());
    const auto published_remote =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_remote, profile);
    ASSERT_TRUE(published_remote.has_value());

    kasumi::application::observation::LocalObservationSession session{};
    session.cache = initial_scan->cache;

    auto observed = kasumi::application::observation::collect_reconciliation_input(
        runtime_data, *storage, key, false, {}, &session);
    ASSERT_TRUE(observed.has_value());
    auto result = kasumi::reconciliation::reconcile(*observed);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->plan.operations.front().action, kasumi::Action::DeleteLocal);

    // Concurrently remove file.txt on disk before stabilize
    std::filesystem::remove(local_file);

    const auto stable = kasumi::application::sync::coordinator::reobservation::stabilize(
        runtime_data, *storage, key, *observed, *result, &session);
    ASSERT_FALSE(stable.has_value());
    EXPECT_EQ(stable.error().code,
              kasumi::application::sync::coordinator::ErrorCode::ObservationFailure);
}

TEST(ReobservationSafeguardTest, DestructiveSafeguardFailsClosedWhenDeleteTargetReplacedByDirectory) {
    auto workspace = kasumi::test::make_temp_workspace("safeguard-del-replaced-dir");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path = kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto local_file = local / "file.txt";

    kasumi::test::write_text(local_file, "AAAA");
    const auto initial_scan = kasumi::application::observation::scanner::scan_result(
        local, {}, kasumi::application::observation::scanner::ScanPolicy::ReuseStrongFingerprint);
    ASSERT_TRUE(initial_scan.has_value());

    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto runtime_data = make_runtime_data(profile, local, storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto hash_a = kasumi::hasher::hash_string("AAAA");

    const kasumi::Snapshot base_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true},
                 kasumi::NodeRow{.path = "file.txt", .hash = hash_a, .size = 4}}};

    const auto prepared_base =
        kasumi::application::sync::publication::prepare_commit(
            base_tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared_base.has_value());
    const auto published_base =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_base, profile);
    ASSERT_TRUE(published_base.has_value());

    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        kasumi::state_storage::StoredState{
            .tree = base_tree,
            .height = prepared_base->commit.height,
            .commit_id = published_base->head.commit_id,
            .ciphertext_id = published_base->head.ciphertext_id,
        }));

    // Remote deletes file.txt
    const kasumi::Snapshot remote_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    const std::array base_parents{published_base->head.commit_id};
    const auto prepared_remote =
        kasumi::application::sync::publication::prepare_commit(
            remote_tree, true, prepared_base->commit.height,
            base_parents, 101, key);
    ASSERT_TRUE(prepared_remote.has_value());
    const auto published_remote =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_remote, profile);
    ASSERT_TRUE(published_remote.has_value());

    kasumi::application::observation::LocalObservationSession session{};
    session.cache = initial_scan->cache;

    auto observed = kasumi::application::observation::collect_reconciliation_input(
        runtime_data, *storage, key, false, {}, &session);
    ASSERT_TRUE(observed.has_value());
    auto result = kasumi::reconciliation::reconcile(*observed);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->plan.operations.front().action, kasumi::Action::DeleteLocal);

    // Concurrently replace file.txt on disk with directory before stabilize
    std::filesystem::remove(local_file);
    ASSERT_TRUE(std::filesystem::create_directory(local_file));

    const auto stable = kasumi::application::sync::coordinator::reobservation::stabilize(
        runtime_data, *storage, key, *observed, *result, &session);
    ASSERT_FALSE(stable.has_value());
    EXPECT_EQ(stable.error().code,
              kasumi::application::sync::coordinator::ErrorCode::ObservationFailure);
}

TEST(ReobservationSafeguardTest, DestructiveSafeguardFailsClosedWhenDownloadDestinationAlreadyExists) {
    auto workspace = kasumi::test::make_temp_workspace("safeguard-dl-dest-exists");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path = kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto new_file = local / "new.txt";

    const auto initial_scan = kasumi::application::observation::scanner::scan_result(
        local, {}, kasumi::application::observation::scanner::ScanPolicy::ReuseStrongFingerprint);
    ASSERT_TRUE(initial_scan.has_value());

    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto runtime_data = make_runtime_data(profile, local, storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto hash_new = kasumi::hasher::hash_string("NEW_CONTENT");

    const kasumi::Snapshot base_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};

    const auto prepared_base =
        kasumi::application::sync::publication::prepare_commit(
            base_tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared_base.has_value());
    const auto published_base =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_base, profile);
    ASSERT_TRUE(published_base.has_value());

    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        kasumi::state_storage::StoredState{
            .tree = base_tree,
            .height = prepared_base->commit.height,
            .commit_id = published_base->head.commit_id,
            .ciphertext_id = published_base->head.ciphertext_id,
        }));

    // Remote adds new.txt
    const kasumi::Snapshot remote_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true},
                 kasumi::NodeRow{.path = "new.txt", .hash = hash_new, .size = 11}}};
    const std::array base_parents{published_base->head.commit_id};
    const auto prepared_remote =
        kasumi::application::sync::publication::prepare_commit(
            remote_tree, true, prepared_base->commit.height,
            base_parents, 101, key);
    ASSERT_TRUE(prepared_remote.has_value());
    const auto published_remote =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_remote, profile);
    ASSERT_TRUE(published_remote.has_value());

    const auto remote_payload = kasumi::test::workspace_path(workspace, "payload_new.bin");
    kasumi::test::write_text(remote_payload, "NEW_CONTENT");
    add_storage_payload(*storage, remote_payload, hash_new);

    kasumi::application::observation::LocalObservationSession session{};
    session.cache = initial_scan->cache;

    auto observed = kasumi::application::observation::collect_reconciliation_input(
        runtime_data, *storage, key, false, {}, &session);
    ASSERT_TRUE(observed.has_value());
    auto result = kasumi::reconciliation::reconcile(*observed);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->plan.operations.front().action, kasumi::Action::Download);

    // Concurrently create new.txt on disk before stabilize
    kasumi::test::write_text(new_file, "UNEXPECTED_LOCAL_CREATION");

    const auto stable = kasumi::application::sync::coordinator::reobservation::stabilize(
        runtime_data, *storage, key, *observed, *result, &session);
    ASSERT_FALSE(stable.has_value());
    EXPECT_EQ(stable.error().code,
              kasumi::application::sync::coordinator::ErrorCode::ObservationFailure);
}

TEST(ReobservationSafeguardTest, DestructiveSafeguardAllowsCleanDownloadWhenDestinationAbsent) {
    auto workspace = kasumi::test::make_temp_workspace("safeguard-dl-clean");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path = kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto new_file = local / "new.txt";

    const auto initial_scan = kasumi::application::observation::scanner::scan_result(
        local, {}, kasumi::application::observation::scanner::ScanPolicy::ReuseStrongFingerprint);
    ASSERT_TRUE(initial_scan.has_value());

    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto runtime_data = make_runtime_data(profile, local, storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto hash_new = kasumi::hasher::hash_string("NEW_CONTENT");

    const kasumi::Snapshot base_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};

    const auto prepared_base =
        kasumi::application::sync::publication::prepare_commit(
            base_tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared_base.has_value());
    const auto published_base =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_base, profile);
    ASSERT_TRUE(published_base.has_value());

    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        kasumi::state_storage::StoredState{
            .tree = base_tree,
            .height = prepared_base->commit.height,
            .commit_id = published_base->head.commit_id,
            .ciphertext_id = published_base->head.ciphertext_id,
        }));

    // Remote adds new.txt
    const kasumi::Snapshot remote_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true},
                 kasumi::NodeRow{.path = "new.txt", .hash = hash_new, .size = 11}}};
    const std::array base_parents{published_base->head.commit_id};
    const auto prepared_remote =
        kasumi::application::sync::publication::prepare_commit(
            remote_tree, true, prepared_base->commit.height,
            base_parents, 101, key);
    ASSERT_TRUE(prepared_remote.has_value());
    const auto published_remote =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared_remote, profile);
    ASSERT_TRUE(published_remote.has_value());

    const auto remote_payload = kasumi::test::workspace_path(workspace, "payload_new.bin");
    kasumi::test::write_text(remote_payload, "NEW_CONTENT");
    add_storage_payload(*storage, remote_payload, hash_new);

    kasumi::application::observation::LocalObservationSession session{};
    session.cache = initial_scan->cache;

    auto observed = kasumi::application::observation::collect_reconciliation_input(
        runtime_data, *storage, key, false, {}, &session);
    ASSERT_TRUE(observed.has_value());
    auto result = kasumi::reconciliation::reconcile(*observed);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->plan.operations.front().action, kasumi::Action::Download);

    // Destination does not exist - must succeed
    EXPECT_FALSE(std::filesystem::exists(new_file));

    const auto stable = kasumi::application::sync::coordinator::reobservation::stabilize(
        runtime_data, *storage, key, *observed, *result, &session);
    ASSERT_TRUE(stable.has_value()) << stable.error().detail;
}

} // namespace


