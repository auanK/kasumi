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

TEST(ReobservationSafeguardTest, DestructiveSafeguardProtectsRenameLocal) {
    auto workspace = kasumi::test::make_temp_workspace("safeguard-rename-local");
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

    const auto hash_c = kasumi::hasher::hash_string("CCCC");
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

    // Modify file.txt on disk to "BBBB" with same size and restored mtime
    kasumi::test::write_text(local_file, "BBBB");
    std::filesystem::last_write_time(local_file, old_mtime);

    kasumi::application::observation::LocalObservationSession session{};
    session.cache = initial_scan->cache;

    auto observed = kasumi::application::observation::collect_reconciliation_input(
        runtime_data, *storage, key, false, {}, &session);
    ASSERT_TRUE(observed.has_value());

    auto result = kasumi::reconciliation::reconcile(*observed);
    ASSERT_TRUE(result.has_value());

    const auto stable = kasumi::application::sync::coordinator::reobservation::stabilize(
        runtime_data, *storage, key, *observed, *result, &session);
    ASSERT_TRUE(stable.has_value()) << stable.error().detail;

    // Verify that the safeguard inspected the source of RenameLocal, detected on-disk modification,
    // and updated local_tree to the real content hash!
    const auto* row = kasumi::find_row(stable->input.local_tree, "file.txt");
    ASSERT_NE(row, nullptr);
    EXPECT_EQ(row->hash, hash_b);
}

} // namespace

