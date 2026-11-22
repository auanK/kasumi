#define KASUMI_TEST_HISTORY_STORAGE_NO_ERROR_CODE_ALIAS
#include "application/execute.hpp"
#include "application/history_storage/epoch.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/publication.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/maintenance.hpp"
#include "application/integrity/repack.hpp"
#include "application/observation/history.hpp"
#include "application/sync/journal.hpp"
#include "core/history.hpp"
#include "crypto/pack.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/history_storage.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/clock.hpp"
#include "platform/metadata.hpp"
#include "runtime/machine.hpp"
#include "runtime/resolver.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace repack = kasumi::application::integrity::repack;
namespace integrity = kasumi::application::integrity;
namespace history_storage = kasumi::application::history_storage;
namespace protocol = kasumi::application::history_storage::maintenance_protocol;

using kasumi::application::Credentials;
using kasumi::application::ExecutionEnvironment;
using kasumi::application::MasterKeyHex;
using kasumi::application::Operation;
using kasumi::application::Request;
using kasumi::application::SyncCompleted;
using kasumi::runtime::AccessMode;
using kasumi::runtime::RuntimeData;
using kasumi::test::TempWorkspace;

struct MachineEnv {
    std::filesystem::path app_dir;
    std::filesystem::path local_dir;
    std::filesystem::path remote_dir;
    std::string profile_name = "demo";

    ExecutionEnvironment env() const {
        return ExecutionEnvironment{app_dir};
    }

    Credentials creds() const {
        return Credentials{MasterKeyHex{test_key_hex()}};
    }

    RuntimeData resolve(AccessMode mode = AccessMode::ReadWrite) const {
        auto resolved = kasumi::runtime::resolve(app_dir, profile_name, mode);
        EXPECT_TRUE(resolved.has_value()) << resolved.error().detail;
        return *resolved;
    }
};

void init_remote(const std::filesystem::path& remote_dir) {
    auto storage = kasumi::transport::open_transport(remote_dir.string());
    ASSERT_TRUE(storage.has_value()) << storage.error().message;
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
}

MachineEnv create_machine(const TempWorkspace& workspace,
                          std::string_view tag,
                          const std::filesystem::path& remote_dir,
                          bool initialize_db = true) {
    const auto app = kasumi::test::workspace_path(workspace, std::string{tag} + "_app");
    const auto local =
        kasumi::test::workspace_path(workspace, std::string{tag} + "_local");
    std::filesystem::create_directories(app / "profiles" / "demo");
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(remote_dir);

    kasumi::test::write_text(
        app / "config.toml",
        "[profiles.demo]\n"
        "local_dir = '" + local.string() + "'\n"
        "remote_dir = '" + remote_dir.string() + "'\n"
        "min_history_depth = 5\n"
        "min_history_age_hours = 6\n"
        "key_storage = 'file'\n");
    if (initialize_db) {
        EXPECT_TRUE(kasumi::state_storage::initialize(
            app / "profiles" / "demo" / "db.sqlite"));
    }
    return MachineEnv{
        .app_dir = app,
        .local_dir = local,
        .remote_dir = remote_dir,
        .profile_name = "demo",
    };
}

void write_settled_file(const std::filesystem::path& path,
                        std::string_view contents) {
    kasumi::test::write_text(path, contents);
    const auto settled =
        std::filesystem::file_time_type::clock::now() - std::chrono::seconds{2};
    ASSERT_TRUE(kasumi::platform::metadata::set_last_write_time(path, settled));
}

kasumi::application::Response run_sync(const MachineEnv& machine,
                                       bool initial = false) {
    auto res = kasumi::application::execute(
        {Request{.operation = Operation::Sync,
                 .profile_name = machine.profile_name,
                 .initial = initial},
         machine.creds(),
         machine.env()});
    EXPECT_TRUE(res.has_value()) << res.error().detail;
    return std::move(*res);
}

std::vector<kasumi::Hash> unique_pack_hashes(
    const kasumi::history::StorageManifest& manifest) {
    std::vector<kasumi::Hash> hashes;
    hashes.reserve(manifest.packed_blobs.size());
    for (const auto& entry : manifest.packed_blobs) {
        hashes.push_back(entry.pack_hash);
    }
    std::ranges::sort(hashes);
    hashes.erase(std::ranges::unique(hashes).begin(), hashes.end());
    return hashes;
}

struct WrappedStorageContext {
    kasumi::transport::Transport inner;
    std::string target_put_identifier;
    std::function<void()> on_target_put;
    std::function<void(const std::filesystem::path&, std::string_view)> on_put;
    bool fired = false;
};

kasumi::transport::Result wrapped_init(void* ctx) {
    auto* state = static_cast<WrappedStorageContext*>(ctx);
    return kasumi::transport::initialize(state->inner);
}

kasumi::transport::Result wrapped_put(void* ctx,
                                      const std::filesystem::path& source,
                                      std::string_view identifier) {
    auto* state = static_cast<WrappedStorageContext*>(ctx);
    if (state->on_put) {
        state->on_put(source, identifier);
    }
    auto res = kasumi::transport::put(state->inner, source, identifier);
    if (res && !state->fired && identifier == state->target_put_identifier) {
        state->fired = true;
        if (state->on_target_put) {
            state->on_target_put();
        }
    }
    return res;
}

kasumi::transport::Result wrapped_get(void* ctx,
                                      std::string_view identifier,
                                      const std::filesystem::path& dest) {
    auto* state = static_cast<WrappedStorageContext*>(ctx);
    return kasumi::transport::get(state->inner, identifier, dest);
}

kasumi::transport::PresenceResult wrapped_presence(void* ctx,
                                                   std::string_view identifier) {
    auto* state = static_cast<WrappedStorageContext*>(ctx);
    return kasumi::transport::presence(state->inner, identifier);
}

kasumi::transport::ListingResult wrapped_list(void* ctx) {
    auto* state = static_cast<WrappedStorageContext*>(ctx);
    return kasumi::transport::list(state->inner);
}

kasumi::transport::ListingResult wrapped_list_prefix(void* ctx,
                                                     std::string_view prefix) {
    auto* state = static_cast<WrappedStorageContext*>(ctx);
    return kasumi::transport::list(state->inner, prefix);
}

kasumi::transport::RemovalResult wrapped_remove(void* ctx,
                                                std::string_view identifier) {
    auto* state = static_cast<WrappedStorageContext*>(ctx);
    return kasumi::transport::remove(state->inner, identifier);
}

std::expected<std::string, kasumi::transport::Error>
wrapped_physical_hash(void* ctx,
                      std::string_view identifier,
                      std::string_view algo) {
    auto* state = static_cast<WrappedStorageContext*>(ctx);
    return kasumi::transport::physical_hash(state->inner, identifier, algo);
}

void destroy_wrapped(void* raw) noexcept {
    delete static_cast<WrappedStorageContext*>(raw);
}

kasumi::transport::Transport make_wrapped_transport(
    kasumi::transport::Transport inner,
    std::string target_put_identifier,
    std::function<void()> on_target_put,
    std::function<void(const std::filesystem::path&, std::string_view)> on_put =
        {}) {
    auto* ctx = new WrappedStorageContext{
        .inner = std::move(inner),
        .target_put_identifier = std::move(target_put_identifier),
        .on_target_put = std::move(on_target_put),
        .on_put = std::move(on_put),
    };
    return kasumi::transport::Transport{
        .state = kasumi::transport::TransportStateHandle{ctx, &destroy_wrapped},
        .storage =
            kasumi::transport::StorageOperations{
                .initialize = wrapped_init,
                .put = wrapped_put,
                .get = wrapped_get,
                .presence = wrapped_presence,
                .list = wrapped_list,
                .list_prefix = wrapped_list_prefix,
                .physical_hash = ctx->inner.storage.physical_hash
                                     ? wrapped_physical_hash
                                     : nullptr,
                .remove = wrapped_remove,
            },
    };
}

TEST(RepackTest, ConsolidatesLooseSmallFilesWithDryRunFsckAndIdempotency) {
    const auto ws = kasumi::test::make_temp_workspace("repack-loose");
    const auto remote = kasumi::test::workspace_path(ws, "remote");
    init_remote(remote);
    const auto machine = create_machine(ws, "a", remote);
    const auto key = test_key();
    const auto layout = test_layout();

    // Sync 3 small files across separate syncs so local transport leaves them as
    // loose objects (local threshold is 16).
    for (int i = 0; i < 3; ++i) {
        write_settled_file(machine.local_dir / ("note_" + std::to_string(i) + ".txt"),
                           "small loose payload number " + std::to_string(i));
        run_sync(machine);
    }

    const auto runtime = machine.resolve();
    auto storage = kasumi::transport::open_transport(runtime.storage_location,
                                                     runtime.local_dir);
    ASSERT_TRUE(storage.has_value());

    const auto before_state = kasumi::state_storage::load_state(runtime.database_path);
    ASSERT_TRUE(before_state.has_value() && before_state->has_value());
    const auto before_listing = kasumi::transport::list(*storage);
    ASSERT_TRUE(before_listing.has_value());

    // Dry-run plans the pack without touching remote objects or local db.sqlite.
    const auto dry = repack::execute(runtime, *storage, key, {.dry_run = true});
    ASSERT_TRUE(dry.has_value()) << dry.error().detail;
    EXPECT_TRUE(dry->dry_run);
    EXPECT_FALSE(dry->published);
    EXPECT_TRUE(dry->plan.actionable);
    EXPECT_EQ(dry->plan.source_loose_blobs, 3U);
    EXPECT_EQ(dry->plan.new_packs.size(), 1U);
    EXPECT_EQ(dry->wire_upload_bytes, 0U);
    EXPECT_EQ(*kasumi::transport::list(*storage), *before_listing);
    EXPECT_EQ((*kasumi::state_storage::load_state(runtime.database_path))->commit_id,
              (*before_state)->commit_id);

    // Real repack publishes the pack and updates commit + db.sqlite.
    const auto exec = repack::execute(runtime, *storage, key);
    ASSERT_TRUE(exec.has_value()) << exec.error().detail;
    EXPECT_FALSE(exec->dry_run);
    EXPECT_TRUE(exec->published);
    EXPECT_NE(exec->published_commit_id, (*before_state)->commit_id);
    EXPECT_EQ(exec->published_height, (*before_state)->height + 1);
    EXPECT_GE(exec->pruned_markers, 1U);
    EXPECT_GT(exec->wire_upload_bytes, 0U);
    EXPECT_GE(exec->physical_objects_uploaded, 1U);

    const auto after_state = kasumi::state_storage::load_state(runtime.database_path);
    ASSERT_TRUE(after_state.has_value() && after_state->has_value());
    EXPECT_EQ((*after_state)->commit_id, exec->published_commit_id);
    EXPECT_EQ((*after_state)->tree, (*before_state)->tree);
    EXPECT_EQ((*after_state)->storage_manifest.packed_blobs.size(), 3U);

    // No lingering writer marker remains on remote.
    const auto writers = protocol::active_writers(*storage, layout);
    ASSERT_TRUE(writers.has_value());
    EXPECT_TRUE(writers->empty());

    // Remote integrity audit succeeds on the repacked history.
    const auto audited = integrity::fsck(runtime, *storage, key, 1);
    ASSERT_TRUE(audited.has_value()) << audited.error().detail;

    // Second repack is a clean no-op with zero uploads.
    const auto second = repack::execute(runtime, *storage, key);
    ASSERT_TRUE(second.has_value()) << second.error().detail;
    EXPECT_FALSE(second->published);
    EXPECT_FALSE(second->plan.actionable);
    EXPECT_EQ(second->wire_upload_bytes, 0U);
    EXPECT_EQ(second->physical_objects_uploaded, 0U);
}

TEST(RepackTest, ReclaimsDirtyPackSecondMachineFastForwardsAndFreshMachineEnrolls) {
    const auto ws = kasumi::test::make_temp_workspace("repack-multi-machine");
    const auto remote = kasumi::test::workspace_path(ws, "remote");
    init_remote(remote);
    const auto machine_a = create_machine(ws, "a", remote);
    const auto machine_b = create_machine(ws, "b", remote);
    const auto machine_c = create_machine(ws, "c", remote, false);
    const auto key = test_key();

    // Sync 18 small files at once on Machine A so local transport creates P_old.
    for (int i = 0; i < 18; ++i) {
        write_settled_file(
            machine_a.local_dir / ("item_" + std::to_string(i) + ".txt"),
            std::string(2048, static_cast<char>('a' + i)));
    }
    run_sync(machine_a);

    const auto runtime_a = machine_a.resolve();
    const auto init_state = kasumi::state_storage::load_state(runtime_a.database_path);
    ASSERT_TRUE(init_state.has_value() && init_state->has_value());
    const auto initial_packs = unique_pack_hashes((*init_state)->storage_manifest);
    ASSERT_EQ(initial_packs.size(), 1U);
    const auto p_old = initial_packs.front();

    // Delete 16 files and sync so P_old now contains mostly dead blobs.
    for (int i = 2; i < 18; ++i) {
        std::filesystem::remove(
            machine_a.local_dir / ("item_" + std::to_string(i) + ".txt"));
    }
    run_sync(machine_a);

    // Machine B syncs to the 2 surviving files while still referencing P_old.
    run_sync(machine_b);

    // Machine A repacks the dirty pack into P_new.
    auto storage = kasumi::transport::open_transport(runtime_a.storage_location,
                                                     runtime_a.local_dir);
    ASSERT_TRUE(storage.has_value());
    const auto repacked = repack::execute(runtime_a, *storage, key);
    ASSERT_TRUE(repacked.has_value()) << repacked.error().detail;
    ASSERT_TRUE(repacked->published);
    ASSERT_EQ(repacked->plan.source_dirty_packs, 1U);
    ASSERT_EQ(repacked->plan.new_packs.size(), 1U);
    const auto p_new = repacked->plan.new_packs.front().pack_hash;
    EXPECT_NE(p_new, p_old);

    const auto audited = integrity::fsck(runtime_a, *storage, key, 1);
    ASSERT_TRUE(audited.has_value()) << audited.error().detail;

    // Machine B fast-forwards to the repacked commit with zero downloads/mutations.
    const auto sync_b = run_sync(machine_b);
    const auto* summary_b = std::get_if<SyncCompleted>(&sync_b.data);
    ASSERT_NE(summary_b, nullptr);
    EXPECT_EQ(summary_b->downloaded, 0U);
    EXPECT_EQ(summary_b->uploaded, 0U);
    EXPECT_EQ(summary_b->total, 0U);
    const auto state_b =
        kasumi::state_storage::load_state(machine_b.resolve().database_path);
    ASSERT_TRUE(state_b.has_value() && state_b->has_value());
    EXPECT_EQ((*state_b)->commit_id, repacked->published_commit_id);
    EXPECT_EQ(unique_pack_hashes((*state_b)->storage_manifest),
              std::vector{p_new});

    // Fresh Machine C enrolls using initial sync and downloads from P_new.
    run_sync(machine_c, true);
    EXPECT_EQ(
        kasumi::test::read_text(machine_c.local_dir / "item_0.txt"),
        kasumi::test::read_text(machine_a.local_dir / "item_0.txt"));
    EXPECT_EQ(
        kasumi::test::read_text(machine_c.local_dir / "item_1.txt"),
        kasumi::test::read_text(machine_a.local_dir / "item_1.txt"));
    EXPECT_FALSE(std::filesystem::exists(machine_c.local_dir / "item_2.txt"));
}

TEST(RepackTest, RejectsDirtyLocalWorkspaceUnsyncedRemoteAndEmptyHistory) {
    const auto key = test_key();
    const auto layout = test_layout();

    // Case 1: Empty remote history.
    {
        const auto ws = kasumi::test::make_temp_workspace("repack-empty-history");
        const auto remote = kasumi::test::workspace_path(ws, "remote");
        init_remote(remote);
        const auto machine = create_machine(ws, "a", remote);
        const auto runtime = machine.resolve();
        auto storage = kasumi::transport::open_transport(
            runtime.storage_location, runtime.local_dir);
        ASSERT_TRUE(storage.has_value());
        const auto res = repack::execute(runtime, *storage, key);
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error().code, integrity::ErrorCode::StateFailure);
        EXPECT_TRUE(protocol::active_writers(*storage, layout)->empty());
    }

    // Case 2: Local workspace has unsynced file changes.
    {
        const auto ws = kasumi::test::make_temp_workspace("repack-dirty-local");
        const auto remote = kasumi::test::workspace_path(ws, "remote");
        init_remote(remote);
        const auto machine = create_machine(ws, "a", remote);
        write_settled_file(machine.local_dir / "synced.txt", "v1");
        run_sync(machine);
        write_settled_file(machine.local_dir / "unsynced.txt", "dirty local");

        const auto runtime = machine.resolve();
        auto storage = kasumi::transport::open_transport(
            runtime.storage_location, runtime.local_dir);
        ASSERT_TRUE(storage.has_value());
        const auto before_listing = kasumi::transport::list(*storage);
        ASSERT_TRUE(before_listing.has_value());

        const auto res = repack::execute(runtime, *storage, key);
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error().code, integrity::ErrorCode::StateFailure);
        EXPECT_EQ(*kasumi::transport::list(*storage), *before_listing);
        EXPECT_TRUE(protocol::active_writers(*storage, layout)->empty());
    }

    // Case 3: Remote has a newer commit not yet synced to local db.sqlite.
    {
        const auto ws = kasumi::test::make_temp_workspace("repack-behind-remote");
        const auto remote = kasumi::test::workspace_path(ws, "remote");
        init_remote(remote);
        const auto machine_a = create_machine(ws, "a", remote);
        const auto machine_b = create_machine(ws, "b", remote);
        write_settled_file(machine_a.local_dir / "base.txt", "base");
        run_sync(machine_a);
        run_sync(machine_b);

        write_settled_file(machine_b.local_dir / "newer.txt", "remote newer");
        run_sync(machine_b);

        const auto runtime_a = machine_a.resolve();
        auto storage = kasumi::transport::open_transport(
            runtime_a.storage_location, runtime_a.local_dir);
        ASSERT_TRUE(storage.has_value());
        const auto res = repack::execute(runtime_a, *storage, key);
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error().code, integrity::ErrorCode::StateFailure);
        EXPECT_TRUE(protocol::active_writers(*storage, layout)->empty());
    }
}

TEST(RepackTest, RejectsWhenGcBarrierIsActive) {
    const auto ws = kasumi::test::make_temp_workspace("repack-barrier");
    const auto remote = kasumi::test::workspace_path(ws, "remote");
    init_remote(remote);
    const auto machine = create_machine(ws, "a", remote);
    const auto key = test_key();
    const auto layout = test_layout();

    for (int i = 0; i < 3; ++i) {
        write_settled_file(machine.local_dir / ("f_" + std::to_string(i) + ".txt"),
                           "barrier payload " + std::to_string(i));
        run_sync(machine);
    }

    const auto runtime = machine.resolve();
    auto storage = kasumi::transport::open_transport(runtime.storage_location,
                                                     runtime.local_dir);
    ASSERT_TRUE(storage.has_value());

    const auto before_listing = kasumi::transport::list(*storage);
    ASSERT_TRUE(before_listing.has_value());

    auto barrier = protocol::establish_barrier(
        *storage, layout, runtime.database_path.parent_path());
    ASSERT_TRUE(barrier.has_value()) << barrier.error().detail;

    const auto res = repack::execute(runtime, *storage, key);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, integrity::ErrorCode::ConcurrentChange);
    EXPECT_TRUE(protocol::active_writers(*storage, layout)->empty());

    ASSERT_TRUE(protocol::release_registration(*barrier).has_value());
    EXPECT_EQ(*kasumi::transport::list(*storage), *before_listing);
}

TEST(RepackTest, RejectsOnConcurrentRemoteHeadWithoutPublishingDivergentCommit) {
    const auto ws = kasumi::test::make_temp_workspace("repack-concurrent-head");
    const auto remote = kasumi::test::workspace_path(ws, "remote");
    init_remote(remote);
    const auto machine_a = create_machine(ws, "a", remote);
    const auto machine_b = create_machine(ws, "b", remote);
    const auto key = test_key();
    const auto layout = test_layout();

    for (int i = 0; i < 3; ++i) {
        write_settled_file(machine_a.local_dir / ("f_" + std::to_string(i) + ".txt"),
                           "concurrent test payload " + std::to_string(i));
        run_sync(machine_a);
    }
    run_sync(machine_b);

    const auto runtime_a = machine_a.resolve();
    const auto before_state =
        kasumi::state_storage::load_state(runtime_a.database_path);
    ASSERT_TRUE(before_state.has_value() && before_state->has_value());

    // Precompute the pack identifier repack will upload via dry-run.
    auto inner = kasumi::transport::open_transport(runtime_a.storage_location,
                                                   runtime_a.local_dir);
    ASSERT_TRUE(inner.has_value());
    const auto dry = repack::execute(runtime_a, *inner, key, {.dry_run = true});
    ASSERT_TRUE(dry.has_value());
    ASSERT_EQ(dry->plan.new_packs.size(), 1U);
    const auto target_pack_id =
        kasumi::crypto::pack_identifier(key, dry->plan.new_packs[0].pack_hash);

    std::string concurrent_commit_id;
    auto wrapped = make_wrapped_transport(
        std::move(*inner),
        target_pack_id,
        [&] {
            write_settled_file(machine_b.local_dir / "concurrent_b.txt",
                               "published while repack was uploading");
            run_sync(machine_b);
            const auto state_b = kasumi::state_storage::load_state(
                machine_b.resolve().database_path);
            ASSERT_TRUE(state_b.has_value() && state_b->has_value());
            concurrent_commit_id = (*state_b)->commit_id;
        });

    const auto res = repack::execute(runtime_a, wrapped, key);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, integrity::ErrorCode::ConcurrentChange);

    // Local db.sqlite must stay at before_state and remote head must be only
    // Machine B's concurrent commit (repack did not publish a divergent commit).
    const auto after_a =
        kasumi::state_storage::load_state(runtime_a.database_path);
    ASSERT_TRUE(after_a.has_value() && after_a->has_value());
    EXPECT_EQ((*after_a)->commit_id, (*before_state)->commit_id);

    auto check_storage = kasumi::transport::open_transport(
        runtime_a.storage_location, runtime_a.local_dir);
    ASSERT_TRUE(check_storage.has_value());
    EXPECT_TRUE(protocol::active_writers(*check_storage, layout)->empty());
    const auto heads =
        history_storage::list_remote_head_commit_ids(*check_storage, layout);
    ASSERT_TRUE(heads.has_value());
    EXPECT_EQ(*heads, std::vector{concurrent_commit_id});
}

TEST(RepackTest, DryRunRefusesPendingJournalWithoutMutatingFiles) {
    const auto ws = kasumi::test::make_temp_workspace("repack-dry-journal");
    const auto remote = kasumi::test::workspace_path(ws, "remote");
    init_remote(remote);
    const auto machine = create_machine(ws, "a", remote);
    const auto key = test_key();

    write_settled_file(machine.local_dir / "a.txt", "payload");
    run_sync(machine);

    const auto runtime = machine.resolve();
    const auto profile_dir = runtime.database_path.parent_path();
    const auto paths = kasumi::application::sync::journal::make_paths(profile_dir);
    ASSERT_TRUE(paths.has_value());

    const auto state = kasumi::state_storage::load_state(runtime.database_path);
    ASSERT_TRUE(state.has_value() && state->has_value());
    auto record = kasumi::application::sync::journal::create_record(
        (*state)->height,
        (*state)->height,
        kasumi::SyncPlan{},
        false,
        (*state)->commit_id);
    ASSERT_TRUE(record.has_value());
    ASSERT_TRUE(kasumi::application::sync::journal::save(
        *paths, *record, key, kasumi::application::sync::journal::SaveMode::Advance));
    ASSERT_EQ(kasumi::application::sync::journal::inspect(*paths, key),
              kasumi::application::sync::journal::InspectionResult::Active);

    auto storage = kasumi::transport::open_transport(runtime.storage_location,
                                                     runtime.local_dir);
    ASSERT_TRUE(storage.has_value());
    const auto res = repack::execute(runtime, *storage, key, {.dry_run = true});
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, integrity::ErrorCode::StateFailure);
    EXPECT_EQ(kasumi::application::sync::journal::inspect(*paths, key),
              kasumi::application::sync::journal::InspectionResult::Active);
}

TEST(RepackTest, OldDirtyPackIsCollectedByGcAfterEpochAdvances) {
    const auto ws = kasumi::test::make_temp_workspace("repack-gc-collect");
    const auto remote = kasumi::test::workspace_path(ws, "remote");
    init_remote(remote);
    const auto machine = create_machine(ws, "a", remote);
    const auto key = test_key();

    for (int i = 0; i < 18; ++i) {
        write_settled_file(
            machine.local_dir / ("gc_" + std::to_string(i) + ".txt"),
            std::string(2048, static_cast<char>('A' + i)));
    }
    run_sync(machine);

    const auto runtime = machine.resolve();
    const auto state_0 = kasumi::state_storage::load_state(runtime.database_path);
    ASSERT_TRUE(state_0.has_value() && state_0->has_value());
    const auto p_old = unique_pack_hashes((*state_0)->storage_manifest).front();
    const auto p_old_id = kasumi::crypto::pack_identifier(key, p_old);

    for (int i = 2; i < 18; ++i) {
        std::filesystem::remove(
            machine.local_dir / ("gc_" + std::to_string(i) + ".txt"));
    }
    run_sync(machine);

    auto storage = kasumi::transport::open_transport(runtime.storage_location,
                                                     runtime.local_dir);
    ASSERT_TRUE(storage.has_value());
    const auto repacked = repack::execute(runtime, *storage, key);
    ASSERT_TRUE(repacked.has_value()) << repacked.error().detail;
    ASSERT_TRUE(repacked->published);
    ASSERT_EQ(repacked->plan.new_packs.size(), 1U);
    const auto p_new_id =
        kasumi::crypto::pack_identifier(key, repacked->plan.new_packs[0].pack_hash);

    // Anchor an Epoch advancing from the vault's genesis Epoch at the repacked
    // commit so commits referencing P_old fall outside reachable ancestry for GC.
    const auto latest_epoch = history_storage::epoch::load_latest(
        *storage, key, kasumi::test::workspace_root(ws));
    ASSERT_TRUE(latest_epoch.has_value() && latest_epoch->has_value());
    const auto now_sec = kasumi::platform::clock::unix_seconds();
    ASSERT_TRUE(now_sec.has_value());
    const auto issued_at = std::max(*now_sec, (*latest_epoch)->value.issued_at);
    const history_storage::epoch::Epoch epoch{
        .vault_id = (*latest_epoch)->value.vault_id,
        .sequence = (*latest_epoch)->reference.sequence + 1U,
        .issued_at = issued_at,
        .policy = (*latest_epoch)->value.policy,
        .anchors = {history_storage::epoch::Anchor{
            .commit_id = repacked->published_commit_id,
            .height = repacked->published_height,
        }},
        .previous_epoch_id = (*latest_epoch)->reference.epoch_id,
    };
    const auto sealed = history_storage::epoch::seal(epoch, key);
    ASSERT_TRUE(sealed.has_value());
    ASSERT_TRUE(history_storage::epoch::publish(
        *storage, key, *sealed, kasumi::test::workspace_root(ws)));

    const auto gc_res = integrity::garbage_collect(
        runtime,
        *storage,
        key,
        integrity::GarbageCollectOptions{
            .min_orphan_age = std::chrono::seconds{0}});
    ASSERT_TRUE(gc_res.has_value()) << gc_res.error().detail;
    EXPECT_GE(gc_res->removed_objects, 1U);

    EXPECT_EQ(*kasumi::transport::presence(*storage, p_old_id),
              kasumi::transport::Presence::Absent);
    EXPECT_EQ(*kasumi::transport::presence(*storage, p_new_id),
              kasumi::transport::Presence::Present);

    const auto audited = integrity::fsck(runtime, *storage, key, 1);
    ASSERT_TRUE(audited.has_value()) << audited.error().detail;
}

TEST(RepackTest, BoundedWindowsCleanStagingBetweenBatchesAndPublishSingleCommit) {
    const auto ws = kasumi::test::make_temp_workspace("repack-windows");
    const auto remote = kasumi::test::workspace_path(ws, "remote");
    init_remote(remote);
    const auto machine = create_machine(ws, "a", remote);
    const auto key = test_key();

    // Sync 6 loose 220 KiB files one by one so local transport keeps them loose.
    for (int i = 0; i < 6; ++i) {
        write_settled_file(
            machine.local_dir / ("win_" + std::to_string(i) + ".bin"),
            std::string(220U * 1024U, static_cast<char>('0' + i)));
        run_sync(machine);
    }

    const auto runtime = machine.resolve();
    const auto before_state =
        kasumi::state_storage::load_state(runtime.database_path);
    ASSERT_TRUE(before_state.has_value() && before_state->has_value());

    auto raw_storage = kasumi::transport::open_transport(
        runtime.storage_location, runtime.local_dir);
    ASSERT_TRUE(raw_storage.has_value());

    std::size_t max_staged_files = 0;
    std::size_t pack_puts_seen = 0;
    auto wrapped = make_wrapped_transport(
        std::move(*raw_storage),
        {},
        {},
        [&](const std::filesystem::path& source, std::string_view identifier) {
            static_cast<void>(identifier);
            if (source.parent_path().filename() != "packs") {
                return;
            }
            ++pack_puts_seen;
            std::size_t staged_now = 0;
            std::error_code ec;
            for (const auto& entry :
                 std::filesystem::directory_iterator(source.parent_path(), ec)) {
                static_cast<void>(entry);
                ++staged_now;
            }
            max_staged_files = std::max(max_staged_files, staged_now);
        });

    repack::Options opts;
    opts.policy.target_pack_size = 500ULL * 1024ULL;
    opts.policy.underfilled_pack_threshold = 450ULL * 1024ULL;
    opts.upload_window_packs = 2U;

    const auto exec = repack::execute(runtime, wrapped, key, opts);
    ASSERT_TRUE(exec.has_value()) << exec.error().detail;
    EXPECT_TRUE(exec->published);
    EXPECT_EQ(exec->plan.new_packs.size(), 3U);
    EXPECT_EQ(pack_puts_seen, 3U);
    EXPECT_GT(max_staged_files, 0U);
    EXPECT_LE(max_staged_files, 2U);
    EXPECT_EQ(exec->published_height, (*before_state)->height + 1U);

    const auto audited = integrity::fsck(runtime, wrapped, key, 1);
    ASSERT_TRUE(audited.has_value()) << audited.error().detail;
}

TEST(RepackTest,
     ExecutePublishesRepackAuthorshipViaApplicationWhileDryRunStaysReadOnly) {
    const auto workspace =
        kasumi::test::make_temp_workspace("repack-authorship-kcom-v4");
    const auto remote_dir =
        kasumi::test::workspace_path(workspace, "remote");
    init_remote(remote_dir);
    auto machine = create_machine(workspace, "m1", remote_dir);

    for (int i = 0; i < 3; ++i) {
        write_settled_file(machine.local_dir /
                               ("s" + std::to_string(i + 1) + ".txt"),
                           "small-" + std::to_string(i + 1));
        run_sync(machine, false);
    }

    const auto key = test_key();
    const auto runtime = machine.resolve(AccessMode::ReadOnly);
    const auto before_state =
        kasumi::state_storage::load_state(runtime.database_path);
    ASSERT_TRUE(before_state.has_value() && before_state->has_value());

    // Simulate a separate machine checking repack --dry-run without creating
    // machine.id or publishing any commit.
    auto observer = create_machine(workspace, "obs", remote_dir, false);
    std::filesystem::copy_file(
        machine.app_dir / "profiles" / "demo" / "db.sqlite",
        observer.app_dir / "profiles" / "demo" / "db.sqlite",
        std::filesystem::copy_options::overwrite_existing);
    for (int i = 0; i < 3; ++i) {
        write_settled_file(observer.local_dir /
                               ("s" + std::to_string(i + 1) + ".txt"),
                           "small-" + std::to_string(i + 1));
    }
    const auto dry_resp = kasumi::application::execute(
        {Request{.operation = Operation::Repack,
                 .profile_name = observer.profile_name,
                 .dry_run = true},
         observer.creds(),
         observer.env()});
    ASSERT_TRUE(dry_resp.has_value()) << dry_resp.error().detail;
    EXPECT_FALSE(
        std::filesystem::exists(observer.app_dir / "machine.id"));

    // Run real repack through application::execute -> embeds KCOM v4 Repack
    // authorship and atomically updates accepted_commit_meta.
    const auto real_resp = kasumi::application::execute(
        {Request{.operation = Operation::Repack,
                 .profile_name = machine.profile_name},
         machine.creds(),
         machine.env()});
    ASSERT_TRUE(real_resp.has_value()) << real_resp.error().detail;
    const auto* repacked =
        std::get_if<kasumi::application::RepackCompleted>(&real_resp->data);
    ASSERT_NE(repacked, nullptr);
    EXPECT_TRUE(repacked->published);
    EXPECT_NE(repacked->published_commit_id, (*before_state)->commit_id);

    auto storage = kasumi::transport::open_transport(runtime.storage_location,
                                                     runtime.local_dir);
    ASSERT_TRUE(storage.has_value());
    const auto observed = kasumi::application::observation::history::observe(
        *storage, key, machine.app_dir, false);
    ASSERT_TRUE(observed.has_value()) << observed.error().detail;
    const auto head_it =
        std::ranges::find(observed->reachable_commits,
                          repacked->published_commit_id,
                          &kasumi::history::LoadedCommit::id);
    ASSERT_NE(head_it, observed->reachable_commits.end());
    EXPECT_TRUE(
        kasumi::history::has_commit_authorship(head_it->commit.authorship));
    EXPECT_EQ(head_it->commit.authorship.operation,
              kasumi::history::CommitOriginOperation::Repack);

    const auto machine_id =
        kasumi::runtime::resolve_machine_identity(machine.app_dir, false);
    ASSERT_TRUE(machine_id.has_value());
    EXPECT_EQ(head_it->commit.authorship.machine_id, machine_id->id);

    const auto activity =
        kasumi::state_storage::load_local_activity(runtime.database_path);
    ASSERT_TRUE(activity.has_value()) << activity.error();
    ASSERT_TRUE(activity->accepted_commit.has_value());
    EXPECT_EQ(activity->accepted_commit->commit_id,
              repacked->published_commit_id);
    EXPECT_EQ(activity->accepted_commit->origin_operation,
              kasumi::history::CommitOriginOperation::Repack);
    EXPECT_EQ(activity->accepted_commit->machine_id_hex, machine_id->id_hex);

    // No-work repack publishes nothing and leaves accepted_commit_meta intact.
    const auto second = kasumi::application::execute(
        {Request{.operation = Operation::Repack,
                 .profile_name = machine.profile_name},
         machine.creds(),
         machine.env()});
    ASSERT_TRUE(second.has_value()) << second.error().detail;
    const auto* second_repack =
        std::get_if<kasumi::application::RepackCompleted>(&second->data);
    ASSERT_NE(second_repack, nullptr);
    EXPECT_FALSE(second_repack->published);
    const auto activity_after =
        kasumi::state_storage::load_local_activity(runtime.database_path);
    ASSERT_TRUE(activity_after.has_value() && activity_after->accepted_commit);
    EXPECT_EQ(activity_after->accepted_commit->commit_id,
              repacked->published_commit_id);
}

} // namespace
