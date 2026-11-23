#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/maintenance.hpp"
#include "application/integrity/repack.hpp"
#include "application/use_cases/context.hpp"
#include "core/hasher.hpp"
#include "crypto/file_crypto.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/path.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace kasumi::application::detail {
std::expected<Response, Error> run_sync(OperationContext& context);
}

namespace {

namespace integrity = kasumi::application::integrity;
namespace repack = kasumi::application::integrity::repack;

constexpr std::size_t default_soak_cycles = 12U;
constexpr std::size_t maximum_soak_cycles = 200U;

std::size_t soak_cycle_count() noexcept {
    const char* setting = std::getenv("KASUMI_SOAK_CYCLES");
    if (setting == nullptr) {
        return default_soak_cycles;
    }
    std::size_t value = 0;
    const std::string_view text{setting};
    const auto parsed =
        std::from_chars(text.data(), text.data() + text.size(), value);
    return parsed.ec == std::errc{} &&
                   parsed.ptr == text.data() + text.size() && value > 0U &&
                   value <= maximum_soak_cycles
               ? value
               : default_soak_cycles;
}

std::uint64_t next_rng(std::uint64_t& state) noexcept {
    state ^= state << 13U;
    state ^= state >> 7U;
    state ^= state << 17U;
    return state;
}

std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> test_key() noexcept {
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(0x41U + i);
    }
    return key;
}

struct FaultInjectorState {
    kasumi::transport::Transport* base = nullptr;
    std::mutex mutex;
    std::size_t put_calls = 0;
    std::size_t put_batch_calls = 0;
    std::size_t get_calls = 0;
    std::size_t get_batch_calls = 0;
    std::size_t list_calls = 0;

    std::optional<std::size_t> fail_put_on_call;
    std::optional<std::string> fail_put_prefix;
    std::optional<std::size_t> fail_put_prefix_on_call;
    std::optional<std::size_t> fail_put_batch_on_call;
    std::optional<std::size_t> fail_get_on_call;
    bool fail_content_gets = false;
    bool fail_all_get_batches = false;
    std::optional<std::size_t> fail_get_batch_on_call;
    std::optional<std::size_t> fail_list_on_call;
    std::size_t prefix_put_calls = 0;
    bool active = true;

    void reset_faults() {
        std::lock_guard lock(mutex);
        active = false;
        fail_put_on_call.reset();
        fail_put_prefix.reset();
        fail_put_prefix_on_call.reset();
        fail_put_batch_on_call.reset();
        fail_get_on_call.reset();
        fail_content_gets = false;
        fail_all_get_batches = false;
        fail_get_batch_on_call.reset();
        fail_list_on_call.reset();
    }
};

void destroy_fault_state(void*) noexcept {
}

kasumi::transport::Error injected_error(std::string detail) {
    return kasumi::transport::Error{
        .code = kasumi::transport::ErrorCode::BackendUnavailable,
        .message = std::move(detail),
    };
}

kasumi::transport::Result fi_initialize(void* context) {
    return kasumi::transport::initialize(
        *static_cast<FaultInjectorState*>(context)->base);
}

kasumi::transport::Result fi_put(void* context,
                                 const std::filesystem::path& source,
                                 std::string_view identifier) {
    auto* state = static_cast<FaultInjectorState*>(context);
    {
        std::lock_guard lock(state->mutex);
        const auto n = ++state->put_calls;
        if (state->active && state->fail_put_on_call &&
            *state->fail_put_on_call == n) {
            return std::unexpected(injected_error(
                "injected put fault at call " + std::to_string(n)));
        }
        if (state->active && state->fail_put_prefix &&
            identifier.starts_with(*state->fail_put_prefix)) {
            const auto pn = ++state->prefix_put_calls;
            if (!state->fail_put_prefix_on_call ||
                *state->fail_put_prefix_on_call == pn) {
                return std::unexpected(injected_error(
                    "injected prefix put fault at call " + std::to_string(pn)));
            }
        }
    }
    return kasumi::transport::put(*state->base, source, identifier);
}

kasumi::transport::Result
fi_put_batch(void* context, const kasumi::transport::PutBatch& batch) {
    auto* state = static_cast<FaultInjectorState*>(context);
    {
        std::lock_guard lock(state->mutex);
        const auto n = ++state->put_batch_calls;
        if (state->active && state->fail_put_batch_on_call &&
            *state->fail_put_batch_on_call == n) {
            return std::unexpected(injected_error(
                "injected put_batch fault at call " + std::to_string(n)));
        }
    }
    return kasumi::transport::put_batch(*state->base, batch);
}

kasumi::transport::Result fi_get(void* context,
                                 std::string_view identifier,
                                 const std::filesystem::path& destination) {
    auto* state = static_cast<FaultInjectorState*>(context);
    {
        std::lock_guard lock(state->mutex);
        const auto n = ++state->get_calls;
        if (state->active && state->fail_content_gets &&
            identifier.find('/') == std::string_view::npos) {
            return std::unexpected(
                injected_error("injected content get fault"));
        }
        if (state->active && state->fail_get_on_call &&
            *state->fail_get_on_call == n) {
            return std::unexpected(injected_error(
                "injected get fault at call " + std::to_string(n)));
        }
    }
    return kasumi::transport::get(*state->base, identifier, destination);
}

kasumi::transport::Result
fi_get_batch(void* context, const kasumi::transport::GetBatch& batch) {
    auto* state = static_cast<FaultInjectorState*>(context);
    {
        std::lock_guard lock(state->mutex);
        const auto n = ++state->get_batch_calls;
        if (state->active && (state->fail_all_get_batches ||
                              (state->fail_get_batch_on_call &&
                               *state->fail_get_batch_on_call == n))) {
            return std::unexpected(injected_error(
                "injected get_batch fault at call " + std::to_string(n)));
        }
    }
    return kasumi::transport::get_batch(*state->base, batch);
}

kasumi::transport::PresenceResult fi_presence(void* context,
                                              std::string_view identifier) {
    return kasumi::transport::presence(
        *static_cast<FaultInjectorState*>(context)->base, identifier);
}

kasumi::transport::ListingResult fi_list(void* context) {
    auto* state = static_cast<FaultInjectorState*>(context);
    {
        std::lock_guard lock(state->mutex);
        const auto n = ++state->list_calls;
        if (state->active && state->fail_list_on_call &&
            *state->fail_list_on_call == n) {
            return std::unexpected(injected_error(
                "injected list fault at call " + std::to_string(n)));
        }
    }
    return kasumi::transport::list(*state->base);
}

kasumi::transport::MetadataListingResult fi_list_metadata(void* context) {
    return kasumi::transport::list_metadata(
        *static_cast<FaultInjectorState*>(context)->base);
}

kasumi::transport::ListingResult fi_list_prefix(void* context,
                                                std::string_view prefix) {
    return kasumi::transport::list(
        *static_cast<FaultInjectorState*>(context)->base, prefix);
}

kasumi::transport::ControlReadBatchResponse
fi_control_read_batch(void* context,
                      const kasumi::transport::ControlReadBatchRequest& req) {
    return kasumi::transport::control_read_batch(
        *static_cast<FaultInjectorState*>(context)->base, req);
}

kasumi::transport::RemovalResult fi_remove(void* context,
                                           std::string_view identifier) {
    return kasumi::transport::remove(
        *static_cast<FaultInjectorState*>(context)->base, identifier);
}

kasumi::transport::RemoveBatchResult
fi_remove_batch(void* context, const kasumi::transport::RemoveBatch& batch) {
    return kasumi::transport::remove_batch(
        *static_cast<FaultInjectorState*>(context)->base, batch);
}

kasumi::transport::Transport make_fault_transport(FaultInjectorState& state) {
    const auto& ops = state.base->storage;
    return kasumi::transport::Transport{
        .state = kasumi::transport::TransportStateHandle{&state,
                                                         destroy_fault_state},
        .storage =
            kasumi::transport::StorageOperations{
                .initialize = fi_initialize,
                .put = fi_put,
                .put_batch = ops.put_batch ? fi_put_batch : nullptr,
                .get = fi_get,
                .get_batch = ops.get_batch ? fi_get_batch : nullptr,
                .presence = fi_presence,
                .list = fi_list,
                .list_metadata = ops.list_metadata ? fi_list_metadata : nullptr,
                .list_prefix = ops.list_prefix ? fi_list_prefix : nullptr,
                .control_read_batch =
                    ops.control_read_batch ? fi_control_read_batch : nullptr,
                .remove = fi_remove,
                .remove_batch = ops.remove_batch ? fi_remove_batch : nullptr,
            },
    };
}

class ClientNode {
public:
    ClientNode(const std::filesystem::path& root,
               const std::filesystem::path& remote_dir,
               std::string_view name,
               std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key)
        : profile_dir_(root / (std::string{name} + "_profile")),
          local_dir_(root / (std::string{name} + "_local")),
          database_(profile_dir_ / "state.db"), key_(key), machine_name_(name) {
        std::filesystem::create_directories(profile_dir_);
        std::filesystem::create_directories(local_dir_);
        EXPECT_TRUE(kasumi::state_storage::initialize(database_));
        auto opened = kasumi::transport::open_transport(
            kasumi::platform::path::to_utf8(remote_dir));
        EXPECT_TRUE(opened.has_value()) << opened.error().message;
        if (opened) {
            storage_ = std::move(*opened);
            EXPECT_TRUE(kasumi::transport::initialize(storage_).has_value());
        }
        runtime_ = kasumi::runtime::RuntimeData{
            .local_dir = local_dir_,
            .database_path = database_,
            .key_path = profile_dir_ / "key.bin",
            .storage_location = kasumi::platform::path::to_utf8(remote_dir),
        };
    }

    const std::filesystem::path& local_dir() const noexcept {
        return local_dir_;
    }

    kasumi::transport::Transport& storage() noexcept {
        return storage_;
    }

    std::expected<kasumi::application::Response, kasumi::application::Error>
    sync(kasumi::transport::Transport* custom_storage = nullptr) {
        kasumi::application::detail::OperationContext ctx{
            .operation = kasumi::application::Operation::Sync,
            .runtime = runtime_,
            .summary = {.local_dir = local_dir_,
                        .remote_dir = runtime_.storage_location},
            .machine_identity =
                kasumi::runtime::MachineIdentity{
                    .id = {1},
                    .name = machine_name_,
                },
            .key = key_,
            .storage = custom_storage ? std::move(*custom_storage)
                                      : open_fresh_storage(),
        };
        return kasumi::application::detail::run_sync(ctx);
    }

    std::expected<repack::Result, integrity::Error> run_repack() {
        return repack::execute(
            runtime_,
            storage_,
            key_,
            repack::Options{.policy = {.reclaim_large_dirty_packs = true}});
    }

    std::expected<integrity::GarbageCollectResult, integrity::Error>
    run_gc_default_grace() {
        return integrity::garbage_collect(runtime_, storage_, key_);
    }

    std::expected<integrity::GarbageCollectResult, integrity::Error>
    run_gc_immediate() {
        return integrity::garbage_collect(
            runtime_,
            storage_,
            key_,
            integrity::GarbageCollectOptions{.min_orphan_age =
                                                 std::chrono::seconds{0}});
    }

    std::expected<integrity::FsckResult, integrity::Error> run_fsck() {
        return integrity::fsck(runtime_, storage_, key_, 4U);
    }

    void write_text_file(std::string_view rel, std::string_view text) {
        const auto target = local_dir_ / kasumi::platform::path::from_utf8(rel);
        std::filesystem::create_directories(target.parent_path());
        kasumi::test::write_text(target, text);
    }

    void write_patterned_binary(std::string_view rel,
                                std::size_t bytes,
                                std::uint8_t seed,
                                std::size_t patch_offset = 0,
                                std::size_t patch_len = 0,
                                std::uint8_t patch_byte = 0) {
        const auto target = local_dir_ / kasumi::platform::path::from_utf8(rel);
        std::filesystem::create_directories(target.parent_path());
        std::vector<std::byte> buf(bytes);
        for (std::size_t i = 0; i < bytes; ++i) {
            buf[i] = static_cast<std::byte>(
                (seed + static_cast<std::uint8_t>(i * 131U) +
                 static_cast<std::uint8_t>(i >> 11U)) &
                0xFFU);
        }
        const std::size_t limit = std::min(patch_offset + patch_len, bytes);
        for (std::size_t i = patch_offset; i < limit; ++i) {
            buf[i] = static_cast<std::byte>(patch_byte ^
                                            static_cast<std::uint8_t>(i));
        }
        kasumi::test::write_binary(target, buf);
    }

    void move_file(std::string_view from_rel, std::string_view to_rel) {
        const auto from =
            local_dir_ / kasumi::platform::path::from_utf8(from_rel);
        const auto to = local_dir_ / kasumi::platform::path::from_utf8(to_rel);
        std::filesystem::create_directories(to.parent_path());
        std::filesystem::rename(from, to);
    }

    void remove_file(std::string_view rel) {
        std::filesystem::remove(local_dir_ /
                                kasumi::platform::path::from_utf8(rel));
    }

private:
    kasumi::transport::Transport open_fresh_storage() const {
        auto opened =
            kasumi::transport::open_transport(runtime_.storage_location);
        EXPECT_TRUE(opened.has_value());
        return std::move(*opened);
    }

    std::filesystem::path profile_dir_;
    std::filesystem::path local_dir_;
    std::filesystem::path database_;
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key_;
    std::string machine_name_;
    kasumi::runtime::RuntimeData runtime_;
    kasumi::transport::Transport storage_;
};

void sync_all(std::array<ClientNode*, 3> clients, std::size_t leader) {
    auto res0 = clients[leader]->sync();
    ASSERT_TRUE(res0.has_value()) << res0.error().detail;
    for (std::size_t i = 0; i < clients.size(); ++i) {
        if (i != leader) {
            auto res = clients[i]->sync();
            ASSERT_TRUE(res.has_value()) << res.error().detail;
        }
    }
}

TEST(SyncMaintenanceSoakTest, RandomizedMultiClientSyncGcRepackAndFsckCycles) {
    auto ws = kasumi::test::make_temp_workspace("sync-maintenance-soak");
    const auto remote = kasumi::test::workspace_path(ws, "remote");
    std::filesystem::create_directories(remote);
    const auto key = test_key();

    ClientNode a(kasumi::test::workspace_root(ws), remote, "client_a", key);
    ClientNode b(kasumi::test::workspace_root(ws), remote, "client_b", key);
    ClientNode c(kasumi::test::workspace_root(ws), remote, "client_c", key);
    std::array<ClientNode*, 3> clients{&a, &b, &c};

    // Seed initial Micro-Pack batch from client A and converge A/B/C.
    for (int i = 0; i < 6; ++i) {
        a.write_text_file("seed/file_" + std::to_string(i) + ".txt",
                          "initial-payload-" + std::to_string(i) + "-" +
                              std::string(static_cast<std::size_t>(40 + i * 7),
                                          static_cast<char>('a' + i)));
    }
    sync_all(clients, 0U);
    EXPECT_EQ(kasumi::test::snapshot_tree(a.local_dir()),
              kasumi::test::snapshot_tree(b.local_dir()));
    EXPECT_EQ(kasumi::test::snapshot_tree(a.local_dir()),
              kasumi::test::snapshot_tree(c.local_dir()));

    std::vector<std::string> live_small;
    for (int i = 0; i < 6; ++i) {
        live_small.push_back("seed/file_" + std::to_string(i) + ".txt");
    }

    std::uint64_t rng = 0x5A0C2201ULL;
    const std::size_t cycles = soak_cycle_count();
    std::size_t seq = 1;
    bool created_large = false;
    bool edited_large = false;

    for (std::size_t cycle = 0; cycle < cycles; ++cycle) {
        const std::size_t leader =
            static_cast<std::size_t>(next_rng(rng) % clients.size());
        ClientNode& active = *clients[leader];

        // 1. Add 2 small files to exercise Micro-Pack bundling cleanly.
        for (int k = 0; k < 2; ++k) {
            const std::string rel = "dir_" + std::to_string(cycle % 3U) +
                                    "/item_" + std::to_string(seq) + ".txt";
            active.write_text_file(
                rel,
                "cycle-" + std::to_string(cycle) + "-seq-" +
                    std::to_string(seq) + "-" +
                    std::string(static_cast<std::size_t>(64U + (seq % 128U)),
                                'x'));
            live_small.push_back(rel);
            ++seq;
        }

        // 2. Edit an existing small file with distinct byte length.
        if (!live_small.empty()) {
            const auto idx =
                static_cast<std::size_t>(next_rng(rng) % live_small.size());
            active.write_text_file(
                live_small[idx],
                "edited-at-" + std::to_string(cycle) + "-" +
                    std::to_string(seq) + "-" +
                    std::string(static_cast<std::size_t>(200U + seq * 3U),
                                'e'));
            ++seq;
        }

        // 3. Move or rename a small file when pool is non-empty.
        if (live_small.size() > 3U && (next_rng(rng) % 2U) == 0U) {
            const auto idx =
                static_cast<std::size_t>(next_rng(rng) % live_small.size());
            const std::string new_rel =
                "moved/at_" + std::to_string(seq) + ".txt";
            active.move_file(live_small[idx], new_rel);
            live_small[idx] = new_rel;
            ++seq;
        }

        // 4. Delete a small file when enough files exist.
        if (live_small.size() > 6U && (next_rng(rng) % 2U) == 0U) {
            const auto idx =
                static_cast<std::size_t>(next_rng(rng) % live_small.size());
            active.remove_file(live_small[idx]);
            live_small.erase(live_small.begin() +
                             static_cast<std::ptrdiff_t>(idx));
        }

        // 5. Exercise a > 256 KiB loose file periodically.
        if ((cycle % 4U) == 0U) {
            active.write_patterned_binary(
                "loose/blob.bin",
                300U * 1024U + cycle * 1024U,
                static_cast<std::uint8_t>(0x10U + cycle));
        }

        // 6. Exercise > 8 MiB FastCDC creation and incremental delta edit.
        constexpr std::size_t fastcdc_bytes = 9U * 1024U * 1024U;
        if (!created_large && (cycle == 1U || cycle + 1U == cycles)) {
            active.write_patterned_binary(
                "large/dataset.bin", fastcdc_bytes, 0x22U);
            created_large = true;
        } else if (created_large && !edited_large &&
                   (cycle == 5U || cycle + 1U == cycles)) {
            active.write_patterned_binary("large/dataset.bin",
                                          fastcdc_bytes,
                                          0x22U,
                                          4U * 1024U * 1024U,
                                          64U * 1024U,
                                          0xA5U);
            edited_large = true;
        }

        sync_all(clients, leader);
        ASSERT_EQ(kasumi::test::snapshot_tree(a.local_dir()),
                  kasumi::test::snapshot_tree(b.local_dir()))
            << "divergence at cycle " << cycle;
        ASSERT_EQ(kasumi::test::snapshot_tree(a.local_dir()),
                  kasumi::test::snapshot_tree(c.local_dir()))
            << "divergence at cycle " << cycle;

        if ((cycle + 1U) % 3U == 0U || cycle + 1U == cycles) {
            auto repacked = active.run_repack();
            ASSERT_TRUE(repacked.has_value())
                << integrity::describe(repacked.error());
            if (repacked->published) {
                sync_all(clients, leader);
            }

            // Default safe GC (6h grace) defers recent orphans safely.
            auto gc_safe = active.run_gc_default_grace();
            ASSERT_TRUE(gc_safe.has_value())
                << integrity::describe(gc_safe.error());

            // Explicit immediate GC reclaims unreferenced blobs/dirty packs.
            auto gc_now = active.run_gc_immediate();
            ASSERT_TRUE(gc_now.has_value())
                << integrity::describe(gc_now.error());

            auto checked = active.run_fsck();
            ASSERT_TRUE(checked.has_value())
                << integrity::describe(checked.error());
            EXPECT_EQ(checked->repaired_objects, 0U);
        }
    }
}

TEST(SyncMaintenanceSoakTest,
     InjectedTransportFaultsRecoverCleanlyAcrossCycles) {
    auto ws = kasumi::test::make_temp_workspace("sync-fault-injection");
    const auto remote = kasumi::test::workspace_path(ws, "remote");
    std::filesystem::create_directories(remote);
    const auto key = test_key();

    ClientNode a(kasumi::test::workspace_root(ws), remote, "client_a", key);
    ClientNode b(kasumi::test::workspace_root(ws), remote, "client_b", key);

    for (int i = 0; i < 4; ++i) {
        a.write_text_file("base/f" + std::to_string(i) + ".txt",
                          "base-content-" + std::to_string(i));
    }
    ASSERT_TRUE(a.sync().has_value());
    ASSERT_TRUE(b.sync().has_value());

    // Fault A: transient failure on put_batch / put during upload.
    for (int i = 0; i < 6; ++i) {
        a.write_text_file("fault_upload/u" + std::to_string(i) + ".txt",
                          "upload-payload-" + std::to_string(i) + "-" +
                              std::string(96U, 'u'));
    }
    {
        FaultInjectorState fi_state{.base = &a.storage()};
        fi_state.fail_put_batch_on_call = 1U;
        fi_state.fail_put_on_call = 2U;
        auto injected = make_fault_transport(fi_state);
        auto res = a.sync(&injected);
        EXPECT_FALSE(res.has_value());
    }
    ASSERT_TRUE(a.sync().has_value());
    ASSERT_TRUE(b.sync().has_value());
    EXPECT_EQ(kasumi::test::snapshot_tree(a.local_dir()),
              kasumi::test::snapshot_tree(b.local_dir()));

    // Fault B: transient failure while publishing commit object.
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(key);
    a.write_text_file("fault_publish/p1.txt",
                      "commit-publication-test-payload");
    a.write_text_file("fault_publish/p2.txt",
                      "commit-publication-test-payload-2");
    {
        FaultInjectorState fi_state{.base = &a.storage()};
        fi_state.fail_put_prefix = layout.commits_prefix;
        fi_state.fail_put_prefix_on_call = 1U;
        auto injected = make_fault_transport(fi_state);
        auto res = a.sync(&injected);
        EXPECT_FALSE(res.has_value());
    }
    ASSERT_TRUE(a.sync().has_value());
    ASSERT_TRUE(b.sync().has_value());
    EXPECT_EQ(kasumi::test::snapshot_tree(a.local_dir()),
              kasumi::test::snapshot_tree(b.local_dir()));

    // Fault C: transient failure mid-download on client B.
    for (int i = 0; i < 8; ++i) {
        a.write_text_file("fault_download/d" + std::to_string(i) + ".txt",
                          "download-payload-" + std::to_string(i) + "-" +
                              std::string(80U, 'd'));
    }
    ASSERT_TRUE(a.sync().has_value());
    {
        FaultInjectorState fi_state{.base = &b.storage()};
        fi_state.fail_all_get_batches = true;
        fi_state.fail_content_gets = true;
        auto injected = make_fault_transport(fi_state);
        auto res = b.sync(&injected);
        EXPECT_FALSE(res.has_value());
    }
    ASSERT_TRUE(b.sync().has_value());
    EXPECT_EQ(kasumi::test::snapshot_tree(a.local_dir()),
              kasumi::test::snapshot_tree(b.local_dir()));

    auto audited = a.run_fsck();
    ASSERT_TRUE(audited.has_value()) << integrity::describe(audited.error());
    EXPECT_EQ(audited->repaired_objects, 0U);
}

TEST(SyncEngineBenchmarkTest, MultiFilePackAndChunkedRoundTripBenchmark) {
    auto ws = kasumi::test::make_temp_workspace("sync-engine-benchmark");
    const auto remote = kasumi::test::workspace_path(ws, "remote");
    std::filesystem::create_directories(remote);
    const auto key = test_key();

    ClientNode a(kasumi::test::workspace_root(ws), remote, "client_a", key);
    ClientNode b(kasumi::test::workspace_root(ws), remote, "client_b", key);

    auto measure = [](std::string_view scenario, auto&& fn) {
        const auto t0 = std::chrono::steady_clock::now();
        fn();
        const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - t0)
                            .count();
        std::cout << "SYNC_BENCHMARK {\"scenario\":\"" << scenario
                  << "\",\"wall_us\":" << us << "}\n";
    };

    for (int i = 0; i < 120; ++i) {
        a.write_text_file(
            "pack/" + std::to_string(i / 20) + "/f_" + std::to_string(i) +
                ".txt",
            "bench-small-" + std::to_string(i) + "-" +
                std::string(1024U, static_cast<char>('a' + (i % 26))));
    }
    measure("120_small_files_initial_upload", [&]() {
        auto res = a.sync();
        ASSERT_TRUE(res.has_value()) << res.error().detail;
    });

    for (int i = 0; i < 10; ++i) {
        a.write_text_file("pack/0/f_" + std::to_string(i) + ".txt",
                          "bench-edited-" + std::to_string(i) + "-" +
                              std::string(1100U, static_cast<char>('A' + i)));
    }
    measure("10_small_files_incremental_edit", [&]() {
        auto res = a.sync();
        ASSERT_TRUE(res.has_value()) << res.error().detail;
    });

    measure("120_small_files_second_client_download", [&]() {
        auto res = b.sync();
        ASSERT_TRUE(res.has_value()) << res.error().detail;
    });
    ASSERT_EQ(kasumi::test::snapshot_tree(a.local_dir()),
              kasumi::test::snapshot_tree(b.local_dir()));

    constexpr std::size_t big_size = 12U * 1024U * 1024U;
    a.write_patterned_binary("big/stream.bin", big_size, 0x33U);
    measure("12mib_fastcdc_initial_upload", [&]() {
        auto res = a.sync();
        ASSERT_TRUE(res.has_value()) << res.error().detail;
    });

    a.write_patterned_binary("big/stream.bin",
                             big_size,
                             0x33U,
                             5U * 1024U * 1024U,
                             64U * 1024U,
                             0x7EU);
    measure("12mib_fastcdc_delta_edit_upload", [&]() {
        auto res = a.sync();
        ASSERT_TRUE(res.has_value()) << res.error().detail;
    });

    measure("12mib_fastcdc_second_client_download", [&]() {
        auto res = b.sync();
        ASSERT_TRUE(res.has_value()) << res.error().detail;
    });

    EXPECT_EQ(kasumi::test::snapshot_tree(a.local_dir()),
              kasumi::test::snapshot_tree(b.local_dir()));
    auto audited = a.run_fsck();
    ASSERT_TRUE(audited.has_value()) << integrity::describe(audited.error());
    EXPECT_EQ(audited->repaired_objects, 0U);
}

} // namespace
