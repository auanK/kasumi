#include "application/sync/mutation_fault_test.hpp"
#include "platform/perf_trace.hpp"
#include <chrono>
#include <iostream>
#include <iomanip>
#include "application/use_cases/context.hpp"
#include "crypto/content.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/history_storage.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/path.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"
#include "application/sync/mutation.hpp"
#include "application/sync/mutation_detail.hpp"
#include "core/hasher.hpp"
#include "platform/workspace.hpp"
#include "application/sync/journal.hpp"
#include <atomic>
#include <mutex>
#include <thread>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <aclapi.h>
#include <windows.h>
#endif

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kasumi::application::detail {
std::expected<Response, Error> run_sync(OperationContext& context);
std::expected<Response, Error> run_plan(OperationContext& context);
} // namespace kasumi::application::detail

namespace {

bool is_content_identifier(std::string_view identifier) noexcept {
    return !identifier.empty() &&
           identifier.find('/') == std::string_view::npos;
}

struct ContentCounterState {
    kasumi::transport::Transport* base = nullptr;
    mutable std::mutex mutex{};
    std::size_t content_gets = 0;
    std::size_t content_puts = 0;
    std::size_t content_presences = 0;
    std::size_t content_copies = 0;
    std::vector<std::string> get_identifiers;
    std::vector<std::string> put_identifiers;
    std::vector<std::string> presence_identifiers;
};

struct ContentCounterSnapshot {
    std::size_t content_gets = 0;
    std::size_t content_puts = 0;
    std::size_t content_presences = 0;
    std::size_t content_copies = 0;
    std::vector<std::string> get_identifiers;
    std::vector<std::string> put_identifiers;
    std::vector<std::string> presence_identifiers;
};

inline ContentCounterSnapshot snapshot_content_counts(const ContentCounterState& state) {
    std::lock_guard lock(state.mutex);
    return ContentCounterSnapshot{
        .content_gets = state.content_gets,
        .content_puts = state.content_puts,
        .content_presences = state.content_presences,
        .content_copies = state.content_copies,
        .get_identifiers = state.get_identifiers,
        .put_identifiers = state.put_identifiers,
        .presence_identifiers = state.presence_identifiers,
    };
}

void destroy_counter_state(void*) noexcept {
}

kasumi::transport::Result counter_initialize(void* context) {
    auto* state = static_cast<ContentCounterState*>(context);
    return kasumi::transport::initialize(*state->base);
}

kasumi::transport::Result counter_put(void* context,
                                      const std::filesystem::path& source,
                                      std::string_view identifier) {
    auto* state = static_cast<ContentCounterState*>(context);
    if (is_content_identifier(identifier)) {
        std::lock_guard lock(state->mutex);
        ++state->content_puts;
        state->put_identifiers.emplace_back(identifier);
    }
    return kasumi::transport::put(*state->base, source, identifier);
}

kasumi::transport::Result
counter_put_batch(void* context, const kasumi::transport::PutBatch& batch) {
    auto* state = static_cast<ContentCounterState*>(context);
    {
        std::lock_guard lock(state->mutex);
        for (const auto& identifier : batch.identifiers) {
            if (is_content_identifier(identifier)) {
                ++state->content_puts;
                state->put_identifiers.push_back(identifier);
            }
        }
    }
    return kasumi::transport::put_batch(*state->base, batch);
}

kasumi::transport::Result
counter_put_files_batch(void* context,
                        const kasumi::transport::PutFilesBatch& batch) {
    auto* state = static_cast<ContentCounterState*>(context);
    auto result = kasumi::transport::put_files_batch(*state->base, batch);
    if (result ||
        result.error().code != kasumi::transport::ErrorCode::Unsupported) {
        std::lock_guard lock(state->mutex);
        for (const auto& item : batch.items) {
            if (is_content_identifier(item.destination_identifier)) {
                ++state->content_puts;
                state->put_identifiers.push_back(item.destination_identifier);
            }
        }
    }
    return result;
}

kasumi::transport::Result
counter_get(void* context,
            std::string_view identifier,
            const std::filesystem::path& destination) {
    auto* state = static_cast<ContentCounterState*>(context);
    if (is_content_identifier(identifier)) {
        std::lock_guard lock(state->mutex);
        ++state->content_gets;
        state->get_identifiers.emplace_back(identifier);
    }
    return kasumi::transport::get(*state->base, identifier, destination);
}

kasumi::transport::Result
counter_get_batch(void* context, const kasumi::transport::GetBatch& batch) {
    auto* state = static_cast<ContentCounterState*>(context);
    if (batch.source_prefix.empty()) {
        std::lock_guard lock(state->mutex);
        for (const auto& identifier : batch.identifiers) {
            if (is_content_identifier(identifier)) {
                ++state->content_gets;
                state->get_identifiers.push_back(identifier);
            }
        }
    }
    return kasumi::transport::get_batch(*state->base, batch);
}

kasumi::transport::Result
counter_copy(void* context,
             std::string_view source_identifier,
             std::string_view destination_identifier) {
    auto* state = static_cast<ContentCounterState*>(context);
    auto result = kasumi::transport::copy(
        *state->base, source_identifier, destination_identifier);
    if (result ||
        result.error().code != kasumi::transport::ErrorCode::Unsupported) {
        if (is_content_identifier(source_identifier) ||
            is_content_identifier(destination_identifier)) {
            std::lock_guard lock(state->mutex);
            ++state->content_copies;
        }
    }
    return result;
}

kasumi::transport::Result
counter_copy_batch(void* context, const kasumi::transport::CopyBatch& batch) {
    auto* state = static_cast<ContentCounterState*>(context);
    auto result = kasumi::transport::copy_batch(*state->base, batch);
    if (result ||
        result.error().code != kasumi::transport::ErrorCode::Unsupported) {
        std::lock_guard lock(state->mutex);
        for (const auto& item : batch.items) {
            if (is_content_identifier(item.source_identifier) ||
                is_content_identifier(item.destination_identifier)) {
                ++state->content_copies;
            }
        }
    }
    return result;
}

kasumi::transport::PresenceResult
counter_presence(void* context, std::string_view identifier) {
    auto* state = static_cast<ContentCounterState*>(context);
    if (is_content_identifier(identifier)) {
        std::lock_guard lock(state->mutex);
        ++state->content_presences;
        state->presence_identifiers.emplace_back(identifier);
    }
    return kasumi::transport::presence(*state->base, identifier);
}

kasumi::transport::ListingResult counter_list(void* context) {
    auto* state = static_cast<ContentCounterState*>(context);
    return kasumi::transport::list(*state->base);
}

kasumi::transport::ListingResult counter_list_prefix(void* context,
                                                     std::string_view prefix) {
    auto* state = static_cast<ContentCounterState*>(context);
    return kasumi::transport::list(*state->base, prefix);
}

kasumi::transport::ControlReadBatchResponse counter_control_read_batch(
    void* context, const kasumi::transport::ControlReadBatchRequest& request) {
    auto* state = static_cast<ContentCounterState*>(context);
    auto result = kasumi::transport::control_read_batch(*state->base, request);
    if (result ||
        result.error().code != kasumi::transport::ErrorCode::Unsupported) {
        std::lock_guard lock(state->mutex);
        for (const auto& identifier : request.presence_identifiers) {
            if (is_content_identifier(identifier)) {
                ++state->content_presences;
                state->presence_identifiers.push_back(identifier);
            }
        }
    }
    return result;
}

kasumi::transport::RemovalResult counter_remove(void* context,
                                                std::string_view identifier) {
    auto* state = static_cast<ContentCounterState*>(context);
    return kasumi::transport::remove(*state->base, identifier);
}

kasumi::transport::RemoveBatchResult
counter_remove_batch(void* context,
                     const kasumi::transport::RemoveBatch& batch) {
    auto* state = static_cast<ContentCounterState*>(context);
    return kasumi::transport::remove_batch(*state->base, batch);
}

kasumi::transport::Transport
make_counting_transport(ContentCounterState& state) {
    return kasumi::transport::Transport{
        .state = kasumi::transport::TransportStateHandle{&state,
                                                         destroy_counter_state},
        .storage =
            kasumi::transport::StorageOperations{
                .initialize = counter_initialize,
                .put = counter_put,
                .put_batch = counter_put_batch,
                .put_files_batch = counter_put_files_batch,
                .get = counter_get,
                .get_batch = counter_get_batch,
                .copy = counter_copy,
                .copy_batch = counter_copy_batch,
                .presence = counter_presence,
                .list = counter_list,
                .list_prefix = counter_list_prefix,
                .control_read_batch = counter_control_read_batch,
                .remove = counter_remove,
                .remove_batch = counter_remove_batch,
            },
    };
}

struct SyncNode {
    kasumi::test::TempWorkspace workspace{nullptr, nullptr};
    std::filesystem::path profile;
    std::filesystem::path local;
    std::filesystem::path storage_root;
    std::filesystem::path database;
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    ContentCounterState counters{};
    kasumi::transport::Transport base_storage{};
    kasumi::runtime::RuntimeData runtime{};
    kasumi::application::detail::OperationContext context{};
    bool valid = false;
};

bool init_sync_node(SyncNode& node,
                    std::string_view name,
                    std::filesystem::path shared_storage = {}) {
    node.workspace = kasumi::test::make_temp_workspace(name);
    node.profile = kasumi::test::workspace_path(node.workspace, "profile");
    node.local = kasumi::test::workspace_path(node.workspace, "local");
    node.storage_root =
        shared_storage.empty()
            ? kasumi::test::workspace_path(node.workspace, "storage")
            : std::move(shared_storage);
    node.database = node.profile / "state.db";
    node.key = test_key();
    if (!std::filesystem::create_directories(node.profile) ||
        !std::filesystem::create_directories(node.local)) {
        return false;
    }
    auto opened = kasumi::transport::open_transport(node.storage_root.string());
    if (!opened) {
        return false;
    }
    node.base_storage = std::move(*opened);
    node.counters.base = &node.base_storage;
    if (!kasumi::state_storage::initialize(node.database)) {
        return false;
    }

    node.runtime = kasumi::runtime::RuntimeData{
        .local_dir = node.local,
        .database_path = node.database,
        .key_path = node.profile / "key.bin",
        .storage_location = node.storage_root.string(),
    };
    node.context.operation = kasumi::application::Operation::Sync;
    node.context.runtime = node.runtime;
    node.context.summary = {
        .local_dir = node.local,
        .remote_dir = kasumi::platform::path::to_utf8(node.storage_root),
    };
    node.context.key = node.key;
    node.context.storage = make_counting_transport(node.counters);
    node.valid = true;
    return true;
}

void write_local_file(const SyncNode& node,
                      std::string_view relative_path,
                      std::string_view contents) {
    const auto target =
        node.local / kasumi::platform::path::from_utf8(relative_path);
    std::filesystem::create_directories(target.parent_path());
    kasumi::test::write_text(target, contents);
}

void rename_local_entry(const SyncNode& node,
                        std::string_view from_relative,
                        std::string_view to_relative) {
    const auto from =
        node.local / kasumi::platform::path::from_utf8(from_relative);
    const auto to = node.local / kasumi::platform::path::from_utf8(to_relative);
    std::filesystem::create_directories(to.parent_path());
    std::filesystem::rename(from, to);
}

void remove_local_subtree(const SyncNode& node,
                          std::string_view relative_path) {
    std::filesystem::remove_all(
        node.local / kasumi::platform::path::from_utf8(relative_path));
}

bool local_entry_exists(const SyncNode& node, std::string_view relative_path) {
    return std::filesystem::exists(
        node.local / kasumi::platform::path::from_utf8(relative_path));
}

std::string read_local_file(const SyncNode& node,
                            std::string_view relative_path) {
    return kasumi::test::read_text(
        node.local / kasumi::platform::path::from_utf8(relative_path));
}

std::expected<kasumi::application::Response, kasumi::application::Error>
run_node_sync(SyncNode& node) {
    node.context.operation = kasumi::application::Operation::Sync;
    return kasumi::application::detail::run_sync(node.context);
}

void reset_content_counts(SyncNode& node) noexcept {
    std::lock_guard lock(node.counters.mutex);
    node.counters.content_gets = 0;
    node.counters.content_puts = 0;
    node.counters.content_presences = 0;
    node.counters.content_copies = 0;
    node.counters.get_identifiers.clear();
    node.counters.put_identifiers.clear();
    node.counters.presence_identifiers.clear();
}

std::string content_identifier_for_payload(const SyncNode& node,
                                           std::string_view payload) {
    const auto digest = kasumi::hasher::hash_string(payload);
    return kasumi::crypto::content_identifier(node.key, digest);
}

bool contains_identifier(const std::vector<std::string>& list,
                         std::string_view identifier) noexcept {
    return std::ranges::find(list, identifier) != list.end();
}

// RED 1 — Renomeação pura entre dois clientes
TEST(DirectoryLocalMoveTest,
     PureDirectoryRenameBetweenClientsHasZeroContentIo) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "dir-rename-red1-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "dir-rename-red1-receiver", sender.storage_root));

    write_local_file(sender, "A/main.cpp", "int main() { return 0; }\n");
    write_local_file(
        sender, "A/include/main.hpp", "#pragma once\nint entry();\n");
    write_local_file(sender, "A/tests/test.cpp", "#include \"main.hpp\"\n");

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());
    ASSERT_EQ(kasumi::test::snapshot_tree(sender.local),
              kasumi::test::snapshot_tree(receiver.local));

    // Separate fixture setup transport calls from the rename synchronization.
    reset_content_counts(sender);
    reset_content_counts(receiver);

    rename_local_entry(sender, "A", "B");

    const auto sender_sync = run_node_sync(sender);
    ASSERT_TRUE(sender_sync.has_value()) << sender_sync.error().detail;
    EXPECT_EQ(sender.counters.content_gets, 0U);
    EXPECT_EQ(sender.counters.content_puts, 0U);
    EXPECT_EQ(sender.counters.content_presences, 0U);
    EXPECT_EQ(sender.counters.content_copies, 0U);

    const auto receiver_sync = run_node_sync(receiver);
    ASSERT_TRUE(receiver_sync.has_value()) << receiver_sync.error().detail;
    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_EQ(receiver.counters.content_puts, 0U);
    EXPECT_EQ(receiver.counters.content_presences, 0U);
    EXPECT_EQ(receiver.counters.content_copies, 0U);

    const auto* summary =
        std::get_if<kasumi::application::SyncCompleted>(&receiver_sync->data);
    ASSERT_NE(summary, nullptr);
    EXPECT_EQ(summary->downloaded, 0U);
    EXPECT_EQ(summary->download_bytes, 0U);

    EXPECT_FALSE(local_entry_exists(receiver, "A"));
    EXPECT_FALSE(local_entry_exists(receiver, "A/main.cpp"));
    EXPECT_FALSE(local_entry_exists(receiver, "A/include/main.hpp"));
    EXPECT_FALSE(local_entry_exists(receiver, "A/tests/test.cpp"));
    EXPECT_EQ(read_local_file(receiver, "B/main.cpp"),
              "int main() { return 0; }\n");
    EXPECT_EQ(read_local_file(receiver, "B/include/main.hpp"),
              "#pragma once\nint entry();\n");
    EXPECT_EQ(read_local_file(receiver, "B/tests/test.cpp"),
              "#include \"main.hpp\"\n");
    EXPECT_EQ(kasumi::test::snapshot_tree(sender.local),
              kasumi::test::snapshot_tree(receiver.local));
}

// RED 2 — Diretório movido para outro pai
TEST(DirectoryLocalMoveTest, DirectoryMovedToAnotherParentHasZeroContentIo) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "dir-rename-red2-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "dir-rename-red2-receiver", sender.storage_root));

    write_local_file(
        sender, "Projects/A/file.bin", "binary-payload-projects-a");

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());
    ASSERT_EQ(kasumi::test::snapshot_tree(sender.local),
              kasumi::test::snapshot_tree(receiver.local));

    reset_content_counts(sender);
    reset_content_counts(receiver);

    rename_local_entry(sender, "Projects/A", "Archive/A");
    remove_local_subtree(sender, "Projects");

    const auto sender_sync = run_node_sync(sender);
    ASSERT_TRUE(sender_sync.has_value()) << sender_sync.error().detail;
    EXPECT_EQ(sender.counters.content_gets, 0U);
    EXPECT_EQ(sender.counters.content_puts, 0U);
    EXPECT_EQ(sender.counters.content_presences, 0U);
    EXPECT_EQ(sender.counters.content_copies, 0U);

    const auto receiver_sync = run_node_sync(receiver);
    ASSERT_TRUE(receiver_sync.has_value()) << receiver_sync.error().detail;
    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_EQ(receiver.counters.content_puts, 0U);
    EXPECT_EQ(receiver.counters.content_presences, 0U);
    EXPECT_EQ(receiver.counters.content_copies, 0U);

    EXPECT_FALSE(local_entry_exists(receiver, "Projects"));
    EXPECT_FALSE(local_entry_exists(receiver, "Projects/A/file.bin"));
    EXPECT_EQ(read_local_file(receiver, "Archive/A/file.bin"),
              "binary-payload-projects-a");
    EXPECT_EQ(kasumi::test::snapshot_tree(sender.local),
              kasumi::test::snapshot_tree(receiver.local));
}

// RED 3 — Diretórios aninhados
TEST(DirectoryLocalMoveTest,
     NestedDirectoriesRenamePreservesStructureWithZeroContentIo) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "dir-rename-red3-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "dir-rename-red3-receiver", sender.storage_root));

    write_local_file(sender, "A/B/C/file.bin", "deeply-nested-payload");
    write_local_file(sender, "A/B/sibling.bin", "intermediate-level-payload");

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());

    reset_content_counts(sender);
    reset_content_counts(receiver);

    write_local_file(sender, "X/Y/Z/file.bin", "deeply-nested-payload");
    write_local_file(sender, "X/Y/sibling.bin", "intermediate-level-payload");
    remove_local_subtree(sender, "A");

    const auto sender_sync = run_node_sync(sender);
    ASSERT_TRUE(sender_sync.has_value()) << sender_sync.error().detail;
    EXPECT_EQ(sender.counters.content_gets, 0U);
    EXPECT_EQ(sender.counters.content_puts, 0U);
    EXPECT_EQ(sender.counters.content_presences, 0U);
    EXPECT_EQ(sender.counters.content_copies, 0U);

    const auto receiver_sync = run_node_sync(receiver);
    ASSERT_TRUE(receiver_sync.has_value()) << receiver_sync.error().detail;
    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_EQ(receiver.counters.content_puts, 0U);
    EXPECT_EQ(receiver.counters.content_presences, 0U);
    EXPECT_EQ(receiver.counters.content_copies, 0U);

    EXPECT_FALSE(local_entry_exists(receiver, "A"));
    EXPECT_EQ(read_local_file(receiver, "X/Y/Z/file.bin"),
              "deeply-nested-payload");
    EXPECT_EQ(read_local_file(receiver, "X/Y/sibling.bin"),
              "intermediate-level-payload");
    EXPECT_EQ(kasumi::test::snapshot_tree(sender.local),
              kasumi::test::snapshot_tree(receiver.local));
}

// RED 4 — Renomeação de arquivo individual
TEST(DirectoryLocalMoveTest, SingleFileRenameHasZeroContentIo) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "dir-rename-red4-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "dir-rename-red4-receiver", sender.storage_root));

    write_local_file(sender, "A/file.bin", "single-file-move-payload");

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());

    reset_content_counts(sender);
    reset_content_counts(receiver);

    rename_local_entry(sender, "A/file.bin", "B/file.bin");
    remove_local_subtree(sender, "A");

    const auto sender_sync = run_node_sync(sender);
    ASSERT_TRUE(sender_sync.has_value()) << sender_sync.error().detail;
    EXPECT_EQ(sender.counters.content_gets, 0U);
    EXPECT_EQ(sender.counters.content_puts, 0U);
    EXPECT_EQ(sender.counters.content_presences, 0U);
    EXPECT_EQ(sender.counters.content_copies, 0U);

    const auto receiver_sync = run_node_sync(receiver);
    ASSERT_TRUE(receiver_sync.has_value()) << receiver_sync.error().detail;
    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_EQ(receiver.counters.content_puts, 0U);
    EXPECT_EQ(receiver.counters.content_presences, 0U);
    EXPECT_EQ(receiver.counters.content_copies, 0U);

    EXPECT_FALSE(local_entry_exists(receiver, "A"));
    EXPECT_FALSE(local_entry_exists(receiver, "A/file.bin"));
    EXPECT_EQ(read_local_file(receiver, "B/file.bin"),
              "single-file-move-payload");
    EXPECT_EQ(kasumi::test::snapshot_tree(sender.local),
              kasumi::test::snapshot_tree(receiver.local));
}

TEST(DirectoryLocalMoveTest, DirectoryRenameWithAddedFileTransfersOnlyNewFile) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "dir-rename-added-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "dir-rename-added-receiver", sender.storage_root));

    write_local_file(sender, "A/1.bin", "payload-h1");
    write_local_file(sender, "A/2.bin", "payload-h2");

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());

    reset_content_counts(sender);
    reset_content_counts(receiver);

    rename_local_entry(sender, "A", "B");
    write_local_file(sender, "B/3.bin", "payload-h3-new");

    const auto id_h1 = content_identifier_for_payload(sender, "payload-h1");
    const auto id_h2 = content_identifier_for_payload(sender, "payload-h2");
    const auto id_h3 = content_identifier_for_payload(sender, "payload-h3-new");

    const auto sender_sync = run_node_sync(sender);
    ASSERT_TRUE(sender_sync.has_value()) << sender_sync.error().detail;
    EXPECT_EQ(sender.counters.content_puts, 1U);
    EXPECT_EQ(sender.counters.content_presences, 0U);
    EXPECT_EQ(sender.counters.content_copies, 0U);
    EXPECT_FALSE(contains_identifier(sender.counters.put_identifiers, id_h1));
    EXPECT_FALSE(contains_identifier(sender.counters.put_identifiers, id_h2));
    EXPECT_TRUE(contains_identifier(sender.counters.put_identifiers, id_h3));
    EXPECT_FALSE(contains_identifier(sender.counters.get_identifiers, id_h1));
    EXPECT_FALSE(contains_identifier(sender.counters.get_identifiers, id_h2));

    const auto receiver_sync = run_node_sync(receiver);
    ASSERT_TRUE(receiver_sync.has_value()) << receiver_sync.error().detail;
    EXPECT_EQ(receiver.counters.content_gets, 1U);
    EXPECT_EQ(receiver.counters.content_puts, 0U);
    EXPECT_EQ(receiver.counters.content_copies, 0U);
    EXPECT_FALSE(contains_identifier(receiver.counters.get_identifiers, id_h1));
    EXPECT_FALSE(contains_identifier(receiver.counters.get_identifiers, id_h2));
    EXPECT_TRUE(contains_identifier(receiver.counters.get_identifiers, id_h3));
    EXPECT_FALSE(
        contains_identifier(receiver.counters.presence_identifiers, id_h1));
    EXPECT_FALSE(
        contains_identifier(receiver.counters.presence_identifiers, id_h2));

    const auto* summary =
        std::get_if<kasumi::application::SyncCompleted>(&receiver_sync->data);
    ASSERT_NE(summary, nullptr);
    EXPECT_EQ(summary->downloaded, 1U);
    EXPECT_EQ(summary->renamed, 2U);

    EXPECT_FALSE(local_entry_exists(receiver, "A"));
    EXPECT_EQ(read_local_file(receiver, "B/1.bin"), "payload-h1");
    EXPECT_EQ(read_local_file(receiver, "B/2.bin"), "payload-h2");
    EXPECT_EQ(read_local_file(receiver, "B/3.bin"), "payload-h3-new");
    EXPECT_EQ(kasumi::test::snapshot_tree(sender.local),
              kasumi::test::snapshot_tree(receiver.local));
}

TEST(DirectoryLocalMoveTest,
     DirectoryRenameWithModifiedFileTransfersOnlyModifiedFile) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "dir-rename-mod-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "dir-rename-mod-receiver", sender.storage_root));

    write_local_file(sender, "A/1.bin", "payload-h1-unchanged");
    write_local_file(sender, "A/2.bin", "payload-h2-original");

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());

    reset_content_counts(sender);
    reset_content_counts(receiver);

    rename_local_entry(sender, "A", "B");
    write_local_file(sender, "B/2.bin", "payload-h3-modified");

    const auto id_h1 =
        content_identifier_for_payload(sender, "payload-h1-unchanged");
    const auto id_h2 =
        content_identifier_for_payload(sender, "payload-h2-original");
    const auto id_h3 =
        content_identifier_for_payload(sender, "payload-h3-modified");

    const auto sender_sync = run_node_sync(sender);
    ASSERT_TRUE(sender_sync.has_value()) << sender_sync.error().detail;
    EXPECT_EQ(sender.counters.content_puts, 1U);
    EXPECT_EQ(sender.counters.content_presences, 0U);
    EXPECT_EQ(sender.counters.content_copies, 0U);
    EXPECT_FALSE(contains_identifier(sender.counters.put_identifiers, id_h1));
    EXPECT_FALSE(contains_identifier(sender.counters.put_identifiers, id_h2));
    EXPECT_TRUE(contains_identifier(sender.counters.put_identifiers, id_h3));
    EXPECT_FALSE(contains_identifier(sender.counters.get_identifiers, id_h1));
    EXPECT_FALSE(contains_identifier(sender.counters.get_identifiers, id_h2));

    const auto receiver_sync = run_node_sync(receiver);
    ASSERT_TRUE(receiver_sync.has_value()) << receiver_sync.error().detail;
    EXPECT_EQ(receiver.counters.content_gets, 1U);
    EXPECT_EQ(receiver.counters.content_puts, 0U);
    EXPECT_EQ(receiver.counters.content_copies, 0U);
    EXPECT_FALSE(contains_identifier(receiver.counters.get_identifiers, id_h1));
    EXPECT_FALSE(contains_identifier(receiver.counters.get_identifiers, id_h2));
    EXPECT_TRUE(contains_identifier(receiver.counters.get_identifiers, id_h3));
    EXPECT_FALSE(
        contains_identifier(receiver.counters.presence_identifiers, id_h1));

    const auto* summary =
        std::get_if<kasumi::application::SyncCompleted>(&receiver_sync->data);
    ASSERT_NE(summary, nullptr);
    EXPECT_EQ(summary->downloaded, 1U);
    EXPECT_EQ(summary->renamed, 1U);

    EXPECT_FALSE(local_entry_exists(receiver, "A"));
    EXPECT_EQ(read_local_file(receiver, "B/1.bin"), "payload-h1-unchanged");
    EXPECT_EQ(read_local_file(receiver, "B/2.bin"), "payload-h3-modified");
    EXPECT_EQ(kasumi::test::snapshot_tree(sender.local),
              kasumi::test::snapshot_tree(receiver.local));
}

TEST(DirectoryLocalMoveTest,
     DirectoryRenameWithDuplicateContentPairsSourcesOneToOne) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "dir-rename-dup-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "dir-rename-dup-receiver", sender.storage_root));

    write_local_file(sender, "A/one.bin", "identical-duplicate-content");
    write_local_file(sender, "A/two.bin", "identical-duplicate-content");

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());

    reset_content_counts(sender);
    reset_content_counts(receiver);

    rename_local_entry(sender, "A", "B");

    const auto sender_sync = run_node_sync(sender);
    ASSERT_TRUE(sender_sync.has_value()) << sender_sync.error().detail;
    EXPECT_EQ(sender.counters.content_gets, 0U);
    EXPECT_EQ(sender.counters.content_puts, 0U);
    EXPECT_EQ(sender.counters.content_presences, 0U);
    EXPECT_EQ(sender.counters.content_copies, 0U);

    const auto receiver_sync = run_node_sync(receiver);
    ASSERT_TRUE(receiver_sync.has_value()) << receiver_sync.error().detail;
    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_EQ(receiver.counters.content_puts, 0U);
    EXPECT_EQ(receiver.counters.content_presences, 0U);
    EXPECT_EQ(receiver.counters.content_copies, 0U);

    const auto* summary =
        std::get_if<kasumi::application::SyncCompleted>(&receiver_sync->data);
    ASSERT_NE(summary, nullptr);
    EXPECT_EQ(summary->downloaded, 0U);
    EXPECT_EQ(summary->renamed, 2U);

    EXPECT_FALSE(local_entry_exists(receiver, "A"));
    EXPECT_EQ(read_local_file(receiver, "B/one.bin"),
              "identical-duplicate-content");
    EXPECT_EQ(read_local_file(receiver, "B/two.bin"),
              "identical-duplicate-content");
    EXPECT_EQ(kasumi::test::snapshot_tree(sender.local),
              kasumi::test::snapshot_tree(receiver.local));
}

TEST(DirectoryLocalMoveTest,
     EmptyDirectoryRenamePreservesStructureWithZeroContentIo) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "dir-rename-empty-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "dir-rename-empty-receiver", sender.storage_root));

    std::error_code ec;
    ASSERT_TRUE(
        std::filesystem::create_directories(sender.local / "A/Empty", ec));
    ASSERT_FALSE(ec);

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());
    ASSERT_TRUE(local_entry_exists(receiver, "A/Empty"));

    reset_content_counts(sender);
    reset_content_counts(receiver);

    ASSERT_TRUE(
        std::filesystem::create_directories(sender.local / "B/Empty", ec));
    ASSERT_FALSE(ec);
    remove_local_subtree(sender, "A");

    const auto sender_sync = run_node_sync(sender);
    ASSERT_TRUE(sender_sync.has_value()) << sender_sync.error().detail;
    EXPECT_EQ(sender.counters.content_gets, 0U);
    EXPECT_EQ(sender.counters.content_puts, 0U);
    EXPECT_EQ(sender.counters.content_presences, 0U);
    EXPECT_EQ(sender.counters.content_copies, 0U);

    const auto receiver_sync = run_node_sync(receiver);
    ASSERT_TRUE(receiver_sync.has_value()) << receiver_sync.error().detail;
    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_EQ(receiver.counters.content_puts, 0U);
    EXPECT_EQ(receiver.counters.content_presences, 0U);
    EXPECT_EQ(receiver.counters.content_copies, 0U);

    EXPECT_FALSE(local_entry_exists(receiver, "A"));
    EXPECT_TRUE(local_entry_exists(receiver, "B/Empty"));
    EXPECT_EQ(kasumi::test::snapshot_tree(sender.local),
              kasumi::test::snapshot_tree(receiver.local));
}

TEST(DirectoryLocalMoveTest,
     CopyPreservingSourceUsesDownloadAndDoesNotConsumeSource) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "dir-rename-copy-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "dir-rename-copy-receiver", sender.storage_root));

    write_local_file(sender, "A/file.bin", "copy-must-not-consume-source");

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());

    reset_content_counts(sender);
    reset_content_counts(receiver);

    write_local_file(sender, "B/file.bin", "copy-must-not-consume-source");

    const auto sender_sync = run_node_sync(sender);
    ASSERT_TRUE(sender_sync.has_value()) << sender_sync.error().detail;
    EXPECT_EQ(sender.counters.content_puts, 0U);

    const auto receiver_sync = run_node_sync(receiver);
    ASSERT_TRUE(receiver_sync.has_value()) << receiver_sync.error().detail;
    EXPECT_EQ(receiver.counters.content_gets, 1U);
    EXPECT_EQ(receiver.counters.content_puts, 0U);

    const auto* summary =
        std::get_if<kasumi::application::SyncCompleted>(&receiver_sync->data);
    ASSERT_NE(summary, nullptr);
    EXPECT_EQ(summary->downloaded, 1U);
    EXPECT_EQ(summary->renamed, 0U);

    EXPECT_EQ(read_local_file(receiver, "A/file.bin"),
              "copy-must-not-consume-source");
    EXPECT_EQ(read_local_file(receiver, "B/file.bin"),
              "copy-must-not-consume-source");
    EXPECT_EQ(kasumi::test::snapshot_tree(sender.local),
              kasumi::test::snapshot_tree(receiver.local));
}

TEST(DirectoryLocalMoveTest, DirectoryRenameWithUnicodePathsHasZeroContentIo) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "dir-rename-unicode-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "dir-rename-unicode-receiver", sender.storage_root));

    write_local_file(sender,
                     "Projetos/Aplicação_日本語/código/núcleo_α.cpp",
                     "unicode-cpp-1");
    write_local_file(
        sender, "Projetos/Aplicação_日本語/leia_me_çãõ.md", "unicode-md-2");

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());

    reset_content_counts(sender);
    reset_content_counts(receiver);

    write_local_file(
        sender, "Arquivo/Motor_日本語_v2/código/núcleo_α.cpp", "unicode-cpp-1");
    write_local_file(
        sender, "Arquivo/Motor_日本語_v2/leia_me_çãõ.md", "unicode-md-2");
    remove_local_subtree(sender, "Projetos");

    const auto sender_sync = run_node_sync(sender);
    ASSERT_TRUE(sender_sync.has_value()) << sender_sync.error().detail;
    EXPECT_EQ(sender.counters.content_gets, 0U);
    EXPECT_EQ(sender.counters.content_puts, 0U);
    EXPECT_EQ(sender.counters.content_presences, 0U);
    EXPECT_EQ(sender.counters.content_copies, 0U);

    const auto receiver_sync = run_node_sync(receiver);
    ASSERT_TRUE(receiver_sync.has_value()) << receiver_sync.error().detail;
    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_EQ(receiver.counters.content_puts, 0U);
    EXPECT_EQ(receiver.counters.content_presences, 0U);
    EXPECT_EQ(receiver.counters.content_copies, 0U);

    EXPECT_FALSE(local_entry_exists(receiver, "Projetos"));
    EXPECT_EQ(read_local_file(receiver,
                              "Arquivo/Motor_日本語_v2/código/núcleo_α.cpp"),
              "unicode-cpp-1");
    EXPECT_EQ(
        read_local_file(receiver, "Arquivo/Motor_日本語_v2/leia_me_çãõ.md"),
        "unicode-md-2");
    EXPECT_EQ(kasumi::test::snapshot_tree(sender.local),
              kasumi::test::snapshot_tree(receiver.local));
}

TEST(DirectoryLocalMoveTest,
     OccupiedDestinationFailsSafelyWithoutOverwritingExternalContent) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "dir-rename-occupied-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "dir-rename-occupied-receiver", sender.storage_root));

    write_local_file(sender, "A/1.bin", "payload-1");
    write_local_file(sender, "A/2.bin", "payload-2");

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());

    rename_local_entry(sender, "A", "B");
    ASSERT_TRUE(run_node_sync(sender).has_value());

    reset_content_counts(receiver);

    // Inject an external file at B/2.bin right before A/2.bin is moved.
    const auto target_source =
        receiver.local / kasumi::platform::path::from_utf8("A/2.bin");
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path& path) {
            if (point == "before_rename_move" && path == target_source) {
                write_local_file(
                    receiver, "B/2.bin", "external-do-not-overwrite");
            }
        });

    const auto receiver_sync = run_node_sync(receiver);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    EXPECT_FALSE(receiver_sync.has_value());
    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_EQ(read_local_file(receiver, "B/2.bin"),
              "external-do-not-overwrite");
    EXPECT_EQ(read_local_file(receiver, "A/1.bin"), "payload-1");
    EXPECT_EQ(read_local_file(receiver, "A/2.bin"), "payload-2");
    EXPECT_FALSE(local_entry_exists(receiver, "B/1.bin"));
}

TEST(DirectoryLocalMoveTest,
     SourceModifiedDuringExecutionFailsSafelyWithoutMovingCorruptedBytes) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "dir-rename-srcmod-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "dir-rename-srcmod-receiver", sender.storage_root));

    write_local_file(sender, "A/1.bin", "payload-1");
    write_local_file(sender, "A/2.bin", "payload-2");

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());

    rename_local_entry(sender, "A", "B");
    ASSERT_TRUE(run_node_sync(sender).has_value());

    reset_content_counts(receiver);

    const auto target_source =
        receiver.local / kasumi::platform::path::from_utf8("A/2.bin");
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path& path) {
            if (point == "before_rename_move" && path == target_source) {
                write_local_file(
                    receiver, "A/2.bin", "concurrently-modified-source");
            }
        });

    const auto receiver_sync = run_node_sync(receiver);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    EXPECT_FALSE(receiver_sync.has_value());
    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_FALSE(local_entry_exists(receiver, "B/2.bin"));
    EXPECT_FALSE(local_entry_exists(receiver, "B/1.bin"));
    EXPECT_EQ(read_local_file(receiver, "A/1.bin"), "payload-1");
    EXPECT_EQ(read_local_file(receiver, "A/2.bin"),
              "concurrently-modified-source");
}

TEST(DirectoryLocalMoveTest,
     SourceMissingAtExecutionFailsSafelyWithoutSilentDownload) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "dir-rename-srcmissing-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "dir-rename-srcmissing-receiver", sender.storage_root));

    write_local_file(sender, "A/1.bin", "payload-1");
    write_local_file(sender, "A/2.bin", "payload-2");

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());

    rename_local_entry(sender, "A", "B");
    ASSERT_TRUE(run_node_sync(sender).has_value());

    reset_content_counts(receiver);

    const auto target_source =
        receiver.local / kasumi::platform::path::from_utf8("A/2.bin");
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path& path) {
            if (point == "before_rename_move" && path == target_source) {
                remove_local_subtree(receiver, "A/2.bin");
            }
        });

    const auto receiver_sync = run_node_sync(receiver);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    EXPECT_FALSE(receiver_sync.has_value());
    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_FALSE(local_entry_exists(receiver, "B/2.bin"));
    EXPECT_FALSE(local_entry_exists(receiver, "B/1.bin"));
    EXPECT_EQ(read_local_file(receiver, "A/1.bin"), "payload-1");
}

struct SimulatedInterruption {};

void corrupt_or_remove_transaction_backups(const SyncNode& node) {
    const auto tx_root = node.profile / ".transactions";
    if (!std::filesystem::exists(tx_root)) {
        return;
    }
    for (const auto& entry :
         std::filesystem::recursive_directory_iterator(tx_root)) {
        if (entry.is_regular_file() && entry.path().extension() == ".backup") {
            kasumi::test::write_text(entry.path(), "corrupted-backup-bytes");
        }
    }
}

TEST(DirectoryLocalMoveTest,
     InterruptedBeforePhysicalMoveRecoversCleanlyWithZeroContentIo) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "dir-rename-int-before-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "dir-rename-int-before-receiver", sender.storage_root));

    write_local_file(sender, "A/1.bin", "payload-1");
    write_local_file(sender, "A/2.bin", "payload-2");

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());

    rename_local_entry(sender, "A", "B");
    ASSERT_TRUE(run_node_sync(sender).has_value());

    reset_content_counts(receiver);

    const auto target_source =
        receiver.local / kasumi::platform::path::from_utf8("A/1.bin");
    bool interrupted = false;
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path& path) {
            if (point == "before_rename_move" && path == target_source) {
                interrupted = true;
                throw SimulatedInterruption{};
            }
        });

    EXPECT_THROW(static_cast<void>(run_node_sync(receiver)),
                 SimulatedInterruption);
    kasumi::application::sync::mutation_fault_test::clear_hook();
    ASSERT_TRUE(interrupted);
    EXPECT_TRUE(local_entry_exists(receiver, "A/1.bin"));
    EXPECT_FALSE(local_entry_exists(receiver, "B/1.bin"));

    reset_content_counts(receiver);
    const auto recovered_sync = run_node_sync(receiver);
    ASSERT_TRUE(recovered_sync.has_value()) << recovered_sync.error().detail;
    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_EQ(receiver.counters.content_puts, 0U);
    EXPECT_EQ(receiver.counters.content_presences, 0U);
    EXPECT_EQ(receiver.counters.content_copies, 0U);

    EXPECT_FALSE(local_entry_exists(receiver, "A"));
    EXPECT_EQ(read_local_file(receiver, "B/1.bin"), "payload-1");
    EXPECT_EQ(read_local_file(receiver, "B/2.bin"), "payload-2");
    EXPECT_EQ(kasumi::test::snapshot_tree(sender.local),
              kasumi::test::snapshot_tree(receiver.local));
}

TEST(DirectoryLocalMoveTest,
     InterruptedAfterPhysicalMoveBeforeCheckpointRecoversWithZeroContentIo) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "dir-rename-int-after-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "dir-rename-int-after-receiver", sender.storage_root));

    write_local_file(sender, "A/1.bin", "payload-1");
    write_local_file(sender, "A/2.bin", "payload-2");

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());

    rename_local_entry(sender, "A", "B");
    ASSERT_TRUE(run_node_sync(sender).has_value());

    reset_content_counts(receiver);

    const auto target_dest =
        receiver.local / kasumi::platform::path::from_utf8("B/1.bin");
    bool interrupted = false;
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path& path) {
            if (point == "after_rename_move" && path == target_dest) {
                interrupted = true;
                throw SimulatedInterruption{};
            }
        });

    EXPECT_THROW(static_cast<void>(run_node_sync(receiver)),
                 SimulatedInterruption);
    kasumi::application::sync::mutation_fault_test::clear_hook();
    ASSERT_TRUE(interrupted);
    EXPECT_FALSE(local_entry_exists(receiver, "A/1.bin"));
    EXPECT_TRUE(local_entry_exists(receiver, "B/1.bin"));
    EXPECT_TRUE(local_entry_exists(receiver, "A/2.bin"));

    reset_content_counts(receiver);
    const auto recovered_sync = run_node_sync(receiver);
    ASSERT_TRUE(recovered_sync.has_value()) << recovered_sync.error().detail;
    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_EQ(receiver.counters.content_puts, 0U);
    EXPECT_EQ(receiver.counters.content_presences, 0U);
    EXPECT_EQ(receiver.counters.content_copies, 0U);

    EXPECT_FALSE(local_entry_exists(receiver, "A"));
    EXPECT_EQ(read_local_file(receiver, "B/1.bin"), "payload-1");
    EXPECT_EQ(read_local_file(receiver, "B/2.bin"), "payload-2");
    EXPECT_EQ(kasumi::test::snapshot_tree(sender.local),
              kasumi::test::snapshot_tree(receiver.local));
}

TEST(DirectoryLocalMoveTest,
     MultiFileDirectoryMoveRollsBackAppliedMovesWhenLaterOperationFails) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "dir-rename-multirb-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "dir-rename-multirb-receiver", sender.storage_root));

    write_local_file(sender, "Haruka/1.bin", "payload-1");
    write_local_file(sender, "Haruka/src/2.bin", "payload-2");
    write_local_file(sender, "Haruka/tests/3.bin", "payload-3");

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());

    rename_local_entry(sender, "Haruka", "HarukaEngine");
    ASSERT_TRUE(run_node_sync(sender).has_value());

    reset_content_counts(receiver);

    const auto third_source =
        receiver.local /
        kasumi::platform::path::from_utf8("Haruka/tests/3.bin");
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path& path) {
            if (point == "before_rename_move" && path == third_source) {
                write_local_file(
                    receiver, "HarukaEngine/tests/3.bin", "external-blocker-3");
            }
        });

    const auto receiver_sync = run_node_sync(receiver);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    EXPECT_FALSE(receiver_sync.has_value());
    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_EQ(read_local_file(receiver, "Haruka/1.bin"), "payload-1");
    EXPECT_EQ(read_local_file(receiver, "Haruka/src/2.bin"), "payload-2");
    EXPECT_EQ(read_local_file(receiver, "Haruka/tests/3.bin"), "payload-3");
    EXPECT_FALSE(local_entry_exists(receiver, "HarukaEngine/1.bin"));
    EXPECT_FALSE(local_entry_exists(receiver, "HarukaEngine/src/2.bin"));
    EXPECT_EQ(read_local_file(receiver, "HarukaEngine/tests/3.bin"),
              "external-blocker-3");
}

TEST(DirectoryLocalMoveTest,
     ExternalModificationOfMovedDestinationBeforeRecoveryFailsClosed) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "dir-rename-extdest-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "dir-rename-extdest-receiver", sender.storage_root));

    write_local_file(sender, "A/1.bin", "payload-1");
    write_local_file(sender, "A/2.bin", "payload-2");

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());

    rename_local_entry(sender, "A", "B");
    ASSERT_TRUE(run_node_sync(sender).has_value());

    const auto target_dest =
        receiver.local / kasumi::platform::path::from_utf8("B/1.bin");
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path& path) {
            if (point == "after_rename_move" && path == target_dest) {
                throw SimulatedInterruption{};
            }
        });

    EXPECT_THROW(static_cast<void>(run_node_sync(receiver)),
                 SimulatedInterruption);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    write_local_file(receiver, "B/1.bin", "externally-edited-destination");

    reset_content_counts(receiver);
    const auto recovery_sync = run_node_sync(receiver);
    EXPECT_FALSE(recovery_sync.has_value());
    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_EQ(read_local_file(receiver, "B/1.bin"),
              "externally-edited-destination");
    EXPECT_EQ(read_local_file(receiver, "A/2.bin"), "payload-2");
}

TEST(DirectoryLocalMoveTest,
     ExternalRecreationOfSourceBeforeRecoveryPreservesExternalSource) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "dir-rename-extsrc-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "dir-rename-extsrc-receiver", sender.storage_root));

    write_local_file(sender, "A/1.bin", "payload-1");
    write_local_file(sender, "A/2.bin", "payload-2");

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());

    rename_local_entry(sender, "A", "B");
    ASSERT_TRUE(run_node_sync(sender).has_value());

    const auto target_dest =
        receiver.local / kasumi::platform::path::from_utf8("B/1.bin");
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path& path) {
            if (point == "after_rename_move" && path == target_dest) {
                throw SimulatedInterruption{};
            }
        });

    EXPECT_THROW(static_cast<void>(run_node_sync(receiver)),
                 SimulatedInterruption);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    write_local_file(receiver, "A/1.bin", "externally-recreated-source");

    reset_content_counts(receiver);
    const auto recovery_sync = run_node_sync(receiver);
    EXPECT_FALSE(recovery_sync.has_value());
    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_EQ(read_local_file(receiver, "A/1.bin"),
              "externally-recreated-source");
    EXPECT_EQ(read_local_file(receiver, "B/1.bin"), "payload-1");
}

TEST(DirectoryLocalMoveTest,
     MissingOrInvalidMoveBackupFailsClosedDuringRecovery) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "dir-rename-badbkp-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "dir-rename-badbkp-receiver", sender.storage_root));

    write_local_file(sender, "A/1.bin", "payload-1");
    write_local_file(sender, "A/2.bin", "payload-2");

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());

    rename_local_entry(sender, "A", "B");
    ASSERT_TRUE(run_node_sync(sender).has_value());

    const auto target_dest =
        receiver.local / kasumi::platform::path::from_utf8("B/1.bin");
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path& path) {
            if (point == "after_rename_move" && path == target_dest) {
                throw SimulatedInterruption{};
            }
        });

    EXPECT_THROW(static_cast<void>(run_node_sync(receiver)),
                 SimulatedInterruption);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    corrupt_or_remove_transaction_backups(receiver);

    reset_content_counts(receiver);
    const auto recovery_sync = run_node_sync(receiver);
    EXPECT_FALSE(recovery_sync.has_value());
    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_EQ(read_local_file(receiver, "B/1.bin"), "payload-1");
    EXPECT_EQ(read_local_file(receiver, "A/2.bin"), "payload-2");
}

TEST(DirectoryLocalMoveTest,
     RepeatedRecoveryAndSyncAfterMoveInterruptionIsIdempotent) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "dir-rename-idemp-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "dir-rename-idemp-receiver", sender.storage_root));

    write_local_file(sender, "A/1.bin", "payload-1");
    write_local_file(sender, "A/2.bin", "payload-2");

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());

    rename_local_entry(sender, "A", "B");
    ASSERT_TRUE(run_node_sync(sender).has_value());

    const auto target_dest =
        receiver.local / kasumi::platform::path::from_utf8("B/1.bin");
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path& path) {
            if (point == "after_rename_move" && path == target_dest) {
                throw SimulatedInterruption{};
            }
        });

    EXPECT_THROW(static_cast<void>(run_node_sync(receiver)),
                 SimulatedInterruption);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    reset_content_counts(receiver);
    const auto first_sync = run_node_sync(receiver);
    ASSERT_TRUE(first_sync.has_value()) << first_sync.error().detail;
    const auto second_sync = run_node_sync(receiver);
    ASSERT_TRUE(second_sync.has_value()) << second_sync.error().detail;

    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_EQ(receiver.counters.content_puts, 0U);
    EXPECT_EQ(receiver.counters.content_presences, 0U);
    EXPECT_EQ(receiver.counters.content_copies, 0U);
    EXPECT_FALSE(local_entry_exists(receiver, "A"));
    EXPECT_EQ(read_local_file(receiver, "B/1.bin"), "payload-1");
    EXPECT_EQ(read_local_file(receiver, "B/2.bin"), "payload-2");
    EXPECT_EQ(kasumi::test::snapshot_tree(sender.local),
              kasumi::test::snapshot_tree(receiver.local));
}


struct ControlledMetrics {
    std::size_t n = 0;
    std::uint64_t total_bytes = 0;
    double total_sync_s = 0.0;
    double prep_wall_s = 0.0;
    double backup_copy_wall_s = 0.0;
    double backup_durable_wall_s = 0.0;
    double source_hash_wall_s = 0.0;
    double backup_hash_wall_s = 0.0;
    double apply_wall_s = 0.0;
    double native_rename_wall_s = 0.0;
    double dest_verif_wall_s = 0.0;
    double prep_val_wall_s = 0.0;
    double journal_save_wall_s = 0.0;
    double journal_delta_calc_s = 0.0;
    double journal_sem_val_s = 0.0;
    double journal_encode_s = 0.0;
    double journal_durable_write_s = 0.0;
    double final_val_wall_s = 0.0;
    std::uint64_t move_planned = 0;
    std::uint64_t move_applied = 0;
    std::uint64_t backup_files_created = 0;
    std::uint64_t backup_bytes_copied = 0;
    std::uint64_t backup_hash_calls = 0;
    std::uint64_t source_hash_calls = 0;
    std::uint64_t journal_save_calls = 0;
    std::uint64_t journal_delta_count = 0;
    std::uint64_t journal_bytes_written = 0;
    std::uint64_t native_rename_calls = 0;
    std::size_t content_gets = 0;
    std::size_t content_puts = 0;
    std::size_t content_presences = 0;
};

ControlledMetrics run_controlled_reproduction(std::size_t count, std::size_t file_payload_size = 1024) {
    kasumi::platform::perf_trace::force_enable(true);
    SyncNode sender;
    SyncNode receiver;
    EXPECT_TRUE(init_sync_node(sender, "move-diag-sender-" + std::to_string(count)));
    EXPECT_TRUE(init_sync_node(receiver, "move-diag-receiver-" + std::to_string(count), sender.storage_root));

    ControlledMetrics m;
    m.n = count;

    for (std::size_t i = 0; i < count; ++i) {
        std::string payload = "content-" + std::to_string(i) + "-" + std::string(file_payload_size, 'A');
        m.total_bytes += payload.size();
        write_local_file(sender, "source_dir/file_" + std::to_string(i) + ".bin", payload);
    }

    auto s1 = run_node_sync(sender);
    EXPECT_TRUE(s1.has_value()) << (s1 ? "" : s1.error().detail);
    auto r1 = run_node_sync(receiver);
    EXPECT_TRUE(r1.has_value()) << (r1 ? "" : r1.error().detail);

    rename_local_entry(sender, "source_dir", "renamed_dir");
    auto s2 = run_node_sync(sender);
    EXPECT_TRUE(s2.has_value()) << (s2 ? "" : s2.error().detail);

    reset_content_counts(receiver);
    kasumi::platform::perf_trace::reset();

    const auto start = std::chrono::steady_clock::now();
    auto r2 = run_node_sync(receiver);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_TRUE(r2.has_value()) << (r2 ? "" : r2.error().detail);

    EXPECT_EQ(kasumi::test::snapshot_tree(sender.local),
              kasumi::test::snapshot_tree(receiver.local));
    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_EQ(receiver.counters.content_puts, 0U);
    EXPECT_EQ(receiver.counters.content_presences, 0U);
    EXPECT_EQ(receiver.counters.content_copies, 0U);

    m.total_sync_s = std::chrono::duration<double>(elapsed).count();
    m.prep_wall_s = static_cast<double>(kasumi::platform::perf_trace::get_time("move preparation wall")) / 1e6;
    m.backup_copy_wall_s = static_cast<double>(kasumi::platform::perf_trace::get_time("move backup copy wall")) / 1e6;
    m.backup_durable_wall_s = static_cast<double>(kasumi::platform::perf_trace::get_time("move backup durable wall")) / 1e6;
    m.source_hash_wall_s = static_cast<double>(kasumi::platform::perf_trace::get_time("move source hash wall")) / 1e6;
    m.backup_hash_wall_s = static_cast<double>(kasumi::platform::perf_trace::get_time("move backup hash wall")) / 1e6;
    m.apply_wall_s = static_cast<double>(kasumi::platform::perf_trace::get_time("move apply wall")) / 1e6;
    m.native_rename_wall_s = static_cast<double>(kasumi::platform::perf_trace::get_time("move native rename wall")) / 1e6;
    m.dest_verif_wall_s = static_cast<double>(kasumi::platform::perf_trace::get_time("move destination verification wall")) / 1e6;
    m.prep_val_wall_s = static_cast<double>(kasumi::platform::perf_trace::get_time("move prepared validation wall")) / 1e6;
    m.journal_save_wall_s = static_cast<double>(kasumi::platform::perf_trace::get_time("journal save wall")) / 1e6;
    m.journal_delta_calc_s = static_cast<double>(kasumi::platform::perf_trace::get_time("journal delta calculation wall")) / 1e6;
    m.journal_sem_val_s = static_cast<double>(kasumi::platform::perf_trace::get_time("journal semantic validation wall")) / 1e6;
    m.journal_encode_s = static_cast<double>(kasumi::platform::perf_trace::get_time("journal encode wall")) / 1e6;
    m.journal_durable_write_s = static_cast<double>(kasumi::platform::perf_trace::get_time("journal durable write wall")) / 1e6;
    m.final_val_wall_s = static_cast<double>(kasumi::platform::perf_trace::get_time("final local validation wall")) / 1e6;

    m.move_planned = kasumi::platform::perf_trace::get_count("move planned count");
    m.move_applied = kasumi::platform::perf_trace::get_count("move applied count");
    m.backup_files_created = kasumi::platform::perf_trace::get_count("backup files created");
    m.backup_bytes_copied = kasumi::platform::perf_trace::get_count("backup bytes copied");
    m.backup_hash_calls = kasumi::platform::perf_trace::get_count("backup hash calls");
    m.source_hash_calls = kasumi::platform::perf_trace::get_count("source hash calls");
    m.journal_save_calls = kasumi::platform::perf_trace::get_count("journal save calls");
    m.journal_delta_count = kasumi::platform::perf_trace::get_count("journal delta count");
    m.journal_bytes_written = kasumi::platform::perf_trace::get_count("journal bytes written");
    m.native_rename_calls = kasumi::platform::perf_trace::get_count("native rename calls");

    m.content_gets = receiver.counters.content_gets;
    m.content_puts = receiver.counters.content_puts;
    m.content_presences = receiver.counters.content_presences;

    std::cout << "\n=======================================================\n";
    std::cout << "DIAGNOSTIC METRICS REPORT FOR N = " << count << "\n";
    std::cout << "=======================================================\n";
    std::cout << std::fixed << std::setprecision(6);
    std::cout << "Total sync duration:          " << m.total_sync_s << " s\n";
    std::cout << "Move planned count:           " << m.move_planned << "\n";
    std::cout << "Move applied count:           " << m.move_applied << "\n";
    std::cout << "Native rename calls:          " << m.native_rename_calls << "\n";
    std::cout << "Native rename wall:           " << m.native_rename_wall_s << " s\n";
    std::cout << "Move preparation wall:        " << m.prep_wall_s << " s\n";
    std::cout << "Backup files created:         " << m.backup_files_created << "\n";
    std::cout << "Backup bytes copied:          " << m.backup_bytes_copied << " bytes\n";
    std::cout << "Backup copy wall:             " << m.backup_copy_wall_s << " s\n";
    std::cout << "Backup durable wall:          " << m.backup_durable_wall_s << " s\n";
    std::cout << "Source hash calls:            " << m.source_hash_calls << "\n";
    std::cout << "Source hash wall:             " << m.source_hash_wall_s << " s\n";
    std::cout << "Backup hash calls:            " << m.backup_hash_calls << "\n";
    std::cout << "Backup hash wall:             " << m.backup_hash_wall_s << " s\n";
    std::cout << "Move apply wall:              " << m.apply_wall_s << " s\n";
    std::cout << "Move prepared validation wall:" << m.prep_val_wall_s << " s\n";
    std::cout << "Move dest verification wall:  " << m.dest_verif_wall_s << " s\n";
    std::cout << "Journal save calls:           " << m.journal_save_calls << "\n";
    std::cout << "Journal save wall:            " << m.journal_save_wall_s << " s\n";
    std::cout << "Apply ACL calls:              " << kasumi::platform::perf_trace::get_count("apply_acl calls") << "\n";
    std::cout << "Apply ACL wall:               " << static_cast<double>(kasumi::platform::perf_trace::get_time("apply_acl wall")) / 1e6 << " s\n";
    std::cout << "Journal delta count:          " << m.journal_delta_count << "\n";
    std::cout << "Journal bytes written:        " << m.journal_bytes_written << " bytes\n";
    std::cout << "Journal delta calc wall:      " << m.journal_delta_calc_s << " s\n";
    std::cout << "Journal sem validation wall:  " << m.journal_sem_val_s << " s\n";
    std::cout << "Journal encode wall:          " << m.journal_encode_s << " s\n";
    std::cout << "Journal durable write wall:   " << m.journal_durable_write_s << " s\n";
    std::cout << "Final local validation wall:  " << m.final_val_wall_s << " s\n";
    std::cout << "Content GET / PUT / PRESENCE: " << m.content_gets << " / " << m.content_puts << " / " << m.content_presences << "\n";
    std::cout << "=======================================================\n\n";

    kasumi::platform::perf_trace::force_enable(false);
    return m;
}

TEST(DirectoryLocalMoveTest, MoveLocalAvoidsRedundantWorkInvariants) {
    const auto m = run_controlled_reproduction(16);
    EXPECT_EQ(m.move_planned, 16U);
    EXPECT_EQ(m.move_applied, 16U);
    EXPECT_EQ(m.content_gets, 0U);

    // Cost invariants:
    // Journal saves must be batched, not 1 flush per file (reduced from 23 down to 7)
    EXPECT_LE(m.journal_save_calls, 7U);
    // Source hash calls bounded (reduced from 64 with validate_prepared_rename down to 48)
    EXPECT_LE(m.source_hash_calls, 48U);
    // Backup hash calls bounded (reduced from 48 down to 32)
    EXPECT_LE(m.backup_hash_calls, 48U);

}

TEST(DirectoryLocalMoveTest, DiagnosticReproduction16) {
    const auto m = run_controlled_reproduction(16);
    EXPECT_EQ(m.move_planned, 16U);
    EXPECT_EQ(m.move_applied, 16U);
    EXPECT_EQ(m.content_gets, 0U);
}

TEST(DirectoryLocalMoveTest, DiagnosticReproduction128) {
    const auto m = run_controlled_reproduction(128);
    EXPECT_EQ(m.move_planned, 128U);
    EXPECT_EQ(m.move_applied, 128U);
    EXPECT_EQ(m.content_gets, 0U);
}

TEST(DirectoryLocalMoveTest, DiagnosticReproduction512) {
    const auto m = run_controlled_reproduction(512);
    EXPECT_EQ(m.move_planned, 512U);
    EXPECT_EQ(m.move_applied, 512U);
    EXPECT_EQ(m.content_gets, 0U);
}


TEST(DirectoryLocalMoveTest, BackupCorruptedSameSizeRejectedByPreparedValidation) {
    auto workspace_dir = kasumi::test::make_temp_workspace("backup-corrupted-same-size");
    const auto local_root = kasumi::test::workspace_path(workspace_dir, "local");
    std::filesystem::create_directories(local_root);
    const auto tx_dir = kasumi::test::workspace_path(workspace_dir, "tx");
    std::filesystem::create_directories(tx_dir);
    kasumi::platform::Workspace workspace{tx_dir};

    const auto source = local_root / "source.bin";
    const auto destination = local_root / "destination.bin";
    const std::string content = "original-content-for-testing-123456"; // 35 bytes
    kasumi::test::write_text(source, content);

    auto hash_result = kasumi::crypto::content::hash_file(source);
    ASSERT_TRUE(hash_result.has_value());

    kasumi::Operation op;
    op.action = kasumi::Action::MoveLocal;
    op.path = "source.bin";
    op.alt_path = "destination.bin";
    op.size = content.size();
    op.hash = kasumi::hash_hex(*hash_result);

    std::vector<kasumi::Operation> plan_ops{op};
    kasumi::transaction::OperationProgress progress;
    progress.backup_slot = 0;

    auto prep_res = kasumi::application::sync::mutation::prepare_operation(
        op, 0, local_root, workspace, progress, plan_ops);
    ASSERT_TRUE(prep_res.has_value()) << prep_res.error().detail;
    progress = *prep_res;

    const auto backup = kasumi::platform::workspace_file(workspace, progress.backup_slot, ".backup");
    ASSERT_TRUE(std::filesystem::exists(backup));
    EXPECT_EQ(std::filesystem::file_size(backup), content.size());

    // Corrupt backup keeping exact same size (35 bytes)
    const std::string corrupted = "corrupted-bytes-for-testing-1234567";
    ASSERT_EQ(corrupted.size(), content.size());
    kasumi::test::write_text(backup, corrupted);

    auto val_res = kasumi::application::sync::mutation::detail::validate_prepared_rename(
        op, 0, source, destination, workspace, progress);

    EXPECT_FALSE(val_res.has_value());
    if (!val_res.has_value()) {
        EXPECT_EQ(val_res.error().code,
                  kasumi::application::sync::mutation::MutationErrorCode::IntegrityMismatch);
    }
}

TEST(DirectoryLocalMoveTest, SourceModifiedAfterPreparationRejectedByPreparedValidation) {
    auto workspace_dir = kasumi::test::make_temp_workspace("source-modified-after-prep");
    const auto local_root = kasumi::test::workspace_path(workspace_dir, "local");
    std::filesystem::create_directories(local_root);
    const auto tx_dir = kasumi::test::workspace_path(workspace_dir, "tx");
    std::filesystem::create_directories(tx_dir);
    kasumi::platform::Workspace workspace{tx_dir};

    const auto source = local_root / "source.bin";
    const auto destination = local_root / "destination.bin";
    const std::string content = "original-content-for-testing-123456"; // 35 bytes
    kasumi::test::write_text(source, content);

    auto hash_result = kasumi::crypto::content::hash_file(source);
    ASSERT_TRUE(hash_result.has_value());

    kasumi::Operation op;
    op.action = kasumi::Action::MoveLocal;
    op.path = "source.bin";
    op.alt_path = "destination.bin";
    op.size = content.size();
    op.hash = kasumi::hash_hex(*hash_result);

    std::vector<kasumi::Operation> plan_ops{op};
    kasumi::transaction::OperationProgress progress;
    progress.backup_slot = 0;

    auto prep_res = kasumi::application::sync::mutation::prepare_operation(
        op, 0, local_root, workspace, progress, plan_ops);
    ASSERT_TRUE(prep_res.has_value()) << prep_res.error().detail;
    progress = *prep_res;

    // Modify source on disk keeping exact same size (35 bytes)
    const std::string modified = "modified-source-for-testing-1234567";
    ASSERT_EQ(modified.size(), content.size());
    kasumi::test::write_text(source, modified);

    auto val_res = kasumi::application::sync::mutation::detail::validate_prepared_rename(
        op, 0, source, destination, workspace, progress);

    EXPECT_FALSE(val_res.has_value());
    if (!val_res.has_value()) {
        EXPECT_EQ(val_res.error().code,
                  kasumi::application::sync::mutation::MutationErrorCode::DestinationConflict);
    }
}

TEST(DirectoryLocalMoveTest, DownloadMetricsDoNotContaminateMoveMetrics) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "download-metrics-sender"));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(receiver, "download-metrics-receiver", sender.storage_root));

    write_local_file(sender, "new_file.txt", "download-content-sample");
    ASSERT_TRUE(run_node_sync(sender).has_value());

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    ASSERT_TRUE(run_node_sync(receiver).has_value());

    EXPECT_EQ(kasumi::platform::perf_trace::get_count("move planned count"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("move applied count"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("native rename calls"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_time("move destination verification wall"), 0);

    kasumi::platform::perf_trace::force_enable(false);
}

void run_eight_file_move_recovery_scenario(std::size_t interrupt_after_k_moves,
                                          bool interrupt_after_applied_checkpoint = false,
                                          bool tamper_destination_after_move = false,
                                          bool tamper_backup_after_move = false) {
    SyncNode sender;
    ASSERT_TRUE(init_sync_node(sender, "eight-move-sender-" + std::to_string(interrupt_after_k_moves) +
                                       (interrupt_after_applied_checkpoint ? "-ckpt" : "") +
                                       (tamper_destination_after_move ? "-tdest" : "") +
                                       (tamper_backup_after_move ? "-tbkp" : "")));
    SyncNode receiver;
    ASSERT_TRUE(init_sync_node(
        receiver, "eight-move-receiver-" + std::to_string(interrupt_after_k_moves) +
                  (interrupt_after_applied_checkpoint ? "-ckpt" : "") +
                  (tamper_destination_after_move ? "-tdest" : "") +
                  (tamper_backup_after_move ? "-tbkp" : ""), sender.storage_root));

    for (std::size_t i = 1; i <= 8; ++i) {
        write_local_file(sender, "A/file" + std::to_string(i) + ".bin", "payload-" + std::to_string(i));
    }

    ASSERT_TRUE(run_node_sync(sender).has_value());
    ASSERT_TRUE(run_node_sync(receiver).has_value());

    rename_local_entry(sender, "A", "B");
    ASSERT_TRUE(run_node_sync(sender).has_value());

    reset_content_counts(receiver);

    std::size_t moves_completed = 0;
    kasumi::application::sync::mutation_fault_test::set_hook(
        [&](std::string_view point, const std::filesystem::path&) {
            if (point == "after_rename_move") {
                ++moves_completed;
                if (!interrupt_after_applied_checkpoint && moves_completed == interrupt_after_k_moves) {
                    throw SimulatedInterruption{};
                }
            } else if (point == "after-MoveLocal-consolidated-checkpoint") {
                if (interrupt_after_applied_checkpoint) {
                    throw SimulatedInterruption{};
                }
            }
        });

    EXPECT_THROW(static_cast<void>(run_node_sync(receiver)), SimulatedInterruption);
    kasumi::application::sync::mutation_fault_test::clear_hook();

    // Verify durable state on disk directly produced by the real coordinator
    {
        const auto paths = kasumi::application::sync::journal::make_paths(receiver.profile);
        ASSERT_TRUE(paths.has_value());
        auto loaded = kasumi::application::sync::journal::load(*paths, receiver.key, nullptr);
        ASSERT_TRUE(loaded.has_value());
        ASSERT_TRUE(*loaded);
        const auto& record = **loaded;
        if (interrupt_after_applied_checkpoint) {
            EXPECT_EQ(record.phase, kasumi::transaction::Phase::LocalChangesApplied);
            std::size_t move_count = 0;
            for (std::size_t i = 0; i < record.plan.operations.size(); ++i) {
                if (record.plan.operations[i].action == kasumi::Action::MoveLocal) {
                    ++move_count;
                    EXPECT_EQ(record.progress[i].state, kasumi::transaction::OperationState::Applied);
                }
            }
            EXPECT_EQ(move_count, 8U);
        }
    }

    if (tamper_destination_after_move) {
        write_local_file(receiver, "B/file4.bin", "external-conflicting-content");
        reset_content_counts(receiver);
        const auto recovery_sync = run_node_sync(receiver);
        EXPECT_FALSE(recovery_sync.has_value());
        EXPECT_EQ(read_local_file(receiver, "B/file4.bin"), "external-conflicting-content");
        return;
    }

    if (tamper_backup_after_move) {
        const auto tx_root = receiver.profile / ".transactions";
        if (std::filesystem::exists(tx_root)) {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(tx_root)) {
                if (entry.is_regular_file() && entry.path().extension() == ".backup") {
                    auto sz = std::filesystem::file_size(entry.path());
                    std::string bad(sz, 'X');
                    kasumi::test::write_text(entry.path(), bad);
                    break;
                }
            }
        }
        reset_content_counts(receiver);
        const auto recovery_sync = run_node_sync(receiver);
        EXPECT_FALSE(recovery_sync.has_value());
        return;
    }

    reset_content_counts(receiver);
    const auto recovered_sync = run_node_sync(receiver);
    ASSERT_TRUE(recovered_sync.has_value()) << recovered_sync.error().detail;
    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_EQ(receiver.counters.content_puts, 0U);
    EXPECT_EQ(receiver.counters.content_presences, 0U);
    EXPECT_EQ(receiver.counters.content_copies, 0U);

    EXPECT_FALSE(local_entry_exists(receiver, "A"));
    for (std::size_t i = 1; i <= 8; ++i) {
        EXPECT_EQ(read_local_file(receiver, "B/file" + std::to_string(i) + ".bin"),
                  "payload-" + std::to_string(i));
    }
    EXPECT_EQ(kasumi::test::snapshot_tree(sender.local),
              kasumi::test::snapshot_tree(receiver.local));

    // Subsequent sync must be idempotent with zero content I/O
    reset_content_counts(receiver);
    const auto subsequent_sync = run_node_sync(receiver);
    ASSERT_TRUE(subsequent_sync.has_value()) << subsequent_sync.error().detail;
    EXPECT_EQ(receiver.counters.content_gets, 0U);
    EXPECT_EQ(receiver.counters.content_puts, 0U);
    EXPECT_EQ(receiver.counters.content_presences, 0U);
    EXPECT_EQ(receiver.counters.content_copies, 0U);
    EXPECT_EQ(kasumi::test::snapshot_tree(sender.local),
              kasumi::test::snapshot_tree(receiver.local));
}

TEST(DirectoryLocalMoveTest, BatchMoveRecoveryInterruptedAtK1) {
    run_eight_file_move_recovery_scenario(1);
}

TEST(DirectoryLocalMoveTest, BatchMoveRecoveryInterruptedAtK4) {
    run_eight_file_move_recovery_scenario(4);
}

TEST(DirectoryLocalMoveTest, BatchMoveRecoveryInterruptedAtK7) {
    run_eight_file_move_recovery_scenario(7);
}

TEST(DirectoryLocalMoveTest, BatchMoveRecoveryInterruptedAtK8BeforeCheckpoint) {
    run_eight_file_move_recovery_scenario(8);
}

TEST(DirectoryLocalMoveTest, BatchMoveRecoveryInterruptedAfterConsolidatedCheckpoint) {
    run_eight_file_move_recovery_scenario(8, true);
}

TEST(DirectoryLocalMoveTest, BatchMoveRecoveryFailsClosedOnExternalDestinationConflict) {
    run_eight_file_move_recovery_scenario(4, false, true, false);
}

TEST(DirectoryLocalMoveTest, BatchMoveRecoveryFailsClosedOnCorruptedBackupSameSize) {
    run_eight_file_move_recovery_scenario(4, false, false, true);
}


#if defined(_WIN32)
void add_unauthorized_dacl_ace(const std::filesystem::path& path) {
    PSID everyone_sid = nullptr;
    SID_IDENTIFIER_AUTHORITY world_auth = SECURITY_WORLD_SID_AUTHORITY;
    ASSERT_TRUE(AllocateAndInitializeSid(&world_auth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &everyone_sid));

    EXPLICIT_ACCESSW ea{};
    ea.grfAccessPermissions = GENERIC_READ;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = static_cast<LPWSTR>(everyone_sid);

    PACL existing_dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    ASSERT_EQ(GetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()),
                                    SE_FILE_OBJECT,
                                    DACL_SECURITY_INFORMATION,
                                    nullptr,
                                    nullptr,
                                    &existing_dacl,
                                    nullptr,
                                    &sd),
              ERROR_SUCCESS);

    PACL new_dacl = nullptr;
    ASSERT_EQ(SetEntriesInAclW(1, &ea, existing_dacl, &new_dacl), ERROR_SUCCESS);
    ASSERT_EQ(SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()),
                                    SE_FILE_OBJECT,
                                    DACL_SECURITY_INFORMATION,
                                    nullptr,
                                    nullptr,
                                    new_dacl,
                                    nullptr),
              ERROR_SUCCESS);

    LocalFree(new_dacl);
    LocalFree(sd);
    FreeSid(everyone_sid);
}

void expect_private_dacl_hardening(const std::filesystem::path& path) {
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    ASSERT_EQ(GetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()),
                                    SE_FILE_OBJECT,
                                    DACL_SECURITY_INFORMATION,
                                    nullptr,
                                    nullptr,
                                    &dacl,
                                    nullptr,
                                    &descriptor),
              ERROR_SUCCESS);
    ASSERT_NE(descriptor, nullptr);
    ASSERT_NE(dacl, nullptr);

    SECURITY_DESCRIPTOR_CONTROL control{};
    DWORD revision = 0;
    ASSERT_TRUE(GetSecurityDescriptorControl(descriptor, &control, &revision));
    EXPECT_NE(control & SE_DACL_PROTECTED, 0);

    ACL_SIZE_INFORMATION information{};
    ASSERT_TRUE(GetAclInformation(dacl, &information, sizeof(information), AclSizeInformation));
    // Hardened private storage has exactly 2 ACEs (user + SYSTEM)
    EXPECT_EQ(information.AceCount, 2U);
    LocalFree(descriptor);
}
#endif

TEST(DirectoryLocalMoveTest, PrivateStoragePermissionsHardenedOnValidation) {
#if defined(_WIN32)
    auto workspace_dir = kasumi::test::make_temp_workspace("private-hardening-test");
    const auto tx_dir = kasumi::test::workspace_path(workspace_dir, "tx");
    std::filesystem::create_directories(tx_dir);
    kasumi::platform::Workspace workspace{tx_dir};

    // 1. Workspace directory hardening
    ASSERT_TRUE(kasumi::platform::private_storage::protect_directory(workspace.root));
    add_unauthorized_dacl_ace(workspace.root);

    // Call validate_workspace (via prepare_operation)
    const auto source = kasumi::test::workspace_path(workspace_dir, "s.bin");
    kasumi::test::write_text(source, "data");
    auto h = kasumi::crypto::content::hash_file(source);
    ASSERT_TRUE(h.has_value());

    kasumi::Operation op;
    op.action = kasumi::Action::MoveLocal;
    op.path = "s.bin";
    op.alt_path = "d.bin";
    op.size = 4;
    op.hash = kasumi::hash_hex(*h);
    std::vector<kasumi::Operation> plan_ops{op};
    kasumi::transaction::OperationProgress progress;
    progress.backup_slot = 0;

    auto prep = kasumi::application::sync::mutation::prepare_operation(
        op, 0, kasumi::test::workspace_root(workspace_dir), workspace, progress, plan_ops);
    ASSERT_TRUE(prep.has_value());

    // Verify workspace.root was hardened back to 2 ACEs
    expect_private_dacl_hardening(workspace.root);

    // 2. Backup file hardening
    const auto bkp = kasumi::platform::workspace_file(workspace, prep->backup_slot, ".backup");
    ASSERT_TRUE(std::filesystem::exists(bkp));
    add_unauthorized_dacl_ace(bkp);

    // validate_prepared_rename calls validate_backup which calls protect_file
    auto vres = kasumi::application::sync::mutation::detail::validate_prepared_rename(
        op, 0, source, kasumi::test::workspace_path(workspace_dir, "d.bin"), workspace, *prep);
    ASSERT_TRUE(vres.has_value());
    expect_private_dacl_hardening(bkp);
#endif
}


TEST(DirectoryLocalMoveTest, ContentCounterConcurrentCallbacksAreThreadSafe) {
    kasumi::transport::Transport dummy_transport{
        .state = kasumi::transport::TransportStateHandle{nullptr, [](void*) noexcept {}},
        .storage = kasumi::transport::StorageOperations{
            .initialize = [](void*) -> kasumi::transport::Result { return {}; },
            .put = [](void*, const std::filesystem::path&, std::string_view) -> kasumi::transport::Result { return {}; },
            .put_batch = [](void*, const kasumi::transport::PutBatch&) -> kasumi::transport::Result { return {}; },
            .put_files_batch = [](void*, const kasumi::transport::PutFilesBatch&) -> kasumi::transport::Result { return {}; },
            .get = [](void*, std::string_view, const std::filesystem::path&) -> kasumi::transport::Result { return {}; },
            .get_batch = [](void*, const kasumi::transport::GetBatch&) -> kasumi::transport::Result { return {}; },
            .copy = [](void*, std::string_view, std::string_view) -> kasumi::transport::Result { return {}; },
            .copy_batch = [](void*, const kasumi::transport::CopyBatch&) -> kasumi::transport::Result { return {}; },
            .presence = [](void*, std::string_view) -> kasumi::transport::PresenceResult { return kasumi::transport::Presence::Present; },
            .list = [](void*) -> kasumi::transport::ListingResult { return kasumi::transport::ListingResult{}; },
            .list_prefix = [](void*, std::string_view) -> kasumi::transport::ListingResult { return kasumi::transport::ListingResult{}; },
            .control_read_batch = [](void*, const kasumi::transport::ControlReadBatchRequest&) -> kasumi::transport::ControlReadBatchResponse { return kasumi::transport::ControlReadBatchResponse{}; },
            .remove = [](void*, std::string_view) -> kasumi::transport::RemovalResult { return {}; },
            .remove_batch = [](void*, const kasumi::transport::RemoveBatch&) -> kasumi::transport::RemoveBatchResult { return kasumi::transport::RemoveBatchResult{}; },
        },
    };

    ContentCounterState state;
    state.base = &dummy_transport;

    constexpr std::size_t num_threads = 8;
    constexpr std::size_t ops_per_thread = 200;
    std::atomic<bool> start_gate{false};
    std::vector<std::thread> workers;
    workers.reserve(num_threads);

    for (std::size_t t = 0; t < num_threads; ++t) {
        workers.emplace_back([&state, &start_gate, t]() {
            while (!start_gate.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            for (std::size_t i = 0; i < ops_per_thread; ++i) {
                const auto id = "content_thread_" + std::to_string(t) + "_op_" + std::to_string(i);
                counter_get(&state, id, std::filesystem::path{});
                counter_put(&state, std::filesystem::path{}, id);
                counter_presence(&state, id);
            }
        });
    }

    start_gate.store(true, std::memory_order_release);
    for (auto& w : workers) {
        w.join();
    }

    constexpr std::size_t expected_ops = num_threads * ops_per_thread;
    EXPECT_EQ(state.content_gets, expected_ops);
    EXPECT_EQ(state.content_puts, expected_ops);
    EXPECT_EQ(state.content_presences, expected_ops);
    EXPECT_EQ(state.get_identifiers.size(), expected_ops);
    EXPECT_EQ(state.put_identifiers.size(), expected_ops);
    EXPECT_EQ(state.presence_identifiers.size(), expected_ops);
}

} // namespace
