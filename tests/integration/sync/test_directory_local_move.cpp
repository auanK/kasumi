#include "application/sync/mutation_fault_test.hpp"
#include "application/use_cases/context.hpp"
#include "crypto/content.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/history_storage.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/path.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

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
    std::size_t content_gets = 0;
    std::size_t content_puts = 0;
    std::size_t content_presences = 0;
    std::size_t content_copies = 0;
    std::vector<std::string> get_identifiers;
    std::vector<std::string> put_identifiers;
    std::vector<std::string> presence_identifiers;
};

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
        ++state->content_puts;
        state->put_identifiers.emplace_back(identifier);
    }
    return kasumi::transport::put(*state->base, source, identifier);
}

kasumi::transport::Result
counter_put_batch(void* context, const kasumi::transport::PutBatch& batch) {
    auto* state = static_cast<ContentCounterState*>(context);
    for (const auto& identifier : batch.identifiers) {
        if (is_content_identifier(identifier)) {
            ++state->content_puts;
            state->put_identifiers.push_back(identifier);
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
        ++state->content_gets;
        state->get_identifiers.emplace_back(identifier);
    }
    return kasumi::transport::get(*state->base, identifier, destination);
}

kasumi::transport::Result
counter_get_batch(void* context, const kasumi::transport::GetBatch& batch) {
    auto* state = static_cast<ContentCounterState*>(context);
    if (batch.source_prefix.empty()) {
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

} // namespace
