#ifndef KASUMI_TEST_HISTORY_STORAGE_HELPERS_HPP
#define KASUMI_TEST_HISTORY_STORAGE_HELPERS_HPP

#include "application/history_storage/history_storage.hpp"
#include "core/history.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/physical_hash.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using kasumi::Snapshot;
#ifndef KASUMI_TEST_HISTORY_STORAGE_NO_ERROR_CODE_ALIAS
using kasumi::application::history_storage::ErrorCode;
#endif
using kasumi::application::history_storage::HeadReference;
using kasumi::application::history_storage::LoadedHistory;
using kasumi::history::Commit;
using kasumi::history::CommitResult;
using kasumi::history::LoadedCommit;
using kasumi::history::Resolution;
using kasumi::test::TempWorkspace;

std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> test_key() {
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    for (std::size_t index = 0; index < key.size(); ++index) {
        key[index] = static_cast<std::uint8_t>(index + 1);
    }
    return key;
}

Snapshot make_tree(std::string_view path, std::string_view contents) {
    Snapshot tree{
        .rows =
            {
                kasumi::NodeRow{.path = "",
                                .hash = {},
                                .size = 0,
                                .mtime = {},
                                .is_directory = true},
                kasumi::NodeRow{.path = std::string{path},
                                .hash = kasumi::hasher::hash_string(contents),
                                .size = contents.size(),
                                .mtime = {},
                                .is_directory = false},
            },
    };
    kasumi::finalize_snapshot(tree);
    return tree;
}

[[maybe_unused]] CommitResult
make_commit(std::uint64_t height,
            const std::vector<std::string>& parents,
            std::string_view path,
            std::string_view contents) {
    return kasumi::history::make_commit(
        height, parents, make_tree(path, contents));
}

std::string commit_id(const Commit& commit) {
    const auto canonical = kasumi::history::serialize(commit).value();
    return kasumi::crypto::commit_identifier(test_key(), canonical);
}

std::string object_path(const HeadReference& reference) {
    return "history/commits/" + reference.commit_id + "/" +
           reference.ciphertext_id + ".kcom";
}

std::string marker_path(const HeadReference& reference) {
    return "history/heads/" + reference.commit_id + "-" +
           reference.ciphertext_id + ".head";
}

struct LocalStorage {
    kasumi::transport::Transport transport;
    TempWorkspace workspace;
};

[[maybe_unused]] LocalStorage make_local_storage() {
    LocalStorage storage{.transport = {},
                         .workspace = kasumi::test::make_temp_workspace(
                             "history-storage-local")};
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(storage.workspace, "storage").string());
    EXPECT_TRUE(opened.has_value());
    if (opened) {
        storage.transport = std::move(*opened);
        EXPECT_TRUE(kasumi::transport::initialize(storage.transport));
    }
    return storage;
}

[[maybe_unused]] HeadReference add_variant(LocalStorage& storage,
                                           const Commit& commit) {
    const auto key = test_key();
    const auto canonical = kasumi::history::serialize(commit).value();
    const auto plaintext =
        kasumi::test::workspace_path(storage.workspace, "variant.kcom");
    const auto ciphertext =
        kasumi::test::workspace_path(storage.workspace, "variant.ciphertext");
    kasumi::test::write_binary(plaintext, std::as_bytes(std::span{canonical}));
    EXPECT_TRUE(kasumi::crypto::encrypt_file(
        plaintext, ciphertext, key, kasumi::crypto::FilePurpose::History));
    const auto hash = kasumi::crypto::content::hash_file(ciphertext).value();
    HeadReference reference{.commit_id = commit_id(commit),
                            .ciphertext_id = kasumi::hash_hex(hash)};
    EXPECT_TRUE(kasumi::transport::put(
        storage.transport, ciphertext, object_path(reference)));
    const auto marker =
        kasumi::application::history_storage::encode_marker(reference).value();
    const auto marker_file =
        kasumi::test::workspace_path(storage.workspace, "variant.head");
    kasumi::test::write_binary(marker_file, std::as_bytes(std::span{marker}));
    EXPECT_TRUE(kasumi::transport::put(
        storage.transport, marker_file, marker_path(reference)));
    return reference;
}

[[maybe_unused]] kasumi::application::history_storage::PublishedCommit
publish(LocalStorage& storage, const Commit& commit) {
    auto key = test_key();
    auto result = kasumi::application::history_storage::publish_commit(
        storage.transport,
        key,
        commit,
        kasumi::test::workspace_root(storage.workspace));
    EXPECT_TRUE(result.has_value());
    return result ? *result
                  : kasumi::application::history_storage::PublishedCommit{};
}

[[maybe_unused]] LoadedHistory load(LocalStorage& storage) {
    auto key = test_key();
    auto result = kasumi::application::history_storage::load_history(
        storage.transport,
        key,
        kasumi::test::workspace_root(storage.workspace));
    EXPECT_TRUE(result.has_value());
    return result ? *result : LoadedHistory{};
}

struct FakeState {
    std::map<std::string, std::vector<std::uint8_t>> objects;
    std::map<std::string, std::vector<std::uint8_t>> hidden_objects;
    std::size_t list_count = 0;
    std::size_t full_list_count = 0;
    std::size_t prefix_list_count = 0;
    std::size_t reveal_on_list_count = 0;
    std::size_t get_count = 0;
    std::size_t get_batch_count = 0;
    std::size_t presence_count = 0;
    std::size_t remove_count = 0;
    std::size_t put_count = 0;
    std::size_t put_batch_count = 0;
    std::size_t commit_put_count = 0;
    std::size_t marker_put_count = 0;
    std::size_t commit_get_count = 0;
    std::size_t marker_get_count = 0;
    std::size_t physical_hash_count = 0;
    std::map<std::string, std::string> physical_hashes;
    bool physical_hash_supported = false;
    bool physical_hash_mismatch = false;
    std::size_t control_read_batch_count = 0;
    bool control_read_batch_supported = false;
    std::optional<kasumi::transport::ErrorCode> control_read_batch_failure;
    bool hide_writer_listing = false;
    bool publish_barrier_after_writer_list = false;
    bool fail_writer_list = false;
    bool fail_barrier_presence = false;
    bool fail_commit_put = false;
    bool persist_commit_on_put_failure = false;
    bool fail_commit_get = false;
    bool fail_content_get = false;
    bool fail_marker_put = false;
    bool persist_marker_on_put_failure = false;
    bool fail_marker_get = false;
    std::size_t fail_remove_at = 0;
    std::string fail_remove_identifier;
    std::string remove_then_fail_identifier;
    bool directory_destination = false;
    bool reverse_listing = false;
    bool hide_probe_listing = false;
    bool replace_barrier_after_quarantine_put = false;
    std::string disappear_on_get;
    std::optional<kasumi::transport::ErrorCode> physical_hash_failure;
    std::vector<std::string> remote_events;
};

void destroy_fake(void* context) noexcept {
    delete static_cast<FakeState*>(context);
}

FakeState* fake_state(void* context) {
    return static_cast<FakeState*>(context);
}

bool is_commit(std::string_view identifier) {
    return identifier.starts_with("history/commits/");
}

bool is_marker(std::string_view identifier) {
    return identifier.starts_with("history/heads/");
}

kasumi::transport::Result fake_initialize(void*) {
    return {};
}

kasumi::transport::Result fake_put(void* context,
                                   const std::filesystem::path& source,
                                   std::string_view identifier) {
    auto* state = fake_state(context);
    const bool failed_commit = is_commit(identifier) && state->fail_commit_put;
    const bool failed_marker = is_marker(identifier) && state->fail_marker_put;
    if ((failed_commit && !state->persist_commit_on_put_failure) ||
        (failed_marker && !state->persist_marker_on_put_failure)) {
        return std::unexpected(
            kasumi::transport::Error{.code = kasumi::transport::ErrorCode::Io,
                                     .message = "injected put failure"});
    }
    ++state->put_count;
    if (is_commit(identifier)) {
        ++state->commit_put_count;
        state->remote_events.emplace_back("PutCommit");
    } else if (is_marker(identifier)) {
        ++state->marker_put_count;
        state->remote_events.emplace_back("PutHead");
    }
    auto physical_hash = kasumi::crypto::physical::hash_file(source, "sha256");
    if (!physical_hash) {
        return std::unexpected(
            kasumi::transport::Error{.code = kasumi::transport::ErrorCode::Io,
                                     .message = physical_hash.error()});
    }
    std::ifstream input(source, std::ios::binary);
    if (!input) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::ObjectNotFound,
            .message = "source missing"});
    }
    const auto size = std::filesystem::file_size(source);
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    input.read(reinterpret_cast<char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
    state->objects[std::string{identifier}] = std::move(bytes);
    state->physical_hashes[std::string{identifier}] = std::move(*physical_hash);
    if (state->replace_barrier_after_quarantine_put &&
        identifier.starts_with("history/gc/v1/quarantine/")) {
        state->replace_barrier_after_quarantine_put = false;
        for (auto& [object_identifier, object] : state->objects) {
            constexpr std::string_view barrier_payload =
                "kasumi-gc-v1:barrier:";
            static_cast<void>(object_identifier);
            if (object.size() >= barrier_payload.size() &&
                std::ranges::equal(
                    barrier_payload,
                    std::span{object}.first(barrier_payload.size()))) {
                object.assign({'r', 'e', 'p', 'l', 'a', 'c', 'e', 'd'});
            }
        }
    }
    if (failed_commit || failed_marker) {
        return std::unexpected(
            kasumi::transport::Error{.code = kasumi::transport::ErrorCode::Io,
                                     .message = "injected put failure"});
    }
    return {};
}

inline kasumi::transport::Result
fake_put_batch(void* context, const kasumi::transport::PutBatch& batch) {
    auto* state = fake_state(context);
    ++state->put_batch_count;
    for (const auto& identifier : batch.identifiers) {
        auto result =
            fake_put(context, batch.source_root / identifier, identifier);
        if (!result) {
            return result;
        }
    }
    return {};
}

kasumi::transport::Result fake_get(void* context,
                                   std::string_view identifier,
                                   const std::filesystem::path& destination) {
    auto* state = fake_state(context);
    ++state->get_count;
    if (is_commit(identifier)) {
        ++state->commit_get_count;
        state->remote_events.emplace_back("GetCommit");
    } else if (is_marker(identifier)) {
        ++state->marker_get_count;
        state->remote_events.emplace_back("GetHead");
    }
    if ((is_commit(identifier) && state->fail_commit_get) ||
        (is_marker(identifier) && state->fail_marker_get) ||
        (!is_commit(identifier) && !is_marker(identifier) &&
         state->fail_content_get)) {
        return std::unexpected(
            kasumi::transport::Error{.code = kasumi::transport::ErrorCode::Io,
                                     .message = "injected get failure"});
    }
    if (identifier == state->disappear_on_get) {
        state->disappear_on_get.clear();
        state->objects.erase(std::string{identifier});
        state->physical_hashes.erase(std::string{identifier});
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::ObjectNotFound,
            .message = "object disappeared"});
    }
    const auto found = state->objects.find(std::string{identifier});
    if (found == state->objects.end()) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::ObjectNotFound,
            .message = "object missing"});
    }
    std::error_code error;
    if (state->directory_destination && is_commit(identifier)) {
        std::filesystem::create_directories(destination, error);
        return error ? kasumi::transport::
                           Result{std::unexpect,
                                  kasumi::transport::Error{
                                      .code = kasumi::transport::ErrorCode::Io,
                                      .message = "destination unavailable"}}
                     : kasumi::transport::Result{};
    }
    std::filesystem::create_directories(destination.parent_path(), error);
    std::ofstream output(destination, std::ios::binary | std::ios::trunc);
    if (error || !output) {
        return std::unexpected(
            kasumi::transport::Error{.code = kasumi::transport::ErrorCode::Io,
                                     .message = "destination unavailable"});
    }
    output.write(reinterpret_cast<const char*>(found->second.data()),
                 static_cast<std::streamsize>(found->second.size()));
    return output ? kasumi::transport::Result{}
                  : kasumi::transport::Result{
                        std::unexpect,
                        kasumi::transport::Error{
                            .code = kasumi::transport::ErrorCode::Io,
                            .message = "write failed"}};
}

kasumi::transport::PresenceResult fake_presence(void* context,
                                                std::string_view identifier) {
    auto* state = fake_state(context);
    ++state->presence_count;
    if (state->fail_barrier_presence && identifier == "history/gc/v1/barrier") {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Io,
            .message = "injected barrier presence failure"});
    }
    return state->objects.contains(std::string{identifier})
               ? kasumi::transport::Presence::Present
               : kasumi::transport::Presence::Absent;
}

kasumi::transport::ListingResult fake_list(void* context) {
    auto* state = fake_state(context);
    ++state->list_count;
    ++state->full_list_count;
    if (state->reveal_on_list_count == state->list_count) {
        state->objects.merge(state->hidden_objects);
        state->reveal_on_list_count = 0;
    }
    std::vector<std::string> result;
    for (const auto& [identifier, unused] : state->objects) {
        static_cast<void>(unused);
        result.push_back(identifier);
    }
    if (state->reverse_listing) {
        std::ranges::reverse(result);
    }
    return result;
}

kasumi::transport::ListingResult fake_list_prefix(void* context,
                                                  std::string_view prefix) {
    auto* state = fake_state(context);
    ++state->list_count;
    ++state->prefix_list_count;
    if (state->reveal_on_list_count == state->list_count) {
        state->objects.merge(state->hidden_objects);
        state->reveal_on_list_count = 0;
    }
    if (state->hide_probe_listing && prefix.ends_with("/probes")) {
        return std::vector<std::string>{};
    }
    if (state->fail_writer_list && prefix.ends_with("/writers")) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Io,
            .message = "injected writer listing failure"});
    }
    const auto full_prefix = std::string{prefix} + "/";
    std::vector<std::string> result;
    for (const auto& [identifier, unused] : state->objects) {
        static_cast<void>(unused);
        if (!identifier.starts_with(full_prefix)) {
            continue;
        }
        const auto name = identifier.substr(full_prefix.size());
        if (name.find('/') == std::string::npos) {
            result.push_back(name);
        }
    }
    if (state->reverse_listing) {
        std::ranges::reverse(result);
    }
    if (state->hide_writer_listing && prefix.ends_with("/writers")) {
        result.clear();
    }
    if (state->publish_barrier_after_writer_list &&
        prefix.ends_with("/writers")) {
        state->objects["history/gc/v1/barrier"] = {};
    }
    return result;
}

kasumi::transport::RemovalResult fake_remove(void* context,
                                             std::string_view identifier) {
    auto* state = fake_state(context);
    ++state->remove_count;
    if (identifier == state->remove_then_fail_identifier) {
        state->remove_then_fail_identifier.clear();
        state->physical_hashes.erase(std::string{identifier});
        state->objects.erase(std::string{identifier});
        return std::unexpected(
            kasumi::transport::Error{.code = kasumi::transport::ErrorCode::Io,
                                     .message = "injected remove failure"});
    }
    if (state->fail_remove_at != 0 &&
        state->remove_count == state->fail_remove_at) {
        return std::unexpected(
            kasumi::transport::Error{.code = kasumi::transport::ErrorCode::Io,
                                     .message = "injected remove failure"});
    }
    if (identifier == state->fail_remove_identifier) {
        state->fail_remove_identifier.clear();
        return std::unexpected(
            kasumi::transport::Error{.code = kasumi::transport::ErrorCode::Io,
                                     .message = "injected remove failure"});
    }
    state->physical_hashes.erase(std::string{identifier});
    return state->objects.erase(std::string{identifier})
               ? kasumi::transport::Removal::Removed
               : kasumi::transport::Removal::AlreadyAbsent;
}

std::expected<std::string, kasumi::transport::Error> fake_physical_hash(
    void* context, std::string_view identifier, std::string_view algorithm) {
    auto* state = fake_state(context);
    ++state->physical_hash_count;
    if (is_commit(identifier)) {
        state->remote_events.emplace_back("HashCommit");
    } else if (is_marker(identifier)) {
        state->remote_events.emplace_back("HashHead");
    }
    if (state->physical_hash_failure) {
        return std::unexpected(kasumi::transport::Error{
            .code = *state->physical_hash_failure,
            .message = "injected physical hash failure"});
    }
    if (!state->physical_hash_supported || algorithm != "sha256") {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Unsupported,
            .message = "physical hash unavailable"});
    }
    const auto found = state->physical_hashes.find(std::string{identifier});
    if (found == state->physical_hashes.end()) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::ObjectNotFound,
            .message = "object missing"});
    }
    return state->physical_hash_mismatch ? std::string(64, '0') : found->second;
}

kasumi::transport::ControlReadBatchResponse fake_control_read_batch(
    void* context, const kasumi::transport::ControlReadBatchRequest& request) {
    auto* state = fake_state(context);
    ++state->control_read_batch_count;
    if (state->control_read_batch_failure) {
        return std::unexpected(kasumi::transport::Error{
            .code = *state->control_read_batch_failure,
            .message = "injected control read batch failure"});
    }
    if (!state->control_read_batch_supported) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Unsupported,
            .message = "control read batch unavailable"});
    }
    kasumi::transport::ControlReadBatchResult result;
    for (const auto& prefix : request.list_prefixes) {
        auto listed = fake_list_prefix(context, prefix);
        if (!listed) {
            return std::unexpected(listed.error());
        }
        result.listings.push_back(std::move(*listed));
    }
    for (const auto& identifier : request.presence_identifiers) {
        auto presence = fake_presence(context, identifier);
        if (!presence) {
            return std::unexpected(presence.error());
        }
        result.presences.push_back(*presence);
    }
    return result;
}

[[maybe_unused]] kasumi::transport::Transport
make_fake_transport(FakeState*& state) {
    state = new FakeState;
    return kasumi::transport::Transport{
        .state = kasumi::transport::TransportStateHandle{state, destroy_fake},
        .storage =
            kasumi::transport::StorageOperations{
                .initialize = fake_initialize,
                .put = fake_put,
                .get = fake_get,
                .presence = fake_presence,
                .list = fake_list,
                .list_prefix = fake_list_prefix,
                .physical_hash = fake_physical_hash,
                .control_read_batch = fake_control_read_batch,
                .remove = fake_remove,
            },
    };
}

} // namespace

#endif
