#ifndef KASUMI_TEST_HISTORY_STORAGE_HELPERS_HPP
#define KASUMI_TEST_HISTORY_STORAGE_HELPERS_HPP

#include "application/history_storage/history_storage.hpp"
#include "application/history_storage/remote_layout.hpp"
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
#include <set>
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
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    return kasumi::application::history_storage::commit_object(layout,
                                                               reference);
}

std::string marker_path(const HeadReference& reference) {
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    return kasumi::application::history_storage::marker_object(layout,
                                                               reference);
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
        kasumi::test::workspace_path(storage.workspace, "variant.canonical");
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
        kasumi::test::workspace_path(storage.workspace, "variant.marker");
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
    std::size_t full_list_identifier_count = 0;
    std::size_t prefix_list_count = 0;
    std::size_t reveal_on_list_count = 0;
    std::size_t get_count = 0;
    std::size_t get_batch_count = 0;
    std::size_t copy_count = 0;
    std::size_t copy_batch_count = 0;
    std::size_t copy_batch_item_count = 0;
    std::size_t copy_batch_concurrency = 0;
    std::size_t presence_count = 0;
    std::size_t remove_count = 0;
    std::size_t put_count = 0;
    std::size_t put_batch_count = 0;
    std::size_t put_files_batch_count = 0;
    std::size_t put_files_batch_item_count = 0;
    std::size_t put_files_batch_concurrency = 0;
    std::size_t commit_put_count = 0;
    std::size_t marker_put_count = 0;
    std::size_t commit_get_count = 0;
    std::size_t marker_get_count = 0;
    std::size_t epoch_get_count = 0;
    std::size_t orphan_payload_get_count = 0;
    std::size_t orphan_payload_get_bytes = 0;
    std::size_t quarantine_payload_put_count = 0;
    std::size_t quarantine_payload_put_bytes = 0;
    std::size_t native_copy_bytes = 0;
    std::size_t quarantine_metadata_put_count = 0;
    std::size_t physical_hash_count = 0;
    std::size_t physical_hash_batch_count = 0;
    std::size_t barrier_verification_count = 0;
    std::map<std::string, std::string> physical_hashes;
    bool physical_hash_supported = false;
    bool physical_hash_mismatch = false;
    bool copy_supported = false;
    bool copy_batch_supported = false;
    std::optional<kasumi::transport::ErrorCode> copy_batch_failure;
    std::size_t copy_batch_fail_after_items = 0;
    bool copy_destination_mismatch = false;
    std::optional<kasumi::transport::ErrorCode> copy_failure;
    std::string physical_hash_mismatch_identifier;
    std::string physical_hash_unsupported_identifier;
    std::string physical_hash_failure_identifier;
    std::optional<std::string> physical_hash_override;
    std::size_t control_read_batch_count = 0;
    bool control_read_batch_supported = false;
    std::optional<kasumi::transport::ErrorCode> control_read_batch_failure;
    bool hide_writer_listing = false;
    bool publish_barrier_after_writer_list = false;
    bool fail_writer_list = false;
    std::size_t fail_list_at = 0;
    std::optional<kasumi::transport::ErrorCode> fail_list;
    bool fail_barrier_presence = false;
    bool fail_commit_put = false;
    bool persist_commit_on_put_failure = false;
    bool fail_quarantine_metadata_put = false;
    bool put_files_batch_supported = false;
    std::optional<kasumi::transport::ErrorCode> put_files_batch_failure;
    std::size_t put_files_batch_fail_after_items = 0;
    bool fail_commit_get = false;
    bool fail_content_get = false;
    bool fail_marker_put = false;
    bool persist_marker_on_put_failure = false;
    bool fail_marker_get = false;
    std::size_t fail_remove_at = 0;
    std::size_t source_remove_count = 0;
    std::size_t replace_barrier_after_source_remove_count = 0;
    std::string fail_remove_identifier;
    std::string fail_get_identifier;
    std::string fail_put_identifier;
    std::string remove_then_fail_identifier;
    std::optional<kasumi::transport::ErrorCode> copy_failure_after_effect;
    std::string corrupt_get_identifier;
    bool directory_destination = false;
    bool reverse_listing = false;
    bool hide_probe_listing = false;
    bool replace_barrier_after_quarantine_put = false;
    bool replace_barrier_after_writer_list = false;
    std::string disappear_on_get;
    std::string observed_payload_identifier;
    std::set<std::string> observed_payload_identifiers;
    std::optional<kasumi::transport::ErrorCode> physical_hash_failure;
    bool physical_hash_batch_supported = false;
    std::size_t physical_hash_batch_min_objects = 2;
    std::optional<kasumi::transport::ErrorCode> physical_hash_batch_failure;
    std::set<std::string> physical_hash_batch_mismatches;
    std::set<std::string> physical_hash_batch_missing;
    std::set<std::string> physical_hash_batch_errors;
    std::optional<kasumi::transport::PhysicalHashBatchReport> physical_hash_batch_override_report;
    std::set<std::string> physical_hash_batch_omitted;
    bool metadata_physical_hash_batch_unsupported = false;
    bool replace_barrier_after_metadata_verification = false;
    std::vector<std::string> remote_events;
    std::vector<std::string> gc_events;
};

void destroy_fake(void* context) noexcept {
    delete static_cast<FakeState*>(context);
}

FakeState* fake_state(void* context) {
    return static_cast<FakeState*>(context);
}

[[maybe_unused]] void reset_fake_traffic(FakeState& state) {
    state.list_count = state.full_list_count = state.prefix_list_count = 0;
    state.full_list_identifier_count = 0;
    state.get_count = state.get_batch_count = state.copy_count = 0;
    state.copy_batch_count = state.copy_batch_item_count = 0;
    state.copy_batch_concurrency = 0;
    state.presence_count = state.remove_count = state.put_count = 0;
    state.source_remove_count = 0;
    state.put_batch_count = state.commit_put_count = state.marker_put_count = 0;
    state.put_files_batch_count = 0;
    state.put_files_batch_item_count = 0;
    state.put_files_batch_concurrency = 0;
    state.commit_get_count = state.marker_get_count = state.epoch_get_count = 0;
    state.orphan_payload_get_count = 0;
    state.orphan_payload_get_bytes = 0;
    state.quarantine_payload_put_count = 0;
    state.quarantine_payload_put_bytes = 0;
    state.native_copy_bytes = 0;
    state.quarantine_metadata_put_count = 0;
    state.physical_hash_count = state.physical_hash_batch_count = 0;
    state.barrier_verification_count = 0;
    state.control_read_batch_count = 0;
    state.fail_list.reset();
    state.fail_list_at = 0;
    state.remote_events.clear();
    state.gc_events.clear();
}

bool is_commit(std::string_view identifier) {
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    return identifier.starts_with("history/commits/") ||
           identifier.starts_with(layout.commits_prefix);
}

bool is_marker(std::string_view identifier) {
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    return identifier.starts_with("history/heads/") ||
           identifier.starts_with(layout.heads_prefix);
}

bool is_epoch(std::string_view identifier) {
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    return identifier.starts_with("history/epochs/") ||
           identifier.starts_with(layout.epochs_prefix);
}

void replace_barrier_contents(
    FakeState* state,
    std::string_view identifier) {
    std::vector<std::uint8_t> replacement{'r', 'e', 'p', 'l', 'a', 'c', 'e', 'd'};
    auto hash = kasumi::crypto::physical::sha256_init();
    kasumi::crypto::physical::sha256_update(hash, replacement);
    state->objects[std::string{identifier}] = replacement;
    state->physical_hashes[std::string{identifier}] =
        kasumi::crypto::physical::sha256_finish(hash);
}

void maybe_replace_barrier_after_quarantine_put(
    FakeState* state,
    std::string_view identifier,
    const kasumi::application::history_storage::RemoteLayout& layout) {
    if (!state->replace_barrier_after_quarantine_put ||
        (!identifier.starts_with("history/gc/v1/quarantine/") &&
         !identifier.starts_with(layout.quarantine_prefix))) {
        return;
    }
    state->replace_barrier_after_quarantine_put = false;
    for (auto& [object_identifier, object] : state->objects) {
        constexpr std::string_view barrier_payload = "kasumi-gc-v1:barrier:";
        static_cast<void>(object_identifier);
        if (object.size() >= barrier_payload.size() &&
            std::ranges::equal(
                barrier_payload, std::span{object}.first(barrier_payload.size()))) {
            replace_barrier_contents(state, object_identifier);
            return;
        }
    }
}

kasumi::transport::Result fake_initialize(void*) {
    return {};
}

kasumi::transport::Result fake_put(void* context,
                                   const std::filesystem::path& source,
                                   std::string_view identifier) {
    auto* state = fake_state(context);
    const bool failed_target = identifier == state->fail_put_identifier;
    const bool failed_commit = is_commit(identifier) && state->fail_commit_put;
    const bool failed_marker = is_marker(identifier) && state->fail_marker_put;
    const bool failed_quarantine_metadata =
        state->fail_quarantine_metadata_put && identifier.ends_with(".meta");
    if ((failed_commit && !state->persist_commit_on_put_failure) ||
        (failed_marker && !state->persist_marker_on_put_failure) ||
        failed_quarantine_metadata || failed_target) {
        if (failed_target) {
            state->fail_put_identifier.clear();
        }
        return std::unexpected(
            kasumi::transport::Error{.code = kasumi::transport::ErrorCode::Io,
                                     .message = "injected put failure"});
    }
    ++state->put_count;
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    if (is_commit(identifier)) {
        ++state->commit_put_count;
        state->remote_events.emplace_back("PutCommit");
    } else if (is_marker(identifier)) {
        ++state->marker_put_count;
        state->remote_events.emplace_back("PutHead");
    }
    const bool quarantine_metadata =
        identifier.starts_with(layout.quarantine_prefix) &&
        identifier.ends_with(".meta");
    const bool quarantine_payload =
        identifier.starts_with(layout.quarantine_prefix) &&
        !identifier.ends_with(".meta");
    if (quarantine_metadata) {
        ++state->quarantine_metadata_put_count;
    } else if (quarantine_payload) {
        ++state->quarantine_payload_put_count;
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
    if (quarantine_metadata) {
        state->gc_events.emplace_back("metadata:" + std::string{identifier});
    }
    if (quarantine_payload) {
        state->quarantine_payload_put_bytes +=
            state->objects[std::string{identifier}].size();
    }
    maybe_replace_barrier_after_quarantine_put(state, identifier, layout);
    if (failed_commit || failed_marker) {
        return std::unexpected(
            kasumi::transport::Error{.code = kasumi::transport::ErrorCode::Io,
                                     .message = "injected put failure"});
    }
    return {};
}

kasumi::transport::Result fake_copy(
    void* context,
    std::string_view source_identifier,
    std::string_view destination_identifier) {
    auto* state = fake_state(context);
    ++state->copy_count;
    if (!state->copy_supported) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Unsupported,
            .message = "native copy unavailable"});
    }
    if (state->copy_failure) {
        return std::unexpected(kasumi::transport::Error{
            .code = *state->copy_failure,
            .message = "injected copy failure"});
    }
    const auto found = state->objects.find(std::string{source_identifier});
    if (found == state->objects.end()) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::ObjectNotFound,
            .message = "source object missing"});
    }
    state->objects[std::string{destination_identifier}] = found->second;
    state->native_copy_bytes += found->second.size();
    const auto hash = state->physical_hashes.find(std::string{source_identifier});
    if (hash == state->physical_hashes.end()) {
        state->physical_hashes.erase(std::string{destination_identifier});
    } else {
        state->physical_hashes[std::string{destination_identifier}] =
            hash->second;
    }
    if (state->copy_destination_mismatch) {
        state->physical_hash_mismatch_identifier =
            std::string{destination_identifier};
    }
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    maybe_replace_barrier_after_quarantine_put(
        state, destination_identifier, layout);
    state->gc_events.emplace_back("copy:" + std::string{source_identifier} +
                                  "|" + std::string{destination_identifier});
    if (state->copy_failure_after_effect) {
        const auto failure = *state->copy_failure_after_effect;
        state->copy_failure_after_effect.reset();
        return std::unexpected(kasumi::transport::Error{
            .code = failure,
            .message = "injected copy error after destination effect"});
    }
    return {};
}

kasumi::transport::Result fake_copy_batch(
    void* context, const kasumi::transport::CopyBatch& batch) {
    auto* state = fake_state(context);
    ++state->copy_batch_count;
    state->copy_batch_item_count += batch.items.size();
    state->copy_batch_concurrency = batch.concurrency;
    state->gc_events.emplace_back("copy_batch:" +
                                  std::to_string(batch.items.size()));
    if (!state->copy_batch_supported) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Unsupported,
            .message = "copy batch unavailable"});
    }
    for (std::size_t index = 0; index < batch.items.size(); ++index) {
        const auto& item = batch.items[index];
        auto copied = fake_copy(context, item.source_identifier,
                                item.destination_identifier);
        if (!copied) {
            return copied;
        }
        if (state->copy_batch_failure &&
            state->copy_batch_fail_after_items != 0 &&
            index + 1 == state->copy_batch_fail_after_items) {
            return std::unexpected(kasumi::transport::Error{
                .code = *state->copy_batch_failure,
                .message = "injected copy batch failure after remote effect"});
        }
    }
    if (state->copy_batch_failure) {
        return std::unexpected(kasumi::transport::Error{
            .code = *state->copy_batch_failure,
            .message = "injected copy batch failure"});
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

inline kasumi::transport::Result fake_put_files_batch(
    void* context, const kasumi::transport::PutFilesBatch& batch) {
    auto* state = fake_state(context);
    ++state->put_files_batch_count;
    state->put_files_batch_item_count += batch.items.size();
    state->put_files_batch_concurrency = batch.concurrency;
    state->gc_events.emplace_back("put_files_batch:" +
                                  std::to_string(batch.items.size()));
    if (!state->put_files_batch_supported) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Unsupported,
            .message = "explicit put files batch unavailable"});
    }
    for (std::size_t index = 0; index < batch.items.size(); ++index) {
        auto result = fake_put(context, batch.items[index].source,
                               batch.items[index].destination_identifier);
        if (!result) {
            return result;
        }
        if (state->put_files_batch_failure &&
            state->put_files_batch_fail_after_items != 0 &&
            index + 1 == state->put_files_batch_fail_after_items) {
            return std::unexpected(kasumi::transport::Error{
                .code = *state->put_files_batch_failure,
                .message = "injected put files batch failure after remote effect"});
        }
    }
    if (state->put_files_batch_failure) {
        return std::unexpected(kasumi::transport::Error{
            .code = *state->put_files_batch_failure,
            .message = "injected put files batch failure"});
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
    } else if (is_epoch(identifier)) {
        ++state->epoch_get_count;
        state->remote_events.emplace_back("GetEpoch");
    }
    const bool observed_payload =
        identifier == state->observed_payload_identifier ||
        state->observed_payload_identifiers.contains(std::string{identifier});
    if (observed_payload) {
        ++state->orphan_payload_get_count;
    }
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    if (identifier == layout.barrier_identifier) {
        ++state->barrier_verification_count;
        state->gc_events.emplace_back("barrier:" + std::string{identifier});
    }
    const bool failed_target = identifier == state->fail_get_identifier;
    if ((is_commit(identifier) && state->fail_commit_get) ||
        (is_marker(identifier) && state->fail_marker_get) ||
        (!is_commit(identifier) && !is_marker(identifier) &&
         state->fail_content_get) ||
        failed_target) {
        if (failed_target) {
            state->fail_get_identifier.clear();
        }
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
    auto bytes = found->second;
    if (identifier == state->corrupt_get_identifier && !bytes.empty()) {
        bytes.front() ^= 1U;
    }
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    output.flush();
    if (!output) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Io,
            .message = "write failed"});
    }
    if (observed_payload) {
        state->orphan_payload_get_bytes += found->second.size();
    }
    return {};
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
    if (state->fail_list && (state->fail_list_at == 0 || state->fail_list_at == state->list_count)) {
        return std::unexpected(kasumi::transport::Error{
            .code = *state->fail_list,
            .message = "injected full list failure"});
    }
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
    state->full_list_identifier_count += result.size();
    return result;
}

kasumi::transport::ListingResult fake_list_prefix(void* context,
                                                  std::string_view prefix) {
    auto* state = fake_state(context);
    ++state->list_count;
    ++state->prefix_list_count;
    if (state->fail_list && (state->fail_list_at == 0 || state->fail_list_at == state->list_count)) {
        return std::unexpected(kasumi::transport::Error{
            .code = *state->fail_list,
            .message = "injected prefix list failure"});
    }
    if (state->reveal_on_list_count == state->list_count) {
        state->objects.merge(state->hidden_objects);
        state->reveal_on_list_count = 0;
    }
    const auto test_layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    const auto probes_dir = test_layout.probes_prefix.ends_with('/')
                                ? test_layout.probes_prefix.substr(
                                      0, test_layout.probes_prefix.size() - 1)
                                : test_layout.probes_prefix;
    const auto writers_dir = test_layout.writers_prefix.ends_with('/')
                                 ? test_layout.writers_prefix.substr(
                                       0, test_layout.writers_prefix.size() - 1)
                                 : test_layout.writers_prefix;
    const bool is_probes = prefix.ends_with("/probes") || prefix == probes_dir;
    const bool is_writers =
        prefix.ends_with("/writers") || prefix == writers_dir;

    if (state->hide_probe_listing && is_probes) {
        return std::vector<std::string>{};
    }
    if (state->fail_writer_list && is_writers) {
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
    if (state->hide_writer_listing && is_writers) {
        result.clear();
    }
    if (state->publish_barrier_after_writer_list && is_writers) {
        state->objects[test_layout.barrier_identifier] = {};
        state->objects["history/gc/v1/barrier"] = {};
    }
    if (state->replace_barrier_after_writer_list && is_writers) {
        state->replace_barrier_after_writer_list = false;
        replace_barrier_contents(state, test_layout.barrier_identifier);
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
    const bool removed = state->objects.erase(std::string{identifier}) != 0;
    if (removed) {
        state->gc_events.emplace_back("remove:" + std::string{identifier});
        const bool content_identifier = identifier.size() == 64 &&
            std::ranges::all_of(identifier, [](unsigned char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            });
        if (content_identifier &&
            ++state->source_remove_count ==
                state->replace_barrier_after_source_remove_count) {
            state->replace_barrier_after_source_remove_count = 0;
            replace_barrier_contents(
                state,
                kasumi::application::history_storage::derive_remote_layout(
                    test_key()).barrier_identifier);
        }
    }
    return removed ? kasumi::transport::Removal::Removed
                   : kasumi::transport::Removal::AlreadyAbsent;
}

std::expected<std::string, kasumi::transport::Error> fake_physical_hash(
    void* context, std::string_view identifier, std::string_view algorithm) {
    auto* state = fake_state(context);
    ++state->physical_hash_count;
    state->gc_events.emplace_back("physical_hash:" + std::string{identifier});
    if (is_commit(identifier)) {
        state->remote_events.emplace_back("HashCommit");
    } else if (is_marker(identifier)) {
        state->remote_events.emplace_back("HashHead");
    }
    if (state->physical_hash_failure &&
        (state->physical_hash_failure_identifier.empty() ||
         identifier == state->physical_hash_failure_identifier)) {
        return std::unexpected(kasumi::transport::Error{
            .code = *state->physical_hash_failure,
            .message = "injected physical hash failure"});
    }
    if (!state->physical_hash_supported || algorithm != "sha256" ||
        identifier == state->physical_hash_unsupported_identifier) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Unsupported,
            .message = "physical hash unavailable"});
    }
    if (state->physical_hash_override) {
        return *state->physical_hash_override;
    }
    const auto found = state->physical_hashes.find(std::string{identifier});
    if (found == state->physical_hashes.end()) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::ObjectNotFound,
            .message = "object missing"});
    }
    const bool mismatched = state->physical_hash_mismatch ||
        identifier == state->physical_hash_mismatch_identifier;
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    if (identifier.starts_with(layout.quarantine_prefix)) {
        state->gc_events.emplace_back("verify:" + std::string{identifier});
    }
    return mismatched
               ? std::string(64, '0')
               : found->second;
}

kasumi::transport::PhysicalHashBatchResult fake_physical_hash_batch(
    void* context,
    const kasumi::transport::PhysicalHashBatchRequest& request) {
    auto* state = fake_state(context);
    ++state->physical_hash_batch_count;
    if (state->physical_hash_batch_failure) {
        return std::unexpected(kasumi::transport::Error{
            .code = *state->physical_hash_batch_failure,
            .message = "injected physical hash batch failure"});
    }
    if (!state->physical_hash_batch_supported) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Unsupported,
            .message = "physical hash batch unavailable"});
    }
    const bool metadata_batch = !request.objects.empty() &&
        std::ranges::all_of(request.objects, [](const auto& object) {
            return object.identifier.ends_with(".meta");
        });
    if (metadata_batch && state->metadata_physical_hash_batch_unsupported) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Unsupported,
            .message = "metadata physical hash batch unavailable"});
    }
    if (state->physical_hash_batch_override_report) {
        return *state->physical_hash_batch_override_report;
    }
    kasumi::transport::PhysicalHashBatchReport report;
    for (const auto& object : request.objects) {
        if (state->physical_hash_batch_omitted.contains(object.identifier)) {
            continue;
        }
        if (state->physical_hash_batch_errors.contains(object.identifier)) {
            report.errors.push_back(object.identifier);
            continue;
        }
        if (state->physical_hash_batch_missing.contains(object.identifier)) {
            report.missing.push_back(object.identifier);
            continue;
        }
        if (state->physical_hash_mismatch ||
            object.identifier == state->physical_hash_mismatch_identifier ||
            state->physical_hash_batch_mismatches.contains(object.identifier)) {
            report.mismatched.push_back(object.identifier);
            continue;
        }
        const auto found = state->physical_hashes.find(object.identifier);
        if (found == state->physical_hashes.end()) {
            report.missing.push_back(object.identifier);
        } else if (found->second != object.expected_hash) {
            report.mismatched.push_back(object.identifier);
        } else {
            report.matched.push_back(object.identifier);
        }
    }
    std::string event = "batch";
    for (const auto& object : request.objects) {
        event += "|" + object.identifier;
    }
    state->gc_events.push_back(std::move(event));
    if (metadata_batch && state->replace_barrier_after_metadata_verification) {
        state->replace_barrier_after_metadata_verification = false;
        for (auto& [identifier, bytes] : state->objects) {
            static_cast<void>(identifier);
            constexpr std::string_view barrier_payload = "kasumi-gc-v1:barrier:";
            if (bytes.size() >= barrier_payload.size() &&
                std::ranges::equal(barrier_payload,
                                   std::span{bytes}.first(barrier_payload.size()))) {
                bytes.assign({'r', 'e', 'p', 'l', 'a', 'c', 'e', 'd'});
            }
        }
    }
    return report;
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

[[maybe_unused]] inline void enable_fake_physical_hash_batch(
    kasumi::transport::Transport& transport,
    FakeState& state,
    std::size_t min_objects = 2) {
    state.physical_hash_batch_supported = true;
    state.physical_hash_batch_min_objects = min_objects;
    transport.storage.physical_hash_batch_min_objects = min_objects;
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
                .put_files_batch = fake_put_files_batch,
                .get = fake_get,
                .copy = fake_copy,
                .copy_batch = fake_copy_batch,
                .presence = fake_presence,
                .list = fake_list,
                .list_prefix = fake_list_prefix,
                .physical_hash = fake_physical_hash,
                .physical_hash_batch = fake_physical_hash_batch,
                .control_read_batch = fake_control_read_batch,
                .remove = fake_remove,
            },
    };
}

} // namespace

#endif
