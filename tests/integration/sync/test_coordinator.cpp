#include "application/history_storage/epoch.hpp"
#include "application/history_storage/publication.hpp"
#include "application/observation/state.hpp"
#include "application/sync/coordinator.hpp"
#include "application/sync/coordinator_detail.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/metadata.hpp"
#include "application/sync/mutation.hpp"
#include "application/sync/publication.hpp"
#include "application/sync/reobservation.hpp"
#include "core/hasher.hpp"
#include "core/history.hpp"
#include "core/node.hpp"
#include "core/operation.hpp"
#include "core/reconciliation/plan.hpp"
#include "core/transaction/types.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/physical_hash.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/clock.hpp"
#include "platform/metadata.hpp"
#include "platform/path.hpp"
#include "platform/workspace.hpp"
#include "runtime/resolver.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <gtest/gtest.h>
#include <limits>
#include <map>
#include <mutex>
#include <span>
#include <sqlite3.h>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#endif

namespace {

std::filesystem::file_time_type make_file_time(std::chrono::nanoseconds ns) {
    return std::filesystem::file_time_type{
        std::chrono::duration_cast<std::filesystem::file_time_type::duration>(
            ns)};
}

kasumi::application::history_storage::epoch::SealedEpoch set_test_genesis_epoch(
    kasumi::transaction::Record& record,
    std::span<const std::uint8_t, kasumi::crypto::KEY_SIZE> key) {
    record.epoch_vault_id = std::string(64, 'e');
    record.epoch_issued_at = 123;
    record.epoch_min_history_depth =
        kasumi::application::history_storage::epoch::default_min_history_depth;
    record.epoch_min_history_age_hours = kasumi::application::history_storage::
        epoch::default_min_history_age_hours;
    auto sealed = kasumi::application::history_storage::epoch::seal(
        {.vault_id = record.epoch_vault_id,
         .sequence = 0,
         .issued_at = record.epoch_issued_at,
         .policy = {.min_history_depth = record.epoch_min_history_depth,
                    .min_history_age_hours =
                        record.epoch_min_history_age_hours},
         .anchors = {{.commit_id = record.commit_id, .height = 0}},
         .previous_epoch_id = {}},
        key);
    EXPECT_TRUE(sealed.has_value());
    if (!sealed) {
        return {};
    }
    record.epoch_id = sealed->reference.epoch_id;
    return *sealed;
}

#ifdef _WIN32

bool create_test_junction(const std::filesystem::path& link,
                          const std::filesystem::path& target,
                          std::error_code& error) {
    struct MountPointData {
        DWORD tag = IO_REPARSE_TAG_MOUNT_POINT;
        WORD data_length = 0;
        WORD reserved = 0;
        WORD substitute_offset = 0;
        WORD substitute_length = 0;
        WORD print_offset = 0;
        WORD print_length = 0;
        std::array<wchar_t, 2048> path_buffer{};
    } data;

    if (!CreateDirectoryW(link.c_str(), nullptr)) {
        error = std::error_code{static_cast<int>(GetLastError()),
                                std::system_category()};
        return false;
    }
    const auto substitute = std::wstring{L"\\??\\"} + target.wstring();
    const auto printed = target.wstring();
    const auto substitute_bytes = substitute.size() * sizeof(wchar_t);
    const auto print_bytes = printed.size() * sizeof(wchar_t);
    if (substitute_bytes + print_bytes + 2 * sizeof(wchar_t) >
        data.path_buffer.size() * sizeof(wchar_t)) {
        RemoveDirectoryW(link.c_str());
        error = std::make_error_code(std::errc::filename_too_long);
        return false;
    }
    data.substitute_length = static_cast<WORD>(substitute_bytes);
    data.print_offset = static_cast<WORD>(substitute_bytes + sizeof(wchar_t));
    data.print_length = static_cast<WORD>(print_bytes);
    data.data_length = static_cast<WORD>(
        8 + substitute_bytes + sizeof(wchar_t) + print_bytes + sizeof(wchar_t));
    std::memcpy(data.path_buffer.data(), substitute.data(), substitute_bytes);
    std::memcpy(reinterpret_cast<std::byte*>(data.path_buffer.data()) +
                    data.print_offset,
                printed.data(),
                print_bytes);

    const auto handle =
        CreateFileW(link.c_str(),
                    GENERIC_WRITE,
                    0,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                    nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        error = std::error_code{static_cast<int>(GetLastError()),
                                std::system_category()};
        RemoveDirectoryW(link.c_str());
        return false;
    }
    DWORD returned = 0;
    const auto configured =
        DeviceIoControl(handle,
                        FSCTL_SET_REPARSE_POINT,
                        &data,
                        static_cast<DWORD>(8 + data.data_length),
                        nullptr,
                        0,
                        &returned,
                        nullptr);
    const auto code = configured ? ERROR_SUCCESS : GetLastError();
    CloseHandle(handle);
    if (!configured) {
        RemoveDirectoryW(link.c_str());
        error = std::error_code{static_cast<int>(code), std::system_category()};
        return false;
    }
    error.clear();
    return true;
}

#endif

std::string save_recovery_record(
    const std::filesystem::path& profile,
    kasumi::transaction::Phase phase,
    std::span<const std::uint8_t, kasumi::crypto::KEY_SIZE> key,
    std::string commit_id = std::string(64, 'a'),
    std::string ciphertext_id = std::string(64, 'b'),
    std::vector<std::string> parent_ids = {}) {
    if (!std::filesystem::exists(profile) &&
        !std::filesystem::create_directories(profile)) {
        ADD_FAILURE() << "could not create profile";
        return {};
    }
    if (!std::filesystem::exists(profile / ".transactions") &&
        !std::filesystem::create_directories(profile / ".transactions")) {
        ADD_FAILURE() << "could not create transactions directory";
        return {};
    }
    auto record = kasumi::application::sync::journal::create_record(
        0, 0, kasumi::make_sync_plan({}, 0));
    EXPECT_TRUE(record.has_value());
    if (!record)
        return {};
    record->phase = phase;
    if (phase >= kasumi::transaction::Phase::CommitPrepared) {
        record->commit_id = std::move(commit_id);
        record->parent_ids = std::move(parent_ids);
    }
    if (phase >= kasumi::transaction::Phase::CommitUploaded) {
        record->ciphertext_id = std::move(ciphertext_id);
        record->marker_id =
            kasumi::application::history_storage::marker_identifier(
                {.commit_id = record->commit_id,
                 .ciphertext_id = record->ciphertext_id});
    }
    if (phase >= kasumi::transaction::Phase::EpochPrepared) {
        static_cast<void>(set_test_genesis_epoch(*record, key));
    }
    const auto paths = kasumi::application::sync::journal::make_paths(profile);
    EXPECT_TRUE(paths.has_value());
    if (!paths)
        return {};
    const auto saved =
        kasumi::application::sync::journal::save(*paths, *record, key);
    if (!saved) {
        ADD_FAILURE() << saved.error();
        return {};
    }
    if (!std::filesystem::create_directories(profile / ".transactions" /
                                             record->operation_id)) {
        ADD_FAILURE() << "could not create transaction workspace";
        return {};
    }
    return record->operation_id;
}

std::string save_local_only_recovery_record(
    const std::filesystem::path& profile,
    kasumi::transaction::Phase phase,
    std::span<const std::uint8_t, kasumi::crypto::KEY_SIZE> key,
    std::string observed_head_id = std::string(64, 'a'),
    std::uint64_t generation = 0) {
    std::filesystem::create_directories(profile / ".transactions");
    auto record = kasumi::application::sync::journal::create_record(
        generation,
        generation,
        kasumi::make_sync_plan({}, generation),
        false,
        std::move(observed_head_id));
    EXPECT_TRUE(record.has_value());
    if (!record)
        return {};
    record->phase = phase;
    const auto paths = kasumi::application::sync::journal::make_paths(profile);
    EXPECT_TRUE(paths.has_value());
    if (!paths)
        return {};
    EXPECT_TRUE(kasumi::application::sync::journal::save(*paths, *record, key));
    EXPECT_TRUE(std::filesystem::create_directories(profile / ".transactions" /
                                                    record->operation_id));
    return record->operation_id;
}

std::string save_pruning_recovery_record(
    const std::filesystem::path& profile,
    kasumi::transaction::Phase phase,
    std::span<const std::uint8_t, kasumi::crypto::KEY_SIZE> key,
    const kasumi::application::history_storage::HeadReference& head,
    const std::vector<std::string>& parents,
    const kasumi::application::history_storage::epoch::SealedEpoch& epoch,
    std::string vault_id) {
    std::filesystem::create_directories(profile / ".transactions");
    auto record = kasumi::application::sync::journal::create_record(
        0, 0, kasumi::make_sync_plan({}, 0));
    EXPECT_TRUE(record.has_value());
    if (!record) {
        return {};
    }
    record->phase = phase;
    record->commit_id = head.commit_id;
    record->ciphertext_id = head.ciphertext_id;
    record->parent_ids = parents;
    record->marker_id =
        kasumi::application::history_storage::marker_identifier(head);
    record->epoch_vault_id = std::move(vault_id);
    record->epoch_id = epoch.reference.epoch_id;
    record->epoch_issued_at = 123;
    record->epoch_min_history_depth = 1;
    record->epoch_min_history_age_hours = 6;
    const auto paths = kasumi::application::sync::journal::make_paths(profile);
    EXPECT_TRUE(paths.has_value());
    if (!paths ||
        !kasumi::application::sync::journal::save(*paths, *record, key)) {
        return {};
    }
    EXPECT_TRUE(std::filesystem::create_directories(profile / ".transactions" /
                                                    record->operation_id));
    return record->operation_id;
}

kasumi::runtime::RuntimeData
make_runtime(const std::filesystem::path& profile,
             const std::filesystem::path& local,
             const std::filesystem::path& storage) {
    return {.local_dir = local,
            .database_path = profile / "state.db",
            .key_path = profile / "key.bin",
            .storage_location = kasumi::platform::path::to_utf8(storage)};
}

std::string
remote_content_id(std::span<const std::uint8_t, kasumi::crypto::KEY_SIZE> key,
                  std::string_view plaintext_hash) {
    return kasumi::crypto::content_identifier(
        key, kasumi::hash_from_hex(plaintext_hash).value());
}

std::string authenticated_commit_id(
    std::span<const std::uint8_t, kasumi::crypto::KEY_SIZE> key,
    const kasumi::history::Commit& commit) {
    return kasumi::crypto::commit_identifier(
        key, kasumi::history::serialize(commit).value());
}

struct AmbiguousPublicationState {
    enum class UploadCorruption {
        None,
        Truncated,
        Altered,
        OtherContent,
        TooLarge,
        MissingOnGet,
        DecryptFailure,
        PlaintextSizeMismatch,
    };

    std::mutex mutex;
    std::map<std::string, std::vector<std::uint8_t>> objects;
    std::vector<std::uint8_t> replacement_object;
    std::size_t list_count = 0;
    std::size_t get_count = 0;
    std::size_t presence_count = 0;
    std::size_t put_count = 0;
    std::size_t content_put_count = 0;
    std::size_t epoch_put_count = 0;
    std::size_t remove_count = 0;
    std::size_t fail_list_at = 0;
    bool fail_marker_put = false;
    bool persist_marker_on_failure = false;
    bool fail_list_after_marker = false;
    bool marker_failed = false;
    bool fail_content_put_after_store = false;
    std::size_t fail_content_put_at = 0;
    bool fail_epoch_put = false;
    bool persist_epoch_on_put_failure = false;
    bool fail_epoch_put_after_store = false;
    bool fail_epoch_get = false;
    std::vector<std::vector<std::string>> scripted_epoch_listings;
    std::size_t scripted_epoch_listing_index = 0;
    bool fail_content_get = false;
    UploadCorruption upload_corruption = UploadCorruption::None;
    bool claim_present_after_upload = false;
};

struct ReobserveTransportState {
    std::mutex mutex;
    std::condition_variable condition;
    kasumi::transport::Transport* base = nullptr;
    std::filesystem::path local_file;
    std::filesystem::path storage_root;
    std::vector<std::string> listed_prefixes;
    std::vector<std::string> events;
    std::vector<std::string> request_events;
    std::size_t remaining_mutations = 0;
    std::size_t next_value = 1;
    std::size_t initialize_count = 0;
    std::size_t put_count = 0;
    std::size_t get_count = 0;
    std::size_t presence_count = 0;
    std::size_t list_count = 0;
    std::size_t full_list_count = 0;
    std::size_t prefix_list_count = 0;
    std::size_t physical_hash_count = 0;
    std::size_t remove_count = 0;
    std::size_t marker_get_count = 0;
    std::size_t commit_get_count = 0;
    bool require_commit_overlap = false;
    bool commit_put_started = false;
    bool commit_verification_started = false;
    bool commit_overlap_timed_out = false;
    bool require_local_change_overlap = false;
    bool local_change_observed = false;
    bool local_change_overlap_timed_out = false;
};

void destroy_reobserve_state(void*) noexcept {
}

ReobserveTransportState* reobserve_state(void* context) {
    return static_cast<ReobserveTransportState*>(context);
}

kasumi::transport::Result reobserve_initialize(void* context) {
    auto* state = reobserve_state(context);
    {
        std::lock_guard lock(state->mutex);
        ++state->initialize_count;
        state->request_events.emplace_back("INITIALIZE");
    }
    return kasumi::transport::initialize(*state->base);
}

kasumi::transport::Result reobserve_put(void* context,
                                        const std::filesystem::path& source,
                                        std::string_view identifier) {
    auto* state = reobserve_state(context);
    const bool commit = identifier.starts_with("history/commits/");
    const bool marker = identifier.starts_with("history/heads/");
    {
        std::unique_lock lock(state->mutex);
        ++state->put_count;
        state->request_events.emplace_back("PUT " + std::string{identifier});
        state->events.push_back(commit   ? "commit PUT"
                                : marker ? "head PUT"
                                         : "content PUT");
        if (commit) {
            state->commit_put_started = true;
            state->condition.notify_all();
        } else if (!marker && state->require_commit_overlap &&
                   !state->condition.wait_for(
                       lock, std::chrono::seconds{2}, [&] {
                           return state->commit_put_started;
                       })) {
            state->commit_overlap_timed_out = true;
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::Timeout,
                .message = "commit upload did not overlap content upload"});
        }
    }
    return kasumi::transport::put(*state->base, source, identifier);
}

kasumi::transport::Result
reobserve_get(void* context,
              std::string_view identifier,
              const std::filesystem::path& destination) {
    auto* state = reobserve_state(context);
    {
        std::lock_guard lock(state->mutex);
        ++state->get_count;
        state->request_events.emplace_back("GET " + std::string{identifier});
        if (identifier.starts_with("history/heads/")) {
            ++state->marker_get_count;
        } else if (identifier.starts_with("history/commits/")) {
            ++state->commit_get_count;
        }
    }
    return kasumi::transport::get(*state->base, identifier, destination);
}

kasumi::transport::PresenceResult
reobserve_presence(void* context, std::string_view identifier) {
    auto* state = reobserve_state(context);
    {
        std::lock_guard lock(state->mutex);
        ++state->presence_count;
        state->request_events.emplace_back("PRESENCE " +
                                           std::string{identifier});
    }
    return kasumi::transport::presence(*state->base, identifier);
}

kasumi::transport::ListingResult reobserve_list(void* context) {
    auto* state = reobserve_state(context);
    std::optional<std::size_t> mutation;
    {
        std::lock_guard lock(state->mutex);
        ++state->list_count;
        ++state->full_list_count;
        state->request_events.emplace_back("LIST <root>");
        if (state->remaining_mutations != 0) {
            --state->remaining_mutations;
            mutation = state->next_value++;
        }
    }
    if (mutation) {
        kasumi::test::write_text(state->local_file, std::to_string(*mutation));
    }
    return kasumi::transport::list(*state->base);
}

kasumi::transport::ListingResult
reobserve_list_prefix(void* context, std::string_view prefix) {
    auto* state = reobserve_state(context);
    std::optional<std::size_t> mutation;
    {
        std::unique_lock lock(state->mutex);
        ++state->list_count;
        ++state->prefix_list_count;
        state->listed_prefixes.emplace_back(prefix);
        state->request_events.emplace_back("LIST " + std::string{prefix});
        if (state->remaining_mutations != 0) {
            --state->remaining_mutations;
            mutation = state->next_value++;
        }
        if (prefix == "history/heads" && state->require_local_change_overlap &&
            !state->condition.wait_for(lock, std::chrono::seconds{2}, [&] {
                return state->local_change_observed;
            })) {
            state->local_change_overlap_timed_out = true;
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::Timeout,
                .message =
                    "local change was not observed during remote observation"});
        }
    }
    if (mutation) {
        kasumi::test::write_text(state->local_file, std::to_string(*mutation));
    }
    return kasumi::transport::list(*state->base, prefix);
}

std::expected<std::string, kasumi::transport::Error> reobserve_physical_hash(
    void* context, std::string_view identifier, std::string_view algorithm) {
    auto* state = reobserve_state(context);
    {
        std::unique_lock lock(state->mutex);
        ++state->physical_hash_count;
        state->request_events.emplace_back("HASH " + std::string{identifier});
        state->events.push_back(
            identifier.starts_with("history/commits/") ? "commit verified"
            : identifier.starts_with("history/heads/") ? "head verified"
                                                       : "content verified");
        if (identifier.starts_with("history/commits/")) {
            state->commit_verification_started = true;
            state->condition.notify_all();
        } else if (!identifier.starts_with("history/") &&
                   state->require_commit_overlap &&
                   !state->condition.wait_for(
                       lock, std::chrono::seconds{2}, [&] {
                           return state->commit_verification_started;
                       })) {
            state->commit_overlap_timed_out = true;
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::Timeout,
                .message = "commit verification did not overlap content "
                           "verification"});
        }
    }
    if (!state->storage_root.empty()) {
        auto hash = kasumi::crypto::physical::hash_file(
            state->storage_root / std::filesystem::path{identifier},
            algorithm);
        if (hash) {
            return *hash;
        }
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Io, .message = hash.error()});
    }
    return kasumi::transport::physical_hash(
        *state->base, identifier, algorithm);
}

kasumi::transport::RemovalResult reobserve_remove(void* context,
                                                  std::string_view identifier) {
    auto* state = reobserve_state(context);
    {
        std::lock_guard lock(state->mutex);
        ++state->remove_count;
        state->request_events.emplace_back("DELETE " + std::string{identifier});
        state->events.emplace_back("parent marker DELETE");
    }
    return kasumi::transport::remove(*state->base, identifier);
}

kasumi::transport::Transport
make_reobserve_transport(ReobserveTransportState& state) {
    kasumi::transport::Transport result;
    result.state = {&state, destroy_reobserve_state};
    result.storage = {.initialize = reobserve_initialize,
                      .put = reobserve_put,
                      .get = reobserve_get,
                      .presence = reobserve_presence,
                      .list = reobserve_list,
                      .list_prefix = reobserve_list_prefix,
                      .physical_hash = reobserve_physical_hash,
                      .remove = reobserve_remove};
    return result;
}

void destroy_ambiguous_state(void* context) noexcept {
    delete static_cast<AmbiguousPublicationState*>(context);
}

AmbiguousPublicationState* ambiguous_state(void* context) {
    return static_cast<AmbiguousPublicationState*>(context);
}

bool ambiguous_marker(std::string_view identifier) {
    return identifier.starts_with("history/heads/");
}

bool ambiguous_content(std::string_view identifier) {
    return !identifier.starts_with("history/");
}

bool ambiguous_epoch(std::string_view identifier) {
    return identifier.starts_with("history/epochs/");
}

kasumi::transport::Result ambiguous_initialize(void*) {
    return {};
}

kasumi::transport::Result ambiguous_put(void* context,
                                        const std::filesystem::path& source,
                                        std::string_view identifier) {
    auto* state = ambiguous_state(context);
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
    if (!input && !bytes.empty()) {
        return std::unexpected(
            kasumi::transport::Error{.code = kasumi::transport::ErrorCode::Io,
                                     .message = "source read failed"});
    }
    std::lock_guard lock(state->mutex);
    ++state->put_count;
    if (ambiguous_content(identifier)) {
        ++state->content_put_count;
    }
    if (ambiguous_epoch(identifier)) {
        ++state->epoch_put_count;
    }
    if (ambiguous_epoch(identifier) && state->fail_epoch_put &&
        !state->persist_epoch_on_put_failure) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Io,
            .message = "injected epoch publication failure"});
    }
    if (ambiguous_marker(identifier) && state->fail_marker_put) {
        state->marker_failed = true;
        if (state->persist_marker_on_failure) {
            state->objects[std::string{identifier}] = std::move(bytes);
        }
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Io,
            .message = "injected marker publication failure"});
    }
    if (ambiguous_content(identifier)) {
        switch (state->upload_corruption) {
            case AmbiguousPublicationState::UploadCorruption::Truncated:
                bytes.resize(bytes.size() / 2);
                break;
            case AmbiguousPublicationState::UploadCorruption::Altered:
                if (!bytes.empty()) {
                    bytes[bytes.size() / 2] ^= 0x80U;
                }
                break;
            case AmbiguousPublicationState::UploadCorruption::DecryptFailure:
                if (!bytes.empty()) {
                    bytes[bytes.size() / 2] ^= 0x40U;
                }
                break;
            case AmbiguousPublicationState::UploadCorruption::OtherContent:
                bytes = state->replacement_object;
                break;
            case AmbiguousPublicationState::UploadCorruption::TooLarge:
                bytes.push_back(0xA5U);
                break;
            case AmbiguousPublicationState::UploadCorruption::MissingOnGet:
                break;
            case AmbiguousPublicationState::UploadCorruption::
                PlaintextSizeMismatch:
                bytes = state->replacement_object;
                break;
            case AmbiguousPublicationState::UploadCorruption::None:
                break;
        }
    }
    state->objects[std::string{identifier}] = std::move(bytes);
    if (ambiguous_epoch(identifier) &&
        (state->fail_epoch_put_after_store || state->fail_epoch_put)) {
        state->fail_epoch_put_after_store = false;
        state->fail_epoch_put = false;
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Io,
            .message = "injected ambiguous epoch put"});
    }
    if (ambiguous_content(identifier) &&
        state->upload_corruption ==
            AmbiguousPublicationState::UploadCorruption::MissingOnGet) {
        state->objects.erase(std::string{identifier});
    }
    if (ambiguous_content(identifier) &&
        (std::exchange(state->fail_content_put_after_store, false) ||
         (state->fail_content_put_at != 0 &&
          state->content_put_count >= state->fail_content_put_at))) {
        state->fail_content_put_at = 0;
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Io,
            .message = "injected ambiguous content put"});
    }
    return {};
}

kasumi::transport::Result
ambiguous_get(void* context,
              std::string_view identifier,
              const std::filesystem::path& destination) {
    auto* state = ambiguous_state(context);
    std::vector<std::uint8_t> bytes;
    {
        std::lock_guard lock(state->mutex);
        ++state->get_count;
        if (ambiguous_epoch(identifier) && state->fail_epoch_get) {
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::Io,
                .message = "injected epoch read failure"});
        }
        if (ambiguous_content(identifier) && state->fail_content_get) {
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::Io,
                .message = "injected content read failure"});
        }
        const auto found = state->objects.find(std::string{identifier});
        if (found == state->objects.end()) {
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::ObjectNotFound,
                .message = "object missing"});
        }
        bytes = found->second;
    }
    std::error_code error;
    std::filesystem::create_directories(destination.parent_path(), error);
    std::ofstream output(destination, std::ios::binary | std::ios::trunc);
    if (error || !output) {
        return std::unexpected(
            kasumi::transport::Error{.code = kasumi::transport::ErrorCode::Io,
                                     .message = "destination unavailable"});
    }
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    return output ? kasumi::transport::Result{}
                  : kasumi::transport::Result{
                        std::unexpect,
                        kasumi::transport::Error{
                            .code = kasumi::transport::ErrorCode::Io,
                            .message = "destination write failed"}};
}

kasumi::transport::PresenceResult
ambiguous_presence(void* context, std::string_view identifier) {
    auto* state = ambiguous_state(context);
    std::lock_guard lock(state->mutex);
    ++state->presence_count;
    return (state->claim_present_after_upload ||
            state->objects.contains(std::string{identifier}))
               ? kasumi::transport::Presence::Present
               : kasumi::transport::Presence::Absent;
}

kasumi::transport::ListingResult ambiguous_list(void* context) {
    auto* state = ambiguous_state(context);
    std::lock_guard lock(state->mutex);
    ++state->list_count;
    if ((state->fail_list_at != 0 &&
         state->list_count == state->fail_list_at) ||
        (state->marker_failed && state->fail_list_after_marker)) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Io,
            .message = "injected reachability inspection failure"});
    }
    std::vector<std::string> identifiers;
    for (const auto& [identifier, unused] : state->objects) {
        static_cast<void>(unused);
        identifiers.push_back(identifier);
    }
    return identifiers;
}

kasumi::transport::ListingResult
ambiguous_list_prefix(void* context, std::string_view prefix) {
    auto* state = ambiguous_state(context);
    std::lock_guard lock(state->mutex);
    ++state->list_count;
    if ((state->fail_list_at != 0 &&
         state->list_count == state->fail_list_at) ||
        (state->marker_failed && state->fail_list_after_marker)) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Io,
            .message = "injected reachability inspection failure"});
    }
    if (prefix == "history/epochs/v1" &&
        state->scripted_epoch_listing_index <
            state->scripted_epoch_listings.size()) {
        return state
            ->scripted_epoch_listings[state->scripted_epoch_listing_index++];
    }
    const auto full_prefix = std::string{prefix} + "/";
    std::vector<std::string> identifiers;
    for (const auto& [identifier, unused] : state->objects) {
        static_cast<void>(unused);
        if (identifier.starts_with(full_prefix)) {
            const auto name = identifier.substr(full_prefix.size());
            if (name.find('/') == std::string::npos) {
                identifiers.push_back(name);
            }
        }
    }
    return identifiers;
}

kasumi::transport::RemovalResult ambiguous_remove(void* context,
                                                  std::string_view identifier) {
    auto* state = ambiguous_state(context);
    std::lock_guard lock(state->mutex);
    ++state->remove_count;
    return state->objects.erase(std::string{identifier})
               ? kasumi::transport::Removal::Removed
               : kasumi::transport::Removal::AlreadyAbsent;
}

kasumi::transport::Transport
make_ambiguous_transport(AmbiguousPublicationState*& state) {
    state = new AmbiguousPublicationState;
    return kasumi::transport::Transport{
        .state =
            kasumi::transport::TransportStateHandle{state,
                                                    destroy_ambiguous_state},
        .storage = kasumi::transport::StorageOperations{
            .initialize = ambiguous_initialize,
            .put = ambiguous_put,
            .get = ambiguous_get,
            .presence = ambiguous_presence,
            .list = ambiguous_list,
            .list_prefix = ambiguous_list_prefix,
            .remove = ambiguous_remove}};
}

kasumi::reconciliation::Input empty_publication_input() {
    kasumi::Snapshot local_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    kasumi::finalize_snapshot(local_tree);
    return {.local_tree = local_tree,
            .base_tree = {},
            .base_commit_id = {},
            .base_state_present = false,
            .storage = {.tree = {},
                        .object_identifiers = {},
                        .reachable_commits = {},
                        .reachable_commit_ids = {},
                        .marked_heads = {},
                        .marked_head_identifiers = {},
                        .logical_heads = {},
                        .ancestral_marked_heads = {},
                        .generation = 0,
                        .history_present = false,
                        .history_has_conflicts = false},
            .local_generation = 0,
            .audit_storage_objects = false};
}

void add_reachable_head(kasumi::reconciliation::Input& input,
                        std::string head = std::string(64, 'a')) {
    input.storage.history_present = true;
    input.storage.generation = 1;
    input.storage.logical_heads = {head};
    input.storage.reachable_commits = {kasumi::history::LoadedCommit{
        .id = head,
        .commit = kasumi::history::Commit{
            .height = 1, .parents = {}, .tree = input.storage.tree}}};
}

struct PruningFixture {
    kasumi::test::TempWorkspace workspace{nullptr,
                                          kasumi::test::remove_temp_workspace};
    std::filesystem::path profile;
    std::filesystem::path local;
    std::filesystem::path storage_path;
    kasumi::runtime::RuntimeData runtime;
    kasumi::transport::Transport storage;
    AmbiguousPublicationState* state = nullptr;
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    kasumi::reconciliation::Input input;
    kasumi::reconciliation::Result result;
    std::vector<kasumi::history::LoadedCommit> commits;
    kasumi::application::history_storage::epoch::SealedEpoch previous_epoch;
    kasumi::application::history_storage::epoch::RetentionPolicy
        previous_policy;
    kasumi::application::history_storage::HeadReference recovery_head;
    std::vector<std::string> recovery_parents;
    bool ready = false;
};

PruningFixture make_pruning_fixture(
    kasumi::application::history_storage::epoch::RetentionPolicy remote_policy =
        {.min_history_depth = 1, .min_history_age_hours = 6},
    std::uint32_t local_depth = 1,
    std::uint32_t local_age_hours = 6) {
    PruningFixture fixture;
    fixture.workspace = kasumi::test::make_temp_workspace("pruning-acceptance");
    fixture.profile =
        kasumi::test::workspace_path(fixture.workspace, "profile");
    fixture.local = kasumi::test::workspace_path(fixture.workspace, "local");
    fixture.storage_path =
        kasumi::test::workspace_path(fixture.workspace, "storage");
    if (!std::filesystem::create_directories(fixture.profile) ||
        !std::filesystem::create_directories(fixture.local)) {
        return fixture;
    }
    fixture.runtime =
        make_runtime(fixture.profile, fixture.local, fixture.storage_path);
    fixture.runtime.min_history_depth = local_depth;
    fixture.runtime.min_history_age_hours = local_age_hours;
    fixture.storage = make_ambiguous_transport(fixture.state);
    if (!kasumi::transport::initialize(fixture.storage)) {
        return fixture;
    }

    fixture.input = empty_publication_input();
    fixture.input.local_tree.rows.front().mtime =
        std::filesystem::last_write_time(fixture.local);
    kasumi::finalize_snapshot(fixture.input.local_tree);
    fixture.input.storage.tree = fixture.input.local_tree;
    fixture.input.storage.history_present = true;

    std::vector<kasumi::history::LoadedCommit> commits;
    auto prepared = kasumi::application::sync::publication::prepare_commit(
        fixture.input.storage.tree, false, 0, {}, 100, fixture.key);
    if (!prepared ||
        !kasumi::application::sync::publication::publish_commit(
            fixture.storage, fixture.key, *prepared, fixture.local)) {
        return fixture;
    }
    commits.push_back({.id = prepared->commit_id, .commit = prepared->commit});
    for (std::uint64_t height = 1; height <= 5; ++height) {
        const std::vector<std::string> parents{commits.back().id};
        auto next = kasumi::application::sync::publication::prepare_commit(
            fixture.input.storage.tree,
            true,
            height - 1,
            parents,
            100 + static_cast<std::int64_t>(height) * 100,
            fixture.key);
        if (!next || !kasumi::application::sync::publication::publish_commit(
                         fixture.storage, fixture.key, *next, fixture.local)) {
            return fixture;
        }
        commits.push_back(kasumi::history::LoadedCommit{
            .id = next->commit_id, .commit = next->commit});
    }
    const std::vector<std::string> branch_parents{commits.front().id};
    auto branch = kasumi::application::sync::publication::prepare_commit(
        fixture.input.storage.tree, true, 0, branch_parents, 200, fixture.key);
    if (!branch) {
        return fixture;
    }
    auto branch_published =
        kasumi::application::sync::publication::publish_commit(
            fixture.storage, fixture.key, *branch, fixture.local);
    if (!branch_published) {
        return fixture;
    }
    commits.push_back(kasumi::history::LoadedCommit{.id = branch->commit_id,
                                                    .commit = branch->commit});
    fixture.recovery_head = branch_published->head;
    fixture.recovery_parents = branch->commit.parents;
    {
        std::lock_guard lock(fixture.state->mutex);
        for (auto it = fixture.state->objects.begin();
             it != fixture.state->objects.end();) {
            if (it->first.starts_with("history/heads/")) {
                it = fixture.state->objects.erase(it);
            } else {
                ++it;
            }
        }
    }
    if (!kasumi::application::sync::publication::publish_head_marker(
            fixture.storage, fixture.recovery_head, fixture.local)) {
        return fixture;
    }

    const auto vault_id = std::string(64, 'e');
    std::optional<kasumi::application::history_storage::epoch::SealedEpoch>
        previous;
    for (std::uint64_t sequence = 0; sequence <= 2; ++sequence) {
        auto current = kasumi::application::history_storage::epoch::seal(
            {.vault_id = vault_id,
             .sequence = sequence,
             .issued_at = 123 + static_cast<std::int64_t>(sequence),
             .policy = remote_policy,
             .anchors = {{.commit_id = commits.front().id, .height = 0}},
             .previous_epoch_id =
                 previous ? previous->reference.epoch_id : std::string{}},
            fixture.key);
        if (!current || !kasumi::application::history_storage::epoch::publish(
                            fixture.storage, *current, fixture.local)) {
            return fixture;
        }
        previous = std::move(*current);
    }
    fixture.previous_epoch = *previous;
    fixture.previous_policy = remote_policy;
    fixture.input.local_tree.rows.front().mtime =
        std::filesystem::last_write_time(fixture.local);
    kasumi::finalize_snapshot(fixture.input.local_tree);
    fixture.input.storage.tree = fixture.input.local_tree;
    fixture.input.storage.generation = 5;
    fixture.input.storage.epoch_vault_id = vault_id;
    fixture.input.storage.epoch_id = previous->reference.epoch_id;
    fixture.input.storage.epoch_sequence = previous->reference.sequence;
    fixture.input.storage.epoch_policy =
        kasumi::reconciliation::EpochRetentionPolicy{
            .min_history_depth = remote_policy.min_history_depth,
            .min_history_age_hours = remote_policy.min_history_age_hours};
    fixture.input.storage.epoch_anchors = {
        {.commit_id = commits.front().id, .height = 0}};
    fixture.input.storage.logical_heads = {commits[5].id, commits.back().id};
    std::ranges::sort(fixture.input.storage.logical_heads);
    fixture.input.storage.marked_heads = fixture.input.storage.logical_heads;
    fixture.input.storage.reachable_commits = commits;
    fixture.commits = commits;
    for (const auto& commit : commits) {
        fixture.input.storage.reachable_commit_ids.push_back(commit.id);
    }

    auto result = kasumi::reconciliation::reconcile(fixture.input);
    if (!result || !result->requires_publication) {
        return fixture;
    }
    fixture.result = *result;
    fixture.ready = true;
    return fixture;
}

kasumi::transaction::Record
metadata_record(kasumi::Operation operation,
                kasumi::transaction::OperationState state =
                    kasumi::transaction::OperationState::Applied) {
    auto record = kasumi::transaction::Record{};
    record.plan = kasumi::make_sync_plan({std::move(operation)}, 1);
    record.progress.resize(1);
    record.progress.front().state = state;
    return record;
}

kasumi::Operation metadata_operation(kasumi::Action action,
                                     std::string path,
                                     std::string alt_path = {}) {
    return {.action = action,
            .path = std::move(path),
            .hash = {},
            .alt_path = std::move(alt_path),
            .size = 0,
            .exclusive_destination = false};
}

kasumi::Snapshot metadata_tree(std::initializer_list<std::string> paths) {
    kasumi::Snapshot tree;
    tree.rows.push_back(kasumi::NodeRow{.path = "", .is_directory = true});
    for (const auto& path : paths) {
        tree.rows.push_back(kasumi::NodeRow{
            .path = path, .is_directory = path.find('.') == std::string::npos});
    }
    kasumi::finalize_snapshot(tree);
    return tree;
}

bool has_path(const std::vector<std::string>& paths, std::string_view path) {
    return std::ranges::find(paths, path) != paths.end();
}

TEST(SyncCoordinatorTest, DeleteLocalMetadataRestoreSet) {
    const auto record = metadata_record(
        metadata_operation(kasumi::Action::DeleteLocal, "docs/alpha.txt"));
    const auto paths = kasumi::application::sync::metadata_restore_paths(
        record, metadata_tree({"docs", "docs/keep.txt"}));
    ASSERT_TRUE(paths.has_value()) << paths.error();
    EXPECT_TRUE(has_path(*paths, ""));
    EXPECT_TRUE(has_path(*paths, "docs"));
    EXPECT_FALSE(has_path(*paths, "docs/alpha.txt"));
}

TEST(SyncCoordinatorTest, DeleteLocalDirectoryMetadataRestoreSet) {
    const auto record = metadata_record(
        metadata_operation(kasumi::Action::DeleteLocalDirectory, "remove"));
    const auto paths = kasumi::application::sync::metadata_restore_paths(
        record, metadata_tree({"keep"}));
    ASSERT_TRUE(paths.has_value()) << paths.error();
    ASSERT_EQ(paths->size(), 1U);
    EXPECT_EQ(paths->front(), "");
    EXPECT_FALSE(has_path(*paths, "remove"));
}

TEST(SyncCoordinatorTest, RenameLocalMetadataRestoreSet) {
    const auto record = metadata_record(metadata_operation(
        kasumi::Action::RenameLocal, "a/file.txt", "b/file.txt"));
    const auto paths = kasumi::application::sync::metadata_restore_paths(
        record, metadata_tree({"a", "a/keep.txt", "b", "b/file.txt"}));
    ASSERT_TRUE(paths.has_value()) << paths.error();
    EXPECT_TRUE(has_path(*paths, "a"));
    EXPECT_TRUE(has_path(*paths, "b"));
    EXPECT_TRUE(has_path(*paths, "b/file.txt"));
    EXPECT_TRUE(has_path(*paths, ""));
    EXPECT_FALSE(has_path(*paths, "a/file.txt"));
}

TEST(SyncCoordinatorTest, MetadataRestorePathsRejectsProgressMismatch) {
    auto record = metadata_record(
        metadata_operation(kasumi::Action::Download, "docs/file.txt"));
    record.progress.clear();
    const auto paths = kasumi::application::sync::metadata_restore_paths(
        record, metadata_tree({"docs", "docs/file.txt"}));
    ASSERT_FALSE(paths.has_value());
    EXPECT_EQ(paths.error(), "transaction progress does not match its plan");
}

TEST(SyncCoordinatorTest, MetadataRestorePathsIncludesAppliedDownloadInOrder) {
    const auto record = metadata_record(
        metadata_operation(kasumi::Action::Download, "docs/file.txt"));
    const auto paths = kasumi::application::sync::metadata_restore_paths(
        record, metadata_tree({"docs", "docs/file.txt"}));
    ASSERT_TRUE(paths.has_value()) << paths.error();
    EXPECT_EQ(*paths, (std::vector<std::string>{"docs/file.txt", "docs", ""}));
}

TEST(SyncCoordinatorTest,
     MetadataRestorePathsIncludesAppliedLocalDirectoryInOrder) {
    const auto record = metadata_record(
        metadata_operation(kasumi::Action::CreateLocalDirectory, "a/b"));
    const auto paths = kasumi::application::sync::metadata_restore_paths(
        record, metadata_tree({"a", "a/b"}));
    ASSERT_TRUE(paths.has_value()) << paths.error();
    EXPECT_EQ(*paths, (std::vector<std::string>{"a/b", "a", ""}));
}

TEST(SyncCoordinatorTest,
     MetadataRestorePathsDeduplicatesAncestorsAndRootInDeterministicOrder) {
    auto record = kasumi::transaction::Record{};
    record.plan = kasumi::make_sync_plan(
        {metadata_operation(kasumi::Action::Download, "docs/a.txt"),
         metadata_operation(kasumi::Action::Download, "docs/b.txt")},
        1);
    record.progress.resize(2);
    for (auto& progress : record.progress) {
        progress.state = kasumi::transaction::OperationState::Applied;
    }
    const auto paths = kasumi::application::sync::metadata_restore_paths(
        record, metadata_tree({"docs", "docs/a.txt", "docs/b.txt"}));
    ASSERT_TRUE(paths.has_value()) << paths.error();
    EXPECT_EQ(
        *paths,
        (std::vector<std::string>{"docs/a.txt", "docs/b.txt", "docs", ""}));
    EXPECT_EQ(std::ranges::count(*paths, ""), 1);
}

TEST(SyncCoordinatorTest,
     MetadataRestorePathsIncludesObservedRemoteDirectoryDifferences) {
    auto record = kasumi::transaction::Record{};
    record.plan = kasumi::make_sync_plan({}, 1);
    record.publication_required = false;
    auto observed = metadata_tree({"empty"});
    auto expected = observed;
    const auto remote_time =
        std::filesystem::file_time_type::clock::now() - std::chrono::hours{1};
    kasumi::find_row(expected, "")->mtime = remote_time;
    kasumi::find_row(expected, "empty")->mtime = remote_time;

    const auto paths = kasumi::application::sync::metadata_restore_paths(
        record, expected, &observed);

    ASSERT_TRUE(paths.has_value()) << paths.error();
    EXPECT_EQ(*paths, (std::vector<std::string>{"empty", ""}));
}

TEST(SyncCoordinatorTest, MetadataRestorePathsOnlyUsesAppliedLocalOperations) {
    const auto expected = metadata_tree({"docs", "docs/file.txt"});
    for (const auto state :
         {kasumi::transaction::OperationState::Pending,
          kasumi::transaction::OperationState::Prepared,
          kasumi::transaction::OperationState::BackupCreated}) {
        const auto record = metadata_record(
            metadata_operation(kasumi::Action::Download, "docs/file.txt"),
            state);
        const auto paths =
            kasumi::application::sync::metadata_restore_paths(record, expected);
        ASSERT_TRUE(paths.has_value()) << paths.error();
        EXPECT_TRUE(paths->empty());
    }

    for (const auto action : {kasumi::Action::Upload,
                              kasumi::Action::CreateRemoteDirectory,
                              kasumi::Action::DeleteRemote,
                              kasumi::Action::DeleteRemoteDirectory}) {
        const auto record =
            metadata_record(metadata_operation(action, "docs/file.txt"));
        const auto paths =
            kasumi::application::sync::metadata_restore_paths(record, expected);
        ASSERT_TRUE(paths.has_value()) << paths.error();
        EXPECT_TRUE(paths->empty());
    }
}

void add_storage_object(kasumi::transport::Transport& storage,
                        const std::filesystem::path& source,
                        const kasumi::Hash& hash) {
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto encrypted =
        kasumi::platform::path::temporary_sibling_path(source, "", ".encrypted");
    ASSERT_TRUE(kasumi::crypto::encrypt_file(source, encrypted, key));
    ASSERT_TRUE(kasumi::transport::put(
        storage, encrypted, kasumi::crypto::content_identifier(key, hash)));
}

TEST(SyncCoordinatorTest,
     LogicalMutationsPrepareApplyReplayAndRollbackWithoutExternalIo) {
    auto workspace =
        kasumi::test::make_temp_workspace("logical-mutation-replay");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto transaction =
        kasumi::test::workspace_path(workspace, "transaction");
    ASSERT_TRUE(std::filesystem::create_directories(local));
    ASSERT_TRUE(std::filesystem::create_directories(transaction));
    kasumi::test::write_text(local / "untouched.txt", "untouched");
    kasumi::transport::Transport unavailable{};
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const kasumi::platform::Workspace tx{.root = transaction};

    for (const auto action : {kasumi::Action::CreateRemoteDirectory,
                              kasumi::Action::DeleteRemote,
                              kasumi::Action::DeleteRemoteDirectory}) {
        SCOPED_TRACE(kasumi::action_index(action));
        const kasumi::Operation operation{
            .action = action,
            .path = action == kasumi::Action::DeleteRemote ? "remote.txt"
                                                           : "remote-dir",
            .hash = {},
            .alt_path = {},
            .size = 0,
            .exclusive_destination = false};
        kasumi::transaction::OperationProgress progress;
        const auto prepared =
            kasumi::application::sync::mutation::prepare_operation(
                operation, 0, local, tx, progress);
        ASSERT_TRUE(prepared.has_value()) << prepared.error().detail;
        EXPECT_EQ(prepared->state,
                  kasumi::transaction::OperationState::Prepared);
        EXPECT_TRUE(kasumi::application::sync::mutation::apply_operation(
            operation, 0, local, unavailable, key, tx));
        EXPECT_TRUE(kasumi::application::sync::mutation::apply_operation(
            operation, 0, local, unavailable, key, tx));
        progress = *prepared;
        progress.state = kasumi::transaction::OperationState::Applied;
        EXPECT_TRUE(kasumi::application::sync::mutation::rollback_operation(
            operation, 0, local, tx, progress));
    }

    EXPECT_TRUE(std::filesystem::is_regular_file(local / "untouched.txt"));
    EXPECT_EQ(std::filesystem::file_size(local / "untouched.txt"), 9U);
    EXPECT_TRUE(std::filesystem::is_empty(transaction));
}

TEST(SyncCoordinatorTest,
     DeleteLocalDirectoryFailsClosedWhenUnexpectedFileAppears) {
    auto workspace =
        kasumi::test::make_temp_workspace("delete-directory-fail-closed");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto transaction =
        kasumi::test::workspace_path(workspace, "transaction");
    ASSERT_TRUE(std::filesystem::create_directories(local / "dir"));
    ASSERT_TRUE(std::filesystem::create_directories(transaction));
    kasumi::test::write_text(local / "dir/unexpected.txt", "important");
    const kasumi::Operation operation{
        .action = kasumi::Action::DeleteLocalDirectory, .path = "dir"};
    kasumi::transaction::OperationProgress progress{.backup_slot = 0};
    const kasumi::platform::Workspace tx{.root = transaction};
    auto prepared = kasumi::application::sync::mutation::prepare_operation(
        operation, 0, local, tx, progress);
    ASSERT_TRUE(prepared.has_value()) << prepared.error().detail;
    kasumi::transport::Transport unavailable{};
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto applied = kasumi::application::sync::mutation::apply_operation(
        operation, 0, local, unavailable, key, tx);

    ASSERT_FALSE(applied.has_value());
    EXPECT_EQ(applied.error().code,
              kasumi::application::sync::mutation::MutationErrorCode::LocalIo);
    EXPECT_TRUE(kasumi::application::sync::mutation::rollback_operation(
        operation, 0, local, tx, *prepared));
    EXPECT_EQ(kasumi::test::read_text(local / "dir/unexpected.txt"),
              "important");
}

TEST(SyncCoordinatorTest, RenameMutationIsExclusiveAndIdempotent) {
    auto workspace =
        kasumi::test::make_temp_workspace("rename-mutation-states");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto transaction =
        kasumi::test::workspace_path(workspace, "transaction");
    ASSERT_TRUE(std::filesystem::create_directories(local));
    ASSERT_TRUE(std::filesystem::create_directories(transaction));
    kasumi::transport::Transport unavailable{};
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const kasumi::platform::Workspace tx{.root = transaction};

    const kasumi::Operation rename{
        .action = kasumi::Action::RenameLocal,
        .path = "source.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("source")),
        .alt_path = "destination.txt",
        .size = 6,
        .exclusive_destination = true};
    kasumi::test::write_text(local / rename.path, "source");
    ASSERT_TRUE(kasumi::application::sync::mutation::apply_operation(
        rename, 0, local, unavailable, key, tx));
    EXPECT_FALSE(std::filesystem::exists(local / rename.path));
    EXPECT_EQ(kasumi::test::read_text(local / rename.alt_path), "source");
    EXPECT_TRUE(kasumi::application::sync::mutation::apply_operation(
        rename, 0, local, unavailable, key, tx));

    auto conflict = rename;
    conflict.path = "conflict-source.txt";
    conflict.alt_path = "conflict-destination.txt";
    kasumi::test::write_text(local / conflict.path, "source");
    kasumi::test::write_text(local / conflict.alt_path, "destination");
    const auto conflicted =
        kasumi::application::sync::mutation::apply_operation(
            conflict, 1, local, unavailable, key, tx);
    ASSERT_FALSE(conflicted.has_value());
    EXPECT_EQ(conflicted.error().code,
              kasumi::application::sync::mutation::MutationErrorCode::
                  DestinationConflict);
    EXPECT_EQ(kasumi::test::read_text(local / conflict.path), "source");
    EXPECT_EQ(kasumi::test::read_text(local / conflict.alt_path),
              "destination");

    auto missing = rename;
    missing.path = "missing-source.txt";
    missing.alt_path = "missing-destination.txt";
    const auto absent = kasumi::application::sync::mutation::apply_operation(
        missing, 2, local, unavailable, key, tx);
    ASSERT_FALSE(absent.has_value());
    EXPECT_EQ(absent.error().code,
              kasumi::application::sync::mutation::MutationErrorCode::LocalIo);
}

TEST(SyncCoordinatorTest, CorruptedRenameBackupFailsClosed) {
    auto workspace =
        kasumi::test::make_temp_workspace("rename-corrupted-backup");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto transaction =
        kasumi::test::workspace_path(workspace, "transaction");
    ASSERT_TRUE(std::filesystem::create_directories(local));
    ASSERT_TRUE(std::filesystem::create_directories(transaction));
    const kasumi::platform::Workspace tx{.root = transaction};
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    kasumi::transport::Transport unavailable{};
    const kasumi::Operation rename{
        .action = kasumi::Action::RenameLocal,
        .path = "source.txt",
        .hash = kasumi::hash_hex(kasumi::hasher::hash_string("original")),
        .alt_path = "destination.txt",
        .size = 8,
        .exclusive_destination = true};
    kasumi::test::write_text(local / rename.path, "original");
    kasumi::transaction::OperationProgress progress;
    progress.backup_slot = 0;
    const auto prepared =
        kasumi::application::sync::mutation::prepare_operation(
            rename, 0, local, tx, progress);
    ASSERT_TRUE(prepared.has_value()) << prepared.error().detail;
    ASSERT_TRUE(kasumi::application::sync::mutation::apply_operation(
        rename, 0, local, unavailable, key, tx));
    kasumi::test::write_text(transaction / "0.backup", "corrupt");

    progress = *prepared;
    progress.state = kasumi::transaction::OperationState::Applied;
    const auto rolled = kasumi::application::sync::mutation::rollback_operation(
        rename, 0, local, tx, progress);
    ASSERT_FALSE(rolled.has_value());
    EXPECT_EQ(rolled.error().code,
              kasumi::application::sync::mutation::MutationErrorCode::
                  DestinationConflict);
    EXPECT_FALSE(std::filesystem::exists(local / rename.path));
    EXPECT_EQ(kasumi::test::read_text(local / rename.alt_path), "original");
}

TEST(SyncCoordinatorTest, PrepareCommitTimestampSurvivesCanonicalRoundTrip) {
    const kasumi::Snapshot tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto prepared =
        kasumi::application::sync::publication::prepare_commit(
            tree, false, 0, {}, 123456, key);
    ASSERT_TRUE(prepared.has_value()) << prepared.error().detail;
    EXPECT_EQ(prepared->commit.created_at, 123456);

    const auto encoded = kasumi::history::serialize(prepared->commit);
    ASSERT_TRUE(encoded.has_value()) << encoded.error().detail;
    const auto decoded = kasumi::history::deserialize(*encoded);
    ASSERT_TRUE(decoded.has_value()) << decoded.error().detail;
    EXPECT_EQ(decoded->created_at, 123456);
}

TEST(SyncCoordinatorTest,
     ReadOnlyUploadPublishesStateAndRemovesTransactionArtifacts) {
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-read-only-upload");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto source = local / "read-only.txt";
    kasumi::test::write_text(source, "read-only");
    std::error_code permission_error;
    std::filesystem::permissions(source,
                                 std::filesystem::perms::owner_write |
                                     std::filesystem::perms::group_write |
                                     std::filesystem::perms::others_write,
                                 std::filesystem::perm_options::remove,
                                 permission_error);
    ASSERT_FALSE(permission_error);

    auto input = empty_publication_input();
    const auto hash = kasumi::hasher::hash_string("read-only");
    input.local_tree.rows.front().mtime =
        std::filesystem::last_write_time(local);
    input.local_tree.rows.push_back(
        kasumi::NodeRow{.path = "read-only.txt",
                        .hash = hash,
                        .size = 9,
                        .mtime = std::filesystem::last_write_time(source),
                        .is_directory = false});
    kasumi::finalize_snapshot(input.local_tree);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_TRUE(std::ranges::any_of(
        result->plan.operations, [](const kasumi::Operation& operation) {
            return operation.action == kasumi::Action::Upload;
        }));

    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    auto runtime_data = make_runtime(profile, local, storage_path);
    runtime_data.min_history_depth = 7;
    runtime_data.min_history_age_hours = 9;
    const auto before = kasumi::platform::clock::unix_seconds();
    ASSERT_TRUE(before.has_value()) << before.error();
    const auto executed = kasumi::application::sync::coordinator::execute(
        runtime_data, *storage, key, input, *result);
    ASSERT_TRUE(executed.has_value()) << executed.error().detail;
    const auto after = kasumi::platform::clock::unix_seconds();
    ASSERT_TRUE(after.has_value()) << after.error();

    const auto state =
        kasumi::state_storage::load_state(runtime_data.database_path);
    ASSERT_TRUE(state.has_value() && *state);
    EXPECT_TRUE(kasumi::history::valid_commit_id((*state)->commit_id));
    const auto loaded_commit =
        kasumi::application::sync::publication::find_reachable_commit(
            *storage,
            key,
            runtime_data.database_path.parent_path(),
            (*state)->commit_id);
    ASSERT_TRUE(loaded_commit.has_value() && *loaded_commit);
    EXPECT_GT((**loaded_commit).commit.created_at, 0);
    EXPECT_GE((**loaded_commit).commit.created_at, *before);
    EXPECT_LE((**loaded_commit).commit.created_at, *after);
    EXPECT_TRUE(kasumi::history::valid_commit_id((*state)->epoch_id));
    EXPECT_EQ((*state)->epoch_sequence, 0U);
    const auto latest =
        kasumi::application::history_storage::epoch::load_latest(
            *storage, key, runtime_data.database_path.parent_path());
    ASSERT_TRUE(latest.has_value() && *latest);
    EXPECT_EQ((*state)->epoch_id, (**latest).reference.epoch_id);
    EXPECT_EQ((*state)->epoch_sequence, (**latest).reference.sequence);
    EXPECT_EQ((**latest).value.policy.min_history_depth, 7U);
    EXPECT_EQ((**latest).value.policy.min_history_age_hours, 9U);
    const auto remote_objects = kasumi::transport::list(*storage);
    ASSERT_TRUE(remote_objects.has_value());
    EXPECT_EQ(std::ranges::count_if(*remote_objects,
                                    [](const auto& identifier) {
                                        return identifier.starts_with(
                                            "history/epochs/v1/");
                                    }),
              1U);
    EXPECT_EQ(kasumi::transport::presence(
                  *storage, kasumi::crypto::content_identifier(key, hash)),
              kasumi::transport::Presence::Present);
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_TRUE(std::filesystem::is_empty(profile / ".transactions"));
    EXPECT_EQ(std::filesystem::status(source).permissions() &
                  std::filesystem::perms::owner_write,
              std::filesystem::perms::none);
}

TEST(SyncCoordinatorTest, PruningEpochPersistsMatchingEpochSequence) {
    auto workspace =
        kasumi::test::make_temp_workspace("pruning-epoch-sequence");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));

    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto runtime_data = make_runtime(profile, local, storage_path);
    const auto id = [](char value) {
        return std::string(64, value);
    };
    const auto vault_id = id('e');
    const auto policy =
        kasumi::application::history_storage::epoch::RetentionPolicy{};
    std::optional<kasumi::application::history_storage::epoch::SealedEpoch>
        previous;
    for (std::uint64_t sequence = 0; sequence <= 2; ++sequence) {
        auto current = kasumi::application::history_storage::epoch::seal(
            {.vault_id = vault_id,
             .sequence = sequence,
             .issued_at = 123 + static_cast<std::int64_t>(sequence),
             .policy = policy,
             .anchors = {{.commit_id = id('1'), .height = 0}},
             .previous_epoch_id =
                 previous ? previous->reference.epoch_id : std::string{}},
            key);
        ASSERT_TRUE(current.has_value());
        ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
            *storage, *current, profile));
        previous = std::move(*current);
    }
    ASSERT_TRUE(previous.has_value());

    auto input = empty_publication_input();
    input.local_tree.rows.front().mtime =
        std::filesystem::last_write_time(local);
    kasumi::finalize_snapshot(input.local_tree);
    input.storage.tree = input.local_tree;
    input.storage.history_present = true;
    input.storage.generation = 5;
    input.storage.epoch_vault_id = vault_id;
    input.storage.epoch_id = previous->reference.epoch_id;
    input.storage.epoch_sequence = previous->reference.sequence;
    input.storage.epoch_policy = kasumi::reconciliation::EpochRetentionPolicy{
        .min_history_depth = policy.min_history_depth,
        .min_history_age_hours = policy.min_history_age_hours};
    input.storage.logical_heads = {id('6'), id('a')};
    input.storage.marked_heads = input.storage.logical_heads;
    for (unsigned value = 1; value <= 6; ++value) {
        std::vector<std::string> parents;
        if (value > 1) {
            parents.push_back(id(static_cast<char>('0' + value - 1)));
        }
        input.storage.reachable_commits.push_back(
            {.id = id(static_cast<char>('0' + value)),
             .commit = {.height = value - 1,
                        .created_at = static_cast<std::int64_t>(value) * 5000,
                        .parents = std::move(parents),
                        .tree = input.storage.tree}});
    }
    input.storage.reachable_commits.push_back(
        {.id = id('a'),
         .commit = {
             .height = 0, .created_at = 5000, .tree = input.storage.tree}});
    for (const auto& commit : input.storage.reachable_commits) {
        input.storage.reachable_commit_ids.push_back(commit.id);
    }

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_TRUE(result->requires_publication);
    const auto executed = kasumi::application::sync::coordinator::execute(
        runtime_data, *storage, key, input, *result);
    ASSERT_TRUE(executed) << executed.error().detail;

    const auto state =
        kasumi::state_storage::load_state(runtime_data.database_path);
    ASSERT_TRUE(state.has_value() && *state);
    const auto latest =
        kasumi::application::history_storage::epoch::load_latest(
            *storage, key, profile);
    ASSERT_TRUE(latest.has_value());
    ASSERT_TRUE(*latest);
    EXPECT_EQ((*state)->epoch_id, (**latest).reference.epoch_id);
    EXPECT_EQ((*state)->epoch_sequence, 3U);
    EXPECT_EQ((*state)->epoch_sequence, (**latest).reference.sequence);
}

TEST(
    SyncCoordinatorTest,
    ExistingVaultUsesAuthenticatedRemotePolicyInsteadOfMoreAggressiveLocalPolicy) {
    auto fixture = make_pruning_fixture(
        {.min_history_depth = 5, .min_history_age_hours = 1}, 1, 1);
    ASSERT_TRUE(fixture.ready);
    const auto epoch_puts = fixture.state->epoch_put_count;

    const auto executed =
        kasumi::application::sync::coordinator::execute(fixture.runtime,
                                                        fixture.storage,
                                                        fixture.key,
                                                        fixture.input,
                                                        fixture.result);
    ASSERT_TRUE(executed.has_value()) << executed.error().detail;
    EXPECT_EQ(fixture.state->epoch_put_count, epoch_puts);

    const auto latest =
        kasumi::application::history_storage::epoch::load_latest(
            fixture.storage, fixture.key, fixture.profile);
    ASSERT_TRUE(latest.has_value() && *latest);
    EXPECT_EQ((**latest).reference, fixture.previous_epoch.reference);
    EXPECT_EQ((**latest).value.policy.min_history_depth, 5U);
    EXPECT_EQ((**latest).value.policy.min_history_age_hours, 1U);

    const auto state =
        kasumi::state_storage::load_state(fixture.runtime.database_path);
    ASSERT_TRUE(state.has_value() && *state);
    EXPECT_EQ((*state)->epoch_id, fixture.previous_epoch.reference.epoch_id);
    EXPECT_EQ((*state)->epoch_sequence,
              fixture.previous_epoch.reference.sequence);
}

TEST(
    SyncCoordinatorTest,
    ExistingVaultUsesAuthenticatedRemotePolicyInsteadOfMoreConservativeLocalPolicy) {
    auto fixture = make_pruning_fixture(
        {.min_history_depth = 1, .min_history_age_hours = 1}, 5, 24);
    ASSERT_TRUE(fixture.ready);
    const auto epoch_puts = fixture.state->epoch_put_count;

    const auto executed =
        kasumi::application::sync::coordinator::execute(fixture.runtime,
                                                        fixture.storage,
                                                        fixture.key,
                                                        fixture.input,
                                                        fixture.result);
    ASSERT_TRUE(executed.has_value()) << executed.error().detail;
    EXPECT_EQ(fixture.state->epoch_put_count, epoch_puts + 1);

    const auto latest =
        kasumi::application::history_storage::epoch::load_latest(
            fixture.storage, fixture.key, fixture.profile);
    ASSERT_TRUE(latest.has_value() && *latest);
    EXPECT_EQ((**latest).reference.sequence,
              fixture.previous_epoch.reference.sequence + 1);
    EXPECT_EQ((**latest).value.previous_epoch_id,
              fixture.previous_epoch.reference.epoch_id);
    EXPECT_EQ((**latest).value.policy, fixture.previous_policy);
    EXPECT_EQ((**latest).value.policy.min_history_depth, 1U);
    EXPECT_EQ((**latest).value.policy.min_history_age_hours, 1U);

    const auto state =
        kasumi::state_storage::load_state(fixture.runtime.database_path);
    ASSERT_TRUE(state.has_value() && *state);
    EXPECT_EQ((*state)->epoch_id, (**latest).reference.epoch_id);
    EXPECT_EQ((*state)->epoch_sequence, (**latest).reference.sequence);
}

TEST(SyncCoordinatorTest, UnchangedFrontierDoesNotPublishRedundantEpoch) {
    auto fixture = make_pruning_fixture(
        {.min_history_depth = 2, .min_history_age_hours = 1}, 2, 1);
    ASSERT_TRUE(fixture.ready);

    const auto now = kasumi::platform::clock::unix_seconds();
    ASSERT_TRUE(now.has_value()) << now.error();
    auto prepared = kasumi::application::sync::publication::prepare_commit(
        fixture.result.candidate_shared_tree,
        true,
        fixture.input.storage.generation,
        fixture.input.storage.logical_heads,
        *now,
        fixture.key);
    ASSERT_TRUE(prepared.has_value()) << prepared.error().detail;
    auto dag = fixture.input.storage.reachable_commits;
    dag.push_back({.id = prepared->commit_id, .commit = prepared->commit});
    const auto plan = kasumi::application::history_storage::epoch::plan_pruning(
        dag, fixture.previous_policy);
    ASSERT_TRUE(plan.has_value()) << plan.error().reason;
    auto accepted = kasumi::application::history_storage::epoch::seal(
        {.vault_id = fixture.input.storage.epoch_vault_id,
         .sequence = fixture.previous_epoch.reference.sequence + 1,
         .issued_at = 124,
         .policy = fixture.previous_policy,
         .anchors = plan->anchors,
         .previous_epoch_id = fixture.previous_epoch.reference.epoch_id},
        fixture.key);
    ASSERT_TRUE(accepted.has_value()) << accepted.error().detail;
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        fixture.storage, *accepted, fixture.profile));
    fixture.previous_epoch = *accepted;
    fixture.input.storage.epoch_id = accepted->reference.epoch_id;
    fixture.input.storage.epoch_sequence = accepted->reference.sequence;
    fixture.input.storage.epoch_anchors.clear();
    for (const auto& anchor : plan->anchors) {
        fixture.input.storage.epoch_anchors.push_back(
            {.commit_id = anchor.commit_id, .height = anchor.height});
    }
    const auto epoch_puts = fixture.state->epoch_put_count;

    const auto executed =
        kasumi::application::sync::coordinator::execute(fixture.runtime,
                                                        fixture.storage,
                                                        fixture.key,
                                                        fixture.input,
                                                        fixture.result);
    ASSERT_TRUE(executed.has_value()) << executed.error().detail;
    EXPECT_EQ(fixture.state->epoch_put_count, epoch_puts);

    const auto latest =
        kasumi::application::history_storage::epoch::load_latest(
            fixture.storage, fixture.key, fixture.profile);
    ASSERT_TRUE(latest.has_value() && *latest);
    EXPECT_EQ((**latest).reference, fixture.previous_epoch.reference);

    const auto state =
        kasumi::state_storage::load_state(fixture.runtime.database_path);
    ASSERT_TRUE(state.has_value() && *state);
    EXPECT_EQ((*state)->epoch_id, fixture.previous_epoch.reference.epoch_id);
    EXPECT_EQ((*state)->epoch_sequence,
              fixture.previous_epoch.reference.sequence);
}

TEST(SyncCoordinatorTest, MaximumEpochSequenceFailsBeforePublication) {
    kasumi::transaction::Record record;
    const kasumi::application::history_storage::epoch::EpochPlan plan{
        .anchors = {{.commit_id = std::string(64, 'a'), .height = 0}}};
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto prepared =
        kasumi::application::sync::coordinator::detail::prepare_pruning_epoch(
            record,
            {},
            plan,
            std::string(64, 'b'),
            std::numeric_limits<std::uint64_t>::max(),
            std::string(64, 'c'),
            key);

    ASSERT_FALSE(prepared.has_value());
    EXPECT_EQ(prepared.error().code,
              kasumi::application::sync::coordinator::ErrorCode::InvalidInput);
    EXPECT_TRUE(record.epoch_id.empty());
}

TEST(SyncCoordinatorTest,
     FutureAuthenticatedHeadInheritsTimestampAndDisablesPruning) {
    auto fixture = make_pruning_fixture();
    ASSERT_TRUE(fixture.ready);
    const auto local_now = kasumi::platform::clock::unix_seconds();
    ASSERT_TRUE(local_now.has_value()) << local_now.error();
    const auto future_timestamp = *local_now + 3600;
    const auto main_head_id = fixture.commits[5].id;
    const auto branch_head_id = fixture.commits.back().id;
    const std::vector<std::string> parent_ids{main_head_id};

    auto future_parent = kasumi::application::sync::publication::prepare_commit(
        fixture.input.storage.tree,
        true,
        fixture.commits[5].commit.height,
        parent_ids,
        future_timestamp,
        fixture.key);
    ASSERT_TRUE(future_parent.has_value()) << future_parent.error().detail;
    ASSERT_TRUE(kasumi::application::sync::publication::publish_commit(
        fixture.storage, fixture.key, *future_parent, fixture.profile));
    fixture.commits.push_back(
        {.id = future_parent->commit_id, .commit = future_parent->commit});

    fixture.input.storage.generation = future_parent->commit.height;
    fixture.input.storage.logical_heads = {future_parent->commit_id,
                                           branch_head_id};
    std::ranges::sort(fixture.input.storage.logical_heads);
    fixture.input.storage.marked_heads = fixture.input.storage.logical_heads;
    fixture.input.storage.reachable_commits = fixture.commits;
    fixture.input.storage.reachable_commit_ids.clear();
    for (const auto& commit : fixture.commits) {
        fixture.input.storage.reachable_commit_ids.push_back(commit.id);
    }
    const auto result = kasumi::reconciliation::reconcile(fixture.input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_TRUE(result->requires_publication);
    fixture.result = *result;

    const auto epoch_puts = fixture.state->epoch_put_count;
    const auto executed =
        kasumi::application::sync::coordinator::execute(fixture.runtime,
                                                        fixture.storage,
                                                        fixture.key,
                                                        fixture.input,
                                                        fixture.result);
    ASSERT_TRUE(executed.has_value()) << executed.error().detail;
    EXPECT_EQ(fixture.state->epoch_put_count, epoch_puts);

    const auto state =
        kasumi::state_storage::load_state(fixture.runtime.database_path);
    ASSERT_TRUE(state.has_value() && *state);
    EXPECT_EQ((*state)->epoch_id, fixture.previous_epoch.reference.epoch_id);
    EXPECT_EQ((*state)->epoch_sequence,
              fixture.previous_epoch.reference.sequence);
    const auto loaded =
        kasumi::application::sync::publication::find_reachable_commit(
            fixture.storage,
            fixture.key,
            fixture.runtime.database_path.parent_path(),
            (*state)->commit_id);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_GE((**loaded).commit.created_at, future_timestamp);
}

TEST(SyncCoordinatorTest, MissingLogicalHeadFailsBeforeRemotePublication) {
    auto fixture = make_pruning_fixture();
    ASSERT_TRUE(fixture.ready);
    const auto missing_head = fixture.input.storage.logical_heads.front();
    std::erase_if(fixture.input.storage.reachable_commits,
                  [&](const auto& commit) {
                      return commit.id == missing_head;
                  });
    ASSERT_FALSE(std::ranges::any_of(fixture.input.storage.reachable_commits,
                                     [&](const auto& commit) {
                                         return commit.id == missing_head;
                                     }));
    const auto remote_puts = fixture.state->put_count;
    const auto epoch_puts = fixture.state->epoch_put_count;

    const auto executed =
        kasumi::application::sync::coordinator::execute(fixture.runtime,
                                                        fixture.storage,
                                                        fixture.key,
                                                        fixture.input,
                                                        fixture.result);
    ASSERT_FALSE(executed.has_value());
    EXPECT_EQ(executed.error().code,
              kasumi::application::sync::coordinator::ErrorCode::InvalidInput);
    EXPECT_EQ(fixture.state->put_count, remote_puts);
    EXPECT_EQ(fixture.state->epoch_put_count, epoch_puts);
    EXPECT_FALSE(std::filesystem::exists(fixture.runtime.database_path));
}

TEST(SyncCoordinatorTest, MissingObservedEpochPolicyFailsClosed) {
    auto fixture = make_pruning_fixture();
    ASSERT_TRUE(fixture.ready);
    const auto epoch_puts = fixture.state->epoch_put_count;
    fixture.input.storage.epoch_policy.reset();

    const auto executed =
        kasumi::application::sync::coordinator::execute(fixture.runtime,
                                                        fixture.storage,
                                                        fixture.key,
                                                        fixture.input,
                                                        fixture.result);
    ASSERT_FALSE(executed.has_value());
    EXPECT_EQ(executed.error().code,
              kasumi::application::sync::coordinator::ErrorCode::InvalidInput);
    EXPECT_EQ(fixture.state->epoch_put_count, epoch_puts);
    EXPECT_FALSE(std::filesystem::exists(fixture.runtime.database_path));
}

TEST(SyncCoordinatorTest, MalformedObservedEpochPolicyFailsClosed) {
    auto fixture = make_pruning_fixture();
    ASSERT_TRUE(fixture.ready);
    const auto epoch_puts = fixture.state->epoch_put_count;
    fixture.input.storage.epoch_policy =
        kasumi::reconciliation::EpochRetentionPolicy{
            .min_history_depth = 0, .min_history_age_hours = 1};

    const auto executed =
        kasumi::application::sync::coordinator::execute(fixture.runtime,
                                                        fixture.storage,
                                                        fixture.key,
                                                        fixture.input,
                                                        fixture.result);
    ASSERT_FALSE(executed.has_value());
    EXPECT_EQ(executed.error().code,
              kasumi::application::sync::coordinator::ErrorCode::InvalidInput);
    EXPECT_EQ(fixture.state->epoch_put_count, epoch_puts);
    EXPECT_FALSE(std::filesystem::exists(fixture.runtime.database_path));
}

TEST(SyncCoordinatorTest, RejectsEveryPartialObservedEpochStateBeforeJournal) {
    const auto invalid = [](auto& storage, int case_number) {
        switch (case_number) {
            case 0: // vault only
                storage.epoch_id.clear();
                storage.epoch_sequence = 0;
                storage.epoch_policy.reset();
                break;
            case 1: // policy only
                storage.epoch_vault_id.clear();
                storage.epoch_id.clear();
                storage.epoch_sequence = 0;
                break;
            case 2: // sequence > 0 only
                storage.epoch_vault_id.clear();
                storage.epoch_id.clear();
                storage.epoch_sequence = 1;
                storage.epoch_policy.reset();
                break;
            case 3: // id without vault
                storage.epoch_vault_id.clear();
                break;
            case 4: // id without policy
                storage.epoch_policy.reset();
                break;
        }
    };

    for (int case_number = 0; case_number < 5; ++case_number) {
        auto fixture = make_pruning_fixture();
        ASSERT_TRUE(fixture.ready);
        invalid(fixture.input.storage, case_number);
        const auto epoch_puts = fixture.state->epoch_put_count;
        const auto executed =
            kasumi::application::sync::coordinator::execute(fixture.runtime,
                                                            fixture.storage,
                                                            fixture.key,
                                                            fixture.input,
                                                            fixture.result);
        ASSERT_FALSE(executed.has_value()) << case_number;
        EXPECT_EQ(
            executed.error().code,
            kasumi::application::sync::coordinator::ErrorCode::InvalidInput)
            << case_number;
        EXPECT_EQ(fixture.state->epoch_put_count, epoch_puts) << case_number;
        EXPECT_FALSE(std::filesystem::exists(fixture.runtime.database_path))
            << case_number;
    }
}

TEST(SyncCoordinatorTest,
     AuthenticatedEpochPolicyPropagatesThroughObservation) {
    auto fixture = make_pruning_fixture();
    ASSERT_TRUE(fixture.ready);

    const auto storage_state =
        kasumi::application::observation::collect_storage_state(
            fixture.storage, fixture.key, fixture.profile, true);
    ASSERT_TRUE(storage_state.has_value()) << storage_state.error();
    ASSERT_TRUE(storage_state->epoch_policy.has_value());
    EXPECT_EQ(storage_state->epoch_policy->min_history_depth, 1U);
    EXPECT_EQ(storage_state->epoch_policy->min_history_age_hours, 6U);

    ASSERT_FALSE(storage_state->reachable_commits.empty());
    const auto& base = storage_state->reachable_commits.front();
    ASSERT_TRUE(
        kasumi::state_storage::initialize(fixture.runtime.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        fixture.runtime.database_path,
        {.tree = base.commit.tree,
         .height = base.commit.height,
         .commit_id = base.id,
         .epoch_id = fixture.previous_epoch.reference.epoch_id,
         .epoch_sequence = fixture.previous_epoch.reference.sequence}));

    const auto observed =
        kasumi::application::observation::collect_reconciliation_input(
            fixture.runtime, fixture.storage, fixture.key, true);
    ASSERT_TRUE(observed.has_value()) << observed.error().detail;
    ASSERT_TRUE(observed->storage.epoch_policy.has_value());
    EXPECT_EQ(observed->storage.epoch_policy->min_history_depth, 1U);
    EXPECT_EQ(observed->storage.epoch_policy->min_history_age_hours, 6U);
}

TEST(SyncCoordinatorTest,
     PruningEpochPublishFailureNeverAdvancesAcceptedEpoch) {
    auto fixture = make_pruning_fixture();
    ASSERT_TRUE(fixture.ready);
    ASSERT_TRUE(
        kasumi::state_storage::initialize(fixture.runtime.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        fixture.runtime.database_path,
        {.tree = fixture.input.storage.tree,
         .height = fixture.input.storage.generation,
         .commit_id = fixture.input.storage.logical_heads.front(),
         .ciphertext_id = std::string(64, 'c'),
         .epoch_id = fixture.previous_epoch.reference.epoch_id,
         .epoch_sequence = fixture.previous_epoch.reference.sequence}));

    fixture.state->fail_epoch_put = true;
    const auto executed =
        kasumi::application::sync::coordinator::execute(fixture.runtime,
                                                        fixture.storage,
                                                        fixture.key,
                                                        fixture.input,
                                                        fixture.result);
    ASSERT_FALSE(executed.has_value());
    EXPECT_EQ(
        executed.error().code,
        kasumi::application::sync::coordinator::ErrorCode::PublicationFailure);

    const auto state =
        kasumi::state_storage::load_state(fixture.runtime.database_path);
    ASSERT_TRUE(state.has_value() && *state);
    EXPECT_EQ((*state)->epoch_id, fixture.previous_epoch.reference.epoch_id);
    EXPECT_EQ((*state)->epoch_sequence,
              fixture.previous_epoch.reference.sequence);
    const auto paths =
        kasumi::application::sync::journal::make_paths(fixture.profile);
    ASSERT_TRUE(paths.has_value());
    const auto pending =
        kasumi::application::sync::journal::load(*paths, fixture.key);
    ASSERT_TRUE(pending.has_value() && *pending);
    EXPECT_EQ((*pending)->phase, kasumi::transaction::Phase::HeadVerified);
    EXPECT_TRUE((*pending)->epoch_id.empty());

    fixture.state->fail_epoch_put = false;
    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            fixture.runtime, fixture.storage, fixture.key);
    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
    EXPECT_EQ(
        *recovered,
        kasumi::application::sync::coordinator::RecoveryResult::RolledForward);
    const auto after_recovery =
        kasumi::state_storage::load_state(fixture.runtime.database_path);
    ASSERT_TRUE(after_recovery.has_value() && *after_recovery);
    EXPECT_EQ((*after_recovery)->epoch_id,
              fixture.previous_epoch.reference.epoch_id);
    EXPECT_EQ((*after_recovery)->epoch_sequence,
              fixture.previous_epoch.reference.sequence);
}

TEST(SyncCoordinatorTest,
     PruningEpochAmbiguousPutWithVerifiedEffectContinuesSafely) {
    auto fixture = make_pruning_fixture();
    ASSERT_TRUE(fixture.ready);
    const auto epoch_puts_before = fixture.state->epoch_put_count;
    fixture.state->fail_epoch_put = true;
    fixture.state->persist_epoch_on_put_failure = true;

    const auto executed =
        kasumi::application::sync::coordinator::execute(fixture.runtime,
                                                        fixture.storage,
                                                        fixture.key,
                                                        fixture.input,
                                                        fixture.result);
    ASSERT_TRUE(executed.has_value()) << executed.error().detail;
    EXPECT_EQ(fixture.state->epoch_put_count, epoch_puts_before + 1);
    const auto state =
        kasumi::state_storage::load_state(fixture.runtime.database_path);
    ASSERT_TRUE(state.has_value() && *state);
    EXPECT_EQ((*state)->epoch_sequence, 3U);
    EXPECT_NE((*state)->epoch_id, fixture.previous_epoch.reference.epoch_id);
}

TEST(SyncCoordinatorTest,
     PruningEpochVerificationFailureDoesNotCommitCandidate) {
    auto fixture = make_pruning_fixture();
    ASSERT_TRUE(fixture.ready);
    fixture.state->fail_epoch_get = true;

    const auto executed =
        kasumi::application::sync::coordinator::execute(fixture.runtime,
                                                        fixture.storage,
                                                        fixture.key,
                                                        fixture.input,
                                                        fixture.result);
    ASSERT_FALSE(executed.has_value());
    EXPECT_EQ(
        executed.error().code,
        kasumi::application::sync::coordinator::ErrorCode::PublicationFailure);
    EXPECT_FALSE(std::filesystem::exists(fixture.runtime.database_path));
    const auto paths =
        kasumi::application::sync::journal::make_paths(fixture.profile);
    ASSERT_TRUE(paths.has_value());
    const auto pending =
        kasumi::application::sync::journal::load(*paths, fixture.key);
    ASSERT_TRUE(pending.has_value() && *pending);
    EXPECT_EQ((*pending)->phase, kasumi::transaction::Phase::EpochUploaded);

    fixture.state->fail_epoch_get = false;
    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            fixture.runtime, fixture.storage, fixture.key);
    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
    const auto state =
        kasumi::state_storage::load_state(fixture.runtime.database_path);
    ASSERT_TRUE(state.has_value() && *state);
    EXPECT_EQ((*state)->epoch_sequence, 3U);
}

kasumi::application::history_storage::epoch::SealedEpoch
make_pruning_candidate(const PruningFixture& fixture) {
    return kasumi::application::history_storage::epoch::seal(
               {.vault_id = std::string(64, 'e'),
                .sequence = 3,
                .issued_at = 123,
                .policy = fixture.previous_policy,
                .anchors = {{.commit_id = fixture.recovery_parents.front(),
                             .height = 0}},
                .previous_epoch_id = fixture.previous_epoch.reference.epoch_id},
               fixture.key)
        .value();
}

kasumi::application::history_storage::epoch::SealedEpoch make_pruning_successor(
    const kasumi::application::history_storage::epoch::SealedEpoch& previous,
    const PruningFixture& fixture) {
    return kasumi::application::history_storage::epoch::seal(
               {.vault_id = std::string(64, 'e'),
                .sequence = 4,
                .issued_at = 124,
                .policy = fixture.previous_policy,
                .anchors = {{.commit_id = fixture.recovery_parents.front(),
                             .height = 0}},
                .previous_epoch_id = previous.reference.epoch_id},
               fixture.key)
        .value();
}

std::string epoch_listing_name(
    const kasumi::application::history_storage::epoch::SealedEpoch& epoch) {
    constexpr std::string_view prefix = "history/epochs/v1/";
    return kasumi::application::history_storage::epoch::object_identifier(
               epoch.reference)
        .value()
        .substr(prefix.size());
}

TEST(SyncCoordinatorTest,
     RecoveryFromUploadedPruningEpochAuthenticatesExactReference) {
    auto fixture = make_pruning_fixture();
    ASSERT_TRUE(fixture.ready);
    const auto candidate = make_pruning_candidate(fixture);
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        fixture.storage, candidate, fixture.local));
    const auto epoch_puts = fixture.state->epoch_put_count;
    const auto id =
        save_pruning_recovery_record(fixture.profile,
                                     kasumi::transaction::Phase::EpochUploaded,
                                     fixture.key,
                                     fixture.recovery_head,
                                     fixture.recovery_parents,
                                     candidate,
                                     std::string(64, 'e'));
    ASSERT_FALSE(id.empty());

    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            fixture.runtime, fixture.storage, fixture.key);
    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
    const auto state =
        kasumi::state_storage::load_state(fixture.runtime.database_path);
    ASSERT_TRUE(state.has_value() && *state);
    EXPECT_EQ((*state)->epoch_id, candidate.reference.epoch_id);
    EXPECT_EQ((*state)->epoch_sequence, candidate.reference.sequence);
    EXPECT_EQ(fixture.state->epoch_put_count, epoch_puts);
}

TEST(SyncCoordinatorTest,
     RecoveryKeepsExactJournalEpochWhenAValidNewerEpochExists) {
    auto fixture = make_pruning_fixture();
    ASSERT_TRUE(fixture.ready);
    const auto candidate = make_pruning_candidate(fixture);
    const auto newer = make_pruning_successor(candidate, fixture);
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        fixture.storage, candidate, fixture.local));
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        fixture.storage, newer, fixture.local));
    ASSERT_FALSE(
        save_pruning_recovery_record(fixture.profile,
                                     kasumi::transaction::Phase::EpochUploaded,
                                     fixture.key,
                                     fixture.recovery_head,
                                     fixture.recovery_parents,
                                     candidate,
                                     std::string(64, 'e'))
            .empty());

    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            fixture.runtime, fixture.storage, fixture.key);
    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
    const auto state =
        kasumi::state_storage::load_state(fixture.runtime.database_path);
    ASSERT_TRUE(state.has_value() && *state);
    EXPECT_EQ((*state)->epoch_id, candidate.reference.epoch_id);
    EXPECT_EQ((*state)->epoch_sequence, candidate.reference.sequence);
}

TEST(SyncCoordinatorTest,
     RecoveryRejectsJournalEpochNotInChangingRemoteAncestry) {
    auto fixture = make_pruning_fixture();
    ASSERT_TRUE(fixture.ready);
    const auto candidate_a = make_pruning_candidate(fixture);
    const auto candidate_b =
        kasumi::application::history_storage::epoch::seal(
            {.vault_id = std::string(64, 'e'),
             .sequence = 3,
             .issued_at = 124,
             .policy = fixture.previous_policy,
             .anchors = {{.commit_id = fixture.recovery_parents.front(),
                          .height = 0}},
             .previous_epoch_id = fixture.previous_epoch.reference.epoch_id},
            fixture.key)
            .value();
    const auto successor_b =
        kasumi::application::history_storage::epoch::seal(
            {.vault_id = std::string(64, 'e'),
             .sequence = 4,
             .issued_at = 125,
             .policy = fixture.previous_policy,
             .anchors = {{.commit_id = fixture.recovery_parents.front(),
                          .height = 0}},
             .previous_epoch_id = candidate_b.reference.epoch_id},
            fixture.key)
            .value();
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        fixture.storage, candidate_a, fixture.local));
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        fixture.storage, candidate_b, fixture.local));
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        fixture.storage, successor_b, fixture.local));

    constexpr std::string_view prefix = "history/epochs/v1/";
    std::vector<std::string> first_listing;
    for (const auto& [identifier, unused] : fixture.state->objects) {
        static_cast<void>(unused);
        if (!identifier.starts_with(prefix)) {
            continue;
        }
        const auto parsed = kasumi::application::history_storage::epoch::
            parse_object_identifier(identifier);
        ASSERT_TRUE(parsed.has_value());
        if (parsed->sequence <= 2) {
            first_listing.push_back(identifier.substr(prefix.size()));
        }
    }
    first_listing.push_back(epoch_listing_name(candidate_a));
    auto second_listing = first_listing;
    second_listing.pop_back();
    second_listing.push_back(epoch_listing_name(candidate_b));
    second_listing.push_back(epoch_listing_name(successor_b));
    fixture.state->scripted_epoch_listings = {std::move(first_listing),
                                              std::move(second_listing)};
    const auto epoch_puts = fixture.state->epoch_put_count;
    ASSERT_FALSE(
        save_pruning_recovery_record(fixture.profile,
                                     kasumi::transaction::Phase::EpochUploaded,
                                     fixture.key,
                                     fixture.recovery_head,
                                     fixture.recovery_parents,
                                     candidate_a,
                                     std::string(64, 'e'))
            .empty());

    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            fixture.runtime, fixture.storage, fixture.key);
    ASSERT_FALSE(recovered.has_value());
    EXPECT_EQ(
        recovered.error().code,
        kasumi::application::sync::coordinator::ErrorCode::RecoveryConflict);
    EXPECT_FALSE(std::filesystem::exists(fixture.runtime.database_path));
    EXPECT_TRUE(
        std::filesystem::exists(fixture.profile / "transaction.bin.enc"));
    EXPECT_EQ(fixture.state->epoch_put_count, epoch_puts);
    const auto paths =
        kasumi::application::sync::journal::make_paths(fixture.profile);
    ASSERT_TRUE(paths.has_value());
    const auto journal =
        kasumi::application::sync::journal::load(*paths, fixture.key);
    ASSERT_TRUE(journal.has_value() && *journal);
    EXPECT_EQ((*journal)->phase, kasumi::transaction::Phase::EpochUploaded);
}

TEST(SyncCoordinatorTest,
     RecoveryFromVerifiedPruningEpochPersistsNonZeroSequence) {
    auto fixture = make_pruning_fixture();
    ASSERT_TRUE(fixture.ready);
    const auto candidate = make_pruning_candidate(fixture);
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        fixture.storage, candidate, fixture.local));
    const auto id =
        save_pruning_recovery_record(fixture.profile,
                                     kasumi::transaction::Phase::EpochVerified,
                                     fixture.key,
                                     fixture.recovery_head,
                                     fixture.recovery_parents,
                                     candidate,
                                     std::string(64, 'e'));
    ASSERT_FALSE(id.empty());

    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            fixture.runtime, fixture.storage, fixture.key);
    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
    const auto state =
        kasumi::state_storage::load_state(fixture.runtime.database_path);
    ASSERT_TRUE(state.has_value() && *state);
    EXPECT_EQ((*state)->epoch_id, candidate.reference.epoch_id);
    EXPECT_EQ((*state)->epoch_sequence, 3U);
}

TEST(SyncCoordinatorTest,
     RecoveryFailsClosedWhenUploadedPruningEpochIsMissing) {
    auto fixture = make_pruning_fixture();
    ASSERT_TRUE(fixture.ready);
    const auto candidate = make_pruning_candidate(fixture);
    const auto id =
        save_pruning_recovery_record(fixture.profile,
                                     kasumi::transaction::Phase::EpochUploaded,
                                     fixture.key,
                                     fixture.recovery_head,
                                     fixture.recovery_parents,
                                     candidate,
                                     std::string(64, 'e'));
    ASSERT_FALSE(id.empty());

    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            fixture.runtime, fixture.storage, fixture.key);
    ASSERT_FALSE(recovered.has_value());
    EXPECT_EQ(
        recovered.error().code,
        kasumi::application::sync::coordinator::ErrorCode::RecoveryConflict);
    EXPECT_FALSE(std::filesystem::exists(fixture.runtime.database_path));
    EXPECT_TRUE(
        std::filesystem::exists(fixture.profile / "transaction.bin.enc"));
}

TEST(SyncCoordinatorTest,
     RecoveryRejectsAuthenticCandidateWhenItsHistoricalPredecessorIsMissing) {
    auto fixture = make_pruning_fixture();
    ASSERT_TRUE(fixture.ready);
    const auto candidate = make_pruning_candidate(fixture);
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        fixture.storage, candidate, fixture.local));
    const auto predecessor_identifier =
        kasumi::application::history_storage::epoch::object_identifier(
            fixture.previous_epoch.reference)
            .value();
    {
        std::lock_guard lock(fixture.state->mutex);
        EXPECT_EQ(fixture.state->objects.erase(predecessor_identifier), 1U);
    }
    ASSERT_FALSE(
        save_pruning_recovery_record(fixture.profile,
                                     kasumi::transaction::Phase::EpochUploaded,
                                     fixture.key,
                                     fixture.recovery_head,
                                     fixture.recovery_parents,
                                     candidate,
                                     std::string(64, 'e'))
            .empty());

    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            fixture.runtime, fixture.storage, fixture.key);
    ASSERT_FALSE(recovered.has_value());
    EXPECT_EQ(
        recovered.error().code,
        kasumi::application::sync::coordinator::ErrorCode::RecoveryConflict);
    EXPECT_FALSE(std::filesystem::exists(fixture.runtime.database_path));
    EXPECT_TRUE(
        std::filesystem::exists(fixture.profile / "transaction.bin.enc"));
}

TEST(SyncCoordinatorTest,
     RecoveryFailsClosedWhenPruningEpochAuthenticationFails) {
    auto fixture = make_pruning_fixture();
    ASSERT_TRUE(fixture.ready);
    const auto candidate = make_pruning_candidate(fixture);
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        fixture.storage, candidate, fixture.local));
    const auto identifier =
        kasumi::application::history_storage::epoch::object_identifier(
            candidate.reference)
            .value();
    {
        std::lock_guard lock(fixture.state->mutex);
        auto& bytes = fixture.state->objects[identifier];
        ASSERT_FALSE(bytes.empty());
        bytes.back() ^= 0x01U;
    }
    const auto id =
        save_pruning_recovery_record(fixture.profile,
                                     kasumi::transaction::Phase::EpochUploaded,
                                     fixture.key,
                                     fixture.recovery_head,
                                     fixture.recovery_parents,
                                     candidate,
                                     std::string(64, 'e'));
    ASSERT_FALSE(id.empty());

    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            fixture.runtime, fixture.storage, fixture.key);
    ASSERT_FALSE(recovered.has_value());
    EXPECT_EQ(
        recovered.error().code,
        kasumi::application::sync::coordinator::ErrorCode::RecoveryConflict);
    EXPECT_FALSE(std::filesystem::exists(fixture.runtime.database_path));
}

TEST(SyncCoordinatorTest,
     PruningEpochCrashCheckpointsRecoverDeterministically) {
    const std::array phases{kasumi::transaction::Phase::HeadVerified,
                            kasumi::transaction::Phase::EpochUploaded,
                            kasumi::transaction::Phase::EpochVerified,
                            kasumi::transaction::Phase::DatabaseCommitted,
                            kasumi::transaction::Phase::CleanupCompleted};

    for (const auto phase : phases) {
        auto fixture = make_pruning_fixture();
        ASSERT_TRUE(fixture.ready) << static_cast<int>(phase);

        const auto candidate = make_pruning_candidate(fixture);
        const bool has_candidate =
            phase >= kasumi::transaction::Phase::EpochUploaded;
        if (has_candidate) {
            ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
                fixture.storage, candidate, fixture.local));
        }
        if (phase >= kasumi::transaction::Phase::DatabaseCommitted) {
            ASSERT_TRUE(kasumi::state_storage::initialize(
                fixture.runtime.database_path));
            ASSERT_TRUE(kasumi::state_storage::save_state(
                fixture.runtime.database_path,
                {.tree = fixture.input.storage.tree,
                 .height = fixture.input.storage.generation,
                 .commit_id = fixture.recovery_head.commit_id,
                 .ciphertext_id = fixture.recovery_head.ciphertext_id,
                 .epoch_id = candidate.reference.epoch_id,
                 .epoch_sequence = candidate.reference.sequence}));
        }

        const auto epoch_puts = fixture.state->epoch_put_count;
        const auto transaction_id =
            has_candidate
                ? save_pruning_recovery_record(fixture.profile,
                                               phase,
                                               fixture.key,
                                               fixture.recovery_head,
                                               fixture.recovery_parents,
                                               candidate,
                                               std::string(64, 'e'))
                : save_recovery_record(fixture.profile,
                                       phase,
                                       fixture.key,
                                       fixture.recovery_head.commit_id,
                                       fixture.recovery_head.ciphertext_id,
                                       fixture.recovery_parents);
        ASSERT_FALSE(transaction_id.empty()) << static_cast<int>(phase);

        const auto recovered =
            kasumi::application::sync::coordinator::recover_if_needed(
                fixture.runtime, fixture.storage, fixture.key);
        ASSERT_TRUE(recovered.has_value())
            << static_cast<int>(phase) << ": " << recovered.error().detail;
        EXPECT_EQ(*recovered,
                  kasumi::application::sync::coordinator::RecoveryResult::
                      RolledForward)
            << static_cast<int>(phase);
        EXPECT_EQ(fixture.state->epoch_put_count, epoch_puts)
            << static_cast<int>(phase);

        const auto state =
            kasumi::state_storage::load_state(fixture.runtime.database_path);
        ASSERT_TRUE(state.has_value() && *state) << static_cast<int>(phase);
        EXPECT_EQ((*state)->epoch_sequence,
                  has_candidate ? candidate.reference.sequence
                                : fixture.previous_epoch.reference.sequence)
            << static_cast<int>(phase);
        EXPECT_FALSE(
            std::filesystem::exists(fixture.profile / "transaction.bin.enc"));
        EXPECT_FALSE(std::filesystem::exists(fixture.profile / ".transactions" /
                                             transaction_id));
    }
}

TEST(SyncCoordinatorTest, SyncWithoutNewEpochPreservesAcceptedEpochReference) {
    auto workspace =
        kasumi::test::make_temp_workspace("preserve-epoch-sequence");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));

    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto runtime_data = make_runtime(profile, local, storage_path);
    const auto id = [](char value) {
        return std::string(64, value);
    };
    auto input = empty_publication_input();
    input.local_tree.rows.front().mtime =
        std::filesystem::last_write_time(local);
    kasumi::finalize_snapshot(input.local_tree);
    input.storage.tree = input.local_tree;
    input.storage.history_present = true;
    input.storage.generation = 0;
    input.storage.logical_heads = {id('a'), id('b')};
    input.storage.marked_heads = input.storage.logical_heads;
    input.storage.reachable_commits = {
        {.id = id('a'), .commit = {.height = 0, .tree = input.storage.tree}},
        {.id = id('b'), .commit = {.height = 0, .tree = input.storage.tree}}};
    input.storage.reachable_commit_ids = {id('a'), id('b')};
    input.storage.epoch_vault_id = id('a');
    input.storage.epoch_id = id('e');
    input.storage.epoch_sequence = 3;
    input.storage.epoch_policy = kasumi::reconciliation::EpochRetentionPolicy{
        .min_history_depth = 5, .min_history_age_hours = 6};

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_TRUE(result->requires_publication);
    const auto executed = kasumi::application::sync::coordinator::execute(
        runtime_data, *storage, key, input, *result);
    ASSERT_TRUE(executed) << executed.error().detail;

    const auto state =
        kasumi::state_storage::load_state(runtime_data.database_path);
    ASSERT_TRUE(state.has_value() && *state);
    EXPECT_EQ((*state)->epoch_id, id('e'));
    EXPECT_EQ((*state)->epoch_sequence, 3U);
}

TEST(SyncCoordinatorTest,
     CommitUploadOverlapsContentAndHeadWaitsForBothVerifications) {
    auto workspace = kasumi::test::make_temp_workspace(
        "transaction-overlapped-commit-upload");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    kasumi::test::write_text(local / "file.txt", "contents");

    const auto local_tree =
        kasumi::application::observation::collect_local_tree(local);
    ASSERT_TRUE(local_tree.has_value()) << local_tree.error();
    auto input = empty_publication_input();
    input.local_tree = *local_tree;
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_TRUE(result->requires_publication);

    auto base = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(base.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*base));
    ReobserveTransportState state{};
    state.base = &*base;
    state.storage_root = storage_path;
    state.require_commit_overlap = true;
    auto storage = make_reobserve_transport(state);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto executed = kasumi::application::sync::coordinator::execute(
        make_runtime(profile, local, storage_path),
        storage,
        key,
        input,
        *result);
    ASSERT_TRUE(executed.has_value()) << executed.error().detail;
    EXPECT_FALSE(state.commit_overlap_timed_out);

    const auto event_index = [&](std::string_view name) {
        const auto found = std::ranges::find(state.events, name);
        EXPECT_NE(found, state.events.end()) << name;
        return static_cast<std::size_t>(
            std::ranges::distance(state.events.begin(), found));
    };
    const auto content_verified = event_index("content verified");
    const auto commit_verified = event_index("commit verified");
    const auto head_put = event_index("head PUT");
    const auto head_verified = event_index("head verified");
    EXPECT_LT(content_verified, head_put);
    EXPECT_LT(commit_verified, head_put);
    EXPECT_LT(head_put, head_verified);
}

TEST(SyncCoordinatorTest, RenameReusesContentReferencedByRemoteHistory) {
    auto workspace =
        kasumi::test::make_temp_workspace("rename-reuses-remote-content");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto source = local / "renamed.txt";
    kasumi::test::write_text(source, "same-content");

    const auto local_tree =
        kasumi::application::observation::collect_local_tree(local);
    ASSERT_TRUE(local_tree.has_value()) << local_tree.error();
    auto input = empty_publication_input();
    input.local_tree = *local_tree;
    input.storage.tree = *local_tree;
    auto* previous = kasumi::find_row(input.storage.tree, "renamed.txt");
    ASSERT_NE(previous, nullptr);
    previous->path = "original.txt";
    kasumi::finalize_snapshot(input.storage.tree);
    input.base_tree = input.storage.tree;
    add_reachable_head(input);

    auto base = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(base.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*base));
    const auto content_hash = kasumi::hasher::hash_string("same-content");
    const auto remote_source =
        kasumi::test::workspace_path(workspace, "remote-source.txt");
    kasumi::test::write_text(remote_source, "same-content");
    add_storage_object(*base, remote_source, content_hash);
    ReobserveTransportState state{};
    state.base = &*base;
    auto storage = make_reobserve_transport(state);

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_EQ(std::ranges::count(result->plan.operations,
                                 kasumi::Action::Upload,
                                 &kasumi::Operation::action),
              1);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto executed = kasumi::application::sync::coordinator::execute(
        make_runtime(profile, local, storage_path),
        storage,
        key,
        input,
        *result);
    ASSERT_TRUE(executed.has_value()) << executed.error().detail;
    EXPECT_EQ(std::ranges::count(state.events, "content PUT"), 0);
    EXPECT_EQ(state.put_count, 2U);
    EXPECT_EQ(
        kasumi::transport::presence(
            storage, kasumi::crypto::content_identifier(key, content_hash)),
        kasumi::transport::Presence::Present);
}

TEST(SyncCoordinatorTest, DuplicateUploadsTransferContentOnce) {
    auto workspace =
        kasumi::test::make_temp_workspace("duplicate-uploads-transfer-once");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    kasumi::test::write_text(local / "alpha.txt", "duplicate");
    kasumi::test::write_text(local / "beta.txt", "duplicate");

    const auto local_tree =
        kasumi::application::observation::collect_local_tree(local);
    ASSERT_TRUE(local_tree.has_value()) << local_tree.error();
    auto input = empty_publication_input();
    input.local_tree = *local_tree;
    input.storage.tree.rows = {input.local_tree.rows.front()};
    kasumi::finalize_snapshot(input.storage.tree);
    input.base_tree = input.storage.tree;
    add_reachable_head(input);

    auto base = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(base.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*base));
    ReobserveTransportState state{};
    state.base = &*base;
    auto storage = make_reobserve_transport(state);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_EQ(std::ranges::count(result->plan.operations,
                                 kasumi::Action::Upload,
                                 &kasumi::Operation::action),
              2);

    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto executed = kasumi::application::sync::coordinator::execute(
        make_runtime(profile, local, storage_path),
        storage,
        key,
        input,
        *result);
    ASSERT_TRUE(executed.has_value()) << executed.error().detail;
    EXPECT_EQ(std::ranges::count(state.events, "content PUT"), 1);
    EXPECT_EQ(state.put_count, 3U);
    const auto content_hash = kasumi::hasher::hash_string("duplicate");
    EXPECT_EQ(
        kasumi::transport::presence(
            storage, kasumi::crypto::content_identifier(key, content_hash)),
        kasumi::transport::Presence::Present);
}

TEST(SyncCoordinatorTest, DuplicateDownloadsFetchContentOnce) {
    auto workspace =
        kasumi::test::make_temp_workspace("duplicate-downloads-fetch-once");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));

    const auto local_tree =
        kasumi::application::observation::collect_local_tree(local);
    ASSERT_TRUE(local_tree.has_value()) << local_tree.error();
    const auto content_hash = kasumi::hasher::hash_string("duplicate");
    const auto source = kasumi::test::workspace_path(workspace, "source.txt");
    kasumi::test::write_text(source, "duplicate");
    std::error_code mtime_error;
    const auto source_mtime =
        std::filesystem::last_write_time(source, mtime_error);
    ASSERT_FALSE(mtime_error);

    auto input = empty_publication_input();
    input.local_tree = *local_tree;
    input.base_tree = *local_tree;
    input.storage.tree = *local_tree;
    input.storage.tree.rows.push_back(kasumi::NodeRow{.path = "alpha.txt",
                                                      .hash = content_hash,
                                                      .size = 9,
                                                      .mtime = source_mtime,
                                                      .is_directory = false});
    input.storage.tree.rows.push_back(kasumi::NodeRow{.path = "beta.txt",
                                                      .hash = content_hash,
                                                      .size = 9,
                                                      .mtime = source_mtime,
                                                      .is_directory = false});
    kasumi::finalize_snapshot(input.storage.tree);
    add_reachable_head(input);

    auto base = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(base.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*base));
    add_storage_object(*base, source, content_hash);
    ReobserveTransportState state{};
    state.base = &*base;
    auto storage = make_reobserve_transport(state);

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_EQ(std::ranges::count(result->plan.operations,
                                 kasumi::Action::Download,
                                 &kasumi::Operation::action),
              2);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto executed = kasumi::application::sync::coordinator::execute(
        make_runtime(profile, local, storage_path),
        storage,
        key,
        input,
        *result);
    ASSERT_TRUE(executed.has_value()) << executed.error().detail;
    EXPECT_EQ(state.get_count, 1U);
    EXPECT_EQ(kasumi::test::read_text(local / "alpha.txt"), "duplicate");
    EXPECT_EQ(kasumi::test::read_text(local / "beta.txt"), "duplicate");
}

TEST(SyncCoordinatorTest,
     LargeDuplicateDownloadCacheRevalidatesAndReusesPlaintext) {
    auto workspace =
        kasumi::test::make_temp_workspace("large-duplicate-plaintext-cache");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto transaction =
        kasumi::test::workspace_path(workspace, "transaction");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(local));
    ASSERT_TRUE(std::filesystem::create_directories(transaction));

    const std::string payload(kasumi::crypto::CHUNK_SIZE, 'x');
    const auto source = kasumi::test::workspace_path(workspace, "source.bin");
    kasumi::test::write_text(source, payload);
    const auto content_hash = kasumi::hasher::hash_string(payload);
    const auto content_id = kasumi::hash_hex(content_hash);
    auto base = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(base.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*base));
    add_storage_object(*base, source, content_hash);
    ReobserveTransportState state{};
    state.base = &*base;
    auto storage = make_reobserve_transport(state);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const kasumi::platform::Workspace tx{.root = transaction};

    const auto download =
        [&](std::string path,
            std::size_t index,
            kasumi::application::sync::mutation::DownloadCacheMode mode) {
            const kasumi::Operation operation{.action =
                                                  kasumi::Action::Download,
                                              .path = std::move(path),
                                              .hash = content_id,
                                              .alt_path = {},
                                              .size = payload.size()};
            return kasumi::application::sync::mutation::apply_operation(
                operation, index, local, storage, key, tx, mode);
        };

    ASSERT_TRUE(download(
        "alpha.bin",
        0,
        kasumi::application::sync::mutation::DownloadCacheMode::Populate));
    EXPECT_EQ(state.get_count, 1U);
    const auto plaintext = transaction / ("download-" + content_id + ".plain");
    const auto encrypted = transaction / ("download-" + content_id + ".enc");
    ASSERT_TRUE(std::filesystem::is_regular_file(plaintext));
    ASSERT_TRUE(std::filesystem::is_regular_file(encrypted));

    kasumi::test::write_text(plaintext, "corrupt");
    ASSERT_TRUE(download(
        "beta.bin",
        1,
        kasumi::application::sync::mutation::DownloadCacheMode::Reuse));
    EXPECT_EQ(state.get_count, 1U);
    kasumi::test::write_text(encrypted, "corrupt");
    ASSERT_TRUE(download(
        "gamma.bin",
        2,
        kasumi::application::sync::mutation::DownloadCacheMode::Reuse));
    EXPECT_EQ(state.get_count, 1U);
    EXPECT_EQ(kasumi::test::read_text(local / "alpha.bin"), payload);
    EXPECT_EQ(kasumi::test::read_text(local / "beta.bin"), payload);
    EXPECT_EQ(kasumi::test::read_text(local / "gamma.bin"), payload);
}

TEST(SyncCoordinatorTest, ChangedUploadSourceIsRejectedBeforePut) {
    auto workspace = kasumi::test::make_temp_workspace("changed-upload-source");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto transaction =
        kasumi::test::workspace_path(workspace, "transaction");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(local));
    ASSERT_TRUE(std::filesystem::create_directories(transaction));
    kasumi::test::write_text(local / "alpha.txt", "bravo");

    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    const auto expected_hash =
        kasumi::hash_hex(kasumi::hasher::hash_string("alpha"));
    const kasumi::Operation operation{.action = kasumi::Action::Upload,
                                      .path = "alpha.txt",
                                      .hash = expected_hash,
                                      .alt_path = {},
                                      .size = 5};
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const kasumi::platform::Workspace tx{.root = transaction};

    const auto applied = kasumi::application::sync::mutation::apply_operation(
        operation, 0, local, *storage, key, tx);

    EXPECT_FALSE(applied.has_value());
    const auto uploaded = kasumi::transport::presence(
        *storage, remote_content_id(key, expected_hash));
    ASSERT_TRUE(uploaded.has_value());
    EXPECT_EQ(*uploaded, kasumi::transport::Presence::Absent);
    EXPECT_FALSE(std::filesystem::exists(transaction / "0.upload.enc"));
    EXPECT_FALSE(std::filesystem::exists(transaction / "0.upload.plain"));
}

TEST(SyncCoordinatorTest, ConcurrentUntouchedFileMtimeChangeIsNotMasked) {
    auto workspace =
        kasumi::test::make_temp_workspace("concurrent-untouched-file-mtime");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    kasumi::test::write_text(local / "tracked.txt", "old");
    kasumi::test::write_text(local / "untouched.txt", "same");

    const auto old_hash = kasumi::hasher::hash_string("old");
    const auto new_hash = kasumi::hasher::hash_string("new");
    const auto same_hash = kasumi::hasher::hash_string("same");
    const auto base_mtime = std::filesystem::file_time_type::clock::now();
    const auto tracked_mtime = base_mtime + std::chrono::seconds{1};
    const auto untouched_mtime = base_mtime + std::chrono::seconds{2};
    std::error_code error;
    std::filesystem::last_write_time(
        local / "tracked.txt", tracked_mtime, error);
    ASSERT_FALSE(error);
    std::filesystem::last_write_time(
        local / "untouched.txt", untouched_mtime, error);
    ASSERT_FALSE(error);
    const auto actual_tracked_mtime =
        std::filesystem::last_write_time(local / "tracked.txt", error);
    ASSERT_FALSE(error);
    const auto actual_untouched_mtime =
        std::filesystem::last_write_time(local / "untouched.txt", error);
    ASSERT_FALSE(error);
    const auto root_mtime = std::filesystem::last_write_time(local, error);
    ASSERT_FALSE(error);

    auto input = empty_publication_input();
    input.local_tree = kasumi::Snapshot{
        .rows = {kasumi::NodeRow{
                     .path = "", .mtime = root_mtime, .is_directory = true},
                 kasumi::NodeRow{.path = "tracked.txt",
                                 .hash = old_hash,
                                 .size = 3,
                                 .mtime = actual_tracked_mtime,
                                 .is_directory = false},
                 kasumi::NodeRow{.path = "untouched.txt",
                                 .hash = same_hash,
                                 .size = 4,
                                 .mtime = actual_untouched_mtime,
                                 .is_directory = false}}};
    kasumi::finalize_snapshot(input.local_tree);
    input.base_tree = input.local_tree;
    input.storage.tree = kasumi::Snapshot{
        .rows = {kasumi::NodeRow{
                     .path = "", .mtime = root_mtime, .is_directory = true},
                 kasumi::NodeRow{.path = "tracked.txt",
                                 .hash = new_hash,
                                 .size = 3,
                                 .mtime = actual_tracked_mtime,
                                 .is_directory = false},
                 kasumi::NodeRow{.path = "untouched.txt",
                                 .hash = same_hash,
                                 .size = 4,
                                 .mtime = actual_untouched_mtime,
                                 .is_directory = false}}};
    kasumi::finalize_snapshot(input.storage.tree);
    input.storage.object_identifiers.insert(kasumi::hash_hex(new_hash));
    add_reachable_head(input);

    const auto source = kasumi::test::workspace_path(workspace, "new.txt");
    kasumi::test::write_text(source, "new");
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    add_storage_object(*storage, source, new_hash);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_TRUE(std::ranges::any_of(
        result->plan.operations, [](const kasumi::Operation& operation) {
            return operation.action == kasumi::Action::Download &&
                   operation.path == "tracked.txt";
        }));

    const auto requested_concurrent_mtime =
        base_mtime + std::chrono::seconds{10};
    std::filesystem::last_write_time(
        local / "untouched.txt", requested_concurrent_mtime, error);
    ASSERT_FALSE(error);
    const auto concurrent_mtime =
        std::filesystem::last_write_time(local / "untouched.txt", error);
    ASSERT_FALSE(error);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto executed = kasumi::application::sync::coordinator::execute(
        make_runtime(profile, local, storage_path),
        *storage,
        key,
        input,
        *result);
    ASSERT_FALSE(executed.has_value()) << executed.error().detail;
    EXPECT_EQ(
        executed.error().code,
        kasumi::application::sync::coordinator::ErrorCode::CompositionMismatch);
    EXPECT_EQ(std::filesystem::last_write_time(local / "untouched.txt"),
              concurrent_mtime);
    EXPECT_FALSE(std::filesystem::exists(profile / "state.db"));
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_TRUE(std::filesystem::is_empty(profile / ".transactions"));
}

TEST(SyncCoordinatorTest, ConcurrentUntouchedDirectoryMtimeChangeIsNotMasked) {
    auto workspace = kasumi::test::make_temp_workspace(
        "concurrent-untouched-directory-mtime");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local / "modified"));
    ASSERT_TRUE(std::filesystem::create_directories(local / "untouched"));
    kasumi::test::write_text(local / "modified" / "tracked.txt", "old");
    kasumi::test::write_text(local / "untouched" / "other.txt", "same");

    const auto old_hash = kasumi::hasher::hash_string("old");
    const auto new_hash = kasumi::hasher::hash_string("new");
    const auto same_hash = kasumi::hasher::hash_string("same");
    const auto base_mtime = std::filesystem::file_time_type::clock::now();
    const auto tracked_mtime = base_mtime + std::chrono::seconds{3};
    const auto other_mtime = base_mtime + std::chrono::seconds{4};
    std::error_code error;
    std::filesystem::last_write_time(
        local / "modified" / "tracked.txt", tracked_mtime, error);
    ASSERT_FALSE(error);
    std::filesystem::last_write_time(
        local / "untouched" / "other.txt", other_mtime, error);
    ASSERT_FALSE(error);
    const auto root_mtime = std::filesystem::last_write_time(local, error);
    ASSERT_FALSE(error);
    const auto actual_modified_mtime =
        std::filesystem::last_write_time(local / "modified", error);
    ASSERT_FALSE(error);
    const auto actual_untouched_mtime =
        std::filesystem::last_write_time(local / "untouched", error);
    ASSERT_FALSE(error);
    const auto actual_tracked_mtime = std::filesystem::last_write_time(
        local / "modified" / "tracked.txt", error);
    ASSERT_FALSE(error);
    const auto actual_other_mtime = std::filesystem::last_write_time(
        local / "untouched" / "other.txt", error);
    ASSERT_FALSE(error);

    auto input = empty_publication_input();
    input.local_tree = kasumi::Snapshot{
        .rows = {kasumi::NodeRow{
                     .path = "", .mtime = root_mtime, .is_directory = true},
                 kasumi::NodeRow{.path = "modified",
                                 .mtime = actual_modified_mtime,
                                 .is_directory = true},
                 kasumi::NodeRow{.path = "modified/tracked.txt",
                                 .hash = old_hash,
                                 .size = 3,
                                 .mtime = actual_tracked_mtime,
                                 .is_directory = false},
                 kasumi::NodeRow{.path = "untouched",
                                 .mtime = actual_untouched_mtime,
                                 .is_directory = true},
                 kasumi::NodeRow{.path = "untouched/other.txt",
                                 .hash = same_hash,
                                 .size = 4,
                                 .mtime = actual_other_mtime,
                                 .is_directory = false}}};
    kasumi::finalize_snapshot(input.local_tree);
    input.base_tree = input.local_tree;
    input.storage.tree = input.local_tree;
    kasumi::find_row(input.storage.tree, "modified/tracked.txt")->hash =
        new_hash;
    kasumi::finalize_snapshot(input.storage.tree);
    input.storage.object_identifiers.insert(kasumi::hash_hex(new_hash));
    add_reachable_head(input);

    const auto source = kasumi::test::workspace_path(workspace, "new.txt");
    kasumi::test::write_text(source, "new");
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    add_storage_object(*storage, source, new_hash);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    const auto requested_concurrent_mtime =
        std::filesystem::file_time_type::clock::now() +
        std::chrono::seconds{10};
    const auto written = kasumi::platform::metadata::set_last_write_time(
        local / "untouched", requested_concurrent_mtime);
    ASSERT_TRUE(written.has_value()) << written.error();
    const auto concurrent_mtime =
        std::filesystem::last_write_time(local / "untouched", error);
    ASSERT_FALSE(error);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto executed = kasumi::application::sync::coordinator::execute(
        make_runtime(profile, local, storage_path),
        *storage,
        key,
        input,
        *result);
    ASSERT_FALSE(executed.has_value());
    EXPECT_EQ(
        executed.error().code,
        kasumi::application::sync::coordinator::ErrorCode::CompositionMismatch);
    EXPECT_EQ(std::filesystem::last_write_time(local / "untouched"),
              concurrent_mtime);
    EXPECT_FALSE(std::filesystem::exists(profile / "state.db"));
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_TRUE(std::filesystem::is_empty(profile / ".transactions"));
}

TEST(SyncCoordinatorTest, AffectedParentMetadataIsRestoredAfterDownload) {
    auto workspace =
        kasumi::test::make_temp_workspace("affected-parent-metadata");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local / "docs"));

    const auto hash = kasumi::hasher::hash_string("alpha");
    const auto file_mtime = std::chrono::time_point_cast<std::chrono::seconds>(
        std::filesystem::file_time_type::clock::now() +
        std::chrono::seconds{2});
    std::error_code error;
    const auto actual_root_mtime =
        std::filesystem::last_write_time(local, error);
    ASSERT_FALSE(error);
    const auto actual_docs_mtime =
        std::filesystem::last_write_time(local / "docs", error);
    ASSERT_FALSE(error);

    auto input = empty_publication_input();
    input.local_tree =
        kasumi::Snapshot{.rows = {kasumi::NodeRow{.path = "",
                                                  .mtime = actual_root_mtime,
                                                  .is_directory = true},
                                  kasumi::NodeRow{.path = "docs",
                                                  .mtime = actual_docs_mtime,
                                                  .is_directory = true}}};
    kasumi::finalize_snapshot(input.local_tree);
    input.base_tree = input.local_tree;
    input.storage.tree =
        kasumi::Snapshot{.rows = {kasumi::NodeRow{.path = "",
                                                  .mtime = actual_root_mtime,
                                                  .is_directory = true},
                                  kasumi::NodeRow{.path = "docs",
                                                  .mtime = actual_docs_mtime,
                                                  .is_directory = true},
                                  kasumi::NodeRow{.path = "docs/alpha.txt",
                                                  .hash = hash,
                                                  .size = 5,
                                                  .mtime = file_mtime,
                                                  .is_directory = false}}};
    kasumi::finalize_snapshot(input.storage.tree);
    input.storage.object_identifiers.insert(kasumi::hash_hex(hash));
    add_reachable_head(input);

    const auto source = kasumi::test::workspace_path(workspace, "alpha.txt");
    kasumi::test::write_text(source, "alpha");
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    add_storage_object(*storage, source, hash);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto executed = kasumi::application::sync::coordinator::execute(
        make_runtime(profile, local, storage_path),
        *storage,
        key,
        input,
        *result);
    ASSERT_TRUE(executed.has_value()) << executed.error().detail;
    EXPECT_EQ(std::filesystem::last_write_time(local), actual_root_mtime);
    EXPECT_EQ(std::filesystem::last_write_time(local / "docs"),
              actual_docs_mtime);
    EXPECT_EQ(std::filesystem::last_write_time(local / "docs" / "alpha.txt"),
              file_mtime);
}

TEST(SyncCoordinatorTest, ConcurrentImmutablePublicationsRemainMultipleHeads) {
    auto workspace = kasumi::test::make_temp_workspace("sync-concurrent-heads");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const kasumi::Snapshot root_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    auto branch_tree = [](std::string_view path, std::string_view contents) {
        kasumi::Snapshot tree{
            .rows = {
                kasumi::NodeRow{.path = "", .is_directory = true},
                kasumi::NodeRow{.path = std::string(path),
                                .hash = kasumi::hasher::hash_string(contents),
                                .size = contents.size(),
                                .is_directory = false}}};
        kasumi::finalize_snapshot(tree);
        return tree;
    };
    const auto first_tree = branch_tree("first.txt", "one");
    const auto second_tree = branch_tree("second.txt", "two");
    auto root = kasumi::application::sync::publication::prepare_commit(
        root_tree, false, 0, {}, 100, key);
    ASSERT_TRUE(root.has_value());
    const std::vector<std::string> root_heads{root->commit_id};
    auto first = kasumi::application::sync::publication::prepare_commit(
        first_tree, true, 0, root_heads, 200, key);
    auto second = kasumi::application::sync::publication::prepare_commit(
        second_tree, true, 0, root_heads, 200, key);
    ASSERT_TRUE(first.has_value() && second.has_value());

    const auto publish = [&](const auto& prepared) {
        auto object =
            kasumi::application::sync::publication::publish_commit_object(
                *storage, key, prepared, local);
        EXPECT_TRUE(object.has_value());
        if (!object)
            return;
        EXPECT_TRUE(
            kasumi::application::sync::publication::verify_commit_object(
                *storage, key, prepared, object->head, local));
        auto marker =
            kasumi::application::sync::publication::publish_head_marker(
                *storage, object->head, local);
        EXPECT_TRUE(marker.has_value());
        EXPECT_TRUE(kasumi::application::sync::publication::verify_head_marker(
            *storage, object->head, local));
    };
    publish(*root);
    publish(*first);
    publish(*second);

    const auto observed =
        kasumi::application::observation::collect_storage_state(
            *storage, key, local, false);
    ASSERT_TRUE(observed.has_value());
    std::vector<std::string> heads = observed->logical_heads;
    std::ranges::sort(heads);
    std::vector<std::string> expected{first->commit_id, second->commit_id};
    std::ranges::sort(expected);
    EXPECT_EQ(heads, expected);
    const auto listing = kasumi::transport::list(*storage);
    ASSERT_TRUE(listing.has_value());
    EXPECT_EQ(std::ranges::count_if(*listing,
                                    [](const auto& id) {
                                        return id.starts_with("history/heads/");
                                    }),
              3);
}

TEST(SyncCoordinatorTest, RejectsInvalidCompositionRootInput) {
    kasumi::runtime::RuntimeData runtime_data{};
    kasumi::transport::Transport transport{};
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    kasumi::reconciliation::Input input{};
    kasumi::reconciliation::Result result{
        .plan = kasumi::make_sync_plan({}, 1),
        .missing_objects = kasumi::HashSet{0, kasumi::hash_key},
        .pending_storage_rows = {},
        .unrecoverable_paths = {},
        .observed_storage_generation = 0,
        .target_generation = 1,
        .recovering_missing_history = false,
        .has_conflicts = false,
        .requires_local_mutation = false,
        .requires_storage_repair = false,
        .candidate_shared_tree = {},
        .shared_tree_changed = false,
        .requires_publication = false,
        .requires_state_commit = false,
    };

    const auto execution = kasumi::application::sync::coordinator::execute(
        runtime_data, transport, key, input, result);
    ASSERT_FALSE(execution.has_value());
    EXPECT_EQ(execution.error().code,
              kasumi::application::sync::coordinator::ErrorCode::InvalidInput);
}

TEST(SyncCoordinatorTest, EmptyPlanStillPublishesConvergenceCommit) {
    auto input = empty_publication_input();
    input.storage.history_present = true;
    input.storage.tree = input.local_tree;
    input.storage.generation = 7;
    input.storage.logical_heads = {std::string(64, 'a'), std::string(64, 'b')};

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_TRUE(result->plan.operations.empty());
    EXPECT_EQ(result->target_generation, 8U);
    EXPECT_TRUE(result->requires_publication);
    EXPECT_TRUE(result->requires_state_commit);
}

TEST(ReobservationTest, NormalizesLogicalHeadsAndReachableCommitIds) {
    auto left = empty_publication_input();
    auto right = left;
    left.storage.logical_heads = {"b", "a", "a"};
    right.storage.logical_heads = {"a", "b"};
    left.storage.reachable_commit_ids = {"c", "a", "c"};
    right.storage.reachable_commit_ids = {"a", "c"};

    EXPECT_TRUE(
        kasumi::application::sync::coordinator::reobservation::same_observation(
            left, right));
}

TEST(ReobservationTest, IgnoresDirectoryMetadataButDetectsFileMetadata) {
    auto directory_left = empty_publication_input();
    auto directory_right = directory_left;
    directory_right.local_tree.rows.front().mtime += std::chrono::seconds{1};
    EXPECT_TRUE(
        kasumi::application::sync::coordinator::reobservation::same_observation(
            directory_left, directory_right));

    directory_right.local_tree.rows.push_back(
        kasumi::NodeRow{.path = "file.txt",
                        .mtime = std::filesystem::file_time_type::clock::now(),
                        .is_directory = false});
    kasumi::finalize_snapshot(directory_right.local_tree);
    EXPECT_FALSE(
        kasumi::application::sync::coordinator::reobservation::same_observation(
            directory_left, directory_right));
}

TEST(ReobservationTest, DetectsRemoteHeadChanges) {
    auto left = empty_publication_input();
    auto right = left;
    left.storage.logical_heads = {std::string(64, 'a')};
    right.storage.logical_heads = {std::string(64, 'b')};

    EXPECT_FALSE(
        kasumi::application::sync::coordinator::reobservation::same_observation(
            left, right));
}

TEST(ReobservationTest, DetectsNewCiphertextVariantForTheSameLogicalHead) {
    auto left = empty_publication_input();
    auto right = left;
    left.storage.logical_heads = {std::string(64, 'a')};
    right.storage.logical_heads = left.storage.logical_heads;
    left.storage.marked_head_identifiers = {"history/heads/" +
                                            std::string(64, 'a') + "-" +
                                            std::string(64, 'b') + ".head"};
    right.storage.marked_head_identifiers = {"history/heads/" +
                                             std::string(64, 'a') + "-" +
                                             std::string(64, 'c') + ".head"};

    EXPECT_FALSE(
        kasumi::application::sync::coordinator::reobservation::same_observation(
            left, right));
}

TEST(ReobservationTest, DetectsAuthenticatedEpochPolicyChanges) {
    auto left = empty_publication_input();
    auto right = left;
    left.storage.epoch_vault_id = std::string(64, 'v');
    left.storage.epoch_id = std::string(64, 'e');
    left.storage.epoch_sequence = 3;
    left.storage.epoch_policy = kasumi::reconciliation::EpochRetentionPolicy{
        .min_history_depth = 1, .min_history_age_hours = 6};
    right.storage.epoch_vault_id = left.storage.epoch_vault_id;
    right.storage.epoch_id = left.storage.epoch_id;
    right.storage.epoch_sequence = left.storage.epoch_sequence;
    right.storage.epoch_policy = kasumi::reconciliation::EpochRetentionPolicy{
        .min_history_depth = 5, .min_history_age_hours = 24};

    EXPECT_FALSE(
        kasumi::application::sync::coordinator::reobservation::same_observation(
            left, right));
}

TEST(ReobservationTest, MissingKnownBaseHistoryFailsClosed) {
    auto workspace =
        kasumi::test::make_temp_workspace("missing-known-base-history");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    kasumi::test::write_text(local / "base.txt", "base");
    const auto tree =
        kasumi::application::observation::collect_local_tree(local);
    ASSERT_TRUE(tree.has_value()) << tree.error();
    const auto commit = kasumi::history::make_bootstrap(*tree, 0);
    ASSERT_TRUE(commit.has_value()) << commit.error().detail;
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto id = authenticated_commit_id(key, *commit);
    const auto runtime_data = make_runtime(profile, local, storage_path);
    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        {.tree = *tree,
         .height = 0,
         .commit_id = id,
         .ciphertext_id = std::string(64, 'c')}));
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    const auto observed =
        kasumi::application::observation::collect_reconciliation_input(
            runtime_data, *storage, key, true);

    ASSERT_FALSE(observed.has_value());
    EXPECT_EQ(observed.error().code,
              kasumi::reconciliation::ErrorCode::MissingStorageHistory);
}

TEST(ReobservationTest, AuditStorageObjectsDisablesTrustedMarkerShortcut) {
    auto workspace =
        kasumi::test::make_temp_workspace("audit-revalidates-marker");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    kasumi::test::write_text(local / "base.txt", "base");

    const auto tree =
        kasumi::application::observation::collect_local_tree(local);
    ASSERT_TRUE(tree.has_value()) << tree.error();
    const auto runtime_data = make_runtime(profile, local, storage_path);
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto commit = kasumi::history::make_bootstrap(*tree, 0);
    ASSERT_TRUE(commit.has_value()) << commit.error().detail;
    const auto prepared =
        kasumi::application::sync::publication::prepare_commit(
            *tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared.has_value()) << prepared.error().detail;
    const auto published =
        kasumi::application::sync::publication::publish_commit(
            *storage, key, *prepared, profile);
    ASSERT_TRUE(published.has_value()) << published.error().detail;
    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        {.tree = *tree,
         .height = prepared->commit.height,
         .commit_id = published->head.commit_id,
         .ciphertext_id = published->head.ciphertext_id}));

    const auto marker_id =
        kasumi::application::history_storage::marker_identifier(
            published->head);
    kasumi::test::write_text(storage_path / marker_id,
                             "corrupt marker bytes");

    const auto observed =
        kasumi::application::observation::collect_reconciliation_input(
            runtime_data, *storage, key, true);
    ASSERT_FALSE(observed.has_value());
    EXPECT_EQ(observed.error().code,
              kasumi::reconciliation::ErrorCode::InvalidStorageTree);
}

TEST(ReobservationTest, ObservationOverlapPreservesBranchErrorPrecedence) {
    auto workspace =
        kasumi::test::make_temp_workspace("observation-overlap-errors");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    auto missing_local =
        make_runtime(profile,
                     kasumi::test::workspace_path(workspace, "missing-local"),
                     storage_path);
    const auto local_failure =
        kasumi::application::observation::collect_reconciliation_input(
            missing_local, *storage, key, false);
    ASSERT_FALSE(local_failure.has_value());
    EXPECT_EQ(local_failure.error().code,
              kasumi::reconciliation::ErrorCode::InvalidLocalTree);

    kasumi::transport::Transport unavailable{};
    const auto runtime_data = make_runtime(profile, local, storage_path);
    const auto remote_failure =
        kasumi::application::observation::collect_reconciliation_input(
            runtime_data, unavailable, key, false);
    ASSERT_FALSE(remote_failure.has_value());
    EXPECT_EQ(remote_failure.error().code,
              kasumi::reconciliation::ErrorCode::InvalidStorageTree);

    const auto both_fail =
        kasumi::application::observation::collect_reconciliation_input(
            missing_local, unavailable, key, false);
    ASSERT_FALSE(both_fail.has_value());
    EXPECT_EQ(both_fail.error().code,
              kasumi::reconciliation::ErrorCode::InvalidLocalTree);
}

TEST(ReobservationTest, KnownBaseNoLongerReachableFailsClosed) {
    auto workspace =
        kasumi::test::make_temp_workspace("unreachable-known-base");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    kasumi::test::write_text(local / "base.txt", "base");
    const auto tree =
        kasumi::application::observation::collect_local_tree(local);
    ASSERT_TRUE(tree.has_value()) << tree.error();
    const auto base = kasumi::history::make_bootstrap(*tree, 0);
    ASSERT_TRUE(base.has_value()) << base.error().detail;
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto base_id = authenticated_commit_id(key, *base);
    const auto unrelated = kasumi::history::make_empty_bootstrap();
    ASSERT_TRUE(unrelated.has_value()) << unrelated.error().detail;
    const auto runtime_data = make_runtime(profile, local, storage_path);
    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        {.tree = *tree,
         .height = 0,
         .commit_id = base_id,
         .ciphertext_id = std::string(64, 'c')}));
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    ASSERT_TRUE(kasumi::application::history_storage::publish_commit(
        *storage, key, *base, profile));
    ASSERT_TRUE(kasumi::application::history_storage::publish_commit(
        *storage, key, *unrelated, profile));
    const std::vector<std::string> old_head{base_id};
    ASSERT_TRUE(kasumi::application::history_storage::remove_marker_variants(
        *storage, old_head));

    const auto observed =
        kasumi::application::observation::collect_reconciliation_input(
            runtime_data, *storage, key, true);

    ASSERT_FALSE(observed.has_value());
    EXPECT_EQ(observed.error().code,
              kasumi::reconciliation::ErrorCode::StorageHistoryRegression);
}

TEST(ReobservationTest, StableFirstAttemptDoesNotCreateJournal) {
    auto workspace = kasumi::test::make_temp_workspace("reobservation-stable");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "storage").string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    const kasumi::runtime::RuntimeData runtime_data{
        .local_dir = local,
        .database_path = profile / "state.db",
        .key_path = profile / "key.bin",
        .storage_location =
            kasumi::test::workspace_path(workspace, "storage").string()};
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto input = empty_publication_input();
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;

    const auto stable =
        kasumi::application::sync::coordinator::reobservation::stabilize(
            runtime_data, storage, key, input, *result);
    ASSERT_TRUE(stable.has_value()) << stable.error().detail;
    EXPECT_EQ(stable->input.storage.logical_heads, input.storage.logical_heads);
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_TRUE(!std::filesystem::exists(profile / ".transactions") ||
                std::filesystem::is_empty(profile / ".transactions"));
}

TEST(ReobservationTest, ChangedSyncReobservesScopedHistory) {
    auto workspace =
        kasumi::test::make_temp_workspace("two-inventory-listings");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    kasumi::test::write_text(local / "file.txt", "contents");
    auto base = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "storage").string());
    ASSERT_TRUE(base.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*base));
    ReobserveTransportState state{};
    state.base = &*base;
    auto storage = make_reobserve_transport(state);
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    auto observed =
        kasumi::application::observation::collect_reconciliation_input(
            runtime_data, storage, key, false);
    ASSERT_TRUE(observed.has_value()) << observed.error().detail;
    auto result = kasumi::reconciliation::reconcile(*observed);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_TRUE(result->requires_publication);
    auto stable =
        kasumi::application::sync::coordinator::reobservation::stabilize(
            runtime_data, storage, key, *observed, *result);

    ASSERT_TRUE(stable.has_value()) << stable.error().detail;
    EXPECT_EQ(state.list_count, 4);
}

TEST(ReobservationTest,
     NormalSyncRequestsStayConstantAcrossTrustedContentCounts) {
    std::optional<std::size_t> no_op_requests;
    for (const std::size_t content_count : {1U, 10U, 100U, 1000U}) {
        SCOPED_TRACE(content_count);
        auto workspace = kasumi::test::make_temp_workspace(
            "trusted-content-count-" + std::to_string(content_count));
        const auto profile = kasumi::test::workspace_path(workspace, "profile");
        const auto local = kasumi::test::workspace_path(workspace, "local");
        const auto storage_path =
            kasumi::test::workspace_path(workspace, "storage");
        ASSERT_TRUE(std::filesystem::create_directories(profile));
        ASSERT_TRUE(std::filesystem::create_directories(local));
        for (std::size_t index = 0; index < content_count; ++index) {
            kasumi::test::write_text(
                local / ("file-" + std::to_string(index) + ".txt"),
                std::to_string(index));
        }

        const auto tree =
            kasumi::application::observation::collect_local_tree(local);
        ASSERT_TRUE(tree.has_value()) << tree.error();
        const auto commit = kasumi::history::make_bootstrap(*tree, 0);
        ASSERT_TRUE(commit.has_value()) << commit.error().detail;
        const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
        const auto commit_id = authenticated_commit_id(key, *commit);
        auto base = kasumi::transport::open_transport(storage_path.string());
        ASSERT_TRUE(base.has_value());
        ASSERT_TRUE(kasumi::transport::initialize(*base));
        const auto published =
            kasumi::application::history_storage::publish_commit(
                *base, key, *commit, profile);
        ASSERT_TRUE(published.has_value()) << published.error().detail;
        const auto runtime_data = make_runtime(profile, local, storage_path);
        ASSERT_TRUE(
            kasumi::state_storage::initialize(runtime_data.database_path));
        ASSERT_TRUE(kasumi::state_storage::save_state(
            runtime_data.database_path,
            {.tree = *tree,
             .height = 0,
             .commit_id = commit_id,
             .ciphertext_id = published->head.ciphertext_id}));

        ReobserveTransportState state{};
        state.base = &*base;
        state.storage_root = storage_path;
        auto storage = make_reobserve_transport(state);
        const auto request_count = [&] {
            return state.initialize_count + state.put_count + state.get_count +
                   state.presence_count + state.list_count +
                   state.physical_hash_count + state.remove_count;
        };
        const auto reset_counts = [&] {
            state.initialize_count = 0;
            state.put_count = 0;
            state.get_count = 0;
            state.presence_count = 0;
            state.list_count = 0;
            state.full_list_count = 0;
            state.prefix_list_count = 0;
            state.physical_hash_count = 0;
            state.remove_count = 0;
            state.marker_get_count = 0;
            state.commit_get_count = 0;
            state.listed_prefixes.clear();
            state.events.clear();
            state.request_events.clear();
            state.local_change_observed = false;
            state.local_change_overlap_timed_out = false;
        };

        bool local_change_observed = false;
        auto observed =
            kasumi::application::observation::collect_reconciliation_input(
                runtime_data, storage, key, false, {}, nullptr, [&] {
                    local_change_observed = true;
                });
        ASSERT_TRUE(observed.has_value()) << observed.error().detail;
        EXPECT_FALSE(local_change_observed);
        auto result = kasumi::reconciliation::reconcile(*observed);
        ASSERT_TRUE(result.has_value()) << result.error().detail;
        auto stable =
            kasumi::application::sync::coordinator::reobservation::stabilize(
                runtime_data, storage, key, *observed, *result);
        ASSERT_TRUE(stable.has_value()) << stable.error().detail;
        EXPECT_EQ(state.presence_count, 0U);
        EXPECT_EQ(state.full_list_count, 0U);
        EXPECT_EQ(state.request_events,
                  (std::vector<std::string>{"LIST history/heads",
                                            "LIST history/epochs/v1"}));
        EXPECT_EQ(state.list_count, 2U);
        EXPECT_EQ(state.prefix_list_count, 2U);
        EXPECT_EQ(state.get_count, 0U);
        EXPECT_EQ(state.put_count, 0U);
        EXPECT_EQ(state.physical_hash_count, 0U);
        EXPECT_EQ(state.remove_count, 0U);
        RecordProperty("noop_" + std::to_string(content_count) + "_requests",
                       request_count());
        if (no_op_requests) {
            EXPECT_EQ(request_count(), *no_op_requests);
        } else {
            no_op_requests = request_count();
        }

        if (content_count != 1000U) {
            continue;
        }

        reset_counts();
        kasumi::test::write_text(local / "new.txt", "new");
        state.require_local_change_overlap = true;
        observed =
            kasumi::application::observation::collect_reconciliation_input(
                runtime_data, storage, key, false, {}, nullptr, [&] {
                    std::lock_guard lock(state.mutex);
                    state.local_change_observed = true;
                    state.condition.notify_all();
                });
        ASSERT_TRUE(observed.has_value()) << observed.error().detail;
        EXPECT_TRUE(state.local_change_observed);
        EXPECT_FALSE(state.local_change_overlap_timed_out);
        result = kasumi::reconciliation::reconcile(*observed);
        ASSERT_TRUE(result.has_value()) << result.error().detail;
        ASSERT_TRUE(result->requires_publication);
        stable =
            kasumi::application::sync::coordinator::reobservation::stabilize(
                runtime_data, storage, key, *observed, *result);
        ASSERT_TRUE(stable.has_value()) << stable.error().detail;
        ASSERT_TRUE(kasumi::application::sync::coordinator::execute(
            runtime_data, storage, key, stable->input, stable->result));
        EXPECT_EQ(state.presence_count, 0U);
        EXPECT_EQ(state.full_list_count, 0U);
        EXPECT_EQ(state.initialize_count, 0U);
        EXPECT_EQ(state.prefix_list_count, 4U);
        EXPECT_EQ(state.listed_prefixes,
                  (std::vector<std::string>{"history/heads",
                                            "history/epochs/v1",
                                            "history/heads",
                                            "history/epochs/v1"}));
        EXPECT_EQ(state.get_count, 0U);
        EXPECT_EQ(state.marker_get_count, 0U);
        EXPECT_EQ(state.commit_get_count, 0U);
        EXPECT_EQ(state.put_count, 3U);
        EXPECT_EQ(state.physical_hash_count, 3U);
        EXPECT_EQ(state.remove_count, 1U);
        for (const auto event : {"content PUT",
                                 "content verified",
                                 "commit PUT",
                                 "commit verified",
                                 "head PUT",
                                 "head verified",
                                 "parent marker DELETE"}) {
            EXPECT_EQ(std::ranges::count(state.events, event), 1) << event;
        }
        ASSERT_EQ(state.request_events.size(), 11U);
        EXPECT_EQ(state.request_events[0], "LIST history/heads");
        EXPECT_EQ(state.request_events[1], "LIST history/epochs/v1");
        EXPECT_EQ(state.request_events[2], "LIST history/heads");
        EXPECT_EQ(state.request_events[3], "LIST history/epochs/v1");
        const auto request_index = [&](const auto& predicate) {
            const auto found =
                std::ranges::find_if(state.request_events, predicate);
            EXPECT_NE(found, state.request_events.end());
            return static_cast<std::size_t>(
                std::ranges::distance(state.request_events.begin(), found));
        };
        const auto content_put = request_index([](std::string_view event) {
            return event.starts_with("PUT ") &&
                   !event.starts_with("PUT history/");
        });
        const auto content_hash = request_index([](std::string_view event) {
            return event.starts_with("HASH ") &&
                   !event.starts_with("HASH history/");
        });
        const auto commit_put = request_index([](std::string_view event) {
            return event.starts_with("PUT history/commits/");
        });
        const auto commit_hash = request_index([](std::string_view event) {
            return event.starts_with("HASH history/commits/");
        });
        const auto head_put = request_index([](std::string_view event) {
            return event.starts_with("PUT history/heads/");
        });
        const auto head_hash = request_index([](std::string_view event) {
            return event.starts_with("HASH history/heads/");
        });
        const auto cleanup = request_index([](std::string_view event) {
            return event.starts_with("DELETE history/heads/");
        });
        EXPECT_LT(content_put, content_hash);
        EXPECT_LT(commit_put, commit_hash);
        EXPECT_LT(content_hash, head_put);
        EXPECT_LT(commit_hash, head_put);
        EXPECT_LT(head_put, head_hash);
        EXPECT_LT(head_hash, cleanup);
        RecordProperty("incremental_1000_plus_1_requests", request_count());
        EXPECT_EQ(request_count(), 11U);
        // A trusted NOOP performs exactly the two control-plane prefix LISTs
        // used to observe heads and Epochs; neither operation scales with the
        // number of content objects.
        EXPECT_EQ(no_op_requests, 2U);
    }
}

TEST(ReobservationTest, LocalChangeRetriesAndUsesTheStableObservation) {
    auto workspace = kasumi::test::make_temp_workspace("reobservation-retry");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto local_file = local / "file.txt";
    kasumi::test::write_text(local_file, "0");

    auto base = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "storage").string());
    ASSERT_TRUE(base.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*base));
    ReobserveTransportState state{};
    state.base = &*base;
    state.local_file = local_file;
    auto storage = make_reobserve_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    const kasumi::runtime::RuntimeData runtime_data{
        .local_dir = local,
        .database_path = profile / "state.db",
        .key_path = profile / "key.bin",
        .storage_location =
            kasumi::test::workspace_path(workspace, "storage").string()};
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    auto observed =
        kasumi::application::observation::collect_reconciliation_input(
            runtime_data, storage, key, false);
    ASSERT_TRUE(observed.has_value());
    auto result = kasumi::reconciliation::reconcile(*observed);
    ASSERT_TRUE(result.has_value() && result->requires_publication);

    state.remaining_mutations = 1;
    const auto stable =
        kasumi::application::sync::coordinator::reobservation::stabilize(
            runtime_data, storage, key, *observed, *result);
    ASSERT_TRUE(stable.has_value()) << stable.error().detail;
    EXPECT_EQ(stable->input.local_tree.rows.back().hash,
              kasumi::hasher::hash_string("1"));
    EXPECT_TRUE(stable->result.requires_publication);
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    const auto listing = kasumi::transport::list(storage);
    ASSERT_TRUE(listing.has_value());
    EXPECT_TRUE(listing->empty());
}

TEST(ReobservationTest, RepeatedLocalChangesExhaustThreeAttempts) {
    auto workspace =
        kasumi::test::make_temp_workspace("reobservation-unstable");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto local_file = local / "file.txt";
    kasumi::test::write_text(local_file, "0");

    auto base = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "storage").string());
    ASSERT_TRUE(base.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*base));
    ReobserveTransportState state{};
    state.base = &*base;
    state.local_file = local_file;
    auto storage = make_reobserve_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    const kasumi::runtime::RuntimeData runtime_data{
        .local_dir = local,
        .database_path = profile / "state.db",
        .key_path = profile / "key.bin",
        .storage_location =
            kasumi::test::workspace_path(workspace, "storage").string()};
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    auto observed =
        kasumi::application::observation::collect_reconciliation_input(
            runtime_data, storage, key, false);
    ASSERT_TRUE(observed.has_value());
    auto result = kasumi::reconciliation::reconcile(*observed);
    ASSERT_TRUE(result.has_value() && result->requires_publication);

    state.remaining_mutations = 6;
    const auto stable =
        kasumi::application::sync::coordinator::reobservation::stabilize(
            runtime_data, storage, key, *observed, *result);
    ASSERT_FALSE(stable.has_value());
    EXPECT_EQ(stable.error().code,
              kasumi::application::sync::coordinator::ErrorCode::
                  ConcurrentModification);
    EXPECT_NE(stable.error().detail.find("repetidamente"), std::string::npos);
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    const auto listing = kasumi::transport::list(storage);
    ASSERT_TRUE(listing.has_value());
    EXPECT_TRUE(listing->empty());
}

TEST(SyncCoordinatorTest, StateOnlyPlanDoesNotPublishOrPrune) {
    auto input = empty_publication_input();
    input.storage.history_present = true;
    input.storage.tree = input.local_tree;
    input.storage.generation = 7;
    input.storage.logical_heads = {std::string(64, 'a')};

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_TRUE(result->plan.operations.empty());
    EXPECT_FALSE(result->requires_publication);
    EXPECT_TRUE(result->requires_state_commit);
}

TEST(SyncCoordinatorTest, StateOnlyPlanRestoresObservedRemoteRootMtime) {
    auto workspace = kasumi::test::make_temp_workspace("state-only-root-mtime");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    std::error_code error;
    const auto local_mtime = std::filesystem::last_write_time(local, error);
    ASSERT_FALSE(error);
    const auto remote_mtime =
        std::chrono::time_point_cast<std::chrono::seconds>(
            std::filesystem::file_time_type::clock::now() -
            std::chrono::hours{1});

    auto input = empty_publication_input();
    input.local_tree.rows.front().mtime = local_mtime;
    input.storage.tree = input.local_tree;
    input.storage.tree.rows.front().mtime = remote_mtime;
    add_reachable_head(input);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_TRUE(result->plan.operations.empty());
    ASSERT_FALSE(result->requires_publication);
    ASSERT_TRUE(result->requires_state_commit);

    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto executed = kasumi::application::sync::coordinator::execute(
        make_runtime(profile, local, storage_path),
        *storage,
        key,
        input,
        *result);

    ASSERT_TRUE(executed.has_value()) << executed.error().detail;
    EXPECT_EQ(std::filesystem::last_write_time(local, error), remote_mtime);
    EXPECT_FALSE(error);
}

TEST(SyncCoordinatorTest,
     StateOnlyPlanDoesNotMaskDirectoryChangeAfterObservation) {
    auto workspace =
        kasumi::test::make_temp_workspace("state-only-concurrent-mtime");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    std::error_code error;
    const auto local_mtime = std::filesystem::last_write_time(local, error);
    ASSERT_FALSE(error);

    auto input = empty_publication_input();
    input.local_tree.rows.front().mtime = local_mtime;
    input.storage.tree = input.local_tree;
    input.storage.tree.rows.front().mtime = local_mtime - std::chrono::hours{1};
    add_reachable_head(input);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_FALSE(result->requires_publication);
    ASSERT_TRUE(result->requires_state_commit);

    const auto changed = kasumi::platform::metadata::set_last_write_time(
        local, local_mtime + std::chrono::hours{1});
    ASSERT_TRUE(changed.has_value()) << changed.error();
    const auto changed_mtime = std::filesystem::last_write_time(local, error);
    ASSERT_FALSE(error);
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto executed = kasumi::application::sync::coordinator::execute(
        make_runtime(profile, local, storage_path),
        *storage,
        key,
        input,
        *result);

    ASSERT_FALSE(executed.has_value());
    EXPECT_EQ(executed.error().code,
              kasumi::application::sync::coordinator::ErrorCode::
                  ConcurrentModification);
    EXPECT_EQ(std::filesystem::last_write_time(local, error), changed_mtime);
    EXPECT_FALSE(error);
    EXPECT_FALSE(std::filesystem::exists(profile / "state.db"));
}

TEST(SyncCoordinatorTest, LocalOnlyDatabaseFailureRollsBackAppliedDownload) {
    auto workspace =
        kasumi::test::make_temp_workspace("local-only-database-failure");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto runtime_data = make_runtime(profile, local, storage_path);
    ASSERT_TRUE(
        std::filesystem::create_directories(runtime_data.database_path));
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    auto input = empty_publication_input();
    const auto directory_mtime =
        std::chrono::time_point_cast<std::chrono::seconds>(
            std::filesystem::file_time_type::clock::now() -
            std::chrono::hours{1});
    input.local_tree.rows.front().mtime = directory_mtime;
    input.storage.history_present = true;
    input.storage.logical_heads = {std::string(64, 'a')};
    input.storage.tree = input.local_tree;
    input.storage.tree.rows.push_back(kasumi::NodeRow{
        .path = "remote-dir", .mtime = directory_mtime, .is_directory = true});
    kasumi::finalize_snapshot(input.storage.tree);
    input.base_tree = input.local_tree;
    input.storage.reachable_commits = {kasumi::history::LoadedCommit{
        .id = std::string(64, 'a'),
        .commit = kasumi::history::Commit{
            .height = 0, .parents = {}, .tree = input.storage.tree}}};
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_FALSE(result->requires_publication);
    ASSERT_TRUE(result->requires_local_mutation);

    const auto executed = kasumi::application::sync::coordinator::execute(
        runtime_data, *storage, key, input, *result);
    ASSERT_FALSE(executed.has_value());
    EXPECT_EQ(
        executed.error().code,
        kasumi::application::sync::coordinator::ErrorCode::DatabaseFailure)
        << executed.error().detail;
    EXPECT_FALSE(std::filesystem::exists(local / "remote-dir"));
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_TRUE(std::filesystem::is_empty(profile / ".transactions"));
    const auto listing = kasumi::transport::list(*storage);
    ASSERT_TRUE(listing.has_value());
    EXPECT_EQ(std::ranges::count_if(*listing,
                                    [](const auto& id) {
                                        return id.starts_with("history/");
                                    }),
              0);
}

TEST(SyncCoordinatorTest,
     SaveStateFailureRollsBackAbsentAndExistingDownloadedFiles) {
    for (const bool originally_exists : {false, true}) {
        SCOPED_TRACE(originally_exists ? "existing" : "absent");
        auto workspace =
            kasumi::test::make_temp_workspace("local-only-file-rollback");
        const auto profile = kasumi::test::workspace_path(workspace, "profile");
        const auto local = kasumi::test::workspace_path(workspace, "local");
        const auto storage_path =
            kasumi::test::workspace_path(workspace, "storage");
        ASSERT_TRUE(std::filesystem::create_directories(profile));
        ASSERT_TRUE(std::filesystem::create_directories(local));
        const auto remote_directory = local / "remote";
        const auto local_file = remote_directory / "alpha.txt";
        const auto runtime_data = make_runtime(profile, local, storage_path);
        const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

        auto old_mtime = std::filesystem::file_time_type::clock::now() -
                         std::chrono::hours{2};
        const auto remote_mtime =
            std::chrono::time_point_cast<std::chrono::seconds>(
                std::filesystem::file_time_type::clock::now() -
                std::chrono::hours{1});
        if (originally_exists) {
            ASSERT_TRUE(std::filesystem::create_directories(remote_directory));
            kasumi::test::write_text(local_file, "old");
            std::error_code mtime_error;
            std::filesystem::last_write_time(
                local_file, old_mtime, mtime_error);
            ASSERT_FALSE(mtime_error);
            old_mtime =
                std::filesystem::last_write_time(local_file, mtime_error);
            ASSERT_FALSE(mtime_error);
        }

        auto storage = kasumi::transport::open_transport(storage_path.string());
        ASSERT_TRUE(storage.has_value());
        ASSERT_TRUE(kasumi::transport::initialize(*storage));
        const auto content_id =
            kasumi::hash_hex(kasumi::hasher::hash_string("remote"));
        const auto source =
            kasumi::test::workspace_path(workspace, "remote-source");
        const auto encrypted =
            kasumi::test::workspace_path(workspace, "remote-source.enc");
        kasumi::test::write_text(source, "remote");
        ASSERT_TRUE(kasumi::crypto::encrypt_file(source, encrypted, key));
        ASSERT_TRUE(kasumi::transport::put(
            *storage, encrypted, remote_content_id(key, content_id)));

        const auto directory_mtime =
            std::chrono::time_point_cast<std::chrono::seconds>(
                std::filesystem::file_time_type::clock::now() -
                std::chrono::hours{3});
        kasumi::Snapshot local_tree{
            .rows = {kasumi::NodeRow{
                .path = "", .mtime = directory_mtime, .is_directory = true}}};
        if (originally_exists) {
            local_tree.rows.push_back(kasumi::NodeRow{.path = "remote",
                                                      .mtime = directory_mtime,
                                                      .is_directory = true});
            local_tree.rows.push_back(
                kasumi::NodeRow{.path = "remote/alpha.txt",
                                .hash = kasumi::hasher::hash_string("old"),
                                .size = 3,
                                .mtime = old_mtime,
                                .is_directory = false});
        }
        kasumi::finalize_snapshot(local_tree);

        kasumi::Snapshot remote_tree{
            .rows = {
                kasumi::NodeRow{
                    .path = "", .mtime = directory_mtime, .is_directory = true},
                kasumi::NodeRow{.path = "remote",
                                .mtime = directory_mtime,
                                .is_directory = true},
                kasumi::NodeRow{.path = "remote/alpha.txt",
                                .hash = kasumi::hasher::hash_string("remote"),
                                .size = 6,
                                .mtime = remote_mtime,
                                .is_directory = false}}};
        kasumi::finalize_snapshot(remote_tree);

        auto input = empty_publication_input();
        input.local_tree = local_tree;
        input.base_tree = local_tree;
        input.storage.history_present = true;
        input.storage.tree = remote_tree;
        input.storage.logical_heads = {std::string(64, 'a')};
        input.storage.reachable_commits = {kasumi::history::LoadedCommit{
            .id = std::string(64, 'a'),
            .commit = kasumi::history::Commit{
                .height = 0, .parents = {}, .tree = remote_tree}}};
        const auto result = kasumi::reconciliation::reconcile(input);
        ASSERT_TRUE(result.has_value()) << result.error().detail;
        ASSERT_FALSE(result->requires_publication);

        ASSERT_TRUE(
            kasumi::state_storage::initialize(runtime_data.database_path));
        sqlite3* database = nullptr;
        ASSERT_EQ(sqlite3_open(runtime_data.database_path.string().c_str(),
                               &database),
                  SQLITE_OK);
        char* sqlite_error = nullptr;
        ASSERT_EQ(
            sqlite3_exec(
                database,
                "CREATE TRIGGER fail_state_write BEFORE INSERT ON nodes "
                "BEGIN SELECT RAISE(ABORT, 'injected state failure'); END;",
                nullptr,
                nullptr,
                &sqlite_error),
            SQLITE_OK)
            << (sqlite_error == nullptr ? "" : sqlite_error);
        sqlite3_free(sqlite_error);
        ASSERT_EQ(sqlite3_close(database), SQLITE_OK);

        const auto executed = kasumi::application::sync::coordinator::execute(
            runtime_data, *storage, key, input, *result);
        ASSERT_FALSE(executed.has_value());
        EXPECT_EQ(
            executed.error().code,
            kasumi::application::sync::coordinator::ErrorCode::DatabaseFailure)
            << executed.error().detail;
        if (originally_exists) {
            EXPECT_TRUE(std::filesystem::is_regular_file(local_file));
            EXPECT_EQ(kasumi::test::read_text(local_file), "old");
            std::error_code mtime_error;
            const auto restored_mtime =
                std::filesystem::last_write_time(local_file, mtime_error);
            ASSERT_FALSE(mtime_error);
            EXPECT_EQ(restored_mtime, old_mtime);
        } else {
            EXPECT_FALSE(std::filesystem::exists(local_file));
            EXPECT_FALSE(std::filesystem::exists(remote_directory));
        }
        auto state =
            kasumi::state_storage::load_state(runtime_data.database_path);
        ASSERT_TRUE(state.has_value());
        EXPECT_FALSE(state->has_value());
        EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
        EXPECT_TRUE(std::filesystem::is_empty(profile / ".transactions"));
        const auto listing = kasumi::transport::list(*storage);
        ASSERT_TRUE(listing.has_value());
        EXPECT_EQ(std::ranges::count_if(*listing,
                                        [](const auto& id) {
                                            return id.starts_with("history/");
                                        }),
                  0);
    }
}

TEST(SyncCoordinatorTest,
     UploadRepairRejectsEveryCorruptionAfterSuccessfulPut) {
    using Corruption = AmbiguousPublicationState::UploadCorruption;
    const std::array corruptions{
        Corruption::Truncated,
        Corruption::Altered,
        Corruption::OtherContent,
        Corruption::TooLarge,
        Corruption::MissingOnGet,
        Corruption::DecryptFailure,
        Corruption::PlaintextSizeMismatch,
    };
    const auto expected_hash =
        kasumi::hash_hex(kasumi::hasher::hash_string("alpha"));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    for (const auto corruption : corruptions) {
        SCOPED_TRACE(static_cast<int>(corruption));
        auto workspace =
            kasumi::test::make_temp_workspace("upload-repair-corruption");
        const auto local = kasumi::test::workspace_path(workspace, "local");
        const auto transaction =
            kasumi::test::workspace_path(workspace, "transaction");
        ASSERT_TRUE(std::filesystem::create_directories(local));
        ASSERT_TRUE(std::filesystem::create_directories(transaction));
        kasumi::test::write_text(local / "alpha.txt", "alpha");

        AmbiguousPublicationState* state = nullptr;
        auto storage = make_ambiguous_transport(state);
        ASSERT_TRUE(kasumi::transport::initialize(storage));
        state->upload_corruption = corruption;
        state->claim_present_after_upload = true;

        if (corruption == Corruption::OtherContent ||
            corruption == Corruption::PlaintextSizeMismatch) {
            const auto other = kasumi::test::workspace_path(workspace, "other");
            const auto encrypted =
                kasumi::test::workspace_path(workspace, "other.enc");
            kasumi::test::write_text(other,
                                     corruption == Corruption::OtherContent
                                         ? "bravo"
                                         : "other-content");
            ASSERT_TRUE(kasumi::crypto::encrypt_file(other, encrypted, key));
            std::ifstream input(encrypted, std::ios::binary | std::ios::ate);
            ASSERT_TRUE(input);
            const auto size = input.tellg();
            ASSERT_GE(size, std::streampos{0});
            state->replacement_object.resize(static_cast<std::size_t>(size));
            input.seekg(0, std::ios::beg);
            input.read(
                reinterpret_cast<char*>(state->replacement_object.data()),
                static_cast<std::streamsize>(state->replacement_object.size()));
            ASSERT_TRUE(input || state->replacement_object.empty());
        }

        const kasumi::Operation operation{.action = kasumi::Action::Upload,
                                          .path = "alpha.txt",
                                          .hash = expected_hash,
                                          .alt_path = {},
                                          .size = 5};
        const kasumi::platform::Workspace tx{.root = transaction};
        const auto applied =
            kasumi::application::sync::mutation::apply_operation(
                operation, 0, local, storage, key, tx);
        EXPECT_FALSE(applied.has_value());
        EXPECT_EQ(kasumi::transport::presence(
                      storage, remote_content_id(key, expected_hash))
                      .value(),
                  kasumi::transport::Presence::Present);
        EXPECT_EQ(state->put_count, 1U);
        EXPECT_EQ(state->get_count, 1U);
        EXPECT_FALSE(
            std::filesystem::exists(transaction / "0.upload.verify.enc"));
        EXPECT_FALSE(
            std::filesystem::exists(transaction / "0.upload.verify.plain"));
    }
}

TEST(SyncCoordinatorTest, AmbiguousContentPutRollsForwardFromVerifiedEffect) {
    auto workspace = kasumi::test::make_temp_workspace("ambiguous-content-put");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    kasumi::test::write_text(local / "alpha.txt", "alpha");
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));

    auto input = empty_publication_input();
    input.local_tree.rows.push_back(kasumi::NodeRow{
        .path = "alpha.txt",
        .hash = kasumi::hasher::hash_string("alpha"),
        .size = 5,
        .mtime = std::filesystem::last_write_time(local / "alpha.txt"),
        .is_directory = false});
    input.local_tree.rows.front().mtime =
        std::filesystem::last_write_time(local);
    kasumi::finalize_snapshot(input.local_tree);
    input.base_tree = input.storage.tree;
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;

    AmbiguousPublicationState* state = nullptr;
    auto storage = make_ambiguous_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    state->fail_content_put_after_store = true;
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto executed = kasumi::application::sync::coordinator::execute(
        runtime_data, storage, key, input, *result);

    ASSERT_TRUE(executed.has_value()) << executed.error().detail;
    EXPECT_EQ(state->put_count, 4U);
    EXPECT_FALSE(state->fail_content_put_after_store);
    EXPECT_TRUE(std::filesystem::exists(runtime_data.database_path));
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_TRUE(std::filesystem::is_empty(profile / ".transactions"));
}

TEST(SyncCoordinatorTest, UnknownContentPutEffectPreservesJournalForRecovery) {
    auto workspace = kasumi::test::make_temp_workspace("unknown-content-put");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    kasumi::test::write_text(local / "alpha.txt", "alpha");
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));

    auto input = empty_publication_input();
    input.local_tree.rows.push_back(kasumi::NodeRow{
        .path = "alpha.txt",
        .hash = kasumi::hasher::hash_string("alpha"),
        .size = 5,
        .mtime = std::filesystem::last_write_time(local / "alpha.txt"),
        .is_directory = false});
    input.local_tree.rows.front().mtime =
        std::filesystem::last_write_time(local);
    kasumi::finalize_snapshot(input.local_tree);
    input.base_tree = input.storage.tree;
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;

    AmbiguousPublicationState* state = nullptr;
    auto storage = make_ambiguous_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    state->fail_content_put_after_store = true;
    state->fail_content_get = true;
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto executed = kasumi::application::sync::coordinator::execute(
        runtime_data, storage, key, input, *result);

    ASSERT_FALSE(executed.has_value());
    const auto paths = kasumi::application::sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    const auto pending = kasumi::application::sync::journal::load(*paths, key);
    ASSERT_TRUE(pending.has_value() && pending->has_value());
    EXPECT_TRUE(std::filesystem::exists(profile / ".transactions" /
                                        (*pending)->operation_id));

    state->fail_content_get = false;
    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, storage, key);
    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
    EXPECT_EQ(
        *recovered,
        kasumi::application::sync::coordinator::RecoveryResult::RolledBack);
    EXPECT_FALSE(std::filesystem::exists(paths->final_path));
}

TEST(SyncCoordinatorTest,
     CorruptUploadLeavesOnlyUnreachableCommitAndDoesNotAdvanceState) {
    auto workspace =
        kasumi::test::make_temp_workspace("corrupt-upload-publication");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    kasumi::test::write_text(local / "alpha.txt", "alpha");

    auto input = empty_publication_input();
    input.local_tree.rows.push_back(
        kasumi::NodeRow{.path = "alpha.txt",
                        .hash = kasumi::hasher::hash_string("alpha"),
                        .size = 5,
                        .is_directory = false});
    kasumi::finalize_snapshot(input.local_tree);
    input.base_tree = input.storage.tree;
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_TRUE(result->requires_publication);

    AmbiguousPublicationState* state = nullptr;
    auto storage = make_ambiguous_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    state->upload_corruption =
        AmbiguousPublicationState::UploadCorruption::Truncated;
    state->claim_present_after_upload = true;

    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto executed = kasumi::application::sync::coordinator::execute(
        runtime_data, storage, key, input, *result);
    ASSERT_FALSE(executed.has_value());
    EXPECT_EQ(
        executed.error().code,
        kasumi::application::sync::coordinator::ErrorCode::MutationFailure);
    EXPECT_EQ(state->put_count, 2U);
    EXPECT_EQ(state->get_count, 2U);
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    const auto listing = kasumi::transport::list(storage);
    ASSERT_TRUE(listing.has_value());
    EXPECT_EQ(std::ranges::count_if(*listing,
                                    [](const auto& id) {
                                        return id.starts_with(
                                            "history/commits/");
                                    }),
              1);
    EXPECT_TRUE(std::ranges::none_of(*listing, [](const auto& id) {
        return id.starts_with("history/heads/");
    }));
}

TEST(SyncCoordinatorTest, StablePublicationPerformsNoListOrPresence) {
    auto workspace =
        kasumi::test::make_temp_workspace("stable-publication-inventory");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    kasumi::test::write_text(local / "alpha.txt", "alpha");
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));

    auto input = empty_publication_input();
    const auto local_tree =
        kasumi::application::observation::collect_local_tree(local);
    ASSERT_TRUE(local_tree.has_value()) << local_tree.error();
    input.local_tree = *local_tree;
    input.base_tree = input.storage.tree;
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_TRUE(result->requires_publication);

    AmbiguousPublicationState* state = nullptr;
    auto storage = make_ambiguous_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto executed = kasumi::application::sync::coordinator::execute(
        runtime_data, storage, key, input, *result);

    ASSERT_TRUE(executed.has_value()) << executed.error().detail;
    EXPECT_EQ(state->list_count, 0);
    EXPECT_EQ(state->presence_count, 0);
    EXPECT_EQ(state->remove_count, 0);
}

TEST(SyncCoordinatorTest, ObservedParentCleanupPreservesConcurrentHeads) {
    AmbiguousPublicationState* state = nullptr;
    auto storage = make_ambiguous_transport(state);
    const kasumi::application::history_storage::HeadReference parent{
        .commit_id = std::string(64, 'a'),
        .ciphertext_id = std::string(64, 'b')};
    const kasumi::application::history_storage::HeadReference concurrent{
        .commit_id = parent.commit_id, .ciphertext_id = std::string(64, 'd')};
    const kasumi::application::history_storage::HeadReference ancestral{
        .commit_id = std::string(64, 'e'),
        .ciphertext_id = std::string(64, 'f')};
    const auto parent_marker =
        kasumi::application::history_storage::marker_identifier(parent);
    const auto concurrent_marker =
        kasumi::application::history_storage::marker_identifier(concurrent);
    const auto ancestral_marker =
        kasumi::application::history_storage::marker_identifier(ancestral);
    state->objects[parent_marker] = {1};
    state->objects[concurrent_marker] = {2};
    state->objects[ancestral_marker] = {3};
    const std::vector<std::string> observed_cleanup_ids{parent.commit_id,
                                                        ancestral.commit_id};
    const std::vector<std::string> observed_marker_ids{parent_marker,
                                                       ancestral_marker};

    const auto pruned =
        kasumi::application::sync::publication::prune_observed_parent_markers(
            storage, observed_cleanup_ids, observed_marker_ids);

    ASSERT_TRUE(pruned.has_value()) << pruned.error().detail;
    EXPECT_EQ(pruned->removed_markers, 2);
    EXPECT_FALSE(state->objects.contains(parent_marker));
    EXPECT_FALSE(state->objects.contains(ancestral_marker));
    EXPECT_TRUE(state->objects.contains(concurrent_marker));
    EXPECT_EQ(state->list_count, 0);
    EXPECT_EQ(state->remove_count, 2);
}

TEST(ReconciliationTest, RejectsMaximumStorageGeneration) {
    auto input = empty_publication_input();
    input.storage.history_present = true;
    input.storage.tree = input.local_tree;
    input.storage.generation = std::numeric_limits<std::uint64_t>::max();

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::reconciliation::ErrorCode::StorageGenerationOverflow);
}

TEST(ReconciliationTest, DownloadDoesNotChangeSharedTree) {
    auto input = empty_publication_input();
    const auto content = kasumi::hasher::hash_string("remote");
    input.storage.history_present = true;
    input.storage.logical_heads = {std::string(64, 'a')};
    input.storage.tree = input.local_tree;
    input.storage.tree.rows.push_back(kasumi::NodeRow{.path = "remote.txt",
                                                      .hash = content,
                                                      .size = 6,
                                                      .is_directory = false});
    kasumi::finalize_snapshot(input.storage.tree);
    input.base_tree = input.local_tree;

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_FALSE(result->shared_tree_changed);
    EXPECT_FALSE(result->requires_storage_repair);
    EXPECT_FALSE(result->requires_publication);
    EXPECT_EQ(result->target_generation, input.storage.generation);
}

TEST(ReconciliationTest, LocalUploadChangesSharedTree) {
    auto input = empty_publication_input();
    input.storage.history_present = true;
    input.storage.logical_heads = {std::string(64, 'a')};
    input.storage.tree = input.local_tree;
    input.base_tree = input.local_tree;
    input.local_tree.rows.push_back(
        kasumi::NodeRow{.path = "local.txt",
                        .hash = kasumi::hasher::hash_string("local"),
                        .size = 5,
                        .is_directory = false});
    kasumi::finalize_snapshot(input.local_tree);

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->shared_tree_changed);
    EXPECT_FALSE(result->requires_storage_repair);
    EXPECT_TRUE(result->requires_publication);
    EXPECT_EQ(result->target_generation, input.storage.generation + 1);
}

TEST(ReconciliationTest, MissingReferencedObjectIsRepairOnly) {
    auto input = empty_publication_input();
    input.storage.history_present = true;
    input.storage.logical_heads = {std::string(64, 'a')};
    input.storage.tree = input.local_tree;
    input.storage.tree.rows.push_back(
        kasumi::NodeRow{.path = "repair.txt",
                        .hash = kasumi::hasher::hash_string("repair"),
                        .size = 6,
                        .is_directory = false});
    kasumi::finalize_snapshot(input.storage.tree);
    input.local_tree = input.storage.tree;
    input.base_tree = input.storage.tree;
    input.audit_storage_objects = true;

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_TRUE(result->requires_storage_repair);
    EXPECT_FALSE(result->shared_tree_changed);
    EXPECT_FALSE(result->requires_publication);
    EXPECT_EQ(result->target_generation, input.storage.generation);
    EXPECT_TRUE(std::ranges::any_of(
        result->plan.operations, [](const kasumi::Operation& operation) {
            return operation.action == kasumi::Action::Upload;
        }));
}

TEST(ReconciliationTest, RejectsNonCanonicalRows) {
    auto input = empty_publication_input();
    input.storage.history_present = true;
    input.storage.logical_heads = {std::string(64, 'a')};
    input.storage.tree = input.local_tree;
    input.storage.tree.rows.push_back(
        kasumi::NodeRow{.path = "same.txt",
                        .hash = kasumi::hasher::hash_string("same"),
                        .size = 4,
                        .is_directory = false});
    kasumi::finalize_snapshot(input.storage.tree);
    input.local_tree = input.storage.tree;
    input.base_tree = input.storage.tree;
    std::ranges::reverse(input.local_tree.rows);
    std::ranges::reverse(input.base_tree.rows);
    std::ranges::reverse(input.storage.tree.rows);

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::reconciliation::ErrorCode::InvalidLocalTree);
}

TEST(ReconciliationTest, NewRemoteDirectoryPreservesLocalMtime) {
    auto input = empty_publication_input();
    const auto directory_mtime =
        std::filesystem::file_time_type::clock::now() - std::chrono::hours{3};
    input.storage.history_present = true;
    input.storage.logical_heads = {std::string(64, 'a')};
    input.storage.tree = input.local_tree;
    input.base_tree = input.local_tree;
    input.local_tree.rows.push_back(kasumi::NodeRow{
        .path = "docs", .mtime = directory_mtime, .is_directory = true});
    kasumi::finalize_snapshot(input.local_tree);

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    const auto* candidate =
        kasumi::find_row(result->candidate_shared_tree, "docs");
    ASSERT_NE(candidate, nullptr);
    EXPECT_TRUE(candidate->is_directory);
    EXPECT_EQ(candidate->mtime, directory_mtime);
    EXPECT_TRUE(result->shared_tree_changed);
    EXPECT_TRUE(result->requires_publication);
}

TEST(ReconciliationTest, ExistingAncestorsUseLocalMetadata) {
    auto input = empty_publication_input();
    const auto root_mtime = make_file_time(std::chrono::nanoseconds{101});
    const auto storage_directory_mtime =
        make_file_time(std::chrono::nanoseconds{102});
    const auto local_directory_mtime =
        make_file_time(std::chrono::nanoseconds{202});
    input.storage.history_present = true;
    input.storage.logical_heads = {std::string(64, 'a')};
    input.storage.tree = input.local_tree;
    input.storage.tree.rows.push_back(
        kasumi::NodeRow{.path = "docs",
                        .mtime = storage_directory_mtime,
                        .is_directory = true});
    kasumi::finalize_snapshot(input.storage.tree);
    input.base_tree = input.storage.tree;
    input.local_tree = input.storage.tree;
    input.local_tree.rows.front().mtime = root_mtime;
    kasumi::find_row(input.local_tree, "docs")->mtime = local_directory_mtime;
    input.local_tree.rows.push_back(
        kasumi::NodeRow{.path = "docs/new.txt",
                        .hash = kasumi::hasher::hash_string("new"),
                        .size = 3,
                        .is_directory = false});
    kasumi::finalize_snapshot(input.local_tree);

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(kasumi::find_row(result->candidate_shared_tree, "")->mtime,
              root_mtime);
    EXPECT_EQ(kasumi::find_row(result->candidate_shared_tree, "docs")->mtime,
              local_directory_mtime);
    EXPECT_NE(kasumi::find_row(result->candidate_shared_tree, "docs/new.txt"),
              nullptr);
    EXPECT_TRUE(result->shared_tree_changed);
    EXPECT_TRUE(result->requires_publication);
}

TEST(ReconciliationTest, DeletedAncestorsUseSurvivingLocalMetadata) {
    auto input = empty_publication_input();
    const auto root_mtime = make_file_time(std::chrono::nanoseconds{301});
    const auto directory_mtime = make_file_time(std::chrono::nanoseconds{302});
    input.storage.history_present = true;
    input.storage.logical_heads = {std::string(64, 'a')};
    input.storage.tree = input.local_tree;
    input.storage.tree.rows.push_back(
        kasumi::NodeRow{.path = "docs", .is_directory = true});
    input.storage.tree.rows.push_back(
        kasumi::NodeRow{.path = "docs/alpha.txt",
                        .hash = kasumi::hasher::hash_string("alpha"),
                        .size = 5,
                        .is_directory = false});
    kasumi::finalize_snapshot(input.storage.tree);
    input.base_tree = input.storage.tree;
    input.local_tree = kasumi::Snapshot{
        .rows = {kasumi::NodeRow{
                     .path = "", .mtime = root_mtime, .is_directory = true},
                 kasumi::NodeRow{.path = "docs",
                                 .mtime = directory_mtime,
                                 .is_directory = true}}};
    kasumi::finalize_snapshot(input.local_tree);

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(kasumi::find_row(result->candidate_shared_tree, "")->mtime,
              root_mtime);
    EXPECT_EQ(kasumi::find_row(result->candidate_shared_tree, "docs")->mtime,
              directory_mtime);
    EXPECT_EQ(kasumi::find_row(result->candidate_shared_tree, "docs/alpha.txt"),
              nullptr);
    EXPECT_TRUE(result->requires_publication);

    input.local_tree.rows.pop_back();
    kasumi::finalize_snapshot(input.local_tree);
    const auto removed_directory = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(removed_directory.has_value())
        << removed_directory.error().detail;
    EXPECT_EQ(
        kasumi::find_row(removed_directory->candidate_shared_tree, "docs"),
        nullptr);
    EXPECT_EQ(
        kasumi::find_row(removed_directory->candidate_shared_tree, "")->mtime,
        root_mtime);
}

TEST(ReconciliationTest, OrdersNestedLocalSubtreeDeletionSafely) {
    kasumi::Snapshot shared{.rows = {{.path = "", .is_directory = true},
                                     {.path = "a", .is_directory = true},
                                     {.path = "a/b", .is_directory = true},
                                     {.path = "a/b/c.txt",
                                      .hash = kasumi::hasher::hash_string("c"),
                                      .size = 1},
                                     {.path = "a/d.txt",
                                      .hash = kasumi::hasher::hash_string("d"),
                                      .size = 1}}};
    kasumi::finalize_snapshot(shared);
    kasumi::Snapshot remote{.rows = {{.path = "", .is_directory = true}}};
    kasumi::finalize_snapshot(remote);
    const auto base_id = std::string(64, 'a');
    const auto head_id = std::string(64, 'b');
    auto input = empty_publication_input();
    input.local_tree = shared;
    input.base_tree = shared;
    input.base_commit_id = base_id;
    input.base_state_present = true;
    input.storage.tree = remote;
    input.storage.reachable_commits = {
        {.id = base_id, .commit = {.height = 0, .tree = shared}},
        {.id = head_id,
         .commit = {.height = 1, .parents = {base_id}, .tree = remote}}};
    input.storage.reachable_commit_ids = {base_id, head_id};
    input.storage.marked_heads = {head_id};
    input.storage.logical_heads = {head_id};
    input.storage.generation = 1;
    input.storage.history_present = true;

    const auto result = kasumi::reconciliation::reconcile(input);

    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_EQ(result->plan.operations.size(), 4U);
    EXPECT_EQ(result->plan.operations[0].action, kasumi::Action::DeleteLocal);
    EXPECT_EQ(result->plan.operations[0].path, "a/b/c.txt");
    EXPECT_EQ(result->plan.operations[1].action, kasumi::Action::DeleteLocal);
    EXPECT_EQ(result->plan.operations[1].path, "a/d.txt");
    EXPECT_EQ(result->plan.operations[2].action,
              kasumi::Action::DeleteLocalDirectory);
    EXPECT_EQ(result->plan.operations[2].path, "a/b");
    EXPECT_EQ(result->plan.operations[3].action,
              kasumi::Action::DeleteLocalDirectory);
    EXPECT_EQ(result->plan.operations[3].path, "a");
    EXPECT_TRUE(result->requires_local_mutation);
    EXPECT_FALSE(result->requires_publication);
    EXPECT_TRUE(result->requires_state_commit);
}

TEST(ReconciliationTest, MissingObservedParentRejectsCandidateConstruction) {
    auto input = empty_publication_input();
    input.storage.history_present = true;
    input.storage.logical_heads = {std::string(64, 'a')};
    input.storage.tree = input.local_tree;
    input.base_tree = input.local_tree;
    input.local_tree.rows.push_back(
        kasumi::NodeRow{.path = "docs/alpha.txt",
                        .hash = kasumi::hasher::hash_string("alpha"),
                        .size = 5,
                        .is_directory = false});
    kasumi::finalize_snapshot(input.local_tree);

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::reconciliation::ErrorCode::InvalidLocalTree);
}

TEST(ReconciliationTest, FileObservedAsParentRejectsCandidateConstruction) {
    auto input = empty_publication_input();
    input.storage.history_present = true;
    input.storage.logical_heads = {std::string(64, 'a')};
    input.storage.tree = input.local_tree;
    input.base_tree = input.local_tree;
    input.local_tree.rows.push_back(
        kasumi::NodeRow{.path = "docs",
                        .hash = kasumi::hasher::hash_string("file"),
                        .size = 4,
                        .is_directory = false});
    input.local_tree.rows.push_back(
        kasumi::NodeRow{.path = "docs/alpha.txt",
                        .hash = kasumi::hasher::hash_string("alpha"),
                        .size = 5,
                        .is_directory = false});
    kasumi::finalize_snapshot(input.local_tree);

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::reconciliation::ErrorCode::InvalidLocalTree);
}

TEST(ReconciliationTest, RepairDoesNotChangeDirectoryMetadata) {
    auto input = empty_publication_input();
    const auto directory_mtime =
        std::filesystem::file_time_type::clock::now() - std::chrono::hours{4};
    input.storage.history_present = true;
    input.storage.logical_heads = {std::string(64, 'a')};
    input.storage.tree = input.local_tree;
    input.storage.tree.rows.push_back(kasumi::NodeRow{
        .path = "docs", .mtime = directory_mtime, .is_directory = true});
    input.storage.tree.rows.push_back(
        kasumi::NodeRow{.path = "docs/alpha.txt",
                        .hash = kasumi::hasher::hash_string("alpha"),
                        .size = 5,
                        .is_directory = false});
    kasumi::finalize_snapshot(input.storage.tree);
    input.local_tree = input.storage.tree;
    input.base_tree = input.storage.tree;
    input.audit_storage_objects = true;

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_TRUE(result->requires_storage_repair);
    EXPECT_FALSE(result->shared_tree_changed);
    EXPECT_EQ(kasumi::find_row(result->candidate_shared_tree, "docs")->mtime,
              directory_mtime);
}

TEST(ReconciliationTest, PendingReferencesUseTrustedAncestorMetadata) {
    const auto root_mtime = make_file_time(std::chrono::nanoseconds{401});
    const auto directory_mtime = make_file_time(std::chrono::nanoseconds{402});
    kasumi::Snapshot local_tree{
        .rows = {kasumi::NodeRow{
                     .path = "", .mtime = root_mtime, .is_directory = true},
                 kasumi::NodeRow{.path = "docs",
                                 .mtime = directory_mtime,
                                 .is_directory = true}}};
    kasumi::finalize_snapshot(local_tree);
    const auto candidate = local_tree;
    const kasumi::NodeRow pending{.path = "docs/remote.txt",
                                  .hash = kasumi::hasher::hash_string("remote"),
                                  .size = 6,
                                  .is_directory = false};

    const auto result = kasumi::reconciliation::build_publication_tree(
        local_tree, std::span<const kasumi::NodeRow>{&pending, 1}, candidate);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(kasumi::find_row(*result, "")->mtime, root_mtime);
    EXPECT_EQ(kasumi::find_row(*result, "docs")->mtime, directory_mtime);
    EXPECT_NE(kasumi::find_row(*result, "docs/remote.txt"), nullptr);
}

TEST(ReconciliationTest,
     ConflictReservationFoldsAsciiCaseAndAvoidsFalseCollisions) {
    auto input = empty_publication_input();
    input.storage.history_present = true;
    input.storage.logical_heads = {std::string(64, 'a')};

    const auto now = std::filesystem::file_time_type::clock::now();
    const auto remote_time = now - std::chrono::hours{1};
    const auto local_time = now + std::chrono::hours{1};

    const auto base_file_hash = kasumi::hasher::hash_string("base_file");
    const auto remote_file_hash = kasumi::hasher::hash_string("remote_file");
    const auto local_file_hash = kasumi::hasher::hash_string("local_file");

    const auto base_foo_hash = kasumi::hasher::hash_string("base_foo");
    const auto remote_foo_hash = kasumi::hasher::hash_string("remote_foo");
    const auto local_foo_hash = kasumi::hasher::hash_string("local_foo");

    const auto base_foobar_hash = kasumi::hasher::hash_string("base_foobar");
    const auto remote_foobar_hash =
        kasumi::hasher::hash_string("remote_foobar");
    const auto local_foobar_hash = kasumi::hasher::hash_string("local_foobar");

    const auto dummy_hash = kasumi::hasher::hash_string("dummy");

    input.base_tree = kasumi::Snapshot{
        .rows = {
            kasumi::NodeRow{.path = "", .is_directory = true},
            kasumi::NodeRow{.path = "FooBar",
                            .hash = base_foobar_hash,
                            .size = 11,
                            .mtime = remote_time,
                            .is_directory = false},
            kasumi::NodeRow{.path = "file.txt",
                            .hash = base_file_hash,
                            .size = 9,
                            .mtime = remote_time,
                            .is_directory = false},
            kasumi::NodeRow{.path = "foo",
                            .hash = base_foo_hash,
                            .size = 8,
                            .mtime = remote_time,
                            .is_directory = false},
        }};
    kasumi::finalize_snapshot(input.base_tree);

    input.storage.tree = kasumi::Snapshot{
        .rows = {
            kasumi::NodeRow{.path = "", .is_directory = true},
            kasumi::NodeRow{.path = "FooBar",
                            .hash = remote_foobar_hash,
                            .size = 13,
                            .mtime = remote_time,
                            .is_directory = false},
            kasumi::NodeRow{.path = "file.txt",
                            .hash = remote_file_hash,
                            .size = 11,
                            .mtime = remote_time,
                            .is_directory = false},
            kasumi::NodeRow{.path = "foo",
                            .hash = remote_foo_hash,
                            .size = 10,
                            .mtime = remote_time,
                            .is_directory = false},
        }};
    kasumi::finalize_snapshot(input.storage.tree);

    // local_tree has:
    // - "FILE.txt.kasumiconflict_remote": pre-existing reserved path in local tree
    // - "FooBar": locally modified (newer than remote) -> preferred "FooBar.kasumiconflict_remote"
    // - "file.txt": locally modified (newer than remote) -> preferred "file.txt.kasumiconflict_remote"
    // - "foo": locally modified (newer than remote) -> preferred "foo.kasumiconflict_remote"
    input.local_tree = kasumi::Snapshot{
        .rows = {
            kasumi::NodeRow{.path = "", .is_directory = true},
            kasumi::NodeRow{.path = "FILE.txt.kasumiconflict_remote",
                            .hash = dummy_hash,
                            .size = 5,
                            .mtime = now,
                            .is_directory = false},
            kasumi::NodeRow{.path = "FooBar",
                            .hash = local_foobar_hash,
                            .size = 12,
                            .mtime = local_time,
                            .is_directory = false},
            kasumi::NodeRow{.path = "file.txt",
                            .hash = local_file_hash,
                            .size = 10,
                            .mtime = local_time,
                            .is_directory = false},
            kasumi::NodeRow{.path = "foo",
                            .hash = local_foo_hash,
                            .size = 9,
                            .mtime = local_time,
                            .is_directory = false},
        }};
    kasumi::finalize_snapshot(input.local_tree);

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;

    // "FILE.txt.kasumiconflict_remote" in reserved causes preferred
    // "file.txt.kasumiconflict_remote" to be assigned ".1" via ASCII-fold matching.
    const bool has_numbered_conflict = std::ranges::any_of(
        result->plan.operations, [](const kasumi::Operation& op) {
            return op.action == kasumi::Action::Download &&
                   op.path == "file.txt.kasumiconflict_remote.1";
        });
    EXPECT_TRUE(has_numbered_conflict);

    const bool has_unfolded_collision = std::ranges::any_of(
        result->plan.operations, [](const kasumi::Operation& op) {
            return op.action == kasumi::Action::Download &&
                   op.path == "file.txt.kasumiconflict_remote";
        });
    EXPECT_FALSE(has_unfolded_collision);

    // "foo" and "FooBar" do not falsely collide with each other:
    // preferred "foo.kasumiconflict_remote" does not collide with "FooBar" or "FooBar.kasumiconflict_remote",
    // and "FooBar.kasumiconflict_remote" does not collide with "foo" or "foo.kasumiconflict_remote".
    const bool has_foo_conflict = std::ranges::any_of(
        result->plan.operations, [](const kasumi::Operation& op) {
            return op.action == kasumi::Action::Download &&
                   op.path == "foo.kasumiconflict_remote";
        });
    EXPECT_TRUE(has_foo_conflict);

    const bool has_foo_numbered = std::ranges::any_of(
        result->plan.operations, [](const kasumi::Operation& op) {
            return op.action == kasumi::Action::Download &&
                   op.path == "foo.kasumiconflict_remote.1";
        });
    EXPECT_FALSE(has_foo_numbered);

    const bool has_foobar_conflict = std::ranges::any_of(
        result->plan.operations, [](const kasumi::Operation& op) {
            return op.action == kasumi::Action::Download &&
                   op.path == "FooBar.kasumiconflict_remote";
        });
    EXPECT_TRUE(has_foobar_conflict);

    const bool has_foobar_numbered = std::ranges::any_of(
        result->plan.operations, [](const kasumi::Operation& op) {
            return op.action == kasumi::Action::Download &&
                   op.path == "FooBar.kasumiconflict_remote.1";
        });
    EXPECT_FALSE(has_foobar_numbered);
}

TEST(ReconciliationTest, ConflictReservationAvoidsUnicodeCaseCollisions) {
    auto input = empty_publication_input();
    input.storage.history_present = true;
    input.storage.logical_heads = {std::string(64, 'a')};

    const auto now = std::filesystem::file_time_type::clock::now();
    const auto remote_time = now - std::chrono::hours{1};
    const auto local_time = now + std::chrono::hours{1};

    const auto base_hash = kasumi::hasher::hash_string("base");
    const auto remote_hash = kasumi::hasher::hash_string("remote");
    const auto local_hash = kasumi::hasher::hash_string("local");
    const auto dummy_hash = kasumi::hasher::hash_string("dummy");

    input.base_tree = kasumi::Snapshot{
        .rows = {
            kasumi::NodeRow{.path = "", .is_directory = true},
            kasumi::NodeRow{.path = "ä.txt",
                            .hash = base_hash,
                            .size = 4,
                            .mtime = remote_time,
                            .is_directory = false},
        }};
    kasumi::finalize_snapshot(input.base_tree);

    input.storage.tree = kasumi::Snapshot{
        .rows = {
            kasumi::NodeRow{.path = "", .is_directory = true},
            kasumi::NodeRow{.path = "ä.txt",
                            .hash = remote_hash,
                            .size = 6,
                            .mtime = remote_time,
                            .is_directory = false},
        }};
    kasumi::finalize_snapshot(input.storage.tree);

    input.local_tree = kasumi::Snapshot{
        .rows = {
            kasumi::NodeRow{.path = "", .is_directory = true},
            kasumi::NodeRow{.path = "Ä.txt.kasumiconflict_remote",
                            .hash = dummy_hash,
                            .size = 5,
                            .mtime = now,
                            .is_directory = false},
            kasumi::NodeRow{.path = "ä.txt",
                            .hash = local_hash,
                            .size = 5,
                            .mtime = local_time,
                            .is_directory = false},
        }};
    kasumi::finalize_snapshot(input.local_tree);

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;

    const bool has_numbered_conflict = std::ranges::any_of(
        result->plan.operations, [](const kasumi::Operation& op) {
            return op.action == kasumi::Action::Download &&
                   op.path == kasumi::platform::path::from_utf8(
                                  "ä.txt.kasumiconflict_remote.1");
        });
    EXPECT_TRUE(has_numbered_conflict);

    const bool has_unfolded_collision = std::ranges::any_of(
        result->plan.operations, [](const kasumi::Operation& op) {
            return op.action == kasumi::Action::Download &&
                   op.path == kasumi::platform::path::from_utf8(
                                  "ä.txt.kasumiconflict_remote");
        });
    EXPECT_FALSE(has_unfolded_collision);
}

TEST(ReconciliationTest, UnicodeLocalConflictReservationUpdatesRelatedUpload) {
    auto input = empty_publication_input();
    input.storage.history_present = true;
    input.storage.logical_heads = {std::string(64, 'a')};
    const auto now = std::filesystem::file_time_type::clock::now();
    const std::string logical_path = "高松灯/ä🌸.txt";
    const std::string reserved_path = "高松灯/Ä🌸.txt.kasumiconflict_local";
    const auto local_hash = kasumi::hasher::hash_string("local");
    input.base_tree = input.local_tree;
    input.base_tree.rows.push_back({.path = "高松灯", .is_directory = true});
    input.base_tree.rows.push_back({.path = logical_path,
                                    .hash = kasumi::hasher::hash_string("base"),
                                    .size = 4,
                                    .mtime = now});
    kasumi::finalize_snapshot(input.base_tree);
    input.local_tree = input.base_tree;
    input.local_tree.rows.back().hash = local_hash;
    input.local_tree.rows.back().size = 5;
    input.local_tree.rows.push_back({.path = reserved_path,
                                     .hash = kasumi::hasher::hash_string("reserved"),
                                     .size = 8,
                                     .mtime = now});
    kasumi::finalize_snapshot(input.local_tree);
    input.storage.tree = input.base_tree;
    input.storage.tree.rows.back().hash = kasumi::hasher::hash_string("remote");
    input.storage.tree.rows.back().size = 6;
    input.storage.tree.rows.back().mtime = now + std::chrono::hours{1};
    kasumi::finalize_snapshot(input.storage.tree);

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_TRUE(result->has_conflicts);
    const auto selected = kasumi::platform::path::from_utf8(
        logical_path + ".kasumiconflict_local.1");
    const auto renames = kasumi::sync_plan_phase(result->plan, kasumi::Action::RenameLocal);
    ASSERT_EQ(renames.size(), 1U);
    EXPECT_EQ(renames.front().path, kasumi::platform::path::from_utf8(logical_path));
    EXPECT_EQ(renames.front().alt_path, selected);
    EXPECT_TRUE(std::ranges::any_of(result->plan.operations, [&](const auto& operation) {
        return operation.action == kasumi::Action::Upload &&
               operation.hash == kasumi::hash_hex(local_hash) &&
               operation.path == selected;
    }));
    EXPECT_NE(kasumi::find_row(result->candidate_shared_tree,
                              logical_path + ".kasumiconflict_local.1"), nullptr);
    EXPECT_NE(kasumi::find_row(result->candidate_shared_tree, reserved_path), nullptr);
    EXPECT_TRUE(kasumi::valid_snapshot(result->candidate_shared_tree, false));
}

TEST(ReconciliationTest, UnicodeMissingObjectPathsPreserveRecoverySources) {
    auto input = empty_publication_input();
    input.storage.history_present = true;
    input.storage.logical_heads = {std::string(64, 'a')};
    input.audit_storage_objects = true;
    const std::string source_path = "千早愛音/𝑬𝒎𝒊𝒍𝒊𝒂.txt";
    const std::string missing_path = "高松灯/カード💝.png";
    const auto missing_hash = kasumi::hasher::hash_string("missing");
    const auto remote_hash = kasumi::hasher::hash_string("remote");
    input.local_tree.rows.push_back({.path = "千早愛音", .is_directory = true});
    input.local_tree.rows.push_back({.path = "高松灯", .is_directory = true});
    input.local_tree.rows.push_back({.path = source_path,
                                     .hash = missing_hash,
                                     .size = 7});
    kasumi::finalize_snapshot(input.local_tree);
    input.base_tree = input.local_tree;
    input.storage.tree = input.local_tree;
    auto source = std::ranges::find(input.storage.tree.rows, source_path, &kasumi::NodeRow::path);
    ASSERT_NE(source, input.storage.tree.rows.end());
    source->hash = remote_hash;
    source->size = 6;
    input.storage.tree.rows.push_back({.path = missing_path,
                                       .hash = missing_hash,
                                       .size = 7});
    input.storage.object_identifiers.insert(kasumi::hash_hex(remote_hash));
    kasumi::finalize_snapshot(input.storage.tree);

    const auto repaired = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(repaired.has_value()) << repaired.error().detail;
    EXPECT_TRUE(repaired->requires_storage_repair);
    EXPECT_TRUE(repaired->unrecoverable_paths.empty());
    const auto uploads = kasumi::sync_plan_phase(repaired->plan, kasumi::Action::Upload);
    ASSERT_EQ(uploads.size(), 1U);
    EXPECT_EQ(uploads.front().path, kasumi::platform::path::from_utf8(source_path));
    EXPECT_EQ(uploads.front().hash, kasumi::hash_hex(missing_hash));
    EXPECT_FALSE(repaired->shared_tree_changed);

    std::erase_if(input.local_tree.rows, [&](const auto& row) {
        return row.path == source_path;
    });
    kasumi::finalize_snapshot(input.local_tree);
    const auto pending = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(pending.has_value()) << pending.error().detail;
    ASSERT_EQ(pending->unrecoverable_paths.size(), 1U);
    EXPECT_EQ(pending->unrecoverable_paths.front(),
              kasumi::platform::path::from_utf8(missing_path));
    ASSERT_EQ(pending->pending_storage_rows.size(), 1U);
    EXPECT_EQ(pending->pending_storage_rows.front().path, missing_path);
}

TEST(SyncCoordinatorTest, EmptyPlanPublishesAndPersistsConvergenceCommit) {
    auto workspace = kasumi::test::make_temp_workspace("runtime-convergence");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto runtime_data = make_runtime(profile, local, storage_path);
    auto opened = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto make_tree =
        [](std::initializer_list<std::pair<std::string, std::string>> files) {
            kasumi::Snapshot tree{
                .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
            for (const auto& [path, contents] : files) {
                tree.rows.push_back(kasumi::NodeRow{
                    .path = path,
                    .hash = kasumi::hasher::hash_string(contents),
                    .size = contents.size(),
                    .is_directory = false});
            }
            kasumi::finalize_snapshot(tree);
            return tree;
        };
    const auto first_tree = make_tree({{"first.txt", "first"}});
    const auto second_tree = make_tree({{"second.txt", "second"}});
    auto effective_tree =
        make_tree({{"first.txt", "first"}, {"second.txt", "second"}});
    kasumi::test::write_text(local / "first.txt", "first");
    kasumi::test::write_text(local / "second.txt", "second");
    const auto local_root_mtime = std::filesystem::last_write_time(local);
    effective_tree.rows.front().mtime = local_root_mtime;
    for (auto& row : effective_tree.rows) {
        if (!row.is_directory) {
            row.mtime = std::filesystem::last_write_time(local / row.path);
        }
    }
    for (const auto& path : {local / "first.txt", local / "second.txt"}) {
        const auto hash = kasumi::crypto::content::hash_file(path);
        ASSERT_TRUE(hash.has_value());
        ASSERT_TRUE(kasumi::transport::put(
            storage, path, kasumi::crypto::content_identifier(key, *hash)));
    }

    const auto root_tree = make_tree({});
    auto root = kasumi::application::sync::publication::prepare_commit(
        root_tree, false, 0, {}, 100, key);
    ASSERT_TRUE(root.has_value());
    const std::vector<std::string> root_heads{root->commit_id};
    auto first = kasumi::application::sync::publication::prepare_commit(
        first_tree, true, 0, root_heads, 200, key);
    auto second = kasumi::application::sync::publication::prepare_commit(
        second_tree, true, 0, root_heads, 200, key);
    ASSERT_TRUE(root.has_value() && first.has_value() && second.has_value());
    const auto root_published =
        kasumi::application::sync::publication::publish_commit(
            storage, key, *root, profile);
    const auto first_published =
        kasumi::application::sync::publication::publish_commit(
            storage, key, *first, profile);
    const auto second_published =
        kasumi::application::sync::publication::publish_commit(
            storage, key, *second, profile);
    ASSERT_TRUE(root_published.has_value());
    ASSERT_TRUE(first_published.has_value());
    ASSERT_TRUE(second_published.has_value());
    std::vector<std::string> heads{first->commit_id, second->commit_id};
    std::ranges::sort(heads);

    kasumi::reconciliation::Input input{
        .local_tree = effective_tree,
        .base_tree = effective_tree,
        .base_commit_id = {},
        .base_state_present = false,
        .storage =
            {.tree = effective_tree,
             .object_identifiers =
                 {kasumi::hash_hex(first_tree.rows.back().hash),
                  kasumi::hash_hex(second_tree.rows.back().hash)},
             .reachable_commits =
                 {{.id = root->commit_id, .commit = root->commit},
                  {.id = first->commit_id, .commit = first->commit},
                  {.id = second->commit_id, .commit = second->commit}},
             .reachable_commit_ids = {root->commit_id,
                                      first->commit_id,
                                      second->commit_id},
             .marked_heads = heads,
             .marked_head_identifiers =
                 {kasumi::application::history_storage::marker_identifier(
                      root_published->head),
                  kasumi::application::history_storage::marker_identifier(
                      first_published->head),
                  kasumi::application::history_storage::marker_identifier(
                      second_published->head)},
             .logical_heads = heads,
             .ancestral_marked_heads = {root->commit_id},
             .generation = 1,
             .history_present = true,
             .history_has_conflicts = false},
        .local_generation = 0,
        .audit_storage_objects = false};
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->plan.operations.empty());
    ASSERT_TRUE(result->requires_publication);
    const auto local_before = kasumi::test::snapshot_tree(local);
    const auto executed = kasumi::application::sync::coordinator::execute(
        runtime_data, storage, key, input, *result);
    ASSERT_TRUE(executed) << executed.error().detail;
    EXPECT_EQ(kasumi::test::snapshot_tree(local), local_before);
    const auto stored =
        kasumi::state_storage::load_state(runtime_data.database_path);
    ASSERT_TRUE(stored.has_value() && *stored);
    EXPECT_EQ((*stored)->height, 2U);
    const auto convergence =
        kasumi::application::sync::publication::find_reachable_commit(
            storage, key, profile, (*stored)->commit_id);
    ASSERT_TRUE(convergence.has_value() && *convergence);
    EXPECT_EQ((*convergence)->commit.height, 2U);
    EXPECT_EQ((*convergence)->commit.parents, heads);
    ASSERT_EQ((*convergence)->commit.tree.rows.size(),
              effective_tree.rows.size());
    for (std::size_t index = 0; index < effective_tree.rows.size(); ++index) {
        EXPECT_EQ((*convergence)->commit.tree.rows[index].path,
                  effective_tree.rows[index].path);
        EXPECT_EQ((*convergence)->commit.tree.rows[index].hash,
                  effective_tree.rows[index].hash);
        EXPECT_EQ((*convergence)->commit.tree.rows[index].size,
                  effective_tree.rows[index].size);
        EXPECT_EQ((*convergence)->commit.tree.rows[index].is_directory,
                  effective_tree.rows[index].is_directory);
    }
    const auto listing = kasumi::transport::list(storage);
    ASSERT_TRUE(listing.has_value());
    EXPECT_EQ(std::ranges::count_if(*listing,
                                    [](const auto& id) {
                                        return id.starts_with(
                                            "history/commits/");
                                    }),
              4);
    EXPECT_EQ(std::ranges::count_if(*listing,
                                    [](const auto& id) {
                                        return id.starts_with("history/heads/");
                                    }),
              1);
}

TEST(SyncCoordinatorTest, PublishedCommitMatchesCandidateTreeMetadata) {
    auto workspace =
        kasumi::test::make_temp_workspace("candidate-commit-fidelity");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local / "docs"));
    kasumi::test::write_text(local / "docs" / "alpha.txt", "alpha");

    const auto root_requested =
        std::filesystem::file_time_type::clock::now() - std::chrono::hours{3};
    const auto directory_requested =
        std::filesystem::file_time_type::clock::now() - std::chrono::hours{2};
    const auto file_requested =
        std::filesystem::file_time_type::clock::now() - std::chrono::hours{1};
    ASSERT_TRUE(kasumi::platform::metadata::set_last_write_time(
        local / "docs" / "alpha.txt", file_requested));
    ASSERT_TRUE(kasumi::platform::metadata::set_last_write_time(
        local / "docs", directory_requested));
    ASSERT_TRUE(
        kasumi::platform::metadata::set_last_write_time(local, root_requested));
    std::error_code time_error;
    const auto file_mtime = std::filesystem::last_write_time(
        local / "docs" / "alpha.txt", time_error);
    ASSERT_FALSE(time_error);
    const auto directory_mtime =
        std::filesystem::last_write_time(local / "docs", time_error);
    ASSERT_FALSE(time_error);
    const auto root_mtime = std::filesystem::last_write_time(local, time_error);
    ASSERT_FALSE(time_error);

    kasumi::Snapshot local_tree{
        .rows = {kasumi::NodeRow{
                     .path = "", .mtime = root_mtime, .is_directory = true},
                 kasumi::NodeRow{.path = "docs",
                                 .mtime = directory_mtime,
                                 .is_directory = true},
                 kasumi::NodeRow{.path = "docs/alpha.txt",
                                 .hash = kasumi::hasher::hash_string("alpha"),
                                 .size = 5,
                                 .mtime = file_mtime,
                                 .is_directory = false}}};
    kasumi::finalize_snapshot(local_tree);
    kasumi::Snapshot storage_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    kasumi::finalize_snapshot(storage_tree);

    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    ASSERT_TRUE(
        kasumi::transport::put(*storage,
                               local / "docs" / "alpha.txt",
                               kasumi::crypto::content_identifier(
                                   key, kasumi::hasher::hash_string("alpha"))));

    auto input = empty_publication_input();
    input.local_tree = local_tree;
    input.storage.tree = storage_tree;
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_TRUE(result->requires_publication);

    const auto runtime_data = make_runtime(profile, local, storage_path);
    const auto executed = kasumi::application::sync::coordinator::execute(
        runtime_data, *storage, key, input, *result);
    ASSERT_TRUE(executed) << executed.error().detail;

    const auto stored =
        kasumi::state_storage::load_state(runtime_data.database_path);
    ASSERT_TRUE(stored.has_value() && *stored);
    const auto loaded =
        kasumi::application::sync::publication::find_reachable_commit(
            *storage, key, local, (*stored)->commit_id);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    ASSERT_EQ((*loaded)->commit.tree.rows.size(),
              result->candidate_shared_tree.rows.size());
    for (std::size_t index = 0;
         index < result->candidate_shared_tree.rows.size();
         ++index) {
        const auto& expected = result->candidate_shared_tree.rows[index];
        const auto& actual = (*loaded)->commit.tree.rows[index];
        EXPECT_EQ(actual.path, expected.path);
        EXPECT_EQ(actual.hash, expected.hash);
        EXPECT_EQ(actual.size, expected.size);
        EXPECT_EQ(actual.mtime, expected.mtime);
        EXPECT_EQ(actual.is_directory, expected.is_directory);
    }
}

TEST(SyncCoordinatorTest, RejectsMismatchedResultBeforeRemotePruning) {
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-composition");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));

    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "storage").string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    kasumi::Snapshot local_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    kasumi::finalize_snapshot(local_tree);
    kasumi::reconciliation::Input input{
        .local_tree = local_tree,
        .base_tree = {},
        .base_commit_id = {},
        .base_state_present = false,
        .storage = {.tree = {},
                    .object_identifiers = {},
                    .reachable_commits = {},
                    .reachable_commit_ids = {},
                    .marked_heads = {},
                    .marked_head_identifiers = {},
                    .logical_heads = {},
                    .ancestral_marked_heads = {},
                    .generation = 0,
                    .history_present = false,
                    .history_has_conflicts = false},
        .local_generation = 0,
        .audit_storage_objects = false,
    };
    auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value());
    result->target_generation = 99;

    const kasumi::runtime::RuntimeData runtime_data{
        .local_dir = local,
        .database_path = profile / "state.db",
        .key_path = profile / "key.bin",
        .storage_location =
            kasumi::test::workspace_path(workspace, "storage").string(),
    };
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto execution = kasumi::application::sync::coordinator::execute(
        runtime_data, storage, key, input, *result);
    ASSERT_FALSE(execution.has_value());
    EXPECT_EQ(
        execution.error().code,
        kasumi::application::sync::coordinator::ErrorCode::CompositionMismatch);
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
}

TEST(SyncCoordinatorTest, CompositionMismatchMatrixHasNoSideEffects) {
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-composition-matrix");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    AmbiguousPublicationState* state = nullptr;
    auto opened = make_ambiguous_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(opened));
    kasumi::test::write_text(local / "file.txt", "file");
    auto input = empty_publication_input();
    input.local_tree.rows.push_back(
        kasumi::NodeRow{.path = "file.txt",
                        .hash = kasumi::hasher::hash_string("file"),
                        .size = 4,
                        .is_directory = false});
    kasumi::finalize_snapshot(input.local_tree);
    input.base_tree = kasumi::Snapshot{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    kasumi::finalize_snapshot(input.base_tree);
    input.storage.tree = input.base_tree;
    const auto expected = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(expected.has_value());
    ASSERT_FALSE(expected->plan.operations.empty());
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto local_before = kasumi::test::snapshot_tree(local);

    using Mutation = std::function<void(kasumi::reconciliation::Result&)>;
    const std::vector<std::pair<std::string, Mutation>> mutations{
        {"plan target",
         [](auto& value) {
             ++value.plan.target_generation;
         }},
        {"result target",
         [](auto& value) {
             ++value.target_generation;
         }},
        {"observed generation",
         [](auto& value) {
             ++value.observed_storage_generation;
         }},
        {"recovering",
         [](auto& value) {
             value.recovering_missing_history = false;
         }},
        {"conflicts",
         [](auto& value) {
             value.has_conflicts = true;
         }},
        {"state commit",
         [](auto& value) {
             value.requires_state_commit = !value.requires_state_commit;
         }},
        {"candidate tree",
         [](auto& value) {
             value.candidate_shared_tree.rows.front().mtime +=
                 std::chrono::seconds{1};
         }},
        {"missing objects",
         [](auto& value) {
             value.missing_objects.insert(
                 kasumi::hasher::hash_string("missing"));
         }},
        {"pending rows",
         [](auto& value) {
             value.pending_storage_rows.push_back(
                 kasumi::NodeRow{.path = "pending", .is_directory = false});
         }},
        {"unrecoverable paths",
         [](auto& value) {
             value.unrecoverable_paths.emplace_back("unrecoverable");
         }},
        {"offsets",
         [](auto& value) {
             ++value.plan.offsets[0];
         }},
        {"operation action",
         [](auto& value) {
             value.plan.operations.front().action = kasumi::Action::Download;
         }},
        {"operation path",
         [](auto& value) {
             value.plan.operations.front().path = "other.txt";
         }},
        {"operation hash",
         [](auto& value) {
             value.plan.operations.front().hash = "bad";
         }},
        {"operation size",
         [](auto& value) {
             ++value.plan.operations.front().size;
         }},
        {"operation alternate path",
         [](auto& value) {
             value.plan.operations.front().alt_path = "alternate.txt";
         }},
        {"operation exclusive destination",
         [](auto& value) {
             value.plan.operations.front().exclusive_destination =
                 !value.plan.operations.front().exclusive_destination;
         }},
    };
    for (const auto& [name, mutate] : mutations) {
        auto result = *expected;
        mutate(result);
        const auto execution = kasumi::application::sync::coordinator::execute(
            runtime_data, opened, key, input, result);
        ASSERT_FALSE(execution.has_value()) << name;
        EXPECT_EQ(execution.error().code,
                  kasumi::application::sync::coordinator::ErrorCode::
                      CompositionMismatch)
            << name;
        EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
        EXPECT_FALSE(std::filesystem::exists(runtime_data.database_path))
            << name;
        EXPECT_EQ(kasumi::test::snapshot_tree(local), local_before) << name;
        EXPECT_EQ(state->list_count, 0U) << name;
        EXPECT_EQ(state->get_count, 0U) << name;
        EXPECT_EQ(state->put_count, 0U) << name;
        EXPECT_EQ(state->remove_count, 0U) << name;
    }
}

TEST(SyncCoordinatorTest, ConcurrentAddedFileDoesNotAbortSyncAndIsPreserved) {
    auto workspace =
        kasumi::test::make_temp_workspace("concurrent-added-file");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    AmbiguousPublicationState* state = nullptr;
    auto opened = make_ambiguous_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(opened));
    kasumi::test::write_text(local / "file.txt", "file");
    auto input = empty_publication_input();
    input.local_tree.rows.push_back(
        kasumi::NodeRow{.path = "file.txt",
                        .hash = kasumi::hasher::hash_string("file"),
                        .size = 4,
                        .mtime = std::filesystem::last_write_time(local / "file.txt"),
                        .is_directory = false});
    kasumi::finalize_snapshot(input.local_tree);
    input.base_tree = kasumi::Snapshot{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    const auto expected = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(expected.has_value());

    // Arquivo novo criado concorrentemente durante o upload/sincronização
    kasumi::test::write_text(local / "screenshot.png", "image-bytes");

    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto execution = kasumi::application::sync::coordinator::execute(
        runtime_data, opened, key, input, *expected);
    // Não deve abortar o sync!
    ASSERT_TRUE(execution.has_value()) << execution.error().detail;
    // O arquivo novo deve continuar intacto no disco para ser sincronizado na próxima execução
    EXPECT_TRUE(std::filesystem::exists(local / "screenshot.png"));
    EXPECT_EQ(kasumi::test::read_text(local / "screenshot.png"), "image-bytes");
}

TEST(SyncCoordinatorTest, ConcurrentModifiedFileFailsSync) {
    auto workspace =
        kasumi::test::make_temp_workspace("concurrent-modified-file");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    AmbiguousPublicationState* state = nullptr;
    auto opened = make_ambiguous_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(opened));
    kasumi::test::write_text(local / "file.txt", "file");
    auto input = empty_publication_input();
    input.local_tree.rows.push_back(
        kasumi::NodeRow{.path = "file.txt",
                        .hash = kasumi::hasher::hash_string("file"),
                        .size = 4,
                        .mtime = std::filesystem::last_write_time(local / "file.txt"),
                        .is_directory = false});
    kasumi::finalize_snapshot(input.local_tree);
    input.base_tree = kasumi::Snapshot{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    const auto expected = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(expected.has_value());

    // Modifica o conteúdo de um arquivo existente sendo publicado
    kasumi::test::write_text(local / "file.txt", "tampered-content");

    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto execution = kasumi::application::sync::coordinator::execute(
        runtime_data, opened, key, input, *expected);
    ASSERT_FALSE(execution.has_value());
    EXPECT_EQ(execution.error().code,
              kasumi::application::sync::coordinator::ErrorCode::MutationFailure);
    EXPECT_NE(execution.error().detail.find("file.txt"), std::string::npos)
        << "Detail should mention the modified file: " << execution.error().detail;
}

TEST(SyncCoordinatorTest, AmbiguousPublicationWithReachableCommitRollsForward) {
    auto workspace =
        kasumi::test::make_temp_workspace("execute-ambiguous-reachable");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    AmbiguousPublicationState* state = nullptr;
    auto storage = make_ambiguous_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    state->fail_marker_put = true;
    state->persist_marker_on_failure = true;
    auto input = empty_publication_input();
    input.local_tree.rows.front().mtime =
        std::filesystem::last_write_time(local);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value());
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto executed = kasumi::application::sync::coordinator::execute(
        runtime_data, storage, key, input, *result);
    ASSERT_TRUE(executed.has_value());
    const auto state_db =
        kasumi::state_storage::load_state(runtime_data.database_path);
    ASSERT_TRUE(state_db.has_value() && *state_db);
    EXPECT_TRUE(kasumi::history::valid_commit_id((*state_db)->commit_id));
    EXPECT_EQ(state->objects.size(), 3U);
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_TRUE(std::filesystem::is_empty(profile / ".transactions"));
}

TEST(SyncCoordinatorTest, AmbiguousPublicationWithoutCommitRollsBack) {
    auto workspace =
        kasumi::test::make_temp_workspace("execute-ambiguous-absent");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    AmbiguousPublicationState* state = nullptr;
    auto storage = make_ambiguous_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    state->fail_marker_put = true;
    auto input = empty_publication_input();
    input.local_tree.rows.front().mtime =
        std::filesystem::last_write_time(local);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value());
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto executed = kasumi::application::sync::coordinator::execute(
        runtime_data, storage, key, input, *result);
    ASSERT_FALSE(executed.has_value()) << executed.error().detail;
    EXPECT_EQ(
        executed.error().code,
        kasumi::application::sync::coordinator::ErrorCode::PublicationFailure);
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_FALSE(std::filesystem::exists(profile / "state.db"));
    EXPECT_TRUE(std::filesystem::is_empty(profile / ".transactions"));
}

TEST(SyncCoordinatorTest, AmbiguousPublicationPreservesRecoveryTransaction) {
    auto workspace =
        kasumi::test::make_temp_workspace("execute-ambiguous-unknown");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    AmbiguousPublicationState* state = nullptr;
    auto storage = make_ambiguous_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    state->fail_marker_put = true;
    state->fail_list_after_marker = true;
    auto input = empty_publication_input();
    input.local_tree.rows.front().mtime =
        std::filesystem::last_write_time(local);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value());
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto executed = kasumi::application::sync::coordinator::execute(
        runtime_data, storage, key, input, *result);
    ASSERT_FALSE(executed.has_value()) << executed.error().detail;
    EXPECT_EQ(
        executed.error().code,
        kasumi::application::sync::coordinator::ErrorCode::PublicationFailure)
        << executed.error().detail;
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_FALSE(std::filesystem::exists(profile / "state.db"));
    EXPECT_TRUE(std::filesystem::is_empty(profile / ".transactions"));
}

TEST(SyncCoordinatorTest, RecoveryWithoutJournalLeavesStateUntouched) {
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-no-journal");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto transactions = profile / ".transactions";
    const auto orphan = transactions / std::string(32, 'a');
    ASSERT_TRUE(std::filesystem::create_directories(orphan));
    kasumi::test::write_text(orphan / "0.backup", "backup");
    ASSERT_TRUE(std::filesystem::create_directories(transactions / "invalid"));
    kasumi::test::write_text(transactions / "plain-file", "keep");
    std::error_code symlink_error;
    std::filesystem::create_symlink(
        orphan, transactions / "unrelated-link", symlink_error);

    kasumi::runtime::RuntimeData runtime_data{
        .local_dir = local,
        .database_path = profile / "state.db",
        .key_path = profile / "key.bin",
        .storage_location =
            kasumi::test::workspace_path(workspace, "storage").string(),
    };
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "storage").string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, storage, key);
    if (!recovered) {
        ADD_FAILURE() << recovered.error().detail;
        return;
    }
    EXPECT_EQ(
        *recovered,
        kasumi::application::sync::coordinator::RecoveryResult::NoJournal);
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_FALSE(std::filesystem::exists(orphan));
    EXPECT_TRUE(std::filesystem::exists(transactions / "invalid"));
    EXPECT_TRUE(std::filesystem::exists(transactions / "plain-file"));
    if (!symlink_error) {
        EXPECT_TRUE(
            std::filesystem::is_symlink(transactions / "unrelated-link"));
    }
}

TEST(SyncCoordinatorTest, ReadOnlyOrphanWorkspaceIsCleanedOnRecovery) {
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-read-only-orphan");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto orphan = profile / ".transactions" / std::string(32, 'd');
    ASSERT_TRUE(std::filesystem::create_directories(orphan));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto staged = orphan / "0.upload.plain";
    kasumi::test::write_text(staged, "staged");
    std::error_code permission_error;
    std::filesystem::permissions(staged,
                                 std::filesystem::perms::owner_write |
                                     std::filesystem::perms::group_write |
                                     std::filesystem::perms::others_write,
                                 std::filesystem::perm_options::remove,
                                 permission_error);
    ASSERT_FALSE(permission_error);

    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    kasumi::transport::Transport unavailable{};
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, unavailable, key);
    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
    EXPECT_EQ(
        *recovered,
        kasumi::application::sync::coordinator::RecoveryResult::NoJournal);
    EXPECT_FALSE(std::filesystem::exists(orphan));
}

TEST(SyncCoordinatorTest, SymlinkOrphanWorkspaceIsRejectedWithoutDeletion) {
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-symlink-orphan");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto transactions = profile / ".transactions";
    const auto outside = kasumi::test::workspace_path(workspace, "outside");
    ASSERT_TRUE(std::filesystem::create_directories(transactions));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    ASSERT_TRUE(std::filesystem::create_directories(outside));
    kasumi::test::write_text(outside / "keep.txt", "keep");
    const auto link = transactions / std::string(32, 'e');
    std::error_code symlink_error;
    std::filesystem::create_directory_symlink(outside, link, symlink_error);
    if (symlink_error) {
#ifdef _WIN32
        constexpr DWORD allow_unprivileged_create = 0x2;
        if (!CreateSymbolicLinkW(link.c_str(),
                                 outside.c_str(),
                                 SYMBOLIC_LINK_FLAG_DIRECTORY |
                                     allow_unprivileged_create)) {
            if (!create_test_junction(link, outside, symlink_error)) {
                GTEST_SKIP() << symlink_error.message();
            }
        }
#else
        GTEST_SKIP() << symlink_error.message();
#endif
    }

    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    kasumi::transport::Transport unavailable{};
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, unavailable, key);
    ASSERT_FALSE(recovered.has_value());
    EXPECT_EQ(
        recovered.error().code,
        kasumi::application::sync::coordinator::ErrorCode::WorkspaceFailure);
    EXPECT_NE(recovered.error().detail.find(link.string()), std::string::npos);
#ifdef _WIN32
    EXPECT_NE(GetFileAttributesW(link.c_str()) & FILE_ATTRIBUTE_REPARSE_POINT,
              0U);
#else
    EXPECT_TRUE(std::filesystem::is_symlink(link));
#endif
    EXPECT_EQ(kasumi::test::read_text(outside / "keep.txt"), "keep");
#ifdef _WIN32
    RemoveDirectoryW(link.c_str());
#else
    std::filesystem::remove(link);
#endif
}

TEST(SyncCoordinatorTest, NestedReparsePointCannotEscapeOrphanWorkspace) {
#ifndef _WIN32
    GTEST_SKIP() << "Windows reparse semantics only";
#else
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-nested-reparse");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto outside = kasumi::test::workspace_path(workspace, "outside");
    const auto orphan = profile / ".transactions" / std::string(32, '7');
    ASSERT_TRUE(std::filesystem::create_directories(orphan));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    ASSERT_TRUE(std::filesystem::create_directories(outside));
    kasumi::test::write_text(outside / "keep.txt", "keep");
    std::error_code junction_error;
    ASSERT_TRUE(
        create_test_junction(orphan / "outside", outside, junction_error))
        << junction_error.message();

    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    kasumi::transport::Transport unavailable{};
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, unavailable, key);
    ASSERT_FALSE(recovered.has_value());
    EXPECT_EQ(
        recovered.error().code,
        kasumi::application::sync::coordinator::ErrorCode::WorkspaceFailure);
    EXPECT_NE(recovered.error().detail.find((orphan / "outside").string()),
              std::string::npos);
    EXPECT_EQ(kasumi::test::read_text(outside / "keep.txt"), "keep");
    RemoveDirectoryW((orphan / "outside").c_str());
#endif
}

TEST(SyncCoordinatorTest, LocalOnlyRecoveryRollsForwardWithoutStorage) {
    auto workspace =
        kasumi::test::make_temp_workspace("local-only-recovery-forward");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const kasumi::runtime::RuntimeData runtime_data{
        .local_dir = local,
        .database_path = profile / "state.db",
        .key_path = profile / "key.bin",
        .storage_location =
            kasumi::test::workspace_path(workspace, "unavailable").string(),
    };
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto transaction_id = save_local_only_recovery_record(
        profile, kasumi::transaction::Phase::LocalChangesApplied, key);
    ASSERT_FALSE(transaction_id.empty());
    kasumi::Snapshot root{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    kasumi::finalize_snapshot(root);
    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        kasumi::state_storage::StoredState{.tree = root,
                                           .height = 0,
                                           .commit_id = std::string(64, 'a'),
                                           .ciphertext_id =
                                               std::string(64, 'c')}));

    kasumi::transport::Transport unavailable{};
    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, unavailable, key);
    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
    EXPECT_EQ(
        *recovered,
        kasumi::application::sync::coordinator::RecoveryResult::RolledForward);
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_FALSE(
        std::filesystem::exists(profile / ".transactions" / transaction_id));
}

TEST(SyncCoordinatorTest, LocalOnlyRecoveryRollsBackWithoutStorage) {
    auto workspace =
        kasumi::test::make_temp_workspace("local-only-recovery-back");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const kasumi::runtime::RuntimeData runtime_data{
        .local_dir = local,
        .database_path = profile / "state.db",
        .key_path = profile / "key.bin",
        .storage_location =
            kasumi::test::workspace_path(workspace, "unavailable").string(),
    };
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto transaction_id = save_local_only_recovery_record(
        profile, kasumi::transaction::Phase::LocalChangesApplied, key);
    ASSERT_FALSE(transaction_id.empty());

    kasumi::transport::Transport unavailable{};
    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, unavailable, key);
    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
    EXPECT_EQ(
        *recovered,
        kasumi::application::sync::coordinator::RecoveryResult::RolledBack);
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_FALSE(
        std::filesystem::exists(profile / ".transactions" / transaction_id));
}

TEST(SyncCoordinatorTest, FailedRepairRollsBackRenameAndNextRecoveryCompletes) {
    auto workspace =
        kasumi::test::make_temp_workspace("repair-rollback-rename");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto runtime_data = make_runtime(profile, local, storage_path);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto head_id = std::string(64, 'a');
    const auto original_hash =
        kasumi::hash_hex(kasumi::hasher::hash_string("original"));
    const auto repair_hash =
        kasumi::hash_hex(kasumi::hasher::hash_string("repair"));
    kasumi::test::write_text(local / "source.txt", "original");

    const auto plan = kasumi::make_sync_plan(
        {kasumi::Operation{.action = kasumi::Action::RenameLocal,
                           .path = "source.txt",
                           .hash = original_hash,
                           .alt_path = "destination.txt",
                           .size = 8,
                           .exclusive_destination = true},
         kasumi::Operation{.action = kasumi::Action::Upload,
                           .path = "repair.txt",
                           .hash = repair_hash,
                           .alt_path = {},
                           .size = 6}},
        0);
    auto record = kasumi::application::sync::journal::create_record(
        0, 0, plan, false, head_id);
    ASSERT_TRUE(record.has_value());
    ASSERT_EQ(record->plan.operations[0].action, kasumi::Action::RenameLocal);
    ASSERT_EQ(record->plan.operations[1].action, kasumi::Action::Upload);
    const auto transaction_root =
        profile / ".transactions" / record->operation_id;
    ASSERT_TRUE(std::filesystem::create_directories(transaction_root));
    const kasumi::platform::Workspace transaction{.root = transaction_root};

    const auto prepared =
        kasumi::application::sync::mutation::prepare_operation(
            record->plan.operations[0],
            0,
            local,
            transaction,
            record->progress[0]);
    ASSERT_TRUE(prepared.has_value()) << prepared.error().detail;
    record->progress[0] = *prepared;
    kasumi::transport::Transport unavailable{};
    ASSERT_TRUE(kasumi::application::sync::mutation::apply_operation(
        record->plan.operations[0], 0, local, unavailable, key, transaction));
    record->progress[0].state = kasumi::transaction::OperationState::Applied;
    record->phase = kasumi::transaction::Phase::FilesStaged;
    const auto paths = kasumi::application::sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    ASSERT_TRUE(kasumi::application::sync::journal::save(*paths, *record, key));

    kasumi::Snapshot target{
        .rows = {
            kasumi::NodeRow{.path = "", .is_directory = true},
            kasumi::NodeRow{.path = "destination.txt",
                            .hash = kasumi::hasher::hash_string("original"),
                            .size = 8},
            kasumi::NodeRow{.path = "repair.txt",
                            .hash = kasumi::hasher::hash_string("repair"),
                            .size = 6}}};
    kasumi::finalize_snapshot(target);
    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        kasumi::state_storage::StoredState{.tree = target,
                                           .height = 0,
                                           .commit_id = head_id,
                                           .ciphertext_id =
                                               std::string(64, 'c')}));
    auto storage = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*storage));

    const auto interrupted =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, *storage, key);
    ASSERT_FALSE(interrupted.has_value());
    EXPECT_EQ(
        interrupted.error().code,
        kasumi::application::sync::coordinator::ErrorCode::MutationFailure);
    EXPECT_EQ(kasumi::test::read_text(local / "source.txt"), "original");
    EXPECT_FALSE(std::filesystem::exists(local / "destination.txt"));
    auto checkpoint = kasumi::application::sync::journal::load(*paths, key);
    ASSERT_TRUE(checkpoint.has_value() && *checkpoint);
    EXPECT_EQ((*checkpoint)->phase, kasumi::transaction::Phase::FilesStaged);
    EXPECT_EQ((*checkpoint)->progress[0].state,
              kasumi::transaction::OperationState::Prepared);
    EXPECT_EQ((*checkpoint)->progress[1].state,
              kasumi::transaction::OperationState::Pending);

    kasumi::test::write_text(local / "repair.txt", "repair");
    const auto resumed =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, *storage, key);
    ASSERT_TRUE(resumed.has_value()) << resumed.error().detail;
    EXPECT_EQ(
        *resumed,
        kasumi::application::sync::coordinator::RecoveryResult::RolledForward);
    EXPECT_FALSE(std::filesystem::exists(local / "source.txt"));
    EXPECT_EQ(kasumi::test::read_text(local / "destination.txt"), "original");
    EXPECT_EQ(kasumi::transport::presence(*storage,
                                          remote_content_id(key, repair_hash))
                  .value(),
              kasumi::transport::Presence::Present);
    EXPECT_FALSE(std::filesystem::exists(paths->final_path));
    EXPECT_FALSE(std::filesystem::exists(transaction_root));
}

TEST(SyncCoordinatorTest, LocalOnlyRecoveryRepeatsPresentRepairBeforeApplied) {
    auto workspace =
        kasumi::test::make_temp_workspace("local-only-pending-repair");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile / ".transactions"));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "unavailable"));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    kasumi::test::write_text(local / "repair.txt", "repair");

    const auto content_hash =
        kasumi::hash_hex(kasumi::hasher::hash_string("repair"));
    const auto plan = kasumi::make_sync_plan(
        {kasumi::Operation{.action = kasumi::Action::Upload,
                           .path = "repair.txt",
                           .hash = content_hash,
                           .alt_path = {},
                           .size = 6}},
        0);
    auto record = kasumi::application::sync::journal::create_record(
        0, 0, plan, false, std::string(64, 'a'));
    ASSERT_TRUE(record.has_value());
    const auto paths = kasumi::application::sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    ASSERT_TRUE(kasumi::application::sync::journal::save(*paths, *record, key));
    const auto transaction_root =
        profile / ".transactions" / record->operation_id;
    ASSERT_TRUE(std::filesystem::create_directories(transaction_root));

    kasumi::Snapshot tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true},
                 kasumi::NodeRow{.path = "repair.txt",
                                 .hash = kasumi::hasher::hash_string("repair"),
                                 .size = 6,
                                 .is_directory = false}}};
    kasumi::finalize_snapshot(tree);
    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        kasumi::state_storage::StoredState{.tree = tree,
                                           .height = 0,
                                           .commit_id = std::string(64, 'a'),
                                           .ciphertext_id =
                                               std::string(64, 'c')}));

    AmbiguousPublicationState* state = nullptr;
    auto storage = make_ambiguous_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    const auto encrypted =
        kasumi::test::workspace_path(workspace, "repair.enc");
    ASSERT_TRUE(
        kasumi::crypto::encrypt_file(local / "repair.txt", encrypted, key));
    ASSERT_TRUE(kasumi::transport::put(
        storage, encrypted, remote_content_id(key, content_hash)));
    std::error_code remove_error;
    std::filesystem::remove(encrypted, remove_error);
    ASSERT_FALSE(remove_error);
    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, storage, key);
    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
    EXPECT_EQ(
        *recovered,
        kasumi::application::sync::coordinator::RecoveryResult::RolledForward);
    EXPECT_EQ(state->put_count, 3U);
    EXPECT_EQ(state->get_count, 2U);
    EXPECT_EQ(kasumi::transport::presence(storage,
                                          remote_content_id(key, content_hash))
                  .value(),
              kasumi::transport::Presence::Present);
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_FALSE(std::filesystem::exists(transaction_root));
}

TEST(SyncCoordinatorTest, FailedRepairRemainsDurableAcrossRecoveryAttempts) {
    auto workspace =
        kasumi::test::make_temp_workspace("durable-repair-recovery");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    kasumi::test::write_text(local / "alpha.txt", "alpha");

    const auto head_id = std::string(64, 'a');
    const auto content_hash = kasumi::hasher::hash_string("alpha");
    const auto content_id = kasumi::hash_hex(content_hash);
    kasumi::Snapshot tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true},
                 kasumi::NodeRow{.path = "alpha.txt",
                                 .hash = content_hash,
                                 .size = 5,
                                 .is_directory = false}}};
    kasumi::finalize_snapshot(tree);

    auto input = empty_publication_input();
    input.local_tree = tree;
    input.base_tree = tree;
    input.storage.history_present = true;
    input.storage.tree = tree;
    input.storage.logical_heads = {head_id};
    input.storage.reachable_commits = {kasumi::history::LoadedCommit{
        .id = head_id,
        .commit =
            kasumi::history::Commit{.height = 0, .parents = {}, .tree = tree}}};
    input.audit_storage_objects = true;

    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        kasumi::state_storage::StoredState{.tree = tree,
                                           .height = 0,
                                           .commit_id = head_id,
                                           .ciphertext_id =
                                               std::string(64, 'c')}));

    AmbiguousPublicationState* state = nullptr;
    auto storage = make_ambiguous_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    const auto count_objects = [&](std::string_view prefix) {
        return std::ranges::count_if(state->objects, [&](const auto& entry) {
            return entry.first.starts_with(prefix);
        });
    };
    const auto commits_before = count_objects("history/commits/");
    const auto markers_before = count_objects("history/heads/");
    state->upload_corruption =
        AmbiguousPublicationState::UploadCorruption::Truncated;
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_TRUE(result->requires_storage_repair);
    ASSERT_FALSE(result->requires_publication);

    const auto first = kasumi::application::sync::coordinator::execute(
        runtime_data, storage, key, input, *result);
    ASSERT_FALSE(first.has_value());
    EXPECT_EQ(
        first.error().code,
        kasumi::application::sync::coordinator::ErrorCode::MutationFailure);

    const auto paths = kasumi::application::sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    auto record = kasumi::application::sync::journal::load(*paths, key);
    ASSERT_TRUE(record.has_value());
    ASSERT_TRUE(record->has_value());
    const auto transaction_id = (*record)->operation_id;
    const auto transaction_root = profile / ".transactions" / transaction_id;
    EXPECT_TRUE(std::filesystem::exists(transaction_root));
    EXPECT_TRUE(
        std::ranges::any_of((*record)->progress, [](const auto& progress) {
            return progress.state <
                   kasumi::transaction::OperationState::Applied;
        }));
    EXPECT_EQ(
        kasumi::transport::presence(storage, remote_content_id(key, content_id))
            .value(),
        kasumi::transport::Presence::Present);

    const auto second =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, storage, key);
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(
        second.error().code,
        kasumi::application::sync::coordinator::ErrorCode::MutationFailure);
    EXPECT_TRUE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_TRUE(std::filesystem::exists(transaction_root));
    EXPECT_EQ(
        kasumi::transport::presence(storage, remote_content_id(key, content_id))
            .value(),
        kasumi::transport::Presence::Present);

    state->upload_corruption =
        AmbiguousPublicationState::UploadCorruption::None;
    const auto third =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, storage, key);
    ASSERT_TRUE(third.has_value()) << third.error().detail;
    EXPECT_EQ(
        *third,
        kasumi::application::sync::coordinator::RecoveryResult::RolledForward);
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_FALSE(std::filesystem::exists(transaction_root));
    EXPECT_EQ(state->put_count, 5U);
    EXPECT_EQ(state->get_count, 5U);
    EXPECT_TRUE(std::ranges::none_of(state->objects, [](const auto& entry) {
        return entry.first.starts_with("history/");
    }));
    EXPECT_EQ(count_objects("history/commits/"), commits_before);
    EXPECT_EQ(count_objects("history/heads/"), markers_before);
    EXPECT_EQ(input.storage.logical_heads, std::vector<std::string>{head_id});
    auto final_state =
        kasumi::state_storage::load_state(runtime_data.database_path);
    ASSERT_TRUE(final_state.has_value());
    ASSERT_TRUE(final_state->has_value());
    EXPECT_EQ((*final_state)->commit_id, head_id);
    EXPECT_EQ((*final_state)->height, 0U);
}

TEST(SyncCoordinatorTest, DurableRepairKeepsARealHistoryHead) {
    auto workspace =
        kasumi::test::make_temp_workspace("real-history-durable-repair");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto real_storage_path =
        kasumi::test::workspace_path(workspace, "real-storage");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    kasumi::test::write_text(local / "alpha.txt", "alpha");
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    kasumi::Snapshot tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true},
                 kasumi::NodeRow{.path = "alpha.txt",
                                 .hash = kasumi::hasher::hash_string("alpha"),
                                 .size = 5,
                                 .is_directory = false}}};
    kasumi::finalize_snapshot(tree);
    auto real_storage =
        kasumi::transport::open_transport(real_storage_path.string());
    ASSERT_TRUE(real_storage.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*real_storage));
    const auto content_id =
        kasumi::hash_hex(kasumi::hasher::hash_string("alpha"));
    const auto encrypted = kasumi::test::workspace_path(workspace, "alpha.enc");
    ASSERT_TRUE(
        kasumi::crypto::encrypt_file(local / "alpha.txt", encrypted, key));
    ASSERT_TRUE(kasumi::transport::put(
        *real_storage, encrypted, remote_content_id(key, content_id)));
    auto prepared = kasumi::application::sync::publication::prepare_commit(
        tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared.has_value());
    auto published = kasumi::application::sync::publication::publish_commit(
        *real_storage, key, *prepared, local);
    ASSERT_TRUE(published.has_value());

    AmbiguousPublicationState* state = nullptr;
    auto storage = make_ambiguous_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    const auto copied = kasumi::test::workspace_path(workspace, "copied");
    ASSERT_TRUE(std::filesystem::create_directories(copied));
    auto listing = kasumi::transport::list(*real_storage);
    ASSERT_TRUE(listing.has_value());
    for (std::size_t index = 0; index < listing->size(); ++index) {
        const auto object = copied / std::to_string(index);
        ASSERT_TRUE(
            kasumi::transport::get(*real_storage, (*listing)[index], object));
        std::ifstream input(object, std::ios::binary | std::ios::ate);
        ASSERT_TRUE(input);
        const auto size = input.tellg();
        ASSERT_GE(size, std::streampos{0});
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
        input.seekg(0, std::ios::beg);
        input.read(reinterpret_cast<char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
        ASSERT_TRUE(input || bytes.empty());
        state->objects[(*listing)[index]] = std::move(bytes);
    }
    const auto remote_id = remote_content_id(key, content_id);
    ASSERT_TRUE(state->objects.contains(remote_id));
    state->objects.erase(remote_id);

    ASSERT_TRUE(std::filesystem::create_directories(
        kasumi::test::workspace_path(workspace, "real-history")));
    const auto real_history =
        kasumi::application::history_storage::load_history(
            *real_storage,
            key,
            kasumi::test::workspace_path(workspace, "real-history"));
    ASSERT_TRUE(real_history.has_value()) << real_history.error().detail;
    ASSERT_EQ(real_history->marked_heads,
              std::vector<std::string>{prepared->commit_id});
    const auto before = kasumi::transport::list(storage);
    ASSERT_TRUE(before.has_value());

    auto input = empty_publication_input();
    input.local_tree = tree;
    input.base_tree = tree;
    input.storage.tree = tree;
    for (const auto& [identifier, bytes] : state->objects) {
        static_cast<void>(bytes);
        input.storage.object_identifiers.insert(identifier);
    }
    input.storage.object_identifiers.erase(content_id);
    input.storage.reachable_commits = {kasumi::history::LoadedCommit{
        .id = prepared->commit_id, .commit = prepared->commit}};
    input.storage.reachable_commit_ids = {prepared->commit_id};
    input.storage.marked_heads = {prepared->commit_id};
    input.storage.logical_heads = {prepared->commit_id};
    input.storage.generation = 0;
    input.storage.history_present = true;
    input.audit_storage_objects = true;
    ASSERT_TRUE(kasumi::state_storage::initialize(profile / "state.db"));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        profile / "state.db",
        kasumi::state_storage::StoredState{.tree = tree,
                                           .height = 0,
                                           .commit_id = prepared->commit_id,
                                           .ciphertext_id =
                                               std::string(64, 'c')}));

    state->upload_corruption =
        AmbiguousPublicationState::UploadCorruption::Truncated;
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_FALSE(result->requires_publication);
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "unused"));
    ASSERT_FALSE(kasumi::application::sync::coordinator::execute(
                     runtime_data, storage, key, input, *result)
                     .has_value());
    const auto paths = kasumi::application::sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    auto pending = kasumi::application::sync::journal::load(*paths, key);
    ASSERT_TRUE(pending.has_value() && *pending);
    const auto transaction_root =
        profile / ".transactions" / (*pending)->operation_id;
    EXPECT_TRUE(std::filesystem::exists(transaction_root));

    ASSERT_FALSE(kasumi::application::sync::coordinator::recover_if_needed(
                     runtime_data, storage, key)
                     .has_value());
    state->upload_corruption =
        AmbiguousPublicationState::UploadCorruption::None;
    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, storage, key);
    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;

    auto after = kasumi::transport::list(storage);
    ASSERT_TRUE(after.has_value());
    const auto count = [](const auto& values, std::string_view prefix) {
        return std::ranges::count_if(values, [&](const auto& value) {
            return value.starts_with(prefix);
        });
    };
    EXPECT_EQ(count(*before, "history/commits/"),
              count(*after, "history/commits/"));
    EXPECT_EQ(count(*before, "history/heads/"),
              count(*after, "history/heads/"));
    ASSERT_TRUE(std::filesystem::create_directories(
        kasumi::test::workspace_path(workspace, "after-history")));
    const auto after_history =
        kasumi::application::history_storage::load_history(
            storage,
            key,
            kasumi::test::workspace_path(workspace, "after-history"));
    ASSERT_TRUE(after_history.has_value()) << after_history.error().detail;
    EXPECT_EQ(after_history->marked_heads, real_history->marked_heads);
    EXPECT_FALSE(std::filesystem::exists(paths->final_path));
    EXPECT_FALSE(std::filesystem::exists(transaction_root));
}

TEST(SyncCoordinatorTest,
     LogicalCheckpointCrashStatesRollbackWithoutPublicationOrLocalChange) {
    const std::array cases{
        std::pair{kasumi::transaction::Phase::Started,
                  kasumi::transaction::OperationState::Pending},
        std::pair{kasumi::transaction::Phase::FilesStaged,
                  kasumi::transaction::OperationState::Prepared},
        std::pair{kasumi::transaction::Phase::LocalChangesApplied,
                  kasumi::transaction::OperationState::Applied},
    };
    for (const auto& [phase, operation_state] : cases) {
        SCOPED_TRACE(static_cast<int>(phase));
        auto workspace = kasumi::test::make_temp_workspace(
            "logical-checkpoint-crash-" +
            std::to_string(static_cast<int>(phase)));
        const auto profile = kasumi::test::workspace_path(workspace, "profile");
        const auto local = kasumi::test::workspace_path(workspace, "local");
        const auto storage_path =
            kasumi::test::workspace_path(workspace, "storage");
        ASSERT_TRUE(std::filesystem::create_directories(profile));
        ASSERT_TRUE(std::filesystem::create_directories(local));
        kasumi::test::write_text(local / "untouched.txt", "untouched");
        auto storage = kasumi::transport::open_transport(storage_path.string());
        ASSERT_TRUE(storage.has_value());
        ASSERT_TRUE(kasumi::transport::initialize(*storage));
        const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

        std::vector<kasumi::Operation> operations;
        for (std::size_t index = 0; index < 100; ++index) {
            operations.push_back(
                {.action = kasumi::Action::DeleteRemote,
                 .path = "remote-" + std::to_string(index) + ".bin",
                 .hash = {},
                 .alt_path = {},
                 .size = 0,
                 .exclusive_destination = false});
        }
        auto record = kasumi::application::sync::journal::create_record(
            0, 0, kasumi::make_sync_plan(std::move(operations), 1));
        ASSERT_TRUE(record.has_value()) << record.error();
        record->phase = phase;
        for (auto& progress : record->progress) {
            progress.state = operation_state;
        }
        const auto paths =
            kasumi::application::sync::journal::make_paths(profile);
        ASSERT_TRUE(paths.has_value()) << paths.error();
        ASSERT_TRUE(
            kasumi::application::sync::journal::save(*paths, *record, key));
        const auto transaction_root =
            profile / ".transactions" / record->operation_id;
        ASSERT_TRUE(std::filesystem::create_directories(transaction_root));

        const auto recovered =
            kasumi::application::sync::coordinator::recover_if_needed(
                make_runtime(profile, local, storage_path), *storage, key);
        ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
        EXPECT_EQ(
            *recovered,
            kasumi::application::sync::coordinator::RecoveryResult::RolledBack);
        EXPECT_TRUE(std::filesystem::is_regular_file(local / "untouched.txt"));
        EXPECT_EQ(std::filesystem::file_size(local / "untouched.txt"), 9U);
        EXPECT_FALSE(std::filesystem::exists(paths->final_path));
        EXPECT_FALSE(std::filesystem::exists(transaction_root));
        const auto remote_objects = kasumi::transport::list(*storage);
        ASSERT_TRUE(remote_objects.has_value());
        EXPECT_TRUE(remote_objects->empty());
    }
}

TEST(SyncCoordinatorTest,
     CleanupCompletedRecoveryFinalizesWithoutRemoteObservation) {
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-markers-pruned");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto transaction_id = std::string(32, 'c');
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto transaction_root = profile / ".transactions" / transaction_id;
    ASSERT_TRUE(std::filesystem::create_directories(transaction_root));

    const kasumi::runtime::RuntimeData runtime_data{
        .local_dir = local,
        .database_path = profile / "state.db",
        .key_path = profile / "key.bin",
        .storage_location =
            kasumi::test::workspace_path(workspace, "storage").string(),
    };
    const auto paths = kasumi::application::sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    auto record = kasumi::application::sync::journal::create_record(
        0, 0, kasumi::make_sync_plan({}, 0));
    ASSERT_TRUE(record.has_value());
    record->operation_id = transaction_id;
    record->phase = kasumi::transaction::Phase::CleanupCompleted;
    record->commit_id = std::string(64, 'a');
    record->ciphertext_id = std::string(64, 'b');
    record->marker_id = kasumi::application::history_storage::marker_identifier(
        {.commit_id = record->commit_id,
         .ciphertext_id = record->ciphertext_id});
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    static_cast<void>(set_test_genesis_epoch(*record, key));
    ASSERT_TRUE(kasumi::application::sync::journal::save(*paths, *record, key));

    kasumi::transport::Transport unavailable{};
    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, unavailable, key);
    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
    EXPECT_EQ(
        *recovered,
        kasumi::application::sync::coordinator::RecoveryResult::RolledForward);
    EXPECT_FALSE(std::filesystem::exists(paths->final_path));
    EXPECT_FALSE(std::filesystem::exists(transaction_root));
}

TEST(SyncCoordinatorTest,
     CleanupCompletedWithMissingWorkspaceClearsTerminalJournal) {
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-cleanup-missing");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto id = save_recovery_record(
        profile, kasumi::transaction::Phase::CleanupCompleted, key);
    ASSERT_FALSE(id.empty());
    const auto transaction_root = profile / ".transactions" / id;
    ASSERT_TRUE(std::filesystem::remove(transaction_root));
    const auto paths = kasumi::application::sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());

    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    kasumi::transport::Transport unavailable{};
    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, unavailable, key);
    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
    EXPECT_EQ(
        *recovered,
        kasumi::application::sync::coordinator::RecoveryResult::RolledForward);
    EXPECT_FALSE(std::filesystem::exists(paths->final_path));
}

TEST(SyncCoordinatorTest,
     LockedTerminalWorkspacePreservesJournalAndReportsPhysicalPath) {
#ifndef _WIN32
    GTEST_SKIP() << "Windows sharing semantics only";
#else
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-locked-terminal");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto id = save_recovery_record(
        profile, kasumi::transaction::Phase::CleanupCompleted, key);
    ASSERT_FALSE(id.empty());
    const auto transaction_root = profile / ".transactions" / id;
    const auto staged = transaction_root / "0.upload.plain";
    kasumi::test::write_text(staged, "locked");
    const auto handle = CreateFileW(staged.c_str(),
                                    GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    ASSERT_NE(handle, INVALID_HANDLE_VALUE);
    const auto paths = kasumi::application::sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    kasumi::transport::Transport unavailable{};

    const auto first =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, unavailable, key);
    EXPECT_FALSE(first.has_value());
    if (!first) {
        EXPECT_EQ(first.error().code,
                  kasumi::application::sync::coordinator::ErrorCode::
                      WorkspaceFailure);
        EXPECT_NE(first.error().detail.find("remover o espaço de trabalho da transação"),
                  std::string::npos);
        EXPECT_NE(first.error().detail.find(transaction_root.string()),
                  std::string::npos);
    }
    EXPECT_TRUE(std::filesystem::exists(paths->final_path));
    EXPECT_TRUE(std::filesystem::exists(transaction_root));
    EXPECT_TRUE(CloseHandle(handle));

    const auto second =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, unavailable, key);
    ASSERT_TRUE(second.has_value()) << second.error().detail;
    EXPECT_FALSE(std::filesystem::exists(paths->final_path));
    EXPECT_FALSE(std::filesystem::exists(transaction_root));
#endif
}

TEST(SyncCoordinatorTest,
     LockedRollbackPersistsResetCheckpointBeforeWorkspaceCleanup) {
#ifndef _WIN32
    GTEST_SKIP() << "Windows sharing semantics only";
#else
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-locked-rollback");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto id =
        save_recovery_record(profile, kasumi::transaction::Phase::Started, key);
    ASSERT_FALSE(id.empty());
    const auto transaction_root = profile / ".transactions" / id;
    const auto staged = transaction_root / "0.upload.plain";
    kasumi::test::write_text(staged, "locked");
    const auto handle = CreateFileW(staged.c_str(),
                                    GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    ASSERT_NE(handle, INVALID_HANDLE_VALUE);
    const auto paths = kasumi::application::sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    kasumi::transport::Transport unavailable{};

    const auto first =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, unavailable, key);
    EXPECT_FALSE(first.has_value());
    auto checkpoint = kasumi::application::sync::journal::load(*paths, key);
    ASSERT_TRUE(checkpoint.has_value() && *checkpoint);
    EXPECT_EQ((*checkpoint)->phase, kasumi::transaction::Phase::Started);
    EXPECT_TRUE(std::filesystem::exists(transaction_root));
    EXPECT_TRUE(CloseHandle(handle));

    const auto second =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, unavailable, key);
    ASSERT_TRUE(second.has_value()) << second.error().detail;
    EXPECT_EQ(
        *second,
        kasumi::application::sync::coordinator::RecoveryResult::RolledBack);
    EXPECT_FALSE(std::filesystem::exists(paths->final_path));
    EXPECT_FALSE(std::filesystem::exists(transaction_root));
#endif
}

TEST(SyncCoordinatorTest, TransientOrphanSharingViolationIsRetried) {
#ifndef _WIN32
    GTEST_SKIP() << "Windows sharing semantics only";
#else
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-transient-lock");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto orphan = profile / ".transactions" / std::string(32, 'f');
    ASSERT_TRUE(std::filesystem::create_directories(orphan));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto staged = orphan / "0.upload.plain";
    kasumi::test::write_text(staged, "locked");
    const auto handle = CreateFileW(staged.c_str(),
                                    GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    ASSERT_NE(handle, INVALID_HANDLE_VALUE);
    std::thread release_handle([handle] {
        std::this_thread::sleep_for(std::chrono::milliseconds{15});
        CloseHandle(handle);
    });
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    kasumi::transport::Transport unavailable{};
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, unavailable, key);
    release_handle.join();

    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
    EXPECT_FALSE(std::filesystem::exists(orphan));
#endif
}

TEST(SyncCoordinatorTest, LockedOrphanFailsExplicitlyAndNextRecoverySucceeds) {
#ifndef _WIN32
    GTEST_SKIP() << "Windows sharing semantics only";
#else
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-locked-orphan");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto orphan = profile / ".transactions" / std::string(32, '9');
    ASSERT_TRUE(std::filesystem::create_directories(orphan));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto staged = orphan / "0.upload.plain";
    kasumi::test::write_text(staged, "locked");
    const auto handle = CreateFileW(staged.c_str(),
                                    GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    ASSERT_NE(handle, INVALID_HANDLE_VALUE);
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    kasumi::transport::Transport unavailable{};
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto first =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, unavailable, key);
    ASSERT_FALSE(first.has_value());
    EXPECT_EQ(
        first.error().code,
        kasumi::application::sync::coordinator::ErrorCode::WorkspaceFailure);
    EXPECT_NE(first.error().detail.find(orphan.string()), std::string::npos);
    EXPECT_TRUE(std::filesystem::exists(orphan));
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_TRUE(CloseHandle(handle));

    const auto second =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, unavailable, key);
    ASSERT_TRUE(second.has_value()) << second.error().detail;
    EXPECT_FALSE(std::filesystem::exists(orphan));
#endif
}

TEST(SyncCoordinatorTest, InvalidJournalIsRejectedBeforeMutation) {
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-invalid-journal");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    const kasumi::runtime::RuntimeData runtime_data{
        .local_dir = kasumi::test::workspace_path(workspace, "local"),
        .database_path = profile / "state.db",
        .key_path = profile / "key.bin",
        .storage_location =
            kasumi::test::workspace_path(workspace, "storage").string(),
    };
    ASSERT_TRUE(std::filesystem::create_directories(runtime_data.local_dir));
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "storage").string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto paths = kasumi::application::sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    kasumi::test::write_binary(paths->final_path, {std::byte{0x01}});

    const auto result =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, storage, key);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(
        result.error().code,
        kasumi::application::sync::coordinator::ErrorCode::JournalFailure);
}

TEST(SyncCoordinatorTest, StartedTransactionRollsBackBeforePublication) {
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-before-publication");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    const kasumi::runtime::RuntimeData runtime_data{
        .local_dir = kasumi::test::workspace_path(workspace, "local"),
        .database_path = profile / "state.db",
        .key_path = profile / "key.bin",
        .storage_location =
            kasumi::test::workspace_path(workspace, "storage").string(),
    };
    ASSERT_TRUE(std::filesystem::create_directories(runtime_data.local_dir));
    const auto document = runtime_data.local_dir / "document.txt";
    kasumi::test::write_text(document, "before-transaction");

    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "storage").string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const kasumi::Operation operation{
        .action = kasumi::Action::DeleteLocal,
        .path = "document.txt",
        .hash = {},
        .alt_path = {},
        .size = 0,
        .exclusive_destination = false,
    };
    auto record = kasumi::application::sync::journal::create_record(
        0, 0, kasumi::make_sync_plan({operation}, 1));
    ASSERT_TRUE(record.has_value());
    ASSERT_EQ(record->plan.operations.size(), 1U);
    ASSERT_EQ(record->progress.size(), 1U);
    EXPECT_NE(record->progress[0].backup_slot,
              std::numeric_limits<std::uint32_t>::max());

    const auto transaction_root =
        profile / ".transactions" / record->operation_id;
    ASSERT_TRUE(std::filesystem::create_directories(transaction_root));
    const kasumi::platform::Workspace transaction_workspace{
        .root = transaction_root};

    auto prepared = kasumi::application::sync::mutation::prepare_operation(
        record->plan.operations[0],
        0,
        runtime_data.local_dir,
        transaction_workspace,
        record->progress[0]);
    ASSERT_TRUE(prepared.has_value());
    record->progress[0] = *prepared;
    EXPECT_TRUE(record->progress[0].had_original);
    EXPECT_FALSE(record->progress[0].previous_hash.empty());
    EXPECT_EQ(record->progress[0].state,
              kasumi::transaction::OperationState::BackupCreated);

    auto applied = kasumi::application::sync::mutation::apply_operation(
        record->plan.operations[0],
        0,
        runtime_data.local_dir,
        storage,
        key,
        transaction_workspace);
    ASSERT_TRUE(applied.has_value());
    record->progress[0].state = kasumi::transaction::OperationState::Applied;
    record->phase = kasumi::transaction::Phase::LocalChangesApplied;
    EXPECT_FALSE(std::filesystem::exists(document));
    EXPECT_TRUE(
        std::filesystem::exists(transaction_workspace.root / "0.backup"));

    const auto paths = kasumi::application::sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    ASSERT_TRUE(kasumi::application::sync::journal::save(*paths, *record, key));
    const auto result =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, storage, key);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(
        *result,
        kasumi::application::sync::coordinator::RecoveryResult::RolledBack);
    EXPECT_TRUE(std::filesystem::exists(document));
    EXPECT_EQ(kasumi::test::read_text(document), "before-transaction");
    const auto loaded = kasumi::application::sync::journal::load(*paths, key);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_FALSE(*loaded);
    EXPECT_FALSE(std::filesystem::exists(transaction_root));
}

TEST(SyncCoordinatorTest, StartedPhaseRollsBackWithoutRemoteAccess) {
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-started-phase");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto id =
        save_recovery_record(profile, kasumi::transaction::Phase::Started, key);
    ASSERT_FALSE(id.empty());

    kasumi::transport::Transport unavailable{};
    const auto result =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, unavailable, key);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(
        *result,
        kasumi::application::sync::coordinator::RecoveryResult::RolledBack);
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_FALSE(std::filesystem::exists(profile / ".transactions" / id));
}

TEST(SyncCoordinatorTest, FilesStagedPhaseRollsBackWithoutRemoteAccess) {
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-files-staged-phase");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto id = save_recovery_record(
        profile, kasumi::transaction::Phase::FilesStaged, key);
    ASSERT_FALSE(id.empty());

    kasumi::transport::Transport unavailable{};
    const auto result =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, unavailable, key);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(
        *result,
        kasumi::application::sync::coordinator::RecoveryResult::RolledBack);
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_FALSE(std::filesystem::exists(profile / ".transactions" / id));
}

TEST(SyncCoordinatorTest, CommitPreparedAbsenceRollsBack) {
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-prepared-absent");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    const auto runtime_data = make_runtime(profile, local, storage_path);
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto id = save_recovery_record(
        profile, kasumi::transaction::Phase::CommitPrepared, key);
    ASSERT_FALSE(id.empty());
    auto opened = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(opened.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*opened));

    const auto result =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, *opened, key);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(
        *result,
        kasumi::application::sync::coordinator::RecoveryResult::RolledBack);
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_FALSE(std::filesystem::exists(profile / ".transactions" / id));
}

TEST(SyncCoordinatorTest, CommitPreparedInspectionFailurePreservesTransaction) {
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-prepared-unknown");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto id = save_recovery_record(
        profile, kasumi::transaction::Phase::CommitPrepared, key);
    ASSERT_FALSE(id.empty());

    kasumi::transport::Transport unavailable{};
    const auto result =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, unavailable, key);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(
        *result,
        kasumi::application::sync::coordinator::RecoveryResult::RolledBack);
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_FALSE(std::filesystem::exists(profile / ".transactions" / id));
}

TEST(SyncCoordinatorTest, CommitUploadedAbsenceRollsBack) {
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-published-absent");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    const auto runtime_data = make_runtime(profile, local, storage_path);
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto id = save_recovery_record(
        profile, kasumi::transaction::Phase::CommitUploaded, key);
    ASSERT_FALSE(id.empty());
    auto opened = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(opened.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*opened));

    const auto result =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, *opened, key);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(
        *result,
        kasumi::application::sync::coordinator::RecoveryResult::RolledBack);
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_FALSE(std::filesystem::exists(profile / ".transactions" / id));
    EXPECT_FALSE(std::filesystem::exists(profile / "state.db"));
}

TEST(SyncCoordinatorTest, DatabaseCommittedAbsencePreservesTransaction) {
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-database-absent");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    const auto runtime_data = make_runtime(profile, local, storage_path);
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto id = save_recovery_record(
        profile, kasumi::transaction::Phase::DatabaseCommitted, key);
    ASSERT_FALSE(id.empty());
    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    auto opened = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(opened.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*opened));

    const auto result =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, *opened, key);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(
        result.error().code,
        kasumi::application::sync::coordinator::ErrorCode::RecoveryConflict);
    EXPECT_TRUE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_TRUE(std::filesystem::exists(profile / ".transactions" / id));
    const auto loaded =
        kasumi::state_storage::load_state(runtime_data.database_path);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_FALSE(*loaded);
}

TEST(SyncCoordinatorTest, CommitPreparedReachabilityPersistsPublishedPhase) {
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-prepared-published");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    auto runtime_data = make_runtime(profile, local, storage_path);
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const kasumi::Snapshot tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    auto prepared = kasumi::application::sync::publication::prepare_commit(
        tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared.has_value());
    auto opened = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(opened.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*opened));
    auto published = kasumi::application::sync::publication::publish_commit(
        *opened, key, *prepared, local);
    ASSERT_TRUE(published.has_value());
    const auto id =
        save_recovery_record(profile,
                             kasumi::transaction::Phase::CommitUploaded,
                             key,
                             prepared->commit_id,
                             published->head.ciphertext_id);
    ASSERT_FALSE(id.empty());
    std::filesystem::create_directory(profile / "state.db");

    const auto result =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, *opened, key);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(
        result.error().code,
        kasumi::application::sync::coordinator::ErrorCode::DatabaseFailure);
    const auto paths = kasumi::application::sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    const auto loaded = kasumi::application::sync::journal::load(*paths, key);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_EQ((*loaded)->phase, kasumi::transaction::Phase::EpochVerified);
    EXPECT_TRUE(std::filesystem::exists(profile / ".transactions" / id));
}

TEST(SyncCoordinatorTest, DatabaseCommittedRecoveryKeepsStateDatabaseBytes) {
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-database-no-rewrite");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    const auto runtime_data = make_runtime(profile, local, storage_path);
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const kasumi::Snapshot tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    auto prepared = kasumi::application::sync::publication::prepare_commit(
        tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared.has_value());
    auto opened = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(opened.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*opened));
    auto published = kasumi::application::sync::publication::publish_commit(
        *opened, key, *prepared, local);
    ASSERT_TRUE(published.has_value());
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        {.tree = tree,
         .height = prepared->commit.height,
         .commit_id = prepared->commit_id,
         .ciphertext_id = std::string(64, 'c')}));
    const auto before = kasumi::test::read_binary(runtime_data.database_path);
    const auto id =
        save_recovery_record(profile,
                             kasumi::transaction::Phase::DatabaseCommitted,
                             key,
                             prepared->commit_id,
                             published->head.ciphertext_id);
    ASSERT_FALSE(id.empty());

    const auto result =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, *opened, key);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(
        *result,
        kasumi::application::sync::coordinator::RecoveryResult::RolledForward);
    EXPECT_EQ(kasumi::test::read_binary(runtime_data.database_path), before);
}

TEST(SyncCoordinatorTest,
     CrashBetweenEveryPublicationCheckpointRecoversDeterministically) {
    const std::array phases{
        kasumi::transaction::Phase::CommitPrepared,
        kasumi::transaction::Phase::CommitUploaded,
        kasumi::transaction::Phase::CommitVerified,
        kasumi::transaction::Phase::HeadPublished,
        kasumi::transaction::Phase::HeadVerified,
        kasumi::transaction::Phase::EpochPrepared,
        kasumi::transaction::Phase::EpochUploaded,
        kasumi::transaction::Phase::EpochVerified,
        kasumi::transaction::Phase::DatabaseCommitted,
        kasumi::transaction::Phase::CleanupCompleted,
    };
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    for (const auto phase : phases) {
        auto workspace =
            kasumi::test::make_temp_workspace("publication-checkpoint-crash");
        const auto profile = kasumi::test::workspace_path(workspace, "profile");
        const auto local = kasumi::test::workspace_path(workspace, "local");
        ASSERT_TRUE(std::filesystem::create_directories(profile));
        ASSERT_TRUE(std::filesystem::create_directories(local));
        const auto runtime_data = make_runtime(
            profile, local, kasumi::test::workspace_path(workspace, "storage"));
        const kasumi::Snapshot tree{
            .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
        auto prepared = kasumi::application::sync::publication::prepare_commit(
            tree, false, 0, {}, 100, key);
        ASSERT_TRUE(prepared.has_value());

        AmbiguousPublicationState* remote = nullptr;
        auto storage = make_ambiguous_transport(remote);
        ASSERT_TRUE(kasumi::transport::initialize(storage));
        std::string ciphertext_id;
        if (phase >= kasumi::transaction::Phase::CommitUploaded) {
            auto object =
                kasumi::application::sync::publication::publish_commit_object(
                    storage, key, *prepared, local);
            ASSERT_TRUE(object.has_value()) << object.error().detail;
            ciphertext_id = object->head.ciphertext_id;
            if (phase >= kasumi::transaction::Phase::CommitVerified) {
                ASSERT_TRUE(
                    kasumi::application::sync::publication::
                        verify_commit_object(
                            storage, key, *prepared, object->head, local));
            }
            if (phase >= kasumi::transaction::Phase::HeadPublished) {
                auto marker =
                    kasumi::application::sync::publication::publish_head_marker(
                        storage, object->head, local);
                ASSERT_TRUE(marker.has_value()) << marker.error().detail;
                if (phase >= kasumi::transaction::Phase::HeadVerified) {
                    ASSERT_TRUE(
                        kasumi::application::sync::publication::
                            verify_head_marker(storage, object->head, local));
                }
            }
        }
        kasumi::transaction::Record epoch_record;
        epoch_record.commit_id = prepared->commit_id;
        const auto genesis_epoch = set_test_genesis_epoch(epoch_record, key);
        if (phase >= kasumi::transaction::Phase::EpochUploaded) {
            ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
                storage, genesis_epoch, local));
        }
        if (phase >= kasumi::transaction::Phase::EpochVerified) {
            const auto expected =
                kasumi::application::history_storage::epoch::Epoch{
                    .vault_id = epoch_record.epoch_vault_id,
                    .sequence = 0,
                    .issued_at = epoch_record.epoch_issued_at,
                    .policy = {},
                    .anchors = {{.commit_id = prepared->commit_id,
                                 .height = 0}},
                    .previous_epoch_id = {}};
            ASSERT_TRUE(kasumi::application::history_storage::epoch::verify(
                storage, expected, genesis_epoch.reference, key, local));
        }
        if (phase >= kasumi::transaction::Phase::DatabaseCommitted) {
            ASSERT_TRUE(
                kasumi::state_storage::initialize(runtime_data.database_path));
            ASSERT_TRUE(kasumi::state_storage::save_state(
                runtime_data.database_path,
                {.tree = prepared->commit.tree,
                 .height = prepared->commit.height,
                 .commit_id = prepared->commit_id,
                 .ciphertext_id = ciphertext_id,
                 .epoch_id = genesis_epoch.reference.epoch_id}));
        }
        const auto transaction_id = save_recovery_record(
            profile, phase, key, prepared->commit_id, ciphertext_id);
        ASSERT_FALSE(transaction_id.empty());

        const auto recovered =
            kasumi::application::sync::coordinator::recover_if_needed(
                runtime_data, storage, key);

        ASSERT_TRUE(recovered.has_value())
            << static_cast<int>(phase) << ": " << recovered.error().detail;
        const bool visible = phase >= kasumi::transaction::Phase::HeadPublished;
        EXPECT_EQ(*recovered,
                  visible ? kasumi::application::sync::coordinator::
                                RecoveryResult::RolledForward
                          : kasumi::application::sync::coordinator::
                                RecoveryResult::RolledBack)
            << static_cast<int>(phase);
        EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
        EXPECT_FALSE(std::filesystem::exists(profile / ".transactions" /
                                             transaction_id));
        const auto listing = kasumi::transport::list(storage);
        ASSERT_TRUE(listing.has_value());
        EXPECT_EQ(std::ranges::count_if(*listing,
                                        [](const auto& id) {
                                            return id.starts_with(
                                                "history/heads/");
                                        }),
                  visible ? 1 : 0)
            << static_cast<int>(phase);
        EXPECT_EQ(std::ranges::count_if(*listing,
                                        [](const auto& id) {
                                            return id.starts_with(
                                                "history/commits/");
                                        }),
                  phase >= kasumi::transaction::Phase::CommitUploaded ? 1 : 0)
            << static_cast<int>(phase);
        EXPECT_EQ(std::ranges::count_if(*listing,
                                        [](const auto& id) {
                                            return id.starts_with(
                                                "history/epochs/");
                                        }),
                  visible ? 1 : 0)
            << static_cast<int>(phase);
        EXPECT_EQ(std::filesystem::exists(runtime_data.database_path), visible)
            << static_cast<int>(phase);
    }
}

TEST(SyncCoordinatorTest,
     GenesisRecoveryUsesThePreparedPolicyAfterConfigChange) {
    auto workspace =
        kasumi::test::make_temp_workspace("genesis-policy-recovery");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    auto runtime = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const kasumi::Snapshot tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    const auto prepared =
        kasumi::application::sync::publication::prepare_commit(
            tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared.has_value());

    AmbiguousPublicationState* remote = nullptr;
    auto storage = make_ambiguous_transport(remote);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    const auto published =
        kasumi::application::sync::publication::publish_commit(
            storage, key, *prepared, local);
    ASSERT_TRUE(published.has_value()) << published.error().detail;
    const auto transaction_id =
        save_recovery_record(profile,
                             kasumi::transaction::Phase::EpochPrepared,
                             key,
                             prepared->commit_id,
                             published->head.ciphertext_id);
    ASSERT_FALSE(transaction_id.empty());
    const auto paths = kasumi::application::sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    const auto journal = kasumi::application::sync::journal::load(*paths, key);
    ASSERT_TRUE(journal.has_value() && *journal);
    const auto prepared_epoch_id = (*journal)->epoch_id;

    runtime.min_history_depth =
        kasumi::application::history_storage::epoch::default_min_history_depth +
        1;
    runtime.min_history_age_hours = kasumi::application::history_storage::
                                        epoch::default_min_history_age_hours +
                                    1;
    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime, storage, key);

    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
    EXPECT_EQ(
        *recovered,
        kasumi::application::sync::coordinator::RecoveryResult::RolledForward);
    const auto state = kasumi::state_storage::load_state(runtime.database_path);
    ASSERT_TRUE(state.has_value() && *state);
    EXPECT_EQ((*state)->epoch_id, prepared_epoch_id);
    const auto latest =
        kasumi::application::history_storage::epoch::load_latest(
            storage, key, profile);
    ASSERT_TRUE(latest.has_value() && *latest);
    EXPECT_EQ((**latest).reference.epoch_id, prepared_epoch_id);
    EXPECT_EQ(
        (**latest).value.policy.min_history_depth,
        kasumi::application::history_storage::epoch::default_min_history_depth);
    EXPECT_EQ((**latest).value.policy.min_history_age_hours,
              kasumi::application::history_storage::epoch::
                  default_min_history_age_hours);
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
}

TEST(SyncCoordinatorTest,
     LateRecoveryNeverReuploadsAnApplied975MiBContentObject) {
    constexpr std::uint64_t logical_size = 975ULL * 1024ULL * 1024ULL;
    const std::array phases{
        kasumi::transaction::Phase::CommitUploaded,
        kasumi::transaction::Phase::CommitVerified,
        kasumi::transaction::Phase::HeadPublished,
        kasumi::transaction::Phase::HeadVerified,
        kasumi::transaction::Phase::DatabaseCommitted,
    };

    for (const auto phase : phases) {
        auto workspace =
            kasumi::test::make_temp_workspace("late-large-recovery");
        const auto profile = kasumi::test::workspace_path(workspace, "profile");
        const auto local = kasumi::test::workspace_path(workspace, "local");
        ASSERT_TRUE(std::filesystem::create_directories(local));
        const auto runtime_data = make_runtime(
            profile, local, kasumi::test::workspace_path(workspace, "storage"));
        const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
        const auto content_id = kasumi::hash_hex(
            kasumi::hasher::hash_string("logical 975 MiB content"));
        kasumi::Snapshot tree{
            .rows = {
                kasumi::NodeRow{.path = "", .is_directory = true},
                kasumi::NodeRow{.path = "large.bin",
                                .hash =
                                    kasumi::hash_from_hex(content_id).value(),
                                .size = logical_size,
                                .is_directory = false},
            }};
        kasumi::finalize_snapshot(tree);

        AmbiguousPublicationState* state = nullptr;
        auto storage = make_ambiguous_transport(state);
        ASSERT_TRUE(kasumi::transport::initialize(storage));
        const auto seeded =
            kasumi::test::workspace_path(workspace, "already-uploaded.enc");
        kasumi::test::write_text(seeded, "opaque uploaded object");
        ASSERT_TRUE(kasumi::transport::put(
            storage, seeded, remote_content_id(key, content_id)));

        auto prepared = kasumi::application::sync::publication::prepare_commit(
            tree, false, 0, {}, 100, key);
        ASSERT_TRUE(prepared.has_value());
        auto published = kasumi::application::sync::publication::publish_commit(
            storage, key, *prepared, local);
        ASSERT_TRUE(published.has_value()) << published.error().detail;

        const auto plan = kasumi::make_sync_plan(
            {kasumi::Operation{.action = kasumi::Action::Upload,
                               .path = "large.bin",
                               .hash = content_id,
                               .size = logical_size}},
            0);
        auto record =
            kasumi::application::sync::journal::create_record(0, 0, plan, true);
        ASSERT_TRUE(record.has_value());
        record->phase = phase;
        record->progress.front().state =
            kasumi::transaction::OperationState::Applied;
        record->commit_id = prepared->commit_id;
        record->ciphertext_id = published->head.ciphertext_id;
        record->parent_ids = prepared->commit.parents;
        record->marker_id =
            kasumi::application::history_storage::marker_identifier(
                published->head);
        if (phase >= kasumi::transaction::Phase::EpochPrepared) {
            static_cast<void>(set_test_genesis_epoch(*record, key));
        }
        const auto paths =
            kasumi::application::sync::journal::make_paths(profile);
        ASSERT_TRUE(paths.has_value());
        ASSERT_TRUE(std::filesystem::create_directories(
            profile / ".transactions" / record->operation_id));
        ASSERT_TRUE(
            kasumi::application::sync::journal::save(*paths, *record, key));
        if (phase == kasumi::transaction::Phase::DatabaseCommitted) {
            ASSERT_TRUE(
                kasumi::state_storage::initialize(runtime_data.database_path));
            ASSERT_TRUE(kasumi::state_storage::save_state(
                runtime_data.database_path,
                {.tree = tree,
                 .height = prepared->commit.height,
                 .commit_id = prepared->commit_id,
                 .ciphertext_id = published->head.ciphertext_id}));
        }
        state->content_put_count = 0;

        const auto recovered =
            kasumi::application::sync::coordinator::recover_if_needed(
                runtime_data, storage, key);

        ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
        EXPECT_EQ(*recovered,
                  kasumi::application::sync::coordinator::RecoveryResult::
                      RolledForward);
        EXPECT_EQ(state->content_put_count, 0U) << static_cast<int>(phase);
    }
}

TEST(SyncCoordinatorTest, PublishedTransactionRollsForwardAfterRecovery) {
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-after-publication");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto transaction_id = std::string(32, '1');
    const auto transaction_root = profile / ".transactions" / transaction_id;
    ASSERT_TRUE(std::filesystem::create_directories(transaction_root));
    const kasumi::runtime::RuntimeData runtime_data{
        .local_dir = kasumi::test::workspace_path(workspace, "local"),
        .database_path = profile / "state.db",
        .key_path = profile / "key.bin",
        .storage_location =
            kasumi::test::workspace_path(workspace, "storage").string(),
    };
    ASSERT_TRUE(std::filesystem::create_directories(runtime_data.local_dir));
    auto opened = kasumi::transport::open_transport(
        kasumi::test::workspace_path(workspace, "storage").string());
    ASSERT_TRUE(opened.has_value());
    auto& storage = *opened;
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    kasumi::Snapshot history_tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    auto prepared = kasumi::application::sync::publication::prepare_commit(
        history_tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared.has_value());
    auto published = kasumi::application::sync::publication::publish_commit(
        storage, key, *prepared, runtime_data.local_dir);
    ASSERT_TRUE(published.has_value());
    auto record = kasumi::application::sync::journal::create_record(
        0, 0, kasumi::make_sync_plan({}, 0));
    ASSERT_TRUE(record.has_value());
    record->operation_id = transaction_id;
    record->phase = kasumi::transaction::Phase::CommitUploaded;
    record->commit_id = prepared->commit_id;
    record->ciphertext_id = published->head.ciphertext_id;
    record->parent_ids = prepared->commit.parents;
    record->marker_id = kasumi::application::history_storage::marker_identifier(
        published->head);
    const auto paths = kasumi::application::sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    ASSERT_TRUE(kasumi::application::sync::journal::save(*paths, *record, key));

    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, storage, key);
    if (!recovered) {
        ADD_FAILURE() << recovered.error().detail;
        return;
    }
    EXPECT_EQ(
        *recovered,
        kasumi::application::sync::coordinator::RecoveryResult::RolledForward);
    const auto loaded = kasumi::application::sync::journal::load(*paths, key);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_FALSE(*loaded);
    EXPECT_FALSE(std::filesystem::exists(transaction_root));
    EXPECT_TRUE(std::filesystem::exists(runtime_data.database_path));
}

TEST(SyncCoordinatorTest, PublishedRecoveryRollsForwardWithoutWorkspace) {
    auto workspace =
        kasumi::test::make_temp_workspace("transaction-published-no-workspace");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto runtime_data = make_runtime(profile, local, storage_path);
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const kasumi::Snapshot tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    auto prepared = kasumi::application::sync::publication::prepare_commit(
        tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared.has_value());
    auto opened = kasumi::transport::open_transport(storage_path.string());
    ASSERT_TRUE(opened.has_value());
    ASSERT_TRUE(kasumi::transport::initialize(*opened));
    auto published = kasumi::application::sync::publication::publish_commit(
        *opened, key, *prepared, local);
    ASSERT_TRUE(published.has_value());
    const auto id =
        save_recovery_record(profile,
                             kasumi::transaction::Phase::CommitUploaded,
                             key,
                             prepared->commit_id,
                             published->head.ciphertext_id);
    ASSERT_FALSE(id.empty());
    ASSERT_TRUE(std::filesystem::remove(profile / ".transactions" / id));

    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, *opened, key);
    ASSERT_TRUE(recovered.has_value());
    EXPECT_EQ(
        *recovered,
        kasumi::application::sync::coordinator::RecoveryResult::RolledForward);
    const auto state =
        kasumi::state_storage::load_state(runtime_data.database_path);
    ASSERT_TRUE(state.has_value() && *state);
    EXPECT_EQ((*state)->commit_id, prepared->commit_id);
    EXPECT_FALSE(std::filesystem::exists(profile / "transaction.bin.enc"));
    EXPECT_FALSE(std::filesystem::exists(profile / ".transactions" / id));
}

TEST(SyncCoordinatorTest, PruningFailurePreservesDatabaseCommittedPhase) {
    auto workspace =
        kasumi::test::make_temp_workspace("recovery-pruning-retry");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto storage_path =
        kasumi::test::workspace_path(workspace, "storage");
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto runtime_data = make_runtime(profile, local, storage_path);
    AmbiguousPublicationState* state = nullptr;
    auto storage = make_ambiguous_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const kasumi::Snapshot tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    auto prepared = kasumi::application::sync::publication::prepare_commit(
        tree, false, 0, {}, 100, key);
    ASSERT_TRUE(prepared.has_value());
    auto published = kasumi::application::sync::publication::publish_commit(
        storage, key, *prepared, local);
    ASSERT_TRUE(published.has_value());
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(kasumi::state_storage::initialize(runtime_data.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime_data.database_path,
        {.tree = prepared->commit.tree,
         .height = prepared->commit.height,
         .commit_id = prepared->commit_id,
         .ciphertext_id = std::string(64, 'c')}));
    const auto id =
        save_recovery_record(profile,
                             kasumi::transaction::Phase::DatabaseCommitted,
                             key,
                             prepared->commit_id,
                             published->head.ciphertext_id);
    ASSERT_FALSE(id.empty());
    state->fail_list_at = state->list_count + 2;

    const auto first =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, storage, key);
    ASSERT_FALSE(first.has_value());
    EXPECT_EQ(first.error().code,
              kasumi::application::sync::coordinator::ErrorCode::
                  RecoveryIndeterminate);
    const auto paths = kasumi::application::sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    const auto pending = kasumi::application::sync::journal::load(*paths, key);
    ASSERT_TRUE(pending.has_value() && *pending);
    EXPECT_EQ((*pending)->phase, kasumi::transaction::Phase::DatabaseCommitted);
    EXPECT_TRUE(std::filesystem::exists(profile / ".transactions" / id));

    state->fail_list_at = 0;
    const auto second =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, storage, key);
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(
        *second,
        kasumi::application::sync::coordinator::RecoveryResult::RolledForward);
    EXPECT_FALSE(std::filesystem::exists(paths->final_path));
    EXPECT_FALSE(std::filesystem::exists(profile / ".transactions" / id));
}

TEST(SyncCoordinatorTest, UploadSubBatchChunkingAndSafeResumption) {
    auto workspace =
        kasumi::test::make_temp_workspace("sub-batch-resumption");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    const auto local = kasumi::test::workspace_path(workspace, "local");
    ASSERT_TRUE(std::filesystem::create_directories(profile));
    ASSERT_TRUE(std::filesystem::create_directories(local));
    const auto runtime_data = make_runtime(
        profile, local, kasumi::test::workspace_path(workspace, "storage"));

    // Create 260 files: 256 in first sub-batch, 4 in second sub-batch
    constexpr std::size_t file_count = 260;
    auto input = empty_publication_input();
    for (std::size_t i = 0; i < file_count; ++i) {
        const auto filename = "file_" + std::to_string(i) + ".txt";
        const auto content = "payload_" + std::to_string(i);
        kasumi::test::write_text(local / filename, content);
        input.local_tree.rows.push_back(kasumi::NodeRow{
            .path = filename,
            .hash = kasumi::hasher::hash_string(content),
            .size = content.size(),
            .mtime = std::filesystem::last_write_time(local / filename),
            .is_directory = false});
    }
    input.local_tree.rows.front().mtime = std::filesystem::last_write_time(local);
    kasumi::finalize_snapshot(input.local_tree);
    input.base_tree = input.storage.tree;

    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_EQ(result->plan.operations.size(), file_count);

    AmbiguousPublicationState* state = nullptr;
    auto storage = make_ambiguous_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));

    // Fail content put at item 257 (the first upload in the second sub-batch)
    state->fail_content_put_at = 257;
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto first_exec = kasumi::application::sync::coordinator::execute(
        runtime_data, storage, key, input, *result);
    ASSERT_FALSE(first_exec.has_value());

    // Check that journal exists and sub-batch 1 (items 0..255) is checkpointed as Applied
    const auto paths = kasumi::application::sync::journal::make_paths(profile);
    ASSERT_TRUE(paths.has_value());
    const auto journal_rec = kasumi::application::sync::journal::load(*paths, key);
    ASSERT_TRUE(journal_rec.has_value() && *journal_rec);

    std::size_t applied_count = 0;
    for (const auto& op_progress : (*journal_rec)->progress) {
        if (op_progress.state == kasumi::transaction::OperationState::Applied) {
            ++applied_count;
        }
    }
    EXPECT_EQ(applied_count, 256);

    // Call recover_if_needed: should recognize progress and declare ResumableTransaction
    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, storage, key);
    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
    EXPECT_EQ(
        *recovered,
        kasumi::application::sync::coordinator::RecoveryResult::ResumableTransaction);
    EXPECT_TRUE(std::filesystem::exists(paths->final_path));

    // Reset failure and reset content put counter
    state->fail_content_put_at = 0;
    state->content_put_count = 0;

    // Second execution: must resume, elide the 256 already-applied uploads, and upload only 4 files!
    const auto second_exec = kasumi::application::sync::coordinator::execute(
        runtime_data, storage, key, input, *result);
    ASSERT_TRUE(second_exec.has_value()) << second_exec.error().detail;

    // Exactly 4 files uploaded in the second execution!
    EXPECT_EQ(state->content_put_count, 4);

    // After successful execution, the journal is removed
    EXPECT_FALSE(std::filesystem::exists(paths->final_path));

    // Subsequent recovery returns NoJournal
    const auto post_recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data, storage, key);
    ASSERT_TRUE(post_recovered.has_value());
    EXPECT_EQ(
        *post_recovered,
        kasumi::application::sync::coordinator::RecoveryResult::NoJournal);
}

} // namespace
