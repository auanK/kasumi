#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/maintenance.hpp"
#include "application/observation/file_metadata.hpp"
#include "application/sync/reobservation.hpp"
#include "application/use_cases/context.hpp"
#include "core/hasher.hpp"
#include "core/node.hpp"
#include "core/reconciliation/plan.hpp"
#include "crypto/content.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/history_storage.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/path.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <array>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace kasumi::application::detail {
std::expected<Response, Error> run_sync(OperationContext& context);
}

namespace {

struct CountingStorageState {
    kasumi::transport::Transport* base = nullptr;
    std::size_t content_puts = 0;
    std::size_t puts = 0;
    std::size_t gets = 0;
    std::size_t presences = 0;
    std::size_t lists = 0;
    bool cancel_next_content_put = false;
    bool ambiguous_next_content_put_after_effect = false;
    bool barrier_injected = false;
    bool nested_gc_attempted = false;
    bool nested_gc_succeeded = false;
    bool barrier_sync_attempted = false;
    bool barrier_sync_succeeded = false;
    std::size_t barrier_sync_content_puts = 0;
    std::size_t barrier_absent_observations = 0;
    std::string fail_get_identifier;
    std::string hidden_list_identifier;
    std::string nested_gc_error;
    std::function<void()> before_next_content_put;
    std::function<void(std::string_view)> after_put;
    std::function<void(std::string_view,
                       const kasumi::transport::PresenceResult&)>
        after_presence;
};

void destroy_counting_storage(void*) noexcept {
}

kasumi::transport::Result counting_initialize(void* context) {
    auto* state = static_cast<CountingStorageState*>(context);
    return kasumi::transport::initialize(*state->base);
}

kasumi::transport::Result counting_put(void* context,
                                       const std::filesystem::path& source,
                                       std::string_view identifier) {
    auto* state = static_cast<CountingStorageState*>(context);
    ++state->puts;
    if (identifier.find('/') == std::string_view::npos) {
        ++state->content_puts;
        if (state->before_next_content_put) {
            auto callback = std::move(state->before_next_content_put);
            callback();
        }
        if (state->cancel_next_content_put) {
            state->cancel_next_content_put = false;
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::Cancelled,
                .message = "cancelled repair upload"});
        }
        if (state->ambiguous_next_content_put_after_effect) {
            state->ambiguous_next_content_put_after_effect = false;
            auto uploaded = kasumi::transport::put(
                *state->base, source, identifier);
            if (!uploaded) {
                return uploaded;
            }
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::Timeout,
                .message = "injected lost PUT response"});
        }
    }
    auto uploaded = kasumi::transport::put(*state->base, source, identifier);
    if (uploaded && state->after_put) {
        auto callback = std::move(state->after_put);
        callback(identifier);
    }
    return uploaded;
}

kasumi::transport::Result
counting_get(void* context,
             std::string_view identifier,
             const std::filesystem::path& destination) {
    auto* state = static_cast<CountingStorageState*>(context);
    ++state->gets;
    if (identifier == state->fail_get_identifier) {
        state->fail_get_identifier.clear();
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Io,
            .message = "injected readback failure"});
    }
    return kasumi::transport::get(*state->base, identifier, destination);
}

kasumi::transport::PresenceResult
counting_presence(void* context, std::string_view identifier) {
    auto* state = static_cast<CountingStorageState*>(context);
    ++state->presences;
    auto result = kasumi::transport::presence(*state->base, identifier);
    if (state->after_presence) {
        state->after_presence(identifier, result);
    }
    return result;
}

kasumi::transport::ListingResult counting_list(void* context) {
    auto* state = static_cast<CountingStorageState*>(context);
    ++state->lists;
    auto result = kasumi::transport::list(*state->base);
    if (result && !state->hidden_list_identifier.empty()) {
        std::erase(*result, state->hidden_list_identifier);
    }
    return result;
}

kasumi::transport::ListingResult counting_list_prefix(void* context,
                                                      std::string_view prefix) {
    auto* state = static_cast<CountingStorageState*>(context);
    ++state->lists;
    return kasumi::transport::list(*state->base, prefix);
}

kasumi::transport::RemovalResult counting_remove(void* context,
                                                 std::string_view identifier) {
    return kasumi::transport::remove(
        *static_cast<CountingStorageState*>(context)->base, identifier);
}

kasumi::transport::Transport
make_counting_storage(CountingStorageState& state) {
    return kasumi::transport::Transport{
        .state =
            kasumi::transport::TransportStateHandle{&state,
                                                    destroy_counting_storage},
        .storage =
            kasumi::transport::StorageOperations{
                .initialize = counting_initialize,
                .put = counting_put,
                .get = counting_get,
                .presence = counting_presence,
                .list = counting_list,
                .list_prefix = counting_list_prefix,
                .remove = counting_remove,
            },
    };
}

class SyncHarness {
public:
    explicit SyncHarness(std::string_view name,
                         std::filesystem::path shared_storage = {})
        : workspace_(kasumi::test::make_temp_workspace(name)),
          profile_(kasumi::test::workspace_path(workspace_, "profile")),
          local_(kasumi::test::workspace_path(workspace_, "local")),
          storage_root_(shared_storage.empty() ? kasumi::test::workspace_path(
                                                     workspace_, "storage")
                                               : std::move(shared_storage)),
          database_(profile_ / "state.db"), key_(test_key()) {
        valid_ = std::filesystem::create_directories(profile_) &&
                 std::filesystem::create_directories(local_);
        auto opened = kasumi::transport::open_transport(storage_root_.string());
        if (!opened) {
            return;
        }
        base_storage_ = std::move(*opened);
        counting_state_.base = &base_storage_;
        valid_ = valid_ && kasumi::state_storage::initialize(database_);
        if (!valid_) {
            return;
        }

        runtime_ = kasumi::runtime::RuntimeData{
            .local_dir = local_,
            .database_path = database_,
            .key_path = profile_ / "key.bin",
            .storage_location = storage_root_.string(),
        };
        context_.operation = kasumi::application::Operation::Sync;
        context_.runtime = runtime_;
        context_.summary = {
            .local_dir = local_,
            .remote_dir = kasumi::platform::path::to_utf8(storage_root_),
        };
        context_.key = key_;
        context_.storage = make_counting_storage(counting_state_);
    }

    [[nodiscard]] bool valid() const noexcept {
        return valid_;
    }

    void write(std::string_view path, std::string_view contents) const {
        const auto target = local_ / kasumi::platform::path::from_utf8(path);
        std::filesystem::create_directories(target.parent_path());
        kasumi::test::write_text(target, contents);
    }

    void write_preserving_fingerprint(std::string_view path,
                                      std::string_view contents) const {
        const auto target = local_ / kasumi::platform::path::from_utf8(path);
#if defined(_WIN32)
        // Preserve the exact 100 ns FILETIME; MinGW's filesystem setter rounds it.
        FILETIME modified{};
        auto file = ::CreateFileW(target.c_str(),
                                  FILE_READ_ATTRIBUTES,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE |
                                      FILE_SHARE_DELETE,
                                  nullptr,
                                  OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL,
                                  nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            throw std::system_error(
                static_cast<int>(::GetLastError()),
                std::system_category(),
                "failed to open fingerprint fixture");
        }
        const BOOL read_time = ::GetFileTime(file, nullptr, nullptr, &modified);
        const DWORD read_error = read_time ? ERROR_SUCCESS : ::GetLastError();
        ::CloseHandle(file);
        if (!read_time) {
            throw std::system_error(static_cast<int>(read_error),
                                    std::system_category(),
                                    "failed to read fingerprint fixture timestamp");
        }

        kasumi::test::write_text(target, contents);

        file = ::CreateFileW(target.c_str(),
                             FILE_WRITE_ATTRIBUTES,
                             FILE_SHARE_READ | FILE_SHARE_WRITE |
                                 FILE_SHARE_DELETE,
                             nullptr,
                             OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL,
                             nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            throw std::system_error(
                static_cast<int>(::GetLastError()),
                std::system_category(),
                "failed to reopen fingerprint fixture");
        }
        const BOOL restored = ::SetFileTime(file, nullptr, nullptr, &modified);
        const DWORD restore_error = restored ? ERROR_SUCCESS : ::GetLastError();
        ::CloseHandle(file);
        if (!restored) {
            throw std::system_error(static_cast<int>(restore_error),
                                    std::system_category(),
                                    "failed to restore fingerprint fixture timestamp");
        }
#else
        const auto modified = std::filesystem::last_write_time(target);
        kasumi::test::write_text(target, contents);
        std::filesystem::last_write_time(target, modified);
#endif
    }

    [[nodiscard]] std::string read(std::string_view path) const {
        return kasumi::test::read_text(local_ /
                                       kasumi::platform::path::from_utf8(path));
    }

    [[nodiscard]] std::expected<kasumi::application::Response,
                                kasumi::application::Error>
    sync() {
        return kasumi::application::detail::run_sync(context_);
    }

    [[nodiscard]] std::filesystem::path
    content_path(const kasumi::Hash& hash) const {
        return storage_root_ /
               kasumi::platform::path::from_utf8(
                   kasumi::crypto::content_identifier(key_, hash));
    }

    void write_remote(std::string_view identifier,
                      std::string_view contents) const {
        const auto target =
            storage_root_ / kasumi::platform::path::from_utf8(identifier);
        std::filesystem::create_directories(target.parent_path());
        kasumi::test::write_text(target, contents);
    }

    bool remove_remote(std::string_view identifier) {
        return kasumi::transport::remove(base_storage_, identifier).has_value();
    }

    [[nodiscard]] std::optional<std::string>
    add_orphan_content(std::string_view contents) {
        const auto source = profile_ / "orphan.source";
        const auto encrypted = profile_ / "orphan.enc";
        kasumi::test::write_text(source, contents);
        const auto result = kasumi::crypto::encrypt_file_with_hashes(
            source, encrypted, key_);
        if (!result) {
            return std::nullopt;
        }
        const auto identifier =
            kasumi::crypto::content_identifier(key_, result->plaintext_hash);
        if (!kasumi::transport::put(base_storage_, encrypted, identifier)) {
            return std::nullopt;
        }
        return identifier;
    }

    [[nodiscard]] std::expected<kasumi::application::integrity::
                                   GarbageCollectResult,
                               kasumi::application::integrity::Error>
    collect_garbage() {
        return kasumi::application::integrity::garbage_collect(
            runtime_, context_.storage, key_);
    }

    [[nodiscard]] std::expected<kasumi::application::integrity::FsckResult,
                                kasumi::application::integrity::Error>
    fsck() {
        return kasumi::application::integrity::fsck(
            runtime_, context_.storage, key_);
    }

    void collect_before_next_content_put() {
        counting_state_.before_next_content_put = [this] {
            const auto result = collect_garbage();
            counting_state_.nested_gc_attempted = true;
            counting_state_.nested_gc_succeeded = result.has_value();
            if (!result) {
                counting_state_.nested_gc_error =
                    kasumi::application::integrity::describe(result.error());
            }
        };
    }

    void sync_after_barrier_is_published() {
        const auto identifier =
            kasumi::application::history_storage::derive_remote_layout(key_)
                .barrier_identifier;
        counting_state_.after_put = [this, identifier](
                                       std::string_view current) {
            if (current == identifier) {
                counting_state_.barrier_sync_attempted = true;
                const auto result = sync();
                counting_state_.barrier_sync_succeeded = result.has_value();
                counting_state_.barrier_sync_content_puts =
                    counting_state_.content_puts;
            }
        };
    }

    [[nodiscard]] std::filesystem::path
    remote_path(std::string_view identifier) const {
        return storage_root_ / kasumi::platform::path::from_utf8(identifier);
    }

    [[nodiscard]] const std::filesystem::path& local() const noexcept {
        return local_;
    }

    [[nodiscard]] const std::filesystem::path& storage_root() const noexcept {
        return storage_root_;
    }

    [[nodiscard]] const std::filesystem::path& database() const noexcept {
        return database_;
    }

    [[nodiscard]] const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE>&
    key() const noexcept {
        return key_;
    }

    [[nodiscard]] std::size_t content_puts() const noexcept {
        return counting_state_.content_puts;
    }

    [[nodiscard]] std::size_t puts() const noexcept {
        return counting_state_.puts;
    }

    [[nodiscard]] std::size_t presence_checks() const noexcept {
        return counting_state_.presences;
    }

    void reset_transfer_counts() noexcept {
        counting_state_.puts = 0;
        counting_state_.content_puts = 0;
        counting_state_.gets = 0;
        counting_state_.presences = 0;
        counting_state_.lists = 0;
    }

    void cancel_next_content_put() noexcept {
        counting_state_.cancel_next_content_put = true;
    }

    void lose_next_content_put_response() noexcept {
        counting_state_.ambiguous_next_content_put_after_effect = true;
    }

    void fail_next_content_readback(const kasumi::Hash& hash) {
        counting_state_.fail_get_identifier =
            kasumi::crypto::content_identifier(key_, hash);
    }

    void hide_from_listing(const kasumi::Hash& hash) {
        counting_state_.hidden_list_identifier =
            kasumi::crypto::content_identifier(key_, hash);
    }

    void place_barrier_after_writer_admission() {
        const auto identifier =
            kasumi::application::history_storage::derive_remote_layout(key_)
                .barrier_identifier;
        counting_state_.after_presence = [this, identifier](
                                              std::string_view current,
                                              const kasumi::transport::PresenceResult& result) {
            if (current == identifier && result &&
                *result == kasumi::transport::Presence::Absent &&
                !counting_state_.barrier_injected) {
                counting_state_.barrier_injected = true;
                write_remote(identifier, "injected active GC barrier");
            }
        };
    }

    void place_barrier_after_final_admission_observation() {
        const auto identifier =
            kasumi::application::history_storage::derive_remote_layout(key_)
                .barrier_identifier;
        counting_state_.barrier_absent_observations = 0;
        counting_state_.after_presence = [this, identifier](
                                              std::string_view current,
                                              const kasumi::transport::PresenceResult& result) {
            if (current == identifier && result &&
                *result == kasumi::transport::Presence::Absent &&
                ++counting_state_.barrier_absent_observations == 2U) {
                counting_state_.barrier_injected = true;
                write_remote(identifier, "injected active GC barrier");
            }
        };
    }

    [[nodiscard]] bool barrier_injected() const noexcept {
        return counting_state_.barrier_injected;
    }

    [[nodiscard]] bool nested_gc_attempted() const noexcept {
        return counting_state_.nested_gc_attempted;
    }

    [[nodiscard]] bool nested_gc_succeeded() const noexcept {
        return counting_state_.nested_gc_succeeded;
    }

    [[nodiscard]] const std::string& nested_gc_error() const noexcept {
        return counting_state_.nested_gc_error;
    }

    [[nodiscard]] bool barrier_sync_attempted() const noexcept {
        return counting_state_.barrier_sync_attempted;
    }

    [[nodiscard]] bool barrier_sync_succeeded() const noexcept {
        return counting_state_.barrier_sync_succeeded;
    }

    [[nodiscard]] std::size_t barrier_sync_content_puts() const noexcept {
        return counting_state_.barrier_sync_content_puts;
    }

private:
    kasumi::test::TempWorkspace workspace_;
    std::filesystem::path profile_;
    std::filesystem::path local_;
    std::filesystem::path storage_root_;
    std::filesystem::path database_;
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key_{};
    CountingStorageState counting_state_{};
    kasumi::transport::Transport base_storage_{};
    kasumi::runtime::RuntimeData runtime_{};
    kasumi::application::detail::OperationContext context_{};
    bool valid_ = true;
};

TEST(SyncRemoteAvailabilityTest, NoOpSyncRepairsMissingRemoteContent) {
    SyncHarness harness("gc-r3-no-op-missing-content");
    ASSERT_TRUE(harness.valid());
    harness.write("alpha.txt", "alpha contents");
    harness.write("beta.txt", "beta contents");
    harness.write("gamma.txt", "gamma contents");

    const auto first = harness.sync();
    ASSERT_TRUE(first.has_value()) << first.error().detail;
    const auto* first_summary =
        std::get_if<kasumi::application::SyncCompleted>(&first->data);
    ASSERT_NE(first_summary, nullptr);
    EXPECT_TRUE(first_summary->published);
    EXPECT_GE(first_summary->uploaded, 3U);
    EXPECT_TRUE(std::filesystem::is_regular_file(
        harness.content_path(kasumi::hasher::hash_string("alpha contents"))));
    EXPECT_TRUE(std::filesystem::is_regular_file(
        harness.content_path(kasumi::hasher::hash_string("gamma contents"))));

    const auto before_state =
        kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(before_state.has_value() && *before_state);
    ASSERT_FALSE((*before_state)->commit_id.empty());
    ASSERT_EQ((*before_state)->pending_materializations.size(), 0U);
    harness.reset_transfer_counts();

    const auto beta_hash = kasumi::hasher::hash_string("beta contents");
    const auto beta_path = harness.content_path(beta_hash);
    ASSERT_TRUE(std::filesystem::is_regular_file(beta_path));

    std::error_code remove_error;
    ASSERT_TRUE(std::filesystem::remove(beta_path, remove_error));
    ASSERT_FALSE(remove_error);
    ASSERT_FALSE(std::filesystem::exists(beta_path));

    const auto repaired = harness.sync();
    ASSERT_TRUE(repaired.has_value()) << repaired.error().detail;
    const auto* repaired_summary =
        std::get_if<kasumi::application::SyncCompleted>(&repaired->data);
    ASSERT_NE(repaired_summary, nullptr);
    EXPECT_EQ(repaired_summary->total, 1U);
    EXPECT_EQ(repaired_summary->uploaded, 1U);
    EXPECT_FALSE(repaired_summary->published);
    EXPECT_FALSE(repaired_summary->partial);
    EXPECT_EQ(repaired_summary->pending, 0U);
    EXPECT_EQ(harness.content_puts(), 1U);

    EXPECT_TRUE(std::filesystem::is_regular_file(beta_path));
    EXPECT_EQ(harness.read("alpha.txt"), "alpha contents");
    EXPECT_EQ(harness.read("beta.txt"), "beta contents");
    EXPECT_EQ(harness.read("gamma.txt"), "gamma contents");

    const auto after_state =
        kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(after_state.has_value() && *after_state);
    EXPECT_EQ((*after_state)->commit_id, (*before_state)->commit_id);
    EXPECT_EQ((*after_state)->ciphertext_id, (*before_state)->ciphertext_id);
    EXPECT_EQ((*after_state)->tree, (*before_state)->tree);
    EXPECT_EQ((*after_state)->pending_materializations.size(), 0U);

    harness.reset_transfer_counts();
    const auto no_op = harness.sync();
    ASSERT_TRUE(no_op.has_value()) << no_op.error().detail;
    const auto* no_op_summary =
        std::get_if<kasumi::application::SyncCompleted>(&no_op->data);
    ASSERT_NE(no_op_summary, nullptr);
    EXPECT_EQ(no_op_summary->total, 0U);
    EXPECT_EQ(no_op_summary->uploaded, 0U);
    EXPECT_FALSE(no_op_summary->published);
    EXPECT_FALSE(no_op_summary->partial);
    EXPECT_EQ(harness.content_puts(), 0U);
}

TEST(SyncRemoteAvailabilityTest, CorruptLocalRepairSourceIsRejected) {
    SyncHarness harness("gc-r3-corrupt-repair-source");
    ASSERT_TRUE(harness.valid());
    harness.write("alpha.txt", "alpha contents");
    const auto first = harness.sync();
    ASSERT_TRUE(first.has_value()) << first.error().detail;
    const auto source_path = harness.local() / "alpha.txt";
    const auto metadata_before =
        kasumi::application::observation::cache::read_file_metadata(
            source_path, "alpha.txt");
    ASSERT_TRUE(metadata_before.has_value() && metadata_before->has_value());
    ASSERT_TRUE((**metadata_before).identity.has_value());
    const auto hash = kasumi::hasher::hash_string("alpha contents");
    const auto accepted_before =
        kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(accepted_before.has_value() && *accepted_before);
    const auto cached =
        kasumi::state_storage::load_file_cache(harness.database());
    ASSERT_TRUE(cached.has_value());
    const auto cached_source = std::ranges::find(
        *cached,
        std::string{"alpha.txt"},
        &kasumi::state_storage::FileCacheRow::path);
    ASSERT_NE(cached_source, cached->end());
    EXPECT_EQ(cached_source->hash, hash);
    const auto path = harness.content_path(hash);
    ASSERT_TRUE(std::filesystem::exists(path));
    ASSERT_TRUE(std::filesystem::remove(path));
    harness.reset_transfer_counts();

    // Preserve the full cache fingerprint while changing the bytes.
    harness.write_preserving_fingerprint("alpha.txt", "omega contents");
    const auto metadata_after =
        kasumi::application::observation::cache::read_file_metadata(
            source_path, "alpha.txt");
    ASSERT_TRUE(metadata_after.has_value() && metadata_after->has_value());
    EXPECT_EQ((**metadata_after).size, (**metadata_before).size);
    EXPECT_EQ((**metadata_after).mtime_nanoseconds,
              (**metadata_before).mtime_nanoseconds);
    EXPECT_EQ((**metadata_after).identity, (**metadata_before).identity);
    EXPECT_EQ(harness.read("alpha.txt"), "omega contents");
    const auto rejected = harness.sync();
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error().code,
              kasumi::application::ErrorCode::SynchronizationFailure);
    EXPECT_EQ(harness.content_puts(), 0U);
    EXPECT_FALSE(std::filesystem::exists(path));
    EXPECT_EQ(harness.read("alpha.txt"), "omega contents");
    const auto accepted_after =
        kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(accepted_after.has_value() && *accepted_after);
    EXPECT_EQ((*accepted_after)->commit_id, (*accepted_before)->commit_id);
    EXPECT_EQ((*accepted_after)->tree, (*accepted_before)->tree);
    EXPECT_EQ((*accepted_after)->pending_materializations,
              (*accepted_before)->pending_materializations);

    harness.write("alpha.txt", "alpha contents");
    harness.reset_transfer_counts();
    const auto recovered = harness.sync();
    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
    EXPECT_EQ(harness.content_puts(), 1U);
    EXPECT_TRUE(std::filesystem::exists(path));
    EXPECT_EQ(harness.read("alpha.txt"), "alpha contents");
}

TEST(SyncRemoteAvailabilityTest, CancelledRepairIsNotAcceptedAndRecovers) {
    SyncHarness harness("gc-r3-cancelled-repair");
    ASSERT_TRUE(harness.valid());
    harness.write("alpha.txt", "alpha contents");
    const auto first = harness.sync();
    ASSERT_TRUE(first.has_value()) << first.error().detail;
    const auto hash = kasumi::hasher::hash_string("alpha contents");
    const auto path = harness.content_path(hash);
    ASSERT_TRUE(std::filesystem::remove(path));
    harness.reset_transfer_counts();
    harness.cancel_next_content_put();

    const auto cancelled = harness.sync();
    ASSERT_FALSE(cancelled.has_value());
    EXPECT_FALSE(std::filesystem::exists(path));
    EXPECT_EQ(harness.read("alpha.txt"), "alpha contents");

    harness.reset_transfer_counts();
    const auto recovered = harness.sync();
    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
    EXPECT_TRUE(std::filesystem::exists(path));
    EXPECT_GE(harness.content_puts(), 1U);
    EXPECT_EQ(harness.read("alpha.txt"), "alpha contents");
}

TEST(SyncRemoteAvailabilityTest, RepairsAllMissingDistinctContentsOnce) {
    SyncHarness harness("gc-r3-multiple-missing");
    ASSERT_TRUE(harness.valid());
    harness.write("a.txt", "content a");
    harness.write("b.txt", "content b");
    harness.write("c.txt", "content c");
    ASSERT_TRUE(harness.sync().has_value());

    const auto before = kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(before.has_value() && *before);
    harness.reset_transfer_counts();

    const auto hash_a = kasumi::hasher::hash_string("content a");
    const auto hash_b = kasumi::hasher::hash_string("content b");
    const auto hash_c = kasumi::hasher::hash_string("content c");
    ASSERT_TRUE(std::filesystem::remove(harness.content_path(hash_a)));
    ASSERT_TRUE(std::filesystem::remove(harness.content_path(hash_c)));
    ASSERT_TRUE(std::filesystem::exists(harness.content_path(hash_b)));

    const auto repaired = harness.sync();
    ASSERT_TRUE(repaired.has_value()) << repaired.error().detail;
    const auto* summary =
        std::get_if<kasumi::application::SyncCompleted>(&repaired->data);
    ASSERT_NE(summary, nullptr);
    EXPECT_EQ(summary->total, 2U);
    EXPECT_EQ(summary->uploaded, 2U);
    EXPECT_FALSE(summary->published);
    EXPECT_FALSE(summary->partial);
    EXPECT_EQ(harness.content_puts(), 2U);

    EXPECT_TRUE(std::filesystem::exists(harness.content_path(hash_a)));
    EXPECT_TRUE(std::filesystem::exists(harness.content_path(hash_c)));
    EXPECT_EQ(harness.read("a.txt"), "content a");
    EXPECT_EQ(harness.read("b.txt"), "content b");
    EXPECT_EQ(harness.read("c.txt"), "content c");

    const auto after = kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(after.has_value() && *after);
    EXPECT_EQ((*after)->commit_id, (*before)->commit_id);
    EXPECT_EQ((*after)->tree, (*before)->tree);
    EXPECT_TRUE((*after)->pending_materializations.empty());
}

TEST(SyncRemoteAvailabilityTest, DuplicateContentIsProbedAndRepairedOnce) {
    SyncHarness harness("gc-r3-deduplicated-content");
    ASSERT_TRUE(harness.valid());
    harness.write("one.txt", "shared bytes");
    harness.write("two.txt", "shared bytes");

    const auto first = harness.sync();
    ASSERT_TRUE(first.has_value()) << first.error().detail;
    const auto* first_summary =
        std::get_if<kasumi::application::SyncCompleted>(&first->data);
    ASSERT_NE(first_summary, nullptr);
    EXPECT_TRUE(first_summary->published);
    EXPECT_EQ(harness.content_puts(), 1U);

    const auto before = kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(before.has_value() && *before);
    harness.reset_transfer_counts();
    const auto shared_hash = kasumi::hasher::hash_string("shared bytes");
    ASSERT_TRUE(std::filesystem::remove(harness.content_path(shared_hash)));

    const auto repaired = harness.sync();
    ASSERT_TRUE(repaired.has_value()) << repaired.error().detail;
    const auto* summary =
        std::get_if<kasumi::application::SyncCompleted>(&repaired->data);
    ASSERT_NE(summary, nullptr);
    EXPECT_FALSE(summary->published);
    EXPECT_FALSE(summary->partial);
    // The plan keeps one logical upload per path; the physical Content
    // transfer is deduplicated by plaintext hash.
    EXPECT_EQ(harness.content_puts(), 1U);
    EXPECT_TRUE(std::filesystem::exists(harness.content_path(shared_hash)));
    EXPECT_EQ(harness.read("one.txt"), "shared bytes");
    EXPECT_EQ(harness.read("two.txt"), "shared bytes");

    const auto after = kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(after.has_value() && *after);
    EXPECT_EQ((*after)->commit_id, (*before)->commit_id);
}

TEST(SyncRemoteAvailabilityTest,
     ChangedLocalFilePublishesNewContentWithoutRepairingOldContent) {
    SyncHarness harness("gc-r3-changed-local-source");
    ASSERT_TRUE(harness.valid());
    harness.write("file.txt", "original");
    ASSERT_TRUE(harness.sync().has_value());

    const auto before = kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(before.has_value() && *before);
    harness.reset_transfer_counts();
    const auto old_hash = kasumi::hasher::hash_string("original");
    const auto new_hash = kasumi::hasher::hash_string("replacement");
    ASSERT_TRUE(std::filesystem::remove(harness.content_path(old_hash)));

    harness.write("file.txt", "replacement");
    const auto synchronized = harness.sync();
    ASSERT_TRUE(synchronized.has_value()) << synchronized.error().detail;
    const auto* summary =
        std::get_if<kasumi::application::SyncCompleted>(&synchronized->data);
    ASSERT_NE(summary, nullptr);
    EXPECT_TRUE(summary->published);
    EXPECT_FALSE(summary->partial);
    EXPECT_EQ(summary->uploaded, 1U);
    EXPECT_EQ(harness.content_puts(), 1U);
    EXPECT_FALSE(std::filesystem::exists(harness.content_path(old_hash)));
    EXPECT_TRUE(std::filesystem::exists(harness.content_path(new_hash)));

    const auto after = kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(after.has_value() && *after);
    EXPECT_NE((*after)->commit_id, (*before)->commit_id);
    const auto* row = kasumi::find_row((*after)->tree, "file.txt");
    ASSERT_NE(row, nullptr);
    EXPECT_EQ(row->hash, new_hash);
    EXPECT_TRUE((*after)->pending_materializations.empty());
}

TEST(SyncRemoteAvailabilityTest,
     MissingContentWithoutLocalSourcePreservesLogicalAndPendingState) {
    SyncHarness publisher("gc-r3-missing-without-source-publisher");
    ASSERT_TRUE(publisher.valid());
    publisher.write("lost.txt", "lost bytes");
    ASSERT_TRUE(publisher.sync().has_value());

    const auto before = kasumi::state_storage::load_state(publisher.database());
    ASSERT_TRUE(before.has_value() && *before);
    const auto lost_hash = kasumi::hasher::hash_string("lost bytes");
    ASSERT_TRUE(std::filesystem::remove(publisher.content_path(lost_hash)));

    SyncHarness observer("gc-r3-missing-without-source-observer",
                         publisher.storage_root());
    ASSERT_TRUE(observer.valid());
    const auto synchronized = observer.sync();
    ASSERT_TRUE(synchronized.has_value()) << synchronized.error().detail;
    const auto* summary =
        std::get_if<kasumi::application::SyncCompleted>(&synchronized->data);
    ASSERT_NE(summary, nullptr);
    EXPECT_FALSE(summary->published);
    EXPECT_TRUE(summary->partial);
    EXPECT_EQ(summary->pending, 1U);
    ASSERT_EQ(summary->pending_paths.size(), 1U);
    EXPECT_EQ(summary->pending_paths.front(), "lost.txt");
    EXPECT_EQ(summary->uploaded, 0U);
    EXPECT_EQ(observer.content_puts(), 0U);

    const auto after = kasumi::state_storage::load_state(observer.database());
    ASSERT_TRUE(after.has_value() && *after);
    EXPECT_EQ((*after)->commit_id, (*before)->commit_id);
    EXPECT_EQ((*after)->tree, (*before)->tree);
    ASSERT_EQ((*after)->pending_materializations.size(), 1U);
    EXPECT_EQ((*after)->pending_materializations.front().path, "lost.txt");
    EXPECT_FALSE(std::filesystem::exists(publisher.content_path(lost_hash)));
    EXPECT_FALSE(std::filesystem::exists(observer.local() / "lost.txt"));
}

TEST(SyncRemoteAvailabilityTest, ActiveGcBarrierBlocksRepairBeforeContentPut) {
    SyncHarness harness("gc-r3-active-barrier");
    ASSERT_TRUE(harness.valid());
    harness.write("file.txt", "barrier protected");
    ASSERT_TRUE(harness.sync().has_value());

    const auto before = kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(before.has_value() && *before);
    harness.reset_transfer_counts();
    const auto hash = kasumi::hasher::hash_string("barrier protected");
    ASSERT_TRUE(std::filesystem::remove(harness.content_path(hash)));

    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(
            harness.key());
    harness.write_remote(layout.barrier_identifier, "active barrier");

    const auto blocked = harness.sync();
    ASSERT_FALSE(blocked.has_value());
    EXPECT_EQ(harness.content_puts(), 0U);
    EXPECT_FALSE(std::filesystem::exists(harness.content_path(hash)));
    const auto after = kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(after.has_value() && *after);
    EXPECT_EQ((*after)->commit_id, (*before)->commit_id);
    EXPECT_EQ((*after)->tree, (*before)->tree);
}

TEST(SyncGcCertificationTest, AmbiguousRepairPutAfterRemoteEffect) {
    SyncHarness harness("gc-r4-ambiguous-repair-put");
    ASSERT_TRUE(harness.valid());
    harness.write("file.txt", "repair me");
    ASSERT_TRUE(harness.sync().has_value());
    const auto before = kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(before.has_value() && *before);

    const auto hash = kasumi::hasher::hash_string("repair me");
    const auto path = harness.content_path(hash);
    ASSERT_TRUE(std::filesystem::remove(path));
    harness.reset_transfer_counts();
    harness.lose_next_content_put_response();

    const auto repaired = harness.sync();
    ASSERT_TRUE(repaired.has_value()) << repaired.error().detail;
    EXPECT_EQ(harness.content_puts(), 1U);
    EXPECT_TRUE(std::filesystem::is_regular_file(path));

    const auto after = kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(after.has_value() && *after);
    EXPECT_EQ((*after)->commit_id, (*before)->commit_id);
    EXPECT_EQ((*after)->tree, (*before)->tree);

    harness.reset_transfer_counts();
    const auto no_op = harness.sync();
    ASSERT_TRUE(no_op.has_value()) << no_op.error().detail;
    EXPECT_EQ(harness.content_puts(), 0U);
}

TEST(SyncGcCertificationTest,
     AmbiguousRepairPutWithFailedReadbackRecoversWithoutBlindPut) {
    SyncHarness harness("gc-r4-ambiguous-repair-readback");
    ASSERT_TRUE(harness.valid());
    harness.write("file.txt", "repair me");
    ASSERT_TRUE(harness.sync().has_value());
    const auto before = kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(before.has_value() && *before);

    const auto hash = kasumi::hasher::hash_string("repair me");
    const auto path = harness.content_path(hash);
    ASSERT_TRUE(std::filesystem::remove(path));
    harness.reset_transfer_counts();
    harness.lose_next_content_put_response();
    harness.fail_next_content_readback(hash);

    const auto uncertain = harness.sync();
    ASSERT_FALSE(uncertain.has_value());
    EXPECT_EQ(harness.content_puts(), 1U);
    EXPECT_TRUE(std::filesystem::is_regular_file(path));
    auto after_failure = kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(after_failure.has_value() && *after_failure);
    EXPECT_EQ((*after_failure)->commit_id, (*before)->commit_id);
    EXPECT_EQ((*after_failure)->tree, (*before)->tree);

    harness.reset_transfer_counts();
    const auto recovered = harness.sync();
    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
    EXPECT_EQ(harness.content_puts(), 0U);
    EXPECT_TRUE(std::filesystem::is_regular_file(path));
    const auto after_recovery =
        kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(after_recovery.has_value() && *after_recovery);
    EXPECT_EQ((*after_recovery)->commit_id, (*before)->commit_id);
    EXPECT_EQ((*after_recovery)->tree, (*before)->tree);

    const auto orphan = harness.add_orphan_content("post-recovery orphan");
    ASSERT_TRUE(orphan.has_value());
    const auto collected = harness.collect_garbage();
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->removed_objects, 1U);
    EXPECT_TRUE(std::filesystem::is_regular_file(path));
    const auto audited = harness.fsck();
    ASSERT_TRUE(audited.has_value()) << audited.error().detail;
}

TEST(SyncGcCertificationTest,
     RecoveryFailsClosedWhenListAndPresenceDisagreeForRepair) {
    SyncHarness harness("gc-r4-recovery-presence-divergence");
    ASSERT_TRUE(harness.valid());
    harness.write("file.txt", "repair me");
    ASSERT_TRUE(harness.sync().has_value());
    const auto before = kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(before.has_value() && *before);

    const auto hash = kasumi::hasher::hash_string("repair me");
    const auto path = harness.content_path(hash);
    ASSERT_TRUE(std::filesystem::remove(path));
    harness.reset_transfer_counts();
    harness.lose_next_content_put_response();
    harness.fail_next_content_readback(hash);
    ASSERT_FALSE(harness.sync().has_value());
    ASSERT_TRUE(std::filesystem::is_regular_file(path));

    harness.reset_transfer_counts();
    harness.hide_from_listing(hash);
    const auto blocked = harness.sync();
    ASSERT_FALSE(blocked.has_value());
    EXPECT_EQ(harness.content_puts(), 0U);
    EXPECT_TRUE(std::filesystem::is_regular_file(path));
    const auto after = kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(after.has_value() && *after);
    EXPECT_EQ((*after)->commit_id, (*before)->commit_id);
    EXPECT_EQ((*after)->tree, (*before)->tree);
}

TEST(SyncGcCertificationTest, SyncWriterRegisteredFirstBlocksGc) {
    SyncHarness harness("gc-r4-sync-writer-first");
    ASSERT_TRUE(harness.valid());
    harness.write("file.txt", "sync writer first");
    harness.collect_before_next_content_put();

    const auto synchronized = harness.sync();
    ASSERT_TRUE(synchronized.has_value()) << synchronized.error().detail;
    EXPECT_TRUE(harness.nested_gc_attempted());
    EXPECT_FALSE(harness.nested_gc_succeeded());
    EXPECT_NE(harness.nested_gc_error().find("active writers block"),
              std::string::npos);
    EXPECT_EQ(harness.content_puts(), 1U);
    EXPECT_TRUE(std::filesystem::is_regular_file(
        harness.content_path(kasumi::hasher::hash_string("sync writer first"))));
}

TEST(SyncGcCertificationTest, GcBarrierFirstBlocksSyncAndThenConverges) {
    SyncHarness harness("gc-r4-gc-barrier-first");
    ASSERT_TRUE(harness.valid());
    harness.write("kept.txt", "protected content");
    ASSERT_TRUE(harness.sync().has_value());
    const auto orphan = harness.add_orphan_content("discardable orphan");
    ASSERT_TRUE(orphan.has_value());
    harness.write("new.txt", "published after GC");
    harness.reset_transfer_counts();
    harness.sync_after_barrier_is_published();

    const auto collected = harness.collect_garbage();
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->removed_objects, 1U);
    EXPECT_TRUE(harness.barrier_sync_attempted());
    EXPECT_FALSE(harness.barrier_sync_succeeded());
    EXPECT_EQ(harness.barrier_sync_content_puts(), 0U);
    EXPECT_FALSE(std::filesystem::exists(harness.remote_path(*orphan)));
    EXPECT_TRUE(std::filesystem::is_regular_file(
        harness.content_path(kasumi::hasher::hash_string("protected content"))));

    const auto synchronized = harness.sync();
    ASSERT_TRUE(synchronized.has_value()) << synchronized.error().detail;
    const auto* summary =
        std::get_if<kasumi::application::SyncCompleted>(&synchronized->data);
    ASSERT_NE(summary, nullptr);
    EXPECT_TRUE(summary->published);
    EXPECT_EQ(harness.content_puts(), 1U);

    harness.reset_transfer_counts();
    const auto no_op = harness.sync();
    ASSERT_TRUE(no_op.has_value()) << no_op.error().detail;
    const auto* no_op_summary =
        std::get_if<kasumi::application::SyncCompleted>(&no_op->data);
    ASSERT_NE(no_op_summary, nullptr);
    EXPECT_FALSE(no_op_summary->published);
    EXPECT_EQ(harness.content_puts(), 0U);
}

TEST(SyncGcCertificationTest,
     GarbageCollectThenSyncRepairsMissingReachableContent) {
    SyncHarness harness("gc-r4-gc-then-repair");
    ASSERT_TRUE(harness.valid());
    harness.write("kept.txt", "protected content");
    ASSERT_TRUE(harness.sync().has_value());
    const auto before = kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(before.has_value() && *before);

    const auto orphan = harness.add_orphan_content("discardable orphan");
    ASSERT_TRUE(orphan.has_value());
    const auto collected = harness.collect_garbage();
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->removed_objects, 1U);
    EXPECT_FALSE(std::filesystem::exists(harness.remote_path(*orphan)));

    harness.reset_transfer_counts();
    const auto no_op = harness.sync();
    ASSERT_TRUE(no_op.has_value()) << no_op.error().detail;
    const auto* no_op_summary =
        std::get_if<kasumi::application::SyncCompleted>(&no_op->data);
    ASSERT_NE(no_op_summary, nullptr);
    EXPECT_FALSE(no_op_summary->published);
    EXPECT_EQ(harness.content_puts(), 0U);
    EXPECT_FALSE(std::filesystem::exists(harness.remote_path(*orphan)));
    const auto after_no_op =
        kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(after_no_op.has_value() && *after_no_op);
    EXPECT_EQ((*after_no_op)->commit_id, (*before)->commit_id);
    EXPECT_EQ((*after_no_op)->tree, (*before)->tree);

    const auto hash = kasumi::hasher::hash_string("protected content");
    const auto content = harness.content_path(hash);
    ASSERT_TRUE(std::filesystem::remove(content));
    harness.reset_transfer_counts();
    const auto repaired = harness.sync();
    ASSERT_TRUE(repaired.has_value()) << repaired.error().detail;
    EXPECT_EQ(harness.content_puts(), 1U);
    EXPECT_TRUE(std::filesystem::is_regular_file(content));
    const auto* summary =
        std::get_if<kasumi::application::SyncCompleted>(&repaired->data);
    ASSERT_NE(summary, nullptr);
    EXPECT_FALSE(summary->published);

    const auto after = kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(after.has_value() && *after);
    EXPECT_EQ((*after)->commit_id, (*before)->commit_id);
    EXPECT_EQ((*after)->tree, (*before)->tree);
    const auto audited = harness.fsck();
    ASSERT_TRUE(audited.has_value()) << audited.error().detail;
}

TEST(SyncGcCertificationTest,
     LogicalDeletionStaysDeletedAcrossGcAndNoOpSync) {
    SyncHarness harness("gc-r4-delete-gc-noop");
    ASSERT_TRUE(harness.valid());
    harness.write("deleted.txt", "logically deleted");
    ASSERT_TRUE(harness.sync().has_value());
    ASSERT_TRUE(std::filesystem::remove(harness.local() / "deleted.txt"));

    const auto deleted = harness.sync();
    ASSERT_TRUE(deleted.has_value()) << deleted.error().detail;
    const auto* deleted_summary =
        std::get_if<kasumi::application::SyncCompleted>(&deleted->data);
    ASSERT_NE(deleted_summary, nullptr);
    EXPECT_TRUE(deleted_summary->published);
    const auto deleted_state =
        kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(deleted_state.has_value() && *deleted_state);

    const auto collected = harness.collect_garbage();
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    const auto audited = harness.fsck();
    ASSERT_TRUE(audited.has_value()) << audited.error().detail;
    harness.reset_transfer_counts();
    const auto no_op = harness.sync();
    ASSERT_TRUE(no_op.has_value()) << no_op.error().detail;
    const auto* no_op_summary =
        std::get_if<kasumi::application::SyncCompleted>(&no_op->data);
    ASSERT_NE(no_op_summary, nullptr);
    EXPECT_FALSE(no_op_summary->published);
    EXPECT_EQ(harness.content_puts(), 0U);
    EXPECT_FALSE(std::filesystem::exists(harness.local() / "deleted.txt"));
    const auto final_state =
        kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(final_state.has_value() && *final_state);
    EXPECT_EQ((*final_state)->commit_id, (*deleted_state)->commit_id);
}

TEST(SyncGcCertificationTest,
     MissingRemoteAndLocalContentDoesNotAdvanceHistory) {
    SyncHarness harness("gc-r4-missing-unrecoverable-content");
    ASSERT_TRUE(harness.valid());
    harness.write("lost.txt", "unrecoverable content");
    ASSERT_TRUE(harness.sync().has_value());
    const auto before = kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(before.has_value() && *before);
    const auto hash = kasumi::hasher::hash_string("unrecoverable content");
    const auto content_id =
        kasumi::crypto::content_identifier(harness.key(), hash);
    const auto* required = kasumi::find_row((*before)->tree, "lost.txt");
    ASSERT_NE(required, nullptr);
    EXPECT_EQ(required->hash, hash);
    const auto content = harness.content_path(hash);
    ASSERT_TRUE(harness.remove_remote(content_id));
    ASSERT_TRUE(std::filesystem::remove(harness.local() / "lost.txt"));
    ASSERT_FALSE(std::filesystem::exists(harness.local() / "lost.txt"));
    harness.reset_transfer_counts();

    const auto partial = harness.sync();
    ASSERT_TRUE(partial.has_value()) << partial.error().detail;
    const auto* summary =
        std::get_if<kasumi::application::SyncCompleted>(&partial->data);
    ASSERT_NE(summary, nullptr);
    EXPECT_FALSE(summary->published);
    EXPECT_TRUE(summary->partial);
    EXPECT_EQ(summary->pending, 1U);
    ASSERT_EQ(summary->pending_paths.size(), 1U);
    EXPECT_EQ(summary->pending_paths.front(), "lost.txt");
    EXPECT_EQ(harness.content_puts(), 0U);
    const auto after = kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(after.has_value() && *after);
    EXPECT_EQ((*after)->commit_id, (*before)->commit_id);
    EXPECT_EQ((*after)->ciphertext_id, (*before)->ciphertext_id);
    EXPECT_EQ((*after)->tree, (*before)->tree);
    ASSERT_EQ((*after)->pending_materializations.size(), 1U);
    EXPECT_EQ((*after)->pending_materializations.front().path, "lost.txt");
    EXPECT_EQ((*after)->pending_materializations.front().hash, hash);
    EXPECT_FALSE(std::filesystem::exists(content));
    EXPECT_FALSE(std::filesystem::exists(harness.remote_path(content_id)));
    EXPECT_FALSE(std::filesystem::exists(harness.local() / "lost.txt"));

    harness.reset_transfer_counts();
    const auto repeated = harness.sync();
    ASSERT_TRUE(repeated.has_value()) << repeated.error().detail;
    const auto* repeated_summary =
        std::get_if<kasumi::application::SyncCompleted>(&repeated->data);
    ASSERT_NE(repeated_summary, nullptr);
    EXPECT_FALSE(repeated_summary->published);
    EXPECT_TRUE(repeated_summary->partial);
    EXPECT_EQ(repeated_summary->pending_paths,
              std::vector<std::filesystem::path>{"lost.txt"});
    EXPECT_EQ(harness.content_puts(), 0U);
    const auto after_repeat =
        kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(after_repeat.has_value() && *after_repeat);
    EXPECT_EQ((*after_repeat)->commit_id, (*before)->commit_id);
    ASSERT_EQ((*after_repeat)->pending_materializations.size(), 1U);
    EXPECT_EQ((*after_repeat)->pending_materializations.front().hash, hash);
}

TEST(SyncGcCertificationTest,
     ReplacedRemoteContentFailsClosedBeforeDownloadMutation) {
    SyncHarness source("gc-r4-corrupt-download-source");
    ASSERT_TRUE(source.valid());
    source.write("protected.txt", "authenticated content");
    ASSERT_TRUE(source.sync().has_value());
    const auto content_id = kasumi::crypto::content_identifier(
        source.key(), kasumi::hasher::hash_string("authenticated content"));
    source.write_remote(content_id, "replacement bytes");

    SyncHarness consumer("gc-r4-corrupt-download-consumer",
                         source.storage_root());
    ASSERT_TRUE(consumer.valid());
    const auto blocked = consumer.sync();
    ASSERT_FALSE(blocked.has_value());
    EXPECT_FALSE(std::filesystem::exists(consumer.local() / "protected.txt"));
    EXPECT_EQ(consumer.content_puts(), 0U);
    EXPECT_TRUE(std::filesystem::exists(consumer.remote_path(content_id)));
}

TEST(SyncGcCertificationTest, BarrierAppearingAfterWriterAdmissionBlocksRepair) {
    SyncHarness harness("gc-r4-barrier-during-repair");
    ASSERT_TRUE(harness.valid());
    harness.write("file.txt", "barrier protected repair");
    ASSERT_TRUE(harness.sync().has_value());
    const auto before = kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(before.has_value() && *before);

    const auto hash = kasumi::hasher::hash_string("barrier protected repair");
    const auto path = harness.content_path(hash);
    ASSERT_TRUE(std::filesystem::remove(path));
    harness.reset_transfer_counts();
    harness.place_barrier_after_writer_admission();

    const auto blocked = harness.sync();
    ASSERT_FALSE(blocked.has_value());
    EXPECT_TRUE(harness.barrier_injected());
    EXPECT_EQ(harness.content_puts(), 0U);
    EXPECT_FALSE(std::filesystem::exists(path));
    const auto after = kasumi::state_storage::load_state(harness.database());
    ASSERT_TRUE(after.has_value() && *after);
    EXPECT_EQ((*after)->commit_id, (*before)->commit_id);
    EXPECT_EQ((*after)->tree, (*before)->tree);
}

TEST(SyncGcCertificationTest,
     BarrierCreatedAfterFinalAdmissionObservationCanRaceWithPublication) {
    SyncHarness harness("gc-r4-admission-check-to-put-race");
    ASSERT_TRUE(harness.valid());
    harness.write("file.txt", "before race");
    ASSERT_TRUE(harness.sync().has_value());
    harness.write("file.txt", "after race");
    harness.reset_transfer_counts();
    harness.place_barrier_after_final_admission_observation();

    const auto synchronized = harness.sync();
    ASSERT_TRUE(synchronized.has_value()) << synchronized.error().detail;
    EXPECT_TRUE(harness.barrier_injected());
    EXPECT_EQ(harness.content_puts(), 1U);
    EXPECT_TRUE(std::filesystem::exists(harness.remote_path(
        kasumi::application::history_storage::derive_remote_layout(
            harness.key())
            .barrier_identifier)));
    const auto* summary =
        std::get_if<kasumi::application::SyncCompleted>(&synchronized->data);
    ASSERT_NE(summary, nullptr);
    EXPECT_TRUE(summary->published);
}

namespace {

kasumi::Snapshot empty_tree() {
    kasumi::Snapshot tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    kasumi::finalize_snapshot(tree);
    return tree;
}

kasumi::Snapshot remote_tree_with(const kasumi::Hash& hash,
                                  std::uint64_t size) {
    kasumi::Snapshot tree;
    tree.rows = {
        kasumi::NodeRow{.path = "", .is_directory = true},
        kasumi::NodeRow{.path = "missing.txt",
                        .hash = hash,
                        .size = size,
                        .is_directory = false},
    };
    kasumi::finalize_snapshot(tree);
    return tree;
}

kasumi::reconciliation::Input availability_input(const kasumi::Snapshot& remote,
                                                 bool audit) {
    kasumi::reconciliation::Input input{};
    input.local_tree = empty_tree();
    input.storage.tree = remote;
    input.storage.history_present = true;
    input.audit_storage_objects = audit;
    return input;
}

} // namespace

TEST(SyncRemoteAvailabilityTest, ListPresentPresenceAbsentFailsClosed) {
    const auto key = test_key();
    const auto hash = kasumi::hasher::hash_string("missing");
    const auto identifier = kasumi::crypto::content_identifier(key, hash);
    auto input = availability_input(remote_tree_with(hash, 7), true);
    input.storage.object_identifiers.insert(identifier);

    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    const auto refreshed = kasumi::application::sync::coordinator::
        reobservation::refresh_content_availability(
            input, kasumi::reconciliation::Result{}, storage, key);
    ASSERT_FALSE(refreshed.has_value());
    EXPECT_EQ(
        refreshed.error().code,
        kasumi::application::sync::coordinator::ErrorCode::ObservationFailure);
    EXPECT_NE(refreshed.error().detail.find("disagreement"), std::string::npos);
    EXPECT_FALSE(input.known_missing_content_objects.contains(hash));
}

TEST(SyncRemoteAvailabilityTest, ListAbsentPresencePresentFailsClosed) {
    const auto key = test_key();
    const auto hash = kasumi::hasher::hash_string("present");
    const auto identifier = kasumi::crypto::content_identifier(key, hash);
    auto input = availability_input(remote_tree_with(hash, 7), true);

    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    state->objects[identifier] = {1U, 2U, 3U, 4U, 5U, 6U, 7U};
    const auto refreshed = kasumi::application::sync::coordinator::
        reobservation::refresh_content_availability(
            input, kasumi::reconciliation::Result{}, storage, key);
    ASSERT_FALSE(refreshed.has_value());
    EXPECT_EQ(
        refreshed.error().code,
        kasumi::application::sync::coordinator::ErrorCode::ObservationFailure);
    EXPECT_NE(refreshed.error().detail.find("disagreement"), std::string::npos);
}

TEST(SyncRemoteAvailabilityTest,
     ListAndPresenceAgreementOnlyMarksAbsentContent) {
    const auto key = test_key();
    const auto present_hash = kasumi::hasher::hash_string("present");
    const auto absent_hash = kasumi::hasher::hash_string("absent");
    const auto present_identifier =
        kasumi::crypto::content_identifier(key, present_hash);
    const auto absent_identifier =
        kasumi::crypto::content_identifier(key, absent_hash);
    kasumi::Snapshot tree;
    tree.rows = {
        kasumi::NodeRow{.path = "", .is_directory = true},
        kasumi::NodeRow{.path = "present.txt",
                        .hash = present_hash,
                        .size = 7,
                        .is_directory = false},
        kasumi::NodeRow{.path = "absent.txt",
                        .hash = absent_hash,
                        .size = 6,
                        .is_directory = false},
    };
    kasumi::finalize_snapshot(tree);
    auto input = availability_input(tree, true);
    input.storage.object_identifiers.insert(present_identifier);

    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    state->objects[present_identifier] = {1U, 2U, 3U, 4U, 5U, 6U, 7U};
    const auto refreshed = kasumi::application::sync::coordinator::
        reobservation::refresh_content_availability(
            input, kasumi::reconciliation::Result{}, storage, key);
    ASSERT_TRUE(refreshed.has_value()) << refreshed.error().detail;
    EXPECT_FALSE(input.known_missing_content_objects.contains(present_hash));
    EXPECT_TRUE(input.known_missing_content_objects.contains(absent_hash));
    EXPECT_NE(present_identifier, absent_identifier);
}

TEST(SyncRemoteAvailabilityTest, MissingProbeCapabilityFailsClosed) {
    const auto key = test_key();
    const auto hash = kasumi::hasher::hash_string("unprobeable");
    auto input = availability_input(remote_tree_with(hash, 11), false);

    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    storage.storage.presence = nullptr;
    storage.storage.control_read_batch = nullptr;
    const auto refreshed = kasumi::application::sync::coordinator::
        reobservation::refresh_content_availability(
            input, kasumi::reconciliation::Result{}, storage, key);
    ASSERT_FALSE(refreshed.has_value());
    EXPECT_EQ(
        refreshed.error().code,
        kasumi::application::sync::coordinator::ErrorCode::ObservationFailure);
    EXPECT_TRUE(input.known_missing_content_objects.empty());
}

TEST(SyncRemoteAvailabilityTest, PresenceFailureIsNotClassifiedAsMissing) {
    const auto key = test_key();
    const auto hash = kasumi::hasher::hash_string("transport failure");
    const auto identifier = kasumi::crypto::content_identifier(key, hash);
    const auto prior_missing =
        kasumi::hasher::hash_string("prior confirmed missing");
    auto input = availability_input(remote_tree_with(hash, 17), true);
    input.known_missing_content_objects.insert(prior_missing);

    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    state->fail_presence_after_removal_identifier = identifier;
    const auto refreshed = kasumi::application::sync::coordinator::
        reobservation::refresh_content_availability(
            input, kasumi::reconciliation::Result{}, storage, key);
    ASSERT_FALSE(refreshed.has_value());
    EXPECT_EQ(
        refreshed.error().code,
        kasumi::application::sync::coordinator::ErrorCode::ObservationFailure);
    EXPECT_TRUE(input.known_missing_content_objects.contains(prior_missing));
    EXPECT_FALSE(input.known_missing_content_objects.contains(hash));
}

TEST(SyncRemoteAvailabilityTest, CancelledPresenceBatchDoesNotBecomeMissing) {
    const auto key = test_key();
    const auto hash = kasumi::hasher::hash_string("cancelled");
    auto input = availability_input(remote_tree_with(hash, 9), false);

    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    state->control_read_batch_failure = kasumi::transport::ErrorCode::Cancelled;
    const auto refreshed = kasumi::application::sync::coordinator::
        reobservation::refresh_content_availability(
            input, kasumi::reconciliation::Result{}, storage, key);
    ASSERT_FALSE(refreshed.has_value());
    EXPECT_EQ(
        refreshed.error().code,
        kasumi::application::sync::coordinator::ErrorCode::ObservationFailure);
    EXPECT_TRUE(input.known_missing_content_objects.empty());
}

} // namespace
