#include "application/history_storage/commit_cache.hpp"
#include "application/history_storage/epoch.hpp"
#include "application/history_storage/history_storage.hpp"
#include "application/history_storage/publication.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/history_storage.hpp"
#include "kasumi/test/history_timestamp_fixture.hpp"
#include "platform/cancellation.hpp"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace {

kasumi::transport::Result
fake_get_batch(void* context, const kasumi::transport::GetBatch& batch) {
    ++fake_state(context)->get_batch_count;
    for (const auto& identifier : batch.identifiers) {
        const auto source = batch.source_prefix.empty()
                                ? identifier
                                : batch.source_prefix + "/" + identifier;
        auto result =
            fake_get(context, source, batch.destination_root / identifier);
        if (!result) {
            return result;
        }
        --fake_state(context)->get_count;
        --fake_state(context)->commit_get_count;
        fake_state(context)->remote_events.pop_back();
    }
    return {};
}

std::mutex test_fake_state_mutex;

kasumi::transport::Result
safe_fake_get_batch(void* context, const kasumi::transport::GetBatch& batch) {
    std::scoped_lock lock(test_fake_state_mutex);
    return fake_get_batch(context, batch);
}

kasumi::transport::Result
safe_fake_get(void* context,
              std::string_view identifier,
              const std::filesystem::path& destination) {
    std::scoped_lock lock(test_fake_state_mutex);
    return fake_get(context, identifier, destination);
}

struct HistoryReadGates {
    bool batch_entered = false;
    bool epoch_entered = false;
    bool marker_entered = false;
    bool heads_entered = false;

    std::size_t current_in_flight = 0;
    std::size_t peak_in_flight = 0;

    bool release_batch = false;
    bool release_epoch = false;
    bool release_marker = false;
    bool release_heads = false;

    bool fail_batch = false;
    bool fail_epoch = false;
    bool fail_marker = false;
    bool fail_heads = false;

    std::mutex mutex;
    std::mutex fake_state_mutex;
    std::condition_variable cv;

    void update_peak(std::size_t active) {
        if (active > peak_in_flight) {
            peak_in_flight = active;
        }
    }

    void release_all() {
        std::lock_guard lock(mutex);
        release_batch = true;
        release_epoch = true;
        release_marker = true;
        release_heads = true;
        cv.notify_all();
    }
};

HistoryReadGates* active_gates = nullptr;

kasumi::transport::ListingResult
gated_fake_list_prefix(void* context, std::string_view prefix) {
    const auto& layout = test_layout();
    if (prefix ==
        layout.heads_prefix.substr(0, layout.heads_prefix.size() - 1)) {
        std::unique_lock lock(active_gates->mutex);
        active_gates->heads_entered = true;
        active_gates->update_peak(++active_gates->current_in_flight);
        active_gates->cv.notify_all();
        active_gates->cv.wait(lock, [&] {
            return active_gates->release_heads ||
                   kasumi::platform::cancellation::requested();
        });
        --active_gates->current_in_flight;
        if (active_gates->fail_heads) {
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::Io,
                .message = "injected heads failure"});
        }
    }
    std::scoped_lock lock(active_gates->fake_state_mutex);
    return fake_list_prefix(context, prefix);
}

struct GatesSessionGuard {
    HistoryReadGates& gates;
    std::jthread& worker;
    ~GatesSessionGuard() {
        gates.release_all();
        if (worker.joinable()) {
            worker.join();
        }
        active_gates = nullptr;
    }
};

kasumi::transport::Result
gated_fake_get_batch(void* context, const kasumi::transport::GetBatch& batch) {
    bool should_fail = false;
    if (active_gates) {
        {
            std::unique_lock lock(active_gates->mutex);
            active_gates->batch_entered = true;
            const auto active = ++active_gates->current_in_flight;
            active_gates->update_peak(active);
            active_gates->cv.notify_all();
            active_gates->cv.wait(lock, [&] {
                return active_gates->release_batch ||
                       kasumi::platform::cancellation::requested();
            });
            --active_gates->current_in_flight;
            should_fail = active_gates->fail_batch;
        }
        if (should_fail) {
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::Io,
                .message = "injected batch failure",
            });
        }
    }
    if (active_gates) {
        std::scoped_lock lock(active_gates->fake_state_mutex);
        return fake_get_batch(context, batch);
    }
    return fake_get_batch(context, batch);
}

kasumi::transport::Result
gated_fake_get(void* context,
               std::string_view identifier,
               const std::filesystem::path& destination) {
    if (active_gates) {
        if (is_epoch(identifier)) {
            bool should_fail = false;
            {
                std::unique_lock lock(active_gates->mutex);
                active_gates->epoch_entered = true;
                const auto active = ++active_gates->current_in_flight;
                active_gates->update_peak(active);
                active_gates->cv.notify_all();
                active_gates->cv.wait(lock, [&] {
                    return active_gates->release_epoch ||
                           kasumi::platform::cancellation::requested();
                });
                --active_gates->current_in_flight;
                should_fail = active_gates->fail_epoch;
            }
            if (should_fail) {
                return std::unexpected(kasumi::transport::Error{
                    .code = kasumi::transport::ErrorCode::Io,
                    .message = "injected epoch failure",
                });
            }
        } else if (is_marker(identifier)) {
            bool should_fail = false;
            {
                std::unique_lock lock(active_gates->mutex);
                active_gates->marker_entered = true;
                const auto active = ++active_gates->current_in_flight;
                active_gates->update_peak(active);
                active_gates->cv.notify_all();
                active_gates->cv.wait(lock, [&] {
                    return active_gates->release_marker ||
                           kasumi::platform::cancellation::requested();
                });
                --active_gates->current_in_flight;
                should_fail = active_gates->fail_marker;
            }
            if (should_fail) {
                return std::unexpected(kasumi::transport::Error{
                    .code = kasumi::transport::ErrorCode::Io,
                    .message = "injected marker failure",
                });
            }
        }
    }
    if (active_gates) {
        std::scoped_lock lock(active_gates->fake_state_mutex);
        return fake_get(context, identifier, destination);
    }
    return fake_get(context, identifier, destination);
}

HeadReference seed_fake_commit(FakeState& state,
                               const std::filesystem::path& root,
                               const Commit& commit,
                               std::string_view name) {
    const auto canonical = kasumi::history::serialize(commit).value();
    const auto plaintext = root / (std::string{name} + ".plain");
    const auto ciphertext = root / (std::string{name} + ".cipher");
    kasumi::test::write_binary(plaintext, std::as_bytes(std::span{canonical}));
    EXPECT_TRUE(
        kasumi::crypto::encrypt_file(plaintext,
                                     ciphertext,
                                     test_key(),
                                     kasumi::crypto::FilePurpose::History));
    const auto hash = kasumi::crypto::content::hash_file(ciphertext).value();
    const HeadReference reference{.commit_id = commit_id(commit),
                                  .ciphertext_id = kasumi::hash_hex(hash)};
    EXPECT_TRUE(fake_put(&state, ciphertext, object_path(reference)));
    state.objects[marker_path(reference)] =
        kasumi::application::history_storage::encode_marker(reference).value();
    return reference;
}

kasumi::transport::Transport init_fake_transport(FakeState*& state) {
    auto transport = make_fake_transport(state);
    EXPECT_TRUE(kasumi::transport::initialize(transport));
    return transport;
}

TEST(HistoryStorageTest, CompleteLoadConsumesOneNativeCommitBatch) {
    auto workspace =
        kasumi::test::make_temp_workspace("history-native-get-batch");
    FakeState* state = nullptr;
    auto storage = init_fake_transport(state);
    const auto root = kasumi::test::workspace_root(workspace);

    const auto parent = make_commit(0, {}, "file.txt", "zero").value();
    const auto published_parent =
        seed_fake_commit(*state, root, parent, "parent");
    const auto child =
        make_commit(1, {published_parent.commit_id}, "file.txt", "one").value();
    seed_fake_commit(*state, root, child, "child");

    storage.storage.get = safe_fake_get;
    storage.storage.get_batch = safe_fake_get_batch;
    reset_remote_counts(*state);
    state->get_batch_count = 0;
    const auto loaded = kasumi::application::history_storage::load_history(
        storage, test_key(), root);

    ASSERT_TRUE(loaded.has_value()) << loaded.error().detail;
    EXPECT_EQ(loaded->commits.size(), 2U);
    EXPECT_EQ(state->get_batch_count, 1U);
    EXPECT_EQ(state->commit_get_count, 0U);
}

TEST(HistoryStorageTest, LinuxNanosecondGoldenVariantAuthenticates) {
    auto storage = make_local_storage();
    const auto reference =
        add_variant_bytes(storage,
                          std::span<const std::uint8_t>{
                              kasumi::test::fixtures::linux_nanosecond_commit});

    const auto loaded = kasumi::application::history_storage::load_history(
        storage.transport,
        test_key(),
        kasumi::test::workspace_root(storage.workspace));

    ASSERT_TRUE(loaded.has_value())
        << (loaded.has_value() ? "" : loaded.error().detail);
    ASSERT_EQ(loaded->commits.size(), 1U);
    EXPECT_EQ(loaded->commits.front().id, reference.commit_id);
    EXPECT_EQ(loaded->authenticated_commit_variants, std::vector{reference});
}

TEST(HistoryStorageTest,
     InspectsOnlySelectedPhysicalCommitVariantsWithoutMutation) {
    auto workspace =
        kasumi::test::make_temp_workspace("history-inspect-variants");
    FakeState* state = nullptr;
    auto storage = init_fake_transport(state);
    const auto root = kasumi::test::workspace_root(workspace);
    const auto selected = make_commit(0, {}, "selected", "selected").value();
    const auto other = make_commit(0, {}, "other", "other").value();
    const auto selected_object =
        kasumi::application::history_storage::publish_commit_object_scoped(
            storage, test_key(), selected, root);
    const auto other_object =
        kasumi::application::history_storage::publish_commit_object_scoped(
            storage, test_key(), other, root);
    ASSERT_TRUE(selected_object.has_value());
    ASSERT_TRUE(other_object.has_value());

    const HeadReference incompatible{
        .commit_id = selected_object->head.commit_id,
        .ciphertext_id = other_object->head.ciphertext_id,
    };
    state->objects[object_path(incompatible)] =
        state->objects.at(object_path(other_object->head));
    const HeadReference invalid_ciphertext{
        .commit_id = selected_object->head.commit_id,
        .ciphertext_id = std::string(64, 'f'),
    };
    state->objects[object_path(invalid_ciphertext)] = {
        'i', 'n', 'v', 'a', 'l', 'i', 'd'};

    const auto objects_before = state->objects;
    const auto puts_before = state->put_count;
    const auto removes_before = state->remove_count;
    reset_remote_counts(*state);
    const auto inspected =
        kasumi::application::history_storage::inspect_commit_variants(
            storage, test_key(), selected_object->head.commit_id, root);

    ASSERT_TRUE(inspected.has_value()) << inspected.error().detail;
    ASSERT_EQ(inspected->size(), 3U);
    EXPECT_TRUE(std::ranges::is_sorted(*inspected, {}, [](const auto& variant) {
        return variant.reference;
    }));
    const auto state_for = [&](std::string_view ciphertext_id) {
        const auto found = std::ranges::find(
            *inspected, ciphertext_id, [](const auto& variant) {
                return variant.reference.ciphertext_id;
            });
        EXPECT_NE(found, inspected->end());
        return found == inspected->end()
                   ? kasumi::application::history_storage::
                         PhysicalCommitVariantState::InvalidCiphertext
                   : found->state;
    };
    EXPECT_EQ(state_for(selected_object->head.ciphertext_id),
              kasumi::application::history_storage::PhysicalCommitVariantState::
                  Valid);
    EXPECT_EQ(state_for(incompatible.ciphertext_id),
              kasumi::application::history_storage::PhysicalCommitVariantState::
                  InvalidCommit);
    EXPECT_EQ(state_for(invalid_ciphertext.ciphertext_id),
              kasumi::application::history_storage::PhysicalCommitVariantState::
                  InvalidCiphertext);
    EXPECT_EQ(state->commit_get_count, 3U);
    EXPECT_EQ(state->marker_get_count, 0U);
    EXPECT_EQ(state->put_count, puts_before);
    EXPECT_EQ(state->remove_count, removes_before);
    EXPECT_EQ(state->objects, objects_before);
}

TEST(HistoryStorageTest, AmbiguousCommitAndHeadPutsRollForwardWithoutRetry) {
    auto workspace = kasumi::test::make_temp_workspace("history-ambiguous-put");
    FakeState* state = nullptr;
    auto storage = init_fake_transport(state);
    state->physical_hash_supported = true;
    state->fail_commit_put = true;
    state->persist_commit_on_put_failure = true;
    const auto commit = make_commit(0, {}, "file.txt", "contents").value();
    const auto root = kasumi::test::workspace_root(workspace);

    auto object =
        kasumi::application::history_storage::publish_commit_object_scoped(
            storage, test_key(), commit, root);
    ASSERT_TRUE(object.has_value()) << object.error().detail;
    EXPECT_EQ(state->commit_put_count, 1U);
    EXPECT_EQ(state->physical_hash_count, 1U);

    state->fail_marker_put = true;
    state->persist_marker_on_put_failure = true;
    reset_remote_counts(*state);
    auto marker =
        kasumi::application::history_storage::publish_head_marker_scoped(
            storage, test_layout(), object->head, root);
    ASSERT_TRUE(marker.has_value()) << marker.error().detail;
    EXPECT_EQ(state->marker_put_count, 1U);
    EXPECT_EQ(state->physical_hash_count, 1U);
}

TEST(HistoryStorageTest, AmbiguousDeleteRemainsErrorWithoutRetry) {
    FakeState* state = nullptr;
    auto storage = init_fake_transport(state);
    state->objects["object"] = {'x'};
    state->remove_then_fail_identifier = "object";
    state->remove_failure_native_code = 1234;

    const auto removed = kasumi::transport::remove(storage, "object");

    ASSERT_FALSE(removed.has_value());
    EXPECT_EQ(removed.error().code, kasumi::transport::ErrorCode::Io);
    EXPECT_EQ(removed.error().message, "injected remove failure");
    EXPECT_EQ(removed.error().native_code, 1234);
    EXPECT_EQ(state->remove_count, 1U);
    EXPECT_EQ(state->presence_count, 0U);
}

TEST(HistoryStorageTest, StrongPhysicalHashAvoidsCommitAndHeadReadback) {
    auto workspace = kasumi::test::make_temp_workspace("history-physical-hash");
    FakeState* state = nullptr;
    auto storage = init_fake_transport(state);
    state->physical_hash_supported = true;
    const auto commit = make_commit(0, {}, "file.txt", "contents").value();
    const auto root = kasumi::test::workspace_root(workspace);

    auto object =
        kasumi::application::history_storage::publish_commit_object_scoped(
            storage, test_key(), commit, root);
    ASSERT_TRUE(object.has_value()) << object.error().detail;
    EXPECT_EQ(state->list_count, 0U);
    reset_remote_counts(*state);
    auto commit_verified =
        kasumi::application::history_storage::verify_commit_object(
            storage,
            test_key(),
            commit,
            object->head,
            root,
            object->physical_hash);
    ASSERT_TRUE(commit_verified.has_value()) << commit_verified.error().detail;
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->commit_get_count, 0U);

    auto marker =
        kasumi::application::history_storage::publish_head_marker_scoped(
            storage, test_layout(), object->head, root);
    ASSERT_TRUE(marker.has_value()) << marker.error().detail;
    EXPECT_EQ(state->list_count, 0U);
    reset_remote_counts(*state);
    auto head_verified =
        kasumi::application::history_storage::verify_head_marker(
            storage, test_layout(), object->head, root, marker->physical_hash);
    ASSERT_TRUE(head_verified.has_value()) << head_verified.error().detail;
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->marker_get_count, 0U);
}

TEST(HistoryStorageTest, UnsupportedPhysicalHashFallsBackToSemanticReadback) {
    auto workspace = kasumi::test::make_temp_workspace("history-hash-fallback");
    FakeState* state = nullptr;
    auto storage = init_fake_transport(state);
    const auto commit = make_commit(0, {}, "file.txt", "contents").value();
    const auto root = kasumi::test::workspace_root(workspace);
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());

    auto object =
        kasumi::application::history_storage::publish_commit_object_scoped(
            storage, layout, test_key(), commit, root);
    ASSERT_TRUE(object.has_value());
    reset_remote_counts(*state);
    ASSERT_TRUE(kasumi::application::history_storage::verify_commit_object(
        storage,
        layout,
        test_key(),
        commit,
        object->head,
        root,
        object->physical_hash));
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->commit_get_count, 1U);

    auto marker =
        kasumi::application::history_storage::publish_head_marker_scoped(
            storage, layout, object->head, root);
    ASSERT_TRUE(marker.has_value());
    reset_remote_counts(*state);
    ASSERT_TRUE(kasumi::application::history_storage::verify_head_marker(
        storage, layout, object->head, root, marker->physical_hash));
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->marker_get_count, 1U);
}

TEST(HistoryStorageTest, PhysicalHashMismatchFailsCommitAndHeadVerification) {
    auto workspace = kasumi::test::make_temp_workspace("history-hash-mismatch");
    FakeState* state = nullptr;
    auto storage = init_fake_transport(state);
    state->physical_hash_supported = true;
    const auto commit = make_commit(0, {}, "file.txt", "contents").value();
    const auto root = kasumi::test::workspace_root(workspace);
    auto object =
        kasumi::application::history_storage::publish_commit_object_scoped(
            storage, test_key(), commit, root);
    ASSERT_TRUE(object.has_value());
    auto marker =
        kasumi::application::history_storage::publish_head_marker_scoped(
            storage, test_layout(), object->head, root);
    ASSERT_TRUE(marker.has_value());

    state->physical_hash_mismatch = true;
    const auto commit_verified =
        kasumi::application::history_storage::verify_commit_object(
            storage,
            test_key(),
            commit,
            object->head,
            root,
            object->physical_hash);
    ASSERT_FALSE(commit_verified.has_value());
    EXPECT_EQ(
        commit_verified.error().code,
        kasumi::application::history_storage::ErrorCode::VerificationFailure);
    const auto head_verified =
        kasumi::application::history_storage::verify_head_marker(
            storage, test_layout(), object->head, root, marker->physical_hash);
    ASSERT_FALSE(head_verified.has_value());
    EXPECT_EQ(
        head_verified.error().code,
        kasumi::application::history_storage::ErrorCode::VerificationFailure);
    EXPECT_EQ(state->commit_get_count, 0U);
    EXPECT_EQ(state->marker_get_count, 0U);
}

TEST(HistoryStorageTest,
     PhysicalHashTransportFailureDoesNotFallbackToReadback) {
    auto workspace = kasumi::test::make_temp_workspace("history-hash-error");
    FakeState* state = nullptr;
    auto storage = init_fake_transport(state);
    state->physical_hash_supported = true;
    const auto commit = make_commit(0, {}, "file.txt", "contents").value();
    const auto root = kasumi::test::workspace_root(workspace);
    auto object =
        kasumi::application::history_storage::publish_commit_object_scoped(
            storage, test_key(), commit, root);
    ASSERT_TRUE(object.has_value());
    auto marker =
        kasumi::application::history_storage::publish_head_marker_scoped(
            storage, test_layout(), object->head, root);
    ASSERT_TRUE(marker.has_value());

    state->physical_hash_failure = kasumi::transport::ErrorCode::Io;
    reset_remote_counts(*state);
    const auto commit_verified =
        kasumi::application::history_storage::verify_commit_object(
            storage,
            test_key(),
            commit,
            object->head,
            root,
            object->physical_hash);
    ASSERT_FALSE(commit_verified.has_value());
    EXPECT_EQ(
        commit_verified.error().code,
        kasumi::application::history_storage::ErrorCode::TransportFailure);
    EXPECT_EQ(state->commit_get_count, 0U);

    reset_remote_counts(*state);
    const auto head_verified =
        kasumi::application::history_storage::verify_head_marker(
            storage, test_layout(), object->head, root, marker->physical_hash);
    ASSERT_FALSE(head_verified.has_value());
    EXPECT_EQ(
        head_verified.error().code,
        kasumi::application::history_storage::ErrorCode::TransportFailure);
    EXPECT_EQ(state->marker_get_count, 0U);
}

TEST(HistoryStorageTest, HealthyPublicationUsesOrderedRemoteVerification) {
    auto workspace =
        kasumi::test::make_temp_workspace("history-publication-order");
    FakeState* state = nullptr;
    auto storage = init_fake_transport(state);
    state->physical_hash_supported = true;
    const auto commit = make_commit(0, {}, "file.txt", "contents").value();

    const auto published = kasumi::application::history_storage::publish_commit(
        storage, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(published.has_value()) << published.error().detail;
    EXPECT_EQ(state->remote_events,
              (std::vector<std::string>{
                  "PutCommit", "HashCommit", "PutHead", "HashHead"}));
    EXPECT_EQ(state->commit_get_count, 0U);
    EXPECT_EQ(state->marker_get_count, 0U);
}

TEST(HistoryStorageTest, TrustedOldMarkerDoesNotHideNewRemoteMarker) {
    auto workspace = kasumi::test::make_temp_workspace("history-marker-reuse");
    FakeState* state = nullptr;
    auto storage = init_fake_transport(state);
    const auto root = kasumi::test::workspace_root(workspace);
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    const auto first_commit = make_commit(0, {}, "first.txt", "first").value();
    const auto second_commit =
        make_commit(0, {}, "second.txt", "second").value();
    auto first =
        kasumi::application::history_storage::publish_commit_object_scoped(
            storage, layout, test_key(), first_commit, root);
    ASSERT_TRUE(first.has_value());
    auto first_marker =
        kasumi::application::history_storage::publish_head_marker_scoped(
            storage, layout, first->head, root);
    ASSERT_TRUE(first_marker.has_value());

    reset_remote_counts(*state);
    auto initial = kasumi::application::history_storage::load_history_scoped(
        storage, test_key(), root);
    ASSERT_TRUE(initial.has_value()) << initial.error().detail;
    EXPECT_EQ(state->marker_get_count, 1U);
    ASSERT_EQ(initial->marked_head_identifiers,
              (std::vector<std::string>{first_marker->marker_id}));

    reset_remote_counts(*state);
    auto unchanged = kasumi::application::history_storage::load_history_scoped(
        storage, test_key(), root, nullptr, initial->marked_head_identifiers);
    ASSERT_TRUE(unchanged.has_value()) << unchanged.error().detail;
    EXPECT_EQ(state->marker_get_count, 0U);

    auto second =
        kasumi::application::history_storage::publish_commit_object_scoped(
            storage, layout, test_key(), second_commit, root);
    ASSERT_TRUE(second.has_value());
    auto second_marker =
        kasumi::application::history_storage::publish_head_marker_scoped(
            storage, layout, second->head, root);
    ASSERT_TRUE(second_marker.has_value());
    reset_remote_counts(*state);
    auto changed = kasumi::application::history_storage::load_history_scoped(
        storage, test_key(), root, nullptr, initial->marked_head_identifiers);
    ASSERT_TRUE(changed.has_value()) << changed.error().detail;
    EXPECT_EQ(state->marker_get_count, 1U);
    EXPECT_EQ(changed->marked_head_identifiers.size(), 2U);
}

TEST(HistoryStorageTest, TrustedMarkerPathCannotRedirectToDifferentBytes) {
    auto storage = make_local_storage();
    const auto commit = make_commit(0, {}, "first.txt", "first").value();
    const auto published = publish(storage, commit);
    const auto trusted_marker = marker_path(published.head);
    const auto marker_file =
        kasumi::test::workspace_path(storage.workspace, "storage") /
        std::filesystem::path{trusted_marker};

    const HeadReference different_reference{published.head.commit_id,
                                            std::string(64, 'f')};
    const auto altered = kasumi::application::history_storage::encode_marker(
        different_reference);
    ASSERT_TRUE(altered.has_value());
    kasumi::test::write_binary(marker_file, std::as_bytes(std::span{*altered}));

    const kasumi::application::history_storage::KnownHistoryAnchor anchor{
        .commit_id = published.head.commit_id,
        .height = commit.height,
        .tree = commit.tree};
    const kasumi::application::history_storage::KnownHistoryFrontier frontier{
        .anchors = {anchor}, .accepted_epoch = std::nullopt};
    const std::vector<std::string> trusted{trusted_marker};

    const auto trusted_load =
        kasumi::application::history_storage::load_history_scoped(
            storage.transport,
            test_key(),
            kasumi::test::workspace_root(storage.workspace),
            &frontier,
            trusted);
    ASSERT_TRUE(trusted_load.has_value()) << trusted_load.error().detail;
    EXPECT_EQ(trusted_load->marked_head_identifiers,
              std::vector<std::string>{trusted_marker});

    const auto strict_load =
        kasumi::application::history_storage::load_history_scoped(
            storage.transport,
            test_key(),
            kasumi::test::workspace_root(storage.workspace),
            &frontier);
    ASSERT_FALSE(strict_load.has_value());
    EXPECT_EQ(strict_load.error().code, ErrorCode::InvalidMarker);
}

void add_marker_variants(LocalStorage& storage,
                         const HeadReference& base,
                         std::size_t count) {
    const auto digits = std::string{"0123456789abcdef"};
    const auto marker_file =
        kasumi::test::workspace_path(storage.workspace, "extra.head");
    std::size_t created = 0;
    for (std::size_t index = 0; created < count; ++index) {
        auto ciphertext_id = std::string(64, '0');
        ciphertext_id[62] = digits[(index >> 4) & 0x0fU];
        ciphertext_id[63] = digits[index & 0x0fU];
        if (ciphertext_id == base.ciphertext_id) {
            continue;
        }
        const HeadReference reference{base.commit_id, std::move(ciphertext_id)};
        const auto marker =
            kasumi::application::history_storage::encode_marker(reference)
                .value();
        kasumi::test::write_binary(marker_file,
                                   std::as_bytes(std::span{marker}));
        EXPECT_TRUE(kasumi::transport::put(
            storage.transport, marker_file, marker_path(reference)));
        ++created;
    }
}

std::string indexed_id(std::size_t index) {
    const auto digits = std::string{"0123456789abcdef"};
    auto result = std::string(64, '0');
    result[62] = digits[(index >> 4U) & 0x0fU];
    result[63] = digits[index & 0x0fU];
    return result;
}

void add_fake_commit_variants(FakeState& state,
                              std::string_view commit,
                              std::size_t count) {
    for (std::size_t index = 0; index < count; ++index) {
        const HeadReference reference{std::string{commit}, indexed_id(index)};
        state.objects.emplace(object_path(reference),
                              std::vector<std::uint8_t>{0});
    }
}

void add_fake_marker_variants(FakeState& state,
                              const HeadReference& base,
                              std::size_t count) {
    for (std::size_t index = 0; index < count; ++index) {
        const HeadReference reference{base.commit_id, indexed_id(index)};
        const auto marker =
            kasumi::application::history_storage::encode_marker(reference)
                .value();
        state.objects[marker_path(reference)] = marker;
    }
}

void add_fake_marked_heads(FakeState& state, std::size_t count) {
    for (std::size_t index = 0; index < count; ++index) {
        const HeadReference reference{indexed_id(index), std::string(64, 'f')};
        const auto marker =
            kasumi::application::history_storage::encode_marker(reference)
                .value();
        state.objects.emplace(marker_path(reference), marker);
    }
}

TEST(HistoryStorageTest, MarkerCodecIsDeterministicAndRejectsMalformedBytes) {
    const HeadReference reference{std::string(64, 'a'), std::string(64, 'b')};
    const auto first =
        kasumi::application::history_storage::encode_marker(reference);
    const auto second =
        kasumi::application::history_storage::encode_marker(reference);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(*first, *second);
    EXPECT_EQ(first->size(), 69U);
    EXPECT_EQ(
        kasumi::application::history_storage::decode_marker(*first).value(),
        reference);

    auto truncated = *first;
    truncated.pop_back();
    EXPECT_EQ(kasumi::application::history_storage::decode_marker(truncated)
                  .error()
                  .code,
              ErrorCode::InvalidMarker);
    auto trailing = *first;
    trailing.push_back(0);
    EXPECT_EQ(kasumi::application::history_storage::decode_marker(trailing)
                  .error()
                  .code,
              ErrorCode::InvalidMarker);
    auto bad_magic = *first;
    bad_magic[0] = 'X';
    EXPECT_EQ(kasumi::application::history_storage::decode_marker(bad_magic)
                  .error()
                  .code,
              ErrorCode::InvalidMarker);
    EXPECT_FALSE(kasumi::application::history_storage::valid(
        HeadReference{std::string(64, 'A'), std::string(64, 'b')}));
}

TEST(HistoryStorageTest, CommitAndHeadPublicationHaveSeparateDurableStages) {
    auto storage = make_local_storage();
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto key = test_key();
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(key);

    const auto object =
        kasumi::application::history_storage::publish_commit_object(
            storage.transport,
            layout,
            key,
            commit,
            kasumi::test::workspace_root(storage.workspace));
    ASSERT_TRUE(object.has_value());
    EXPECT_EQ(kasumi::transport::presence(storage.transport, object->marker_id)
                  .value(),
              kasumi::transport::Presence::Absent);
    EXPECT_EQ(kasumi::transport::presence(storage.transport,
                                          object_path(object->head))
                  .value(),
              kasumi::transport::Presence::Present);

    ASSERT_TRUE(kasumi::application::history_storage::verify_commit_object(
                    storage.transport,
                    layout,
                    key,
                    commit,
                    object->head,
                    kasumi::test::workspace_root(storage.workspace))
                    .has_value());
    const auto marker =
        kasumi::application::history_storage::publish_head_marker(
            storage.transport,
            layout,
            object->head,
            kasumi::test::workspace_root(storage.workspace));
    ASSERT_TRUE(marker.has_value());
    EXPECT_EQ(marker->marker_id, object->marker_id);
    ASSERT_TRUE(kasumi::application::history_storage::verify_head_marker(
                    storage.transport,
                    layout,
                    object->head,
                    kasumi::test::workspace_root(storage.workspace))
                    .has_value());

    const auto repeated =
        kasumi::application::history_storage::publish_commit_object(
            storage.transport,
            layout,
            key,
            commit,
            kasumi::test::workspace_root(storage.workspace));
    ASSERT_TRUE(repeated.has_value());
    EXPECT_TRUE(repeated->reused_existing_ciphertext);
}

TEST(HistoryStorageTest, PublishesLoadsAndResolvesThroughLocalTransport) {
    auto storage = make_local_storage();
    const auto base = kasumi::history::make_empty_bootstrap().value();
    const auto published = publish(storage, base);
    ASSERT_TRUE(kasumi::application::history_storage::valid(published.head));
    EXPECT_EQ(kasumi::transport::presence(storage.transport,
                                          object_path(published.head))
                  .value(),
              kasumi::transport::Presence::Present);
    EXPECT_EQ(kasumi::transport::presence(storage.transport,
                                          marker_path(published.head))
                  .value(),
              kasumi::transport::Presence::Present);

    const auto loaded = load(storage);
    ASSERT_EQ(loaded.commits.size(), 1U);
    ASSERT_EQ(loaded.marked_heads, std::vector<std::string>{commit_id(base)});
    const auto resolved = kasumi::history::resolve_authenticated(
        loaded.commits, loaded.marked_heads);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_FALSE(resolved->has_conflicts);
}

TEST(HistoryStorageTest, PublishingTwiceReusesTheExistingCiphertext) {
    auto storage = make_local_storage();
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto first = publish(storage, commit);
    const auto second = publish(storage, commit);
    EXPECT_EQ(first.head, second.head);
    EXPECT_TRUE(second.reused_existing_ciphertext);
    const auto loaded = load(storage);
    EXPECT_EQ(loaded.commits.size(), 1U);
    EXPECT_EQ(loaded.marked_heads.size(), 1U);
}

TEST(HistoryStorageTest, MultipleCiphertextVariantsBecomeOneLogicalHead) {
    auto storage = make_local_storage();
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto first = publish(storage, commit);
    const auto second = add_variant(storage, commit);
    ASSERT_NE(first.head.ciphertext_id, second.ciphertext_id);

    const auto loaded = load(storage);
    ASSERT_EQ(loaded.commits.size(), 1U);
    ASSERT_EQ(loaded.marked_heads,
              std::vector<std::string>{first.head.commit_id});
}

TEST(HistoryStorageTest, CorruptVariantFallsBackToAnotherValidVariant) {
    auto storage = make_local_storage();
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto first = publish(storage, commit);
    const auto second = add_variant(storage, commit);
    const auto corrupt =
        std::min(first.head.ciphertext_id, second.ciphertext_id);
    const HeadReference corrupt_reference{first.head.commit_id, corrupt};
    const auto path =
        kasumi::test::workspace_path(storage.workspace, "storage/") /
        std::filesystem::path{object_path(corrupt_reference)};
    kasumi::test::write_text(path, "corrupt variant");

    const auto loaded = load(storage);
    ASSERT_EQ(loaded.commits.size(), 1U);
    EXPECT_EQ(loaded.marked_heads.front(), first.head.commit_id);
}

TEST(HistoryStorageTest, ValidMarkerSurvivesAnotherInvalidMarkerForSameCommit) {
    auto storage = make_local_storage();
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto published = publish(storage, commit);
    const HeadReference invalid_marker_reference{published.head.commit_id,
                                                 std::string(64, 'c')};
    const auto marker_file =
        kasumi::test::workspace_path(storage.workspace, "invalid.head");
    kasumi::test::write_text(marker_file, "not a marker");
    ASSERT_TRUE(kasumi::transport::put(
        storage.transport, marker_file, marker_path(invalid_marker_reference)));

    const auto loaded = load(storage);
    ASSERT_EQ(loaded.commits.size(), 1U);
    EXPECT_EQ(loaded.marked_heads.front(), published.head.commit_id);
}

TEST(HistoryStorageTest, LoadsOnlyTheLatestLogicalHeadFromACompleteDag) {
    auto storage = make_local_storage();
    const auto base = kasumi::history::make_empty_bootstrap().value();
    const auto base_id = commit_id(base);
    const auto left = make_commit(1, {base_id}, "left.txt", "left").value();
    const auto right = make_commit(1, {base_id}, "right.txt", "right").value();
    const auto left_id = commit_id(left);
    const auto right_id = commit_id(right);
    const auto merge = kasumi::history::make_commit(
                           2, {left_id, right_id}, make_tree("merge.txt", "M"))
                           .value();
    publish(storage, base);
    publish(storage, left);
    publish(storage, right);
    publish(storage, merge);

    const auto loaded = load(storage);
    ASSERT_EQ(loaded.commits.size(), 4U);
    const auto resolved = kasumi::history::resolve_authenticated(
        loaded.commits, loaded.marked_heads);
    ASSERT_TRUE(resolved.has_value());
    ASSERT_EQ(resolved->heads.size(), 1U);
    EXPECT_EQ(resolved->heads.front(), commit_id(merge));
    EXPECT_NE(kasumi::find_row(resolved->tree, "merge.txt"), nullptr);
}

TEST(HistoryStorageTest, EmptyHistoryIgnoresNonHistoryObjects) {
    auto storage = make_local_storage();
    const auto source =
        kasumi::test::workspace_path(storage.workspace, "ordinary.bin");
    kasumi::test::write_text(source, "ordinary");
    ASSERT_TRUE(kasumi::transport::put(storage.transport, source, "content/x"));
    const auto loaded = load(storage);
    EXPECT_TRUE(loaded.commits.empty());
    EXPECT_TRUE(loaded.marked_heads.empty());
}

TEST(HistoryStorageTest, IgnoresLargeNonHistoryListings) {
    auto workspace =
        kasumi::test::make_temp_workspace("history-storage-large-listing");
    FakeState* state = nullptr;
    auto transport = init_fake_transport(state);
    for (std::size_t index = 0; index < 9000; ++index) {
        state->objects.emplace("content/" + std::to_string(index),
                               std::vector<std::uint8_t>{});
    }

    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto published = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(published.has_value());
    const auto loaded = kasumi::application::history_storage::load_history(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->commits.size(), 1U);
}

TEST(HistoryStorageTest, RejectsNewPublicationAtHistoryObjectLimitBeforePut) {
    auto workspace =
        kasumi::test::make_temp_workspace("history-storage-object-budget");
    FakeState* state = nullptr;
    auto transport = init_fake_transport(state);
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    for (std::size_t index = 0; index < 8192; ++index) {
        state->objects.emplace(layout.history_prefix + "unknown/" +
                                   std::to_string(index),
                               std::vector<std::uint8_t>{});
    }

    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto result = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::LimitExceeded);
    EXPECT_EQ(state->put_count, 0U);
    EXPECT_EQ(state->objects.size(), 8192U);
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        kasumi::test::workspace_root(workspace)));
}

TEST(HistoryStorageTest, IdempotentPublicationWorksAtHistoryObjectLimit) {
    auto workspace =
        kasumi::test::make_temp_workspace("history-storage-idempotent-budget");
    FakeState* state = nullptr;
    auto transport = init_fake_transport(state);
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto first = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(first.has_value());
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    for (std::size_t index = 0; index < 8190; ++index) {
        state->objects.emplace(layout.history_prefix + "unknown/" +
                                   std::to_string(index),
                               std::vector<std::uint8_t>{});
    }
    state->put_count = 0;
    const auto second = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second->head, first->head);
    EXPECT_TRUE(second->reused_existing_ciphertext);
    EXPECT_EQ(state->put_count, 0U);
    const auto loaded = kasumi::application::history_storage::load_history(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->commits.size(), 1U);
}

TEST(HistoryStorageTest, RejectsThe65thCommitVariantBeforePut) {
    auto workspace = kasumi::test::make_temp_workspace(
        "history-storage-commit-variant-budget");
    FakeState* state = nullptr;
    auto transport = init_fake_transport(state);
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    add_fake_commit_variants(*state, commit_id(commit), 64);

    const auto result = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::LimitExceeded);
    EXPECT_EQ(state->put_count, 0U);
}

TEST(HistoryStorageTest, CreatesThe64thCommitVariant) {
    auto workspace = kasumi::test::make_temp_workspace(
        "history-storage-commit-variant-boundary");
    FakeState* state = nullptr;
    auto transport = init_fake_transport(state);
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    add_fake_commit_variants(*state, commit_id(commit), 63);

    const auto result = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->reused_existing_ciphertext);
    EXPECT_EQ(state->commit_put_count, 1U);
    EXPECT_EQ(state->marker_put_count, 1U);
    const auto loaded = kasumi::application::history_storage::load_history(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->commits.size(), 1U);
}

TEST(HistoryStorageTest, RejectsThe65thMarkerVariantBeforePut) {
    auto workspace = kasumi::test::make_temp_workspace(
        "history-storage-marker-variant-budget");
    FakeState* state = nullptr;
    auto transport = init_fake_transport(state);
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto first = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(first.has_value());
    state->objects.erase(marker_path(first->head));
    add_fake_marker_variants(*state, first->head, 64);
    state->put_count = 0;

    const auto result = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::LimitExceeded);
    EXPECT_EQ(state->put_count, 0U);
    EXPECT_EQ(state->objects.size(), 65U);
}

TEST(HistoryStorageTest, CreatesThe64thMarkerVariantByReusingCiphertext) {
    auto workspace =
        kasumi::test::make_temp_workspace("history-storage-marker-boundary");
    FakeState* state = nullptr;
    auto transport = init_fake_transport(state);
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto first = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(first.has_value());
    state->objects.erase(marker_path(first->head));
    add_fake_marker_variants(*state, first->head, 63);
    state->put_count = 0;

    const auto second = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second->head, first->head);
    EXPECT_TRUE(second->reused_existing_ciphertext);
    EXPECT_EQ(state->put_count, 1U);
    const auto loaded = kasumi::application::history_storage::load_history(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(loaded.has_value());
}

TEST(HistoryStorageTest, RejectsThe65thMarkedCommitBeforePut) {
    auto workspace =
        kasumi::test::make_temp_workspace("history-storage-marked-head-budget");
    FakeState* state = nullptr;
    auto transport = init_fake_transport(state);
    add_fake_marked_heads(*state, 64);
    const auto commit = kasumi::history::make_empty_bootstrap().value();

    const auto result = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::LimitExceeded);
    EXPECT_EQ(state->put_count, 0U);
}

TEST(HistoryStorageTest, AllowsThe64thMarkedCommit) {
    auto workspace = kasumi::test::make_temp_workspace(
        "history-storage-marked-head-boundary");
    FakeState* state = nullptr;
    auto transport = init_fake_transport(state);
    add_fake_marked_heads(*state, 63);
    const auto commit = kasumi::history::make_empty_bootstrap().value();

    const auto result = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(state->put_count, 2U);
}

TEST(HistoryStorageTest, Exactly64MarkerVariantsAreAccepted) {
    auto storage = make_local_storage();
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto published = publish(storage, commit);
    add_marker_variants(storage, published.head, 63);

    const auto loaded = load(storage);
    ASSERT_EQ(loaded.commits.size(), 1U);
    EXPECT_EQ(loaded.marked_heads,
              std::vector<std::string>{published.head.commit_id});
}

TEST(HistoryStorageTest, SixtyFiveMarkerVariantsAreRejected) {
    auto storage = make_local_storage();
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto published = publish(storage, commit);
    add_marker_variants(storage, published.head, 64);

    const auto loaded = kasumi::application::history_storage::load_history(
        storage.transport,
        test_key(),
        kasumi::test::workspace_root(storage.workspace));
    ASSERT_FALSE(loaded.has_value());
    EXPECT_EQ(loaded.error().code, ErrorCode::LimitExceeded);
}

TEST(HistoryStorageTest, PropagatesCommitTransportFailure) {
    auto workspace =
        kasumi::test::make_temp_workspace("history-storage-transport-failure");
    FakeState* state = nullptr;
    auto transport = init_fake_transport(state);
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto published = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(published.has_value());

    state->fail_commit_get = true;
    const auto loaded = kasumi::application::history_storage::load_history(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(loaded.has_value());
    EXPECT_EQ(loaded.error().code, ErrorCode::TransportFailure);
}

TEST(HistoryStorageTest, PropagatesMarkerGetFailureDuringLoadAndReuse) {
    auto workspace =
        kasumi::test::make_temp_workspace("history-storage-marker-failure");
    FakeState* state = nullptr;
    auto transport = init_fake_transport(state);
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto first = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(first.has_value());
    const auto object_count = state->objects.size();

    state->fail_marker_get = true;
    const auto loaded = kasumi::application::history_storage::load_history(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(loaded.has_value());
    EXPECT_EQ(loaded.error().code, ErrorCode::TransportFailure);

    const auto republished =
        kasumi::application::history_storage::publish_commit(
            transport,
            test_key(),
            commit,
            kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(republished.has_value());
    EXPECT_EQ(republished.error().code, ErrorCode::TransportFailure);
    EXPECT_EQ(state->objects.size(), object_count);
}

TEST(HistoryStorageTest, PropagatesCommitGetFailureDuringReuse) {
    auto workspace =
        kasumi::test::make_temp_workspace("history-storage-commit-failure");
    FakeState* state = nullptr;
    auto transport = init_fake_transport(state);
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto first = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(first.has_value());
    const auto object_count = state->objects.size();

    state->fail_commit_get = true;
    const auto republished =
        kasumi::application::history_storage::publish_commit(
            transport,
            test_key(),
            commit,
            kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(republished.has_value());
    EXPECT_EQ(republished.error().code, ErrorCode::TransportFailure);
    EXPECT_EQ(state->objects.size(), object_count);
}

TEST(HistoryStorageTest, RejectsOversizedDownloadedCiphertext) {
    auto workspace =
        kasumi::test::make_temp_workspace("history-storage-large-ciphertext");
    FakeState* state = nullptr;
    auto transport = init_fake_transport(state);
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const HeadReference reference{commit_id(commit), std::string(64, 'a')};
    state->objects[object_path(reference)] =
        std::vector<std::uint8_t>(64U * 1024U * 1024U + 1024U);
    state->objects[marker_path(reference)] =
        kasumi::application::history_storage::encode_marker(reference).value();

    const auto loaded = kasumi::application::history_storage::load_history(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(loaded.has_value());
    EXPECT_EQ(loaded.error().code, ErrorCode::InvalidCiphertext);
}

TEST(HistoryStorageTest, OversizedVariantFallsBackToValidVariant) {
    auto storage = make_local_storage();
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto valid_variant = publish(storage, commit);
    const HeadReference oversized{valid_variant.head.commit_id,
                                  std::string(63, '0') + "1"};
    const auto source =
        kasumi::test::workspace_path(storage.workspace, "oversized.ciphertext");
    constexpr auto oversized_size = std::uintmax_t{64} * 1024U * 1024U + 1024U;
    std::ofstream output(source, std::ios::binary);
    ASSERT_TRUE(output);
    output.seekp(static_cast<std::streamoff>(oversized_size - 1));
    output.put('\0');
    ASSERT_TRUE(output);
    output.close();
    ASSERT_TRUE(kasumi::transport::put(
        storage.transport, source, object_path(oversized)));

    const auto loaded = load(storage);
    ASSERT_EQ(loaded.commits.size(), 1U);
    EXPECT_EQ(loaded.marked_heads.front(), valid_variant.head.commit_id);
}

TEST(HistoryStorageTest, CorruptedMarkerForcesANewImmutableVariant) {
    auto storage = make_local_storage();
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto published = publish(storage, commit);
    const auto marker =
        kasumi::test::workspace_path(storage.workspace, "storage/") /
        std::filesystem::path{marker_path(published.head)};
    kasumi::test::write_text(marker, "corrupt marker");

    const auto republished =
        kasumi::application::history_storage::publish_commit(
            storage.transport,
            test_key(),
            commit,
            kasumi::test::workspace_root(storage.workspace));
    ASSERT_TRUE(republished.has_value());
    EXPECT_FALSE(republished->reused_existing_ciphertext);
    EXPECT_EQ(republished->head.commit_id, published.head.commit_id);
    EXPECT_NE(republished->head.ciphertext_id, published.head.ciphertext_id);
    EXPECT_EQ(kasumi::test::read_text(marker), "corrupt marker");
    EXPECT_TRUE(kasumi::transport::presence(storage.transport,
                                            object_path(republished->head))
                    .value() == kasumi::transport::Presence::Present);
    EXPECT_TRUE(kasumi::transport::presence(storage.transport,
                                            marker_path(republished->head))
                    .value() == kasumi::transport::Presence::Present);
    const auto loaded = load(storage);
    ASSERT_EQ(loaded.commits.size(), 1U);
    EXPECT_EQ(loaded.marked_heads.front(), published.head.commit_id);
}

TEST(HistoryStorageTest, EmptyOptionalVariantCreatesANewCiphertext) {
    auto storage = make_local_storage();
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto published = publish(storage, commit);
    const auto object =
        kasumi::test::workspace_path(storage.workspace, "storage/") /
        std::filesystem::path{object_path(published.head)};
    kasumi::test::write_text(object, "bad ciphertext");

    const auto republished =
        kasumi::application::history_storage::publish_commit(
            storage.transport,
            test_key(),
            commit,
            kasumi::test::workspace_root(storage.workspace));
    ASSERT_TRUE(republished.has_value());
    EXPECT_FALSE(republished->reused_existing_ciphertext);
    EXPECT_NE(republished->head.ciphertext_id, published.head.ciphertext_id);
    EXPECT_EQ(kasumi::test::read_text(object), "bad ciphertext");
}

TEST(HistoryStorageTest, ParentVariantFallbackLoadsAndResolves) {
    auto storage = make_local_storage();
    const auto base = kasumi::history::make_empty_bootstrap().value();
    const auto first = publish(storage, base);
    const auto second = add_variant(storage, base);
    const auto child =
        make_commit(1, {first.head.commit_id}, "child.txt", "child").value();
    publish(storage, child);

    ASSERT_EQ(
        kasumi::transport::remove(storage.transport, marker_path(first.head))
            .value(),
        kasumi::transport::Removal::Removed);
    ASSERT_EQ(kasumi::transport::remove(storage.transport, marker_path(second))
                  .value(),
              kasumi::transport::Removal::Removed);

    const auto corrupt =
        std::min(first.head.ciphertext_id, second.ciphertext_id);
    const HeadReference corrupt_reference{first.head.commit_id, corrupt};
    const auto corrupt_path =
        kasumi::test::workspace_path(storage.workspace, "storage/") /
        std::filesystem::path{object_path(corrupt_reference)};
    kasumi::test::write_text(corrupt_path, "corrupt parent variant");

    auto loaded = load(storage);
    ASSERT_EQ(loaded.commits.size(), 2U);
    const auto resolved = kasumi::history::resolve_authenticated(
        loaded.commits, loaded.marked_heads);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->heads, std::vector<std::string>{commit_id(child)});

    const auto valid_parent =
        first.head.ciphertext_id == corrupt ? second : first.head;
    const auto valid_path =
        kasumi::test::workspace_path(storage.workspace, "storage/") /
        std::filesystem::path{object_path(valid_parent)};
    kasumi::test::write_text(valid_path, "corrupt parent variant too");
    const auto failed = kasumi::application::history_storage::load_history(
        storage.transport,
        test_key(),
        kasumi::test::workspace_root(storage.workspace));
    ASSERT_FALSE(failed.has_value());
    EXPECT_EQ(failed.error().code, ErrorCode::InvalidCiphertext);
}

TEST(HistoryStorageTest, WrongKeyIsNotAnOperationalFailure) {
    auto storage = make_local_storage();
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto published = publish(storage, commit);
    auto wrong_key = test_key();
    wrong_key[0] ^= 0xffU;
    const auto wrong_layout =
        kasumi::application::history_storage::derive_remote_layout(wrong_key);
    ASSERT_TRUE(kasumi::transport::put(
        storage.transport,
        kasumi::test::workspace_path(storage.workspace, "storage") /
            std::filesystem::path{object_path(published.head)},
        kasumi::application::history_storage::commit_object(wrong_layout,
                                                            published.head)));
    ASSERT_TRUE(kasumi::transport::put(
        storage.transport,
        kasumi::test::workspace_path(storage.workspace, "storage") /
            std::filesystem::path{marker_path(published.head)},
        kasumi::application::history_storage::marker_object(wrong_layout,
                                                            published.head)));

    const auto loaded = kasumi::application::history_storage::load_history(
        storage.transport,
        wrong_key,
        kasumi::test::workspace_root(storage.workspace));
    ASSERT_FALSE(loaded.has_value());
    EXPECT_EQ(loaded.error().code, ErrorCode::InvalidCiphertext);
}

TEST(HistoryStorageTest, TemporaryWorkspacesAreRemovedAfterSuccessAndFailure) {
    auto storage = make_local_storage();
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        kasumi::test::workspace_root(storage.workspace)));
    publish(storage, commit);
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        kasumi::test::workspace_root(storage.workspace)));
    load(storage);
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        kasumi::test::workspace_root(storage.workspace)));

    const auto marker = kasumi::transport::list(storage.transport).value();
    ASSERT_FALSE(marker.empty());
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    const auto first_marker =
        std::ranges::find_if(marker, [&](const std::string& id) {
            return id.starts_with(layout.heads_prefix);
        });
    ASSERT_NE(first_marker, marker.end());
    const auto marker_file =
        kasumi::test::workspace_path(storage.workspace, "storage/") /
        std::filesystem::path{*first_marker};
    kasumi::test::write_text(marker_file, "bad marker");
    const auto failed = kasumi::application::history_storage::load_history(
        storage.transport,
        test_key(),
        kasumi::test::workspace_root(storage.workspace));
    ASSERT_FALSE(failed.has_value());
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        kasumi::test::workspace_root(storage.workspace)));
}

TEST(HistoryStorageTest, LocalCiphertextVerificationFailureIsNotCorruption) {
    auto workspace = kasumi::test::make_temp_workspace(
        "history-storage-local-verification-failure");
    FakeState* state = nullptr;
    auto transport = init_fake_transport(state);
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto first = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(first.has_value());

    state->directory_destination = true;
    const auto result = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::WorkspaceFailure);
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        kasumi::test::workspace_root(workspace)));
}

TEST(HistoryStorageTest, MissingMarkerReusesCiphertext) {
    auto storage = make_local_storage();
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto published = publish(storage, commit);
    ASSERT_EQ(kasumi::transport::remove(storage.transport,
                                        marker_path(published.head))
                  .value(),
              kasumi::transport::Removal::Removed);

    const auto republished =
        kasumi::application::history_storage::publish_commit(
            storage.transport,
            test_key(),
            commit,
            kasumi::test::workspace_root(storage.workspace));
    ASSERT_TRUE(republished.has_value());
    EXPECT_EQ(republished->head, published.head);
    EXPECT_TRUE(republished->reused_existing_ciphertext);
    EXPECT_EQ(kasumi::transport::presence(storage.transport,
                                          marker_path(published.head))
                  .value(),
              kasumi::transport::Presence::Present);
}

TEST(HistoryStorageTest, CorruptedCiphertextAndMarkerAreNotAccepted) {
    auto storage = make_local_storage();
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto published = publish(storage, commit);
    const auto object =
        kasumi::test::workspace_path(storage.workspace, "storage/") /
        std::filesystem::path{object_path(published.head)};
    kasumi::test::write_text(object, "corrupted");
    auto loaded = kasumi::application::history_storage::load_history(
        storage.transport,
        test_key(),
        kasumi::test::workspace_root(storage.workspace));
    ASSERT_FALSE(loaded.has_value());
    EXPECT_EQ(loaded.error().code, ErrorCode::InvalidCiphertext);

    auto marker_storage = make_local_storage();
    const auto marker_published = publish(marker_storage, commit);
    const auto marker =
        kasumi::test::workspace_path(marker_storage.workspace, "storage/") /
        std::filesystem::path{marker_path(marker_published.head)};
    kasumi::test::write_text(marker, "bad marker");
    loaded = kasumi::application::history_storage::load_history(
        marker_storage.transport,
        test_key(),
        kasumi::test::workspace_root(marker_storage.workspace));
    ASSERT_FALSE(loaded.has_value());
    EXPECT_EQ(loaded.error().code, ErrorCode::InvalidMarker);
}

TEST(HistoryStorageTest, HeightMaximumIsRejectedBeforePublishing) {
    auto storage = make_local_storage();
    const auto commit = kasumi::history::make_bootstrap(
                            make_tree("max.txt", "max"),
                            std::numeric_limits<std::uint64_t>::max())
                            .value();
    const auto result = kasumi::application::history_storage::publish_commit(
        storage.transport,
        test_key(),
        commit,
        kasumi::test::workspace_root(storage.workspace));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::LimitExceeded);
    const auto listing = kasumi::transport::list(storage.transport).value();
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    EXPECT_TRUE(std::ranges::none_of(listing, [&](const std::string& id) {
        return id.starts_with(layout.heads_prefix) ||
               id.starts_with("history/heads/");
    }));
}

TEST(HistoryStorageTest, MarkerIsNeverPublishedBeforeCommitVerification) {
    auto workspace =
        kasumi::test::make_temp_workspace("history-storage-faults");
    FakeState* state = nullptr;
    auto transport = init_fake_transport(state);
    const auto commit = kasumi::history::make_empty_bootstrap().value();

    state->fail_commit_put = true;
    auto result = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(result.has_value());
    EXPECT_TRUE(std::ranges::none_of(state->objects, [](const auto& item) {
        return is_marker(item.first);
    }));

    state->fail_commit_put = false;
    state->fail_commit_get = true;
    result = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(result.has_value());
    EXPECT_TRUE(std::ranges::none_of(state->objects, [](const auto& item) {
        return is_marker(item.first);
    }));

    state->fail_commit_get = false;
    state->fail_marker_put = true;
    result = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(result.has_value());
    EXPECT_TRUE(std::ranges::none_of(state->objects, [](const auto& item) {
        return is_marker(item.first);
    }));
}

TEST(HistoryStorageTest, EmptyMarkerRemovalDoesNotList) {
    auto workspace = kasumi::test::make_temp_workspace("history-empty-prune");
    FakeState* state = nullptr;
    auto transport = init_fake_transport(state);

    const auto result =
        kasumi::application::history_storage::remove_marker_variants(
            transport, test_layout(), {});
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->removed, 0U);
    EXPECT_EQ(state->list_count, 0U);
    EXPECT_EQ(state->remove_count, 0U);
}

TEST(HistoryStorageTest, PartialMarkerRemovalCanBeRetriedIdempotently) {
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    const auto first =
        HeadReference{std::string(64, 'a'), std::string(64, '1')};
    const auto second =
        HeadReference{std::string(64, 'b'), std::string(64, '2')};
    const auto current =
        HeadReference{std::string(64, 'c'), std::string(64, '3')};
    for (const auto& reference : {first, second, current}) {
        const auto encoded =
            kasumi::application::history_storage::encode_marker(reference);
        ASSERT_TRUE(encoded.has_value());
        state->objects.emplace(marker_path(reference), *encoded);
    }
    state->fail_remove_at = 2;
    const std::array<std::string, 2> ancestral{first.commit_id,
                                               second.commit_id};
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    const auto first_attempt =
        kasumi::application::history_storage::remove_marker_variants(
            transport, layout, ancestral);
    ASSERT_FALSE(first_attempt.has_value());
    EXPECT_FALSE(state->objects.contains(marker_path(first)));
    EXPECT_TRUE(state->objects.contains(marker_path(second)));
    EXPECT_TRUE(state->objects.contains(marker_path(current)));

    state->fail_remove_at = 0;
    const auto second_attempt =
        kasumi::application::history_storage::remove_marker_variants(
            transport, layout, ancestral);
    ASSERT_TRUE(second_attempt.has_value());
    EXPECT_EQ(second_attempt->removed, 1U);
    EXPECT_FALSE(state->objects.contains(marker_path(second)));
    EXPECT_TRUE(state->objects.contains(marker_path(current)));
}

struct TestHistoryFixture {
    kasumi::test::TempWorkspace workspace;
    FakeState* state = nullptr;
    kasumi::transport::Transport storage;
    std::filesystem::path root;
    Commit commit;
    HeadReference head_ref;
};

TestHistoryFixture make_test_history_fixture(std::string_view name) {
    auto workspace = kasumi::test::make_temp_workspace(name);
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    EXPECT_TRUE(kasumi::transport::initialize(storage));
    const auto root = kasumi::test::workspace_root(workspace);

    const auto commit = make_commit(0, {}, "file.txt", "content").value();
    const auto head_ref = seed_fake_commit(*state, root, commit, "c1");

    kasumi::application::history_storage::epoch::Epoch epoch_data{
        .vault_id = std::string(64, 'a'),
        .sequence = 0,
        .issued_at = 100,
        .policy =
            {
                .min_history_depth = 1,
                .min_history_age_hours = 1,
            },
        .anchors = {{.commit_id = commit_id(commit), .height = 0}},
        .previous_epoch_id = {},
    };
    auto sealed = kasumi::application::history_storage::epoch::seal(epoch_data,
                                                                    test_key());
    EXPECT_TRUE(sealed.has_value());
    EXPECT_TRUE(kasumi::application::history_storage::epoch::publish(
        storage, test_key(), *sealed, root));

    return TestHistoryFixture{
        .workspace = std::move(workspace),
        .state = state,
        .storage = std::move(storage),
        .root = root,
        .commit = commit,
        .head_ref = head_ref,
    };
}

TEST(HistoryStorageTest,
     DemonstratesCurrentHistoryLoadingIsSerialOrConcurrent) {
    auto fixture = make_test_history_fixture("history-serial-characterization");
    HistoryReadGates gates;
    active_gates = &gates;
    fixture.storage.storage.get_batch = gated_fake_get_batch;
    fixture.storage.storage.get = gated_fake_get;

    kasumi::application::history_storage::LoadResult loaded;
    std::jthread worker([&] {
        loaded = kasumi::application::history_storage::load_history(
            fixture.storage, test_key(), fixture.root);
    });
    GatesSessionGuard guard{gates, worker};

    bool entered = false;
    {
        std::unique_lock lock(gates.mutex);
        entered = gates.cv.wait_for(lock, std::chrono::seconds(5), [&] {
            return gates.batch_entered && gates.epoch_entered &&
                   gates.marker_entered;
        });
        if (!entered) {
            FAIL() << "Timed out waiting for history load gates! Diagnostics: "
                   << "batch_entered=" << gates.batch_entered
                   << ", epoch_entered=" << gates.epoch_entered
                   << ", marker_entered=" << gates.marker_entered
                   << ", current_in_flight=" << gates.current_in_flight
                   << ", peak_in_flight=" << gates.peak_in_flight;
        }
    }
    EXPECT_TRUE(gates.batch_entered);
    EXPECT_TRUE(gates.epoch_entered);
    EXPECT_TRUE(gates.marker_entered);
    EXPECT_FALSE(gates.release_batch);
    EXPECT_FALSE(gates.release_epoch);
    EXPECT_FALSE(gates.release_marker);

    gates.release_all();
    worker.join();
    active_gates = nullptr;

    ASSERT_TRUE(loaded.has_value()) << loaded.error().detail;
    EXPECT_EQ(gates.peak_in_flight, 3U);
}

TEST(HistoryStorageTest,
     NativeCompletePathOverlapsBatchEpochAndMarkerWithPeakThree) {
    auto fixture = make_test_history_fixture("history-concurrent-peak");
    HistoryReadGates gates;
    active_gates = &gates;
    fixture.storage.storage.get_batch = gated_fake_get_batch;
    fixture.storage.storage.get = gated_fake_get;

    kasumi::application::history_storage::LoadResult loaded;
    std::jthread worker([&] {
        loaded = kasumi::application::history_storage::load_history(
            fixture.storage, test_key(), fixture.root);
    });
    GatesSessionGuard guard{gates, worker};

    bool all_three_entered = false;
    {
        std::unique_lock lock(gates.mutex);
        all_three_entered =
            gates.cv.wait_for(lock, std::chrono::seconds(5), [&] {
                return gates.batch_entered && gates.epoch_entered &&
                       gates.marker_entered;
            });
    }

    gates.release_all();
    worker.join();
    active_gates = nullptr;

    EXPECT_TRUE(all_three_entered);
    EXPECT_TRUE(gates.batch_entered);
    EXPECT_TRUE(gates.epoch_entered);
    EXPECT_TRUE(gates.marker_entered);
    EXPECT_EQ(gates.peak_in_flight, 3U);
    ASSERT_TRUE(loaded.has_value()) << loaded.error().detail;
}

TEST(HistoryStorageTest, DeterministicErrorPrecedenceBatchOverEpochAndMarker) {
    auto fixture = make_test_history_fixture("history-precedence-batch");
    HistoryReadGates gates;
    gates.fail_batch = true;
    gates.fail_epoch = true;
    gates.fail_marker = false;
    active_gates = &gates;
    fixture.storage.storage.get_batch = gated_fake_get_batch;
    fixture.storage.storage.get = gated_fake_get;

    kasumi::application::history_storage::LoadResult loaded;
    std::jthread worker([&] {
        loaded = kasumi::application::history_storage::load_history(
            fixture.storage, test_key(), fixture.root);
    });
    GatesSessionGuard guard{gates, worker};

    gates.release_all();
    worker.join();
    active_gates = nullptr;

    ASSERT_FALSE(loaded.has_value());
    EXPECT_EQ(
        loaded.error().code,
        kasumi::application::history_storage::ErrorCode::TransportFailure);
    EXPECT_NE(loaded.error().detail.find("injected batch failure"),
              std::string::npos);
}

TEST(HistoryStorageTest, DeterministicErrorPrecedenceEpochOverMarker) {
    auto fixture = make_test_history_fixture("history-precedence-epoch");
    HistoryReadGates gates;
    gates.fail_batch = false;
    gates.fail_epoch = true;
    gates.fail_marker = true;
    active_gates = &gates;
    fixture.storage.storage.get_batch = gated_fake_get_batch;
    fixture.storage.storage.get = gated_fake_get;

    kasumi::application::history_storage::LoadResult loaded;
    std::jthread worker([&] {
        loaded = kasumi::application::history_storage::load_history(
            fixture.storage, test_key(), fixture.root);
    });
    GatesSessionGuard guard{gates, worker};

    gates.release_all();
    worker.join();
    active_gates = nullptr;

    ASSERT_FALSE(loaded.has_value());
    EXPECT_EQ(
        loaded.error().code,
        kasumi::application::history_storage::ErrorCode::TransportFailure);
    EXPECT_NE(loaded.error().detail.find("injected epoch failure"),
              std::string::npos);
}

TEST(HistoryStorageTest,
     DeterministicErrorPrecedenceMarkerWhenBatchAndEpochSucceed) {
    auto fixture = make_test_history_fixture("history-precedence-marker");
    HistoryReadGates gates;
    gates.fail_batch = false;
    gates.fail_epoch = false;
    gates.fail_marker = true;
    active_gates = &gates;
    fixture.storage.storage.get_batch = gated_fake_get_batch;
    fixture.storage.storage.get = gated_fake_get;

    kasumi::application::history_storage::LoadResult loaded;
    std::jthread worker([&] {
        loaded = kasumi::application::history_storage::load_history(
            fixture.storage, test_key(), fixture.root);
    });
    GatesSessionGuard guard{gates, worker};

    gates.release_all();
    worker.join();
    active_gates = nullptr;

    ASSERT_FALSE(loaded.has_value());
    EXPECT_EQ(
        loaded.error().code,
        kasumi::application::history_storage::ErrorCode::TransportFailure);
    EXPECT_NE(loaded.error().detail.find("injected marker failure"),
              std::string::npos);
}

TEST(HistoryStorageTest, DrainsAllLanesWhenOneFailsEarly) {
    auto fixture = make_test_history_fixture("history-drain-early-failure");
    HistoryReadGates gates;
    gates.fail_batch = true;
    gates.release_batch = true;
    gates.release_epoch = false;
    gates.release_marker = false;
    active_gates = &gates;
    fixture.storage.storage.get_batch = gated_fake_get_batch;
    fixture.storage.storage.get = gated_fake_get;

    kasumi::application::history_storage::LoadResult loaded;
    std::jthread worker([&] {
        loaded = kasumi::application::history_storage::load_history(
            fixture.storage, test_key(), fixture.root);
    });
    GatesSessionGuard guard{gates, worker};

    // In a three-lane model, all lanes must be drained/joined before
    // load_history returns. Give it a short moment, then release epoch and
    // marker
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    gates.release_all();
    worker.join();
    active_gates = nullptr;

    ASSERT_FALSE(loaded.has_value());
    EXPECT_EQ(
        loaded.error().code,
        kasumi::application::history_storage::ErrorCode::TransportFailure);
}

TEST(HistoryStorageTest, RespectsGlobalCancellationAndDrains) {
    auto fixture = make_test_history_fixture("history-cancellation");
    HistoryReadGates gates;
    active_gates = &gates;
    fixture.storage.storage.get_batch = gated_fake_get_batch;
    fixture.storage.storage.get = gated_fake_get;

    kasumi::application::history_storage::LoadResult loaded;
    std::jthread worker([&] {
        loaded = kasumi::application::history_storage::load_history(
            fixture.storage, test_key(), fixture.root);
    });
    GatesSessionGuard guard{gates, worker};

    {
        std::unique_lock lock(gates.mutex);
        const bool entered =
            gates.cv.wait_for(lock, std::chrono::seconds(5), [&] {
                return gates.batch_entered || gates.epoch_entered ||
                       gates.marker_entered;
            });
        ASSERT_TRUE(entered);
    }

    kasumi::platform::cancellation::request();
    gates.release_all();
    worker.join();
    active_gates = nullptr;
    kasumi::platform::cancellation::reset();

    ASSERT_FALSE(loaded.has_value());
}

TEST(HistoryStorageTest,
     GatesSequentialOrConcurrentRepeatedRunsPreserveIsolation) {
    for (int run = 0; run < 5; ++run) {
        auto fixture = make_test_history_fixture("history-repeated-isolation");
        HistoryReadGates gates;
        active_gates = &gates;
        fixture.storage.storage.get_batch = gated_fake_get_batch;
        fixture.storage.storage.get = gated_fake_get;

        kasumi::application::history_storage::LoadResult loaded;
        std::jthread worker([&] {
            loaded = kasumi::application::history_storage::load_history(
                fixture.storage, test_key(), fixture.root);
        });
        GatesSessionGuard guard{gates, worker};

        bool entered = false;
        {
            std::unique_lock lock(gates.mutex);
            entered = gates.cv.wait_for(lock, std::chrono::seconds(5), [&] {
                return gates.batch_entered && gates.epoch_entered &&
                       gates.marker_entered;
            });
        }
        EXPECT_TRUE(entered) << "run=" << run;
        gates.release_all();
        worker.join();
        active_gates = nullptr;

        ASSERT_TRUE(loaded.has_value()) << loaded.error().detail;
        EXPECT_EQ(gates.peak_in_flight, 3U);
    }
}

TEST(HistoryStorageTest, PreservesSequentialPathWhenGetBatchIsNull) {
    auto fixture = make_test_history_fixture("history-no-get-batch");
    fixture.storage.storage.get_batch = nullptr;

    const auto loaded = kasumi::application::history_storage::load_history(
        fixture.storage, test_key(), fixture.root);

    ASSERT_TRUE(loaded.has_value()) << loaded.error().detail;
    EXPECT_EQ(loaded->commits.size(), 1U);

    const auto scoped =
        kasumi::application::history_storage::load_history_scoped(
            fixture.storage, test_key(), fixture.root);
    ASSERT_TRUE(scoped.has_value()) << scoped.error().detail;
    EXPECT_EQ(scoped->commits.size(), 1U);
    EXPECT_EQ(fixture.state->get_batch_count, 0U);
}

TEST(HistoryStorageTest, ScopedNoopOverlapsHeadsAndEpochAndDrainsFailures) {
    for (const auto failure :
         {"none", "heads", "epoch", "both", "corrupt", "cancel"}) {
        SCOPED_TRACE(failure);
        auto fixture = make_test_history_fixture("history-scoped-concurrent");
        const auto accepted_epoch =
            kasumi::application::history_storage::epoch::load_latest(
                fixture.storage, test_key(), fixture.root)
                .value()
                .value();
        const kasumi::application::history_storage::KnownHistoryFrontier
            frontier{.anchors = {{.commit_id = commit_id(fixture.commit),
                                  .height = fixture.commit.height,
                                  .tree = fixture.commit.tree}},
                     .accepted_epoch = accepted_epoch.reference};
        const std::array trusted_markers{marker_path(fixture.head_ref)};
        if (std::string_view{failure} == "corrupt") {
            const auto identifier =
                kasumi::application::history_storage::epoch::object_identifier(
                    test_layout(), accepted_epoch.reference)
                    .value();
            fixture.state->objects.at(identifier).front() ^= 0xff;
        }
        HistoryReadGates gates;
        gates.fail_heads = std::string_view{failure} == "heads" ||
                           std::string_view{failure} == "both";
        gates.fail_epoch = std::string_view{failure} == "epoch" ||
                           std::string_view{failure} == "both";
        active_gates = &gates;
        fixture.storage.storage.get_batch = gated_fake_get_batch;
        fixture.storage.storage.get = gated_fake_get;
        fixture.storage.storage.list_prefix = gated_fake_list_prefix;
        reset_remote_counts(*fixture.state);
        fixture.state->epoch_get_count = 0;

        kasumi::application::history_storage::LoadResult loaded;
        std::jthread worker([&] {
            loaded = kasumi::application::history_storage::load_history_scoped(
                fixture.storage,
                test_key(),
                fixture.root,
                &frontier,
                trusted_markers);
        });
        GatesSessionGuard guard{gates, worker};
        {
            std::unique_lock lock(gates.mutex);
            const auto overlapped =
                gates.cv.wait_for(lock, std::chrono::seconds(5), [&] {
                    return gates.heads_entered && gates.epoch_entered;
                });
            ASSERT_TRUE(overlapped);
        }
        if (std::string_view{failure} == "cancel") {
            kasumi::platform::cancellation::request();
        }
        gates.release_all();
        worker.join();
        active_gates = nullptr;
        kasumi::platform::cancellation::reset();
        EXPECT_EQ(gates.current_in_flight, 0U);
        EXPECT_EQ(gates.peak_in_flight, 2U);
        if (std::string_view{failure} == "none") {
            ASSERT_TRUE(loaded.has_value()) << loaded.error().detail;
            EXPECT_EQ(fixture.state->list_count, 2U);
            EXPECT_EQ(fixture.state->epoch_get_count, 1U);
            EXPECT_EQ(fixture.state->commit_get_count, 0U);
            EXPECT_EQ(fixture.state->marker_get_count, 0U);
            ASSERT_EQ(loaded->commits.size(), 1U);
            EXPECT_EQ(loaded->commits.front().commit.tree, fixture.commit.tree);
        } else {
            ASSERT_FALSE(loaded.has_value());
            if (gates.fail_heads) {
                EXPECT_NE(loaded.error().detail.find("heads failure"),
                          std::string::npos);
            } else if (gates.fail_epoch) {
                EXPECT_NE(loaded.error().detail.find("epoch failure"),
                          std::string::npos);
            }
        }
    }
}

namespace {

std::mutex reobservation_reads_mutex;

kasumi::transport::Result
reobservation_locked_get(void* context,
                         std::string_view id,
                         const std::filesystem::path& destination) {
    std::lock_guard lock(reobservation_reads_mutex);
    return fake_get(context, id, destination);
}

kasumi::transport::ListingResult
reobservation_locked_list(void* context, std::string_view prefix) {
    std::lock_guard lock(reobservation_reads_mutex);
    return fake_list_prefix(context, prefix);
}

kasumi::transport::Result
reobservation_read_batch(void* context,
                         const kasumi::transport::GetBatch& batch) {
    std::lock_guard lock(reobservation_reads_mutex);
    ++fake_state(context)->get_batch_count;
    EXPECT_LE(batch.identifiers.size(), 8U);
    for (const auto& id : batch.identifiers) {
        auto result = fake_get(context,
                               batch.source_prefix + "/" + id,
                               batch.destination_root / id);
        if (!result) {
            return result;
        }
    }
    return {};
}

struct ReobservationChainFixture {
    TempWorkspace workspace =
        kasumi::test::make_temp_workspace("history-reobs");
    FakeState* state = nullptr;
    kasumi::transport::Transport storage = make_fake_transport(state);
    std::vector<Commit> commits;
    std::vector<HeadReference> references;
    kasumi::application::history_storage::epoch::Reference epoch;
};

ReobservationChainFixture make_reobservation_chain(std::size_t count) {
    ReobservationChainFixture fixture;
    const auto root = kasumi::test::workspace_root(fixture.workspace);
    auto first =
        kasumi::history::make_bootstrap(make_tree("file", "base"), 0).value();
    fixture.commits.push_back(first);
    fixture.references.push_back(
        publish_object(fixture.storage, fixture.workspace, first, "initial"));
    kasumi::application::history_storage::epoch::Epoch epoch{
        .vault_id = fixture.references.front().commit_id,
        .sequence = 0,
        .issued_at = 1,
        .anchors = {{fixture.references.front().commit_id, 0}}};
    auto sealed =
        kasumi::application::history_storage::epoch::seal(epoch, test_key())
            .value();
    fixture.epoch = sealed.reference;
    EXPECT_TRUE(kasumi::application::history_storage::epoch::publish(
        fixture.storage, test_key(), sealed, root));
    for (std::size_t i = 1; i <= count; ++i) {
        auto commit = make_commit(i,
                                  {fixture.references.back().commit_id},
                                  "file",
                                  std::to_string(i))
                          .value();
        auto object =
            kasumi::application::history_storage::publish_commit_object_scoped(
                fixture.storage, test_layout(), test_key(), commit, root)
                .value();
        EXPECT_TRUE(
            kasumi::application::history_storage::publish_head_marker_scoped(
                fixture.storage, test_layout(), object.head, root));
        fixture.state->objects.erase(marker_path(fixture.references.back()));
        fixture.references.push_back(object.head);
        fixture.commits.push_back(std::move(commit));
    }
    reset_fake_traffic(*fixture.state);
    return fixture;
}

kasumi::application::history_storage::KnownHistoryFrontier
reobservation_frontier(const ReobservationChainFixture& fixture) {
    return {.anchors = {{fixture.references.front().commit_id,
                         0,
                         fixture.commits.front().tree}},
            .accepted_epoch = fixture.epoch};
}

} // namespace

TEST(HistoryStorageTest,
     ReobservationRereadsInBoundedWindowsWithoutAncestorLists) {
    auto fixture = make_reobservation_chain(33);
    auto known = reobservation_frontier(fixture);
    const auto root = kasumi::test::workspace_root(fixture.workspace);
    auto first = kasumi::application::history_storage::load_history_scoped(
        fixture.storage, test_key(), root, &known);
    ASSERT_TRUE(first);
    known.observed_variants = first->authenticated_commit_variants;
    known.observed_markers = first->marked_head_identifiers;
    known.observed_epoch = first->epoch->reference;
    fixture.storage.storage.get = reobservation_locked_get;
    fixture.storage.storage.list_prefix = reobservation_locked_list;
    fixture.storage.storage.get_batch = reobservation_read_batch;
    reset_fake_traffic(*fixture.state);
    auto second = kasumi::application::history_storage::load_history_scoped(
        fixture.storage, test_key(), root, &known);
    ASSERT_TRUE(second) << second.error().detail;
    EXPECT_EQ(second->commits.size(), first->commits.size());
    EXPECT_EQ(fixture.state->prefix_list_count, 2U);
    EXPECT_EQ(fixture.state->get_batch_count, 4U);
    EXPECT_EQ(fixture.state->commit_get_count, 33U);
}

TEST(HistoryStorageTest, ReobservationDoesNotHideMissingOrReplacedVariants) {
    for (const bool replacement : {false, true}) {
        auto fixture = make_reobservation_chain(8);
        auto known = reobservation_frontier(fixture);
        const auto root = kasumi::test::workspace_root(fixture.workspace);
        auto first = kasumi::application::history_storage::load_history_scoped(
            fixture.storage, test_key(), root, &known);
        ASSERT_TRUE(first);
        known.observed_variants = first->authenticated_commit_variants;
        known.observed_markers = first->marked_head_identifiers;
        known.observed_epoch = first->epoch->reference;
        ASSERT_TRUE(kasumi::transport::remove(
            fixture.storage, object_path(fixture.references[4])));
        if (replacement) {
            publish_object(fixture.storage,
                           fixture.workspace,
                           fixture.commits[4],
                           "replacement",
                           false);
        }
        fixture.storage.storage.get = reobservation_locked_get;
        fixture.storage.storage.list_prefix = reobservation_locked_list;
        fixture.storage.storage.get_batch = reobservation_read_batch;
        auto second = kasumi::application::history_storage::load_history_scoped(
            fixture.storage, test_key(), root, &known);
        EXPECT_EQ(second.has_value(), replacement);
        if (second) {
            EXPECT_EQ(second->commits.size(), 9U);
        }
    }
}

TEST(HistoryStorageTest, ReobservationInvalidatesHintsWhenHeadOrEpochChanges) {
    for (const bool epoch_change : {true, false}) {
        auto fixture = make_reobservation_chain(8);
        auto known = reobservation_frontier(fixture);
        const auto root = kasumi::test::workspace_root(fixture.workspace);
        auto first = kasumi::application::history_storage::load_history_scoped(
            fixture.storage, test_key(), root, &known);
        ASSERT_TRUE(first);
        known.observed_variants = first->authenticated_commit_variants;
        known.observed_markers = first->marked_head_identifiers;
        known.observed_epoch = first->epoch->reference;
        if (epoch_change) {
            kasumi::application::history_storage::epoch::Epoch next{
                .vault_id = fixture.references.front().commit_id,
                .sequence = 1,
                .issued_at = 2,
                .anchors = {{fixture.references.front().commit_id, 0}},
                .previous_epoch_id = fixture.epoch.epoch_id};
            auto sealed = kasumi::application::history_storage::epoch::seal(
                              next, test_key())
                              .value();
            ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
                fixture.storage, test_key(), sealed, root));
        } else {
            auto next = make_commit(9,
                                    {fixture.references.back().commit_id},
                                    "file",
                                    "new head")
                            .value();
            publish_object(
                fixture.storage, fixture.workspace, next, "new-head");
            fixture.state->objects.erase(
                marker_path(fixture.references.back()));
        }
        fixture.storage.storage.get = reobservation_locked_get;
        fixture.storage.storage.list_prefix = reobservation_locked_list;
        fixture.storage.storage.get_batch = reobservation_read_batch;
        reset_fake_traffic(*fixture.state);
        auto second = kasumi::application::history_storage::load_history_scoped(
            fixture.storage, test_key(), root, &known);
        ASSERT_TRUE(second) << second.error().detail;
        EXPECT_EQ(fixture.state->get_batch_count, 0U);
        EXPECT_EQ(fixture.state->prefix_list_count, 3U);
    }
}

TEST(HistoryStorageTest, CommitCacheReusesMemoryCommitsAndDownloadsOnlyNewOnes) {
    auto workspace = kasumi::test::make_temp_workspace("commit-cache-memory");
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    storage.storage.get_batch = safe_fake_get_batch;
    storage.storage.get = safe_fake_get;
    storage.storage.list_prefix = reobservation_locked_list;

    const auto root = kasumi::test::workspace_root(workspace);
    auto c0 = make_commit(0, {}, "a.txt", "alpha").value();
    auto r0 = publish(storage, workspace, c0).head;
    auto c1 = make_commit(1, {r0.commit_id}, "b.txt", "beta").value();
    auto r1 = publish(storage, workspace, c1).head;

    kasumi::application::history_storage::CommitCache cache;
    reset_fake_traffic(*state);

    auto first = kasumi::application::history_storage::load_history(
        storage, test_key(), root, &cache);
    ASSERT_TRUE(first) << first.error().detail;
    EXPECT_EQ(first->commits.size(), 2U);
    EXPECT_EQ(state->get_batch_count, 1U);
    EXPECT_EQ(state->commit_get_count, 0U);

    reset_fake_traffic(*state);
    auto second = kasumi::application::history_storage::load_history(
        storage, test_key(), root, &cache);
    ASSERT_TRUE(second) << second.error().detail;
    EXPECT_EQ(second->commits.size(), 2U);
    EXPECT_EQ(state->get_batch_count, 0U);
    EXPECT_EQ(state->commit_get_count, 0U);

    auto c2 = make_commit(2, {r1.commit_id}, "c.txt", "gamma").value();
    static_cast<void>(publish(storage, workspace, c2));
    reset_fake_traffic(*state);

    std::size_t downloaded_batch_items = 0;
    state->on_operation = [&](FakeState&,
                              std::string_view op,
                              std::string_view id) {
        if (op == "get" && id.starts_with(test_layout().commits_prefix)) {
            ++downloaded_batch_items;
        }
    };
    auto third = kasumi::application::history_storage::load_history(
        storage, test_key(), root, &cache);
    state->on_operation = nullptr;
    ASSERT_TRUE(third) << third.error().detail;
    EXPECT_EQ(third->commits.size(), 3U);
    EXPECT_EQ(state->get_batch_count, 1U);
    EXPECT_EQ(state->commit_get_count, 0U);
    // Only the 1 newly published commit object should have been fetched.
    EXPECT_EQ(downloaded_batch_items, 1U);
}

TEST(HistoryStorageTest, CommitCacheDiskCiphertextPersistsAndSelfHealsCorruption) {
    auto workspace = kasumi::test::make_temp_workspace("commit-cache-disk");
    const auto disk_root =
        kasumi::test::workspace_path(workspace, "disk-cache");
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    storage.storage.get_batch = safe_fake_get_batch;
    storage.storage.get = safe_fake_get;
    storage.storage.list_prefix = reobservation_locked_list;

    const auto root = kasumi::test::workspace_root(workspace);
    auto c0 = make_commit(0, {}, "a.txt", "alpha").value();
    auto r0 = publish(storage, workspace, c0).head;
    auto c1 = make_commit(1, {r0.commit_id}, "b.txt", "beta").value();
    auto r1 = publish(storage, workspace, c1).head;

    {
        kasumi::application::history_storage::CommitCache writer_cache;
        writer_cache.disk_cache_root = disk_root;
        writer_cache.max_memory_bytes = 0;
        writer_cache.max_memory_entries = 0;
        auto first = kasumi::application::history_storage::load_history(
            storage, test_key(), root, &writer_cache);
        ASSERT_TRUE(first) << first.error().detail;
        EXPECT_EQ(first->commits.size(), 2U);
    }

    kasumi::application::history_storage::CommitCache reader_cache;
    reader_cache.disk_cache_root = disk_root;
    reader_cache.max_memory_bytes = 0;
    reader_cache.max_memory_entries = 0;
    reset_fake_traffic(*state);

    auto second = kasumi::application::history_storage::load_history(
        storage, test_key(), root, &reader_cache);
    ASSERT_TRUE(second) << second.error().detail;
    EXPECT_EQ(second->commits.size(), 2U);
    EXPECT_EQ(state->get_batch_count, 0U);
    EXPECT_EQ(state->commit_get_count, 0U);

    // Corrupt one cached ciphertext file on disk and verify automatic self-heal.
    auto cached_file =
        kasumi::application::history_storage::lookup_cached_ciphertext_path(
            reader_cache, test_layout().commits_prefix, r1);
    ASSERT_TRUE(cached_file.has_value());
    kasumi::test::write_text(*cached_file, "corrupted-ciphertext");

    reset_fake_traffic(*state);
    auto third = kasumi::application::history_storage::load_history(
        storage, test_key(), root, &reader_cache);
    ASSERT_TRUE(third) << third.error().detail;
    EXPECT_EQ(third->commits.size(), 2U);
    // Remote fallback fetched r1 once and re-healed it on disk.
    EXPECT_EQ(state->commit_get_count, 1U);

    reset_fake_traffic(*state);
    auto fourth = kasumi::application::history_storage::load_history(
        storage, test_key(), root, &reader_cache);
    ASSERT_TRUE(fourth) << fourth.error().detail;
    EXPECT_EQ(fourth->commits.size(), 2U);
    EXPECT_EQ(state->get_batch_count, 0U);
    EXPECT_EQ(state->commit_get_count, 0U);
}

TEST(HistoryStorageTest, CommitCacheDoesNotHideDeletedCommitWithDanglingMarker) {
    auto workspace = kasumi::test::make_temp_workspace("commit-cache-dangling");
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    storage.storage.get_batch = safe_fake_get_batch;
    storage.storage.get = safe_fake_get;
    storage.storage.list_prefix = reobservation_locked_list;

    const auto root = kasumi::test::workspace_root(workspace);
    auto c0 = make_commit(0, {}, "a.txt", "alpha").value();
    auto r0 = publish(storage, workspace, c0).head;

    kasumi::application::history_storage::CommitCache cache;
    cache.disk_cache_root =
        kasumi::test::workspace_path(workspace, "disk-cache");

    auto first = kasumi::application::history_storage::load_history(
        storage, test_key(), root, &cache);
    ASSERT_TRUE(first) << first.error().detail;
    EXPECT_EQ(first->commits.size(), 1U);

    // Delete the remote commit object while leaving its head marker intact.
    ASSERT_TRUE(kasumi::transport::remove(storage, object_path(r0)));
    auto second = kasumi::application::history_storage::load_history(
        storage, test_key(), root, &cache);
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, ErrorCode::MissingCommit);
}

TEST(HistoryStorageTest, CommitCacheRespectsMemoryEvictionAndClear) {
    auto workspace = kasumi::test::make_temp_workspace("commit-cache-evict");
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    storage.storage.get_batch = safe_fake_get_batch;
    storage.storage.get = safe_fake_get;
    storage.storage.list_prefix = reobservation_locked_list;

    const auto root = kasumi::test::workspace_root(workspace);
    auto c0 = make_commit(0, {}, "a.txt", "alpha").value();
    auto r0 = publish(storage, workspace, c0).head;
    auto c1 = make_commit(1, {r0.commit_id}, "b.txt", "beta").value();
    auto r1 = publish(storage, workspace, c1).head;

    kasumi::application::history_storage::CommitCache cache;
    cache.max_memory_entries = 1U;

    auto first = kasumi::application::history_storage::load_history(
        storage, test_key(), root, &cache);
    ASSERT_TRUE(first) << first.error().detail;
    EXPECT_EQ(cache.memory_entries.size(), 1U);

    // A different keyed namespace with identical commit/ciphertext IDs must not
    // collide with the cached entry.
    EXPECT_FALSE(
        kasumi::application::history_storage::lookup_cached_commit(
            cache, "deadbeef/01234567/", r0)
            .has_value());
    EXPECT_FALSE(
        kasumi::application::history_storage::lookup_cached_commit(
            cache, "deadbeef/01234567/", r1)
            .has_value());

    kasumi::application::history_storage::clear_memory_cache(cache);
    EXPECT_TRUE(cache.memory_entries.empty());
    EXPECT_EQ(cache.current_memory_bytes, 0U);
}

TEST(HistoryStorageTest, CommitCacheLookupByIdFindsCachedCommitAcrossNamespaces) {
    auto workspace = kasumi::test::make_temp_workspace("commit-cache-by-id");
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    storage.storage.get_batch = safe_fake_get_batch;
    storage.storage.get = safe_fake_get;
    storage.storage.list_prefix = reobservation_locked_list;

    const auto root = kasumi::test::workspace_root(workspace);
    auto c0 = make_commit(0, {}, "a.txt", "alpha").value();
    auto r0 = publish(storage, workspace, c0).head;

    kasumi::application::history_storage::CommitCache cache;
    auto first = kasumi::application::history_storage::load_history(
        storage, test_key(), root, &cache);
    ASSERT_TRUE(first) << first.error().detail;

    auto hit = kasumi::application::history_storage::lookup_cached_commit_by_id(
        cache, test_layout().commits_prefix, r0.commit_id);
    ASSERT_TRUE(hit.has_value());
    EXPECT_EQ(hit->id, r0.commit_id);
    EXPECT_EQ(hit->commit.tree, c0.tree);

    EXPECT_FALSE(
        kasumi::application::history_storage::lookup_cached_commit_by_id(
            cache, "deadbeef/01234567/", r0.commit_id)
            .has_value());
    EXPECT_FALSE(
        kasumi::application::history_storage::lookup_cached_commit_by_id(
            cache, test_layout().commits_prefix, "not-a-hex-id")
            .has_value());
}

TEST(HistoryStorageTest, CommitCacheReusesCachedEpochsAndValidatedMarkers) {
    auto workspace =
        kasumi::test::make_temp_workspace("commit-cache-epoch-marker");
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    storage.storage.get_batch = safe_fake_get_batch;
    storage.storage.get = safe_fake_get;
    storage.storage.list_prefix = reobservation_locked_list;

    const auto root = kasumi::test::workspace_root(workspace);
    auto c0 = make_commit(0, {}, "a.txt", "alpha").value();
    auto r0 = publish(storage, workspace, c0).head;
    auto c1 = make_commit(1, {r0.commit_id}, "b.txt", "beta").value();
    auto r1 = publish(storage, workspace, c1).head;
    auto c2 = make_commit(2, {r1.commit_id}, "c.txt", "gamma").value();
    auto r2 = publish(storage, workspace, c2).head;
    state->objects.erase(marker_path(r0));
    state->objects.erase(marker_path(r1));

    kasumi::application::history_storage::epoch::Epoch epoch_value{
        .vault_id = r0.commit_id,
        .sequence = 0,
        .issued_at = 1,
        .anchors = {{r1.commit_id, 1}},
    };
    auto sealed_epoch =
        kasumi::application::history_storage::epoch::seal(epoch_value, test_key())
            .value();
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        storage, test_key(), sealed_epoch, root));

    kasumi::application::history_storage::CommitCache warm_cache;
    warm_cache.disk_cache_root =
        kasumi::test::workspace_path(workspace, "disk-cache");

    reset_fake_traffic(*state);
    auto first = kasumi::application::history_storage::load_history(
        storage, test_key(), root, &warm_cache);
    ASSERT_TRUE(first) << first.error().detail;
    EXPECT_EQ(state->epoch_get_count, 1U);
    EXPECT_EQ(state->marker_get_count, 1U);

    // Warm in-memory cache skips epoch, marker, and commit downloads cleanly.
    reset_fake_traffic(*state);
    auto second = kasumi::application::history_storage::load_history(
        storage, test_key(), root, &warm_cache);
    ASSERT_TRUE(second) << second.error().detail;
    EXPECT_EQ(second->commits.size(), 2U);
    EXPECT_EQ(state->epoch_get_count, 0U);
    EXPECT_EQ(state->marker_get_count, 0U);
    EXPECT_EQ(state->get_batch_count, 0U);
    EXPECT_EQ(state->commit_get_count, 0U);

    // Cold RAM with same disk cache still skips epoch download by opening and
    // authenticating the sealed KEPA file on disk.
    kasumi::application::history_storage::CommitCache disk_only_cache;
    disk_only_cache.disk_cache_root = warm_cache.disk_cache_root;
    reset_fake_traffic(*state);
    auto third = kasumi::application::history_storage::load_history(
        storage, test_key(), root, &disk_only_cache);
    ASSERT_TRUE(third) << third.error().detail;
    EXPECT_EQ(third->commits.size(), 2U);
    EXPECT_EQ(state->epoch_get_count, 0U);
    EXPECT_EQ(state->marker_get_count, 1U);
    EXPECT_EQ(state->get_batch_count, 0U);
    EXPECT_EQ(state->commit_get_count, 0U);

    // Corrupt the cached sealed epoch file on disk and verify self-healing.
    std::filesystem::path cached_epoch_file;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(
             warm_cache.disk_cache_root)) {
        if (entry.is_regular_file() &&
            entry.path().filename().string().ends_with(
                "_" + sealed_epoch.reference.epoch_id)) {
            cached_epoch_file = entry.path();
            break;
        }
    }
    ASSERT_FALSE(cached_epoch_file.empty());
    kasumi::test::write_text(cached_epoch_file, "corrupted-epoch-envelope");

    kasumi::application::history_storage::CommitCache corrupted_disk_cache;
    corrupted_disk_cache.disk_cache_root = warm_cache.disk_cache_root;
    reset_fake_traffic(*state);
    auto healed = kasumi::application::history_storage::load_history(
        storage, test_key(), root, &corrupted_disk_cache);
    ASSERT_TRUE(healed) << healed.error().detail;
    EXPECT_EQ(state->epoch_get_count, 1U);

    kasumi::application::history_storage::CommitCache after_heal_cache;
    after_heal_cache.disk_cache_root = warm_cache.disk_cache_root;
    reset_fake_traffic(*state);
    auto after_heal = kasumi::application::history_storage::load_history(
        storage, test_key(), root, &after_heal_cache);
    ASSERT_TRUE(after_heal) << after_heal.error().detail;
    EXPECT_EQ(state->epoch_get_count, 0U);

    // Complete listing prunes deleted remote commits (even pre-seeded ones)
    // from RAM CommitCache.
    kasumi::application::history_storage::store_cached_commit(
        warm_cache,
        test_layout().commits_prefix,
        r0,
        kasumi::history::LoadedCommit{.id = r0.commit_id, .commit = c0});
    ASSERT_TRUE(
        kasumi::application::history_storage::lookup_cached_commit_by_id(
            warm_cache, test_layout().commits_prefix, r0.commit_id)
            .has_value());
    ASSERT_TRUE(kasumi::transport::remove(storage, object_path(r0)));

    reset_fake_traffic(*state);
    auto fourth = kasumi::application::history_storage::load_history(
        storage, test_key(), root, &warm_cache);
    ASSERT_TRUE(fourth) << fourth.error().detail;
    EXPECT_EQ(state->epoch_get_count, 0U);
    EXPECT_EQ(state->marker_get_count, 0U);
    EXPECT_FALSE(
        kasumi::application::history_storage::lookup_cached_commit_by_id(
            warm_cache, test_layout().commits_prefix, r0.commit_id)
            .has_value());
}

} // namespace
