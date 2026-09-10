#include "application/history_storage/history_storage.hpp"
#include "application/history_storage/publication.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/history_storage.hpp"

namespace {

void reset_remote_counts(FakeState& state) {
    state.list_count = 0;
    state.get_count = 0;
    state.commit_get_count = 0;
    state.marker_get_count = 0;
    state.physical_hash_count = 0;
}

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

TEST(HistoryStorageTest, CompleteLoadConsumesOneNativeCommitBatch) {
    auto workspace =
        kasumi::test::make_temp_workspace("history-native-get-batch");
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    const auto root = kasumi::test::workspace_root(workspace);

    const auto parent = make_commit(0, {}, "file.txt", "zero").value();
    const auto published_parent =
        seed_fake_commit(*state, root, parent, "parent");
    const auto child =
        make_commit(1, {published_parent.commit_id}, "file.txt", "one").value();
    seed_fake_commit(*state, root, child, "child");

    storage.storage.get_batch = fake_get_batch;
    reset_remote_counts(*state);
    state->get_batch_count = 0;
    const auto loaded = kasumi::application::history_storage::load_history(
        storage, test_key(), root);

    ASSERT_TRUE(loaded.has_value()) << loaded.error().detail;
    EXPECT_EQ(loaded->commits.size(), 2U);
    EXPECT_EQ(state->get_batch_count, 1U);
    EXPECT_EQ(state->commit_get_count, 0U);
}

TEST(HistoryStorageTest,
     InspectsOnlySelectedPhysicalCommitVariantsWithoutMutation) {
    auto workspace =
        kasumi::test::make_temp_workspace("history-inspect-variants");
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
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
    auto storage = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
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
            storage, object->head, root);
    ASSERT_TRUE(marker.has_value()) << marker.error().detail;
    EXPECT_EQ(state->marker_put_count, 1U);
    EXPECT_EQ(state->physical_hash_count, 1U);
}

TEST(HistoryStorageTest, AmbiguousDeleteConfirmsAbsenceWithoutRetry) {
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    state->objects["object"] = {'x'};
    state->remove_then_fail_identifier = "object";

    const auto removed = kasumi::transport::remove(storage, "object");

    ASSERT_TRUE(removed.has_value());
    EXPECT_EQ(*removed, kasumi::transport::Removal::Removed);
    EXPECT_EQ(state->remove_count, 1U);
    EXPECT_EQ(state->presence_count, 1U);
}

TEST(HistoryStorageTest, StrongPhysicalHashAvoidsCommitAndHeadReadback) {
    auto workspace = kasumi::test::make_temp_workspace("history-physical-hash");
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
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
            storage, object->head, root);
    ASSERT_TRUE(marker.has_value()) << marker.error().detail;
    EXPECT_EQ(state->list_count, 0U);
    reset_remote_counts(*state);
    auto head_verified =
        kasumi::application::history_storage::verify_head_marker(
            storage, object->head, root, marker->physical_hash);
    ASSERT_TRUE(head_verified.has_value()) << head_verified.error().detail;
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->marker_get_count, 0U);
}

TEST(HistoryStorageTest, UnsupportedPhysicalHashFallsBackToSemanticReadback) {
    auto workspace = kasumi::test::make_temp_workspace("history-hash-fallback");
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    const auto commit = make_commit(0, {}, "file.txt", "contents").value();
    const auto root = kasumi::test::workspace_root(workspace);

    auto object =
        kasumi::application::history_storage::publish_commit_object_scoped(
            storage, test_key(), commit, root);
    ASSERT_TRUE(object.has_value());
    reset_remote_counts(*state);
    ASSERT_TRUE(kasumi::application::history_storage::verify_commit_object(
        storage,
        test_key(),
        commit,
        object->head,
        root,
        object->physical_hash));
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->commit_get_count, 1U);

    auto marker =
        kasumi::application::history_storage::publish_head_marker_scoped(
            storage, object->head, root);
    ASSERT_TRUE(marker.has_value());
    reset_remote_counts(*state);
    ASSERT_TRUE(kasumi::application::history_storage::verify_head_marker(
        storage, object->head, root, marker->physical_hash));
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->marker_get_count, 1U);
}

TEST(HistoryStorageTest, PhysicalHashMismatchFailsCommitAndHeadVerification) {
    auto workspace = kasumi::test::make_temp_workspace("history-hash-mismatch");
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    state->physical_hash_supported = true;
    const auto commit = make_commit(0, {}, "file.txt", "contents").value();
    const auto root = kasumi::test::workspace_root(workspace);
    auto object =
        kasumi::application::history_storage::publish_commit_object_scoped(
            storage, test_key(), commit, root);
    ASSERT_TRUE(object.has_value());
    auto marker =
        kasumi::application::history_storage::publish_head_marker_scoped(
            storage, object->head, root);
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
            storage, object->head, root, marker->physical_hash);
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
    auto storage = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    state->physical_hash_supported = true;
    const auto commit = make_commit(0, {}, "file.txt", "contents").value();
    const auto root = kasumi::test::workspace_root(workspace);
    auto object =
        kasumi::application::history_storage::publish_commit_object_scoped(
            storage, test_key(), commit, root);
    ASSERT_TRUE(object.has_value());
    auto marker =
        kasumi::application::history_storage::publish_head_marker_scoped(
            storage, object->head, root);
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
            storage, object->head, root, marker->physical_hash);
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
    auto storage = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
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
    auto storage = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    const auto root = kasumi::test::workspace_root(workspace);
    const auto first_commit = make_commit(0, {}, "first.txt", "first").value();
    const auto second_commit =
        make_commit(0, {}, "second.txt", "second").value();
    auto first =
        kasumi::application::history_storage::publish_commit_object_scoped(
            storage, test_key(), first_commit, root);
    ASSERT_TRUE(first.has_value());
    auto first_marker =
        kasumi::application::history_storage::publish_head_marker_scoped(
            storage, first->head, root);
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
            storage, test_key(), second_commit, root);
    ASSERT_TRUE(second.has_value());
    auto second_marker =
        kasumi::application::history_storage::publish_head_marker_scoped(
            storage, second->head, root);
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

    const auto object =
        kasumi::application::history_storage::publish_commit_object(
            storage.transport,
            key,
            commit,
            kasumi::test::workspace_root(storage.workspace));
    ASSERT_TRUE(object.has_value());
    EXPECT_EQ(kasumi::transport::presence(storage.transport, object->marker_id)
                  .value(),
              kasumi::transport::Presence::Absent);
    EXPECT_EQ(kasumi::transport::presence(
                  storage.transport,
                  "history/commits/" + object->head.commit_id + "/" +
                      object->head.ciphertext_id + ".kcom")
                  .value(),
              kasumi::transport::Presence::Present);

    ASSERT_TRUE(kasumi::application::history_storage::verify_commit_object(
                    storage.transport,
                    key,
                    commit,
                    object->head,
                    kasumi::test::workspace_root(storage.workspace))
                    .has_value());
    const auto marker =
        kasumi::application::history_storage::publish_head_marker(
            storage.transport,
            object->head,
            kasumi::test::workspace_root(storage.workspace));
    ASSERT_TRUE(marker.has_value());
    EXPECT_EQ(marker->marker_id, object->marker_id);
    ASSERT_TRUE(kasumi::application::history_storage::verify_head_marker(
                    storage.transport,
                    object->head,
                    kasumi::test::workspace_root(storage.workspace))
                    .has_value());

    const auto repeated =
        kasumi::application::history_storage::publish_commit_object(
            storage.transport,
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
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
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
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    for (std::size_t index = 0; index < 8192; ++index) {
        state->objects.emplace("history/unknown/" + std::to_string(index),
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
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto first = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(first.has_value());
    for (std::size_t index = 0; index < 8190; ++index) {
        state->objects.emplace("history/unknown/" + std::to_string(index),
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
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
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
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
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
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
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
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
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
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
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
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
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
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
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
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
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
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
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
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
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
    publish(storage, commit);
    auto wrong_key = test_key();
    wrong_key[0] ^= 0xffU;
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
    const auto first_marker =
        std::ranges::find_if(marker, [](const std::string& id) {
            return id.starts_with("history/heads/");
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
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
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
    EXPECT_TRUE(std::ranges::none_of(listing, [](const std::string& id) {
        return id.starts_with("history/heads/");
    }));
}

TEST(HistoryStorageTest, MarkerIsNeverPublishedBeforeCommitVerification) {
    auto workspace =
        kasumi::test::make_temp_workspace("history-storage-faults");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
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
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto result =
        kasumi::application::history_storage::remove_marker_variants(transport,
                                                                     {});
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
    const auto first_attempt =
        kasumi::application::history_storage::remove_marker_variants(transport,
                                                                     ancestral);
    ASSERT_FALSE(first_attempt.has_value());
    EXPECT_FALSE(state->objects.contains(marker_path(first)));
    EXPECT_TRUE(state->objects.contains(marker_path(second)));
    EXPECT_TRUE(state->objects.contains(marker_path(current)));

    state->fail_remove_at = 0;
    const auto second_attempt =
        kasumi::application::history_storage::remove_marker_variants(transport,
                                                                     ancestral);
    ASSERT_TRUE(second_attempt.has_value());
    EXPECT_EQ(second_attempt->removed, 1U);
    EXPECT_FALSE(state->objects.contains(marker_path(second)));
    EXPECT_TRUE(state->objects.contains(marker_path(current)));
}

} // namespace
