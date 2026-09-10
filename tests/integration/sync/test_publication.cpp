#include "application/sync/publication.hpp"
#include "kasumi/test/history_storage.hpp"

namespace {

TEST(HistoryStorageTest, EmptyCurrentPruneOnlyObservesOnce) {
    auto workspace =
        kasumi::test::make_temp_workspace("history-empty-current-prune");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto result =
        kasumi::application::sync::publication::prune_current_ancestral_markers(
            transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->removed_markers, 0U);
    EXPECT_EQ(state->list_count, 2U);
    EXPECT_EQ(state->remove_count, 0U);
}

TEST(HistoryStorageTest, PublicationFindsAncestralCommitByReachability) {
    auto storage = make_local_storage();
    const auto base = kasumi::history::make_empty_bootstrap().value();
    const auto base_id = commit_id(base);
    ASSERT_TRUE(publish(storage, base).head.commit_id == base_id);
    const auto child =
        kasumi::history::make_commit(
            1, {base_id}, kasumi::history::make_empty_bootstrap().value().tree)
            .value();
    ASSERT_TRUE(publish(storage, child).head.commit_id == commit_id(child));

    const auto found =
        kasumi::application::sync::publication::find_reachable_commit(
            storage.transport,
            test_key(),
            kasumi::test::workspace_root(storage.workspace),
            base_id);
    ASSERT_TRUE(found.has_value());
    ASSERT_TRUE(*found);
    EXPECT_EQ(found->value().id, base_id);
}

TEST(HistoryStorageTest, RemovesAllPhysicalVariantsOfAncestralMarker) {
    auto storage = make_local_storage();
    const auto root = make_commit(0, {}, "root.txt", "root");
    ASSERT_TRUE(root.has_value());
    const auto root_published = publish(storage, *root);
    ASSERT_FALSE(root_published.head.commit_id.empty());
    const auto extra = add_variant(storage, *root);
    const auto child =
        make_commit(1, {root_published.head.commit_id}, "child.txt", "child");
    ASSERT_TRUE(child.has_value());
    const auto child_published = publish(storage, *child);
    ASSERT_FALSE(child_published.head.commit_id.empty());

    const auto pruned =
        kasumi::application::sync::publication::prune_current_ancestral_markers(
            storage.transport,
            test_key(),
            kasumi::test::workspace_root(storage.workspace));
    ASSERT_TRUE(pruned.has_value());
    EXPECT_EQ(pruned->removed_markers, 2U);
    const auto listing = kasumi::transport::list(storage.transport);
    ASSERT_TRUE(listing.has_value());
    EXPECT_FALSE(std::ranges::any_of(*listing, [&](const auto& id) {
        return id == marker_path(root_published.head);
    }));
    EXPECT_FALSE(std::ranges::any_of(*listing, [&](const auto& id) {
        return id == marker_path(extra);
    }));
    EXPECT_TRUE(std::ranges::any_of(*listing, [&](const auto& id) {
        return id == marker_path(child_published.head);
    }));
    EXPECT_EQ(std::ranges::count_if(*listing,
                                    [](const auto& id) {
                                        return id.starts_with(
                                            "history/commits/");
                                    }),
              3);
}

TEST(HistoryStorageTest, PrunesSixtyFourMarkedCommitsAndPreservesCommits) {
    auto storage = make_local_storage();
    std::vector<std::string> parents;
    std::vector<kasumi::application::history_storage::PublishedCommit>
        published;
    published.reserve(64);
    for (std::size_t index = 0; index < 64; ++index) {
        const auto commit =
            make_commit(index, parents, "file.txt", std::to_string(index));
        ASSERT_TRUE(commit.has_value());
        auto result = publish(storage, *commit);
        ASSERT_FALSE(result.head.commit_id.empty());
        parents = {result.head.commit_id};
        published.push_back(result);
    }

    const auto pruned =
        kasumi::application::sync::publication::prune_current_ancestral_markers(
            storage.transport,
            test_key(),
            kasumi::test::workspace_root(storage.workspace));
    ASSERT_TRUE(pruned.has_value());
    EXPECT_EQ(pruned->removed_markers, 63U);
    const auto listing = kasumi::transport::list(storage.transport);
    ASSERT_TRUE(listing.has_value());
    EXPECT_EQ(std::ranges::count_if(*listing,
                                    [](const auto& id) {
                                        return id.starts_with(
                                            "history/commits/");
                                    }),
              64);
    EXPECT_EQ(std::ranges::count_if(*listing,
                                    [](const auto& id) {
                                        return id.starts_with("history/heads/");
                                    }),
              1);
    EXPECT_TRUE(std::ranges::any_of(*listing, [&](const auto& id) {
        return id == marker_path(published.back().head);
    }));
    const auto observed = load(storage);
    ASSERT_EQ(observed.marked_heads.size(), 1U);
    EXPECT_EQ(observed.marked_heads.front(), published.back().head.commit_id);
}

} // namespace
