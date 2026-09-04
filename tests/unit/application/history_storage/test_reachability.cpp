#include "application/history_storage/reachability.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/history_storage.hpp"

#include <algorithm>
#include <array>
#include <map>
#include <span>

namespace {

using kasumi::application::history_storage::ReachabilityInventory;
using kasumi::application::history_storage::ReachabilityMarkerState;
using kasumi::application::history_storage::ReachabilityVariant;
using kasumi::application::history_storage::detail::VariantState;

HeadReference add_fake_commit(kasumi::transport::Transport& transport,
                              TempWorkspace& workspace,
                              const Commit& commit,
                              std::string_view suffix,
                              bool add_marker = true) {
    const auto canonical = kasumi::history::serialize(commit).value();
    const auto plain =
        kasumi::test::workspace_path(workspace, std::string{suffix} + ".plain");
    const auto cipher = kasumi::test::workspace_path(
        workspace, std::string{suffix} + ".cipher");
    kasumi::test::write_binary(plain, std::as_bytes(std::span{canonical}));
    EXPECT_TRUE(kasumi::crypto::encrypt_file(
        plain, cipher, test_key(), kasumi::crypto::FilePurpose::History));
    const auto hash = kasumi::crypto::content::hash_file(cipher).value();
    const HeadReference reference{commit_id(commit), kasumi::hash_hex(hash)};
    EXPECT_TRUE(
        kasumi::transport::put(transport, cipher, object_path(reference)));
    if (add_marker) {
        const auto marker =
            kasumi::application::history_storage::encode_marker(reference)
                .value();
        const auto marker_file = kasumi::test::workspace_path(
            workspace, std::string{suffix} + ".head");
        kasumi::test::write_binary(marker_file,
                                   std::as_bytes(std::span{marker}));
        EXPECT_TRUE(kasumi::transport::put(
            transport, marker_file, marker_path(reference)));
    }
    return reference;
}

HeadReference add_fake_payload(kasumi::transport::Transport& transport,
                               TempWorkspace& workspace,
                               std::string_view commit_identifier,
                               std::span<const std::uint8_t> payload,
                               std::string_view suffix,
                               bool add_marker = true) {
    const auto plain =
        kasumi::test::workspace_path(workspace, std::string{suffix} + ".plain");
    const auto cipher = kasumi::test::workspace_path(
        workspace, std::string{suffix} + ".cipher");
    kasumi::test::write_binary(plain, std::as_bytes(payload));
    EXPECT_TRUE(kasumi::crypto::encrypt_file(
        plain, cipher, test_key(), kasumi::crypto::FilePurpose::History));
    const auto hash = kasumi::crypto::content::hash_file(cipher).value();
    const HeadReference reference{std::string{commit_identifier},
                                  kasumi::hash_hex(hash)};
    EXPECT_TRUE(
        kasumi::transport::put(transport, cipher, object_path(reference)));
    if (add_marker) {
        const auto marker =
            kasumi::application::history_storage::encode_marker(reference)
                .value();
        const auto marker_file = kasumi::test::workspace_path(
            workspace, std::string{suffix} + ".head");
        kasumi::test::write_binary(marker_file,
                                   std::as_bytes(std::span{marker}));
        EXPECT_TRUE(kasumi::transport::put(
            transport, marker_file, marker_path(reference)));
    }
    return reference;
}

void add_fake_marker(FakeState& state, const HeadReference& reference) {
    state.objects[marker_path(reference)] =
        kasumi::application::history_storage::encode_marker(reference).value();
}

const kasumi::application::history_storage::ReachabilityCommit*
find_commit(const ReachabilityInventory& inventory, std::string_view id) {
    const auto found =
        std::ranges::find_if(inventory.commits, [id](const auto& commit) {
            return commit.commit_id == id;
        });
    return found == inventory.commits.end() ? nullptr : &*found;
}

const ReachabilityVariant* find_variant(
    const kasumi::application::history_storage::ReachabilityCommit& commit,
    const HeadReference& reference) {
    const auto found = std::ranges::find(
        commit.variants, reference, &ReachabilityVariant::reference);
    return found == commit.variants.end() ? nullptr : &*found;
}

ReachabilityInventory inventory(LocalStorage& storage) {
    const auto result =
        kasumi::application::history_storage::inventory_reachability(
            storage.transport,
            test_key(),
            kasumi::test::workspace_root(storage.workspace));
    EXPECT_TRUE(result.has_value()) << result.error().detail;
    return result ? *result : ReachabilityInventory{};
}

ReachabilityInventory fake_inventory(kasumi::transport::Transport& transport,
                                     TempWorkspace& workspace) {
    const auto result =
        kasumi::application::history_storage::inventory_reachability(
            transport, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_TRUE(result.has_value()) << result.error().detail;
    return result ? *result : ReachabilityInventory{};
}

TEST(ReachabilityTest, EmptyHistoryProducesEmptyReachabilityInventory) {
    static_cast<void>(&load);
    auto storage = make_local_storage();
    const auto result = inventory(storage);
    EXPECT_TRUE(result.logical_heads.empty());
    EXPECT_TRUE(result.reachable_commits.empty());
    EXPECT_TRUE(result.orphan_commits.empty());
    EXPECT_TRUE(result.unknown_history_objects.empty());
}

TEST(ReachabilityTest, BootstrapCommitIsReachableFromSingleHead) {
    auto storage = make_local_storage();
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto published = publish(storage, commit);
    const auto result = inventory(storage);
    ASSERT_EQ(result.logical_heads,
              std::vector<std::string>{published.head.commit_id});
    ASSERT_EQ(result.reachable_commits,
              std::vector<std::string>{published.head.commit_id});
    EXPECT_TRUE(result.orphan_commits.empty());
    const auto* entry = find_commit(result, published.head.commit_id);
    ASSERT_NE(entry, nullptr);
    EXPECT_TRUE(entry->valid);
    EXPECT_TRUE(entry->reachable);
    ASSERT_EQ(entry->variants.size(), 1U);
    EXPECT_EQ(entry->variants.front().state, VariantState::Valid);
    EXPECT_EQ(result.markers.front().state, ReachabilityMarkerState::Valid);
}

TEST(ReachabilityTest, LinearHistoryMarksEveryAncestorReachable) {
    auto storage = make_local_storage();
    const auto base = kasumi::history::make_empty_bootstrap().value();
    const auto child =
        make_commit(1, {commit_id(base)}, "child.txt", "child").value();
    const auto tip =
        make_commit(2, {commit_id(child)}, "tip.txt", "tip").value();
    const auto first = publish(storage, base);
    const auto second = publish(storage, child);
    const auto third = publish(storage, tip);
    ASSERT_EQ(
        kasumi::transport::remove(storage.transport, marker_path(first.head))
            .value(),
        kasumi::transport::Removal::Removed);
    ASSERT_EQ(
        kasumi::transport::remove(storage.transport, marker_path(second.head))
            .value(),
        kasumi::transport::Removal::Removed);
    const auto result = inventory(storage);
    auto expected_reachable = std::vector<std::string>{
        commit_id(base), commit_id(child), commit_id(tip)};
    std::ranges::sort(expected_reachable);
    EXPECT_EQ(result.logical_heads,
              std::vector<std::string>{third.head.commit_id});
    EXPECT_EQ(result.reachable_commits, expected_reachable);
    EXPECT_TRUE(result.orphan_commits.empty());
}

TEST(ReachabilityTest, MultiHeadSharesReachableAncestors) {
    auto storage = make_local_storage();
    const auto base = kasumi::history::make_empty_bootstrap().value();
    const auto left =
        make_commit(1, {commit_id(base)}, "left.txt", "left").value();
    const auto right =
        make_commit(1, {commit_id(base)}, "right.txt", "right").value();
    const auto base_ref = publish(storage, base);
    const auto left_ref = publish(storage, left);
    const auto right_ref = publish(storage, right);
    ASSERT_EQ(
        kasumi::transport::remove(storage.transport, marker_path(base_ref.head))
            .value(),
        kasumi::transport::Removal::Removed);
    const auto result = inventory(storage);
    auto expected_heads = std::vector<std::string>{left_ref.head.commit_id,
                                                   right_ref.head.commit_id};
    auto expected_reachable = std::vector<std::string>{
        commit_id(base), commit_id(left), commit_id(right)};
    std::ranges::sort(expected_heads);
    std::ranges::sort(expected_reachable);
    EXPECT_EQ(result.logical_heads, expected_heads);
    EXPECT_EQ(result.reachable_commits, expected_reachable);
    EXPECT_EQ(std::ranges::count(result.reachable_commits, commit_id(base)), 1);
}

TEST(ReachabilityTest, UnmarkedValidCommitIsOrphan) {
    auto storage = make_local_storage();
    const auto reachable = kasumi::history::make_empty_bootstrap().value();
    const auto orphan = make_commit(0, {}, "orphan.txt", "orphan").value();
    const auto reachable_ref = publish(storage, reachable);
    const auto orphan_ref = publish(storage, orphan);
    ASSERT_EQ(kasumi::transport::remove(storage.transport,
                                        marker_path(orphan_ref.head))
                  .value(),
              kasumi::transport::Removal::Removed);
    const auto result = inventory(storage);
    EXPECT_EQ(result.reachable_commits,
              std::vector<std::string>{reachable_ref.head.commit_id});
    EXPECT_EQ(result.orphan_commits,
              std::vector<std::string>{orphan_ref.head.commit_id});
}

TEST(ReachabilityTest, UnmarkedValidChainIsOrphan) {
    auto storage = make_local_storage();
    const auto first = kasumi::history::make_empty_bootstrap().value();
    const auto second =
        make_commit(1, {commit_id(first)}, "second", "2").value();
    const auto first_ref = publish(storage, first);
    const auto second_ref = publish(storage, second);
    ASSERT_EQ(kasumi::transport::remove(storage.transport,
                                        marker_path(first_ref.head))
                  .value(),
              kasumi::transport::Removal::Removed);
    ASSERT_EQ(kasumi::transport::remove(storage.transport,
                                        marker_path(second_ref.head))
                  .value(),
              kasumi::transport::Removal::Removed);
    const auto result = inventory(storage);
    EXPECT_TRUE(result.reachable_commits.empty());
    EXPECT_EQ(result.orphan_commits,
              (std::vector<std::string>{commit_id(first), commit_id(second)}));
}

TEST(ReachabilityTest, ReachableCommitReportsMissingParent) {
    auto storage = make_local_storage();
    const auto missing = std::string(64, 'a');
    const auto child = make_commit(1, {missing}, "child.txt", "child").value();
    const auto child_ref = add_variant(storage, child);
    const auto result = inventory(storage);
    EXPECT_EQ(result.reachable_commits,
              std::vector<std::string>{child_ref.commit_id});
    EXPECT_EQ(result.missing_parent_ids, std::vector<std::string>{missing});
    EXPECT_TRUE(result.invalid_parent_ids.empty());
}

TEST(ReachabilityTest, ParentWithOnlyMissingMarkerVariantIsMissing) {
    auto workspace =
        kasumi::test::make_temp_workspace("reachability-missing-marker-parent");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto parent = kasumi::history::make_empty_bootstrap().value();
    const HeadReference missing{commit_id(parent), std::string(64, 'a')};
    add_fake_marker(*state, missing);
    const auto child =
        make_commit(1, {missing.commit_id}, "child", "child").value();
    const auto child_ref =
        add_fake_commit(transport, workspace, child, "child");

    const auto result = fake_inventory(transport, workspace);
    EXPECT_EQ(result.reachable_commits,
              std::vector<std::string>{child_ref.commit_id});
    EXPECT_EQ(result.missing_parent_ids,
              std::vector<std::string>{missing.commit_id});
    EXPECT_TRUE(result.invalid_parent_ids.empty());
    const auto* entry = find_commit(result, missing.commit_id);
    ASSERT_NE(entry, nullptr);
    ASSERT_NE(find_variant(*entry, missing), nullptr);
    EXPECT_EQ(find_variant(*entry, missing)->state, VariantState::Missing);
    const auto marker =
        std::ranges::find_if(result.markers, [&missing](const auto& value) {
            return value.reference.has_value() &&
                   value.reference->commit_id == missing.commit_id &&
                   value.reference->ciphertext_id == missing.ciphertext_id;
        });
    ASSERT_NE(marker, result.markers.end());
    EXPECT_EQ(marker->state, ReachabilityMarkerState::MissingCommit);
}

TEST(ReachabilityTest, MultipleMissingVariantsRemainMissingParent) {
    auto workspace = kasumi::test::make_temp_workspace(
        "reachability-multiple-missing-parent");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto parent = kasumi::history::make_empty_bootstrap().value();
    const HeadReference first{commit_id(parent), std::string(64, 'a')};
    const HeadReference second{commit_id(parent), std::string(64, 'b')};
    add_fake_marker(*state, first);
    add_fake_marker(*state, second);
    const auto child =
        make_commit(1, {first.commit_id}, "child", "child").value();
    const auto child_ref =
        add_fake_commit(transport, workspace, child, "child");

    const auto result = fake_inventory(transport, workspace);
    EXPECT_EQ(result.reachable_commits,
              std::vector<std::string>{child_ref.commit_id});
    EXPECT_EQ(result.missing_parent_ids,
              std::vector<std::string>{first.commit_id});
    EXPECT_TRUE(result.invalid_parent_ids.empty());
    const auto* entry = find_commit(result, first.commit_id);
    ASSERT_NE(entry, nullptr);
    ASSERT_EQ(entry->variants.size(), 2U);
    EXPECT_EQ(find_variant(*entry, first)->state, VariantState::Missing);
    EXPECT_EQ(find_variant(*entry, second)->state, VariantState::Missing);
}

TEST(ReachabilityTest, InvalidCiphertextParentIsInvalid) {
    auto workspace = kasumi::test::make_temp_workspace(
        "reachability-invalid-ciphertext-parent");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto parent = kasumi::history::make_empty_bootstrap().value();
    const HeadReference invalid{commit_id(parent), std::string(64, 'a')};
    state->objects[object_path(invalid)] = {0};
    const auto child =
        make_commit(1, {invalid.commit_id}, "child", "child").value();
    const auto child_ref =
        add_fake_commit(transport, workspace, child, "child");

    const auto result = fake_inventory(transport, workspace);
    EXPECT_EQ(result.reachable_commits,
              std::vector<std::string>{child_ref.commit_id});
    EXPECT_EQ(result.invalid_parent_ids,
              std::vector<std::string>{invalid.commit_id});
    EXPECT_TRUE(result.missing_parent_ids.empty());
    EXPECT_EQ(
        find_variant(*find_commit(result, invalid.commit_id), invalid)->state,
        VariantState::InvalidCiphertext);
}

TEST(ReachabilityTest, InvalidCommitParentIsInvalid) {
    auto workspace =
        kasumi::test::make_temp_workspace("reachability-invalid-commit-parent");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto parent = kasumi::history::make_empty_bootstrap().value();
    const std::array<std::uint8_t, 3> payload{1, 2, 3};
    const auto invalid = add_fake_payload(
        transport, workspace, commit_id(parent), payload, "invalid", false);
    const auto child =
        make_commit(1, {invalid.commit_id}, "child", "child").value();
    const auto child_ref =
        add_fake_commit(transport, workspace, child, "child");

    const auto result = fake_inventory(transport, workspace);
    EXPECT_EQ(result.reachable_commits,
              std::vector<std::string>{child_ref.commit_id});
    EXPECT_EQ(result.invalid_parent_ids,
              std::vector<std::string>{invalid.commit_id});
    EXPECT_TRUE(result.missing_parent_ids.empty());
    EXPECT_EQ(
        find_variant(*find_commit(result, invalid.commit_id), invalid)->state,
        VariantState::InvalidCommit);
}

TEST(ReachabilityTest, MissingAndInvalidVariantsProduceInvalidParent) {
    auto workspace = kasumi::test::make_temp_workspace(
        "reachability-missing-invalid-parent");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto parent = kasumi::history::make_empty_bootstrap().value();
    const HeadReference missing{commit_id(parent), std::string(64, 'a')};
    add_fake_marker(*state, missing);
    const HeadReference invalid{commit_id(parent), std::string(64, 'b')};
    state->objects[object_path(invalid)] = {0};
    const auto child =
        make_commit(1, {commit_id(parent)}, "child", "child").value();
    const auto child_ref =
        add_fake_commit(transport, workspace, child, "child");

    const auto result = fake_inventory(transport, workspace);
    EXPECT_EQ(result.reachable_commits,
              std::vector<std::string>{child_ref.commit_id});
    EXPECT_EQ(result.invalid_parent_ids,
              std::vector<std::string>{missing.commit_id});
    EXPECT_TRUE(result.missing_parent_ids.empty());
    static_cast<void>(invalid);
}

TEST(ReachabilityTest, MissingAndValidVariantsProduceValidParent) {
    auto workspace =
        kasumi::test::make_temp_workspace("reachability-missing-valid-parent");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto parent = kasumi::history::make_empty_bootstrap().value();
    const HeadReference missing{commit_id(parent), std::string(64, 'a')};
    add_fake_marker(*state, missing);
    const auto valid =
        add_fake_commit(transport, workspace, parent, "valid", false);
    const auto child =
        make_commit(1, {valid.commit_id}, "child", "child").value();
    const auto child_ref =
        add_fake_commit(transport, workspace, child, "child");

    const auto result = fake_inventory(transport, workspace);
    auto expected_reachable =
        std::vector<std::string>{child_ref.commit_id, valid.commit_id};
    std::ranges::sort(expected_reachable);
    EXPECT_EQ(result.reachable_commits, expected_reachable);
    EXPECT_TRUE(result.missing_parent_ids.empty());
    EXPECT_TRUE(result.invalid_parent_ids.empty());
    EXPECT_EQ(
        find_variant(*find_commit(result, valid.commit_id), missing)->state,
        VariantState::Missing);
    EXPECT_EQ(find_variant(*find_commit(result, valid.commit_id), valid)->state,
              VariantState::Valid);
}

TEST(ReachabilityTest, InvalidAndValidVariantsProduceValidParent) {
    auto workspace =
        kasumi::test::make_temp_workspace("reachability-invalid-valid-parent");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto parent = kasumi::history::make_empty_bootstrap().value();
    const std::array<std::uint8_t, 3> payload{1, 2, 3};
    const auto invalid = add_fake_payload(
        transport, workspace, commit_id(parent), payload, "invalid", false);
    const auto valid =
        add_fake_commit(transport, workspace, parent, "valid", false);
    const auto child =
        make_commit(1, {valid.commit_id}, "child", "child").value();
    const auto child_ref =
        add_fake_commit(transport, workspace, child, "child");

    const auto result = fake_inventory(transport, workspace);
    auto expected_reachable =
        std::vector<std::string>{child_ref.commit_id, valid.commit_id};
    std::ranges::sort(expected_reachable);
    EXPECT_EQ(result.reachable_commits, expected_reachable);
    EXPECT_TRUE(result.missing_parent_ids.empty());
    EXPECT_TRUE(result.invalid_parent_ids.empty());
    EXPECT_EQ(
        find_variant(*find_commit(result, valid.commit_id), invalid)->state,
        VariantState::InvalidCommit);
    EXPECT_EQ(find_variant(*find_commit(result, valid.commit_id), valid)->state,
              VariantState::Valid);
}

TEST(ReachabilityTest, ParentDisappearingAfterListingIsMissing) {
    auto workspace =
        kasumi::test::make_temp_workspace("reachability-disappearing-parent");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto parent = kasumi::history::make_empty_bootstrap().value();
    const HeadReference disappearing{commit_id(parent), std::string(64, 'a')};
    state->objects[object_path(disappearing)] = {0};
    const auto child =
        make_commit(1, {disappearing.commit_id}, "child", "child").value();
    const auto child_ref =
        add_fake_commit(transport, workspace, child, "child");
    state->disappear_on_get = object_path(disappearing);

    const auto result = fake_inventory(transport, workspace);
    EXPECT_EQ(result.reachable_commits,
              std::vector<std::string>{child_ref.commit_id});
    EXPECT_EQ(result.missing_parent_ids,
              std::vector<std::string>{disappearing.commit_id});
    EXPECT_TRUE(result.invalid_parent_ids.empty());
    EXPECT_EQ(
        find_variant(*find_commit(result, disappearing.commit_id), disappearing)
            ->state,
        VariantState::Missing);
}

TEST(ReachabilityTest, SelfParentOrCycleInvariantIsEnforced) {
    const auto candidate =
        make_commit(1, {std::string(64, '0')}, "candidate", "candidate")
            .value();
    const auto candidate_id = commit_id(candidate);
    auto self_parent = candidate;
    self_parent.parents.front() = candidate_id;

    EXPECT_NE(commit_id(self_parent), self_parent.parents.front());
}

TEST(ReachabilityTest, ReachableCommitReportsInvalidParent) {
    auto workspace =
        kasumi::test::make_temp_workspace("reachability-invalid-parent");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto invalid_parent = std::string(64, 'a');
    const HeadReference invalid_reference{invalid_parent, std::string(64, 'b')};
    state->objects[object_path(invalid_reference)] = {0};
    const auto child =
        make_commit(1, {invalid_parent}, "child.txt", "child").value();
    const auto child_ref =
        add_fake_commit(transport, workspace, child, "child");
    state->put_count = 0;
    state->remove_count = 0;
    const auto result = fake_inventory(transport, workspace);
    EXPECT_EQ(result.reachable_commits,
              std::vector<std::string>{child_ref.commit_id});
    EXPECT_EQ(result.invalid_parent_ids,
              std::vector<std::string>{invalid_parent});
    EXPECT_TRUE(result.missing_parent_ids.empty());
}

TEST(ReachabilityTest, MultipleCiphertextVariantsAreClassified) {
    auto storage = make_local_storage();
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto first = add_variant(storage, commit);
    const auto second = add_variant(storage, commit);
    const auto result = inventory(storage);
    const auto* entry = find_commit(result, first.commit_id);
    ASSERT_NE(entry, nullptr);
    ASSERT_EQ(entry->variants.size(), 2U);
    EXPECT_EQ(find_variant(*entry, first)->state, VariantState::Valid);
    EXPECT_EQ(find_variant(*entry, second)->state, VariantState::Valid);
    EXPECT_EQ(result.logical_heads, std::vector<std::string>{first.commit_id});
}

TEST(ReachabilityTest, MarkerReferencingInvalidVariantIsNotLogicalHead) {
    auto workspace =
        kasumi::test::make_temp_workspace("reachability-invalid-variant");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto valid =
        add_fake_commit(transport, workspace, commit, "valid", false);
    const auto invalid = HeadReference{valid.commit_id, std::string(64, 'b')};
    state->objects[object_path(invalid)] = {0};
    const auto marker =
        kasumi::application::history_storage::encode_marker(invalid).value();
    state->objects[marker_path(invalid)] = marker;
    state->put_count = 0;
    const auto result = fake_inventory(transport, workspace);
    EXPECT_TRUE(result.logical_heads.empty());
    const auto* entry = find_commit(result, valid.commit_id);
    ASSERT_NE(entry, nullptr);
    EXPECT_TRUE(entry->valid);
    EXPECT_EQ(find_variant(*entry, invalid)->state,
              VariantState::InvalidCiphertext);
    ASSERT_EQ(result.markers.size(), 1U);
    EXPECT_EQ(result.markers.front().state,
              ReachabilityMarkerState::InvalidCiphertext);
    EXPECT_EQ(result.orphan_commits, std::vector<std::string>{valid.commit_id});
}

TEST(ReachabilityTest, MultipleValidMarkersProduceOneLogicalHead) {
    auto storage = make_local_storage();
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto first = add_variant(storage, commit);
    const auto second = add_variant(storage, commit);
    const auto result = inventory(storage);
    EXPECT_EQ(result.logical_heads, std::vector<std::string>{first.commit_id});
    EXPECT_EQ(std::ranges::count_if(result.markers,
                                    [](const auto& marker) {
                                        return marker.state ==
                                               ReachabilityMarkerState::Valid;
                                    }),
              2);
    static_cast<void>(second);
}

TEST(ReachabilityTest, UnknownHistoryObjectsAreReported) {
    auto workspace = kasumi::test::make_temp_workspace("reachability-unknown");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->objects["history/foo"] = {0};
    state->objects["history/commits/x"] = {0};
    state->objects["history/random/object"] = {0};
    state->objects["history/heads/bad.head"] = {0};
    const auto result = fake_inventory(transport, workspace);
    EXPECT_EQ(result.unknown_history_objects,
              (std::vector<std::string>{"history/commits/x",
                                        "history/foo",
                                        "history/heads/bad.head",
                                        "history/random/object"}));
    EXPECT_TRUE(result.markers.empty());
}

TEST(ReachabilityTest, InvalidCiphertextIsReported) {
    auto workspace =
        kasumi::test::make_temp_workspace("reachability-invalid-ciphertext");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const HeadReference reference{commit_id(commit), std::string(64, 'c')};
    state->objects[object_path(reference)] = {0};
    const auto marker =
        kasumi::application::history_storage::encode_marker(reference).value();
    state->objects[marker_path(reference)] = marker;
    const auto result = fake_inventory(transport, workspace);
    const auto* entry = find_commit(result, reference.commit_id);
    ASSERT_NE(entry, nullptr);
    EXPECT_FALSE(entry->valid);
    EXPECT_EQ(entry->variants.front().state, VariantState::InvalidCiphertext);
    EXPECT_EQ(result.markers.front().state,
              ReachabilityMarkerState::InvalidCiphertext);
    EXPECT_TRUE(result.orphan_commits.empty());
}

TEST(ReachabilityTest, MarkerReferencingMissingCommitIsReported) {
    auto workspace =
        kasumi::test::make_temp_workspace("reachability-missing-marker-commit");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const HeadReference reference{std::string(64, 'd'), std::string(64, 'e')};
    state->objects[marker_path(reference)] =
        kasumi::application::history_storage::encode_marker(reference).value();
    const auto result = fake_inventory(transport, workspace);
    ASSERT_EQ(result.markers.size(), 1U);
    EXPECT_EQ(result.markers.front().state,
              ReachabilityMarkerState::MissingCommit);
    EXPECT_TRUE(result.logical_heads.empty());
    const auto* entry = find_commit(result, reference.commit_id);
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->variants.front().state, VariantState::Missing);
}

TEST(ReachabilityTest, InvalidMarkerBytesAreReported) {
    auto workspace =
        kasumi::test::make_temp_workspace("reachability-invalid-marker");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const HeadReference reference{std::string(64, 'f'), std::string(64, '0')};
    state->objects[marker_path(reference)] = {1, 2, 3};
    const auto result = fake_inventory(transport, workspace);
    ASSERT_EQ(result.markers.size(), 1U);
    EXPECT_EQ(result.markers.front().state,
              ReachabilityMarkerState::InvalidMarker);
    EXPECT_TRUE(result.logical_heads.empty());
}

TEST(ReachabilityTest, InvalidCommitIsReported) {
    auto workspace =
        kasumi::test::make_temp_workspace("reachability-invalid-commit");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const std::array<std::uint8_t, 3> payload{1, 2, 3};
    const auto reference = add_fake_payload(
        transport, workspace, commit_id(commit), payload, "invalid");
    const auto result = fake_inventory(transport, workspace);
    const auto* entry = find_commit(result, reference.commit_id);
    ASSERT_NE(entry, nullptr);
    EXPECT_FALSE(entry->valid);
    EXPECT_EQ(entry->variants.front().state, VariantState::InvalidCommit);
    EXPECT_EQ(result.markers.front().state,
              ReachabilityMarkerState::InvalidCommit);
}

TEST(ReachabilityTest, InventoryIsReadOnly) {
    auto workspace =
        kasumi::test::make_temp_workspace("reachability-read-only");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    add_fake_commit(transport, workspace, commit, "read-only");
    state->put_count = 0;
    state->remove_count = 0;
    const auto before = state->objects;
    const auto result = fake_inventory(transport, workspace);
    ASSERT_FALSE(result.commits.empty());
    EXPECT_EQ(state->objects, before);
    EXPECT_EQ(state->put_count, 0U);
    EXPECT_EQ(state->remove_count, 0U);
    EXPECT_FALSE(
        kasumi::test::has_temporary_history_workspace(kasumi::test::workspace_root(workspace)));
}

TEST(ReachabilityTest, InventoryIsDeterministicAcrossListingOrder) {
    auto workspace = kasumi::test::make_temp_workspace("reachability-order");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    add_fake_commit(transport, workspace, commit, "order");
    state->put_count = 0;
    const auto first = fake_inventory(transport, workspace);
    state->reverse_listing = true;
    const auto second = fake_inventory(transport, workspace);
    EXPECT_EQ(first.logical_heads, second.logical_heads);
    EXPECT_EQ(first.reachable_commits, second.reachable_commits);
    EXPECT_EQ(first.orphan_commits, second.orphan_commits);
    EXPECT_EQ(first.unknown_history_objects, second.unknown_history_objects);
    ASSERT_EQ(first.commits.size(), second.commits.size());
    EXPECT_EQ(first.commits.front().commit_id,
              second.commits.front().commit_id);
    EXPECT_EQ(first.commits.front().variants.front().reference,
              second.commits.front().variants.front().reference);
}

TEST(ReachabilityTest, InventoryCleansTemporaryWorkspaceAfterFailure) {
    auto workspace = kasumi::test::make_temp_workspace("reachability-cleanup");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    add_fake_commit(transport, workspace, commit, "failure");
    state->put_count = 0;
    state->fail_commit_get = true;
    const auto result =
        kasumi::application::history_storage::inventory_reachability(
            transport, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_FALSE(
        kasumi::test::has_temporary_history_workspace(kasumi::test::workspace_root(workspace)));
}

} // namespace
