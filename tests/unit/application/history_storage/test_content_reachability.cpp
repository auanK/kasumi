#include "application/history_storage/content_reachability.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/history_storage.hpp"

#include <algorithm>
#include <array>
#include <map>
#include <span>

namespace {

using kasumi::NodeRow;
using kasumi::Snapshot;
using kasumi::application::history_storage::ContentEntry;
using kasumi::application::history_storage::ContentObjectState;
using kasumi::application::history_storage::ContentReachabilityInventory;
using kasumi::application::history_storage::ReachabilityInventory;

Commit make_tree_commit(std::uint64_t height,
                        std::vector<std::string> parents,
                        std::vector<NodeRow> rows) {
    Snapshot tree{.rows = std::move(rows)};
    kasumi::finalize_snapshot(tree);
    return kasumi::history::make_commit(height, std::move(parents), tree)
        .value();
}

NodeRow file_row(std::string path,
                 std::string_view contents,
                 std::optional<std::uint64_t> size = std::nullopt) {
    return NodeRow{.path = std::move(path),
                   .hash = kasumi::hasher::hash_string(contents),
                   .size = size.value_or(contents.size()),
                   .is_directory = false};
}

std::string content_id(std::string_view contents) {
    return kasumi::crypto::content_identifier(
        test_key(), kasumi::hasher::hash_string(contents));
}

void put_encrypted_payload(kasumi::transport::Transport& transport,
                           TempWorkspace& workspace,
                           std::string_view identifier,
                           std::string_view contents,
                           std::string_view suffix) {
    const auto plain =
        kasumi::test::workspace_path(workspace, std::string{suffix} + ".plain");
    const auto encrypted =
        kasumi::test::workspace_path(workspace, std::string{suffix} + ".enc");
    kasumi::test::write_text(plain, contents);
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, encrypted, test_key()));
    ASSERT_TRUE(kasumi::transport::put(transport, encrypted, identifier));
}

HeadReference add_fake_commit(kasumi::transport::Transport& transport,
                              TempWorkspace& workspace,
                              const Commit& commit,
                              std::string_view suffix) {
    const auto canonical = kasumi::history::serialize(commit).value();
    const auto plain =
        kasumi::test::workspace_path(workspace, std::string{suffix} + ".plain");
    const auto encrypted =
        kasumi::test::workspace_path(workspace, std::string{suffix} + ".enc");
    kasumi::test::write_binary(plain, std::as_bytes(std::span{canonical}));
    EXPECT_TRUE(kasumi::crypto::encrypt_file(
        plain, encrypted, test_key(), kasumi::crypto::FilePurpose::History));
    const auto hash = kasumi::crypto::content::hash_file(encrypted).value();
    const HeadReference reference{commit_id(commit), kasumi::hash_hex(hash)};
    EXPECT_TRUE(
        kasumi::transport::put(transport, encrypted, object_path(reference)));
    const auto marker =
        kasumi::application::history_storage::encode_marker(reference).value();
    const auto marker_file =
        kasumi::test::workspace_path(workspace, std::string{suffix} + ".head");
    kasumi::test::write_binary(marker_file, std::as_bytes(std::span{marker}));
    EXPECT_TRUE(
        kasumi::transport::put(transport, marker_file, marker_path(reference)));
    return reference;
}

ReachabilityInventory history_inventory(kasumi::transport::Transport& transport,
                                        const std::filesystem::path& root) {
    const auto result =
        kasumi::application::history_storage::inventory_reachability(
            transport, test_key(), root);
    EXPECT_TRUE(result.has_value()) << result.error().detail;
    return result ? *result : ReachabilityInventory{};
}

ContentReachabilityInventory
content_inventory(kasumi::transport::Transport& transport,
                  const std::filesystem::path& root,
                  bool audit_payloads = true) {
    const auto history = history_inventory(transport, root);
    const auto result =
        kasumi::application::history_storage::inventory_content_reachability(
            transport, test_key(), history, root, audit_payloads);
    EXPECT_TRUE(result.has_value()) << result.error().detail;
    return result ? *result : ContentReachabilityInventory{};
}

const ContentEntry* find_content(const ContentReachabilityInventory& inventory,
                                 std::string_view identifier) {
    const auto found = std::ranges::find_if(
        inventory.contents, [identifier](const auto& entry) {
            return entry.content_id == identifier;
        });
    return found == inventory.contents.end() ? nullptr : &*found;
}

TEST(ContentReachabilityTest, EmptyHistoryProducesEmptyContentInventory) {
    static_cast<void>(&add_variant);
    static_cast<void>(&load);
    static_cast<void>(&make_commit);
    auto storage = make_local_storage();
    const auto result = content_inventory(
        storage.transport, kasumi::test::workspace_root(storage.workspace));
    EXPECT_TRUE(result.reachable_content_ids.empty());
    EXPECT_TRUE(result.missing_content_ids.empty());
    EXPECT_TRUE(result.corrupt_content_ids.empty());
    EXPECT_TRUE(result.orphan_content_ids.empty());
}

TEST(ContentReachabilityTest, BootstrapWithoutFilesHasNoReachableContent) {
    auto storage = make_local_storage();
    publish(storage, kasumi::history::make_empty_bootstrap().value());
    const auto result = content_inventory(
        storage.transport, kasumi::test::workspace_root(storage.workspace));
    EXPECT_TRUE(result.reachable_content_ids.empty());
    EXPECT_TRUE(result.contents.empty());
}

TEST(ContentReachabilityTest, SingleReachableFileIsPresent) {
    auto storage = make_local_storage();
    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("alpha.txt", "alpha")});
    publish(storage, commit);
    const auto identifier = content_id("alpha");
    put_encrypted_payload(
        storage.transport, storage.workspace, identifier, "alpha", "present");

    const auto result = content_inventory(
        storage.transport, kasumi::test::workspace_root(storage.workspace));
    EXPECT_EQ(result.reachable_content_ids,
              std::vector<std::string>{identifier});
    EXPECT_TRUE(result.missing_content_ids.empty());
    EXPECT_TRUE(result.corrupt_content_ids.empty());
    ASSERT_EQ(result.contents.size(), 1U);
    EXPECT_EQ(result.contents.front().state, ContentObjectState::Present);
    EXPECT_TRUE(result.contents.front().reachable);
}

TEST(ContentReachabilityTest, DuplicateContentInOneCommitIsDeduplicated) {
    auto storage = make_local_storage();
    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("a.txt", "same"),
                          file_row("b.txt", "same")});
    publish(storage, commit);
    const auto identifier = content_id("same");
    put_encrypted_payload(storage.transport,
                          storage.workspace,
                          identifier,
                          "same",
                          "duplicate-tree");

    const auto result = content_inventory(
        storage.transport, kasumi::test::workspace_root(storage.workspace));
    ASSERT_EQ(result.contents.size(), 1U);
    ASSERT_EQ(result.contents.front().references.size(), 2U);
    EXPECT_EQ(result.contents.front().references[0].path, "a.txt");
    EXPECT_EQ(result.contents.front().references[1].path, "b.txt");
}

TEST(ContentReachabilityTest, DuplicateContentAcrossCommitsIsDeduplicated) {
    auto storage = make_local_storage();
    const auto first = make_tree_commit(
        0,
        {},
        {NodeRow{.path = "", .is_directory = true}, file_row("a", "same")});
    const auto second = make_tree_commit(
        1,
        {commit_id(first)},
        {NodeRow{.path = "", .is_directory = true}, file_row("b", "same")});
    const auto first_published = publish(storage, first);
    publish(storage, second);
    ASSERT_EQ(kasumi::transport::remove(storage.transport,
                                        marker_path(first_published.head))
                  .value(),
              kasumi::transport::Removal::Removed);
    const auto identifier = content_id("same");
    put_encrypted_payload(storage.transport,
                          storage.workspace,
                          identifier,
                          "same",
                          "duplicate-commits");

    const auto result = content_inventory(
        storage.transport, kasumi::test::workspace_root(storage.workspace));
    ASSERT_EQ(result.contents.size(), 1U);
    EXPECT_EQ(result.contents.front().references.size(), 2U);
}

TEST(ContentReachabilityTest, DirectoriesDoNotCreateContentReferences) {
    auto storage = make_local_storage();
    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          NodeRow{.path = "docs", .is_directory = true},
                          file_row("docs/a.txt", "file")});
    publish(storage, commit);
    const auto identifier = content_id("file");
    put_encrypted_payload(
        storage.transport, storage.workspace, identifier, "file", "directory");

    const auto result = content_inventory(
        storage.transport, kasumi::test::workspace_root(storage.workspace));
    EXPECT_EQ(result.reachable_content_ids,
              std::vector<std::string>{identifier});
}

TEST(ContentReachabilityTest, MissingReachableContentIsReported) {
    auto storage = make_local_storage();
    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("missing", "missing")});
    publish(storage, commit);
    const auto identifier = content_id("missing");
    const auto result = content_inventory(
        storage.transport, kasumi::test::workspace_root(storage.workspace));
    EXPECT_EQ(result.reachable_content_ids,
              std::vector<std::string>{identifier});
    EXPECT_EQ(result.missing_content_ids, std::vector<std::string>{identifier});
    EXPECT_TRUE(result.corrupt_content_ids.empty());
    EXPECT_EQ(find_content(result, identifier)->state,
              ContentObjectState::Missing);
}

TEST(ContentReachabilityTest, CorruptReachableCiphertextIsReported) {
    auto storage = make_local_storage();
    const auto commit = make_tree_commit(
        0,
        {},
        {NodeRow{.path = "", .is_directory = true}, file_row("bad", "bad")});
    publish(storage, commit);
    const auto identifier = content_id("bad");
    const auto corrupt =
        kasumi::test::workspace_path(storage.workspace, "corrupt");
    kasumi::test::write_binary(corrupt,
                               {std::byte{0}, std::byte{1}, std::byte{2}});
    ASSERT_TRUE(kasumi::transport::put(storage.transport, corrupt, identifier));

    const auto result = content_inventory(
        storage.transport, kasumi::test::workspace_root(storage.workspace));
    EXPECT_EQ(result.corrupt_content_ids, std::vector<std::string>{identifier});
    EXPECT_TRUE(result.missing_content_ids.empty());
    EXPECT_EQ(find_content(result, identifier)->state,
              ContentObjectState::Corrupt);
}

TEST(ContentReachabilityTest, ReachableContentHashMismatchIsCorrupt) {
    auto storage = make_local_storage();
    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("bad", "expected")});
    publish(storage, commit);
    const auto identifier = content_id("expected");
    put_encrypted_payload(storage.transport,
                          storage.workspace,
                          identifier,
                          "changed",
                          "hash-mismatch");

    const auto result = content_inventory(
        storage.transport, kasumi::test::workspace_root(storage.workspace));
    EXPECT_EQ(result.corrupt_content_ids, std::vector<std::string>{identifier});
}

TEST(ContentReachabilityTest, ReachableContentSizeMismatchIsCorrupt) {
    auto storage = make_local_storage();
    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("bad", "sized", std::uint64_t{99})});
    publish(storage, commit);
    const auto identifier = content_id("sized");
    put_encrypted_payload(storage.transport,
                          storage.workspace,
                          identifier,
                          "sized",
                          "size-mismatch");

    const auto result = content_inventory(
        storage.transport, kasumi::test::workspace_root(storage.workspace));
    EXPECT_EQ(result.corrupt_content_ids, std::vector<std::string>{identifier});
}

TEST(ContentReachabilityTest, ConflictingSizesForSameContentAreRejected) {
    auto storage = make_local_storage();
    const auto first =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("a", "same", std::uint64_t{4})});
    const auto second =
        make_tree_commit(1,
                         {commit_id(first)},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("b", "same", std::uint64_t{9})});
    const auto first_published = publish(storage, first);
    publish(storage, second);
    ASSERT_EQ(kasumi::transport::remove(storage.transport,
                                        marker_path(first_published.head))
                  .value(),
              kasumi::transport::Removal::Removed);

    const auto history = history_inventory(
        storage.transport, kasumi::test::workspace_root(storage.workspace));
    const auto result =
        kasumi::application::history_storage::inventory_content_reachability(
            storage.transport,
            test_key(),
            history,
            kasumi::test::workspace_root(storage.workspace));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::VerificationFailure);
}

TEST(ContentReachabilityTest, ContentReferencedOnlyByOrphanCommitIsOrphan) {
    auto storage = make_local_storage();
    const auto reachable = kasumi::history::make_empty_bootstrap().value();
    const auto orphan = make_tree_commit(
        0,
        {},
        {NodeRow{.path = "", .is_directory = true}, file_row("old", "old")});
    publish(storage, reachable);
    const auto orphan_published = publish(storage, orphan);
    ASSERT_EQ(kasumi::transport::remove(storage.transport,
                                        marker_path(orphan_published.head))
                  .value(),
              kasumi::transport::Removal::Removed);
    const auto identifier = content_id("old");
    put_encrypted_payload(
        storage.transport, storage.workspace, identifier, "old", "orphan");

    const auto result = content_inventory(
        storage.transport, kasumi::test::workspace_root(storage.workspace));
    EXPECT_TRUE(result.reachable_content_ids.empty());
    EXPECT_EQ(result.orphan_content_ids, std::vector<std::string>{identifier});
    EXPECT_FALSE(find_content(result, identifier)->reachable);
}

TEST(ContentReachabilityTest, ContentSharedByReachableAndOrphanIsReachable) {
    auto storage = make_local_storage();
    const auto reachable =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("live", "shared")});
    const auto orphan = make_tree_commit(
        0,
        {},
        {NodeRow{.path = "", .is_directory = true}, file_row("old", "shared")});
    const auto reachable_published = publish(storage, reachable);
    const auto orphan_published = publish(storage, orphan);
    ASSERT_EQ(kasumi::transport::remove(storage.transport,
                                        marker_path(orphan_published.head))
                  .value(),
              kasumi::transport::Removal::Removed);
    const auto identifier = content_id("shared");
    put_encrypted_payload(
        storage.transport, storage.workspace, identifier, "shared", "shared");

    const auto result = content_inventory(
        storage.transport, kasumi::test::workspace_root(storage.workspace));
    EXPECT_EQ(result.reachable_content_ids,
              std::vector<std::string>{identifier});
    EXPECT_TRUE(result.orphan_content_ids.empty());
    EXPECT_TRUE(find_content(result, identifier)->reachable);
    static_cast<void>(reachable_published);
}

TEST(ContentReachabilityTest, UnreferencedValidContentObjectIsOrphan) {
    auto storage = make_local_storage();
    const auto identifier = content_id("unreferenced");
    put_encrypted_payload(storage.transport,
                          storage.workspace,
                          identifier,
                          "unreferenced",
                          "unreferenced");

    const auto result = content_inventory(
        storage.transport, kasumi::test::workspace_root(storage.workspace));
    EXPECT_EQ(result.orphan_content_ids, std::vector<std::string>{identifier});
}

TEST(ContentReachabilityTest, CorruptUnreferencedContentIsStillOrphan) {
    auto workspace =
        kasumi::test::make_temp_workspace("content-corrupt-orphan");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto identifier = std::string(64, 'a');
    state->objects[identifier] = {0};

    const auto result =
        content_inventory(transport, kasumi::test::workspace_root(workspace));
    EXPECT_EQ(result.orphan_content_ids, std::vector<std::string>{identifier});
    EXPECT_EQ(result.corrupt_content_ids, std::vector<std::string>{identifier});
    const auto* entry = find_content(result, identifier);
    ASSERT_NE(entry, nullptr);
    EXPECT_FALSE(entry->reachable);
    EXPECT_EQ(entry->state, ContentObjectState::Corrupt);
}

TEST(ContentReachabilityTest, CorruptOrphanIsReportedInCorruptContentIds) {
    auto workspace =
        kasumi::test::make_temp_workspace("content-corrupt-orphan-aggregate");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto identifier = std::string(64, 'b');
    state->objects[identifier] = {0};

    const auto result =
        content_inventory(transport, kasumi::test::workspace_root(workspace));
    EXPECT_TRUE(result.reachable_content_ids.empty());
    EXPECT_EQ(result.corrupt_content_ids, std::vector<std::string>{identifier});
    EXPECT_EQ(result.orphan_content_ids, std::vector<std::string>{identifier});
}

TEST(ContentReachabilityTest,
     CorruptContentReferencedOnlyByOrphanCommitIsOrphan) {
    auto workspace =
        kasumi::test::make_temp_workspace("content-corrupt-orphan-commit");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto orphan = make_tree_commit(
        0,
        {},
        {NodeRow{.path = "", .is_directory = true}, file_row("old", "old")});
    const auto reference =
        add_fake_commit(transport, workspace, orphan, "orphan");
    ASSERT_EQ(
        kasumi::transport::remove(transport, marker_path(reference)).value(),
        kasumi::transport::Removal::Removed);
    const auto identifier = content_id("old");
    state->objects[identifier] = {0};

    const auto result =
        content_inventory(transport, kasumi::test::workspace_root(workspace));
    EXPECT_TRUE(result.reachable_content_ids.empty());
    EXPECT_EQ(result.orphan_content_ids, std::vector<std::string>{identifier});
    EXPECT_EQ(result.corrupt_content_ids, std::vector<std::string>{identifier});
}

TEST(ContentReachabilityTest, ReachableCorruptContentIsNotOrphan) {
    auto workspace =
        kasumi::test::make_temp_workspace("content-reachable-corrupt");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto reachable = make_tree_commit(
        0,
        {},
        {NodeRow{.path = "", .is_directory = true}, file_row("live", "live")});
    add_fake_commit(transport, workspace, reachable, "reachable");
    const auto identifier = content_id("live");
    state->objects[identifier] = {0};

    const auto result =
        content_inventory(transport, kasumi::test::workspace_root(workspace));
    EXPECT_EQ(result.reachable_content_ids,
              std::vector<std::string>{identifier});
    EXPECT_EQ(result.corrupt_content_ids, std::vector<std::string>{identifier});
    EXPECT_TRUE(result.orphan_content_ids.empty());
}

TEST(ContentReachabilityTest,
     SharedReachableAndOrphanCorruptContentIsReachable) {
    auto workspace =
        kasumi::test::make_temp_workspace("content-shared-corrupt");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto reachable =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("live", "shared")});
    const auto orphan = make_tree_commit(
        0,
        {},
        {NodeRow{.path = "", .is_directory = true}, file_row("old", "shared")});
    add_fake_commit(transport, workspace, reachable, "reachable");
    const auto orphan_reference =
        add_fake_commit(transport, workspace, orphan, "orphan");
    ASSERT_EQ(
        kasumi::transport::remove(transport, marker_path(orphan_reference))
            .value(),
        kasumi::transport::Removal::Removed);
    const auto identifier = content_id("shared");
    state->objects[identifier] = {0};

    const auto result =
        content_inventory(transport, kasumi::test::workspace_root(workspace));
    EXPECT_EQ(result.reachable_content_ids,
              std::vector<std::string>{identifier});
    EXPECT_EQ(result.corrupt_content_ids, std::vector<std::string>{identifier});
    EXPECT_TRUE(result.orphan_content_ids.empty());
}

TEST(ContentReachabilityTest, OrphanReachabilityDoesNotDependOnPhysicalHealth) {
    auto workspace =
        kasumi::test::make_temp_workspace("content-health-independent");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto identifier = content_id("health");
    put_encrypted_payload(
        transport, workspace, identifier, "health", "healthy");

    const auto healthy =
        content_inventory(transport, kasumi::test::workspace_root(workspace));
    state->objects[identifier] = {0};
    const auto corrupt =
        content_inventory(transport, kasumi::test::workspace_root(workspace));
    EXPECT_TRUE(healthy.reachable_content_ids.empty());
    EXPECT_TRUE(corrupt.reachable_content_ids.empty());
    EXPECT_EQ(healthy.orphan_content_ids, corrupt.orphan_content_ids);
    EXPECT_EQ(healthy.orphan_content_ids, std::vector<std::string>{identifier});
    EXPECT_EQ(find_content(healthy, identifier)->state,
              ContentObjectState::Present);
    EXPECT_EQ(find_content(corrupt, identifier)->state,
              ContentObjectState::Corrupt);
}

TEST(ContentReachabilityTest,
     OrphanContentDisappearingAfterListingRemainsObservedAsOrphan) {
    auto workspace =
        kasumi::test::make_temp_workspace("content-orphan-disappearing");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto identifier = std::string(64, 'c');
    state->objects[identifier] = {0};
    state->disappear_on_get = identifier;

    const auto result =
        content_inventory(transport, kasumi::test::workspace_root(workspace));
    EXPECT_EQ(result.orphan_content_ids, std::vector<std::string>{identifier});
    EXPECT_TRUE(result.missing_content_ids.empty());
    const auto* entry = find_content(result, identifier);
    ASSERT_NE(entry, nullptr);
    EXPECT_FALSE(entry->reachable);
    EXPECT_EQ(entry->state, ContentObjectState::Missing);
}

TEST(ContentReachabilityTest,
     CorruptContentAggregateIncludesReachableAndOrphan) {
    auto workspace =
        kasumi::test::make_temp_workspace("content-corrupt-aggregate");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto reachable = make_tree_commit(
        0,
        {},
        {NodeRow{.path = "", .is_directory = true}, file_row("live", "live")});
    add_fake_commit(transport, workspace, reachable, "reachable");
    const auto reachable_id = content_id("live");
    const auto orphan_id = content_id("orphan");
    state->objects[reachable_id] = {0};
    state->objects[orphan_id] = {0};

    const auto result =
        content_inventory(transport, kasumi::test::workspace_root(workspace));
    auto expected_corrupt = std::vector<std::string>{reachable_id, orphan_id};
    std::ranges::sort(expected_corrupt);
    EXPECT_EQ(result.corrupt_content_ids, expected_corrupt);
    EXPECT_EQ(result.orphan_content_ids, std::vector<std::string>{orphan_id});
}

TEST(ContentReachabilityTest, InvalidRootStorageObjectIsUnknown) {
    auto workspace = kasumi::test::make_temp_workspace("content-unknown");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->objects["not-a-content-object"] = {0};
    state->objects["foreign/object"] = {0};
    state->objects["tmp/object"] = {0};

    const auto result =
        content_inventory(transport, kasumi::test::workspace_root(workspace));
    EXPECT_EQ(result.unknown_storage_objects,
              (std::vector<std::string>{
                  "foreign/object", "not-a-content-object", "tmp/object"}));
    EXPECT_TRUE(result.orphan_content_ids.empty());
}

TEST(ContentReachabilityTest, HistoryObjectsAreExcludedFromContentInventory) {
    auto workspace =
        kasumi::test::make_temp_workspace("content-history-excluded");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->objects["history/commits/garbage"] = {0};
    state->objects["history/heads/garbage"] = {0};

    const auto result =
        content_inventory(transport, kasumi::test::workspace_root(workspace));
    EXPECT_TRUE(result.unknown_storage_objects.empty());
    EXPECT_TRUE(result.contents.empty());
}

TEST(ContentReachabilityTest,
     ReachableContentDisappearingAfterListingIsMissing) {
    auto workspace = kasumi::test::make_temp_workspace("content-disappearing");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("alpha", "alpha")});
    const auto commit_ref =
        add_fake_commit(transport, workspace, commit, "commit");
    const auto identifier = content_id("alpha");
    state->objects[identifier] = {0};
    state->disappear_on_get = identifier;
    static_cast<void>(commit_ref);

    const auto result =
        content_inventory(transport, kasumi::test::workspace_root(workspace));
    EXPECT_EQ(result.missing_content_ids, std::vector<std::string>{identifier});
    EXPECT_TRUE(result.corrupt_content_ids.empty());
}

TEST(ContentReachabilityTest, TransportFailureIsNotReportedAsMissing) {
    auto workspace =
        kasumi::test::make_temp_workspace("content-transport-failure");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("alpha", "alpha")});
    add_fake_commit(transport, workspace, commit, "commit");
    state->objects[content_id("alpha")] = {0};
    state->fail_content_get = true;

    const auto history =
        history_inventory(transport, kasumi::test::workspace_root(workspace));
    const auto result =
        kasumi::application::history_storage::inventory_content_reachability(
            transport,
            test_key(),
            history,
            kasumi::test::workspace_root(workspace),
            true);
    ASSERT_FALSE(result.has_value());
    EXPECT_TRUE(result.error().code == ErrorCode::TransportFailure);
}

TEST(ContentReachabilityTest, ContentInventoryIsReadOnly) {
    auto workspace = kasumi::test::make_temp_workspace("content-read-only");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("alpha", "alpha")});
    add_fake_commit(transport, workspace, commit, "commit");
    const auto identifier = content_id("alpha");
    put_encrypted_payload(transport, workspace, identifier, "alpha", "content");
    state->put_count = 0;
    state->remove_count = 0;
    const auto before = state->objects;

    const auto result =
        content_inventory(transport, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(result.contents.empty());
    EXPECT_EQ(state->objects, before);
    EXPECT_EQ(state->put_count, 0U);
    EXPECT_EQ(state->remove_count, 0U);
}

TEST(ContentReachabilityTest,
     ContentInventoryIsDeterministicAcrossListingOrder) {
    auto workspace = kasumi::test::make_temp_workspace("content-order");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("a", "a"),
                          file_row("b", "b")});
    add_fake_commit(transport, workspace, commit, "commit");
    put_encrypted_payload(transport, workspace, content_id("a"), "a", "a");
    put_encrypted_payload(transport, workspace, content_id("b"), "b", "b");

    const auto first =
        content_inventory(transport, kasumi::test::workspace_root(workspace));
    state->reverse_listing = true;
    const auto second =
        content_inventory(transport, kasumi::test::workspace_root(workspace));
    EXPECT_EQ(first.reachable_content_ids, second.reachable_content_ids);
    EXPECT_EQ(first.missing_content_ids, second.missing_content_ids);
    EXPECT_EQ(first.corrupt_content_ids, second.corrupt_content_ids);
    EXPECT_EQ(first.orphan_content_ids, second.orphan_content_ids);
    EXPECT_EQ(first.unknown_storage_objects, second.unknown_storage_objects);
    ASSERT_EQ(first.contents.size(), second.contents.size());
    for (std::size_t index = 0; index < first.contents.size(); ++index) {
        EXPECT_EQ(first.contents[index].content_id,
                  second.contents[index].content_id);
        EXPECT_EQ(first.contents[index].state, second.contents[index].state);
        EXPECT_EQ(first.contents[index].references,
                  second.contents[index].references);
    }
}

TEST(ContentReachabilityTest,
     ObservedIdentifiersExcludeObjectsPublishedAfterTheSnapshot) {
    auto workspace =
        kasumi::test::make_temp_workspace("content-observed-identifiers");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("alpha", "alpha")});
    add_fake_commit(transport, workspace, commit, "commit");
    put_encrypted_payload(
        transport, workspace, content_id("alpha"), "alpha", "alpha");
    const auto identifiers = kasumi::transport::list(transport);
    ASSERT_TRUE(identifiers.has_value());

    const auto late_content = content_id("late");
    put_encrypted_payload(transport, workspace, late_content, "late", "late");
    state->full_list_count = 0;
    state->prefix_list_count = 0;

    const auto history =
        kasumi::application::history_storage::inventory_reachability(
            transport,
            test_key(),
            *identifiers,
            kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(history.has_value()) << history.error().detail;
    const auto contents =
        kasumi::application::history_storage::inventory_content_reachability(
            transport,
            test_key(),
            *identifiers,
            *history,
            kasumi::test::workspace_root(workspace));

    ASSERT_TRUE(contents.has_value()) << contents.error().detail;
    EXPECT_EQ(find_content(*contents, late_content), nullptr);
    EXPECT_EQ(state->full_list_count, 0U);
    EXPECT_EQ(state->prefix_list_count, 0U);
}

TEST(ContentReachabilityTest, ContentInventoryCleansWorkspaceAfterSuccess) {
    auto workspace =
        kasumi::test::make_temp_workspace("content-cleanup-success");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("alpha", "alpha")});
    add_fake_commit(transport, workspace, commit, "commit");
    put_encrypted_payload(
        transport, workspace, content_id("alpha"), "alpha", "alpha");
    const auto result =
        content_inventory(transport, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(result.contents.empty());
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        kasumi::test::workspace_root(workspace)));
}

TEST(ContentReachabilityTest, ContentInventoryCleansWorkspaceAfterFailure) {
    auto workspace =
        kasumi::test::make_temp_workspace("content-cleanup-failure");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("alpha", "alpha")});
    add_fake_commit(transport, workspace, commit, "commit");
    state->objects[content_id("alpha")] = {0};
    state->fail_content_get = true;
    const auto history =
        history_inventory(transport, kasumi::test::workspace_root(workspace));
    const auto result =
        kasumi::application::history_storage::inventory_content_reachability(
            transport,
            test_key(),
            history,
            kasumi::test::workspace_root(workspace),
            true);
    EXPECT_FALSE(result.has_value());
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        kasumi::test::workspace_root(workspace)));
}

TEST(ContentReachabilityTest,
     ContentInventoryWithoutPayloadAuditSkipsPayloadDownloads) {
    auto workspace =
        kasumi::test::make_temp_workspace("content-no-audit-downloads");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("alpha", "alpha")});
    add_fake_commit(transport, workspace, commit, "commit");
    state->objects[content_id("alpha")] = {0};
    state->fail_content_get = true;

    const auto history =
        history_inventory(transport, kasumi::test::workspace_root(workspace));
    const auto result =
        kasumi::application::history_storage::inventory_content_reachability(
            transport,
            test_key(),
            history,
            kasumi::test::workspace_root(workspace),
            false);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->reachable_content_ids,
              std::vector<std::string>{content_id("alpha")});
    EXPECT_TRUE(result->missing_content_ids.empty());
    EXPECT_TRUE(result->corrupt_content_ids.empty());
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        kasumi::test::workspace_root(workspace)));
}

} // namespace
