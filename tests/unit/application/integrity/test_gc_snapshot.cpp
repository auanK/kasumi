#include "application/integrity/maintenance.hpp"

#include "application/history_storage/content_reachability.hpp"
#include "application/history_storage/epoch.hpp"
#include "application/history_storage/reachability.hpp"
#include "application/history_storage/remote_layout.hpp"

#define KASUMI_TEST_HISTORY_STORAGE_NO_ERROR_CODE_ALIAS
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/history_storage.hpp"

#include <algorithm>
#include <array>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <vector>

namespace {

using kasumi::NodeRow;
using kasumi::Snapshot;
using kasumi::application::integrity::ErrorCode;
using kasumi::application::integrity::GcCandidate;
using kasumi::application::integrity::GcCandidateKind;
using kasumi::application::integrity::GcSnapshot;
using kasumi::application::integrity::collect_gc_snapshot;
using kasumi::application::integrity::same_gc_snapshot;
using kasumi::application::integrity::select_gc_candidates;

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

void put_encrypted_content(kasumi::transport::Transport& transport,
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

HeadReference add_fake_commit_object(kasumi::transport::Transport& transport,
                                     TempWorkspace& workspace,
                                     const Commit& commit,
                                     std::string_view suffix,
                                     bool add_marker = true) {
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

// ============================================================================
// Grupo A — Snapshot saudável
// ============================================================================

TEST(GcSnapshotTest, A1_EmptyCandidates) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-a1");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("hello.txt", "world")});
    const auto ref =
        add_fake_commit_object(transport, workspace, commit, "head");
    const auto c_id = content_id("world");
    put_encrypted_content(transport, workspace, c_id, "world", "c_world");

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(snapshot.has_value()) << snapshot.error().detail;

    EXPECT_EQ(snapshot->logical_heads, std::vector<std::string>{ref.commit_id});
    EXPECT_EQ(snapshot->reachable_commits,
              std::vector<std::string>{ref.commit_id});
    EXPECT_EQ(snapshot->required_commit_objects,
              std::vector<std::string>{object_path(ref)});
    EXPECT_EQ(snapshot->reachable_content, std::vector<std::string>{c_id});
    EXPECT_TRUE(snapshot->candidates.empty());
}

TEST(GcSnapshotTest, A2_OrphanContent) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-a2");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("hello.txt", "world")});
    add_fake_commit_object(transport, workspace, commit, "head");
    const auto c_id = content_id("world");
    put_encrypted_content(transport, workspace, c_id, "world", "c_world");

    const auto orphan = content_id("orphan_payload");
    put_encrypted_content(
        transport, workspace, orphan, "orphan_payload", "c_orphan");

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(snapshot.has_value()) << snapshot.error().detail;

    ASSERT_EQ(snapshot->candidates.size(), 1U);
    EXPECT_EQ(snapshot->candidates[0].kind, GcCandidateKind::Content);
    EXPECT_EQ(snapshot->candidates[0].identifier, orphan);
}

TEST(GcSnapshotTest, A3_RedundantVariant) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-a3");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("hello.txt", "world")});
    const auto head_ref =
        add_fake_commit_object(transport, workspace, commit, "head_var", true);
    const auto extra_ref =
        add_fake_commit_object(transport, workspace, commit, "extra_var", false);
    ASSERT_NE(head_ref.ciphertext_id, extra_ref.ciphertext_id);

    const auto c_id = content_id("world");
    put_encrypted_content(transport, workspace, c_id, "world", "c_world");

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(snapshot.has_value()) << snapshot.error().detail;

    EXPECT_EQ(snapshot->required_commit_objects,
              std::vector<std::string>{object_path(head_ref)});
    ASSERT_EQ(snapshot->candidates.size(), 1U);
    EXPECT_EQ(snapshot->candidates[0].kind, GcCandidateKind::CommitVariant);
    EXPECT_EQ(snapshot->candidates[0].identifier, object_path(extra_ref));
}

TEST(GcSnapshotTest, A4_MixedCandidates) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-a4");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("hello.txt", "world")});
    const auto head_ref =
        add_fake_commit_object(transport, workspace, commit, "head_var", true);
    const auto extra_ref =
        add_fake_commit_object(transport, workspace, commit, "extra_var", false);
    const auto c_id = content_id("world");
    put_encrypted_content(transport, workspace, c_id, "world", "c_world");

    const auto orphan = content_id("orphan_data");
    put_encrypted_content(
        transport, workspace, orphan, "orphan_data", "c_orphan");

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(snapshot.has_value()) << snapshot.error().detail;

    ASSERT_EQ(snapshot->candidates.size(), 2U);
    std::vector<GcCandidate> expected{
        GcCandidate{.identifier = object_path(extra_ref),
                    .kind = GcCandidateKind::CommitVariant},
        GcCandidate{.identifier = orphan, .kind = GcCandidateKind::Content},
    };
    std::ranges::sort(expected, [](const auto& l, const auto& r) {
        if (l.identifier != r.identifier)
            return l.identifier < r.identifier;
        return l.kind < r.kind;
    });
    EXPECT_EQ(snapshot->candidates, expected);
}

TEST(GcSnapshotTest, A5_VariableListingOrder) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-a5");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("hello.txt", "world")});
    add_fake_commit_object(transport, workspace, commit, "head_var", true);
    add_fake_commit_object(transport, workspace, commit, "extra_var", false);
    const auto c_id = content_id("world");
    put_encrypted_content(transport, workspace, c_id, "world", "c_world");
    const auto orphan = content_id("orphan_data");
    put_encrypted_content(
        transport, workspace, orphan, "orphan_data", "c_orphan");

    const auto first = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(first.has_value());

    state->reverse_listing = true;
    const auto second = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(second.has_value());

    EXPECT_TRUE(same_gc_snapshot(*first, *second));
    EXPECT_EQ(*first, *second);
}

// ============================================================================
// Grupo B — Proteção
// ============================================================================

TEST(GcSnapshotTest, B1_HeadReferencedContentProtected) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-b1");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("file.txt", "head_content")});
    add_fake_commit_object(transport, workspace, commit, "head");
    const auto c_id = content_id("head_content");
    put_encrypted_content(
        transport, workspace, c_id, "head_content", "c_head");

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(snapshot.has_value());

    EXPECT_TRUE(std::ranges::none_of(
        snapshot->candidates,
        [&](const GcCandidate& c) { return c.identifier == c_id; }));
}

TEST(GcSnapshotTest, B2_RetainedHistoryContentProtected) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-b2");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto base =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("old.txt", "historical_data")});
    const auto child =
        make_tree_commit(1,
                         {commit_id(base)},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("new.txt", "new_data")});

    const auto base_ref =
        add_fake_commit_object(transport, workspace, base, "base", false);
    const auto child_ref =
        add_fake_commit_object(transport, workspace, child, "child", true);
    static_cast<void>(base_ref);
    static_cast<void>(child_ref);

    const auto c_old = content_id("historical_data");
    const auto c_new = content_id("new_data");
    put_encrypted_content(
        transport, workspace, c_old, "historical_data", "c_old");
    put_encrypted_content(transport, workspace, c_new, "new_data", "c_new");

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(snapshot.has_value());

    EXPECT_TRUE(std::ranges::binary_search(snapshot->reachable_content, c_old));
    EXPECT_TRUE(std::ranges::none_of(
        snapshot->candidates,
        [&](const GcCandidate& c) { return c.identifier == c_old; }));
}

TEST(GcSnapshotTest, B3_SharedContentAcrossMultiplePathsProtected) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-b3");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto base =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("shared.txt", "shared_content")});
    const auto left =
        make_tree_commit(1,
                         {commit_id(base)},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("shared.txt", "shared_content"),
                          file_row("left.txt", "left")});
    const auto right =
        make_tree_commit(1,
                         {commit_id(base)},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("shared.txt", "shared_content"),
                          file_row("right.txt", "right")});

    add_fake_commit_object(transport, workspace, base, "base", false);
    add_fake_commit_object(transport, workspace, left, "left", true);
    add_fake_commit_object(transport, workspace, right, "right", true);

    const auto c_shared = content_id("shared_content");
    put_encrypted_content(
        transport, workspace, c_shared, "shared_content", "c_shared");
    put_encrypted_content(
        transport, workspace, content_id("left"), "left", "c_left");
    put_encrypted_content(
        transport, workspace, content_id("right"), "right", "c_right");

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(snapshot.has_value());

    EXPECT_TRUE(
        std::ranges::binary_search(snapshot->reachable_content, c_shared));
    EXPECT_TRUE(std::ranges::none_of(
        snapshot->candidates,
        [&](const GcCandidate& c) { return c.identifier == c_shared; }));
}

TEST(GcSnapshotTest, B4_HeadCommitProtected) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-b4");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("file.txt", "data")});
    const auto head_ref =
        add_fake_commit_object(transport, workspace, commit, "head");
    put_encrypted_content(
        transport, workspace, content_id("data"), "data", "c_data");

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(snapshot.has_value());

    EXPECT_TRUE(std::ranges::binary_search(snapshot->required_commit_objects,
                                           object_path(head_ref)));
    EXPECT_TRUE(std::ranges::none_of(
        snapshot->candidates,
        [&](const GcCandidate& c) { return c.identifier == object_path(head_ref); }));
}

TEST(GcSnapshotTest, B5_AncestorCommitProtected) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-b5");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto base =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("base.txt", "base")});
    const auto child =
        make_tree_commit(1,
                         {commit_id(base)},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("child.txt", "child")});

    const auto base_ref =
        add_fake_commit_object(transport, workspace, base, "base", false);
    const auto child_ref =
        add_fake_commit_object(transport, workspace, child, "child", true);
    static_cast<void>(child_ref);

    put_encrypted_content(
        transport, workspace, content_id("base"), "base", "c_base");
    put_encrypted_content(
        transport, workspace, content_id("child"), "child", "c_child");

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(snapshot.has_value());

    EXPECT_TRUE(std::ranges::binary_search(snapshot->required_commit_objects,
                                           object_path(base_ref)));
    EXPECT_TRUE(std::ranges::none_of(
        snapshot->candidates,
        [&](const GcCandidate& c) { return c.identifier == object_path(base_ref); }));
}

TEST(GcSnapshotTest, B6_ControlObjectsNotCandidates) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-b6");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("file.txt", "data")});
    const auto ref =
        add_fake_commit_object(transport, workspace, commit, "head");
    put_encrypted_content(
        transport, workspace, content_id("data"), "data", "c_data");

    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());

    // Inject maintenance barrier
    state->objects[layout.barrier_identifier] = {'b', 'a', 'r', 'r', 'i', 'e', 'r'};
    // Inject writer marker
    state->objects[layout.writers_prefix + std::string(32, 'a')] = {'w', 'r', 'i', 't', 'e', 'r'};

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(snapshot.has_value()) << snapshot.error().detail;

    for (const auto& cand : snapshot->candidates) {
        EXPECT_NE(cand.identifier, layout.barrier_identifier);
        EXPECT_NE(cand.identifier, marker_path(ref));
        EXPECT_FALSE(cand.identifier.starts_with(layout.writers_prefix));
        EXPECT_FALSE(cand.identifier.starts_with(layout.heads_prefix));
    }
}

TEST(GcSnapshotTest, B7_PhysicalPresenceObservedWithoutPayloadAudit) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-b7");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("file.txt", "valid_payload")});
    const auto ref =
        add_fake_commit_object(transport, workspace, commit, "head");
    const auto c_id = content_id("valid_payload");

    put_encrypted_content(
        transport, workspace, c_id, "valid_payload", "c_payload");

    // Corrupt payload bytes directly in transport storage.
    // The identifier remains present in listing, but ciphertext bytes are corrupted.
    state->objects[c_id] = {0xDE, 0xAD, 0xBE, 0xEF};

    // collect_gc_snapshot uses audit_payloads = false (presence only).
    // It verifies that c_id exists in physical listing without downloading or decrypting bytes.
    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(snapshot.has_value()) << snapshot.error().detail;

    EXPECT_TRUE(std::ranges::binary_search(snapshot->reachable_content, c_id));
    EXPECT_TRUE(std::ranges::none_of(
        snapshot->candidates,
        [&](const GcCandidate& c) { return c.identifier == c_id; }));

    // In contrast, running inventory_content_reachability with audit_payloads = true
    // detects payload corruption.
    const auto listing = kasumi::transport::list(transport);
    ASSERT_TRUE(listing.has_value());
    const auto history =
        kasumi::application::history_storage::inventory_reachability(
            transport, test_key(), *listing, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(history.has_value());

    const auto audited_content =
        kasumi::application::history_storage::inventory_content_reachability(
            transport,
            test_key(),
            *listing,
            *history,
            kasumi::test::workspace_root(workspace),
            true);
    ASSERT_TRUE(audited_content.has_value());
    EXPECT_TRUE(std::ranges::binary_search(audited_content->corrupt_content_ids, c_id));
}

TEST(GcSnapshotTest, B8_AncestorCommitDeterministicVariantChoiceUnderPerturbedListing) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-b8");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    // 1. Ancestor commit A
    const auto commit_a =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("a.txt", "payload_a")});

    // 2. Two distinct valid physical variants of commit A (neither is a HEAD)
    const auto ref_a1 =
        add_fake_commit_object(transport, workspace, commit_a, "var_a1", false);
    const auto ref_a2 =
        add_fake_commit_object(transport, workspace, commit_a, "var_a2", false);
    ASSERT_NE(ref_a1.ciphertext_id, ref_a2.ciphertext_id);
    ASSERT_NE(object_path(ref_a1), object_path(ref_a2));

    // 3. Descendant commit B pointing to A
    const auto commit_b =
        make_tree_commit(1,
                         {commit_id(commit_a)},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("b.txt", "payload_b")});

    // 4. Valid HEAD pointing to B (commit A is reachable only via history ancestry)
    const auto ref_b =
        add_fake_commit_object(transport, workspace, commit_b, "head_b", true);

    // 5. Contents for both commits
    const auto c_a = content_id("payload_a");
    const auto c_b = content_id("payload_b");
    put_encrypted_content(transport, workspace, c_a, "payload_a", "c_a");
    put_encrypted_content(transport, workspace, c_b, "payload_b", "c_b");

    // Observation 1: default forward listing
    reset_fake_traffic(*state);
    const auto first = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(first.has_value()) << first.error().detail;

    // Observation 2: reverse listing order
    state->reverse_listing = true;
    reset_fake_traffic(*state);
    const auto second = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(second.has_value()) << second.error().detail;

    // Both snapshots must be fully equivalent
    EXPECT_TRUE(same_gc_snapshot(*first, *second));
    EXPECT_EQ(*first, *second);

    // HEAD B is the only logical head
    EXPECT_EQ(first->logical_heads, std::vector<std::string>{ref_b.commit_id});

    // Both A and B are reachable commits
    std::vector<std::string> expected_commits{commit_id(commit_a), commit_id(commit_b)};
    std::ranges::sort(expected_commits);
    EXPECT_EQ(first->reachable_commits, expected_commits);

    // Head B object is required
    EXPECT_TRUE(std::ranges::binary_search(first->required_commit_objects, object_path(ref_b)));

    // Exactly one variant of commit A is in required_commit_objects
    const bool a1_required_first =
        std::ranges::binary_search(first->required_commit_objects, object_path(ref_a1));
    const bool a2_required_first =
        std::ranges::binary_search(first->required_commit_objects, object_path(ref_a2));
    EXPECT_NE(a1_required_first, a2_required_first);

    // In observation 2, the EXACT SAME variant of commit A was chosen
    const bool a1_required_second =
        std::ranges::binary_search(second->required_commit_objects, object_path(ref_a1));
    const bool a2_required_second =
        std::ranges::binary_search(second->required_commit_objects, object_path(ref_a2));
    EXPECT_EQ(a1_required_first, a1_required_second);
    EXPECT_EQ(a2_required_first, a2_required_second);

    // The other variant is classified as dispensable CommitVariant candidate in BOTH snapshots
    const std::string dispensable_path =
        a1_required_first ? object_path(ref_a2) : object_path(ref_a1);
    const auto check_candidate = [&](const GcSnapshot& snap) {
        auto it = std::ranges::find_if(snap.candidates, [&](const GcCandidate& c) {
            return c.identifier == dispensable_path;
        });
        ASSERT_NE(it, snap.candidates.end());
        EXPECT_EQ(it->kind, GcCandidateKind::CommitVariant);
    };
    check_candidate(*first);
    check_candidate(*second);

    // Zero mutations occurred
    EXPECT_EQ(state->remove_count, 0U);
    EXPECT_EQ(state->remove_batch_count, 0U);
    EXPECT_EQ(state->put_count, 0U);
}

// ============================================================================
// Grupo C — Corrupção e falhas
// ============================================================================

TEST(GcSnapshotTest, C1_RemoteHistoryAbsent) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-c1");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(snapshot.has_value());
    EXPECT_EQ(snapshot.error().code, ErrorCode::IntegrityFailure);
}

TEST(GcSnapshotTest, C2_InvalidHeadMarker) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-c2");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const HeadReference ref{std::string(64, 'a'), std::string(64, 'b')};
    state->objects[marker_path(ref)] = {1, 2, 3}; // corrupt marker

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(snapshot.has_value());
    EXPECT_EQ(snapshot.error().code, ErrorCode::IntegrityFailure);
}

TEST(GcSnapshotTest, C3_UnauthenticatedMarker) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-c3");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const HeadReference missing_commit_ref{std::string(64, 'a'), std::string(64, 'b')};
    state->objects[marker_path(missing_commit_ref)] =
        kasumi::application::history_storage::encode_marker(missing_commit_ref).value();

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(snapshot.has_value());
    EXPECT_EQ(snapshot.error().code, ErrorCode::IntegrityFailure);
}

TEST(GcSnapshotTest, C4_CorruptedCommit) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-c4");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("file.txt", "data")});
    const auto ref =
        add_fake_commit_object(transport, workspace, commit, "head");
    state->objects[object_path(ref)] = {0, 0, 0}; // corrupt commit ciphertext

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(snapshot.has_value());
    EXPECT_EQ(snapshot.error().code, ErrorCode::IntegrityFailure);
}

TEST(GcSnapshotTest, C5_MissingParentCommit) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-c5");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto missing_parent_id = std::string(64, 'a');
    const auto commit =
        make_tree_commit(1,
                         {missing_parent_id},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("file.txt", "data")});
    add_fake_commit_object(transport, workspace, commit, "child");
    put_encrypted_content(
        transport, workspace, content_id("data"), "data", "c_data");

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(snapshot.has_value());
    EXPECT_EQ(snapshot.error().code, ErrorCode::IntegrityFailure);
}

TEST(GcSnapshotTest, C6_MissingRequiredVariant) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-c6");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("file.txt", "data")});
    const auto ref =
        add_fake_commit_object(transport, workspace, commit, "head");
    state->objects.erase(object_path(ref)); // remove commit variant file

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(snapshot.has_value());
    EXPECT_EQ(snapshot.error().code, ErrorCode::IntegrityFailure);
}

TEST(GcSnapshotTest, C7_InvalidAuthenticatedVariant) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-c7");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("file.txt", "data")});
    const auto head_ref =
        add_fake_commit_object(transport, workspace, commit, "head_var", true);
    put_encrypted_content(
        transport, workspace, content_id("data"), "data", "c_data");

    // Add corrupt variant
    const HeadReference corrupt_ref{head_ref.commit_id, std::string(64, 'f')};
    state->objects[object_path(corrupt_ref)] = {0, 1, 2};

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(snapshot.has_value());
    EXPECT_EQ(snapshot.error().code, ErrorCode::IntegrityFailure);
}

TEST(GcSnapshotTest, C8_ProtectedContentMissing) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-c8");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("missing.txt", "missing_content")});
    add_fake_commit_object(transport, workspace, commit, "head");
    // Deliberately do NOT put content into transport

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(snapshot.has_value());
    EXPECT_EQ(snapshot.error().code, ErrorCode::IntegrityFailure);
}

TEST(GcSnapshotTest, C9_MalformedContentIdentifier) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-c9");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("file.txt", "data")});
    add_fake_commit_object(transport, workspace, commit, "head");
    put_encrypted_content(
        transport, workspace, content_id("data"), "data", "c_data");

    // Injected malformed identifier (63 chars instead of 64)
    state->objects[std::string(63, 'a')] = {0};

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(snapshot.has_value());
    EXPECT_EQ(snapshot.error().code, ErrorCode::IntegrityFailure);
}

TEST(GcSnapshotTest, C10_EmptyIdentifierInListing) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-c10");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("file.txt", "data")});
    add_fake_commit_object(transport, workspace, commit, "head");
    put_encrypted_content(
        transport, workspace, content_id("data"), "data", "c_data");

    // Empty object identifier in transport
    state->objects[""] = {0};

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(snapshot.has_value());
    EXPECT_EQ(snapshot.error().code, ErrorCode::IntegrityFailure);
}

TEST(GcSnapshotTest, C11_ContradictoryClassification) {
    const std::string identifier(64, 'a');
    const std::vector<std::string> variants{identifier};
    const std::vector<std::string> orphans{identifier};

    const auto result = select_gc_candidates(variants, orphans);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::IntegrityFailure);
    EXPECT_EQ(result.error().detail, "contradictory GC candidate classification");
    EXPECT_EQ(result.error().object_identifier, identifier);
}

TEST(GcSnapshotTest, C11_EmptyCandidateIdentifierRejected) {
    const std::string valid_id(64, 'a');
    // Empty variant
    {
        const auto res = select_gc_candidates(std::vector<std::string>{""},
                                              std::vector<std::string>{valid_id});
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error().code, ErrorCode::InvalidInput);
        EXPECT_EQ(res.error().detail, "empty GC candidate identifier");
    }
    // Empty orphan
    {
        const auto res = select_gc_candidates(std::vector<std::string>{valid_id},
                                              std::vector<std::string>{""});
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error().code, ErrorCode::InvalidInput);
        EXPECT_EQ(res.error().detail, "empty GC candidate identifier");
    }
}

TEST(GcSnapshotTest, C11_MalformedContentCandidateIdentifierRejected) {
    const std::string valid_id(64, 'a');
    const std::string malformed_id = "not_a_64_hex_string";
    const auto res = select_gc_candidates(std::vector<std::string>{valid_id},
                                          std::vector<std::string>{malformed_id});
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::IntegrityFailure);
    EXPECT_EQ(res.error().detail, "invalid content candidate identifier");
    EXPECT_EQ(res.error().object_identifier, malformed_id);
}

TEST(GcSnapshotTest, C11_DuplicateCandidateInSameCategoryDeduplicated) {
    const std::string id_var(64, '1');
    const std::string id_cnt(64, '2');

    // Duplicate variants and duplicate orphans
    const std::vector<std::string> variants{id_var, id_var};
    const std::vector<std::string> orphans{id_cnt, id_cnt};

    const auto res = select_gc_candidates(variants, orphans);
    ASSERT_TRUE(res.has_value());
    ASSERT_EQ(res->size(), 2U);
    EXPECT_EQ((*res)[0], (GcCandidate{.identifier = id_var, .kind = GcCandidateKind::CommitVariant}));
    EXPECT_EQ((*res)[1], (GcCandidate{.identifier = id_cnt, .kind = GcCandidateKind::Content}));
}

TEST(GcSnapshotTest, C11_DeterministicOrderingAfterDeduplication) {
    const std::string id_1(64, '1');
    const std::string id_2(64, '2');
    const std::string id_3(64, '3');
    const std::string id_4(64, '4');

    // Input in arbitrary order with duplicates
    const std::vector<std::string> variants{id_3, id_1, id_3};
    const std::vector<std::string> orphans{id_4, id_2, id_4};

    const auto res = select_gc_candidates(variants, orphans);
    ASSERT_TRUE(res.has_value());
    ASSERT_EQ(res->size(), 4U);

    // Must be strictly sorted by identifier
    EXPECT_EQ((*res)[0].identifier, id_1);
    EXPECT_EQ((*res)[0].kind, GcCandidateKind::CommitVariant);
    EXPECT_EQ((*res)[1].identifier, id_2);
    EXPECT_EQ((*res)[1].kind, GcCandidateKind::Content);
    EXPECT_EQ((*res)[2].identifier, id_3);
    EXPECT_EQ((*res)[2].kind, GcCandidateKind::CommitVariant);
    EXPECT_EQ((*res)[3].identifier, id_4);
    EXPECT_EQ((*res)[3].kind, GcCandidateKind::Content);
}

TEST(GcSnapshotTest, C12_UnknownStorageObject) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-c12");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("file.txt", "data")});
    add_fake_commit_object(transport, workspace, commit, "head");
    put_encrypted_content(
        transport, workspace, content_id("data"), "data", "c_data");

    // Unknown foreign file
    state->objects["random/unknown/junk.bin"] = {0};

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(snapshot.has_value());
    EXPECT_EQ(snapshot.error().code, ErrorCode::IntegrityFailure);
}

TEST(GcSnapshotTest, C13_ListFailure) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-c13");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("file.txt", "data")});
    add_fake_commit_object(transport, workspace, commit, "head");
    put_encrypted_content(
        transport, workspace, content_id("data"), "data", "c_data");

    state->fail_list = kasumi::transport::ErrorCode::Io;

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(snapshot.has_value());
    EXPECT_EQ(snapshot.error().code, ErrorCode::TransportFailure);
}

TEST(GcSnapshotTest, C14_InventoryReadFailure) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-c14");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("file.txt", "data")});
    add_fake_commit_object(transport, workspace, commit, "head");
    put_encrypted_content(
        transport, workspace, content_id("data"), "data", "c_data");

    state->fail_commit_get = true;

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(snapshot.has_value());
    EXPECT_EQ(snapshot.error().code, ErrorCode::TransportFailure);
}

TEST(GcSnapshotTest, C15_InconclusiveTransportResult) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-c15");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("file.txt", "data")});
    add_fake_commit_object(transport, workspace, commit, "head");
    put_encrypted_content(
        transport, workspace, content_id("data"), "data", "c_data");

    state->fail_marker_get = true;

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(snapshot.has_value());
    EXPECT_EQ(snapshot.error().code, ErrorCode::TransportFailure);
}

// ============================================================================
// Grupo D — Estabilidade & Equivalência
// ============================================================================

TEST(GcSnapshotTest, D1_IdenticalSnapshotsEquivalent) {
    GcSnapshot snap{
        .logical_heads = {"h1"},
        .reachable_commits = {"c1"},
        .required_commit_objects = {"v1"},
        .reachable_content = {"cont1"},
        .physical_namespace = {"p1"},
        .candidates = {GcCandidate{.identifier = "cand1", .kind = GcCandidateKind::Content}},
    };
    EXPECT_TRUE(same_gc_snapshot(snap, snap));
}

TEST(GcSnapshotTest, D2_DifferentLogicalHeadsNotEquivalent) {
    GcSnapshot s1{.logical_heads = {"h1"}};
    GcSnapshot s2{.logical_heads = {"h2"}};
    EXPECT_FALSE(same_gc_snapshot(s1, s2));
}

TEST(GcSnapshotTest, D3_DifferentReachableCommitsNotEquivalent) {
    GcSnapshot s1{.reachable_commits = {"c1"}};
    GcSnapshot s2{.reachable_commits = {"c2"}};
    EXPECT_FALSE(same_gc_snapshot(s1, s2));
}

TEST(GcSnapshotTest, D4_DifferentReachableContentNotEquivalent) {
    GcSnapshot s1{.reachable_content = {"cnt1"}};
    GcSnapshot s2{.reachable_content = {"cnt2"}};
    EXPECT_FALSE(same_gc_snapshot(s1, s2));
}

TEST(GcSnapshotTest, D5_DifferentPhysicalNamespaceNotEquivalent) {
    GcSnapshot s1{.physical_namespace = {"p1"}};
    GcSnapshot s2{.physical_namespace = {"p2"}};
    EXPECT_FALSE(same_gc_snapshot(s1, s2));
}

TEST(GcSnapshotTest, D6_DifferentClassificationNotEquivalent) {
    GcSnapshot s1{
        .candidates = {GcCandidate{.identifier = "obj1", .kind = GcCandidateKind::Content}},
    };
    GcSnapshot s2{
        .candidates = {GcCandidate{.identifier = "obj1", .kind = GcCandidateKind::CommitVariant}},
    };
    EXPECT_FALSE(same_gc_snapshot(s1, s2));
}

TEST(GcSnapshotTest, D7_OrderInsensitiveAfterNormalization) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-d7");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    // Setup multi-head, multi-commit, multi-content environment
    const auto commit1 =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("c1.txt", "payload1")});
    const auto ref1 =
        add_fake_commit_object(transport, workspace, commit1, "head1_v1", true);
    const auto ref1_extra =
        add_fake_commit_object(transport, workspace, commit1, "head1_v2", false);
    static_cast<void>(ref1);
    static_cast<void>(ref1_extra);

    const auto commit2 =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("c2.txt", "payload2")});
    const auto ref2 =
        add_fake_commit_object(transport, workspace, commit2, "head2", true);
    static_cast<void>(ref2);

    const auto c1 = content_id("payload1");
    const auto c2 = content_id("payload2");
    put_encrypted_content(transport, workspace, c1, "payload1", "c1");
    put_encrypted_content(transport, workspace, c2, "payload2", "c2");

    const auto orphan1 = content_id("orphan_alpha");
    const auto orphan2 = content_id("orphan_beta");
    put_encrypted_content(transport, workspace, orphan1, "orphan_alpha", "orph1");
    put_encrypted_content(transport, workspace, orphan2, "orphan_beta", "orph2");

    // Observation 1: natural listing
    const auto raw_list1 = kasumi::transport::list(transport);
    ASSERT_TRUE(raw_list1.has_value());
    const auto first = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(first.has_value()) << first.error().detail;

    // Observation 2: reverse listing
    state->reverse_listing = true;
    const auto raw_list2 = kasumi::transport::list(transport);
    ASSERT_TRUE(raw_list2.has_value());

    // Confirm that the transport listing order ACTUALLY differed
    ASSERT_NE(*raw_list1, *raw_list2);

    const auto second = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(second.has_value()) << second.error().detail;

    // Verify all canonical collections are equivalent across different transport orders
    EXPECT_GT(first->logical_heads.size(), 1U);
    EXPECT_EQ(first->logical_heads, second->logical_heads);

    EXPECT_GT(first->reachable_commits.size(), 1U);
    EXPECT_EQ(first->reachable_commits, second->reachable_commits);

    EXPECT_GT(first->required_commit_objects.size(), 1U);
    EXPECT_EQ(first->required_commit_objects, second->required_commit_objects);

    EXPECT_GT(first->reachable_content.size(), 1U);
    EXPECT_EQ(first->reachable_content, second->reachable_content);

    EXPECT_GT(first->physical_namespace.size(), 1U);
    EXPECT_EQ(first->physical_namespace, second->physical_namespace);

    EXPECT_GT(first->candidates.size(), 1U);
    EXPECT_EQ(first->candidates, second->candidates);

    // Snapshot equality and same_gc_snapshot comparison
    EXPECT_TRUE(same_gc_snapshot(*first, *second));
    EXPECT_EQ(*first, *second);

    // Verify that same_gc_snapshot is pure and fails if any individual collection differs
    {
        auto perturbed = *first;
        perturbed.logical_heads.push_back("extra_head");
        EXPECT_FALSE(same_gc_snapshot(*first, perturbed));
    }
    {
        auto perturbed = *first;
        perturbed.reachable_commits.push_back("extra_commit");
        EXPECT_FALSE(same_gc_snapshot(*first, perturbed));
    }
    {
        auto perturbed = *first;
        perturbed.required_commit_objects.push_back("extra_req");
        EXPECT_FALSE(same_gc_snapshot(*first, perturbed));
    }
    {
        auto perturbed = *first;
        perturbed.reachable_content.push_back("extra_content");
        EXPECT_FALSE(same_gc_snapshot(*first, perturbed));
    }
    {
        auto perturbed = *first;
        perturbed.physical_namespace.push_back("extra_phys");
        EXPECT_FALSE(same_gc_snapshot(*first, perturbed));
    }
    {
        auto perturbed = *first;
        perturbed.candidates.push_back(
            GcCandidate{.identifier = "extra_cand", .kind = GcCandidateKind::Content});
        EXPECT_FALSE(same_gc_snapshot(*first, perturbed));
    }
}

// ============================================================================
// Grupo E — Ausência de efeitos colaterais
// ============================================================================

TEST(GcSnapshotTest, E1_ZeroMutatingCallsOnSuccess) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-e1");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("file.txt", "data")});
    add_fake_commit_object(transport, workspace, commit, "head_var", true);
    add_fake_commit_object(transport, workspace, commit, "extra_var", false);
    put_encrypted_content(
        transport, workspace, content_id("data"), "data", "c_data");
    put_encrypted_content(
        transport, workspace, content_id("orphan"), "orphan", "c_orphan");

    reset_fake_traffic(*state);
    const auto objects_before = state->objects;

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(snapshot.has_value()) << snapshot.error().detail;

    EXPECT_EQ(state->remove_count, 0U);
    EXPECT_EQ(state->remove_batch_count, 0U);
    EXPECT_EQ(state->copy_count, 0U);
    EXPECT_EQ(state->copy_batch_count, 0U);
    EXPECT_EQ(state->put_count, 0U);
    EXPECT_EQ(state->put_batch_count, 0U);
    EXPECT_EQ(state->put_files_batch_count, 0U);
    EXPECT_EQ(state->quarantine_metadata_put_count, 0U);
    EXPECT_EQ(state->objects, objects_before);
}

TEST(GcSnapshotTest, E2_ZeroMutatingCallsOnError) {
    auto workspace = kasumi::test::make_temp_workspace("gc-snap-e2");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    const auto commit =
        make_tree_commit(0,
                         {},
                         {NodeRow{.path = "", .is_directory = true},
                          file_row("file.txt", "data")});
    add_fake_commit_object(transport, workspace, commit, "head");
    state->objects["random/unknown/junk.bin"] = {0};

    reset_fake_traffic(*state);
    const auto objects_before = state->objects;

    const auto snapshot = collect_gc_snapshot(
        transport, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(snapshot.has_value());

    EXPECT_EQ(state->remove_count, 0U);
    EXPECT_EQ(state->remove_batch_count, 0U);
    EXPECT_EQ(state->copy_count, 0U);
    EXPECT_EQ(state->copy_batch_count, 0U);
    EXPECT_EQ(state->put_count, 0U);
    EXPECT_EQ(state->put_batch_count, 0U);
    EXPECT_EQ(state->put_files_batch_count, 0U);
    EXPECT_EQ(state->objects, objects_before);
}

} // namespace
