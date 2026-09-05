#include "application/history_storage/epoch.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/reachability.hpp"
#include "application/integrity/maintenance.hpp"
#include "core/maintenance.hpp"
#include "kasumi/test/history_storage.hpp"
#include "platform/clock.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

using kasumi::application::history_storage::PublishedCommit;
namespace protocol = kasumi::application::history_storage::maintenance_protocol;
using IntegrityErrorCode = kasumi::application::integrity::ErrorCode;
using kasumi::runtime::RuntimeData;
using kasumi::transport::Presence;

RuntimeData runtime_data(TempWorkspace& workspace) {
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    EXPECT_TRUE(std::filesystem::create_directories(local));
    EXPECT_TRUE(std::filesystem::create_directories(profile));
    return RuntimeData{
        .local_dir = local,
        .database_path = profile / "db.sqlite",
        .key_path = profile / "key.bin",
        .storage_location = "unused",
    };
}

std::string put_content(kasumi::transport::Transport& transport,
                        TempWorkspace& workspace,
                        std::string_view content,
                        std::string_view suffix) {
    const auto identifier = kasumi::crypto::content_identifier(
        test_key(), kasumi::hasher::hash_string(content));
    const auto plain =
        kasumi::test::workspace_path(workspace, std::string{suffix} + ".plain");
    const auto encrypted =
        kasumi::test::workspace_path(workspace, std::string{suffix} + ".enc");
    kasumi::test::write_text(plain, content);
    EXPECT_TRUE(kasumi::crypto::encrypt_file(plain, encrypted, test_key()));
    EXPECT_TRUE(kasumi::transport::put(transport, encrypted, identifier));
    return identifier;
}

PublishedCommit publish_remote(kasumi::transport::Transport& transport,
                               TempWorkspace& workspace,
                               const Commit& commit) {
    auto published = kasumi::application::history_storage::publish_commit(
        transport, test_key(), commit, kasumi::test::workspace_root(workspace));
    EXPECT_TRUE(published.has_value()) << published.error().detail;
    return published ? *published : PublishedCommit{};
}

void expect_presence(kasumi::transport::Transport& transport,
                     std::string_view identifier,
                     Presence expected) {
    const auto present = kasumi::transport::presence(transport, identifier);
    ASSERT_TRUE(present.has_value()) << present.error().message;
    EXPECT_EQ(*present, expected);
}

TEST(MaintenanceTest, UnicodeReferenceAndRecoveryPaths) {
    const auto hash = kasumi::hasher::hash_string("content");
    const std::string first_path = "千早愛音/𓆩🌸𓆪.txt";
    const std::string second_path = "高松灯/カード💝.png";
    kasumi::Snapshot tree{.rows = {
        {.path = "", .is_directory = true},
        {.path = "千早愛音", .is_directory = true},
        {.path = first_path, .hash = hash, .size = 7},
        {.path = "高松灯", .is_directory = true},
        {.path = second_path, .hash = hash, .size = 7},
    }};
    kasumi::finalize_snapshot(tree);
    const std::vector<std::string> physical{kasumi::hash_hex(hash), "unexpected-🌸.object"};
    const auto inventory = kasumi::maintenance::analyze(tree, tree, physical);
    ASSERT_TRUE(inventory.has_value()) << inventory.error().detail;
    ASSERT_EQ(inventory->referenced_objects.size(), 1U);
    const auto& reference = inventory->referenced_objects.front();
    ASSERT_EQ(reference.referenced_paths.size(), 2U);
    EXPECT_EQ(reference.referenced_paths[0], kasumi::platform::path::from_utf8(first_path));
    EXPECT_EQ(reference.referenced_paths[1], kasumi::platform::path::from_utf8(second_path));
    ASSERT_TRUE(reference.local_source.has_value());
    EXPECT_EQ(*reference.local_source, kasumi::platform::path::from_utf8(first_path));
    EXPECT_TRUE(reference.physically_present);
    EXPECT_EQ(inventory->unknown_identifiers,
              (std::vector<std::string>{"unexpected-🌸.object"}));

    tree.rows.back().size = 8;
    kasumi::finalize_snapshot(tree);
    const auto conflict = kasumi::maintenance::analyze(tree, {}, physical);
    ASSERT_FALSE(conflict.has_value());
    EXPECT_EQ(conflict.error().code, kasumi::maintenance::ErrorCode::ConflictingReference);
    ASSERT_EQ(conflict.error().paths.size(), 2U);
    EXPECT_EQ(conflict.error().paths[0], kasumi::platform::path::from_utf8(first_path));
    EXPECT_EQ(conflict.error().paths[1], kasumi::platform::path::from_utf8(second_path));
}

TEST(IntegrityMaintenanceTest,
     GarbageCollectPreservesHeadsAndQuarantinesAllKnownOrphans) {
    static_cast<void>(&publish);
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);

    const auto alpha = make_commit(0, {}, "alpha.txt", "alpha").value();
    const auto beta = make_commit(0, {}, "beta.txt", "beta").value();
    const auto alpha_published =
        publish_remote(storage.transport, storage.workspace, alpha);
    const auto beta_published =
        publish_remote(storage.transport, storage.workspace, beta);
    const auto alpha_content =
        put_content(storage.transport, storage.workspace, "alpha", "alpha");
    const auto beta_content =
        put_content(storage.transport, storage.workspace, "beta", "beta");

    const auto orphan = make_commit(0, {}, "old.txt", "old").value();
    const auto orphan_published =
        publish_remote(storage.transport, storage.workspace, orphan);
    ASSERT_EQ(kasumi::transport::remove(storage.transport,
                                        marker_path(orphan_published.head))
                  .value(),
              kasumi::transport::Removal::Removed);
    const auto orphan_content =
        put_content(storage.transport, storage.workspace, "old", "old");
    const auto loose_content =
        put_content(storage.transport, storage.workspace, "loose", "loose");
    const auto orphan_content_quarantine =
        protocol::quarantine_identifier(orphan_content).value();
    const auto orphan_commit_quarantine =
        protocol::quarantine_identifier(object_path(orphan_published.head))
            .value();

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 3U);
    EXPECT_EQ(collected->quarantined_objects, 3U);
    EXPECT_EQ(collected->restored_objects, 0U);
    EXPECT_EQ(collected->purged_objects, 0U);
    EXPECT_FALSE(collected->analysis_only);

    expect_presence(storage.transport, alpha_content, Presence::Present);
    expect_presence(storage.transport, beta_content, Presence::Present);
    expect_presence(storage.transport,
                    object_path(alpha_published.head),
                    Presence::Present);
    expect_presence(
        storage.transport, object_path(beta_published.head), Presence::Present);
    expect_presence(storage.transport, orphan_content, Presence::Absent);
    expect_presence(storage.transport, loose_content, Presence::Absent);
    expect_presence(storage.transport,
                    object_path(orphan_published.head),
                    Presence::Absent);
    expect_presence(
        storage.transport, orphan_content_quarantine, Presence::Present);
    expect_presence(storage.transport,
                    protocol::quarantine_identifier(loose_content).value(),
                    Presence::Present);
    expect_presence(
        storage.transport, orphan_commit_quarantine, Presence::Present);

    ASSERT_TRUE(protocol::record_quarantine(
        storage.transport,
        orphan_content_quarantine,
        0,
        test_key(),
        kasumi::test::workspace_root(storage.workspace)));
    ASSERT_TRUE(protocol::record_quarantine(
        storage.transport,
        orphan_commit_quarantine,
        0,
        test_key(),
        kasumi::test::workspace_root(storage.workspace)));

    const auto marker = kasumi::application::history_storage::encode_marker(
                            orphan_published.head)
                            .value();
    const auto marker_file =
        kasumi::test::workspace_path(storage.workspace, "restored.head");
    kasumi::test::write_binary(marker_file, std::as_bytes(std::span{marker}));
    ASSERT_TRUE(kasumi::transport::put(
        storage.transport, marker_file, marker_path(orphan_published.head)));

    const auto restored = kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key());
    ASSERT_TRUE(restored.has_value()) << restored.error().detail;
    EXPECT_EQ(restored->quarantined_objects, 0U);
    EXPECT_EQ(restored->restored_objects, 2U);
    EXPECT_EQ(restored->purged_objects, 0U);
    expect_presence(storage.transport, orphan_content, Presence::Present);
    expect_presence(storage.transport,
                    object_path(orphan_published.head),
                    Presence::Present);

    const auto repeated = kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key());
    ASSERT_TRUE(repeated.has_value()) << repeated.error().detail;
    EXPECT_EQ(repeated->candidate_objects, 0U);
    EXPECT_EQ(repeated->quarantined_objects, 0U);
    EXPECT_EQ(repeated->restored_objects, 0U);
    EXPECT_EQ(repeated->purged_objects, 0U);
}

TEST(IntegrityMaintenanceTest,
     HistoricalEpochObjectsAreNeverGarbageCollectionCandidates) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);
    const auto bootstrap = kasumi::history::make_empty_bootstrap().value();
    const auto published =
        publish_remote(storage.transport, storage.workspace, bootstrap);

    const std::string vault_id(64, 'a');
    std::string previous_epoch_id;
    std::vector<std::string> epoch_objects;
    for (std::uint64_t sequence = 0; sequence < 3; ++sequence) {
        kasumi::application::history_storage::epoch::Epoch value{
            .vault_id = vault_id,
            .sequence = sequence,
            .issued_at = static_cast<std::int64_t>(sequence),
            .policy = {},
            .anchors = {{published.head.commit_id, 0}},
            .previous_epoch_id = previous_epoch_id,
        };
        const auto sealed = kasumi::application::history_storage::epoch::seal(
            value, test_key());
        ASSERT_TRUE(sealed.has_value()) << sealed.error().detail;
        const auto identifier =
            kasumi::application::history_storage::epoch::object_identifier(
                sealed->reference);
        ASSERT_TRUE(identifier.has_value()) << identifier.error().detail;
        ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
            storage.transport,
            *sealed,
            kasumi::test::workspace_root(storage.workspace)));
        epoch_objects.push_back(*identifier);
        previous_epoch_id = sealed->reference.epoch_id;
    }

    const auto history =
        kasumi::application::history_storage::inventory_reachability(
            storage.transport,
            test_key(),
            kasumi::test::workspace_root(storage.workspace));
    ASSERT_TRUE(history.has_value()) << history.error().detail;
    ASSERT_EQ(history->valid_epochs.size(), 1U);
    ASSERT_EQ(history->orphan_epochs.size(), 2U);
    EXPECT_NE(
        std::ranges::find(history->reachable_commits, published.head.commit_id),
        history->reachable_commits.end());

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 0U);
    EXPECT_EQ(collected->quarantined_objects, 0U);
    EXPECT_EQ(collected->purged_objects, 0U);
    EXPECT_FALSE(collected->analysis_only);
    for (const auto& identifier : epoch_objects) {
        expect_presence(storage.transport, identifier, Presence::Present);
    }

    const auto quarantine = protocol::inventory_quarantine(
        storage.transport,
        test_key(),
        kasumi::test::workspace_root(storage.workspace));
    ASSERT_TRUE(quarantine.has_value()) << quarantine.error().detail;
    EXPECT_TRUE(std::ranges::none_of(*quarantine, [](const auto& entry) {
        return protocol::is_epoch_object(entry.original_identifier);
    }));

    const auto repeated = kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key());
    ASSERT_TRUE(repeated.has_value()) << repeated.error().detail;
    EXPECT_EQ(repeated->candidate_objects, 0U);
    EXPECT_EQ(repeated->quarantined_objects, 0U);
    EXPECT_EQ(repeated->purged_objects, 0U);
    for (const auto& identifier : epoch_objects) {
        expect_presence(storage.transport, identifier, Presence::Present);
    }

    const auto checked = kasumi::application::integrity::fsck(
        runtime, storage.transport, test_key());
    ASSERT_TRUE(checked.has_value()) << checked.error().detail;
}

TEST(IntegrityMaintenanceTest, EpochNamespaceIsBlockedAtTheCopyBoundary) {
    auto storage = make_local_storage();
    const std::string malformed = "history/epochs/v1/garbage";
    const std::string valid_shape = "history/epochs/v1/00000000000000000000-" +
                                    std::string(64, 'a') + ".epoch";

    EXPECT_TRUE(protocol::is_epoch_object(malformed));
    EXPECT_TRUE(protocol::is_epoch_object(valid_shape));
    EXPECT_FALSE(protocol::is_epoch_object("history/epoch/v1/garbage"));
    EXPECT_FALSE(protocol::quarantine_identifier(malformed).has_value());

    const auto into_quarantine = protocol::copy_verified(
        storage.transport,
        malformed,
        "history/gc/v1/quarantine/content/" + std::string(64, 'a'),
        kasumi::test::workspace_root(storage.workspace));
    ASSERT_FALSE(into_quarantine.has_value());
    EXPECT_EQ(into_quarantine.error().code, protocol::ErrorCode::Blocked);

    const auto from_quarantine = protocol::copy_verified(
        storage.transport,
        std::string(64, 'a'),
        malformed,
        kasumi::test::workspace_root(storage.workspace));
    ASSERT_FALSE(from_quarantine.has_value());
    EXPECT_EQ(from_quarantine.error().code, protocol::ErrorCode::Blocked);
}

TEST(IntegrityMaintenanceTest,
     GarbageCollectQuarantinesAndPurgesRedundantReachableVariant) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto first = add_variant(storage, commit);
    const auto second = add_variant(storage, commit);
    ASSERT_NE(first, second);
    const auto redundant = std::min(first, second);
    const auto head = std::max(first, second);
    ASSERT_EQ(
        kasumi::transport::remove(storage.transport, marker_path(redundant))
            .value(),
        kasumi::transport::Removal::Removed);
    const auto quarantined =
        protocol::quarantine_identifier(object_path(redundant)).value();

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 1U);
    EXPECT_EQ(collected->quarantined_objects, 1U);
    expect_presence(
        storage.transport, object_path(redundant), Presence::Absent);
    expect_presence(storage.transport, quarantined, Presence::Present);
    expect_presence(storage.transport, object_path(head), Presence::Present);
    expect_presence(storage.transport, marker_path(head), Presence::Present);
    EXPECT_EQ(load(storage).commits.size(), 1U);

    const auto now = kasumi::platform::clock::unix_seconds();
    ASSERT_TRUE(now.has_value()) << now.error();
    const auto aged = protocol::record_quarantine(
        storage.transport,
        quarantined,
        *now - protocol::quarantine_retention_seconds - 1,
        test_key(),
        kasumi::test::workspace_root(storage.workspace));
    ASSERT_TRUE(aged.has_value()) << aged.error().detail;

    const auto purged = kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key());
    ASSERT_TRUE(purged.has_value()) << purged.error().detail;
    EXPECT_EQ(purged->candidate_objects, 0U);
    EXPECT_EQ(purged->purged_objects, 1U);
    expect_presence(storage.transport, quarantined, Presence::Absent);
    expect_presence(
        storage.transport, aged->metadata_identifier, Presence::Absent);
    expect_presence(storage.transport, object_path(head), Presence::Present);
}

TEST(IntegrityMaintenanceTest,
     GarbageCollectPreservesEveryHeadReferencedVariant) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);
    const auto commit = kasumi::history::make_empty_bootstrap().value();
    const auto first = add_variant(storage, commit);
    const auto second = add_variant(storage, commit);
    ASSERT_NE(first, second);

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 0U);
    EXPECT_EQ(collected->quarantined_objects, 0U);
    expect_presence(storage.transport, object_path(first), Presence::Present);
    expect_presence(storage.transport, object_path(second), Presence::Present);
    expect_presence(storage.transport, marker_path(first), Presence::Present);
    expect_presence(storage.transport, marker_path(second), Presence::Present);
}

TEST(IntegrityMaintenanceTest,
     GarbageCollectKeepsOneValidVariantForUnmarkedReachableAncestor) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);
    const auto parent = kasumi::history::make_empty_bootstrap().value();
    const auto first = add_variant(storage, parent);
    const auto second = add_variant(storage, parent);
    ASSERT_NE(first, second);
    ASSERT_EQ(kasumi::transport::remove(storage.transport, marker_path(first))
                  .value(),
              kasumi::transport::Removal::Removed);
    ASSERT_EQ(kasumi::transport::remove(storage.transport, marker_path(second))
                  .value(),
              kasumi::transport::Removal::Removed);
    const auto child =
        kasumi::history::make_commit(1, {commit_id(parent)}, parent.tree)
            .value();
    const auto child_head = add_variant(storage, child);
    const auto kept = std::min(first, second);
    const auto redundant = std::max(first, second);

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 1U);
    EXPECT_EQ(collected->quarantined_objects, 1U);
    expect_presence(storage.transport, object_path(kept), Presence::Present);
    expect_presence(
        storage.transport, object_path(redundant), Presence::Absent);
    expect_presence(
        storage.transport, object_path(child_head), Presence::Present);
    EXPECT_EQ(load(storage).commits.size(), 2U);
}

TEST(IntegrityMaintenanceTest, PurgesOnlyAfterTenDaysAndAnotherCollection) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);
    publish_remote(storage.transport,
                   storage.workspace,
                   kasumi::history::make_empty_bootstrap().value());
    const auto orphan =
        put_content(storage.transport, storage.workspace, "orphan", "orphan");
    const auto quarantined = protocol::quarantine_identifier(orphan).value();

    const auto first = kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key());
    ASSERT_TRUE(first.has_value()) << first.error().detail;
    EXPECT_EQ(first->quarantined_objects, 1U);
    EXPECT_EQ(first->purged_objects, 0U);

    const auto immediate = kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key());
    ASSERT_TRUE(immediate.has_value()) << immediate.error().detail;
    EXPECT_EQ(immediate->purged_objects, 0U);
    expect_presence(storage.transport, quarantined, Presence::Present);

    const auto now = kasumi::platform::clock::unix_seconds();
    ASSERT_TRUE(now.has_value()) << now.error();
    ASSERT_TRUE(protocol::record_quarantine(
        storage.transport,
        quarantined,
        *now - protocol::quarantine_retention_seconds + 60,
        test_key(),
        kasumi::test::workspace_root(storage.workspace)));
    const auto too_soon = kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key());
    ASSERT_TRUE(too_soon.has_value()) << too_soon.error().detail;
    EXPECT_EQ(too_soon->purged_objects, 0U);
    expect_presence(storage.transport, quarantined, Presence::Present);

    auto aged = protocol::record_quarantine(
        storage.transport,
        quarantined,
        *now - protocol::quarantine_retention_seconds - 1,
        test_key(),
        kasumi::test::workspace_root(storage.workspace));
    ASSERT_TRUE(aged.has_value()) << aged.error().detail;
    const auto purged = kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key());
    ASSERT_TRUE(purged.has_value()) << purged.error().detail;
    EXPECT_EQ(purged->purged_objects, 1U);
    expect_presence(storage.transport, quarantined, Presence::Absent);
    expect_presence(
        storage.transport, aged->metadata_identifier, Presence::Absent);
}

TEST(IntegrityMaintenanceTest,
     GarbageCollectFailsClosedWhenReachableContentIsMissing) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);
    const auto commit = make_commit(0, {}, "live.txt", "live").value();
    const auto published =
        publish_remote(storage.transport, storage.workspace, commit);
    const auto orphan =
        put_content(storage.transport, storage.workspace, "orphan", "orphan");

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::IntegrityFailure);
    expect_presence(storage.transport, orphan, Presence::Present);
    expect_presence(
        storage.transport, object_path(published.head), Presence::Present);
}

TEST(IntegrityMaintenanceTest,
     GarbageCollectAbortsBeforeRemovalWhenTheRemoteChanges) {
    auto workspace =
        kasumi::test::make_temp_workspace("garbage-collect-concurrent");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);

    const auto bootstrap = kasumi::history::make_empty_bootstrap().value();
    publish_remote(transport, workspace, bootstrap);
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");

    const auto concurrent =
        make_commit(0, {}, "concurrent.txt", "concurrent").value();
    const auto concurrent_published =
        publish_remote(transport, workspace, concurrent);
    const auto concurrent_content =
        put_content(transport, workspace, "concurrent", "concurrent");

    const auto hide = [&](const std::string& identifier) {
        auto node = state->objects.extract(identifier);
        ASSERT_FALSE(node.empty());
        state->hidden_objects.insert(std::move(node));
    };
    hide(object_path(concurrent_published.head));
    hide(marker_path(concurrent_published.head));
    hide(concurrent_content);
    state->reveal_on_list_count = state->list_count + 13;

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::ConcurrentChange);
    expect_presence(transport, orphan, Presence::Present);
    expect_presence(transport, concurrent_content, Presence::Present);
    expect_presence(transport,
                    protocol::quarantine_identifier(orphan).value(),
                    Presence::Absent);
}

TEST(IntegrityMaintenanceTest, ActiveOrAbandonedWriterBlocksCollection) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);
    publish_remote(storage.transport,
                   storage.workspace,
                   kasumi::history::make_empty_bootstrap().value());
    const auto orphan =
        put_content(storage.transport, storage.workspace, "orphan", "orphan");
    auto writer = protocol::register_writer(
        storage.transport, kasumi::test::workspace_root(storage.workspace));
    ASSERT_TRUE(writer.has_value()) << writer.error().detail;

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::ConcurrentChange);
    expect_presence(storage.transport, orphan, Presence::Present);
    expect_presence(storage.transport,
                    protocol::quarantine_identifier(orphan).value(),
                    Presence::Absent);
    ASSERT_TRUE(protocol::release_registration(*writer));
}

TEST(IntegrityMaintenanceTest, WriterPhysicalHashSuccessAvoidsReadback) {
    auto workspace = kasumi::test::make_temp_workspace("writer-hash-success");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;

    auto writer = protocol::register_writer(
        transport, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(writer.has_value()) << writer.error().detail;
    EXPECT_EQ(state->put_count, 1U);
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->get_count, 0U);
    ASSERT_TRUE(protocol::release_registration(*writer));
}

TEST(IntegrityMaintenanceTest, WriterPhysicalHashMismatchFailsWithoutReadback) {
    auto workspace = kasumi::test::make_temp_workspace("writer-hash-mismatch");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->physical_hash_mismatch = true;

    const auto writer = protocol::register_writer(
        transport, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(writer.has_value());
    EXPECT_EQ(writer.error().code, protocol::ErrorCode::VerificationFailure);
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->get_count, 0U);
}

TEST(IntegrityMaintenanceTest,
     WriterPhysicalHashUnsupportedFallsBackToReadback) {
    auto workspace = kasumi::test::make_temp_workspace("writer-hash-fallback");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));

    auto writer = protocol::register_writer(
        transport, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(writer.has_value()) << writer.error().detail;
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->get_count, 1U);
    ASSERT_TRUE(protocol::release_registration(*writer));
}

TEST(IntegrityMaintenanceTest,
     WriterPhysicalHashTransportFailureDoesNotReadback) {
    auto workspace = kasumi::test::make_temp_workspace("writer-hash-error");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->physical_hash_failure = kasumi::transport::ErrorCode::Io;

    const auto writer = protocol::register_writer(
        transport, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(writer.has_value());
    EXPECT_EQ(writer.error().code, protocol::ErrorCode::TransportFailure);
    EXPECT_EQ(state->physical_hash_count, 1U);
    EXPECT_EQ(state->get_count, 0U);
}

TEST(IntegrityMaintenanceTest,
     WriterAdmissionFallbackPreservesListBeforeBarrierOrder) {
    auto workspace =
        kasumi::test::make_temp_workspace("writer-admission-fallback");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->publish_barrier_after_writer_list = true;

    const auto writer = protocol::register_writer(
        transport, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(writer.has_value());
    EXPECT_EQ(writer.error().code, protocol::ErrorCode::Blocked);
    EXPECT_EQ(state->control_read_batch_count, 1U);
    EXPECT_EQ(state->list_count, 1U);
    EXPECT_EQ(state->presence_count, 1U);
}

TEST(IntegrityMaintenanceTest, WriterAdmissionAllowsSecondWriter) {
    auto workspace = kasumi::test::make_temp_workspace("writer-admission-peer");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->control_read_batch_supported = true;
    state->objects
        ["history/gc/v1/writers/11111111111111111111111111111111.writer"] = {};

    auto writer = protocol::register_writer(
        transport, kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(writer.has_value()) << writer.error().detail;
    EXPECT_EQ(state->control_read_batch_count, 1U);
    EXPECT_EQ(state->list_count, 1U);
    EXPECT_EQ(state->presence_count, 1U);
    ASSERT_TRUE(protocol::release_registration(*writer));
}

TEST(IntegrityMaintenanceTest, WriterAdmissionBatchRejectsMissingWriter) {
    auto workspace =
        kasumi::test::make_temp_workspace("writer-admission-missing");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->control_read_batch_supported = true;
    state->hide_writer_listing = true;

    const auto writer = protocol::register_writer(
        transport, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(writer.has_value());
    EXPECT_EQ(writer.error().code, protocol::ErrorCode::BackendUnsafe);
    EXPECT_EQ(state->control_read_batch_count, 1U);
    EXPECT_EQ(state->list_count, 1U);
    EXPECT_EQ(state->presence_count, 1U);
}

TEST(IntegrityMaintenanceTest, WriterAdmissionBlocksPresentBarrier) {
    auto workspace =
        kasumi::test::make_temp_workspace("writer-admission-barrier");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->control_read_batch_supported = true;
    state->objects["history/gc/v1/barrier"] = {};

    const auto writer = protocol::register_writer(
        transport, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(writer.has_value());
    EXPECT_EQ(writer.error().code, protocol::ErrorCode::Blocked);
    EXPECT_EQ(state->control_read_batch_count, 1U);
    EXPECT_EQ(state->list_count, 1U);
    EXPECT_EQ(state->presence_count, 1U);
}

TEST(IntegrityMaintenanceTest,
     WriterAdmissionBlocksBarrierEstablishedAfterWriterList) {
    auto workspace =
        kasumi::test::make_temp_workspace("writer-admission-racing-barrier");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->control_read_batch_supported = true;
    state->publish_barrier_after_writer_list = true;

    const auto writer = protocol::register_writer(
        transport, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(writer.has_value());
    EXPECT_EQ(writer.error().code, protocol::ErrorCode::Blocked);
    EXPECT_EQ(state->control_read_batch_count, 1U);
    EXPECT_EQ(state->list_count, 1U);
    EXPECT_EQ(state->presence_count, 1U);
}

TEST(IntegrityMaintenanceTest,
     WriterAdmissionListFailureFailsClosedBeforeBarrierRead) {
    auto workspace =
        kasumi::test::make_temp_workspace("writer-admission-list-error");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->control_read_batch_supported = true;
    state->fail_writer_list = true;

    const auto writer = protocol::register_writer(
        transport, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(writer.has_value());
    EXPECT_EQ(writer.error().code, protocol::ErrorCode::TransportFailure);
    EXPECT_EQ(state->control_read_batch_count, 1U);
    EXPECT_EQ(state->list_count, 1U);
    EXPECT_EQ(state->presence_count, 0U);
}

TEST(IntegrityMaintenanceTest, WriterAdmissionBarrierFailureFailsClosed) {
    auto workspace =
        kasumi::test::make_temp_workspace("writer-admission-barrier-error");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->control_read_batch_supported = true;
    state->fail_barrier_presence = true;

    const auto writer = protocol::register_writer(
        transport, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(writer.has_value());
    EXPECT_EQ(writer.error().code, protocol::ErrorCode::TransportFailure);
    EXPECT_EQ(state->control_read_batch_count, 1U);
    EXPECT_EQ(state->list_count, 1U);
    EXPECT_EQ(state->presence_count, 1U);
}

TEST(IntegrityMaintenanceTest, WriterAdmissionBatchFailureDoesNotRetryReads) {
    auto workspace =
        kasumi::test::make_temp_workspace("writer-admission-batch-error");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->control_read_batch_failure = kasumi::transport::ErrorCode::Io;

    const auto writer = protocol::register_writer(
        transport, kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(writer.has_value());
    EXPECT_EQ(writer.error().code, protocol::ErrorCode::TransportFailure);
    EXPECT_EQ(state->control_read_batch_count, 1U);
    EXPECT_EQ(state->list_count, 0U);
    EXPECT_EQ(state->presence_count, 0U);
}

TEST(IntegrityMaintenanceTest, UnsafeBackendRunsAnalysisWithoutQuarantine) {
    auto workspace = kasumi::test::make_temp_workspace("gc-analysis-only");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);
    publish_remote(
        transport, workspace, kasumi::history::make_empty_bootstrap().value());
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");
    state->hide_probe_listing = true;

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_TRUE(collected->analysis_only);
    EXPECT_EQ(collected->candidate_objects, 1U);
    EXPECT_EQ(collected->quarantined_objects, 0U);
    expect_presence(transport, orphan, Presence::Present);
    expect_presence(transport,
                    protocol::quarantine_identifier(orphan).value(),
                    Presence::Absent);
}

TEST(IntegrityMaintenanceTest,
     QuarantineVerificationFailurePreservesTheOriginal) {
    auto workspace =
        kasumi::test::make_temp_workspace("gc-quarantine-verification");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);
    publish_remote(
        transport, workspace, kasumi::history::make_empty_bootstrap().value());
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");
    state->physical_hash_supported = true;
    state->physical_hash_mismatch = true;

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::IntegrityFailure);
    expect_presence(transport, orphan, Presence::Present);
}

TEST(IntegrityMaintenanceTest, LostBarrierBeforeRemovalPreservesTheOriginal) {
    auto workspace = kasumi::test::make_temp_workspace("gc-lost-barrier");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);
    publish_remote(
        transport, workspace, kasumi::history::make_empty_bootstrap().value());
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");
    state->replace_barrier_after_quarantine_put = true;

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::ConcurrentChange);
    expect_presence(transport, orphan, Presence::Present);
    expect_presence(transport,
                    protocol::quarantine_identifier(orphan).value(),
                    Presence::Present);
}

TEST(IntegrityMaintenanceTest, UnknownControlObjectFailsClosed) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);
    publish_remote(storage.transport,
                   storage.workspace,
                   kasumi::history::make_empty_bootstrap().value());
    const auto orphan =
        put_content(storage.transport, storage.workspace, "orphan", "orphan");
    const auto unknown =
        kasumi::test::workspace_path(storage.workspace, "unknown.control");
    kasumi::test::write_text(unknown, "unknown");
    ASSERT_TRUE(kasumi::transport::put(
        storage.transport, unknown, "history/gc/v1/unknown"));

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::IntegrityFailure);
    expect_presence(storage.transport, orphan, Presence::Present);
    expect_presence(storage.transport,
                    protocol::quarantine_identifier(orphan).value(),
                    Presence::Absent);
}

TEST(IntegrityMaintenanceTest, InvalidRetentionMetadataPreservesQuarantine) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);
    publish_remote(storage.transport,
                   storage.workspace,
                   kasumi::history::make_empty_bootstrap().value());
    const auto orphan =
        put_content(storage.transport, storage.workspace, "orphan", "orphan");
    const auto quarantined = protocol::quarantine_identifier(orphan).value();
    ASSERT_TRUE(kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key()));

    const auto invalid =
        kasumi::test::workspace_path(storage.workspace, "invalid.meta");
    kasumi::test::write_text(invalid, "invalid");
    ASSERT_TRUE(kasumi::transport::put(
        storage.transport, invalid, quarantined + ".meta"));

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::IntegrityFailure);
    expect_presence(storage.transport, quarantined, Presence::Present);
}

TEST(IntegrityMaintenanceTest, InterruptedPurgeRestartsRetention) {
    auto workspace = kasumi::test::make_temp_workspace("gc-purge-resume");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);
    publish_remote(
        transport, workspace, kasumi::history::make_empty_bootstrap().value());
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");
    const auto quarantined = protocol::quarantine_identifier(orphan).value();
    ASSERT_TRUE(kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key()));
    auto aged =
        protocol::record_quarantine(transport,
                                    quarantined,
                                    0,
                                    test_key(),
                                    kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(aged.has_value()) << aged.error().detail;
    state->fail_remove_identifier = quarantined;

    const auto interrupted = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(interrupted.has_value());
    expect_presence(transport, quarantined, Presence::Present);
    expect_presence(transport, aged->metadata_identifier, Presence::Absent);

    const auto resumed = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(resumed.has_value()) << resumed.error().detail;
    EXPECT_EQ(resumed->purged_objects, 0U);
    expect_presence(transport, quarantined, Presence::Present);
    expect_presence(transport, aged->metadata_identifier, Presence::Present);
}

TEST(IntegrityMaintenanceTest, InterruptedMoveResumesIdempotently) {
    auto workspace = kasumi::test::make_temp_workspace("gc-resume");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);
    publish_remote(
        transport, workspace, kasumi::history::make_empty_bootstrap().value());
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");
    const auto quarantined = protocol::quarantine_identifier(orphan).value();
    state->fail_remove_at = 2;

    const auto interrupted = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(interrupted.has_value());
    expect_presence(transport, orphan, Presence::Present);
    expect_presence(transport, quarantined, Presence::Present);

    state->fail_remove_at = 0;
    const auto resumed = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(resumed.has_value()) << resumed.error().detail;
    EXPECT_EQ(resumed->quarantined_objects, 1U);
    expect_presence(transport, orphan, Presence::Absent);
    expect_presence(transport, quarantined, Presence::Present);
}

} // namespace
