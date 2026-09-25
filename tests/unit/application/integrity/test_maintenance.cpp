#include "application/history_storage/epoch.hpp"
#include "application/history_storage/epoch.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/reachability.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/maintenance.hpp"
#include "core/maintenance.hpp"
#include "kasumi/test/history_storage.hpp"
#include "platform/clock.hpp"
#include "platform/perf_trace.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <map>
#include <set>
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

inline const auto& test_layout() {
    static const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    return layout;
}

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

enum class IntegratedCopyPath {
    Native,
    SourceHashUnsupported,
    NativeCopyUnsupported,
    DestinationHashUnsupported,
};

enum class IntegratedFailure {
    SourceHash,
    FallbackGet,
    FallbackPut,
    CopyEffectThenError,
    CorruptReadback,
};

struct IntegratedGcFixture {
    kasumi::test::TempWorkspace workspace;
    FakeState* state = nullptr;
    kasumi::transport::Transport storage;
    RuntimeData runtime;
    std::string reachable_content;
    std::string reachable_commit;
    std::string reachable_marker;
    std::vector<std::string> candidates;
    std::vector<std::string> quarantines;
    std::map<std::string, std::vector<std::uint8_t>> initial_objects;
    std::map<std::string, std::vector<std::uint8_t>> expected_payload_objects;
    std::map<std::string, std::string> expected_hashes;

    IntegratedGcFixture(std::string_view name, std::size_t candidate_count)
        : workspace(kasumi::test::make_temp_workspace("gc-integrated-" +
                                                      std::string{name})),
          storage(make_fake_transport(state)),
          runtime(runtime_data(workspace)) {
        EXPECT_TRUE(kasumi::transport::initialize(storage));
        state->physical_hash_supported = true;
        state->copy_supported = true;

        const auto commit = make_commit(0, {}, "live.txt", "live").value();
        const auto published = publish_remote(storage, workspace, commit);
        reachable_content =
            put_content(storage, workspace, "live", "live-content");
        reachable_commit = object_path(published.head);
        reachable_marker = marker_path(published.head);
        for (std::size_t index = 0; index < candidate_count; ++index) {
            const auto suffix = "orphan-" + std::to_string(index);
            candidates.push_back(
                put_content(storage, workspace, suffix, suffix));
        }
        std::ranges::sort(candidates);
        for (const auto& candidate : candidates) {
            const auto quarantine =
                protocol::quarantine_identifier(test_layout(), candidate);
            EXPECT_TRUE(quarantine.has_value());
            if (!quarantine) {
                continue;
            }
            quarantines.push_back(*quarantine);
            expected_hashes.emplace(candidate,
                                    state->physical_hashes.at(candidate));
        }

        initial_objects = state->objects;
        expected_payload_objects = initial_objects;
        for (std::size_t index = 0; index < candidates.size(); ++index) {
            const auto bytes = expected_payload_objects.at(candidates[index]);
            expected_payload_objects.erase(candidates[index]);
            expected_payload_objects.emplace(quarantines[index], bytes);
        }
    }
};

void expect_integrated_copy_case(IntegratedCopyPath path,
                                 std::string_view name,
                                 std::size_t candidate_count = 1) {
    struct TraceGuard {
        ~TraceGuard() {
            kasumi::platform::perf_trace::force_enable(false);
        }
    } trace_guard;
    kasumi::platform::perf_trace::force_enable(true);

    IntegratedGcFixture fixture{name, candidate_count};
    const auto& first_candidate = fixture.candidates.front();
    switch (path) {
        case IntegratedCopyPath::Native:
            break;
        case IntegratedCopyPath::SourceHashUnsupported:
            fixture.state->physical_hash_unsupported_identifier =
                first_candidate;
            break;
        case IntegratedCopyPath::NativeCopyUnsupported:
            fixture.state->copy_supported = false;
            break;
        case IntegratedCopyPath::DestinationHashUnsupported:
            fixture.state->physical_hash_unsupported_identifier =
                fixture.quarantines.front();
            break;
    }
    for (const auto& identifier : fixture.candidates) {
        fixture.state->observed_payload_identifiers.insert(identifier);
    }
    reset_fake_traffic(*fixture.state);
    kasumi::platform::perf_trace::reset();

    const auto collected = kasumi::application::integrity::garbage_collect(
        fixture.runtime, fixture.storage, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_FALSE(collected->analysis_only);
    EXPECT_EQ(collected->candidate_objects, candidate_count);
    EXPECT_EQ(collected->quarantined_objects, candidate_count);
    EXPECT_EQ(collected->restored_objects, 0U);
    EXPECT_EQ(collected->purged_objects, 0U);

    EXPECT_TRUE(fixture.initial_objects.contains(fixture.reachable_commit));
    EXPECT_TRUE(fixture.initial_objects.contains(fixture.reachable_marker));
    EXPECT_TRUE(fixture.initial_objects.contains(fixture.reachable_content));
    for (const auto& candidate : fixture.candidates) {
        EXPECT_TRUE(fixture.initial_objects.contains(candidate));
        EXPECT_FALSE(fixture.initial_objects.contains(
            protocol::quarantine_identifier(test_layout(), candidate).value()));
    }
    EXPECT_EQ(fixture.state->objects.size(),
              fixture.expected_payload_objects.size() + candidate_count);
    auto actual_payload_objects = fixture.state->objects;
    for (const auto& quarantine : fixture.quarantines) {
        EXPECT_TRUE(fixture.state->objects.contains(quarantine + ".meta"));
        actual_payload_objects.erase(quarantine + ".meta");
    }
    EXPECT_EQ(actual_payload_objects, fixture.expected_payload_objects);

    const auto inventory = protocol::inventory_quarantine(
        fixture.storage,
        test_key(),
        kasumi::test::workspace_root(fixture.workspace));
    ASSERT_TRUE(inventory.has_value()) << inventory.error().detail;
    ASSERT_EQ(inventory->size(), candidate_count);
    for (const auto& entry : *inventory) {
        EXPECT_EQ(entry.quarantined_at.has_value(), true);
        EXPECT_EQ(entry.physical_sha256,
                  fixture.expected_hashes.at(entry.original_identifier));
        const auto verified = protocol::verify_quarantine(
            fixture.storage,
            entry,
            kasumi::test::workspace_root(fixture.workspace));
        ASSERT_TRUE(verified.has_value()) << verified.error().detail;
        EXPECT_TRUE(*verified);
    }

    const bool source_hash_supported =
        path != IntegratedCopyPath::SourceHashUnsupported;
    const bool native_copy_attempted = source_hash_supported;
    const bool native_copy_succeeded =
        path == IntegratedCopyPath::Native ||
        path == IntegratedCopyPath::DestinationHashUnsupported;
    const bool native_destination_hash_attempted = native_copy_succeeded;
    const bool client_fallback =
        path == IntegratedCopyPath::SourceHashUnsupported ||
        path == IntegratedCopyPath::NativeCopyUnsupported;
    std::size_t candidate_bytes = 0;
    for (const auto& candidate : fixture.candidates) {
        candidate_bytes += fixture.initial_objects.at(candidate).size();
    }
    EXPECT_EQ(fixture.state->copy_count,
              native_copy_attempted ? candidate_count : 0U);
    EXPECT_EQ(fixture.state->orphan_payload_get_count,
              client_fallback ? candidate_count : 0U);
    EXPECT_EQ(fixture.state->orphan_payload_get_bytes,
              client_fallback ? candidate_bytes : 0U);
    EXPECT_EQ(fixture.state->quarantine_payload_put_count,
              client_fallback ? candidate_count : 0U);
    EXPECT_EQ(fixture.state->quarantine_payload_put_bytes,
              client_fallback ? candidate_bytes : 0U);
    EXPECT_EQ(fixture.state->quarantine_metadata_put_count, candidate_count);
    EXPECT_EQ(fixture.state->native_copy_bytes,
              native_copy_succeeded ? candidate_bytes : 0U);

    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "verified copy source physical hash"),
              candidate_count);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("verified copy native copy"),
        native_copy_attempted ? candidate_count : 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "verified copy native copy successes"),
              native_copy_succeeded ? candidate_count : 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "verified copy native copy verifications"),
              native_copy_succeeded ? candidate_count : 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "verified copy destination physical hash"),
              native_destination_hash_attempted ? candidate_count : 0U);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("gc candidate verified copy"),
        candidate_count);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "gc candidate metadata publish"),
              candidate_count);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "gc candidate pre-remove barrier verification"),
              candidate_count);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc candidate remove"),
              candidate_count);
}

void expect_integrated_failure(IntegratedFailure failure,
                               std::string_view name,
                               IntegrityErrorCode expected_error) {
    struct TraceGuard {
        ~TraceGuard() {
            kasumi::platform::perf_trace::force_enable(false);
        }
    } trace_guard;
    kasumi::platform::perf_trace::force_enable(true);

    IntegratedGcFixture fixture{name, 1};
    const auto& source = fixture.candidates.front();
    const auto& quarantine = fixture.quarantines.front();
    fixture.state->observed_payload_identifiers.insert(source);
    fixture.state->physical_hash_supported = true;
    switch (failure) {
        case IntegratedFailure::SourceHash:
            fixture.state->physical_hash_failure =
                kasumi::transport::ErrorCode::Io;
            fixture.state->physical_hash_failure_identifier = source;
            break;
        case IntegratedFailure::FallbackGet:
            fixture.state->copy_supported = false;
            fixture.state->fail_get_identifier = source;
            break;
        case IntegratedFailure::FallbackPut:
            fixture.state->copy_supported = false;
            fixture.state->fail_put_identifier = quarantine;
            break;
        case IntegratedFailure::CopyEffectThenError:
            fixture.state->copy_failure_after_effect =
                kasumi::transport::ErrorCode::Io;
            break;
        case IntegratedFailure::CorruptReadback:
            fixture.state->physical_hash_unsupported_identifier = quarantine;
            fixture.state->corrupt_get_identifier = quarantine;
            break;
    }
    reset_fake_traffic(*fixture.state);
    kasumi::platform::perf_trace::reset();

    const auto collected = kasumi::application::integrity::garbage_collect(
        fixture.runtime, fixture.storage, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, expected_error);

    auto expected_objects = fixture.initial_objects;
    const bool copy_effect =
        failure == IntegratedFailure::CopyEffectThenError ||
        failure == IntegratedFailure::CorruptReadback;
    if (copy_effect) {
        expected_objects.emplace(quarantine,
                                 fixture.initial_objects.at(source));
    }
    EXPECT_EQ(fixture.state->objects, expected_objects);
    EXPECT_TRUE(fixture.state->objects.contains(source));
    EXPECT_EQ(fixture.state->objects.contains(quarantine), copy_effect);
    EXPECT_FALSE(fixture.state->objects.contains(quarantine + ".meta"));

    const bool source_hash_failed = failure == IntegratedFailure::SourceHash;
    const bool fallback_read_failed = failure == IntegratedFailure::FallbackGet;
    const bool fallback_put_failed = failure == IntegratedFailure::FallbackPut;
    const auto source_bytes = fixture.initial_objects.at(source).size();
    EXPECT_EQ(fixture.state->copy_count, source_hash_failed ? 0U : 1U);
    EXPECT_EQ(fixture.state->orphan_payload_get_count,
              fallback_read_failed || fallback_put_failed ? 1U : 0U);
    EXPECT_EQ(fixture.state->orphan_payload_get_bytes,
              fallback_put_failed ? source_bytes : 0U);
    if (fallback_read_failed) {
        EXPECT_TRUE(fixture.state->fail_get_identifier.empty());
    }
    if (fallback_put_failed) {
        EXPECT_TRUE(fixture.state->fail_put_identifier.empty());
    }
    EXPECT_EQ(fixture.state->quarantine_payload_put_count, 0U);
    EXPECT_EQ(fixture.state->quarantine_metadata_put_count, 0U);
    EXPECT_EQ(fixture.state->native_copy_bytes,
              copy_effect ? source_bytes : 0U);

    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "verified copy source physical hash"),
              1U);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("verified copy native copy"),
        source_hash_failed ? 0U : 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "verified copy native copy successes"),
              failure == IntegratedFailure::CorruptReadback ? 1U : 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "verified copy native copy verifications"),
              0U);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("gc candidate verified copy"),
        1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "gc candidate metadata publish"),
              0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "gc candidate pre-remove barrier verification"),
              0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc candidate remove"),
              0U);
}

TEST(IntegratedGcFixtureTest,
     NativeCopyPreservesExactInventoryAndAggregatesMetrics) {
    expect_integrated_copy_case(IntegratedCopyPath::Native, "native", 2);
}

TEST(IntegratedGcFixtureTest, UnsupportedSourceHashUsesVerifiedFallback) {
    expect_integrated_copy_case(IntegratedCopyPath::SourceHashUnsupported,
                                "source-hash-unsupported");
}

TEST(IntegratedGcFixtureTest, UnsupportedNativeCopyUsesVerifiedFallback) {
    expect_integrated_copy_case(IntegratedCopyPath::NativeCopyUnsupported,
                                "copy-unsupported");
}

TEST(IntegratedGcFixtureTest, UnsupportedDestinationHashUsesVerifiedReadback) {
    expect_integrated_copy_case(IntegratedCopyPath::DestinationHashUnsupported,
                                "destination-hash-unsupported");
}

TEST(IntegratedGcFixtureTest, SourceHashTransportFailurePreservesInventory) {
    expect_integrated_failure(IntegratedFailure::SourceHash,
                              "source-hash-failure",
                              IntegrityErrorCode::TransportFailure);
}

TEST(IntegratedGcFixtureTest, FallbackGetFailurePreservesInventory) {
    expect_integrated_failure(IntegratedFailure::FallbackGet,
                              "fallback-get-failure",
                              IntegrityErrorCode::TransportFailure);
}

TEST(IntegratedGcFixtureTest, FallbackPutFailurePreservesInventory) {
    expect_integrated_failure(IntegratedFailure::FallbackPut,
                              "fallback-put-failure",
                              IntegrityErrorCode::TransportFailure);
}

TEST(IntegratedGcFixtureTest,
     CopyEffectThenTransportErrorLeavesUnclaimedResidue) {
    expect_integrated_failure(IntegratedFailure::CopyEffectThenError,
                              "copy-effect-then-error",
                              IntegrityErrorCode::TransportFailure);
}

TEST(IntegratedGcFixtureTest, CorruptReadbackPreservesOriginalWithoutMetadata) {
    expect_integrated_failure(IntegratedFailure::CorruptReadback,
                              "corrupt-readback",
                              IntegrityErrorCode::IntegrityFailure);
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
    const std::vector<std::string> physical{kasumi::hash_hex(hash),
                                            "unexpected-🌸.object"};
    const auto inventory = kasumi::maintenance::analyze(tree, tree, physical);
    ASSERT_TRUE(inventory.has_value()) << inventory.error().detail;
    ASSERT_EQ(inventory->referenced_objects.size(), 1U);
    const auto& reference = inventory->referenced_objects.front();
    ASSERT_EQ(reference.referenced_paths.size(), 2U);
    EXPECT_EQ(reference.referenced_paths[0],
              kasumi::platform::path::from_utf8(first_path));
    EXPECT_EQ(reference.referenced_paths[1],
              kasumi::platform::path::from_utf8(second_path));
    ASSERT_TRUE(reference.local_source.has_value());
    EXPECT_EQ(*reference.local_source,
              kasumi::platform::path::from_utf8(first_path));
    EXPECT_TRUE(reference.physically_present);
    EXPECT_EQ(inventory->unknown_identifiers,
              (std::vector<std::string>{"unexpected-🌸.object"}));

    tree.rows.back().size = 8;
    kasumi::finalize_snapshot(tree);
    const auto conflict = kasumi::maintenance::analyze(tree, {}, physical);
    ASSERT_FALSE(conflict.has_value());
    EXPECT_EQ(conflict.error().code,
              kasumi::maintenance::ErrorCode::ConflictingReference);
    ASSERT_EQ(conflict.error().paths.size(), 2U);
    EXPECT_EQ(conflict.error().paths[0],
              kasumi::platform::path::from_utf8(first_path));
    EXPECT_EQ(conflict.error().paths[1],
              kasumi::platform::path::from_utf8(second_path));
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
        protocol::quarantine_identifier(test_layout(), orphan_content).value();
    const auto orphan_commit_quarantine =
        protocol::quarantine_identifier(test_layout(),
                                        object_path(orphan_published.head))
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
    expect_presence(
        storage.transport,
        protocol::quarantine_identifier(test_layout(), loose_content).value(),
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
                test_layout(), sealed->reference);
        ASSERT_TRUE(identifier.has_value()) << identifier.error().detail;
        ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
            storage.transport,
            test_key(),
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
     CopyVerifiedStagesWhenSourcePhysicalHashIsUnsupported) {
    auto workspace =
        kasumi::test::make_temp_workspace("copy-source-hash-unsupported");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto source = put_content(transport, workspace, "payload", "source");
    constexpr std::string_view destination = "copy/source-hash-fallback";
    state->copy_supported = true;
    state->get_count = 0;
    state->put_count = 0;
    state->copy_count = 0;

    const auto copied = protocol::copy_verified(
        transport,
        source,
        destination,
        kasumi::test::workspace_root(workspace));

    ASSERT_TRUE(copied.has_value()) << copied.error().detail;
    EXPECT_EQ(*copied, state->physical_hashes.at(source));
    EXPECT_EQ(state->copy_count, 0U);
    EXPECT_EQ(state->get_count, 2U);
    EXPECT_EQ(state->put_count, 1U);
    EXPECT_EQ(state->objects.at(source),
              state->objects.at(std::string{destination}));
}

TEST(IntegrityMaintenanceTest,
     CopyVerifiedReadsBackWhenDestinationPhysicalHashIsUnsupported) {
    struct TraceGuard {
        ~TraceGuard() { kasumi::platform::perf_trace::force_enable(false); }
    } trace_guard;
    kasumi::platform::perf_trace::force_enable(true);
    auto workspace =
        kasumi::test::make_temp_workspace("copy-destination-hash-unsupported");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const auto source = put_content(transport, workspace, "payload", "source");
    constexpr std::string_view destination = "copy/destination-hash-fallback";
    state->physical_hash_supported = true;
    state->physical_hash_unsupported_identifier = std::string{destination};
    state->copy_supported = true;
    state->get_count = 0;
    state->put_count = 0;
    state->copy_count = 0;
    kasumi::platform::perf_trace::reset();

    const auto copied = protocol::copy_verified(
        transport,
        source,
        destination,
        kasumi::test::workspace_root(workspace));

    ASSERT_TRUE(copied.has_value()) << copied.error().detail;
    EXPECT_EQ(*copied, state->physical_hashes.at(source));
    EXPECT_EQ(state->copy_count, 1U);
    EXPECT_EQ(state->get_count, 1U);
    EXPECT_EQ(state->put_count, 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "verified copy native copy"),
              1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "verified copy native copy successes"),
              1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "verified copy native copy verifications"),
              1U);
    EXPECT_EQ(state->objects.at(source),
              state->objects.at(std::string{destination}));
}

TEST(IntegrityMaintenanceTest,
     CopyVerifiedTraceSeparatesNativeAttemptSuccessAndVerification) {
    struct TraceGuard {
        ~TraceGuard() { kasumi::platform::perf_trace::force_enable(false); }
    } trace_guard;
    kasumi::platform::perf_trace::force_enable(true);

    const auto verify_case = [](std::string_view suffix,
                                bool copy_supported,
                                bool destination_mismatch) {
        auto workspace = kasumi::test::make_temp_workspace(
            "copy-trace-" + std::string{suffix});
        FakeState* state = nullptr;
        auto transport = make_fake_transport(state);
        ASSERT_TRUE(kasumi::transport::initialize(transport));
        state->physical_hash_supported = true;
        state->copy_supported = copy_supported;
        state->copy_destination_mismatch = destination_mismatch;
        const auto source = put_content(transport, workspace, "payload", suffix);
        const auto destination = "copy/trace/" + std::string{suffix};
        reset_fake_traffic(*state);
        kasumi::platform::perf_trace::reset();

        const auto copied = protocol::copy_verified(
            transport,
            source,
            destination,
            kasumi::test::workspace_root(workspace));

        if (destination_mismatch) {
            ASSERT_FALSE(copied.has_value());
            EXPECT_EQ(copied.error().code,
                      protocol::ErrorCode::VerificationFailure);
        } else {
            ASSERT_TRUE(copied.has_value()) << copied.error().detail;
        }
        EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                      "verified copy native copy"),
                  1U);
        EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                      "verified copy native copy successes"),
                  copy_supported ? 1U : 0U);
        EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                      "verified copy native copy verifications"),
                  copy_supported && !destination_mismatch ? 1U : 0U);
        EXPECT_EQ(state->get_count, copy_supported ? 0U : 1U);
        EXPECT_EQ(state->put_count, copy_supported ? 0U : 1U);
        EXPECT_TRUE(state->objects.contains(source));
    };

    verify_case("native-success", true, false);
    verify_case("unsupported-fallback", false, false);
    verify_case("destination-mismatch", true, true);
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
        protocol::quarantine_identifier(test_layout(), object_path(redundant))
            .value();

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
    const auto quarantined =
        protocol::quarantine_identifier(test_layout(), orphan).value();

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

TEST(IntegrityMaintenanceTest, QuarantineRetentionBoundaryUsesInclusiveAge) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);
    publish_remote(storage.transport,
                   storage.workspace,
                   kasumi::history::make_empty_bootstrap().value());
    const auto boundary =
        put_content(storage.transport, storage.workspace, "boundary", "boundary");
    const auto beyond =
        put_content(storage.transport, storage.workspace, "beyond", "beyond");
    const auto boundary_quarantine =
        protocol::quarantine_identifier(test_layout(), boundary).value();
    const auto beyond_quarantine =
        protocol::quarantine_identifier(test_layout(), beyond).value();
    ASSERT_TRUE(kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key()));

    const auto now = kasumi::platform::clock::unix_seconds();
    ASSERT_TRUE(now.has_value()) << now.error();
    ASSERT_TRUE(protocol::record_quarantine(
        storage.transport,
        boundary_quarantine,
        *now - protocol::quarantine_retention_seconds,
        test_key(),
        kasumi::test::workspace_root(storage.workspace)));
    ASSERT_TRUE(protocol::record_quarantine(
        storage.transport,
        beyond_quarantine,
        *now - protocol::quarantine_retention_seconds - 1,
        test_key(),
        kasumi::test::workspace_root(storage.workspace)));

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->purged_objects, 2U);
    expect_presence(storage.transport, boundary_quarantine, Presence::Absent);
    expect_presence(storage.transport, beyond_quarantine, Presence::Absent);
}

TEST(IntegrityMaintenanceTest,
     OriginalReappearancePreservesExpiredQuarantineCopy) {
    auto storage = make_local_storage();
    auto runtime = runtime_data(storage.workspace);
    publish_remote(storage.transport,
                   storage.workspace,
                   kasumi::history::make_empty_bootstrap().value());
    const auto orphan =
        put_content(storage.transport, storage.workspace, "orphan", "orphan");
    const auto quarantined =
        protocol::quarantine_identifier(test_layout(), orphan).value();
    ASSERT_TRUE(kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key()));

    const auto now = kasumi::platform::clock::unix_seconds();
    ASSERT_TRUE(now.has_value()) << now.error();
    ASSERT_TRUE(protocol::record_quarantine(
        storage.transport,
        quarantined,
        *now - protocol::quarantine_retention_seconds - 1,
        test_key(),
        kasumi::test::workspace_root(storage.workspace)));
    put_content(storage.transport, storage.workspace, "orphan", "orphan-again");

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->purged_objects, 0U);
    expect_presence(storage.transport, orphan, Presence::Absent);
    expect_presence(storage.transport, quarantined, Presence::Present);
    expect_presence(storage.transport, quarantined + ".meta", Presence::Present);
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
    state->reveal_on_list_count = state->list_count + 9;

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::ConcurrentChange);
    expect_presence(transport, orphan, Presence::Present);
    expect_presence(transport, concurrent_content, Presence::Present);
    expect_presence(
        transport,
        protocol::quarantine_identifier(test_layout(), orphan).value(),
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
        storage.transport,
        test_layout(),
        kasumi::test::workspace_root(storage.workspace));
    ASSERT_TRUE(writer.has_value()) << writer.error().detail;

    struct TraceGuard {
        ~TraceGuard() { kasumi::platform::perf_trace::force_enable(false); }
    } trace_guard;
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();
    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, storage.transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::ConcurrentChange);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "gc writer consistency checks"),
              1U);
    expect_presence(storage.transport, orphan, Presence::Present);
    expect_presence(
        storage.transport,
        protocol::quarantine_identifier(test_layout(), orphan).value(),
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

TEST(IntegrityMaintenanceTest, WriterAdmissionResumesAfterBarrierRelease) {
    auto storage = make_local_storage();
    const auto root = kasumi::test::workspace_root(storage.workspace);
    auto barrier = protocol::establish_barrier(storage.transport, root);
    ASSERT_TRUE(barrier.has_value()) << barrier.error().detail;

    const auto blocked = protocol::register_writer(storage.transport, root);
    ASSERT_FALSE(blocked.has_value());
    EXPECT_EQ(blocked.error().code, protocol::ErrorCode::Blocked);

    ASSERT_TRUE(protocol::release_registration(*barrier));
    auto writer = protocol::register_writer(storage.transport, root);
    ASSERT_TRUE(writer.has_value()) << writer.error().detail;
    ASSERT_TRUE(protocol::release_registration(*writer));
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
    expect_presence(
        transport,
        protocol::quarantine_identifier(test_layout(), orphan).value(),
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

TEST(IntegrityMaintenanceTest, CopyFailurePreservesTheOriginal) {
    auto workspace = kasumi::test::make_temp_workspace("gc-copy-failure");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);
    publish_remote(
        transport, workspace, kasumi::history::make_empty_bootstrap().value());
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");
    const auto quarantined =
        protocol::quarantine_identifier(test_layout(), orphan).value();
    state->physical_hash_supported = true;
    state->copy_supported = true;
    state->copy_failure = kasumi::transport::ErrorCode::Io;
    state->observed_payload_identifier = orphan;
    state->orphan_payload_get_count = 0;
    state->quarantine_payload_put_count = 0;
    state->copy_count = 0;

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::TransportFailure);
    expect_presence(transport, orphan, Presence::Present);
    expect_presence(transport, quarantined, Presence::Absent);
    expect_presence(transport, quarantined + ".meta", Presence::Absent);
    EXPECT_EQ(state->orphan_payload_get_count, 0U);
    EXPECT_EQ(state->quarantine_payload_put_count, 0U);
    EXPECT_EQ(state->copy_count, 1U);
}

TEST(IntegrityMaintenanceTest,
     DestinationCopyVerificationFailurePreservesTheOriginal) {
    auto workspace =
        kasumi::test::make_temp_workspace("gc-copy-verification-failure");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);
    publish_remote(
        transport, workspace, kasumi::history::make_empty_bootstrap().value());
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");
    const auto quarantined =
        protocol::quarantine_identifier(test_layout(), orphan).value();
    state->physical_hash_supported = true;
    state->copy_supported = true;
    state->copy_destination_mismatch = true;

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::IntegrityFailure);
    expect_presence(transport, orphan, Presence::Present);
    expect_presence(transport, quarantined, Presence::Present);
    expect_presence(transport, quarantined + ".meta", Presence::Absent);
    EXPECT_EQ(state->copy_count, 1U);
}

TEST(IntegrityMaintenanceTest,
     QuarantineMetadataFailurePreservesTheOriginal) {
    auto workspace = kasumi::test::make_temp_workspace("gc-metadata-failure");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);
    publish_remote(
        transport, workspace, kasumi::history::make_empty_bootstrap().value());
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");
    const auto quarantined =
        protocol::quarantine_identifier(test_layout(), orphan).value();
    state->physical_hash_supported = true;
    state->copy_supported = true;
    state->fail_quarantine_metadata_put = true;

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::TransportFailure);
    expect_presence(transport, orphan, Presence::Present);
    expect_presence(transport, quarantined, Presence::Present);
    expect_presence(transport, quarantined + ".meta", Presence::Absent);
    EXPECT_EQ(state->copy_count, 1U);
    EXPECT_EQ(state->orphan_payload_get_count, 0U);
    EXPECT_EQ(state->quarantine_payload_put_count, 0U);
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
    state->physical_hash_supported = true;
    state->copy_supported = true;
    state->replace_barrier_after_quarantine_put = true;

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::ConcurrentChange);
    expect_presence(transport, orphan, Presence::Present);
    expect_presence(
        transport,
        protocol::quarantine_identifier(test_layout(), orphan).value(),
        Presence::Present);
    EXPECT_EQ(state->copy_count, 1U);
    EXPECT_EQ(state->orphan_payload_get_count, 0U);
    EXPECT_EQ(state->quarantine_payload_put_count, 0U);
}

TEST(IntegrityMaintenanceTest,
     AmbiguousOriginalRemovalPreservesRecoveryEvidence) {
    auto workspace = kasumi::test::make_temp_workspace("gc-ambiguous-remove");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);
    publish_remote(
        transport, workspace, kasumi::history::make_empty_bootstrap().value());
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");
    const auto quarantined =
        protocol::quarantine_identifier(test_layout(), orphan).value();
    state->remove_then_fail_identifier = orphan;

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->quarantined_objects, 1U);
    expect_presence(transport, orphan, Presence::Absent);
    expect_presence(transport, quarantined, Presence::Present);
    expect_presence(transport, quarantined + ".meta", Presence::Present);
}

TEST(IntegrityMaintenanceTest,
     BarrierReleaseFailureDoesNotLoseQuarantineEvidence) {
    auto workspace = kasumi::test::make_temp_workspace("gc-barrier-release");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);
    publish_remote(
        transport, workspace, kasumi::history::make_empty_bootstrap().value());
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");
    const auto quarantined =
        protocol::quarantine_identifier(test_layout(), orphan).value();
    state->fail_remove_identifier = test_layout().barrier_identifier;

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::TransportFailure);
    expect_presence(transport, orphan, Presence::Absent);
    expect_presence(transport, quarantined, Presence::Present);
    expect_presence(transport, quarantined + ".meta", Presence::Present);
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
    expect_presence(
        storage.transport,
        protocol::quarantine_identifier(test_layout(), orphan).value(),
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
    const auto quarantined =
        protocol::quarantine_identifier(test_layout(), orphan).value();
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
    const auto quarantined =
        protocol::quarantine_identifier(test_layout(), orphan).value();
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
    const auto quarantined =
        protocol::quarantine_identifier(test_layout(), orphan).value();
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

TEST(IntegrityMaintenanceTest,
     StableGarbageCollectPerformsZeroContentPayloadGets) {
    auto workspace =
        kasumi::test::make_temp_workspace("gc-zero-content-payload-gets");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    auto runtime = runtime_data(workspace);

    const auto commit = make_commit(0, {}, "alpha.txt", "alpha").value();
    publish_remote(transport, workspace, commit);
    const auto alpha_content =
        put_content(transport, workspace, "alpha", "alpha");

    state->get_count = 0;
    state->commit_get_count = 0;
    state->marker_get_count = 0;
    state->disappear_on_get = alpha_content;

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 0U);
    EXPECT_EQ(collected->quarantined_objects, 0U);

    EXPECT_EQ(state->disappear_on_get, alpha_content);
    EXPECT_EQ(state->commit_get_count, 2U);
    EXPECT_EQ(state->marker_get_count, 2U);
    EXPECT_EQ(state->get_count, 7U);
}

TEST(IntegrityMaintenanceTest,
     GarbageCollectQuarantineAvoidsClientPayloadRoundTrip) {
    auto workspace =
        kasumi::test::make_temp_workspace("gc-quarantine-remote-copy-red");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    auto runtime = runtime_data(workspace);

    const auto reachable = make_commit(0, {}, "alpha.txt", "alpha").value();
    publish_remote(transport, workspace, reachable);
    put_content(transport, workspace, "alpha", "alpha");
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");
    const auto quarantined =
        protocol::quarantine_identifier(test_layout(), orphan).value();

    state->observed_payload_identifier = orphan;
    state->get_count = 0;
    state->put_count = 0;
    state->commit_get_count = 0;
    state->marker_get_count = 0;
    state->orphan_payload_get_count = 0;
    state->quarantine_payload_put_count = 0;
    state->quarantine_metadata_put_count = 0;
    state->physical_hash_count = 0;
    state->remove_count = 0;
    state->copy_count = 0;

    ASSERT_TRUE(state->physical_hash_supported);
    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 1U);
    EXPECT_EQ(collected->quarantined_objects, 1U);
    expect_presence(transport, orphan, Presence::Absent);
    expect_presence(transport, quarantined, Presence::Present);
    expect_presence(transport, quarantined + ".meta", Presence::Present);

    const auto counters = [&] {
        return "total GET=" + std::to_string(state->get_count) +
               ", orphan payload GET=" +
               std::to_string(state->orphan_payload_get_count) +
               ", total PUT=" + std::to_string(state->put_count) +
               ", quarantine payload PUT=" +
               std::to_string(state->quarantine_payload_put_count) +
               ", quarantine metadata PUT=" +
               std::to_string(state->quarantine_metadata_put_count) +
               ", physical_hash=" +
               std::to_string(state->physical_hash_count) +
               ", remove=" + std::to_string(state->remove_count) +
               ", copy=" + std::to_string(state->copy_count);
    };
    EXPECT_EQ(state->quarantine_metadata_put_count, 1U);
    EXPECT_EQ(state->copy_count, 1U);
    EXPECT_EQ(state->orphan_payload_get_count, 0U) << counters();
    EXPECT_EQ(state->quarantine_payload_put_count, 0U) << counters();
}

TEST(IntegrityMaintenanceTest,
     FailedOrphanPayloadGetDoesNotCountDownloadedBytes) {
    auto workspace =
        kasumi::test::make_temp_workspace("gc-failed-payload-get-bytes");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    constexpr std::string_view identifier = "content/orphan-payload";
    state->objects[std::string{identifier}] = {1, 2, 3, 4};
    state->observed_payload_identifier = identifier;
    state->fail_content_get = true;

    const auto result = kasumi::transport::get(
        transport,
        identifier,
        kasumi::test::workspace_root(workspace) / "orphan-payload.bin");

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(state->orphan_payload_get_count, 1U);
    EXPECT_EQ(state->orphan_payload_get_bytes, 0U);
}

TEST(IntegrityMaintenanceTest,
     GarbageCollectQuarantineFallsBackWhenNativeCopyUnsupported) {
    auto workspace =
        kasumi::test::make_temp_workspace("gc-quarantine-copy-fallback");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    auto runtime = runtime_data(workspace);

    const auto reachable = make_commit(0, {}, "alpha.txt", "alpha").value();
    publish_remote(transport, workspace, reachable);
    put_content(transport, workspace, "alpha", "alpha");
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");
    const auto quarantined =
        protocol::quarantine_identifier(test_layout(), orphan).value();

    state->observed_payload_identifier = orphan;
    state->get_count = 0;
    state->put_count = 0;
    state->orphan_payload_get_count = 0;
    state->quarantine_payload_put_count = 0;
    state->copy_count = 0;

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 1U);
    EXPECT_EQ(collected->quarantined_objects, 1U);
    expect_presence(transport, orphan, Presence::Absent);
    expect_presence(transport, quarantined, Presence::Present);
    EXPECT_EQ(state->orphan_payload_get_count, 1U);
    EXPECT_EQ(state->quarantine_payload_put_count, 1U);
    EXPECT_EQ(state->copy_count, 1U);
}

TEST(IntegrityMaintenanceTest, FinalListingDetectsLateConcurrentChange) {
    auto workspace =
        kasumi::test::make_temp_workspace("gc-final-list-concurrent");
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
    state->reveal_on_list_count = state->list_count + 9;

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::ConcurrentChange);
    expect_presence(transport, orphan, Presence::Present);
    expect_presence(transport, concurrent_content, Presence::Present);
}

TEST(IntegrityMaintenanceTest,
     DirectedQuarantineRestorationRestoresReachableWithoutPayloadGets) {
    auto workspace =
        kasumi::test::make_temp_workspace("gc-directed-quarantine-restore");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    auto runtime = runtime_data(workspace);

    const auto alpha = make_commit(0, {}, "alpha.txt", "alpha").value();
    publish_remote(transport, workspace, alpha);
    put_content(transport, workspace, "alpha", "alpha");

    const auto orphan = make_commit(0, {}, "old.txt", "old").value();
    const auto orphan_published = publish_remote(transport, workspace, orphan);
    ASSERT_EQ(
        kasumi::transport::remove(transport, marker_path(orphan_published.head))
            .value(),
        kasumi::transport::Removal::Removed);
    const auto orphan_content = put_content(transport, workspace, "old", "old");
    const auto orphan_content_quarantine =
        protocol::quarantine_identifier(test_layout(), orphan_content).value();
    const auto orphan_commit_quarantine =
        protocol::quarantine_identifier(test_layout(),
                                        object_path(orphan_published.head))
            .value();

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->quarantined_objects, 2U);

    ASSERT_TRUE(
        protocol::record_quarantine(transport,
                                    orphan_content_quarantine,
                                    0,
                                    test_key(),
                                    kasumi::test::workspace_root(workspace)));
    ASSERT_TRUE(
        protocol::record_quarantine(transport,
                                    orphan_commit_quarantine,
                                    0,
                                    test_key(),
                                    kasumi::test::workspace_root(workspace)));

    const auto marker = kasumi::application::history_storage::encode_marker(
                            orphan_published.head)
                            .value();
    const auto marker_file =
        kasumi::test::workspace_path(workspace, "restored.head");
    kasumi::test::write_binary(marker_file, std::as_bytes(std::span{marker}));
    ASSERT_TRUE(kasumi::transport::put(
        transport, marker_file, marker_path(orphan_published.head)));

    state->disappear_on_get = orphan_content;
    state->observed_payload_identifier = orphan_content_quarantine;
    state->orphan_payload_get_count = 0;
    state->quarantine_payload_put_count = 0;
    state->copy_count = 0;

    const auto restored = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(restored.has_value()) << restored.error().detail;
    EXPECT_EQ(restored->restored_objects, 2U);
    EXPECT_EQ(state->disappear_on_get, orphan_content);
    expect_presence(transport, orphan_content, Presence::Present);
    expect_presence(
        transport, object_path(orphan_published.head), Presence::Present);
    EXPECT_EQ(state->copy_count, 2U);
    EXPECT_EQ(state->orphan_payload_get_count, 0U);
    EXPECT_EQ(state->quarantine_payload_put_count, 0U);
}

TEST(IntegrityMaintenanceTest, GarbageCollectionBatchBaselineScale) {
    struct TraceGuard {
        ~TraceGuard() { kasumi::platform::perf_trace::force_enable(false); }
    } trace_guard;

    kasumi::platform::perf_trace::force_enable(true);
    std::cout << "GC_MEASUREMENT_COLUMNS n,total_us,barrier_acquire_us,"
                 "writer_checks_us,probe_us,quarantine_inventory_us,"
                 "restore_us,prior_metadata_us,reachability_1_us,"
                 "reachability_2_us,stable_compare_us,"
                 "final_namespace_verify_us,"
                 "purge_us,candidate_pre_copy_barrier_us,candidate_copy_us,"
                 "candidate_source_hash_us,native_copy_us,"
                 "candidate_destination_hash_us,"
                 "candidate_metadata_us,put_verification_us,"
                 "candidate_pre_remove_barrier_us,"
                 "candidate_remove_us,barrier_release_us,get,orphan_get,"
                 "orphan_get_bytes,put,quarantine_payload_put,"
                 "quarantine_payload_put_bytes,metadata_put,full_list,"
                 "full_list_identifiers,prefix_list,presence,physical_hash,"
                 "physical_hash_batch,"
                 "put_batch,control_read_batch,copy_attempts,copy_successes,"
                 "copy_verifications,native_copy_bytes,"
                 "remove,barrier_verification,writer_hash_verification_calls,"
                 "candidates,quarantined,"
                 "restored,purged,analysis_only\n";

    const auto trace_us = [](std::string_view name) {
        return kasumi::platform::perf_trace::get_time(name);
    };
    for (const std::size_t orphan_count : {0U, 1U, 10U, 100U}) {
        auto workspace =
            kasumi::test::make_temp_workspace("gc-batch-baseline");
        FakeState* state = nullptr;
        auto transport = make_fake_transport(state);
        ASSERT_TRUE(kasumi::transport::initialize(transport));
        state->physical_hash_supported = true;
        state->copy_supported = true;
        auto runtime = runtime_data(workspace);

        const auto retained =
            make_commit(0, {}, "retained.txt", "retained").value();
        const auto published = publish_remote(transport, workspace, retained);
        const auto retained_content =
            put_content(transport, workspace, "retained", "retained");

        std::vector<std::pair<std::string, std::vector<std::uint8_t>>> orphans;
        orphans.reserve(orphan_count);
        std::set<std::string> unique_orphan_identifiers;
        std::set<std::vector<std::uint8_t>> unique_orphan_ciphertexts;
        std::size_t orphan_bytes = 0;
        for (std::size_t index = 0; index < orphan_count; ++index) {
            const auto suffix = "orphan-" + std::to_string(index);
            const auto identifier =
                put_content(transport, workspace, suffix, suffix);
            state->observed_payload_identifiers.insert(identifier);
            const auto& ciphertext = state->objects.at(identifier);
            EXPECT_TRUE(unique_orphan_identifiers.insert(identifier).second);
            EXPECT_TRUE(unique_orphan_ciphertexts.insert(ciphertext).second);
            orphans.emplace_back(identifier, ciphertext);
            orphan_bytes += state->objects.at(identifier).size();
        }
        const auto layout = test_layout();
        EXPECT_TRUE(std::ranges::none_of(state->objects, [&](const auto& item) {
            return protocol::is_epoch_object(layout, item.first);
        }));

        reset_fake_traffic(*state);
        kasumi::platform::perf_trace::reset();
        const auto started = std::chrono::steady_clock::now();
        const auto collected = kasumi::application::integrity::garbage_collect(
            runtime, transport, test_key());
        const auto total_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - started)
                .count());
        ASSERT_TRUE(collected.has_value()) << collected.error().detail;

        EXPECT_FALSE(collected->analysis_only);
        EXPECT_EQ(collected->candidate_objects, orphan_count);
        EXPECT_EQ(collected->quarantined_objects, orphan_count);
        EXPECT_EQ(collected->restored_objects, 0U);
        EXPECT_EQ(collected->purged_objects, 0U);
        EXPECT_EQ(state->get_count, 7U + 2U * orphan_count);
        EXPECT_EQ(state->orphan_payload_get_count, 0U);
        EXPECT_EQ(state->orphan_payload_get_bytes, 0U);
        EXPECT_EQ(state->put_count, 2U + orphan_count);
        EXPECT_EQ(state->quarantine_payload_put_count, 0U);
        EXPECT_EQ(state->quarantine_payload_put_bytes, 0U);
        EXPECT_EQ(state->quarantine_metadata_put_count, orphan_count);
        EXPECT_EQ(state->full_list_count, 4U);
        EXPECT_EQ(state->full_list_identifier_count,
                  4U * (orphan_count + 4U));
        EXPECT_EQ(state->prefix_list_count, 6U);
        EXPECT_EQ(state->presence_count, 0U);
        EXPECT_EQ(state->physical_hash_count, 2U + 3U * orphan_count);
        EXPECT_EQ(state->physical_hash_batch_count, 0U);
        EXPECT_EQ(state->put_batch_count, 0U);
        EXPECT_EQ(state->control_read_batch_count, 0U);
        EXPECT_EQ(state->copy_count, orphan_count);
        EXPECT_EQ(state->native_copy_bytes, orphan_bytes);
        EXPECT_EQ(state->remove_count, 2U + orphan_count);
        EXPECT_EQ(state->barrier_verification_count,
                  3U + 2U * orphan_count);
        EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                      "writer physical hash calls"),
                  2U + orphan_count);
        EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                      "writer verification"),
                  2U + orphan_count);
        EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                      "verified copy source physical hash"),
                  orphan_count);
        EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                      "verified copy native copy"),
                  orphan_count);
        EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                      "verified copy native copy successes"),
                  orphan_count);
        EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                      "verified copy native copy verifications"),
                  orphan_count);
        EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                      "verified copy destination physical hash"),
                  orphan_count);

        std::cout << "GC_MEASUREMENT " << orphan_count << ',' << total_us << ','
                  << trace_us("gc barrier acquire") << ','
                  << trace_us("gc writer consistency checks") << ','
                  << trace_us("gc backend consistency probe") << ','
                  << trace_us("gc quarantine inventory") << ','
                  << trace_us("gc quarantine restoration") << ','
                  << trace_us("gc prior metadata initialization") << ','
                  << trace_us("gc reachability observation 1") << ','
                  << trace_us("gc reachability observation 2") << ','
                  << trace_us("gc stable-state comparison") << ','
                  << trace_us("gc final namespace verification") << ','
                  << trace_us("gc expired quarantine purge") << ','
                  << trace_us("gc candidate pre-copy barrier verification")
                  << ',' << trace_us("gc candidate verified copy") << ','
                  << trace_us("verified copy source physical hash") << ','
                  << trace_us("verified copy native copy") << ','
                  << trace_us("verified copy destination physical hash")
                  << ','
                  << trace_us("gc candidate metadata publish") << ','
                  << trace_us("writer verification") << ','
                  << trace_us("gc candidate pre-remove barrier verification")
                  << ',' << trace_us("gc candidate remove") << ','
                  << trace_us("gc barrier release") << ',' << state->get_count
                  << ',' << state->orphan_payload_get_count << ','
                  << state->orphan_payload_get_bytes << ',' << state->put_count
                  << ','
                  << state->quarantine_payload_put_count << ','
                  << state->quarantine_payload_put_bytes << ','
                  << state->quarantine_metadata_put_count << ','
                  << state->full_list_count << ','
                  << state->full_list_identifier_count << ','
                  << state->prefix_list_count
                  << ',' << state->presence_count << ','
                  << state->physical_hash_count << ','
                  << state->physical_hash_batch_count << ','
                  << state->put_batch_count << ','
                  << state->control_read_batch_count << ','
                  << kasumi::platform::perf_trace::get_count(
                         "verified copy native copy")
                  << ','
                  << kasumi::platform::perf_trace::get_count(
                         "verified copy native copy successes")
                  << ','
                  << kasumi::platform::perf_trace::get_count(
                         "verified copy native copy verifications")
                  << ',' << state->native_copy_bytes << ','
                  << state->remove_count << ','
                  << state->barrier_verification_count << ','
                  << kasumi::platform::perf_trace::get_count(
                         "writer physical hash calls")
                  << ','
                  << collected->candidate_objects << ','
                  << collected->quarantined_objects << ','
                  << collected->restored_objects << ','
                  << collected->purged_objects << ','
                  << collected->analysis_only << '\n';

        EXPECT_TRUE(state->objects.contains(retained_content));
        EXPECT_TRUE(state->objects.contains(object_path(published.head)));
        EXPECT_TRUE(state->objects.contains(marker_path(published.head)));
        for (const auto& [identifier, bytes] : orphans) {
            const auto quarantine =
                protocol::quarantine_identifier(test_layout(), identifier);
            ASSERT_TRUE(quarantine.has_value());
            EXPECT_FALSE(state->objects.contains(identifier));
            const auto quarantined = state->objects.find(*quarantine);
            ASSERT_NE(quarantined, state->objects.end());
            EXPECT_EQ(quarantined->second, bytes);
        }

        const auto inventory = protocol::inventory_quarantine(
            transport, test_key(), kasumi::test::workspace_root(workspace));
        ASSERT_TRUE(inventory.has_value());
        EXPECT_EQ(inventory->size(), orphan_count);
        for (const auto& entry : *inventory) {
            EXPECT_FALSE(protocol::is_epoch_object(
                test_layout(), entry.original_identifier));
            const auto verified = protocol::verify_quarantine(
                transport, entry, kasumi::test::workspace_root(workspace));
            ASSERT_TRUE(verified.has_value());
            EXPECT_TRUE(*verified);
        }
    }
    kasumi::platform::perf_trace::force_enable(false);
}

namespace {
kasumi::transport::Result
fake_reachability_get_batch(void* context,
                            const kasumi::transport::GetBatch& batch) {
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

// ============================================================================
// Phase 10: Batch Garbage Collection Tests (Scenarios A through K)
// ============================================================================

TEST(IntegrityMaintenanceTest, GarbageCollectionBatchMeasurementScale) {
    constexpr std::size_t batch_capacity = 8;
    constexpr std::size_t min_batch_threshold = 6;
    for (const std::size_t count : {0U, 1U, 10U, 100U}) {
        auto workspace =
            kasumi::test::make_temp_workspace("gc-batch-measure-" + std::to_string(count));
        FakeState* state = nullptr;
        auto transport = make_fake_transport(state);
        ASSERT_TRUE(kasumi::transport::initialize(transport));
        state->physical_hash_supported = true;
        state->copy_supported = true;
        enable_fake_physical_hash_batch(transport, *state, min_batch_threshold);
        auto runtime = runtime_data(workspace);

        const auto retained =
            make_commit(0, {}, "retained.txt", "retained").value();
        publish_remote(transport, workspace, retained);
        put_content(transport, workspace, "retained", "retained");

        for (std::size_t i = 0; i < count; ++i) {
            const auto suffix = "orphan-" + std::to_string(i);
            put_content(transport, workspace, suffix, suffix);
        }

        reset_fake_traffic(*state);
        kasumi::platform::perf_trace::force_enable(true);
        kasumi::platform::perf_trace::reset();
        const auto collected = kasumi::application::integrity::garbage_collect(
            runtime, transport, test_key());
        const auto source_hash_indiv =
            kasumi::platform::perf_trace::get_count("verified copy source physical hash");
        const auto dest_hash_indiv =
            kasumi::platform::perf_trace::get_count("verified copy destination physical hash");
        const auto candidates_verified =
            kasumi::platform::perf_trace::get_count("gc.candidates_verified");
        kasumi::platform::perf_trace::force_enable(false);
        ASSERT_TRUE(collected.has_value()) << collected.error().detail;
        EXPECT_EQ(collected->candidate_objects, count);
        EXPECT_EQ(collected->quarantined_objects, count);
        const std::size_t batches =
            count == 0 ? 0 : (count + batch_capacity - 1) / batch_capacity;
        const std::size_t expected_batch_calls =
            count == 0 ? 0 :
            count == 1 ? 0 :
            count == 10 ? 1 : 12;
        EXPECT_EQ(state->physical_hash_batch_count, expected_batch_calls);
        EXPECT_EQ(state->copy_count, count);
        EXPECT_EQ(state->orphan_payload_get_count, 0U);
        EXPECT_EQ(state->quarantine_payload_put_count, 0U);

        std::cout << "PHASE10_BATCH_SCALE N=" << count
                  << " batches=" << batches
                  << " copy_count=" << state->copy_count
                  << " physical_hash_batch_count=" << state->physical_hash_batch_count
                  << " source_hash_indiv=" << source_hash_indiv
                  << " dest_hash_indiv=" << dest_hash_indiv
                  << " get_payload=" << state->orphan_payload_get_count
                  << " put_payload=" << state->quarantine_payload_put_count
                  << " put_metadata=" << state->quarantine_metadata_put_count
                  << " remove=" << state->remove_count
                  << " verified=" << candidates_verified
                  << " quarantined=" << collected->quarantined_objects
                  << std::endl;
    }
}

TEST(IntegrityMaintenanceTest, BatchGcScenarioAZeroCandidates) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-a-zero");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");

    reset_fake_traffic(*state);
    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 0U);
    EXPECT_EQ(collected->quarantined_objects, 0U);
    EXPECT_EQ(collected->restored_objects, 0U);
    EXPECT_EQ(collected->purged_objects, 0U);
    EXPECT_EQ(state->physical_hash_batch_count, 0U);
    EXPECT_EQ(state->copy_count, 0U);
    EXPECT_EQ(state->quarantine_metadata_put_count, 0U);
    EXPECT_EQ(state->remove_count, 2U);
}

TEST(IntegrityMaintenanceTest, BatchGcScenarioBOneCandidate) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-b-one");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");

    reset_fake_traffic(*state);
    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 1U);
    EXPECT_EQ(collected->quarantined_objects, 1U);
    EXPECT_EQ(state->physical_hash_batch_count, 0U);
    EXPECT_EQ(state->copy_count, 1U);
    expect_presence(transport, orphan, Presence::Absent);
    const auto q_id = protocol::quarantine_identifier(test_layout(), orphan);
    ASSERT_TRUE(q_id.has_value());
    expect_presence(transport, *q_id, Presence::Present);
}

TEST(IntegrityMaintenanceTest, BatchGcScenarioCTenCandidatesBoundedBatches) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-c-ten");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 6);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    const auto published = publish_remote(transport, workspace, retained);
    const auto live_content = put_content(transport, workspace, "live", "live-content");

    std::vector<std::string> orphans;
    for (std::size_t i = 0; i < 10; ++i) {
        const auto suffix = "orphan-" + std::to_string(i);
        orphans.push_back(put_content(transport, workspace, suffix, suffix));
    }

    reset_fake_traffic(*state);
    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 10U);
    EXPECT_EQ(collected->quarantined_objects, 10U);
    EXPECT_EQ(state->physical_hash_batch_count, 1U);
    expect_presence(transport, live_content, Presence::Present);
    expect_presence(transport, object_path(published.head), Presence::Present);
    expect_presence(transport, marker_path(published.head), Presence::Present);
    for (const auto& orphan : orphans) {
        expect_presence(transport, orphan, Presence::Absent);
        const auto q_id = protocol::quarantine_identifier(test_layout(), orphan);
        ASSERT_TRUE(q_id.has_value());
        expect_presence(transport, *q_id, Presence::Present);
        expect_presence(transport, *q_id + ".meta", Presence::Present);

        const auto copy_event = std::ranges::find(
            state->gc_events, "copy:" + orphan + "|" + *q_id);
        auto verify_event = std::ranges::find_if(
            state->gc_events, [&](const auto& event) {
                return event.starts_with("batch|") &&
                       event.find(*q_id) != std::string::npos;
            });
        if (verify_event == state->gc_events.end()) {
            verify_event = std::ranges::find(
                state->gc_events, "verify:" + *q_id);
        }
        const auto metadata_event = std::ranges::find(
            state->gc_events, "metadata:" + *q_id + ".meta");
        const auto remove_event = std::ranges::find(
            state->gc_events, "remove:" + orphan);
        ASSERT_NE(copy_event, state->gc_events.end());
        ASSERT_NE(verify_event, state->gc_events.end());
        ASSERT_NE(metadata_event, state->gc_events.end());
        ASSERT_NE(remove_event, state->gc_events.end());
        EXPECT_LT(std::distance(state->gc_events.begin(), copy_event),
                  std::distance(state->gc_events.begin(), verify_event));
        EXPECT_LT(std::distance(state->gc_events.begin(), verify_event),
                  std::distance(state->gc_events.begin(), metadata_event));
        EXPECT_LT(std::distance(state->gc_events.begin(), metadata_event),
                  std::distance(state->gc_events.begin(), remove_event));
    }
    EXPECT_EQ(state->quarantine_metadata_put_count, 10U);
}

TEST(IntegrityMaintenanceTest, BatchGcScenarioDOneHundredCandidatesScale) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-d-hundred");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");

    std::vector<std::string> orphans;
    for (std::size_t i = 0; i < 100; ++i) {
        const auto suffix = "orphan-" + std::to_string(i);
        orphans.push_back(put_content(transport, workspace, suffix, suffix));
    }

    reset_fake_traffic(*state);
    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 100U);
    EXPECT_EQ(collected->quarantined_objects, 100U);
    EXPECT_EQ(state->physical_hash_batch_count, 13U);
    for (const auto& orphan : orphans) {
        expect_presence(transport, orphan, Presence::Absent);
    }
}

TEST(IntegrityMaintenanceTest, BatchGcScenarioEBatchSupportedReducesCalls) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-e-reduction");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");

    for (std::size_t i = 0; i < 10; ++i) {
        const auto suffix = "orphan-" + std::to_string(i);
        put_content(transport, workspace, suffix, suffix);
    }

    reset_fake_traffic(*state);
    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(state->physical_hash_batch_count, 2U);
    EXPECT_EQ(state->physical_hash_count, 22U);
}

TEST(IntegrityMaintenanceTest, BatchGcScenarioFBatchUnsupportedFallback) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-f-fallback");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    state->physical_hash_batch_supported = false;
    transport.storage.physical_hash_batch_min_objects = 2;
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");

    std::vector<std::string> orphans;
    for (std::size_t i = 0; i < 10; ++i) {
        const auto suffix = "orphan-" + std::to_string(i);
        orphans.push_back(put_content(transport, workspace, suffix, suffix));
    }

    reset_fake_traffic(*state);
    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 10U);
    EXPECT_EQ(collected->quarantined_objects, 10U);
    for (const auto& orphan : orphans) {
        expect_presence(transport, orphan, Presence::Absent);
    }
}

TEST(IntegrityMaintenanceTest, BatchGcScenarioGBatchPartialCorruptedResult) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-g-corrupted");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");

    std::vector<std::string> orphans;
    for (std::size_t i = 0; i < 3; ++i) {
        const auto suffix = "orphan-" + std::to_string(i);
        orphans.push_back(put_content(transport, workspace, suffix, suffix));
    }

    const auto q1 = protocol::quarantine_identifier(test_layout(), orphans[1]);
    ASSERT_TRUE(q1.has_value());
    state->physical_hash_batch_mismatches.insert(*q1);

    reset_fake_traffic(*state);
    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());

    expect_presence(transport, orphans[1], Presence::Present);
}

TEST(IntegrityMaintenanceTest, BatchGcScenarioHIntermediateCandidateFailure) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-h-interm");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");

    std::vector<std::string> orphans;
    for (std::size_t i = 0; i < 3; ++i) {
        const auto suffix = "orphan-" + std::to_string(i);
        orphans.push_back(put_content(transport, workspace, suffix, suffix));
    }
    std::ranges::sort(orphans);

    state->physical_hash_mismatch_identifier =
        *protocol::quarantine_identifier(test_layout(), orphans[1]);

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    // Candidate 0 was completed before failure
    expect_presence(transport, orphans[0], Presence::Absent);
    // Candidate 1 failed verification: must NOT be removed
    expect_presence(transport, orphans[1], Presence::Present);
    // Candidate 2 was not processed: must remain intact
    expect_presence(transport, orphans[2], Presence::Present);
}

TEST(IntegrityMaintenanceTest, BatchGcScenarioIBarrierLossBeforeRemoval) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-i-barrier");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");

    state->replace_barrier_after_quarantine_put = true;

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    expect_presence(transport, orphan, Presence::Present);
}

TEST(IntegrityMaintenanceTest, BatchGcScenarioJInterruptionRecovery) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-j-interrupt");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");

    state->fail_quarantine_metadata_put = true;
    const auto run1 = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(run1.has_value());
    expect_presence(transport, orphan, Presence::Present);

    state->fail_quarantine_metadata_put = false;
    const auto run2 = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(run2.has_value()) << run2.error().detail;
    expect_presence(transport, orphan, Presence::Absent);
}

TEST(IntegrityMaintenanceTest, BatchGcScenarioKConcurrentChangeBetweenObservations) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-k-concurrent");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    const auto published = publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");

    const auto concurrent =
        make_commit(1, {published.head.commit_id}, "extra.txt", "extra").value();
    const auto concurrent_published =
        publish_remote(transport, workspace, concurrent);
    const auto concurrent_content =
        put_content(transport, workspace, "extra", "extra");

    const auto hide = [&](const std::string& identifier) {
        auto node = state->objects.extract(identifier);
        ASSERT_FALSE(node.empty());
        state->hidden_objects.insert(std::move(node));
    };
    hide(object_path(concurrent_published.head));
    hide(marker_path(concurrent_published.head));
    hide(concurrent_content);
    state->reveal_on_list_count = state->list_count + 9;

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::ConcurrentChange);
    expect_presence(transport, orphan, Presence::Present);
    EXPECT_EQ(state->copy_count, 0U);
}

TEST(IntegrityMaintenanceTest, BatchGcScenarioLRejectsEmptyBatchReport) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-l-empty");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");

    const auto orphan0 = put_content(transport, workspace, "orphan0", "orphan0");
    const auto orphan1 = put_content(transport, workspace, "orphan1", "orphan1");

    state->physical_hash_batch_override_report =
        kasumi::transport::PhysicalHashBatchReport{};

    reset_fake_traffic(*state);
    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::TransportFailure);
    expect_presence(transport, orphan0, Presence::Present);
    expect_presence(transport, orphan1, Presence::Present);
}

TEST(IntegrityMaintenanceTest, BatchGcScenarioMRejectsOmittedCandidateFromBatchReport) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-m-omitted");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");

    const auto orphan0 = put_content(transport, workspace, "orphan0", "orphan0");
    const auto orphan1 = put_content(transport, workspace, "orphan1", "orphan1");

    const auto q1 = protocol::quarantine_identifier(test_layout(), orphan1);
    ASSERT_TRUE(q1.has_value());
    state->physical_hash_batch_omitted.insert(*q1);

    reset_fake_traffic(*state);
    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::TransportFailure);
    expect_presence(transport, orphan1, Presence::Present);
}

TEST(IntegrityMaintenanceTest, BatchGcScenarioNRejectsUnexpectedIdentifierInBatchReport) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-n-unexpected");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");

    const auto orphan0 = put_content(transport, workspace, "orphan0", "orphan0");
    const auto orphan1 = put_content(transport, workspace, "orphan1", "orphan1");

    const auto q0 = *protocol::quarantine_identifier(test_layout(), orphan0);
    const auto q1 = *protocol::quarantine_identifier(test_layout(), orphan1);

    state->physical_hash_batch_override_report =
        kasumi::transport::PhysicalHashBatchReport{
            .matched = {q0, q1, "foreign_unrequested_object"},
            .mismatched = {},
            .missing = {},
            .errors = {},
        };

    reset_fake_traffic(*state);
    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::TransportFailure);
    expect_presence(transport, orphan0, Presence::Present);
    expect_presence(transport, orphan1, Presence::Present);
}

TEST(IntegrityMaintenanceTest, BatchGcScenarioORejectsCrossCategoryDuplicateInBatchReport) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-o-crossdup");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");

    const auto orphan0 = put_content(transport, workspace, "orphan0", "orphan0");
    const auto orphan1 = put_content(transport, workspace, "orphan1", "orphan1");

    const auto q0 = *protocol::quarantine_identifier(test_layout(), orphan0);
    const auto q1 = *protocol::quarantine_identifier(test_layout(), orphan1);

    state->physical_hash_batch_override_report =
        kasumi::transport::PhysicalHashBatchReport{
            .matched = {q0, q1},
            .mismatched = {},
            .missing = {q0},
            .errors = {},
        };

    reset_fake_traffic(*state);
    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::TransportFailure);
    expect_presence(transport, orphan0, Presence::Present);
    expect_presence(transport, orphan1, Presence::Present);
}

TEST(IntegrityMaintenanceTest, BatchGcScenarioPRejectsContradictoryMatchedAndMismatched) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-p-contra");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");

    const auto orphan0 = put_content(transport, workspace, "orphan0", "orphan0");
    const auto orphan1 = put_content(transport, workspace, "orphan1", "orphan1");

    const auto q0 = *protocol::quarantine_identifier(test_layout(), orphan0);
    const auto q1 = *protocol::quarantine_identifier(test_layout(), orphan1);

    state->physical_hash_batch_override_report =
        kasumi::transport::PhysicalHashBatchReport{
            .matched = {q0, q1},
            .mismatched = {q0},
            .missing = {},
            .errors = {},
        };

    reset_fake_traffic(*state);
    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::TransportFailure);
    expect_presence(transport, orphan0, Presence::Present);
    expect_presence(transport, orphan1, Presence::Present);
}

TEST(IntegrityMaintenanceTest, BatchGcScenarioQDestinationMissingFailsSafely) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-q-missing");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");

    const auto orphan0 = put_content(transport, workspace, "orphan0", "orphan0");
    const auto orphan1 = put_content(transport, workspace, "orphan1", "orphan1");

    const auto q1 = *protocol::quarantine_identifier(test_layout(), orphan1);
    state->physical_hash_batch_missing.insert(q1);

    reset_fake_traffic(*state);
    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    expect_presence(transport, orphan1, Presence::Present);
}

TEST(IntegrityMaintenanceTest, BatchGcScenarioRIndividualErrorFailsSafely) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-r-error");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");

    const auto orphan0 = put_content(transport, workspace, "orphan0", "orphan0");
    const auto orphan1 = put_content(transport, workspace, "orphan1", "orphan1");

    const auto q1 = *protocol::quarantine_identifier(test_layout(), orphan1);
    state->physical_hash_batch_errors.insert(q1);

    reset_fake_traffic(*state);
    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    expect_presence(transport, orphan1, Presence::Present);
}

TEST(IntegrityMaintenanceTest, BatchGcScenarioSGlobalBatchFailureAbortsFailClosed) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-s-failure");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");

    const auto orphan0 = put_content(transport, workspace, "orphan0", "orphan0");
    const auto orphan1 = put_content(transport, workspace, "orphan1", "orphan1");

    state->physical_hash_batch_failure = kasumi::transport::ErrorCode::BackendUnavailable;

    reset_fake_traffic(*state);
    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    expect_presence(transport, orphan0, Presence::Present);
    expect_presence(transport, orphan1, Presence::Present);
}

TEST(IntegrityMaintenanceTest, BatchGcScenarioTPositiveVerificationConfirmsAllAndQuarantines) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-t-positive");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");

    const auto orphan0 = put_content(transport, workspace, "orphan0", "orphan0");
    const auto orphan1 = put_content(transport, workspace, "orphan1", "orphan1");

    reset_fake_traffic(*state);
    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 2U);
    EXPECT_EQ(collected->quarantined_objects, 2U);
    EXPECT_EQ(state->physical_hash_batch_count, 1U);
    expect_presence(transport, orphan0, Presence::Absent);
    expect_presence(transport, orphan1, Presence::Absent);

    const auto q0 = *protocol::quarantine_identifier(test_layout(), orphan0);
    const auto q1 = *protocol::quarantine_identifier(test_layout(), orphan1);
    expect_presence(transport, q0, Presence::Present);
    expect_presence(transport, q1, Presence::Present);
}

TEST(IntegrityMaintenanceTest, BatchGcSmallTailStillUsesNativeCopyWithoutBatchVerification) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-small-tail-native-copy");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 6);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");

    std::vector<std::string> orphans;
    for (int i = 0; i < 3; ++i) {
        const auto name = "orphan-" + std::to_string(i);
        orphans.push_back(put_content(transport, workspace, name, name + "-content"));
    }

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();
    reset_fake_traffic(*state);

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 3U);
    EXPECT_EQ(collected->quarantined_objects, 3U);

    // Native copy MUST be used for all 3 candidates directly by the GC pipeline
    EXPECT_EQ(state->copy_count, 3U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.native_copy_attempts"), 3U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.fallback_copy_attempts"), 0U);

    // Batch verification was not preferred because 3 < 6
    EXPECT_EQ(state->physical_hash_batch_count, 0U);
    // Individual physical hash should be called for each destination candidate in Phase 2
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.individual_destination_hash_attempts"), 3U);

    // No payload GET or PUT should be performed as copy fallback
    EXPECT_EQ(state->orphan_payload_get_count, 0U);
    EXPECT_EQ(state->quarantine_payload_put_count, 0U);
    // Only metadata PUTs (3 for quarantine metadata)
    EXPECT_EQ(state->quarantine_metadata_put_count, 3U);

    // All 3 orphan sources should be removed
    for (const auto& orphan : orphans) {
        expect_presence(transport, orphan, Presence::Absent);
    }
}

TEST(IntegrityMaintenanceTest, BatchGcThresholdBoundaryFiveAndSixCandidates) {
    // A. N = 5 (strictly below min_objects 6): native copy, individual destination verification
    {
        auto workspace = kasumi::test::make_temp_workspace("gc-batch-boundary-5");
        FakeState* state = nullptr;
        auto transport = make_fake_transport(state);
        ASSERT_TRUE(kasumi::transport::initialize(transport));
        state->physical_hash_supported = true;
        state->copy_supported = true;
        enable_fake_physical_hash_batch(transport, *state, 6);
        auto runtime = runtime_data(workspace);

        const auto retained = make_commit(0, {}, "live.txt", "live").value();
        publish_remote(transport, workspace, retained);
        put_content(transport, workspace, "live", "live-content");

        for (int i = 0; i < 5; ++i) {
            const auto name = "orphan-5-" + std::to_string(i);
            put_content(transport, workspace, name, name + "-content");
        }

        reset_fake_traffic(*state);
        const auto collected = kasumi::application::integrity::garbage_collect(
            runtime, transport, test_key());
        ASSERT_TRUE(collected.has_value()) << collected.error().detail;
        EXPECT_EQ(collected->candidate_objects, 5U);
        EXPECT_EQ(collected->quarantined_objects, 5U);
        EXPECT_EQ(state->copy_count, 5U);
        EXPECT_EQ(state->physical_hash_batch_count, 0U);
        EXPECT_EQ(state->orphan_payload_get_count, 0U);
        EXPECT_EQ(state->quarantine_payload_put_count, 0U);
    }

    // B. N = 6 (at min_objects 6): native copy + batch verification
    {
        auto workspace = kasumi::test::make_temp_workspace("gc-batch-boundary-6");
        FakeState* state = nullptr;
        auto transport = make_fake_transport(state);
        ASSERT_TRUE(kasumi::transport::initialize(transport));
        state->physical_hash_supported = true;
        state->copy_supported = true;
        enable_fake_physical_hash_batch(transport, *state, 6);
        auto runtime = runtime_data(workspace);

        const auto retained = make_commit(0, {}, "live.txt", "live").value();
        publish_remote(transport, workspace, retained);
        put_content(transport, workspace, "live", "live-content");

        for (int i = 0; i < 6; ++i) {
            const auto name = "orphan-6-" + std::to_string(i);
            put_content(transport, workspace, name, name + "-content");
        }

        reset_fake_traffic(*state);
        const auto collected = kasumi::application::integrity::garbage_collect(
            runtime, transport, test_key());
        ASSERT_TRUE(collected.has_value()) << collected.error().detail;
        EXPECT_EQ(collected->candidate_objects, 6U);
        EXPECT_EQ(collected->quarantined_objects, 6U);
        EXPECT_EQ(state->copy_count, 6U);
        EXPECT_EQ(state->physical_hash_batch_count, 1U);
        EXPECT_EQ(state->orphan_payload_get_count, 0U);
        EXPECT_EQ(state->quarantine_payload_put_count, 0U);
    }
}

TEST(IntegrityMaintenanceTest, BatchGcTailOfOneHundredCandidatesWithThresholdSix) {
    auto workspace = kasumi::test::make_temp_workspace("gc-batch-tail-100");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    // Real rclone threshold: 6 objects minimum for batch
    enable_fake_physical_hash_batch(transport, *state, 6);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");

    for (int i = 0; i < 100; ++i) {
        const auto name = "orphan-100-" + std::to_string(i);
        put_content(transport, workspace, name, name + "-content");
    }

    reset_fake_traffic(*state);
    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 100U);
    EXPECT_EQ(collected->quarantined_objects, 100U);

    // All 100 candidates must be copied natively
    EXPECT_EQ(state->copy_count, 100U);
    // 12 batches of 8 (8 >= 6) use batch verify; 1 tail of 4 (4 < 6) uses individual verify
    EXPECT_EQ(state->physical_hash_batch_count, 12U);
    // Zero payload fallback
    EXPECT_EQ(state->orphan_payload_get_count, 0U);
    EXPECT_EQ(state->quarantine_payload_put_count, 0U);
}

TEST(IntegrityMaintenanceTest,
     CorruptPhysicalOrphanCommitStillBlocksGcWithValidEpoch) {
    auto workspace = kasumi::test::make_temp_workspace(
        "gc-corrupt-old-commit-with-epoch");
    FakeState* state = nullptr;
    auto storage = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(storage));
    auto runtime = runtime_data(workspace);

    const auto head = make_commit(0, {}, "live.txt", "live").value();
    const auto published_head =
        publish_remote(storage, workspace, head);
    put_content(storage, workspace, "live", "live");

    const auto orphan = make_commit(0, {}, "old.txt", "old").value();
    const auto published_orphan = publish_remote(storage, workspace, orphan);
    ASSERT_EQ(kasumi::transport::remove(
                  storage, marker_path(published_orphan.head)).value(),
              kasumi::transport::Removal::Removed);
    const auto orphan_object = object_path(published_orphan.head);
    ASSERT_FALSE(state->objects.at(orphan_object).empty());
    state->objects.at(orphan_object).front() ^= 0xff;

    const std::string vault_id(64, 'a');
    const kasumi::application::history_storage::epoch::Epoch genesis{
        .vault_id = vault_id,
        .sequence = 0,
        .issued_at = 1,
        .policy = {},
        .anchors = {{.commit_id = published_head.head.commit_id,
                     .height = 0}},
    };
    const auto sealed =
        kasumi::application::history_storage::epoch::seal(genesis, test_key());
    ASSERT_TRUE(sealed.has_value()) << sealed.error().detail;
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        storage, test_key(), *sealed,
        kasumi::test::workspace_root(workspace)));

    const auto collected =
        kasumi::application::integrity::garbage_collect(
            runtime, storage, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::IntegrityFailure);
    EXPECT_TRUE(state->objects.contains(orphan_object));
    EXPECT_FALSE(state->objects.contains(
        protocol::quarantine_identifier(test_layout(), orphan_object).value()));
}

TEST(IntegrityMaintenanceTest, SnapshotTraceScopesResetAndKeepPartialFailures) {
    struct TraceGuard {
        ~TraceGuard() { kasumi::platform::perf_trace::force_enable(false); }
    } trace_guard;
    kasumi::platform::perf_trace::force_enable(true);

    IntegratedGcFixture fixture{"snapshot-traces", 0};
    reset_fake_traffic(*fixture.state);
    kasumi::platform::perf_trace::reset();

    const auto collected = kasumi::application::integrity::garbage_collect(
        fixture.runtime, fixture.storage, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(fixture.state->commit_get_count, 2U);
    EXPECT_EQ(fixture.state->marker_get_count, 2U);
    EXPECT_EQ(fixture.state->get_count, 7U);
    EXPECT_EQ(fixture.state->list_count, 10U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "gc.snapshot.first/rc/load_and_auth_commits"),
              1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "gc.snapshot.second/rc/load_and_auth_commits"),
              1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("rc/get_commit"), 2U);

    kasumi::platform::perf_trace::reset();
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "gc.snapshot.first.physical_listing_us"),
              0U);
    reset_fake_traffic(*fixture.state);
    fixture.state->fail_commit_get = true;

    const auto failed = kasumi::application::integrity::garbage_collect(
        fixture.runtime, fixture.storage, test_key());
    ASSERT_FALSE(failed.has_value());
    EXPECT_EQ(fixture.state->commit_get_count, 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "gc.snapshot.first.physical_listing_us"),
              1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "gc.snapshot.first.history_reconstruction_us"),
              1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "gc.snapshot.first/rc/load_and_auth_commits"),
              1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "gc.snapshot.second.physical_listing_us"),
              0U);
}

} // namespace

TEST(IntegrityMaintenanceTest, TwoGcObservationsIndependentlyDownloadSingleCommitDirectly) {
    auto workspace =
        kasumi::test::make_temp_workspace("gc-single-commit-direct");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);
    const auto published = publish_remote(
        transport, workspace, kasumi::history::make_empty_bootstrap().value());
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");
    state->physical_hash_supported = true;
    state->copy_supported = true;
    transport.storage.get_batch = fake_reachability_get_batch;
    state->get_batch_count = 0;
    state->commit_get_count = 0;

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 1U);
    EXPECT_EQ(collected->quarantined_objects, 1U);
    EXPECT_EQ(state->get_batch_count, 0U);
    EXPECT_EQ(state->commit_get_count, 2U);
}

TEST(IntegrityMaintenanceTest, DirectCommitDownloadFailureDuringGcFailsClosed) {
    auto workspace =
        kasumi::test::make_temp_workspace("gc-single-commit-download-failure");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);
    publish_remote(
        transport, workspace, kasumi::history::make_empty_bootstrap().value());
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");
    state->physical_hash_supported = true;
    state->copy_supported = true;
    transport.storage.get_batch = fake_reachability_get_batch;
    state->fail_commit_get = true;

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::TransportFailure);
    expect_presence(transport, orphan, Presence::Present);
}

TEST(IntegrityMaintenanceTest, RemoteCommitMutationBetweenObservationsAbortsGcWithoutLocalReuse) {
    auto workspace =
        kasumi::test::make_temp_workspace("gc-commit-mutation-between-observations");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);
    const auto published = publish_remote(
        transport, workspace, kasumi::history::make_empty_bootstrap().value());
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");
    state->physical_hash_supported = true;
    state->copy_supported = true;
    transport.storage.get_batch = fake_reachability_get_batch;

    static std::size_t commit_gets_seen = 0;
    commit_gets_seen = 0;
    static auto original_get = transport.storage.get;
    original_get = transport.storage.get;

    transport.storage.get = [](void* ctx,
                               std::string_view identifier,
                               const std::filesystem::path& destination) -> kasumi::transport::Result {
        if (is_commit(identifier)) {
            commit_gets_seen++;
            if (commit_gets_seen == 2) {
                auto* s = fake_state(ctx);
                auto it = s->objects.find(std::string{identifier});
                if (it != s->objects.end() && !it->second.empty()) {
                    it->second.front() ^= 0xFF;
                }
            }
        }
        return original_get(ctx, identifier, destination);
    };

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    transport.storage.get = original_get;

    ASSERT_FALSE(collected.has_value());
    EXPECT_GE(commit_gets_seen, 2U);
    expect_presence(transport, orphan, Presence::Present);
}

TEST(IntegrityMaintenanceTest, MultipleCommitsPreserveBatchDuringGc) {
    auto workspace =
        kasumi::test::make_temp_workspace("gc-multiple-commits-batch");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);
    const auto parent = publish_remote(
        transport, workspace, make_commit(0, {}, "file.txt", "zero").value());
    publish_remote(
        transport,
        workspace,
        make_commit(1, {parent.head.commit_id}, "file.txt", "one").value());
    put_content(transport, workspace, "zero", "zero");
    put_content(transport, workspace, "one", "one");
    const auto orphan = put_content(transport, workspace, "orphan", "orphan");
    state->physical_hash_supported = true;
    state->copy_supported = true;
    transport.storage.get_batch = fake_reachability_get_batch;
    state->get_batch_count = 0;
    state->commit_get_count = 0;

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 1U);
    EXPECT_EQ(collected->quarantined_objects, 1U);
    EXPECT_EQ(state->get_batch_count, 2U);
    EXPECT_EQ(state->commit_get_count, 0U);
}


// ============================================================================
// Phase 10B Telemetry Tests
// ============================================================================

TEST(IntegrityMaintenanceTelemetryTest, ScenarioANZeroCandidates) {
    auto workspace = kasumi::test::make_temp_workspace("gc-telem-a-zero");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;

    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_selected"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_verified"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_quarantined"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidate_batches"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_sizes"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_verify_attempts"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_verify_supported"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_verify_unsupported"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_verify_failures"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.individual_destination_hash_attempts"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.native_copy_attempts"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.native_copy_successes"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.native_copy_unsupported"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.fallback_copy_attempts"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.source_removals"), 0U);
    EXPECT_GT(kasumi::platform::perf_trace::get_time("gc.total_duration_us"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_time("gc.batch_prepare_duration_us"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_time("gc.batch_verify_duration_us"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_time("gc.batch_publish_remove_duration_us"), 0U);

    kasumi::platform::perf_trace::reset();
    kasumi::platform::perf_trace::force_enable(false);
}

TEST(IntegrityMaintenanceTelemetryTest, ScenarioBOneCandidate) {
    auto workspace = kasumi::test::make_temp_workspace("gc-telem-b-one");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");
    put_content(transport, workspace, "orphan-0", "orphan-content");

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;

    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_selected"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_verified"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_quarantined"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidate_batches"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_sizes"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_verify_attempts"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.native_copy_attempts"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.native_copy_successes"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.fallback_copy_attempts"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.individual_destination_hash_attempts"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.source_removals"), 1U);
    EXPECT_GT(kasumi::platform::perf_trace::get_time("gc.total_duration_us"), 0U);

    kasumi::platform::perf_trace::reset();
    kasumi::platform::perf_trace::force_enable(false);
}

TEST(IntegrityMaintenanceTelemetryTest, ScenarioCSixCandidatesThreshold) {
    auto workspace = kasumi::test::make_temp_workspace("gc-telem-c-six");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 6);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");
    for (std::size_t i = 0; i < 6; ++i) {
        const auto name = "orphan-" + std::to_string(i);
        put_content(transport, workspace, name, name);
    }

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;

    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_selected"), 6U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidate_batches"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_sizes"), 6U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.native_copy_attempts"), 6U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.native_copy_successes"), 6U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_verify_attempts"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_verify_supported"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.individual_destination_hash_attempts"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.fallback_copy_attempts"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_verified"), 6U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_quarantined"), 6U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.source_removals"), 6U);
    EXPECT_GT(kasumi::platform::perf_trace::get_time("gc.batch_prepare_duration_us"), 0U);
    EXPECT_GT(kasumi::platform::perf_trace::get_time("gc.batch_verify_duration_us"), 0U);
    EXPECT_GT(kasumi::platform::perf_trace::get_time("gc.batch_publish_remove_duration_us"), 0U);

    kasumi::platform::perf_trace::reset();
    kasumi::platform::perf_trace::force_enable(false);
}

TEST(IntegrityMaintenanceTelemetryTest, ScenarioDEightCandidatesFullBatch) {
    auto workspace = kasumi::test::make_temp_workspace("gc-telem-d-eight");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");
    for (std::size_t i = 0; i < 8; ++i) {
        const auto name = "orphan-" + std::to_string(i);
        put_content(transport, workspace, name, name);
    }

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;

    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_selected"), 8U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidate_batches"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_sizes"), 8U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.native_copy_attempts"), 8U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.native_copy_successes"), 8U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_verify_attempts"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_verify_supported"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_verified"), 8U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_quarantined"), 8U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.source_removals"), 8U);

    kasumi::platform::perf_trace::reset();
    kasumi::platform::perf_trace::force_enable(false);
}

TEST(IntegrityMaintenanceTelemetryTest, ScenarioETenCandidatesDecompositionAndTail) {
    auto workspace = kasumi::test::make_temp_workspace("gc-telem-e-ten");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");
    for (std::size_t i = 0; i < 10; ++i) {
        const auto name = "orphan-" + std::to_string(i);
        put_content(transport, workspace, name, name);
    }

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;

    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_selected"), 10U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidate_batches"), 2U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_sizes"), 10U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.native_copy_attempts"), 10U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.native_copy_successes"), 10U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_verify_attempts"), 2U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_verify_supported"), 2U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_verified"), 10U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_quarantined"), 10U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.source_removals"), 10U);

    kasumi::platform::perf_trace::reset();
    kasumi::platform::perf_trace::force_enable(false);
}

TEST(IntegrityMaintenanceTelemetryTest, ScenarioFOneHundredCandidatesScale) {
    auto workspace = kasumi::test::make_temp_workspace("gc-telem-f-hundred");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");
    for (std::size_t i = 0; i < 100; ++i) {
        const auto name = "orphan-" + std::to_string(i);
        put_content(transport, workspace, name, name);
    }

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;

    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_selected"), 100U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidate_batches"), 13U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_sizes"), 100U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_quarantined"), 100U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.source_removals"), 100U);

    kasumi::platform::perf_trace::reset();
    kasumi::platform::perf_trace::force_enable(false);
}

TEST(IntegrityMaintenanceTelemetryTest, ScenarioGBatchUnsupportedFallback) {
    auto workspace = kasumi::test::make_temp_workspace("gc-telem-g-unsupported");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    state->physical_hash_batch_supported = false;
    transport.storage.physical_hash_batch_min_objects = 2;
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");
    for (std::size_t i = 0; i < 6; ++i) {
        const auto name = "orphan-" + std::to_string(i);
        put_content(transport, workspace, name, name);
    }

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;

    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_selected"), 6U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidate_batches"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_verify_attempts"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_verify_unsupported"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_verify_supported"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.individual_destination_hash_attempts"), 6U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_verified"), 6U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_quarantined"), 6U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.source_removals"), 6U);

    kasumi::platform::perf_trace::reset();
    kasumi::platform::perf_trace::force_enable(false);
}

TEST(IntegrityMaintenanceTelemetryTest, ScenarioHFailureAbortsBeforeRemoval) {
    auto workspace = kasumi::test::make_temp_workspace("gc-telem-h-failure");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");

    std::vector<std::string> orphans;
    orphans.push_back(put_content(transport, workspace, "orphan-0", "orphan-0"));
    orphans.push_back(put_content(transport, workspace, "orphan-1", "orphan-1"));
    std::ranges::sort(orphans);

    const auto q0 = protocol::quarantine_identifier(test_layout(), orphans[0]);
    ASSERT_TRUE(q0.has_value());
    // Simulate first candidate failure in batch report (mismatched)
    state->physical_hash_batch_mismatches.insert(*q0);

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());

    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_selected"), 2U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_verify_attempts"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_verify_failures"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_quarantined"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.source_removals"), 0U);

    kasumi::platform::perf_trace::reset();
    kasumi::platform::perf_trace::force_enable(false);
}

TEST(IntegrityMaintenanceTelemetryTest, ScenarioKTelemetryDisabled) {
    auto workspace = kasumi::test::make_temp_workspace("gc-telem-k-disabled");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");
    put_content(transport, workspace, "orphan-0", "orphan-0");

    kasumi::platform::perf_trace::force_enable(false);
    kasumi::platform::perf_trace::reset();

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->quarantined_objects, 1U);

    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_selected"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_quarantined"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_time("gc.total_duration_us"), 0U);
}

TEST(IntegrityMaintenanceTelemetryTest, ScenarioLConcurrency) {
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    constexpr int threads_count = 8;
    constexpr int iterations_per_thread = 500;
    std::vector<std::thread> workers;
    workers.reserve(threads_count);

    for (int t = 0; t < threads_count; ++t) {
        workers.emplace_back([] {
            for (int i = 0; i < iterations_per_thread; ++i) {
                kasumi::platform::perf_trace::count("gc.candidates_selected", 1);
                kasumi::platform::perf_trace::count("gc.source_removals", 2);
                const auto tok = kasumi::platform::perf_trace::begin();
                kasumi::platform::perf_trace::finish("gc.batch_prepare_duration_us", tok);
            }
        });
    }

    for (auto& w : workers) {
        w.join();
    }

    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_selected"),
              static_cast<std::uint64_t>(threads_count * iterations_per_thread));
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.source_removals"),
              static_cast<std::uint64_t>(threads_count * iterations_per_thread * 2));
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.batch_prepare_duration_us"),
              static_cast<std::uint64_t>(threads_count * iterations_per_thread));

    kasumi::platform::perf_trace::reset();
    kasumi::platform::perf_trace::force_enable(false);
}

TEST(IntegrityMaintenanceTelemetryTest, ScenarioMInterruption) {
    auto workspace = kasumi::test::make_temp_workspace("gc-telem-m-interruption");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 2);
    auto runtime = runtime_data(workspace);

    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");
    const auto orphan = put_content(transport, workspace, "orphan-0", "orphan-0");

    // Fail remove of candidate to simulate interruption during phase 3
    state->fail_remove_identifier = orphan;

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());

    // Verified was reached, but quarantined was not!
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_selected"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_verified"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.source_removals"), 1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("gc.candidates_quarantined"), 0U);

    kasumi::platform::perf_trace::reset();
    kasumi::platform::perf_trace::force_enable(false);
}

TEST(IntegrityMaintenancePhase14Scenarios, Scenario1HistoricalContentRetained) {
    auto workspace = kasumi::test::make_temp_workspace("gc-phase14-scen1");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);

    // Commit 0: creates "x.txt" with "content_X"
    const auto commit0 = make_commit(0, {}, "x.txt", "content_X").value();
    const auto pub0 = publish_remote(transport, workspace, commit0);
    const auto id_x = put_content(transport, workspace, "content_X", "x-content");

    // Commit 1: updates to "y.txt" with "content_Y", parent is commit0
    const auto commit1 = make_commit(1, {pub0.head.commit_id}, "y.txt", "content_Y").value();
    const auto pub1 = publish_remote(transport, workspace, commit1);
    const auto id_y = put_content(transport, workspace, "content_Y", "y-content");

    // Orphan candidate
    const auto id_orphan = put_content(transport, workspace, "orphan_data", "orphan-content");

    reset_fake_traffic(*state);

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 1U);
    EXPECT_EQ(collected->quarantined_objects, 1U);

    // X is NOT in head commit1, but is in historical commit0 reachable from head -> protected!
    expect_presence(transport, id_x, Presence::Present);
    expect_presence(transport, id_y, Presence::Present);
    expect_presence(transport, id_orphan, Presence::Absent);
}

TEST(IntegrityMaintenancePhase14Scenarios, Scenario2SharedBranch) {
    auto workspace = kasumi::test::make_temp_workspace("gc-phase14-scen2");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);

    // Root commit with "shared.txt" = "content_X"
    const auto root = make_commit(0, {}, "shared.txt", "content_X").value();
    const auto pub_root = publish_remote(transport, workspace, root);
    const auto id_x = put_content(transport, workspace, "content_X", "x-content");

    // Branch A: drops shared.txt, adds branch_a.txt = "content_A"
    const auto commit_a = make_commit(1, {pub_root.head.commit_id}, "branch_a.txt", "content_A").value();
    publish_remote(transport, workspace, commit_a);
    const auto id_a = put_content(transport, workspace, "content_A", "a-content");

    // Branch B: keeps shared.txt, adds branch_b.txt = "content_B"
    Snapshot snap_b{
        .rows = {
            kasumi::NodeRow{.path = "", .hash = {}, .size = 0, .mtime = {}, .is_directory = true},
            kasumi::NodeRow{.path = "branch_b.txt", .hash = kasumi::hasher::hash_string("content_B"), .size = 9, .mtime = {}, .is_directory = false},
            kasumi::NodeRow{.path = "shared.txt", .hash = kasumi::hasher::hash_string("content_X"), .size = 9, .mtime = {}, .is_directory = false},
        },
    };
    kasumi::finalize_snapshot(snap_b);
    const auto commit_b = kasumi::history::make_commit(1, {pub_root.head.commit_id}, std::move(snap_b)).value();
    publish_remote(transport, workspace, commit_b);
    const auto id_b = put_content(transport, workspace, "content_B", "b-content");

    // Orphan candidate
    const auto id_orphan = put_content(transport, workspace, "orphan_data", "orphan-content");

    reset_fake_traffic(*state);

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 1U);
    EXPECT_EQ(collected->quarantined_objects, 1U);

    // Branch A drops X, but Branch B (and root) still reference X -> X remains protected!
    expect_presence(transport, id_x, Presence::Present);
    expect_presence(transport, id_a, Presence::Present);
    expect_presence(transport, id_b, Presence::Present);
    expect_presence(transport, id_orphan, Presence::Absent);
}

TEST(IntegrityMaintenancePhase14Scenarios, Scenario3ContentReturn) {
    auto workspace = kasumi::test::make_temp_workspace("gc-phase14-scen3");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);

    // Commit 0: has X
    const auto c0 = make_commit(0, {}, "data.txt", "content_X").value();
    const auto pub0 = publish_remote(transport, workspace, c0);
    const auto id_x = put_content(transport, workspace, "content_X", "x-content");

    // Commit 1: replaces X with Y
    const auto c1 = make_commit(1, {pub0.head.commit_id}, "data.txt", "content_Y").value();
    const auto pub1 = publish_remote(transport, workspace, c1);
    const auto id_y = put_content(transport, workspace, "content_Y", "y-content");

    // Commit 2: returns to X
    const auto c2 = make_commit(2, {pub1.head.commit_id}, "data.txt", "content_X").value();
    publish_remote(transport, workspace, c2);

    // Orphan candidate
    const auto id_orphan = put_content(transport, workspace, "orphan_data", "orphan-content");

    reset_fake_traffic(*state);

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 1U);
    EXPECT_EQ(collected->quarantined_objects, 1U);

    // X was removed in commit 1, but re-introduced in commit 2 (and existed in commit 0).
    // The prior removal must not authorize collection of X!
    expect_presence(transport, id_x, Presence::Present);
    expect_presence(transport, id_y, Presence::Present);
    expect_presence(transport, id_orphan, Presence::Absent);
}

TEST(IntegrityMaintenancePhase14Scenarios, Scenario4Merge) {
    auto workspace = kasumi::test::make_temp_workspace("gc-phase14-scen4");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);

    // Base commit
    const auto c0 = make_commit(0, {}, "base.txt", "content_C0").value();
    const auto pub0 = publish_remote(transport, workspace, c0);
    const auto id_c0 = put_content(transport, workspace, "content_C0", "c0-content");

    // Branch 1
    const auto c1a = make_commit(1, {pub0.head.commit_id}, "branch_1.txt", "content_1A").value();
    const auto pub1a = publish_remote(transport, workspace, c1a);
    const auto id_1a = put_content(transport, workspace, "content_1A", "1a-content");

    // Branch 2
    const auto c1b = make_commit(1, {pub0.head.commit_id}, "branch_2.txt", "content_1B").value();
    const auto pub1b = publish_remote(transport, workspace, c1b);
    const auto id_1b = put_content(transport, workspace, "content_1B", "1b-content");

    // Merge commit with 2 parents: pub1a and pub1b
    Snapshot snap_merge{
        .rows = {
            kasumi::NodeRow{.path = "", .hash = {}, .size = 0, .mtime = {}, .is_directory = true},
            kasumi::NodeRow{.path = "base.txt", .hash = kasumi::hasher::hash_string("content_C0"), .size = 10, .mtime = {}, .is_directory = false},
            kasumi::NodeRow{.path = "branch_1.txt", .hash = kasumi::hasher::hash_string("content_1A"), .size = 10, .mtime = {}, .is_directory = false},
            kasumi::NodeRow{.path = "branch_2.txt", .hash = kasumi::hasher::hash_string("content_1B"), .size = 10, .mtime = {}, .is_directory = false},
        },
    };
    kasumi::finalize_snapshot(snap_merge);
    const auto c_merge = kasumi::history::make_commit(2, {pub1a.head.commit_id, pub1b.head.commit_id}, std::move(snap_merge)).value();
    publish_remote(transport, workspace, c_merge);

    // Orphan candidate
    const auto id_orphan = put_content(transport, workspace, "orphan_data", "orphan-content");

    reset_fake_traffic(*state);

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 1U);
    EXPECT_EQ(collected->quarantined_objects, 1U);

    // All merged branches and base remain protected
    expect_presence(transport, id_c0, Presence::Present);
    expect_presence(transport, id_1a, Presence::Present);
    expect_presence(transport, id_1b, Presence::Present);
    expect_presence(transport, id_orphan, Presence::Absent);
}

TEST(IntegrityMaintenancePhase14Scenarios, Scenario5EpochRetention) {
    auto workspace = kasumi::test::make_temp_workspace("gc-phase14-scen5");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);

    // Commit 0
    const auto c0 = make_commit(0, {}, "c0.txt", "content_0").value();
    const auto pub0 = publish_remote(transport, workspace, c0);
    const auto id_0 = put_content(transport, workspace, "content_0", "c0-content");

    // Commit 1
    const auto c1 = make_commit(1, {pub0.head.commit_id}, "c1.txt", "content_1").value();
    const auto pub1 = publish_remote(transport, workspace, c1);
    const auto id_1 = put_content(transport, workspace, "content_1", "c1-content");

    // Commit 2
    const auto c2 = make_commit(2, {pub1.head.commit_id}, "c2.txt", "content_2").value();
    publish_remote(transport, workspace, c2);
    const auto id_2 = put_content(transport, workspace, "content_2", "c2-content");

    // Publish an Epoch anchored at commit 0
    const std::string vault_id(64, 'e');
    kasumi::application::history_storage::epoch::Epoch epoch_val{
        .vault_id = vault_id,
        .sequence = 0,
        .issued_at = 100,
        .policy = {},
        .anchors = {{pub0.head.commit_id, 0}},
        .previous_epoch_id = {},
    };
    const auto sealed = kasumi::application::history_storage::epoch::seal(epoch_val, test_key());
    ASSERT_TRUE(sealed.has_value());
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        transport, test_key(), *sealed, kasumi::test::workspace_root(workspace)));

    // Orphan candidate
    const auto id_orphan = put_content(transport, workspace, "orphan_data", "orphan-content");

    reset_fake_traffic(*state);

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 1U);
    EXPECT_EQ(collected->quarantined_objects, 1U);

    // Everything protected by epoch boundary and history is preserved
    expect_presence(transport, id_0, Presence::Present);
    expect_presence(transport, id_1, Presence::Present);
    expect_presence(transport, id_2, Presence::Present);
    expect_presence(transport, id_orphan, Presence::Absent);
}

TEST(IntegrityMaintenancePhase14Scenarios, Scenario6AlterationBetweenObservations) {
    auto workspace = kasumi::test::make_temp_workspace("gc-phase14-scen6");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);

    const auto c0 = make_commit(0, {}, "data.txt", "content_0").value();
    publish_remote(transport, workspace, c0);
    const auto id_0 = put_content(transport, workspace, "content_0", "c0-content");
    const auto id_orphan = put_content(transport, workspace, "orphan_data", "orphan-content");

    reset_fake_traffic(*state);

    // Observation 1 is list call 8. Observation 2 is list call 9.
    // Reveal a new valid content object on list call 9 so snapshot 2 diverges from snapshot 1.
    state->reveal_on_list_count = 9;
    const auto concurrent_id = kasumi::crypto::content_identifier(
        test_key(), kasumi::hasher::hash_string("concurrent_valid_content"));
    state->hidden_objects[concurrent_id] = {1, 2, 3, 4};

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::ConcurrentChange)
        << collected.error().detail;

    // Fail-closed invariant: no destructive operations occurred!
    expect_presence(transport, id_0, Presence::Present);
    expect_presence(transport, id_orphan, Presence::Present);
}

TEST(IntegrityMaintenancePhase14Scenarios, Scenario7AlterationBeforeFinalListing) {
    auto workspace = kasumi::test::make_temp_workspace("gc-phase14-scen7");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);

    const auto c0 = make_commit(0, {}, "data.txt", "content_0").value();
    publish_remote(transport, workspace, c0);
    const auto id_0 = put_content(transport, workspace, "content_0", "c0-content");
    const auto id_orphan = put_content(transport, workspace, "orphan_data", "orphan-content");

    reset_fake_traffic(*state);

    // Snapshot 1 (call 8) and Snapshot 2 (call 9) match!
    // Final listing (call 10) sees a newly added object.
    state->reveal_on_list_count = 10;
    state->hidden_objects["late_arriving_object"] = {5, 6, 7, 8};

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::ConcurrentChange);

    // Fail-closed invariant: no removals!
    expect_presence(transport, id_0, Presence::Present);
    expect_presence(transport, id_orphan, Presence::Present);
}

TEST(IntegrityMaintenancePhase14Scenarios, Scenario8IoErrorAndIncompleteListing) {
    auto workspace = kasumi::test::make_temp_workspace("gc-phase14-scen8");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    auto runtime = runtime_data(workspace);

    const auto c0 = make_commit(0, {}, "data.txt", "content_0").value();
    publish_remote(transport, workspace, c0);
    const auto id_0 = put_content(transport, workspace, "content_0", "c0-content");
    const auto id_orphan = put_content(transport, workspace, "orphan_data", "orphan-content");

    // Part A: Explicit I/O failure during snapshot listing (call 8)
    reset_fake_traffic(*state);
    state->fail_list_at = 8;
    state->fail_list = kasumi::transport::ErrorCode::Io;

    auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::TransportFailure);
    expect_presence(transport, id_0, Presence::Present);
    expect_presence(transport, id_orphan, Presence::Present);

    // Part B: Explicit I/O failure during final listing (call 10)
    reset_fake_traffic(*state);
    state->fail_list_at = 10;
    state->fail_list = kasumi::transport::ErrorCode::Io;

    collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key());
    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(collected.error().code, IntegrityErrorCode::TransportFailure);
    expect_presence(transport, id_0, Presence::Present);
    expect_presence(transport, id_orphan, Presence::Present);
}

std::vector<std::string> seed_copy_batch_gc(
    kasumi::transport::Transport& transport,
    TempWorkspace& workspace,
    std::size_t count) {
    const auto retained = make_commit(0, {}, "live.txt", "live").value();
    publish_remote(transport, workspace, retained);
    put_content(transport, workspace, "live", "live-content");
    std::vector<std::string> candidates;
    for (std::size_t index = 0; index < count; ++index) {
        const auto value = "batch-orphan-" + std::to_string(index);
        candidates.push_back(put_content(transport, workspace, value, value));
    }
    return candidates;
}

TEST(IntegrityMaintenanceTest, CopyBatchEightPreservesVerificationAndRemovalOrder) {
    auto workspace = kasumi::test::make_temp_workspace("gc-copy-batch-eight");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    state->copy_batch_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 6);
    const auto candidates = seed_copy_batch_gc(transport, workspace, 8);
    auto runtime = runtime_data(workspace);
    reset_fake_traffic(*state);

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key(), 8);

    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->candidate_objects, 8U);
    EXPECT_EQ(collected->quarantined_objects, 8U);
    EXPECT_EQ(state->copy_batch_count, 1U);
    EXPECT_EQ(state->copy_batch_item_count, 8U);
    EXPECT_EQ(state->copy_batch_concurrency, 8U);
    EXPECT_EQ(state->physical_hash_batch_count, 1U);
    EXPECT_EQ(state->quarantine_metadata_put_count, 8U);
    EXPECT_EQ(state->remove_count, 8U);

    const auto copy_batch = std::ranges::find(state->gc_events, "copy_batch:8");
    const auto destination_verify = std::ranges::find_if(
        state->gc_events,
        [](const auto& event) { return event.starts_with("batch|"); });
    const auto first_metadata = std::ranges::find_if(
        state->gc_events,
        [](const auto& event) { return event.starts_with("metadata:"); });
    const auto first_remove = std::ranges::find_if(
        state->gc_events,
        [](const auto& event) { return event.starts_with("remove:"); });
    ASSERT_NE(copy_batch, state->gc_events.end());
    ASSERT_NE(destination_verify, state->gc_events.end());
    ASSERT_NE(first_metadata, state->gc_events.end());
    ASSERT_NE(first_remove, state->gc_events.end());
    EXPECT_LT(copy_batch, destination_verify);
    EXPECT_LT(destination_verify, first_metadata);
    EXPECT_LT(first_metadata, first_remove);
    for (const auto& candidate : candidates) {
        const auto source_hash = std::ranges::find(
            state->gc_events, "physical_hash:" + candidate);
        ASSERT_NE(source_hash, state->gc_events.end());
        EXPECT_LT(source_hash, copy_batch);
        expect_presence(transport, candidate, Presence::Absent);
    }
}

TEST(IntegrityMaintenanceTest, CopyBatchPartialAmbiguousFailureKeepsEverySource) {
    auto workspace = kasumi::test::make_temp_workspace("gc-copy-batch-partial");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    state->copy_batch_supported = true;
    state->copy_batch_failure = kasumi::transport::ErrorCode::Io;
    state->copy_batch_fail_after_items = 1;
    enable_fake_physical_hash_batch(transport, *state, 6);
    const auto candidates = seed_copy_batch_gc(transport, workspace, 8);
    auto runtime = runtime_data(workspace);
    reset_fake_traffic(*state);

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key(), 8);

    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(state->copy_batch_count, 1U);
    EXPECT_EQ(state->copy_count, 1U);
    EXPECT_EQ(state->quarantine_metadata_put_count, 0U);
    EXPECT_EQ(state->remove_count, 0U);
    for (const auto& candidate : candidates) {
        expect_presence(transport, candidate, Presence::Present);
    }
}

TEST(IntegrityMaintenanceTest, CopyBatchBarrierLossPreventsMetadataAndRemoval) {
    auto workspace = kasumi::test::make_temp_workspace("gc-copy-batch-barrier");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    state->copy_batch_supported = true;
    state->replace_barrier_after_quarantine_put = true;
    enable_fake_physical_hash_batch(transport, *state, 6);
    const auto candidates = seed_copy_batch_gc(transport, workspace, 8);
    auto runtime = runtime_data(workspace);
    reset_fake_traffic(*state);

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key(), 8);

    ASSERT_FALSE(collected.has_value());
    EXPECT_EQ(state->copy_batch_count, 1U);
    EXPECT_EQ(state->quarantine_metadata_put_count, 0U);
    EXPECT_EQ(state->remove_count, 0U);
    for (const auto& candidate : candidates) {
        expect_presence(transport, candidate, Presence::Present);
    }
}

TEST(IntegrityMaintenanceTest, UnsupportedCopyBatchFallsBackToSequentialCopies) {
    auto workspace = kasumi::test::make_temp_workspace("gc-copy-batch-unsupported");
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    state->physical_hash_supported = true;
    state->copy_supported = true;
    state->copy_batch_supported = false;
    enable_fake_physical_hash_batch(transport, *state, 6);
    const auto candidates = seed_copy_batch_gc(transport, workspace, 8);
    auto runtime = runtime_data(workspace);
    reset_fake_traffic(*state);

    const auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, test_key(), 8);

    ASSERT_TRUE(collected.has_value()) << collected.error().detail;
    EXPECT_EQ(collected->quarantined_objects, 8U);
    EXPECT_EQ(state->copy_batch_count, 1U);
    EXPECT_EQ(state->copy_count, 8U);
    for (const auto& candidate : candidates) {
        expect_presence(transport, candidate, Presence::Absent);
    }
}

} // namespace
