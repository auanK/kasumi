#include "application/history_storage/epoch.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/reachability.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/maintenance.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/history_storage.hpp"
#include "platform/cancellation.hpp"
#include "platform/perf_trace.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <chrono>
#include <filesystem>
#include <functional>
#include <gtest/gtest.h>
#include <iostream>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

namespace protocol = kasumi::application::history_storage::maintenance_protocol;
using kasumi::NodeRow;
using kasumi::Snapshot;
using kasumi::application::GarbageCollectProgress;
using kasumi::application::GarbageCollectStage;
using kasumi::application::history_storage::HeadReference;
using kasumi::application::history_storage::RemoteLayout;
using kasumi::application::history_storage::epoch::Anchor;
using kasumi::application::history_storage::epoch::Epoch;
using kasumi::runtime::RuntimeData;
using kasumi::test::TempWorkspace;

RemoteLayout layout() {
    return kasumi::application::history_storage::derive_remote_layout(
        test_key());
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

kasumi::history::Commit commit_with_file(std::string_view contents) {
    Snapshot tree{
        .rows = {NodeRow{.path = "", .is_directory = true},
                 NodeRow{.path = "live.txt",
                         .hash = kasumi::hasher::hash_string(contents),
                         .size = contents.size(),
                         .is_directory = false}}};
    kasumi::finalize_snapshot(tree);
    return kasumi::history::make_commit(0, {}, std::move(tree)).value();
}

HeadReference publish_object(kasumi::transport::Transport& transport,
                             TempWorkspace& workspace,
                             const kasumi::history::Commit& commit,
                             std::string_view suffix,
                             bool marker = true) {
    const auto canonical = kasumi::history::serialize(commit).value();
    const auto plain =
        kasumi::test::workspace_path(workspace, std::string{suffix} + ".plain");
    const auto cipher = kasumi::test::workspace_path(
        workspace, std::string{suffix} + ".cipher");
    kasumi::test::write_binary(plain, std::as_bytes(std::span{canonical}));
    EXPECT_TRUE(kasumi::crypto::encrypt_file(
        plain, cipher, test_key(), kasumi::crypto::FilePurpose::History));
    const auto hash = kasumi::crypto::content::hash_file(cipher).value();
    const HeadReference reference{.commit_id = commit_id(commit),
                                  .ciphertext_id = kasumi::hash_hex(hash)};
    EXPECT_TRUE(
        kasumi::transport::put(transport, cipher, object_path(reference)));
    if (marker) {
        const auto encoded =
            kasumi::application::history_storage::encode_marker(reference)
                .value();
        const auto marker_file = kasumi::test::workspace_path(
            workspace, std::string{suffix} + ".head");
        kasumi::test::write_binary(marker_file,
                                   std::as_bytes(std::span{encoded}));
        EXPECT_TRUE(kasumi::transport::put(
            transport, marker_file, marker_path(reference)));
    }
    return reference;
}

HeadReference add_variant_object(kasumi::transport::Transport& transport,
                                 TempWorkspace& workspace,
                                 const kasumi::history::Commit& commit,
                                 std::string_view suffix) {
    return publish_object(transport, workspace, commit, suffix, false);
}

void put_object_bytes(kasumi::transport::Transport& transport,
                      TempWorkspace& workspace,
                      std::string_view identifier,
                      std::span<const std::uint8_t> bytes,
                      std::string_view suffix) {
    const auto path =
        kasumi::test::workspace_path(workspace, std::string{suffix} + ".bin");
    kasumi::test::write_binary(path, std::as_bytes(bytes));
    EXPECT_TRUE(kasumi::transport::put(transport, path, identifier));
}

std::string content_identifier(std::string_view contents) {
    return kasumi::crypto::content_identifier(
        test_key(), kasumi::hasher::hash_string(contents));
}

std::string put_content(kasumi::transport::Transport& transport,
                        TempWorkspace& workspace,
                        std::string_view contents,
                        std::string_view suffix) {
    const auto identifier = content_identifier(contents);
    const auto plain =
        kasumi::test::workspace_path(workspace, std::string{suffix} + ".plain");
    const auto cipher =
        kasumi::test::workspace_path(workspace, std::string{suffix} + ".enc");
    kasumi::test::write_text(plain, contents);
    EXPECT_TRUE(kasumi::crypto::encrypt_file(plain, cipher, test_key()));
    EXPECT_TRUE(kasumi::transport::put(transport, cipher, identifier));
    return identifier;
}

void put_corrupt_content(kasumi::transport::Transport& transport,
                         TempWorkspace& workspace,
                         std::string_view contents,
                         std::string_view suffix) {
    const std::array<std::uint8_t, 4> garbage{0xde, 0xad, 0xbe, 0xef};
    put_object_bytes(
        transport, workspace, content_identifier(contents), garbage, suffix);
}

HeadReference put_corrupt_variant(kasumi::transport::Transport& transport,
                                  TempWorkspace& workspace,
                                  const kasumi::history::Commit& commit,
                                  std::string_view suffix) {
    const std::array<std::uint8_t, 8> garbage{
        0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04};
    const auto path =
        kasumi::test::workspace_path(workspace, std::string{suffix} + ".bin");
    kasumi::test::write_binary(path, std::as_bytes(std::span{garbage}));
    const auto hash = kasumi::crypto::content::hash_file(path).value();
    const HeadReference reference{.commit_id = commit_id(commit),
                                  .ciphertext_id = kasumi::hash_hex(hash)};
    EXPECT_TRUE(
        kasumi::transport::put(transport, path, object_path(reference)));
    return reference;
}

std::vector<std::uint8_t> marker_bytes(const HeadReference& reference) {
    const auto encoded =
        kasumi::application::history_storage::encode_marker(reference).value();
    return {encoded.begin(), encoded.end()};
}

bool object_present(kasumi::transport::Transport& transport,
                    std::string_view identifier) {
    const auto presence = kasumi::transport::presence(transport, identifier);
    EXPECT_TRUE(presence.has_value());
    return presence && *presence == kasumi::transport::Presence::Present;
}

std::size_t candidate_remove_attempts(const FakeState& state) {
    return static_cast<std::size_t>(std::ranges::count_if(
        state.remove_attempts, [](const std::string& identifier) {
            return !protocol::is_control_object(layout(), identifier);
        }));
}

std::size_t barrier_remove_attempts(const FakeState& state) {
    return static_cast<std::size_t>(
        std::ranges::count(state.remove_attempts, layout().barrier_identifier));
}

void after_full_list(FakeState* state,
                     std::size_t count,
                     std::function<void(FakeState&)> action) {
    state->on_operation =
        [count, action = std::move(action)](FakeState& current,
                                            std::string_view operation,
                                            std::string_view) mutable {
            if (operation == "after_list" && current.full_list_count == count) {
                action(current);
            }
        };
}

struct LocalFixture {
    LocalStorage storage = make_local_storage();
    RuntimeData runtime = runtime_data(storage.workspace);

    std::expected<kasumi::application::integrity::GarbageCollectResult,
                  kasumi::application::integrity::Error>
    collect(kasumi::application::integrity::GarbageCollectProgressCallback
                progress = {}) {
        return kasumi::application::integrity::garbage_collect(
            runtime, storage.transport, test_key(), std::move(progress));
    }
};

struct FakeFixture {
    TempWorkspace workspace;
    FakeState* state = nullptr;
    kasumi::transport::Transport transport;
    RuntimeData runtime;

    explicit FakeFixture(std::string_view name)
        : workspace(kasumi::test::make_temp_workspace(name)),
          transport(make_fake_transport(state)),
          runtime(runtime_data(workspace)) {
        EXPECT_TRUE(kasumi::transport::initialize(transport));
    }

    std::expected<kasumi::application::integrity::GarbageCollectResult,
                  kasumi::application::integrity::Error>
    collect(kasumi::application::integrity::GarbageCollectProgressCallback
                progress = {}) {
        return kasumi::application::integrity::garbage_collect(
            runtime, transport, test_key(), std::move(progress));
    }
};

template <typename Fixture>
auto measure_gc(Fixture& fixture, std::string_view scenario) {
    using Result = decltype(fixture.collect());
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();
    const auto started = std::chrono::steady_clock::now();
    Result result = fixture.collect();
    const auto wall_us = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - started)
            .count());
    const auto count = [](std::string_view name) {
        return kasumi::platform::perf_trace::get_count(name);
    };
    const auto time = [](std::string_view name) {
        return kasumi::platform::perf_trace::get_time(name);
    };
    const auto optional_time = [&](std::string_view calls_name,
                                   std::string_view time_name) {
        return count(calls_name) == 0 ? std::string{"null"}
                                      : std::to_string(time(time_name));
    };
    std::cerr << "GC_BENCHMARK {\"scenario\":\"" << scenario
              << "\",\"measurement_level\":\"local file-backed transport; "
                 "fixture setup excluded\",\"wall_us\":"
              << wall_us << ",\"gc_total_us\":" << time("gc.total_us")
              << ",\"preparing_us\":" << time("gc.preparing_us")
              << ",\"analyzing_us\":" << time("gc.analyzing_us")
              << ",\"applying_us\":" << time("gc.applying_us")
              << ",\"finalizing_us\":" << time("gc.finalizing_us")
              << ",\"candidate_count\":" << count("gc.candidate_count")
              << ",\"content_candidates\":"
              << count("gc.candidate_content_count")
              << ",\"variant_candidates\":"
              << count("gc.candidate_variant_count")
              << ",\"confirmed_removed\":"
              << count("gc.confirmed_removed")
              << ",\"candidate_remove_attempts\":"
              << count("gc.remove_attempts")
              << ",\"list_calls\":"
              << count("transport list") + count("transport list prefix")
              << ",\"presence_calls\":"
              << count("transport presence") << ",\"get_calls\":"
              << count("transport get") << ",\"remove_calls\":"
              << count("transport remove")
              << ",\"history_reconstructions\":"
              << count("gc.history_reconstructions")
              << ",\"content_classification_us\":"
              << time("gc.content_classification_us")
              << ",\"candidate_audit_us\":"
              << optional_time("gc.candidate_audit_batches",
                               "gc.candidate_audit_us")
              << ",\"content_revalidation_us\":"
              << optional_time("gc.content_revalidations",
                               "gc.content_revalidation_us")
              << ",\"variant_revalidation_us\":"
              << optional_time("gc.variant_revalidations",
                               "gc.variant_revalidation_us")
              << "}\n";
    kasumi::platform::perf_trace::force_enable(false);
    return result;
}

struct Repository {
    HeadReference head;
    std::string live_content;
    std::string orphan_content;
    HeadReference redundant_variant;
};

Repository seed_repository(kasumi::transport::Transport& transport,
                           TempWorkspace& workspace) {
    const auto commit = commit_with_file("live");
    return Repository{
        .head = publish_object(transport, workspace, commit, "head"),
        .live_content = put_content(transport, workspace, "live", "live"),
        .orphan_content = put_content(transport, workspace, "orphan", "orphan"),
        .redundant_variant =
            add_variant_object(transport, workspace, commit, "variant"),
    };
}

TEST(GarbageCollectionTest, RemovesAuthenticatedOrphanContent) {
    LocalFixture fixture;
    const auto orphan = put_content(fixture.storage.transport,
                                    fixture.storage.workspace,
                                    "orphan",
                                    "orphan");
    publish_object(fixture.storage.transport,
                   fixture.storage.workspace,
                   commit_with_file("live"),
                   "head");
    const auto live = put_content(
        fixture.storage.transport, fixture.storage.workspace, "live", "live");

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 1U);
    EXPECT_EQ(result->removed_objects, 1U);
    EXPECT_FALSE(result->analysis_only);
    EXPECT_FALSE(object_present(fixture.storage.transport, orphan));
    EXPECT_TRUE(object_present(fixture.storage.transport, live));
}

TEST(GarbageCollectionTest, RemovesOnlyRedundantValidCommitVariants) {
    LocalFixture fixture;
    const auto repository =
        seed_repository(fixture.storage.transport, fixture.storage.workspace);
    const auto corrupt = put_corrupt_variant(fixture.storage.transport,
                                             fixture.storage.workspace,
                                             commit_with_file("live"),
                                             "corrupt-variant");
    const auto required_path = object_path(repository.head);

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 2U);
    EXPECT_EQ(result->removed_objects, 2U);
    EXPECT_FALSE(object_present(fixture.storage.transport,
                                object_path(repository.redundant_variant)));
    EXPECT_TRUE(object_present(fixture.storage.transport, required_path));
    EXPECT_TRUE(
        object_present(fixture.storage.transport, object_path(corrupt)));
    EXPECT_FALSE(
        object_present(fixture.storage.transport, repository.orphan_content));
}

TEST(GarbageCollectionTest, PreservesCorruptOrphanContent) {
    LocalFixture fixture;
    publish_object(fixture.storage.transport,
                   fixture.storage.workspace,
                   commit_with_file("live"),
                   "head");
    put_content(
        fixture.storage.transport, fixture.storage.workspace, "live", "live");
    const auto valid = put_content(fixture.storage.transport,
                                   fixture.storage.workspace,
                                   "valid-orphan",
                                   "valid-orphan");
    put_corrupt_content(fixture.storage.transport,
                        fixture.storage.workspace,
                        "corrupt-orphan",
                        "corrupt-orphan");
    const auto corrupt = content_identifier("corrupt-orphan");

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 1U);
    EXPECT_EQ(result->removed_objects, 1U);
    EXPECT_FALSE(object_present(fixture.storage.transport, valid));
    EXPECT_TRUE(object_present(fixture.storage.transport, corrupt));
}

TEST(GarbageCollectionTest, PreservesReachableContentAndRequiredHistory) {
    LocalFixture fixture;
    const auto repository =
        seed_repository(fixture.storage.transport, fixture.storage.workspace);

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_TRUE(
        object_present(fixture.storage.transport, repository.live_content));
    EXPECT_TRUE(object_present(fixture.storage.transport,
                               object_path(repository.head)));
    EXPECT_TRUE(object_present(fixture.storage.transport,
                               marker_path(repository.head)));
}

// CONTENT-R01
TEST(GarbageCollectionTest, ContentRevalidationAllowsStillOrphan) {
    LocalFixture fixture;
    publish_object(fixture.storage.transport,
                   fixture.storage.workspace,
                   commit_with_file("live"),
                   "head");
    put_content(
        fixture.storage.transport, fixture.storage.workspace, "live", "live");
    const auto orphan = put_content(fixture.storage.transport,
                                    fixture.storage.workspace,
                                    "revalidated-orphan",
                                    "revalidated-orphan");

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 1U);
    EXPECT_EQ(result->removed_objects, 1U);
    EXPECT_FALSE(object_present(fixture.storage.transport, orphan));
}

// CONTENT-R02
TEST(GarbageCollectionTest, ContentRevalidationBlocksNewlyReachableContent) {
    FakeFixture fixture("gc-content-newly-reachable");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto deferred = commit_with_file("protected");
    const auto deferred_reference = publish_object(
        fixture.transport, fixture.workspace, deferred, "deferred", false);
    const auto content = put_content(
        fixture.transport, fixture.workspace, "protected", "protected");
    ASSERT_EQ(content, content_identifier("protected"));

    after_full_list(fixture.state, 4, [deferred_reference](FakeState& state) {
        state.objects[marker_path(deferred_reference)] =
            marker_bytes(deferred_reference);
    });

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::ConcurrentChange);
    EXPECT_NE(result.error().detail.find("reachable"), std::string::npos);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
    EXPECT_TRUE(object_present(fixture.transport, content));
}

// CONTENT-R03
TEST(GarbageCollectionTest,
     ContentRevalidationBlocksReplacedHistoryPayloadWithSameNamespace) {
    FakeFixture fixture("gc-content-history-replacement");
    const auto head = commit_with_file("live");
    const auto reference =
        publish_object(fixture.transport, fixture.workspace, head, "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto orphan =
        put_content(fixture.transport, fixture.workspace, "orphan", "orphan");
    const auto head_object = object_path(reference);

    after_full_list(fixture.state, 4, [head_object](FakeState& state) {
        state.objects[head_object] = {0xde, 0xad, 0xbe, 0xef};
    });

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::IntegrityFailure);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
    EXPECT_TRUE(object_present(fixture.transport, orphan));
}

// CONTENT-R04
TEST(GarbageCollectionTest, ContentRevalidationBlocksIncompleteHistory) {
    FakeFixture fixture("gc-content-incomplete-history");
    const auto head = commit_with_file("live");
    const auto reference =
        publish_object(fixture.transport, fixture.workspace, head, "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto orphan =
        put_content(fixture.transport, fixture.workspace, "orphan", "orphan");
    const auto head_object = object_path(reference);

    after_full_list(fixture.state, 4, [head_object](FakeState& state) {
        state.objects.erase(head_object);
    });

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::IntegrityFailure);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
    EXPECT_TRUE(object_present(fixture.transport, orphan));
}

// CONTENT-R05
TEST(GarbageCollectionTest,
     PhysicallyValidContentReferencedByHistoryIsPreserved) {
    LocalFixture fixture;
    const auto commit = commit_with_file("protected");
    publish_object(
        fixture.storage.transport, fixture.storage.workspace, commit, "head");
    const auto content = put_content(fixture.storage.transport,
                                     fixture.storage.workspace,
                                     "protected",
                                     "protected");

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 0U);
    EXPECT_EQ(result->removed_objects, 0U);
    EXPECT_TRUE(object_present(fixture.storage.transport, content));
}

TEST(GarbageCollectionTest, MissingReachableContentBlocksAllMutation) {
    LocalFixture fixture;
    const auto commit = commit_with_file("missing");
    publish_object(
        fixture.storage.transport, fixture.storage.workspace, commit, "head");
    const auto orphan = put_content(fixture.storage.transport,
                                    fixture.storage.workspace,
                                    "orphan",
                                    "orphan");

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::IntegrityFailure);
    EXPECT_TRUE(object_present(fixture.storage.transport, orphan));
}

TEST(GarbageCollectionTest, UnknownPhysicalAndHistoryObjectsBlockMutation) {
    LocalFixture fixture;
    const auto repository =
        seed_repository(fixture.storage.transport, fixture.storage.workspace);
    const std::array<std::uint8_t, 1> byte{0};
    put_object_bytes(fixture.storage.transport,
                     fixture.storage.workspace,
                     layout().history_prefix + "unknown/history-object",
                     byte,
                     "unknown-history");

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::IntegrityFailure);
    EXPECT_TRUE(
        object_present(fixture.storage.transport, repository.orphan_content));
    EXPECT_TRUE(object_present(fixture.storage.transport,
                               object_path(repository.redundant_variant)));
}

TEST(GarbageCollectionTest, UnknownStorageObjectsBlockMutation) {
    LocalFixture fixture;
    const auto repository =
        seed_repository(fixture.storage.transport, fixture.storage.workspace);
    const std::array<std::uint8_t, 1> byte{0};
    put_object_bytes(fixture.storage.transport,
                     fixture.storage.workspace,
                     "not-a-content-or-history-object",
                     byte,
                     "unknown-storage");

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::IntegrityFailure);
    EXPECT_TRUE(
        object_present(fixture.storage.transport, repository.orphan_content));
}

TEST(GarbageCollectionTest, UnreachableCommitVariantsArePreserved) {
    LocalFixture fixture;
    const auto reachable = commit_with_file("live");
    publish_object(fixture.storage.transport,
                   fixture.storage.workspace,
                   reachable,
                   "head");
    put_content(
        fixture.storage.transport, fixture.storage.workspace, "live", "live");
    const auto orphan_commit = commit_with_file("unreachable");
    const auto orphan_head = publish_object(fixture.storage.transport,
                                            fixture.storage.workspace,
                                            orphan_commit,
                                            "orphan-commit",
                                            false);
    const auto orphan_variant = add_variant_object(fixture.storage.transport,
                                                   fixture.storage.workspace,
                                                   orphan_commit,
                                                   "orphan-variant");

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 0U);
    EXPECT_EQ(result->removed_objects, 0U);
    EXPECT_TRUE(
        object_present(fixture.storage.transport, object_path(orphan_head)));
    EXPECT_TRUE(
        object_present(fixture.storage.transport, object_path(orphan_variant)));
}

TEST(GarbageCollectionTest, UnmarkedReachableCommitKeepsOneRequiredVariant) {
    LocalFixture fixture;
    const auto parent = commit_with_file("parent");
    const auto child_tree = commit_with_file("child").tree;
    const auto child =
        kasumi::history::make_commit(1, {commit_id(parent)}, child_tree)
            .value();
    const auto parent_head = publish_object(
        fixture.storage.transport, fixture.storage.workspace, parent, "parent");
    publish_object(
        fixture.storage.transport, fixture.storage.workspace, child, "child");
    put_content(
        fixture.storage.transport, fixture.storage.workspace, "child", "child");
    put_content(fixture.storage.transport,
                fixture.storage.workspace,
                "parent",
                "parent");
    ASSERT_TRUE(kasumi::transport::remove(fixture.storage.transport,
                                          marker_path(parent_head)));
    const auto extra = add_variant_object(fixture.storage.transport,
                                          fixture.storage.workspace,
                                          parent,
                                          "parent-extra");

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 1U);
    EXPECT_EQ(result->removed_objects, 1U);
    const bool original_present =
        object_present(fixture.storage.transport, object_path(parent_head));
    const bool extra_present =
        object_present(fixture.storage.transport, object_path(extra));
    EXPECT_NE(original_present, extra_present);
    const auto inventory =
        kasumi::application::history_storage::inventory_reachability(
            fixture.storage.transport,
            test_key(),
            kasumi::test::workspace_root(fixture.storage.workspace));
    ASSERT_TRUE(inventory.has_value()) << inventory.error().detail;
    EXPECT_TRUE(
        std::ranges::find(inventory->reachable_commits, commit_id(parent)) !=
        inventory->reachable_commits.end());
}

TEST(GarbageCollectionTest, CancellationBeforeMutationStopsCleanly) {
    LocalFixture fixture;
    const auto repository =
        seed_repository(fixture.storage.transport, fixture.storage.workspace);
    kasumi::platform::cancellation::reset();
    struct ResetCancellation {
        ~ResetCancellation() {
            kasumi::platform::cancellation::reset();
        }
    } reset_guard;

    const auto result =
        fixture.collect([](const GarbageCollectProgress& progress) {
            if (progress.stage == GarbageCollectStage::Applying) {
                kasumi::platform::cancellation::request();
            }
        });
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::StateFailure);
    EXPECT_TRUE(
        object_present(fixture.storage.transport, repository.orphan_content));
    EXPECT_TRUE(object_present(fixture.storage.transport,
                               object_path(repository.redundant_variant)));
}

TEST(GarbageCollectionTest, UncertainPostRemovalVisibilityStopsRun) {
    FakeFixture fixture("gc-post-removal-visibility");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto first =
        put_content(fixture.transport, fixture.workspace, "orphan-a", "a");
    const auto second =
        put_content(fixture.transport, fixture.workspace, "orphan-b", "b");
    const auto removed = std::min(first, second);
    fixture.state->fail_presence_after_removal_identifier = removed;
    fixture.state->remove_count = 0;

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::TransportFailure);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 1U);
    EXPECT_FALSE(object_present(fixture.transport, removed));
    EXPECT_TRUE(object_present(fixture.transport, std::max(first, second)));
}

// PARTIAL-R01
TEST(GarbageCollectionTest, PartialFailureBeforeFirstRemovalKeepsZeroCounts) {
    FakeFixture fixture("gc-partial-before-first");
    const auto head = commit_with_file("live");
    const auto reference =
        publish_object(fixture.transport, fixture.workspace, head, "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto orphan =
        put_content(fixture.transport, fixture.workspace, "orphan", "orphan");
    const auto head_object = object_path(reference);
    after_full_list(fixture.state, 4, [head_object](FakeState& state) {
        state.objects[head_object] = {0xde, 0xad, 0xbe, 0xef};
    });

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_EQ(diagnostic.candidate_objects, 1U);
    EXPECT_EQ(diagnostic.confirmed_removed, 0U);
    EXPECT_EQ(diagnostic.failed_identifier, std::optional<std::string>{orphan});
    EXPECT_EQ(diagnostic.stage, GarbageCollectStage::Applying);
    EXPECT_EQ(diagnostic.mutation_state,
              kasumi::application::GarbageCollectMutationState::NotAttempted);
    EXPECT_TRUE(diagnostic.barrier_release_attempted);
    EXPECT_TRUE(diagnostic.barrier_release_confirmed);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
}

// PARTIAL-R02
TEST(GarbageCollectionTest, PartialFailureAtThirtySeventhRemovalKeepsCounts) {
    FakeFixture fixture("gc-partial-thirty-seven");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    std::vector<std::string> orphans;
    for (std::size_t index = 0; index < 100; ++index) {
        orphans.push_back(put_content(fixture.transport,
                                      fixture.workspace,
                                      "partial-" + std::to_string(index),
                                      "partial-" + std::to_string(index)));
    }
    std::ranges::sort(orphans);
    fixture.state->fail_candidate_remove_at = 37;
    fixture.state->remove_failure_native_code = 123;

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_EQ(diagnostic.candidate_objects, 100U);
    EXPECT_EQ(diagnostic.confirmed_removed, 36U);
    EXPECT_EQ(diagnostic.failed_identifier,
              std::optional<std::string>{orphans[36]});
    EXPECT_EQ(diagnostic.stage, GarbageCollectStage::Applying);
    EXPECT_EQ(diagnostic.mutation_state,
              kasumi::application::GarbageCollectMutationState::Uncertain);
    ASSERT_TRUE(diagnostic.transport_error.has_value());
    EXPECT_EQ(diagnostic.transport_error->code,
              kasumi::transport::ErrorCode::Io);
    EXPECT_EQ(diagnostic.transport_error->native_code, 123);
    EXPECT_TRUE(diagnostic.barrier_release_attempted);
    EXPECT_TRUE(diagnostic.barrier_release_confirmed);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 37U);
    EXPECT_FALSE(object_present(fixture.transport, orphans[35]));
    EXPECT_TRUE(object_present(fixture.transport, orphans[36]));
    EXPECT_TRUE(object_present(fixture.transport, orphans[37]));
}

// PARTIAL-R03
TEST(GarbageCollectionTest,
     AmbiguousRemovalPreservesNativeCodeAndUncertainMutation) {
    FakeFixture fixture("gc-partial-ambiguous");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto orphan =
        put_content(fixture.transport, fixture.workspace, "orphan", "orphan");
    fixture.state->remove_then_fail_identifier = orphan;
    fixture.state->remove_failure_native_code = 4321;

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_EQ(diagnostic.confirmed_removed, 0U);
    EXPECT_EQ(diagnostic.failed_identifier, std::optional<std::string>{orphan});
    EXPECT_EQ(diagnostic.mutation_state,
              kasumi::application::GarbageCollectMutationState::Uncertain);
    ASSERT_TRUE(diagnostic.transport_error.has_value());
    EXPECT_EQ(diagnostic.transport_error->code,
              kasumi::transport::ErrorCode::Io);
    EXPECT_EQ(diagnostic.transport_error->native_code, 4321);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 1U);
    EXPECT_FALSE(object_present(fixture.transport, orphan));
}

// PARTIAL-R04
TEST(GarbageCollectionTest, PostRemovalPresenceFailureRemainsUncertain) {
    FakeFixture fixture("gc-partial-presence");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto orphan =
        put_content(fixture.transport, fixture.workspace, "orphan", "orphan");
    fixture.state->fail_presence_after_removal_identifier = orphan;

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_EQ(diagnostic.confirmed_removed, 0U);
    EXPECT_EQ(diagnostic.failed_identifier, std::optional<std::string>{orphan});
    EXPECT_EQ(diagnostic.mutation_state,
              kasumi::application::GarbageCollectMutationState::Uncertain);
    ASSERT_TRUE(diagnostic.transport_error.has_value());
    EXPECT_EQ(diagnostic.transport_error->code,
              kasumi::transport::ErrorCode::Io);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 1U);
    EXPECT_FALSE(object_present(fixture.transport, orphan));
}

// PARTIAL-R06 / BARRIER-R07
TEST(GarbageCollectionTest,
     CancellationAfterConfirmedRemovalPreservesCountsAndCleanup) {
    FakeFixture fixture("gc-partial-cancellation");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    std::vector<std::string> orphans;
    for (const std::string_view name : {"cancel-a", "cancel-b", "cancel-c"}) {
        orphans.push_back(
            put_content(fixture.transport, fixture.workspace, name, name));
    }
    std::ranges::sort(orphans);
    kasumi::platform::cancellation::reset();
    struct ResetCancellation {
        ~ResetCancellation() {
            kasumi::platform::cancellation::reset();
        }
    } reset_guard;

    const auto result =
        fixture.collect([&](const GarbageCollectProgress& progress) {
            if (progress.stage == GarbageCollectStage::Applying &&
                progress.removed_objects == 1U) {
                kasumi::platform::cancellation::request();
            }
        });
    ASSERT_FALSE(result.has_value());
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_EQ(diagnostic.candidate_objects, 3U);
    EXPECT_EQ(diagnostic.confirmed_removed, 1U);
    EXPECT_FALSE(diagnostic.failed_identifier.has_value());
    EXPECT_EQ(diagnostic.stage, GarbageCollectStage::Applying);
    EXPECT_EQ(diagnostic.mutation_state,
              kasumi::application::GarbageCollectMutationState::NotAttempted);
    EXPECT_TRUE(diagnostic.barrier_release_attempted);
    EXPECT_TRUE(diagnostic.barrier_release_confirmed);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 1U);
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 1U);
    EXPECT_FALSE(object_present(fixture.transport, orphans.front()));
    EXPECT_TRUE(object_present(fixture.transport, orphans[1]));
    EXPECT_TRUE(object_present(fixture.transport, orphans[2]));
}

TEST(GarbageCollectionTest, AnalysisOnlyDoesNotCountCorruptCandidates) {
    FakeFixture fixture("gc-analysis-only-corrupt");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    put_corrupt_content(
        fixture.transport, fixture.workspace, "corrupt", "corrupt");
    fixture.state->hide_probe_listing = true;
    fixture.state->remove_count = 0;

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_TRUE(result->analysis_only);
    EXPECT_EQ(result->candidate_objects, 0U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
}

TEST(GarbageCollectionTest, ExistingBarrierBlocksBeforeEstablishingOwnership) {
    FakeFixture fixture("gc-existing-barrier");
    seed_repository(fixture.transport, fixture.workspace);
    fixture.state->objects[layout().barrier_identifier] = {1, 2, 3};
    fixture.state->remove_count = 0;

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::ConcurrentChange);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
}

TEST(GarbageCollectionTest, ActiveWriterBlocksMutation) {
    FakeFixture fixture("gc-active-writer");
    seed_repository(fixture.transport, fixture.workspace);
    auto writer = protocol::register_writer(
        fixture.transport,
        layout(),
        kasumi::test::workspace_root(fixture.workspace));
    ASSERT_TRUE(writer.has_value()) << writer.error().detail;
    fixture.state->remove_count = 0;

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::ConcurrentChange);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
    EXPECT_TRUE(protocol::release_registration(*writer));
}

TEST(GarbageCollectionTest, WriterAppearingBetweenRemovalsStopsNextCandidate) {
    FakeFixture fixture("gc-writer-during-apply");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto first =
        put_content(fixture.transport, fixture.workspace, "orphan-a", "a");
    const auto second =
        put_content(fixture.transport, fixture.workspace, "orphan-b", "b");
    const auto first_candidate = std::min(first, second);
    const auto second_candidate = std::max(first, second);
    const auto writer_identifier =
        layout().writers_prefix + "0123456789abcdef0123456789abcdef";
    const std::string writer_payload =
        "kasumi-gc-v1:writer:0123456789abcdef0123456789abcdef";
    fixture.state->on_operation =
        [first_candidate, writer_identifier, writer_payload](
            FakeState& state,
            std::string_view operation,
            std::string_view identifier) {
            if (operation == "after_remove" &&
                identifier == first_candidate) {
                state.objects[writer_identifier] = std::vector<std::uint8_t>(
                    writer_payload.begin(), writer_payload.end());
            }
        };
    fixture.state->remove_attempts.clear();

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::ConcurrentChange);
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_EQ(diagnostic.candidate_objects, 2U);
    EXPECT_EQ(diagnostic.confirmed_removed, 1U);
    EXPECT_EQ(diagnostic.failed_identifier,
              std::optional<std::string>{second_candidate});
    EXPECT_EQ(diagnostic.mutation_state,
              kasumi::application::GarbageCollectMutationState::NotAttempted);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 1U);
    EXPECT_FALSE(object_present(fixture.transport, first_candidate));
    EXPECT_TRUE(object_present(fixture.transport, second_candidate));
    EXPECT_TRUE(object_present(fixture.transport, writer_identifier));
}

TEST(GarbageCollectionTest, BarrierOwnershipIsRecheckedBeforeEachRemoval) {
    FakeFixture fixture("gc-barrier-replaced");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto first =
        put_content(fixture.transport, fixture.workspace, "orphan-a", "a");
    const auto second =
        put_content(fixture.transport, fixture.workspace, "orphan-b", "b");
    fixture.state->replace_barrier_after_source_remove_count = 1;
    fixture.state->remove_count = 0;

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 1U);
    EXPECT_FALSE(object_present(fixture.transport, std::min(first, second)));
    EXPECT_TRUE(object_present(fixture.transport, std::max(first, second)));
}

// BARRIER-R01
TEST(GarbageCollectionTest, SuccessfulRunReleasesBarrierExactlyOnce) {
    FakeFixture fixture("gc-barrier-success");
    seed_repository(fixture.transport, fixture.workspace);
    fixture.state->remove_attempts.clear();

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 1U);
    EXPECT_FALSE(
        object_present(fixture.transport, layout().barrier_identifier));
}

// BARRIER-R02
TEST(GarbageCollectionTest,
     PrimaryFailureKeepsSuccessfulBarrierCleanupDiagnostic) {
    FakeFixture fixture("gc-barrier-primary-cleanup-ok");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto orphan =
        put_content(fixture.transport, fixture.workspace, "orphan", "orphan");
    fixture.state->fail_candidate_remove_at = 1;
    fixture.state->remove_attempts.clear();

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_EQ(diagnostic.failed_identifier, std::optional<std::string>{orphan});
    EXPECT_TRUE(diagnostic.barrier_release_attempted);
    EXPECT_TRUE(diagnostic.barrier_release_confirmed);
    EXPECT_FALSE(diagnostic.barrier_cleanup_error.has_value());
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 1U);
    EXPECT_FALSE(
        object_present(fixture.transport, layout().barrier_identifier));
}

// BARRIER-R03
TEST(GarbageCollectionTest,
     PrimaryAndBarrierCleanupFailuresRemainDistinguishable) {
    FakeFixture fixture("gc-barrier-primary-cleanup-fail");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto orphan =
        put_content(fixture.transport, fixture.workspace, "orphan", "orphan");
    fixture.state->fail_candidate_remove_at = 1;
    fixture.state->fail_remove_identifier = layout().barrier_identifier;
    fixture.state->remove_failure_native_code = 777;
    fixture.state->remove_attempts.clear();

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::TransportFailure);
    EXPECT_NE(result.error().detail.find("candidate remove failure"),
              std::string::npos);
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_EQ(diagnostic.failed_identifier, std::optional<std::string>{orphan});
    EXPECT_TRUE(diagnostic.barrier_release_attempted);
    EXPECT_FALSE(diagnostic.barrier_release_confirmed);
    ASSERT_TRUE(diagnostic.barrier_cleanup_error.has_value());
    EXPECT_NE(diagnostic.barrier_cleanup_error->find("injected remove failure"),
              std::string::npos);
    ASSERT_TRUE(diagnostic.barrier_cleanup_transport_error.has_value());
    EXPECT_EQ(diagnostic.barrier_cleanup_transport_error->code,
              kasumi::transport::ErrorCode::Io);
    EXPECT_EQ(diagnostic.barrier_cleanup_transport_error->native_code, 777);
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 1U);
    EXPECT_TRUE(object_present(fixture.transport, layout().barrier_identifier));
}

// BARRIER-R04
TEST(GarbageCollectionTest, AmbiguousBarrierRemovalIsNotRetriedOrConfirmed) {
    FakeFixture fixture("gc-barrier-ambiguous-release");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto orphan =
        put_content(fixture.transport, fixture.workspace, "orphan", "orphan");
    fixture.state->remove_then_fail_identifier = layout().barrier_identifier;
    fixture.state->remove_failure_native_code = 778;
    fixture.state->remove_attempts.clear();

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_EQ(diagnostic.candidate_objects, 1U);
    EXPECT_EQ(diagnostic.confirmed_removed, 1U);
    EXPECT_EQ(diagnostic.stage, GarbageCollectStage::Finalizing);
    EXPECT_EQ(diagnostic.mutation_state,
              kasumi::application::GarbageCollectMutationState::Confirmed);
    EXPECT_TRUE(diagnostic.barrier_release_attempted);
    EXPECT_FALSE(diagnostic.barrier_release_confirmed);
    ASSERT_TRUE(diagnostic.barrier_cleanup_transport_error.has_value());
    EXPECT_EQ(diagnostic.barrier_cleanup_transport_error->native_code, 778);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 1U);
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 1U);
    EXPECT_FALSE(object_present(fixture.transport, orphan));
    EXPECT_FALSE(
        object_present(fixture.transport, layout().barrier_identifier));
}

// BARRIER-R05
TEST(GarbageCollectionTest, ForeignBarrierIsNotRemovedDuringCleanup) {
    FakeFixture fixture("gc-barrier-foreign-cleanup");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto first =
        put_content(fixture.transport, fixture.workspace, "orphan-a", "a");
    const auto second =
        put_content(fixture.transport, fixture.workspace, "orphan-b", "b");
    fixture.state->replace_barrier_after_source_remove_count = 1;
    fixture.state->remove_attempts.clear();

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_FALSE(diagnostic.barrier_release_attempted);
    EXPECT_FALSE(diagnostic.barrier_release_confirmed);
    ASSERT_TRUE(diagnostic.barrier_cleanup_error.has_value());
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 0U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 1U);
    EXPECT_TRUE(object_present(fixture.transport, layout().barrier_identifier));
    EXPECT_FALSE(object_present(fixture.transport, std::min(first, second)));
    EXPECT_TRUE(object_present(fixture.transport, std::max(first, second)));
}

TEST(GarbageCollectionTest, ExceptionDuringApplyKeepsPartialDiagnostic) {
    FakeFixture fixture("gc-apply-exception");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    std::vector<std::string> orphans;
    for (const std::string_view name : {"apply-a", "apply-b"}) {
        orphans.push_back(
            put_content(fixture.transport, fixture.workspace, name, name));
    }
    std::ranges::sort(orphans);
    fixture.state->on_operation =
        [identifier = orphans.front()](
            FakeState&, std::string_view operation, std::string_view current) {
            if (operation == "before_remove" && current == identifier) {
                throw std::runtime_error("injected apply exception");
            }
        };
    fixture.state->remove_attempts.clear();

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::StateFailure);
    EXPECT_NE(result.error().detail.find("injected apply exception"),
              std::string::npos);
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_EQ(diagnostic.candidate_objects, 2U);
    EXPECT_EQ(diagnostic.confirmed_removed, 0U);
    EXPECT_EQ(diagnostic.failed_identifier,
              std::optional<std::string>{orphans.front()});
    EXPECT_EQ(diagnostic.stage, GarbageCollectStage::Applying);
    EXPECT_EQ(diagnostic.mutation_state,
              kasumi::application::GarbageCollectMutationState::Uncertain);
    EXPECT_TRUE(diagnostic.barrier_release_attempted);
    EXPECT_TRUE(diagnostic.barrier_release_confirmed);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 1U);
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 1U);
    EXPECT_TRUE(object_present(fixture.transport, orphans.front()));
}

// GC-R2.2
TEST(GarbageCollectionTest,
     ExceptionDuringAnalysisAndCleanupFailurePreservesBothErrors) {
    FakeFixture fixture("gc-analysis-cleanup-exception");
    seed_repository(fixture.transport, fixture.workspace);
    fixture.state->on_operation =
        [](FakeState& state, std::string_view operation, std::string_view) {
            if (operation == "after_list" && state.full_list_count == 1) {
                throw std::runtime_error("injected analysis exception");
            }
        };
    fixture.state->fail_remove_identifier = layout().barrier_identifier;
    fixture.state->remove_failure_native_code = 783;
    fixture.state->remove_attempts.clear();

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::StateFailure);
    EXPECT_NE(result.error().detail.find("injected analysis exception"),
              std::string::npos);
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_EQ(diagnostic.stage, GarbageCollectStage::Analyzing);
    EXPECT_EQ(diagnostic.confirmed_removed, 0U);
    EXPECT_EQ(diagnostic.mutation_state,
              kasumi::application::GarbageCollectMutationState::NotAttempted);
    EXPECT_TRUE(diagnostic.barrier_release_attempted);
    EXPECT_FALSE(diagnostic.barrier_release_confirmed);
    ASSERT_TRUE(diagnostic.barrier_cleanup_error.has_value());
    ASSERT_TRUE(diagnostic.barrier_cleanup_transport_error.has_value());
    EXPECT_EQ(diagnostic.barrier_cleanup_transport_error->code,
              kasumi::transport::ErrorCode::Io);
    EXPECT_EQ(diagnostic.barrier_cleanup_transport_error->native_code, 783);
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 1U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
    EXPECT_TRUE(object_present(fixture.transport, layout().barrier_identifier));
}

// BARRIER-R06
TEST(GarbageCollectionTest, ExceptionDuringAnalysisReleasesBarrierOnce) {
    FakeFixture fixture("gc-barrier-exception");
    seed_repository(fixture.transport, fixture.workspace);
    fixture.state->on_operation =
        [](FakeState& state, std::string_view operation, std::string_view) {
            if (operation == "after_list" && state.full_list_count == 1) {
                throw std::runtime_error("injected analysis exception");
            }
        };
    fixture.state->remove_attempts.clear();

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::StateFailure);
    EXPECT_NE(result.error().detail.find("injected analysis exception"),
              std::string::npos);
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 1U);
    EXPECT_FALSE(
        object_present(fixture.transport, layout().barrier_identifier));
}

TEST(GarbageCollectionTest,
     ProbeInvisibilityReturnsAnalysisOnlyWithoutMutation) {
    FakeFixture fixture("gc-probe-hidden");
    const auto repository =
        seed_repository(fixture.transport, fixture.workspace);
    fixture.state->hide_probe_listing = true;
    fixture.state->remove_count = 0;

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_TRUE(result->analysis_only);
    EXPECT_EQ(result->candidate_objects, 2U);
    EXPECT_EQ(result->removed_objects, 0U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
    EXPECT_TRUE(object_present(fixture.transport, repository.orphan_content));
}

TEST(GarbageCollectionTest, ProbeTransportFailureFailsClosed) {
    FakeFixture fixture("gc-probe-failure");
    seed_repository(fixture.transport, fixture.workspace);
    fixture.state->fail_probe_listing = true;
    fixture.state->remove_count = 0;

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::TransportFailure);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
}

TEST(GarbageCollectionTest, DivergentObservationsBlockMutation) {
    FakeFixture fixture("gc-divergent-observation");
    const auto repository =
        seed_repository(fixture.transport, fixture.workspace);
    const auto hidden =
        put_content(fixture.transport, fixture.workspace, "hidden", "hidden");
    const auto bytes = fixture.state->objects.at(hidden);
    fixture.state->objects.erase(hidden);
    fixture.state->hidden_objects[hidden] = bytes;
    fixture.state->on_operation =
        [](FakeState& state, std::string_view operation, std::string_view) {
            if (operation == "after_list" && state.full_list_count == 1 &&
                !state.hidden_objects.empty()) {
                state.objects.merge(state.hidden_objects);
            }
        };
    fixture.state->remove_count = 0;

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::ConcurrentChange);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
    EXPECT_TRUE(object_present(fixture.transport, repository.orphan_content));
}

TEST(GarbageCollectionTest, ListedCandidateMissingOnPresenceBlocksMutation) {
    FakeFixture fixture("gc-presence-divergence");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto orphan =
        put_content(fixture.transport, fixture.workspace, "extra", "extra");
    bool erased = false;
    fixture.state->on_operation = [orphan,
                                   &erased](FakeState& state,
                                            std::string_view operation,
                                            std::string_view identifier) {
        if (!erased && operation == "presence" && identifier == orphan) {
            erased = true;
            state.objects.erase(std::string{identifier});
        }
    };
    fixture.state->remove_count = 0;

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::ConcurrentChange);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
}

TEST(GarbageCollectionTest, RemovalFailureIsNotRetried) {
    FakeFixture fixture("gc-remove-failure");
    seed_repository(fixture.transport, fixture.workspace);
    const auto extra =
        put_content(fixture.transport, fixture.workspace, "extra", "extra");
    fixture.state->fail_candidate_remove_at = 1;
    fixture.state->remove_failure_native_code = 23;
    fixture.state->remove_count = 0;

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::TransportFailure);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 1U);
    EXPECT_TRUE(object_present(fixture.transport, extra));
}

TEST(GarbageCollectionTest, AmbiguousRemovalStopsWithoutCompensatingRetry) {
    FakeFixture fixture("gc-ambiguous-remove");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto first =
        put_content(fixture.transport, fixture.workspace, "orphan-a", "a");
    const auto second =
        put_content(fixture.transport, fixture.workspace, "orphan-b", "b");
    const auto removed = std::min(first, second);
    fixture.state->remove_then_fail_identifier = removed;
    fixture.state->remove_failure_native_code = 41;
    fixture.state->remove_count = 0;

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::TransportFailure);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 1U);
    EXPECT_FALSE(object_present(fixture.transport, removed));
    EXPECT_TRUE(object_present(fixture.transport, std::max(first, second)));
}

TEST(GarbageCollectionTest,
     TransportRemoveDoesNotTurnAmbiguousFailureIntoSuccess) {
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    ASSERT_TRUE(kasumi::transport::initialize(transport));
    const std::string identifier = "ambiguous-object";
    state->objects[identifier] = {1, 2, 3};
    state->remove_then_fail_identifier = identifier;
    state->remove_failure_native_code = 99;
    state->remove_count = 0;
    state->presence_count = 0;

    const auto result = kasumi::transport::remove(transport, identifier);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, kasumi::transport::ErrorCode::Io);
    EXPECT_EQ(result.error().native_code, 99);
    EXPECT_EQ(state->remove_count, 1U);
    EXPECT_EQ(state->presence_count, 0U);
    EXPECT_FALSE(object_present(transport, identifier));
}

TEST(GarbageCollectionTest, GarbageCollectFsckGarbageCollectRoundTrip) {
    LocalFixture fixture;
    const auto repository =
        seed_repository(fixture.storage.transport, fixture.storage.workspace);
    const Epoch epoch{
        .vault_id = std::string(64, 'a'),
        .sequence = 0,
        .issued_at = 1,
        .policy = {},
        .anchors = {Anchor{.commit_id = repository.head.commit_id,
                           .height = 0}},
    };
    const auto sealed =
        kasumi::application::history_storage::epoch::seal(epoch, test_key());
    ASSERT_TRUE(sealed.has_value()) << sealed.error().detail;
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        fixture.storage.transport,
        test_key(),
        *sealed,
        kasumi::test::workspace_root(fixture.storage.workspace)));
    const auto epoch_object =
        kasumi::application::history_storage::epoch::object_identifier(
            layout(), sealed->reference);
    ASSERT_TRUE(epoch_object.has_value());

    const auto first = fixture.collect();
    ASSERT_TRUE(first.has_value()) << first.error().detail;
    EXPECT_EQ(first->candidate_objects, 2U);
    EXPECT_EQ(first->removed_objects, 2U);
    EXPECT_FALSE(
        object_present(fixture.storage.transport, repository.orphan_content));
    EXPECT_FALSE(object_present(fixture.storage.transport,
                                object_path(repository.redundant_variant)));
    EXPECT_TRUE(
        object_present(fixture.storage.transport, repository.live_content));
    EXPECT_TRUE(object_present(fixture.storage.transport,
                               object_path(repository.head)));
    EXPECT_TRUE(object_present(fixture.storage.transport, *epoch_object));

    const auto audit = kasumi::application::integrity::fsck(
        fixture.runtime, fixture.storage.transport, test_key(), 1);
    ASSERT_TRUE(audit.has_value()) << audit.error().detail;
    EXPECT_GT(audit->checked_objects, 0U);
    EXPECT_EQ(audit->repaired_objects, 0U);

    const auto second = fixture.collect();
    ASSERT_TRUE(second.has_value()) << second.error().detail;
    EXPECT_EQ(second->candidate_objects, 0U);
    EXPECT_EQ(second->removed_objects, 0U);
}

TEST(GarbageCollectionTest, SecondCollectionIsIdempotent) {
    LocalFixture fixture;
    seed_repository(fixture.storage.transport, fixture.storage.workspace);
    const auto first = fixture.collect();
    ASSERT_TRUE(first.has_value()) << first.error().detail;
    EXPECT_EQ(first->removed_objects, 2U);

    const auto second = fixture.collect();
    ASSERT_TRUE(second.has_value()) << second.error().detail;
    EXPECT_EQ(second->candidate_objects, 0U);
    EXPECT_EQ(second->removed_objects, 0U);
    EXPECT_FALSE(second->analysis_only);
}

TEST(GarbageCollectionTest, ProgressReportsAllStagesAndConfirmedRemovals) {
    LocalFixture fixture;
    seed_repository(fixture.storage.transport, fixture.storage.workspace);
    std::vector<GarbageCollectProgress> progress;

    const auto result =
        fixture.collect([&progress](const GarbageCollectProgress& value) {
            progress.push_back(value);
        });
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_FALSE(progress.empty());
    EXPECT_EQ(progress.front().stage, GarbageCollectStage::Preparing);
    const auto analyzing = std::ranges::find(progress,
                                             GarbageCollectStage::Analyzing,
                                             &GarbageCollectProgress::stage);
    const auto applying = std::ranges::find(progress,
                                            GarbageCollectStage::Applying,
                                            &GarbageCollectProgress::stage);
    ASSERT_NE(analyzing, progress.end());
    ASSERT_NE(applying, progress.end());
    EXPECT_NE(analyzing, applying);
    EXPECT_EQ(progress.back().stage, GarbageCollectStage::Finalizing);
    EXPECT_EQ(progress.back().removed_objects, 2U);
    EXPECT_EQ(applying->candidate_count, std::optional<std::size_t>{2});
}

TEST(GarbageCollectionTest, LegacyConcurrencyHintsAreValidated) {
    LocalFixture fixture;
    seed_repository(fixture.storage.transport, fixture.storage.workspace);

    const auto invalid = kasumi::application::integrity::garbage_collect(
        fixture.runtime, fixture.storage.transport, test_key(), 1, 0, 1);
    ASSERT_FALSE(invalid.has_value());
    EXPECT_EQ(invalid.error().code,
              kasumi::application::integrity::ErrorCode::InvalidInput);

    const auto valid = kasumi::application::integrity::garbage_collect(
        fixture.runtime, fixture.storage.transport, test_key(), 2, 3, 4);
    ASSERT_TRUE(valid.has_value()) << valid.error().detail;
    EXPECT_EQ(valid->removed_objects, 2U);
}

TEST(GarbageCollectionTest, FailureInjectionPositionsStopAfterOneAttempt) {
    for (const std::size_t position : {0U, 1U, 5U, 50U, 99U}) {
        SCOPED_TRACE("candidate position " + std::to_string(position));
        FakeFixture fixture("gc-injection");
        publish_object(fixture.transport,
                       fixture.workspace,
                       commit_with_file("live"),
                       "head");
        put_content(fixture.transport, fixture.workspace, "live", "live");
        std::vector<std::string> orphans;
        for (std::size_t index = 0; index < 100; ++index) {
            orphans.push_back(put_content(fixture.transport,
                                          fixture.workspace,
                                          "orphan-" + std::to_string(index),
                                          "orphan-" + std::to_string(index)));
        }
        std::ranges::sort(orphans);
        fixture.state->fail_candidate_remove_at = position;

        const auto result = fixture.collect();
        if (position == 0) {
            ASSERT_TRUE(result.has_value()) << result.error().detail;
            EXPECT_EQ(result->candidate_objects, 100U);
            EXPECT_EQ(result->removed_objects, 100U);
            EXPECT_EQ(candidate_remove_attempts(*fixture.state), 100U);
            continue;
        }
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code,
                  kasumi::application::integrity::ErrorCode::TransportFailure);
        EXPECT_EQ(candidate_remove_attempts(*fixture.state), position);
        if (position > 1) {
            EXPECT_FALSE(
                object_present(fixture.transport, orphans[position - 2]));
        }
        EXPECT_TRUE(object_present(fixture.transport, orphans[position - 1]));
    }
}

TEST(GarbageCollectionBenchmarkTest, ZeroCandidates) {
    LocalFixture fixture;
    publish_object(fixture.storage.transport,
                   fixture.storage.workspace,
                   commit_with_file("live"),
                   "bench-zero-head");
    const auto protected_content = put_content(
        fixture.storage.transport, fixture.storage.workspace, "live", "bench-live");

    const auto result = measure_gc(fixture, "0_candidates");
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 0U);
    EXPECT_EQ(result->removed_objects, 0U);
    EXPECT_TRUE(object_present(fixture.storage.transport, protected_content));
}

TEST(GarbageCollectionBenchmarkTest, TenOrphanContents) {
    LocalFixture fixture;
    publish_object(fixture.storage.transport,
                   fixture.storage.workspace,
                   commit_with_file("live"),
                   "bench-ten-head");
    const auto protected_content = put_content(
        fixture.storage.transport, fixture.storage.workspace, "live", "bench-ten-live");
    std::vector<std::string> orphans;
    for (std::size_t index = 0; index < 10; ++index) {
        const auto contents = "bench-ten-orphan-" + std::to_string(index);
        orphans.push_back(put_content(fixture.storage.transport,
                                      fixture.storage.workspace,
                                      contents,
                                      contents));
    }

    const auto result = measure_gc(fixture, "10_content_orphans");
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 10U);
    EXPECT_EQ(result->removed_objects, 10U);
    EXPECT_TRUE(object_present(fixture.storage.transport, protected_content));
    EXPECT_TRUE(std::ranges::all_of(orphans, [&](const auto& identifier) {
        return !object_present(fixture.storage.transport, identifier);
    }));
}

TEST(GarbageCollectionBenchmarkTest, OneHundredContentOrphans) {
    LocalFixture fixture;
    publish_object(fixture.storage.transport,
                   fixture.storage.workspace,
                   commit_with_file("live"),
                   "head");
    put_content(
        fixture.storage.transport, fixture.storage.workspace, "live", "live");
    std::vector<std::string> orphans;
    for (std::size_t index = 0; index < 100; ++index) {
        orphans.push_back(put_content(fixture.storage.transport,
                                      fixture.storage.workspace,
                                      "load-content-" + std::to_string(index),
                                      "load-content-" + std::to_string(index)));
    }

    const auto result = measure_gc(fixture, "100_content_orphans");
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 100U);
    EXPECT_EQ(result->removed_objects, 100U);
    EXPECT_TRUE(std::ranges::all_of(orphans, [&](const auto& identifier) {
        return !object_present(fixture.storage.transport, identifier);
    }));
}

TEST(GarbageCollectionBenchmarkTest, OneHundredRedundantVariants) {
    LocalFixture fixture;
    const auto parent = commit_with_file("parent");
    const auto child_tree = commit_with_file("child").tree;
    const auto child =
        kasumi::history::make_commit(1, {commit_id(parent)}, child_tree)
            .value();
    publish_object(fixture.storage.transport,
                   fixture.storage.workspace,
                   parent,
                   "load-parent");
    publish_object(fixture.storage.transport,
                   fixture.storage.workspace,
                   child,
                   "load-child");
    put_content(fixture.storage.transport,
                fixture.storage.workspace,
                "parent",
                "load-parent-content");
    put_content(fixture.storage.transport,
                fixture.storage.workspace,
                "child",
                "load-child-content");
    std::vector<HeadReference> variants;
    for (std::size_t index = 0; index < 50; ++index) {
        variants.push_back(
            add_variant_object(fixture.storage.transport,
                               fixture.storage.workspace,
                               parent,
                               "load-parent-variant-" + std::to_string(index)));
        variants.push_back(
            add_variant_object(fixture.storage.transport,
                               fixture.storage.workspace,
                               child,
                               "load-child-variant-" + std::to_string(index)));
    }

    const auto result = measure_gc(fixture, "100_redundant_commit_variants");
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 100U);
    EXPECT_EQ(result->removed_objects, 100U);
    EXPECT_TRUE(std::ranges::all_of(variants, [&](const auto& variant) {
        return !object_present(fixture.storage.transport, object_path(variant));
    }));
    const auto inventory =
        kasumi::application::history_storage::inventory_reachability(
            fixture.storage.transport,
            test_key(),
            kasumi::test::workspace_root(fixture.storage.workspace));
    ASSERT_TRUE(inventory.has_value()) << inventory.error().detail;
    EXPECT_EQ(inventory->logical_heads.size(), 2U);
}

TEST(GarbageCollectionTest, LocalLoadRemovesHybridCandidates) {
    LocalFixture fixture;
    const auto commit = commit_with_file("live");
    publish_object(
        fixture.storage.transport, fixture.storage.workspace, commit, "head");
    put_content(
        fixture.storage.transport, fixture.storage.workspace, "live", "live");
    for (std::size_t index = 0; index < 50; ++index) {
        add_variant_object(fixture.storage.transport,
                           fixture.storage.workspace,
                           commit,
                           "hybrid-variant-" + std::to_string(index));
        put_content(fixture.storage.transport,
                    fixture.storage.workspace,
                    "hybrid-content-" + std::to_string(index),
                    "hybrid-content-" + std::to_string(index));
    }

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 100U);
    EXPECT_EQ(result->removed_objects, 100U);
}

TEST(GarbageCollectionTest,
     DISABLED_LocalLoadRemovesOneThousandContentCandidates) {
    LocalFixture fixture;
    publish_object(fixture.storage.transport,
                   fixture.storage.workspace,
                   commit_with_file("live"),
                   "head");
    put_content(
        fixture.storage.transport, fixture.storage.workspace, "live", "live");
    for (std::size_t index = 0; index < 1000; ++index) {
        put_content(fixture.storage.transport,
                    fixture.storage.workspace,
                    "thousand-" + std::to_string(index),
                    "thousand-" + std::to_string(index));
    }

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 1000U);
    EXPECT_EQ(result->removed_objects, 1000U);
}

TEST(GarbageCollectionTest, EpochRetentionIsPreserved) {
    LocalFixture fixture;
    const auto commit = commit_with_file("live");
    publish_object(
        fixture.storage.transport, fixture.storage.workspace, commit, "head");
    put_content(
        fixture.storage.transport, fixture.storage.workspace, "live", "live");
    const auto orphan = put_content(fixture.storage.transport,
                                    fixture.storage.workspace,
                                    "orphan",
                                    "orphan");
    add_variant_object(fixture.storage.transport,
                       fixture.storage.workspace,
                       commit,
                       "variant");
    const Epoch epoch{
        .vault_id = std::string(64, 'a'),
        .sequence = 0,
        .issued_at = 1,
        .policy = {},
        .anchors = {Anchor{.commit_id = commit_id(commit), .height = 0}},
    };
    const auto sealed =
        kasumi::application::history_storage::epoch::seal(epoch, test_key());
    ASSERT_TRUE(sealed.has_value()) << sealed.error().detail;
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        fixture.storage.transport,
        test_key(),
        *sealed,
        kasumi::test::workspace_root(fixture.storage.workspace)));
    const auto epoch_object =
        kasumi::application::history_storage::epoch::object_identifier(
            layout(), sealed->reference);
    ASSERT_TRUE(epoch_object.has_value());

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->removed_objects, 2U);
    EXPECT_FALSE(object_present(fixture.storage.transport, orphan));
    EXPECT_TRUE(object_present(fixture.storage.transport, *epoch_object));
}

} // namespace
