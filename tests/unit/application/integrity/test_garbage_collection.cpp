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
              << ",\"candidate_remove_acknowledged\":"
              << count("gc.candidate_remove_acknowledged")
              << ",\"analysis_get_calls\":"
              << count("gc.analysis_get_calls")
              << ",\"analysis_list_calls\":"
              << count("gc.analysis_list_calls")
              << ",\"analysis_presence_calls\":"
              << count("gc.analysis_presence_calls")
              << ",\"apply_get_calls\":"
              << count("gc.apply_get_calls")
              << ",\"apply_list_calls\":"
              << count("gc.apply_list_calls")
              << ",\"apply_presence_calls\":"
              << count("gc.apply_presence_calls")
              << ",\"list_calls\":"
              << count("transport list") + count("transport list prefix")
              << ",\"presence_calls\":"
              << count("transport presence") << ",\"get_calls\":"
              << count("transport get") << ",\"remove_calls\":"
              << count("transport remove")
              << ",\"history_reconstructions\":"
              << count("gc.history_reconstructions")
              << ",\"history_reconstruction_attempts\":"
              << count("gc.history_reconstruction_attempts")
              << ",\"omitted_variant_downloads\":"
              << count("gc.variant_revalidation_omitted_objects")
              << ",\"commit_authentications\":"
              << count("commit.decrypt_auth_count")
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
    if (result) {
        auto audited = kasumi::application::integrity::fsck(
            fixture.runtime, fixture.storage.transport, test_key());
        EXPECT_TRUE(audited.has_value())
            << (audited ? "" : audited.error().detail);
        std::cerr << "GC_FSCK {\"scenario\":\"" << scenario
                  << "\",\"passed\":" << (audited ? "true" : "false")
                  << "}\n";
    }
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

TEST(GarbageCollectionTest, BarrierReplacementBeforeApplyPreventsAllDeletes) {
    for (const bool physical_hash : {false, true}) {
        SCOPED_TRACE(physical_hash);
        FakeFixture fixture("gc-pre-apply-replacement");
        seed_repository(fixture.transport, fixture.workspace);
        fixture.state->physical_hash_supported = physical_hash;
        auto expected = fixture.state->objects;
        std::vector<std::uint8_t> replacement;

        const auto result =
            fixture.collect([&](const GarbageCollectProgress& progress) {
                if (progress.stage == GarbageCollectStage::Applying &&
                    progress.removed_objects == 0) {
                    replace_barrier_contents(fixture.state,
                                             layout().barrier_identifier);
                    replacement =
                        fixture.state->objects.at(layout().barrier_identifier);
                }
            });

        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code,
                  kasumi::application::integrity::ErrorCode::ConcurrentChange);
        ASSERT_TRUE(result.error().garbage_collection.has_value());
        const auto& diagnostic = *result.error().garbage_collection;
        EXPECT_EQ(diagnostic.candidate_objects, 2U);
        EXPECT_EQ(diagnostic.confirmed_removed, 0U);
        EXPECT_EQ(
            diagnostic.mutation_state,
            kasumi::application::GarbageCollectMutationState::NotAttempted);
        EXPECT_FALSE(diagnostic.barrier_release_attempted);
        EXPECT_FALSE(diagnostic.barrier_release_confirmed);
        EXPECT_TRUE(diagnostic.barrier_cleanup_error.has_value());
        EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
        EXPECT_EQ(barrier_remove_attempts(*fixture.state), 0U);
        expected[layout().barrier_identifier] = replacement;
        EXPECT_EQ(fixture.state->objects, expected);
    }
}

TEST(GarbageCollectionTest, BarrierDisappearanceBeforeApplyPreventsAllDeletes) {
    for (const bool physical_hash : {false, true}) {
        SCOPED_TRACE(physical_hash);
        FakeFixture fixture("gc-pre-apply-disappearance");
        seed_repository(fixture.transport, fixture.workspace);
        fixture.state->physical_hash_supported = physical_hash;
        const auto expected = fixture.state->objects;

        const auto result =
            fixture.collect([&](const GarbageCollectProgress& progress) {
                if (progress.stage == GarbageCollectStage::Applying &&
                    progress.removed_objects == 0) {
                    fixture.state->objects.erase(layout().barrier_identifier);
                    fixture.state->physical_hashes.erase(
                        layout().barrier_identifier);
                }
            });

        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code,
                  kasumi::application::integrity::ErrorCode::ConcurrentChange);
        ASSERT_TRUE(result.error().garbage_collection.has_value());
        EXPECT_EQ(result.error().garbage_collection->confirmed_removed, 0U);
        EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
        EXPECT_EQ(barrier_remove_attempts(*fixture.state), 0U);
        EXPECT_EQ(fixture.state->objects, expected);
    }
}

TEST(GarbageCollectionTest,
     PreApplyOwnershipTransportFailureKeepsOriginalError) {
    FakeFixture fixture("gc-pre-apply-transport");
    seed_repository(fixture.transport, fixture.workspace);
    fixture.state->physical_hash_supported = true;
    auto expected = fixture.state->objects;
    std::size_t hashes_before_apply = 0;

    const auto result =
        fixture.collect([&](const GarbageCollectProgress& progress) {
            if (progress.stage == GarbageCollectStage::Applying &&
                progress.removed_objects == 0) {
                hashes_before_apply = fixture.state->physical_hash_count;
                fixture.state->physical_hash_failure_identifier =
                    layout().barrier_identifier;
                fixture.state->physical_hash_failure =
                    kasumi::transport::ErrorCode::Timeout;
                fixture.state->physical_hash_failure_native_code = 10060;
                expected[layout().barrier_identifier] =
                    fixture.state->objects.at(layout().barrier_identifier);
            }
        });

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::TransportFailure);
    ASSERT_TRUE(result.error().transport_failure.has_value());
    EXPECT_EQ(result.error().transport_failure->code,
              kasumi::transport::ErrorCode::Timeout);
    EXPECT_EQ(result.error().transport_failure->native_code, 10060);
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_EQ(diagnostic.candidate_objects, 2U);
    EXPECT_EQ(diagnostic.confirmed_removed, 0U);
    EXPECT_EQ(diagnostic.mutation_state,
              kasumi::application::GarbageCollectMutationState::NotAttempted);
    ASSERT_TRUE(diagnostic.transport_error.has_value());
    EXPECT_EQ(diagnostic.transport_error->native_code, 10060);
    EXPECT_TRUE(diagnostic.barrier_cleanup_error.has_value());
    EXPECT_FALSE(diagnostic.barrier_release_attempted);
    EXPECT_FALSE(diagnostic.barrier_release_confirmed);
    EXPECT_EQ(fixture.state->physical_hash_count - hashes_before_apply, 2U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 0U);
    EXPECT_EQ(fixture.state->objects, expected);
}

TEST(GarbageCollectionTest,
     CancellationBeforeFirstDeleteCleansUpWithoutMutation) {
    FakeFixture fixture("gc-cancel-before-delete");
    seed_repository(fixture.transport, fixture.workspace);
    const auto expected = fixture.state->objects;
    struct ResetCancellation {
        ~ResetCancellation() {
            kasumi::platform::cancellation::reset();
        }
    } reset_guard;
    kasumi::platform::cancellation::reset();

    const auto result =
        fixture.collect([](const GarbageCollectProgress& progress) {
            if (progress.stage == GarbageCollectStage::Applying) {
                kasumi::platform::cancellation::request();
            }
        });

    ASSERT_FALSE(result.has_value());
    EXPECT_NE(result.error().detail.find("cancelled"), std::string::npos);
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_EQ(diagnostic.candidate_objects, 2U);
    EXPECT_EQ(diagnostic.confirmed_removed, 0U);
    EXPECT_FALSE(diagnostic.failed_identifier.has_value());
    EXPECT_EQ(diagnostic.mutation_state,
              kasumi::application::GarbageCollectMutationState::NotAttempted);
    EXPECT_TRUE(diagnostic.barrier_release_confirmed);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 1U);
    EXPECT_EQ(fixture.state->objects, expected);
}

TEST(GarbageCollectionTest,
     DeleteExceptionAfterPartialApplyAndCleanupIsNotRetried) {
    FakeFixture fixture("gc-partial-exception-cleanup");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    std::vector<std::string> orphans;
    for (const auto name : {"exception-a", "exception-b", "exception-c"}) {
        orphans.push_back(
            put_content(fixture.transport, fixture.workspace, name, name));
    }
    std::ranges::sort(orphans);
    fixture.state->on_operation =
        [&](FakeState&, std::string_view op, std::string_view id) {
            if (op == "after_remove" && id == orphans[1]) {
                throw std::runtime_error("candidate exception after effect");
            }
            if (op == "before_remove" && id == layout().barrier_identifier) {
                throw std::runtime_error("cleanup exception");
            }
        };

    const auto result = fixture.collect();

    ASSERT_FALSE(result.has_value());
    EXPECT_NE(result.error().detail.find("candidate exception after effect"),
              std::string::npos);
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_EQ(diagnostic.confirmed_removed, 1U);
    EXPECT_EQ(diagnostic.failed_identifier,
              std::optional<std::string>{orphans[1]});
    EXPECT_EQ(diagnostic.mutation_state,
              kasumi::application::GarbageCollectMutationState::Uncertain);
    ASSERT_TRUE(diagnostic.barrier_cleanup_error.has_value());
    EXPECT_NE(diagnostic.barrier_cleanup_error->find("cleanup exception"),
              std::string::npos);
    EXPECT_TRUE(diagnostic.barrier_release_attempted);
    EXPECT_FALSE(diagnostic.barrier_release_confirmed);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 2U);
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 1U);
    EXPECT_FALSE(fixture.state->objects.contains(orphans[0]));
    EXPECT_FALSE(fixture.state->objects.contains(orphans[1]));
    EXPECT_TRUE(fixture.state->objects.contains(orphans[2]));
    EXPECT_TRUE(fixture.state->objects.contains(layout().barrier_identifier));
}

TEST(GarbageCollectionTest, DeleteErrorCategoryDoesNotProveNoMutation) {
    using kasumi::transport::ErrorCode;
    for (const auto code : {ErrorCode::PermissionDenied,
                            ErrorCode::ProtocolFailure,
                            ErrorCode::Unknown,
                            ErrorCode::Timeout}) {
        SCOPED_TRACE(kasumi::transport::error_code_name(code));
        FakeFixture fixture("gc-delete-error-state");
        publish_object(fixture.transport,
                       fixture.workspace,
                       commit_with_file("live"),
                       "head");
        put_content(fixture.transport, fixture.workspace, "live", "live");
        std::vector<std::string> orphans;
        for (const auto name : {"error-a", "error-b", "error-c"}) {
            orphans.push_back(
                put_content(fixture.transport, fixture.workspace, name, name));
        }
        std::ranges::sort(orphans);
        fixture.state->remove_then_fail_identifier = orphans[1];
        fixture.state->fail_remove_code = code;
        fixture.state->remove_failure_native_code = 10054;

        const auto result = fixture.collect();

        ASSERT_FALSE(result.has_value());
        ASSERT_TRUE(result.error().garbage_collection.has_value());
        const auto& diagnostic = *result.error().garbage_collection;
        EXPECT_EQ(diagnostic.confirmed_removed, 1U);
        EXPECT_EQ(diagnostic.failed_identifier,
                  std::optional<std::string>{orphans[1]});
        EXPECT_EQ(diagnostic.mutation_state,
                  kasumi::application::GarbageCollectMutationState::Uncertain);
        ASSERT_TRUE(diagnostic.transport_error.has_value());
        EXPECT_EQ(diagnostic.transport_error->code, code);
        EXPECT_EQ(diagnostic.transport_error->native_code, 10054);
        EXPECT_TRUE(diagnostic.barrier_release_confirmed);
        EXPECT_EQ(candidate_remove_attempts(*fixture.state), 2U);
        EXPECT_EQ(barrier_remove_attempts(*fixture.state), 1U);
        EXPECT_FALSE(fixture.state->objects.contains(orphans[0]));
        EXPECT_FALSE(fixture.state->objects.contains(orphans[1]));
        EXPECT_TRUE(fixture.state->objects.contains(orphans[2]));
    }
}

TEST(GarbageCollectionTest, OwnershipChecksStayFixedWithOneThousandCandidates) {
    for (const bool physical_hash : {false, true}) {
        for (const std::size_t count : {1U, 1000U}) {
            SCOPED_TRACE(physical_hash);
            SCOPED_TRACE(count);
            FakeFixture fixture("gc-fixed-ownership-checks");
            publish_object(fixture.transport,
                           fixture.workspace,
                           commit_with_file("live"),
                           "head");
            put_content(fixture.transport, fixture.workspace, "live", "live");
            for (std::size_t index = 0; index < count; ++index) {
                const auto contents = "fixed-" + std::to_string(index);
                put_corrupt_content(
                    fixture.transport, fixture.workspace, contents, contents);
                fixture.state->observed_payload_identifiers.insert(
                    content_identifier(contents));
            }
            fixture.state->physical_hash_supported = physical_hash;
            std::size_t control_gets = 0;
            std::array<std::size_t, 3> before_apply{}, after_apply{};
            std::chrono::steady_clock::time_point apply_started;
            std::int64_t first_delete_delay_us = 0;
            fixture.state->on_operation = [&](FakeState&,
                                              std::string_view op,
                                              std::string_view id) {
                if (op == "get" && id == layout().barrier_identifier) {
                    ++control_gets;
                }
                if (op == "before_remove" &&
                    fixture.state->candidate_remove_count == 1 &&
                    !protocol::is_control_object(layout(), id)) {
                    first_delete_delay_us =
                        std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - apply_started)
                            .count();
                }
            };

            const auto result =
                fixture.collect([&](const GarbageCollectProgress& progress) {
                    const std::array counters{fixture.state->get_count,
                                              fixture.state->list_count,
                                              fixture.state->presence_count};
                    if (progress.stage == GarbageCollectStage::Applying &&
                        progress.removed_objects == 0) {
                        before_apply = counters;
                        apply_started = std::chrono::steady_clock::now();
                    } else if (progress.stage ==
                               GarbageCollectStage::Finalizing) {
                        after_apply = counters;
                    }
                });

            ASSERT_TRUE(result.has_value()) << result.error().detail;
            EXPECT_EQ(result->candidate_objects, count);
            EXPECT_EQ(result->removed_objects, count);
            const auto ownership_hashes = std::ranges::count(
                fixture.state->gc_events,
                "physical_hash:" + layout().barrier_identifier);
            EXPECT_EQ(
                ownership_hashes,
                5U); // Acquisition, admission, pre-Apply, two cleanup checks.
            EXPECT_EQ(control_gets, physical_hash ? 0U : 5U);
            EXPECT_EQ(after_apply[0] - before_apply[0],
                      physical_hash ? 0U : 1U);
            EXPECT_EQ(after_apply[1], before_apply[1]);
            EXPECT_EQ(after_apply[2], before_apply[2]);
            EXPECT_EQ(fixture.state->full_list_count, 1U);
            EXPECT_EQ(fixture.state->commit_get_count, 1U);
            EXPECT_EQ(fixture.state->marker_get_count, 1U);
            EXPECT_EQ(fixture.state->orphan_payload_get_count, 0U);
            EXPECT_EQ(candidate_remove_attempts(*fixture.state), count);
            EXPECT_EQ(fixture.state->remove_batch_count, 0U);
            std::cout << "GC_PRE_APPLY candidates=" << count
                      << " physical_hash=" << physical_hash
                      << " first_delete_delay_us=" << first_delete_delay_us
                      << '\n';
        }
    }
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

TEST(GarbageCollectionTest, RemovesCorruptOrphanContent) {
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
    EXPECT_EQ(result->candidate_objects, 2U);
    EXPECT_EQ(result->removed_objects, 2U);
    EXPECT_FALSE(object_present(fixture.storage.transport, valid));
    EXPECT_FALSE(object_present(fixture.storage.transport, corrupt));
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

// CONTENT-R02: under the cooperative contract, reachability is established by
// the single authenticated observation, not revalidated per candidate.
TEST(GarbageCollectionTest,
     AnalysisPreservesContentMadeReachableBeforeObservation) {
    FakeFixture fixture("gc-content-reachable");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto deferred = commit_with_file("protected");
    const auto deferred_reference = publish_object(
        fixture.transport, fixture.workspace, deferred, "deferred", false);
    const auto content = put_content(
        fixture.transport, fixture.workspace, "protected", "protected");
    ASSERT_EQ(content, content_identifier("protected"));
    fixture.state->objects[marker_path(deferred_reference)] =
        marker_bytes(deferred_reference);

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 0U);
    EXPECT_EQ(result->removed_objects, 0U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
    EXPECT_TRUE(object_present(fixture.transport, content));
}

// CONTENT-R03: a history payload replaced between LIST and GET is still inside
// the analysis window, so it fails closed before any mutation.
TEST(GarbageCollectionTest, AnalysisRejectsHistoryPayloadReplacedAfterListing) {
    FakeFixture fixture("gc-content-history-replacement");
    const auto head = commit_with_file("live");
    const auto reference =
        publish_object(fixture.transport, fixture.workspace, head, "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto orphan =
        put_content(fixture.transport, fixture.workspace, "orphan", "orphan");
    const auto head_object = object_path(reference);

    after_full_list(fixture.state, 1, [head_object](FakeState& state) {
        state.objects[head_object] = {0xde, 0xad, 0xbe, 0xef};
    });

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::IntegrityFailure);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
    EXPECT_TRUE(object_present(fixture.transport, orphan));
}

// CONTENT-R04: the same fail-closed rule applies when a listed history object
// disappears before it is authenticated.
TEST(GarbageCollectionTest, AnalysisRejectsHistoryObjectRemovedAfterListing) {
    FakeFixture fixture("gc-content-incomplete-history");
    const auto head = commit_with_file("live");
    const auto reference =
        publish_object(fixture.transport, fixture.workspace, head, "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto orphan =
        put_content(fixture.transport, fixture.workspace, "orphan", "orphan");
    const auto head_object = object_path(reference);

    after_full_list(fixture.state, 1, [head_object](FakeState& state) {
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

// Old contract: a post-REMOVE presence read confirmed physical absence.
// New contract: a successful REMOVE is API-acknowledged and is not read back.
TEST(GarbageCollectionTest, SuccessfulRemoveIsNotReadBackWithPresence) {
    FakeFixture fixture("gc-post-removal-visibility");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto first =
        put_content(fixture.transport, fixture.workspace, "orphan-a", "a");
    const auto second =
        put_content(fixture.transport, fixture.workspace, "orphan-b", "b");
    fixture.state->fail_presence_after_removal_identifier = std::min(first, second);
    fixture.state->remove_count = 0;

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->removed_objects, 2U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 2U);
    fixture.state->fail_presence_after_removal_identifier.clear();
    EXPECT_FALSE(object_present(fixture.transport, first));
    EXPECT_FALSE(object_present(fixture.transport, second));
}

// PARTIAL-R01: analysis failure before Apply keeps zero mutation counts.
TEST(GarbageCollectionTest, AnalysisFailureBeforeApplyKeepsZeroCounts) {
    FakeFixture fixture("gc-partial-before-first");
    const auto head = commit_with_file("live");
    const auto reference =
        publish_object(fixture.transport, fixture.workspace, head, "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    put_content(fixture.transport, fixture.workspace, "orphan", "orphan");
    const auto head_object = object_path(reference);
    after_full_list(fixture.state, 1, [head_object](FakeState& state) {
        state.objects[head_object] = {0xde, 0xad, 0xbe, 0xef};
    });

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_EQ(diagnostic.stage, GarbageCollectStage::Analyzing);
    EXPECT_EQ(diagnostic.confirmed_removed, 0U);
    EXPECT_FALSE(diagnostic.failed_identifier.has_value());
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

// PLAN-R04: the third of eight REMOVE calls fails with an ambiguous I/O
// result. Two are acknowledged, the third is uncertain, and no fourth starts.
TEST(GarbageCollectionTest, ThirdRemovalFailureKeepsPartialDiagnostic) {
    FakeFixture fixture("gc-partial-third-remove");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    std::vector<std::string> orphans;
    for (std::size_t index = 0; index < 8; ++index) {
        orphans.push_back(put_content(fixture.transport,
                                      fixture.workspace,
                                      "third-" + std::to_string(index),
                                      "third-" + std::to_string(index)));
    }
    std::ranges::sort(orphans);
    fixture.state->fail_candidate_remove_at = 3;
    fixture.state->remove_failure_native_code = 456;
    fixture.state->remove_attempts.clear();

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::application::integrity::ErrorCode::TransportFailure);
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_EQ(diagnostic.candidate_objects, 8U);
    EXPECT_EQ(diagnostic.confirmed_removed, 2U);
    EXPECT_EQ(diagnostic.failed_identifier,
              std::optional<std::string>{orphans[2]});
    EXPECT_EQ(diagnostic.stage, GarbageCollectStage::Applying);
    EXPECT_EQ(diagnostic.mutation_state,
              kasumi::application::GarbageCollectMutationState::Uncertain);
    ASSERT_TRUE(diagnostic.transport_error.has_value());
    EXPECT_EQ(diagnostic.transport_error->code, kasumi::transport::ErrorCode::Io);
    EXPECT_EQ(diagnostic.transport_error->native_code, 456);
    EXPECT_TRUE(diagnostic.barrier_release_attempted);
    EXPECT_TRUE(diagnostic.barrier_release_confirmed);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 3U);
    EXPECT_FALSE(object_present(fixture.transport, orphans[0]));
    EXPECT_FALSE(object_present(fixture.transport, orphans[1]));
    EXPECT_TRUE(object_present(fixture.transport, orphans[2]));
    EXPECT_TRUE(object_present(fixture.transport, orphans[3]));
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

TEST(GarbageCollectionTest, AnalysisOnlyCountsCorruptCandidates) {
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
    EXPECT_EQ(result->candidate_objects, 1U);
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

TEST(GarbageCollectionTest, CooperativeWriterCannotRegisterWhileBarrierActive) {
    FakeFixture fixture("gc-writer-during-apply");
    seed_repository(fixture.transport, fixture.workspace);
    auto barrier = protocol::establish_barrier(
        fixture.transport, layout(), kasumi::test::workspace_root(fixture.workspace));
    ASSERT_TRUE(barrier.has_value()) << barrier.error().detail;

    auto writer = protocol::register_writer(
        fixture.transport,
        layout(),
        kasumi::test::workspace_root(fixture.workspace));
    EXPECT_FALSE(writer.has_value());
    if (!writer.has_value()) {
        EXPECT_EQ(writer.error().code, protocol::ErrorCode::Blocked);
    }
    EXPECT_TRUE(protocol::release_registration(*barrier));
}

TEST(GarbageCollectionTest,
     BarrierReplacementDuringApplyPreservesAcknowledgedRemovals) {
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
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_EQ(diagnostic.confirmed_removed, 2U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 2U);
    EXPECT_FALSE(object_present(fixture.transport, std::min(first, second)));
    EXPECT_FALSE(object_present(fixture.transport, std::max(first, second)));
    EXPECT_FALSE(diagnostic.barrier_release_attempted);
    EXPECT_TRUE(object_present(fixture.transport, layout().barrier_identifier));
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
    EXPECT_EQ(diagnostic.confirmed_removed, 2U);
    ASSERT_TRUE(diagnostic.barrier_cleanup_error.has_value());
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 0U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 2U);
    EXPECT_TRUE(object_present(fixture.transport, layout().barrier_identifier));
    EXPECT_FALSE(object_present(fixture.transport, std::min(first, second)));
    EXPECT_FALSE(object_present(fixture.transport, std::max(first, second)));
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

TEST(GarbageCollectionTest, ObjectsAppearingAfterObservationAreNotPlanned) {
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
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->removed_objects, 2U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 2U);
    EXPECT_TRUE(object_present(fixture.transport, hidden));
    EXPECT_FALSE(object_present(fixture.transport, repository.orphan_content));
    EXPECT_FALSE(
        object_present(fixture.transport, object_path(repository.redundant_variant)));
}

TEST(GarbageCollectionTest,
     CandidateMissingAfterListRemainsInFrozenPlanAndAcknowledgesAbsent) {
    FakeFixture fixture("gc-missing-candidate");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto orphan =
        put_content(fixture.transport, fixture.workspace, "extra", "extra");
    fixture.state->on_operation = [orphan](FakeState& state,
                                           std::string_view operation,
                                           std::string_view) {
        if (operation == "after_list" && state.full_list_count == 1) {
            state.objects.erase(orphan);
        }
    };
    fixture.state->remove_count = 0;

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 1U);
    EXPECT_EQ(result->removed_objects, 1U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 1U);
}

TEST(GarbageCollectionTest, OrphanContentRemovedWithoutPayloadGet) {
    FakeFixture fixture("gc-orphan-no-get");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    const auto live =
        put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto orphan =
        put_content(fixture.transport, fixture.workspace, "orphan", "orphan");
    fixture.state->observed_payload_identifiers.insert(orphan);

    std::vector<std::string> get_calls;
    fixture.state->on_operation =
        [&](FakeState&, std::string_view op, std::string_view id) {
            if (op == "get") {
                get_calls.emplace_back(id);
            }
        };

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 1U);
    EXPECT_EQ(result->removed_objects, 1U);
    EXPECT_TRUE(object_present(fixture.transport, live));
    EXPECT_FALSE(object_present(fixture.transport, orphan));
    EXPECT_EQ(fixture.state->orphan_payload_get_count, 0U);
    EXPECT_EQ(std::ranges::count(get_calls, orphan), 0);
}

TEST(GarbageCollectionTest, OrphanRemovalSucceedsWhenContentGetFails) {
    FakeFixture fixture("gc-orphan-get-fail");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    const auto live =
        put_content(fixture.transport, fixture.workspace, "live", "live");
    const auto orphan =
        put_content(fixture.transport, fixture.workspace, "orphan", "orphan");
    fixture.state->fail_get_identifier = orphan;

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 1U);
    EXPECT_EQ(result->removed_objects, 1U);
    EXPECT_TRUE(object_present(fixture.transport, live));
    EXPECT_FALSE(object_present(fixture.transport, orphan));
}

TEST(GarbageCollectionTest, ManyOrphansCollectedWithZeroContentGets) {
    FakeFixture fixture("gc-many-orphans");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    const auto live =
        put_content(fixture.transport, fixture.workspace, "live", "live");

    std::unordered_set<std::string> orphan_ids;
    for (std::size_t i = 0; i < 50; ++i) {
        const auto id = put_content(fixture.transport,
                                    fixture.workspace,
                                    "orphan-" + std::to_string(i),
                                    "orphan-" + std::to_string(i));
        orphan_ids.insert(id);
        fixture.state->observed_payload_identifiers.insert(id);
    }

    std::vector<std::string> get_calls;
    fixture.state->on_operation =
        [&](FakeState&, std::string_view op, std::string_view id) {
            if (op == "get") {
                get_calls.emplace_back(id);
            }
        };

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 50U);
    EXPECT_EQ(result->removed_objects, 50U);
    EXPECT_TRUE(object_present(fixture.transport, live));
    EXPECT_EQ(fixture.state->orphan_payload_get_count, 0U);
    EXPECT_EQ(fixture.state->full_list_count, 1U);
    for (const auto& id : orphan_ids) {
        EXPECT_FALSE(object_present(fixture.transport, id));
        EXPECT_EQ(std::ranges::count(get_calls, id), 0);
        EXPECT_EQ(std::ranges::count(fixture.state->gc_events,
                                     "physical_hash:" + id),
                  0);
    }
}

TEST(GarbageCollectionTest, ReferencedCorruptContentIsPreservedWithoutGet) {
    FakeFixture fixture("gc-referenced-corrupt");
    publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    put_corrupt_content(fixture.transport, fixture.workspace, "live", "live");
    const auto live = content_identifier("live");
    const auto orphan =
        put_content(fixture.transport, fixture.workspace, "orphan", "orphan");

    std::vector<std::string> get_calls;
    fixture.state->on_operation =
        [&](FakeState&, std::string_view op, std::string_view id) {
            if (op == "get") {
                get_calls.emplace_back(id);
            }
        };

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 1U);
    EXPECT_EQ(result->removed_objects, 1U);
    EXPECT_TRUE(object_present(fixture.transport, live));
    EXPECT_FALSE(object_present(fixture.transport, orphan));
    EXPECT_EQ(std::ranges::count(get_calls, live), 0);
    EXPECT_EQ(std::ranges::count(get_calls, orphan), 0);
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

void benchmark_redundant_variants(std::size_t candidate_count) {
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
    for (std::size_t index = 0; index < candidate_count / 2; ++index) {
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

    const auto result = measure_gc(
        fixture, std::to_string(candidate_count) + "_redundant_commit_variants");
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, candidate_count);
    EXPECT_EQ(result->removed_objects, candidate_count);
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

TEST(GarbageCollectionBenchmarkTest, TwoRedundantVariants) {
    benchmark_redundant_variants(2);
}

TEST(GarbageCollectionBenchmarkTest, EightRedundantVariants) {
    benchmark_redundant_variants(8);
}

TEST(GarbageCollectionBenchmarkTest, SixteenRedundantVariants) {
    benchmark_redundant_variants(16);
}

TEST(GarbageCollectionBenchmarkTest, ThirtyTwoRedundantVariants) {
    benchmark_redundant_variants(32);
}

TEST(GarbageCollectionBenchmarkTest, SixtyFourRedundantVariants) {
    benchmark_redundant_variants(64);
}

TEST(GarbageCollectionBenchmarkTest, TenRedundantVariants) {
    benchmark_redundant_variants(10);
}

TEST(GarbageCollectionBenchmarkTest, OneHundredRedundantVariants) {
    benchmark_redundant_variants(100);
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

// These cases used to be caught by per-candidate history revalidation. Under
// cooperative exclusivity they are non-cooperative mutations after the
// authoritative observation, so Apply keeps its frozen plan and does not
// perform a second read. The barrier still keeps its special cleanup rules.
class PostApplyMutationTest : public testing::TestWithParam<std::string> {};

TEST_P(PostApplyMutationTest, MutationAfterFirstRemovalDoesNotChangeThePlan) {
    FakeFixture fixture("gc-variant-concurrent-change");
    const auto parent = commit_with_file("parent");
    const auto parent_reference = publish_object(
        fixture.transport, fixture.workspace, parent, "parent", false);
    const auto child = kasumi::history::make_commit(
        1, {commit_id(parent)}, commit_with_file("live").tree).value();
    const auto head = publish_object(
        fixture.transport, fixture.workspace, child, "head");
    put_content(fixture.transport, fixture.workspace, "parent", "parent-content");
    put_content(fixture.transport, fixture.workspace, "live", "live-content");
    const auto a = add_variant_object(
        fixture.transport, fixture.workspace, child, "a");
    const auto b = add_variant_object(
        fixture.transport, fixture.workspace, child, "b");
    const auto first = std::min(object_path(a), object_path(b));
    const auto second = std::max(object_path(a), object_path(b));
    const auto second_reference = object_path(a) == second ? a : b;
    const Epoch epoch{
        .vault_id = std::string(64, 'a'), .sequence = 0, .issued_at = 1,
        .policy = {}, .anchors = {Anchor{commit_id(parent), 0}}};
    const auto sealed =
        kasumi::application::history_storage::epoch::seal(epoch, test_key());
    ASSERT_TRUE(sealed.has_value());
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        fixture.transport, test_key(), *sealed,
        kasumi::test::workspace_root(fixture.workspace)));
    const auto epoch_id =
        kasumi::application::history_storage::epoch::object_identifier(
            layout(), sealed->reference).value();
    const auto change = GetParam();
    fixture.state->on_operation =
        [=](FakeState& state, std::string_view operation,
                           std::string_view identifier) mutable {
            if (operation != "after_remove" || identifier != first) {
                return;
            }
            if (change == "head") {
                state.objects[marker_path(second_reference)] =
                    marker_bytes(second_reference);
            } else if (change == "alternative_missing") {
                state.objects.erase(object_path(head));
            } else if (change == "alternative_replaced") {
                state.objects[object_path(head)] = {0xde, 0xad};
            } else if (change == "candidate_replaced") {
                state.objects[second] = {0xde, 0xad};
            } else if (change == "unmarked_parent_replaced") {
                state.objects[object_path(parent_reference)] = {0xde, 0xad};
            } else if (change == "marker_replaced") {
                state.objects[marker_path(head)] = {0xde, 0xad};
            } else if (change == "epoch_replaced") {
                state.objects[epoch_id] = {0xde, 0xad};
            } else if (change == "writer") {
                state.objects[layout().writers_prefix + std::string(32, 'a')] =
                    {'w'};
            } else if (change == "barrier") {
                state.objects[layout().barrier_identifier] = {'f'};
            } else if (change == "namespace") {
                state.objects["unexpected"] = {'x'};
            } else if (change == "exception_cleanup") {
                state.fail_remove_identifier = layout().barrier_identifier;
                state.remove_failure_native_code = 907;
            }
        };
    fixture.state->remove_attempts.clear();
    const auto result = fixture.collect();
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 2U);
    EXPECT_FALSE(object_present(fixture.transport, first));
    EXPECT_FALSE(object_present(fixture.transport, second));
    if (change == "barrier") {
        ASSERT_FALSE(result.has_value());
        ASSERT_TRUE(result.error().garbage_collection.has_value());
        const auto& diagnostic = *result.error().garbage_collection;
        EXPECT_EQ(diagnostic.confirmed_removed, 2U);
        EXPECT_EQ(barrier_remove_attempts(*fixture.state), 0U);
        EXPECT_TRUE(object_present(fixture.transport, layout().barrier_identifier));
    } else if (change == "exception_cleanup") {
        ASSERT_FALSE(result.has_value());
        ASSERT_TRUE(result.error().garbage_collection.has_value());
        const auto& diagnostic = *result.error().garbage_collection;
        EXPECT_EQ(diagnostic.confirmed_removed, 2U);
        ASSERT_TRUE(diagnostic.barrier_cleanup_transport_error.has_value());
        EXPECT_EQ(diagnostic.barrier_cleanup_transport_error->native_code, 907);
        EXPECT_EQ(barrier_remove_attempts(*fixture.state), 1U);
    } else {
        ASSERT_TRUE(result.has_value()) << result.error().detail;
        EXPECT_EQ(result->removed_objects, 2U);
    }
}

INSTANTIATE_TEST_SUITE_P(
    GcOptimization, PostApplyMutationTest,
    testing::Values("head", "alternative_missing", "alternative_replaced",
                    "candidate_replaced", "unmarked_parent_replaced",
                    "marker_replaced", "epoch_replaced", "writer", "barrier",
                    "namespace", "exception_cleanup"),
    [](const testing::TestParamInfo<std::string>& parameter) {
        return parameter.param;
    });

TEST(GarbageCollectionOptimizationTest, UncertainVariantRemoveIsNeverRetried) {
    FakeFixture fixture("gc-variant-uncertain");
    const auto commit = commit_with_file("live");
    publish_object(fixture.transport, fixture.workspace, commit, "head");
    put_content(fixture.transport, fixture.workspace, "live", "content");
    const auto a = object_path(add_variant_object(
        fixture.transport, fixture.workspace, commit, "a"));
    const auto b = object_path(add_variant_object(
        fixture.transport, fixture.workspace, commit, "b"));
    fixture.state->remove_then_fail_identifier = std::min(a, b);
    fixture.state->remove_attempts.clear();
    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    EXPECT_EQ(result.error().garbage_collection->confirmed_removed, 0U);
    EXPECT_EQ(result.error().garbage_collection->mutation_state,
              kasumi::application::GarbageCollectMutationState::Uncertain);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 1U);
    EXPECT_TRUE(object_present(fixture.transport, std::max(a, b)));
}

TEST(GarbageCollectionOptimizationTest, PlanPreservesOneVariantPerCommit) {
    FakeFixture fixture("gc-distinct-variant-commits");
    std::vector<std::string> heads;
    std::vector<std::string> redundant;
    for (const std::string_view contents : {"a", "b"}) {
        const auto commit = commit_with_file(contents);
        heads.push_back(object_path(publish_object(fixture.transport,
                                                  fixture.workspace,
                                                  commit,
                                                  std::string{contents} + "-head")));
        put_content(fixture.transport, fixture.workspace, contents, contents);
        redundant.push_back(object_path(add_variant_object(
            fixture.transport, fixture.workspace, commit,
            std::string{contents} + "-variant")));
    }
    std::ranges::sort(redundant);
    fixture.state->remove_attempts.clear();
    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 2U);
    EXPECT_EQ(result->removed_objects, 2U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 2U);
    for (const auto& identifier : heads) {
        EXPECT_TRUE(object_present(fixture.transport, identifier));
    }
    for (const auto& identifier : redundant) {
        EXPECT_FALSE(object_present(fixture.transport, identifier));
    }
    const auto inventory =
        kasumi::application::history_storage::inventory_reachability(
            fixture.transport,
            test_key(),
            kasumi::test::workspace_root(fixture.workspace));
    ASSERT_TRUE(inventory.has_value()) << inventory.error().detail;
    EXPECT_EQ(inventory->logical_heads.size(), 2U);
    EXPECT_EQ(inventory->reachable_commits.size(), 2U);
}

TEST(GarbageCollectionOptimizationTest,
     RemovesEveryRedundantVariantOfOneCommit) {
    FakeFixture fixture("gc-variant-get-budget");
    const auto commit = commit_with_file("live");
    const auto head =
        publish_object(fixture.transport, fixture.workspace, commit, "head");
    put_content(fixture.transport, fixture.workspace, "live", "content");
    for (std::size_t index = 0; index < 10; ++index) {
        add_variant_object(fixture.transport, fixture.workspace, commit,
                           "variant-" + std::to_string(index));
    }
    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->removed_objects, 10U);
    EXPECT_TRUE(object_present(fixture.transport, object_path(head)));
}

TEST(GarbageCollectionOptimizationTest,
     FailedListDoesNotCountAnUnperformedReconstruction) {
    FakeFixture fixture("gc-reconstruction-counter");
    publish_object(fixture.transport, fixture.workspace,
                   commit_with_file("live"), "head");
    put_content(fixture.transport, fixture.workspace, "live", "content");
    put_content(fixture.transport, fixture.workspace, "orphan", "orphan");
    fixture.state->fail_list = kasumi::transport::ErrorCode::Io;
    fixture.state->fail_list_at = 1;
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();
    const auto result = fixture.collect();
    const auto reconstructed =
        kasumi::platform::perf_trace::get_count("gc.history_reconstructions");
    kasumi::platform::perf_trace::force_enable(false);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(reconstructed, 0U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
}

// RERUN: acknowledged removals survive a partial failure. A new run starts from
// a fresh observation and re-plans the objects that are still present.
TEST(GarbageCollectionTest, NewRunAfterPartialFailureReplansFromCurrentState) {
    FakeFixture fixture("gc-rerun-after-partial-failure");
    const auto head = publish_object(
        fixture.transport, fixture.workspace, commit_with_file("live"), "head");
    const auto live =
        put_content(fixture.transport, fixture.workspace, "live", "live");
    std::vector<std::string> orphans;
    for (std::size_t index = 0; index < 6; ++index) {
        orphans.push_back(put_content(fixture.transport,
                                      fixture.workspace,
                                      "rerun-" + std::to_string(index),
                                      "rerun-" + std::to_string(index)));
    }
    std::ranges::sort(orphans);

    fixture.state->fail_candidate_remove_at = 3;
    fixture.state->remove_failure_native_code = 456;
    fixture.state->remove_attempts.clear();
    const auto first = fixture.collect();
    ASSERT_FALSE(first.has_value());
    ASSERT_TRUE(first.error().garbage_collection.has_value());
    const auto& first_diagnostic = *first.error().garbage_collection;
    EXPECT_EQ(first_diagnostic.candidate_objects, 6U);
    EXPECT_EQ(first_diagnostic.confirmed_removed, 2U);
    EXPECT_EQ(first_diagnostic.failed_identifier,
              std::optional<std::string>{orphans[2]});
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 3U);
    EXPECT_FALSE(object_present(fixture.transport, orphans[0]));
    EXPECT_FALSE(object_present(fixture.transport, orphans[1]));
    EXPECT_TRUE(object_present(fixture.transport, orphans[2]));

    fixture.state->fail_candidate_remove_at = 0;
    fixture.state->remove_failure_native_code = 0;
    fixture.state->remove_attempts.clear();
    const auto second = fixture.collect();
    ASSERT_TRUE(second.has_value()) << second.error().detail;
    EXPECT_EQ(second->candidate_objects, 4U);
    EXPECT_EQ(second->removed_objects, 4U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 4U);
    for (const auto& orphan : orphans) {
        EXPECT_FALSE(object_present(fixture.transport, orphan));
    }
    EXPECT_TRUE(object_present(fixture.transport, live));
    EXPECT_TRUE(object_present(fixture.transport, object_path(head)));

    const auto inventory =
        kasumi::application::history_storage::inventory_reachability(
            fixture.transport,
            test_key(),
            kasumi::test::workspace_root(fixture.workspace));
    ASSERT_TRUE(inventory.has_value()) << inventory.error().detail;
    EXPECT_EQ(inventory->logical_heads.size(), 1U);
}

TEST(GarbageCollectionTest, GlobalPlanPreservesOneOfThreeValidVariants) {
    LocalFixture fixture;
    const auto commit = commit_with_file("live");
    const auto head = publish_object(fixture.storage.transport,
                                     fixture.storage.workspace,
                                     commit,
                                     "three-head");
    put_content(
        fixture.storage.transport, fixture.storage.workspace, "live", "live");
    std::vector<std::string> variants{object_path(head)};
    for (const std::string_view suffix : {"three-a", "three-b"}) {
        variants.push_back(object_path(add_variant_object(
            fixture.storage.transport,
            fixture.storage.workspace,
            commit,
            suffix)));
    }
    std::ranges::sort(variants);

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 2U);
    EXPECT_EQ(result->removed_objects, 2U);
    EXPECT_EQ(std::ranges::count_if(variants,
                                    [&](const auto& identifier) {
                                        return object_present(
                                            fixture.storage.transport,
                                            identifier);
                                    }),
              1);

    const auto inventory =
        kasumi::application::history_storage::inventory_reachability(
            fixture.storage.transport,
            test_key(),
            kasumi::test::workspace_root(fixture.storage.workspace));
    ASSERT_TRUE(inventory.has_value()) << inventory.error().detail;
    EXPECT_EQ(inventory->logical_heads.size(), 1U);
    EXPECT_EQ(inventory->reachable_commits.size(), 1U);
}

class GlobalPlanSizeTest : public testing::TestWithParam<std::size_t> {};

TEST_P(GlobalPlanSizeTest, PlanIsCompleteDeterministicAndSafe) {
    const auto count = GetParam();
    FakeFixture fixture("gc-plan-size-" + std::to_string(count));
    const auto head = commit_with_file("live");
    const auto reference =
        publish_object(fixture.transport, fixture.workspace, head, "head");
    const auto live =
        put_content(fixture.transport, fixture.workspace, "live", "live");
    std::vector<std::string> orphans;
    for (std::size_t index = 0; index < count; ++index) {
        orphans.push_back(put_content(fixture.transport,
                                      fixture.workspace,
                                      "plan-" + std::to_string(index),
                                      "plan-" + std::to_string(index)));
    }
    std::ranges::sort(orphans);
    fixture.state->remove_attempts.clear();

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, count);
    EXPECT_EQ(result->removed_objects, count);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), count);

    std::vector<std::string> attempted;
    for (const auto& identifier : fixture.state->remove_attempts) {
        if (!protocol::is_control_object(layout(), identifier)) {
            attempted.push_back(identifier);
        }
    }
    EXPECT_EQ(attempted, orphans);
    EXPECT_TRUE(object_present(fixture.transport, live));
    EXPECT_TRUE(object_present(fixture.transport, object_path(reference)));
    for (const auto& identifier : orphans) {
        EXPECT_FALSE(object_present(fixture.transport, identifier));
    }
}

INSTANTIATE_TEST_SUITE_P(
    GcPlan, GlobalPlanSizeTest,
    testing::Values(0U, 1U, 2U, 7U, 8U, 9U, 64U),
    [](const testing::TestParamInfo<std::size_t>& parameter) {
        return "N" + std::to_string(parameter.param);
    });

TEST(GarbageCollectionTest, GlobalPlanPreservesAnchoredCommitVariant) {
    LocalFixture fixture;
    const auto parent = commit_with_file("parent");
    const auto child = kasumi::history::make_commit(
        1, {commit_id(parent)}, commit_with_file("child").tree).value();
    publish_object(fixture.storage.transport,
                   fixture.storage.workspace,
                   parent,
                   "anchor-parent");
    publish_object(fixture.storage.transport,
                   fixture.storage.workspace,
                   child,
                   "anchor-child");
    put_content(fixture.storage.transport,
                fixture.storage.workspace,
                "parent",
                "anchor-parent-content");
    put_content(fixture.storage.transport,
                fixture.storage.workspace,
                "child",
                "anchor-child-content");
    const auto parent_variant = add_variant_object(fixture.storage.transport,
                                                   fixture.storage.workspace,
                                                   parent,
                                                   "anchor-parent-variant");
    const auto child_variant = add_variant_object(fixture.storage.transport,
                                                  fixture.storage.workspace,
                                                  child,
                                                  "anchor-child-variant");
    const Epoch epoch{
        .vault_id = std::string(64, 'a'),
        .sequence = 0,
        .issued_at = 1,
        .policy = {},
        .anchors = {Anchor{.commit_id = commit_id(parent), .height = 0}},
    };
    const auto sealed =
        kasumi::application::history_storage::epoch::seal(epoch, test_key());
    ASSERT_TRUE(sealed.has_value());
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
    EXPECT_EQ(result->candidate_objects, 2U);
    EXPECT_EQ(result->removed_objects, 2U);
    EXPECT_FALSE(
        object_present(fixture.storage.transport, object_path(parent_variant)));
    EXPECT_FALSE(
        object_present(fixture.storage.transport, object_path(child_variant)));
    EXPECT_TRUE(object_present(fixture.storage.transport, *epoch_object));

    const auto inventory =
        kasumi::application::history_storage::inventory_reachability(
            fixture.storage.transport,
            test_key(),
            kasumi::test::workspace_root(fixture.storage.workspace));
    ASSERT_TRUE(inventory.has_value()) << inventory.error().detail;
    EXPECT_NE(std::ranges::find(inventory->reachable_commits, commit_id(parent)),
              inventory->reachable_commits.end());
    EXPECT_NE(std::ranges::find(inventory->reachable_commits, commit_id(child)),
              inventory->reachable_commits.end());
}

} // namespace
