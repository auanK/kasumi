#include "application/history_storage/activity.hpp"
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
#include "platform/clock.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
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
namespace gc_int = kasumi::application::integrity;
using GcErrorCode = gc_int::ErrorCode;
using kasumi::NodeRow;
using kasumi::Snapshot;
using kasumi::application::GarbageCollectProgress;
using kasumi::application::GarbageCollectStage;
using kasumi::application::GarbageCollectSubStage;
using kasumi::application::history_storage::HeadReference;
using kasumi::application::history_storage::RemoteLayout;
using kasumi::application::history_storage::epoch::Anchor;
using kasumi::application::history_storage::epoch::Epoch;
using kasumi::runtime::RuntimeData;
using kasumi::test::TempWorkspace;

RemoteLayout layout() {
    return test_layout();
}

struct ResetCancellation {
    ResetCancellation() {
        kasumi::platform::cancellation::reset();
    }
    ~ResetCancellation() {
        kasumi::platform::cancellation::reset();
    }
};

kasumi::history::Commit commit_with_file(std::string_view contents) {
    return kasumi::history::make_commit(0, {}, make_tree("live.txt", contents))
        .value();
}

HeadReference add_variant_object(kasumi::transport::Transport& transport,
                                 TempWorkspace& workspace,
                                 const kasumi::history::Commit& commit,
                                 std::string_view suffix) {
    return publish_object(transport, workspace, commit, suffix, false);
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
        return collect_with_options(
            gc_int::GarbageCollectOptions{.min_orphan_age =
                                              std::chrono::seconds{0}},
            std::move(progress));
    }

    std::expected<kasumi::application::integrity::GarbageCollectResult,
                  kasumi::application::integrity::Error>
    collect_with_options(
        gc_int::GarbageCollectOptions options,
        kasumi::application::integrity::GarbageCollectProgressCallback
            progress = {}) {
        return gc_int::garbage_collect(runtime,
                                       storage.transport,
                                       test_key(),
                                       options,
                                       std::move(progress));
    }

    HeadReference publish(const kasumi::history::Commit& commit,
                          std::string_view suffix,
                          bool create_head = true) {
        return publish_object(
            storage.transport, storage.workspace, commit, suffix, create_head);
    }

    std::string put_content(std::string_view contents,
                            std::string_view suffix) {
        return ::put_content(
            storage.transport, storage.workspace, contents, suffix);
    }

    bool present(std::string_view identifier) {
        return object_present(storage.transport, identifier);
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
        return collect_with_options(
            gc_int::GarbageCollectOptions{.min_orphan_age =
                                              std::chrono::seconds{0}},
            std::move(progress));
    }

    std::expected<kasumi::application::integrity::GarbageCollectResult,
                  kasumi::application::integrity::Error>
    collect_with_options(
        gc_int::GarbageCollectOptions options,
        kasumi::application::integrity::GarbageCollectProgressCallback
            progress = {}) {
        return gc_int::garbage_collect(
            runtime, transport, test_key(), options, std::move(progress));
    }

    HeadReference publish(const kasumi::history::Commit& commit,
                          std::string_view suffix,
                          bool create_head = true) {
        return publish_object(
            transport, workspace, commit, suffix, create_head);
    }

    std::string put_content(std::string_view contents,
                            std::string_view suffix) {
        return ::put_content(transport, workspace, contents, suffix);
    }

    bool present(std::string_view identifier) {
        return object_present(transport, identifier);
    }

    HeadReference add_variant(const kasumi::history::Commit& commit,
                              std::string_view suffix) {
        return add_variant_object(transport, workspace, commit, suffix);
    }
};

template <typename Fixture>
auto measure_gc(Fixture& fixture, std::string_view scenario) {
    using Result = decltype(fixture.collect());
    const auto started = std::chrono::steady_clock::now();
    Result result = fixture.collect();
    const auto wall_us = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - started)
            .count());
    std::cerr << "GC_BENCHMARK {\"scenario\":\"" << scenario
              << "\",\"measurement_level\":\"local file-backed transport; "
                 "fixture setup excluded\",\"wall_us\":"
              << wall_us << "}\n";
    if (result) {
        auto audited = kasumi::application::integrity::fsck(
            fixture.runtime, fixture.storage.transport, test_key());
        EXPECT_TRUE(audited.has_value())
            << (audited ? "" : audited.error().detail);
        std::cerr << "GC_FSCK {\"scenario\":\"" << scenario
                  << "\",\"passed\":" << (audited ? "true" : "false") << "}\n";
    }
    return result;
}

template <typename Fixture>
std::optional<kasumi::application::GarbageCollectFailure>
collect_diagnostic(Fixture& fixture) {
    const auto result = fixture.collect();
    if (result.has_value()) {
        ADD_FAILURE() << "expected GC failure, succeeded instead";
        return std::nullopt;
    }
    if (!result.error().garbage_collection.has_value()) {
        ADD_FAILURE() << "expected garbage_collection diagnostic payload";
        return std::nullopt;
    }
    return *result.error().garbage_collection;
}

template <typename Fixture>
[[nodiscard]] ::testing::AssertionResult
expect_collect_error(Fixture& fixture, GcErrorCode expected) {
    const auto result = fixture.collect();
    if (result.has_value()) {
        return ::testing::AssertionFailure()
               << "expected GC error, succeeded instead";
    }
    if (result.error().code != expected) {
        return ::testing::AssertionFailure()
               << "unexpected error detail: " << result.error().detail;
    }
    return ::testing::AssertionSuccess();
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
        EXPECT_EQ(result.error().code, GcErrorCode::ConcurrentChange);
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
        EXPECT_EQ(result.error().code, GcErrorCode::ConcurrentChange);
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
    EXPECT_EQ(result.error().code, GcErrorCode::TransportFailure);
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
    ResetCancellation reset_guard;

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
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    std::vector<std::string> orphans;
    for (const auto name : {"exception-a", "exception-b", "exception-c"}) {
        orphans.push_back(fixture.put_content(name, name));
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
        fixture.publish(commit_with_file("live"), "head");
        fixture.put_content("live", "live");
        std::vector<std::string> orphans;
        for (const auto name : {"error-a", "error-b", "error-c"}) {
            orphans.push_back(fixture.put_content(name, name));
        }
        std::ranges::sort(orphans);
        fixture.state->remove_then_fail_identifier = orphans[1];
        fixture.state->fail_remove_code = code;
        fixture.state->remove_failure_native_code = 10054;

        const auto diagnostic = collect_diagnostic(fixture);
        ASSERT_TRUE(diagnostic.has_value());
        EXPECT_EQ(diagnostic->confirmed_removed, 1U);
        EXPECT_EQ(diagnostic->failed_identifier,
                  std::optional<std::string>{orphans[1]});
        EXPECT_EQ(diagnostic->mutation_state,
                  kasumi::application::GarbageCollectMutationState::Uncertain);
        ASSERT_TRUE(diagnostic->transport_error.has_value());
        EXPECT_EQ(diagnostic->transport_error->code, code);
        EXPECT_EQ(diagnostic->transport_error->native_code, 10054);
        EXPECT_TRUE(diagnostic->barrier_release_confirmed);
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
            fixture.publish(commit_with_file("live"), "head");
            fixture.put_content("live", "live");
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

TEST(GarbageCollectionTest,
     TracePartialFailureMatchesAcknowledgementsAndCleanup) {
    for (const bool throws : {false, true}) {
        SCOPED_TRACE(throws);
        FakeFixture fixture("gc-trace-partial");
        fixture.publish(commit_with_file("live"), "head");
        fixture.put_content("live", "live");
        for (const auto name :
             {"partial-a", "partial-b", "partial-c", "partial-d"}) {
            put_corrupt_content(
                fixture.transport, fixture.workspace, name, name);
        }
        fixture.state->fail_candidate_remove_at = 3;
        fixture.state->fail_remove_identifier = layout().barrier_identifier;
        fixture.state->on_operation = [throws](FakeState& state,
                                               std::string_view op,
                                               std::string_view) {
            if (throws && op == "before_remove" &&
                state.candidate_remove_count == 3) {
                throw std::runtime_error("injected traced DELETE exception");
            }
        };
        const auto diagnostic = collect_diagnostic(fixture);
        ASSERT_TRUE(diagnostic.has_value());
        EXPECT_EQ(diagnostic->confirmed_removed, 2U);
        EXPECT_EQ(diagnostic->mutation_state,
                  kasumi::application::GarbageCollectMutationState::Uncertain);
        EXPECT_TRUE(diagnostic->barrier_cleanup_error.has_value());
        EXPECT_FALSE(diagnostic->barrier_release_confirmed);
        EXPECT_EQ(candidate_remove_attempts(*fixture.state), 3U);
        EXPECT_EQ(barrier_remove_attempts(*fixture.state), 1U);
    }
}

TEST(GarbageCollectionTest,
     TraceOwnershipAndHistoryReadsStayFixedAsCandidatesGrow) {
    for (const auto count : {1U, 100U, 1000U}) {
        SCOPED_TRACE(count);
        FakeFixture fixture("gc-trace-fixed-cost");
        fixture.publish(commit_with_file("live"), "head");
        fixture.put_content("live", "live");
        for (std::size_t index = 0; index < count; ++index) {
            const auto contents = "counter-" + std::to_string(index);
            put_corrupt_content(
                fixture.transport, fixture.workspace, contents, contents);
            fixture.state->observed_payload_identifiers.insert(
                content_identifier(contents));
        }
        const auto result = fixture.collect();
        ASSERT_TRUE(result.has_value()) << result.error().detail;
        EXPECT_EQ(result->removed_objects, count);
        EXPECT_EQ(fixture.state->orphan_payload_get_count, 0U);
        for (const auto& id : fixture.state->observed_payload_identifiers) {
            EXPECT_EQ(std::ranges::count(fixture.state->gc_events,
                                         "physical_hash:" + id),
                      0);
        }
    }
}

TEST(GarbageCollectionTest, TracingDisabledPreservesCollectionBehavior) {
    FakeFixture fixture("gc-tracing-disabled");
    const auto repository =
        seed_repository(fixture.transport, fixture.workspace);
    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->removed_objects, 2U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 2U);
    EXPECT_TRUE(fixture.state->objects.contains(repository.live_content));
    EXPECT_TRUE(fixture.state->objects.contains(object_path(repository.head)));
    EXPECT_FALSE(fixture.state->objects.contains(repository.orphan_content));
    EXPECT_FALSE(fixture.state->objects.contains(layout().barrier_identifier));
}

TEST(GarbageCollectionTest, RemovesAuthenticatedOrphanContent) {
    LocalFixture fixture;
    const auto orphan = fixture.put_content("orphan", "orphan");
    fixture.publish(commit_with_file("live"), "head");
    const auto live = fixture.put_content("live", "live");

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 1U);
    EXPECT_EQ(result->removed_objects, 1U);
    EXPECT_FALSE(result->analysis_only);
    EXPECT_FALSE(fixture.present(orphan));
    EXPECT_TRUE(fixture.present(live));
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
    EXPECT_FALSE(fixture.present(object_path(repository.redundant_variant)));
    EXPECT_TRUE(fixture.present(required_path));
    EXPECT_TRUE(fixture.present(object_path(corrupt)));
    EXPECT_FALSE(fixture.present(repository.orphan_content));
}

TEST(GarbageCollectionTest, RemovesCorruptOrphanContent) {
    LocalFixture fixture;
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    const auto valid = fixture.put_content("valid-orphan", "valid-orphan");
    put_corrupt_content(fixture.storage.transport,
                        fixture.storage.workspace,
                        "corrupt-orphan",
                        "corrupt-orphan");
    const auto corrupt = content_identifier("corrupt-orphan");

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 2U);
    EXPECT_EQ(result->removed_objects, 2U);
    EXPECT_FALSE(fixture.present(valid));
    EXPECT_FALSE(fixture.present(corrupt));
}

TEST(GarbageCollectionTest, PreservesReachableContentAndRequiredHistory) {
    LocalFixture fixture;
    const auto repository =
        seed_repository(fixture.storage.transport, fixture.storage.workspace);

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_TRUE(fixture.present(repository.live_content));
    EXPECT_TRUE(fixture.present(object_path(repository.head)));
    EXPECT_TRUE(fixture.present(marker_path(repository.head)));
}

// CONTENT-R01
TEST(GarbageCollectionTest, ContentRevalidationAllowsStillOrphan) {
    LocalFixture fixture;
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    const auto orphan =
        fixture.put_content("revalidated-orphan", "revalidated-orphan");

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 1U);
    EXPECT_EQ(result->removed_objects, 1U);
    EXPECT_FALSE(fixture.present(orphan));
}

// CONTENT-R02: under the cooperative contract, reachability is established by
// the single authenticated observation, not revalidated per candidate.
TEST(GarbageCollectionTest,
     AnalysisPreservesContentMadeReachableBeforeObservation) {
    FakeFixture fixture("gc-content-reachable");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    const auto deferred = commit_with_file("protected");
    const auto deferred_reference =
        fixture.publish(deferred, "deferred", false);
    const auto content = fixture.put_content("protected", "protected");
    ASSERT_EQ(content, content_identifier("protected"));
    fixture.state->objects[marker_path(deferred_reference)] =
        marker_bytes(deferred_reference);

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 0U);
    EXPECT_EQ(result->removed_objects, 0U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
    EXPECT_TRUE(fixture.present(content));
}

// CONTENT-R03: a history payload replaced between LIST and GET is still inside
// the analysis window, so it fails closed before any mutation.
TEST(GarbageCollectionTest, AnalysisRejectsHistoryPayloadReplacedAfterListing) {
    FakeFixture fixture("gc-content-history-replacement");
    const auto head = commit_with_file("live");
    const auto reference = fixture.publish(head, "head");
    fixture.put_content("live", "live");
    const auto orphan = fixture.put_content("orphan", "orphan");
    const auto head_object = object_path(reference);

    after_full_list(fixture.state, 1, [head_object](FakeState& state) {
        state.objects[head_object] = {0xde, 0xad, 0xbe, 0xef};
    });

    ASSERT_TRUE(expect_collect_error(fixture, GcErrorCode::IntegrityFailure));
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
    EXPECT_TRUE(fixture.present(orphan));
}

// CONTENT-R04: the same fail-closed rule applies when a listed history object
// disappears before it is authenticated.
TEST(GarbageCollectionTest, AnalysisRejectsHistoryObjectRemovedAfterListing) {
    FakeFixture fixture("gc-content-incomplete-history");
    const auto head = commit_with_file("live");
    const auto reference = fixture.publish(head, "head");
    fixture.put_content("live", "live");
    const auto orphan = fixture.put_content("orphan", "orphan");
    const auto head_object = object_path(reference);

    after_full_list(fixture.state, 1, [head_object](FakeState& state) {
        state.objects.erase(head_object);
    });

    ASSERT_TRUE(expect_collect_error(fixture, GcErrorCode::IntegrityFailure));
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
    EXPECT_TRUE(fixture.present(orphan));
}

// CONTENT-R05
TEST(GarbageCollectionTest,
     PhysicallyValidContentReferencedByHistoryIsPreserved) {
    LocalFixture fixture;
    const auto commit = commit_with_file("protected");
    fixture.publish(commit, "head");
    const auto content = fixture.put_content("protected", "protected");

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 0U);
    EXPECT_EQ(result->removed_objects, 0U);
    EXPECT_TRUE(fixture.present(content));
}

TEST(GarbageCollectionTest, MissingReachableContentBlocksAllMutation) {
    LocalFixture fixture;
    const auto commit = commit_with_file("missing");
    fixture.publish(commit, "head");
    const auto orphan = fixture.put_content("orphan", "orphan");

    ASSERT_TRUE(expect_collect_error(fixture, GcErrorCode::IntegrityFailure));
    EXPECT_TRUE(fixture.present(orphan));
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

    ASSERT_TRUE(expect_collect_error(fixture, GcErrorCode::IntegrityFailure));
    EXPECT_TRUE(fixture.present(repository.orphan_content));
    EXPECT_TRUE(fixture.present(object_path(repository.redundant_variant)));
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

    ASSERT_TRUE(expect_collect_error(fixture, GcErrorCode::IntegrityFailure));
    EXPECT_TRUE(fixture.present(repository.orphan_content));
}

TEST(GarbageCollectionTest, FreshUnreachableCommitIsDeferredByGracePeriod) {
    LocalFixture fixture;
    const auto reachable = commit_with_file("live");
    fixture.publish(reachable, "head");
    fixture.put_content("live", "live");
    const auto now_unix = *kasumi::platform::clock::unix_seconds();
    const auto orphan_commit =
        kasumi::history::make_commit(
            0, {}, make_tree("unreachable.txt", "unreachable"), now_unix)
            .value();
    const auto orphan_head =
        fixture.publish(orphan_commit, "orphan-commit", false);
    const auto orphan_variant = add_variant_object(fixture.storage.transport,
                                                   fixture.storage.workspace,
                                                   orphan_commit,
                                                   "orphan-variant");

    const auto result =
        fixture.collect_with_options(gc_int::GarbageCollectOptions{});
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 0U);
    EXPECT_EQ(result->removed_objects, 0U);
    EXPECT_EQ(result->deferred_recent_objects, 2U);
    EXPECT_EQ(result->effective_min_age_hours, 6U);
    EXPECT_TRUE(fixture.present(object_path(orphan_head)));
    EXPECT_TRUE(fixture.present(object_path(orphan_variant)));
}

TEST(GarbageCollectionTest, ExpiredCommitsBehindEpochArePrunedSafely) {
    FakeFixture fixture("gc-expired-commits");
    fixture.state->list_metadata_supported = true;
    const auto now_unix = *kasumi::platform::clock::unix_seconds();
    fixture.state->default_object_mtime = now_unix - 10LL * 3600LL;

    const auto old_commit =
        kasumi::history::make_commit(
            0, {}, make_tree("old.txt", "old"), now_unix - 10LL * 3600LL)
            .value();
    const auto mid_commit =
        kasumi::history::make_commit(1,
                                     {commit_id(old_commit)},
                                     make_tree("mid.txt", "mid"),
                                     now_unix - 2LL * 3600LL)
            .value();
    const auto head_commit =
        kasumi::history::make_commit(2,
                                     {commit_id(mid_commit)},
                                     make_tree("live.txt", "live"),
                                     now_unix - 60LL)
            .value();

    const auto old_ref = fixture.publish(old_commit, "old", false);
    const auto mid_ref = fixture.publish(mid_commit, "mid", false);
    fixture.publish(head_commit, "head", true);
    const auto old_content = fixture.put_content("old", "old");
    const auto mid_content = fixture.put_content("mid", "mid");
    const auto live_content = fixture.put_content("live", "live");
    fixture.state->object_mtimes[live_content] = now_unix - 60LL;
    fixture.state->object_mtimes[object_path(mid_ref)] =
        now_unix - 2LL * 3600LL;
    fixture.state->object_mtimes[object_path(old_ref)] =
        now_unix - 10LL * 3600LL;
    fixture.state->object_mtimes[old_content] = now_unix - 10LL * 3600LL;

    const Epoch epoch{
        .vault_id = std::string(64, 'a'),
        .sequence = 0,
        .issued_at = now_unix - 3600LL,
        .policy = {},
        .anchors = {Anchor{.commit_id = commit_id(mid_commit), .height = 1}},
    };
    const auto sealed =
        kasumi::application::history_storage::epoch::seal(epoch, test_key());
    ASSERT_TRUE(sealed.has_value());
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        fixture.transport,
        test_key(),
        *sealed,
        kasumi::test::workspace_root(fixture.workspace)));
    const auto epoch_object =
        kasumi::application::history_storage::epoch::object_identifier(
            layout(), sealed->reference);
    ASSERT_TRUE(epoch_object.has_value());

    const auto result =
        fixture.collect_with_options(gc_int::GarbageCollectOptions{});
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_expired_commits, 1U);
    EXPECT_EQ(result->candidate_content_objects, 1U);
    EXPECT_EQ(result->candidate_objects, 2U);
    EXPECT_EQ(result->removed_objects, 2U);
    EXPECT_GT(result->candidate_bytes, 0U);
    EXPECT_EQ(result->removed_bytes, result->candidate_bytes);
    EXPECT_FALSE(fixture.present(object_path(old_ref)));
    EXPECT_FALSE(fixture.present(old_content));
    EXPECT_TRUE(fixture.present(object_path(mid_ref)));
    EXPECT_TRUE(fixture.present(mid_content));
    EXPECT_TRUE(fixture.present(live_content));
    EXPECT_TRUE(fixture.present(*epoch_object));

    const auto audited =
        gc_int::fsck(fixture.runtime, fixture.transport, test_key());
    ASSERT_TRUE(audited.has_value()) << audited.error().detail;
    const auto history = kasumi::application::history_storage::load_history(
        fixture.transport,
        test_key(),
        kasumi::test::workspace_root(fixture.workspace));
    ASSERT_TRUE(history.has_value()) << history.error().detail;
}

TEST(GarbageCollectionTest, UnmarkedReachableCommitKeepsOneRequiredVariant) {
    LocalFixture fixture;
    const auto parent = commit_with_file("parent");
    const auto child_tree = commit_with_file("child").tree;
    const auto child =
        kasumi::history::make_commit(1, {commit_id(parent)}, child_tree)
            .value();
    const auto parent_head = fixture.publish(parent, "parent");
    fixture.publish(child, "child");
    fixture.put_content("child", "child");
    fixture.put_content("parent", "parent");
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
    const bool original_present = fixture.present(object_path(parent_head));
    const bool extra_present = fixture.present(object_path(extra));
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
    ResetCancellation reset_guard;

    const auto result =
        fixture.collect([](const GarbageCollectProgress& progress) {
            if (progress.stage == GarbageCollectStage::Applying) {
                kasumi::platform::cancellation::request();
            }
        });
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, GcErrorCode::StateFailure);
    EXPECT_TRUE(fixture.present(repository.orphan_content));
    EXPECT_TRUE(fixture.present(object_path(repository.redundant_variant)));
}

// Old contract: a post-REMOVE presence read confirmed physical absence.
// New contract: a successful REMOVE is API-acknowledged and is not read back.
TEST(GarbageCollectionTest, SuccessfulRemoveIsNotReadBackWithPresence) {
    FakeFixture fixture("gc-post-removal-visibility");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    const auto first = fixture.put_content("orphan-a", "a");
    const auto second = fixture.put_content("orphan-b", "b");
    fixture.state->fail_presence_after_removal_identifier =
        std::min(first, second);
    fixture.state->remove_count = 0;

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->removed_objects, 2U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 2U);
    fixture.state->fail_presence_after_removal_identifier.clear();
    EXPECT_FALSE(fixture.present(first));
    EXPECT_FALSE(fixture.present(second));
}

// PARTIAL-R01: analysis failure before Apply keeps zero mutation counts.
TEST(GarbageCollectionTest, AnalysisFailureBeforeApplyKeepsZeroCounts) {
    FakeFixture fixture("gc-partial-before-first");
    const auto head = commit_with_file("live");
    const auto reference = fixture.publish(head, "head");
    fixture.put_content("live", "live");
    fixture.put_content("orphan", "orphan");
    const auto head_object = object_path(reference);
    after_full_list(fixture.state, 1, [head_object](FakeState& state) {
        state.objects[head_object] = {0xde, 0xad, 0xbe, 0xef};
    });

    const auto diagnostic = collect_diagnostic(fixture);
    ASSERT_TRUE(diagnostic.has_value());
    EXPECT_EQ(diagnostic->stage, GarbageCollectStage::Analyzing);
    EXPECT_EQ(diagnostic->confirmed_removed, 0U);
    EXPECT_FALSE(diagnostic->failed_identifier.has_value());
    EXPECT_EQ(diagnostic->mutation_state,
              kasumi::application::GarbageCollectMutationState::NotAttempted);
    EXPECT_TRUE(diagnostic->barrier_release_attempted);
    EXPECT_TRUE(diagnostic->barrier_release_confirmed);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
}

// PARTIAL-R02
TEST(GarbageCollectionTest, PartialFailureAtThirtySeventhRemovalKeepsCounts) {
    FakeFixture fixture("gc-partial-thirty-seven");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    std::vector<std::string> orphans;
    for (std::size_t index = 0; index < 100; ++index) {
        orphans.push_back(
            fixture.put_content("partial-" + std::to_string(index),
                                "partial-" + std::to_string(index)));
    }
    std::ranges::sort(orphans);
    fixture.state->fail_candidate_remove_at = 37;
    fixture.state->remove_failure_native_code = 123;

    const auto diagnostic = collect_diagnostic(fixture);
    ASSERT_TRUE(diagnostic.has_value());
    EXPECT_EQ(diagnostic->candidate_objects, 100U);
    EXPECT_EQ(diagnostic->confirmed_removed, 36U);
    EXPECT_EQ(diagnostic->failed_identifier,
              std::optional<std::string>{orphans[36]});
    EXPECT_EQ(diagnostic->stage, GarbageCollectStage::Applying);
    EXPECT_EQ(diagnostic->mutation_state,
              kasumi::application::GarbageCollectMutationState::Uncertain);
    ASSERT_TRUE(diagnostic->transport_error.has_value());
    EXPECT_EQ(diagnostic->transport_error->code,
              kasumi::transport::ErrorCode::Io);
    EXPECT_EQ(diagnostic->transport_error->native_code, 123);
    EXPECT_TRUE(diagnostic->barrier_release_attempted);
    EXPECT_TRUE(diagnostic->barrier_release_confirmed);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 37U);
    EXPECT_FALSE(fixture.present(orphans[35]));
    EXPECT_TRUE(fixture.present(orphans[36]));
    EXPECT_TRUE(fixture.present(orphans[37]));
}

// PARTIAL-R03
TEST(GarbageCollectionTest,
     AmbiguousRemovalPreservesNativeCodeAndUncertainMutation) {
    FakeFixture fixture("gc-partial-ambiguous");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    const auto orphan = fixture.put_content("orphan", "orphan");
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
    EXPECT_FALSE(fixture.present(orphan));
}

// PLAN-R04: the third of eight REMOVE calls fails with an ambiguous I/O
// result. Two are acknowledged, the third is uncertain, and no fourth starts.
TEST(GarbageCollectionTest, ThirdRemovalFailureKeepsPartialDiagnostic) {
    FakeFixture fixture("gc-partial-third-remove");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    std::vector<std::string> orphans;
    for (std::size_t index = 0; index < 8; ++index) {
        orphans.push_back(
            fixture.put_content("third-" + std::to_string(index),
                                "third-" + std::to_string(index)));
    }
    std::ranges::sort(orphans);
    fixture.state->fail_candidate_remove_at = 3;
    fixture.state->remove_failure_native_code = 456;
    fixture.state->remove_attempts.clear();

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, GcErrorCode::TransportFailure);
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
    EXPECT_EQ(diagnostic.transport_error->code,
              kasumi::transport::ErrorCode::Io);
    EXPECT_EQ(diagnostic.transport_error->native_code, 456);
    EXPECT_TRUE(diagnostic.barrier_release_attempted);
    EXPECT_TRUE(diagnostic.barrier_release_confirmed);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 3U);
    EXPECT_FALSE(fixture.present(orphans[0]));
    EXPECT_FALSE(fixture.present(orphans[1]));
    EXPECT_TRUE(fixture.present(orphans[2]));
    EXPECT_TRUE(fixture.present(orphans[3]));
}

// PARTIAL-R06 / BARRIER-R07
TEST(GarbageCollectionTest,
     CancellationAfterConfirmedRemovalPreservesCountsAndCleanup) {
    FakeFixture fixture("gc-partial-cancellation");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    std::vector<std::string> orphans;
    for (const std::string_view name : {"cancel-a", "cancel-b", "cancel-c"}) {
        orphans.push_back(fixture.put_content(name, name));
    }
    std::ranges::sort(orphans);
    ResetCancellation reset_guard;

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
    EXPECT_FALSE(fixture.present(orphans.front()));
    EXPECT_TRUE(fixture.present(orphans[1]));
    EXPECT_TRUE(fixture.present(orphans[2]));
}

TEST(GarbageCollectionTest, AnalysisOnlyCountsCorruptCandidates) {
    FakeFixture fixture("gc-analysis-only-corrupt");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
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

    ASSERT_TRUE(expect_collect_error(fixture, GcErrorCode::ConcurrentChange));
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

    ASSERT_TRUE(expect_collect_error(fixture, GcErrorCode::ConcurrentChange));
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
    EXPECT_TRUE(protocol::release_registration(*writer));
}

TEST(GarbageCollectionTest, CooperativeWriterCannotRegisterWhileBarrierActive) {
    FakeFixture fixture("gc-writer-during-apply");
    seed_repository(fixture.transport, fixture.workspace);
    auto barrier = protocol::establish_barrier(
        fixture.transport,
        layout(),
        kasumi::test::workspace_root(fixture.workspace));
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
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    const auto first = fixture.put_content("orphan-a", "a");
    const auto second = fixture.put_content("orphan-b", "b");
    fixture.state->replace_barrier_after_source_remove_count = 1;
    fixture.state->remove_count = 0;

    const auto diagnostic = collect_diagnostic(fixture);
    ASSERT_TRUE(diagnostic.has_value());
    EXPECT_EQ(diagnostic->confirmed_removed, 2U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 2U);
    EXPECT_FALSE(fixture.present(std::min(first, second)));
    EXPECT_FALSE(fixture.present(std::max(first, second)));
    EXPECT_FALSE(diagnostic->barrier_release_attempted);
    EXPECT_TRUE(fixture.present(layout().barrier_identifier));
}

// BARRIER-R01
TEST(GarbageCollectionTest, SuccessfulRunReleasesBarrierExactlyOnce) {
    FakeFixture fixture("gc-barrier-success");
    seed_repository(fixture.transport, fixture.workspace);
    fixture.state->remove_attempts.clear();

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 1U);
    EXPECT_FALSE(fixture.present(layout().barrier_identifier));
}

// BARRIER-R02
TEST(GarbageCollectionTest,
     PrimaryFailureKeepsSuccessfulBarrierCleanupDiagnostic) {
    FakeFixture fixture("gc-barrier-primary-cleanup-ok");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    const auto orphan = fixture.put_content("orphan", "orphan");
    fixture.state->fail_candidate_remove_at = 1;
    fixture.state->remove_attempts.clear();

    const auto diagnostic = collect_diagnostic(fixture);
    ASSERT_TRUE(diagnostic.has_value());
    EXPECT_EQ(diagnostic->failed_identifier,
              std::optional<std::string>{orphan});
    EXPECT_TRUE(diagnostic->barrier_release_attempted);
    EXPECT_TRUE(diagnostic->barrier_release_confirmed);
    EXPECT_FALSE(diagnostic->barrier_cleanup_error.has_value());
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 1U);
    EXPECT_FALSE(fixture.present(layout().barrier_identifier));
}

// BARRIER-R03
TEST(GarbageCollectionTest,
     PrimaryAndBarrierCleanupFailuresRemainDistinguishable) {
    FakeFixture fixture("gc-barrier-primary-cleanup-fail");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    const auto orphan = fixture.put_content("orphan", "orphan");
    fixture.state->fail_candidate_remove_at = 1;
    fixture.state->fail_remove_identifier = layout().barrier_identifier;
    fixture.state->remove_failure_native_code = 777;
    fixture.state->remove_attempts.clear();

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, GcErrorCode::TransportFailure);
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
    EXPECT_TRUE(fixture.present(layout().barrier_identifier));
}

// BARRIER-R04
TEST(GarbageCollectionTest, AmbiguousBarrierRemovalIsNotRetriedOrConfirmed) {
    FakeFixture fixture("gc-barrier-ambiguous-release");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    const auto orphan = fixture.put_content("orphan", "orphan");
    fixture.state->remove_then_fail_identifier = layout().barrier_identifier;
    fixture.state->remove_failure_native_code = 778;
    fixture.state->remove_attempts.clear();

    const auto diagnostic = collect_diagnostic(fixture);
    ASSERT_TRUE(diagnostic.has_value());
    EXPECT_EQ(diagnostic->candidate_objects, 1U);
    EXPECT_EQ(diagnostic->confirmed_removed, 1U);
    EXPECT_EQ(diagnostic->stage, GarbageCollectStage::Finalizing);
    EXPECT_EQ(diagnostic->mutation_state,
              kasumi::application::GarbageCollectMutationState::Confirmed);
    EXPECT_TRUE(diagnostic->barrier_release_attempted);
    EXPECT_FALSE(diagnostic->barrier_release_confirmed);
    ASSERT_TRUE(diagnostic->barrier_cleanup_transport_error.has_value());
    EXPECT_EQ(diagnostic->barrier_cleanup_transport_error->native_code, 778);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 1U);
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 1U);
    EXPECT_FALSE(fixture.present(orphan));
    EXPECT_FALSE(fixture.present(layout().barrier_identifier));
}

// BARRIER-R05
TEST(GarbageCollectionTest, ForeignBarrierIsNotRemovedDuringCleanup) {
    FakeFixture fixture("gc-barrier-foreign-cleanup");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    const auto first = fixture.put_content("orphan-a", "a");
    const auto second = fixture.put_content("orphan-b", "b");
    fixture.state->replace_barrier_after_source_remove_count = 1;
    fixture.state->remove_attempts.clear();

    const auto diagnostic = collect_diagnostic(fixture);
    ASSERT_TRUE(diagnostic.has_value());
    EXPECT_FALSE(diagnostic->barrier_release_attempted);
    EXPECT_FALSE(diagnostic->barrier_release_confirmed);
    EXPECT_EQ(diagnostic->confirmed_removed, 2U);
    ASSERT_TRUE(diagnostic->barrier_cleanup_error.has_value());
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 0U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 2U);
    EXPECT_TRUE(fixture.present(layout().barrier_identifier));
    EXPECT_FALSE(fixture.present(std::min(first, second)));
    EXPECT_FALSE(fixture.present(std::max(first, second)));
}

TEST(GarbageCollectionTest, ExceptionDuringApplyKeepsPartialDiagnostic) {
    FakeFixture fixture("gc-apply-exception");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    std::vector<std::string> orphans;
    for (const std::string_view name : {"apply-a", "apply-b"}) {
        orphans.push_back(fixture.put_content(name, name));
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
    EXPECT_EQ(result.error().code, GcErrorCode::StateFailure);
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
    EXPECT_TRUE(fixture.present(orphans.front()));
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
    EXPECT_EQ(result.error().code, GcErrorCode::StateFailure);
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
    EXPECT_TRUE(fixture.present(layout().barrier_identifier));
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
    EXPECT_EQ(result.error().code, GcErrorCode::StateFailure);
    EXPECT_NE(result.error().detail.find("injected analysis exception"),
              std::string::npos);
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 1U);
    EXPECT_FALSE(fixture.present(layout().barrier_identifier));
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
    EXPECT_TRUE(fixture.present(repository.orphan_content));
}

TEST(GarbageCollectionTest, ProbeTransportFailureFailsClosed) {
    FakeFixture fixture("gc-probe-failure");
    seed_repository(fixture.transport, fixture.workspace);
    fixture.state->fail_probe_listing = true;
    fixture.state->remove_count = 0;

    ASSERT_TRUE(expect_collect_error(fixture, GcErrorCode::TransportFailure));
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
}

TEST(GarbageCollectionTest, ObjectsAppearingAfterObservationAreNotPlanned) {
    FakeFixture fixture("gc-divergent-observation");
    const auto repository =
        seed_repository(fixture.transport, fixture.workspace);
    const auto hidden = fixture.put_content("hidden", "hidden");
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
    EXPECT_TRUE(fixture.present(hidden));
    EXPECT_FALSE(fixture.present(repository.orphan_content));
    EXPECT_FALSE(fixture.present(object_path(repository.redundant_variant)));
}

TEST(GarbageCollectionTest,
     CandidateMissingAfterListRemainsInFrozenPlanAndAcknowledgesAbsent) {
    FakeFixture fixture("gc-missing-candidate");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    const auto orphan = fixture.put_content("extra", "extra");
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
    fixture.publish(commit_with_file("live"), "head");
    const auto live = fixture.put_content("live", "live");
    const auto orphan = fixture.put_content("orphan", "orphan");
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
    EXPECT_TRUE(fixture.present(live));
    EXPECT_FALSE(fixture.present(orphan));
    EXPECT_EQ(fixture.state->orphan_payload_get_count, 0U);
    EXPECT_EQ(std::ranges::count(get_calls, orphan), 0);
}

TEST(GarbageCollectionTest, OrphanRemovalSucceedsWhenContentGetFails) {
    FakeFixture fixture("gc-orphan-get-fail");
    fixture.publish(commit_with_file("live"), "head");
    const auto live = fixture.put_content("live", "live");
    const auto orphan = fixture.put_content("orphan", "orphan");
    fixture.state->fail_get_identifier = orphan;

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 1U);
    EXPECT_EQ(result->removed_objects, 1U);
    EXPECT_TRUE(fixture.present(live));
    EXPECT_FALSE(fixture.present(orphan));
}

TEST(GarbageCollectionTest, ManyOrphansCollectedWithZeroContentGets) {
    FakeFixture fixture("gc-many-orphans");
    fixture.publish(commit_with_file("live"), "head");
    const auto live = fixture.put_content("live", "live");

    std::unordered_set<std::string> orphan_ids;
    for (std::size_t i = 0; i < 50; ++i) {
        const auto id = fixture.put_content("orphan-" + std::to_string(i),
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
    EXPECT_TRUE(fixture.present(live));
    EXPECT_EQ(fixture.state->orphan_payload_get_count, 0U);
    EXPECT_EQ(fixture.state->full_list_count, 1U);
    for (const auto& id : orphan_ids) {
        EXPECT_FALSE(fixture.present(id));
        EXPECT_EQ(std::ranges::count(get_calls, id), 0);
        EXPECT_EQ(
            std::ranges::count(fixture.state->gc_events, "physical_hash:" + id),
            0);
    }
}

TEST(GarbageCollectionTest, ReferencedCorruptContentIsPreservedWithoutGet) {
    FakeFixture fixture("gc-referenced-corrupt");
    fixture.publish(commit_with_file("live"), "head");
    put_corrupt_content(fixture.transport, fixture.workspace, "live", "live");
    const auto live = content_identifier("live");
    const auto orphan = fixture.put_content("orphan", "orphan");

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
    EXPECT_TRUE(fixture.present(live));
    EXPECT_FALSE(fixture.present(orphan));
    EXPECT_EQ(std::ranges::count(get_calls, live), 0);
    EXPECT_EQ(std::ranges::count(get_calls, orphan), 0);
}

TEST(GarbageCollectionTest, RemovalFailureIsNotRetried) {
    FakeFixture fixture("gc-remove-failure");
    seed_repository(fixture.transport, fixture.workspace);
    const auto extra = fixture.put_content("extra", "extra");
    fixture.state->fail_candidate_remove_at = 1;
    fixture.state->remove_failure_native_code = 23;
    fixture.state->remove_count = 0;

    ASSERT_TRUE(expect_collect_error(fixture, GcErrorCode::TransportFailure));
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 1U);
    EXPECT_TRUE(fixture.present(extra));
}

TEST(GarbageCollectionTest, AmbiguousRemovalStopsWithoutCompensatingRetry) {
    FakeFixture fixture("gc-ambiguous-remove");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    const auto first = fixture.put_content("orphan-a", "a");
    const auto second = fixture.put_content("orphan-b", "b");
    const auto removed = std::min(first, second);
    fixture.state->remove_then_fail_identifier = removed;
    fixture.state->remove_failure_native_code = 41;
    fixture.state->remove_count = 0;

    ASSERT_TRUE(expect_collect_error(fixture, GcErrorCode::TransportFailure));
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 1U);
    EXPECT_FALSE(fixture.present(removed));
    EXPECT_TRUE(fixture.present(std::max(first, second)));
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
    EXPECT_FALSE(fixture.present(repository.orphan_content));
    EXPECT_FALSE(fixture.present(object_path(repository.redundant_variant)));
    EXPECT_TRUE(fixture.present(repository.live_content));
    EXPECT_TRUE(fixture.present(object_path(repository.head)));
    EXPECT_TRUE(fixture.present(*epoch_object));

    const auto audit =
        gc_int::fsck(fixture.runtime, fixture.storage.transport, test_key(), 1);
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
    fixture.runtime.min_history_age_hours = 0;
    seed_repository(fixture.storage.transport, fixture.storage.workspace);

    const auto invalid = gc_int::garbage_collect(
        fixture.runtime, fixture.storage.transport, test_key(), 1, 0, 1);
    ASSERT_FALSE(invalid.has_value());
    EXPECT_EQ(invalid.error().code, GcErrorCode::InvalidInput);

    const auto valid = gc_int::garbage_collect(
        fixture.runtime, fixture.storage.transport, test_key(), 2, 3, 4);
    ASSERT_TRUE(valid.has_value()) << valid.error().detail;
    EXPECT_EQ(valid->removed_objects, 2U);
}

TEST(GarbageCollectionTest, FailureInjectionPositionsStopAfterOneAttempt) {
    for (const std::size_t position : {0U, 1U, 5U, 50U, 99U}) {
        SCOPED_TRACE("candidate position " + std::to_string(position));
        FakeFixture fixture("gc-injection");
        fixture.publish(commit_with_file("live"), "head");
        fixture.put_content("live", "live");
        std::vector<std::string> orphans;
        for (std::size_t index = 0; index < 100; ++index) {
            orphans.push_back(
                fixture.put_content("orphan-" + std::to_string(index),
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
        EXPECT_EQ(result.error().code, GcErrorCode::TransportFailure);
        EXPECT_EQ(candidate_remove_attempts(*fixture.state), position);
        if (position > 1) {
            EXPECT_FALSE(fixture.present(orphans[position - 2]));
        }
        EXPECT_TRUE(fixture.present(orphans[position - 1]));
    }
}

TEST(GarbageCollectionBenchmarkTest, ZeroCandidates) {
    LocalFixture fixture;
    fixture.publish(commit_with_file("live"), "bench-zero-head");
    const auto protected_content = fixture.put_content("live", "bench-live");

    const auto result = measure_gc(fixture, "0_candidates");
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 0U);
    EXPECT_EQ(result->removed_objects, 0U);
    EXPECT_TRUE(fixture.present(protected_content));
}

TEST(GarbageCollectionBenchmarkTest, TenOrphanContents) {
    LocalFixture fixture;
    fixture.publish(commit_with_file("live"), "bench-ten-head");
    const auto protected_content =
        fixture.put_content("live", "bench-ten-live");
    std::vector<std::string> orphans;
    for (std::size_t index = 0; index < 10; ++index) {
        const auto contents = "bench-ten-orphan-" + std::to_string(index);
        orphans.push_back(fixture.put_content(contents, contents));
    }

    const auto result = measure_gc(fixture, "10_content_orphans");
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 10U);
    EXPECT_EQ(result->removed_objects, 10U);
    EXPECT_TRUE(fixture.present(protected_content));
    EXPECT_TRUE(std::ranges::all_of(orphans, [&](const auto& identifier) {
        return !fixture.present(identifier);
    }));
}

TEST(GarbageCollectionBenchmarkTest, OneHundredContentOrphans) {
    LocalFixture fixture;
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    std::vector<std::string> orphans;
    for (std::size_t index = 0; index < 100; ++index) {
        orphans.push_back(
            fixture.put_content("load-content-" + std::to_string(index),
                                "load-content-" + std::to_string(index)));
    }

    const auto result = measure_gc(fixture, "100_content_orphans");
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 100U);
    EXPECT_EQ(result->removed_objects, 100U);
    EXPECT_TRUE(std::ranges::all_of(orphans, [&](const auto& identifier) {
        return !fixture.present(identifier);
    }));
}

void benchmark_redundant_variants(std::size_t candidate_count) {
    LocalFixture fixture;
    const auto parent = commit_with_file("parent");
    const auto child_tree = commit_with_file("child").tree;
    const auto child =
        kasumi::history::make_commit(1, {commit_id(parent)}, child_tree)
            .value();
    fixture.publish(parent, "load-parent");
    fixture.publish(child, "load-child");
    fixture.put_content("parent", "load-parent-content");
    fixture.put_content("child", "load-child-content");
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

    const auto result = measure_gc(fixture,
                                   std::to_string(candidate_count) +
                                       "_redundant_commit_variants");
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, candidate_count);
    EXPECT_EQ(result->removed_objects, candidate_count);
    EXPECT_TRUE(std::ranges::all_of(variants, [&](const auto& variant) {
        return !fixture.present(object_path(variant));
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
    fixture.publish(commit, "head");
    fixture.put_content("live", "live");
    for (std::size_t index = 0; index < 50; ++index) {
        add_variant_object(fixture.storage.transport,
                           fixture.storage.workspace,
                           commit,
                           "hybrid-variant-" + std::to_string(index));
        fixture.put_content("hybrid-content-" + std::to_string(index),
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
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    for (std::size_t index = 0; index < 1000; ++index) {
        fixture.put_content("thousand-" + std::to_string(index),
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
    fixture.publish(commit, "head");
    fixture.put_content("live", "live");
    const auto orphan = fixture.put_content("orphan", "orphan");
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
    EXPECT_FALSE(fixture.present(orphan));
    EXPECT_TRUE(fixture.present(*epoch_object));
}

// These cases used to be caught by per-candidate history revalidation. Under
// cooperative exclusivity they are non-cooperative mutations after the
// authoritative observation, so Apply keeps its frozen plan and does not
// perform a second read. The barrier still keeps its special cleanup rules.
class PostApplyMutationTest : public testing::TestWithParam<std::string> {};

TEST_P(PostApplyMutationTest, MutationAfterFirstRemovalDoesNotChangeThePlan) {
    FakeFixture fixture("gc-variant-concurrent-change");
    const auto parent = commit_with_file("parent");
    const auto parent_reference = fixture.publish(parent, "parent", false);
    const auto child =
        kasumi::history::make_commit(
            1, {commit_id(parent)}, commit_with_file("live").tree)
            .value();
    const auto head = fixture.publish(child, "head");
    fixture.put_content("parent", "parent-content");
    fixture.put_content("live", "live-content");
    const auto a = fixture.add_variant(child, "a");
    const auto b = fixture.add_variant(child, "b");
    const auto first = std::min(object_path(a), object_path(b));
    const auto second = std::max(object_path(a), object_path(b));
    const auto second_reference = object_path(a) == second ? a : b;
    const Epoch epoch{.vault_id = std::string(64, 'a'),
                      .sequence = 0,
                      .issued_at = 1,
                      .policy = {},
                      .anchors = {Anchor{commit_id(parent), 0}}};
    const auto sealed =
        kasumi::application::history_storage::epoch::seal(epoch, test_key());
    ASSERT_TRUE(sealed.has_value());
    ASSERT_TRUE(kasumi::application::history_storage::epoch::publish(
        fixture.transport,
        test_key(),
        *sealed,
        kasumi::test::workspace_root(fixture.workspace)));
    const auto epoch_id =
        kasumi::application::history_storage::epoch::object_identifier(
            layout(), sealed->reference)
            .value();
    const auto change = GetParam();
    fixture.state->on_operation = [=](FakeState& state,
                                      std::string_view operation,
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
            state.objects[layout().writers_prefix + std::string(32, 'a')] = {
                'w'};
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
    EXPECT_FALSE(fixture.present(first));
    EXPECT_FALSE(fixture.present(second));
    if (change == "barrier") {
        ASSERT_FALSE(result.has_value());
        ASSERT_TRUE(result.error().garbage_collection.has_value());
        const auto& diagnostic = *result.error().garbage_collection;
        EXPECT_EQ(diagnostic.confirmed_removed, 2U);
        EXPECT_EQ(barrier_remove_attempts(*fixture.state), 0U);
        EXPECT_TRUE(fixture.present(layout().barrier_identifier));
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
    GcOptimization,
    PostApplyMutationTest,
    testing::Values("head",
                    "alternative_missing",
                    "alternative_replaced",
                    "candidate_replaced",
                    "unmarked_parent_replaced",
                    "marker_replaced",
                    "epoch_replaced",
                    "writer",
                    "barrier",
                    "namespace",
                    "exception_cleanup"),
    [](const testing::TestParamInfo<std::string>& parameter) {
        return parameter.param;
    });

TEST(GarbageCollectionOptimizationTest, UncertainVariantRemoveIsNeverRetried) {
    FakeFixture fixture("gc-variant-uncertain");
    const auto commit = commit_with_file("live");
    fixture.publish(commit, "head");
    fixture.put_content("live", "content");
    const auto a = object_path(fixture.add_variant(commit, "a"));
    const auto b = object_path(fixture.add_variant(commit, "b"));
    fixture.state->remove_then_fail_identifier = std::min(a, b);
    fixture.state->remove_attempts.clear();
    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    EXPECT_EQ(result.error().garbage_collection->confirmed_removed, 0U);
    EXPECT_EQ(result.error().garbage_collection->mutation_state,
              kasumi::application::GarbageCollectMutationState::Uncertain);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 1U);
    EXPECT_TRUE(fixture.present(std::max(a, b)));
}

TEST(GarbageCollectionOptimizationTest, PlanPreservesOneVariantPerCommit) {
    FakeFixture fixture("gc-distinct-variant-commits");
    std::vector<std::string> heads;
    std::vector<std::string> redundant;
    for (const std::string_view contents : {"a", "b"}) {
        const auto commit = commit_with_file(contents);
        heads.push_back(object_path(
            fixture.publish(commit, std::string{contents} + "-head")));
        fixture.put_content(contents, contents);
        redundant.push_back(object_path(
            fixture.add_variant(commit, std::string{contents} + "-variant")));
    }
    std::ranges::sort(redundant);
    fixture.state->remove_attempts.clear();
    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 2U);
    EXPECT_EQ(result->removed_objects, 2U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 2U);
    for (const auto& identifier : heads) {
        EXPECT_TRUE(fixture.present(identifier));
    }
    for (const auto& identifier : redundant) {
        EXPECT_FALSE(fixture.present(identifier));
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
    const auto head = fixture.publish(commit, "head");
    fixture.put_content("live", "content");
    for (std::size_t index = 0; index < 10; ++index) {
        fixture.add_variant(commit, "variant-" + std::to_string(index));
    }
    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->removed_objects, 10U);
    EXPECT_TRUE(fixture.present(object_path(head)));
}

TEST(GarbageCollectionOptimizationTest,
     FailedListDoesNotCountAnUnperformedReconstruction) {
    FakeFixture fixture("gc-reconstruction-counter");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "content");
    fixture.put_content("orphan", "orphan");
    fixture.state->fail_list = kasumi::transport::ErrorCode::Io;
    fixture.state->fail_list_at = 1;
    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
}

// RERUN: acknowledged removals survive a partial failure. A new run starts from
// a fresh observation and re-plans the objects that are still present.
TEST(GarbageCollectionTest, NewRunAfterPartialFailureReplansFromCurrentState) {
    FakeFixture fixture("gc-rerun-after-partial-failure");
    const auto head = fixture.publish(commit_with_file("live"), "head");
    const auto live = fixture.put_content("live", "live");
    std::vector<std::string> orphans;
    for (std::size_t index = 0; index < 6; ++index) {
        orphans.push_back(
            fixture.put_content("rerun-" + std::to_string(index),
                                "rerun-" + std::to_string(index)));
    }
    std::ranges::sort(orphans);

    fixture.state->fail_candidate_remove_at = 3;
    fixture.state->remove_failure_native_code = 456;
    fixture.state->remove_attempts.clear();
    const auto first_diagnostic = collect_diagnostic(fixture);
    ASSERT_TRUE(first_diagnostic.has_value());
    EXPECT_EQ(first_diagnostic->candidate_objects, 6U);
    EXPECT_EQ(first_diagnostic->confirmed_removed, 2U);
    EXPECT_EQ(first_diagnostic->failed_identifier,
              std::optional<std::string>{orphans[2]});
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 3U);
    EXPECT_FALSE(fixture.present(orphans[0]));
    EXPECT_FALSE(fixture.present(orphans[1]));
    EXPECT_TRUE(fixture.present(orphans[2]));

    fixture.state->fail_candidate_remove_at = 0;
    fixture.state->remove_failure_native_code = 0;
    fixture.state->remove_attempts.clear();
    const auto second = fixture.collect();
    ASSERT_TRUE(second.has_value()) << second.error().detail;
    EXPECT_EQ(second->candidate_objects, 4U);
    EXPECT_EQ(second->removed_objects, 4U);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 4U);
    for (const auto& orphan : orphans) {
        EXPECT_FALSE(fixture.present(orphan));
    }
    EXPECT_TRUE(fixture.present(live));
    EXPECT_TRUE(fixture.present(object_path(head)));

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
    const auto head = fixture.publish(commit, "three-head");
    fixture.put_content("live", "live");
    std::vector<std::string> variants{object_path(head)};
    for (const std::string_view suffix : {"three-a", "three-b"}) {
        variants.push_back(
            object_path(add_variant_object(fixture.storage.transport,
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
                                        return fixture.present(identifier);
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
    const auto reference = fixture.publish(head, "head");
    const auto live = fixture.put_content("live", "live");
    std::vector<std::string> orphans;
    for (std::size_t index = 0; index < count; ++index) {
        orphans.push_back(fixture.put_content("plan-" + std::to_string(index),
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
    EXPECT_TRUE(fixture.present(live));
    EXPECT_TRUE(fixture.present(object_path(reference)));
    for (const auto& identifier : orphans) {
        EXPECT_FALSE(fixture.present(identifier));
    }
}

INSTANTIATE_TEST_SUITE_P(
    GcPlan,
    GlobalPlanSizeTest,
    testing::Values(0U, 1U, 2U, 7U, 8U, 9U, 64U),
    [](const testing::TestParamInfo<std::size_t>& parameter) {
        return "N" + std::to_string(parameter.param);
    });

TEST(GarbageCollectionTest, GlobalPlanPreservesAnchoredCommitVariant) {
    LocalFixture fixture;
    const auto parent = commit_with_file("parent");
    const auto child =
        kasumi::history::make_commit(
            1, {commit_id(parent)}, commit_with_file("child").tree)
            .value();
    fixture.publish(parent, "anchor-parent");
    fixture.publish(child, "anchor-child");
    fixture.put_content("parent", "anchor-parent-content");
    fixture.put_content("child", "anchor-child-content");
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
    EXPECT_FALSE(fixture.present(object_path(parent_variant)));
    EXPECT_FALSE(fixture.present(object_path(child_variant)));
    EXPECT_TRUE(fixture.present(*epoch_object));

    const auto inventory =
        kasumi::application::history_storage::inventory_reachability(
            fixture.storage.transport,
            test_key(),
            kasumi::test::workspace_root(fixture.storage.workspace));
    ASSERT_TRUE(inventory.has_value()) << inventory.error().detail;
    EXPECT_NE(
        std::ranges::find(inventory->reachable_commits, commit_id(parent)),
        inventory->reachable_commits.end());
    EXPECT_NE(std::ranges::find(inventory->reachable_commits, commit_id(child)),
              inventory->reachable_commits.end());
}

struct FakeBatchFixture : FakeFixture {
    explicit FakeBatchFixture(std::string_view name) : FakeFixture(name) {
        enable_fake_remove_batch(transport, *state);
    }
};

// 1. Divisao exata dos lotes em 0, 1, 7, 8, 9, 16, 17 e 1.000 candidatos.
TEST(GarbageCollectionTest, BatchDivisionExactForVariousCandidateCounts) {
    struct Case {
        std::size_t candidate_count;
        std::size_t expected_batches;
        std::vector<std::size_t> expected_batch_sizes;
    };

    const std::vector<Case> cases = {
        {0, 0, {}},
        {1, 1, {1}},
        {7, 1, {7}},
        {8, 1, {8}},
        {9, 2, {8, 1}},
        {16, 2, {8, 8}},
        {17, 3, {8, 8, 1}},
        {1000, 125, std::vector<std::size_t>(125, 8)},
    };

    for (const auto& [candidate_count, expected_batches, expected_batch_sizes] :
         cases) {
        SCOPED_TRACE("candidate_count " + std::to_string(candidate_count));
        FakeBatchFixture fixture("gc-batch-div-" +
                                 std::to_string(candidate_count));
        fixture.publish(commit_with_file("live"), "head");
        fixture.put_content("live", "live");

        std::vector<std::string> orphans;
        orphans.reserve(candidate_count);
        for (std::size_t index = 0; index < candidate_count; ++index) {
            orphans.push_back(
                fixture.put_content("orphan-" + std::to_string(index),
                                    "orphan-" + std::to_string(index)));
        }

        const auto result = fixture.collect();
        ASSERT_TRUE(result.has_value()) << result.error().detail;
        EXPECT_EQ(result->candidate_objects, candidate_count);
        EXPECT_EQ(result->removed_objects, candidate_count);
        EXPECT_EQ(fixture.state->remove_batch_count, expected_batches);
        EXPECT_EQ(fixture.state->remove_batch_sizes, expected_batch_sizes);
        if (expected_batches > 0) {
            EXPECT_EQ(fixture.state->remove_batch_concurrency, 8U);
        }
    }
}

// 2. concurrency == 8, com nenhum lote contendo mais de oito identificadores.
TEST(GarbageCollectionTest, BatchConcurrencyIsEightAndBatchesNeverExceedEight) {
    FakeBatchFixture fixture("gc-batch-concurrency");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");

    for (std::size_t index = 0; index < 20; ++index) {
        fixture.put_content("batch20-" + std::to_string(index),
                            "batch20-" + std::to_string(index));
    }

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->removed_objects, 20U);
    EXPECT_EQ(fixture.state->remove_batch_count, 3U);
    EXPECT_EQ(fixture.state->remove_batch_concurrency, 8U);
    const std::vector<std::size_t> expected_sizes = {8, 8, 4};
    EXPECT_EQ(fixture.state->remove_batch_sizes, expected_sizes);
    for (const auto size : fixture.state->remove_batch_sizes) {
        EXPECT_LE(size, 8U);
    }
}

// 3. Ausencia de lote seguinte enquanto o anterior nao tiver sido concluido.
TEST(GarbageCollectionTest, BatchDoesNotStartNextBeforePreviousCompletes) {
    FakeBatchFixture fixture("gc-batch-sequence");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");

    for (std::size_t index = 0; index < 16; ++index) {
        fixture.put_content("seq-" + std::to_string(index),
                            "seq-" + std::to_string(index));
    }

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->removed_objects, 16U);
    EXPECT_EQ(fixture.state->remove_batch_count, 2U);
    const std::vector<std::string> expected_events = {
        "batch_1_started",
        "batch_1_completed",
        "batch_2_started",
        "batch_2_completed",
    };
    EXPECT_EQ(fixture.state->batch_lifecycle_events, expected_events);
}

// 4. Fallback sequencial quando a capacidade nativa nao existe.
TEST(GarbageCollectionTest, BatchFallbackToSequentialWhenNativeUnsupported) {
    FakeFixture fixture("gc-batch-fallback-native");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");

    std::vector<std::string> orphans;
    for (std::size_t index = 0; index < 10; ++index) {
        orphans.push_back(
            fixture.put_content("native-fall-" + std::to_string(index),
                                "native-fall-" + std::to_string(index)));
    }

    ASSERT_EQ(fixture.transport.storage.remove_batch, nullptr);
    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->removed_objects, 10U);
    EXPECT_EQ(fixture.state->remove_batch_count, 0U);
    EXPECT_EQ(fixture.state->source_remove_count, 10U);
    for (const auto& orphan : orphans) {
        EXPECT_FALSE(fixture.present(orphan));
    }
}

// 5. Fallback apos Unsupported comprovadamente sem submissao.
TEST(GarbageCollectionTest,
     BatchFallbackAfterUnsupportedErrorWithoutSubmission) {
    FakeBatchFixture fixture("gc-batch-fallback-unsupported");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");

    std::vector<std::string> orphans;
    for (std::size_t index = 0; index < 17; ++index) {
        orphans.push_back(
            fixture.put_content("unsupp-fall-" + std::to_string(index),
                                "unsupp-fall-" + std::to_string(index)));
    }

    fixture.state->remove_batch_supported =
        false; // Returns Unsupported before submitting
    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->removed_objects, 17U);
    EXPECT_EQ(fixture.state->remove_batch_count,
              1U); // Attempted batch once, then fallback
    EXPECT_EQ(fixture.state->source_remove_count,
              17U); // All 17 deleted via sequential fallback
    for (const auto& orphan : orphans) {
        EXPECT_FALSE(fixture.present(orphan));
    }
}

// 5a. Fallback e contadores nao duplicados
TEST(GarbageCollectionTest, BatchFallbackCountersAreNotDuplicated) {
    FakeBatchFixture fixture("gc-batch-fallback-counters");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");

    for (std::size_t index = 0; index < 8; ++index) {
        fixture.put_content("fall-cnt-" + std::to_string(index),
                            "fall-cnt-" + std::to_string(index));
    }

    fixture.state->remove_batch_supported =
        false; // Unsupported before submission
    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->removed_objects, 8U);
    EXPECT_EQ(fixture.state->remove_batch_count, 1U);
    EXPECT_EQ(fixture.state->source_remove_count, 8U);
}

// 5b. Fallback com mais de um lote segue exclusivamente sequencial
TEST(GarbageCollectionTest,
     BatchFallbackAcrossMultipleBatchesFollowsSequentialOnly) {
    FakeBatchFixture fixture("gc-batch-fallback-multi");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");

    for (std::size_t index = 0; index < 17; ++index) {
        fixture.put_content("multi-fall-" + std::to_string(index),
                            "multi-fall-" + std::to_string(index));
    }

    fixture.state->remove_batch_supported = false;
    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->removed_objects, 17U);
    EXPECT_EQ(fixture.state->remove_batch_count,
              1U); // No more batches attempted
    EXPECT_EQ(fixture.state->source_remove_count, 17U);
}

// 6. Erro parcial dentro do primeiro lote.
TEST(GarbageCollectionTest,
     BatchPartialFailureWithinFirstBatchStopsSubsequentBatches) {
    FakeBatchFixture fixture("gc-batch-partial-first");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");

    std::vector<std::string> orphans;
    for (std::size_t index = 0; index < 8; ++index) {
        orphans.push_back(
            fixture.put_content("batch-part-" + std::to_string(index),
                                "batch-part-" + std::to_string(index)));
    }
    std::ranges::sort(orphans);

    // Fail candidate at index 2 (third item)
    fixture.state->remove_batch_failure = kasumi::transport::ErrorCode::Io;
    fixture.state->remove_batch_fail_single_index = 2;
    fixture.state->remove_failure_native_code = 987;

    const auto result = fixture.collect();
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, GcErrorCode::TransportFailure);
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_EQ(diagnostic.candidate_objects, 8U);
    EXPECT_EQ(diagnostic.confirmed_removed, 7U); // 7 items acknowledged
    EXPECT_EQ(diagnostic.failed_identifier,
              std::optional<std::string>{orphans[2]});
    EXPECT_EQ(diagnostic.stage, GarbageCollectStage::Applying);
    EXPECT_EQ(diagnostic.mutation_state,
              kasumi::application::GarbageCollectMutationState::Uncertain);
    ASSERT_TRUE(diagnostic.transport_error.has_value());
    EXPECT_EQ(diagnostic.transport_error->code,
              kasumi::transport::ErrorCode::Io);
    EXPECT_EQ(diagnostic.transport_error->native_code, 987);
    EXPECT_EQ(fixture.state->remove_batch_count, 1U);
    EXPECT_TRUE(diagnostic.barrier_release_attempted);
    EXPECT_TRUE(diagnostic.barrier_release_confirmed);
}

// 7. Erro parcial depois de lotes completos.
TEST(GarbageCollectionTest,
     BatchPartialFailureAfterFullBatchesPreservesCounts) {
    FakeBatchFixture fixture("gc-batch-partial-second");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");

    std::vector<std::string> orphans;
    for (std::size_t index = 0; index < 16; ++index) {
        orphans.push_back(
            fixture.put_content("batch-two-" + std::to_string(index),
                                "batch-two-" + std::to_string(index)));
    }
    std::ranges::sort(orphans);

    // Batch 0 (8 items) succeeds. Batch 1 (8 items) fails at index 1 (item 9
    // overall).
    fixture.state->remove_batch_failure = kasumi::transport::ErrorCode::Io;
    fixture.state->remove_batch_fail_at_batch_index = 1;
    fixture.state->remove_batch_fail_single_index = 1;
    fixture.state->remove_failure_native_code = 555;

    const auto diagnostic = collect_diagnostic(fixture);
    ASSERT_TRUE(diagnostic.has_value());
    EXPECT_EQ(diagnostic->candidate_objects, 16U);
    EXPECT_EQ(diagnostic->confirmed_removed,
              15U); // 8 from batch 0 + 7 from batch 1
    EXPECT_EQ(diagnostic->failed_identifier,
              std::optional<std::string>{orphans[9]});
    EXPECT_EQ(diagnostic->mutation_state,
              kasumi::application::GarbageCollectMutationState::Uncertain);
    EXPECT_EQ(fixture.state->remove_batch_count, 2U);
}

// 8. Resultados individuais fora de ordem.
TEST(GarbageCollectionTest, BatchReportResultsOutOfOrderAreCorrectlyMatched) {
    FakeBatchFixture fixture("gc-batch-reorder");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");

    std::vector<std::string> orphans;
    for (std::size_t index = 0; index < 8; ++index) {
        orphans.push_back(
            fixture.put_content("reorder-" + std::to_string(index),
                                "reorder-" + std::to_string(index)));
    }

    fixture.state->remove_batch_reverse_report = true;
    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->removed_objects, 8U);
    EXPECT_EQ(fixture.state->remove_batch_count, 1U);
    for (const auto& orphan : orphans) {
        EXPECT_FALSE(fixture.present(orphan));
    }
}

// 9. Relatorio incompleto, duplicado ou invalido.
TEST(GarbageCollectionTest,
     BatchInvalidOrIncompleteReportYieldsUncertainMutation) {
    // 9a: Incomplete report (omits item)
    {
        FakeBatchFixture fixture("gc-batch-incomplete");
        fixture.publish(commit_with_file("live"), "head");
        fixture.put_content("live", "live");
        for (std::size_t index = 0; index < 8; ++index) {
            fixture.put_content("incomp-" + std::to_string(index),
                                "incomp-" + std::to_string(index));
        }
        fixture.state->remove_batch_incomplete_report = true;
        const auto diagnostic = collect_diagnostic(fixture);
        ASSERT_TRUE(diagnostic.has_value());
        EXPECT_EQ(diagnostic->mutation_state,
                  kasumi::application::GarbageCollectMutationState::Uncertain);
        EXPECT_FALSE(diagnostic->failed_identifier.has_value());
    }

    // 9b: Duplicate report
    {
        FakeBatchFixture fixture("gc-batch-duplicate");
        fixture.publish(commit_with_file("live"), "head");
        fixture.put_content("live", "live");
        for (std::size_t index = 0; index < 8; ++index) {
            fixture.put_content("dup-" + std::to_string(index),
                                "dup-" + std::to_string(index));
        }
        fixture.state->remove_batch_duplicate_report = true;
        const auto diagnostic = collect_diagnostic(fixture);
        ASSERT_TRUE(diagnostic.has_value());
        EXPECT_EQ(diagnostic->mutation_state,
                  kasumi::application::GarbageCollectMutationState::Uncertain);
        EXPECT_FALSE(diagnostic->failed_identifier.has_value());
    }

    // 9c: Unknown item in report
    {
        FakeBatchFixture fixture("gc-batch-unknown-item");
        fixture.publish(commit_with_file("live"), "head");
        fixture.put_content("live", "live");
        for (std::size_t index = 0; index < 8; ++index) {
            fixture.put_content("unkn-" + std::to_string(index),
                                "unkn-" + std::to_string(index));
        }
        fixture.state->remove_batch_unknown_item_report = true;
        const auto diagnostic = collect_diagnostic(fixture);
        ASSERT_TRUE(diagnostic.has_value());
        EXPECT_EQ(diagnostic->mutation_state,
                  kasumi::application::GarbageCollectMutationState::Uncertain);
        EXPECT_FALSE(diagnostic->failed_identifier.has_value());
    }
}

// 10. Timeout ou erro ambiguo do batch inteiro.
TEST(GarbageCollectionTest,
     BatchAmbiguousErrorYieldsUncertainMutationWithoutFallback) {
    FakeBatchFixture fixture("gc-batch-timeout");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");

    for (std::size_t index = 0; index < 8; ++index) {
        fixture.put_content("timeout-" + std::to_string(index),
                            "timeout-" + std::to_string(index));
    }

    fixture.state->remove_batch_failure = kasumi::transport::ErrorCode::Timeout;
    fixture.state->remove_batch_fail_after_items =
        0; // entire batch call fails with Timeout
    fixture.state->remove_failure_native_code = 504;

    const auto diagnostic = collect_diagnostic(fixture);
    ASSERT_TRUE(diagnostic.has_value());
    EXPECT_EQ(diagnostic->mutation_state,
              kasumi::application::GarbageCollectMutationState::Uncertain);
    EXPECT_FALSE(diagnostic->failed_identifier.has_value());
    EXPECT_EQ(diagnostic->confirmed_removed, 0U);
    ASSERT_TRUE(diagnostic->transport_error.has_value());
    EXPECT_EQ(diagnostic->transport_error->code,
              kasumi::transport::ErrorCode::Timeout);
    EXPECT_EQ(diagnostic->transport_error->native_code, 504);
    EXPECT_EQ(fixture.state->remove_batch_count, 1U);
    EXPECT_EQ(fixture.state->source_remove_count,
              0U); // No sequential fallback attempt
}

// 10a. Falha de lote inteiro deixa failed_identifier vazio
TEST(GarbageCollectionTest, BatchWholeFailureLeavesFailedIdentifierEmpty) {
    FakeBatchFixture fixture("gc-batch-whole-failure");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");

    for (std::size_t index = 0; index < 8; ++index) {
        fixture.put_content("whole-fail-" + std::to_string(index),
                            "whole-fail-" + std::to_string(index));
    }

    fixture.state->remove_batch_failure = kasumi::transport::ErrorCode::Timeout;
    fixture.state->remove_batch_fail_after_items =
        0; // whole batch fails without report
    fixture.state->remove_failure_native_code = 504;

    const auto diagnostic = collect_diagnostic(fixture);
    ASSERT_TRUE(diagnostic.has_value());
    EXPECT_EQ(diagnostic->mutation_state,
              kasumi::application::GarbageCollectMutationState::Uncertain);
    EXPECT_FALSE(diagnostic->failed_identifier
                     .has_value()); // Must NOT attribute to candidate 0
    EXPECT_EQ(diagnostic->confirmed_removed, 0U);
    ASSERT_TRUE(diagnostic->transport_error.has_value());
    EXPECT_EQ(diagnostic->transport_error->code,
              kasumi::transport::ErrorCode::Timeout);
    EXPECT_EQ(diagnostic->transport_error->native_code, 504);
}

// 10b. Segundo lote falha integralmente: preserva confirmados do primeiro e
// deixa failed_identifier vazio
TEST(
    GarbageCollectionTest,
    BatchSecondBatchWholeFailureLeavesFailedIdentifierEmptyAndPreservesFirstBatch) {
    FakeBatchFixture fixture("gc-batch-second-whole-fail");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");

    for (std::size_t index = 0; index < 16; ++index) {
        fixture.put_content("second-fail-" + std::to_string(index),
                            "second-fail-" + std::to_string(index));
    }

    // Batch 0 succeeds (8 items removed). Batch 1 fails at batch level with
    // NetworkError.
    fixture.state->remove_batch_fail_at_batch_index = 1;
    fixture.state->remove_batch_failure =
        kasumi::transport::ErrorCode::BackendUnavailable;
    fixture.state->remove_batch_fail_after_items =
        0; // Whole batch failure on batch 1
    fixture.state->remove_failure_native_code = 503;

    const auto diagnostic = collect_diagnostic(fixture);
    ASSERT_TRUE(diagnostic.has_value());
    EXPECT_EQ(diagnostic->confirmed_removed, 8U); // 8 from batch 0
    EXPECT_FALSE(
        diagnostic->failed_identifier
            .has_value()); // Whole batch failure, no individual candidate
    EXPECT_EQ(diagnostic->mutation_state,
              kasumi::application::GarbageCollectMutationState::Uncertain);
    ASSERT_TRUE(diagnostic->transport_error.has_value());
    EXPECT_EQ(diagnostic->transport_error->code,
              kasumi::transport::ErrorCode::BackendUnavailable);
    EXPECT_EQ(diagnostic->transport_error->native_code, 503);
    EXPECT_EQ(fixture.state->remove_batch_count, 2U);
}

TEST(GarbageCollectionTest, ReportsAcknowledgedRemovalProgress) {
    FakeBatchFixture fixture("gc-removal-progress");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    for (int i = 0; i < 12; ++i) {
        const auto payload = "orphan-" + std::to_string(i);
        fixture.put_content(payload, payload);
    }
    std::vector<GarbageCollectProgress> removals;
    const auto collected =
        fixture.collect([&](const GarbageCollectProgress& progress) {
            if (progress.stage == GarbageCollectStage::Applying) {
                removals.push_back(progress);
            }
        });
    ASSERT_TRUE(collected) << collected.error().detail;
    ASSERT_GE(removals.size(), 3U);
    EXPECT_EQ(removals.front().removed_objects, 0U);
    EXPECT_EQ(removals.back().candidate_count, 12U);
    EXPECT_EQ(removals.back().removed_objects, 12U);
    EXPECT_GT(removals.back().removal_elapsed,
              removals.front().removal_elapsed);
}

// 11. Cancelamento antes do lote e entre dois lotes.
TEST(GarbageCollectionTest, BatchCancellationCheckedBeforeAndBetweenBatches) {
    ResetCancellation reset_guard;

    // 11a: Cancellation before first batch
    {
        FakeBatchFixture fixture("gc-batch-cancel-before");
        fixture.publish(commit_with_file("live"), "head");
        fixture.put_content("live", "live");
        for (std::size_t index = 0; index < 8; ++index) {
            fixture.put_content("cbef-" + std::to_string(index),
                                "cbef-" + std::to_string(index));
        }
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
        EXPECT_EQ(diagnostic.stage, GarbageCollectStage::Applying);
        EXPECT_EQ(
            diagnostic.mutation_state,
            kasumi::application::GarbageCollectMutationState::NotAttempted);
        EXPECT_EQ(diagnostic.confirmed_removed, 0U);
        EXPECT_EQ(fixture.state->remove_batch_count, 0U);
    }

    // 11b: Cancellation between batch 1 and batch 2
    {
        kasumi::platform::cancellation::reset();
        FakeBatchFixture fixture("gc-batch-cancel-between");
        fixture.publish(commit_with_file("live"), "head");
        fixture.put_content("live", "live");
        for (std::size_t index = 0; index < 16; ++index) {
            fixture.put_content("cbetw-" + std::to_string(index),
                                "cbetw-" + std::to_string(index));
        }

        fixture.state->on_operation =
            [&](FakeState& state, std::string_view op, std::string_view) {
                if (op == "remove_batch" && state.remove_batch_count == 1) {
                    kasumi::platform::cancellation::request();
                }
            };

        const auto result = fixture.collect();
        ASSERT_FALSE(result.has_value());
        EXPECT_NE(result.error().detail.find("cancelled"), std::string::npos);
        ASSERT_TRUE(result.error().garbage_collection.has_value());
        const auto& diagnostic = *result.error().garbage_collection;
        EXPECT_EQ(diagnostic.confirmed_removed, 8U); // Batch 1 completed
        EXPECT_EQ(
            diagnostic.mutation_state,
            kasumi::application::GarbageCollectMutationState::NotAttempted);
        EXPECT_EQ(fixture.state->remove_batch_count,
                  1U); // Batch 2 never submitted
        EXPECT_TRUE(diagnostic.barrier_release_attempted);
        EXPECT_TRUE(diagnostic.barrier_release_confirmed);
    }
}

// 12. Cleanup do barrier apos falha parcial.
TEST(GarbageCollectionTest,
     BatchBarrierCleanupExecutedAndConfirmedAfterPartialFailure) {
    FakeBatchFixture fixture("gc-batch-cleanup-partial");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");

    for (std::size_t index = 0; index < 8; ++index) {
        fixture.put_content("cleanpart-" + std::to_string(index),
                            "cleanpart-" + std::to_string(index));
    }

    fixture.state->remove_batch_failure = kasumi::transport::ErrorCode::Io;
    fixture.state->remove_batch_fail_single_index = 4;

    const auto diagnostic = collect_diagnostic(fixture);
    ASSERT_TRUE(diagnostic.has_value());
    EXPECT_TRUE(diagnostic->barrier_release_attempted);
    EXPECT_TRUE(diagnostic->barrier_release_confirmed);
    EXPECT_FALSE(fixture.present(layout().barrier_identifier));
}

// 13. Zero GETs de Content orfao.
TEST(GarbageCollectionTest, BatchDeletionPerformsZeroContentPayloadGets) {
    FakeBatchFixture fixture("gc-batch-zero-gets");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");

    std::unordered_set<std::string> orphan_ids;
    for (std::size_t index = 0; index < 24; ++index) {
        const auto id = fixture.put_content("zeroget-" + std::to_string(index),
                                            "zeroget-" + std::to_string(index));
        orphan_ids.insert(id);
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
    EXPECT_EQ(result->removed_objects, 24U);
    EXPECT_EQ(fixture.state->remove_batch_count, 3U);
    EXPECT_EQ(fixture.state->orphan_payload_get_count, 0U);
    for (const auto& orphan : orphan_ids) {
        EXPECT_EQ(std::ranges::count(get_calls, orphan), 0);
    }
}

// 14. Protecao de Content referenciado e objetos de controle.
TEST(GarbageCollectionTest,
     BatchDeletionProtectsReachableContentAndControlObjects) {
    FakeBatchFixture fixture("gc-batch-protection");
    const auto repo = seed_repository(fixture.transport, fixture.workspace);

    std::vector<std::string> orphans;
    for (std::size_t index = 0; index < 8; ++index) {
        orphans.push_back(
            fixture.put_content("prot-orph-" + std::to_string(index),
                                "prot-orph-" + std::to_string(index)));
    }

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->removed_objects, 10U);

    // Protected objects must still exist
    EXPECT_TRUE(fixture.present(repo.live_content));
    EXPECT_TRUE(fixture.present(object_path(repo.head)));

    // Verify no batch contained any protected object
    for (const auto& event : fixture.state->gc_events) {
        for (const auto& protected_id :
             {repo.live_content, object_path(repo.head)}) {
            EXPECT_EQ(event.find(protected_id), std::string::npos);
        }
    }
}

// 15. Nenhuma revalidacao remota por candidato.
TEST(GarbageCollectionTest,
     BatchDeletionPerformsNoReadbackOrPresenceVerificationPerCandidate) {
    FakeBatchFixture fixture("gc-batch-no-presence");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");

    for (std::size_t index = 0; index < 16; ++index) {
        fixture.put_content("nopresence-" + std::to_string(index),
                            "nopresence-" + std::to_string(index));
    }

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->removed_objects, 16U);
    EXPECT_EQ(fixture.state->remove_batch_count, 2U);
}

TEST(GarbageCollectionTest,
     GracePeriodDefersRecentObjectsAndPrunesAgedObjects) {
    FakeFixture fixture("gc-grace-mixed");
    fixture.state->list_metadata_supported = true;
    const auto now_unix = *kasumi::platform::clock::unix_seconds();
    fixture.state->default_object_mtime = now_unix - 60LL;

    fixture.publish(commit_with_file("live"), "head");
    const auto live_id = fixture.put_content("live", "live");
    const auto recent_orphan = fixture.put_content("recent-orph", "recent");
    const auto aged_orphan = fixture.put_content("aged-orph", "aged");
    fixture.state->object_mtimes[recent_orphan] = now_unix - 3600LL;
    fixture.state->object_mtimes[aged_orphan] = now_unix - 7LL * 3600LL;

    const auto first =
        fixture.collect_with_options(gc_int::GarbageCollectOptions{});
    ASSERT_TRUE(first.has_value()) << first.error().detail;
    EXPECT_EQ(first->candidate_objects, 1U);
    EXPECT_EQ(first->removed_objects, 1U);
    EXPECT_EQ(first->deferred_recent_objects, 1U);
    EXPECT_EQ(first->effective_min_age_hours, 6U);
    EXPECT_FALSE(fixture.present(aged_orphan));
    EXPECT_TRUE(fixture.present(recent_orphan));
    EXPECT_TRUE(fixture.present(live_id));

    const auto second =
        fixture.collect_with_options(gc_int::GarbageCollectOptions{
            .min_orphan_age = std::chrono::seconds{0}});
    ASSERT_TRUE(second.has_value()) << second.error().detail;
    EXPECT_EQ(second->candidate_objects, 1U);
    EXPECT_EQ(second->removed_objects, 1U);
    EXPECT_EQ(second->deferred_recent_objects, 0U);
    EXPECT_FALSE(fixture.present(recent_orphan));
    EXPECT_TRUE(fixture.present(live_id));
}

TEST(GarbageCollectionTest,
     GracePeriodFailsSafeOnMissingZeroAndFutureTimestamps) {
    FakeFixture fixture("gc-grace-failsafe");
    const auto now_unix = *kasumi::platform::clock::unix_seconds();
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    const auto orphan = fixture.put_content("orphan-ts", "orphan-ts");

    // 1. Metadata listing unsupported -> must defer under positive grace
    // period.
    fixture.state->list_metadata_supported = false;
    const auto no_meta =
        fixture.collect_with_options(gc_int::GarbageCollectOptions{});
    ASSERT_TRUE(no_meta.has_value()) << no_meta.error().detail;
    EXPECT_EQ(no_meta->removed_objects, 0U);
    EXPECT_EQ(no_meta->deferred_recent_objects, 1U);
    EXPECT_TRUE(fixture.present(orphan));

    // 2. Missing, zero, negative, and future mtimes -> all deferred fail-safe.
    fixture.state->list_metadata_supported = true;
    for (const std::optional<std::int64_t> bad_mtime : {
             std::optional<std::int64_t>{std::nullopt},
             std::optional<std::int64_t>{0},
             std::optional<std::int64_t>{-100},
             std::optional<std::int64_t>{now_unix + 600},
         }) {
        fixture.state->object_mtimes[orphan] = bad_mtime;
        const auto res =
            fixture.collect_with_options(gc_int::GarbageCollectOptions{});
        ASSERT_TRUE(res.has_value()) << res.error().detail;
        EXPECT_EQ(res->removed_objects, 0U);
        EXPECT_EQ(res->deferred_recent_objects, 1U);
        EXPECT_TRUE(fixture.present(orphan));
    }

    // 3. Dual-clock guard on expired commits: old mtime + fresh created_at is
    // deferred, and old created_at + fresh mtime is deferred.
    fixture.state->object_mtimes[orphan] =
        now_unix - 60LL; // keep orphan deferred
    const auto fresh_created_commit =
        kasumi::history::make_commit(
            0, {}, make_tree("fresh-c.txt", "fresh-c"), now_unix - 60LL)
            .value();
    const auto fresh_created_ref =
        fixture.publish(fresh_created_commit, "fresh-c", false);
    fixture.state->object_mtimes[object_path(fresh_created_ref)] =
        now_unix - 10LL * 3600LL;

    const auto old_created_commit =
        kasumi::history::make_commit(
            0, {}, make_tree("old-c.txt", "old-c"), now_unix - 10LL * 3600LL)
            .value();
    const auto old_created_ref =
        fixture.publish(old_created_commit, "old-c", false);
    fixture.state->object_mtimes[object_path(old_created_ref)] =
        now_unix - 60LL;

    const auto dual =
        fixture.collect_with_options(gc_int::GarbageCollectOptions{});
    ASSERT_TRUE(dual.has_value()) << dual.error().detail;
    EXPECT_EQ(dual->removed_objects, 0U);
    EXPECT_EQ(dual->deferred_recent_objects, 3U);
    EXPECT_TRUE(fixture.present(object_path(fresh_created_ref)));
    EXPECT_TRUE(fixture.present(object_path(old_created_ref)));
}

TEST(GarbageCollectionTest,
     PreBarrierBusyCheckBailsOutReadOnlyWithoutCreatingBarrier) {
    for (const bool use_batch : {false, true}) {
        SCOPED_TRACE(use_batch);
        FakeFixture fixture("gc-prebarrier-busy");
        fixture.state->control_read_batch_supported = use_batch;
        fixture.publish(commit_with_file("live"), "head");
        fixture.put_content("live", "live");
        fixture.put_content("orph", "orph");

        // Register an active writer.
        auto writer = protocol::register_writer(
            fixture.transport,
            layout(),
            kasumi::test::workspace_root(fixture.workspace));
        ASSERT_TRUE(writer.has_value());
        reset_fake_traffic(*fixture.state);

        const auto blocked_by_writer = fixture.collect();
        ASSERT_FALSE(blocked_by_writer.has_value());
        EXPECT_EQ(blocked_by_writer.error().code,
                  GcErrorCode::ConcurrentChange);
        EXPECT_EQ(fixture.state->put_count, 0U);
        EXPECT_EQ(fixture.state->barrier_verification_count, 0U);
        EXPECT_FALSE(fixture.present(layout().barrier_identifier));
        if (use_batch) {
            EXPECT_EQ(fixture.state->control_read_batch_count, 1U);
        }

        // Remove writer, insert foreign barrier -> still read-only bailout.
        ASSERT_TRUE(protocol::release_registration(*writer));
        fixture.state->objects[layout().barrier_identifier] =
            protocol::testing::format_payload(
                "barrier", "0123456789abcdef0123456789abcdef");
        reset_fake_traffic(*fixture.state);

        const auto blocked_by_barrier = fixture.collect();
        ASSERT_FALSE(blocked_by_barrier.has_value());
        EXPECT_EQ(blocked_by_barrier.error().code,
                  GcErrorCode::ConcurrentChange);
        EXPECT_EQ(fixture.state->put_count, 0U);
        EXPECT_EQ(fixture.state->remove_count, 0U);
        EXPECT_TRUE(fixture.present(layout().barrier_identifier));
    }
}

TEST(GarbageCollectionTest, ZeroCandidateFastPathSkipsConsistencyProbe) {
    FakeFixture fixture("gc-zero-cand-fast-path");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    reset_fake_traffic(*fixture.state);

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->candidate_objects, 0U);
    EXPECT_EQ(result->removed_objects, 0U);
    EXPECT_FALSE(result->analysis_only);
    EXPECT_EQ(fixture.state->probe_list_count, 0U);
}

TEST(GarbageCollectionTest,
     ProgressReportsSubStagesCommitCountsBytesAndDeferredObjects) {
    FakeFixture fixture("gc-rich-progress");
    fixture.state->list_metadata_supported = true;
    const auto now_unix = *kasumi::platform::clock::unix_seconds();
    fixture.state->default_object_mtime = now_unix - 60LL;

    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    const auto aged_orphan =
        fixture.put_content("aged-progress-payload", "aged-progress");
    const auto fresh_orphan =
        fixture.put_content("fresh-progress-payload", "fresh-progress");
    fixture.state->object_mtimes[aged_orphan] = now_unix - 8LL * 3600LL;
    fixture.state->object_mtimes[fresh_orphan] = now_unix - 120LL;

    std::vector<GarbageCollectProgress> events;
    const auto res = fixture.collect_with_options(
        gc_int::GarbageCollectOptions{}, [&](const GarbageCollectProgress& ev) {
            events.push_back(ev);
        });
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_EQ(res->removed_objects, 1U);
    EXPECT_EQ(res->deferred_recent_objects, 1U);
    EXPECT_GT(res->candidate_bytes, 0U);
    EXPECT_EQ(res->removed_bytes, res->candidate_bytes);

    const auto has_sub = [&](GarbageCollectSubStage sub) {
        return std::ranges::any_of(events, [sub](const auto& ev) {
            return ev.sub_stage == sub;
        });
    };
    EXPECT_TRUE(has_sub(GarbageCollectSubStage::CheckingControls));
    EXPECT_TRUE(has_sub(GarbageCollectSubStage::EstablishingBarrier));
    EXPECT_TRUE(has_sub(GarbageCollectSubStage::ListingRemote));
    EXPECT_TRUE(has_sub(GarbageCollectSubStage::AuthenticatingHistory));
    EXPECT_TRUE(has_sub(GarbageCollectSubStage::AnalyzingReachability));
    EXPECT_TRUE(has_sub(GarbageCollectSubStage::LoadingActivities));
    EXPECT_TRUE(has_sub(GarbageCollectSubStage::ProbingConsistency));
    EXPECT_TRUE(has_sub(GarbageCollectSubStage::RemovingObjects));
    EXPECT_TRUE(has_sub(GarbageCollectSubStage::ReleasingBarrier));

    EXPECT_TRUE(std::ranges::any_of(events, [](const auto& ev) {
        return ev.sub_stage == GarbageCollectSubStage::AuthenticatingHistory &&
               ev.commits_total == std::optional<std::size_t>{1} &&
               ev.commits_processed == std::optional<std::size_t>{1};
    }));
    EXPECT_EQ(events.back().stage, GarbageCollectStage::Finalizing);
    EXPECT_EQ(events.back().removed_bytes, res->removed_bytes);
    EXPECT_EQ(events.back().deferred_recent_objects,
              std::optional<std::size_t>{1});
    EXPECT_EQ(events.back().min_age_hours, std::optional<std::uint32_t>{6});
}

TEST(GarbageCollectionTest,
     ExplicitShorterMinAgeDoesNotShrinkActivityRetention) {
    namespace activity = kasumi::application::history_storage::activity;
    FakeFixture fixture("gc-min-age-activity-floor");
    fixture.state->list_metadata_supported = true;
    fixture.runtime.min_history_depth = 1;
    fixture.runtime.min_history_age_hours = 168; // 7 days

    const auto now_unix = *kasumi::platform::clock::unix_seconds();
    fixture.state->default_object_mtime = now_unix - 60LL;

    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    const auto orphan = fixture.put_content("aged-orphan-2h", "orphan-2h");
    fixture.state->object_mtimes[orphan] = now_unix - 2LL * 3600LL;

    const auto publish_activity = [&](std::string event_id,
                                      std::int64_t finished_at) {
        const activity::ActivityRecord record{
            .event_id = std::move(event_id),
            .operation = activity::ActivityOperation::Fsck,
            .outcome = activity::ActivityOutcome::Succeeded,
            .machine_id = {1, 2, 3, 4},
            .machine_name = "host-a",
            .started_at = finished_at - 5,
            .finished_at = finished_at,
            .duration_ms = 5000,
            .metric_primary = 1,
            .stage = "finalizing",
            .detail = "ok",
        };
        const auto id =
            activity::publish(fixture.transport,
                              layout(),
                              test_key(),
                              record,
                              kasumi::test::workspace_root(fixture.workspace));
        EXPECT_TRUE(id.has_value());
        fixture.state->object_mtimes[*id] = finished_at;
        return *id;
    };

    const auto older_act =
        publish_activity(std::string(32, 'a'), now_unix - 24LL * 3600LL);
    const auto newer_act =
        publish_activity(std::string(32, 'b'), now_unix - 3600LL);

    // Explicit --min-age 1 reclaims the 2h-old orphan content, while keeping
    // the 24h-old KACT activity protected under the profile's 168h retention.
    const auto res = fixture.collect_with_options(
        gc_int::GarbageCollectOptions{.min_orphan_age = std::chrono::hours{1}});
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_EQ(res->candidate_content_objects, 1U);
    EXPECT_EQ(res->candidate_activities, 0U);
    EXPECT_EQ(res->removed_objects, 1U);
    EXPECT_FALSE(fixture.present(orphan));
    EXPECT_TRUE(fixture.present(older_act));
    EXPECT_TRUE(fixture.present(newer_act));
}

} // namespace
