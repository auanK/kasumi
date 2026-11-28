#include "application/history_storage/activity.hpp"
#include "application/history_storage/commit_cache.hpp"
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
#include "state_storage/database.hpp"

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
#include <stop_token>
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
    return static_cast<std::size_t>(std::ranges::count_if(
        state.remove_attempts, [](const std::string& identifier) {
            return is_barrier(identifier);
        }));
}

std::string active_barrier_id(const FakeState& state) {
    return find_active_barrier(state, layout())
        .value_or(layout().barrier_identifier);
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

        std::string active_barrier;
        const auto result =
            fixture.collect([&](const GarbageCollectProgress& progress) {
                if (progress.stage == GarbageCollectStage::Applying &&
                    progress.removed_objects == 0) {
                    active_barrier = active_barrier_id(*fixture.state);
                    replace_barrier_contents(fixture.state, active_barrier);
                    replacement = fixture.state->objects.at(active_barrier);
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
        expected[active_barrier] = replacement;
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
                    const auto active_barrier =
                        active_barrier_id(*fixture.state);
                    fixture.state->objects.erase(active_barrier);
                    fixture.state->physical_hashes.erase(active_barrier);
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
                const auto active_barrier = active_barrier_id(*fixture.state);
                fixture.state->physical_hash_failure_identifier =
                    active_barrier;
                fixture.state->physical_hash_failure =
                    kasumi::transport::ErrorCode::Timeout;
                fixture.state->physical_hash_failure_native_code = 10060;
                expected[active_barrier] =
                    fixture.state->objects.at(active_barrier);
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
            if (op == "before_remove" && is_barrier(id)) {
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
    EXPECT_TRUE(find_active_barrier(*fixture.state, layout()).has_value());
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
                if (op == "get" && is_barrier(id)) {
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
            const std::size_t expected_mid_apply_checks =
                count <= 128U ? 0U : (count - 1U) / 128U;
            // Pre-apply + post-settle + acquire + admission + 2 cleanup checks
            // + bounded periodic mid-Apply checkpoints (every 128 candidates).
            const std::size_t expected_ownership_checks =
                7U + expected_mid_apply_checks;
            const auto ownership_hashes =
                static_cast<std::size_t>(std::ranges::count_if(
                    fixture.state->gc_events, [](const auto& ev) {
                        return ev.starts_with("physical_hash:");
                    }));
            EXPECT_EQ(ownership_hashes, expected_ownership_checks);
            EXPECT_EQ(control_gets,
                      physical_hash ? 0U : 6U + expected_mid_apply_checks);
            EXPECT_EQ(after_apply[0] - before_apply[0],
                      physical_hash ? 0U : 1U + expected_mid_apply_checks);
            EXPECT_EQ(after_apply[1] - before_apply[1],
                      (1U + expected_mid_apply_checks) * 2U);
            EXPECT_EQ(after_apply[2] - before_apply[2],
                      1U + expected_mid_apply_checks);
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
    fixture.state->default_object_mtime = now_unix - 60LL;

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
    EXPECT_TRUE(find_active_barrier(*fixture.state, layout()).has_value());
}

// BARRIER-R01
TEST(GarbageCollectionTest, SuccessfulRunReleasesBarrierExactlyOnce) {
    FakeFixture fixture("gc-barrier-success");
    seed_repository(fixture.transport, fixture.workspace);
    fixture.state->remove_attempts.clear();

    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 1U);
    EXPECT_FALSE(find_active_barrier(*fixture.state, layout()).has_value());
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
    EXPECT_FALSE(find_active_barrier(*fixture.state, layout()).has_value());
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
    EXPECT_TRUE(find_active_barrier(*fixture.state, layout()).has_value());
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
    EXPECT_FALSE(find_active_barrier(*fixture.state, layout()).has_value());
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
    EXPECT_TRUE(find_active_barrier(*fixture.state, layout()).has_value());
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
    EXPECT_TRUE(find_active_barrier(*fixture.state, layout()).has_value());
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
    EXPECT_FALSE(find_active_barrier(*fixture.state, layout()).has_value());
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
            state.objects[active_barrier_id(state)] = {'f'};
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
        EXPECT_TRUE(find_active_barrier(*fixture.state, layout()).has_value());
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

TEST(GarbageCollectionTest,
     RequiresLocallyAcceptedHistoryBeforePlanningDeletions) {
    namespace epoch = kasumi::application::history_storage::epoch;
    namespace db = kasumi::state_storage;
    FakeFixture fixture("gc-local-checkpoint");
    const auto root = commit_with_file("root");
    fixture.publish(root, "root");
    fixture.put_content("root", "root-content");
    const auto child = kasumi::history::make_commit(
                           1, {commit_id(root)}, make_tree("live.txt", "child"))
                           .value();
    const auto accepted = fixture.publish(child, "child", false);
    const auto child_content = fixture.put_content("child", "child-content");
    const auto orphan = fixture.put_content("orphan", "orphan-content");
    Epoch genesis{.vault_id = std::string(64, 'a'),
                  .sequence = 0,
                  .issued_at = 1,
                  .policy = {},
                  .anchors = {{.commit_id = commit_id(root), .height = 0}}};
    const auto checkpoint = epoch::seal(genesis, test_key()).value();
    ASSERT_TRUE(db::initialize(fixture.runtime.database_path));
    ASSERT_TRUE(db::save_state(fixture.runtime.database_path,
                               {.tree = child.tree,
                                .height = 1,
                                .commit_id = accepted.commit_id,
                                .ciphertext_id = accepted.ciphertext_id,
                                .epoch_id = checkpoint.reference.epoch_id}));

    const auto expect_blocked = [&](std::string_view missing) {
        for (const bool dry_run : {true, false}) {
            const auto result = fixture.collect_with_options(
                {.dry_run = dry_run,
                 .min_orphan_age = std::chrono::seconds{0}});
            ASSERT_FALSE(result.has_value());
            EXPECT_EQ(result.error().code, GcErrorCode::IntegrityFailure);
            EXPECT_EQ(result.error().object_identifier, missing);
            EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
            EXPECT_TRUE(fixture.present(child_content));
            EXPECT_TRUE(fixture.present(orphan));
        }
    };
    expect_blocked(accepted.commit_id);
    const auto marker =
        kasumi::application::history_storage::marker_object(layout(), accepted);
    fixture.state->objects[marker] = marker_bytes(accepted);
    expect_blocked(
        epoch::object_identifier(layout(), checkpoint.reference).value());

    const auto workspace = kasumi::test::workspace_root(fixture.workspace);
    ASSERT_TRUE(
        epoch::publish(fixture.transport, test_key(), checkpoint, workspace));
    auto successor = genesis;
    successor.sequence = 1;
    successor.previous_epoch_id = checkpoint.reference.epoch_id;
    const auto next = epoch::seal(successor, test_key()).value();
    ASSERT_TRUE(epoch::publish(fixture.transport, test_key(), next, workspace));
    const auto result = fixture.collect();
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_FALSE(fixture.present(orphan));
    EXPECT_TRUE(fixture.present(child_content));
}

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
    EXPECT_FALSE(find_active_barrier(*fixture.state, layout()).has_value());
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
        EXPECT_FALSE(find_active_barrier(*fixture.state, layout()).has_value());
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

TEST(GarbageCollectionTest,
     RemoteClockClampsMinAgeFailClosedWhenLocalClockIsAhead) {
    FakeFixture fixture("gc-remote-clock-clamp");
    fixture.state->list_metadata_supported = true;
    const auto now_unix = *kasumi::platform::clock::unix_seconds();
    // Simulate local clock 5h ahead of the remote server clock: backend stamps
    // our freshly published barrier at remote_now = now_unix - 5h.
    const auto simulated_remote_now = now_unix - 5LL * 3600LL;
    fixture.state->default_object_mtime = simulated_remote_now;

    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    // Uploaded 2h ago by remote clock (appears 7h old to skewed local clock).
    const auto recent_by_remote =
        fixture.put_content("remote-recent", "remote-recent");
    fixture.state->object_mtimes[recent_by_remote] =
        simulated_remote_now - 2LL * 3600LL;
    // Uploaded 7h ago by remote clock -> aged even under min(local, remote).
    const auto aged_by_remote =
        fixture.put_content("remote-aged", "remote-aged");
    fixture.state->object_mtimes[aged_by_remote] =
        simulated_remote_now - 7LL * 3600LL;

    const auto res =
        fixture.collect_with_options(gc_int::GarbageCollectOptions{});
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_EQ(res->candidate_objects, 1U);
    EXPECT_EQ(res->removed_objects, 1U);
    EXPECT_EQ(res->deferred_recent_objects, 1U);
    EXPECT_TRUE(fixture.present(recent_by_remote));
    EXPECT_FALSE(fixture.present(aged_by_remote));
}

TEST(GarbageCollectionTest,
     RemoteClockMissingOrZeroBarrierMtimeDefersFailClosed) {
    FakeFixture fixture("gc-remote-clock-missing");
    fixture.state->list_metadata_supported = true;
    const auto now_unix = *kasumi::platform::clock::unix_seconds();
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    const auto aged_orphan = fixture.put_content("aged-orphan", "aged-orphan");
    fixture.state->object_mtimes[aged_orphan] = now_unix - 12LL * 3600LL;

    // 1. Nullopt barrier mtime (default_object_mtime unset) -> fail-closed.
    fixture.state->default_object_mtime.reset();
    const auto null_res =
        fixture.collect_with_options(gc_int::GarbageCollectOptions{});
    ASSERT_TRUE(null_res.has_value()) << null_res.error().detail;
    EXPECT_EQ(null_res->removed_objects, 0U);
    EXPECT_EQ(null_res->deferred_recent_objects, 1U);
    EXPECT_TRUE(fixture.present(aged_orphan));

    // 2. Non-positive barrier mtime -> fail-closed.
    fixture.state->default_object_mtime = 0;
    const auto zero_res =
        fixture.collect_with_options(gc_int::GarbageCollectOptions{});
    ASSERT_TRUE(zero_res.has_value()) << zero_res.error().detail;
    EXPECT_EQ(zero_res->removed_objects, 0U);
    EXPECT_EQ(zero_res->deferred_recent_objects, 1U);
    EXPECT_TRUE(fixture.present(aged_orphan));
}

TEST(
    GarbageCollectionTest,
    PeriodicApplyRevalidationStopsRemainingBatchesOnConcurrentWriterOrBarrier) {
    for (const bool inject_competing_barrier : {false, true}) {
        SCOPED_TRACE(inject_competing_barrier);
        FakeBatchFixture fixture("gc-mid-apply-revalidation");
        fixture.state->control_read_batch_supported = true;
        fixture.publish(commit_with_file("live"), "head");
        fixture.put_content("live", "live");

        std::vector<std::string> orphans;
        for (int i = 0; i < 16; ++i) {
            orphans.push_back(fixture.put_content(
                "reval-" + std::to_string(i), "reval-" + std::to_string(i)));
        }
        std::ranges::sort(orphans);

        const std::string peer_control =
            inject_competing_barrier
                ? (layout().barriers_prefix + std::string(32, 'd'))
                : (layout().writers_prefix + std::string(32, 'c'));
        bool injected = false;
        fixture.state->on_operation =
            [&](FakeState& s, std::string_view op, std::string_view) {
                if (!injected && op == "after_remove" &&
                    s.candidate_remove_count == 8) {
                    injected = true;
                    s.objects[peer_control] = protocol::testing::format_payload(
                        inject_competing_barrier ? "barrier" : "writer",
                        std::string(32, inject_competing_barrier ? 'd' : 'c'));
                }
            };

        const auto res =
            fixture.collect_with_options(gc_int::GarbageCollectOptions{
                .min_orphan_age = std::chrono::seconds{0},
                .apply_revalidation_batch_interval = 1,
            });
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error().code, GcErrorCode::ConcurrentChange);
        ASSERT_TRUE(res.error().garbage_collection.has_value());
        const auto& diag = *res.error().garbage_collection;
        EXPECT_EQ(diag.confirmed_removed, 8U);
        EXPECT_EQ(
            diag.mutation_state,
            kasumi::application::GarbageCollectMutationState::NotAttempted);
        EXPECT_TRUE(diag.barrier_release_confirmed);
        EXPECT_EQ(candidate_remove_attempts(*fixture.state), 8U);
        EXPECT_TRUE(fixture.present(peer_control));
        // Only our own barrier was removed; peer marker remains untouched and
        // batch 2 orphans stay intact.
        for (std::size_t i = 0; i < 8; ++i) {
            EXPECT_FALSE(fixture.present(orphans[i]));
        }
        for (std::size_t i = 8; i < 16; ++i) {
            EXPECT_TRUE(fixture.present(orphans[i]));
        }
        fixture.state->objects.erase(peer_control);
    }
}

TEST(GarbageCollectionTest, ScopedIgnoreCancellationShieldsStopTokenAndGlobalFlag) {
    ResetCancellation reset_guard;
    std::stop_source stop_source;
    const kasumi::platform::cancellation::ScopedStopToken stop_scope{
        stop_source.get_token()};

    EXPECT_FALSE(kasumi::platform::cancellation::ignoring());
    EXPECT_FALSE(kasumi::platform::cancellation::requested());

    stop_source.request_stop();
    kasumi::platform::cancellation::request();
    EXPECT_TRUE(kasumi::platform::cancellation::requested());
    EXPECT_TRUE(
        kasumi::platform::cancellation::current_stop_token().stop_requested());

    {
        const kasumi::platform::cancellation::ScopedIgnoreCancellation outer;
        EXPECT_TRUE(kasumi::platform::cancellation::ignoring());
        EXPECT_FALSE(kasumi::platform::cancellation::requested());
        EXPECT_FALSE(kasumi::platform::cancellation::current_stop_token()
                         .stop_requested());
        {
            const kasumi::platform::cancellation::ScopedIgnoreCancellation inner;
            EXPECT_TRUE(kasumi::platform::cancellation::ignoring());
            EXPECT_FALSE(kasumi::platform::cancellation::requested());
        }
        EXPECT_TRUE(kasumi::platform::cancellation::ignoring());
        EXPECT_FALSE(kasumi::platform::cancellation::requested());
    }

    EXPECT_FALSE(kasumi::platform::cancellation::ignoring());
    EXPECT_TRUE(kasumi::platform::cancellation::requested());
    EXPECT_TRUE(
        kasumi::platform::cancellation::current_stop_token().stop_requested());
}

TEST(GarbageCollectionTest,
     CancellationMidAnalyzingStillReleasesBarrierWhenTransportHonoursCancel) {
    FakeFixture fixture("gc-cancel-analyzing-releases-barrier");
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    fixture.put_content("orphan", "orphan");
    fixture.state->remove_attempts.clear();

    static auto raw_get = fixture.transport.storage.get;
    static auto raw_remove = fixture.transport.storage.remove;
    static auto raw_presence = fixture.transport.storage.presence;
    raw_get = fixture.transport.storage.get;
    raw_remove = fixture.transport.storage.remove;
    raw_presence = fixture.transport.storage.presence;

    auto cancel_error = []() -> kasumi::transport::Error {
        return kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Cancelled,
            .message = "operation cancelled by user",
        };
    };
    fixture.transport.storage.get =
        +[](void* ctx,
             std::string_view id,
             const std::filesystem::path& dst) -> kasumi::transport::Result {
        if (kasumi::platform::cancellation::requested()) {
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::Cancelled,
                .message = "operation cancelled by user",
            });
        }
        return raw_get(ctx, id, dst);
    };
    fixture.transport.storage.remove =
        +[](void* ctx, std::string_view id)
            -> kasumi::transport::RemovalResult {
        if (kasumi::platform::cancellation::requested()) {
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::Cancelled,
                .message = "operation cancelled by user",
            });
        }
        return raw_remove(ctx, id);
    };
    fixture.transport.storage.presence =
        +[](void* ctx, std::string_view id)
            -> kasumi::transport::PresenceResult {
        if (kasumi::platform::cancellation::requested()) {
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::Cancelled,
                .message = "operation cancelled by user",
            });
        }
        return raw_presence(ctx, id);
    };
    static_cast<void>(cancel_error);

    ResetCancellation reset_guard;
    std::stop_source stop_source;
    const kasumi::platform::cancellation::ScopedStopToken stop_scope{
        stop_source.get_token()};

    const auto result = fixture.collect_with_options(
        gc_int::GarbageCollectOptions{.min_orphan_age = std::chrono::seconds{0}},
        [&](const GarbageCollectProgress& progress) {
            if (progress.stage == GarbageCollectStage::Analyzing &&
                progress.sub_stage ==
                    GarbageCollectSubStage::AuthenticatingHistory) {
                stop_source.request_stop();
            }
        });

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, GcErrorCode::TransportFailure);
    ASSERT_TRUE(result.error().garbage_collection.has_value());
    const auto& diagnostic = *result.error().garbage_collection;
    EXPECT_EQ(diagnostic.stage, GarbageCollectStage::Analyzing);
    EXPECT_TRUE(diagnostic.barrier_release_attempted);
    EXPECT_TRUE(diagnostic.barrier_release_confirmed);
    EXPECT_FALSE(diagnostic.barrier_cleanup_error.has_value());
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 1U);
    EXPECT_FALSE(find_active_barrier(*fixture.state, layout()).has_value());
}

TEST(GarbageCollectionTest, GcReusesCommitCacheToSkipRemoteCommitDownloads) {
    FakeFixture fixture("gc-reuses-commit-cache");
    const auto c0 = commit_with_file("v1");
    const auto c1 =
        kasumi::history::make_commit(1, {commit_id(c0)}, make_tree("f.txt", "v2"))
            .value();
    fixture.publish(c0, "c0", false);
    fixture.publish(c1, "c1", true);
    fixture.put_content("v1", "v1");
    fixture.put_content("v2", "v2");
    fixture.put_content("orphan", "orphan");

    kasumi::application::history_storage::CommitCache commit_cache;
    commit_cache.disk_cache_root =
        kasumi::test::workspace_path(fixture.workspace, "commit-cache");

    const gc_int::GarbageCollectOptions opts{
        .dry_run = true,
        .min_orphan_age = std::chrono::seconds{0},
        .commit_cache = &commit_cache,
    };

    const auto first = fixture.collect_with_options(opts);
    ASSERT_TRUE(first.has_value()) << first.error().detail;
    EXPECT_EQ(first->candidate_objects, 1U); // "orphan" only; "v1" is reachable via c0
    EXPECT_EQ(fixture.state->commit_get_count, 2U);

    reset_remote_counts(*fixture.state);
    const auto second = fixture.collect_with_options(opts);
    ASSERT_TRUE(second.has_value()) << second.error().detail;
    EXPECT_EQ(second->candidate_objects, first->candidate_objects);
    EXPECT_EQ(fixture.state->commit_get_count, 0U);
}

TEST(GarbageCollectionTest,
     BifurcatedLegacyEpochChainFailsClosedAndPreservesAllBranches) {
    namespace epoch = kasumi::application::history_storage::epoch;
    FakeFixture fixture("gc-bifurcated-epochs");
    const auto c0 = commit_with_file("base");
    const auto ca =
        kasumi::history::make_commit(1, {commit_id(c0)}, make_tree("a.txt", "va"))
            .value();
    const auto cb =
        kasumi::history::make_commit(1, {commit_id(c0)}, make_tree("b.txt", "vb"))
            .value();
    const auto c0_variant = fixture.publish(c0, "c0", false);
    const auto ca_variant = fixture.publish(ca, "ca", true);
    const auto cb_variant = fixture.publish(cb, "cb", true);
    const auto base_content = fixture.put_content("base", "base");
    const auto a_content = fixture.put_content("va", "va");
    const auto b_content = fixture.put_content("vb", "vb");
    const auto orphan = fixture.put_content("orphan", "orphan");

    const auto root = kasumi::test::workspace_root(fixture.workspace);
    const Epoch e0_val{
        .vault_id = std::string(64, 'a'),
        .sequence = 0,
        .issued_at = 100,
        .policy = {},
        .anchors = {Anchor{.commit_id = commit_id(c0), .height = 0}},
    };
    const auto e0 = epoch::seal(e0_val, test_key());
    ASSERT_TRUE(e0.has_value());
    ASSERT_TRUE(epoch::publish(fixture.transport, test_key(), *e0, root));

    const Epoch e1a_val{
        .vault_id = std::string(64, 'a'),
        .sequence = 1,
        .issued_at = 200,
        .policy = {},
        .anchors = {Anchor{.commit_id = commit_id(ca), .height = 1}},
        .previous_epoch_id = e0->reference.epoch_id,
    };
    const Epoch e1b_val{
        .vault_id = std::string(64, 'a'),
        .sequence = 1,
        .issued_at = 205,
        .policy = {},
        .anchors = {Anchor{.commit_id = commit_id(cb), .height = 1}},
        .previous_epoch_id = e0->reference.epoch_id,
    };
    const auto e1a = epoch::seal(e1a_val, test_key());
    const auto e1b = epoch::seal(e1b_val, test_key());
    ASSERT_TRUE(e1a.has_value() && e1b.has_value());
    ASSERT_TRUE(epoch::publish(fixture.transport, test_key(), *e1a, root));
    ASSERT_TRUE(epoch::publish(fixture.transport, test_key(), *e1b, root));

    const auto e0_obj = epoch::object_identifier(layout(), e0->reference).value();
    const auto e1a_obj =
        epoch::object_identifier(layout(), e1a->reference).value();
    const auto e1b_obj =
        epoch::object_identifier(layout(), e1b->reference).value();

    const auto gc = fixture.collect_with_options(
        gc_int::GarbageCollectOptions{.min_orphan_age = std::chrono::seconds{0}});
    ASSERT_FALSE(gc.has_value());
    EXPECT_EQ(fixture.state->candidate_remove_count, 0U);
    EXPECT_EQ(fixture.state->source_remove_count, 0U);
    EXPECT_EQ(fixture.state->remove_batch_count, 0U);
    EXPECT_EQ(barrier_remove_attempts(*fixture.state), 1U);
    EXPECT_EQ(fixture.state->remove_count, 1U);
    EXPECT_TRUE(fixture.present(e0_obj));
    EXPECT_TRUE(fixture.present(e1a_obj));
    EXPECT_TRUE(fixture.present(e1b_obj));
    EXPECT_TRUE(fixture.present(object_path(c0_variant)));
    EXPECT_TRUE(fixture.present(object_path(ca_variant)));
    EXPECT_TRUE(fixture.present(object_path(cb_variant)));
    EXPECT_TRUE(fixture.present(base_content));
    EXPECT_TRUE(fixture.present(a_content));
    EXPECT_TRUE(fixture.present(b_content));
    EXPECT_TRUE(fixture.present(orphan));
}

TEST(GarbageCollectionTest,
     GarbageCollectRecoversAfterPostPutBarrierVerificationOutageAndPreservesPeer) {
    FakeFixture fixture("gc-post-put-barrier-recovery");
    fixture.state->physical_hash_supported = true;
    fixture.publish(commit_with_file("live"), "head");
    fixture.put_content("live", "live");
    const auto orphan = fixture.put_content("orphan", "orphan");

    // 1. Barrier PUT succeeds, post-PUT verification fails -> GC fails and
    // persists recoverable registration evidence locally.
    fixture.state->physical_hash_failure_identifier =
        layout().barrier_identifier;
    fixture.state->physical_hash_failure = kasumi::transport::ErrorCode::Timeout;
    const auto first = fixture.collect_with_options(
        gc_int::GarbageCollectOptions{.min_orphan_age = std::chrono::seconds{0}});
    ASSERT_FALSE(first.has_value());
    EXPECT_EQ(first.error().code, GcErrorCode::TransportFailure);
    const auto maintenance_root = fixture.runtime.database_path.parent_path();
    EXPECT_TRUE(
        std::filesystem::exists(maintenance_root / ".pending-control-markers"));
    EXPECT_TRUE(fixture.present(orphan));

    // 2. Backend recovers -> next GC automatically reconciles the abandoned
    // pre-admission barrier and completes cleanly.
    fixture.state->physical_hash_failure.reset();
    fixture.state->physical_hash_failure_identifier.clear();
    const auto second = fixture.collect_with_options(
        gc_int::GarbageCollectOptions{.min_orphan_age = std::chrono::seconds{0}});
    ASSERT_TRUE(second.has_value()) << second.error().detail;
    EXPECT_EQ(second->removed_objects, 1U);
    EXPECT_FALSE(fixture.present(orphan));
    EXPECT_FALSE(
        std::filesystem::exists(maintenance_root / ".pending-control-markers"));
}

TEST(GarbageCollectionTest,
     LocalBackendIgnoresIsolatedStagingAndLegacy0312ResiduesButRejectsUnknownControlFiles) {
    // 1. Crashed .kasumi-staging temp file on local storage backend -> GC
    // succeeds normally.
    {
        LocalFixture fixture;
        fixture.publish(commit_with_file("live"), "head");
        fixture.put_content("live", "live");
        const auto orphan = fixture.put_content("orphan", "orphan");
        const auto storage_root =
            kasumi::test::workspace_path(fixture.storage.workspace, "storage");
        std::filesystem::create_directories(storage_root / ".kasumi-staging");
        kasumi::test::write_text(
            storage_root / ".kasumi-staging" / "put-0123456789abcdef.tmp",
            "abandoned local put temp");

        const auto res = fixture.collect();
        ASSERT_TRUE(res.has_value()) << res.error().detail;
        EXPECT_EQ(res->removed_objects, 1U);
        EXPECT_FALSE(fixture.present(orphan));
    }

    // 2. Confirmed legacy 0.31.2 staging residue in barriers/ -> GC succeeds.
    {
        LocalFixture fixture;
        fixture.publish(commit_with_file("live"), "head");
        fixture.put_content("live", "live");
        const auto orphan = fixture.put_content("orphan", "orphan");
        const std::string token = "cccccccccccccccccccccccccccccccc";
        const auto tmp_path = kasumi::test::workspace_path(
            fixture.storage.workspace, "legacy-barrier.tmp");
        const auto bytes = protocol::testing::format_payload("barrier", token);
        kasumi::test::write_binary(
            tmp_path,
            std::as_bytes(std::span{bytes.data(), bytes.size()}));
        const auto tmp_id =
            layout().barriers_prefix + token + ".kasumi-tmp-abcdef0123456789";
        ASSERT_TRUE(
            kasumi::transport::put(fixture.storage.transport, tmp_path, tmp_id));

        const auto res = fixture.collect();
        ASSERT_TRUE(res.has_value()) << res.error().detail;
        EXPECT_EQ(res->removed_objects, 1U);
        EXPECT_FALSE(fixture.present(orphan));
    }

    // 3. Ambiguous/unknown file in barriers/ -> GC fails closed with
    // diagnostics and preserves the unknown file untouched.
    {
        LocalFixture fixture;
        fixture.publish(commit_with_file("live"), "head");
        fixture.put_content("live", "live");
        const auto orphan = fixture.put_content("orphan", "orphan");
        const std::string token = "dddddddddddddddddddddddddddddddd";
        const auto unknown_path = kasumi::test::workspace_path(
            fixture.storage.workspace, "unknown-barrier.bin");
        kasumi::test::write_text(unknown_path, "user-placed-content");
        const auto unknown_id =
            layout().barriers_prefix + token + ".kasumi-tmp-0011223344556677";
        ASSERT_TRUE(kasumi::transport::put(
            fixture.storage.transport, unknown_path, unknown_id));

        const auto res = fixture.collect();
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error().code, GcErrorCode::IntegrityFailure);
        EXPECT_NE(res.error().detail.find(".kasumi-tmp-0011223344556677"),
                  std::string::npos);
        EXPECT_TRUE(fixture.present(unknown_id));
        EXPECT_TRUE(fixture.present(orphan));
    }
}

TEST(GarbageCollectionTest,
     RetentionPolicyRespectsDepthAgeRecentReplacementAndFileMtime) {
    namespace epoch = kasumi::application::history_storage::epoch;
    namespace db = kasumi::state_storage;
    const std::int64_t t0 = 1'700'000'000;

    // Helper builds a FakeFixture with default 5-gen / 6h Epoch 0 policy,
    // linear commits, and matching local checkpoint at HEAD.
    const auto run_case = [&](const std::vector<std::int64_t>& commit_times,
                              std::int64_t now_unix,
                              std::uint32_t min_orphan_hours,
                              std::int64_t obj_mtime,
                              std::int64_t tree_file_mtime_ns) {
        FakeFixture fixture("gc-policy-boundaries");
        fixture.runtime.min_history_depth = 5;
        fixture.runtime.min_history_age_hours = 6;
        fixture.state->list_metadata_supported = true;

        std::vector<kasumi::history::Commit> commits;
        std::vector<HeadReference> refs;
        std::vector<std::string> contents;
        for (std::size_t i = 0; i < commit_times.size(); ++i) {
            const std::string payload = "payload-v" + std::to_string(i);
            auto tree = make_tree("doc.txt", payload);
            tree.rows[1].mtime = tree_file_mtime_ns;
            kasumi::finalize_snapshot(tree);
            const std::vector<std::string> parents =
                commits.empty()
                    ? std::vector<std::string>{}
                    : std::vector<std::string>{commit_id(commits.back())};
            auto c = kasumi::history::make_commit(
                         i, parents, std::move(tree), commit_times[i])
                         .value();
            const bool is_head = (i + 1 == commit_times.size());
            refs.push_back(fixture.publish(c, "c" + std::to_string(i), is_head));
            contents.push_back(
                fixture.put_content(payload, "p" + std::to_string(i)));
            commits.push_back(std::move(c));
        }

        const auto ws = kasumi::test::workspace_root(fixture.workspace);
        Epoch e0{.vault_id = std::string(64, 'a'),
                 .sequence = 0,
                 .issued_at = t0,
                 .policy = {.min_history_depth = 5, .min_history_age_hours = 6},
                 .anchors = {{.commit_id = refs.front().commit_id, .height = 0}}};
        const auto sealed0 = epoch::seal(e0, test_key()).value();
        EXPECT_TRUE(epoch::publish(fixture.transport, test_key(), sealed0, ws));
        for (const auto& [id, unused] : fixture.state->objects) {
            static_cast<void>(unused);
            fixture.state->object_mtimes[id] = obj_mtime;
        }
        fixture.state->default_object_mtime = now_unix;
        EXPECT_TRUE(db::initialize(fixture.runtime.database_path));
        EXPECT_TRUE(db::save_state(fixture.runtime.database_path,
                                   {.tree = commits.back().tree,
                                    .height = commits.back().height,
                                    .commit_id = refs.back().commit_id,
                                    .ciphertext_id = refs.back().ciphertext_id,
                                    .epoch_id = sealed0.reference.epoch_id,
                                    .epoch_sequence = 0}));

        kasumi::platform::clock::testing::ScopedUnixSecondsOverride clock(
            now_unix);
        auto res = fixture.collect_with_options(
            {.min_orphan_age =
                 std::chrono::hours{min_orphan_hours}});
        struct Outcome {
            std::expected<gc_int::GarbageCollectResult, gc_int::Error> gc;
            bool oldest_content_present = false;
            FakeFixture fixture_keep; // unused
        };
        return std::tuple{std::move(res),
                          fixture.present(contents.front()),
                          std::move(commits),
                          std::move(contents),
                          fixture.state->objects.size()};
    };

    // 1. >5 versions (7 commits), all within 6h -> nothing expires even if file
    // mtime in Commit.tree is 10 years old and min_orphan_age is 0.
    {
        std::vector<std::int64_t> times;
        for (int i = 0; i < 7; ++i) {
            times.push_back(t0 + i * 600);
        }
        auto [gc, oldest_ok, c, ids, n] =
            run_case(times, t0 + 3600, 0, t0 - 10 * 3600, 100LL);
        ASSERT_TRUE(gc.has_value()) << gc.error().detail;
        EXPECT_FALSE(gc->epoch_advanced);
        EXPECT_EQ(gc->removed_objects, 0U);
        EXPECT_TRUE(oldest_ok);
    }

    // 2. <5 generations (4 commits), even 48h old -> nothing expires.
    {
        const std::vector<std::int64_t> times{
            t0, t0 + 60, t0 + 120, t0 + 48 * 3600};
        auto [gc, oldest_ok, c, ids, n] =
            run_case(times, t0 + 72 * 3600, 0, t0, t0 * 1'000'000'000LL);
        ASSERT_TRUE(gc.has_value()) << gc.error().detail;
        EXPECT_FALSE(gc->epoch_advanced);
        EXPECT_EQ(gc->removed_objects, 0U);
        EXPECT_TRUE(oldest_ok);
    }

    // 3. Old file replaced only 5 minutes ago followed by 5 commits -> c0 stays
    // protected because superseded_at(c0) = c1.created_at is within 6h.
    {
        const std::int64_t now = t0 + 72 * 3600;
        const std::vector<std::int64_t> times{
            t0,           now - 300, now - 240, now - 180,
            now - 120,    now - 60,  now - 10};
        auto [gc, oldest_ok, c, ids, n] =
            run_case(times, now, 0, t0, 100LL);
        ASSERT_TRUE(gc.has_value()) << gc.error().detail;
        EXPECT_FALSE(gc->epoch_advanced);
        EXPECT_EQ(gc->removed_objects, 0U);
        EXPECT_TRUE(oldest_ok);
    }

    // 4. Separate physical deletion grace (--min-age 6h) vs version retention:
    // After 7 commits with superseded_at > 6h, Epoch advances (0 -> 1) even if
    // physical object mtime is recent, deferring physical deletion until grace
    // elapses.
    {
        const std::int64_t now = t0 + 12 * 3600;
        const std::vector<std::int64_t> times{
            t0,       t0 + 60,      now - 7200, now - 3600,
            now - 1800, now - 900,  now - 300};
        auto [gc, oldest_ok, c, ids, n] =
            run_case(times, now, 6, now - 60, now * 1'000'000'000LL);
        ASSERT_TRUE(gc.has_value()) << gc.error().detail;
        EXPECT_TRUE(gc->epoch_advanced);
        EXPECT_EQ(gc->target_epoch_sequence, std::optional<std::uint64_t>{1U});
        EXPECT_GT(gc->deferred_recent_objects, 0U);
        EXPECT_EQ(gc->removed_objects, 0U);
        EXPECT_TRUE(oldest_ok);
    }
}

TEST(GarbageCollectionTest,
     ConcurrentCollectorsAndWriterRaceCannotPublishIncompatibleEpochOrDropBranch) {
    namespace epoch = kasumi::application::history_storage::epoch;
    namespace db = kasumi::state_storage;
    const std::int64_t t0 = 1'700'000'000;
    const std::int64_t now = t0 + 12 * 3600;

    const auto setup_prunable = [&](FakeFixture& fixture,
                                    std::vector<HeadReference>& refs,
                                    std::vector<kasumi::history::Commit>& commits) {
        fixture.runtime.min_history_depth = 2;
        fixture.runtime.min_history_age_hours = 1;
        fixture.state->list_metadata_supported = true;
        for (int i = 0; i < 4; ++i) {
            const std::int64_t ts = (i < 2) ? (t0 + i * 60) : (now - (4 - i) * 60);
            const std::vector<std::string> parents =
                commits.empty()
                    ? std::vector<std::string>{}
                    : std::vector<std::string>{commit_id(commits.back())};
            auto c = kasumi::history::make_commit(
                         static_cast<std::uint64_t>(i),
                         parents,
                         make_tree("f.txt", "v" + std::to_string(i)),
                         ts)
                         .value();
            refs.push_back(fixture.publish(c, "c" + std::to_string(i), i == 3));
            fixture.put_content("v" + std::to_string(i), "cv" + std::to_string(i));
            commits.push_back(std::move(c));
        }
        const auto ws = kasumi::test::workspace_root(fixture.workspace);
        Epoch e0{.vault_id = std::string(64, 'c'),
                 .sequence = 0,
                 .issued_at = t0,
                 .policy = {.min_history_depth = 2, .min_history_age_hours = 1},
                 .anchors = {{.commit_id = refs.front().commit_id, .height = 0}}};
        const auto s0 = epoch::seal(e0, test_key()).value();
        ASSERT_TRUE(epoch::publish(fixture.transport, test_key(), s0, ws));
        for (const auto& [id, unused] : fixture.state->objects) {
            static_cast<void>(unused);
            fixture.state->object_mtimes[id] = t0;
        }
        fixture.state->default_object_mtime = now;
        ASSERT_TRUE(db::initialize(fixture.runtime.database_path));
        ASSERT_TRUE(db::save_state(fixture.runtime.database_path,
                                   {.tree = commits.back().tree,
                                    .height = commits.back().height,
                                    .commit_id = refs.back().commit_id,
                                    .ciphertext_id = refs.back().ciphertext_id,
                                    .epoch_id = s0.reference.epoch_id,
                                    .epoch_sequence = 0}));
    };

    // 1. Two collectors starting from Epoch 0: competing collector publishes an
    // incompatible Epoch 1 right before this collector publishes -> aborts fail
    // closed with zero deletions.
    {
        FakeFixture fixture("gc-competing-collectors");
        std::vector<HeadReference> refs;
        std::vector<kasumi::history::Commit> commits;
        ASSERT_NO_FATAL_FAILURE(setup_prunable(fixture, refs, commits));

        const auto latest0 =
            epoch::load_latest(fixture.transport,
                               test_key(),
                               kasumi::test::workspace_root(fixture.workspace))
                .value();
        Epoch competing_e1{
            .vault_id = latest0->value.vault_id,
            .sequence = 1,
            .issued_at = now,
            .policy = latest0->value.policy,
            .anchors = {{.commit_id = refs[2].commit_id, .height = 2}},
            .previous_epoch_id = latest0->reference.epoch_id};
        const auto sealed_competing =
            epoch::seal(competing_e1, test_key()).value();
        const auto competing_id =
            epoch::object_identifier(layout(), sealed_competing.reference)
                .value();
        bool injected = false;
        fixture.state->on_operation = [&](FakeState& st,
                                          std::string_view op,
                                          std::string_view) {
            if (!injected && op == "after_prefix_list" &&
                st.full_list_count >= 1 && st.probe_list_count >= 1) {
                injected = true;
                st.objects[competing_id] = sealed_competing.bytes;
                st.object_mtimes[competing_id] = now;
            }
        };

        kasumi::platform::clock::testing::ScopedUnixSecondsOverride clock(now);
        const auto res = fixture.collect();
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error().code, GcErrorCode::ConcurrentChange);
        EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
        EXPECT_EQ(fixture.state->objects.count(competing_id), 1U);
    }

    // 2. Concurrent writer publishes a new head during maintenance -> GC detects
    // the new head before Epoch publication, fails closed, and preserves branch.
    {
        FakeFixture fixture("gc-concurrent-writer-head");
        std::vector<HeadReference> refs;
        std::vector<kasumi::history::Commit> commits;
        ASSERT_NO_FATAL_FAILURE(setup_prunable(fixture, refs, commits));

        const auto writer_commit =
            kasumi::history::make_commit(
                2,
                {refs[1].commit_id},
                make_tree("branch.txt", "branch-new"),
                now - 10)
                .value();
        const auto writer_content =
            put_content(fixture.transport,
                        fixture.workspace,
                        "branch-new",
                        "branch-new-obj");
        const auto writer_canon =
            kasumi::history::serialize(writer_commit).value();
        const auto writer_cid =
            kasumi::crypto::commit_identifier(test_key(), writer_canon);
        bool writer_injected = false;
        HeadReference writer_ref;
        fixture.state->on_operation = [&](FakeState& st,
                                          std::string_view op,
                                          std::string_view) {
            if (!writer_injected && op == "after_prefix_list" &&
                st.full_list_count >= 1 && st.probe_list_count >= 1) {
                writer_injected = true;
                writer_ref = publish_object(fixture.transport,
                                            fixture.workspace,
                                            writer_commit,
                                            "writer-branch",
                                            true);
            }
        };

        kasumi::platform::clock::testing::ScopedUnixSecondsOverride clock(now);
        const auto res = fixture.collect();
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error().code, GcErrorCode::ConcurrentChange);
        EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
        EXPECT_TRUE(fixture.present(writer_content));
        EXPECT_TRUE(fixture.present(object_path(writer_ref)));
        (void)writer_cid;
    }

    // 3. Two unreconciled heads protect both tips and their merge base even
    // when old enough, while history strictly before the merge base expires.
    {
        FakeFixture fixture("gc-two-heads-merge-base");
        fixture.runtime.min_history_depth = 1;
        fixture.runtime.min_history_age_hours = 1;
        fixture.state->list_metadata_supported = true;

        auto c_pre = kasumi::history::make_commit(
                         0, {}, make_tree("f.txt", "pre-base"), t0)
                         .value();
        const auto pre_ref = fixture.publish(c_pre, "pre", false);
        const auto pre_content = fixture.put_content("pre-base", "pre-c");

        auto c_base = kasumi::history::make_commit(
                          1, {pre_ref.commit_id}, make_tree("f.txt", "base"),
                          t0 + 60)
                          .value();
        const auto base_ref = fixture.publish(c_base, "base", false);
        const auto base_content = fixture.put_content("base", "base-c");

        auto c_h1 = kasumi::history::make_commit(
                        2, {base_ref.commit_id}, make_tree("f.txt", "h1"),
                        now - 10)
                        .value();
        const auto h1_ref = fixture.publish(c_h1, "h1", true);
        const auto h1_content = fixture.put_content("h1", "h1-c");

        auto c_h2 = kasumi::history::make_commit(
                        2, {base_ref.commit_id}, make_tree("f.txt", "h2"),
                        now - 5)
                        .value();
        const auto h2_ref = fixture.publish(c_h2, "h2", true);
        const auto h2_content = fixture.put_content("h2", "h2-c");

        const auto ws = kasumi::test::workspace_root(fixture.workspace);
        Epoch e0{.vault_id = std::string(64, 'f'),
                 .sequence = 0,
                 .issued_at = t0,
                 .policy = {.min_history_depth = 1, .min_history_age_hours = 1},
                 .anchors = {{.commit_id = pre_ref.commit_id, .height = 0}}};
        const auto s0 = epoch::seal(e0, test_key()).value();
        ASSERT_TRUE(epoch::publish(fixture.transport, test_key(), s0, ws));
        for (const auto& [id, unused] : fixture.state->objects) {
            static_cast<void>(unused);
            fixture.state->object_mtimes[id] = t0;
        }
        fixture.state->default_object_mtime = now;
        ASSERT_TRUE(db::initialize(fixture.runtime.database_path));
        ASSERT_TRUE(db::save_state(fixture.runtime.database_path,
                                   {.tree = c_h1.tree,
                                    .height = 2,
                                    .commit_id = h1_ref.commit_id,
                                    .ciphertext_id = h1_ref.ciphertext_id,
                                    .epoch_id = s0.reference.epoch_id,
                                    .epoch_sequence = 0}));

        kasumi::platform::clock::testing::ScopedUnixSecondsOverride clock(now);
        const auto res = fixture.collect();
        ASSERT_TRUE(res.has_value()) << res.error().detail;
        EXPECT_TRUE(res->epoch_advanced);
        EXPECT_FALSE(fixture.present(pre_content));
        EXPECT_TRUE(fixture.present(base_content));
        EXPECT_TRUE(fixture.present(h1_content));
        EXPECT_TRUE(fixture.present(h2_content));
    }
}

TEST(GarbageCollectionTest,
     ListFailureLostResponsePublishAndApplyInterruptionRecoverCleanly) {
    namespace epoch = kasumi::application::history_storage::epoch;
    namespace db = kasumi::state_storage;
    const std::int64_t t0 = 1'700'000'000;
    const std::int64_t now = t0 + 12 * 3600;

    // 1. Listing failure fails closed with zero remote changes.
    {
        FakeFixture fixture("gc-list-failure");
        fixture.state->fail_list = kasumi::transport::ErrorCode::Io;
        const auto res = fixture.collect();
        ASSERT_FALSE(res.has_value());
        EXPECT_EQ(res.error().code, GcErrorCode::TransportFailure);
        EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
    }

    // 2. Lost-response Epoch 1 publish + 3. Interruption mid-Apply.
    FakeFixture fixture("gc-epoch-lost-response-and-apply-crash");
    fixture.runtime.min_history_depth = 2;
    fixture.runtime.min_history_age_hours = 1;
    fixture.state->list_metadata_supported = true;

    std::vector<HeadReference> refs;
    std::vector<kasumi::history::Commit> commits;
    std::vector<std::string> contents;
    for (int i = 0; i < 5; ++i) {
        const std::int64_t ts = (i < 3) ? (t0 + i * 60) : (now - (5 - i) * 60);
        const std::vector<std::string> parents =
            commits.empty()
                ? std::vector<std::string>{}
                : std::vector<std::string>{commit_id(commits.back())};
        auto c = kasumi::history::make_commit(
                     static_cast<std::uint64_t>(i),
                     parents,
                     make_tree("f.txt", "item-" + std::to_string(i)),
                     ts)
                     .value();
        refs.push_back(fixture.publish(c, "c" + std::to_string(i), i == 4));
        contents.push_back(
            fixture.put_content("item-" + std::to_string(i),
                                "p" + std::to_string(i)));
        commits.push_back(std::move(c));
    }
    const auto ws = kasumi::test::workspace_root(fixture.workspace);
    Epoch e0{.vault_id = std::string(64, 'd'),
             .sequence = 0,
             .issued_at = t0,
             .policy = {.min_history_depth = 2, .min_history_age_hours = 1},
             .anchors = {{.commit_id = refs.front().commit_id, .height = 0}}};
    const auto s0 = epoch::seal(e0, test_key()).value();
    ASSERT_TRUE(epoch::publish(fixture.transport, test_key(), s0, ws));
    for (const auto& [id, unused] : fixture.state->objects) {
        static_cast<void>(unused);
        fixture.state->object_mtimes[id] = t0;
    }
    fixture.state->default_object_mtime = now;
    ASSERT_TRUE(db::initialize(fixture.runtime.database_path));
    ASSERT_TRUE(db::save_state(fixture.runtime.database_path,
                               {.tree = commits.back().tree,
                                .height = commits.back().height,
                                .commit_id = refs.back().commit_id,
                                .ciphertext_id = refs.back().ciphertext_id,
                                .epoch_id = s0.reference.epoch_id,
                                .epoch_sequence = 0}));

    // Precompute the exact Epoch 1 object ID GC will publish and inject a
    // lost-response PUT failure on it (bytes ARE stored remotely, PUT fails).
    const std::vector<LoadedCommit> loaded_for_plan{
        {.id = refs[0].commit_id, .commit = commits[0]},
        {.id = refs[1].commit_id, .commit = commits[1]},
        {.id = refs[2].commit_id, .commit = commits[2]},
        {.id = refs[3].commit_id, .commit = commits[3]},
        {.id = refs[4].commit_id, .commit = commits[4]}};
    const std::vector<std::string> tip_ids{refs[4].commit_id};
    const auto expected_plan =
        epoch::plan_pruning(loaded_for_plan, e0.policy,
                            {.reference_now_unix = now,
                             .marked_commit_ids = tip_ids,
                             .current_anchors = e0.anchors,
                             .protected_commit_ids = tip_ids})
            .value();
    Epoch expected_e1{
        .vault_id = e0.vault_id,
        .sequence = 1,
        .issued_at = now,
        .policy = e0.policy,
        .anchors = expected_plan.anchors,
        .previous_epoch_id = s0.reference.epoch_id};
    const auto expected_s1 = epoch::seal(expected_e1, test_key()).value();
    const auto expected_e1_id =
        epoch::object_identifier(layout(), expected_s1.reference).value();

    fixture.state->put_then_fail_identifier = expected_e1_id;
    kasumi::platform::clock::testing::ScopedUnixSecondsOverride clock(now);
    const auto lost_res = fixture.collect();
    ASSERT_FALSE(lost_res.has_value());
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
    EXPECT_TRUE(std::filesystem::exists(
        fixture.runtime.database_path.parent_path() / ".pending-gc-epoch"));

    // Next live GC reconciles .pending-gc-epoch with remote Epoch 1, does not
    // publish a second conflicting Epoch, and if interrupted mid-Apply (fail on
    // 2nd deletion), keeps Epoch 1 confirmed and finishes on the following GC.
    fixture.state->fail_candidate_remove_at = 2;
    const auto mid_apply = fixture.collect();
    ASSERT_FALSE(mid_apply.has_value());
    EXPECT_FALSE(std::filesystem::exists(
        fixture.runtime.database_path.parent_path() / ".pending-gc-epoch"));

    const auto local_after_crash =
        db::load_state(fixture.runtime.database_path).value();
    ASSERT_TRUE(local_after_crash.has_value());
    EXPECT_EQ(local_after_crash->epoch_sequence, 1U);

    fixture.state->fail_candidate_remove_at = 0;
    const auto resumed = fixture.collect();
    ASSERT_TRUE(resumed.has_value()) << resumed.error().detail;
    EXPECT_FALSE(resumed->epoch_advanced);
    EXPECT_FALSE(fixture.present(contents[0]));
    EXPECT_FALSE(fixture.present(contents[1]));
    EXPECT_TRUE(fixture.present(contents[2]));
    EXPECT_TRUE(fixture.present(contents[3]));
    EXPECT_TRUE(fixture.present(contents[4]));
    EXPECT_TRUE(
        kasumi::application::integrity::fsck(
            fixture.runtime, fixture.transport, test_key())
            .has_value());
}

TEST(GarbageCollectionTest,
     LegacyPreEpochVaultAndMixed031WriterFailClosedSafely) {
    // 1. Legacy vault with no epochs/ objects cleans only unreferenced orphans
    // and never synthesizes Epoch 0.
    {
        FakeFixture fixture("gc-legacy-pre-epoch");
        const auto c = commit_with_file("live");
        fixture.publish(c, "legacy-head");
        const auto live = fixture.put_content("live", "live-obj");
        const auto orphan = fixture.put_content("orphan", "orphan-obj");

        const auto res = fixture.collect();
        ASSERT_TRUE(res.has_value()) << res.error().detail;
        EXPECT_FALSE(res->epoch_advanced);
        EXPECT_FALSE(res->epoch_advancement_planned);
        EXPECT_TRUE(fixture.present(live));
        EXPECT_FALSE(fixture.present(orphan));
    }

    // 2. Mixed 0.31 writer publishes conflicting Epoch 1 concurrently: fails
    // closed cleanly without deleting objects.
    namespace epoch = kasumi::application::history_storage::epoch;
    namespace db = kasumi::state_storage;
    const std::int64_t t0 = 1'700'000'000;
    const std::int64_t now = t0 + 12 * 3600;
    FakeFixture fixture("gc-mixed-031-writer");
    fixture.runtime.min_history_depth = 1;
    fixture.runtime.min_history_age_hours = 1;
    fixture.state->list_metadata_supported = true;

    auto c0 =
        kasumi::history::make_commit(0, {}, make_tree("f.txt", "v0"), t0).value();
    const auto r0 = fixture.publish(c0, "c0", false);
    const auto k0 = fixture.put_content("v0", "k0");
    auto c1 = kasumi::history::make_commit(
                  1, {r0.commit_id}, make_tree("f.txt", "v1"), now - 60)
                  .value();
    const auto r1 = fixture.publish(c1, "c1", true);
    const auto k1 = fixture.put_content("v1", "k1");

    const auto ws = kasumi::test::workspace_root(fixture.workspace);
    Epoch e0{.vault_id = std::string(64, 'e'),
             .sequence = 0,
             .issued_at = t0,
             .policy = {.min_history_depth = 1, .min_history_age_hours = 1},
             .anchors = {{.commit_id = r0.commit_id, .height = 0}}};
    const auto s0 = epoch::seal(e0, test_key()).value();
    ASSERT_TRUE(epoch::publish(fixture.transport, test_key(), s0, ws));
    for (const auto& [id, unused] : fixture.state->objects) {
        static_cast<void>(unused);
        fixture.state->object_mtimes[id] = t0;
    }
    fixture.state->default_object_mtime = now;
    ASSERT_TRUE(db::initialize(fixture.runtime.database_path));
    ASSERT_TRUE(db::save_state(fixture.runtime.database_path,
                               {.tree = c1.tree,
                                .height = 1,
                                .commit_id = r1.commit_id,
                                .ciphertext_id = r1.ciphertext_id,
                                .epoch_id = s0.reference.epoch_id,
                                .epoch_sequence = 0}));

    // Seed two conflicting sequence-1 epochs simulating legacy race.
    Epoch e1a = e0;
    e1a.sequence = 1;
    e1a.issued_at = now;
    e1a.anchors = {{.commit_id = r1.commit_id, .height = 1}};
    e1a.previous_epoch_id = s0.reference.epoch_id;
    Epoch e1b = e1a;
    e1b.issued_at = now + 1;
    ASSERT_TRUE(epoch::publish(
        fixture.transport, test_key(), epoch::seal(e1a, test_key()).value(), ws));
    ASSERT_TRUE(epoch::publish(
        fixture.transport, test_key(), epoch::seal(e1b, test_key()).value(), ws));

    kasumi::platform::clock::testing::ScopedUnixSecondsOverride clock(now);
    const auto res = fixture.collect();
    ASSERT_FALSE(res.has_value());
    EXPECT_NE(res.error().detail.find("conflict"), std::string::npos);
    EXPECT_EQ(candidate_remove_attempts(*fixture.state), 0U);
    EXPECT_TRUE(fixture.present(k0));
    EXPECT_TRUE(fixture.present(k1));
}

TEST(GarbageCollectionTest,
     NearMaximumLoadedCommitBudgetMakesProgressThenFailsAboveLimit) {
    namespace epoch = kasumi::application::history_storage::epoch;
    namespace db = kasumi::state_storage;
    const std::int64_t t0 = 1'700'000'000;
    const std::size_t near_limit =
        kasumi::history::maximum_loaded_commit_count - 6U; // 4,090 commits
    const std::int64_t now = t0 + 10 * 3600;

    FakeFixture fixture("gc-near-4096-budget");
    fixture.runtime.min_history_depth = 5;
    fixture.runtime.min_history_age_hours = 6;
    fixture.state->list_metadata_supported = true;

    const auto old_tree = make_tree("live.txt", "c0-exclusive");
    const auto steady_tree = make_tree("live.txt", "steady");
    const auto old_content = fixture.put_content("c0-exclusive", "c0-content");
    const auto steady_content =
        fixture.put_content("steady", "steady-content");

    std::string prev_id;
    HeadReference first_ref;
    HeadReference head_ref;
    kasumi::history::Commit head_commit;
    for (std::size_t i = 0; i < near_limit; ++i) {
        const std::vector<std::string> parents =
            prev_id.empty() ? std::vector<std::string>{}
                            : std::vector<std::string>{prev_id};
        const std::int64_t ts = (i + 10 < near_limit)
                                    ? (t0 + static_cast<std::int64_t>(i))
                                    : (now - 10);
        auto c = kasumi::history::make_commit(
                     i, parents, i == 0 ? old_tree : steady_tree, ts)
                     .value();
        const bool is_head = (i + 1 == near_limit);
        const auto ref = fixture.publish(c, "bulk", is_head);
        if (i == 0) {
            first_ref = ref;
        }
        if (is_head) {
            head_ref = ref;
            head_commit = c;
        }
        prev_id = ref.commit_id;
    }

    const auto ws = kasumi::test::workspace_root(fixture.workspace);
    Epoch e0{.vault_id = std::string(64, 'b'),
             .sequence = 0,
             .issued_at = t0,
             .policy = {.min_history_depth = 5, .min_history_age_hours = 6},
             .anchors = {{.commit_id = first_ref.commit_id, .height = 0}}};
    const auto s0 = epoch::seal(e0, test_key()).value();
    ASSERT_TRUE(epoch::publish(fixture.transport, test_key(), s0, ws));
    for (const auto& [id, unused] : fixture.state->objects) {
        static_cast<void>(unused);
        fixture.state->object_mtimes[id] = t0;
    }
    fixture.state->default_object_mtime = now;
    ASSERT_TRUE(db::initialize(fixture.runtime.database_path));
    ASSERT_TRUE(db::save_state(fixture.runtime.database_path,
                               {.tree = head_commit.tree,
                                .height = head_commit.height,
                                .commit_id = head_ref.commit_id,
                                .ciphertext_id = head_ref.ciphertext_id,
                                .epoch_id = s0.reference.epoch_id,
                                .epoch_sequence = 0}));

    kasumi::platform::clock::testing::ScopedUnixSecondsOverride clock(now);
    const auto res = fixture.collect();
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_TRUE(res->epoch_advanced);
    EXPECT_EQ(res->target_epoch_sequence, std::optional<std::uint64_t>{1U});
    EXPECT_FALSE(fixture.present(old_content));
    EXPECT_TRUE(fixture.present(steady_content));

    const auto inv_after =
        kasumi::application::history_storage::inventory_reachability(
            fixture.transport, test_key(), ws);
    ASSERT_TRUE(inv_after.has_value()) << inv_after.error().detail;
    EXPECT_LT(inv_after->reachable_commits.size(), 20U);

    // Exceeding maximum_loaded_commit_count fails closed without deletions.
    std::vector<LoadedCommit> over_limit;
    over_limit.reserve(kasumi::history::maximum_loaded_commit_count + 1);
    for (std::size_t i = 0;
         i < kasumi::history::maximum_loaded_commit_count + 1;
         ++i) {
        over_limit.push_back(LoadedCommit{
            .id = std::string(64, 'a'),
            .commit = kasumi::history::Commit{.height = i, .created_at = t0}});
    }
    EXPECT_FALSE(
        epoch::plan_pruning(
            over_limit, {.min_history_depth = 5, .min_history_age_hours = 6})
            .has_value());
}

} // namespace
