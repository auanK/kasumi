#include "application/observation/scanner.hpp"
#include "application/observation/state.hpp"
#include "application/sync/coordinator.hpp"
#include "application/sync/coordinator_detail.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/mutation.hpp"
#include "application/sync/mutation_batch.hpp"
#include "core/hasher.hpp"
#include "core/history.hpp"
#include "core/reconciliation/plan.hpp"
#include "core/transaction/types.hpp"
#include "crypto/file_crypto.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/scoped_environment.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

namespace sync = kasumi::application::sync;

struct ContentWindowProbe {
    std::mutex mutex;
    std::condition_variable changed;
    std::filesystem::path profile;
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE>* key = nullptr;
    std::optional<std::size_t> failed_ordinal;
    std::optional<std::size_t> failed_get_ordinal;
    std::size_t checkpoint_target = 0;
    std::size_t content_put_started = 0;
    std::size_t content_put_finished = 0;
    std::size_t content_get_count = 0;
    std::size_t active = 0;
    std::size_t peak_active = 0;
    std::size_t checkpoint_applied = 0;
    std::size_t active_at_checkpoint = 0;
    std::size_t applied_at_commit = 0;
    std::size_t uploads_at_commit = 0;
    kasumi::transaction::Phase phase_at_commit =
        kasumi::transaction::Phase::Started;
    std::size_t physical_hash_started = 0;
    std::size_t content_physical_hash_calls = 0;
    std::size_t physical_hash_batch_calls = 0;
    std::size_t physical_hash_batch_objects = 0;
    bool barrier_first_two_hashes = false;
    bool corrupt_first_physical_hash = false;
    bool physical_hash_unsupported = false;
    bool physical_hash_transport_failure = false;
    bool physical_hash_batch_unsupported = false;
    bool physical_hash_batch_transport_failure = false;
    bool barrier_first_four = false;
    bool barrier_first_four_gets = false;
    bool hold_first_until_fifth = false;
    bool fifth_started_while_first_active = false;
    bool checkpoint_observed = false;
    bool inspect_commit_checkpoint = false;
    bool commit_checkpoint_valid = false;
    bool fail_commit_put = false;
    std::size_t content_put_batch_count = 0;
    std::size_t content_put_batch_objects = 0;
    std::optional<std::size_t> fail_put_batch_after_objects;
    std::string corrupt_physical_hash_identifier;
    std::vector<std::string> bulk_mismatched;
    std::vector<std::string> bulk_missing;
    std::vector<std::string> bulk_errors;
};

struct RecordingTransportState {
    kasumi::transport::Transport* base = nullptr;
    std::vector<std::string>* events = nullptr;
    ContentWindowProbe* probe = nullptr;
    std::mutex events_mutex;
};

void destroy_recording_transport(void*) noexcept {
}

RecordingTransportState* recording_state(void* context) {
    return static_cast<RecordingTransportState*>(context);
}

void record_event(RecordingTransportState& state, std::string event) {
    std::lock_guard lock(state.events_mutex);
    state.events->push_back(std::move(event));
}

kasumi::transport::Result recording_initialize(void* context) {
    return kasumi::transport::initialize(*recording_state(context)->base);
}

kasumi::transport::Error injected_put_error() {
    return {.code = kasumi::transport::ErrorCode::Io,
            .message = "injected put failure",
            .native_code = 0};
}

std::optional<std::size_t> applied_progress(const ContentWindowProbe& probe) {
    if (probe.profile.empty() || probe.key == nullptr) {
        return std::nullopt;
    }
    const auto paths = sync::journal::make_paths(probe.profile);
    if (!paths) {
        return std::nullopt;
    }
    const auto loaded = sync::journal::load(*paths, *probe.key);
    if (!loaded || !*loaded) {
        return std::nullopt;
    }
    return std::ranges::count_if((*loaded)->progress, [](const auto& progress) {
        return progress.state == kasumi::transaction::OperationState::Applied;
    });
}

void wait_for_checkpoint(ContentWindowProbe& probe) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{2};
    while (std::chrono::steady_clock::now() < deadline) {
        const auto applied = applied_progress(probe);
        if (applied && *applied >= probe.checkpoint_target) {
            {
                std::lock_guard lock(probe.mutex);
                probe.checkpoint_applied = *applied;
                probe.active_at_checkpoint = probe.active;
                probe.checkpoint_observed = true;
            }
            probe.changed.notify_all();
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    probe.changed.notify_all();
}

kasumi::transport::Result recording_put(void* context,
                                        const std::filesystem::path& source,
                                        std::string_view identifier) {
    auto* state = recording_state(context);
    auto* probe = state->probe;
    const bool content = !identifier.starts_with("history/");
    const bool commit = identifier.starts_with("history/commits/");

    if (!content) {
        record_event(*state, "put:" + std::string{identifier});
        if (commit && probe != nullptr && probe->inspect_commit_checkpoint) {
            const auto paths = sync::journal::make_paths(probe->profile);
            if (paths) {
                const auto loaded = sync::journal::load(*paths, *probe->key);
                if (loaded && *loaded) {
                    std::lock_guard lock(probe->mutex);
                    probe->applied_at_commit = static_cast<
                        std::size_t>(std::ranges::count_if(
                        (*loaded)->progress, [](const auto& progress) {
                            return progress.state ==
                                   kasumi::transaction::OperationState::Applied;
                        }));
                    probe->uploads_at_commit = static_cast<std::size_t>(
                        std::ranges::count_if((*loaded)->plan.operations,
                                              [](const auto& operation) {
                                                  return operation.action ==
                                                         kasumi::Action::Upload;
                                              }));
                    probe->phase_at_commit = (*loaded)->phase;
                    probe->commit_checkpoint_valid = true;
                }
            }
        }
        if (commit && probe != nullptr && probe->fail_commit_put) {
            return std::unexpected(injected_put_error());
        }
        return kasumi::transport::put(*state->base, source, identifier);
    }

    std::size_t ordinal = 0;
    if (probe != nullptr) {
        std::unique_lock lock(probe->mutex);
        ordinal = probe->content_put_started++;
        ++probe->active;
        probe->peak_active = std::max(probe->peak_active, probe->active);
        record_event(*state, "put:" + std::string{identifier});
        if (ordinal == 4) {
            probe->fifth_started_while_first_active = probe->active > 1;
        }
        probe->changed.notify_all();
        if ((probe->barrier_first_four || probe->hold_first_until_fifth ||
             probe->checkpoint_target != 0) &&
            ordinal < 4) {
            probe->changed.wait_until(
                lock,
                std::chrono::steady_clock::now() + std::chrono::seconds{2},
                [&] {
                    return probe->content_put_started >= 4;
                });
        }
    } else {
        record_event(*state, "put:" + std::string{identifier});
    }

    if (probe != nullptr && probe->hold_first_until_fifth && ordinal == 0) {
        std::unique_lock lock(probe->mutex);
        probe->changed.wait_until(lock,
                                  std::chrono::steady_clock::now() +
                                      std::chrono::seconds{2},
                                  [&] {
                                      return probe->content_put_started >= 5;
                                  });
    }

    if (probe != nullptr && probe->checkpoint_target != 0 &&
        ordinal >= probe->checkpoint_target) {
        if (ordinal == probe->checkpoint_target) {
            wait_for_checkpoint(*probe);
        } else {
            std::unique_lock lock(probe->mutex);
            probe->changed.wait_until(lock,
                                      std::chrono::steady_clock::now() +
                                          std::chrono::seconds{2},
                                      [&] {
                                          return probe->checkpoint_observed;
                                      });
        }
    }

    const bool injected_failure =
        probe != nullptr && probe->failed_ordinal == ordinal;
    auto result =
        injected_failure
            ? kasumi::transport::Result{std::unexpect, injected_put_error()}
            : kasumi::transport::put(*state->base, source, identifier);
    if (probe != nullptr) {
        {
            std::lock_guard lock(probe->mutex);
            --probe->active;
            ++probe->content_put_finished;
        }
        probe->changed.notify_all();
    }
    return result;
}

kasumi::transport::Result
recording_put_batch(void* context, const kasumi::transport::PutBatch& batch) {
    auto* state = recording_state(context);
    auto* probe = state->probe;
    record_event(*state,
                 "put_batch:" + std::to_string(batch.identifiers.size()));
    if (probe != nullptr) {
        std::lock_guard lock(probe->mutex);
        ++probe->content_put_batch_count;
        probe->content_put_batch_objects += batch.identifiers.size();
    }

    const auto limit = probe == nullptr ? std::optional<std::size_t>{}
                                        : probe->fail_put_batch_after_objects;
    const auto count = limit.has_value()
                           ? std::min(*limit, batch.identifiers.size())
                           : batch.identifiers.size();
    for (std::size_t index = 0; index < count; ++index) {
        auto uploaded =
            kasumi::transport::put(*state->base,
                                   batch.source_root / batch.identifiers[index],
                                   batch.identifiers[index]);
        if (!uploaded) {
            return uploaded;
        }
    }
    if (limit.has_value() && count < batch.identifiers.size()) {
        std::lock_guard lock(probe->mutex);
        probe->bulk_missing.insert(
            probe->bulk_missing.end(),
            std::next(batch.identifiers.begin(),
                      static_cast<std::ptrdiff_t>(count)),
            batch.identifiers.end());
        return std::unexpected(injected_put_error());
    }
    return {};
}

std::expected<std::string, kasumi::transport::Error> recording_physical_hash(
    void* context, std::string_view identifier, std::string_view algorithm) {
    auto* state = recording_state(context);
    auto* probe = state->probe;
    if (probe != nullptr && probe->physical_hash_unsupported) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Unsupported,
            .message = "physical hash unavailable"});
    }

    if (probe != nullptr) {
        std::unique_lock lock(probe->mutex);
        if (!identifier.starts_with("history/")) {
            ++probe->content_physical_hash_calls;
        }
        ++probe->active;
        ++probe->physical_hash_started;
        probe->peak_active = std::max(probe->peak_active, probe->active);
        probe->changed.notify_all();
        if (!identifier.starts_with("history/") &&
            probe->barrier_first_two_hashes &&
            probe->content_physical_hash_calls <= 2) {
            probe->changed.wait_until(
                lock,
                std::chrono::steady_clock::now() + std::chrono::seconds{2},
                [&] {
                    return probe->content_physical_hash_calls >= 2;
                });
        }
    }

    auto result =
        probe != nullptr && probe->physical_hash_transport_failure &&
                !identifier.starts_with("history/")
            ? std::expected<
                  std::string,
                  kasumi::transport::
                      Error>{std::unexpect,
                             kasumi::transport::Error{
                                 .code = kasumi::transport::ErrorCode::Io,
                                 .message = "injected physical hash failure"}}
            : kasumi::transport::physical_hash(
                  *state->base, identifier, algorithm);
    if (probe != nullptr && !probe->corrupt_physical_hash_identifier.empty() &&
        identifier.find(probe->corrupt_physical_hash_identifier) !=
            std::string_view::npos) {
        result = std::string{"c0rrupt3d"};
    }
    if (probe != nullptr) {
        std::lock_guard lock(probe->mutex);
        --probe->active;
    }
    if (probe != nullptr) {
        probe->changed.notify_all();
    }
    return result;
}

kasumi::transport::PhysicalHashBatchResult recording_physical_hash_batch(
    void* context, const kasumi::transport::PhysicalHashBatchRequest& request) {
    auto* state = recording_state(context);
    auto* probe = state->probe;
    if (probe != nullptr) {
        std::lock_guard lock(probe->mutex);
        ++probe->physical_hash_batch_calls;
        probe->physical_hash_batch_objects += request.objects.size();
    }
    if (probe != nullptr && (probe->physical_hash_batch_unsupported ||
                             probe->physical_hash_unsupported)) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Unsupported,
            .message = "physical hash batch unavailable",
            .native_code = 0});
    }
    if (probe != nullptr && probe->physical_hash_batch_transport_failure) {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Io,
            .message = "injected physical hash batch failure",
            .native_code = 0});
    }

    kasumi::transport::PhysicalHashBatchReport report{
        .mismatched = probe == nullptr ? std::vector<std::string>{}
                                       : probe->bulk_mismatched,
        .missing =
            probe == nullptr ? std::vector<std::string>{} : probe->bulk_missing,
        .errors =
            probe == nullptr ? std::vector<std::string>{} : probe->bulk_errors};
    if (probe != nullptr && !probe->corrupt_physical_hash_identifier.empty()) {
        for (const auto& object : request.objects) {
            if (object.identifier.find(
                    probe->corrupt_physical_hash_identifier) !=
                std::string::npos) {
                report.mismatched.push_back(object.identifier);
            }
        }
    }
    return report;
}

kasumi::transport::Result
recording_get(void* context,
              std::string_view identifier,
              const std::filesystem::path& destination) {
    auto* state = recording_state(context);
    auto* probe = state->probe;
    if (probe == nullptr || identifier.starts_with("history/")) {
        return kasumi::transport::get(*state->base, identifier, destination);
    }

    std::size_t ordinal = 0;
    {
        std::unique_lock lock(probe->mutex);
        ordinal = probe->content_get_count++;
        ++probe->active;
        probe->peak_active = std::max(probe->peak_active, probe->active);
        probe->changed.notify_all();
        if (probe->barrier_first_four_gets && ordinal < 4) {
            probe->changed.wait_until(lock,
                                      std::chrono::steady_clock::now() +
                                          std::chrono::seconds{2},
                                      [&] {
                                          return probe->content_get_count >= 4;
                                      });
        }
    }
    auto result =
        probe->failed_get_ordinal == ordinal
            ? kasumi::transport::Result{std::unexpect, injected_put_error()}
            : kasumi::transport::get(*state->base, identifier, destination);
    {
        std::lock_guard lock(probe->mutex);
        --probe->active;
    }
    probe->changed.notify_all();
    return result;
}

kasumi::transport::PresenceResult recording_presence(void* context,
                                                     std::string_view id) {
    return kasumi::transport::presence(*recording_state(context)->base, id);
}

kasumi::transport::ListingResult recording_list(void* context) {
    return kasumi::transport::list(*recording_state(context)->base);
}

kasumi::transport::ListingResult
recording_list_prefix(void* context, std::string_view prefix) {
    return kasumi::transport::list(*recording_state(context)->base, prefix);
}

kasumi::transport::RemovalResult recording_remove(void* context,
                                                  std::string_view id) {
    auto& state = *recording_state(context);
    record_event(state, "remove:" + std::string{id});
    return kasumi::transport::remove(*state.base, id);
}

kasumi::transport::Transport
make_recording_transport(RecordingTransportState& state) {
    kasumi::transport::Transport result;
    result.state = {&state, destroy_recording_transport};
    result.storage = {.initialize = recording_initialize,
                      .put = recording_put,
                      .put_batch = recording_put_batch,
                      .get = recording_get,
                      .presence = recording_presence,
                      .list = recording_list,
                      .list_prefix = recording_list_prefix,
                      .physical_hash = recording_physical_hash,
                      .physical_hash_batch = recording_physical_hash_batch,
                      .remove = recording_remove,
                      .physical_hash_batch_min_objects = 6};
    return result;
}

struct FixtureData {
    kasumi::test::TempWorkspace workspace{nullptr,
                                          kasumi::test::remove_temp_workspace};
    std::filesystem::path profile;
    std::filesystem::path local;
    std::filesystem::path storage_path;
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    kasumi::transport::Transport base;
    RecordingTransportState recording;
    kasumi::transport::Transport storage;
    std::vector<std::string> events;
};

using Fixture = std::unique_ptr<FixtureData>;

Fixture make_fixture(std::string name) {
    auto fixture = std::make_unique<FixtureData>();
    fixture->workspace = kasumi::test::make_temp_workspace(name);
    fixture->profile =
        kasumi::test::workspace_path(fixture->workspace, "profile");
    fixture->local = kasumi::test::workspace_path(fixture->workspace, "local");
    fixture->storage_path =
        kasumi::test::workspace_path(fixture->workspace, "storage");
    if (!std::filesystem::create_directories(fixture->profile) ||
        !std::filesystem::create_directories(fixture->local)) {
        ADD_FAILURE() << "could not create fixture directories";
        return fixture;
    }
    auto opened =
        kasumi::transport::open_transport(fixture->storage_path.string());
    if (!opened) {
        ADD_FAILURE() << "could not open fixture transport";
        return fixture;
    }
    fixture->base = std::move(*opened);
    if (!kasumi::transport::initialize(fixture->base)) {
        ADD_FAILURE() << "could not initialize fixture transport";
        return fixture;
    }
    fixture->recording.base = &fixture->base;
    fixture->recording.events = &fixture->events;
    fixture->storage = make_recording_transport(fixture->recording);
    return fixture;
}

kasumi::runtime::RuntimeData runtime_data(const FixtureData& fixture) {
    return {.local_dir = fixture.local,
            .database_path = fixture.profile / "state.db",
            .key_path = fixture.profile / "key.bin",
            .storage_location = fixture.storage_path.string()};
}

kasumi::reconciliation::Input publication_input(const FixtureData& fixture) {
    auto scanned = kasumi::application::observation::scanner::scan_result(
        fixture.local,
        {},
        kasumi::application::observation::scanner::ScanPolicy::FullHash);
    EXPECT_TRUE(scanned.has_value());
    kasumi::Snapshot empty_storage{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    kasumi::finalize_snapshot(empty_storage);
    return {.local_tree = std::move(scanned->snapshot),
            .base_tree = {},
            .base_commit_id = {},
            .base_state_present = false,
            .storage = {.tree = empty_storage,
                        .object_identifiers = {},
                        .reachable_commits = {},
                        .reachable_commit_ids = {},
                        .marked_heads = {},
                        .marked_head_identifiers = {},
                        .logical_heads = {},
                        .ancestral_marked_heads = {},
                        .generation = 0,
                        .history_present = false,
                        .history_has_conflicts = false},
            .local_generation = 0,
            .audit_storage_objects = false};
}

std::expected<void, kasumi::application::sync::coordinator::Error>
execute_with(FixtureData& fixture,
             const kasumi::reconciliation::Input& input,
             const kasumi::reconciliation::Result& result) {
    return sync::coordinator::execute(
        runtime_data(fixture), fixture.storage, fixture.key, input, result);
}

void add_content_files(FixtureData& fixture, std::size_t count) {
    for (std::size_t index = 0; index < count; ++index) {
        kasumi::test::write_text(
            fixture.local / ("content-" + std::to_string(index) + ".txt"),
            "payload-" + std::to_string(index));
    }
}

void attach_probe(FixtureData& fixture, ContentWindowProbe& probe) {
    probe.profile = fixture.profile;
    probe.key = &fixture.key;
    fixture.recording.probe = &probe;
}

std::size_t content_put_events(const FixtureData& fixture) {
    return static_cast<std::size_t>(
        std::ranges::count_if(fixture.events, [](std::string_view event) {
            return event.starts_with("put:") &&
                   !event.starts_with("put:history/");
        }));
}

std::size_t history_put_events(const FixtureData& fixture,
                               std::string_view kind) {
    return static_cast<std::size_t>(
        std::ranges::count_if(fixture.events, [&](std::string_view event) {
            return event.starts_with("put:history/" + std::string{kind} + "/");
        }));
}

TEST(SyncContentWindowTest,
     UniqueDownloadsUseBoundedWindowAndRollbackDrainedPeersOnFailure) {
    auto concurrency = kasumi::test::scoped_environment_variable(
        "KASUMI_CONTENT_CONCURRENCY", "4");
    auto fixture = make_fixture("parallel-unique-downloads");
    add_content_files(*fixture, 4);
    auto input = publication_input(*fixture);
    auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_TRUE(execute_with(*fixture, input, *result));

    const auto make_empty_client = [&](std::string_view name) {
        fixture->profile = kasumi::test::workspace_path(
            fixture->workspace, std::string{name} + "-profile");
        fixture->local = kasumi::test::workspace_path(
            fixture->workspace, std::string{name} + "-local");
        ASSERT_TRUE(std::filesystem::create_directories(fixture->profile));
        ASSERT_TRUE(std::filesystem::create_directories(fixture->local));
    };

    make_empty_client("successful");
    ContentWindowProbe success_probe;
    success_probe.barrier_first_four_gets = true;
    attach_probe(*fixture, success_probe);
    auto observed =
        kasumi::application::observation::collect_reconciliation_input(
            runtime_data(*fixture), fixture->storage, fixture->key, false);
    ASSERT_TRUE(observed.has_value()) << observed.error().detail;
    result = kasumi::reconciliation::reconcile(*observed);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_EQ(std::ranges::count(result->plan.operations,
                                 kasumi::Action::Download,
                                 &kasumi::Operation::action),
              4);
    const auto successful_download = execute_with(*fixture, *observed, *result);
    ASSERT_TRUE(successful_download.has_value())
        << successful_download.error().detail;
    EXPECT_EQ(success_probe.peak_active, 4U);
    EXPECT_EQ(success_probe.content_get_count, 4U);
    EXPECT_EQ(success_probe.active, 0U);

    for (const auto failed_ordinal : {0U, 1U, 3U}) {
        make_empty_client("failing-" + std::to_string(failed_ordinal));
        ContentWindowProbe failure_probe;
        failure_probe.barrier_first_four_gets = true;
        failure_probe.failed_get_ordinal = failed_ordinal;
        attach_probe(*fixture, failure_probe);
        observed =
            kasumi::application::observation::collect_reconciliation_input(
                runtime_data(*fixture), fixture->storage, fixture->key, false);
        ASSERT_TRUE(observed.has_value()) << observed.error().detail;
        result = kasumi::reconciliation::reconcile(*observed);
        ASSERT_TRUE(result.has_value()) << result.error().detail;
        const auto failed = execute_with(*fixture, *observed, *result);
        ASSERT_FALSE(failed.has_value()) << failed_ordinal;
        EXPECT_EQ(failure_probe.peak_active, 4U) << failed_ordinal;
        EXPECT_EQ(failure_probe.content_get_count, 4U) << failed_ordinal;
        EXPECT_EQ(failure_probe.active, 0U) << failed_ordinal;
        EXPECT_TRUE(std::filesystem::is_empty(fixture->local))
            << failed_ordinal;
        EXPECT_FALSE(
            std::filesystem::exists(fixture->profile / "transaction.bin.enc"))
            << failed_ordinal;
    }
}

void add_repeated_content_files(FixtureData& fixture, std::size_t count) {
    for (std::size_t index = 0; index < count; ++index) {
        kasumi::test::write_text(
            fixture.local / ("duplicate-" + std::to_string(index) + ".txt"),
            "payload-" + std::to_string(index % 4));
    }
}

TEST(SyncContentBatchTest, VerificationAtThresholdUsesBulkAndSinglePutBatch) {
    auto fixture = make_fixture("batch-single-put");
    ContentWindowProbe probe;
    attach_probe(*fixture, probe);
    add_content_files(*fixture, 6);

    const auto input = publication_input(*fixture);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;

    const auto executed = execute_with(*fixture, input, *result);
    ASSERT_TRUE(executed.has_value()) << executed.error().detail;

    EXPECT_EQ(probe.content_put_batch_count, 1U);
    EXPECT_EQ(probe.content_put_batch_objects, 6U);
    EXPECT_EQ(probe.physical_hash_batch_calls, 1U);
    EXPECT_EQ(probe.physical_hash_batch_objects, 6U);
    EXPECT_EQ(probe.content_physical_hash_calls, 0U);
    EXPECT_EQ(content_put_events(*fixture), 0U);
    EXPECT_EQ(std::ranges::count_if(fixture->events,
                                    [](std::string_view event) {
                                        return event.starts_with("put_batch:");
                                    }),
              1U);
    EXPECT_EQ(history_put_events(*fixture, "commits"), 1U);
    EXPECT_EQ(history_put_events(*fixture, "heads"), 1U);
}

TEST(SyncContentBatchTest, SingleContentObjectUsesIndividualPhysicalHash) {
    auto fixture = make_fixture("single-content-physical-hash");
    ContentWindowProbe probe;
    attach_probe(*fixture, probe);
    add_content_files(*fixture, 1);

    const auto input = publication_input(*fixture);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;

    const auto executed = execute_with(*fixture, input, *result);
    ASSERT_TRUE(executed.has_value()) << executed.error().detail;

    EXPECT_EQ(probe.physical_hash_batch_calls, 0U);
    EXPECT_EQ(probe.content_physical_hash_calls, 1U);
}

TEST(SyncContentBatchTest, VerificationBelowThresholdUsesIndividualHashes) {
    auto concurrency = kasumi::test::scoped_environment_variable(
        "KASUMI_CONTENT_CONCURRENCY", "2");
    auto fixture = make_fixture("verification-below-threshold");
    ContentWindowProbe probe;
    probe.barrier_first_two_hashes = true;
    attach_probe(*fixture, probe);
    add_content_files(*fixture, 5);

    const auto input = publication_input(*fixture);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    const auto executed = execute_with(*fixture, input, *result);
    ASSERT_TRUE(executed.has_value()) << executed.error().detail;

    EXPECT_EQ(probe.physical_hash_batch_calls, 0U);
    EXPECT_EQ(probe.content_physical_hash_calls, 5U);
    EXPECT_EQ(probe.peak_active, 2U);
}

TEST(SyncContentBatchTest, VerificationAboveThresholdUsesBulk) {
    auto fixture = make_fixture("verification-above-threshold");
    ContentWindowProbe probe;
    attach_probe(*fixture, probe);
    add_content_files(*fixture, 7);

    const auto input = publication_input(*fixture);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    const auto executed = execute_with(*fixture, input, *result);
    ASSERT_TRUE(executed.has_value()) << executed.error().detail;

    EXPECT_EQ(probe.physical_hash_batch_calls, 1U);
    EXPECT_EQ(probe.physical_hash_batch_objects, 7U);
    EXPECT_EQ(probe.content_physical_hash_calls, 0U);
}

TEST(SyncContentBatchTest, PartialBatchFailureLeavesRemoteButZeroApplied) {
    auto fixture = make_fixture("partial-batch-failure");
    ContentWindowProbe probe;
    probe.fail_put_batch_after_objects = 4;
    attach_probe(*fixture, probe);
    add_content_files(*fixture, 10);

    const auto input = publication_input(*fixture);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;

    const auto executed = execute_with(*fixture, input, *result);
    ASSERT_FALSE(executed.has_value());
    EXPECT_EQ(probe.content_put_batch_count, 1U);
    EXPECT_EQ(history_put_events(*fixture, "commits"), 1U);
    EXPECT_EQ(history_put_events(*fixture, "heads"), 0U);

    const auto listed = kasumi::transport::list(fixture->base);
    ASSERT_TRUE(listed.has_value());
    EXPECT_EQ(std::ranges::count_if(*listed,
                                    [](std::string_view identifier) {
                                        return !identifier.starts_with(
                                            "history/");
                                    }),
              4U);
    EXPECT_FALSE(
        std::filesystem::exists(fixture->profile / "transaction.bin.enc"));
}

TEST(SyncContentBatchTest,
     VerificationFailureProducesZeroAppliedAndDeterministicError) {
    auto fixture = make_fixture("batch-verification-failure");
    ContentWindowProbe probe;
    attach_probe(*fixture, probe);
    add_content_files(*fixture, 8);

    const auto input = publication_input(*fixture);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_GE(result->plan.operations.size(), 4U);

    const auto target_index = 3U;
    probe.corrupt_physical_hash_identifier = kasumi::crypto::content_identifier(
        fixture->key,
        kasumi::hash_from_hex(result->plan.operations[target_index].hash)
            .value());

    const auto executed = execute_with(*fixture, input, *result);
    ASSERT_FALSE(executed.has_value());
    ASSERT_TRUE(executed.error().operation_index.has_value());
    EXPECT_EQ(*executed.error().operation_index, target_index);
    EXPECT_EQ(probe.content_put_batch_count, 1U);
    EXPECT_EQ(probe.physical_hash_batch_calls, 1U);
    EXPECT_EQ(probe.content_physical_hash_calls, 0U);
    EXPECT_EQ(history_put_events(*fixture, "commits"), 1U);
    EXPECT_EQ(history_put_events(*fixture, "heads"), 0U);
    EXPECT_FALSE(
        std::filesystem::exists(fixture->profile / "transaction.bin.enc"));
}

TEST(SyncContentBatchTest,
     VerificationFallbackDecryptsIfPhysicalHashUnsupported) {
    auto fixture = make_fixture("verification-fallback");
    ContentWindowProbe probe;
    probe.physical_hash_unsupported = true;
    attach_probe(*fixture, probe);
    add_content_files(*fixture, 6);

    const auto input = publication_input(*fixture);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;

    const auto executed = execute_with(*fixture, input, *result);
    ASSERT_TRUE(executed.has_value()) << executed.error().detail;
    EXPECT_EQ(probe.content_put_batch_count, 1U);
    EXPECT_EQ(probe.physical_hash_batch_calls, 1U);
    EXPECT_EQ(probe.content_physical_hash_calls, 0U);
    EXPECT_EQ(probe.content_get_count, 6U);
}

TEST(SyncContentBatchTest, BulkTransportFailureDoesNotFallback) {
    auto fixture = make_fixture("bulk-transport-failure");
    ContentWindowProbe probe;
    probe.physical_hash_batch_transport_failure = true;
    attach_probe(*fixture, probe);
    add_content_files(*fixture, 6);

    const auto input = publication_input(*fixture);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;

    const auto executed = execute_with(*fixture, input, *result);
    ASSERT_FALSE(executed.has_value());
    EXPECT_EQ(probe.physical_hash_batch_calls, 1U);
    EXPECT_EQ(probe.content_physical_hash_calls, 0U);
    EXPECT_EQ(history_put_events(*fixture, "commits"), 1U);
    EXPECT_EQ(history_put_events(*fixture, "heads"), 0U);
}

TEST(SyncContentBatchTest,
     IndividualPhysicalHashTransportFailureDoesNotFallbackToGet) {
    auto fixture = make_fixture("individual-hash-transport-failure");
    ContentWindowProbe probe;
    probe.physical_hash_transport_failure = true;
    attach_probe(*fixture, probe);
    add_content_files(*fixture, 1);

    const auto input = publication_input(*fixture);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;

    const auto executed = execute_with(*fixture, input, *result);
    ASSERT_FALSE(executed.has_value());
    EXPECT_EQ(probe.content_physical_hash_calls, 1U);
    EXPECT_EQ(probe.content_get_count, 0U);
    EXPECT_EQ(history_put_events(*fixture, "commits"), 1U);
    EXPECT_EQ(history_put_events(*fixture, "heads"), 0U);
}

TEST(SyncContentBatchTest, BulkFailureChoosesSmallestOperationIndex) {
    auto fixture = make_fixture("bulk-smallest-failure");
    ContentWindowProbe probe;
    attach_probe(*fixture, probe);
    add_content_files(*fixture, 8);

    const auto input = publication_input(*fixture);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_GE(result->plan.operations.size(), 8U);
    const auto remote_id = [&](std::size_t index) {
        return kasumi::crypto::content_identifier(
            fixture->key,
            kasumi::hash_from_hex(result->plan.operations[index].hash).value());
    };
    probe.bulk_mismatched = {remote_id(7)};
    probe.bulk_missing = {remote_id(2)};
    probe.bulk_errors = {remote_id(5)};

    const auto executed = execute_with(*fixture, input, *result);
    ASSERT_FALSE(executed.has_value());
    ASSERT_TRUE(executed.error().operation_index.has_value());
    EXPECT_EQ(*executed.error().operation_index, 2U);
    EXPECT_EQ(probe.content_physical_hash_calls, 0U);
    EXPECT_EQ(history_put_events(*fixture, "commits"), 1U);
    EXPECT_EQ(history_put_events(*fixture, "heads"), 0U);
}

TEST(SyncContentBatchTest, BulkVerificationPreservesContentDeduplication) {
    auto fixture = make_fixture("bulk-deduplication");
    ContentWindowProbe probe;
    attach_probe(*fixture, probe);
    add_repeated_content_files(*fixture, 10);

    const auto input = publication_input(*fixture);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result.has_value()) << result.error().detail;

    const auto executed = execute_with(*fixture, input, *result);
    ASSERT_TRUE(executed.has_value()) << executed.error().detail;
    EXPECT_EQ(probe.content_put_batch_count, 1U);
    EXPECT_EQ(probe.content_put_batch_objects, 4U);
    EXPECT_EQ(probe.physical_hash_batch_calls, 0U);
    EXPECT_EQ(probe.physical_hash_batch_objects, 0U);
    EXPECT_EQ(probe.content_physical_hash_calls, 4U);
}

TEST(SyncContentBatchTest, CheckpointBuilderIsPureAndSafe) {
    kasumi::transaction::Record original;
    original.plan.operations.resize(3);
    original.progress.resize(3);
    for (auto& progress : original.progress) {
        progress.state = kasumi::transaction::OperationState::Prepared;
    }

    kasumi::application::sync::mutation::StagedUploadBatch batch;
    batch.objects.push_back(
        kasumi::application::sync::mutation::StagedUploadObject{
            .operation_indices = {0U, 2U}});

    const auto candidate = kasumi::application::sync::coordinator::detail::
        make_upload_batch_checkpoint(original, batch);

    EXPECT_EQ(original.progress[0].state,
              kasumi::transaction::OperationState::Prepared);
    EXPECT_EQ(original.progress[1].state,
              kasumi::transaction::OperationState::Prepared);
    EXPECT_EQ(original.progress[2].state,
              kasumi::transaction::OperationState::Prepared);
    EXPECT_EQ(candidate.progress[0].state,
              kasumi::transaction::OperationState::Applied);
    EXPECT_EQ(candidate.progress[1].state,
              kasumi::transaction::OperationState::Prepared);
    EXPECT_EQ(candidate.progress[2].state,
              kasumi::transaction::OperationState::Applied);
}

TEST(SyncContentBatchTest, CleanupRejectsReplacedBatchRoot) {
    auto fixture = kasumi::test::make_temp_workspace("cleanup-toctou");
    const auto outside = fixture->root / "outside";
    ASSERT_TRUE(std::filesystem::create_directories(outside));
    kasumi::test::write_text(outside / "sentinel.txt", "safe");

    const auto batch_root = fixture->root / "batch";
    ASSERT_TRUE(std::filesystem::create_directories(batch_root));
    ASSERT_TRUE(std::filesystem::remove_all(batch_root));

    std::error_code error;
    std::filesystem::create_directory_symlink(outside, batch_root, error);
    if (error) {
        GTEST_SKIP() << "directory symlink unavailable: " << error.message();
    }

    kasumi::application::sync::mutation::StagedUploadBatch batch;
    batch.root = batch_root;
    const auto cleaned =
        kasumi::application::sync::mutation::cleanup_upload_batch(batch);

    ASSERT_FALSE(cleaned.has_value());
    EXPECT_EQ(
        cleaned.error().code,
        kasumi::application::sync::mutation::MutationErrorCode::UnsafePath);
    EXPECT_TRUE(std::filesystem::exists(outside / "sentinel.txt"));
}

TEST(SyncContentBatchTest, RecoveryUsesSharedContentConcurrency) {
    auto concurrency = kasumi::test::scoped_environment_variable(
        "KASUMI_CONTENT_CONCURRENCY", "2");
    auto fixture = make_fixture("batch-recovery-concurrency");
    ContentWindowProbe probe;
    probe.barrier_first_two_hashes = true;
    probe.physical_hash_batch_unsupported = true;
    attach_probe(*fixture, probe);

    std::vector<kasumi::Operation> operations;
    operations.reserve(6);
    for (std::size_t index = 0; index < 6; ++index) {
        const auto path = "repair-" + std::to_string(index) + ".txt";
        const auto contents = "repair-" + std::to_string(index);
        kasumi::test::write_text(fixture->local / path, contents);
        operations.push_back(kasumi::Operation{
            .action = kasumi::Action::Upload,
            .path = path,
            .hash = kasumi::hash_hex(kasumi::hasher::hash_string(contents)),
            .alt_path = {},
            .size = contents.size()});
    }

    const auto plan = kasumi::make_sync_plan(std::move(operations), 0);
    auto record = kasumi::application::sync::journal::create_record(
        0, 0, plan, false, std::string(64, 'a'));
    ASSERT_TRUE(record.has_value());
    record->phase = kasumi::transaction::Phase::FilesStaged;

    const auto paths =
        kasumi::application::sync::journal::make_paths(fixture->profile);
    ASSERT_TRUE(paths.has_value());
    ASSERT_TRUE(kasumi::application::sync::journal::save(
        *paths, *record, fixture->key));
    const auto transaction_root =
        fixture->profile / ".transactions" / record->operation_id;
    ASSERT_TRUE(std::filesystem::create_directories(transaction_root));

    const auto tree =
        kasumi::application::observation::collect_local_tree(fixture->local);
    ASSERT_TRUE(tree.has_value());
    ASSERT_TRUE(
        kasumi::state_storage::initialize(fixture->profile / "state.db"));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        fixture->profile / "state.db",
        {.tree = *tree,
         .height = 0,
         .commit_id = std::string(64, 'a'),
         .ciphertext_id = std::string(64, 'c')}));

    const auto recovered =
        kasumi::application::sync::coordinator::recover_if_needed(
            runtime_data(*fixture), fixture->storage, fixture->key);
    ASSERT_TRUE(recovered.has_value()) << recovered.error().detail;
    EXPECT_EQ(
        *recovered,
        kasumi::application::sync::coordinator::RecoveryResult::RolledForward);
    EXPECT_EQ(probe.content_put_batch_count, 1U);
    EXPECT_EQ(probe.content_put_batch_objects, 6U);
    EXPECT_EQ(probe.peak_active, 2U);
    EXPECT_EQ(probe.active, 0U);
    EXPECT_FALSE(
        std::filesystem::exists(fixture->profile / "transaction.bin.enc"));
    EXPECT_FALSE(std::filesystem::exists(transaction_root));
}

} // namespace
