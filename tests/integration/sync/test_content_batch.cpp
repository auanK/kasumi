#include "application/observation/scanner.hpp"
#include "application/observation/state.hpp"
#include "application/sync/coordinator.hpp"
#include "application/sync/coordinator_detail.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/mutation.hpp"
#include "application/sync/mutation_batch.hpp"
#include "application/sync/mutation_fault_test.hpp"
#include "application/sync/publication.hpp"
#include "application/sync/reobservation.hpp"
#include "application/use_cases/context.hpp"
#include "core/hasher.hpp"
#include "core/history.hpp"
#include "core/reconciliation/plan.hpp"
#include "core/transaction/types.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/pack.hpp"
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
#include <expected>
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

namespace kasumi::application::detail {
std::expected<Response, Error> run_sync(OperationContext& context);
std::expected<Response, Error> run_garbage_collect(OperationContext& context);
}

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
    std::vector<std::size_t> content_get_batches;
    std::vector<std::size_t> content_get_parallelism;
    std::size_t active = 0;
    std::size_t peak_active = 0;
    // Test-only count of physical hash calls for content objects. It does not
    // measure fallback GET/decrypt/BLAKE3 verification.
    std::size_t active_content_hashes = 0;
    std::size_t peak_active_content_hashes = 0;
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
    std::optional<std::size_t> fail_put_batch_ordinal;
    std::optional<std::size_t> fail_put_batch_after_objects;
    std::string corrupt_physical_hash_identifier;
    std::vector<std::string> bulk_mismatched;
    std::vector<std::string> bulk_missing;
    std::vector<std::string> bulk_errors;
    bool control_read_batch_supported = false;
    std::size_t control_read_batch_calls = 0;
    std::size_t max_presence_batch_seen = 0;
    std::size_t individual_presence_calls = 0;
    bool fail_control_batch_if_oversized = false;
    std::size_t max_allowed_presence_batch = 0;
    std::optional<kasumi::transport::ErrorCode> control_read_batch_failure;
    std::optional<std::size_t> fail_control_batch_on_call_ordinal;
    std::size_t active_workspaces_at_failure = 0;
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
    const bool content = identifier.find('/') == std::string_view::npos;
    const bool commit = identifier.find('/') != std::string_view::npos &&
                        identifier.find('-') == std::string_view::npos;

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
    std::optional<std::size_t> limit;
    if (probe != nullptr) {
        std::lock_guard lock(probe->mutex);
        if (!probe->fail_put_batch_ordinal ||
            *probe->fail_put_batch_ordinal == probe->content_put_batch_count) {
            limit = probe->fail_put_batch_after_objects;
        }
        ++probe->content_put_batch_count;
        probe->content_put_batch_objects += batch.identifiers.size();
    }

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

    const bool content_object = identifier.find('/') == std::string_view::npos;
    if (probe != nullptr) {
        std::unique_lock lock(probe->mutex);
        if (content_object) {
            ++probe->content_physical_hash_calls;
            ++probe->active_content_hashes;
            probe->peak_active_content_hashes =
                std::max(probe->peak_active_content_hashes,
                         probe->active_content_hashes);
        }
        ++probe->active;
        ++probe->physical_hash_started;
        probe->peak_active = std::max(probe->peak_active, probe->active);
        probe->changed.notify_all();
        if (content_object && probe->barrier_first_two_hashes &&
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
                identifier.find('/') == std::string_view::npos
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
        if (content_object) {
            --probe->active_content_hashes;
        }
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
        .matched = {},
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
    for (const auto& object : request.objects) {
        if (std::ranges::find(report.mismatched, object.identifier) ==
                report.mismatched.end() &&
            std::ranges::find(report.missing, object.identifier) ==
                report.missing.end() &&
            std::ranges::find(report.errors, object.identifier) ==
                report.errors.end()) {
            report.matched.push_back(object.identifier);
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
    if (probe == nullptr || identifier.find('/') != std::string_view::npos) {
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
    auto* state = recording_state(context);
    auto* probe = state->probe;
    if (probe != nullptr) {
        std::lock_guard lock(probe->mutex);
        ++probe->individual_presence_calls;
    }
    return kasumi::transport::presence(*state->base, id);
}

kasumi::transport::Result
recording_get_batch(void* context, const kasumi::transport::GetBatch& batch) {
    if (auto* probe = recording_state(context)->probe) {
        probe->content_get_batches.push_back(batch.identifiers.size());
        probe->content_get_parallelism.push_back(batch.max_parallel_transfers);
    }
    for (const auto& id : batch.identifiers) {
        if (auto fetched =
                recording_get(context, id, batch.destination_root / id);
            !fetched) {
            return fetched;
        }
    }
    return {};
}

kasumi::transport::ListingResult recording_list(void* context) {
    record_event(*recording_state(context), "list");
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

kasumi::transport::ControlReadBatchResponse
recording_control_read_batch(void* context,
                             const kasumi::transport::ControlReadBatchRequest& request) {
    auto* state = recording_state(context);
    auto* probe = state->probe;
    if (probe != nullptr) {
        std::lock_guard lock(probe->mutex);
        const std::size_t call_ordinal = probe->control_read_batch_calls++;
        probe->max_presence_batch_seen = std::max(
            probe->max_presence_batch_seen, request.presence_identifiers.size());
        if (!probe->control_read_batch_supported) {
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::Unsupported,
                .message = "control read batch unsupported"});
        }
        if (probe->fail_control_batch_on_call_ordinal &&
            call_ordinal == *probe->fail_control_batch_on_call_ordinal) {
            const auto trans = probe->profile / ".transactions";
            if (std::filesystem::exists(trans) && !std::filesystem::is_empty(trans)) {
                probe->active_workspaces_at_failure = 1;
            }
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::Timeout,
                .message = "injected reobservation presence timeout"});
        }
        if (probe->control_read_batch_failure) {
            return std::unexpected(kasumi::transport::Error{
                .code = *probe->control_read_batch_failure,
                .message = "injected control read batch failure"});
        }
        if (probe->fail_control_batch_if_oversized &&
            request.presence_identifiers.size() > probe->max_allowed_presence_batch) {
            return std::unexpected(kasumi::transport::Error{
                .code = kasumi::transport::ErrorCode::Timeout,
                .message = "batch request exceeds maximum batch size/deadline"});
        }
    } else {
        return std::unexpected(kasumi::transport::Error{
            .code = kasumi::transport::ErrorCode::Unsupported,
            .message = "control read batch unsupported"});
    }
    kasumi::transport::ControlReadBatchResult result;
    result.listings.reserve(request.list_prefixes.size());
    for (const auto& prefix : request.list_prefixes) {
        auto list_res = kasumi::transport::list(*state->base, prefix);
        if (!list_res) {
            return std::unexpected(list_res.error());
        }
        result.listings.push_back(std::move(*list_res));
    }
    result.presences.reserve(request.presence_identifiers.size());
    for (const auto& id : request.presence_identifiers) {
        auto pres_res = kasumi::transport::presence(*state->base, id);
        if (!pres_res) {
            return std::unexpected(pres_res.error());
        }
        result.presences.push_back(*pres_res);
    }
    return result;
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
                      .control_read_batch = recording_control_read_batch,
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

void prepare_recovery_record(const FixtureData& fixture,
                             kasumi::transaction::Record& record,
                             const kasumi::platform::Workspace& workspace) {
    for (std::size_t i = 0; i < record.plan.operations.size(); ++i) {
        const auto prepared =
            sync::mutation::prepare_operation(record.plan.operations[i],
                                              i,
                                              fixture.local,
                                              workspace,
                                              record.progress[i],
                                              record.plan.operations);
        ASSERT_TRUE(prepared) << prepared.error().detail;
        record.progress[i] = *prepared;
    }
    record.phase = kasumi::transaction::Phase::FilesStaged;
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
                   std::string_view{event}.substr(4).find('/') ==
                       std::string_view::npos;
        }));
}

std::size_t history_put_events(const FixtureData& fixture,
                               std::string_view kind) {
    return static_cast<std::size_t>(
        std::ranges::count_if(fixture.events, [&](std::string_view event) {
            if (!event.starts_with("put:")) {
                return false;
            }
            const auto target = std::string_view{event}.substr(4);
            if (kind == "commits") {
                return target.find('/') != std::string_view::npos &&
                       target.find('-') == std::string_view::npos;
            }
            if (kind == "heads") {
                return target.find('-') != std::string_view::npos &&
                       target.substr(target.rfind('/') + 1).size() == 129;
            }
            return target.find('/' + std::string{kind} + '/') !=
                       std::string_view::npos ||
                   target.starts_with(std::string{kind} + '/');
        }));
}

[[nodiscard]] ::testing::AssertionResult
reconcile_and_execute(FixtureData& fixture) {
    const auto input = publication_input(fixture);
    const auto result = kasumi::reconciliation::reconcile(input);
    if (!result.has_value()) {
        return ::testing::AssertionFailure() << result.error().detail;
    }
    const auto executed = execute_with(fixture, input, *result);
    if (!executed.has_value()) {
        return ::testing::AssertionFailure() << executed.error().detail;
    }
    return ::testing::AssertionSuccess();
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

    ASSERT_TRUE(reconcile_and_execute(*fixture));

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

    ASSERT_TRUE(reconcile_and_execute(*fixture));

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

    ASSERT_TRUE(reconcile_and_execute(*fixture));

    EXPECT_EQ(probe.physical_hash_batch_calls, 0U);
    EXPECT_EQ(probe.content_physical_hash_calls, 5U);
    EXPECT_EQ(probe.peak_active_content_hashes, 2U);
}

TEST(SyncContentBatchTest, VerificationAboveThresholdUsesBulk) {
    auto fixture = make_fixture("verification-above-threshold");
    ContentWindowProbe probe;
    attach_probe(*fixture, probe);
    add_content_files(*fixture, 7);

    ASSERT_TRUE(reconcile_and_execute(*fixture));

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
                                        return identifier.find('/') ==
                                               std::string_view::npos;
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

    ASSERT_TRUE(reconcile_and_execute(*fixture));
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

    ASSERT_TRUE(reconcile_and_execute(*fixture));
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
    auto transaction_workspace =
        kasumi::application::sync::coordinator::detail::create_transaction_workspace(
            fixture->profile, record->operation_id, fixture->key);
    ASSERT_TRUE(transaction_workspace.has_value())
        << transaction_workspace.error().detail;
    const auto transaction_root = transaction_workspace->root;

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

TEST(SyncContentBatchTest,
     LargeContentPresenceVerificationDelegatesToControlBatch) {
    auto fixture = make_fixture("large-presence-batch-bounds");
    ContentWindowProbe probe;
    probe.control_read_batch_supported = true;
    attach_probe(*fixture, probe);

    kasumi::reconciliation::Input input;
    input.storage.generation = 1;
    input.storage.logical_heads = {std::string(64, 'a')};
    input.storage.history_present = true;
    input.local_tree.rows.push_back(
        kasumi::NodeRow{.path = "", .is_directory = true});
    kasumi::finalize_snapshot(input.local_tree);

    input.storage.tree.rows.push_back(
        kasumi::NodeRow{.path = "", .is_directory = true});
    for (std::size_t index = 0; index < 300; ++index) {
        const auto path = "blob-" + std::to_string(index) + ".txt";
        const auto hash =
            kasumi::hasher::hash_string("remote-payload-" + std::to_string(index));
        input.storage.tree.rows.push_back(kasumi::NodeRow{
            .path = path,
            .hash = hash,
            .size = 14,
            .is_directory = false,
        });
    }
    kasumi::finalize_snapshot(input.storage.tree);

    auto reconciled = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(reconciled.has_value()) << reconciled.error().detail;
    ASSERT_EQ(reconciled->plan.operations.size(), 300U);

    ASSERT_TRUE(
        kasumi::state_storage::initialize(fixture->profile / "state.db"));

    const auto stabilized =
        kasumi::application::sync::coordinator::reobservation::stabilize(
            runtime_data(*fixture),
            fixture->storage,
            fixture->key,
            input,
            *reconciled);

    ASSERT_TRUE(stabilized.has_value()) << stabilized.error().detail;
    EXPECT_EQ(probe.control_read_batch_calls, 1U);
    EXPECT_EQ(probe.max_presence_batch_seen, 300U);
}

TEST(SyncContentBatchTest,
     ReobservationFallsBackWhenControlReadBatchUnsupported) {
    auto fixture = make_fixture("presence-unsupported-fallback");
    ContentWindowProbe probe;
    probe.control_read_batch_supported = false;
    attach_probe(*fixture, probe);

    kasumi::reconciliation::Input input;
    input.storage.generation = 1;
    input.storage.logical_heads = {std::string(64, 'a')};
    input.storage.history_present = true;
    input.local_tree.rows.push_back(
        kasumi::NodeRow{.path = "", .is_directory = true});
    kasumi::finalize_snapshot(input.local_tree);

    const auto hash = kasumi::hasher::hash_string("fallback-payload");
    input.storage.tree.rows.push_back(
        kasumi::NodeRow{.path = "", .is_directory = true});
    input.storage.tree.rows.push_back(kasumi::NodeRow{
        .path = "fallback.txt",
        .hash = hash,
        .size = 16,
        .is_directory = false,
    });
    kasumi::finalize_snapshot(input.storage.tree);

    auto reconciled = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(reconciled.has_value()) << reconciled.error().detail;

    ASSERT_TRUE(
        kasumi::state_storage::initialize(fixture->profile / "state.db"));

    const auto stabilized =
        kasumi::application::sync::coordinator::reobservation::stabilize(
            runtime_data(*fixture),
            fixture->storage,
            fixture->key,
            input,
            *reconciled);

    ASSERT_TRUE(stabilized.has_value()) << stabilized.error().detail;
    // Failed control_read_batch with Unsupported must cleanly fall back to individual presence
    EXPECT_EQ(probe.control_read_batch_calls, 1U);
    EXPECT_GT(probe.individual_presence_calls, 0U);
}

TEST(SyncContentBatchTest,
     ContentPresenceTransportTimeoutFailsClosedWithoutFalseAbsence) {
    auto fixture = make_fixture("presence-timeout-fail-closed");
    ContentWindowProbe probe;
    probe.control_read_batch_supported = true;
    probe.control_read_batch_failure = kasumi::transport::ErrorCode::Timeout;
    attach_probe(*fixture, probe);

    kasumi::reconciliation::Input input;
    input.storage.generation = 1;
    input.storage.logical_heads = {std::string(64, 'a')};
    input.storage.history_present = true;
    input.local_tree.rows.push_back(
        kasumi::NodeRow{.path = "", .is_directory = true});
    kasumi::finalize_snapshot(input.local_tree);

    const auto hash = kasumi::hasher::hash_string("test-payload");
    input.storage.tree.rows.push_back(
        kasumi::NodeRow{.path = "", .is_directory = true});
    input.storage.tree.rows.push_back(kasumi::NodeRow{
        .path = "file.txt",
        .hash = hash,
        .size = 12,
        .is_directory = false,
    });
    kasumi::finalize_snapshot(input.storage.tree);

    auto reconciled = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(reconciled.has_value()) << reconciled.error().detail;

    ASSERT_TRUE(
        kasumi::state_storage::initialize(fixture->profile / "state.db"));

    const auto stabilized =
        kasumi::application::sync::coordinator::reobservation::stabilize(
            runtime_data(*fixture),
            fixture->storage,
            fixture->key,
            input,
            *reconciled);

    // Fail-closed invariant: Timeout must abort observation immediately with
    // ObservationFailure, never producing a successful stable execution with
    // false absence or proceeding as if the object were missing.
    ASSERT_FALSE(stabilized.has_value());
    EXPECT_EQ(
        stabilized.error().code,
        kasumi::application::sync::coordinator::ErrorCode::ObservationFailure);
    EXPECT_NE(stabilized.error().detail.find("timeout"), std::string::npos);
}

TEST(SyncContentBatchTest,
     ContentPresenceFailureCleansUpTransactionWorkspace) {
    auto fixture = make_fixture("presence-cleanup-workspace");
    add_content_files(*fixture, 1);
    const auto pub_input = publication_input(*fixture);
    const auto pub_result = kasumi::reconciliation::reconcile(pub_input);
    ASSERT_TRUE(pub_result.has_value()) << pub_result.error().detail;
    ASSERT_TRUE(execute_with(*fixture, pub_input, *pub_result));

    fixture->profile = kasumi::test::workspace_path(
        fixture->workspace, "receiver-profile");
    fixture->local = kasumi::test::workspace_path(
        fixture->workspace, "receiver-local");
    ASSERT_TRUE(std::filesystem::create_directories(fixture->profile));
    ASSERT_TRUE(std::filesystem::create_directories(fixture->local));

    ContentWindowProbe probe;
    probe.control_read_batch_supported = true;
    // Fail on the second call (reobservation attempt loop, after staging has created a workspace)
    probe.fail_control_batch_on_call_ordinal = 1;
    attach_probe(*fixture, probe);

    auto observed =
        kasumi::application::observation::collect_reconciliation_input(
            runtime_data(*fixture), fixture->storage, fixture->key, false);
    ASSERT_TRUE(observed.has_value()) << observed.error().detail;

    auto reconciled = kasumi::reconciliation::reconcile(*observed);
    ASSERT_TRUE(reconciled.has_value()) << reconciled.error().detail;

    ASSERT_TRUE(
        kasumi::state_storage::initialize(fixture->profile / "state.db"));

    const auto stabilized =
        kasumi::application::sync::coordinator::reobservation::stabilize(
            runtime_data(*fixture),
            fixture->storage,
            fixture->key,
            *observed,
            *reconciled);

    ASSERT_FALSE(stabilized.has_value());
    // Verify that stage_attempt did indeed create a workspace before failure
    EXPECT_EQ(probe.active_workspaces_at_failure, 1U);
    // Verify that the workspace was properly cleaned up after failure
    const auto transactions_dir = fixture->profile / ".transactions";
    EXPECT_TRUE(!std::filesystem::exists(transactions_dir) ||
                std::filesystem::is_empty(transactions_dir));
}

TEST(SyncContentBatchTest, FastCdcDownloadsReuseLocalChunks) {
    auto fixture = make_fixture("fastcdc-download-delta");
    fixture->storage.storage.get_batch = recording_get_batch;
    ContentWindowProbe probe;
    attach_probe(*fixture, probe);
    const auto first_profile = fixture->profile;
    const auto first_local = fixture->local;
    const auto second_profile = fixture->workspace->root / "second-profile";
    const auto second_local = fixture->workspace->root / "second-local";
    ASSERT_TRUE(std::filesystem::create_directory(second_profile));
    ASSERT_TRUE(std::filesystem::create_directory(second_local));

    std::vector<std::byte> data(24U * 1024U * 1024U);
    std::uint32_t rng = 0x12345678U;
    for (std::size_t i = 0; i < data.size(); i += 4U) {
        rng = rng * 1664525U + 1013904223U;
        for (std::size_t j = 0; j < 4U; ++j) {
            data[i + j] = static_cast<std::byte>((rng >> (8U * j)) & 0xffU);
        }
    }
    kasumi::test::write_binary(first_local / "large.bin", data);

    const auto synchronize = [&]() -> ::testing::AssertionResult {
        kasumi::application::observation::LocalObservationSession session;
        probe.profile = fixture->profile;
        auto observed =
            kasumi::application::observation::collect_reconciliation_input(
                runtime_data(*fixture),
                fixture->storage,
                fixture->key,
                false,
                {},
                &session);
        if (!observed) {
            return ::testing::AssertionFailure() << observed.error().detail;
        }
        auto planned = kasumi::reconciliation::reconcile(*observed);
        if (!planned) {
            return ::testing::AssertionFailure() << planned.error().detail;
        }
        const auto executed = sync::coordinator::execute(runtime_data(*fixture),
                                                         fixture->storage,
                                                         fixture->key,
                                                         *observed,
                                                         *planned,
                                                         &session,
                                                         nullptr,
                                                         true);
        if (!executed) {
            return ::testing::AssertionFailure() << executed.error().detail;
        }
        return ::testing::AssertionSuccess();
    };

    ASSERT_TRUE(synchronize());
    fixture->profile = second_profile;
    fixture->local = second_local;
    probe.content_get_count = 0;
    ASSERT_TRUE(synchronize());
    const auto original =
        kasumi::crypto::pack::chunk_file_fastcdc(second_local / "large.bin");
    ASSERT_TRUE(original.has_value()) << original.error();
    kasumi::HashSet local_hashes{0, kasumi::hash_key};
    for (const auto& c : original->chunks) {
        local_hashes.insert(c.hash);
    }
    ASSERT_GE(local_hashes.size(), 8U);
    EXPECT_EQ(probe.content_get_count, local_hashes.size());
    EXPECT_EQ(kasumi::test::read_binary(second_local / "large.bin"), data);

    for (const bool reorder_only : {false, true}) {
        SCOPED_TRACE(reorder_only ? "all chunks local" : "4 KiB delta");
        fixture->profile = first_profile;
        fixture->local = first_local;
        if (reorder_only) {
            const auto cdc = kasumi::crypto::pack::chunk_file_fastcdc(
                first_local / "large.bin");
            ASSERT_TRUE(cdc.has_value()) << cdc.error();
            std::rotate(data.begin(),
                        data.begin() + cdc->chunks[0].size,
                        data.begin() + cdc->chunks[0].size +
                            cdc->chunks[1].size);
        } else {
            for (std::size_t i = 0; i < 4096U; ++i) {
                data[9U * 1024U * 1024U + i] ^= std::byte{0x5a};
            }
        }
        kasumi::test::write_binary(first_local / "large.bin", data);
        fixture->events.clear();
        ASSERT_TRUE(synchronize());
        EXPECT_NE(std::ranges::find(fixture->events, "list"),
                  fixture->events.end());

        const auto updated =
            kasumi::crypto::pack::chunk_file_fastcdc(first_local / "large.bin");
        ASSERT_TRUE(updated.has_value()) << updated.error();
        kasumi::HashSet needed_hashes{0, kasumi::hash_key};
        std::uint64_t reused_bytes = 0;
        std::uint64_t downloaded_bytes = 0;
        for (const auto& c : updated->chunks) {
            if (local_hashes.contains(c.hash)) {
                reused_bytes += c.size;
            } else if (needed_hashes.insert(c.hash).second) {
                const auto id =
                    kasumi::crypto::content_identifier(fixture->key, c.hash);
                downloaded_bytes +=
                    std::filesystem::file_size(fixture->storage_path / id);
            }
        }
        if (reorder_only) {
            ASSERT_TRUE(needed_hashes.empty());
        } else {
            ASSERT_GT(needed_hashes.size(), 0U);
            ASSERT_LT(needed_hashes.size(), updated->chunks.size());
        }

        fixture->profile = second_profile;
        fixture->local = second_local;
        probe.content_get_count = 0;
        const auto count_chunk_files = [](const std::filesystem::path& dir) {
            return std::ranges::count_if(std::filesystem::directory_iterator(dir),
                                         [](const auto& entry) {
                                             return entry.path().extension() == ".chunk";
                                         });
        };
        bool chunks_checked = false;
        bool assembled_checked = false;
        namespace fault = kasumi::application::sync::mutation_fault_test;
        fault::set_hook([&](std::string_view point, const auto& path) {
            if (point == "fastcdc_chunks_ready") {
                EXPECT_EQ(count_chunk_files(path),
                          static_cast<std::ptrdiff_t>(needed_hashes.size()));
                chunks_checked = true;
            } else if (point == "fastcdc_file_ready") {
                EXPECT_EQ(count_chunk_files(path.parent_path()), 0);
                assembled_checked = true;
            }
        });
        namespace application = kasumi::application;
        application::detail::OperationContext context{
            .operation = application::Operation::Sync,
            .runtime = runtime_data(*fixture),
            .summary = {},
            .key = fixture->key,
            .writer_identifier = {},
            .storage = std::move(fixture->storage),
            .initial_content_identifiers = {},
        };
        probe.profile = fixture->profile;
        const auto result = application::detail::run_sync(context);
        fault::clear_hook();
        fixture->storage = std::move(context.storage);
        ASSERT_TRUE(result) << result.error().detail;
        const auto* summary =
            std::get_if<application::SyncCompleted>(&result->data);
        ASSERT_NE(summary, nullptr);
        EXPECT_TRUE(chunks_checked && assembled_checked);
        EXPECT_EQ(probe.content_get_count, needed_hashes.size());
        EXPECT_EQ(summary->physical_objects_downloaded, needed_hashes.size());
        EXPECT_EQ(summary->wire_download_bytes, downloaded_bytes);
        EXPECT_GT(reused_bytes, 0U);
        EXPECT_EQ(summary->local_delta_reused_bytes, reused_bytes);
        EXPECT_EQ(kasumi::test::read_binary(second_local / "large.bin"), data);
        local_hashes.clear();
        for (const auto& c : updated->chunks) {
            local_hashes.insert(c.hash);
        }
    }
}

TEST(SyncContentBatchTest,
     FastCdcMultiWindowUploadResumesAndRepairsCorruptChunk) {
    auto fixture = make_fixture("fastcdc-multi-window");
    ContentWindowProbe probe;
    attach_probe(*fixture, probe);
    const auto first_local = fixture->local;
    const auto second_profile = fixture->workspace->root / "second-profile";
    const auto second_local = fixture->workspace->root / "second-local";
    ASSERT_TRUE(std::filesystem::create_directory(second_profile));
    ASSERT_TRUE(std::filesystem::create_directory(second_local));

    // Two 45 MiB Tier-1 files (~90 chunks total) force > 1 upload window
    // (window cap = 64 chunk items).
    auto make_random = [](std::size_t bytes, std::uint32_t seed) {
        std::vector<std::byte> buf(bytes);
        for (std::size_t i = 0; i < bytes; i += 4U) {
            seed = seed * 1664525U + 1013904223U;
            for (std::size_t j = 0; j < 4U; ++j) {
                buf[i + j] = static_cast<std::byte>((seed >> (8U * j)) & 0xffU);
            }
        }
        return buf;
    };
    const auto data_a = make_random(45U * 1024U * 1024U, 0x11112222U);
    const auto data_b = make_random(45U * 1024U * 1024U, 0x33334444U);
    kasumi::test::write_binary(first_local / "a.bin", data_a);
    kasumi::test::write_binary(first_local / "b.bin", data_b);

    namespace application = kasumi::application;
    const auto run_sync = [&]() {
        application::detail::OperationContext context{
            .operation = application::Operation::Sync,
            .runtime = runtime_data(*fixture),
            .summary = {},
            .key = fixture->key,
            .writer_identifier = {},
            .storage = std::move(fixture->storage),
            .initial_content_identifiers = {},
        };
        const auto result = application::detail::run_sync(context);
        fixture->storage = std::move(context.storage);
        return result;
    };

    ASSERT_TRUE(kasumi::state_storage::initialize(
        runtime_data(*fixture).database_path));
    probe.fail_put_batch_ordinal = 1;
    probe.fail_put_batch_after_objects = 1;
    const auto interrupted = run_sync();
    ASSERT_FALSE(interrupted);
    ASSERT_EQ(probe.content_put_batch_count, 2U);
    EXPECT_EQ(history_put_events(*fixture, "heads"), 0U);

    auto uploaded = kasumi::transport::list(fixture->base);
    ASSERT_TRUE(uploaded) << uploaded.error().message;
    std::erase_if(*uploaded, [](std::string_view id) {
        return !kasumi::hash_from_hex(id);
    });
    ASSERT_GT(uploaded->size(), 1U);
    kasumi::test::write_text(fixture->storage_path / uploaded->front(),
                             "damaged");

    kasumi::HashSet all_chunks{0, kasumi::hash_key};
    for (const auto filename : {"a.bin", "b.bin"}) {
        const auto chunks =
            kasumi::crypto::pack::chunk_file_fastcdc(first_local / filename);
        ASSERT_TRUE(chunks) << chunks.error();
        for (const auto& chunk : chunks->chunks) {
            all_chunks.insert(chunk.hash);
        }
    }
    ASSERT_LT(uploaded->size(), all_chunks.size());
    probe.fail_put_batch_after_objects.reset();
    probe.bulk_missing.clear();
    probe.content_put_batch_objects = 0;
    const auto completed = run_sync();
    ASSERT_TRUE(completed) << completed.error().detail;
    EXPECT_EQ(probe.content_put_batch_objects,
              all_chunks.size() - uploaded->size() + 1);
    const auto* summary =
        std::get_if<application::SyncCompleted>(&completed->data);
    ASSERT_NE(summary, nullptr);
    EXPECT_EQ(summary->physical_objects_uploaded,
              probe.content_put_batch_objects);
    EXPECT_GT(summary->local_delta_reused_bytes, 0U);

    fixture->profile = second_profile;
    fixture->local = second_local;
    const auto sync_once = [&]() -> ::testing::AssertionResult {
        kasumi::application::observation::LocalObservationSession session;
        probe.profile = fixture->profile;
        auto observed =
            kasumi::application::observation::collect_reconciliation_input(
                runtime_data(*fixture),
                fixture->storage,
                fixture->key,
                false,
                {},
                &session);
        if (!observed) {
            return ::testing::AssertionFailure() << observed.error().detail;
        }
        auto planned = kasumi::reconciliation::reconcile(*observed);
        if (!planned) {
            return ::testing::AssertionFailure() << planned.error().detail;
        }
        const auto executed = sync::coordinator::execute(runtime_data(*fixture),
                                                         fixture->storage,
                                                         fixture->key,
                                                         *observed,
                                                         *planned,
                                                         &session,
                                                         nullptr,
                                                         true);
        if (!executed) {
            return ::testing::AssertionFailure() << executed.error().detail;
        }
        return ::testing::AssertionSuccess();
    };

    ASSERT_TRUE(sync_once());
    EXPECT_EQ(kasumi::test::read_binary(second_local / "a.bin"), data_a);
    EXPECT_EQ(kasumi::test::read_binary(second_local / "b.bin"), data_b);
}

TEST(SyncContentBatchTest,
     FastCdcDownloadBoundsScratchAndSharesVerifiedSlices) {
    auto concurrency = kasumi::test::scoped_environment_variable(
        "KASUMI_CONTENT_CONCURRENCY", "4");
    auto fixture = make_fixture("fastcdc-download-windows");
    ContentWindowProbe probe;
    attach_probe(*fixture, probe);
    fixture->storage.storage.get_batch = recording_get_batch;

    constexpr std::size_t chunk_size = 128 * 1024U;
    constexpr std::size_t unique_chunks = 68;
    kasumi::history::ChunkedFileEntry first;
    std::string first_contents;
    const auto plaintext = fixture->workspace->root / "chunk.source";
    const auto encrypted = fixture->workspace->root / "chunk.enc";
    for (std::size_t i = 0; i < unique_chunks; ++i) {
        const std::string chunk(chunk_size, static_cast<char>(i));
        const auto hash = kasumi::hasher::hash_string(chunk);
        first.chunks.push_back({.hash = hash, .size = chunk_size});
        first_contents += chunk;
        kasumi::test::write_text(plaintext, chunk);
        ASSERT_TRUE(
            kasumi::crypto::encrypt_file(plaintext, encrypted, fixture->key));
        ASSERT_TRUE(kasumi::transport::put(
            fixture->base,
            encrypted,
            kasumi::crypto::content_identifier(fixture->key, hash)));
        ASSERT_TRUE(std::filesystem::remove(encrypted));
    }
    first.chunks.push_back(first.chunks.front());
    first_contents.append(chunk_size, '\0');
    first.file_hash = kasumi::hasher::hash_string(first_contents);
    first.file_size = first_contents.size();

    const auto second_contents =
        first_contents.substr(chunk_size, 2 * chunk_size);
    kasumi::history::ChunkedFileEntry second{
        .file_hash = kasumi::hasher::hash_string(second_contents),
        .file_size = second_contents.size(),
        .chunks = {first.chunks[1], first.chunks[2]},
    };
    kasumi::Snapshot tree{
        .rows = {
            {.path = "", .is_directory = true},
            {.path = "a.bin", .hash = first.file_hash, .size = first.file_size},
            {.path = "b.bin",
             .hash = second.file_hash,
             .size = second.file_size}}};
    kasumi::finalize_snapshot(tree);
    kasumi::history::StorageManifest manifest{
        .packed_blobs = {},
        .chunked_files = {std::move(first), std::move(second)}};
    std::ranges::sort(manifest.chunked_files,
                      {},
                      &kasumi::history::ChunkedFileEntry::file_hash);
    const auto prepared = sync::publication::prepare_commit(
        std::move(tree), false, 0, {}, 1, fixture->key, std::move(manifest));
    ASSERT_TRUE(prepared) << prepared.error().detail;
    ASSERT_TRUE(sync::publication::publish_commit(
        fixture->base, fixture->key, *prepared, fixture->workspace->root));

    auto input = kasumi::application::observation::collect_reconciliation_input(
        runtime_data(*fixture), fixture->storage, fixture->key, false);
    ASSERT_TRUE(input) << input.error().detail;
    auto result = kasumi::reconciliation::reconcile(*input);
    ASSERT_TRUE(result) << result.error().detail;
    std::size_t download_windows = 0;
    namespace fault = kasumi::application::sync::mutation_fault_test;
    fault::set_hook([&](std::string_view point, const auto& path) {
        if (point == "fastcdc_chunks_ready") {
            ++download_windows;
            EXPECT_TRUE(
                std::filesystem::is_empty(path.parent_path() / "chunk-dl"));
            const auto chunks = std::ranges::count_if(
                std::filesystem::directory_iterator(path),
                [](const auto& entry) {
                    return entry.path().extension() == ".chunk";
                });
            EXPECT_LE(chunks, 64);
        } else if (point == "fastcdc_file_ready") {
            for (const auto& entry :
                 std::filesystem::directory_iterator(path.parent_path())) {
                EXPECT_NE(entry.path().extension(), ".chunk");
            }
        }
    });
    const auto downloaded = execute_with(*fixture, *input, *result);
    fault::clear_hook();
    ASSERT_TRUE(downloaded) << downloaded.error().detail;
    EXPECT_EQ(kasumi::test::read_text(fixture->local / "a.bin"),
              first_contents);
    EXPECT_EQ(kasumi::test::read_text(fixture->local / "b.bin"),
              second_contents);
    EXPECT_EQ(probe.content_get_count, unique_chunks);
    EXPECT_GE(download_windows, 3U);
    ASSERT_GE(probe.content_get_batches.size(), 2U);
    for (const auto n : probe.content_get_batches) {
        EXPECT_LE(n, 64U);
    }
    for (const auto transfers : probe.content_get_parallelism) {
        EXPECT_EQ(transfers, 4U);
    }
}

TEST(SyncContentBatchTest, CleanupRemovesStagingWithAnUnfilledFirstSlot) {
    auto fixture = make_fixture("partial-staging-cleanup");
    sync::mutation::StagedUploadBatch batch{
        .root = fixture->workspace->root / "batch", .objects = {}};
    ASSERT_TRUE(std::filesystem::create_directory(batch.root));
    batch.objects.resize(2);
    batch.objects[1].operation_indices.push_back(3);
    kasumi::test::write_text(batch.root / "staged", "temporary data");

    const auto cleaned = sync::mutation::cleanup_upload_batch(batch);
    ASSERT_TRUE(cleaned) << cleaned.error().detail;
    EXPECT_FALSE(std::filesystem::exists(batch.root));
}

TEST(SyncContentBatchTest, ResumedPublicationVerifiesChangedLayoutAndBlocksGc) {
    auto fixture = make_fixture("resume-layout");
    add_content_files(*fixture, 3);
    const auto runtime = runtime_data(*fixture);
    const auto input = publication_input(*fixture);
    const auto result = kasumi::reconciliation::reconcile(input);
    ASSERT_TRUE(result) << result.error().detail;
    auto record = sync::journal::create_record(0, 0, result->plan, true, {});
    ASSERT_TRUE(record) << record.error();
    const auto workspace =
        sync::coordinator::detail::create_transaction_workspace(
            fixture->profile, record->operation_id, fixture->key);
    ASSERT_TRUE(workspace) << workspace.error().detail;
    ASSERT_NO_FATAL_FAILURE(
        prepare_recovery_record(*fixture, *record, *workspace));
    std::vector<std::size_t> uploads;
    for (std::size_t i = 0; i < record->plan.operations.size(); ++i) {
        if (record->plan.operations[i].action == kasumi::Action::Upload) {
            uploads.push_back(i);
        }
    }
    ASSERT_EQ(uploads.size(), 3U);
    const auto loose = sync::mutation::stage_upload_batch(
        uploads, *record, fixture->local, fixture->key, *workspace);
    ASSERT_TRUE(loose) << loose.error().detail;
    ASSERT_TRUE(
        sync::mutation::transfer_upload_batch(*loose, fixture->storage, 1));
    const auto paths = sync::journal::make_paths(fixture->profile);
    ASSERT_TRUE(paths);
    ASSERT_TRUE(sync::journal::save(*paths, *record, fixture->key));
    ASSERT_TRUE(sync::coordinator::detail::checkpoint_upload_batch(
        *paths, *record, *loose, fixture->key));
    ASSERT_TRUE(sync::mutation::cleanup_upload_batch(*loose));

    namespace app = kasumi::application;
    app::detail::OperationContext gc{
        .operation = app::Operation::GarbageCollect,
        .runtime = runtime,
        .summary = {},
        .key = fixture->key,
        .writer_identifier = {},
        .storage = std::move(fixture->storage),
        .initial_content_identifiers = {},
    };
    const auto blocked = app::detail::run_garbage_collect(gc);
    fixture->storage = std::move(gc.storage);
    ASSERT_FALSE(blocked);
    EXPECT_NE(blocked.error().detail.find("interrupted upload"),
              std::string::npos);
    for (const auto& object : loose->objects) {
        EXPECT_TRUE(
            std::filesystem::exists(fixture->storage_path / object.identifier));
    }

    const auto completed = sync::coordinator::execute(runtime,
                                                      fixture->storage,
                                                      fixture->key,
                                                      input,
                                                      *result,
                                                      nullptr,
                                                      nullptr,
                                                      true);
    ASSERT_TRUE(completed) << completed.error().detail;
    const auto saved = kasumi::state_storage::load_state(runtime.database_path);
    ASSERT_TRUE(saved && *saved);
    ASSERT_EQ((*saved)->storage_manifest.packed_blobs.size(), 3U);
    const auto pack = kasumi::crypto::pack_identifier(
        fixture->key,
        (*saved)->storage_manifest.packed_blobs.front().pack_hash);
    EXPECT_TRUE(std::filesystem::exists(fixture->storage_path / pack));
    EXPECT_FALSE(std::filesystem::exists(paths->final_path));
}

TEST(SyncContentBatchTest,
     RecoveryRepairsPinnedPacksChunksAndPartialLooseBatch) {
    auto fixture = make_fixture("manifest-repair-replay");
    const auto runtime = runtime_data(*fixture);
    using kasumi::Action;
    using kasumi::hasher::hash_string;
    const auto alpha = hash_string("alpha");
    const auto beta = hash_string("beta");
    const std::array<kasumi::crypto::pack::PackMemberDescriptor, 2> members{{
        {alpha, 5},
        {beta, 4},
    }};
    const auto pack = kasumi::crypto::pack::compute_pack_hash(members);
    ASSERT_TRUE(pack);
    const auto combined = hash_string("left-right");
    const auto left = hash_string("left-");
    const auto right = hash_string("right");
    kasumi::history::StorageManifest manifest{
        .packed_blobs = {{alpha, 5, *pack}, {beta, 4, *pack}},
        .chunked_files = {{combined, 10, {{left, 5}, {right, 5}}}},
    };
    std::ranges::sort(manifest.packed_blobs,
                      {},
                      &kasumi::history::PackedBlobEntry::blob_hash);

    kasumi::Snapshot tree{.rows = {{.path = "", .is_directory = true}}};
    std::vector<kasumi::Operation> operations;
    const auto add = [&](Action action,
                         std::string_view path,
                         std::string_view content) {
        const auto hash = hash_string(content);
        tree.rows.push_back(
            {.path = std::string{path}, .hash = hash, .size = content.size()});
        operations.push_back({.action = action,
                              .path = std::string{path},
                              .hash = kasumi::hash_hex(hash),
                              .size = content.size()});
        if (action == Action::Upload) {
            kasumi::test::write_text(fixture->local / path, content);
        }
    };
    add(Action::Upload, "alpha.txt", "alpha");
    add(Action::Upload, "beta.txt", "beta");
    add(Action::Upload, "chunked.bin", "left-right");
    add(Action::Upload, "loose-a.txt", "already uploaded");
    add(Action::Upload, "loose-b.txt", "needs repair");
    add(Action::Download, "pack-copy.txt", "alpha");
    add(Action::Download, "chunk-copy.bin", "left-right");
    kasumi::finalize_snapshot(tree);
    const auto prepared = sync::publication::prepare_commit(
        tree, false, 0, {}, 1, fixture->key, manifest);
    ASSERT_TRUE(prepared) << prepared.error().detail;
    const auto remote = sync::publication::publish_commit(
        fixture->base, fixture->key, *prepared, fixture->workspace->root);
    ASSERT_TRUE(remote) << remote.error().detail;
    const auto height = prepared->commit.height;
    ASSERT_TRUE(kasumi::state_storage::initialize(runtime.database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        runtime.database_path,
        {.tree = tree,
         .height = height,
         .commit_id = remote->head.commit_id,
         .ciphertext_id = remote->head.ciphertext_id,
         .epoch_id = {},
         .pending_materializations = {},
         .storage_manifest = manifest}));

    const auto seed = [&](std::string_view bytes) {
        const auto source = fixture->workspace->root / "seed.plain";
        const auto encrypted = fixture->workspace->root / "seed.enc";
        kasumi::test::write_text(source, bytes);
        ASSERT_TRUE(
            kasumi::crypto::encrypt_file(source, encrypted, fixture->key));
        ASSERT_TRUE(
            kasumi::transport::put(fixture->base,
                                   encrypted,
                                   kasumi::crypto::content_identifier(
                                       fixture->key, hash_string(bytes))));
        ASSERT_TRUE(std::filesystem::remove(encrypted));
    };
    ASSERT_NO_FATAL_FAILURE(seed("already uploaded"));
    ASSERT_NO_FATAL_FAILURE(seed("left-"));

    auto record = sync::journal::create_record(
        height,
        height,
        kasumi::make_sync_plan(std::move(operations), height),
        false,
        remote->head.commit_id);
    ASSERT_TRUE(record) << record.error();
    record->observed_base_id = remote->head.commit_id;
    const auto workspace =
        sync::coordinator::detail::create_transaction_workspace(
            fixture->profile, record->operation_id, fixture->key);
    ASSERT_TRUE(workspace) << workspace.error().detail;
    ASSERT_NO_FATAL_FAILURE(
        prepare_recovery_record(*fixture, *record, *workspace));
    // Older repair replay could checkpoint these uploads without restoring the
    // pack.
    for (std::size_t i = 0; i < record->plan.operations.size(); ++i) {
        const auto& op = record->plan.operations[i];
        if (op.action == Action::Upload &&
            (op.path == "alpha.txt" || op.path == "beta.txt")) {
            record->progress[i].state =
                kasumi::transaction::OperationState::Applied;
        }
    }
    const auto paths = sync::journal::make_paths(fixture->profile);
    ASSERT_TRUE(paths);
    ASSERT_TRUE(sync::journal::save(*paths, *record, fixture->key));

    const auto outcome = sync::coordinator::recover_if_needed(
        runtime, fixture->storage, fixture->key);
    ASSERT_TRUE(outcome) << outcome.error().detail;
    EXPECT_EQ(*outcome, sync::coordinator::RecoveryResult::RolledForward);
    EXPECT_EQ(kasumi::test::read_text(fixture->local / "pack-copy.txt"),
              "alpha");
    EXPECT_EQ(kasumi::test::read_text(fixture->local / "chunk-copy.bin"),
              "left-right");
    const auto path_for = [&](const kasumi::Hash& hash) {
        return fixture->storage_path /
               kasumi::crypto::content_identifier(fixture->key, hash);
    };
    EXPECT_TRUE(std::filesystem::exists(
        fixture->storage_path /
        kasumi::crypto::pack_identifier(fixture->key, *pack)));
    EXPECT_TRUE(std::filesystem::exists(path_for(right)));
    EXPECT_TRUE(std::filesystem::exists(path_for(hash_string("needs repair"))));
    EXPECT_FALSE(std::filesystem::exists(path_for(alpha)));
    EXPECT_FALSE(std::filesystem::exists(path_for(combined)));
    EXPECT_FALSE(std::filesystem::exists(paths->final_path));
}

TEST(SyncContentBatchTest,
     PackBatchRetriesOmittedObjectsAndAuthenticatesSharedMembers) {
    auto fixture = make_fixture("pack-partial-batch");
    const auto shared_path = fixture->local / "shared";
    kasumi::test::write_text(shared_path, "shared");
    const auto shared = kasumi::hasher::hash_string("shared");
    kasumi::history::StorageManifest manifest;
    std::vector<kasumi::Operation> operations;
    std::string last_identifier;
    for (std::string_view bytes : {"alpha", "bravo"}) {
        const auto source = fixture->local / bytes;
        kasumi::test::write_text(source, bytes);
        const auto hash = kasumi::hasher::hash_string(bytes);
        const std::array<kasumi::crypto::pack::PackMemberSource, 2> members{{
            {shared, 6, shared_path},
            {hash, 5, source},
        }};
        const auto encoded =
            fixture->workspace->root / (std::string{bytes} + ".pack");
        const auto pack = kasumi::crypto::pack::write_encrypted_pack(
            members, encoded, fixture->key);
        ASSERT_TRUE(pack) << pack.error();
        last_identifier =
            kasumi::crypto::pack_identifier(fixture->key, pack->pack_hash);
        ASSERT_TRUE(
            kasumi::transport::put(fixture->base, encoded, last_identifier));
        manifest.packed_blobs.push_back({hash, 5, pack->pack_hash});
        operations.push_back({.action = kasumi::Action::Download,
                              .path = std::string{bytes},
                              .hash = kasumi::hash_hex(hash),
                              .size = 5});
    }
    std::ranges::sort(manifest.packed_blobs,
                      {},
                      &kasumi::history::PackedBlobEntry::blob_hash);
    const auto record = sync::journal::create_record(
        0, 0, kasumi::make_sync_plan(std::move(operations), 0));
    ASSERT_TRUE(record);
    const auto workspace =
        sync::coordinator::detail::create_transaction_workspace(
            fixture->profile, record->operation_id, fixture->key);
    ASSERT_TRUE(workspace) << workspace.error().detail;
    fixture->storage.storage.get_batch =
        [](void*,
           const kasumi::transport::GetBatch&) -> kasumi::transport::Result {
        return {};
    };
    constexpr std::array<std::size_t, 2> indices{0, 1};
    const auto prefetch = [&] {
        return sync::coordinator::detail::prefetch_manifest_downloads(
            manifest,
            indices,
            *record,
            fixture->local,
            fixture->storage,
            fixture->key,
            *workspace,
            2);
    };
    const auto downloaded = prefetch();
    ASSERT_TRUE(downloaded) << downloaded.error().detail;
    for (const auto& op : record->plan.operations) {
        ASSERT_TRUE(downloaded->contains(op.hash));
        EXPECT_EQ(kasumi::test::read_text(downloaded->at(op.hash)),
                  op.path.string());
    }
    ASSERT_TRUE(kasumi::transport::remove(fixture->base, last_identifier));
    const auto missing = prefetch();
    ASSERT_FALSE(missing);
    EXPECT_EQ(missing.error().code,
              sync::mutation::MutationErrorCode::RemoteContentMissing);
}

} // namespace
