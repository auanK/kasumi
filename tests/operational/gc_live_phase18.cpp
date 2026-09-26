#include "application/history_storage/content_reachability.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/publication.hpp"
#include "application/history_storage/reachability.hpp"
#include "application/integrity/maintenance.hpp"
#include "core/hasher.hpp"
#include "core/history.hpp"
#include "core/node.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/key_derivation.hpp"
#include "crypto/physical_hash.hpp"
#include "platform/perf_trace.hpp"
#include "platform/random.hpp"
#include "runtime/resolver.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <nlohmann/json.hpp>
#include <reproc++/run.hpp>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifndef KASUMI_PHASE18_BUILD_COMMIT
#define KASUMI_PHASE18_BUILD_COMMIT "unknown"
#endif

namespace {

using namespace std::chrono_literals;
using kasumi::transport::Transport;
using Json = nlohmann::json;
using Clock = std::chrono::steady_clock;
namespace history_storage = kasumi::application::history_storage;

constexpr std::string_view remote_parent = "kasumi:integration-tests";
constexpr std::size_t file_bytes = 1024;
constexpr auto gc_limit = 12min;
constexpr auto round_limit = 60min;

struct Scenario {
    std::string_view name;
    std::size_t files;
    std::size_t commits;
};

constexpr Scenario scenarios[] = {
    {"smoke", 10, 1},
    {"files-200", 200, 1},
    {"files-1000", 1000, 1},
    {"history-100", 10, 100},
};

struct Traffic {
    std::size_t put_calls = 0;
    std::size_t put_batch_calls = 0;
    std::size_t put_successes = 0;
    std::size_t put_batch_successes = 0;
    std::size_t get_calls = 0;
    std::size_t barrier_get_calls = 0;
    std::size_t get_batch_calls = 0;
    std::size_t get_objects = 0;
    std::size_t commit_gets = 0;
    std::size_t marker_gets = 0;
    std::size_t epoch_gets = 0;
    std::size_t content_gets = 0;
    std::size_t other_gets = 0;
    std::size_t full_list_calls = 0;
    std::size_t prefix_list_calls = 0;
    std::size_t control_read_batches = 0;
    std::size_t control_read_prefixes = 0;
    std::size_t identifiers_returned = 0;
    std::size_t presence_calls = 0;
    std::size_t physical_hash_calls = 0;
    std::size_t barrier_physical_hash_calls = 0;
    std::size_t barrier_physical_hash_successes = 0;
    std::size_t barrier_physical_hash_errors = 0;
    std::size_t physical_hash_batch_calls = 0;
    std::size_t copy_calls = 0;
    std::size_t copy_batch_calls = 0;
    std::size_t copy_batch_inputs = 0;
    std::size_t copy_batch_concurrency = 0;
    std::uint64_t copy_batch_time_us = 0;
    std::size_t metadata_batch_calls = 0;
    std::size_t metadata_batch_objects = 0;
    std::size_t metadata_batch_concurrency = 0;
    std::uint64_t metadata_batch_time_us = 0;
    std::size_t remove_calls = 0;
    std::size_t errors = 0;
    std::vector<Json> error_events;
    std::vector<Json> operation_events;
    std::string stage = "NOT_MEASURED";
    std::uint64_t get_time_us = 0;
    std::uint64_t barrier_get_time_us = 0;
    std::uint64_t barrier_physical_hash_time_us = 0;
    std::uint64_t list_time_us = 0;
    std::uint64_t control_read_time_us = 0;
    Clock::time_point gc_started_at{};
    std::uint64_t first_quarantine_copy_us = 0;
    std::uint64_t first_content_remove_us = 0;
};

struct CounterContext {
    Transport* inner = nullptr;
    Traffic* metrics = nullptr;
    history_storage::RemoteLayout layout;
};

void destroy_counter_context(void* context) noexcept {
    delete static_cast<CounterContext*>(context);
}

CounterContext& counter_context(void* context) {
    return *static_cast<CounterContext*>(context);
}

std::string classify_identifier(const history_storage::RemoteLayout& layout,
                                std::string_view id) {
    if (id.starts_with(layout.commits_prefix)) return "commit";
    if (id.starts_with(layout.heads_prefix)) return "marker";
    if (id.starts_with(layout.epochs_prefix)) return "epoch";
    if (id.size() == 64 && std::ranges::all_of(id, [](unsigned char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        })) return "content";
    return "other";
}

void count_get(Traffic& m, const history_storage::RemoteLayout& layout,
               std::string_view id) {
    ++m.get_objects;
    const auto type = classify_identifier(layout, id);
    if (type == "commit") ++m.commit_gets;
    else if (type == "marker") ++m.marker_gets;
    else if (type == "epoch") ++m.epoch_gets;
    else if (type == "content") ++m.content_gets;
    else ++m.other_gets;
}

void record_transport_error(Traffic& metrics, std::string_view operation,
                            std::string_view identifier,
                            const kasumi::transport::Error& error) {
    ++metrics.errors;
    metrics.error_events.push_back({
        {"operation", operation},
        {"identifier", identifier.empty() ? "NOT_MEASURED" : std::string{identifier}},
        {"error_code", kasumi::transport::error_code_name(error.code)},
        {"native_code", error.native_code},
        {"message", error.message},
        {"result_ambiguous", kasumi::transport::mutation_result_is_ambiguous(error)},
        {"stage", metrics.stage},
        {"protocol_substage", "NOT_MEASURED"},
    });
}

kasumi::transport::Result count_initialize(void* context) {
    auto& c = counter_context(context);
    auto result = kasumi::transport::initialize(*c.inner);
    if (!result) record_transport_error(*c.metrics, "initialize", {}, result.error());
    return result;
}

kasumi::transport::Result count_put(
    void* context, const std::filesystem::path& source, std::string_view id) {
    auto& c = counter_context(context);
    ++c.metrics->put_calls;
    const auto start = Clock::now();
    auto result = kasumi::transport::put(*c.inner, source, id);
    if (result) ++c.metrics->put_successes;
    if (c.metrics->gc_started_at.time_since_epoch().count() != 0) {
        c.metrics->operation_events.push_back({
            {"operation", "put"}, {"identifier", id},
            {"object_class", classify_identifier(c.layout, id)},
            {"result", result ? "SUCCESS" : "ERROR"},
            {"elapsed_from_gc_start_us", std::chrono::duration_cast<std::chrono::microseconds>(start - c.metrics->gc_started_at).count()}});
    }
    if (!result) record_transport_error(*c.metrics, "put", id, result.error());
    return result;
}

kasumi::transport::Result count_put_batch(
    void* context, const kasumi::transport::PutBatch& batch) {
    auto& c = counter_context(context);
    ++c.metrics->put_batch_calls;
    auto result = kasumi::transport::put_batch(*c.inner, batch);
    if (result) ++c.metrics->put_batch_successes;
    if (!result) record_transport_error(*c.metrics, "put_batch", {}, result.error());
    return result;
}

kasumi::transport::Result count_put_files_batch(
    void* context, const kasumi::transport::PutFilesBatch& batch) {
    auto& c = counter_context(context);
    ++c.metrics->metadata_batch_calls;
    c.metrics->metadata_batch_objects += batch.items.size();
    c.metrics->metadata_batch_concurrency = batch.concurrency;
    const auto start = Clock::now();
    auto result = kasumi::transport::put_files_batch(*c.inner, batch);
    c.metrics->metadata_batch_time_us += static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            Clock::now() - start).count());
    if (c.metrics->gc_started_at.time_since_epoch().count() != 0) {
        Json destinations = Json::array();
        for (const auto& item : batch.items)
            destinations.push_back(item.destination_identifier);
        c.metrics->operation_events.push_back({
            {"operation", "put_files_batch"},
            {"object_count", batch.items.size()},
            {"destinations", std::move(destinations)},
            {"concurrency", batch.concurrency},
            {"result", result ? "SUCCESS" : "ERROR"},
            {"elapsed_from_gc_start_us",
             std::chrono::duration_cast<std::chrono::microseconds>(
                 start - c.metrics->gc_started_at).count()}});
    }
    if (!result) record_transport_error(*c.metrics, "put_files_batch", {},
                                        result.error());
    return result;
}

kasumi::transport::Result count_get(
    void* context, std::string_view id,
    const std::filesystem::path& destination) {
    auto& c = counter_context(context);
    ++c.metrics->get_calls;
    count_get(*c.metrics, c.layout, id);
    const auto start = Clock::now();
    auto result = kasumi::transport::get(*c.inner, id, destination);
    const auto elapsed = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start).count());
    c.metrics->get_time_us += elapsed;
    if (c.metrics->gc_started_at.time_since_epoch().count() != 0 &&
        id == c.layout.barrier_identifier) {
        ++c.metrics->barrier_get_calls;
        c.metrics->barrier_get_time_us += elapsed;
    }
    if (!result) record_transport_error(*c.metrics, "get", id, result.error());
    return result;
}

kasumi::transport::Result count_get_batch(
    void* context, const kasumi::transport::GetBatch& batch) {
    auto& c = counter_context(context);
    ++c.metrics->get_batch_calls;
    const auto prefix = batch.source_prefix.empty()
                            ? std::string{}
                            : batch.source_prefix + "/";
    for (const auto& id : batch.identifiers) count_get(*c.metrics, c.layout, prefix + id);
    const auto start = Clock::now();
    auto result = kasumi::transport::get_batch(*c.inner, batch);
    c.metrics->get_time_us += static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start).count());
    if (!result) record_transport_error(*c.metrics, "get_batch", {}, result.error());
    return result;
}

kasumi::transport::Result count_copy(
    void* context, std::string_view source, std::string_view destination) {
    auto& c = counter_context(context);
    ++c.metrics->copy_calls;
    const auto start = Clock::now();
    if (c.metrics->gc_started_at.time_since_epoch().count() != 0 &&
        c.metrics->first_quarantine_copy_us == 0) {
        c.metrics->first_quarantine_copy_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(start - c.metrics->gc_started_at).count());
    }
    auto result = kasumi::transport::copy(*c.inner, source, destination);
    if (c.metrics->gc_started_at.time_since_epoch().count() != 0) {
        c.metrics->operation_events.push_back({
            {"operation", "copy"}, {"source_identifier", source},
            {"destination_identifier", destination},
            {"result", result ? "SUCCESS" : "ERROR"},
            {"elapsed_from_gc_start_us", std::chrono::duration_cast<std::chrono::microseconds>(start - c.metrics->gc_started_at).count()}});
    }
    if (!result) record_transport_error(*c.metrics, "copy", destination, result.error());
    return result;
}

kasumi::transport::Result count_copy_batch(
    void* context, const kasumi::transport::CopyBatch& batch) {
    auto& c = counter_context(context);
    ++c.metrics->copy_batch_calls;
    c.metrics->copy_batch_inputs += batch.items.size();
    c.metrics->copy_batch_concurrency = batch.concurrency;
    const auto start = Clock::now();
    if (c.metrics->gc_started_at.time_since_epoch().count() != 0 &&
        c.metrics->first_quarantine_copy_us == 0) {
        c.metrics->first_quarantine_copy_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(start - c.metrics->gc_started_at).count());
    }
    auto result = kasumi::transport::copy_batch(*c.inner, batch);
    c.metrics->copy_batch_time_us += static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start).count());
    if (c.metrics->gc_started_at.time_since_epoch().count() != 0) {
        c.metrics->operation_events.push_back({
            {"operation", "copy_batch"}, {"input_count", batch.items.size()},
            {"concurrency", batch.concurrency}, {"result", result ? "SUCCESS" : "ERROR"},
            {"elapsed_from_gc_start_us", std::chrono::duration_cast<std::chrono::microseconds>(start - c.metrics->gc_started_at).count()}});
    }
    if (!result) record_transport_error(*c.metrics, "copy_batch", {}, result.error());
    return result;
}

kasumi::transport::PresenceResult count_presence(void* context,
                                                  std::string_view id) {
    auto& c = counter_context(context);
    ++c.metrics->presence_calls;
    auto result = kasumi::transport::presence(*c.inner, id);
    if (!result) record_transport_error(*c.metrics, "presence", id, result.error());
    return result;
}

void count_list_result(Traffic& metrics, std::string_view prefix,
                       const kasumi::transport::ListingResult& result) {
    if (prefix.empty()) ++metrics.full_list_calls;
    else ++metrics.prefix_list_calls;
    if (result) metrics.identifiers_returned += result->size();
    else record_transport_error(metrics, prefix.empty() ? "list" : "list_prefix",
                                prefix, result.error());
}

kasumi::transport::ListingResult count_list(void* context) {
    auto& c = counter_context(context);
    const auto start = Clock::now();
    auto result = kasumi::transport::list(*c.inner);
    c.metrics->list_time_us += static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start).count());
    count_list_result(*c.metrics, {}, result);
    return result;
}

kasumi::transport::ListingResult count_list_prefix(
    void* context, std::string_view prefix) {
    auto& c = counter_context(context);
    const auto start = Clock::now();
    auto result = kasumi::transport::list(*c.inner, prefix);
    c.metrics->list_time_us += static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start).count());
    count_list_result(*c.metrics, prefix, result);
    return result;
}

std::expected<std::string, kasumi::transport::Error> count_physical_hash(
    void* context, std::string_view id, std::string_view algorithm) {
    auto& c = counter_context(context);
    ++c.metrics->physical_hash_calls;
    const bool barrier_request =
        c.metrics->gc_started_at.time_since_epoch().count() != 0 &&
        id == c.layout.barrier_identifier;
    const auto start = Clock::now();
    auto result = kasumi::transport::physical_hash(*c.inner, id, algorithm);
    if (barrier_request) {
        ++c.metrics->barrier_physical_hash_calls;
        c.metrics->barrier_physical_hash_time_us += static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                Clock::now() - start).count());
        if (result) ++c.metrics->barrier_physical_hash_successes;
        else ++c.metrics->barrier_physical_hash_errors;
    }
    if (!result) record_transport_error(*c.metrics, "physical_hash", id, result.error());
    return result;
}

kasumi::transport::PhysicalHashBatchResult count_physical_hash_batch(
    void* context,
    const kasumi::transport::PhysicalHashBatchRequest& request) {
    auto& c = counter_context(context);
    ++c.metrics->physical_hash_batch_calls;
    auto result = kasumi::transport::physical_hash_batch(*c.inner, request);
    if (!result) record_transport_error(*c.metrics, "physical_hash_batch", {}, result.error());
    return result;
}

kasumi::transport::ControlReadBatchResponse count_control_read_batch(
    void* context, const kasumi::transport::ControlReadBatchRequest& request) {
    auto& c = counter_context(context);
    ++c.metrics->control_read_batches;
    c.metrics->control_read_prefixes += request.list_prefixes.size();
    const auto start = Clock::now();
    auto result = kasumi::transport::control_read_batch(*c.inner, request);
    c.metrics->control_read_time_us += static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start).count());
    if (!result) {
        record_transport_error(*c.metrics, "control_read_batch", {}, result.error());
        return result;
    }
    for (std::size_t i = 0; i < request.list_prefixes.size(); ++i) {
        if (i >= result->listings.size()) {
            record_transport_error(*c.metrics, "control_read_batch", {},
                                   kasumi::transport::Error{
                                       .code = kasumi::transport::ErrorCode::ProtocolFailure,
                                       .message = "missing listing in batch response",
                                   });
            break;
        }
        if (request.list_prefixes[i].empty()) ++c.metrics->full_list_calls;
        else ++c.metrics->prefix_list_calls;
        c.metrics->identifiers_returned += result->listings[i].size();
    }
    c.metrics->presence_calls += request.presence_identifiers.size();
    return result;
}

kasumi::transport::RemovalResult count_remove(void* context,
                                               std::string_view id) {
    auto& c = counter_context(context);
    ++c.metrics->remove_calls;
    const auto start = Clock::now();
    const bool content = classify_identifier(c.layout, id) == "content";
    if (content && c.metrics->gc_started_at.time_since_epoch().count() != 0 &&
        c.metrics->first_content_remove_us == 0) {
        c.metrics->first_content_remove_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(start - c.metrics->gc_started_at).count());
    }
    auto result = kasumi::transport::remove(*c.inner, id);
    if (c.metrics->gc_started_at.time_since_epoch().count() != 0) {
        c.metrics->operation_events.push_back({
            {"operation", "remove"}, {"identifier", id},
            {"object_class", classify_identifier(c.layout, id)},
            {"result", !result ? "ERROR" : *result == kasumi::transport::Removal::Removed ? "REMOVED" : "ALREADY_ABSENT"},
            {"elapsed_from_gc_start_us", std::chrono::duration_cast<std::chrono::microseconds>(start - c.metrics->gc_started_at).count()}});
    }
    if (!result) record_transport_error(*c.metrics, "remove", id, result.error());
    return result;
}

Transport make_counted_transport(Transport& inner, Traffic& metrics,
                                const history_storage::RemoteLayout& layout) {
    auto* context = new CounterContext{.inner = &inner,
                                       .metrics = &metrics,
                                       .layout = layout};
    return Transport{
        .state = kasumi::transport::TransportStateHandle{
            context, destroy_counter_context},
        .storage = kasumi::transport::StorageOperations{
            .initialize = count_initialize,
            .put = count_put,
            .put_batch = inner.storage.put_batch ? count_put_batch : nullptr,
            .put_files_batch = inner.storage.put_files_batch
                                   ? count_put_files_batch
                                   : nullptr,
            .get = count_get,
            .get_batch = inner.storage.get_batch ? count_get_batch : nullptr,
            .copy = inner.storage.copy ? count_copy : nullptr,
            .copy_batch = inner.storage.copy_batch ? count_copy_batch : nullptr,
            .presence = count_presence,
            .list = count_list,
            .list_prefix = inner.storage.list_prefix ? count_list_prefix : nullptr,
            .physical_hash = inner.storage.physical_hash ? count_physical_hash : nullptr,
            .physical_hash_batch = inner.storage.physical_hash_batch
                                       ? count_physical_hash_batch
                                       : nullptr,
            .control_read_batch = inner.storage.control_read_batch
                                      ? count_control_read_batch
                                      : nullptr,
            .remove = count_remove,
            .physical_hash_batch_min_objects =
                inner.storage.physical_hash_batch_min_objects,
        },
    };
}

kasumi::transport::Result self_test_initialize(void*) { return {}; }

kasumi::transport::Result self_test_put(void*, const std::filesystem::path&,
                                         std::string_view) {
    return {};
}

kasumi::transport::PresenceResult self_test_presence(void*, std::string_view) {
    return kasumi::transport::Presence::Present;
}

kasumi::transport::RemovalResult self_test_remove(void*, std::string_view) {
    return kasumi::transport::Removal::Removed;
}

kasumi::transport::Result self_test_get(void*, std::string_view,
                                         const std::filesystem::path&) {
    return {};
}

kasumi::transport::Result self_test_get_batch(
    void*, const kasumi::transport::GetBatch&) {
    return {};
}

kasumi::transport::Result self_test_copy_batch(
    void*, const kasumi::transport::CopyBatch&) {
    return {};
}

kasumi::transport::ListingResult self_test_list(void*) {
    return std::vector<std::string>{"one", "two"};
}

kasumi::transport::ListingResult self_test_list_prefix(void*, std::string_view) {
    return std::vector<std::string>{"three"};
}

bool counter_self_test() {
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    auto layout = history_storage::derive_remote_layout(key);
    static int fake_state = 0;
    Transport fake{
        .state = kasumi::transport::TransportStateHandle{
            &fake_state, +[](void*) noexcept {}},
        .storage = kasumi::transport::StorageOperations{
            .initialize = self_test_initialize,
            .put = self_test_put,
            .get = self_test_get,
            .get_batch = self_test_get_batch,
            .copy_batch = self_test_copy_batch,
            .presence = self_test_presence,
            .list = self_test_list,
            .list_prefix = self_test_list_prefix,
            .remove = self_test_remove,
        },
    };
    Traffic metrics;
    auto counted = make_counted_transport(fake, metrics, layout);
    if (!kasumi::transport::valid(counted)) {
        std::cerr << "counter self-test: invalid decorated transport\n";
        return false;
    }
    const auto temp = std::filesystem::temp_directory_path() / "phase18-counter-test";
    std::error_code fs_error;
    std::filesystem::create_directories(temp, fs_error);
    if (fs_error) return false;
    auto first_get = kasumi::transport::get(counted, layout.commits_prefix + "a/b", temp);
    if (!first_get) {
        std::cerr << "counter self-test first GET: "
                  << kasumi::transport::describe(first_get.error()) << '\n';
        return false;
    }
    auto source_prefix = layout.commits_prefix;
    if (!source_prefix.empty() && source_prefix.back() == '/') source_prefix.pop_back();
    kasumi::transport::GetBatch batch{
        .source_prefix = std::move(source_prefix),
        .destination_root = temp,
        .identifiers = {"c/d"},
    };
    auto batch_get = kasumi::transport::get_batch(counted, batch);
    if (!batch_get) {
        std::cerr << "counter self-test batch GET: "
                  << kasumi::transport::describe(batch_get.error()) << '\n';
        return false;
    }
    const kasumi::transport::CopyBatch copy_batch{
        .items = {{"source/a", "quarantine/a"}, {"source/b", "quarantine/b"}},
        .concurrency = 2,
    };
    auto batch_copy = kasumi::transport::copy_batch(counted, copy_batch);
    if (!batch_copy) {
        std::cerr << "counter self-test COPY batch: "
                  << kasumi::transport::describe(batch_copy.error()) << '\n';
        return false;
    }
    auto marker_get = kasumi::transport::get(counted, layout.heads_prefix + "marker", temp);
    if (!marker_get) {
        std::cerr << "counter self-test marker GET: "
                  << kasumi::transport::describe(marker_get.error()) << '\n';
        return false;
    }
    auto epoch_get = kasumi::transport::get(counted, layout.epochs_prefix + "epoch", temp);
    if (!epoch_get) {
        std::cerr << "counter self-test epoch GET: "
                  << kasumi::transport::describe(epoch_get.error()) << '\n';
        return false;
    }
    auto full = kasumi::transport::list(counted);
    auto prefix = kasumi::transport::list(counted, "prefix");
    const bool passed = full && prefix && metrics.get_calls == 3 &&
                        metrics.get_batch_calls == 1 && metrics.get_objects == 4 &&
                        metrics.copy_batch_calls == 1 && metrics.copy_batch_inputs == 2 &&
                        metrics.copy_batch_concurrency == 2 &&
                        metrics.commit_gets == 2 && metrics.marker_gets == 1 &&
                        metrics.epoch_gets == 1 && metrics.full_list_calls == 1 &&
                        metrics.prefix_list_calls == 1 && metrics.identifiers_returned == 3;
    if (!passed) {
        std::cerr << "counter self-test values: get=" << metrics.get_calls
                  << " batch=" << metrics.get_batch_calls
                  << " objects=" << metrics.get_objects
                  << " commit=" << metrics.commit_gets
                  << " marker=" << metrics.marker_gets
                  << " epoch=" << metrics.epoch_gets
                  << " full=" << metrics.full_list_calls
                  << " prefix=" << metrics.prefix_list_calls
                  << " ids=" << metrics.identifiers_returned
                  << " errors=" << metrics.errors
                  << " list_ok=" << static_cast<bool>(full && prefix) << '\n';
    }
    return passed;
}

bool write_json(const std::filesystem::path& path, const Json& json) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out << json.dump(2) << '\n';
    out.flush();
    return static_cast<bool>(out);
}

bool append_jsonl(const std::filesystem::path& path, const Json& event) {
    std::ofstream out(path, std::ios::binary | std::ios::app);
    if (!out) return false;
    out << event.dump() << '\n';
    out.flush();
    return static_cast<bool>(out);
}

std::expected<std::vector<Json>, std::string>
read_complete_jsonl(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::unexpected("could not open JSONL journal");
    const std::string bytes{std::istreambuf_iterator<char>{in}, {}};
    std::vector<Json> events;
    std::size_t begin = 0;
    while (true) {
        const auto end = bytes.find('\n', begin);
        if (end == std::string::npos) break;
        const auto line = std::string_view{bytes}.substr(begin, end - begin);
        begin = end + 1;
        if (line.empty()) continue;
        try {
            auto event = Json::parse(line);
            if (!event.is_object() || !event.contains("event")) {
                return std::unexpected("invalid event in JSONL journal");
            }
            events.push_back(std::move(event));
        } catch (const Json::exception&) {
            return std::unexpected("invalid complete record in JSONL journal");
        }
    }
    // A torn final line is not a confirmed checkpoint; remote inventory decides.
    return events;
}

bool phase19_journal_self_test() {
    const auto id = kasumi::platform::random::hex_id();
    if (!id) return false;
    const auto dir = std::filesystem::temp_directory_path() /
                     ("kasumi-phase19-journal-" + *id);
    std::error_code ec;
    if (!std::filesystem::create_directories(dir, ec) || ec) return false;
    const auto path = dir / "events.jsonl";
    const bool appended = append_jsonl(path, {{"event", "PREPARED"}, {"id", "a"}}) &&
                          append_jsonl(path, {{"event", "UPLOAD_CONFIRMED"}, {"id", "a"}});
    if (!appended) return false;
    {
        std::ofstream torn(path, std::ios::binary | std::ios::app);
        torn << R"({"event":"REMOVE_INTENT")";
        torn.flush();
        if (!torn) return false;
    }
    auto events = read_complete_jsonl(path);
    std::filesystem::remove(path, ec);
    std::filesystem::remove(dir, ec);
    return events && events->size() == 2 &&
           events->front().at("event") == "PREPARED" &&
           events->back().at("event") == "UPLOAD_CONFIRMED";
}

std::string make_payload(std::string_view run_id, std::string_view scenario,
                         std::size_t index) {
    std::string value = "Kasumi Phase 18 synthetic content " +
                        std::string{run_id} + " " + std::string{scenario} +
                        " " + std::to_string(index) + " ";
    while (value.size() < file_bytes) {
        value.push_back(static_cast<char>((index * 37 + value.size() * 19) & 0x7f));
    }
    value.resize(file_bytes);
    return value;
}

std::string pad_index(std::size_t value) {
    std::ostringstream out;
    out << std::setw(4) << std::setfill('0') << value;
    return out.str();
}

std::vector<std::string> sorted(std::vector<std::string> ids) {
    std::ranges::sort(ids);
    return ids;
}

Json string_array(const std::vector<std::string>& values) {
    Json result = Json::array();
    for (const auto& value : values) result.push_back(value);
    return result;
}

std::uint64_t elapsed_ms(Clock::time_point start) {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count());
}

std::expected<Json, std::string> remote_size(std::string_view remote) {
    std::string output;
    std::string error;
    reproc::options options;
    options.stop = reproc::stop_actions{
        {reproc::stop::wait, reproc::milliseconds(90000)},
        {reproc::stop::terminate, reproc::milliseconds(2000)},
        {reproc::stop::kill, reproc::milliseconds(2000)},
    };
    const std::vector<std::string> args{"rclone", "size", "--json",
                                        std::string{remote}};
    const auto result = reproc::run(reproc::arguments{args}, options,
                                    reproc::sink::string(output),
                                    reproc::sink::string(error));
    if (result.second || result.first != 0) {
        return std::unexpected("rclone size failed; output preserved");
    }
    try {
        return Json::parse(output);
    } catch (const std::exception&) {
        return std::unexpected("rclone size returned invalid JSON");
    }
}

std::expected<std::vector<std::string>, std::string> top_level_test_directories() {
    std::string output;
    std::string error;
    reproc::options options;
    options.stop = reproc::stop_actions{
        {reproc::stop::wait, reproc::milliseconds(90000)},
        {reproc::stop::terminate, reproc::milliseconds(2000)},
        {reproc::stop::kill, reproc::milliseconds(2000)},
    };
    const std::vector<std::string> args{
        "rclone", "lsf", std::string{remote_parent}, "--max-depth", "1",
        "--dirs-only", "--format", "p"};
    const auto result = reproc::run(reproc::arguments{args}, options,
                                    reproc::sink::string(output),
                                    reproc::sink::string(error));
    if (result.second || result.first != 0) {
        return std::unexpected("could not list the authorized test parent with rclone lsf");
    }
    std::vector<std::string> directories;
    std::istringstream lines{output};
    for (std::string line; std::getline(lines, line);) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) directories.push_back(std::move(line));
    }
    return directories;
}

std::string rclone_version() {
    std::string output;
    std::string error;
    reproc::options options;
    options.stop = reproc::stop_actions{
        {reproc::stop::wait, reproc::milliseconds(10000)},
        {reproc::stop::terminate, reproc::milliseconds(1000)},
        {reproc::stop::kill, reproc::milliseconds(1000)},
    };
    const std::vector<std::string> args{"rclone", "version"};
    const auto result = reproc::run(reproc::arguments{args}, options,
                                    reproc::sink::string(output),
                                    reproc::sink::string(error));
    if (result.second || result.first != 0) return "NOT_MEASURED";
    const auto end = output.find_first_of("\r\n");
    return output.substr(0, end);
}

std::string current_git_head() {
    std::string output;
    std::string error;
    reproc::options options;
    options.stop = reproc::stop_actions{
        {reproc::stop::wait, reproc::milliseconds(10000)},
        {reproc::stop::terminate, reproc::milliseconds(1000)},
        {reproc::stop::kill, reproc::milliseconds(1000)},
    };
    const std::vector<std::string> args{"git", "rev-parse", "--short=7", "HEAD"};
    const auto result = reproc::run(reproc::arguments{args}, options,
                                    reproc::sink::string(output),
                                    reproc::sink::string(error));
    if (result.second || result.first != 0) return {};
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r'))
        output.pop_back();
    return output;
}

std::expected<Json, std::string> rclone_remote_config_metadata() {
    std::string output;
    std::string error;
    reproc::options options;
    options.stop = reproc::stop_actions{
        {reproc::stop::wait, reproc::milliseconds(10000)},
        {reproc::stop::terminate, reproc::milliseconds(1000)},
        {reproc::stop::kill, reproc::milliseconds(1000)},
    };
    const std::vector<std::string> args{"rclone", "config", "dump"};
    const auto result = reproc::run(reproc::arguments{args}, options,
                                    reproc::sink::string(output),
                                    reproc::sink::string(error));
    if (result.second || result.first != 0) {
        return std::unexpected("rclone configuration could not be inspected");
    }
    try {
        const auto config = Json::parse(output);
        if (!config.is_object() || !config.contains("kasumi") ||
            !config.at("kasumi").is_object()) {
            return std::unexpected("rclone remote kasumi is not configured");
        }
        const auto& remote = config.at("kasumi");
        const auto string_or = [&remote](std::string_view key) {
            return remote.contains(key) && remote.at(key).is_string()
                       ? remote.at(key).get<std::string>()
                       : std::string{"NOT_SET"};
        };
        return Json{
            {"type", string_or("type")},
            {"scope", string_or("scope")},
            {"team_drive_configured", !string_or("team_drive").empty() &&
                                          string_or("team_drive") != "NOT_SET"},
            {"root_folder_id_configured", !string_or("root_folder_id").empty() &&
                                               string_or("root_folder_id") != "NOT_SET"},
        };
    } catch (const Json::exception&) {
        return std::unexpected("rclone configuration could not be parsed");
    }
}

Json traffic_json(const Traffic& traffic) {
    return Json{
        {"put_calls", traffic.put_calls},
        {"put_successes", traffic.put_successes},
        {"put_batch_calls", traffic.put_batch_calls},
        {"put_batch_successes", traffic.put_batch_successes},
        {"transport_get_calls", traffic.get_calls},
        {"barrier_get_calls", traffic.barrier_get_calls},
        {"transport_get_batch_calls", traffic.get_batch_calls},
        {"get_object_requests", traffic.get_objects},
        {"get_commit_objects", traffic.commit_gets},
        {"get_marker_objects", traffic.marker_gets},
        {"get_epoch_objects", traffic.epoch_gets},
        {"get_content_objects", traffic.content_gets},
        {"get_other_objects", traffic.other_gets},
        {"list_global_calls", traffic.full_list_calls},
        {"list_prefix_calls", traffic.prefix_list_calls},
        {"control_read_batch_calls", traffic.control_read_batches},
        {"control_read_list_prefixes", traffic.control_read_prefixes},
        {"identifiers_returned", traffic.identifiers_returned},
        {"presence_calls", traffic.presence_calls},
        {"physical_hash_calls", traffic.physical_hash_calls},
        {"barrier_physical_hash_calls", traffic.barrier_physical_hash_calls},
        {"barrier_physical_hash_successes", traffic.barrier_physical_hash_successes},
        {"barrier_physical_hash_errors", traffic.barrier_physical_hash_errors},
        {"physical_hash_batch_calls", traffic.physical_hash_batch_calls},
        {"copy_calls", traffic.copy_calls},
        {"copy_batch_calls", traffic.copy_batch_calls},
        {"copy_batch_inputs", traffic.copy_batch_inputs},
        {"copy_batch_concurrency", traffic.copy_batch_concurrency},
        {"copy_batch_time_us", traffic.copy_batch_time_us},
        {"metadata_batch_calls", traffic.metadata_batch_calls},
        {"metadata_batch_objects", traffic.metadata_batch_objects},
        {"metadata_batch_concurrency", traffic.metadata_batch_concurrency},
        {"metadata_batch_time_us", traffic.metadata_batch_time_us},
        {"remove_calls", traffic.remove_calls},
        {"transport_errors", traffic.errors},
        {"transport_error_events", traffic.error_events},
        {"operation_events", traffic.operation_events},
        {"first_quarantine_copy_us", traffic.first_quarantine_copy_us ? Json{traffic.first_quarantine_copy_us} : Json{"NOT_MEASURED"}},
        {"first_content_remove_us", traffic.first_content_remove_us ? Json{traffic.first_content_remove_us} : Json{"NOT_MEASURED"}},
        {"get_transport_time_us", traffic.get_time_us},
        {"barrier_get_transport_time_us", traffic.barrier_get_time_us},
        {"barrier_physical_hash_transport_time_us", traffic.barrier_physical_hash_time_us},
        {"list_transport_time_us", traffic.list_time_us},
        {"control_read_transport_time_us", traffic.control_read_time_us},
        {"rclone_rc_call_count", "NOT_MEASURED"},
        {"google_drive_request_count", "NOT_MEASURED"},
        {"retry_count", "NOT_MEASURED"},
        {"rate_limit_count", "NOT_MEASURED"},
    };
}

Json phase_times_json() {
    using kasumi::platform::perf_trace::get_time;
    const auto obs = [](std::string_view which) {
        const std::string prefix = "gc.snapshot." + std::string{which};
        return Json{
            {"observation_total_us", get_time(which == "first"
                                                  ? "gc reachability observation 1"
                                                  : "gc reachability observation 2")},
            {"physical_listing_us", get_time(prefix + ".physical_listing_us")},
            {"history_reconstruction_us", get_time(prefix + ".history_reconstruction_us")},
            {"build_history_inventory_us", get_time(prefix + "/rc/build_history_inventory")},
            {"load_and_auth_commits_us", get_time(prefix + "/rc/load_and_auth_commits")},
            {"inspect_markers_epochs_us", get_time(prefix + "/rc/inspect_markers_epochs")},
            {"dag_traversal_us", get_time(prefix + "/rc/dag_traversal")},
            {"history_validation_us", get_time(prefix + ".validate_history_us")},
            {"content_reachability_us", get_time(prefix + ".content_reachability_us")},
            {"candidate_selection_us", get_time(prefix + ".candidate_selection_us")},
        };
    };
    return Json{
        {"observation_1", obs("first")},
        {"observation_2", obs("second")},
        {"barrier_acquire_us", get_time("gc barrier acquire")},
        {"writer_consistency_us", get_time("gc writer consistency checks")},
        {"backend_consistency_probe_us", get_time("gc backend consistency probe")},
        {"quarantine_inventory_us", get_time("gc quarantine inventory")},
        {"quarantine_restoration_us", get_time("gc quarantine restoration")},
        {"prior_metadata_initialization_us", get_time("gc prior metadata initialization")},
        {"stable_state_comparison_us", get_time("gc stable-state comparison")},
        {"final_namespace_verification_us", get_time("gc final namespace verification")},
        {"expired_quarantine_purge_us", get_time("gc expired quarantine purge")},
        {"barrier_release_us", get_time("gc barrier release")},
        {"candidate_verified_copy_us", get_time("gc candidate verified copy")},
        {"candidate_source_physical_hash_us", get_time("verified copy source physical hash")},
        {"candidate_native_copy_us", get_time("verified copy native copy")},
        {"candidate_copy_batch_us", get_time("gc candidate copy batch")},
        {"candidate_destination_physical_hash_batch_us", get_time("gc candidate batch physical hash verification")},
        {"candidate_fallback_copy_us", "NOT_MEASURED (included in candidate_verified_copy_us)"},
        {"candidate_individual_destination_verify_us", get_time("verified copy destination physical hash")},
        {"candidate_pre_copy_barrier_verification_us", get_time("gc candidate pre-copy barrier verification")},
        {"candidate_pre_batch_copy_barrier_verification_us", get_time("gc candidate pre-batch copy barrier verification")},
        {"candidate_pre_fallback_copy_barrier_verification_us", get_time("gc candidate pre-fallback copy barrier verification")},
        {"candidate_post_copy_barrier_verification_us", get_time("gc candidate post-copy barrier verification")},
        {"candidate_pre_remove_barrier_verification_us", get_time("gc candidate pre-remove barrier verification")},
        {"barrier_ownership_verification_us", get_time("gc barrier ownership verification")},
        {"barrier_physical_hash_verification_us", get_time("gc barrier physical hash verification")},
        {"barrier_get_fallback_verification_us", get_time("gc barrier GET fallback verification")},
        {"candidate_metadata_publish_us", get_time("gc candidate metadata publish")},
        {"metadata_encode_us", get_time("gc.metadata_encode")},
        {"metadata_encryption_us", get_time("gc.metadata_encryption")},
        {"metadata_local_hash_us", get_time("gc.metadata_local_hash")},
        {"metadata_prepare_total_us", get_time("gc.metadata_prepare_duration_us")},
        {"metadata_publish_batch_us", get_time("gc.metadata_publish_batch_duration_us")},
        {"metadata_verification_batch_us", get_time("gc.metadata_verify_batch_duration_us")},
        {"candidate_remove_us", get_time("gc candidate remove")},
        {"candidate_batch_prepare_us", get_time("gc.batch_prepare_duration_us")},
        {"candidate_batch_verify_us", get_time("gc.batch_verify_duration_us")},
        {"candidate_batch_publish_remove_us", get_time("gc.batch_publish_remove_duration_us")},
        {"candidate_batch_physical_hash_verify_us", get_time("gc candidate batch physical hash verification")},
        {"internal_gc_total_us", get_time("gc.total_duration_us")},
        {"content_reference_capacity_growth_events",
         kasumi::platform::perf_trace::get_count("rc/content_reference_capacity_growth_events")},
    };
}

Json phase20_gc_counters_json() {
    using kasumi::platform::perf_trace::get_count;
    Json counters = Json::object();
    for (const auto* name : {
             "gc.candidates_selected", "gc.candidate_batches", "gc.batch_sizes",
             "gc.native_copy_attempts", "gc.native_copy_successes",
             "gc.native_copy_unsupported", "gc.fallback_copy_attempts",
             "gc.copy_batch_calls", "gc.copy_batch_inputs", "gc.copy_batch_concurrency",
             "gc.copy_batch_errors", "gc.copy_batch_ambiguous", "gc.copy_batch_unsupported",
             "gc.source_physical_hash_calls", "gc.metadata_publications",
             "gc.metadata_prepared", "gc.metadata_batch_calls",
             "gc.metadata_objects_submitted", "gc.metadata_concurrency",
             "gc.metadata_encode", "gc.metadata_encryption",
             "gc.metadata_local_hash",
             "gc.metadata_batch_publish_successes", "gc.metadata_batch_unsupported",
             "gc.metadata_publication_failures", "gc.metadata_physical_hash_calls",
             "gc.metadata_physical_hash_batch_calls",
             "gc.metadata_physical_hash_batch_unsupported", "gc.metadata_verified",
             "rclone.put_files_batch_inputs_submitted",
             "rclone.put_files_batch_concurrency_submitted",
             "rclone.put_files_batch_reported_successes",
             "rclone.put_files_batch_failures",
             "rclone.put_files_batch_transport_errors",
             "gc.pre_copy_barrier_verifications",
             "gc.pre_batch_copy_barrier_verifications",
             "gc.pre_fallback_copy_barrier_verifications",
             "gc.post_copy_barrier_verifications",
             "gc.barrier_ownership_verifications",
             "gc.barrier_physical_hash_attempts",
             "gc.barrier_physical_hash_successes",
             "gc.barrier_physical_hash_mismatches",
             "gc.barrier_physical_hash_not_found",
             "gc.barrier_physical_hash_unsupported",
             "gc.barrier_physical_hash_errors",
             "gc.barrier_physical_hash_malformed",
             "gc.barrier_get_fallbacks",
             "gc.barrier_release_owner_verifications",
             "gc.pre_remove_barrier_verifications", "content batch verify objects",
             "rclone.copy_batch_inputs_submitted", "rclone.copy_batch_concurrency_submitted",
             "rclone.copy_batch_reported_successes", "rclone.copy_batch_partial_responses",
             "gc.candidates_verified", "gc.batch_verify_attempts",
             "gc.batch_verify_supported", "gc.batch_verify_unsupported",
             "gc.batch_verify_failures", "gc.individual_destination_hash_attempts",
             "gc.source_removals", "gc.candidates_quarantined",
             "rc.http_requests_attempted", "RC idempotent read retries",
             "rc.bytes_sent_control_json", "rc.bytes_received_control_json",
             "rc.http_requests_failed"}) {
        counters[name] = get_count(name);
    }
    counters["rc_requests_by_endpoint"] = Json::object();
    for (const auto* endpoint : {"operations/check", "operations/hashsumfile",
                                  "operations/copyfile", "operations/deletefile",
                                  "operations/stat", "operations/mkdir",
                                  "operations/list", "sync/copy", "job/batch"}) {
        const auto metric = std::string{"rc.http_requests_by_endpoint."} + endpoint;
        counters["rc_requests_by_endpoint"][endpoint] = get_count(metric);
    }
    counters["drive_api_request_count"] = "NOT_MEASURED";
    counters["drive_transfer_bytes"] = "NOT_MEASURED";
    return counters;
}

void normalize_phase24_shared_batch_counters(Json& counters,
                                             std::size_t candidate_count) {
    const auto count = [&](const char* name) {
        return counters.value(name, std::uint64_t{0});
    };
    const auto shared_copy_successes =
        count("rclone.copy_batch_reported_successes");
    const auto metadata_successes =
        count("rclone.put_files_batch_reported_successes");
    const auto shared_verified_objects =
        count("content batch verify objects");
    const auto metadata_hash_batches =
        count("gc.metadata_physical_hash_batch_calls");
    const auto metadata_hash_batch_unsupported =
        count("gc.metadata_physical_hash_batch_unsupported");
    const auto successful_metadata_hash_batches =
        metadata_hash_batches >= metadata_hash_batch_unsupported
            ? metadata_hash_batches - metadata_hash_batch_unsupported
            : 0;
    const auto metadata_batch_verified = std::min<std::uint64_t>(
        candidate_count, successful_metadata_hash_batches * 8);

    counters["rclone.copy_batch_reported_successes_shared_total"] =
        shared_copy_successes;
    counters["content batch verify objects shared_total"] =
        shared_verified_objects;
    counters["rclone.copy_batch_reported_successes"] =
        shared_copy_successes >= metadata_successes
            ? shared_copy_successes - metadata_successes
            : 0;
    counters["content batch verify objects"] =
        shared_verified_objects >= metadata_batch_verified
            ? shared_verified_objects - metadata_batch_verified
            : 0;
}

bool validate_history(Transport& storage,
                      std::span<const std::uint8_t, kasumi::crypto::KEY_SIZE> key,
                      const std::vector<std::string>& identifiers,
                      const std::filesystem::path& workspace,
                      const std::string& expected_head,
                      std::size_t expected_commits,
                      std::size_t expected_files,
                      Json& validation) {
    auto history = history_storage::inventory_reachability(
        storage, key, identifiers, workspace);
    if (!history) {
        validation["history_error"] = history.error().detail;
        return false;
    }
    const bool valid = history->logical_heads.size() == 1 &&
                       history->logical_heads.front() == expected_head &&
                       history->reachable_commits.size() == expected_commits &&
                       history->missing_parent_ids.empty() &&
                       history->invalid_parent_ids.empty() &&
                       history->unknown_history_objects.empty() &&
                       std::ranges::count_if(history->markers, [](const auto& marker) {
                           return marker.state == history_storage::ReachabilityMarkerState::Valid;
                       }) == 1;
    validation["authenticated_head_matches"] = valid;
    validation["logical_heads"] = history->logical_heads;
    validation["reachable_commits"] = history->reachable_commits.size();
    validation["valid_markers"] = std::ranges::count_if(
        history->markers, [](const auto& marker) {
            return marker.state == history_storage::ReachabilityMarkerState::Valid;
        });
    validation["valid_epochs"] = history->valid_epochs.size();
    if (!valid) return false;

    auto contents = history_storage::inventory_content_reachability(
        storage, key, identifiers, *history, workspace, false);
    if (!contents) {
        validation["content_error"] = contents.error().detail;
        return false;
    }
    const bool content_valid = contents->reachable_content_ids.size() == expected_files &&
                               contents->missing_content_ids.empty() &&
                               contents->corrupt_content_ids.empty() &&
                               contents->orphan_content_ids.empty() &&
                               contents->unknown_storage_objects.empty();
    validation["reachable_content_objects"] = contents->reachable_content_ids.size();
    validation["content_objects_present"] = contents->missing_content_ids.empty();
    validation["orphan_content_objects"] = contents->orphan_content_ids.size();
    validation["content_inventory_valid"] = content_valid;
    return content_valid;
}

bool verify_content_samples(
    Transport& storage,
    std::span<const std::uint8_t, kasumi::crypto::KEY_SIZE> key,
    const std::filesystem::path& workspace,
    const std::vector<std::string>& identifiers,
    const std::map<std::string, std::pair<kasumi::Hash, std::uint64_t>>& expected,
    std::size_t& verified, std::string* failure = nullptr) {
    const auto count = std::min<std::size_t>(identifiers.size(), 10);
    for (std::size_t i = 0; i < count; ++i) {
        const auto& id = identifiers[i];
        const auto encrypted = workspace / ("verify-" + id + ".enc");
        const auto plaintext = workspace / ("verify-" + id + ".plain");
        auto downloaded = kasumi::transport::get(storage, id, encrypted);
        if (!downloaded) {
            if (failure) *failure = "GET failed for protected ID " + id + ": " +
                                    kasumi::transport::describe(downloaded.error());
            return false;
        }
        auto decrypted = kasumi::crypto::decrypt_file(
            encrypted, plaintext, key, kasumi::crypto::FilePurpose::Content);
        if (!decrypted) {
            if (failure) *failure = "decrypt failed for protected ID " + id;
            return false;
        }
        auto hash = kasumi::crypto::content::hash_file(plaintext);
        std::error_code ec;
        const auto size = std::filesystem::file_size(plaintext, ec);
        const auto found = expected.find(id);
        if (!hash || ec || found == expected.end() || *hash != found->second.first ||
            size != found->second.second ||
            kasumi::crypto::content_identifier(key, *hash) != id) {
            if (failure) *failure = "plaintext check for " + id + ": expected_hash=" +
                (found == expected.end() ? "MISSING" : kasumi::hash_hex(found->second.first)) +
                " observed_hash=" + (hash ? kasumi::hash_hex(*hash) : "HASH_ERROR") +
                " expected_size=" + (found == expected.end() ? "MISSING" : std::to_string(found->second.second)) +
                " observed_size=" + (ec ? "SIZE_ERROR" : std::to_string(size)) +
                " observed_content_id=" + (hash ? kasumi::crypto::content_identifier(key, *hash) : "HASH_ERROR");
            return false;
        }
        ++verified;
    }
    return true;
}

bool valid_run_id(std::string_view id) {
    return id.size() == 32 && std::ranges::all_of(id, [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

std::string trim_slash(std::string value) {
    while (!value.empty() && value.back() == '/') value.pop_back();
    return value;
}

bool run(const std::filesystem::path& output_path) {
    std::error_code fs_error;
    const auto output = std::filesystem::absolute(output_path, fs_error);
    if (fs_error || std::filesystem::exists(output, fs_error) || fs_error ||
        !std::filesystem::is_directory(output.parent_path(), fs_error) || fs_error) {
        std::cerr << "Output must be a new local file in an existing directory.\n";
        return false;
    }
    Json report{
        {"schema_version", 1},
        {"phase", "KASUMI_PHASE_18_REAL_RCLONE_GC"},
        {"status", "PREFLIGHT_RUNNING"},
        {"remote_parent", remote_parent},
        {"build_commit", KASUMI_PHASE18_BUILD_COMMIT},
        {"budget", {{"max_full_gc_runs", 4},
                    {"max_content_objects_per_fixture", 1500},
                    {"max_commits_per_fixture", 150},
                    {"max_gc_seconds", 720},
                    {"max_round_seconds", 3600}}},
        {"instrumentation_self_test", "NOT_RUN"},
        {"scenarios", Json::object()},
    };
    if (!write_json(output, report)) return false;
    if (!counter_self_test()) {
        report["status"] = "FAILED";
        report["instrumentation_self_test"] = "FAIL";
        write_json(output, report);
        return false;
    }
    report["instrumentation_self_test"] = "PASS";
    report["rclone_version"] = rclone_version();
    const auto env_value = [](const char* name) -> std::string {
        const auto* value = std::getenv(name);
        return value ? std::string{value} : "NOT_SET";
    };
    report["concurrency_environment"] = {
        {"KASUMI_CONTENT_CONCURRENCY", env_value("KASUMI_CONTENT_CONCURRENCY")},
        {"RCLONE_TRANSFERS", env_value("RCLONE_TRANSFERS")},
        {"RCLONE_CHECKERS", env_value("RCLONE_CHECKERS")},
    };

    auto generated = kasumi::platform::random::hex_id();
    if (!generated || !valid_run_id(*generated)) {
        report["status"] = "FAILED";
        report["preflight_error"] = "could not generate a 128-bit lowercase hex run id";
        write_json(output, report);
        return false;
    }
    const std::string run_id = *generated;
    const std::string run_dir = "gc-phase18-" + run_id;
    report["run_id"] = run_id;
    report["effective_run_root"] = std::string{remote_parent} + "/" + run_dir;
    report["started_unix_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (!write_json(output, report)) return false;

    const auto round_start = Clock::now();
    auto parent_entries = top_level_test_directories();
    if (!parent_entries) {
        report["status"] = "REMOTE_NOT_RUN";
        report["preflight_error"] = parent_entries.error();
        write_json(output, report);
        return false;
    }
    const auto matching = std::ranges::find_if(*parent_entries, [&](const auto& name) {
        return trim_slash(name) == run_dir;
    });
    report["preflight"] = {
        {"rclone_remote_type", "drive"},
        {"parent_list_succeeded", true},
        {"parent_entry_count", parent_entries->size()},
        {"parent_listing_command", "rclone lsf --max-depth 1 --dirs-only"},
        {"parent_listing_commands", 1},
        {"run_directory_absent", matching == parent_entries->end()},
        {"parent_mutated", false},
    };
    if (matching != parent_entries->end()) {
        report["status"] = "REMOTE_NOT_RUN";
        report["preflight_error"] = "generated Phase 18 run directory already exists";
        write_json(output, report);
        return false;
    }

    std::size_t gc_runs = 0;
    for (const auto& spec : scenarios) {
        if (gc_runs >= 4 || Clock::now() - round_start >= round_limit) {
            report["status"] = "INTERRUPTED_BUDGET";
            report["budget_exhausted"] = true;
            write_json(output, report);
            return false;
        }
        Json item{
            {"status", "PREPARING"},
            {"scenario", spec.name},
            {"remote_path", std::string{remote_parent} + "/" + run_dir + "/" + std::string{spec.name}},
            {"target_files", spec.files},
            {"target_commits", spec.commits},
            {"candidate_expected", 0},
            {"manifest_complete", false},
            {"manifest", Json::array()},
        };
        report["current_scenario"] = spec.name;
        report["scenarios"][spec.name] = item;
        if (!write_json(output, report)) return false;

        const std::string remote_path = item["remote_path"].get<std::string>();
        auto storage = kasumi::transport::open_transport(remote_path);
        if (!storage || !kasumi::transport::initialize(*storage)) {
            item["status"] = "REMOTE_NOT_RUN";
            item["error"] = "could not initialize the new scenario namespace";
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED";
            write_json(output, report);
            return false;
        }
        auto initial = kasumi::transport::list(*storage);
        if (initial && !initial->empty()) {
            item["status"] = "REFUSED_EXISTING_OBJECTS";
            item["error"] = "scenario namespace is not empty";
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED";
            write_json(output, report);
            return false;
        }
        if (!initial && initial.error().code != kasumi::transport::ErrorCode::StorageNotFound) {
            item["status"] = "REMOTE_NOT_RUN";
            item["error"] = "scenario namespace absence could not be established";
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED";
            write_json(output, report);
            return false;
        }

        const auto local_root = output.parent_path() / ("phase18-" + run_id) /
                                std::string{spec.name};
        std::filesystem::create_directories(local_root, fs_error);
        if (fs_error) {
            item["status"] = "FAILED";
            item["error"] = "could not create local scenario workspace";
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED";
            write_json(output, report);
            return false;
        }
        const auto prep_start = Clock::now();
        std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
        for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(i + 1);
        const auto layout = history_storage::derive_remote_layout(key);
        std::vector<std::string> manifest;
        std::vector<std::string> content_ids;
        std::map<std::string, std::pair<kasumi::Hash, std::uint64_t>> content_info;
        kasumi::Snapshot tree;
        tree.rows.push_back(kasumi::NodeRow{.path = "", .hash = {}, .size = 0,
                                             .mtime = {}, .is_directory = true});
        std::uint64_t plaintext_bytes = 0;
        std::uint64_t local_ciphertext_bytes = 0;
        bool prep_ok = true;
        bool budget_exhausted = false;
        for (std::size_t i = 0; i < spec.files; ++i) {
            if (Clock::now() - round_start >= round_limit) {
                prep_ok = false;
                budget_exhausted = true;
                break;
            }
            const auto payload = make_payload(run_id, spec.name, i);
            const auto plain = local_root / ("content-" + pad_index(i) + ".plain");
            const auto encrypted = local_root / ("content-" + pad_index(i) + ".enc");
            {
                std::ofstream file(plain, std::ios::binary | std::ios::trunc);
                file.write(payload.data(), static_cast<std::streamsize>(payload.size()));
                if (!file) { prep_ok = false; break; }
            }
            auto encryption = kasumi::crypto::encrypt_file_with_hashes(
                plain, encrypted, key, kasumi::crypto::FilePurpose::Content);
            if (!encryption) { prep_ok = false; break; }
            const auto id = kasumi::crypto::content_identifier(key, encryption->plaintext_hash);
            if (content_info.contains(id)) { prep_ok = false; break; }
            auto put = kasumi::transport::put(*storage, encrypted, id);
            if (!put) {
                item["ambiguous_put"] = kasumi::transport::mutation_result_is_ambiguous(put.error());
                item["failed_object_id"] = id;
                item["error"] = kasumi::transport::describe(put.error());
                prep_ok = false;
                break;
            }
            manifest.push_back(id);
            content_ids.push_back(id);
            content_info.emplace(id, std::pair{encryption->plaintext_hash,
                                                encryption->plaintext_size});
            tree.rows.push_back(kasumi::NodeRow{
                .path = "file_" + pad_index(i) + ".bin",
                .hash = encryption->plaintext_hash,
                .size = encryption->plaintext_size,
                .mtime = {},
                .is_directory = false,
            });
            plaintext_bytes += payload.size();
            const auto ciphertext_bytes = std::filesystem::file_size(encrypted, fs_error);
            if (fs_error) { prep_ok = false; break; }
            local_ciphertext_bytes += ciphertext_bytes;
            if (i % 25 == 24) {
                item["manifest"] = string_array(manifest);
                report["scenarios"][spec.name] = item;
                if (!write_json(output, report)) return false;
            }
        }
        kasumi::finalize_snapshot(tree);
        if (!prep_ok) {
            item["status"] = budget_exhausted ? "ROUND_LIMIT_PRESERVED"
                                                : "PREPARATION_FAILED_PRESERVED";
            item["manifest"] = string_array(manifest);
            item["manifest_complete"] = false;
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED_PRESERVED";
            write_json(output, report);
            return false;
        }

        kasumi::application::history_storage::HeadReference head;
        std::string previous;
        const auto commit_start = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        for (std::size_t i = 0; i < spec.commits; ++i) {
            if (Clock::now() - round_start >= round_limit) {
                prep_ok = false;
                budget_exhausted = true;
                break;
            }
            std::vector<std::string> parents;
            if (i > 0) parents.push_back(previous);
            auto commit = kasumi::history::make_commit(
                i, std::move(parents), tree, commit_start + static_cast<std::int64_t>(i));
            if (!commit) {
                item["error"] = "production commit construction failed";
                prep_ok = false;
                break;
            }
            auto published = history_storage::publish_commit_object_scoped(
                *storage, layout, key, *commit, local_root);
            if (!published) {
                item["error"] = published.error().detail;
                prep_ok = false;
                break;
            }
            head = published->head;
            previous = head.commit_id;
            manifest.push_back(history_storage::commit_object(layout, head));
            if (i % 25 == 24) {
                item["manifest"] = string_array(manifest);
                report["scenarios"][spec.name] = item;
                if (!write_json(output, report)) return false;
            }
        }
        if (!prep_ok) {
            item["status"] = budget_exhausted ? "ROUND_LIMIT_PRESERVED"
                                                : "PREPARATION_FAILED_PRESERVED";
            item["manifest"] = string_array(manifest);
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED_PRESERVED";
            write_json(output, report);
            return false;
        }
        auto marker = history_storage::publish_head_marker_scoped(
            *storage, layout, head, local_root);
        if (!marker) {
            item["status"] = "PREPARATION_FAILED_PRESERVED";
            item["error"] = marker.error().detail;
            item["manifest"] = string_array(manifest);
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED_PRESERVED";
            write_json(output, report);
            return false;
        }
        manifest.push_back(marker->marker_id);
        const auto prep_ms = elapsed_ms(prep_start);

        auto listing = kasumi::transport::list(*storage);
        auto expected_ids = sorted(manifest);
        if (!listing || sorted(*listing) != expected_ids ||
            expected_ids.size() != spec.files + spec.commits + 1) {
            item["status"] = "PRE_GC_INVENTORY_MISMATCH_PRESERVED";
            item["manifest"] = string_array(expected_ids);
            if (listing) item["observed_inventory"] = string_array(sorted(*listing));
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED_PRESERVED";
            write_json(output, report);
            return false;
        }
        if (Clock::now() - round_start >= round_limit) {
            item["status"] = "ROUND_LIMIT_PRESERVED";
            item["manifest"] = string_array(expected_ids);
            item["manifest_complete"] = true;
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED_PRESERVED";
            write_json(output, report);
            return false;
        }
        const auto verify_start = Clock::now();
        Json pre_validation = Json::object();
        if (!validate_history(*storage, key, expected_ids, local_root,
                              head.commit_id, spec.commits, spec.files,
                              pre_validation)) {
            item["status"] = "PRE_GC_VALIDATION_FAILED_PRESERVED";
            item["pre_gc_validation"] = pre_validation;
            item["manifest"] = string_array(expected_ids);
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED_PRESERVED";
            write_json(output, report);
            return false;
        }
        const auto validation_ms = elapsed_ms(verify_start);
        item["fixture_preparation_ms"] = prep_ms;
        item["pre_gc_validation_ms"] = validation_ms;
        item["manifest"] = string_array(expected_ids);
        item["manifest_complete"] = true;
        item["F"] = spec.files;
        item["N_content_objects"] = content_ids.size();
        item["P_physical_commits"] = spec.commits;
        item["R_protected_commits"] = spec.commits;
        item["C_expected_candidates"] = 0;
        item["E_epochs"] = 0;
        item["A_anchors"] = 0;
        item["total_physical_objects"] = expected_ids.size();
        item["plaintext_content_bytes"] = plaintext_bytes;
        item["local_encrypted_content_bytes"] = local_ciphertext_bytes;
        item["pre_gc_validation"] = pre_validation;
        report["scenarios"][spec.name] = item;
        if (!write_json(output, report)) return false;

        Traffic traffic;
        auto counted = make_counted_transport(*storage, traffic, layout);
        kasumi::runtime::RuntimeData runtime{
            .local_dir = local_root / "runtime-local",
            .database_path = local_root / "runtime-profile" / "db.sqlite",
            .key_path = local_root / "runtime-profile" / "key.bin",
            .storage_location = remote_path,
        };
        std::filesystem::create_directories(runtime.local_dir, fs_error);
        std::filesystem::create_directories(runtime.database_path.parent_path(), fs_error);
        if (fs_error) {
            item["status"] = "FAILED_PRESERVED";
            item["error"] = "could not create isolated local GC runtime paths";
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED_PRESERVED";
            write_json(output, report);
            return false;
        }

        item["status"] = "GC_RUNNING";
        item["gc_started_unix_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        report["scenarios"][spec.name] = item;
        report["status"] = "RUNNING";
        if (!write_json(output, report)) return false;
        if (Clock::now() - round_start >= round_limit) {
            item["status"] = "ROUND_LIMIT_PRESERVED";
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED_PRESERVED";
            write_json(output, report);
            return false;
        }
        kasumi::platform::perf_trace::force_enable(true);
        kasumi::platform::perf_trace::reset();
        const auto gc_start = Clock::now();
        ++gc_runs;
        auto collected = kasumi::application::integrity::garbage_collect(runtime, counted, key);
        const auto gc_end = Clock::now();
        const auto gc_phase_times = phase_times_json();
        kasumi::platform::perf_trace::force_enable(false);
        const auto gc_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(gc_end - gc_start).count());
        item["gc_wall_us"] = gc_us;
        item["gc_phase_times"] = gc_phase_times;
        item["gc_transport"] = traffic_json(traffic);
        item["gc_runs_used"] = gc_runs;
        item["status"] = "GC_COMPLETE";
        report["scenarios"][spec.name] = item;
        if (!write_json(output, report)) return false;
        if (!collected) {
            item["status"] = "GC_FAILED_PRESERVED";
            item["gc_error"] = kasumi::application::integrity::describe(collected.error());
            item["manifest"] = string_array(expected_ids);
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED_PRESERVED";
            write_json(output, report);
            return false;
        }
        item["candidate_objects"] = collected->candidate_objects;
        item["quarantined_objects"] = collected->quarantined_objects;
        item["restored_objects"] = collected->restored_objects;
        item["purged_objects"] = collected->purged_objects;
        if (gc_us > static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::microseconds>(gc_limit).count()) ||
            Clock::now() - round_start > round_limit ||
            collected->candidate_objects != 0 || collected->quarantined_objects != 0 ||
            collected->restored_objects != 0 || collected->purged_objects != 0) {
            item["status"] = "GC_LIMIT_OR_INVARIANT_FAILED_PRESERVED";
            item["manifest"] = string_array(expected_ids);
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED_PRESERVED";
            write_json(output, report);
            return false;
        }

        const auto post_validation_start = Clock::now();
        auto post_listing = kasumi::transport::list(*storage);
        if (!post_listing || sorted(*post_listing) != expected_ids) {
            item["status"] = "POST_GC_INVENTORY_MISMATCH_PRESERVED";
            if (post_listing) item["post_gc_inventory"] = string_array(sorted(*post_listing));
            item["manifest"] = string_array(expected_ids);
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED_PRESERVED";
            write_json(output, report);
            return false;
        }
        Json post_validation = Json::object();
        if (!validate_history(*storage, key, expected_ids, local_root,
                              head.commit_id, spec.commits, spec.files,
                              post_validation)) {
            item["status"] = "POST_GC_VALIDATION_FAILED_PRESERVED";
            item["post_gc_validation"] = post_validation;
            item["manifest"] = string_array(expected_ids);
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED_PRESERVED";
            write_json(output, report);
            return false;
        }
        std::size_t samples_verified = 0;
        if (!verify_content_samples(*storage, key, local_root, content_ids,
                                    content_info, samples_verified)) {
            item["status"] = "POST_GC_CONTENT_SAMPLE_FAILED_PRESERVED";
            item["manifest"] = string_array(expected_ids);
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED_PRESERVED";
            write_json(output, report);
            return false;
        }
        item["post_gc_validation"] = post_validation;
        item["post_gc_authenticated_content_samples"] = samples_verified;
        item["post_gc_validation_ms"] = elapsed_ms(post_validation_start);
        item["integrity"] = "PASS";

        if (Clock::now() - round_start >= round_limit) {
            item["status"] = "ROUND_LIMIT_PRESERVED";
            item["manifest"] = string_array(expected_ids);
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED_PRESERVED";
            write_json(output, report);
            return false;
        }
        const auto size_start = Clock::now();
        auto size = remote_size(remote_path);
        if (!size || !size->contains("count") || !size->contains("bytes")) {
            item["status"] = "REMOTE_SIZE_NOT_MEASURED_PRESERVED";
            item["remote_size_error"] = size ? "missing count/bytes fields" : size.error();
            item["manifest"] = string_array(expected_ids);
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED_PRESERVED";
            write_json(output, report);
            return false;
        }
        item["remote_size_objects"] = (*size)["count"];
        item["remote_size_bytes"] = (*size)["bytes"];
        item["remote_size_elapsed_ms"] = elapsed_ms(size_start);
        item["rclone_size_cli_calls"] = 1;
        if ((*size)["count"].get<std::size_t>() != expected_ids.size()) {
            item["status"] = "REMOTE_SIZE_COUNT_MISMATCH_PRESERVED";
            item["manifest"] = string_array(expected_ids);
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED_PRESERVED";
            write_json(output, report);
            return false;
        }
        if (Clock::now() - round_start >= round_limit) {
            item["status"] = "ROUND_LIMIT_PRESERVED";
            item["manifest"] = string_array(expected_ids);
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED_PRESERVED";
            write_json(output, report);
            return false;
        }

        // Delete only IDs in the completed manifest after an exact inventory match.
        item["status"] = "CLEANING_MANIFEST";
        report["scenarios"][spec.name] = item;
        if (!write_json(output, report)) return false;
        const auto cleanup_start = Clock::now();
        std::vector<std::string> removed;
        for (std::size_t i = 0; i < expected_ids.size(); ++i) {
            if (Clock::now() - round_start >= round_limit) {
                item["status"] = "CLEANUP_STOPPED_BUDGET_PRESERVED";
                item["removed_manifest_ids"] = string_array(removed);
                item["manifest"] = string_array(expected_ids);
                report["scenarios"][spec.name] = item;
                report["status"] = "STOPPED_PRESERVED";
                write_json(output, report);
                return false;
            }
            auto result = kasumi::transport::remove(*storage, expected_ids[i]);
            if (!result || *result != kasumi::transport::Removal::Removed) {
                item["status"] = "CLEANUP_STOPPED_PRESERVED";
                item["cleanup_failed_id"] = expected_ids[i];
                item["cleanup_ambiguous"] = !result &&
                    kasumi::transport::mutation_result_is_ambiguous(result.error());
                item["removed_manifest_ids"] = string_array(removed);
                item["manifest"] = string_array(expected_ids);
                report["scenarios"][spec.name] = item;
                report["status"] = "STOPPED_PRESERVED";
                write_json(output, report);
                return false;
            }
            removed.push_back(expected_ids[i]);
            if (i % 25 == 24) {
                item["removed_manifest_ids"] = string_array(removed);
                report["scenarios"][spec.name] = item;
                if (!write_json(output, report)) return false;
            }
        }
        auto empty = kasumi::transport::list(*storage);
        if (empty && !empty->empty()) {
            item["status"] = "CLEANUP_INVENTORY_REMAINS_PRESERVED";
            item["remaining_objects"] = string_array(sorted(*empty));
            item["manifest"] = string_array(expected_ids);
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED_PRESERVED";
            write_json(output, report);
            return false;
        }
        if (!empty && empty.error().code != kasumi::transport::ErrorCode::StorageNotFound) {
            item["status"] = "CLEANUP_VERIFY_FAILED_PRESERVED";
            item["manifest"] = string_array(expected_ids);
            report["scenarios"][spec.name] = item;
            report["status"] = "STOPPED_PRESERVED";
            write_json(output, report);
            return false;
        }
        item["status"] = "PASS_CLEANED";
        item["manifest_cleanup_ms"] = elapsed_ms(cleanup_start);
        item["objects_removed"] = removed.size();
        item["objects_remaining"] = 0;
        item["empty_remote_folders_may_remain"] = true;
        item["manifest"] = string_array(expected_ids);
        report["scenarios"][spec.name] = item;
        report["status"] = "RUNNING";
        if (!write_json(output, report)) return false;
    }
    report["status"] = "PASS";
    report["full_gc_runs"] = gc_runs;
    report["elapsed_round_ms"] = elapsed_ms(round_start);
    report["remote_object_directories_recursively_removed"] = false;
    return write_json(output, report);
}

bool run_phase19_s2(const std::filesystem::path& output_path) {
    std::error_code ec;
    const auto output = std::filesystem::absolute(output_path, ec);
    if (ec || std::filesystem::exists(output, ec) || ec ||
        !std::filesystem::is_directory(output.parent_path(), ec) || ec) {
        std::cerr << "Output must be a new local file in an existing directory.\n";
        return false;
    }

    const auto generated = kasumi::platform::random::hex_id();
    if (!generated || !valid_run_id(*generated)) return false;
    const auto run_id = *generated;
    const auto run_dir = "gc-phase19-s2-" + run_id;
    const auto remote_path = std::string{remote_parent} + "/" + run_dir;
    const auto journal = std::filesystem::path{output.string() + ".manifest.jsonl"};
    const auto sidecar = std::filesystem::path{output.string() + ".status.json"};
    const auto local_root = output.parent_path() / ("phase19-s2-" + run_id);
    const auto started = Clock::now();
    Json report{
        {"schema_version", 1},
        {"phase", "KASUMI_PHASE_19_REAL_RCLONE_GC_S2"},
        {"status", "PREFLIGHT_RUNNING"},
        {"run_id", run_id},
        {"remote_parent", remote_parent},
        {"remote_path", remote_path},
        {"build_commit", KASUMI_PHASE18_BUILD_COMMIT},
        {"parameters", {{"F_target", 1000}, {"N_target", 1000},
                         {"P_target", 1}, {"R_target", 1}, {"C_target", 0}}},
        {"journal_path", journal.string()},
        {"local_workspace", local_root.string()},
        {"limits", {{"fixture_count", 1}, {"full_gc_count", 1},
                     {"preparation_wall_limit", "NONE"}}},
        {"phase18_s1_baseline", {
            {"F", 200}, {"N_content_objects", 200}, {"P_physical_commits", 1},
            {"R_protected_commits", 1}, {"C_candidates", 0},
            {"total_physical_objects", 202}, {"remote_bytes", 233443},
            {"gc_wall_us", 24265814},
            {"observation_1_us", 3908191}, {"observation_2_us", 3836164},
            {"physical_listing_us", {1574354, 1620671}},
            {"load_and_auth_commits_us", {1242625, 1011072}},
            {"barrier_acquire_us", 3694265}, {"writer_consistency_us", 2872662},
            {"backend_consistency_probe_us", 4671113},
            {"final_namespace_verification_us", 1564825},
            {"list_global_calls", 4}, {"list_prefix_calls", 6},
            {"list_transport_time_us", 8102793}, {"identifiers_returned", 814},
            {"get_objects", 7}, {"get_commits", 2}, {"get_markers", 2},
            {"get_epochs", 0}, {"get_contents", 0},
            {"remove_calls", 2}, {"transport_errors", 2}}},
        {"rclone_version", rclone_version()},
    };
    const auto checkpoint = [&](std::string_view stage, std::string_view status) {
        report["status"] = status;
        report["last_confirmed_stage"] = stage;
        report["updated_unix_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return write_json(output, report) &&
               write_json(sidecar, Json{{"status", status}, {"last_confirmed_stage", stage},
                                        {"remote_path", remote_path},
                                        {"interruption_reason_if_unfinished", "NOT_MEASURED"},
                                        {"resume_rule", "verify exact remote inventory and hashes before any upload"},
                                        {"updated_unix_ms", report["updated_unix_ms"]}});
    };
    const auto event = [&](std::string_view name, Json details = Json::object()) {
        details["event"] = name;
        details["run_id"] = run_id;
        details["unix_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return append_jsonl(journal, details);
    };
    const auto fail = [&](std::string_view status, std::string_view stage,
                          std::string_view reason) {
        report["failure"] = reason;
        report["ended_elapsed_ms"] = elapsed_ms(started);
        checkpoint(stage, status);
        std::cerr << status << ": " << reason << '\n';
        return false;
    };

    if (!write_json(output, report) ||
        !write_json(sidecar, Json{{"status", "PREFLIGHT_RUNNING"},
                                  {"last_confirmed_stage", "LOCAL_MANIFEST_CREATED"},
                                  {"remote_path", remote_path},
                                  {"interruption_reason_if_unfinished", "NOT_MEASURED"},
                                  {"resume_rule", "verify exact remote inventory and hashes before any upload"}}) ||
        !event("RUN_CREATED", {{"remote_path", remote_path}, {"F", 1000},
                               {"N", 1000}, {"P", 1}, {"R", 1}, {"C", 0}})) {
        return false;
    }
    if (!phase19_journal_self_test()) {
        return fail("FAILED", "LOCAL_JOURNAL_SELF_TEST", "append-only journal self-test failed");
    }
    report["journal_self_test"] = "PASS";
    auto remote_metadata = rclone_remote_config_metadata();
    if (!remote_metadata) {
        return fail("REMOTE_NOT_RUN", "PREFLIGHT", remote_metadata.error());
    }
    report["rclone_remote_metadata"] = *remote_metadata;
    if (!remote_metadata->contains("type") || remote_metadata->at("type") != "drive") {
        return fail("REMOTE_NOT_RUN", "PREFLIGHT", "kasumi remote is not confirmed as Google Drive");
    }
    const auto parent_entries = top_level_test_directories();
    if (!parent_entries) return fail("REMOTE_NOT_RUN", "PREFLIGHT", parent_entries.error());
    const auto existing = std::ranges::find_if(*parent_entries, [&](const auto& entry) {
        return trim_slash(entry) == run_dir;
    });
    report["preflight"] = {
        {"remote_type", "drive"}, {"remote_path", remote_path},
        {"parent_listing_succeeded", true}, {"parent_entry_count", parent_entries->size()},
        {"parent_mutated", false}, {"run_directory_absent", existing == parent_entries->end()},
        {"parent_listing_command", "rclone lsf --max-depth 1 --dirs-only"},
    };
    if (existing != parent_entries->end()) {
        return fail("REMOTE_NOT_RUN", "PREFLIGHT", "unique run directory already exists");
    }
    if (!checkpoint("REMOTE_PREFLIGHT_CONFIRMED", "PREPARING")) return false;

    auto opened = kasumi::transport::open_transport(remote_path);
    if (!opened || !kasumi::transport::initialize(*opened)) {
        return fail("REMOTE_NOT_RUN", "PREFLIGHT", "could not initialize exact fixture path");
    }
    auto& storage = *opened;
    if (!storage.storage.put_batch || !storage.storage.physical_hash_batch) {
        return fail("REMOTE_NOT_RUN", "PREFLIGHT", "remote lacks safe batch upload/hash verification");
    }
    const auto initial = kasumi::transport::list(storage);
    if (!initial && initial.error().code != kasumi::transport::ErrorCode::StorageNotFound) {
        return fail("REMOTE_NOT_RUN", "PREFLIGHT", "fixture emptiness could not be established");
    }
    if (initial && !initial->empty()) {
        report["unexpected_initial_inventory"] = string_array(sorted(*initial));
        return fail("REMOTE_NOT_RUN", "PREFLIGHT", "new fixture path is not empty");
    }
    if (!event("REMOTE_NAMESPACE_CONFIRMED_EMPTY", {{"remote_path", remote_path}})) return false;

    std::filesystem::create_directories(local_root, ec);
    if (ec) return fail("FAILED", "LOCAL_SETUP", "could not create isolated local workspace");
    const auto prep_start = Clock::now();
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(i + 1);
    const auto layout = history_storage::derive_remote_layout(key);
    std::vector<std::string> content_ids;
    std::vector<std::string> manifest;
    std::map<std::string, std::pair<kasumi::Hash, std::uint64_t>> content_info;
    kasumi::Snapshot tree;
    tree.rows.push_back(kasumi::NodeRow{.path = "", .hash = {}, .size = 0,
                                        .mtime = {}, .is_directory = true});
    std::uint64_t plaintext_bytes = 0;
    std::uint64_t ciphertext_bytes = 0;
    constexpr std::size_t batch_size = 25;
    constexpr std::size_t transfers = 4;
    std::vector<std::string> pending_ids;
    std::vector<kasumi::transport::PhysicalHashExpectation> pending_hashes;
    std::vector<std::string> uploaded_ids;
    std::size_t batch_number = 0;
    std::size_t batch_hash_checks = 0;
    std::size_t batch_inventory_checks = 0;
    const auto upload_batch = [&]() -> bool {
        if (pending_ids.empty()) return true;
        const auto batch_name = "batch-" + pad_index(batch_number++);
        const auto batch_root = local_root / "batches" / batch_name;
        const auto verify_root = local_root / "verification" / batch_name;
        std::filesystem::create_directories(verify_root, ec);
        if (ec) return false;
        if (!event("BATCH_UPLOAD_INTENT", {{"batch", batch_name},
                                           {"object_ids", string_array(pending_ids)},
                                           {"max_parallel_transfers", transfers}})) return false;
        if (!checkpoint("BATCH_UPLOAD_IN_FLIGHT", "PREPARING")) return false;
        const auto call_start = Clock::now();
        auto put = kasumi::transport::put_batch(
            storage, kasumi::transport::PutBatch{.source_root = batch_root,
                                                 .identifiers = pending_ids,
                                                 .max_parallel_transfers = transfers});
        const auto call_ms = elapsed_ms(call_start);
        if (!put) {
            report["ambiguous_batch"] = kasumi::transport::mutation_result_is_ambiguous(put.error());
            report["failed_batch"] = batch_name;
            report["failed_object_ids"] = string_array(pending_ids);
            report["upload_error"] = kasumi::transport::describe(put.error());
            event("BATCH_UPLOAD_ERROR", {{"batch", batch_name},
                                         {"ambiguous", kasumi::transport::mutation_result_is_ambiguous(put.error())},
                                         {"error_code", kasumi::transport::error_code_name(put.error().code)},
                                         {"message", put.error().message},
                                         {"object_ids", string_array(pending_ids)}});
            return false;
        }
        if (!event("BATCH_UPLOAD_RETURNED", {{"batch", batch_name}, {"elapsed_ms", call_ms}})) return false;
        const auto verified = kasumi::transport::physical_hash_batch(
            storage, kasumi::transport::PhysicalHashBatchRequest{
                .scratch_root = verify_root, .objects = pending_hashes, .algorithm = "sha256"});
        ++batch_hash_checks;
        if (!verified || !verified->mismatched.empty() || !verified->missing.empty() ||
            !verified->errors.empty() || sorted(verified->matched) != sorted(pending_ids)) {
            report["failed_batch"] = batch_name;
            report["batch_verification"] = verified
                ? Json{{"matched", string_array(sorted(verified->matched))},
                       {"mismatched", string_array(verified->mismatched)},
                       {"missing", string_array(verified->missing)},
                       {"errors", string_array(verified->errors)}}
                : Json{{"error", kasumi::transport::describe(verified.error())}};
            event("BATCH_VERIFY_FAILED", {{"batch", batch_name}});
            return false;
        }
        auto inventory = kasumi::transport::list(storage);
        ++batch_inventory_checks;
        auto expected = uploaded_ids;
        expected.insert(expected.end(), pending_ids.begin(), pending_ids.end());
        if (!inventory || sorted(*inventory) != sorted(expected)) {
            report["failed_batch"] = batch_name;
            if (inventory) report["observed_inventory"] = string_array(sorted(*inventory));
            event("BATCH_INVENTORY_MISMATCH", {{"batch", batch_name}});
            return false;
        }
        for (std::size_t i = 0; i < pending_ids.size(); ++i) {
            if (!event("OBJECT_UPLOAD_CONFIRMED", {{"id", pending_ids[i]},
                                                   {"physical_sha256", pending_hashes[i].expected_hash},
                                                   {"batch", batch_name}})) return false;
        }
        uploaded_ids.insert(uploaded_ids.end(), pending_ids.begin(), pending_ids.end());
        report["content_objects_prepared"] = content_ids.size();
        report["content_objects_upload_confirmed"] = uploaded_ids.size();
        report["content_batches_confirmed"] = batch_number;
        pending_ids.clear();
        pending_hashes.clear();
        return checkpoint("CONTENT_BATCH_VERIFIED", "PREPARING");
    };

    for (std::size_t i = 0; i < 1000; ++i) {
        const auto payload = make_payload(run_id, "s2", i);
        const auto plain = local_root / ("plain-" + pad_index(i));
        const auto encrypted = local_root / ("encrypted-" + pad_index(i));
        {
            std::ofstream file(plain, std::ios::binary | std::ios::trunc);
            file.write(payload.data(), static_cast<std::streamsize>(payload.size()));
            if (!file) return fail("FAILED", "CONTENT_PREPARATION", "failed to write plaintext fixture file");
        }
        auto encryption = kasumi::crypto::encrypt_file_with_hashes(
            plain, encrypted, key, kasumi::crypto::FilePurpose::Content);
        if (!encryption) return fail("FAILED", "CONTENT_PREPARATION", "production content encryption failed");
        const auto id = kasumi::crypto::content_identifier(key, encryption->plaintext_hash);
        if (content_info.contains(id)) return fail("FAILED", "CONTENT_PREPARATION", "duplicate content identifier generated");
        const auto size = std::filesystem::file_size(encrypted, ec);
        if (ec) return fail("FAILED", "CONTENT_PREPARATION", "could not measure encrypted object");
        const auto batch_index = i / batch_size;
        const auto batch_name = "batch-" + pad_index(batch_index);
        const auto batch_root = local_root / "batches" / batch_name;
        std::filesystem::create_directories(batch_root, ec);
        if (ec) return fail("FAILED", "CONTENT_PREPARATION", "could not create batch staging directory");
        std::filesystem::rename(encrypted, batch_root / id, ec);
        if (ec) return fail("FAILED", "CONTENT_PREPARATION", "could not stage encrypted object for batch upload");
        content_ids.push_back(id);
        content_info.emplace(id, std::pair{encryption->plaintext_hash, encryption->plaintext_size});
        tree.rows.push_back(kasumi::NodeRow{.path = "file_" + pad_index(i) + ".bin",
                                            .hash = encryption->plaintext_hash,
                                            .size = encryption->plaintext_size,
                                            .mtime = {}, .is_directory = false});
        plaintext_bytes += encryption->plaintext_size;
        ciphertext_bytes += size;
        if (!event("OBJECT_PREPARED", {{"index", i}, {"id", id},
                                        {"remote_path", remote_path + "/" + id},
                                        {"plaintext_hash", kasumi::hash_hex(encryption->plaintext_hash)},
                                        {"plaintext_bytes", encryption->plaintext_size},
                                        {"ciphertext_sha256", encryption->ciphertext_sha256},
                                        {"ciphertext_bytes", size}, {"upload_state", "PENDING"}})) {
            return fail("FAILED", "CONTENT_PREPARATION", "could not checkpoint object manifest");
        }
        pending_ids.push_back(id);
        pending_hashes.push_back({id, encryption->ciphertext_sha256});
        std::filesystem::remove(plain, ec);
        if ((i + 1) % batch_size == 0 || i == 999) {
            if (!upload_batch()) return fail("FAILED_PRESERVED", "CONTENT_UPLOAD",
                                             "batch upload, verification, or exact inventory failed; fixture preserved");
        }
    }
    kasumi::finalize_snapshot(tree);
    if (content_ids.size() != 1000 || uploaded_ids.size() != 1000) {
        return fail("FAILED_PRESERVED", "CONTENT_UPLOAD", "content count did not reach 1,000");
    }
    manifest = content_ids;
    if (!event("CONTENT_SET_COMPLETE", {{"F", tree.rows.size() - 1}, {"N", content_ids.size()},
                                         {"plaintext_bytes", plaintext_bytes},
                                         {"ciphertext_bytes", ciphertext_bytes}})) return false;

    const auto commit_unix = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto commit = kasumi::history::make_commit(0, {}, tree, commit_unix);
    if (!commit) return fail("FAILED_PRESERVED", "COMMIT_PREPARATION", "production commit construction failed");
    if (!event("COMMIT_PUBLISH_INTENT", {{"sequence", 0}, {"file_count", 1000},
                                          {"commit_unix_seconds", commit_unix}})) return false;
    if (!checkpoint("COMMIT_PUBLISH_IN_FLIGHT", "PREPARING")) return false;
    const auto commit_published = history_storage::publish_commit_object_scoped(
        storage, layout, key, *commit, local_root);
    if (!commit_published) {
        report["commit_publish_error"] = commit_published.error().detail;
        report["commit_publish_ambiguous"] = true;
        event("COMMIT_PUBLISH_ERROR", {{"message", commit_published.error().detail}});
        return fail("FAILED_PRESERVED", "COMMIT_PUBLISH", "commit result is ambiguous; no retry attempted");
    }
    auto head = commit_published->head;
    const auto commit_id = history_storage::commit_object(layout, head);
    manifest.push_back(commit_id);
    if (!event("COMMIT_PUBLISH_CONFIRMED", {{"id", commit_id},
                                              {"reused_existing_ciphertext", commit_published->reused_existing_ciphertext},
                                              {"physical_sha256", commit_published->physical_hash}})) return false;
    if (!checkpoint("COMMIT_PUBLISHED", "PREPARING")) return false;
    if (!event("HEAD_PUBLISH_INTENT", {{"commit_id", head.commit_id}})) return false;
    if (!checkpoint("HEAD_PUBLISH_IN_FLIGHT", "PREPARING")) return false;
    const auto marker = history_storage::publish_head_marker_scoped(storage, layout, head, local_root);
    if (!marker) {
        report["head_publish_error"] = marker.error().detail;
        event("HEAD_PUBLISH_ERROR", {{"message", marker.error().detail}});
        return fail("FAILED_PRESERVED", "HEAD_PUBLISH", "HEAD result is ambiguous; no second marker attempted");
    }
    manifest.push_back(marker->marker_id);
    if (!event("HEAD_PUBLISH_CONFIRMED", {{"id", marker->marker_id}, {"commit_id", head.commit_id}})) return false;
    if (!checkpoint("HEAD_PUBLISHED", "VALIDATING")) return false;
    report["fixture_preparation_ms"] = elapsed_ms(prep_start);
    report["local_plaintext_bytes"] = plaintext_bytes;
    report["local_ciphertext_content_bytes"] = ciphertext_bytes;
    report["content_objects"] = content_ids.size();
    report["commit_id"] = head.commit_id;
    report["commit_object_id"] = commit_id;
    report["head_marker_id"] = marker->marker_id;
    report["manifest_object_count"] = manifest.size();

    const auto pre_gc_checks_start = Clock::now();
    auto pre_list = kasumi::transport::list(storage);
    if (!pre_list || sorted(*pre_list) != sorted(manifest) || manifest.size() != 1002) {
        if (pre_list) report["pre_gc_observed_inventory"] = string_array(sorted(*pre_list));
        report["manifest_ids"] = string_array(sorted(manifest));
        return fail("FAILED_PRESERVED", "PRE_GC_INVENTORY", "remote inventory is not exactly 1,002 manifest IDs");
    }
    const auto validation_start = Clock::now();
    Json pre_validation = Json::object();
    if (!validate_history(storage, key, manifest, local_root, head.commit_id, 1, 1000,
                          pre_validation)) {
        report["pre_gc_validation"] = pre_validation;
        return fail("FAILED_PRESERVED", "PRE_GC_VALIDATION", "authenticated history/content inventory failed");
    }
    report["pre_gc_validation_ms"] = elapsed_ms(validation_start);
    report["pre_gc_validation"] = pre_validation;
    report["F"] = 1000;
    report["N_content_objects"] = 1000;
    report["P_physical_commits"] = 1;
    report["R_protected_commits"] = 1;
    report["C_candidates_before_gc"] = 0;
    report["E_epochs"] = pre_validation.value("valid_epochs", 0);
    report["A_anchors"] = 0;
    report["total_physical_objects"] = manifest.size();
    report["remote_inventory_ids"] = string_array(sorted(*pre_list));
    const auto size = remote_size(remote_path);
    if (!size || !size->contains("count") || !size->contains("bytes") ||
        (*size)["count"].get<std::size_t>() != manifest.size()) {
        report["remote_size"] = "NOT_MEASURED";
        report["remote_size_error"] = size ? "unexpected rclone size count" : size.error();
        return fail("FAILED_PRESERVED", "PRE_GC_SIZE", "remote object count/bytes could not be confirmed");
    }
    report["remote_bytes"] = (*size)["bytes"];
    report["remote_size_objects"] = (*size)["count"];
    const auto commit_local = local_root / "commit.enc";
    auto commit_get = kasumi::transport::get(storage, commit_id, commit_local);
    if (commit_get) {
        report["commit_encrypted_bytes"] = std::filesystem::file_size(commit_local, ec);
        if (ec) report["commit_encrypted_bytes"] = "NOT_MEASURED";
    } else {
        report["commit_encrypted_bytes"] = "NOT_MEASURED";
        report["commit_size_error"] = kasumi::transport::describe(commit_get.error());
    }
    report["pre_gc_all_checks_ms"] = elapsed_ms(pre_gc_checks_start);
    report["network_bytes_uploaded"] = "NOT_MEASURED";
    report["upload_batch_count"] = batch_number;
    report["upload_batch_attempts"] = batch_number;
    report["content_batch_hash_checks"] = batch_hash_checks;
    report["content_batch_exact_inventory_checks"] = batch_inventory_checks;
    report["content_objects_uploaded"] = uploaded_ids.size();
    report["upload_max_parallel_transfers"] = transfers;
    report["retry_count"] = "NOT_MEASURED";
    report["rate_limit_count"] = "NOT_MEASURED";
    if (!checkpoint("PRE_GC_VALIDATION_COMPLETE", "READY_FOR_GC")) return false;
    if (!event("PRE_GC_VALIDATED", {{"F", 1000}, {"N", 1000}, {"P", 1}, {"R", 1},
                                     {"C", 0}, {"objects", 1002}, {"remote_bytes", (*size)["bytes"]}})) return false;

    const auto runtime_root = local_root / "gc-runtime";
    kasumi::runtime::RuntimeData runtime{
        .local_dir = runtime_root / "local",
        .database_path = runtime_root / "profile" / "db.sqlite",
        .key_path = runtime_root / "profile" / "key.bin",
        .storage_location = remote_path,
    };
    std::filesystem::create_directories(runtime.local_dir, ec);
    std::filesystem::create_directories(runtime.database_path.parent_path(), ec);
    if (ec) return fail("FAILED_PRESERVED", "GC_SETUP", "could not create isolated GC runtime files");
    Traffic traffic;
    traffic.stage = "garbage_collect";
    auto counted = make_counted_transport(storage, traffic, layout);
    if (!event("GC_STARTED", {{"remote_path", remote_path}, {"prior_full_gc_count", 0}}) ||
        !checkpoint("GC_IN_FLIGHT", "GC_RUNNING")) return false;
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();
    const auto gc_start = Clock::now();
    auto collected = kasumi::application::integrity::garbage_collect(runtime, counted, key);
    const auto gc_end = Clock::now();
    const auto gc_times = phase_times_json(); // Capture before tracing is disabled.
    kasumi::platform::perf_trace::force_enable(false);
    for (auto& error : traffic.error_events) {
        error["gc_returned_success"] = static_cast<bool>(collected);
        error["recovery_detail"] = collected
            ? "GC returned successfully; per-error protocol recovery NOT_MEASURED"
            : "GC failed; per-error protocol recovery NOT_MEASURED";
    }
    report["gc_wall_us"] = std::chrono::duration_cast<std::chrono::microseconds>(gc_end - gc_start).count();
    report["gc_phase_times"] = gc_times;
    report["gc_transport"] = traffic_json(traffic);
    report["full_gc_runs"] = 1;
    if (!collected) {
        report["gc_error"] = kasumi::application::integrity::describe(collected.error());
        event("GC_FAILED", {{"error", report["gc_error"]}});
        return fail("FAILED_PRESERVED", "GC_FAILED", "single full GC failed; fixture preserved and no rerun attempted");
    }
    report["candidate_objects"] = collected->candidate_objects;
    report["quarantined_objects"] = collected->quarantined_objects;
    report["restored_objects"] = collected->restored_objects;
    report["purged_objects"] = collected->purged_objects;
    if (collected->candidate_objects || collected->quarantined_objects ||
        collected->restored_objects || collected->purged_objects) {
        event("GC_INVARIANT_FAILED", {{"candidate_objects", collected->candidate_objects},
                                      {"quarantined_objects", collected->quarantined_objects},
                                      {"restored_objects", collected->restored_objects},
                                      {"purged_objects", collected->purged_objects}});
        return fail("FAILED_PRESERVED", "GC_INVARIANT_FAILED", "GC had nonzero candidates or destructive effects");
    }
    if (!event("GC_COMPLETE", {{"gc_wall_us", report["gc_wall_us"]},
                                {"candidate_objects", 0}, {"quarantined_objects", 0},
                                {"restored_objects", 0}, {"purged_objects", 0}})) return false;
    if (!checkpoint("GC_COMPLETE", "POST_GC_VALIDATING")) return false;

    const auto post_start = Clock::now();
    auto post_list = kasumi::transport::list(storage);
    Json post_validation = Json::object();
    if (!post_list || sorted(*post_list) != sorted(manifest) ||
        !validate_history(storage, key, manifest, local_root, head.commit_id, 1, 1000,
                          post_validation)) {
        if (post_list) report["post_gc_observed_inventory"] = string_array(sorted(*post_list));
        report["post_gc_validation"] = post_validation;
        return fail("FAILED_PRESERVED", "POST_GC_VALIDATION", "post-GC inventory/history validation failed");
    }
    std::vector<std::string> samples;
    constexpr std::size_t sample_count = 10;
    for (std::size_t i = 0; i < sample_count; ++i) {
        samples.push_back(content_ids[i * (content_ids.size() - 1) / (sample_count - 1)]);
    }
    std::size_t samples_verified = 0;
    if (!verify_content_samples(storage, key, local_root, samples, content_info, samples_verified)) {
        report["post_gc_content_sample_error"] = true;
        return fail("FAILED_PRESERVED", "POST_GC_CONTENT_SAMPLE", "deterministic encrypted content sample failed");
    }
    report["post_gc_validation"] = post_validation;
    report["post_gc_validation_ms"] = elapsed_ms(post_start);
    report["post_gc_sample_count"] = samples_verified;
    report["post_gc_sample_ids"] = string_array(samples);
    report["post_gc_sample_criterion"] = "10 evenly spaced entries in sorted content-ID order; GET, decrypt, plaintext hash/size and content ID checked";
    report["content_authentication_scope"] = "presence/reachability for all 1,000; plaintext authentication for 10 deterministic samples";

    const auto post_size_start = Clock::now();
    auto post_size = remote_size(remote_path);
    if (!post_size || !post_size->contains("count") ||
        (*post_size)["count"].get<std::size_t>() != manifest.size()) {
        return fail("FAILED_PRESERVED", "POST_GC_SIZE", "post-GC physical size count mismatch");
    }
    report["post_gc_size_check_ms"] = elapsed_ms(post_size_start);
    report["post_gc_remote_bytes"] = (*post_size)["bytes"];
    report["cleanup_started"] = true;
    if (!checkpoint("CLEANUP_IN_FLIGHT", "CLEANING")) return false;
    const auto cleanup_start = Clock::now();
    std::vector<std::string> removed;
    for (const auto& id : sorted(manifest)) {
        if (!event("REMOVE_INTENT", {{"id", id}, {"remote_path", remote_path + "/" + id}})) return false;
        auto result = kasumi::transport::remove(storage, id);
        if (!result || *result != kasumi::transport::Removal::Removed) {
            report["cleanup_failed_id"] = id;
            report["cleanup_ambiguous"] = !result && kasumi::transport::mutation_result_is_ambiguous(result.error());
            report["cleanup_error"] = result ? "object was not removed" : kasumi::transport::describe(result.error());
            event("REMOVE_FAILED", {{"id", id}, {"ambiguous", report["cleanup_ambiguous"]},
                                    {"error", report["cleanup_error"]}});
            return fail("PASS_WITH_REMAINS", "CLEANUP_INCOMPLETE", "stopped on first unconfirmed object removal");
        }
        removed.push_back(id);
        if (!event("REMOVE_CONFIRMED", {{"id", id}})) return false;
        if (removed.size() % 25 == 0) {
            report["cleanup_objects_removed"] = removed.size();
            if (!checkpoint("CLEANUP_IN_FLIGHT", "CLEANING")) return false;
        }
    }
    auto empty = kasumi::transport::list(storage);
    if (!empty && empty.error().code != kasumi::transport::ErrorCode::StorageNotFound) {
        return fail("PASS_WITH_REMAINS", "CLEANUP_VERIFY", "could not verify empty exact fixture path");
    }
    if (empty && !empty->empty()) {
        report["remaining_ids"] = string_array(sorted(*empty));
        return fail("PASS_WITH_REMAINS", "CLEANUP_VERIFY", "objects remain in exact fixture path");
    }
    report["manifest_cleanup_ms"] = elapsed_ms(cleanup_start);
    report["cleanup_objects_removed"] = removed.size();
    report["cleanup_objects_remaining"] = 0;
    report["verification_elapsed_ms"] = report.value("pre_gc_all_checks_ms", 0ULL) +
                                         report.value("post_gc_validation_ms", 0ULL) +
                                         report.value("post_gc_size_check_ms", 0ULL);
    constexpr std::int64_t s1_gc_us = 24265814;
    const auto observation1 = gc_times["observation_1"]["observation_total_us"].get<std::int64_t>();
    const auto observation2 = gc_times["observation_2"]["observation_total_us"].get<std::int64_t>();
    const auto listing1 = gc_times["observation_1"]["physical_listing_us"].get<std::int64_t>();
    const auto listing2 = gc_times["observation_2"]["physical_listing_us"].get<std::int64_t>();
    const auto auth1 = gc_times["observation_1"]["load_and_auth_commits_us"].get<std::int64_t>();
    const auto auth2 = gc_times["observation_2"]["load_and_auth_commits_us"].get<std::int64_t>();
    Json comparison{
        {"observational_comparison", true}, {"S1_gc_us", s1_gc_us},
        {"S2_minus_S1_gc_us", report["gc_wall_us"].get<std::int64_t>() - s1_gc_us},
        {"S2_minus_S1_gc_percent", 100.0 * (report["gc_wall_us"].get<double>() - s1_gc_us) / s1_gc_us},
        {"F_delta", 800}, {"N_delta", 800},
        {"physical_object_count_delta", static_cast<std::int64_t>(manifest.size()) - 202},
        {"remote_bytes_delta", (*size)["bytes"].get<std::int64_t>() - 233443},
        {"spans_overlap_gc_wall", true},
        {"phase18_detailed_s1_from", "phase18-measured-20260924-bb66ec3.json"},
    };
    comparison["observation_1_us"] = Json{{"S1", 3908191}, {"S2", observation1},
                                           {"delta", observation1 - 3908191}};
    comparison["observation_2_us"] = Json{{"S1", 3836164}, {"S2", observation2},
                                           {"delta", observation2 - 3836164}};
    comparison["physical_listing_us"] = Json{
        {"S1", Json::array({1574354, 1620671})}, {"S2", Json::array({listing1, listing2})},
        {"delta_total", listing1 + listing2 - 3195025}};
    comparison["load_and_auth_commits_us"] = Json{
        {"S1", Json::array({1242625, 1011072})}, {"S2", Json::array({auth1, auth2})},
        {"delta_total", auth1 + auth2 - 2253697}};
    comparison["list_wrapper_us"] = Json{
        {"S1", 8102793}, {"S2", traffic.list_time_us},
        {"delta", static_cast<std::int64_t>(traffic.list_time_us) - 8102793}};
    comparison["list_counts"] = Json{
        {"global", Json{{"S1", 4}, {"S2", traffic.full_list_calls}}},
        {"prefix", Json{{"S1", 6}, {"S2", traffic.prefix_list_calls}}}};
    comparison["identifiers_returned"] = Json{
        {"S1", 814}, {"S2", traffic.identifiers_returned},
        {"delta", static_cast<std::int64_t>(traffic.identifiers_returned) - 814}};
    comparison["get_objects"] = Json{
        {"total", Json{{"S1", 7}, {"S2", traffic.get_objects}}},
        {"commits", Json{{"S1", 2}, {"S2", traffic.commit_gets}}},
        {"markers", Json{{"S1", 2}, {"S2", traffic.marker_gets}}},
        {"epochs", Json{{"S1", 0}, {"S2", traffic.epoch_gets}}},
        {"contents", Json{{"S1", 0}, {"S2", traffic.content_gets}}}};
    comparison["fixed_cost_spans_us"] = Json{
        {"barrier_acquire", Json{{"S1", 3694265}, {"S2", gc_times["barrier_acquire_us"]}}},
        {"writer_consistency", Json{{"S1", 2872662}, {"S2", gc_times["writer_consistency_us"]}}},
        {"backend_probe", Json{{"S1", 4671113}, {"S2", gc_times["backend_consistency_probe_us"]}}},
        {"final_namespace_verification", Json{{"S1", 1564825}, {"S2", gc_times["final_namespace_verification_us"]}}}};
    report["comparison_phase18_s1"] = std::move(comparison);
    report["cleanup_elapsed_ms"] = elapsed_ms(cleanup_start);
    if (!event("CLEANUP_COMPLETE", {{"objects_removed", removed.size()}, {"objects_remaining", 0}})) return false;
    report["full_gc_runs"] = 1;
    report["remote_recursive_delete_used"] = false;
    report["ended_elapsed_ms"] = elapsed_ms(started);
    report["status"] = "PASS_CLEANED";
    report["last_confirmed_stage"] = "COMPLETE";
    if (!write_json(output, report) ||
        !write_json(sidecar, Json{{"status", "PASS_CLEANED"}, {"last_confirmed_stage", "COMPLETE"},
                                  {"remote_path", remote_path}, {"full_gc_runs", 1}})) return false;
    return true;
}

struct Phase20Asset {
    std::string id;
    std::filesystem::path encrypted_path;
    std::string ciphertext_sha256;
    kasumi::Hash plaintext_hash{};
    std::uint64_t plaintext_size = 0;
    std::uint64_t ciphertext_size = 0;
};

constexpr std::array<std::pair<std::string_view, std::size_t>, 5> phase20_plan{{
    {"T1", 1}, {"T2", 10}, {"T3", 100}, {"T4", 200}, {"T5", 1000}}};

bool phase20_plan_self_test() {
    constexpr std::array<std::size_t, 5> expected{1, 10, 100, 200, 1000};
    for (std::size_t i = 0; i < phase20_plan.size(); ++i) {
        if (phase20_plan[i].second != expected[i]) return false;
    }
    const auto delta = static_cast<double>(25'432'164 - 24'265'814);
    return delta / static_cast<double>(1000 - 0) == 1166.35;
}

std::optional<Phase20Asset> phase20_prepare_asset(
    std::string_view run_id, std::string_view kind, std::size_t index,
    const std::filesystem::path& directory,
    std::span<const std::uint8_t, kasumi::crypto::KEY_SIZE> key) {
    std::error_code ec;
    std::filesystem::create_directories(directory, ec);
    if (ec) return std::nullopt;
    const auto name = std::string{kind} + "-" + pad_index(index);
    const auto plaintext_path = directory / (name + ".plain");
    const auto encrypted_path = directory / (name + ".enc");
    const auto payload = make_payload(run_id, kind, index);
    {
        std::ofstream file(plaintext_path, std::ios::binary | std::ios::trunc);
        file.write(payload.data(), static_cast<std::streamsize>(payload.size()));
        if (!file) return std::nullopt;
    }
    if (std::filesystem::exists(encrypted_path, ec)) {
        if (ec) return std::nullopt;
        const auto verify_path = directory / (name + ".verify");
        if (!kasumi::crypto::decrypt_file(encrypted_path, verify_path, key,
                                          kasumi::crypto::FilePurpose::Content)) {
            return std::nullopt;
        }
        std::ifstream verify(verify_path, std::ios::binary);
        const std::string observed{std::istreambuf_iterator<char>{verify}, {}};
        std::filesystem::remove(verify_path, ec);
        if (!verify || observed != payload) return std::nullopt;
    } else {
        auto encrypted = kasumi::crypto::encrypt_file_with_hashes(
            plaintext_path, encrypted_path, key,
            kasumi::crypto::FilePurpose::Content);
        if (!encrypted) return std::nullopt;
    }
    auto plain_hash = kasumi::crypto::content::hash_file(plaintext_path);
    auto encrypted_hash = kasumi::crypto::physical::hash_file(
        encrypted_path, "sha256");
    const auto size = std::filesystem::file_size(encrypted_path, ec);
    std::filesystem::remove(plaintext_path, ec);
    if (!plain_hash || !encrypted_hash || ec) return std::nullopt;
    return Phase20Asset{
        .id = kasumi::crypto::content_identifier(key, *plain_hash),
        .encrypted_path = encrypted_path,
        .ciphertext_sha256 = std::move(*encrypted_hash),
        .plaintext_hash = *plain_hash,
        .plaintext_size = payload.size(),
        .ciphertext_size = size,
    };
}

Json phase20_asset_json(const Phase20Asset& asset, std::string_view kind) {
    return Json{{"id", asset.id}, {"kind", kind},
                {"ciphertext_sha256", asset.ciphertext_sha256},
                {"ciphertext_bytes", asset.ciphertext_size},
                {"plaintext_hash", kasumi::hash_hex(asset.plaintext_hash)},
                {"plaintext_bytes", asset.plaintext_size},
                {"local_ciphertext", asset.encrypted_path.string()}};
}

bool phase20_validate_fixture(
    Transport& storage,
    std::span<const std::uint8_t, kasumi::crypto::KEY_SIZE> key,
    const history_storage::RemoteLayout& layout,
    const std::vector<std::string>& identifiers,
    const std::vector<std::string>& live_ids,
    const std::vector<std::string>& candidate_ids,
    const std::filesystem::path& workspace,
    const std::string& expected_head,
    Json& validation) {
    auto history = history_storage::inventory_reachability(
        storage, key, identifiers, workspace);
    if (!history) {
        validation["history_error"] = history.error().detail;
        return false;
    }
    const auto valid_markers = std::ranges::count_if(
        history->markers, [](const auto& marker) {
            return marker.state == history_storage::ReachabilityMarkerState::Valid;
        });
    const auto physical_commits = std::ranges::count_if(
        identifiers, [&](const auto& id) { return id.starts_with(layout.commits_prefix); });
    const auto physical_markers = std::ranges::count_if(
        identifiers, [&](const auto& id) { return id.starts_with(layout.heads_prefix); });
    const auto physical_epochs = std::ranges::count_if(
        identifiers, [&](const auto& id) { return id.starts_with(layout.epochs_prefix); });
    const bool history_valid = history->logical_heads.size() == 1 &&
        history->logical_heads.front() == expected_head &&
        history->reachable_commits.size() == 1 && history->orphan_commits.empty() &&
        history->missing_parent_ids.empty() && history->invalid_parent_ids.empty() &&
        history->unknown_history_objects.empty() && valid_markers == 1 &&
        history->valid_epochs.empty() && history->orphan_epochs.empty() &&
        physical_commits == 1 && physical_markers == 1 && physical_epochs == 0;
    validation["history_valid"] = history_valid;
    validation["authenticated_head_matches"] = history->logical_heads.size() == 1 &&
                                                history->logical_heads.front() == expected_head;
    validation["logical_heads"] = history->logical_heads;
    validation["reachable_commits"] = history->reachable_commits.size();
    validation["orphan_commits"] = history->orphan_commits.size();
    validation["valid_markers"] = valid_markers;
    validation["physical_commits"] = physical_commits;
    validation["physical_markers"] = physical_markers;
    validation["E_epochs"] = physical_epochs;
    validation["valid_epochs"] = history->valid_epochs.size();
    validation["A_anchors"] = 0;
    if (!history_valid) return false;

    auto contents = history_storage::inventory_content_reachability(
        storage, key, identifiers, *history, workspace, false);
    if (!contents) {
        validation["content_error"] = contents.error().detail;
        return false;
    }
    const bool content_valid =
        sorted(contents->reachable_content_ids) == sorted(live_ids) &&
        sorted(contents->orphan_content_ids) == sorted(candidate_ids) &&
        contents->missing_content_ids.empty() && contents->corrupt_content_ids.empty() &&
        contents->unknown_storage_objects.empty();
    validation["content_valid"] = content_valid;
    validation["N_live"] = contents->reachable_content_ids.size();
    validation["N_orphan"] = contents->orphan_content_ids.size();
    validation["N_total_content"] = contents->reachable_content_ids.size() +
                                     contents->orphan_content_ids.size();
    validation["missing_content_objects"] = contents->missing_content_ids.size();
    validation["corrupt_content_objects"] = contents->corrupt_content_ids.size();
    validation["unknown_storage_objects"] = contents->unknown_storage_objects;
    return content_valid;
}

bool run_phase20_curve(const std::filesystem::path& output_arg, bool resume,
                      bool preflight_only, bool phase22 = false,
                      int phase23_mode = 0, std::size_t copy_concurrency = 8,
                      std::size_t metadata_concurrency = 8,
                      bool phase24 = false) {
    const bool phase23 = phase23_mode != 0 && !phase24;
    const bool phase_batch = phase23_mode != 0;
    const bool strict_revision = phase22 || phase_batch;
    const std::size_t live_count = phase23_mode == 1 ? 10 : 1000;
    const auto phase23_scenario = phase23_mode == 1
        ? std::string{"CANARY"}
        : phase24 ? "M" + std::to_string(metadata_concurrency)
                  : "B" + std::to_string(copy_concurrency);
    std::vector<std::pair<std::string, std::size_t>> plan;
    for (const auto& [name, count] : phase20_plan) plan.emplace_back(name, count);
    if (phase_batch) {
        plan.clear();
        plan.emplace_back(phase23_scenario, phase23_mode == 1 ? 8 : 100);
    }
    const auto phase_name = phase24
        ? (phase23_mode == 1 ? "KASUMI_PHASE_24_METADATA_BATCH_CANARY"
                             : "KASUMI_PHASE_24_METADATA_BATCH_POINT")
        : phase23
        ? (phase23_mode == 1 ? "KASUMI_PHASE_23_COPY_BATCH_CANARY"
                             : "KASUMI_PHASE_23_COPY_BATCH_POINT")
        : phase22 ? "KASUMI_PHASE_22_REAL_REMOTE_GC_CANDIDATE_CURVE"
                  : "KASUMI_PHASE_20_REAL_REMOTE_GC_CANDIDATE_CURVE";
    const auto root_prefix = phase24
        ? (phase23_mode == 1 ? "/gc-phase24-metadata-batch-canary-"
                             : "/gc-phase24-metadata-batch-")
        : phase23
        ? (phase23_mode == 1 ? "/gc-phase23-copy-batch-canary-"
                             : "/gc-phase23-copy-batch-")
        : phase22 ? "/gc-phase22-" : "/gc-phase20-";
    std::error_code ec;
    const auto output = std::filesystem::absolute(output_arg, ec);
    if (ec || !std::filesystem::is_directory(output.parent_path(), ec) || ec) {
        std::cerr << "Output parent must be an existing local directory.\n";
        return false;
    }
    const auto journal = std::filesystem::path{output.string() + ".manifest.jsonl"};
    const auto sidecar = std::filesystem::path{output.string() + ".status.json"};
    const auto artifacts = std::filesystem::path{output.string() + ".artifacts"};
    Json report;
    std::string run_id;
    if (resume) {
        if (!std::filesystem::exists(output, ec) || ec) {
            std::cerr << "Resume requires the existing curve report.\n";
            return false;
        }
        std::ifstream in(output, std::ios::binary);
        try { in >> report; } catch (const Json::exception&) { return false; }
        if (!report.is_object() || report.value("phase", "") != phase_name ||
            !report.contains("run_id") || !report.contains("scenarios") ||
            report["scenarios"].size() != plan.size()) return false;
        run_id = report.at("run_id").get<std::string>();
        if (!valid_run_id(run_id) || !std::filesystem::exists(journal, ec) || ec) return false;
        auto events = read_complete_jsonl(journal);
        if (!events) return false;
        for (std::size_t i = 0; i < plan.size(); ++i) {
            bool started_gc = false, completed_gc = false;
            bool commit_intent = false, commit_confirmed = false;
            for (const auto& event : *events) {
                if (event.value("scenario", "") != plan[i].first) continue;
                const auto name = event.value("event", "");
                if (name == "GC_STARTED") started_gc = true;
                if (name == "GC_COMPLETE") completed_gc = true;
                if (name == "COMMIT_PUBLISH_INTENT") commit_intent = true;
                if (name == "COMMIT_PUBLISH_CONFIRMED") commit_confirmed = true;
            }
            auto& row = report["scenarios"][i];
            if (started_gc && !completed_gc) {
                row["status"] = "INTERRUPTED";
                row["last_confirmed_stage"] = "GC_STARTED";
                row["interruption_reason"] = "GC outcome is indeterminate; GC will not be repeated";
                report["status"] = "INTERRUPTED";
                report["stop_reason"] = row["interruption_reason"];
                write_json(output, report);
                write_json(sidecar, Json{{"status", "INTERRUPTED"},
                    {"last_confirmed_stage", "GC_STARTED"},
                    {"remote_path", row.value("remote_path", "NOT_MEASURED")},
                    {"interruption_reason", row["interruption_reason"]}});
                return false;
            }
            if (started_gc && completed_gc && row.value("status", "") != "PASS_CLEANED") {
                row["status"] = "INTERRUPTED";
                row["last_confirmed_stage"] = "GC_COMPLETE";
                row["interruption_reason"] = "GC is complete; post-GC verification/cleanup needs review; no GC rerun";
                report["status"] = "INTERRUPTED";
                report["stop_reason"] = row["interruption_reason"];
                write_json(output, report);
                write_json(sidecar, Json{{"status", "INTERRUPTED"},
                    {"last_confirmed_stage", "GC_COMPLETE"},
                    {"remote_path", row.value("remote_path", "NOT_MEASURED")},
                    {"interruption_reason", row["interruption_reason"]}});
                return false;
            }
            if (commit_intent && !commit_confirmed &&
                row.value("status", "") != "PASS_CLEANED") {
                row["status"] = "INTERRUPTED";
                row["last_confirmed_stage"] = "COMMIT_PUBLISH_INTENT";
                row["interruption_reason"] = "commit publish outcome is ambiguous; manual inventory review required";
                report["status"] = "INTERRUPTED";
                report["stop_reason"] = row["interruption_reason"];
                write_json(output, report);
                write_json(sidecar, Json{{"status", "INTERRUPTED"},
                    {"last_confirmed_stage", "COMMIT_PUBLISH_INTENT"},
                    {"remote_path", row.value("remote_path", "NOT_MEASURED")},
                    {"interruption_reason", row["interruption_reason"]}});
                return false;
            }
        }
    } else {
        if (std::filesystem::exists(output, ec) || ec) {
            std::cerr << "Output exists; use --resume only for an interrupted pre-GC preparation.\n";
            return false;
        }
        const auto generated = kasumi::platform::random::hex_id();
        if (!generated || !valid_run_id(*generated)) return false;
        run_id = *generated;
        const auto commit_unix = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        report = Json{
            {"schema_version", 1},
            {"phase", phase_name},
            {"status", "PREFLIGHT"}, {"run_id", run_id},
            {"remote_parent", remote_parent},
            {"remote_run_root", std::string{remote_parent} + root_prefix + run_id},
            {"build_commit", KASUMI_PHASE18_BUILD_COMMIT},
            {"initial_head", phase_batch ? KASUMI_PHASE18_BUILD_COMMIT :
                phase22 ? "5ebee41" : "bb66ec3"},
            {"copy_concurrency", phase_batch ? Json{copy_concurrency} : Json{"NOT_APPLICABLE"}},
            {"metadata_concurrency", phase24 ? Json{metadata_concurrency} : Json{"NOT_APPLICABLE"}},
            {"branch", "perf/gc-remote-copy"},
            {"local_output", output.string()}, {"journal_path", journal.string()},
            {"artifact_directory", artifacts.string()},
            {"local_workspace", (artifacts / "workspace").string()},
            {"commit_unix_seconds", commit_unix},
            {"limits", {{"full_gc_max_per_fixture", 1}, {"preparation_wall_limit", "NONE"},
                {"remote_operation_timeout_seconds", {"quick_rc", 30},
                    {"control_read_deadline", 120}, {"transfer", 1800},
                    {"rclone_cli_preflight", 90}},
                {"remote_mutation_retries", 0}, {"idempotent_read_attempts", 2},
                {"idempotent_read_retry_delay_ms", 75},
                {"maximum_candidates_per_fixture", 1000},
                {"maximum_physical_objects_after_gc_per_fixture", 3002},
                {"minimum_free_local_bytes", 536870912}}},
            {"preparation_method", "Production-encrypted live asset corpus prepared locally once; each scenario independently uploads and physically verifies its own copies to its exact fixture root. Candidates are separately encrypted valid content objects with unique plaintexts. No remote base or cross-fixture references."},
            {"phase18_reference", {{"S0", {{"F", 10}, {"C", 0}, {"gc_wall_us", 23433000}}},
                {"S1", {{"F", 200}, {"C", 0}, {"gc_wall_us", 24265814}}}}},
            {"phase19_s2_historical_baseline", {{"F", 1000}, {"N_live", 1000},
                {"C", 0}, {"gc_wall_us", 25432164}, {"rclone_version", "v1.75.1"},
                {"remote_type", "drive"}, {"remote_scope", "drive"},
                {"total_physical_objects", 1002}, {"remote_bytes", 1166243},
                {"comparable", !phase22}, {"use_for_phase22_slopes", false},
                {"source", "build-msys2-ucrt64/phase19/phase19-s2.json"}}},
            {"scenarios", Json::array()}};
        for (const auto& [name, candidates] : plan) {
            const auto suffix = phase_batch
                ? (phase23_mode == 1 ? std::string{} : std::string{"fixture"})
                : name == "T1" ? std::string{"c001"} : name == "T2" ? std::string{"c010"} :
                  name == "T3" ? std::string{"c100"} : name == "T4" ? std::string{"c200"} : std::string{"c1000"};
            report["scenarios"].push_back(Json{
                {"scenario", name}, {"C_expected", candidates}, {"status", "NOT_RUN"},
                {"remote_path", report["remote_run_root"].get<std::string>() +
                    (suffix.empty() ? "" : "/" + suffix)},
                {"full_gc_runs", 0}, {"last_confirmed_stage", "NOT_STARTED"}});
        }
        if (!write_json(output, report) ||
            !write_json(sidecar, Json{{"status", "PREFLIGHT"},
                {"last_confirmed_stage", "LOCAL_REPORT_CREATED"},
                {"interruption_reason_if_unfinished", "process loss is classified from the journal; any GC_STARTED without GC_COMPLETE is never rerun"}}) ||
            !append_jsonl(journal, Json{{"event", "RUN_CREATED"}, {"run_id", run_id},
                {"remote_run_root", report["remote_run_root"]},
                {"planned_candidates", [&] { Json values = Json::array(); for (const auto& p : plan) values.push_back(p.second); return values; }()}})) return false;
    }

    const auto initial_git_head = current_git_head();
    if (strict_revision && (initial_git_head != KASUMI_PHASE18_BUILD_COMMIT ||
                    (!phase_batch && std::string_view{KASUMI_PHASE18_BUILD_COMMIT} != "5ebee41"))) {
        report["git_head_before_remote_work"] = initial_git_head.empty() ?
            Json{"NOT_MEASURED"} : Json{initial_git_head};
        report["preflight_error"] = phase_batch
            ? "The batch phase requires repository HEAD to match the runner build commit"
            : "Phase 22 requires both repository HEAD and runner build commit 5ebee41";
        write_json(output, report);
        std::cerr << report["preflight_error"] << '\n';
        return false;
    }
    if (strict_revision) {
        report["git_head_before_remote_work"] = initial_git_head;
        report["git_head_final"] = "NOT_MEASURED";
        if (!write_json(output, report)) return false;
    }
    const auto started = Clock::now();
    const auto run_root = report.at("remote_run_root").get<std::string>();
    const auto local_root = artifacts / "workspace";
    std::filesystem::create_directories(local_root, ec);
    std::filesystem::create_directories(artifacts, ec);
    if (ec) return false;
    const auto checkpoint = [&](std::string_view stage, std::string_view status,
                                std::string_view scenario = "") {
        report["status"] = status;
        report["last_confirmed_stage"] = stage;
        report["updated_unix_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (!write_json(output, report)) return false;
        Json state{{"status", status}, {"last_confirmed_stage", stage},
            {"scenario", scenario.empty() ? "NOT_MEASURED" : std::string{scenario}},
            {"remote_run_root", run_root},
            {"interruption_reason_if_unfinished", "process loss before terminal checkpoint; preserve fixture and inspect the journal"},
            {"resume_rule", "resume only preparation by verifying existing IDs and SHA-256; never rerun a GC_STARTED scenario"},
            {"updated_unix_ms", report["updated_unix_ms"]}};
        return write_json(sidecar, state);
    };
    const auto event = [&](std::string_view name, std::string_view scenario,
                           Json details = Json::object()) {
        details["event"] = name;
        details["scenario"] = scenario;
        details["run_id"] = run_id;
        details["unix_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return append_jsonl(journal, details);
    };
    const auto fail = [&](std::string_view status, std::string_view stage,
                          std::string_view why, std::size_t row_index) {
        auto& row = report["scenarios"][row_index];
        row["status"] = status;
        row["last_confirmed_stage"] = stage;
        row["failure"] = why;
        report["stop_reason"] = why;
        report["elapsed_ms"] = elapsed_ms(started);
        checkpoint(stage, status, row.value("scenario", ""));
        std::cerr << status << " at " << stage << ": " << why << '\n';
        return false;
    };

    if (!phase20_plan_self_test()) return false;
    report[phase_batch ? (phase24 ? "phase24_point_plan" : "phase23_point_plan")
                       : phase22 ? "phase22_plan_self_test" : "phase20_plan_self_test"] =
        phase_batch ? Json{{"scenario", plan.front().first}, {"C", plan.front().second},
                       {"copy_concurrency", copy_concurrency},
                       {"metadata_concurrency", phase24 ? Json{metadata_concurrency} : Json{"NOT_APPLICABLE"}},
                       {"live_count", live_count}}
                : Json{"PASS"};
    auto remote_metadata = rclone_remote_config_metadata();
    if (!remote_metadata || remote_metadata->value("type", "") != "drive" ||
        remote_metadata->value("scope", "") != "drive" ||
        remote_metadata->value("team_drive_configured", true) ||
        remote_metadata->value("root_folder_id_configured", true)) {
        report["preflight_error"] = remote_metadata ?
            "kasumi remote is not confirmed as Google Drive scope=drive" : remote_metadata.error();
        checkpoint("REMOTE_IDENTITY", "REMOTE_NOT_RUN");
        return false;
    }
    const auto parent_entries = top_level_test_directories();
    if (!parent_entries) {
        report["preflight_error"] = parent_entries.error();
        checkpoint("PARENT_READ_ONLY_PREFLIGHT", "REMOTE_NOT_RUN");
        return false;
    }
    auto run_dir = std::string{root_prefix};
    if (!run_dir.empty() && run_dir.front() == '/') run_dir.erase(run_dir.begin());
    run_dir += run_id;
    const auto root_found = std::ranges::find_if(*parent_entries, [&](const auto& entry) {
        return trim_slash(entry) == run_dir;
    });
    if (!resume && root_found != parent_entries->end()) {
        report["preflight_error"] = "remote run root existence does not match new/resume mode";
        checkpoint("REMOTE_ROOT_CHECK", "REMOTE_NOT_RUN");
        return false;
    }
    auto space = std::filesystem::space(output.parent_path(), ec);
    if (ec || space.available < 536870912ULL) {
        report["preflight_error"] = "local free space is below the 512 MiB floor";
        checkpoint("LOCAL_SPACE_CHECK", "REMOTE_NOT_RUN");
        return false;
    }
    report["rclone_version"] = rclone_version();
    report["rclone_remote_metadata"] = *remote_metadata;
    report["preflight"] = {{"remote_type", "drive"}, {"remote_scope", "drive"},
        {"remote_parent", remote_parent}, {"parent_listing_succeeded", true},
        {"parent_entry_count", parent_entries->size()}, {"parent_mutated", false},
        {"run_root_absent_for_new_run", root_found == parent_entries->end()},
        {"run_root_present_for_resume", resume && root_found != parent_entries->end()},
        {"fixtures", Json::array()}, {"free_local_bytes", space.available},
        {"minimum_free_local_bytes", 536870912},
        {"dedicated_test_namespace", "kasumi:integration-tests (isolated operational test area)"},
        {"local_git_head", KASUMI_PHASE18_BUILD_COMMIT},
        {"local_branch", "perf/gc-remote-copy"},
        {"local_changes_preserved", "pre-existing operational runner modification retained; no production change is part of this run"},
        {"concurrency", "fresh unique fixture paths; production active-writer check and barrier ownership are checked again immediately before each GC"}};
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(i + 1);
    const auto layout = history_storage::derive_remote_layout(key);
    for (auto& row : report["scenarios"]) {
        const auto path = row.at("remote_path").get<std::string>();
        auto probe = kasumi::transport::open_transport(path);
        if (!probe || !kasumi::transport::initialize(*probe)) {
            report["preflight_error"] = "could not probe one exact fixture remote";
            checkpoint("FIXTURE_PATH_PREFLIGHT", "REMOTE_NOT_RUN");
            return false;
        }
        if (strict_revision && (!probe->storage.physical_hash_batch ||
                        probe->storage.physical_hash_batch_min_objects != 6)) {
            report["preflight_error"] = "the current rclone physical hash batch threshold must be six";
            checkpoint("BATCH_THRESHOLD_PREFLIGHT", "REMOTE_NOT_RUN");
            return false;
        }
        if (phase_batch && !probe->storage.copy_batch) {
            report["preflight_error"] = "Phase 23 requires the native copy_batch transport capability";
            checkpoint("COPY_BATCH_CAPABILITY_PREFLIGHT", "REMOTE_NOT_RUN");
            return false;
        }
        if (phase24 && !probe->storage.put_files_batch) {
            report["preflight_error"] = "Phase 24 requires explicit local-file put_files_batch support";
            checkpoint("METADATA_BATCH_CAPABILITY_PREFLIGHT", "REMOTE_NOT_RUN");
            return false;
        }
        auto entries = kasumi::transport::list(*probe);
        if (!entries && entries.error().code != kasumi::transport::ErrorCode::StorageNotFound) {
            report["preflight_error"] = "could not establish exact fixture inventory";
            checkpoint("FIXTURE_PATH_PREFLIGHT", "REMOTE_NOT_RUN");
            return false;
        }
        if (!resume && entries && !entries->empty()) {
            report["preflight_error"] = "one new fixture path is unexpectedly nonempty";
            row["unexpected_initial_inventory"] = string_array(sorted(*entries));
            checkpoint("FIXTURE_PATH_PREFLIGHT", "REMOTE_NOT_RUN");
            return false;
        }
        auto writers = kasumi::application::history_storage::maintenance_protocol::active_writers(
            *probe, layout);
        if (!writers || !writers->empty()) {
            report["preflight_error"] = "could not confirm no active writer in a new fixture namespace";
            checkpoint("WRITER_READ_ONLY_PREFLIGHT", "REMOTE_NOT_RUN");
            return false;
        }
        report["preflight"]["fixtures"].push_back({
            {"remote_path", path}, {"initial_inventory_count", entries ? entries->size() : 0},
            {"exact_path_only", true}, {"active_writers", 0},
            {"physical_hash_batch_min_objects", probe->storage.physical_hash_batch_min_objects},
            {"parent_mutated", false}});
    }
    if (!write_json(artifacts / "preflight.json", report["preflight"])) return false;
    if (!checkpoint("REMOTE_PREFLIGHT_CONFIRMED", "PREPARING")) return false;

    report["isolation"] = {{"transport_root_per_gc", "exact fixture remote_path"},
        {"runtime_storage_location_per_gc", "exact fixture remote_path"},
        {"remote_layout_prefixes_relative_to_fixture", {
            {"history", layout.history_prefix}, {"barrier", layout.barrier_identifier},
            {"writers", layout.writers_prefix}, {"probes", layout.probes_prefix},
            {"quarantine", layout.quarantine_prefix},
            {"quarantine_content", layout.quarantine_content_prefix}}},
        {"root_prefixes_recorded_as_remote_writes", false},
        {"remote_recursive_delete", false}};
    if (preflight_only) {
        report["status"] = "PREFLIGHT_READY";
        report["last_confirmed_stage"] = "READ_ONLY_PREFLIGHT_COMPLETE";
        report["remote_mutations_started"] = false;
        if (!event("PREFLIGHT_COMPLETE", "NOT_MEASURED", {{"fixture_count", plan.size()},
                {"remote_mutations_started", false}}) ||
            !write_json(output, report) ||
            !write_json(sidecar, Json{{"status", "PREFLIGHT_READY"},
                {"last_confirmed_stage", "READ_ONLY_PREFLIGHT_COMPLETE"},
                {"remote_run_root", run_root}, {"remote_mutations_started", false},
                {"resume_command", phase24 ?
                    std::string{phase23_mode == 1 ? "--phase24-canary" : "--phase24-point --metadata-concurrency " + std::to_string(metadata_concurrency)} + " --output <same-json> --execute-live --resume" : phase23 ?
                    std::string{phase23_mode == 1 ? "--phase23-canary" : "--phase23-point --copy-concurrency " + std::to_string(copy_concurrency)} + " --output <same-json> --execute-live --resume" : phase22 ?
                    "--phase22-curve --output <same-json> --execute-live --resume" :
                    "--phase20-curve --output <same-json> --execute-live --resume"}})) return false;
        return true;
    }

    std::vector<Phase20Asset> live_assets;
    std::vector<std::string> live_ids;
    std::map<std::string, std::pair<kasumi::Hash, std::uint64_t>> live_info;
    kasumi::Snapshot tree;
    tree.rows.push_back(kasumi::NodeRow{.path = "", .hash = {}, .size = 0,
                                        .mtime = {}, .is_directory = true});
    const auto live_dir = artifacts / "prepared" / "live";
    const auto shared_live_prep_start = Clock::now();
    for (std::size_t i = 0; i < live_count; ++i) {
        auto asset = phase20_prepare_asset(run_id, "shared-live", i, live_dir, key);
        if (!asset || live_info.contains(asset->id)) {
            report["preparation_error"] = "failed to create the planned distinct protected contents";
            checkpoint("LIVE_CORPUS_PREPARATION", "FAILED");
            return false;
        }
        live_ids.push_back(asset->id);
        live_info.emplace(asset->id, std::pair{asset->plaintext_hash, asset->plaintext_size});
        tree.rows.push_back(kasumi::NodeRow{
            .path = "file_" + pad_index(i) + ".bin", .hash = asset->plaintext_hash,
            .size = asset->plaintext_size, .mtime = {}, .is_directory = false});
        live_assets.push_back(std::move(*asset));
        if ((i + 1) % 100 == 0 || i + 1 == live_count) {
            report["live_local_assets_prepared"] = i + 1;
            if (!checkpoint("LIVE_CORPUS_PREPARATION", "PREPARING")) return false;
        }
    }
    kasumi::finalize_snapshot(tree);
    report["shared_live_corpus_preparation_seconds"] =
        static_cast<double>(elapsed_ms(shared_live_prep_start)) / 1000.0;
    report["live_local_asset_manifest"] = Json::array();
    for (const auto& asset : live_assets)
        report["live_local_asset_manifest"].push_back(phase20_asset_json(asset, "protected"));
    if (!checkpoint("LIVE_CORPUS_READY", "PREPARING")) return false;

    // Preparation is resumable from the local encrypted manifest; existing remote
    // IDs are re-hashed and only missing IDs are sent in a batch.
    for (std::size_t row_index = 0; row_index < plan.size(); ++row_index) {
        auto& row = report["scenarios"][row_index];
        if (strict_revision) {
            const auto current_head = current_git_head();
            if (current_head != initial_git_head) {
                row["git_head_observed_before_scenario"] = current_head.empty() ?
                    Json{"NOT_MEASURED"} : Json{current_head};
                event("GIT_HEAD_CHANGED", row.value("scenario", "NOT_MEASURED"),
                      {{"expected", initial_git_head}, {"observed", row["git_head_observed_before_scenario"]}});
                return fail("INTERRUPTED_HEAD_CHANGED", "GIT_HEAD_CHANGED",
                            "repository HEAD changed during the Phase 22 series", row_index);
            }
        }
        const auto scenario = row.at("scenario").get<std::string>();
        const auto scenario_start = Clock::now();
        const auto candidate_count = plan[row_index].second;
        if (row.value("status", "") == "PASS_CLEANED") continue;
        if (row.value("full_gc_runs", 0) != 0) {
            return fail("INTERRUPTED", row.value("last_confirmed_stage", "GC_COMPLETE"),
                        "this fixture already has a measured GC; no second GC is allowed", row_index);
        }
        row["status"] = "PREPARING";
        row["last_confirmed_stage"] = "FIXTURE_PREPARATION";
        const auto remote_path = row.at("remote_path").get<std::string>();
        const auto local_fixture = local_root / scenario;
        std::filesystem::create_directories(local_fixture, ec);
        if (ec) return fail("FAILED", "LOCAL_FIXTURE_SETUP", "cannot create fixture workspace", row_index);

        std::vector<Phase20Asset> candidates;
        std::vector<std::string> candidate_ids;
        std::set<std::string> unique_ids(live_ids.begin(), live_ids.end());
        for (std::size_t i = 0; i < candidate_count; ++i) {
            auto asset = phase20_prepare_asset(run_id, "orphan-" + scenario, i,
                                               artifacts / "prepared" / scenario, key);
            if (!asset || !unique_ids.insert(asset->id).second) {
                return fail("FAILED", "CANDIDATE_PREPARATION",
                            "candidate content ID duplicates protected/other candidate data", row_index);
            }
            candidate_ids.push_back(asset->id);
            candidates.push_back(std::move(*asset));
        }
        std::ranges::sort(candidate_ids);
        auto commit = kasumi::history::make_commit(
            0, {}, tree, report.at("commit_unix_seconds").get<std::int64_t>());
        if (!commit) return fail("FAILED", "COMMIT_PREPARATION", "production commit creation failed", row_index);
        auto canonical = kasumi::history::serialize(*commit);
        if (!canonical) return fail("FAILED", "COMMIT_PREPARATION", "commit serialization failed", row_index);
        const auto logical_commit_id = kasumi::crypto::commit_identifier(key, *canonical);
        Json asset_manifest = Json::array();
        for (const auto& asset : live_assets) asset_manifest.push_back(phase20_asset_json(asset, "protected"));
        for (const auto& asset : candidates) asset_manifest.push_back(phase20_asset_json(asset, "orphan_candidate"));
        row["manifest"] = asset_manifest;
        row["protected_ids"] = string_array(live_ids);
        row["candidate_ids"] = string_array(candidate_ids);
        row["planned"] = {{"F", live_count}, {"N_live", live_count}, {"C", candidate_count},
            {"N_total_content", live_count + candidate_count}, {"P", 1}, {"R", 1},
            {"E", 0}, {"A", 0}};
        if (!event("FIXTURE_MANIFEST_READY", scenario,
                   {{"remote_path", remote_path}, {"F", live_count}, {"N_live", live_count},
                    {"C", candidate_count}, {"protected_ids", string_array(live_ids)},
                    {"candidate_ids", string_array(candidate_ids)}}) ||
            !write_json(artifacts / (scenario + ".manifest.json"), Json{
                {"run_id", run_id}, {"scenario", scenario}, {"remote_path", remote_path},
                {"F", live_count}, {"N_live", live_count}, {"C_expected", candidate_count},
                {"protected_ids", string_array(live_ids)},
                {"candidate_ids", string_array(candidate_ids)}, {"assets", asset_manifest}}) ||
            !checkpoint("FIXTURE_MANIFEST_READY", "PREPARING", scenario)) return false;

        auto opened = kasumi::transport::open_transport(remote_path);
        if (!opened || !kasumi::transport::initialize(*opened))
            return fail("REMOTE_NOT_RUN", "FIXTURE_TRANSPORT", "could not initialize exact fixture transport", row_index);
        auto& storage = *opened;
        if (!storage.storage.put_batch || !storage.storage.physical_hash_batch ||
            (phase_batch && !storage.storage.copy_batch) ||
            (phase24 && !storage.storage.put_files_batch))
            return fail("REMOTE_NOT_RUN", "TRANSPORT_CAPABILITIES", "safe batch upload/hash verification unavailable", row_index);
        const auto initial = kasumi::transport::list(storage);
        if (!initial && initial.error().code != kasumi::transport::ErrorCode::StorageNotFound)
            return fail("REMOTE_NOT_RUN", "FIXTURE_INVENTORY", "could not read exact fixture inventory", row_index);
        if (!resume && initial && !initial->empty()) {
            row["unexpected_initial_inventory"] = string_array(sorted(*initial));
            return fail("REMOTE_NOT_RUN", "FIXTURE_NOT_EMPTY", "new fixture namespace is not empty", row_index);
        }

        std::vector<Phase20Asset*> all_content;
        all_content.reserve(live_assets.size() + candidates.size());
        for (auto& asset : live_assets) all_content.push_back(&asset);
        for (auto& asset : candidates) all_content.push_back(&asset);
        std::set<std::string> expected_content;
        for (const auto* asset : all_content) expected_content.insert(asset->id);
        const auto validate_partial_inventory = [&](std::span<const std::string> actual) {
            std::set<std::string> seen_commits, seen_markers;
            for (const auto& id : actual) {
                if (expected_content.contains(id)) continue;
                if (id.starts_with(layout.commits_prefix)) {
                    const auto ref = history_storage::parse_commit_object(layout, id);
                    if (!ref || ref->commit_id != logical_commit_id ||
                        !seen_commits.insert(id).second) return false;
                    continue;
                }
                if (id.starts_with(layout.heads_prefix)) {
                    const auto ref = history_storage::parse_marker_object(layout, id);
                    if (!ref || ref->commit_id != logical_commit_id ||
                        !seen_markers.insert(id).second) return false;
                    continue;
                }
                return false;
            }
            if (seen_commits.size() > 1 || seen_markers.size() > 1) return false;
            if (!seen_markers.empty()) {
                const auto ref = history_storage::parse_marker_object(layout, *seen_markers.begin());
                if (!ref || !seen_commits.contains(history_storage::commit_object(layout, *ref))) return false;
            }
            return true;
        };
        auto inventory = kasumi::transport::list(storage);
        std::vector<std::string> present;
        if (inventory) present = *inventory;
        else if (inventory.error().code != kasumi::transport::ErrorCode::StorageNotFound)
            return fail("FAILED_PRESERVED", "FIXTURE_RESUME_INVENTORY", "remote inventory query failed", row_index);
        if (!validate_partial_inventory(present)) {
            row["unexpected_inventory"] = string_array(sorted(present));
            return fail("FAILED_PRESERVED", "FIXTURE_RESUME_INVENTORY", "unknown object or control object in exact fixture", row_index);
        }
        std::set<std::string> confirmed;
        for (const auto& id : present) if (expected_content.contains(id)) confirmed.insert(id);
        const auto verify_ids = [&](const std::vector<Phase20Asset*>& assets) -> bool {
            if (assets.empty()) return true;
            std::filesystem::create_directories(local_fixture / "physical-hash", ec);
            if (ec) return false;
            std::vector<kasumi::transport::PhysicalHashExpectation> expected;
            for (const auto* asset : assets)
                expected.push_back({asset->id, asset->ciphertext_sha256});
            auto checked = kasumi::transport::physical_hash_batch(
                storage, kasumi::transport::PhysicalHashBatchRequest{
                    .scratch_root = local_fixture / "physical-hash",
                    .objects = expected, .algorithm = "sha256"});
            if (expected.size() >= storage.storage.physical_hash_batch_min_objects) {
                if (!checked) {
                    row["last_physical_hash_batch_error"] = kasumi::transport::describe(checked.error());
                    return false;
                }
                row["last_physical_hash_batch_result"] = {{"matched", string_array(sorted(checked->matched))},
                    {"mismatched", string_array(checked->mismatched)},
                    {"missing", string_array(checked->missing)},
                    {"errors", string_array(checked->errors)}};
                return checked->mismatched.empty() && checked->missing.empty() &&
                    checked->errors.empty() && sorted(checked->matched) ==
                    sorted([&] { std::vector<std::string> ids; for (const auto* a : assets) ids.push_back(a->id); return ids; }());
            }
            for (const auto* asset : assets) {
                auto hash = kasumi::transport::physical_hash(storage, asset->id, "sha256");
                if (!hash || *hash != asset->ciphertext_sha256) return false;
            }
            return true;
        };
        std::vector<Phase20Asset*> previously_present;
        for (auto* asset : all_content) if (confirmed.contains(asset->id)) previously_present.push_back(asset);
        if (!verify_ids(previously_present))
            return fail("FAILED_PRESERVED", "FIXTURE_RESUME_HASHES", "existing remote objects do not match the persistent local manifest", row_index);
        row["uploads_already_present_and_verified"] = confirmed.size();
        for (const auto* asset : previously_present) {
            if (!event("OBJECT_UPLOAD_CONFIRMED", scenario, {{"id", asset->id},
                    {"state", "ALREADY_PRESENT"}, {"remote_sha256_confirmed", true},
                    {"retry_count", "NOT_MEASURED"}})) return false;
        }

        constexpr std::size_t upload_batch_size = 25;
        constexpr std::size_t upload_transfers = 4;
        for (std::size_t begin = 0; begin < all_content.size(); begin += upload_batch_size) {
            std::vector<Phase20Asset*> pending;
            for (std::size_t i = begin; i < std::min(begin + upload_batch_size, all_content.size()); ++i)
                if (!confirmed.contains(all_content[i]->id)) pending.push_back(all_content[i]);
            if (pending.empty()) continue;
            const auto attempt_id = kasumi::platform::random::hex_id(4);
            if (!attempt_id) return fail("FAILED_PRESERVED", "CONTENT_STAGING", "could not generate isolated batch staging ID", row_index);
            const auto batch_root = local_fixture / "batches" /
                ("batch-" + pad_index(begin) + "-" + *attempt_id);
            std::filesystem::create_directories(batch_root, ec);
            if (ec) return fail("FAILED_PRESERVED", "CONTENT_STAGING", "could not stage upload batch", row_index);
            std::vector<std::string> batch_ids;
            for (auto* asset : pending) {
                std::filesystem::copy_file(asset->encrypted_path, batch_root / asset->id,
                    std::filesystem::copy_options::overwrite_existing, ec);
                if (ec) return fail("FAILED_PRESERVED", "CONTENT_STAGING", "could not stage encrypted object", row_index);
                batch_ids.push_back(asset->id);
            }
            for (auto* asset : pending) {
                if (!event("OBJECT_UPLOAD_PLANNED", scenario, {{"id", asset->id},
                        {"ciphertext_sha256", asset->ciphertext_sha256},
                        {"ciphertext_bytes", asset->ciphertext_size}, {"batch", batch_root.filename().string()}})) return false;
            }
            if (!event("BATCH_UPLOAD_INTENT", scenario,
                       {{"object_ids", string_array(batch_ids)}, {"max_parallel_transfers", upload_transfers}}) ||
                !checkpoint("BATCH_UPLOAD_IN_FLIGHT", "PREPARING", scenario)) return false;
            for (auto* asset : pending) {
                if (!event("OBJECT_UPLOAD_STARTED", scenario, {{"id", asset->id},
                        {"batch", batch_root.filename().string()}, {"retry_count", 0}})) return false;
            }
            auto uploaded = kasumi::transport::put_batch(storage,
                kasumi::transport::PutBatch{.source_root = batch_root,
                    .identifiers = batch_ids, .max_parallel_transfers = upload_transfers});
            if (!uploaded) {
                row["ambiguous_upload_result"] = kasumi::transport::mutation_result_is_ambiguous(uploaded.error());
                row["upload_error"] = kasumi::transport::describe(uploaded.error());
                event("BATCH_UPLOAD_ERROR", scenario, {{"object_ids", string_array(batch_ids)},
                    {"ambiguous", kasumi::transport::mutation_result_is_ambiguous(uploaded.error())},
                    {"error", kasumi::transport::describe(uploaded.error())}});
                for (auto* asset : pending) event("OBJECT_UPLOAD_ERROR", scenario, {{"id", asset->id},
                    {"stage", "put_batch"}, {"error", kasumi::transport::describe(uploaded.error())},
                    {"ambiguous", kasumi::transport::mutation_result_is_ambiguous(uploaded.error())},
                    {"retry_count", 0}});
                return fail("FAILED_PRESERVED", "CONTENT_UPLOAD", "batch upload failed; resume only after inventory/hash verification", row_index);
            }
            if (!verify_ids(pending)) {
                for (auto* asset : pending) event("OBJECT_UPLOAD_ERROR", scenario, {{"id", asset->id},
                    {"stage", "remote_sha256_confirmation"},
                    {"error", row.value("last_physical_hash_batch_error", "physical hash mismatch or incomplete response")},
                    {"retry_count", "NOT_MEASURED"}});
                return fail("FAILED_PRESERVED", "CONTENT_BATCH_HASH", "uploaded physical SHA-256 mismatch", row_index);
            }
            auto after_batch = kasumi::transport::list(storage);
            if (!after_batch || !validate_partial_inventory(*after_batch))
                return fail("FAILED_PRESERVED", "CONTENT_BATCH_INVENTORY", "post-upload fixture inventory is unavailable or contains unknown IDs", row_index);
            for (const auto& id : batch_ids) confirmed.insert(id);
            for (const auto& id : batch_ids)
                if (std::ranges::find(*after_batch, id) == after_batch->end())
                    return fail("FAILED_PRESERVED", "CONTENT_BATCH_INVENTORY", "uploaded ID is missing from exact inventory", row_index);
            if (!event("BATCH_UPLOAD_CONFIRMED", scenario,
                       {{"object_ids", string_array(batch_ids)}, {"verified_sha256", true}})) return false;
            for (auto* asset : pending) {
                if (!event("OBJECT_UPLOAD_CONFIRMED", scenario, {{"id", asset->id},
                        {"batch", batch_root.filename().string()},
                        {"remote_sha256_confirmed", true}, {"inventory_confirmed", true},
                        {"retry_count", "NOT_MEASURED"}})) return false;
            }
            row["uploads_confirmed"] = confirmed.size();
            if (!checkpoint("CONTENT_BATCH_VERIFIED", "PREPARING", scenario)) return false;
        }
        if (confirmed.size() != all_content.size())
            return fail("FAILED_PRESERVED", "CONTENT_UPLOAD", "not all content objects are present", row_index);

        if (!event("COMMIT_PUBLISH_INTENT", scenario,
                   {{"logical_commit_id", logical_commit_id}, {"commit_unix_seconds", report["commit_unix_seconds"]}}) ||
            !checkpoint("COMMIT_PUBLISH_IN_FLIGHT", "PREPARING", scenario)) return false;
        auto published = history_storage::publish_commit_object(
            storage, layout, key, *commit, local_fixture);
        if (!published) {
            row["commit_publish_error"] = published.error().detail;
            event("COMMIT_PUBLISH_ERROR", scenario, {{"message", published.error().detail}});
            return fail("FAILED_PRESERVED", "COMMIT_PUBLISH", "commit publication failed; do not retry an ambiguous commit intent", row_index);
        }
        const auto commit_id = history_storage::commit_object(layout, published->head);
        if (!event("COMMIT_PUBLISH_CONFIRMED", scenario,
                   {{"id", commit_id}, {"logical_commit_id", published->head.commit_id},
                    {"ciphertext_id", published->head.ciphertext_id},
                    {"reused_existing_ciphertext", published->reused_existing_ciphertext}})) return false;
        if (!event("HEAD_PUBLISH_INTENT", scenario, {{"commit_id", published->head.commit_id}}) ||
            !checkpoint("HEAD_PUBLISH_IN_FLIGHT", "PREPARING", scenario)) return false;
        auto marker = history_storage::publish_head_marker(
            storage, layout, published->head, local_fixture);
        if (!marker) {
            row["head_publish_error"] = marker.error().detail;
            return fail("FAILED_PRESERVED", "HEAD_PUBLISH", "HEAD marker publication failed", row_index);
        }
        const auto protected_marker = marker->marker_id;
        if (!event("HEAD_PUBLISH_CONFIRMED", scenario,
                   {{"id", protected_marker}, {"commit_id", published->head.commit_id}})) return false;
        row["commit_id"] = published->head.commit_id;
        row["commit_object_id"] = commit_id;
        row["head_marker_id"] = protected_marker;
        row["fixture_preparation_ms"] = elapsed_ms(scenario_start);
        row["preparation_seconds"] = static_cast<double>(row["fixture_preparation_ms"].get<std::uint64_t>()) / 1000.0;
        row["F"] = live_count;
        row["N_live"] = live_ids.size();
        row["N_orphan"] = candidate_ids.size();
        row["N_total_content"] = live_ids.size() + candidate_ids.size();
        row["P"] = 1;
        row["R"] = 1;
        row["E"] = 0;
        row["A"] = 0;
        row["C_expected"] = candidate_count;
        row["candidate_ciphertext_bytes"] = 0;
        row["candidate_ciphertext_sizes"] = Json::array();
        for (const auto& candidate : candidates) {
            row["candidate_ciphertext_bytes"] = row["candidate_ciphertext_bytes"].get<std::uint64_t>() + candidate.ciphertext_size;
            row["candidate_ciphertext_sizes"].push_back(candidate.ciphertext_size);
        }

        const auto pre_check_start = Clock::now();
        auto pre = kasumi::transport::list(storage);
        std::vector<std::string> expected_pre = live_ids;
        expected_pre.insert(expected_pre.end(), candidate_ids.begin(), candidate_ids.end());
        expected_pre.push_back(commit_id);
        expected_pre.push_back(protected_marker);
        Json pre_validation = Json::object();
        if (!pre || sorted(*pre) != sorted(expected_pre) ||
            !phase20_validate_fixture(storage, key, layout, *pre, live_ids,
                                      candidate_ids, local_fixture, published->head.commit_id,
                                      pre_validation)) {
            if (pre) row["pre_gc_inventory"] = string_array(sorted(*pre));
            row["pre_gc_validation"] = pre_validation;
            return fail("FAILED_PRESERVED", "PRE_GC_VALIDATION", "exact inventory, protected history, or C orphan validation failed", row_index);
        }
        row["pre_gc_validation"] = pre_validation;
        row["N_total_physical"] = pre->size();
        row["N_content"] = live_ids.size() + candidate_ids.size();
        row["quarantine_objects_preexisting"] = 0;
        row["quarantine_metadata_preexisting"] = 0;
        row["head_present_before_gc"] = std::ranges::find(*pre, protected_marker) != pre->end();
        row["commit_authenticated_before_gc"] = pre_validation.value("history_valid", false);
        row["protected_references_before_gc"] = pre_validation.value("N_live", std::size_t{0});
        row["candidate_objects_unreferenced_before_gc"] = pre_validation.value("N_orphan", std::size_t{0});
        row["pre_gc_inventory"] = string_array(sorted(*pre));
        row["pre_gc_validation_ms"] = elapsed_ms(pre_check_start);
        auto size = remote_size(remote_path);
        if (!size || !size->contains("count") || !size->contains("bytes") ||
            size->at("count").get<std::size_t>() != pre->size())
            return fail("FAILED_PRESERVED", "PRE_GC_REMOTE_SIZE", "rclone size could not confirm exact fixture count", row_index);
        row["pre_gc_remote_bytes"] = size->at("bytes");
        row["pre_gc_remote_size_count"] = size->at("count");
        const auto commit_local = local_fixture / "commit.check.enc";
        auto commit_get = kasumi::transport::get(storage, commit_id, commit_local);
        row["commit_encrypted_bytes"] = commit_get ?
            Json{std::filesystem::file_size(commit_local, ec)} : Json{"NOT_MEASURED"};
        if (strict_revision && (!commit_get || ec))
            return fail("FAILED_PRESERVED", "PRE_GC_COMMIT_SIZE",
                        "commit could not be downloaded and sized before the single GC", row_index);
        row["rclone_calls_gc_only"] = "counts are recorded from perf_trace inside the measured GC call";
        row["retry_policy_gc_transport"] = {{"mutating_rc_retries", 0},
            {"read_attempts_max", 2}, {"read_retry_delay_ms", 75},
            {"drive_api_request_count", "NOT_MEASURED"}};
        if (!write_json(artifacts / (scenario + ".pre-gc.json"), Json{
                {"remote_path", remote_path}, {"F", live_count}, {"N_live", live_count},
                {"N_orphan", candidate_count}, {"N_total_content", live_count + candidate_count},
                {"P", 1}, {"R", 1}, {"E", 0}, {"A", 0},
                {"C_expected", candidate_count}, {"N_total_physical", pre->size()},
                {"remote_bytes", size->at("bytes")}, {"inventory", string_array(sorted(*pre))},
                {"validation", pre_validation}}) ||
            !checkpoint("PRE_GC_VALIDATION_COMPLETE", "READY_FOR_GC", scenario) ||
            !event("PRE_GC_VALIDATED", scenario, {{"F", live_count}, {"N_live", live_count},
                {"N_orphan", candidate_count}, {"N_total_content", live_count + candidate_count},
                {"P", 1}, {"R", 1}, {"E", 0}, {"A", 0}, {"C", candidate_count},
                {"N_total_physical", pre->size()}, {"remote_bytes", size->at("bytes")}})) return false;

        if (!write_json(artifacts / (scenario + ".manifest.json"), Json{
                {"run_id", run_id}, {"scenario", scenario}, {"remote_path", remote_path},
                {"F", live_count}, {"N_live", live_count}, {"C_expected", candidate_count},
                {"P", 1}, {"R", 1}, {"E", 0}, {"A", 0},
                {"C_ids", string_array(candidate_ids)}, {"protected_ids", string_array(live_ids)},
                {"commit_object_id", commit_id}, {"head_marker_id", protected_marker},
                {"assets", asset_manifest}})) return false;
        auto active = kasumi::application::history_storage::maintenance_protocol::active_writers(storage, layout);
        if (!active || !active->empty()) {
            row["active_writers"] = active ? string_array(*active) : Json{active.error().detail};
            return fail("FAILED_PRESERVED", "WRITER_PREFLIGHT", "active writer state is not empty/confirmed", row_index);
        }
        const auto runtime_root = local_fixture / "gc-runtime";
        kasumi::runtime::RuntimeData runtime{
            .local_dir = runtime_root / "local",
            .database_path = runtime_root / "profile" / "db.sqlite",
            .key_path = runtime_root / "profile" / "key.bin",
            .storage_location = remote_path,
        };
        std::filesystem::create_directories(runtime.local_dir, ec);
        std::filesystem::create_directories(runtime.database_path.parent_path(), ec);
        if (ec) return fail("FAILED_PRESERVED", "GC_LOCAL_SETUP", "cannot create isolated runtime workspace", row_index);
        Traffic traffic;
        traffic.stage = "garbage_collect";
        auto counted = make_counted_transport(storage, traffic, layout);
        if (row.value("full_gc_runs", 0) != 0)
            return fail("INTERRUPTED", "GC_ALREADY_STARTED", "a fixture may receive only one measured GC", row_index);
        if (strict_revision) {
            const auto current_head = current_git_head();
            row["git_head_before_gc"] = current_head.empty() ? Json{"NOT_MEASURED"} : Json{current_head};
            if (current_head != initial_git_head) {
                event("GIT_HEAD_CHANGED", scenario,
                      {{"expected", initial_git_head}, {"observed", row["git_head_before_gc"]}});
                return fail("INTERRUPTED_HEAD_CHANGED", "GIT_HEAD_CHANGED_BEFORE_GC",
                            "repository HEAD changed before this scenario's GC", row_index);
            }
        }
        if (!event("GC_STARTED", scenario, {{"remote_path", remote_path},
                {"runtime_storage_location", runtime.storage_location}, {"prior_full_gc_count", 0}}) ||
            !checkpoint("GC_IN_FLIGHT", "GC_RUNNING", scenario)) return false;
        row["full_gc_runs"] = 1;
        kasumi::platform::perf_trace::force_enable(true);
        kasumi::platform::perf_trace::reset();
        traffic.gc_started_at = Clock::now();
        const auto gc_start = traffic.gc_started_at;
        const auto gc_stdout_path = artifacts / (scenario + ".gc.stdout.log");
        const auto gc_stderr_path = artifacts / (scenario + ".gc.stderr.log");
        std::ofstream gc_stdout(gc_stdout_path, std::ios::binary | std::ios::trunc);
        std::ofstream gc_stderr(gc_stderr_path, std::ios::binary | std::ios::trunc);
        const auto old_out = std::cout.rdbuf(gc_stdout.rdbuf());
        const auto old_err = std::cerr.rdbuf(gc_stderr.rdbuf());
        auto collected = kasumi::application::integrity::garbage_collect(
            runtime, counted, key, phase_batch ? copy_concurrency : 8,
            phase24 ? metadata_concurrency : 8);
        const auto gc_end = Clock::now();
        const auto git_head_after_gc = strict_revision ? current_git_head() : std::string{};
        auto gc_times = phase_times_json();
        gc_times["candidate_selection_total_us"] =
            gc_times["observation_1"]["candidate_selection_us"].get<std::uint64_t>() +
            gc_times["observation_2"]["candidate_selection_us"].get<std::uint64_t>();
        auto gc_counters = phase20_gc_counters_json();
        if (phase24)
            normalize_phase24_shared_batch_counters(gc_counters, candidate_count);
        kasumi::platform::perf_trace::report(collected ? "success" : "failure");
        kasumi::platform::perf_trace::force_enable(false);
        std::cout.rdbuf(old_out);
        std::cerr.rdbuf(old_err);
        gc_stdout.flush(); gc_stderr.flush();
        const auto gc_wall_us = std::chrono::duration_cast<std::chrono::microseconds>(gc_end - gc_start).count();
        row["observed_rate_limit_errors"] = 0;
        row["expected_optional_prefix_not_found_errors"] = 0;
        row["unexpected_transport_errors"] = 0;
        for (auto& error : traffic.error_events) {
            error["gc_returned_success"] = static_cast<bool>(collected);
            error["recovery_detail"] = "retry/recovery is reported only where the RC trace or error context exposes it";
            error["retry_count"] = "NOT_MEASURED_PER_ERROR";
            const auto message = error.value("message", "");
            const bool rate_limited = error.value("native_code", 0) == 429 ||
                message.find("429") != std::string::npos ||
                message.find("rate limit") != std::string::npos || message.find("quota") != std::string::npos;
            const bool optional_prefix_absent =
                error.value("error_code", "") == "storage_not_found" &&
                error.value("operation", "") == "list_prefix";
            error["classification"] = optional_prefix_absent ?
                "EXPECTED_EMPTY_OPTIONAL_PREFIX" : "TRANSPORT_ERROR";
            if (optional_prefix_absent) {
                row["expected_optional_prefix_not_found_errors"] =
                    row["expected_optional_prefix_not_found_errors"].get<std::size_t>() + 1;
            } else {
                row["unexpected_transport_errors"] =
                    row["unexpected_transport_errors"].get<std::size_t>() + 1;
            }
            if (rate_limited)
                row["observed_rate_limit_errors"] =
                    row["observed_rate_limit_errors"].get<int>() + 1;
        }
        row["rate_limit_count"] = row["observed_rate_limit_errors"].get<int>() > 0 ?
            Json{row["observed_rate_limit_errors"]} : Json{"NOT_MEASURED"};
        row["gc_wall_us"] = gc_wall_us;
        row["gc_wall_seconds"] = static_cast<double>(gc_wall_us) / 1'000'000.0;
        row["gc_phase_times"] = gc_times;
        row["gc_counters"] = gc_counters;
        row["physical_hash_batch_min_objects"] = storage.storage.physical_hash_batch_min_objects;
        row["physical_hash_batch_calls"] = traffic.physical_hash_batch_calls;
        row["batch_verification_strategy"] = candidate_count < storage.storage.physical_hash_batch_min_objects ?
            "individual_destination_hash_below_backend_threshold" :
            (gc_counters["gc.batch_verify_supported"].get<std::uint64_t>() > 0 ?
                "physical_hash_batch_used; short tails may use individual destination hashes" :
                "no_supported_batch_verification_observed");
        auto gc_traffic = traffic_json(traffic);
        gc_traffic["rclone_rc_call_count"] = gc_counters["rc.http_requests_attempted"];
        gc_traffic["retry_count"] = gc_counters["RC idempotent read retries"];
        gc_traffic["rate_limit_count"] = row["rate_limit_count"];
        row["gc_transport"] = gc_traffic;
        row["retry_count"] = gc_counters["RC idempotent read retries"];
        row["git_head_after_gc"] = strict_revision ?
            (git_head_after_gc.empty() ? Json{"NOT_MEASURED"} : Json{git_head_after_gc}) :
            Json{"NOT_MEASURED"};
        row["phase_spans_may_overlap"] = true;
        row["gc_stdout"] = gc_stdout_path.string();
        row["gc_stderr"] = gc_stderr_path.string();
        row["time_to_identify_candidates_us"] = "NOT_MEASURED";
        row["time_to_first_quarantine_copy_us"] = traffic.first_quarantine_copy_us ? Json{traffic.first_quarantine_copy_us} : Json{"NOT_MEASURED"};
        row["time_to_first_candidate_source_remove_us"] = traffic.first_content_remove_us ? Json{traffic.first_content_remove_us} : Json{"NOT_MEASURED"};
        row["full_gc_runs"] = 1;
        if (!write_json(artifacts / (scenario + ".gc-metrics.json"), Json{
                {"gc_wall_us", gc_wall_us}, {"phase_times", gc_times},
                {"counters", gc_counters}, {"transport", traffic_json(traffic)},
                {"result", collected ? "SUCCESS" : kasumi::application::integrity::describe(collected.error())}})) return false;
        if (strict_revision && git_head_after_gc != initial_git_head) {
            event("GIT_HEAD_CHANGED", scenario,
                  {{"expected", initial_git_head}, {"observed", row["git_head_after_gc"]}});
            return fail("INTERRUPTED_HEAD_CHANGED", "GIT_HEAD_CHANGED_DURING_GC",
                        "repository HEAD changed while this GC was running; fixture preserved", row_index);
        }
        if (!collected) {
            row["gc_error"] = kasumi::application::integrity::describe(collected.error());
            event("GC_FAILED", scenario, {{"error", row["gc_error"]}});
            return fail("FAILED", "GC_FAILED", "the single real GC failed; fixture preserved and next scenarios stopped", row_index);
        }
        if (phase_batch) {
            const auto counter = [&](const char* name) {
                return gc_counters.value(name, std::uint64_t{0});
            };
            const auto expected_batches = (candidate_count + 7) / 8;
            const auto job_batch_calls = gc_counters["rc_requests_by_endpoint"].value(
                "job/batch", std::uint64_t{0});
            const bool batch_valid =
                traffic.copy_batch_calls == expected_batches &&
                traffic.copy_batch_inputs == candidate_count &&
                traffic.copy_batch_concurrency == copy_concurrency &&
                counter("gc.copy_batch_calls") == expected_batches &&
                counter("gc.copy_batch_inputs") == candidate_count &&
                counter("rclone.copy_batch_inputs_submitted") == candidate_count &&
                counter("rclone.copy_batch_concurrency_submitted") ==
                    expected_batches * copy_concurrency &&
                counter("rclone.copy_batch_reported_successes") == candidate_count &&
                counter("rclone.copy_batch_partial_responses") == 0 &&
                counter("gc.copy_batch_errors") == 0 &&
                counter("gc.copy_batch_ambiguous") == 0 &&
                counter("gc.copy_batch_unsupported") == 0 &&
                counter("gc.fallback_copy_attempts") == 0 &&
                counter("gc.source_physical_hash_calls") == candidate_count &&
                counter("gc.candidates_verified") == candidate_count &&
                traffic.physical_hash_batch_calls > 0 &&
                counter("content batch verify objects") +
                    counter("gc.individual_destination_hash_attempts") == candidate_count &&
                counter("gc.metadata_publications") == candidate_count &&
                counter("gc.pre_remove_barrier_verifications") == candidate_count &&
                counter("gc.source_removals") == candidate_count &&
                counter("gc.candidates_quarantined") == candidate_count &&
                job_batch_calls >= expected_batches &&
                row["unexpected_transport_errors"].get<std::size_t>() == 0 &&
                row["observed_rate_limit_errors"].get<std::size_t>() == 0;
            row["copy_batch_validation"] = {
                {"passed", batch_valid}, {"copy_batch_calls", traffic.copy_batch_calls},
                {"expected_copy_batch_calls", expected_batches},
                {"copyfile_inputs", counter("rclone.copy_batch_inputs_submitted")},
                {"copyfile_result_successes", counter("rclone.copy_batch_reported_successes")},
                {"copy_concurrency", traffic.copy_batch_concurrency},
                {"job_batch_rc_calls_including_control_reads", job_batch_calls},
                {"source_physical_hash_calls", counter("gc.source_physical_hash_calls")},
                {"destination_hash_batch_calls", counter("gc.batch_verify_attempts")},
                {"destination_batch_verified_objects", counter("content batch verify objects")},
                {"destination_individual_verified_objects", counter("gc.individual_destination_hash_attempts")},
                {"destination_verified_objects", counter("content batch verify objects") +
                    counter("gc.individual_destination_hash_attempts")},
                {"metadata_publications", counter("gc.metadata_publications")},
                {"pre_remove_barrier_verifications", counter("gc.pre_remove_barrier_verifications")},
                {"source_removals", counter("gc.source_removals")},
                {"fallback_copy_attempts", counter("gc.fallback_copy_attempts")},
                {"copy_batch_errors", counter("gc.copy_batch_errors")},
                {"partial_responses", counter("rclone.copy_batch_partial_responses")},
                {"unexpected_transport_errors", row["unexpected_transport_errors"]}};
            if (!batch_valid)
                return fail("FAILED", "COPY_BATCH_VALIDATION",
                            "the GC completed without the required copy_batch evidence", row_index);
            if (phase24) {
                const auto metadata_calls = counter("gc.metadata_batch_calls");
                const auto metadata_inputs = counter("rclone.put_files_batch_inputs_submitted");
                const auto metadata_reported =
                    counter("rclone.put_files_batch_reported_successes");
                const auto metadata_hash_batches =
                    counter("gc.metadata_physical_hash_batch_calls");
                const auto metadata_batch_valid =
                    traffic.metadata_batch_calls == expected_batches &&
                    traffic.metadata_batch_objects == candidate_count &&
                    traffic.metadata_batch_concurrency == metadata_concurrency &&
                    metadata_calls == expected_batches &&
                    counter("gc.metadata_objects_submitted") == candidate_count &&
                    counter("gc.metadata_concurrency") ==
                        expected_batches * metadata_concurrency &&
                    metadata_inputs == candidate_count &&
                    metadata_reported == candidate_count &&
                    counter("gc.metadata_prepared") == candidate_count &&
                    counter("gc.metadata_encode") == candidate_count &&
                    counter("gc.metadata_encryption") == candidate_count &&
                    counter("gc.metadata_local_hash") == candidate_count &&
                    counter("gc.metadata_publications") == candidate_count &&
                    counter("gc.metadata_verified") == candidate_count &&
                    counter("gc.metadata_publication_failures") == 0 &&
                    counter("rclone.put_files_batch_failures") == 0 &&
                    counter("rclone.put_files_batch_transport_errors") == 0 &&
                    metadata_hash_batches == candidate_count / 8 &&
                    counter("gc.pre_copy_barrier_verifications") == candidate_count &&
                    counter("gc.pre_batch_copy_barrier_verifications") == expected_batches &&
                    counter("gc.post_copy_barrier_verifications") == expected_batches &&
                    counter("gc.barrier_release_owner_verifications") == 1 &&
                    counter("gc.pre_remove_barrier_verifications") == candidate_count &&
                    counter("gc.source_removals") == candidate_count &&
                    counter("gc.candidates_quarantined") == candidate_count &&
                    gc_counters["rc_requests_by_endpoint"].value(
                        "sync/copy", std::uint64_t{0}) == 0;
                row["metadata_batch_validation"] = {
                    {"passed", metadata_batch_valid},
                    {"metadata_batch_calls", metadata_calls},
                    {"expected_metadata_batch_calls", expected_batches},
                    {"metadata_objects_submitted", metadata_inputs},
                    {"metadata_concurrency", traffic.metadata_batch_concurrency},
                    {"metadata_prepared", counter("gc.metadata_prepared")},
                    {"metadata_published", metadata_reported},
                    {"metadata_physical_hash_batch_calls", metadata_hash_batches},
                    {"metadata_verified", counter("gc.metadata_verified")},
                    {"publication_failures", counter("gc.metadata_publication_failures")},
                    {"pre_copy_barrier_verifications", counter("gc.pre_copy_barrier_verifications")},
                    {"pre_batch_copy_barrier_verifications", counter("gc.pre_batch_copy_barrier_verifications")},
                    {"post_copy_barrier_verifications", counter("gc.post_copy_barrier_verifications")},
                    {"pre_remove_barrier_verifications", counter("gc.pre_remove_barrier_verifications")},
                    {"barrier_verification_calls",
                     counter("gc.pre_copy_barrier_verifications") +
                     counter("gc.pre_batch_copy_barrier_verifications") +
                     counter("gc.pre_fallback_copy_barrier_verifications") +
                     counter("gc.post_copy_barrier_verifications") +
                     counter("gc.barrier_release_owner_verifications") +
                     counter("gc.pre_remove_barrier_verifications")},
                    {"source_removals", counter("gc.source_removals")},
                    {"sync_copy_requests_during_gc",
                     gc_counters["rc_requests_by_endpoint"].value("sync/copy", std::uint64_t{0})}};
                if (!metadata_batch_valid)
                    return fail("FAILED", "METADATA_BATCH_VALIDATION",
                                "the GC did not provide complete metadata batch publication and verification evidence", row_index);
            }
        }
        row["C_effective"] = collected->candidate_objects;
        row["candidates_quarantined"] = collected->quarantined_objects;
        row["objects_restored"] = collected->restored_objects;
        row["objects_purged"] = collected->purged_objects;
        if (collected->candidate_objects != candidate_count ||
            collected->quarantined_objects != candidate_count ||
            collected->restored_objects != 0 || collected->purged_objects != 0) {
            event("GC_INVARIANT_FAILED", scenario, {{"C_expected", candidate_count},
                {"C_effective", collected->candidate_objects},
                {"quarantined", collected->quarantined_objects},
                {"restored", collected->restored_objects}, {"purged", collected->purged_objects}});
            return fail("FAILED", "GC_CANDIDATE_COUNT", "effective GC candidate/quarantine counters differ from the planned content orphan count", row_index);
        }
        if (!event("GC_COMPLETE", scenario, {{"gc_wall_us", gc_wall_us},
                {"C_effective", collected->candidate_objects},
                {"quarantined", collected->quarantined_objects},
                {"restored", collected->restored_objects}, {"purged", collected->purged_objects}}) ||
            !checkpoint("GC_COMPLETE", "POST_GC_VALIDATING", scenario)) return false;

        const auto post_start = Clock::now();
        auto post = kasumi::transport::list(storage);
        if (!post) return fail("FAILED", "POST_GC_INVENTORY", "post-GC fixture listing failed", row_index);
        auto quarantine = kasumi::application::history_storage::maintenance_protocol::inventory_quarantine(
            storage, key, *post, local_fixture);
        if (!quarantine || quarantine->size() != candidate_count)
            return fail("FAILED", "QUARANTINE_INVENTORY", "quarantine entry count does not equal C", row_index);
        std::vector<std::string> qids, metadata_ids, originals;
        Json candidate_states = Json::array();
        bool qvalid = true;
        const auto quarantine_verify_start = Clock::now();
        for (const auto& entry : *quarantine) {
            qids.push_back(entry.quarantine_identifier);
            metadata_ids.push_back(entry.metadata_identifier);
            originals.push_back(entry.original_identifier);
            const auto verified = kasumi::application::history_storage::maintenance_protocol::verify_quarantine(
                storage, entry, local_fixture);
            if (!verified || !*verified) qvalid = false;
            candidate_states.push_back({{"original_id", entry.original_identifier},
                {"quarantine_id", entry.quarantine_identifier},
                {"metadata_id", entry.metadata_identifier},
                {"quarantined_at", entry.quarantined_at ? Json{*entry.quarantined_at} : Json{"NOT_MEASURED"}},
                {"physical_sha256", entry.physical_sha256},
                {"source_present", std::ranges::find(*post, entry.original_identifier) != post->end()},
                {"quarantine_present", std::ranges::find(*post, entry.quarantine_identifier) != post->end()},
                {"metadata_present", std::ranges::find(*post, entry.metadata_identifier) != post->end()},
                {"verification", verified ? (*verified ? "PASS" : "HASH_MISMATCH") : entry.original_identifier + ": " + verified.error().detail},
                {"definitively_purged", false}});
        }
        std::vector<std::string> expected_post = live_ids;
        expected_post.push_back(commit_id);
        expected_post.push_back(protected_marker);
        expected_post.insert(expected_post.end(), qids.begin(), qids.end());
        expected_post.insert(expected_post.end(), metadata_ids.begin(), metadata_ids.end());
        Json post_validation = Json::object();
        const bool post_history = sorted(*post) == sorted(expected_post) &&
            sorted(originals) == sorted(candidate_ids) && qvalid &&
            phase20_validate_fixture(storage, key, layout, *post, live_ids, {},
                                     local_fixture, published->head.commit_id, post_validation);
        if (!post_history) {
            row["post_gc_inventory"] = string_array(sorted(*post));
            row["post_gc_validation"] = post_validation;
            row["candidate_quarantine_manifest"] = candidate_states;
            return fail("FAILED", "POST_GC_INTEGRITY", "protected history/content or candidate quarantine verification failed", row_index);
        }
        std::vector<std::string> samples;
        for (std::size_t i = 0; i < 10; ++i)
            samples.push_back(sorted(live_ids)[i * (live_ids.size() - 1) / 9]);
        std::size_t samples_verified = 0;
        if (!verify_content_samples(storage, key, local_fixture, samples, live_info, samples_verified) || samples_verified != 10)
            return fail("FAILED", "POST_GC_CONTENT_SAMPLE", "deterministic protected content sample failed", row_index);
        row["post_gc_validation"] = post_validation;
        row["post_gc_inventory"] = string_array(sorted(*post));
        row["candidate_quarantine_manifest"] = candidate_states;
        row["quarantine_object_ids"] = string_array(sorted(qids));
        row["quarantine_metadata_ids"] = string_array(sorted(metadata_ids));
        row["post_gc_sample_ids"] = string_array(samples);
        row["post_gc_sample_count"] = samples_verified;
        row["post_gc_sample_criterion"] = "10 evenly spaced sorted protected IDs; GET, decrypt, plaintext hash/size, and content ID verified";
        row["integrity"] = "PASS";
        row["post_gc_validation_ms"] = elapsed_ms(post_start);
        row["quarantine_verification_ms"] = elapsed_ms(quarantine_verify_start);
        auto post_size = remote_size(remote_path);
        if (!post_size || post_size->at("count").get<std::size_t>() != post->size())
            return fail("FAILED", "POST_GC_SIZE", "post-GC rclone size count mismatch", row_index);
        row["post_gc_remote_bytes"] = post_size->at("bytes");
        if (!write_json(artifacts / (scenario + ".post-gc.json"), Json{
                {"remote_path", remote_path}, {"inventory", string_array(sorted(*post))},
                {"validation", post_validation}, {"quarantine", candidate_states},
                {"samples", string_array(samples)}, {"integrity", "PASS"}}) ||
            !event("POST_GC_INTEGRITY_PASS", scenario,
                {{"protected_content_count", live_ids.size()}, {"sample_count", samples_verified},
                 {"quarantine_count", quarantine->size()}, {"unexpected_ids", 0}})) return false;

        // Cleanup owns only the exact pre-GC manifest and authenticated quarantine entries.
        std::vector<std::string> cleanup_ids = expected_post;
        std::ranges::sort(cleanup_ids);
        cleanup_ids.erase(std::ranges::unique(cleanup_ids).begin(), cleanup_ids.end());
        auto before_cleanup = kasumi::transport::list(storage);
        if (!before_cleanup || sorted(*before_cleanup) != cleanup_ids)
            return fail("PASS_WITH_REMAINS", "CLEANUP_OWNERSHIP_CHECK", "exact inventory no longer matches owned manifest; preserve fixture", row_index);
        row["cleanup_manifest"] = string_array(cleanup_ids);
        if (!write_json(artifacts / (scenario + ".cleanup.json"), Json{
                {"remote_path", remote_path}, {"owned_ids", string_array(cleanup_ids)},
                {"quarantine_ids", string_array(sorted(qids))},
                {"metadata_ids", string_array(sorted(metadata_ids))},
                {"recursive_delete", false}, {"status", "CLEANUP_READY"}}) ||
            !checkpoint("CLEANUP_IN_FLIGHT", "CLEANING", scenario) ||
            !event("CLEANUP_STARTED", scenario, {{"owned_object_count", cleanup_ids.size()}})) return false;
        const auto cleanup_start = Clock::now();
        std::vector<std::string> removed;
        for (const auto& id : cleanup_ids) {
            if (!event("REMOVE_INTENT", scenario, {{"id", id}, {"remote_path", remote_path + "/" + id}})) return false;
            auto result = kasumi::transport::remove(storage, id);
            if (!result || *result != kasumi::transport::Removal::Removed) {
                row["cleanup_failed_id"] = id;
                row["cleanup_ambiguous"] = !result && kasumi::transport::mutation_result_is_ambiguous(result.error());
                row["cleanup_error"] = result ? "object was not removed" : kasumi::transport::describe(result.error());
                event("REMOVE_FAILED", scenario, {{"id", id}, {"error", row["cleanup_error"]},
                    {"ambiguous", row["cleanup_ambiguous"]}});
                row["cleanup_removed_ids"] = string_array(removed);
                write_json(artifacts / (scenario + ".cleanup.json"), Json{
                    {"remote_path", remote_path}, {"owned_ids", string_array(cleanup_ids)},
                    {"removed_ids", string_array(removed)}, {"failed_id", id},
                    {"status", "PASS_WITH_REMAINS"}});
                return fail("PASS_WITH_REMAINS", "CLEANUP_INCOMPLETE", "stopped at first unconfirmed owned-object removal", row_index);
            }
            removed.push_back(id);
            if (!event("REMOVE_CONFIRMED", scenario, {{"id", id}})) return false;
            if (removed.size() % 25 == 0) {
                row["cleanup_objects_removed"] = removed.size();
                if (!checkpoint("CLEANUP_IN_FLIGHT", "CLEANING", scenario)) return false;
            }
        }
        auto empty = kasumi::transport::list(storage);
        if ((empty && !empty->empty()) || (!empty && empty.error().code != kasumi::transport::ErrorCode::StorageNotFound))
            return fail("PASS_WITH_REMAINS", "CLEANUP_VERIFY", "could not confirm the exact fixture namespace empty", row_index);
        row["cleanup_elapsed_ms"] = elapsed_ms(cleanup_start);
        row["cleanup_seconds"] = static_cast<double>(row["cleanup_elapsed_ms"].get<std::uint64_t>()) / 1000.0;
        row["cleanup_objects_removed"] = removed.size();
        row["cleanup_objects_remaining"] = 0;
        row["removed_ids"] = string_array(removed);
        row["remaining_ids"] = Json::array();
        row["status"] = "PASS_CLEANED";
        row["last_confirmed_stage"] = "COMPLETE";
        row["empty_remote_folders_may_remain"] = true;
        row["remote_recursive_delete"] = false;
        if (!write_json(artifacts / (scenario + ".cleanup.json"), Json{
                {"remote_path", remote_path}, {"removed_ids", string_array(removed)},
                {"objects_remaining", 0}, {"elapsed_ms", row["cleanup_elapsed_ms"]},
                {"recursive_delete", false}, {"status", "PASS_CLEANED"}}) ||
            !event("CLEANUP_COMPLETE", scenario, {{"objects_removed", removed.size()}, {"objects_remaining", 0}}) ||
            !checkpoint("COMPLETE", "RUNNING", scenario)) return false;
        std::cout << scenario << " PASS_CLEANED C=" << candidate_count
                  << " gc=" << (static_cast<double>(gc_wall_us) / 1'000'000.0) << " s\n";
    }

    if (strict_revision) {
        const auto final_head = current_git_head();
        report["git_head_final"] = final_head.empty() ? Json{"NOT_MEASURED"} : Json{final_head};
        if (final_head != initial_git_head) {
            report["status"] = "INTERRUPTED_HEAD_CHANGED";
            report["last_confirmed_stage"] = "GIT_HEAD_FINAL_CHECK";
            report["curve_valid"] = false;
            report["adjacent_observed_slopes"] = "NOT_COMPUTED_HEAD_CHANGED";
            write_json(output, report);
            write_json(sidecar, Json{{"status", "INTERRUPTED_HEAD_CHANGED"},
                {"last_confirmed_stage", "GIT_HEAD_FINAL_CHECK"},
                {"remote_run_root", run_root}});
            return false;
        }
    }
    bool all_scenarios_passed = true;
    for (const auto& row : report["scenarios"])
        all_scenarios_passed = all_scenarios_passed &&
            row.value("status", "") == "PASS_CLEANED";
    Json slopes = Json::array();
    if (!phase22 || all_scenarios_passed) for (std::size_t i = 1; i < plan.size(); ++i) {
        const auto& before = report["scenarios"][i - 1];
        const auto& after = report["scenarios"][i];
        Json slope{{"from", plan[i - 1].first}, {"to", plan[i].first},
            {"delta_C", plan[i].second - plan[i - 1].second}};
        if (before.value("integrity", "") == "PASS" && after.value("integrity", "") == "PASS" &&
            before.contains("gc_wall_us") && after.contains("gc_wall_us")) {
            const auto delta = after["gc_wall_us"].get<std::int64_t>() - before["gc_wall_us"].get<std::int64_t>();
            slope["delta_t_us"] = delta;
            slope["delta_t_per_additional_candidate_us"] =
                static_cast<double>(delta) /
                static_cast<double>(slope["delta_C"].get<std::size_t>());
        } else {
            slope["delta_t_us"] = "NOT_MEASURED";
            slope["delta_t_per_additional_candidate_us"] = "NOT_MEASURED";
        }
        slopes.push_back(std::move(slope));
    }
    if (phase22 && !all_scenarios_passed)
        report["adjacent_observed_slopes"] = "NOT_COMPUTED_INCOMPLETE_SERIES";
    else
        report["adjacent_observed_slopes"] = std::move(slopes);
    if (phase22) {
        report["curve_valid"] = all_scenarios_passed;
        report["historical_reference"] = {
            {"label", "Referência histórica — Phase 19"}, {"C", 0},
            {"gc_wall_seconds", 25.432164}, {"revision_pre_phase21", true},
            {"used_for_phase22_slopes", false}};
        report["rc_request_semantics"] =
            "rclone RC request counts are not Google Drive API request counts";
        report["span_availability"] = {
            {"fallback_copy", "NOT_MEASURED separately; included in candidate_verified_copy_us"},
            {"overlap", "phase spans may overlap and must not be summed"},
            {"drive_api_request_count", "NOT_MEASURED"}};
        if (all_scenarios_passed) {
            const auto first_gc_us = report["scenarios"][0]["gc_wall_us"].get<std::int64_t>();
            report["relative_to_c001"] = Json::array();
            for (const auto& row : report["scenarios"]) {
                const auto gc_us = row["gc_wall_us"].get<std::int64_t>();
                const auto candidates = row["C_expected"].get<std::size_t>();
                report["relative_to_c001"].push_back({
                    {"scenario", row["scenario"]}, {"C", candidates},
                    {"delta_t_seconds", static_cast<double>(gc_us - first_gc_us) / 1'000'000.0}});
            }
        } else {
            report["relative_to_c001"] = "NOT_COMPUTED_INCOMPLETE_SERIES";
        }
    }
    if (phase23) {
        report["curve_valid"] = all_scenarios_passed;
        report["copy_concurrency"] = copy_concurrency;
        report["historical_phase22_reference"] = {
            {"C", 100}, {"gc_wall_seconds", 747.782},
            {"label", "sequential copy, revision 5ebee41; historical only"}};
        report["rc_request_semantics"] =
            "job/batch RC calls and copyfile subinputs are not Google Drive API request counts";
        report["drive_api_request_count"] = "NOT_MEASURED";
        if (!all_scenarios_passed) {
            report["status"] = "FAILED";
            report["stop_reason"] = "Phase 23 point did not reach PASS_CLEANED";
        }
    }
    if (phase24) {
        report["curve_valid"] = all_scenarios_passed;
        report["copy_concurrency"] = 8;
        report["metadata_concurrency"] = metadata_concurrency;
        report["phase23_historical_reference"] = {
            {"C", 100}, {"copy_concurrency", 8}, {"metadata_concurrency", 1},
            {"gc_wall_seconds", 736.000262}, {"metadata_publish_seconds", 253.240692},
            {"label", "historical reference only; Phase 24 M1 is the causal baseline"}};
        report["metadata_metrics"] = {
            {"encode_us", report["scenarios"][0]["gc_phase_times"]["metadata_encode_us"]},
            {"encryption_us", report["scenarios"][0]["gc_phase_times"]["metadata_encryption_us"]},
            {"local_hash_us", report["scenarios"][0]["gc_phase_times"]["metadata_local_hash_us"]},
            {"prepare_total_us", report["scenarios"][0]["gc_phase_times"]["metadata_prepare_total_us"]},
            {"publish_batch_us", report["scenarios"][0]["gc_phase_times"]["metadata_publish_batch_us"]},
            {"verification_batch_us", report["scenarios"][0]["gc_phase_times"]["metadata_verification_batch_us"]}};
        report["drive_api_request_count"] = "NOT_MEASURED";
        report["rc_request_semantics"] =
            "job/batch and explicit operations/copyfile RC counts are not Google Drive API request counts";
        if (!all_scenarios_passed) {
            report["status"] = "FAILED";
            report["stop_reason"] = "Phase 24 fixture did not reach PASS_CLEANED";
        }
    }
    report["interpretation_limits"] = {
        "delta_t/delta_C is an observed interval slope, not a per-object guarantee",
        "candidate count and total physical inventory both increase; the curve does not isolate C mathematically",
        "no extrapolation to 10,000 candidates or readiness claim for 10,000/20,000 protected files",
        "no sixth GC; later-collection persistence is NOT_MEASURED in this phase"};
    report["attribution"] = {{"common_gc_stages", "reported individually in gc_phase_times; spans may overlap"},
        {"larger_physical_inventory", "physical_listing_us per observation"},
        {"quarantine_copy_and_verification", "candidate verified-copy, batch verification, and metadata spans; overlap warning applies"},
        {"source_removals", "candidate_remove_us plus per-ID remove operation events"},
        {"retries_rate_limits", "RC retry counter/error events; backend rate limit count is NOT_MEASURED unless an error exposes it"},
        {"span_sums", "not added because phase timers can nest/overlap"}};
    report["status"] = "PASS";
    report["full_gc_runs"] = 0;
    for (const auto& row : report["scenarios"]) report["full_gc_runs"] = report["full_gc_runs"].get<int>() + row.value("full_gc_runs", 0);
    report["ended_elapsed_ms"] = elapsed_ms(started);
    report["last_confirmed_stage"] = "COMPLETE";
    report["remote_recursive_delete_used"] = false;
    if (!write_json(output, report) ||
        !write_json(sidecar, Json{{"status", "PASS"}, {"last_confirmed_stage", "COMPLETE"},
            {"remote_run_root", run_root}, {"full_gc_runs", report["full_gc_runs"]}})) return false;
    return true;
}

bool finalize_failed_batch_run(const std::filesystem::path& report_path,
                              bool phase24_expected = false) {
    const auto stop = [](std::string_view stage) {
        std::cerr << "Batch-phase recovered-run validation stopped at " << stage << '\n';
        return false;
    };
    Json report;
    {
        std::ifstream input(report_path, std::ios::binary);
        try { input >> report; } catch (const Json::exception&) { return false; }
    }
    const auto phase = report.value("phase", "");
    const bool phase24 =
        phase == "KASUMI_PHASE_24_METADATA_BATCH_CANARY" ||
        phase == "KASUMI_PHASE_24_METADATA_BATCH_POINT";
    const bool phase24_canary =
        phase == "KASUMI_PHASE_24_METADATA_BATCH_CANARY";
    const bool phase23_canary = phase == "KASUMI_PHASE_23_COPY_BATCH_CANARY";
    const bool canary = phase24_canary || phase23_canary;
    if (!report.is_object() || phase24 != phase24_expected ||
        (!phase24 && !phase23_canary &&
         phase != "KASUMI_PHASE_23_COPY_BATCH_POINT") ||
        !report.contains("scenarios") || report["scenarios"].size() != 1 ||
        report.value("build_commit", "") != current_git_head()) return stop("report/head check");
    auto& row = report["scenarios"][0];
    const auto scenario = row.value("scenario", "");
    const auto live_count = row.value("N_live", std::size_t{0});
    const auto candidate_count = row.value("C_expected", std::size_t{0});
    std::size_t concurrency = 0;
    std::size_t metadata_concurrency = 0;
    if (report.contains("copy_concurrency") && report["copy_concurrency"].is_number_integer())
        concurrency = report["copy_concurrency"].get<std::size_t>();
    else if (report.contains("copy_concurrency") && report["copy_concurrency"].is_array() &&
            report["copy_concurrency"].size() == 1 &&
            report["copy_concurrency"][0].is_number_integer())
        concurrency = report["copy_concurrency"][0].get<std::size_t>();
    if (phase24 && report.contains("metadata_concurrency")) {
        if (report["metadata_concurrency"].is_number_integer())
            metadata_concurrency = report["metadata_concurrency"].get<std::size_t>();
        else if (report["metadata_concurrency"].is_array() &&
                 report["metadata_concurrency"].size() == 1 &&
                 report["metadata_concurrency"][0].is_number_integer())
            metadata_concurrency =
                report["metadata_concurrency"][0].get<std::size_t>();
    }
    const auto expected_batches = (candidate_count + 7) / 8;
    const bool phase24_plan_valid = phase24
        ? (canary
            ? scenario == "CANARY" && live_count == 10 && candidate_count == 8 &&
                  concurrency == 8 && metadata_concurrency == 8
            : (scenario == "M1" || scenario == "M2" || scenario == "M4" ||
               scenario == "M8") && live_count == 1000 && candidate_count == 100 &&
                  concurrency == 8 && metadata_concurrency ==
                      static_cast<std::size_t>(std::stoul(scenario.substr(1))))
        : true;
    if (!phase24_plan_valid) return stop("point plan check");
    if ((!phase24 && canary &&
         (scenario != "CANARY" || live_count != 10 || candidate_count != 8 ||
          concurrency != 8)) ||
        (!phase24 && !canary &&
         (scenario != "B1" && scenario != "B2" && scenario != "B4" &&
          scenario != "B8")) ||
        row.value("full_gc_runs", 0) != 1 ||
        row.value("last_confirmed_stage", "") != "COPY_BATCH_VALIDATION" ||
        !row.contains("gc_counters") || !row.contains("gc_transport")) return stop("GC evidence check");
    if ((!phase24 && !canary &&
         (live_count != 1000 || candidate_count != 100 ||
          concurrency != static_cast<std::size_t>(std::stoul(scenario.substr(1))))) ||
        expected_batches == 0) return stop("point plan check");
    std::cerr << "Recovered-run plan validated: " << scenario << '\n';

    const auto& counters = row["gc_counters"];
    const auto counter = [&](const char* name) {
        if (!counters.contains(name)) return std::uint64_t{0};
        const auto& value = counters.at(name);
        if (!value.is_number_integer()) {
            std::cerr << "invalid numeric GC counter " << name << ": " << value.dump() << '\n';
            return std::uint64_t{0};
        }
        return value.get<std::uint64_t>();
    };
    const auto expected_errors = row["gc_transport"].contains("transport_errors") &&
            row["gc_transport"]["transport_errors"].is_number_integer()
        ? row["gc_transport"]["transport_errors"].get<std::size_t>() : std::size_t{0};
    bool only_expected_prefix_errors = expected_errors > 0 &&
        row["gc_transport"].contains("transport_error_events");
    if (only_expected_prefix_errors) {
        for (const auto& error : row["gc_transport"]["transport_error_events"])
            only_expected_prefix_errors = only_expected_prefix_errors &&
                error.value("error_code", "") == "storage_not_found" &&
                error.value("operation", "") == "list_prefix";
    }
    const auto& endpoints = counters["rc_requests_by_endpoint"];
    if (!endpoints.is_object() || !endpoints.contains("job/batch") ||
        !endpoints["job/batch"].is_number_integer()) return stop("job/batch counter type");
    const auto retries = row["gc_transport"].contains("retry_count") &&
            row["gc_transport"]["retry_count"].is_number_integer()
        ? row["gc_transport"]["retry_count"].get<std::uint64_t>() : std::uint64_t{1};
    const auto rate_limits = row.contains("observed_rate_limit_errors") &&
            row["observed_rate_limit_errors"].is_number_integer()
        ? row["observed_rate_limit_errors"].get<std::uint64_t>() : std::uint64_t{1};
    const auto shared_copy_successes =
        counter("rclone.copy_batch_reported_successes");
    const auto metadata_reported_successes =
        counter("rclone.put_files_batch_reported_successes");
    const auto copy_successes = phase24 &&
            shared_copy_successes >= metadata_reported_successes
        ? shared_copy_successes - metadata_reported_successes
        : shared_copy_successes;
    const auto metadata_hash_batches =
        counter("gc.metadata_physical_hash_batch_calls");
    const auto metadata_hash_batch_unsupported =
        counter("gc.metadata_physical_hash_batch_unsupported");
    const auto metadata_hash_batches_verified = metadata_hash_batches >=
            metadata_hash_batch_unsupported
        ? metadata_hash_batches - metadata_hash_batch_unsupported : 0;
    const auto metadata_batch_verified = phase24
        ? std::min<std::uint64_t>(candidate_count,
                                  metadata_hash_batches_verified * 8)
        : 0;
    const auto shared_batch_verified =
        counter("content batch verify objects");
    const auto payload_batch_verified = shared_batch_verified >=
            metadata_batch_verified
        ? shared_batch_verified - metadata_batch_verified : 0;
    const auto payload_individual_verified =
        counter("gc.individual_destination_hash_attempts");
    std::cerr << "Recovered-run counters loaded\n";
    if (!only_expected_prefix_errors || counter("gc.copy_batch_calls") != expected_batches ||
        counter("gc.copy_batch_inputs") != candidate_count ||
        counter("gc.copy_batch_concurrency") != expected_batches * concurrency ||
        counter("gc.copy_batch_errors") != 0 ||
        counter("gc.copy_batch_ambiguous") != 0 ||
        counter("gc.copy_batch_unsupported") != 0 ||
        counter("gc.fallback_copy_attempts") != 0 ||
        counter("rclone.copy_batch_inputs_submitted") != candidate_count ||
        counter("rclone.copy_batch_concurrency_submitted") != expected_batches * concurrency ||
        copy_successes != candidate_count ||
        counter("rclone.copy_batch_partial_responses") != 0 ||
        endpoints.value("job/batch", std::uint64_t{0}) < expected_batches ||
        counter("gc.source_physical_hash_calls") != candidate_count ||
        counter("gc.candidates_verified") != candidate_count ||
        payload_batch_verified + payload_individual_verified != candidate_count ||
        counter("gc.metadata_publications") != candidate_count ||
        counter("gc.pre_remove_barrier_verifications") != candidate_count ||
        counter("gc.source_removals") != candidate_count ||
        counter("gc.candidates_quarantined") != candidate_count ||
        retries != 0 || rate_limits != 0) return stop("copy/GC counters check");
    bool metadata_batch_valid = false;
    if (phase24) {
        const auto expected_metadata_batches = (candidate_count + 7) / 8;
        metadata_batch_valid =
            counter("gc.metadata_batch_calls") == expected_metadata_batches &&
            counter("gc.metadata_objects_submitted") == candidate_count &&
            counter("gc.metadata_concurrency") ==
                expected_metadata_batches * metadata_concurrency &&
            counter("rclone.put_files_batch_inputs_submitted") == candidate_count &&
            metadata_reported_successes == candidate_count &&
            counter("gc.metadata_prepared") == candidate_count &&
            counter("gc.metadata_publications") == candidate_count &&
            counter("gc.metadata_verified") == candidate_count &&
            metadata_hash_batches == candidate_count / 8 &&
            counter("gc.metadata_publication_failures") == 0 &&
            counter("rclone.put_files_batch_failures") == 0 &&
            counter("rclone.put_files_batch_transport_errors") == 0 &&
            counter("gc.pre_copy_barrier_verifications") == candidate_count &&
            counter("gc.pre_batch_copy_barrier_verifications") == expected_batches &&
            counter("gc.post_copy_barrier_verifications") == expected_batches &&
            counter("gc.barrier_release_owner_verifications") == 1 &&
            counter("gc.pre_remove_barrier_verifications") == candidate_count;
        if (!metadata_batch_valid) return stop("metadata batch counters check");
    }
    row["gc_counters"]["rclone.copy_batch_reported_successes_shared_total"] =
        shared_copy_successes;
    row["gc_counters"]["rclone.copy_batch_reported_successes"] = copy_successes;
    row["gc_counters"]["content batch verify objects shared_total"] =
        shared_batch_verified;
    row["gc_counters"]["content batch verify objects"] =
        payload_batch_verified;
    std::cerr << "Recovered-run counters validated\n";

    const auto remote_path = row.value("remote_path", "");
    const auto expected_root_prefix = phase24
        ? (canary
               ? "kasumi:integration-tests/gc-phase24-metadata-batch-canary-"
               : "kasumi:integration-tests/gc-phase24-metadata-batch-")
        : canary ? "kasumi:integration-tests/gc-phase23-copy-batch-canary-"
                 : "kasumi:integration-tests/gc-phase23-copy-batch-";
    if (remote_path.empty() ||
        (canary ? remote_path != report.value("remote_run_root", "")
                : !remote_path.starts_with(report.value("remote_run_root", "") + "/fixture")) ||
        !remote_path.starts_with(expected_root_prefix))
        return stop("remote path check");
    auto opened = kasumi::transport::open_transport(remote_path);
    if (!opened || !kasumi::transport::initialize(*opened)) return stop("transport initialize");
    auto& storage = *opened;
    auto inventory = kasumi::transport::list(storage);
    if (!inventory) return stop("remote inventory");
    std::cerr << "Recovered-run inventory listed: " << inventory->size() << '\n';

    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(i + 1);
    const auto layout = history_storage::derive_remote_layout(key);
    const auto live_ids = row.at("protected_ids").get<std::vector<std::string>>();
    const auto candidate_ids = row.at("candidate_ids").get<std::vector<std::string>>();
    const auto workspace = std::filesystem::path{
        report.at("local_workspace").get<std::string>()} / scenario;
    if (live_ids.size() != live_count || candidate_ids.size() != candidate_count)
        return stop("manifest counts");

    auto quarantine = history_storage::maintenance_protocol::inventory_quarantine(
        storage, key, *inventory, workspace);
    if (!quarantine || quarantine->size() != candidate_ids.size()) return stop("quarantine inventory");
    std::cerr << "Recovered-run quarantine metadata loaded: " << quarantine->size() << '\n';
    std::vector<std::string> originals, quarantine_ids, metadata_ids;
    bool copies_valid = true;
    for (const auto& entry : *quarantine) {
        originals.push_back(entry.original_identifier);
        quarantine_ids.push_back(entry.quarantine_identifier);
        metadata_ids.push_back(entry.metadata_identifier);
        auto verified = history_storage::maintenance_protocol::verify_quarantine(
            storage, entry, workspace);
        copies_valid = copies_valid && verified && *verified;
    }
    std::cerr << "Recovered-run quarantine hashes checked\n";
    std::vector<std::string> expected = live_ids;
    expected.push_back(row.at("commit_object_id").get<std::string>());
    expected.push_back(row.at("head_marker_id").get<std::string>());
    expected.insert(expected.end(), quarantine_ids.begin(), quarantine_ids.end());
    expected.insert(expected.end(), metadata_ids.begin(), metadata_ids.end());
    if (!copies_valid || sorted(*inventory) != sorted(expected) ||
        sorted(originals) != sorted(candidate_ids)) return stop("exact post-GC inventory or quarantine hashes");

    Json validation = Json::object();
    const auto commit_id = row.at("commit_id").get<std::string>();
    if (!phase20_validate_fixture(storage, key, layout, *inventory, live_ids, {},
                                  workspace, commit_id, validation)) return stop("HEAD/history/content validation");
    std::cerr << "Recovered-run HEAD/history/content validated\n";
    std::map<std::string, std::pair<kasumi::Hash, std::uint64_t>> live_info;
    for (const auto& asset : row.at("manifest")) {
        if (asset.value("kind", "") != "protected") continue;
        auto hash = kasumi::hash_from_hex(asset.at("plaintext_hash").get<std::string>());
        if (!hash) return stop("protected manifest hash");
        live_info.emplace(asset.at("id").get<std::string>(), std::pair{
            *hash, asset.at("plaintext_bytes").get<std::uint64_t>()});
    }
    auto samples = sorted(live_ids);
    std::cerr << "Recovered-run protected content samples starting\n";
    std::size_t sample_count = 0;
    std::string sample_failure;
    if (live_info.size() != live_ids.size() ||
        !verify_content_samples(storage, key, workspace, samples, live_info,
                                sample_count, &sample_failure) || sample_count != 10) {
        if (!sample_failure.empty()) {
            std::cerr << sample_failure << '\n';
            if (sample_count < samples.size()) {
                const auto failed_id = samples[sample_count];
                const auto asset = std::ranges::find_if(row.at("manifest"), [&](const auto& item) {
                    return item.value("id", "") == failed_id;
                });
                if (asset != row.at("manifest").end()) {
                    const auto local_plaintext = workspace / "protected-local-check.plain";
                    const bool local_decrypted = kasumi::crypto::decrypt_file(
                        asset->at("local_ciphertext").get<std::string>(), local_plaintext,
                        key, kasumi::crypto::FilePurpose::Content);
                    auto local_hash = local_decrypted
                        ? kasumi::crypto::content::hash_file(local_plaintext)
                        : std::expected<kasumi::Hash, std::string>{std::unexpected("local decrypt failed")};
                    std::cerr << "local-original protected check: id=" << failed_id
                              << " hash=" << (local_hash ? kasumi::hash_hex(*local_hash) : "FAILED")
                              << " expected=" << asset->at("plaintext_hash").get<std::string>()
                              << " content_id=" << (local_hash
                                  ? kasumi::crypto::content_identifier(key, *local_hash) : "FAILED")
                              << '\n';
                }
            }
        }
        return stop("protected plaintext samples");
    }

    std::error_code ec;
    const auto output = std::filesystem::absolute(report_path, ec);
    if (ec) return stop("local report path");
    const auto artifacts = std::filesystem::path{
        report.at("artifact_directory").get<std::string>()};
    row["copy_batch_validation"]["passed"] = true;
    row["copy_batch_validation"]["expected_optional_prefix_not_found_errors"] = expected_errors;
    row["copy_batch_validation"]["copyfile_result_successes"] = copy_successes;
    row["copy_batch_validation"]["destination_hash_batch_calls"] =
        counter("gc.batch_verify_attempts");
    row["copy_batch_validation"]["destination_batch_verified_objects"] =
        payload_batch_verified;
    row["copy_batch_validation"]["destination_individual_verified_objects"] =
        payload_individual_verified;
    row["copy_batch_validation"]["destination_verified_objects"] = candidate_count;
    row["copy_batch_validation"]["unexpected_transport_errors"] =
        row["unexpected_transport_errors"];
    row["copy_batch_validation"]["recovered_after_harness_assertion"] = true;
    if (phase24) {
        row["metadata_batch_validation"] = {
            {"passed", metadata_batch_valid},
            {"metadata_batch_calls", counter("gc.metadata_batch_calls")},
            {"expected_metadata_batch_calls", (candidate_count + 7) / 8},
            {"metadata_objects_submitted", counter("rclone.put_files_batch_inputs_submitted")},
            {"metadata_concurrency", metadata_concurrency},
            {"metadata_prepared", counter("gc.metadata_prepared")},
            {"metadata_published", metadata_reported_successes},
            {"metadata_physical_hash_batch_calls", metadata_hash_batches},
            {"metadata_batch_hash_verified_objects", metadata_batch_verified},
            {"metadata_verified", counter("gc.metadata_verified")},
            {"publication_failures", counter("gc.metadata_publication_failures")},
            {"pre_copy_barrier_verifications", counter("gc.pre_copy_barrier_verifications")},
            {"pre_batch_copy_barrier_verifications", counter("gc.pre_batch_copy_barrier_verifications")},
            {"post_copy_barrier_verifications", counter("gc.post_copy_barrier_verifications")},
            {"pre_remove_barrier_verifications", counter("gc.pre_remove_barrier_verifications")},
            {"barrier_release_owner_verifications", counter("gc.barrier_release_owner_verifications")},
            {"source_removals", counter("gc.source_removals")},
            {"sync_copy_requests_during_gc", endpoints.value("sync/copy", std::uint64_t{0})},
            {"recovered_after_harness_assertion", true}};
    }
    row["C_effective"] = candidate_count;
    row["candidates_quarantined"] = candidate_count;
    row["objects_restored"] = 0;
    row["objects_purged"] = 0;
    row["post_gc_validation"] = validation;
    row["post_gc_inventory"] = string_array(sorted(*inventory));
    row["post_gc_sample_count"] = sample_count;
    row["integrity"] = "PASS";
    row["cleanup_manifest"] = string_array(sorted(expected));
    row["last_confirmed_stage"] = "CLEANUP_READY";
    row["status"] = "CLEANING";
    if (!write_json(artifacts / (scenario + ".cleanup.json"), Json{
            {"remote_path", remote_path}, {"owned_ids", string_array(sorted(expected))},
            {"quarantine_ids", string_array(sorted(quarantine_ids))},
            {"metadata_ids", string_array(sorted(metadata_ids))},
            {"recursive_delete", false}, {"status", "CLEANUP_READY"}}) ||
        !write_json(output, report)) return stop("write cleanup manifest");

    auto before_cleanup = kasumi::transport::list(storage);
    if (!before_cleanup || sorted(*before_cleanup) != sorted(expected)) return stop("pre-cleanup exact inventory");
    const auto journal = std::filesystem::path{output.string() + ".manifest.jsonl"};
    if (!append_jsonl(journal, Json{{"event", "GC_COMPLETE"}, {"scenario", scenario},
            {"recovered_from_reported_success", true}, {"quarantined", candidate_count}}) ||
        !append_jsonl(journal, Json{{"event", "POST_GC_INTEGRITY_PASS"}, {"scenario", scenario},
            {"protected_content_count", live_count}, {"sample_count", sample_count},
            {"quarantine_count", candidate_count}}))
        return stop("cleanup journal");
    for (const auto& id : sorted(expected)) {
        auto removed = kasumi::transport::remove(storage, id);
        if (!removed || *removed != kasumi::transport::Removal::Removed) return stop("exact object removal");
    }
    auto empty = kasumi::transport::list(storage);
    if ((empty && !empty->empty()) ||
        (!empty && empty.error().code != kasumi::transport::ErrorCode::StorageNotFound))
        return stop("empty namespace confirmation");
    row["status"] = canary ? "PASS_CLEANED" : "DIAGNOSTIC_PASS_CLEANED";
    row["last_confirmed_stage"] = "COMPLETE";
    row["cleanup_objects_removed"] = expected.size();
    row["cleanup_objects_remaining"] = 0;
    row["remaining_ids"] = Json::array();
    report["status"] = canary ? "PASS" : "DIAGNOSTIC_CLEANED";
    report["curve_valid"] = canary;
    report["full_gc_runs"] = 1;
    report[canary ? "canary_recovered_after_harness_validation_mismatch" :
                    "diagnostic_point_recovered_after_harness_validation_mismatch"] = true;
    report["git_head_final"] = current_git_head();
    report["last_confirmed_stage"] = "COMPLETE";
    if (report["git_head_final"] != report["build_commit"] ||
        !write_json(artifacts / (scenario + ".post-gc.json"), Json{
            {"remote_path", remote_path}, {"inventory", string_array(sorted(*inventory))},
            {"validation", validation}, {"sample_count", sample_count}, {"integrity", "PASS"}}) ||
        !write_json(output, report) ||
        !write_json(std::filesystem::path{output.string() + ".status.json"}, Json{
            {"status", "PASS"}, {"last_confirmed_stage", "COMPLETE"},
            {"remote_run_root", report["remote_run_root"]}, {"cleanup_objects_remaining", 0}}))
        return stop("write PASS_CLEANED report");
    return append_jsonl(journal, Json{{"event", "CLEANUP_COMPLETE"}, {"scenario", scenario},
        {"objects_removed", expected.size()}, {"objects_remaining", 0},
        {"recovered_after_harness_validation_mismatch", true}});
}

bool inspect_failed_phase20(const std::filesystem::path& report_path,
                           std::string_view scenario_name) {
    std::error_code ec;
    const auto output = std::filesystem::absolute(report_path, ec);
    if (ec || !std::filesystem::exists(output, ec) || ec) return false;
    Json report;
    {
        std::ifstream in(output, std::ios::binary);
        try { in >> report; } catch (const Json::exception&) { return false; }
    }
    if (!report.is_object() || report.value("phase", "") !=
            "KASUMI_PHASE_20_REAL_REMOTE_GC_CANDIDATE_CURVE" ||
        !report.contains("scenarios") || report["scenarios"].size() != 5) return false;
    std::size_t row_index = phase20_plan.size();
    for (std::size_t i = 0; i < phase20_plan.size(); ++i)
        if (phase20_plan[i].first == scenario_name) row_index = i;
    if (row_index == phase20_plan.size()) return false;
    auto& row = report["scenarios"][row_index];
    if (row.value("status", "") != "FAILED" || row.value("full_gc_runs", 0) != 1 ||
        !row.contains("pre_gc_inventory") || !row.contains("protected_ids") ||
        !row.contains("candidate_ids") || !row.contains("commit_id")) return false;
    const auto journal = std::filesystem::path{output.string() + ".manifest.jsonl"};
    auto events = read_complete_jsonl(journal);
    if (!events) return false;
    bool gc_started = false, gc_failed = false, gc_completed = false;
    for (const auto& entry : *events) {
        if (entry.value("scenario", "") != scenario_name) continue;
        const auto event_name = entry.value("event", "");
        gc_started = gc_started || event_name == "GC_STARTED";
        gc_failed = gc_failed || event_name == "GC_FAILED";
        gc_completed = gc_completed || event_name == "GC_COMPLETE";
    }
    if (!gc_started || !gc_failed || gc_completed) return false;

    const auto remote_path = row.at("remote_path").get<std::string>();
    const auto run_root = report.at("remote_run_root").get<std::string>();
    if (!remote_path.starts_with(run_root + "/")) return false;
    auto opened = kasumi::transport::open_transport(remote_path);
    if (!opened || !kasumi::transport::initialize(*opened)) return false;
    auto& storage = *opened;
    auto listing = kasumi::transport::list(storage);
    if (!listing) return false;
    const auto ids = sorted(*listing);

    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(i + 1);
    const auto layout = history_storage::derive_remote_layout(key);
    std::vector<std::string> live_ids = row.at("protected_ids").get<std::vector<std::string>>();
    std::vector<std::string> candidate_ids = row.at("candidate_ids").get<std::vector<std::string>>();
    const auto workspace = std::filesystem::path{report.at("local_workspace").get<std::string>()} /
                           row.at("scenario").get<std::string>();
    const auto artifacts = std::filesystem::path{report.at("artifact_directory").get<std::string>()};
    const auto evidence_dir = artifacts / (std::string{scenario_name} + ".failure-inspection-blobs");
    if (std::filesystem::exists(evidence_dir, ec) || ec ||
        std::filesystem::exists(artifacts / (std::string{scenario_name} + ".failure-inspection.json"), ec) || ec ||
        !std::filesystem::create_directories(evidence_dir, ec) || ec) return false;
    Json protected_validation = Json::object();
    const bool protected_history_valid = phase20_validate_fixture(
        storage, key, layout, ids, live_ids, candidate_ids, workspace,
        row.at("commit_id").get<std::string>(), protected_validation);

    std::map<std::string, std::pair<kasumi::Hash, std::uint64_t>> live_info;
    for (const auto& asset : report.at("live_local_asset_manifest")) {
        const auto decoded = kasumi::hash_from_hex(asset.at("plaintext_hash").get<std::string>());
        if (!decoded) return false;
        live_info.emplace(asset.at("id").get<std::string>(),
            std::pair{*decoded, asset.at("plaintext_bytes").get<std::uint64_t>()});
    }
    std::ranges::sort(live_ids);
    std::vector<std::string> samples;
    for (std::size_t i = 0; i < 10; ++i)
        samples.push_back(live_ids[i * (live_ids.size() - 1) / 9]);
    std::size_t samples_verified = 0;
    const bool sample_valid = verify_content_samples(
        storage, key, workspace, samples, live_info, samples_verified) && samples_verified == 10;

    auto quarantine = kasumi::application::history_storage::maintenance_protocol::
        inventory_quarantine(storage, key, ids, workspace);
    if (!quarantine) return false;
    std::vector<std::string> qids, metadata_ids;
    Json candidate_states = Json::array();
    bool all_sources_present = true, all_copies_match = true, metadata_absent = true;
    for (const auto& candidate : candidate_ids) {
        const auto qid = kasumi::application::history_storage::maintenance_protocol::
            quarantine_identifier(layout, candidate);
        if (!qid) return false;
        const bool source_present = std::ranges::binary_search(ids, candidate);
        const bool q_present = std::ranges::binary_search(ids, *qid);
        all_sources_present = all_sources_present && source_present;
        std::string physical_check = "NOT_PRESENT";
        std::string q_sha256, source_sha256;
        bool q_matches = false;
        if (q_present) {
            qids.push_back(*qid);
            const auto entry = std::ranges::find_if(*quarantine, [&](const auto& item) {
                return item.original_identifier == candidate;
            });
            if (entry == quarantine->end()) return false;
            metadata_ids.push_back(entry->metadata_identifier);
            const bool metadata_present = std::ranges::binary_search(ids, entry->metadata_identifier);
            metadata_absent = metadata_absent && !metadata_present;
            const auto qcopy = evidence_dir / (candidate + ".quarantine-copy");
            const auto source = evidence_dir / (candidate + ".source-copy");
            auto qget = kasumi::transport::get(storage, *qid, qcopy);
            auto sget = kasumi::transport::get(storage, candidate, source);
            auto qhash = qget ? kasumi::crypto::physical::hash_file(qcopy, "sha256")
                              : std::expected<std::string, std::string>{std::unexpected("quarantine GET failed")};
            auto shash = sget ? kasumi::crypto::physical::hash_file(source, "sha256")
                              : std::expected<std::string, std::string>{std::unexpected("source GET failed")};
            if (qhash) q_sha256 = *qhash;
            if (shash) source_sha256 = *shash;
            q_matches = qhash && shash && *qhash == *shash;
            physical_check = q_matches ? "COPY_MATCHES_SOURCE_SHA256" : "COPY_HASH_MISMATCH_OR_UNAVAILABLE";
        }
        all_copies_match = all_copies_match && (!q_present || q_matches);
        candidate_states.push_back({{"original_id", candidate}, {"source_present", source_present},
            {"quarantine_id", *qid}, {"quarantine_copy_present", q_present},
            {"metadata_id", q_present ? Json{metadata_ids.back()} : Json{"NOT_MEASURED"}},
            {"metadata_present", q_present && std::ranges::binary_search(ids, metadata_ids.back())},
            {"physical_copy_check", physical_check}, {"quarantine_sha256", q_sha256},
            {"source_sha256", source_sha256}, {"origin_removed", false},
            {"protocol_quarantined", false}, {"definitively_purged", false}});
    }
    std::vector<std::string> expected_ids = row.at("pre_gc_inventory").get<std::vector<std::string>>();
    expected_ids.insert(expected_ids.end(), qids.begin(), qids.end());
    std::ranges::sort(expected_ids);
    expected_ids.erase(std::ranges::unique(expected_ids).begin(), expected_ids.end());
    const bool exact_owned_inventory = ids == expected_ids;
    std::vector<std::string> unexpected_ids, missing_ids;
    std::ranges::set_difference(ids, expected_ids, std::back_inserter(unexpected_ids));
    std::ranges::set_difference(expected_ids, ids, std::back_inserter(missing_ids));
    Json inspection{
        {"status", "INSPECTED_FAILED_GC_PRESERVED"}, {"remote_path", remote_path},
        {"remote_mutations_performed", false}, {"cleanup_performed", false},
        {"full_gc_runs", 1}, {"gc_error", row.value("gc_error", "NOT_MEASURED")},
        {"C_identified_by_perf_trace", row["gc_counters"].value("gc.candidates_selected", 0)},
        {"C_effective_returned", "NOT_RETURNED"},
        {"copies_native_succeeded", row["gc_counters"].value("gc.native_copy_successes", 0)},
        {"copies_verified_by_gc", row["gc_counters"].value("gc.candidates_verified", 0)},
        {"source_removals_started", row["gc_counters"].value("gc.source_removals", 0)},
        {"sources_present", all_sources_present}, {"quarantine_copies_match_source_sha256", all_copies_match},
        {"quarantine_metadata_absent", metadata_absent},
        {"protected_history_validation", protected_validation},
        {"protected_history_valid", protected_history_valid},
        {"protected_sample_ids", string_array(samples)},
        {"protected_sample_count", samples_verified}, {"protected_sample_valid", sample_valid},
        {"candidate_states", candidate_states}, {"quarantine_inventory", string_array(sorted(qids))},
        {"quarantine_metadata_ids", string_array(sorted(metadata_ids))},
        {"observed_inventory", string_array(ids)},
        {"expected_owned_inventory", string_array(expected_ids)},
        {"exact_owned_inventory", exact_owned_inventory},
        {"unexpected_ids", string_array(unexpected_ids)},
        {"missing_ids", string_array(missing_ids)},
        {"downloaded_copy_evidence_directory", evidence_dir.string()}};
    inspection["safe_to_clean_as_complete_fixture"] = false;
    if (!write_json(artifacts / (std::string{scenario_name} + ".failure-inspection.json"), inspection))
        return false;
    row["failure_inspection"] = inspection;
    row["C_identified"] = inspection["C_identified_by_perf_trace"];
    row["C_effective"] = "NOT_RETURNED";
    row["candidates_quarantined"] = row["gc_counters"].value("gc.candidates_quarantined", 0);
    row["protected_integrity"] = protected_history_valid && sample_valid ? "PASS" : "FAILED";
    row["integrity"] = protected_history_valid && sample_valid && exact_owned_inventory &&
        all_sources_present && all_copies_match && metadata_absent
        ? "PASS_PROTECTED_STATE_ACCOUNTED" : "FAILED_OR_AMBIGUOUS";
    row["origins_removed"] = row["gc_counters"].value("gc.source_removals", 0);
    row["objects_purged"] = 0;
    row["quarantine_copies_observed"] = std::ranges::count_if(
        candidate_states, [](const Json& state) { return state.value("quarantine_copy_present", false); });
    row["quarantine_copies_sha256_matched"] = std::ranges::count_if(
        candidate_states, [](const Json& state) {
            return state.value("physical_copy_check", "") == "COPY_MATCHES_SOURCE_SHA256";
        });
    row["post_failure_inventory_count"] = ids.size();
    row["cleanup_elapsed_ms"] = "NOT_RUN";
    row["partial_quarantine_state"] = candidate_states;
    row["cleanup_status"] = "NOT_RUN_PRESERVED_AFTER_GC_FAILURE";
    row["last_confirmed_stage"] = "FAILURE_INSPECTION_COMPLETE";
    row["status"] = "FAILED";
    for (std::size_t i = row_index + 1; i < report["scenarios"].size(); ++i) {
        report["scenarios"][i]["status"] = "NOT_RUN";
        report["scenarios"][i]["last_confirmed_stage"] = "STOPPED_AFTER_" + std::string{scenario_name} + "_GC_FAILURE";
    }
    Json slopes = Json::array();
    for (std::size_t i = 1; i < phase20_plan.size(); ++i)
        slopes.push_back({{"from", phase20_plan[i - 1].first}, {"to", phase20_plan[i].first},
            {"delta_C", phase20_plan[i].second - phase20_plan[i - 1].second},
            {"delta_t_us", "NOT_MEASURED"}, {"delta_t_per_additional_candidate_us", "NOT_MEASURED"}});
    report["adjacent_observed_slopes"] = std::move(slopes);
    report["status"] = "STOPPED_FAILED";
    report["full_gc_runs"] = 0;
    for (const auto& scenario : report["scenarios"])
        report["full_gc_runs"] = report["full_gc_runs"].get<int>() + scenario.value("full_gc_runs", 0);
    report["stop_reason"] = row["gc_error"];
    report["failure_inspection_path"] = (artifacts / (std::string{scenario_name} + ".failure-inspection.json")).string();
    report["last_confirmed_stage"] = "FAILURE_INSPECTION_COMPLETE";
    report["failure_inspection_completed_unix_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    report["updated_unix_ms"] = report["failure_inspection_completed_unix_ms"];
    if (!write_json(output, report)) return false;
    return write_json(std::filesystem::path{output.string() + ".status.json"}, Json{
        {"status", "STOPPED_FAILED"}, {"last_confirmed_stage", "FAILURE_INSPECTION_COMPLETE"},
        {"scenario", scenario_name}, {"remote_path", remote_path},
        {"remote_mutations_performed_by_inspector", false}, {"cleanup_performed", false},
        {"reason", row["gc_error"]}});
}

} // namespace

int main(int argc, char** argv) {
    bool execute_live = false;
    bool self_test_only = false;
    bool phase19_s2 = false;
    bool phase20_curve = false;
    bool phase22_curve = false;
    bool phase23_canary = false;
    bool phase23_point = false;
    bool phase23_finalize_canary = false;
    bool phase23_finalize_point = false;
    bool phase24_finalize_canary = false;
    bool phase24_finalize_point = false;
    bool phase24_canary = false;
    bool phase24_point = false;
    std::size_t copy_concurrency = 0;
    std::size_t metadata_concurrency = 0;
    bool resume = false;
    bool preflight_only = false;
    bool journal_test_only = false;
    bool phase20_test_only = false;
    bool phase20_inspect_failed = false;
    std::filesystem::path output;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--execute-live") execute_live = true;
        else if (arg == "--phase19-s2") phase19_s2 = true;
        else if (arg == "--phase20-curve") phase20_curve = true;
        else if (arg == "--phase22-curve") phase22_curve = true;
        else if (arg == "--phase23-canary") phase23_canary = true;
        else if (arg == "--phase23-point") phase23_point = true;
        else if (arg == "--phase23-finalize-canary") phase23_finalize_canary = true;
        else if (arg == "--phase23-finalize-point") phase23_finalize_point = true;
        else if (arg == "--phase24-canary") phase24_canary = true;
        else if (arg == "--phase24-point") phase24_point = true;
        else if (arg == "--phase24-finalize-canary") phase24_finalize_canary = true;
        else if (arg == "--phase24-finalize-point") phase24_finalize_point = true;
        else if (arg == "--copy-concurrency" && i + 1 < argc) {
            try { copy_concurrency = std::stoul(argv[++i]); }
            catch (...) { copy_concurrency = 0; }
        }
        else if (arg == "--metadata-concurrency" && i + 1 < argc) {
            try { metadata_concurrency = std::stoul(argv[++i]); }
            catch (...) { metadata_concurrency = 0; }
        }
        else if (arg == "--resume") resume = true;
        else if (arg == "--preflight-only") preflight_only = true;
        else if (arg == "--self-test-counters") self_test_only = true;
        else if (arg == "--self-test-phase19-journal") journal_test_only = true;
        else if (arg == "--self-test-phase20-plan") phase20_test_only = true;
        else if (arg == "--phase20-inspect-failed") phase20_inspect_failed = true;
        else if (arg == "--output" && i + 1 < argc) output = argv[++i];
        else {
            std::cerr << "Usage: kasumi_gc_live_phase18 --self-test-counters\n"
                         "   or: kasumi_gc_live_phase18 --self-test-phase19-journal\n"
                         "   or: kasumi_gc_live_phase18 --self-test-phase20-plan\n"
                         "   or: kasumi_gc_live_phase18 --phase19-s2 --output <new-json> --execute-live\n"
                         "   or: kasumi_gc_live_phase18 --phase20-curve --output <new-json> --execute-live\n"
                         "   or: kasumi_gc_live_phase18 --phase20-curve --output <new-json> --preflight-only\n"
                         "   or: kasumi_gc_live_phase18 --phase20-curve --output <existing-json> --execute-live --resume\n"
                         "   or: kasumi_gc_live_phase18 --phase22-curve --output <new-json> --preflight-only\n"
                         "   or: kasumi_gc_live_phase18 --phase22-curve --output <new-json> --execute-live\n"
                         "   or: kasumi_gc_live_phase18 --phase22-curve --output <existing-json> --execute-live --resume\n"
                         "   or: kasumi_gc_live_phase18 --phase23-canary --output <new-json> --execute-live\n"
                         "   or: kasumi_gc_live_phase18 --phase23-point --copy-concurrency <1|2|4|8> --output <new-json> --execute-live\n"
                         "   or: kasumi_gc_live_phase18 --phase23-finalize-canary --output <existing-json>\n"
                         "   or: kasumi_gc_live_phase18 --phase23-finalize-point --output <existing-json>\n"
                         "   or: kasumi_gc_live_phase18 --phase24-canary --output <new-json> --execute-live\n"
                         "   or: kasumi_gc_live_phase18 --phase24-point --metadata-concurrency <1|2|4|8> --output <new-json> --execute-live\n"
                         "   or: kasumi_gc_live_phase18 --phase24-finalize-canary --output <existing-json>\n"
                         "   or: kasumi_gc_live_phase18 --phase24-finalize-point --output <existing-json>\n"
                         "   or: kasumi_gc_live_phase18 --phase20-inspect-failed --output <existing-json>\n"
                         "   or: kasumi_gc_live_phase18 --output <new-json> --execute-live\n";
            return 2;
        }
    }
    if (self_test_only && !execute_live && output.empty()) {
        const bool passed = counter_self_test();
        std::cout << "Transport counter self-test: "
                  << (passed ? "PASS\n" : "FAIL\n");
        return passed ? 0 : 1;
    }
    if (journal_test_only && !execute_live && output.empty()) {
        const bool passed = phase19_journal_self_test();
        std::cout << "Phase 19 journal self-test: " << (passed ? "PASS\n" : "FAIL\n");
        return passed ? 0 : 1;
    }
    if (phase20_test_only && !execute_live && output.empty()) {
        const bool passed = phase20_plan_self_test();
        std::cout << "Phase 20 plan self-test: " << (passed ? "PASS\n" : "FAIL\n");
        return passed ? 0 : 1;
    }
    if (phase20_inspect_failed && !execute_live && !output.empty()) {
        return inspect_failed_phase20(output, "T2") ? 0 : 1;
    }
    if ((phase23_finalize_canary || phase23_finalize_point) &&
        !execute_live && !preflight_only && !output.empty()) {
        return finalize_failed_batch_run(output) ? 0 : 1;
    }
    if ((phase24_finalize_canary || phase24_finalize_point) &&
        !execute_live && !preflight_only && !output.empty() &&
        phase24_finalize_canary != phase24_finalize_point) {
        return finalize_failed_batch_run(output, true) ? 0 : 1;
    }
    if (phase19_s2 && execute_live && !output.empty()) {
        return run_phase19_s2(output) ? 0 : 1;
    }
    if (phase20_curve && (execute_live || preflight_only) && !output.empty()) {
        if (resume && preflight_only) return 2;
        return run_phase20_curve(output, resume, preflight_only) ? 0 : 1;
    }
    if (phase22_curve && (execute_live || preflight_only) && !output.empty()) {
        if (resume && preflight_only) return 2;
        return run_phase20_curve(output, resume, preflight_only, true) ? 0 : 1;
    }
    if (phase24_canary || phase24_point) {
        const bool valid_metadata_concurrency = metadata_concurrency == 1 ||
            metadata_concurrency == 2 || metadata_concurrency == 4 ||
            metadata_concurrency == 8;
        if (phase24_canary == phase24_point || !(execute_live || preflight_only) ||
            output.empty() || (phase24_point && !valid_metadata_concurrency) ||
            (phase24_canary && metadata_concurrency != 0 &&
             metadata_concurrency != 8) || (resume && preflight_only)) return 2;
        const auto concurrency = phase24_canary ? std::size_t{8}
                                                : metadata_concurrency;
        return run_phase20_curve(output, resume, preflight_only, false,
                                 phase24_canary ? 1 : 2, 8, concurrency, true)
                   ? 0 : 1;
    }
    if (phase23_canary || phase23_point) {
        const bool valid_point_concurrency = copy_concurrency == 1 || copy_concurrency == 2 ||
                                             copy_concurrency == 4 || copy_concurrency == 8;
        if (phase23_canary == phase23_point || !(execute_live || preflight_only) ||
            output.empty() || (phase23_point && !valid_point_concurrency) ||
            (phase23_canary && copy_concurrency != 0 && copy_concurrency != 8) ||
            (resume && preflight_only)) return 2;
        const auto concurrency = phase23_canary ? std::size_t{8} : copy_concurrency;
        return run_phase20_curve(output, resume, preflight_only, false,
                                 phase23_canary ? 1 : 2, concurrency) ? 0 : 1;
    }
    if (!execute_live || output.empty()) {
        std::cerr << "Live Phase 18 execution requires --execute-live and --output.\n";
        return 2;
    }
    return run(output) ? 0 : 1;
}
