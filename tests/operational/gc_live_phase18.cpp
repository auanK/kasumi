#include "application/history_storage/content_reachability.hpp"
#include "application/history_storage/publication.hpp"
#include "application/history_storage/reachability.hpp"
#include "application/integrity/maintenance.hpp"
#include "core/history.hpp"
#include "core/node.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/key_derivation.hpp"
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
    std::size_t get_calls = 0;
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
    std::size_t physical_hash_batch_calls = 0;
    std::size_t copy_calls = 0;
    std::size_t remove_calls = 0;
    std::size_t errors = 0;
    std::uint64_t get_time_us = 0;
    std::uint64_t list_time_us = 0;
    std::uint64_t control_read_time_us = 0;
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

kasumi::transport::Result count_initialize(void* context) {
    auto& c = counter_context(context);
    auto result = kasumi::transport::initialize(*c.inner);
    if (!result) ++c.metrics->errors;
    return result;
}

kasumi::transport::Result count_put(
    void* context, const std::filesystem::path& source, std::string_view id) {
    auto& c = counter_context(context);
    auto result = kasumi::transport::put(*c.inner, source, id);
    if (!result) ++c.metrics->errors;
    return result;
}

kasumi::transport::Result count_put_batch(
    void* context, const kasumi::transport::PutBatch& batch) {
    auto& c = counter_context(context);
    auto result = kasumi::transport::put_batch(*c.inner, batch);
    if (!result) ++c.metrics->errors;
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
    c.metrics->get_time_us += static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() - start).count());
    if (!result) ++c.metrics->errors;
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
    if (!result) ++c.metrics->errors;
    return result;
}

kasumi::transport::Result count_copy(
    void* context, std::string_view source, std::string_view destination) {
    auto& c = counter_context(context);
    ++c.metrics->copy_calls;
    auto result = kasumi::transport::copy(*c.inner, source, destination);
    if (!result) ++c.metrics->errors;
    return result;
}

kasumi::transport::PresenceResult count_presence(void* context,
                                                  std::string_view id) {
    auto& c = counter_context(context);
    ++c.metrics->presence_calls;
    auto result = kasumi::transport::presence(*c.inner, id);
    if (!result) ++c.metrics->errors;
    return result;
}

void count_list_result(Traffic& metrics, std::string_view prefix,
                       const kasumi::transport::ListingResult& result) {
    if (prefix.empty()) ++metrics.full_list_calls;
    else ++metrics.prefix_list_calls;
    if (result) metrics.identifiers_returned += result->size();
    else ++metrics.errors;
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
    auto result = kasumi::transport::physical_hash(*c.inner, id, algorithm);
    if (!result) ++c.metrics->errors;
    return result;
}

kasumi::transport::PhysicalHashBatchResult count_physical_hash_batch(
    void* context,
    const kasumi::transport::PhysicalHashBatchRequest& request) {
    auto& c = counter_context(context);
    ++c.metrics->physical_hash_batch_calls;
    auto result = kasumi::transport::physical_hash_batch(*c.inner, request);
    if (!result) ++c.metrics->errors;
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
        ++c.metrics->errors;
        return result;
    }
    for (std::size_t i = 0; i < request.list_prefixes.size(); ++i) {
        if (i >= result->listings.size()) {
            ++c.metrics->errors;
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
    auto result = kasumi::transport::remove(*c.inner, id);
    if (!result) ++c.metrics->errors;
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
            .get = count_get,
            .get_batch = inner.storage.get_batch ? count_get_batch : nullptr,
            .copy = inner.storage.copy ? count_copy : nullptr,
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

Json traffic_json(const Traffic& traffic) {
    return Json{
        {"transport_get_calls", traffic.get_calls},
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
        {"physical_hash_batch_calls", traffic.physical_hash_batch_calls},
        {"copy_calls", traffic.copy_calls},
        {"remove_calls", traffic.remove_calls},
        {"transport_errors", traffic.errors},
        {"get_transport_time_us", traffic.get_time_us},
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
        {"candidate_metadata_publish_us", get_time("gc candidate metadata publish")},
        {"candidate_remove_us", get_time("gc candidate remove")},
        {"internal_gc_total_us", get_time("gc.total_duration_us")},
        {"content_reference_capacity_growth_events",
         kasumi::platform::perf_trace::get_count("rc/content_reference_capacity_growth_events")},
    };
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
    std::size_t& verified) {
    const auto count = std::min<std::size_t>(identifiers.size(), 10);
    const auto encrypted = workspace / "verify.enc";
    const auto plaintext = workspace / "verify.plain";
    for (std::size_t i = 0; i < count; ++i) {
        const auto& id = identifiers[i];
        if (!kasumi::transport::get(storage, id, encrypted) ||
            !kasumi::crypto::decrypt_file(encrypted, plaintext, key,
                                          kasumi::crypto::FilePurpose::Content)) {
            return false;
        }
        auto hash = kasumi::crypto::content::hash_file(plaintext);
        std::error_code ec;
        const auto size = std::filesystem::file_size(plaintext, ec);
        const auto found = expected.find(id);
        if (!hash || ec || found == expected.end() || *hash != found->second.first ||
            size != found->second.second ||
            kasumi::crypto::content_identifier(key, *hash) != id) {
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
        kasumi::platform::perf_trace::force_enable(false);
        const auto gc_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(gc_end - gc_start).count());
        item["gc_wall_us"] = gc_us;
        item["gc_phase_times"] = phase_times_json();
        item["gc_transport"] = traffic_json(traffic);
        item["gc_runs_used"] = gc_runs;
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

} // namespace

int main(int argc, char** argv) {
    bool execute_live = false;
    bool self_test_only = false;
    std::filesystem::path output;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--execute-live") execute_live = true;
        else if (arg == "--self-test-counters") self_test_only = true;
        else if (arg == "--output" && i + 1 < argc) output = argv[++i];
        else {
            std::cerr << "Usage: kasumi_gc_live_phase18 --self-test-counters\n"
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
    if (!execute_live || output.empty()) {
        std::cerr << "Live Phase 18 execution requires --execute-live and --output.\n";
        return 2;
    }
    return run(output) ? 0 : 1;
}
