#include "application/history_storage/epoch.hpp"
#include "application/history_storage/publication.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/maintenance.hpp"
#include "kasumi/test/history_storage.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/perf_trace.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

namespace {

using kasumi::Snapshot;
using kasumi::NodeRow;
using kasumi::test::TempWorkspace;
using Clock = std::chrono::steady_clock;

kasumi::runtime::RuntimeData make_runtime(TempWorkspace& workspace) {
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto db = kasumi::test::workspace_path(workspace, "db.sqlite3");
    const auto profile = kasumi::test::workspace_path(workspace, "profile");
    return kasumi::runtime::RuntimeData{
        .local_dir = local,
        .database_path = db,
        .key_path = profile / "key.bin",
        .storage_location = "unused",
    };
}

void put_content_fast(
    kasumi::transport::Transport& transport,
    const std::filesystem::path& plain_path,
    const std::filesystem::path& enc_path,
    std::string_view content,
    std::span<const std::uint8_t, kasumi::crypto::KEY_SIZE> key) {
    const auto identifier = kasumi::crypto::content_identifier(
        key, kasumi::hasher::hash_string(content));
    kasumi::test::write_text(plain_path, content);
    kasumi::crypto::encrypt_file(plain_path, enc_path, key);
    kasumi::transport::put(transport, enc_path, identifier);
}

void put_commit_fast(
    kasumi::transport::Transport& transport,
    const std::filesystem::path& plain_path,
    const std::filesystem::path& enc_path,
    const kasumi::history::Commit& commit,
    std::span<const std::uint8_t, kasumi::crypto::KEY_SIZE> key,
    bool publish_head = false) {
    const auto canonical = kasumi::history::serialize(commit).value();
    kasumi::test::write_binary(plain_path, std::as_bytes(std::span{canonical}));
    kasumi::crypto::encrypt_file(plain_path, enc_path, key, kasumi::crypto::FilePurpose::History);
    const auto hash = kasumi::crypto::content::hash_file(enc_path).value();
    HeadReference ref{.commit_id = commit_id(commit), .ciphertext_id = kasumi::hash_hex(hash)};
    kasumi::transport::put(transport, enc_path, object_path(ref));
    if (publish_head) {
        const auto marker = kasumi::application::history_storage::encode_marker(ref).value();
        const auto marker_path_temp = plain_path.parent_path() / "temp.marker";
        kasumi::test::write_binary(marker_path_temp, std::as_bytes(std::span{marker}));
        kasumi::transport::put(transport, marker_path_temp, marker_path(ref));
    }
}

struct SnapshotTimings {
    std::uint64_t physical_listing_us = 0;
    std::uint64_t history_reconstruction_us = 0;
    std::uint64_t build_history_inventory_us = 0;
    std::uint64_t load_and_auth_commits_us = 0;
    std::uint64_t inspect_markers_epochs_us = 0;
    std::uint64_t dag_traversal_us = 0;
    std::uint64_t validate_history_us = 0;
    std::uint64_t content_reachability_us = 0;
    std::uint64_t candidate_selection_us = 0;
};

struct TrialMetrics {
    std::string series;
    std::size_t N = 0;
    std::size_t H = 0;
    std::size_t rep = 0;

    // Fixture state
    std::size_t physical_content_objects = 0;
    std::size_t physical_commit_objects = 0;
    std::size_t physical_control_objects = 0;
    std::size_t physical_quarantine_objects = 0;
    std::size_t total_physical_objects = 0;
    std::size_t retained_heads = 0;
    std::size_t retained_epochs = 0;
    std::size_t retained_commits = 0;
    std::size_t content_references_examined = 0;
    std::size_t unique_reachable_content_ids = 0;
    std::size_t orphan_candidates = 0;

    // History reconstruction
    std::size_t commit_object_get_calls = 0;
    std::size_t marker_object_get_calls = 0;

    // Timings (us)
    std::uint64_t barrier_acquire_us = 0;
    std::uint64_t writer_check_us = 0;
    std::uint64_t consistency_probe_us = 0;
    std::uint64_t stage_barrier_writers_us = 0;

    std::uint64_t quarantine_inventory_us = 0;
    std::uint64_t quarantine_restore_us = 0;
    std::uint64_t quarantine_metadata_init_us = 0;
    std::uint64_t stage_quarantine_inventory_recovery_us = 0;

    std::uint64_t stage_reachability_obs1_us = 0;
    std::uint64_t stage_reachability_obs2_us = 0;
    std::uint64_t stage_snapshot_comparison_us = 0;
    std::uint64_t stage_final_listing_us = 0;
    std::uint64_t stage_purge_expired_us = 0;

    std::uint64_t stage_time_to_first_candidate_us = 0;

    std::uint64_t batch_prepare_us = 0;
    std::uint64_t batch_verify_us = 0;
    std::uint64_t batch_publish_remove_us = 0;
    std::uint64_t stage_candidates_processing_us = 0;

    std::uint64_t total_gc_us = 0;
    std::uint64_t wall_clock_us = 0;
    std::uint64_t get_commit_us = 0;
    std::uint64_t build_history_inventory_us = 0;
    std::uint64_t load_and_auth_commits_us = 0;
    std::uint64_t inspect_markers_epochs_us = 0;
    std::uint64_t dag_traversal_us = 0;
    SnapshotTimings snapshot1;
    SnapshotTimings snapshot2;

    // Transport calls
    std::size_t transport_list_count = 0;
    std::size_t transport_full_list_count = 0;
    std::size_t transport_prefix_list_count = 0;
    std::size_t transport_get_count = 0;
    std::size_t transport_put_count = 0;
    std::size_t transport_copy_count = 0;
    std::size_t transport_remove_count = 0;
    std::size_t transport_presence_count = 0;
    std::size_t transport_physical_hash_count = 0;
    std::size_t transport_physical_hash_batch_count = 0;
    std::size_t transport_barrier_verify_count = 0;

    // Identifiers & structural items
    std::size_t total_identifiers_listed = 0;
    std::size_t candidates_detected = 0;
    std::size_t candidates_quarantined = 0;
};

void collect_metrics_post_gc(TrialMetrics& m, FakeState* state, const kasumi::application::integrity::GarbageCollectResult& collected) {
    // Collect perf trace timers (in microseconds)
    m.barrier_acquire_us = kasumi::platform::perf_trace::get_time("gc barrier acquire");
    m.writer_check_us = kasumi::platform::perf_trace::get_time("gc writer consistency checks");
    m.consistency_probe_us = kasumi::platform::perf_trace::get_time("gc backend consistency probe");
    m.stage_barrier_writers_us = m.barrier_acquire_us + m.writer_check_us + m.consistency_probe_us;

    m.quarantine_inventory_us = kasumi::platform::perf_trace::get_time("gc quarantine inventory");
    m.quarantine_restore_us = kasumi::platform::perf_trace::get_time("gc quarantine restoration");
    m.quarantine_metadata_init_us = kasumi::platform::perf_trace::get_time("gc prior metadata initialization");
    m.stage_quarantine_inventory_recovery_us = m.quarantine_inventory_us + m.quarantine_restore_us + m.quarantine_metadata_init_us;

    m.stage_reachability_obs1_us = kasumi::platform::perf_trace::get_time("gc reachability observation 1");
    m.stage_reachability_obs2_us = kasumi::platform::perf_trace::get_time("gc reachability observation 2");
    m.stage_snapshot_comparison_us = kasumi::platform::perf_trace::get_time("gc stable-state comparison");
    m.stage_final_listing_us = kasumi::platform::perf_trace::get_time("gc final namespace verification");
    m.stage_purge_expired_us = kasumi::platform::perf_trace::get_time("gc expired quarantine purge");

    m.stage_time_to_first_candidate_us =
        m.stage_barrier_writers_us +
        m.stage_quarantine_inventory_recovery_us +
        m.stage_reachability_obs1_us +
        m.stage_reachability_obs2_us +
        m.stage_snapshot_comparison_us +
        m.stage_final_listing_us +
        m.stage_purge_expired_us;

    m.batch_prepare_us = kasumi::platform::perf_trace::get_time("gc.batch_prepare_duration_us");
    m.batch_verify_us = kasumi::platform::perf_trace::get_time("gc.batch_verify_duration_us");
    m.batch_publish_remove_us = kasumi::platform::perf_trace::get_time("gc.batch_publish_remove_duration_us");
    m.stage_candidates_processing_us = m.batch_prepare_us + m.batch_verify_us + m.batch_publish_remove_us;

    m.total_gc_us = kasumi::platform::perf_trace::get_time("gc.total_duration_us");

    m.get_commit_us = kasumi::platform::perf_trace::get_time("rc/get_commit");
    const auto trace_time = [](std::string_view scope,
                               std::string_view name) {
        std::string metric{scope};
        metric.append(name);
        return kasumi::platform::perf_trace::get_time(metric);
    };
    const auto collect_snapshot = [&](SnapshotTimings& timings,
                                      std::string_view scope) {
        timings.physical_listing_us =
            trace_time(scope, ".physical_listing_us");
        timings.history_reconstruction_us =
            trace_time(scope, ".history_reconstruction_us");
        timings.build_history_inventory_us =
            trace_time(scope, "/rc/build_history_inventory");
        timings.load_and_auth_commits_us =
            trace_time(scope, "/rc/load_and_auth_commits");
        timings.inspect_markers_epochs_us =
            trace_time(scope, "/rc/inspect_markers_epochs");
        timings.dag_traversal_us = trace_time(scope, "/rc/dag_traversal");
        timings.validate_history_us = trace_time(scope, ".validate_history_us");
        timings.content_reachability_us =
            trace_time(scope, ".content_reachability_us");
        timings.candidate_selection_us =
            trace_time(scope, ".candidate_selection_us");
    };
    collect_snapshot(m.snapshot1, "gc.snapshot.first");
    collect_snapshot(m.snapshot2, "gc.snapshot.second");
    m.build_history_inventory_us =
        m.snapshot1.build_history_inventory_us +
        m.snapshot2.build_history_inventory_us;
    m.load_and_auth_commits_us = m.snapshot1.load_and_auth_commits_us +
                                 m.snapshot2.load_and_auth_commits_us;
    m.inspect_markers_epochs_us = m.snapshot1.inspect_markers_epochs_us +
                                  m.snapshot2.inspect_markers_epochs_us;
    m.dag_traversal_us =
        m.snapshot1.dag_traversal_us + m.snapshot2.dag_traversal_us;

    kasumi::platform::perf_trace::force_enable(false);

    // Collect Transport stats
    m.transport_list_count = state->list_count;
    m.transport_full_list_count = state->full_list_count;
    m.transport_prefix_list_count = state->prefix_list_count;
    m.transport_get_count = state->get_count;
    m.transport_put_count = state->put_count;
    m.transport_copy_count = state->copy_count;
    m.transport_remove_count = state->remove_count;
    m.transport_presence_count = state->presence_count;
    m.transport_physical_hash_count = state->physical_hash_count;
    m.transport_physical_hash_batch_count = state->physical_hash_batch_count;
    m.transport_barrier_verify_count = state->barrier_verification_count;

    m.total_identifiers_listed = state->full_list_identifier_count;
    m.commit_object_get_calls = state->commit_get_count;
    m.marker_object_get_calls = state->marker_get_count;

    m.candidates_detected = collected.candidate_objects;
    m.candidates_quarantined = collected.quarantined_objects;
}

// Serie A: Vary physical inventory N in {100, 1000, 10000}, C=10, H=1
TrialMetrics run_trial_serie_a(std::size_t N, std::size_t rep) {
    TrialMetrics m;
    m.series = "A";
    m.N = N;
    m.H = 1;
    m.rep = rep;

    auto workspace = kasumi::test::make_temp_workspace(
        "gc-scale-serieA-N" + std::to_string(N) + "-r" + std::to_string(rep));
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    if (!kasumi::transport::initialize(transport)) {
        std::cerr << "Transport initialize failed\n";
        std::abort();
    }
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 6);

    auto runtime = make_runtime(workspace);
    const auto key = test_key();

    constexpr std::size_t orphan_count = 10;
    constexpr std::size_t history_count = 2; // 1 commit + 1 head marker
    if (N < orphan_count + history_count) {
        std::cerr << "N must be at least " << (orphan_count + history_count) << '\n';
        std::abort();
    }
    const std::size_t live_count = N - orphan_count - history_count;

    Snapshot tree;
    tree.rows.reserve(live_count + 1);
    tree.rows.push_back(NodeRow{.path = "", .hash = {}, .size = 0, .mtime = {}, .is_directory = true});
    for (std::size_t i = 0; i < live_count; ++i) {
        std::string path = "file_" + std::to_string(i) + ".bin";
        std::string content = "live_content_" + std::to_string(i);
        tree.rows.push_back(NodeRow{
            .path = path,
            .hash = kasumi::hasher::hash_string(content),
            .size = content.size(),
            .mtime = {},
            .is_directory = false
        });
    }
    kasumi::finalize_snapshot(tree);
    auto commit_res = kasumi::history::make_commit(0, {}, std::move(tree));
    if (!commit_res) {
        std::cerr << "make_commit failed: " << commit_res.error().detail << '\n';
        std::abort();
    }
    auto published = kasumi::application::history_storage::publish_commit(
        transport, key, *commit_res, kasumi::test::workspace_root(workspace));
    if (!published) {
        std::cerr << "publish_commit failed\n";
        std::abort();
    }

    const auto plain_file = kasumi::test::workspace_path(workspace, "temp.plain");
    const auto enc_file = kasumi::test::workspace_path(workspace, "temp.enc");

    for (std::size_t i = 0; i < live_count; ++i) {
        std::string content = "live_content_" + std::to_string(i);
        put_content_fast(transport, plain_file, enc_file, content, key);
    }

    for (std::size_t i = 0; i < orphan_count; ++i) {
        std::string content = "orphan_content_" + std::to_string(i);
        put_content_fast(transport, plain_file, enc_file, content, key);
    }

    if (state->objects.size() != N) {
        std::cerr << "Expected " << N << " objects in storage, found " << state->objects.size() << '\n';
        std::abort();
    }

    m.physical_content_objects = live_count + orphan_count;
    m.physical_commit_objects = 1;
    m.physical_control_objects = 1; // 1 head marker
    m.physical_quarantine_objects = 0;
    m.total_physical_objects = N;
    m.retained_heads = 1;
    m.retained_epochs = 0;
    m.retained_commits = 1;
    m.content_references_examined = live_count;
    m.unique_reachable_content_ids = live_count;
    m.orphan_candidates = orphan_count;

    reset_fake_traffic(*state);
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    const auto start_gc = Clock::now();
    auto collected = kasumi::application::integrity::garbage_collect(runtime, transport, key);
    const auto end_gc = Clock::now();
    m.wall_clock_us = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(end_gc - start_gc).count());

    if (!collected) {
        std::cerr << "garbage_collect failed: " << kasumi::application::integrity::describe(collected.error()) << '\n';
        std::abort();
    }
    if (collected->candidate_objects != orphan_count || collected->quarantined_objects != orphan_count) {
        std::cerr << "Unexpected candidate/quarantine count: " << collected->candidate_objects << " / " << collected->quarantined_objects << '\n';
        std::abort();
    }

    collect_metrics_post_gc(m, state, *collected);
    return m;
}

// Serie B: Vary retained DAG history H in {10, 100, 1000}, constant content (10 live, 10 orphans)
TrialMetrics run_trial_serie_b(std::size_t H, std::size_t rep) {
    TrialMetrics m;
    m.series = "B";
    m.H = H;
    m.rep = rep;

    auto workspace = kasumi::test::make_temp_workspace(
        "gc-scale-serieB-H" + std::to_string(H) + "-r" + std::to_string(rep));
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    if (!kasumi::transport::initialize(transport)) {
        std::cerr << "Transport initialize failed\n";
        std::abort();
    }
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 6);

    auto runtime = make_runtime(workspace);
    const auto key = test_key();
    const auto layout = kasumi::application::history_storage::derive_remote_layout(key);

    constexpr std::size_t live_count = 10;
    constexpr std::size_t orphan_count = 10;

    const auto plain_file = kasumi::test::workspace_path(workspace, "temp.plain");
    const auto enc_file = kasumi::test::workspace_path(workspace, "temp.enc");

    for (std::size_t i = 0; i < live_count; ++i) {
        std::string content = "shared_live_content_" + std::to_string(i);
        put_content_fast(transport, plain_file, enc_file, content, key);
    }

    for (std::size_t i = 0; i < orphan_count; ++i) {
        std::string content = "orphan_content_" + std::to_string(i);
        put_content_fast(transport, plain_file, enc_file, content, key);
    }

    Snapshot tree;
    tree.rows.reserve(live_count + 1);
    tree.rows.push_back(NodeRow{.path = "", .hash = {}, .size = 0, .mtime = {}, .is_directory = true});
    for (std::size_t i = 0; i < live_count; ++i) {
        std::string path = "file_" + std::to_string(i) + ".bin";
        std::string content = "shared_live_content_" + std::to_string(i);
        tree.rows.push_back(NodeRow{
            .path = path,
            .hash = kasumi::hasher::hash_string(content),
            .size = content.size(),
            .mtime = {},
            .is_directory = false
        });
    }
    kasumi::finalize_snapshot(tree);

    // Build chain of H commits
    const auto commit_plain = kasumi::test::workspace_path(workspace, "commit.plain");
    const auto commit_enc = kasumi::test::workspace_path(workspace, "commit.enc");

    std::string previous_commit_id;
    for (std::size_t h = 0; h < H; ++h) {
        std::vector<std::string> parents;
        if (!previous_commit_id.empty()) {
            parents.push_back(previous_commit_id);
        }
        auto commit_res = kasumi::history::make_commit(h, parents, tree);
        if (!commit_res) {
            std::cerr << "make_commit failed at height " << h << '\n';
            std::abort();
        }
        previous_commit_id = commit_id(*commit_res);
        const bool is_tip = (h + 1 == H);
        put_commit_fast(transport, commit_plain, commit_enc, *commit_res, key, is_tip);
    }

    m.N = state->objects.size();
    m.physical_content_objects = live_count + orphan_count;
    m.physical_commit_objects = H;
    m.physical_control_objects = 1; // 1 head marker
    m.physical_quarantine_objects = 0;
    m.total_physical_objects = state->objects.size();
    m.retained_heads = 1;
    m.retained_epochs = 0;
    m.retained_commits = H;
    m.content_references_examined = H * live_count;
    m.unique_reachable_content_ids = live_count;
    m.orphan_candidates = orphan_count;

    reset_fake_traffic(*state);
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    const auto start_gc = Clock::now();
    auto collected = kasumi::application::integrity::garbage_collect(runtime, transport, key);
    const auto end_gc = Clock::now();
    m.wall_clock_us = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(end_gc - start_gc).count());

    if (!collected) {
        std::cerr << "garbage_collect failed in Serie B: " << kasumi::application::integrity::describe(collected.error()) << '\n';
        std::abort();
    }
    if (collected->candidate_objects != orphan_count || collected->quarantined_objects != orphan_count) {
        std::cerr << "Unexpected candidate count in Serie B: " << collected->candidate_objects << '\n';
        std::abort();
    }

    collect_metrics_post_gc(m, state, *collected);
    return m;
}

struct SummaryStats {
    double min_v = 0;
    double median_v = 0;
    double max_v = 0;

    static SummaryStats compute(std::vector<double> vals) {
        if (vals.empty()) return {};
        std::ranges::sort(vals);
        double min_v = vals.front();
        double max_v = vals.back();
        double median_v = 0;
        const auto sz = vals.size();
        if (sz % 2 == 1) {
            median_v = vals[sz / 2];
        } else {
            median_v = (vals[sz / 2 - 1] + vals[sz / 2]) / 2.0;
        }
        return SummaryStats{min_v, median_v, max_v};
    }
};

nlohmann::json summarize_trials(const std::vector<TrialMetrics>& trials) {
    auto extract = [&](auto member_ptr) {
        std::vector<double> vals;
        vals.reserve(trials.size());
        for (const auto& t : trials) {
            vals.push_back(static_cast<double>(t.*member_ptr));
        }
        return SummaryStats::compute(vals);
    };
    auto extract_snapshot = [&](bool first, auto member_ptr) {
        std::vector<double> vals;
        vals.reserve(trials.size());
        for (const auto& trial : trials) {
            const auto& snapshot = first ? trial.snapshot1 : trial.snapshot2;
            vals.push_back(static_cast<double>(snapshot.*member_ptr));
        }
        return SummaryStats::compute(vals);
    };

    auto s_barrier = extract(&TrialMetrics::stage_barrier_writers_us);
    auto s_quarantine = extract(&TrialMetrics::stage_quarantine_inventory_recovery_us);
    auto s_obs1 = extract(&TrialMetrics::stage_reachability_obs1_us);
    auto s_obs2 = extract(&TrialMetrics::stage_reachability_obs2_us);
    auto s_compare = extract(&TrialMetrics::stage_snapshot_comparison_us);
    auto s_final_list = extract(&TrialMetrics::stage_final_listing_us);
    auto s_purge = extract(&TrialMetrics::stage_purge_expired_us);
    auto s_first_cand = extract(&TrialMetrics::stage_time_to_first_candidate_us);
    auto s_cand_proc = extract(&TrialMetrics::stage_candidates_processing_us);
    auto s_batch_prep = extract(&TrialMetrics::batch_prepare_us);
    auto s_batch_verify = extract(&TrialMetrics::batch_verify_us);
    auto s_batch_publish = extract(&TrialMetrics::batch_publish_remove_us);
    auto s_total = extract(&TrialMetrics::total_gc_us);
    auto s_wall = extract(&TrialMetrics::wall_clock_us);
    auto s_build_hist = extract(&TrialMetrics::build_history_inventory_us);
    auto s_dag = extract(&TrialMetrics::dag_traversal_us);
    auto s_get_commit = extract(&TrialMetrics::get_commit_us);
    auto snapshot_attribution = [&](bool first) {
        const auto total = first ? s_obs1 : s_obs2;
        const auto physical = extract_snapshot(
            first, &SnapshotTimings::physical_listing_us);
        const auto history = extract_snapshot(
            first, &SnapshotTimings::history_reconstruction_us);
        const auto validation = extract_snapshot(
            first, &SnapshotTimings::validate_history_us);
        const auto content = extract_snapshot(
            first, &SnapshotTimings::content_reachability_us);
        const auto candidates = extract_snapshot(
            first, &SnapshotTimings::candidate_selection_us);
        const auto inventory = extract_snapshot(
            first, &SnapshotTimings::build_history_inventory_us);
        const auto load = extract_snapshot(
            first, &SnapshotTimings::load_and_auth_commits_us);
        const auto inspect = extract_snapshot(
            first, &SnapshotTimings::inspect_markers_epochs_us);
        const auto dag = extract_snapshot(
            first, &SnapshotTimings::dag_traversal_us);
        const auto history_residual = history.median_v -
                                      inventory.median_v - load.median_v -
                                      inspect.median_v - dag.median_v;
        const auto snapshot_residual = total.median_v - physical.median_v -
                                       history.median_v - validation.median_v -
                                       content.median_v - candidates.median_v;
        return nlohmann::json{
            {"calls_per_successful_observation", 1},
            {"exclusive_partition_median_us",
             {{"physical_listing", physical.median_v},
              {"history_reconstruction", history.median_v},
              {"history_validation", validation.median_v},
              {"content_reachability", content.median_v},
              {"candidate_selection", candidates.median_v},
              {"residual_unattributed", snapshot_residual}}},
            {"history_reconstruction_detail_median_us",
             {{"build_history_inventory", inventory.median_v},
              {"load_and_auth_commits", load.median_v},
              {"inspect_markers_epochs", inspect.median_v},
              {"dag_traversal", dag.median_v},
              {"history_residual_unattributed", history_residual}}}};
    };

    const auto& rep1 = trials.front();
    nlohmann::json entry;
    entry["series"] = rep1.series;
    entry["N"] = rep1.N;
    entry["H"] = rep1.H;
    entry["repetitions"] = trials.size();

    entry["fixture_state"] = {
        {"physical_content_objects", rep1.physical_content_objects},
        {"physical_commit_objects", rep1.physical_commit_objects},
        {"physical_control_objects", rep1.physical_control_objects},
        {"physical_quarantine_objects", rep1.physical_quarantine_objects},
        {"total_physical_objects", rep1.total_physical_objects},
        {"retained_heads", rep1.retained_heads},
        {"retained_epochs", rep1.retained_epochs},
        {"retained_commits", rep1.retained_commits},
        {"content_references_examined", rep1.content_references_examined},
        {"unique_reachable_content_ids", rep1.unique_reachable_content_ids},
        {"orphan_candidates", rep1.orphan_candidates}
    };

    entry["history_reconstruction"] = {
        {"retained_commits_fixture", rep1.retained_commits},
        {"commit_object_get_calls", rep1.commit_object_get_calls},
        {"marker_object_get_calls", rep1.marker_object_get_calls},
        {"other_object_get_calls", rep1.transport_get_count - rep1.commit_object_get_calls - rep1.marker_object_get_calls},
        {"commit_object_get_calls_per_observation", rep1.commit_object_get_calls / 2}
    };
    entry["snapshot_attribution"] = {
        {"observation_1", snapshot_attribution(true)},
        {"observation_2", snapshot_attribution(false)},
        {"get_commit_transport_time_both_observations_inclusive_us",
         s_get_commit.median_v}
    };

    entry["timings_us"] = {
        {"barrier_and_writers", {{"min", s_barrier.min_v}, {"median", s_barrier.median_v}, {"max", s_barrier.max_v}}},
        {"quarantine_inventory_recovery", {{"min", s_quarantine.min_v}, {"median", s_quarantine.median_v}, {"max", s_quarantine.max_v}}},
        {"reachability_obs1", {{"min", s_obs1.min_v}, {"median", s_obs1.median_v}, {"max", s_obs1.max_v}}},
        {"reachability_obs2", {{"min", s_obs2.min_v}, {"median", s_obs2.median_v}, {"max", s_obs2.max_v}}},
        {"snapshot_comparison", {{"min", s_compare.min_v}, {"median", s_compare.median_v}, {"max", s_compare.max_v}}},
        {"final_physical_listing", {{"min", s_final_list.min_v}, {"median", s_final_list.median_v}, {"max", s_final_list.max_v}}},
        {"purge_expired_quarantine", {{"min", s_purge.min_v}, {"median", s_purge.median_v}, {"max", s_purge.max_v}}},
        {"time_to_first_candidate", {{"min", s_first_cand.min_v}, {"median", s_first_cand.median_v}, {"max", s_first_cand.max_v}}},
        {"candidates_processing", {{"min", s_cand_proc.min_v}, {"median", s_cand_proc.median_v}, {"max", s_cand_proc.max_v}}},
        {"batch_prepare_us", {{"min", s_batch_prep.min_v}, {"median", s_batch_prep.median_v}, {"max", s_batch_prep.max_v}}},
        {"batch_verify_us", {{"min", s_batch_verify.min_v}, {"median", s_batch_verify.median_v}, {"max", s_batch_verify.max_v}}},
        {"batch_publish_remove_us", {{"min", s_batch_publish.min_v}, {"median", s_batch_publish.median_v}, {"max", s_batch_publish.max_v}}},
        {"build_history_inventory_us", {{"min", s_build_hist.min_v}, {"median", s_build_hist.median_v}, {"max", s_build_hist.max_v}}},
        {"dag_traversal_us", {{"min", s_dag.min_v}, {"median", s_dag.median_v}, {"max", s_dag.max_v}}},
        {"get_commit_us", {{"min", s_get_commit.min_v}, {"median", s_get_commit.median_v}, {"max", s_get_commit.max_v}}},
        {"total_gc_us", {{"min", s_total.min_v}, {"median", s_total.median_v}, {"max", s_total.max_v}}},
        {"wall_clock_us", {{"min", s_wall.min_v}, {"median", s_wall.median_v}, {"max", s_wall.max_v}}}
    };

    entry["transport_calls"] = {
        {"list_total", rep1.transport_list_count},
        {"list_full_namespace", rep1.transport_full_list_count},
        {"list_scoped_prefix", rep1.transport_prefix_list_count},
        {"get", rep1.transport_get_count},
        {"put", rep1.transport_put_count},
        {"copy", rep1.transport_copy_count},
        {"remove", rep1.transport_remove_count},
        {"presence", rep1.transport_presence_count},
        {"physical_hash_individual", rep1.transport_physical_hash_count},
        {"physical_hash_batch", rep1.transport_physical_hash_batch_count},
        {"barrier_verify", rep1.transport_barrier_verify_count}
    };

    entry["identifiers_examined"] = rep1.total_identifiers_listed;

    return entry;
}

} // namespace

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    std::filesystem::path output_file = "build-msys2-ucrt64/phase11_scratch/phase14_gc_scale_profile.json";
    std::string run_series = "all";
    for (int i = 1; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "--output" && i + 1 < argc) {
            output_file = argv[++i];
        } else if (arg == "--series" && i + 1 < argc) {
            run_series = argv[++i];
        }
    }

    std::cout << "========================================================================\n"
              << "KASUMI PHASE 14: REAL FULL GC SCALE & HISTORY DAG PROFILING (OFFLINE)\n"
              << "========================================================================\n\n";

    constexpr std::size_t repetitions = 5;
    nlohmann::json root_json;

    if (run_series == "all" || run_series == "A" || run_series == "a") {
        std::cout << "=== SÉRIE A: INVENTÁRIO FÍSICO CRESCENTE (N in {100, 1000, 10000}, C=10, H=1) ===\n";
        const std::vector<std::size_t> N_values = {100, 1000, 10000};
        for (const auto N : N_values) {
            std::cout << ">>> Running Série A for N = " << N << " (" << repetitions << " independent repetitions)...\n";
            std::vector<TrialMetrics> trials;
            trials.reserve(repetitions);
            for (std::size_t r = 1; r <= repetitions; ++r) {
                auto m = run_trial_serie_a(N, r);
                std::cout << "  [Rep " << r << "] Total GC: " << (static_cast<double>(m.total_gc_us) / 1000.0) << " ms | Time to first candidate: "
                          << (static_cast<double>(m.stage_time_to_first_candidate_us) / 1000.0) << " ms | Candidates processing: "
                          << (static_cast<double>(m.stage_candidates_processing_us) / 1000.0) << " ms\n";
                trials.push_back(m);
            }
            root_json["series_a"]["N_" + std::to_string(N)] = summarize_trials(trials);
            std::cout << '\n';
        }
    }

    if (run_series == "all" || run_series == "B" || run_series == "b") {
        std::cout << "=== SÉRIE B: HISTÓRICO PROTEGIDO CRESCENTE (H in {10, 100, 1000}, C=10 live + 10 orphans) ===\n";
        const std::vector<std::size_t> H_values = {10, 100, 1000};
        for (const auto H : H_values) {
            std::cout << ">>> Running Série B for H = " << H << " (" << repetitions << " independent repetitions)...\n";
            std::vector<TrialMetrics> trials;
            trials.reserve(repetitions);
            for (std::size_t r = 1; r <= repetitions; ++r) {
                auto m = run_trial_serie_b(H, r);
                std::cout << "  [Rep " << r << "] Total GC: " << (static_cast<double>(m.total_gc_us) / 1000.0) << " ms | Time to first candidate: "
                          << (static_cast<double>(m.stage_time_to_first_candidate_us) / 1000.0) << " ms | Candidates processing: "
                          << (static_cast<double>(m.stage_candidates_processing_us) / 1000.0) << " ms\n";
                trials.push_back(m);
            }
            root_json["series_b"]["H_" + std::to_string(H)] = summarize_trials(trials);
            std::cout << '\n';
        }
    }

    std::filesystem::create_directories(output_file.parent_path());
    std::ofstream out_stream(output_file, std::ios::binary | std::ios::trunc);
    if (out_stream) {
        out_stream << root_json.dump(2) << '\n';
        std::cout << "Saved full JSON profile report to: " << output_file << "\n\n";
    }

    return 0;
}
