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
    const std::filesystem::path& workspace_root,
    const kasumi::history::Commit& commit,
    std::span<const std::uint8_t, kasumi::crypto::KEY_SIZE> key,
    bool publish_head = false) {
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(key);
    auto published = kasumi::application::history_storage::
        publish_commit_object_scoped(
            transport, layout, key, commit, workspace_root);
    if (!published) {
        std::cerr << "publish_commit_object_scoped failed: "
                  << published.error().detail << '\n';
        std::abort();
    }
    if (publish_head) {
        auto marker = kasumi::application::history_storage::
            publish_head_marker_scoped(
                transport, layout, published->head, workspace_root);
        if (!marker) {
            std::cerr << "publish_head_marker_scoped failed: "
                      << marker.error().detail << '\n';
            std::abort();
        }
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
    std::size_t epoch_anchors = 0;
    std::size_t epoch_anchor_total = 0;
    std::size_t restored_objects = 0;
    std::size_t purged_objects = 0;
    std::size_t content_references_examined = 0;
    std::size_t unique_reachable_content_ids = 0;
    std::size_t orphan_candidates = 0;

    // History reconstruction
    std::size_t commit_object_get_calls = 0;
    std::size_t marker_object_get_calls = 0;
    std::size_t epoch_object_get_calls = 0;
    std::size_t content_reference_capacity_growth_events = 0;

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
    m.content_reference_capacity_growth_events =
        kasumi::platform::perf_trace::get_count(
            "rc/content_reference_capacity_growth_events");

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
    m.epoch_object_get_calls = state->epoch_get_count;

    m.candidates_detected = collected.candidate_objects;
    m.candidates_quarantined = collected.quarantined_objects;
    m.restored_objects = collected.restored_objects;
    m.purged_objects = collected.purged_objects;
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
        put_commit_fast(transport,
                        kasumi::test::workspace_root(workspace),
                        *commit_res,
                        key,
                        is_tip);
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

// Phase 17: valid production Epochs with a fixed recent window and physical
// history that grows independently of that window.
TrialMetrics run_trial_retention(std::size_t P,
                                 std::size_t recent_per_head,
                                 std::size_t branch_count,
                                 std::size_t rep) {
    constexpr std::int64_t retention_now = 1'800'000'000;
    using namespace kasumi::application::history_storage;
    namespace epoch = kasumi::application::history_storage::epoch;

    if (branch_count == 0 || P <= branch_count ||
        (P - 1) / branch_count < recent_per_head + 5) {
        std::cerr << "invalid Phase 17 retention fixture dimensions\n";
        std::abort();
    }

    TrialMetrics m;
    m.series = "R";
    m.H = P;
    m.rep = rep;

    auto workspace = kasumi::test::make_temp_workspace(
        "gc-phase17-P" + std::to_string(P) + "-recent" +
        std::to_string(recent_per_head) + "-branches" +
        std::to_string(branch_count) + "-r" + std::to_string(rep));
    FakeState* state = nullptr;
    auto transport = make_fake_transport(state);
    if (!kasumi::transport::initialize(transport)) {
        std::cerr << "Transport initialize failed\n";
        std::abort();
    }
    state->physical_hash_supported = true;
    state->copy_supported = true;
    enable_fake_physical_hash_batch(transport, *state, 6);

    const auto runtime = make_runtime(workspace);
    const auto key = test_key();
    const auto layout = derive_remote_layout(key);
    const auto workspace_root = kasumi::test::workspace_root(workspace);
    const auto plain_file = kasumi::test::workspace_path(workspace, "temp.plain");
    const auto enc_file = kasumi::test::workspace_path(workspace, "temp.enc");
    constexpr std::string_view content = "phase17-shared-retained-content";
    put_content_fast(transport, plain_file, enc_file, content, key);

    Snapshot tree{.rows = {
        NodeRow{.path = "", .hash = {}, .size = 0, .mtime = {},
                .is_directory = true},
        NodeRow{.path = "shared.bin",
                .hash = kasumi::hasher::hash_string(content),
                .size = content.size(), .mtime = {}, .is_directory = false},
    }};
    kasumi::finalize_snapshot(tree);

    const auto publish_object = [&](const kasumi::history::Commit& commit) {
        auto published = publish_commit_object_scoped(
            transport, layout, key, commit, workspace_root);
        if (!published) {
            std::cerr << "publish_commit_object_scoped failed: "
                      << published.error().detail << '\n';
            std::abort();
        }
        return published->head;
    };

    const auto root_time = retention_now - 48 * 3600;
    auto root = kasumi::history::make_commit(0, {}, tree, root_time);
    if (!root) {
        std::cerr << "root commit creation failed\n";
        std::abort();
    }
    auto root_reference = publish_object(*root);
    std::vector<kasumi::history::LoadedCommit> planning_commits;
    planning_commits.push_back(kasumi::history::LoadedCommit{
        .id = root_reference.commit_id, .commit = *root});

    const auto branch_total = P - 1;
    const auto base_branch_size = branch_total / branch_count;
    const auto branch_remainder = branch_total % branch_count;
    std::vector<HeadReference> heads;
    heads.reserve(branch_count);
    for (std::size_t branch = 0; branch < branch_count; ++branch) {
        const auto branch_size =
            base_branch_size + static_cast<std::size_t>(branch < branch_remainder);
        const auto tail = branch_size - recent_per_head + 1;
        auto parent = root_reference.commit_id;
        HeadReference head = root_reference;
        for (std::size_t height = 1; height <= branch_size; ++height) {
            const auto timestamp = height < tail
                ? root_time + static_cast<std::int64_t>(branch * branch_size + height)
                : retention_now - 3600 +
                      static_cast<std::int64_t>(height - tail) *
                          3600 / static_cast<std::int64_t>(recent_per_head);
            auto commit = kasumi::history::make_commit(
                height, {parent}, tree, timestamp);
            if (!commit) {
                std::cerr << "branch commit creation failed at height "
                          << height << '\n';
                std::abort();
            }
            head = publish_object(*commit);
            planning_commits.push_back(kasumi::history::LoadedCommit{
                .id = head.commit_id, .commit = *commit});
            parent = head.commit_id;
        }
        auto marker = publish_head_marker_scoped(
            transport, layout, head, workspace_root);
        if (!marker) {
            std::cerr << "publish_head_marker_scoped failed: "
                      << marker.error().detail << '\n';
            std::abort();
        }
        heads.push_back(std::move(head));
    }

    const epoch::RetentionPolicy policy{};
    const auto plan = epoch::plan_pruning(planning_commits, policy);
    if (!plan) {
        std::cerr << "production retention planner did not produce anchors: "
                  << plan.error().reason << '\n';
        std::abort();
    }
    const std::string vault_id(64, 'a');
    const auto genesis = epoch::seal(
        epoch::Epoch{.vault_id = vault_id,
                     .sequence = 0,
                     .issued_at = root_time,
                     .policy = policy,
                     .anchors = {{.commit_id = root_reference.commit_id,
                                  .height = 0}}}, key);
    if (!genesis || !epoch::publish(transport, key, *genesis, workspace_root)) {
        std::cerr << "production genesis Epoch publication failed\n";
        std::abort();
    }
    const auto latest = epoch::seal(
        epoch::Epoch{.vault_id = vault_id,
                     .sequence = 1,
                     .issued_at = retention_now,
                     .policy = policy,
                     .anchors = plan->anchors,
                     .previous_epoch_id = genesis->reference.epoch_id}, key);
    if (!latest || !epoch::publish(transport, key, *latest, workspace_root)) {
        std::cerr << "production pruning Epoch publication failed\n";
        std::abort();
    }

    const auto protected_count =
        planning_commits.size() - plan->prunable_commits.size() +
        plan->anchors.size();
    m.N = state->objects.size();
    m.physical_commit_objects = planning_commits.size();
    m.physical_content_objects = 1;
    m.physical_control_objects = heads.size() + 2;
    m.total_physical_objects = m.N;
    m.retained_heads = heads.size();
    m.retained_epochs = 2;
    m.retained_commits = protected_count;
    m.epoch_anchors = plan->anchors.size();
    m.epoch_anchor_total = plan->anchors.size() + 1;
    m.content_references_examined = protected_count;
    m.unique_reachable_content_ids = 1;

    reset_fake_traffic(*state);
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();
    const auto start = Clock::now();
    auto collected = kasumi::application::integrity::garbage_collect(
        runtime, transport, key);
    const auto end = Clock::now();
    m.wall_clock_us = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count());
    if (!collected) {
        std::cerr << "Phase 17 full GC failed: "
                  << kasumi::application::integrity::describe(collected.error())
                  << '\n';
        std::abort();
    }
    const auto expected_candidates = planning_commits.size() - protected_count;
    if (collected->candidate_objects != expected_candidates ||
        collected->quarantined_objects != expected_candidates ||
        collected->restored_objects != 0 || collected->purged_objects != 0) {
        std::cerr << "Phase 17 candidate mismatch: expected "
                  << expected_candidates << ", got "
                  << collected->candidate_objects << "/"
                  << collected->quarantined_objects << '\n';
        std::abort();
    }
    m.orphan_candidates = collected->candidate_objects;
    collect_metrics_post_gc(m, state, *collected);
    return m;
}

struct SummaryStats {
    double min_v = 0;
    double median_v = 0;
    double max_v = 0;
    double mean_v = 0;

    static SummaryStats compute(std::vector<double> vals) {
        if (vals.empty()) return {};
        std::ranges::sort(vals);
        double min_v = vals.front();
        double max_v = vals.back();
        const double mean_v =
            std::accumulate(vals.begin(), vals.end(), 0.0) /
            static_cast<double>(vals.size());
        double median_v = 0;
        const auto sz = vals.size();
        if (sz % 2 == 1) {
            median_v = vals[sz / 2];
        } else {
            median_v = (vals[sz / 2 - 1] + vals[sz / 2]) / 2.0;
        }
        return SummaryStats{min_v, median_v, max_v, mean_v};
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
        const auto history_residual = history.mean_v - inventory.mean_v -
                                      load.mean_v - inspect.mean_v - dag.mean_v;
        const auto snapshot_residual = total.mean_v - physical.mean_v -
                                       history.mean_v - validation.mean_v -
                                       content.mean_v - candidates.mean_v;
        return nlohmann::json{
            {"calls_per_successful_observation", 1},
            {"statistic", "arithmetic_mean_over_repetitions"},
            {"exclusive_partition_mean_us",
             {{"physical_listing", physical.mean_v},
              {"history_reconstruction", history.mean_v},
              {"history_validation", validation.mean_v},
              {"content_reachability", content.mean_v},
              {"candidate_selection", candidates.mean_v},
              {"residual_unattributed", snapshot_residual}}},
            {"history_reconstruction_detail_mean_us",
             {{"build_history_inventory", inventory.mean_v},
              {"load_and_auth_commits", load.mean_v},
              {"inspect_markers_epochs", inspect.mean_v},
              {"dag_traversal", dag.mean_v},
              {"history_residual_unattributed", history_residual}}}};
    };

    const auto& rep1 = trials.front();
    nlohmann::json entry;
    entry["series"] = rep1.series;
    entry["N"] = rep1.N;
    entry["H"] = rep1.H;
    entry["repetitions"] = trials.size();

    entry["fixture_state"] = {
        {"P", rep1.physical_commit_objects},
        {"R", rep1.retained_commits},
        {"N", rep1.N},
        {"C", rep1.orphan_candidates},
        {"E", rep1.retained_epochs},
        {"anchors_latest_epoch", rep1.epoch_anchors},
        {"anchors_all_epochs", rep1.epoch_anchor_total},
        {"physical_content_objects", rep1.physical_content_objects},
        {"physical_commit_objects", rep1.physical_commit_objects},
        {"physical_control_objects", rep1.physical_control_objects},
        {"physical_quarantine_objects", rep1.physical_quarantine_objects},
        {"total_physical_objects", rep1.total_physical_objects},
        {"retained_heads", rep1.retained_heads},
        {"retained_epochs", rep1.retained_epochs},
        {"retained_commits", rep1.retained_commits},
        {"epoch_anchors", rep1.epoch_anchors},
        {"epoch_anchor_total", rep1.epoch_anchor_total},
        {"candidates_detected", rep1.candidates_detected},
        {"candidates_quarantined", rep1.candidates_quarantined},
        {"restored_objects", rep1.restored_objects},
        {"purged_objects", rep1.purged_objects},
        {"content_references_examined", rep1.content_references_examined},
        {"unique_reachable_content_ids", rep1.unique_reachable_content_ids},
        {"orphan_candidates", rep1.orphan_candidates}
    };

    entry["history_reconstruction"] = {
        {"retained_commits_fixture", rep1.retained_commits},
        {"commit_object_get_calls", rep1.commit_object_get_calls},
        {"marker_object_get_calls", rep1.marker_object_get_calls},
        {"other_object_get_calls", rep1.transport_get_count - rep1.commit_object_get_calls - rep1.marker_object_get_calls - rep1.epoch_object_get_calls},
        {"commit_object_get_calls_per_observation", rep1.commit_object_get_calls / 2},
        {"commit_object_get_calls_by_observation", {rep1.commit_object_get_calls / 2, rep1.commit_object_get_calls / 2}},
        {"marker_object_get_calls_per_observation", rep1.marker_object_get_calls / 2},
        {"epoch_object_get_calls_by_observation", {rep1.epoch_object_get_calls / 2, rep1.epoch_object_get_calls / 2}},
        {"epoch_object_get_calls", rep1.epoch_object_get_calls},
        {"epoch_object_get_calls_per_observation", rep1.epoch_object_get_calls / 2},
        {"content_reference_capacity_growth_events_both_observations", rep1.content_reference_capacity_growth_events},
        {"content_reference_capacity_growth_events_per_observation", rep1.content_reference_capacity_growth_events / 2}
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

    std::filesystem::path output_file = "build-msys2-ucrt64/phase17/gc_scale_profile.json";
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
              << "KASUMI: REAL FULL GC SCALE & HISTORY DAG PROFILING (OFFLINE)\n"
              << "========================================================================\n\n";

    constexpr std::size_t repetitions = 5;
    nlohmann::json root_json;
    const auto checkpoint_report = [&] {
        std::filesystem::create_directories(output_file.parent_path());
        std::ofstream checkpoint(output_file,
                                 std::ios::binary | std::ios::trunc);
        if (checkpoint) {
            checkpoint << root_json.dump(2) << '\n';
        }
    };

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

    if (run_series == "R" || run_series == "r" || run_series == "R100") {
        const struct Profile {
            std::string_view name;
            std::size_t physical_commits;
            std::size_t recent_per_head;
            std::size_t heads;
            std::size_t repetitions;
        } profiles[] = {
            {"R2_P100", 100, 6, 1, 5},
            {"R2_P1000", 1000, 6, 1, 5},
            {"R3_P10000", 10000, 6, 1, 1},
            {"R3_max_supported_P4096", 4096, 6, 1, 1},
            {"R4_P1000_two_heads", 1000, 6, 2, 5},
            {"R5_P1000_recent100", 1000, 100, 1, 5},
        };
        std::cout << "=== PHASE 17: EPOCH RETENTION (REAL FULL GC + FAKE TRANSPORT) ===\n";
        for (const auto& profile : profiles) {
            if (run_series == "R100" && profile.physical_commits != 100) {
                continue;
            }
            if (profile.physical_commits >
                kasumi::history::maximum_loaded_commit_count) {
                root_json["series_r"][profile.name] = {
                    {"status", "SKIP"},
                    {"reason", "P exceeds history::maximum_loaded_commit_count"},
                    {"configured_limit",
                     kasumi::history::maximum_loaded_commit_count},
                };
                std::cout << ">>> " << profile.name << " SKIP: P exceeds "
                          << kasumi::history::maximum_loaded_commit_count << '\n';
                checkpoint_report();
                continue;
            }
            std::cout << ">>> " << profile.name << " ("
                      << profile.repetitions << " repetitions)\n";
            std::vector<TrialMetrics> trials;
            trials.reserve(profile.repetitions);
            for (std::size_t rep = 1; rep <= profile.repetitions; ++rep) {
                auto metrics = run_trial_retention(profile.physical_commits,
                                                   profile.recent_per_head,
                                                   profile.heads,
                                                   rep);
                std::cout << "  [Rep " << rep << "] P="
                          << metrics.physical_commit_objects << " R="
                          << metrics.retained_commits << " C="
                          << metrics.candidates_quarantined << " commit GETs/obs="
                          << metrics.commit_object_get_calls / 2 << " GC="
                          << (static_cast<double>(metrics.total_gc_us) / 1000.0)
                          << " ms\n";
                trials.push_back(std::move(metrics));
            }
            root_json["series_r"][profile.name] = summarize_trials(trials);
            checkpoint_report();
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
