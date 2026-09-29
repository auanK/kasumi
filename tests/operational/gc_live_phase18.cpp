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
#include "provider_target_config.hpp"

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
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifndef KASUMI_PHASE18_BUILD_COMMIT
#define KASUMI_PHASE18_BUILD_COMMIT "unknown"
#endif

namespace {

using kasumi::transport::Transport;
using Json = nlohmann::json;
using Clock = std::chrono::steady_clock;
namespace history_storage = kasumi::application::history_storage;

constexpr std::size_t file_bytes = 1024;

std::string pad_index(std::size_t value) {
    std::ostringstream out;
    out << std::setw(4) << std::setfill('0') << value;
    return out.str();
}

std::string make_payload(std::string_view run_id, std::string_view scenario, std::size_t index) {
    std::string value = "Kasumi live GC operational content " +
                        std::string{run_id} + " " + std::string{scenario} +
                        " " + std::to_string(index) + " ";
    while (value.size() < file_bytes) {
        value.push_back(static_cast<char>((index * 37 + value.size() * 19) & 0x7f));
    }
    value.resize(file_bytes);
    return value;
}

std::vector<std::string> sorted(std::vector<std::string> ids) {
    std::ranges::sort(ids);
    return ids;
}

bool write_json(const std::filesystem::path& path, const Json& json) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out << json.dump(2) << '\n';
    out.flush();
    return static_cast<bool>(out);
}

struct Phase20Asset {
    std::string id;
    std::filesystem::path encrypted_path;
    std::string ciphertext_sha256;
    kasumi::Hash plaintext_hash{};
    std::uint64_t plaintext_size = 0;
    std::uint64_t ciphertext_size = 0;
};

std::optional<Phase20Asset> prepare_asset(
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
    auto encrypted_hash = kasumi::crypto::physical::hash_file(encrypted_path, "sha256");
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

bool verify_content_samples(
    Transport& storage,
    std::span<const std::uint8_t, kasumi::crypto::KEY_SIZE> key,
    const std::filesystem::path& workspace,
    const std::vector<std::string>& sample_ids,
    const std::map<std::string, std::pair<kasumi::Hash, std::uint64_t>>& live_info,
    std::size_t& verified_count) {
    verified_count = 0;
    std::error_code ec;
    for (const auto& id : sample_ids) {
        auto it = live_info.find(id);
        if (it == live_info.end()) return false;
        const auto enc_path = workspace / ("sample-" + id + ".enc");
        const auto plain_path = workspace / ("sample-" + id + ".plain");
        auto get_res = kasumi::transport::get(storage, id, enc_path);
        if (!get_res) return false;
        if (!kasumi::crypto::decrypt_file(enc_path, plain_path, key,
                                          kasumi::crypto::FilePurpose::Content)) {
            return false;
        }
        auto hash = kasumi::crypto::content::hash_file(plain_path);
        const auto size = std::filesystem::file_size(plain_path, ec);
        std::filesystem::remove(enc_path, ec);
        std::filesystem::remove(plain_path, ec);
        if (!hash || ec || *hash != it->second.first || size != it->second.second) {
            return false;
        }
        if (kasumi::crypto::content_identifier(key, *hash) != id) return false;
        ++verified_count;
    }
    return true;
}

bool validate_fixture_inventory(
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

Json phase_times_json() {
    const auto get_time = [](const char* name) {
        return kasumi::platform::perf_trace::get_time(name);
    };
    return Json{
        {"total_gc_us", get_time("gc.total_duration_us")},
        {"barrier_acquire_us", get_time("gc barrier acquire")},
        {"writer_consistency_checks_us", get_time("gc writer consistency checks")},
        {"backend_consistency_probe_us", get_time("gc backend consistency probe")},
        {"quarantine_inventory_us", get_time("gc quarantine inventory")},
        {"quarantine_restoration_us", get_time("gc quarantine restoration")},
        {"prior_metadata_initialization_us", get_time("gc prior metadata initialization")},
        {"reachability_observation_1_us", get_time("gc reachability observation 1")},
        {"reachability_observation_2_us", get_time("gc reachability observation 2")},
        {"stable_state_comparison_us", get_time("gc stable-state comparison")},
        {"final_namespace_verification_us", get_time("gc final namespace verification")},
        {"expired_quarantine_purge_us", get_time("gc expired quarantine purge")},
        {"batch_prepare_duration_us", get_time("gc.batch_prepare_duration_us")},
        {"batch_verify_duration_us", get_time("gc.batch_verify_duration_us")},
        {"batch_publish_remove_duration_us", get_time("gc.batch_publish_remove_duration_us")},
        {"copy_batch_duration_us", get_time("gc candidate copy batch")},
        {"metadata_publish_batch_duration_us", get_time("gc.metadata_publish_batch_duration_us")},
        {"metadata_verify_batch_duration_us", get_time("gc.metadata_verify_batch_duration_us")},
        {"remove_batch_duration_us", get_time("gc candidate remove batch")},
        {"barrier_ownership_verification_us", get_time("gc barrier ownership verification")},
        {"barrier_release_us", get_time("gc barrier release")},
    };
}

Json gc_counters_json() {
    const auto get_count = [](std::string_view name) {
        return kasumi::platform::perf_trace::get_count(name);
    };
    Json counters = Json::object();
    for (const auto* name : {
             "gc.candidates_selected",
             "gc.candidate_batches",
             "gc.pre_copy_barrier_verifications",
             "gc.source_physical_hash_calls",
             "gc.pre_batch_copy_barrier_verifications",
             "gc.copy_batch_calls",
             "gc.copy_batch_inputs",
             "gc.copy_batch_concurrency",
             "gc.native_copy_attempts",
             "gc.native_copy_successes",
             "gc.native_copy_unsupported",
             "gc.copy_batch_unsupported",
             "gc.copy_batch_errors",
             "gc.copy_batch_ambiguous",
             "gc.pre_fallback_copy_barrier_verifications",
             "gc.fallback_copy_attempts",
             "gc.candidates_verified",
             "gc.batch_verify_attempts",
             "gc.batch_verify_supported",
             "gc.batch_verify_unsupported",
             "gc.individual_destination_hash_attempts",
             "gc.batch_verify_failures",
             "gc.post_copy_barrier_verifications",
             "gc.metadata_prepared",
             "gc.metadata_batch_calls",
             "gc.metadata_objects_submitted",
             "gc.metadata_concurrency",
             "gc.metadata_batch_publish_successes",
             "gc.metadata_batch_unsupported",
             "gc.metadata_publications",
             "gc.metadata_physical_hash_calls",
             "gc.metadata_physical_hash_batch_calls",
             "gc.metadata_physical_hash_batch_unsupported",
             "gc.metadata_verified",
             "gc.metadata_publication_failures",
             "gc.pre_remove_barrier_verifications",
             "gc.source_removals",
             "gc.candidates_quarantined",
             "gc.source_removals_already_absent",
             "gc.remove_batch_calls",
             "gc.remove_batch_objects",
             "gc.remove_batch_concurrency",
             "gc.remove_batch_failures",
             "gc.remove_batch_unsupported",
             "gc.remove_batch_fallback_sequential",
             "gc.remove_batch_ambiguous",
             "gc.barrier_release_owner_verifications",
             "gc.barrier_ownership_verifications",
             "gc.barrier_physical_hash_attempts",
             "gc.barrier_physical_hash_successes",
             "gc.barrier_physical_hash_mismatches",
             "gc.barrier_physical_hash_not_found",
             "gc.barrier_physical_hash_errors",
             "gc.barrier_physical_hash_unsupported",
             "gc.barrier_get_fallbacks",
             "rc.http_requests_attempted",
             "rc.http_requests_completed",
             "rc.http_requests_failed",
         }) {
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
    return counters;
}

struct GcLiveOptions {
    std::string remote_parent;
    kasumi::operational::provider_target_config::LiveTargetAuthorization
        authorization;
    std::optional<std::filesystem::path> provider_config;
    std::optional<std::string> target_id;
    std::string output_path{"gc_live_result.json"};
    std::size_t files = 10;
    std::size_t candidates = 8;
    std::size_t copy_concurrency = 8;
    std::size_t metadata_concurrency = 8;
    std::size_t remove_concurrency = 8;
    bool preflight_only = false;
    bool execute_live = false;
    bool self_test = false;
    bool help = false;
};

void print_help() {
    std::cout << "Usage: kasumi_gc_live_phase18 [options]\n\n"
              << "Options:\n"
              << "  --help, -h                  Show this help message\n"
              << "  --self-test                 Run internal sanity checks\n"
              << "  --config <path>             Live target configuration\n"
              << "  --target-id <id>            Exact configured target id\n"
              << "  --output <path>             Path for output JSON result (default: gc_live_result.json)\n"
              << "  -F, --files <N>             Number of protected live files (default: 10)\n"
              << "  -C, --candidates <N>        Number of orphan candidate files (default: 8)\n"
              << "  --copy-concurrency <N>      Batch copy concurrency (default: 8)\n"
              << "  --metadata-concurrency <N>  Batch metadata concurrency (default: 8)\n"
              << "  --remove-concurrency <N>    Batch remove concurrency (default: 8)\n"
              << "  --preflight-only            Verify remote connectivity and exit\n"
              << "  --execute-live              Required to confirm execution of live remote mutations\n";
}

std::optional<GcLiveOptions> parse_arguments(int argc, char** argv) {
    GcLiveOptions options;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (arg == "--help" || arg == "-h") {
            options.help = true;
            return options;
        } else if (arg == "--self-test") {
            options.self_test = true;
        } else if (arg == "--preflight-only") {
            options.preflight_only = true;
        } else if (arg == "--execute-live") {
            options.execute_live = true;
        } else if (arg == "--config" && i + 1 < argc &&
                   !options.provider_config) {
            options.provider_config = std::filesystem::path{argv[++i]};
        } else if (arg == "--target-id" && i + 1 < argc &&
                   !options.target_id) {
            options.target_id = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            options.output_path = argv[++i];
        } else if ((arg == "-F" || arg == "--files") && i + 1 < argc) {
            options.files = std::stoull(argv[++i]);
        } else if ((arg == "-C" || arg == "--candidates") && i + 1 < argc) {
            options.candidates = std::stoull(argv[++i]);
        } else if (arg == "--copy-concurrency" && i + 1 < argc) {
            options.copy_concurrency = std::stoull(argv[++i]);
        } else if (arg == "--metadata-concurrency" && i + 1 < argc) {
            options.metadata_concurrency = std::stoull(argv[++i]);
        } else if (arg == "--remove-concurrency" && i + 1 < argc) {
            options.remove_concurrency = std::stoull(argv[++i]);
        } else {
            std::cerr << "Unknown or incomplete argument: " << arg << "\n";
            return std::nullopt;
        }
    }
    if (!options.help && !options.self_test) {
        auto target =
            kasumi::operational::provider_target_config::resolve_target(
                kasumi::operational::provider_target_config::
                    TargetSelectionArguments{
                        .target_kind = "rclone",
                        .config_path = options.provider_config,
                        .target_id = options.target_id,
                    });
        if (!target || !target->has_value()) {
            std::cerr << (target ? "Rclone target was not selected"
                                 : target.error()) << '\n';
            return std::nullopt;
        }
        options.remote_parent = (*target)->authorized_parent;
        options.authorization.authorized_parent =
            (*target)->authorized_parent;
    }
    return options;
}

bool run_self_test() {
    std::cout << "[INFO] Running internal operational harness self-test...\n";
    if (pad_index(0) != "0000" || pad_index(42) != "0042") return false;
    const auto payload = make_payload("test-run", "test", 1);
    if (payload.size() != file_bytes) return false;

    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    std::ranges::fill(key, 0xaa);
    const auto tmp_dir = std::filesystem::temp_directory_path() / "kasumi_harness_selftest";
    std::error_code ec;
    std::filesystem::remove_all(tmp_dir, ec);
    std::filesystem::create_directories(tmp_dir, ec);

    auto asset = prepare_asset("test-run", "sample", 0, tmp_dir, key);
    if (!asset || asset->id.empty() || asset->plaintext_size != file_bytes) {
        std::filesystem::remove_all(tmp_dir, ec);
        return false;
    }

    const auto json_path = tmp_dir / "test.json";
    if (!write_json(json_path, Json{{"self_test", "passed"}})) {
        std::filesystem::remove_all(tmp_dir, ec);
        return false;
    }
    std::filesystem::remove_all(tmp_dir, ec);
    std::cout << "[INFO] Operational harness self-test: PASSED.\n";
    return true;
}

bool run_live_gc(const GcLiveOptions& options) {
    if (!kasumi::operational::provider_target_config::authorized_live_parent(
            options.authorization, options.remote_parent) ||
        !kasumi::transport::validate_transport_location(options.remote_parent)) {
        std::cerr << "[ERROR] selected target authorization is invalid.\n";
        return false;
    }
    const auto run_id = kasumi::platform::random::hex_id().value_or("run");
    const auto output = std::filesystem::absolute(options.output_path);
    std::error_code ec;
    if (output.has_parent_path()) {
        std::filesystem::create_directories(output.parent_path(), ec);
    }

    const auto artifacts = std::filesystem::path{output.string() + ".artifacts"};
    std::filesystem::create_directories(artifacts, ec);
    const auto local_root = artifacts / "workspace";
    std::filesystem::create_directories(local_root, ec);

    const auto remote_fixture = options.remote_parent + "/gc-run-" + run_id + "/fixture";

    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    std::ranges::fill(key, 0x42);
    const auto layout = history_storage::derive_remote_layout(key);

    std::cout << "[INFO] Starting GC live operational runner\n"
              << "       run_id:               " << run_id << "\n"
              << "       remote_fixture:       " << remote_fixture << "\n"
              << "       files (F):            " << options.files << "\n"
              << "       candidates (C):       " << options.candidates << "\n"
              << "       copy_concurrency:     " << options.copy_concurrency << "\n"
              << "       metadata_concurrency: " << options.metadata_concurrency << "\n"
              << "       remove_concurrency:   " << options.remove_concurrency << "\n"
              << "       execute_live:         " << (options.execute_live ? "YES" : "NO (dry)") << "\n";

    if (options.preflight_only) {
        std::cout << "[INFO] Preflight-only requested. Verifying parent...\n";
        auto opened = kasumi::transport::open_transport(options.remote_parent);
        if (!opened || !kasumi::transport::initialize(*opened)) {
            std::cerr << "[ERROR] Cannot access remote parent storage.\n";
            return false;
        }
        std::cout << "[INFO] Preflight check PASSED.\n";
        write_json(output, Json{{"status", "PREFLIGHT_PASSED"}, {"remote_parent", options.remote_parent}});
        return true;
    }

    if (!options.execute_live) {
        std::cerr << "[ERROR] --execute-live flag is required to perform live remote operations.\n";
        return false;
    }

    // 1. Prepare local live assets and tree
    std::cout << "[INFO] Preparing " << options.files << " protected assets locally...\n";
    std::vector<Phase20Asset> live_assets;
    std::vector<std::string> live_ids;
    std::map<std::string, std::pair<kasumi::Hash, std::uint64_t>> live_info;
    kasumi::Snapshot tree;
    tree.rows.push_back(kasumi::NodeRow{.path = "", .hash = {}, .size = 0, .mtime = {}, .is_directory = true});
    const auto live_dir = artifacts / "prepared" / "live";
    for (std::size_t i = 0; i < options.files; ++i) {
        auto asset = prepare_asset(run_id, "live", i, live_dir, key);
        if (!asset || live_info.contains(asset->id)) {
            std::cerr << "[ERROR] Failed to prepare live asset " << i << "\n";
            return false;
        }
        live_ids.push_back(asset->id);
        live_info.emplace(asset->id, std::pair{asset->plaintext_hash, asset->plaintext_size});
        tree.rows.push_back(kasumi::NodeRow{
            .path = "file_" + pad_index(i) + ".bin", .hash = asset->plaintext_hash,
            .size = asset->plaintext_size, .mtime = {}, .is_directory = false});
        live_assets.push_back(std::move(*asset));
    }
    kasumi::finalize_snapshot(tree);

    // 2. Prepare candidates locally
    std::cout << "[INFO] Preparing " << options.candidates << " candidate assets locally...\n";
    std::vector<Phase20Asset> candidates;
    std::vector<std::string> candidate_ids;
    std::set<std::string> unique_ids(live_ids.begin(), live_ids.end());
    const auto cand_dir = artifacts / "prepared" / "candidates";
    for (std::size_t i = 0; i < options.candidates; ++i) {
        auto asset = prepare_asset(run_id, "orphan", i, cand_dir, key);
        if (!asset || !unique_ids.insert(asset->id).second) {
            std::cerr << "[ERROR] Failed to prepare candidate " << i << "\n";
            return false;
        }
        candidate_ids.push_back(asset->id);
        candidates.push_back(std::move(*asset));
    }
    std::ranges::sort(candidate_ids);

    // 3. Open remote transport
    auto opened = kasumi::transport::open_transport(remote_fixture);
    if (!opened || !kasumi::transport::initialize(*opened)) {
        std::cerr << "[ERROR] Failed to initialize fixture transport at " << remote_fixture << "\n";
        return false;
    }
    auto& storage = *opened;

    // Verify fixture is empty initially
    auto initial_list = kasumi::transport::list(storage);
    if (initial_list && !initial_list->empty()) {
        std::cerr << "[ERROR] Remote fixture namespace is not empty.\n";
        return false;
    }

    // 4. Upload all content via batch put
    std::vector<Phase20Asset*> all_content;
    all_content.reserve(live_assets.size() + candidates.size());
    for (auto& asset : live_assets) all_content.push_back(&asset);
    for (auto& asset : candidates) all_content.push_back(&asset);

    std::cout << "[INFO] Uploading " << all_content.size() << " assets to remote...\n";
    constexpr std::size_t upload_batch_size = 25;
    constexpr std::size_t upload_transfers = 4;
    for (std::size_t begin = 0; begin < all_content.size(); begin += upload_batch_size) {
        const auto end = std::min(begin + upload_batch_size, all_content.size());
        const auto batch_root = artifacts / "upload_staging" / ("batch-" + pad_index(begin));
        std::filesystem::create_directories(batch_root, ec);
        std::vector<std::string> batch_ids;
        for (std::size_t i = begin; i < end; ++i) {
            std::filesystem::copy_file(all_content[i]->encrypted_path, batch_root / all_content[i]->id,
                                       std::filesystem::copy_options::overwrite_existing, ec);
            batch_ids.push_back(all_content[i]->id);
        }
        auto uploaded = kasumi::transport::put_batch(
            storage, kasumi::transport::PutBatch{.source_root = batch_root,
                                                 .identifiers = batch_ids,
                                                 .max_parallel_transfers = upload_transfers});
        if (!uploaded) {
            std::cerr << "[ERROR] Batch upload failed: " << kasumi::transport::describe(uploaded.error()) << "\n";
            return false;
        }
    }

    // 5. Publish commit & HEAD marker
    const auto commit_unix = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto commit = kasumi::history::make_commit(0, {}, tree, commit_unix);
    if (!commit) {
        std::cerr << "[ERROR] Failed to make commit.\n";
        return false;
    }
    auto published = history_storage::publish_commit_object(storage, layout, key, *commit, local_root);
    if (!published) {
        std::cerr << "[ERROR] Failed to publish commit: " << published.error().detail << "\n";
        return false;
    }
    const auto commit_id = history_storage::commit_object(layout, published->head);
    auto marker = history_storage::publish_head_marker(storage, layout, published->head, local_root);
    if (!marker) {
        std::cerr << "[ERROR] Failed to publish HEAD marker: " << marker.error().detail << "\n";
        return false;
    }
    const auto head_marker_id = marker->marker_id;

    // 6. Pre-GC validation
    std::cout << "[INFO] Validating pre-GC fixture inventory...\n";
    auto pre_list = kasumi::transport::list(storage);
    if (!pre_list) {
        std::cerr << "[ERROR] Pre-GC listing failed.\n";
        return false;
    }
    Json pre_val = Json::object();
    if (!validate_fixture_inventory(storage, key, layout, *pre_list, live_ids, candidate_ids,
                                    local_root, published->head.commit_id, pre_val)) {
        std::cerr << "[ERROR] Pre-GC validation failed: " << pre_val.dump(2) << "\n";
        return false;
    }
    std::cout << "[INFO] Pre-GC inventory confirmed: " << pre_list->size() << " objects.\n";

    // 7. Execute single GC
    std::cout << "[INFO] Executing measured Garbage Collection...\n";
    const auto runtime_root = local_root / "gc-runtime";
    kasumi::runtime::RuntimeData runtime{
        .local_dir = runtime_root / "local",
        .database_path = runtime_root / "profile" / "db.sqlite",
        .key_path = runtime_root / "profile" / "key.bin",
        .storage_location = remote_fixture,
    };
    std::filesystem::create_directories(runtime.local_dir, ec);
    std::filesystem::create_directories(runtime.database_path.parent_path(), ec);

    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();
    const auto gc_start = Clock::now();

    auto collected = kasumi::application::integrity::garbage_collect(
        runtime, storage, key, options.copy_concurrency,
        options.metadata_concurrency, options.remove_concurrency);

    const auto gc_end = Clock::now();
    const auto gc_wall_us = std::chrono::duration_cast<std::chrono::microseconds>(gc_end - gc_start).count();
    auto gc_times = phase_times_json();
    auto gc_counters = gc_counters_json();
    kasumi::platform::perf_trace::force_enable(false);

    if (!collected) {
        std::cerr << "[ERROR] GC execution failed: " << kasumi::application::integrity::describe(collected.error()) << "\n";
        return false;
    }
    std::cout << "[INFO] GC completed in " << (static_cast<double>(gc_wall_us) / 1'000'000.0) << " seconds.\n"
              << "       Candidates quarantined: " << collected->quarantined_objects << "\n";

    // 8. Post-GC validation
    std::cout << "[INFO] Validating post-GC inventory & quarantine...\n";
    auto post_list = kasumi::transport::list(storage);
    if (!post_list) {
        std::cerr << "[ERROR] Post-GC listing failed.\n";
        return false;
    }
    auto quarantine = history_storage::maintenance_protocol::inventory_quarantine(
        storage, key, *post_list, local_root);
    if (!quarantine || quarantine->size() != options.candidates) {
        std::cerr << "[ERROR] Quarantine entry count (" << (quarantine ? quarantine->size() : 0)
                  << ") does not equal expected candidates (" << options.candidates << ")\n";
        return false;
    }

    std::vector<std::string> qids, metadata_ids, originals;
    bool qvalid = true;
    for (const auto& entry : *quarantine) {
        qids.push_back(entry.quarantine_identifier);
        metadata_ids.push_back(entry.metadata_identifier);
        originals.push_back(entry.original_identifier);
        auto verified = history_storage::maintenance_protocol::verify_quarantine(storage, entry, local_root);
        if (!verified || !*verified) qvalid = false;
    }
    if (!qvalid || sorted(originals) != sorted(candidate_ids)) {
        std::cerr << "[ERROR] Quarantine verification failed.\n";
        return false;
    }

    std::vector<std::string> expected_post = live_ids;
    expected_post.push_back(commit_id);
    expected_post.push_back(head_marker_id);
    expected_post.insert(expected_post.end(), qids.begin(), qids.end());
    expected_post.insert(expected_post.end(), metadata_ids.begin(), metadata_ids.end());

    Json post_val = Json::object();
    if (sorted(*post_list) != sorted(expected_post) ||
        !validate_fixture_inventory(storage, key, layout, *post_list, live_ids, {},
                                    local_root, published->head.commit_id, post_val)) {
        std::cerr << "[ERROR] Post-GC fixture validation failed.\n";
        return false;
    }

    // Verify sample of protected live content
    const std::size_t sample_target = std::min<std::size_t>(10, live_ids.size());
    std::vector<std::string> sample_ids;
    for (std::size_t i = 0; i < sample_target; ++i) {
        sample_ids.push_back(sorted(live_ids)[i * (live_ids.size() - 1) / std::max<std::size_t>(1, sample_target - 1)]);
    }
    std::size_t samples_verified = 0;
    if (!verify_content_samples(storage, key, local_root, sample_ids, live_info, samples_verified) ||
        samples_verified != sample_target) {
        std::cerr << "[ERROR] Protected content sample verification failed.\n";
        return false;
    }
    std::cout << "[INFO] Post-GC validation PASSED: " << samples_verified << " samples verified intact.\n";

    // 9. Cleanup fixture
    std::cout << "[INFO] Cleaning up remote fixture...\n";
    std::vector<std::string> cleanup_ids = expected_post;
    std::ranges::sort(cleanup_ids);
    cleanup_ids.erase(std::ranges::unique(cleanup_ids).begin(), cleanup_ids.end());
    for (const auto& id : cleanup_ids) {
        auto rem = kasumi::transport::remove(storage, id);
        if (!rem || *rem != kasumi::transport::Removal::Removed) {
            std::cerr << "[WARN] Failed to remove fixture object: " << id << "\n";
        }
    }
    auto final_list = kasumi::transport::list(storage);
    const bool cleaned = (!final_list || final_list->empty());
    std::cout << "[INFO] Fixture cleanup: " << (cleaned ? "CLEAN" : "REMAINS DETECTED") << "\n";

    // 10. Write report
    Json result{
        {"status", cleaned ? "PASS_CLEANED" : "PASS_WITH_REMAINS"},
        {"run_id", run_id},
        {"remote_fixture", remote_fixture},
        {"files", options.files},
        {"candidates", options.candidates},
        {"copy_concurrency", options.copy_concurrency},
        {"metadata_concurrency", options.metadata_concurrency},
        {"remove_concurrency", options.remove_concurrency},
        {"gc_wall_us", gc_wall_us},
        {"gc_wall_seconds", static_cast<double>(gc_wall_us) / 1'000'000.0},
        {"quarantined_objects", collected->quarantined_objects},
        {"preserved_live_objects", live_ids.size()},
        {"phase_times", gc_times},
        {"counters", gc_counters},
    };
    if (write_json(output, result)) {
        std::cout << "[INFO] Result written to " << output.string() << "\n";
    }
    return true;
}

} // namespace

int main(int argc, char** argv) {
    auto options = parse_arguments(argc, argv);
    if (!options) return 1;
    if (options->help) {
        print_help();
        return 0;
    }
    if (options->self_test) {
        return run_self_test() ? 0 : 1;
    }
    return run_live_gc(*options) ? 0 : 1;
}
