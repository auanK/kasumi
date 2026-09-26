#include "gc_live_phase11_support.hpp"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <span>
#include <system_error>
#include <thread>

namespace kasumi::operational::phase11 {

namespace {

constexpr std::string_view owner_marker_name = "owner.marker";

bool write_file_string(const std::filesystem::path& path, std::string_view text) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    return static_cast<bool>(stream);
}

std::string read_file_string(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return std::string{std::istreambuf_iterator<char>{stream}, {}};
}

std::vector<std::uint8_t> read_file_bytes(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return std::vector<std::uint8_t>{std::istreambuf_iterator<char>{stream}, {}};
}

bool write_synthetic_payload(const std::filesystem::path& path, std::size_t index, std::size_t total_bytes) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) {
        return false;
    }
    constexpr std::size_t chunk_size = 64 * 1024;
    std::vector<std::uint8_t> chunk(chunk_size);
    std::size_t remaining = total_bytes;
    std::size_t written_so_far = 0;
    while (remaining > 0) {
        const std::size_t to_write = std::min(remaining, chunk_size);
        for (std::size_t i = 0; i < to_write; ++i) {
            const std::size_t byte_idx = written_so_far + i;
            chunk[i] = static_cast<std::uint8_t>((index * 137U + byte_idx * 31U + 42U) & 0xFFU);
        }
        stream.write(reinterpret_cast<const char*>(chunk.data()), static_cast<std::streamsize>(to_write));
        if (!stream) {
            return false;
        }
        written_so_far += to_write;
        remaining -= to_write;
    }
    return true;
}

double elapsed_ms(std::chrono::steady_clock::time_point start, std::chrono::steady_clock::time_point end) noexcept {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

} // namespace

bool is_authorized_parent(std::string_view remote_parent) noexcept {
    return remote_parent == "kasumi:integration-tests";
}

bool is_disallowed_root(std::string_view remote) noexcept {
    return remote == "kasumi:" || remote == "kasumi" || remote.empty();
}

std::expected<std::string, std::string> generate_benchmark_child(std::string_view random_hex) {
    if (random_hex.size() != 32) {
        return std::unexpected("namespace nonce must be 128-bit lowercase hex");
    }
    for (char ch : random_hex) {
        const bool is_hex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
        if (!is_hex) {
            return std::unexpected("invalid hex character in nonce");
        }
    }
    return "kasumi-gc-benchmark-" + std::string{random_hex};
}

CapabilityStatus run_capability_test(
    const Phase11Config& config,
    Phase11RunReport& report,
    transport::Transport* parent_transport_override,
    transport::Transport* child_transport_override) {

    report.schema_version = 1;
    report.mode = "batch";
    report.candidate_count = 8;
    report.payload_bytes_per_object = config.payload_bytes;
    report.provider_requests = "NOT_MEASURED";

    // Gate 1: Check execution gate
    if (!config.execute_live && !parent_transport_override) {
        report.status = "REFUSED";
        report.error_message = "dry run safety: --execute-live required";
        return CapabilityStatus::Refused;
    }

    // Gate 2: Check remote parent authorization
    if (!parent_transport_override && !is_authorized_parent(config.remote_parent)) {
        report.status = "REFUSED";
        report.error_message = "remote parent not authorized for live benchmark";
        return CapabilityStatus::Refused;
    }

    const auto parsed_parent = smoke::parse_remote_parent(config.remote_parent);
    if (!parsed_parent) {
        report.status = "REFUSED";
        report.error_message = "invalid remote parent format";
        return CapabilityStatus::Refused;
    }

    // Generate exclusive child namespace
    std::string child_name;
    if (config.explicit_child) {
        child_name = *config.explicit_child;
    } else {
        const auto nonce = kasumi::platform::random::hex_id();
        if (!nonce) {
            report.status = "FAIL";
            report.error_message = "could not generate random nonce";
            return CapabilityStatus::Failed;
        }
        auto generated = generate_benchmark_child(*nonce);
        if (!generated) {
            report.status = "FAIL";
            report.error_message = generated.error();
            return CapabilityStatus::Failed;
        }
        child_name = *generated;
    }

    const auto location = preflight::child_location(*parsed_parent, child_name);
    if (!location) {
        report.status = "REFUSED";
        report.error_message = location.error();
        return CapabilityStatus::Refused;
    }
    report.namespace_path = *location;

    // Local scratch directory
    std::error_code fs_error;
    std::filesystem::create_directories(config.local_scratch, fs_error);

    // Parent transport acquisition
    std::optional<transport::Transport> owned_parent_storage;
    transport::Transport* parent_storage = parent_transport_override;
    if (!parent_storage) {
        auto opened = transport::open_transport(parsed_parent->location);
        if (!opened) {
            report.status = "REFUSED";
            report.error_message = "could not open parent transport: " + transport::describe(opened.error());
            return CapabilityStatus::Refused;
        }
        owned_parent_storage = std::move(*opened);
        parent_storage = &*owned_parent_storage;
    }

    const auto wall_start = std::chrono::steady_clock::now();

    // Preflight observation: ensure child is completely unused
    const auto preflight_start = std::chrono::steady_clock::now();
    if (!parent_transport_override) {
        auto pre_obs = preflight::observe_pre_initialize(
            *parent_storage, *parsed_parent, child_name, config.preflight_timeout);
        auto classification = preflight::classify_pre_initialize(
            pre_obs, *parsed_parent, child_name);
        if (classification.disposition != preflight::ChildDisposition::Unused) {
            report.status = "REFUSED";
            report.error_message = "child namespace not unused: " + classification.reason;
            return CapabilityStatus::Refused;
        }
    }
    const auto preflight_end = std::chrono::steady_clock::now();
    report.timings_ms.preflight_ms = elapsed_ms(preflight_start, preflight_end);

    // Open child transport
    std::optional<transport::Transport> owned_child_storage;
    transport::Transport* child_storage = child_transport_override;
    if (!child_storage) {
        auto opened_child = transport::open_transport(*location);
        if (!opened_child) {
            report.status = "FAIL";
            report.error_message = "could not open child transport: " + transport::describe(opened_child.error());
            return CapabilityStatus::Failed;
        }
        owned_child_storage = std::move(*opened_child);
        child_storage = &*owned_child_storage;
    }

    // Enable and reset perf trace for RC measurements
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    // Write owner marker
    const auto marker_start = std::chrono::steady_clock::now();
    std::string token;
    if (config.explicit_token) {
        token = *config.explicit_token;
    } else {
        const auto generated_token = kasumi::platform::random::hex_id();
        token = generated_token ? *generated_token : "capability-token-fixed";
    }
    const auto marker_file = config.local_scratch / "capability.owner.marker";
    write_file_string(marker_file, token);
    auto put_marker = transport::put(*child_storage, marker_file, owner_marker_name);
    if (!put_marker) {
        report.status = "FAIL";
        report.error_message = "failed to put owner marker: " + transport::describe(put_marker.error());
        return CapabilityStatus::Failed;
    }

    // Verify owner marker via readback
    const auto marker_readback_file = config.local_scratch / "capability.marker.readback";
    auto get_marker = transport::get(*child_storage, owner_marker_name, marker_readback_file);
    if (!get_marker || read_file_string(marker_readback_file) != token) {
        report.status = "FAIL";
        report.error_message = "owner marker verification failed";
        return CapabilityStatus::Failed;
    }
    report.cleanup.owner_marker_verified = true;
    const auto marker_end = std::chrono::steady_clock::now();
    report.timings_ms.marker_ms = elapsed_ms(marker_start, marker_end);

    const std::size_t N = 8;
    std::vector<std::string> source_ids;
    std::vector<std::string> dest_ids;
    std::vector<std::string> expected_hashes;
    source_ids.reserve(N);
    dest_ids.reserve(N);
    expected_hashes.reserve(N);

    // Prepare and upload 8 objects
    const auto upload_start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < N; ++i) {
        const auto src_id = "src-" + std::to_string(i);
        const auto dst_id = "dst-" + std::to_string(i);
        source_ids.push_back(src_id);
        dest_ids.push_back(dst_id);

        const auto payload_file = config.local_scratch / ("cap_payload_" + std::to_string(i) + ".bin");
        if (!write_synthetic_payload(payload_file, i, config.payload_bytes)) {
            report.status = "FAIL";
            report.error_message = "failed to create local payload file";
            return CapabilityStatus::Failed;
        }

        auto local_hash = crypto::physical::hash_file(payload_file, "sha256");
        if (!local_hash) {
            report.status = "FAIL";
            report.error_message = "failed to calculate local SHA-256";
            return CapabilityStatus::Failed;
        }
        expected_hashes.push_back(*local_hash);

        auto put_res = transport::put(*child_storage, payload_file, src_id);
        if (!put_res) {
            report.status = "FAIL";
            report.error_message = "failed to upload source " + src_id + ": " + transport::describe(put_res.error());
            return CapabilityStatus::Failed;
        }
        report.payload_transfer.upload_bytes += config.payload_bytes;
    }
    const auto upload_end = std::chrono::steady_clock::now();
    report.timings_ms.upload_ms = elapsed_ms(upload_start, upload_end);

    // Physical hash of sources
    const auto src_hash_start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < N; ++i) {
        auto hash_res = transport::physical_hash(*child_storage, source_ids[i], "sha256");
        if (!hash_res || *hash_res != expected_hashes[i]) {
            report.status = "FAIL";
            report.error_message = "source physical hash mismatch on " + source_ids[i];
            return CapabilityStatus::Failed;
        }
        ++report.kasumi_operations.individual_source_hashes;
    }
    report.integrity.all_source_hashes_valid = true;
    const auto src_hash_end = std::chrono::steady_clock::now();
    report.timings_ms.source_hash_ms = elapsed_ms(src_hash_start, src_hash_end);

    // Native copy
    const auto copy_start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < N; ++i) {
        ++report.kasumi_operations.native_copy_attempts;
        auto copy_res = transport::copy(*child_storage, source_ids[i], dest_ids[i]);
        if (!copy_res) {
            report.status = "FAIL";
            report.error_message = "native copy failed for " + source_ids[i] + " -> " + dest_ids[i] + ": " + transport::describe(copy_res.error());
            return CapabilityStatus::Failed;
        }
        ++report.kasumi_operations.native_copy_successes;
    }
    const auto copy_end = std::chrono::steady_clock::now();
    report.timings_ms.copy_ms = elapsed_ms(copy_start, copy_end);

    // Batch verification
    const auto verify_start = std::chrono::steady_clock::now();
    transport::PhysicalHashBatchRequest batch_req{
        .scratch_root = config.local_scratch,
        .objects = {},
        .algorithm = "sha256"
    };
    batch_req.objects.reserve(N);
    for (std::size_t i = 0; i < N; ++i) {
        batch_req.objects.push_back(transport::PhysicalHashExpectation{
            .identifier = dest_ids[i],
            .expected_hash = expected_hashes[i]
        });
    }

    ++report.kasumi_operations.batch_hash_calls;
    auto batch_res = transport::physical_hash_batch(*child_storage, batch_req);
    const auto verify_end = std::chrono::steady_clock::now();
    report.timings_ms.verify_ms = elapsed_ms(verify_start, verify_end);

    CapabilityStatus outcome = CapabilityStatus::Supported;
    if (!batch_res) {
        if (batch_res.error().code == transport::ErrorCode::Unsupported) {
            outcome = CapabilityStatus::Unsupported;
            report.status = "UNSUPPORTED";
            report.error_message = "physical_hash_batch is Unsupported on remote backend";
        } else {
            outcome = CapabilityStatus::Failed;
            report.status = "FAIL";
            report.error_message = "physical_hash_batch error: " + transport::describe(batch_res.error());
        }
    } else {
        // Validate strict positive results
        report.integrity.mismatched = batch_res->mismatched.size();
        report.integrity.missing = batch_res->missing.size();
        report.integrity.errors = batch_res->errors.size();

        bool all_matched = (batch_res->matched.size() == N);
        if (all_matched) {
            for (const auto& expected_id : dest_ids) {
                if (std::ranges::find(batch_res->matched, expected_id) == batch_res->matched.end()) {
                    all_matched = false;
                    break;
                }
            }
        }

        if (!all_matched || !batch_res->mismatched.empty() || !batch_res->missing.empty() || !batch_res->errors.empty()) {
            outcome = CapabilityStatus::Failed;
            report.status = "FAIL";
            report.error_message = "batch verification contract violated";
        } else {
            report.integrity.all_destinations_verified = true;
            report.kasumi_operations.candidates_verified = N;
        }
    }

    // Readback verification on dest 0 if successful
    if (outcome == CapabilityStatus::Supported) {
        const auto readback_start = std::chrono::steady_clock::now();
        const auto readback_file = config.local_scratch / "capability_readback_dst_0.bin";
        auto get_res = transport::get(*child_storage, dest_ids[0], readback_file);
        if (get_res) {
            report.payload_transfer.download_bytes += config.payload_bytes;
            const auto original_file = config.local_scratch / "cap_payload_0.bin";
            if (read_file_bytes(readback_file) == read_file_bytes(original_file)) {
                report.integrity.exact_readback_verified = true;
            } else {
                outcome = CapabilityStatus::Failed;
                report.status = "FAIL";
                report.error_message = "readback exact bytes mismatch on destination 0";
            }
        } else {
            outcome = CapabilityStatus::Failed;
            report.status = "FAIL";
            report.error_message = "failed to get destination 0 for readback";
        }
        const auto readback_end = std::chrono::steady_clock::now();
        report.timings_ms.readback_ms = elapsed_ms(readback_start, readback_end);
    }

    // Confirm sources still present
    bool sources_intact = true;
    for (const auto& src : source_ids) {
        auto pres = transport::presence(*child_storage, src);
        if (!pres || *pres != transport::Presence::Present) {
            sources_intact = false;
            break;
        }
    }
    report.integrity.sources_intact_before_cleanup = sources_intact;
    if (!sources_intact && outcome == CapabilityStatus::Supported) {
        outcome = CapabilityStatus::Failed;
        report.status = "FAIL";
        report.error_message = "sources were not preserved before cleanup";
    }

    // Cleanup: verify owner marker and remove owned objects
    const auto cleanup_start = std::chrono::steady_clock::now();
    auto verify_marker_again = transport::get(*child_storage, owner_marker_name, marker_readback_file);
    if (!verify_marker_again || read_file_string(marker_readback_file) != token) {
        report.cleanup.result = "FAILED_OWNER_MISMATCH";
        report.status = "FAIL";
        report.error_message = "cleanup refused: owner marker token mismatch or missing";
        return CapabilityStatus::Failed;
    }

    std::size_t removed = 0;
    for (const auto& dst : dest_ids) {
        if (transport::remove(*child_storage, dst)) {
            ++removed;
            ++report.kasumi_operations.removals;
        }
    }
    for (const auto& src : source_ids) {
        if (transport::remove(*child_storage, src)) {
            ++removed;
            ++report.kasumi_operations.removals;
        }
    }
    if (transport::remove(*child_storage, owner_marker_name)) {
        ++removed;
        report.cleanup.owner_marker_removed = true;
    }
    report.cleanup.objects_removed = removed;
    report.cleanup.result = "SUCCESS";
    const auto cleanup_end = std::chrono::steady_clock::now();
    report.timings_ms.cleanup_ms = elapsed_ms(cleanup_start, cleanup_end);

    const auto wall_end = std::chrono::steady_clock::now();
    report.timings_ms.total_wall_ms = elapsed_ms(wall_start, wall_end);

    // Read RC metrics before disabling perf_trace
    report.rc_requests.total = kasumi::platform::perf_trace::get_count("rc.http_requests_attempted");
    report.rc_requests.control_bytes_sent = kasumi::platform::perf_trace::get_count("rc.bytes_sent_control_json");
    report.rc_requests.control_bytes_received = kasumi::platform::perf_trace::get_count("rc.bytes_received_control_json");

    for (const auto& endpoint : {"operations/check", "operations/hashsumfile", "operations/copyfile", "operations/deletefile", "operations/stat", "operations/mkdir", "operations/list", "sync/copy"}) {
        const std::string metric_name = "rc.http_requests_by_endpoint." + std::string{endpoint};
        const auto count = kasumi::platform::perf_trace::get_count(metric_name);
        if (count > 0) {
            report.rc_requests.by_endpoint[endpoint] = count;
        }
    }

    kasumi::platform::perf_trace::force_enable(false);

    if (outcome == CapabilityStatus::Supported) {
        report.status = "PASS";
    }

    if (!config.output_path.empty()) {
        std::ofstream stream(config.output_path, std::ios::binary | std::ios::trunc);
        if (stream) {
            stream << to_json(report).dump(2) << '\n';
        }
    }

    return outcome;
}

Phase11RunReport run_benchmark_trial(
    const Phase11Config& config,
    transport::Transport* parent_transport_override,
    transport::Transport* child_transport_override) {

    Phase11RunReport report;
    report.schema_version = 1;
    report.mode = std::string{mode_name(config.mode)};
    report.candidate_count = config.candidate_count;
    report.payload_bytes_per_object = config.payload_bytes;
    report.provider_requests = "NOT_MEASURED";

    // Gate 1: Check execution gate
    if (!config.execute_live && !parent_transport_override) {
        report.status = "REFUSED";
        report.error_message = "dry run safety: --execute-live required";
        return report;
    }

    // Gate 2: Check remote parent authorization
    if (!parent_transport_override && !is_authorized_parent(config.remote_parent)) {
        report.status = "REFUSED";
        report.error_message = "remote parent not authorized for live benchmark";
        return report;
    }

    const auto parsed_parent = smoke::parse_remote_parent(config.remote_parent);
    if (!parsed_parent) {
        report.status = "REFUSED";
        report.error_message = "invalid remote parent format";
        return report;
    }

    // Generate exclusive child namespace
    std::string child_name;
    if (config.explicit_child) {
        child_name = *config.explicit_child;
    } else {
        const auto nonce = kasumi::platform::random::hex_id();
        if (!nonce) {
            report.status = "FAIL";
            report.error_message = "could not generate random nonce";
            return report;
        }
        auto generated = generate_benchmark_child(*nonce);
        if (!generated) {
            report.status = "FAIL";
            report.error_message = generated.error();
            return report;
        }
        child_name = *generated;
    }

    const auto location = preflight::child_location(*parsed_parent, child_name);
    if (!location) {
        report.status = "REFUSED";
        report.error_message = location.error();
        return report;
    }
    report.namespace_path = *location;

    // Local scratch directory
    std::error_code fs_error;
    std::filesystem::create_directories(config.local_scratch, fs_error);

    // Parent transport acquisition
    std::optional<transport::Transport> owned_parent_storage;
    transport::Transport* parent_storage = parent_transport_override;
    if (!parent_storage) {
        auto opened = transport::open_transport(parsed_parent->location);
        if (!opened) {
            report.status = "REFUSED";
            report.error_message = "could not open parent transport: " + transport::describe(opened.error());
            return report;
        }
        owned_parent_storage = std::move(*opened);
        parent_storage = &*owned_parent_storage;
    }

    const auto wall_start = std::chrono::steady_clock::now();

    // Preflight observation: ensure child is completely unused
    const auto preflight_start = std::chrono::steady_clock::now();
    if (!parent_transport_override) {
        auto pre_obs = preflight::observe_pre_initialize(
            *parent_storage, *parsed_parent, child_name, config.preflight_timeout);
        auto classification = preflight::classify_pre_initialize(
            pre_obs, *parsed_parent, child_name);
        if (classification.disposition != preflight::ChildDisposition::Unused) {
            report.status = "REFUSED";
            report.error_message = "child namespace not unused: " + classification.reason;
            return report;
        }
    }
    const auto preflight_end = std::chrono::steady_clock::now();
    report.timings_ms.preflight_ms = elapsed_ms(preflight_start, preflight_end);

    // Open child transport
    std::optional<transport::Transport> owned_child_storage;
    transport::Transport* child_storage = child_transport_override;
    if (!child_storage) {
        auto opened_child = transport::open_transport(*location);
        if (!opened_child) {
            report.status = "FAIL";
            report.error_message = "could not open child transport: " + transport::describe(opened_child.error());
            return report;
        }
        owned_child_storage = std::move(*opened_child);
        child_storage = &*owned_child_storage;
    }

    // Enable and reset perf trace for RC measurements
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();

    // Write owner marker
    const auto marker_start = std::chrono::steady_clock::now();
    std::string token;
    if (config.explicit_token) {
        token = *config.explicit_token;
    } else {
        const auto generated_token = kasumi::platform::random::hex_id();
        token = generated_token ? *generated_token : "trial-token-fixed";
    }
    const auto marker_file = config.local_scratch / "trial.owner.marker";
    write_file_string(marker_file, token);
    auto put_marker = transport::put(*child_storage, marker_file, owner_marker_name);
    if (!put_marker) {
        report.status = "FAIL";
        report.error_message = "failed to put owner marker: " + transport::describe(put_marker.error());
        return report;
    }

    // Verify owner marker via readback
    const auto marker_readback_file = config.local_scratch / "trial.marker.readback";
    auto get_marker = transport::get(*child_storage, owner_marker_name, marker_readback_file);
    if (!get_marker || read_file_string(marker_readback_file) != token) {
        report.status = "FAIL";
        report.error_message = "owner marker verification failed";
        return report;
    }
    report.cleanup.owner_marker_verified = true;
    const auto marker_end = std::chrono::steady_clock::now();
    report.timings_ms.marker_ms = elapsed_ms(marker_start, marker_end);

    const std::size_t N = config.candidate_count;
    std::vector<std::string> source_ids;
    std::vector<std::string> dest_ids;
    std::vector<std::string> expected_hashes;
    source_ids.reserve(N);
    dest_ids.reserve(N);
    expected_hashes.reserve(N);

    // 1. Upload N objects
    const auto upload_start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < N; ++i) {
        const auto src_id = "src-" + std::to_string(i);
        const auto dst_id = "dst-" + std::to_string(i);
        source_ids.push_back(src_id);
        dest_ids.push_back(dst_id);

        const auto payload_file = config.local_scratch / ("trial_payload_" + std::to_string(i) + ".bin");
        if (!write_synthetic_payload(payload_file, i, config.payload_bytes)) {
            report.status = "FAIL";
            report.error_message = "failed to create payload file";
            return report;
        }

        auto local_hash = crypto::physical::hash_file(payload_file, "sha256");
        if (!local_hash) {
            report.status = "FAIL";
            report.error_message = "failed to calculate local SHA-256";
            return report;
        }
        expected_hashes.push_back(*local_hash);

        auto put_res = transport::put(*child_storage, payload_file, src_id);
        if (!put_res) {
            report.status = "FAIL";
            report.error_message = "failed to upload source " + src_id + ": " + transport::describe(put_res.error());
            return report;
        }
        report.payload_transfer.upload_bytes += config.payload_bytes;
    }
    const auto upload_end = std::chrono::steady_clock::now();
    report.timings_ms.upload_ms = elapsed_ms(upload_start, upload_end);

    // 2. Physical hash of sources
    const auto src_hash_start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < N; ++i) {
        auto hash_res = transport::physical_hash(*child_storage, source_ids[i], "sha256");
        if (!hash_res || *hash_res != expected_hashes[i]) {
            report.status = "FAIL";
            report.error_message = "source physical hash mismatch on " + source_ids[i];
            return report;
        }
        ++report.kasumi_operations.individual_source_hashes;
    }
    report.integrity.all_source_hashes_valid = true;
    const auto src_hash_end = std::chrono::steady_clock::now();
    report.timings_ms.source_hash_ms = elapsed_ms(src_hash_start, src_hash_end);

    // 3. Native copy
    const auto copy_start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < N; ++i) {
        ++report.kasumi_operations.native_copy_attempts;
        auto copy_res = transport::copy(*child_storage, source_ids[i], dest_ids[i]);
        if (!copy_res) {
            report.status = "FAIL";
            report.error_message = "native copy failed for " + source_ids[i] + " -> " + dest_ids[i] + ": " + transport::describe(copy_res.error());
            return report;
        }
        ++report.kasumi_operations.native_copy_successes;
    }
    const auto copy_end = std::chrono::steady_clock::now();
    report.timings_ms.copy_ms = elapsed_ms(copy_start, copy_end);

    // 4. Destination verification
    const auto verify_start = std::chrono::steady_clock::now();
    if (config.mode == BenchmarkMode::Individual) {
        for (std::size_t i = 0; i < N; ++i) {
            ++report.kasumi_operations.individual_destination_hashes;
            auto dest_hash = transport::physical_hash(*child_storage, dest_ids[i], "sha256");
            if (!dest_hash || *dest_hash != expected_hashes[i]) {
                report.status = "FAIL";
                report.error_message = "destination hash mismatch on " + dest_ids[i];
                return report;
            }
            ++report.kasumi_operations.candidates_verified;
        }
        report.integrity.all_destinations_verified = true;
    } else { // BenchmarkMode::Batch
        constexpr std::size_t batch_capacity = 8;
        constexpr std::size_t min_batch_threshold = 6;
        for (std::size_t start = 0; start < N; start += batch_capacity) {
            const std::size_t slice_count = std::min(batch_capacity, N - start);
            if (slice_count >= min_batch_threshold) {
                // Batch verify
                transport::PhysicalHashBatchRequest batch_req{
                    .scratch_root = config.local_scratch,
                    .objects = {},
                    .algorithm = "sha256"
                };
                batch_req.objects.reserve(slice_count);
                for (std::size_t j = 0; j < slice_count; ++j) {
                    batch_req.objects.push_back(transport::PhysicalHashExpectation{
                        .identifier = dest_ids[start + j],
                        .expected_hash = expected_hashes[start + j]
                    });
                }
                ++report.kasumi_operations.batch_hash_calls;
                auto batch_res = transport::physical_hash_batch(*child_storage, batch_req);
                if (!batch_res) {
                    report.status = "FAIL";
                    report.error_message = "batch hash call failed: " + transport::describe(batch_res.error());
                    return report;
                }
                if (batch_res->matched.size() != slice_count || !batch_res->mismatched.empty() || !batch_res->missing.empty() || !batch_res->errors.empty()) {
                    report.status = "FAIL";
                    report.error_message = "batch verification positive contract violated in slice";
                    return report;
                }
                report.kasumi_operations.candidates_verified += slice_count;
            } else {
                // Individual verify for tail
                for (std::size_t j = 0; j < slice_count; ++j) {
                    const std::size_t idx = start + j;
                    ++report.kasumi_operations.individual_destination_hashes;
                    auto dest_hash = transport::physical_hash(*child_storage, dest_ids[idx], "sha256");
                    if (!dest_hash || *dest_hash != expected_hashes[idx]) {
                        report.status = "FAIL";
                        report.error_message = "tail destination hash mismatch on " + dest_ids[idx];
                        return report;
                    }
                    ++report.kasumi_operations.candidates_verified;
                }
            }
        }
        report.integrity.all_destinations_verified = true;
    }
    const auto verify_end = std::chrono::steady_clock::now();
    report.timings_ms.verify_ms = elapsed_ms(verify_start, verify_end);

    // 5. Readback validation of destination 0
    const auto readback_start = std::chrono::steady_clock::now();
    const auto readback_file = config.local_scratch / "trial_readback_dst_0.bin";
    auto get_res = transport::get(*child_storage, dest_ids[0], readback_file);
    if (get_res) {
        report.payload_transfer.download_bytes += config.payload_bytes;
        const auto original_file = config.local_scratch / "trial_payload_0.bin";
        if (read_file_bytes(readback_file) == read_file_bytes(original_file)) {
            report.integrity.exact_readback_verified = true;
        } else {
            report.status = "INVALID_RUN";
            report.error_message = "readback exact bytes mismatch on destination 0";
            return report;
        }
    } else {
        report.status = "FAIL";
        report.error_message = "failed to get destination 0 for readback";
        return report;
    }
    const auto readback_end = std::chrono::steady_clock::now();
    report.timings_ms.readback_ms = elapsed_ms(readback_start, readback_end);

    // 6. Confirm sources still present before cleanup
    bool sources_intact = true;
    for (const auto& src : source_ids) {
        auto pres = transport::presence(*child_storage, src);
        if (!pres || *pres != transport::Presence::Present) {
            sources_intact = false;
            break;
        }
    }
    report.integrity.sources_intact_before_cleanup = sources_intact;
    if (!sources_intact) {
        report.status = "INVALID_RUN";
        report.error_message = "sources missing before cleanup";
        return report;
    }

    // 7. Cleanup owned objects
    const auto cleanup_start = std::chrono::steady_clock::now();
    auto verify_marker_again = transport::get(*child_storage, owner_marker_name, marker_readback_file);
    if (!verify_marker_again || read_file_string(marker_readback_file) != token) {
        report.cleanup.result = "FAILED_OWNER_MISMATCH";
        report.status = "FAIL";
        report.error_message = "cleanup refused: owner marker token mismatch or missing";
        return report;
    }

    std::size_t removed = 0;
    for (const auto& dst : dest_ids) {
        if (transport::remove(*child_storage, dst)) {
            ++removed;
            ++report.kasumi_operations.removals;
        }
    }
    for (const auto& src : source_ids) {
        if (transport::remove(*child_storage, src)) {
            ++removed;
            ++report.kasumi_operations.removals;
        }
    }
    if (transport::remove(*child_storage, owner_marker_name)) {
        ++removed;
        report.cleanup.owner_marker_removed = true;
    }
    report.cleanup.objects_removed = removed;
    report.cleanup.result = "SUCCESS";
    const auto cleanup_end = std::chrono::steady_clock::now();
    report.timings_ms.cleanup_ms = elapsed_ms(cleanup_start, cleanup_end);

    const auto wall_end = std::chrono::steady_clock::now();
    report.timings_ms.total_wall_ms = elapsed_ms(wall_start, wall_end);

    // Read RC metrics before disabling perf_trace
    report.rc_requests.total = kasumi::platform::perf_trace::get_count("rc.http_requests_attempted");
    report.rc_requests.control_bytes_sent = kasumi::platform::perf_trace::get_count("rc.bytes_sent_control_json");
    report.rc_requests.control_bytes_received = kasumi::platform::perf_trace::get_count("rc.bytes_received_control_json");

    for (const auto& endpoint : {"operations/check", "operations/hashsumfile", "operations/copyfile", "operations/deletefile", "operations/stat", "operations/mkdir", "operations/list", "sync/copy"}) {
        const std::string metric_name = "rc.http_requests_by_endpoint." + std::string{endpoint};
        const auto count = kasumi::platform::perf_trace::get_count(metric_name);
        if (count > 0) {
            report.rc_requests.by_endpoint[endpoint] = count;
        }
    }

    kasumi::platform::perf_trace::force_enable(false);
    report.status = "PASS";

    if (!config.output_path.empty()) {
        std::ofstream stream(config.output_path, std::ios::binary | std::ios::trunc);
        if (stream) {
            stream << to_json(report).dump(2) << '\n';
        }
    }

    return report;
}

nlohmann::json to_json(const Phase11RunReport& report) {
    nlohmann::json root{
        {"schema_version", report.schema_version},
        {"namespace", report.namespace_path},
        {"mode", report.mode},
        {"candidate_count", report.candidate_count},
        {"payload_bytes_per_object", report.payload_bytes_per_object},
        {"status", report.status},
        {"error_message", report.error_message},
        {"timings_ms", {
            {"total_wall_ms", report.timings_ms.total_wall_ms},
            {"preflight_ms", report.timings_ms.preflight_ms},
            {"marker_ms", report.timings_ms.marker_ms},
            {"upload_ms", report.timings_ms.upload_ms},
            {"source_hash_ms", report.timings_ms.source_hash_ms},
            {"copy_ms", report.timings_ms.copy_ms},
            {"verify_ms", report.timings_ms.verify_ms},
            {"readback_ms", report.timings_ms.readback_ms},
            {"cleanup_ms", report.timings_ms.cleanup_ms}
        }},
        {"kasumi_operations", {
            {"native_copy_attempts", report.kasumi_operations.native_copy_attempts},
            {"native_copy_successes", report.kasumi_operations.native_copy_successes},
            {"batch_hash_calls", report.kasumi_operations.batch_hash_calls},
            {"individual_source_hashes", report.kasumi_operations.individual_source_hashes},
            {"individual_destination_hashes", report.kasumi_operations.individual_destination_hashes},
            {"fallback_get_count", report.kasumi_operations.fallback_get_count},
            {"fallback_put_count", report.kasumi_operations.fallback_put_count},
            {"removals", report.kasumi_operations.removals},
            {"candidates_verified", report.kasumi_operations.candidates_verified}
        }},
        {"rc_requests", {
            {"total", report.rc_requests.total},
            {"by_endpoint", report.rc_requests.by_endpoint},
            {"control_bytes_sent", report.rc_requests.control_bytes_sent},
            {"control_bytes_received", report.rc_requests.control_bytes_received}
        }},
        {"payload_transfer", {
            {"upload_bytes", report.payload_transfer.upload_bytes},
            {"download_bytes", report.payload_transfer.download_bytes}
        }},
        {"provider_requests", report.provider_requests},
        {"integrity", {
            {"all_source_hashes_valid", report.integrity.all_source_hashes_valid},
            {"all_destinations_verified", report.integrity.all_destinations_verified},
            {"exact_readback_verified", report.integrity.exact_readback_verified},
            {"sources_intact_before_cleanup", report.integrity.sources_intact_before_cleanup},
            {"mismatched", report.integrity.mismatched},
            {"missing", report.integrity.missing},
            {"errors", report.integrity.errors},
            {"unexpected", report.integrity.unexpected}
        }},
        {"cleanup", {
            {"result", report.cleanup.result},
            {"objects_removed", report.cleanup.objects_removed},
            {"owner_marker_verified", report.cleanup.owner_marker_verified},
            {"owner_marker_removed", report.cleanup.owner_marker_removed}
        }}
    };
    return root;
}

} // namespace kasumi::operational::phase11
