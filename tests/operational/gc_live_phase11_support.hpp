#ifndef KASUMI_GC_LIVE_PHASE11_SUPPORT_HPP
#define KASUMI_GC_LIVE_PHASE11_SUPPORT_HPP

#include "gc_live_preflight_support.hpp"
#include "gc_live_runner_support.hpp"
#include "remote_copy_smoke_support.hpp"

#include "crypto/physical_hash.hpp"
#include "platform/perf_trace.hpp"
#include "platform/random.hpp"
#include "transport/transport.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::operational::phase11 {

namespace transport = kasumi::transport;
namespace preflight = kasumi::operational::gc_live_preflight;
namespace smoke = kasumi::operational::remote_copy_smoke;

enum class BenchmarkMode {
    Individual,
    Batch
};

constexpr std::string_view mode_name(BenchmarkMode mode) noexcept {
    return mode == BenchmarkMode::Individual ? "individual" : "batch";
}

enum class CapabilityStatus {
    Supported,
    Unsupported,
    Failed,
    Refused
};

constexpr std::string_view capability_status_name(CapabilityStatus status) noexcept {
    switch (status) {
        case CapabilityStatus::Supported: return "SUPPORTED";
        case CapabilityStatus::Unsupported: return "UNSUPPORTED";
        case CapabilityStatus::Failed: return "FAILED";
        case CapabilityStatus::Refused: return "REFUSED";
    }
    return "UNKNOWN";
}

struct Phase11Config {
    std::string remote_parent = "kasumi:integration-tests";
    std::optional<std::filesystem::path> rclone_config = std::nullopt;
    std::filesystem::path output_path;
    std::filesystem::path local_scratch;
    bool execute_live = false;
    std::size_t candidate_count = 8;
    std::size_t payload_bytes = 4096;
    BenchmarkMode mode = BenchmarkMode::Batch;
    std::optional<std::string> explicit_child = std::nullopt;
    std::optional<std::string> explicit_token = std::nullopt;
    std::chrono::milliseconds preflight_timeout = std::chrono::minutes{2};
};

struct Phase11RunReport {
    int schema_version = 1;
    std::string namespace_path;
    std::string mode = "batch";
    std::size_t candidate_count = 0;
    std::size_t payload_bytes_per_object = 0;
    std::string status = "NOT_RUN"; // "PASS", "FAIL", "INVALID_RUN", "UNSUPPORTED", "REFUSED"
    std::string error_message;

    struct TimingsMs {
        double total_wall_ms = 0.0;
        double preflight_ms = 0.0;
        double marker_ms = 0.0;
        double upload_ms = 0.0;
        double source_hash_ms = 0.0;
        double copy_ms = 0.0;
        double verify_ms = 0.0;
        double readback_ms = 0.0;
        double cleanup_ms = 0.0;
    } timings_ms;

    struct KasumiOperations {
        std::size_t native_copy_attempts = 0;
        std::size_t native_copy_successes = 0;
        std::size_t batch_hash_calls = 0;
        std::size_t individual_source_hashes = 0;
        std::size_t individual_destination_hashes = 0;
        std::size_t fallback_get_count = 0;
        std::size_t fallback_put_count = 0;
        std::size_t removals = 0;
        std::size_t candidates_verified = 0;
    } kasumi_operations;

    struct RcRequests {
        std::uint64_t total = 0;
        std::map<std::string, std::uint64_t> by_endpoint;
        std::uint64_t control_bytes_sent = 0;
        std::uint64_t control_bytes_received = 0;
    } rc_requests;

    struct PayloadTransfer {
        std::uint64_t upload_bytes = 0;
        std::uint64_t download_bytes = 0;
    } payload_transfer;

    std::string provider_requests = "NOT_MEASURED";

    struct IntegritySummary {
        bool all_source_hashes_valid = false;
        bool all_destinations_verified = false;
        bool exact_readback_verified = false;
        bool sources_intact_before_cleanup = false;
        std::size_t mismatched = 0;
        std::size_t missing = 0;
        std::size_t errors = 0;
        std::size_t unexpected = 0;
    } integrity;

    struct CleanupSummary {
        std::string result = "NOT_ATTEMPTED";
        std::size_t objects_removed = 0;
        bool owner_marker_verified = false;
        bool owner_marker_removed = false;
    } cleanup;
};

// Guardrail validations
bool is_authorized_parent(std::string_view remote_parent) noexcept;
bool is_disallowed_root(std::string_view remote) noexcept;
std::expected<std::string, std::string> generate_benchmark_child(std::string_view random_hex);

// Phase 3 Capability Test
CapabilityStatus run_capability_test(
    const Phase11Config& config,
    Phase11RunReport& report,
    transport::Transport* parent_transport_override = nullptr,
    transport::Transport* child_transport_override = nullptr);

// Phase 4+ Benchmark Trial
Phase11RunReport run_benchmark_trial(
    const Phase11Config& config,
    transport::Transport* parent_transport_override = nullptr,
    transport::Transport* child_transport_override = nullptr);

nlohmann::json to_json(const Phase11RunReport& report);

} // namespace kasumi::operational::phase11

#endif // KASUMI_GC_LIVE_PHASE11_SUPPORT_HPP
