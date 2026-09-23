#ifndef KASUMI_GC_LIVE_RUNNER_SUPPORT_HPP
#define KASUMI_GC_LIVE_RUNNER_SUPPORT_HPP

#include "gc_live_preflight_support.hpp"
#include "remote_copy_smoke_support.hpp"

#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/maintenance.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/physical_hash.hpp"
#include "platform/clock.hpp"
#include "platform/perf_trace.hpp"
#include "platform/random.hpp"
#include "runtime/resolver.hpp"
#include "transport/transport.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <nlohmann/json.hpp>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::operational::gc_live_runner {

namespace preflight = kasumi::operational::gc_live_preflight;
namespace smoke = kasumi::operational::remote_copy_smoke;
namespace transport = kasumi::transport;
namespace integrity = kasumi::application::integrity;

enum class LiveGcStage {
    Start,
    PreflightPassed,
    ChildInitialized,
    OwnershipEstablished,
    ScenarioPublished,
    PreInventoryVerified,
    GcAttempted,
    PostInventoryVerified,
    CleanupCompleted
};

std::string_view stage_name(LiveGcStage stage) noexcept;

struct InventoryEntry {
    std::string identifier;
    std::uint64_t size = 0;
    std::optional<std::string> physical_sha256;
    std::optional<std::vector<std::uint8_t>> exact_bytes;
};

struct StorageInventory {
    std::optional<std::string> owner_marker;
    std::vector<InventoryEntry> vault_objects;
};

struct ScenarioObjects {
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    std::string reachable_content_id;
    std::string reachable_commit_id;
    std::string reachable_marker_id;
    std::string candidate_id;
    std::string candidate_sha256;
    std::size_t candidate_plaintext_bytes = 0;
    std::string expected_quarantine_id;
    std::string expected_quarantine_meta_id;
    std::vector<std::string> expected_pre_vault_objects;
    std::vector<std::string> expected_post_vault_objects;
};

constexpr std::string_view integrity_error_code_name(kasumi::application::integrity::ErrorCode code) noexcept {
    switch (code) {
        case kasumi::application::integrity::ErrorCode::InvalidInput:
            return "invalid_input";
        case kasumi::application::integrity::ErrorCode::StateFailure:
            return "state_failure";
        case kasumi::application::integrity::ErrorCode::WorkspaceFailure:
            return "workspace_failure";
        case kasumi::application::integrity::ErrorCode::TransportFailure:
            return "transport_failure";
        case kasumi::application::integrity::ErrorCode::CryptoFailure:
            return "crypto_failure";
        case kasumi::application::integrity::ErrorCode::IntegrityFailure:
            return "integrity_failure";
        case kasumi::application::integrity::ErrorCode::Unrecoverable:
            return "unrecoverable";
        case kasumi::application::integrity::ErrorCode::ConcurrentChange:
            return "concurrent_change";
    }
    return "unknown";
}

enum class CopyMode {
    Native,
    ForceFallback
};

struct GcExecutionResult {
    bool called = false;
    std::size_t call_count = 0;
    std::string result = "NOT_RUN"; // "SUCCESS", "FAILED"
    std::size_t candidate_objects = 0;
    std::size_t quarantined_objects = 0;
    std::size_t restored_objects = 0;
    std::size_t purged_objects = 0;
    std::optional<kasumi::application::integrity::ErrorCode> error_category;
    std::string error_detail_sanitized;
};

struct GcMetrics {
    std::size_t verified_copy_source_physical_hash = 0;
    std::size_t verified_copy_native_copy = 0;
    std::size_t verified_copy_native_copy_successes = 0;
    std::size_t verified_copy_destination_physical_hash = 0;
    std::size_t verified_copy_native_copy_verifications = 0;
    std::size_t gc_candidate_verified_copy = 0;
    std::size_t gc_candidate_metadata_publish = 0;
    std::size_t gc_candidate_pre_remove_barrier_verification = 0;
    std::size_t gc_candidate_remove = 0;
};

struct PostGcValidation {
    bool reachable_preserved = false;
    bool quarantine_present = false;
    bool quarantine_verified = false;
    bool metadata_authenticated = false;
    bool source_removed = false;
    std::size_t unexpected_removed = 0;
    std::size_t unexpected_created = 0;
};

struct RunnerOptions {
    std::string remote_parent;
    std::optional<std::filesystem::path> rclone_config;
    std::filesystem::path output_path;
    std::filesystem::path local_scratch;
    bool execute_live_gc = false;
    bool preserve_evidence_on_failure = true;
    CopyMode copy_mode = CopyMode::Native;
    std::size_t candidate_payload_bytes = 0;
    std::chrono::milliseconds preflight_timeout = std::chrono::minutes{2};
    std::optional<std::array<std::uint8_t, kasumi::crypto::KEY_SIZE>> explicit_key = std::nullopt;
    std::optional<std::string> explicit_child = std::nullopt;
    std::optional<std::string> explicit_owner_token = std::nullopt;
    using RandomGenerator = std::function<std::optional<std::string>()>;
    std::optional<RandomGenerator> random_generator = std::nullopt;
};

struct RunnerReport {
    int schema_version = 1;
    std::string phase = "GC_LIVE_SMOKE";
    std::string status = "NOT_RUN"; // "PASS", "FAILED", "REFUSED", "EXISTING"
    LiveGcStage stage_reached = LiveGcStage::Start;
    std::string error_message;

    std::string remote_parent;
    std::string effective_namespace;

    nlohmann::json pre_initialize = nullptr;
    nlohmann::json post_initialize = nullptr;

    struct OwnershipSummary {
        std::string result = "NOT_ATTEMPTED";
        bool marker_written = false;
        bool marker_readback_verified = false;
    } ownership;

    struct ScenarioSummary {
        std::string reachable_identifier;
        std::string candidate_identifier;
        std::string candidate_sha256;
        std::string quarantine_identifier;
    } scenario;

    struct BenchmarkReport {
        std::string copy_mode = "native";
        std::size_t candidate_plaintext_bytes = 0;
        std::uint64_t candidate_physical_bytes = 0;
        std::uint64_t gc_total_us = 0;
        std::uint64_t gc_candidate_verified_copy_us = 0;
        std::uint64_t verified_copy_source_physical_hash_us = 0;
        std::uint64_t verified_copy_native_copy_us = 0;
        std::uint64_t verified_copy_destination_physical_hash_us = 0;
        std::uint64_t rclone_download_us = 0;
        std::uint64_t rclone_upload_us = 0;
        std::uint64_t gc_candidate_metadata_publish_us = 0;
        std::uint64_t gc_candidate_pre_remove_barrier_verification_us = 0;
        std::uint64_t gc_candidate_remove_us = 0;
        std::uint64_t process_wall_ms = 0;
    } benchmark;

    StorageInventory inventory_before;
    GcExecutionResult gc;
    GcMetrics metrics;
    StorageInventory inventory_after;
    PostGcValidation validation;
    preflight::CleanupResult cleanup;
};

bool is_authorized_live_parent(std::string_view remote_parent) noexcept;

transport::Transport make_vault_transport(transport::Transport& underlying,
                                          std::string hidden_marker = "owner.marker",
                                          CopyMode copy_mode = CopyMode::Native);

std::expected<ScenarioObjects, transport::Error>
setup_scenario(transport::Transport& vault_storage,
               const std::filesystem::path& scratch_root,
               std::span<const std::uint8_t, kasumi::crypto::KEY_SIZE> key,
               std::size_t candidate_payload_bytes = 0);

std::expected<StorageInventory, transport::Error>
capture_inventory(transport::Transport& child_storage,
                  const std::filesystem::path& scratch_root,
                  bool capture_exact_bytes = false);

using GcInvocation = std::function<std::expected<integrity::GarbageCollectResult, integrity::Error>(
    const kasumi::runtime::RuntimeData& runtime_data,
    transport::Transport& vault_storage,
    std::span<const std::uint8_t, kasumi::crypto::KEY_SIZE> key)>;

RunnerReport run(
    const RunnerOptions& options,
    transport::Transport* parent_transport_override = nullptr,
    transport::Transport* child_transport_override = nullptr,
    GcInvocation gc_override = nullptr);

nlohmann::json to_json(const RunnerReport& report);

struct BenchmarkArguments {
    std::string remote;
    std::optional<std::filesystem::path> rclone_config;
    std::filesystem::path output;
    CopyMode mode = CopyMode::Native;
    std::size_t payload_bytes = 8 * 1024 * 1024; // 8 MiB default
    bool execute_live_benchmark = false;
    bool preserve_evidence_on_failure = true;
};

std::expected<BenchmarkArguments, std::string>
parse_benchmark_arguments(std::span<const std::string_view> args);

} // namespace kasumi::operational::gc_live_runner

#endif
