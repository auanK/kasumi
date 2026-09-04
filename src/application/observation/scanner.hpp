#ifndef KASUMI_APPLICATION_OBSERVATION_SCANNER_HPP
#define KASUMI_APPLICATION_OBSERVATION_SCANNER_HPP

#include "core/node.hpp"
#include "platform/file_fingerprint.hpp"
#include "state_storage/database.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::application::observation::scanner {

// Failure categories during local scanning.
enum class ScanErrorCode {
    PermissionDenied,
    Metadata,
    Io
};

// Strategy used for computing file hashes.
enum class ScanPolicy {
    // Recomputes all hashes.
    FullHash,
    // Reuses hash only when strong fingerprint is unchanged.
    ReuseStrongFingerprint,
};

// Snapshot tree and reusable data produced by a full scan.
struct ScanResult {
    Snapshot snapshot;
    std::vector<state_storage::FileCacheRow> cache;
    // Sorted file references of observed directories.
    std::vector<std::uint64_t> directory_file_references;
    // Indicates that all directory file references were obtained.
    bool directory_lineage_complete = false;
};

// Result of an isolated file observation.
struct TargetedFileObservation {
    NodeRow row;
    // Present only when strong fingerprint allows safe reuse.
    std::optional<state_storage::FileCacheRow> cache;
};

// Contextualized local scan failure.
struct ScanError {
    ScanErrorCode code = ScanErrorCode::Io;
    std::filesystem::path path;
    std::string operation;
    std::string detail;
};

// Function used to obtain a file fingerprint.
using FingerprintQuery =
    platform::FileFingerprintResult (*)(const std::filesystem::path&);

// Formats a scan failure.
std::string describe(const ScanError& error);

// Scans the local tree according to the chosen policy.
std::expected<ScanResult, ScanError> scan_result(
    const std::filesystem::path& local_root,
    std::span<const state_storage::FileCacheRow> previous_cache = {},
    ScanPolicy policy = ScanPolicy::FullHash,
    FingerprintQuery fingerprint_query = platform::regular_file_fingerprint);

// Observes a single safe relative path.
std::expected<TargetedFileObservation, ScanError> observe_file(
    const std::filesystem::path& local_root,
    std::string_view relative_path,
    std::optional<state_storage::FileCacheRow> cached = std::nullopt,
    FingerprintQuery fingerprint_query = platform::regular_file_fingerprint);

} // namespace kasumi::application::observation::scanner

#endif
