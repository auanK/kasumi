#ifndef KASUMI_APPLICATION_OBSERVATION_SCANNER_HPP
#define KASUMI_APPLICATION_OBSERVATION_SCANNER_HPP

#include "core/ignore.hpp"
#include "core/node.hpp"
#include "state_storage/database.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "application/observation/file_metadata.hpp"

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
};

// Contextualized local scan failure.
struct ScanError {
    ScanErrorCode code = ScanErrorCode::Io;
    std::filesystem::path path;
    std::string operation;
    std::string detail;
};

// Function used to obtain file metadata and identity.
using MetadataQuery =
    std::expected<std::optional<cache::FileMetadata>, cache::FileMetadataError> (*)(
        const std::filesystem::path&, std::string_view);

// Formats a scan failure.
std::string describe(const ScanError& error);

// Scans the local tree according to the chosen policy.
std::expected<ScanResult, ScanError> scan_result(
    const std::filesystem::path& local_root,
    std::span<const state_storage::FileCacheRow> previous_cache = {},
    ScanPolicy policy = ScanPolicy::FullHash,
    MetadataQuery metadata_query = cache::read_file_metadata);

// Scans using the ignore rules selected by the current reconciliation.
std::expected<ScanResult, ScanError>
scan_result(const std::filesystem::path& local_root,
            std::span<const state_storage::FileCacheRow> previous_cache,
            ScanPolicy policy,
            MetadataQuery metadata_query,
            const kasumi::ignore::IgnoreList& ignore_list);

} // namespace kasumi::application::observation::scanner

#endif
