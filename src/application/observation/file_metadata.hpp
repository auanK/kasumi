#ifndef KASUMI_APPLICATION_OBSERVATION_FILE_METADATA_HPP
#define KASUMI_APPLICATION_OBSERVATION_FILE_METADATA_HPP

#include "application/observation/cache_contract.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace kasumi::application::observation::cache {

// Error categories when querying filesystem metadata.
enum class FileMetadataErrorCode : std::uint8_t {
    NotFound = 1,
    PermissionDenied = 2,
    IoError = 3,
    Other = 4
};

// Explicit error from filesystem metadata query.
struct FileMetadataError {
    FileMetadataErrorCode code = FileMetadataErrorCode::Other;
    std::string message;

    constexpr bool operator==(const FileMetadataError&) const = default;
};

// Formats error code as human-readable string.
const char* describe_metadata_error(FileMetadataErrorCode code) noexcept;

// Pure conversion functions for native timestamp formats to canonical Unix nanoseconds UTC.
// Returns std::nullopt on overflow, underflow, or invalid subsecond fraction.
std::optional<std::int64_t>
posix_timespec_to_unix_nanoseconds(std::int64_t sec, std::int64_t nsec) noexcept;

std::optional<std::int64_t>
windows_filetime_to_unix_nanoseconds(std::int64_t filetime_ticks) noexcept;

// Queries native filesystem metadata for a file.
//
// Semantics:
// - Valid regular file with complete, supported attributes: returns valid FileMetadata (is_valid = true).
// - Ineligible for hash cache (directory, symlink/reparse point, special file,
//   unsupported file ID, or invalid timestamp): returns std::nullopt.
// - Real filesystem error (file not found, access denied, I/O error): returns std::unexpected(FileMetadataError).
//
// Lifetime contract:
// The `logical_path` view must outlive the returned `FileMetadata`.
std::expected<std::optional<FileMetadata>, FileMetadataError>
read_file_metadata(const std::filesystem::path& physical_path,
                   std::string_view logical_path) noexcept;

} // namespace kasumi::application::observation::cache

namespace kasumi::application::observation {
using cache::describe_metadata_error;
using cache::FileMetadataError;
using cache::FileMetadataErrorCode;
using cache::posix_timespec_to_unix_nanoseconds;
using cache::read_file_metadata;
using cache::windows_filetime_to_unix_nanoseconds;
} // namespace kasumi::application::observation

#endif

