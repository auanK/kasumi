#include "application/observation/file_metadata.hpp"

namespace kasumi::application::observation::cache {

const char* describe_metadata_error(FileMetadataErrorCode code) noexcept {
    switch (code) {
        case FileMetadataErrorCode::NotFound:
            return "NotFound";
        case FileMetadataErrorCode::PermissionDenied:
            return "PermissionDenied";
        case FileMetadataErrorCode::IoError:
            return "IoError";
        case FileMetadataErrorCode::Other:
            return "Other";
    }
    return "Unknown";
}

std::optional<std::int64_t>
posix_timespec_to_unix_nanoseconds(std::int64_t /*sec*/, std::int64_t /*nsec*/) noexcept {
    // TDD RED Phase: Stub returning nullopt to verify tests fail
    return std::nullopt;
}

std::optional<std::int64_t>
windows_filetime_to_unix_nanoseconds(std::int64_t /*filetime_ticks*/) noexcept {
    // TDD RED Phase: Stub returning nullopt to verify tests fail
    return std::nullopt;
}

std::expected<std::optional<FileMetadata>, FileMetadataError>
read_file_metadata(const std::filesystem::path& /*physical_path*/,
                   std::string_view /*logical_path*/) noexcept {
    // TDD RED Phase: Stub returning unexpected to verify tests fail
    return std::unexpected(FileMetadataError{
        .code = FileMetadataErrorCode::Other,
        .message = "TDD RED stub",
    });
}

} // namespace kasumi::application::observation::cache

