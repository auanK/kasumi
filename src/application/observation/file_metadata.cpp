#include "application/observation/file_metadata.hpp"

#include <cerrno>
#include <cstring>
#include <limits>
#include <system_error>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#endif

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
posix_timespec_to_unix_nanoseconds(std::int64_t sec, std::int64_t nsec) noexcept {
    if (nsec < 0 || nsec >= 1'000'000'000LL) {
        return std::nullopt;
    }
    constexpr std::int64_t kMaxSec = 9'223'372'036LL;
    constexpr std::int64_t kMinSec = -9'223'372'036LL;
    constexpr std::int64_t kMaxNsecForMaxSec = 854'775'807LL;

    if (sec > kMaxSec || sec < kMinSec) {
        return std::nullopt;
    }
    if (sec == kMaxSec && nsec > kMaxNsecForMaxSec) {
        return std::nullopt;
    }
    return sec * 1'000'000'000LL + nsec;
}

std::optional<std::int64_t>
windows_filetime_to_unix_nanoseconds(std::int64_t filetime_ticks) noexcept {
    constexpr std::int64_t kEpochOffset = 116'444'736'000'000'000LL;
    constexpr std::int64_t kMaxTicksSinceEpoch = 92'233'720'368'547'758LL;
    constexpr std::int64_t kMinTicksSinceEpoch = -92'233'720'368'547'758LL;

    constexpr std::int64_t kMaxFiletimeTicks = kEpochOffset + kMaxTicksSinceEpoch;
    constexpr std::int64_t kMinFiletimeTicks = kEpochOffset + kMinTicksSinceEpoch;

    if (filetime_ticks < kMinFiletimeTicks || filetime_ticks > kMaxFiletimeTicks) {
        return std::nullopt;
    }

    const std::int64_t ticks_since_1970 = filetime_ticks - kEpochOffset;
    return ticks_since_1970 * 100LL;
}

#if !defined(_WIN32)
std::expected<std::optional<FileMetadata>, FileMetadataError>
read_file_metadata(const std::filesystem::path& physical_path,
                   std::string_view logical_path) noexcept {
    struct stat st{};
    if (::lstat(physical_path.c_str(), &st) != 0) {
        const int err = errno;
        if (err == ENOENT || err == ENOTDIR) {
            return std::unexpected(FileMetadataError{
                .code = FileMetadataErrorCode::NotFound,
                .message = std::system_category().message(err),
            });
        }
        if (err == EACCES || err == EPERM) {
            return std::unexpected(FileMetadataError{
                .code = FileMetadataErrorCode::PermissionDenied,
                .message = std::system_category().message(err),
            });
        }
        return std::unexpected(FileMetadataError{
            .code = FileMetadataErrorCode::IoError,
            .message = std::system_category().message(err),
        });
    }

    // Only regular files produce reusable cache metadata.
    // Directories, symlinks, FIFOs, sockets, block/char devices return std::nullopt.
    if (!S_ISREG(st.st_mode)) {
        return std::nullopt;
    }

    if (st.st_size < 0) {
        return std::nullopt;
    }

    const auto mtime_ns = posix_timespec_to_unix_nanoseconds(
        static_cast<std::int64_t>(st.st_mtim.tv_sec),
        static_cast<std::int64_t>(st.st_mtim.tv_nsec));
    if (!mtime_ns.has_value()) {
        return std::nullopt;
    }

    FileMetadata metadata{
        .path = logical_path,
        .kind = EntryKind::RegularFile,
        .size = static_cast<std::uint64_t>(st.st_size),
        .mtime_nanoseconds = *mtime_ns,
        .identity = FileIdentity{
            .volume = static_cast<std::uint64_t>(st.st_dev),
            .file_low = static_cast<std::uint64_t>(st.st_ino),
            .file_high = 0ULL,
        },
        .is_valid = true,
    };

    return metadata;
}
#else
namespace {
struct ScopedHandle {
    HANDLE handle = INVALID_HANDLE_VALUE;
    ~ScopedHandle() noexcept {
        if (handle != INVALID_HANDLE_VALUE && handle != nullptr) {
            ::CloseHandle(handle);
        }
    }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    ScopedHandle(ScopedHandle&& other) noexcept : handle(other.handle) {
        other.handle = INVALID_HANDLE_VALUE;
    }
};

bool is_unsupported_id_error(DWORD error) noexcept {
    return error == ERROR_NOT_SUPPORTED || error == ERROR_INVALID_FUNCTION ||
           error == ERROR_INVALID_PARAMETER;
}
} // namespace

std::expected<std::optional<FileMetadata>, FileMetadataError>
read_file_metadata(const std::filesystem::path& physical_path,
                   std::string_view logical_path) noexcept {
    const HANDLE raw_handle = ::CreateFileW(
        physical_path.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);

    if (raw_handle == INVALID_HANDLE_VALUE) {
        const DWORD err = ::GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
            return std::unexpected(FileMetadataError{
                .code = FileMetadataErrorCode::NotFound,
                .message = std::system_category().message(static_cast<int>(err)),
            });
        }
        if (err == ERROR_ACCESS_DENIED || err == ERROR_SHARING_VIOLATION) {
            return std::unexpected(FileMetadataError{
                .code = FileMetadataErrorCode::PermissionDenied,
                .message = std::system_category().message(static_cast<int>(err)),
            });
        }
        return std::unexpected(FileMetadataError{
            .code = FileMetadataErrorCode::IoError,
            .message = std::system_category().message(static_cast<int>(err)),
        });
    }

    const ScopedHandle handle{raw_handle};

    FILE_BASIC_INFO basic{};
    if (!::GetFileInformationByHandleEx(
            handle.handle, FileBasicInfo, &basic, sizeof(basic))) {
        const DWORD err = ::GetLastError();
        return std::unexpected(FileMetadataError{
            .code = FileMetadataErrorCode::IoError,
            .message = std::system_category().message(static_cast<int>(err)),
        });
    }

    if ((basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
        (basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return std::nullopt;
    }

    const auto mtime_ns = windows_filetime_to_unix_nanoseconds(
        basic.LastWriteTime.QuadPart);
    if (!mtime_ns.has_value()) {
        return std::nullopt;
    }

    FILE_STANDARD_INFO standard{};
    if (!::GetFileInformationByHandleEx(
            handle.handle, FileStandardInfo, &standard, sizeof(standard))) {
        const DWORD err = ::GetLastError();
        return std::unexpected(FileMetadataError{
            .code = FileMetadataErrorCode::IoError,
            .message = std::system_category().message(static_cast<int>(err)),
        });
    }

    if (standard.Directory || standard.EndOfFile.QuadPart < 0) {
        return std::nullopt;
    }

    FILE_ID_INFO id{};
    if (!::GetFileInformationByHandleEx(
            handle.handle, FileIdInfo, &id, sizeof(id))) {
        const DWORD err = ::GetLastError();
        if (is_unsupported_id_error(err)) {
            return std::nullopt;
        }
        return std::unexpected(FileMetadataError{
            .code = FileMetadataErrorCode::IoError,
            .message = std::system_category().message(static_cast<int>(err)),
        });
    }

    FileIdentity file_identity{};
    file_identity.volume = id.VolumeSerialNumber;
    std::memcpy(&file_identity.file_low,
                id.FileId.Identifier,
                sizeof(std::uint64_t));
    std::memcpy(&file_identity.file_high,
                id.FileId.Identifier + sizeof(std::uint64_t),
                sizeof(std::uint64_t));

    FileMetadata metadata{
        .path = logical_path,
        .kind = EntryKind::RegularFile,
        .size = static_cast<std::uint64_t>(standard.EndOfFile.QuadPart),
        .mtime_nanoseconds = *mtime_ns,
        .identity = file_identity,
        .is_valid = true,
    };

    return metadata;
}
#endif

} // namespace kasumi::application::observation::cache
