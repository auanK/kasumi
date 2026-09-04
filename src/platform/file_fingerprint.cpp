#include "platform/file_fingerprint.hpp"

#include <cerrno>
#include <cstring>
#include <system_error>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#endif

namespace kasumi::platform {
#if defined(_WIN32)
bool unsupported_error(DWORD e) noexcept {
    return e == ERROR_NOT_SUPPORTED || e == ERROR_INVALID_FUNCTION ||
           e == ERROR_INVALID_PARAMETER;
}
#endif

FileFingerprintResult
regular_file_fingerprint(const std::filesystem::path& path) {
#if defined(_WIN32)
    const auto handle =
        CreateFileW(path.c_str(),
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        const auto e = GetLastError();
        if (unsupported_error(e))
            return std::optional<FileFingerprint>{};
        return std::unexpected(
            std::system_category().message(static_cast<int>(e)));
    }
    FILE_ID_INFO id{};
    FILE_BASIC_INFO basic{};
    const auto id_ok =
        GetFileInformationByHandleEx(handle, FileIdInfo, &id, sizeof(id));
    const auto id_error = id_ok ? ERROR_SUCCESS : GetLastError();
    const auto basic_ok = GetFileInformationByHandleEx(
        handle, FileBasicInfo, &basic, sizeof(basic));
    const auto basic_error = basic_ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(handle);
    if (!id_ok || !basic_ok) {
        const auto e = !id_ok ? id_error : basic_error;
        if (unsupported_error(e))
            return std::optional<FileFingerprint>{};
        return std::unexpected(
            std::system_category().message(static_cast<int>(e)));
    }
    if ((basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        return std::optional<FileFingerprint>{};
    FileFingerprint result{.kind = FileFingerprintKind::WindowsFileIdentity};
    result.value[0] = id.VolumeSerialNumber;
    std::memcpy(&result.value[1], id.FileId.Identifier, sizeof(std::uint64_t));
    std::memcpy(&result.value[2],
                id.FileId.Identifier + sizeof(std::uint64_t),
                sizeof(std::uint64_t));
    result.value[3] = static_cast<std::uint64_t>(basic.ChangeTime.QuadPart);
    return std::optional<FileFingerprint>{result};
#else
    struct stat status{};
    if (stat(path.c_str(), &status) != 0)
        return std::unexpected(std::system_category().message(errno));
    if (!S_ISREG(status.st_mode))
        return std::optional<FileFingerprint>{};
    // Inode and ctime can be reused within the same recorded timestamp.
    return std::optional<FileFingerprint>{};
#endif
}

std::expected<std::optional<std::uint64_t>, std::string>
directory_file_reference(const std::filesystem::path& path) {
#if defined(_WIN32)
    const auto handle =
        CreateFileW(path.c_str(),
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        const auto error = GetLastError();
        if (unsupported_error(error))
            return std::optional<std::uint64_t>{};
        return std::unexpected(
            std::system_category().message(static_cast<int>(error)));
    }
    BY_HANDLE_FILE_INFORMATION info{};
    const auto ok = GetFileInformationByHandle(handle, &info);
    const auto error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(handle);
    if (!ok) {
        if (unsupported_error(error))
            return std::optional<std::uint64_t>{};
        return std::unexpected(
            std::system_category().message(static_cast<int>(error)));
    }
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
        return std::optional<std::uint64_t>{};
    return std::optional<std::uint64_t>{
        (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) |
        info.nFileIndexLow};
#else
    static_cast<void>(path);
    return std::optional<std::uint64_t>{};
#endif
}
} // namespace kasumi::platform
