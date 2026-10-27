#ifndef KASUMI_APPLICATION_PROFILE_DIRECTORY_IDENTITY_HPP
#define KASUMI_APPLICATION_PROFILE_DIRECTORY_IDENTITY_HPP

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#endif

namespace kasumi::application::detail {

struct DirectoryIdentity {
#if defined(_WIN32)
    std::array<std::uint8_t, 16> identifier{};
    std::uint64_t volume = 0;
#else
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
#endif
    bool valid = false;
    bool operator==(const DirectoryIdentity&) const = default;
};

inline DirectoryIdentity
query_directory_identity(const std::filesystem::path& path) noexcept {
    DirectoryIdentity result;
#if defined(_WIN32)
    const auto handle =
        CreateFileW(path.c_str(),
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return result;
    }
    FILE_ID_INFO info{};
    if (GetFileInformationByHandleEx(handle, FileIdInfo, &info, sizeof(info))) {
        result.volume = info.VolumeSerialNumber;
        std::memcpy(result.identifier.data(),
                    info.FileId.Identifier,
                    result.identifier.size());
        result.valid = true;
    }
    CloseHandle(handle);
#else
    struct stat status {};
    if (::lstat(path.c_str(), &status) == 0 && S_ISDIR(status.st_mode)) {
        result.device = static_cast<std::uint64_t>(status.st_dev);
        result.inode = static_cast<std::uint64_t>(status.st_ino);
        result.valid = true;
    }
#endif
    return result;
}

inline bool has_reparse_point(const std::filesystem::path& path) noexcept {
#if defined(_WIN32)
    const DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        const DWORD code = GetLastError();
        return code != ERROR_FILE_NOT_FOUND && code != ERROR_PATH_NOT_FOUND;
    }
    return (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
    static_cast<void>(path);
    return false;
#endif
}

} // namespace kasumi::application::detail

#endif
