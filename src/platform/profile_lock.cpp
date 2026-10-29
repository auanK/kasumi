#include "platform/profile_lock.hpp"

#include "platform/private_storage.hpp"

#include <cerrno>
#include <system_error>
#include <utility>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace kasumi::platform {

void release_profile_lock(std::intptr_t& lock) noexcept {
    const auto handle = std::exchange(lock, invalid_profile_lock);
    if (handle == invalid_profile_lock) {
        return;
    }
#ifdef _WIN32
    static_cast<void>(CloseHandle(reinterpret_cast<HANDLE>(handle)));
#else
    static_cast<void>(::close(static_cast<int>(handle)));
#endif
}

std::expected<std::intptr_t, std::string>
acquire_profile_lock(const std::filesystem::path& lock_path) {
    if (lock_path.empty()) {
        return std::unexpected("empty profile lock path");
    }
    const auto parent_path = lock_path.parent_path();
    std::error_code parent_error;
    const auto parent_status =
        std::filesystem::symlink_status(parent_path, parent_error);
    if (parent_error) {
        return std::unexpected("could not inspect profile lock parent: " +
                               parent_error.message());
    }
    if (parent_status.type() != std::filesystem::file_type::directory) {
        return std::unexpected("profile lock parent is not a plain directory");
    }
#if defined(_WIN32)
    if (!private_storage::query_directory_identity(parent_path).valid) {
        return std::unexpected("profile lock parent is not an accessible "
                               "plain directory");
    }
#endif

#ifdef _WIN32
    const auto open_lock = [&] {
        return CreateFileW(lock_path.c_str(),
                           GENERIC_READ,
                           0,
                           nullptr,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                           nullptr);
    };
    auto handle = open_lock();
    DWORD open_error = (handle == INVALID_HANDLE_VALUE) ? GetLastError()
                                                        : ERROR_SUCCESS;
    if (handle == INVALID_HANDLE_VALUE &&
        (open_error == ERROR_FILE_NOT_FOUND ||
         open_error == ERROR_PATH_NOT_FOUND)) {
        auto created = private_storage::create_private_file(lock_path);
        if (!created && !created.error().is_collision) {
            return std::unexpected(created.error().message);
        }
        if (created) {
            private_storage::close_private_file(*created);
        }
        handle = open_lock();
        open_error = (handle == INVALID_HANDLE_VALUE) ? GetLastError()
                                                      : ERROR_SUCCESS;
    }
    if (handle == INVALID_HANDLE_VALUE) {
        if (open_error == ERROR_SHARING_VIOLATION ||
            open_error == ERROR_LOCK_VIOLATION) {
            return std::unexpected(
                "profile is already in use by another execution");
        }
        const auto error =
            std::error_code{static_cast<int>(open_error),
                            std::system_category()};
        return std::unexpected("could not lock profile: " + error.message());
    }
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    const BOOL queried = GetFileInformationByHandleEx(
        handle, FileAttributeTagInfo, &attributes, sizeof(attributes));
    if (!queried ||
        (attributes.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT |
                                      FILE_ATTRIBUTE_DIRECTORY |
                                      FILE_ATTRIBUTE_DEVICE)) != 0) {
        const auto code = queried ? ERROR_INVALID_DATA : GetLastError();
        CloseHandle(handle);
        return std::unexpected(
            "profile lock is not a regular file (native_code=" +
            std::to_string(code) + ")");
    }
    auto secured = private_storage::protect_directory(parent_path);
    if (secured) {
        secured = private_storage::protect_file(lock_path);
    }
    if (!secured) {
        CloseHandle(handle);
        return std::unexpected(secured.error());
    }
    return reinterpret_cast<std::intptr_t>(handle);
#else
    int flags = O_RDONLY | O_CREAT;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    struct stat path_status {};
    if (::lstat(lock_path.c_str(), &path_status) == 0) {
        if (!S_ISREG(path_status.st_mode)) {
            return std::unexpected("profile lock is not a regular file");
        }
    } else if (errno != ENOENT) {
        return std::unexpected(
            "could not inspect profile lock path: " +
            std::error_code{errno, std::generic_category()}.message());
    }
    const int handle = ::open(lock_path.c_str(), flags, 0600);
    if (handle < 0) {
        return std::unexpected(
            "could not open profile lock: " +
            std::error_code{errno, std::generic_category()}.message());
    }
    struct stat lock_status {};
    if (::fstat(handle, &lock_status) != 0) {
        const auto code = errno;
        static_cast<void>(::close(handle));
        return std::unexpected(
            "could not inspect profile lock: " +
            std::error_code{code, std::generic_category()}.message());
    }
    if (!S_ISREG(lock_status.st_mode)) {
        static_cast<void>(::close(handle));
        return std::unexpected("profile lock is not a regular file");
    }
    if (::lstat(lock_path.c_str(), &path_status) != 0 ||
        !S_ISREG(path_status.st_mode) ||
        path_status.st_dev != lock_status.st_dev ||
        path_status.st_ino != lock_status.st_ino) {
        static_cast<void>(::close(handle));
        return std::unexpected("profile lock path changed while opening");
    }
    if (::flock(handle, LOCK_EX | LOCK_NB) != 0) {
        const auto code = errno;
        static_cast<void>(::close(handle));
        if (code == EWOULDBLOCK || code == EAGAIN) {
            return std::unexpected(
                "profile is already in use by another execution");
        }
        return std::unexpected(
            "could not lock profile: " +
            std::error_code{code, std::generic_category()}.message());
    }
    auto secured = private_storage::protect_directory(parent_path);
    if (secured) {
        secured = private_storage::protect_file(lock_path);
    }
    if (!secured) {
        static_cast<void>(::close(handle));
        return std::unexpected(secured.error());
    }
    return handle;
#endif
}

} // namespace kasumi::platform
