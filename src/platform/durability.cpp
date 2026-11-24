#include "platform/durability.hpp"

#include "detail.hpp"
#include "platform/path.hpp"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <limits>
#include <memory>
#include <system_error>
#include <vector>

#if defined(__linux__)
#include <linux/fs.h>
#include <sys/syscall.h>
#elif defined(__APPLE__)
#include <stdio.h>
#endif

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace kasumi::platform::detail {

#if defined(_WIN32)
DWORD rename_windows_handle(HANDLE file,
                            const std::filesystem::path& target,
                            FILE_INFO_BY_HANDLE_CLASS info_class,
                            DWORD flags) {
    std::error_code path_error;
    const auto resolved = std::filesystem::absolute(target, path_error);
    if (path_error) {
        return path_error.value() != 0 ? static_cast<DWORD>(path_error.value())
                                       : ERROR_INVALID_NAME;
    }
    const auto& name = resolved.native();
    if (name.size() >
        (std::numeric_limits<DWORD>::max() - sizeof(FILE_RENAME_INFO)) /
            sizeof(wchar_t)) {
        return ERROR_FILENAME_EXCED_RANGE;
    }
    const auto name_bytes = name.size() * sizeof(wchar_t);
    const auto size = sizeof(FILE_RENAME_INFO) + name_bytes;
    std::vector<FILE_RENAME_INFO> buffer((size - 1) / sizeof(FILE_RENAME_INFO) +
                                         1);
    auto& rename = buffer.front();
    if (info_class == FileRenameInfo) {
        rename.ReplaceIfExists = flags != 0;
#if defined(FILE_RENAME_FLAG_POSIX_SEMANTICS)
    } else {
        rename.Flags = flags;
#endif
    }
    rename.FileNameLength = static_cast<DWORD>(name_bytes);
    std::memcpy(reinterpret_cast<std::byte*>(buffer.data()) +
                    offsetof(FILE_RENAME_INFO, FileName),
                name.data(),
                name_bytes);
    return retry_windows_file_operation([&] {
        return SetFileInformationByHandle(
                   file, info_class, buffer.data(), static_cast<DWORD>(size))
                   ? ERROR_SUCCESS
                   : GetLastError();
    });
}
#endif

std::error_code rename_no_replace(const std::filesystem::path& source,
                                  const std::filesystem::path& destination) {
#if defined(_WIN32)
    const DWORD error = retry_windows_file_operation([&] {
        return MoveFileExW(
                   source.c_str(), destination.c_str(), MOVEFILE_WRITE_THROUGH)
                   ? ERROR_SUCCESS
                   : GetLastError();
    });
    if (error == ERROR_SUCCESS) {
        return {};
    }
    return {static_cast<int>(error), std::system_category()};
#elif defined(__linux__) && defined(SYS_renameat2)
    if (::syscall(SYS_renameat2,
                  AT_FDCWD,
                  source.c_str(),
                  AT_FDCWD,
                  destination.c_str(),
                  RENAME_NOREPLACE) == 0) {
        return {};
    }
    return {errno, std::generic_category()};
#elif defined(__APPLE__)
    if (::renamex_np(source.c_str(), destination.c_str(), RENAME_EXCL) == 0) {
        return {};
    }
    return {errno, std::generic_category()};
#else
    static_cast<void>(source);
    static_cast<void>(destination);
    return std::make_error_code(std::errc::operation_not_supported);
#endif
}

} // namespace kasumi::platform::detail

namespace kasumi::platform::durability {

namespace {

#if !defined(_WIN32)
std::expected<void, std::string>
sync_posix_descriptor(int fd, std::string_view operation) {
    int sync_result = 0;
    do {
        sync_result = ::fsync(fd);
    } while (sync_result != 0 && errno == EINTR);
    const auto sync_error = sync_result == 0 ? 0 : errno;
    const auto close_error = ::close(fd) == 0 ? 0 : errno;
    if (sync_error != 0) {
        return std::unexpected(std::string{operation} +
                               ": fsync failed: " + std::strerror(sync_error));
    }
    if (close_error != 0) {
        return std::unexpected(std::string{operation} +
                               ": close failed: " + std::strerror(close_error));
    }
    return {};
}
std::expected<void, std::string> sync_posix_path(
    const std::filesystem::path& path, int flags, std::string_view operation) {
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int descriptor = ::open(path.c_str(), flags);
    if (descriptor < 0) {
        return std::unexpected(std::string{operation} +
                               ": open failed: " + std::strerror(errno));
    }
    return sync_posix_descriptor(descriptor, operation);
}

#endif

[[maybe_unused]] std::string native_error(std::string_view operation,
                                          unsigned long code) {
    return std::string{operation} + " (native_code=" + std::to_string(code) +
           ")";
}

#if defined(_WIN32)
std::expected<void, std::string>
sync_read_only_file(const std::filesystem::path& path) {
    // Pin the entry while clearing and restoring the attribute by handle.
    constexpr DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE;
    constexpr DWORD flags = FILE_FLAG_OPEN_REPARSE_POINT;
    const auto file = CreateFileW(path.c_str(),
                                  FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
                                  share,
                                  nullptr,
                                  OPEN_EXISTING,
                                  flags,
                                  nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return std::unexpected(
            native_error("sync_file: open attributes failed", GetLastError()));
    }
    const std::unique_ptr<void, decltype(&CloseHandle)> file_guard{file,
                                                                   CloseHandle};
    FILE_ATTRIBUTE_TAG_INFO info{};
    if (!GetFileInformationByHandleEx(
            file, FileAttributeTagInfo, &info, sizeof(info))) {
        return std::unexpected(
            native_error("sync_file: query attributes failed", GetLastError()));
    }
    if ((info.FileAttributes & FILE_ATTRIBUTE_READONLY) == 0 ||
        (info.FileAttributes &
         (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY |
          FILE_ATTRIBUTE_DEVICE)) != 0) {
        return std::unexpected(
            native_error("sync_file: CreateFileW failed", ERROR_ACCESS_DENIED));
    }
    FILE_BASIC_INFO attributes{};
    attributes.FileAttributes =
        info.FileAttributes & ~DWORD{FILE_ATTRIBUTE_READONLY};
    if (attributes.FileAttributes == 0) {
        attributes.FileAttributes = FILE_ATTRIBUTE_NORMAL;
    }
    if (!SetFileInformationByHandle(
            file, FileBasicInfo, &attributes, sizeof(attributes))) {
        return std::unexpected(
            native_error("sync_file: clear read-only failed", GetLastError()));
    }

    HANDLE writable = INVALID_HANDLE_VALUE;
    const auto open_error = detail::retry_windows_file_operation([&] {
        writable = ReOpenFile(file, GENERIC_WRITE, share, flags);
        return writable == INVALID_HANDLE_VALUE ? GetLastError()
                                                : ERROR_SUCCESS;
    });
    const std::unique_ptr<void, decltype(&CloseHandle)> writable_guard{
        writable == INVALID_HANDLE_VALUE ? nullptr : writable, CloseHandle};
    attributes.FileAttributes = info.FileAttributes;
    if (!SetFileInformationByHandle(
            file, FileBasicInfo, &attributes, sizeof(attributes))) {
        return std::unexpected(native_error(
            "sync_file: restore read-only failed", GetLastError()));
    }
    if (open_error != ERROR_SUCCESS) {
        return std::unexpected(
            native_error("sync_file: reopen failed", open_error));
    }
    if (!FlushFileBuffers(writable)) {
        return std::unexpected(
            native_error("sync_file: FlushFileBuffers failed", GetLastError()));
    }
    return {};
}
#endif

bool path_not_found(const std::error_code& error) noexcept {
    return error == std::errc::no_such_file_or_directory;
}

std::expected<void, std::string>
validate_entry(const std::filesystem::path& path,
               bool expect_directory,
               std::string_view operation,
               std::string_view label) {
    if (path.empty()) {
        return std::unexpected(std::string{operation} + ": empty " +
                               std::string{label});
    }
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error) {
        return std::unexpected(std::string{operation} + ": could not query '" +
                               platform::path::to_utf8(path) +
                               "': " + error.message());
    }
    const bool type_ok = expect_directory
                             ? std::filesystem::is_directory(status)
                             : std::filesystem::is_regular_file(status);
    if (std::filesystem::is_symlink(status) || !type_ok) {
        return std::unexpected(std::string{operation} + ": invalid " +
                               std::string{label} + " '" +
                               platform::path::to_utf8(path) + "'");
    }
#if defined(_WIN32)
    const DWORD attributes = GetFileAttributesW(path.wstring().c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return std::unexpected(
            native_error(std::string{operation} + ": GetFileAttributesW failed",
                         GetLastError()));
    }
    if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return std::unexpected(std::string{operation} + ": invalid " +
                               std::string{label} + " '" +
                               platform::path::to_utf8(path) + "'");
    }
#endif
    return {};
}

bool same_parent_dir(const std::filesystem::path& source,
                     const std::filesystem::path& target) {
    return !source.empty() && !target.empty() &&
           source.parent_path().lexically_normal() ==
               target.parent_path().lexically_normal();
}

std::expected<void, std::string>
validate_replace_paths(const std::filesystem::path& source,
                       const std::filesystem::path& target) {
    if (!same_parent_dir(source, target)) {
        return std::unexpected(
            "replace_atomically: source and target must share a valid parent");
    }
    for (const auto& [path, dir, label] :
         {std::tuple{&source, false, "regular file"},
          std::tuple{&source, true, "parent directory"},
          std::tuple{&target, true, "parent directory"}}) {
        const auto check_path = dir ? path->parent_path() : *path;
        if (auto res =
                validate_entry(check_path, dir, "replace_atomically", label);
            !res) {
            return res;
        }
    }
    std::error_code error;
    const auto target_status = std::filesystem::symlink_status(target, error);
    if (path_not_found(error) ||
        (!error &&
         target_status.type() == std::filesystem::file_type::not_found)) {
        return {};
    }
    if (error) {
        return std::unexpected("replace_atomically: could not query target: " +
                               error.message());
    }
    if (std::filesystem::is_symlink(target_status) ||
        !std::filesystem::is_regular_file(target_status)) {
        return std::unexpected(
            "replace_atomically: target cannot be symlink, directory, or "
            "non-regular file");
    }
    return {};
}

} // namespace

std::expected<void, std::string>
replace_atomically(const std::filesystem::path& source,
                   const std::filesystem::path& target) {
    auto validation = validate_replace_paths(source, target);
    if (!validation) {
        return validation;
    }

#if defined(_WIN32)
    const auto error = detail::retry_windows_file_operation([&] {
        return MoveFileExW(source.c_str(),
                           target.c_str(),
                           MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
                   ? ERROR_SUCCESS
                   : GetLastError();
    });
    if (error != ERROR_SUCCESS) {
#if defined(FILE_RENAME_FLAG_POSIX_SEMANTICS)
        if (error == ERROR_ACCESS_DENIED) {
            // MoveFileEx may reject an open target despite delete sharing.
            // A single POSIX rename keeps those readers on the old snapshot.
            HANDLE file = INVALID_HANDLE_VALUE;
            const auto open_error = detail::retry_windows_file_operation([&] {
                file = CreateFileW(
                    source.c_str(),
                    GENERIC_READ | GENERIC_WRITE | DELETE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
                    nullptr);
                return file == INVALID_HANDLE_VALUE ? GetLastError()
                                                    : ERROR_SUCCESS;
            });
            if (open_error != ERROR_SUCCESS) {
                return std::unexpected(native_error(
                    "replace_atomically: open source failed", open_error));
            }
            const std::unique_ptr<void, decltype(&CloseHandle)> guard{
                file, CloseHandle};
            FILE_ATTRIBUTE_TAG_INFO attributes{};
            if (!GetFileInformationByHandleEx(file,
                                              FileAttributeTagInfo,
                                              &attributes,
                                              sizeof(attributes)) ||
                (attributes.FileAttributes &
                 (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY |
                  FILE_ATTRIBUTE_DEVICE)) != 0) {
                return std::unexpected(
                    "replace_atomically: source is not a regular file");
            }
            const auto rename_error =
                FlushFileBuffers(file)
                    ? detail::rename_windows_handle(
                          file,
                          target,
                          FileRenameInfoEx,
                          FILE_RENAME_FLAG_REPLACE_IF_EXISTS |
                              FILE_RENAME_FLAG_POSIX_SEMANTICS)
                    : GetLastError();
            if (rename_error != ERROR_SUCCESS) {
                return std::unexpected(native_error(
                    "replace_atomically: POSIX rename failed", rename_error));
            }
            return {};
        }
#endif
        return std::unexpected(
            native_error("replace_atomically failed", error));
    }
#else
    std::error_code error;
    std::filesystem::rename(source, target, error);
    if (error) {
        return std::unexpected("replace_atomically failed (native_code=" +
                               std::to_string(error.value()) +
                               "): " + error.message());
    }
#endif
    return {};
}

std::expected<void, std::error_code>
install_without_overwrite(const std::filesystem::path& source,
                          const std::filesystem::path& target) {
    if (source == target || !same_parent_dir(source, target)) {
        return std::unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }
    const auto inspect = [](const std::filesystem::path& p,
                            bool dir) -> std::expected<void, std::error_code> {
        std::error_code ec;
        const auto s = std::filesystem::symlink_status(p, ec);
        if (ec)
            return std::unexpected(ec);
        if (std::filesystem::is_symlink(s))
            return std::unexpected(
                std::make_error_code(std::errc::too_many_symbolic_link_levels));
        if (!(dir ? std::filesystem::is_directory(s)
                  : std::filesystem::is_regular_file(s)))
            return std::unexpected(
                std::make_error_code(std::errc::invalid_argument));
        return {};
    };
    if (auto ok = inspect(source, false); !ok)
        return ok;
    if (auto ok = inspect(source.parent_path(), true); !ok)
        return ok;
#if defined(_WIN32)
    const auto attributes = GetFileAttributesW(source.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES)
        return std::unexpected(std::error_code(static_cast<int>(GetLastError()),
                                               std::system_category()));
    if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        return std::unexpected(
            std::make_error_code(std::errc::too_many_symbolic_link_levels));
#endif
    if (const auto ec = detail::rename_no_replace(source, target); ec)
        return std::unexpected(ec);
    return {};
}

std::expected<void, std::string>
retire_directory(const std::filesystem::path& source,
                 const std::filesystem::path& target) {
    if (!same_parent_dir(source, target))
        return std::unexpected("retire_directory: physical siblings required");
    if (auto ok = validate_entry(
            source.parent_path(), true, "retire_directory", "parent directory");
        !ok)
        return ok;
    if (auto ok = validate_entry(source, true, "retire_directory", "directory");
        !ok)
        return ok;
    std::error_code error;
    auto status = std::filesystem::symlink_status(target, error);
    if ((error && !path_not_found(error)) ||
        (!error && status.type() != std::filesystem::file_type::not_found))
        return std::unexpected("retire_directory: target must be absent");
#if defined(_WIN32)
    if (!MoveFileExW(source.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH))
        return std::unexpected(
            native_error("retire_directory failed", GetLastError()));
#else
    error.clear();
    std::filesystem::rename(source, target, error);
    if (error)
        return std::unexpected("retire_directory failed: " + error.message());
#endif
    return {};
}

std::expected<void, std::string> sync_file(const std::filesystem::path& path) {
    if (auto ok = validate_entry(
            path.parent_path(), true, "sync_file", "parent directory");
        !ok) {
        return ok;
    }
    if (auto ok = validate_entry(path, false, "sync_file", "regular file");
        !ok) {
        return ok;
    }

#if defined(_WIN32)
    HANDLE file = INVALID_HANDLE_VALUE;
    const auto open_error = detail::retry_windows_file_operation(
        [&] {
            file = CreateFileW(
                path.wstring().c_str(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                nullptr);
            return file == INVALID_HANDLE_VALUE ? GetLastError()
                                                : ERROR_SUCCESS;
        },
        false);
    if (open_error != ERROR_SUCCESS) {
        if (open_error == ERROR_ACCESS_DENIED) {
            return sync_read_only_file(path);
        }
        return std::unexpected(
            native_error("sync_file: CreateFileW failed", open_error));
    }

    FILE_ATTRIBUTE_TAG_INFO tag_info{};
    if (!GetFileInformationByHandleEx(
            file, FileAttributeTagInfo, &tag_info, sizeof(tag_info))) {
        const auto attr_error = GetLastError();
        CloseHandle(file);
        return std::unexpected(native_error(
            "sync_file: GetFileInformationByHandleEx failed", attr_error));
    }
    if ((tag_info.FileAttributes &
         (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0) {
        CloseHandle(file);
        return std::unexpected("sync_file: target cannot be a reparse point "
                               "or directory");
    }

    const bool flushed = FlushFileBuffers(file) != 0;
    const auto flush_error = flushed ? 0UL : GetLastError();
    const bool closed = CloseHandle(file) != 0;
    const auto close_error = closed ? 0UL : GetLastError();
    if (!flushed) {
        return std::unexpected(
            native_error("sync_file: FlushFileBuffers failed", flush_error));
    }
    if (!closed) {
        return std::unexpected(
            native_error("sync_file: CloseHandle failed", close_error));
    }
#else
    return sync_posix_path(path, O_RDONLY, "sync_file");
#endif
    return {};
}

std::expected<void, std::string>
sync_parent_directory(const std::filesystem::path& path) {
    if (auto ok = validate_entry(path.parent_path(),
                                 true,
                                 "sync_parent_directory",
                                 "parent directory");
        !ok) {
        return ok;
    }

#if defined(_WIN32)
    return {};
#else
    int flags = O_RDONLY;
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
    return sync_posix_path(path.parent_path(), flags, "sync_parent_directory");
#endif
}

} // namespace kasumi::platform::durability
