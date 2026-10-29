#include "platform/durability.hpp"

#include "platform/path.hpp"
#include "platform/perf_trace.hpp"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <limits>
#include <system_error>
#include <vector>

#if defined(__linux__)
#include <linux/fs.h>
#include <sys/syscall.h>
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

namespace kasumi::platform::durability {

namespace {

[[maybe_unused]] std::string native_error(std::string_view operation,
                                          unsigned long code) {
    return std::string{operation} + " (native_code=" + std::to_string(code) +
           ")";
}

bool path_not_found(const std::error_code& error) noexcept {
    return error == std::errc::no_such_file_or_directory;
}

std::expected<void, std::string>
validate_parent(const std::filesystem::path& path, std::string_view operation) {
    const auto parent = path.parent_path();
    if (parent.empty()) {
        return std::unexpected(std::string{operation} +
                               ": empty parent directory for '" +
                               platform::path::to_utf8(path) + "'");
    }

    std::error_code error;
    const auto status = std::filesystem::symlink_status(parent, error);
    if (error) {
        return std::unexpected(
            std::string{operation} +
            ": could not query parent directory: " + error.message());
    }
    if (std::filesystem::is_symlink(status) ||
        !std::filesystem::is_directory(status)) {
        return std::unexpected(std::string{operation} +
                               ": invalid parent directory for '" +
                               platform::path::to_utf8(path) + "'");
    }
    return {};
}

std::expected<void, std::string>
validate_regular_file(const std::filesystem::path& path,
                      std::string_view operation) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error) {
        return std::unexpected(std::string{operation} + ": could not query '" +
                               platform::path::to_utf8(path) +
                               "': " + error.message());
    }
    if (std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        return std::unexpected(std::string{operation} +
                               ": regular file expected at '" +
                               platform::path::to_utf8(path) + "'");
    }
    return {};
}

std::expected<void, std::string>
validate_replace_paths(const std::filesystem::path& source,
                       const std::filesystem::path& target) {
    if (source.empty() || target.empty()) {
        return std::unexpected(
            "replace_atomically: source and target cannot be empty");
    }

    auto source_file = validate_regular_file(source, "replace_atomically");
    if (!source_file) {
        return source_file;
    }

    auto source_parent = validate_parent(source, "replace_atomically");
    if (!source_parent) {
        return source_parent;
    }
    auto target_parent = validate_parent(target, "replace_atomically");
    if (!target_parent) {
        return target_parent;
    }

    if (source.parent_path().lexically_normal() !=
        target.parent_path().lexically_normal()) {
        return std::unexpected(
            "replace_atomically: source and target must share "
            "the parent directory");
    }

    std::error_code error;
    const auto target_status = std::filesystem::symlink_status(target, error);
    std::filesystem::file_status effective_target_status = target_status;
    if (path_not_found(error)) {
        error.clear();
        effective_target_status =
            std::filesystem::file_status{std::filesystem::file_type::not_found};
    } else if (error) {
        return std::unexpected("replace_atomically: could not query target: " +
                               error.message());
    }
    if (std::filesystem::is_symlink(effective_target_status) ||
        std::filesystem::is_directory(effective_target_status)) {
        return std::unexpected(
            "replace_atomically: target cannot be symlink or directory");
    }
    if (!std::filesystem::is_regular_file(effective_target_status) &&
        effective_target_status.type() !=
            std::filesystem::file_type::not_found) {
        return std::unexpected(
            "replace_atomically: target is not a regular file");
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
    if (MoveFileExW(source.wstring().c_str(),
                    target.wstring().c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
        const auto error = GetLastError();
#if defined(FILE_RENAME_FLAG_POSIX_SEMANTICS)
        if (error == ERROR_ACCESS_DENIED) {
            // MoveFileEx may reject an open target despite delete sharing.
            // A single POSIX rename keeps those readers on the old snapshot.
            std::error_code path_error;
            const auto target_name =
                std::filesystem::absolute(target, path_error).wstring();
            if (path_error) {
                return std::unexpected("replace_atomically: " + path_error.message());
            }
            const auto name_bytes = target_name.size() * sizeof(wchar_t);
            if (name_bytes > std::numeric_limits<DWORD>::max() -
                                 sizeof(FILE_RENAME_INFO)) {
                return std::unexpected("replace_atomically: target path is too long");
            }
            std::vector<std::byte> buffer(sizeof(FILE_RENAME_INFO) + name_bytes);
            auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(buffer.data());
            rename->Flags = FILE_RENAME_FLAG_REPLACE_IF_EXISTS |
                            FILE_RENAME_FLAG_POSIX_SEMANTICS;
            rename->RootDirectory = nullptr;
            rename->FileNameLength = static_cast<DWORD>(name_bytes);
            std::memcpy(rename->FileName, target_name.data(), name_bytes);
            const auto file = CreateFileW(
                source.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr);
            if (file == INVALID_HANDLE_VALUE) {
                return std::unexpected(native_error(
                    "replace_atomically: open source failed", GetLastError()));
            }
            FILE_ATTRIBUTE_TAG_INFO attributes{};
            if (!GetFileInformationByHandleEx(file, FileAttributeTagInfo,
                                              &attributes, sizeof(attributes)) ||
                (attributes.FileAttributes &
                 (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY |
                  FILE_ATTRIBUTE_DEVICE)) != 0) {
                CloseHandle(file);
                return std::unexpected("replace_atomically: source is not a regular file");
            }
            const bool flushed = FlushFileBuffers(file) != 0;
            const bool renamed = flushed && SetFileInformationByHandle(
                file, FileRenameInfoEx, rename, static_cast<DWORD>(buffer.size()));
            const auto rename_error = renamed ? ERROR_SUCCESS : GetLastError();
            CloseHandle(file);
            if (!renamed) {
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
    if (source.empty() || target.empty() || source == target ||
        source.parent_path().lexically_normal() !=
            target.parent_path().lexically_normal()) {
        return std::unexpected(
            std::make_error_code(std::errc::invalid_argument));
    }
    std::error_code error;
    const auto source_status = std::filesystem::symlink_status(source, error);
    if (error)
        return std::unexpected(error);
    if (std::filesystem::is_symlink(source_status))
        return std::unexpected(
            std::make_error_code(std::errc::too_many_symbolic_link_levels));
    if (!std::filesystem::is_regular_file(source_status))
        return std::unexpected(
            std::make_error_code(std::errc::invalid_argument));
    const auto parent_status =
        std::filesystem::symlink_status(source.parent_path(), error);
    if (error)
        return std::unexpected(error);
    if (std::filesystem::is_symlink(parent_status))
        return std::unexpected(
            std::make_error_code(std::errc::too_many_symbolic_link_levels));
    if (!std::filesystem::is_directory(parent_status))
        return std::unexpected(
            std::make_error_code(std::errc::invalid_argument));
#if defined(_WIN32)
    const auto attributes = GetFileAttributesW(source.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES)
        return std::unexpected(std::error_code(static_cast<int>(GetLastError()),
                                               std::system_category()));
    if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
        return std::unexpected(
            std::make_error_code(std::errc::too_many_symbolic_link_levels));
    if (!MoveFileExW(source.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH))
        return std::unexpected(std::error_code(static_cast<int>(GetLastError()),
                                               std::system_category()));
#elif defined(__linux__) && defined(SYS_renameat2)
    if (::syscall(SYS_renameat2,
                  AT_FDCWD,
                  source.c_str(),
                  AT_FDCWD,
                  target.c_str(),
                  RENAME_NOREPLACE) != 0)
        return std::unexpected(std::error_code(errno, std::generic_category()));
#else
    return std::unexpected(
        std::make_error_code(std::errc::operation_not_supported));
#endif
    return {};
}

std::expected<void, std::string>
retire_directory(const std::filesystem::path& source,
                 const std::filesystem::path& target) {
    if (source.empty() || target.empty() ||
        source.parent_path().lexically_normal() !=
            target.parent_path().lexically_normal())
        return std::unexpected("retire_directory: physical siblings required");
    auto parent = validate_parent(source, "retire_directory");
    if (!parent)
        return parent;
    auto directory = validate_parent(source / ".", "retire_directory");
    if (!directory)
        return directory;
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
    if (path.empty()) {
        return std::unexpected("sync_file: path cannot be empty");
    }
    auto parent_validation = validate_parent(path, "sync_file");
    if (!parent_validation) {
        return parent_validation;
    }
    auto validation = validate_regular_file(path, "sync_file");
    if (!validation) {
        return validation;
    }

#if defined(_WIN32)
    HANDLE file =
        CreateFileW(path.wstring().c_str(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return std::unexpected(
            native_error("sync_file: CreateFileW failed", GetLastError()));
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
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int file = ::open(path.c_str(), flags);
    if (file < 0) {
        return std::unexpected("sync_file: open failed: " +
                               std::string{std::strerror(errno)});
    }

    int sync_result = 0;
    do {
        sync_result = ::fsync(file);
    } while (sync_result != 0 && errno == EINTR);
    const bool synced = sync_result == 0;
    const auto sync_error = synced ? 0 : errno;
    const bool closed = ::close(file) == 0;
    const auto close_error = closed ? 0 : errno;
    if (!synced) {
        return std::unexpected("sync_file: fsync failed: " +
                               std::string{std::strerror(sync_error)});
    }
    if (!closed) {
        return std::unexpected("sync_file: close failed: " +
                               std::string{std::strerror(close_error)});
    }
#endif
    platform::perf_trace::count("platform durable file sync completions");
    return {};
}

std::expected<void, std::string>
sync_parent_directory(const std::filesystem::path& path) {
    if (path.empty()) {
        return std::unexpected("sync_parent_directory: path cannot be empty");
    }
    auto validation = validate_parent(path, "sync_parent_directory");
    if (!validation) {
        return validation;
    }

#if defined(_WIN32)
    return {};
#else
    int flags = O_RDONLY;
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const auto parent = path.parent_path();
    const int directory = ::open(parent.c_str(), flags);
    if (directory < 0) {
        return std::unexpected("sync_parent_directory: open failed: " +
                               std::string{std::strerror(errno)});
    }

    int sync_result = 0;
    do {
        sync_result = ::fsync(directory);
    } while (sync_result != 0 && errno == EINTR);
    const bool synced = sync_result == 0;
    const auto sync_error = synced ? 0 : errno;
    const bool closed = ::close(directory) == 0;
    const auto close_error = closed ? 0 : errno;
    if (!synced) {
        return std::unexpected("sync_parent_directory: fsync failed: " +
                               std::string{std::strerror(sync_error)});
    }
    if (!closed) {
        return std::unexpected("sync_parent_directory: close failed: " +
                               std::string{std::strerror(close_error)});
    }
    platform::perf_trace::count("platform durable directory sync completions");
    return {};
#endif
}

} // namespace kasumi::platform::durability
