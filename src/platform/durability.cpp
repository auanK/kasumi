#include "platform/durability.hpp"

#include "platform/path.hpp"
#include <cerrno>
#include <cstring>
#include <system_error>

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
                               ": diretório pai vazio para '" + platform::path::to_utf8(path) +
                               "'");
    }

    std::error_code error;
    const auto status = std::filesystem::symlink_status(parent, error);
    if (error) {
        return std::unexpected(
            std::string{operation} +
            ": não foi possível consultar o diretório pai: " + error.message());
    }
    if (std::filesystem::is_symlink(status) ||
        !std::filesystem::is_directory(status)) {
        return std::unexpected(std::string{operation} +
                               ": diretório pai inválido para '" +
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
        return std::unexpected(std::string{operation} +
                               ": não foi possível consultar '" +
                               platform::path::to_utf8(path) + "': " + error.message());
    }
    if (std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        return std::unexpected(std::string{operation} +
                               ": arquivo regular esperado em '" +
                               platform::path::to_utf8(path) + "'");
    }
    return {};
}

std::expected<void, std::string>
validate_replace_paths(const std::filesystem::path& source,
                       const std::filesystem::path& target) {
    if (source.empty() || target.empty()) {
        return std::unexpected(
            "replace_atomically: source e target não podem ser vazios");
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
            "replace_atomically: source e target precisam compartilhar "
            "o diretório pai");
    }

    std::error_code error;
    const auto target_status = std::filesystem::symlink_status(target, error);
    std::filesystem::file_status effective_target_status = target_status;
    if (path_not_found(error)) {
        error.clear();
        effective_target_status =
            std::filesystem::file_status{std::filesystem::file_type::not_found};
    } else if (error) {
        return std::unexpected(
            "replace_atomically: não foi possível consultar target: " +
            error.message());
    }
    if (std::filesystem::is_symlink(effective_target_status) ||
        std::filesystem::is_directory(effective_target_status)) {
        return std::unexpected(
            "replace_atomically: target não pode ser symlink ou diretório");
    }
    if (!std::filesystem::is_regular_file(effective_target_status) &&
        effective_target_status.type() !=
            std::filesystem::file_type::not_found) {
        return std::unexpected(
            "replace_atomically: target não é arquivo regular");
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
        return std::unexpected(
            native_error("replace_atomically falhou", error));
    }
#else
    std::error_code error;
    std::filesystem::rename(source, target, error);
    if (error) {
        return std::unexpected("replace_atomically falhou: " + error.message());
    }
#endif
    return {};
}

std::expected<void, std::string> sync_file(const std::filesystem::path& path) {
    if (path.empty()) {
        return std::unexpected("sync_file: path não pode ser vazio");
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
            native_error("sync_file: CreateFileW falhou", GetLastError()));
    }

    const bool flushed = FlushFileBuffers(file) != 0;
    const auto flush_error = flushed ? 0UL : GetLastError();
    const bool closed = CloseHandle(file) != 0;
    const auto close_error = closed ? 0UL : GetLastError();
    if (!flushed) {
        return std::unexpected(
            native_error("sync_file: FlushFileBuffers falhou", flush_error));
    }
    if (!closed) {
        return std::unexpected(
            native_error("sync_file: CloseHandle falhou", close_error));
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
        return std::unexpected("sync_file: open falhou: " +
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
        return std::unexpected("sync_file: fsync falhou: " +
                               std::string{std::strerror(sync_error)});
    }
    if (!closed) {
        return std::unexpected("sync_file: close falhou: " +
                               std::string{std::strerror(close_error)});
    }
#endif
    return {};
}

std::expected<void, std::string>
sync_parent_directory(const std::filesystem::path& path) {
    if (path.empty()) {
        return std::unexpected(
            "sync_parent_directory: path não pode ser vazio");
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
        return std::unexpected("sync_parent_directory: open falhou: " +
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
        return std::unexpected("sync_parent_directory: fsync falhou: " +
                               std::string{std::strerror(sync_error)});
    }
    if (!closed) {
        return std::unexpected("sync_parent_directory: close falhou: " +
                               std::string{std::strerror(close_error)});
    }
    return {};
#endif
}

} // namespace kasumi::platform::durability
