#include "platform/metadata.hpp"

#include "platform/path.hpp"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <limits>
#include <system_error>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace kasumi::platform::metadata {
namespace {

std::expected<std::filesystem::file_status, std::string>
read_status(const std::filesystem::path& path) {
    if (path.empty()) {
        return std::unexpected("timestamp path is empty");
    }
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error) {
        return std::unexpected("failed to inspect timestamp path: " +
                               error.message());
    }
    if (std::filesystem::is_symlink(status)) {
        return std::unexpected("timestamp path is a symbolic link");
    }
    if (!std::filesystem::is_regular_file(status) &&
        !std::filesystem::is_directory(status)) {
        return std::unexpected(
            "timestamp path is neither a file nor a directory");
    }
    return status;
}

#if defined(_WIN32)
std::expected<std::uint64_t, std::string>
to_windows_ticks(std::filesystem::file_time_type value) {
#if defined(_MSC_VER)
    using file_ticks =
        std::chrono::duration<std::int64_t, std::ratio<1, 10000000>>;
    const auto ticks =
        std::chrono::duration_cast<file_ticks>(value.time_since_epoch())
            .count();
    if (ticks <= 0) {
        return std::unexpected("timestamp out of valid Windows FILETIME range");
    }
    return static_cast<std::uint64_t>(ticks);
#else
    using file_ticks =
        std::chrono::duration<std::int64_t, std::ratio<1, 10000000>>;
    constexpr std::int64_t unix_to_windows_epoch_ticks = 116444736000000000LL;
    const auto sys_time =
        std::chrono::clock_cast<std::chrono::system_clock>(value);
    const auto sys_ticks =
        std::chrono::duration_cast<file_ticks>(sys_time.time_since_epoch())
            .count();
    const auto ticks = sys_ticks + unix_to_windows_epoch_ticks;
    if (ticks <= 0) {
        return std::unexpected("timestamp out of valid Windows FILETIME range");
    }
    return static_cast<std::uint64_t>(ticks);
#endif
}

FILETIME to_file_time(std::uint64_t ticks) {
    FILETIME result{};
    result.dwLowDateTime = static_cast<DWORD>(ticks);
    result.dwHighDateTime =
        static_cast<DWORD>(ticks >> std::numeric_limits<DWORD>::digits);
    return result;
}

std::expected<void, std::string>
set_windows_time(const std::filesystem::path& path,
                 std::filesystem::file_time_type value) {
    auto ticks = to_windows_ticks(value);
    if (!ticks) {
        return std::unexpected(ticks.error());
    }
    const auto file_time = to_file_time(*ticks);
    const auto handle =
        CreateFileW(path.c_str(),
                    FILE_WRITE_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return std::unexpected(
            "CreateFileW failed: " +
            std::system_category().message(static_cast<int>(GetLastError())));
    }
    const auto close = [&] {
        CloseHandle(handle);
    };
    if (!SetFileTime(handle, nullptr, nullptr, &file_time)) {
        const auto message =
            "SetFileTime failed: " +
            std::system_category().message(static_cast<int>(GetLastError()));
        close();
        return std::unexpected(message);
    }
    close();
    return {};
}

std::expected<std::uint64_t, std::string>
read_windows_ticks(const std::filesystem::path& path) {
    const auto handle =
        CreateFileW(path.c_str(),
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return std::unexpected(
            "CreateFileW read failed: " +
            std::system_category().message(static_cast<int>(GetLastError())));
    }
    FILETIME file_time{};
    if (!GetFileTime(handle, nullptr, nullptr, &file_time)) {
        const auto message =
            "GetFileTime failed: " +
            std::system_category().message(static_cast<int>(GetLastError()));
        CloseHandle(handle);
        return std::unexpected(message);
    }
    CloseHandle(handle);
    return (static_cast<std::uint64_t>(file_time.dwHighDateTime) << 32) |
           file_time.dwLowDateTime;
}
#endif

#if defined(_WIN32)
std::expected<bool, std::string>
equivalent_file_time(std::filesystem::file_time_type requested,
                     std::uint64_t actual_ticks) {
    auto requested_ticks = to_windows_ticks(requested);
    if (!requested_ticks) {
        return std::unexpected(requested_ticks.error());
    }
    return *requested_ticks == actual_ticks;
}
#else
std::expected<bool, std::string>
equivalent_file_time(std::filesystem::file_time_type requested,
                     std::filesystem::file_time_type actual) {
    // The API writes and reads the same representation, allowing exact
    // comparison.
    return requested == actual;
}
#endif

} // namespace

std::expected<void, std::string>
set_last_write_time(const std::filesystem::path& path,
                    std::filesystem::file_time_type value) {
    auto status = read_status(path);
    if (!status) {
        return std::unexpected(status.error());
    }

#if defined(_WIN32)
    {
        auto written = set_windows_time(path, value);
        if (!written) {
            return std::unexpected(written.error());
        }
    }
#else
    {
        std::error_code error;
        std::filesystem::last_write_time(path, value, error);
        if (error) {
            return std::unexpected("failed to set timestamp: " +
                                   error.message());
        }
    }
#endif

#if defined(_WIN32)
    const auto actual = read_windows_ticks(path);
    if (!actual) {
        return std::unexpected("failed to confirm timestamp: " +
                               actual.error());
    }
#else
    std::error_code error;
    const auto actual = std::filesystem::last_write_time(path, error);
    if (error) {
        return std::unexpected("failed to confirm timestamp: " +
                               error.message());
    }
#endif
#if defined(_WIN32)
    const auto equivalent = equivalent_file_time(value, *actual);
#else
    const auto equivalent = equivalent_file_time(value, actual);
#endif
    if (!equivalent) {
        return std::unexpected("failed to verify timestamp for " +
                               platform::path::to_utf8(path) + ": " +
                               equivalent.error());
    }
    if (!*equivalent) {
        return std::unexpected("timestamp verification failed for " +
                               platform::path::to_utf8(path));
    }
    return {};
}

} // namespace kasumi::platform::metadata
