#include "platform/metadata.hpp"

#include "platform/path.hpp"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <limits>
#include <optional>
#include <ratio>
#include <system_error>
#include <type_traits>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace kasumi::platform::metadata {
namespace {

template <typename Duration>
std::optional<std::int64_t>
duration_to_nanoseconds(Duration duration) noexcept {
    using Rep = typename Duration::rep;
    using Factor = std::ratio_divide<typename Duration::period, std::nano>;
    static_assert(std::is_integral_v<Rep> && std::is_signed_v<Rep>);
    static_assert(Factor::num > 0 && Factor::den > 0);

    const auto value = static_cast<std::intmax_t>(duration.count());
    const bool negative = value < 0;
    const auto magnitude = negative
                               ? static_cast<std::uintmax_t>(-(value + 1)) + 1U
                               : static_cast<std::uintmax_t>(value);
    const auto numerator = static_cast<std::uintmax_t>(Factor::num);
    const auto denominator = static_cast<std::uintmax_t>(Factor::den);
    const auto whole = magnitude / denominator;
    const auto remainder = magnitude % denominator;
    if (whole > std::numeric_limits<std::uintmax_t>::max() / numerator ||
        remainder > std::numeric_limits<std::uintmax_t>::max() / numerator) {
        return std::nullopt;
    }
    const auto whole_nanos = whole * numerator;
    const auto fractional_nanos = (remainder * numerator) / denominator;
    if (whole_nanos >
        std::numeric_limits<std::uintmax_t>::max() - fractional_nanos) {
        return std::nullopt;
    }
    const auto nanos = whole_nanos + fractional_nanos;
    constexpr auto positive_limit =
        static_cast<std::uintmax_t>(std::numeric_limits<std::int64_t>::max());
    constexpr auto negative_limit = positive_limit + 1U;
    if ((!negative && nanos > positive_limit) ||
        (negative && nanos > negative_limit)) {
        return std::nullopt;
    }
    if (negative) {
        if (nanos == negative_limit) {
            return std::numeric_limits<std::int64_t>::lowest();
        }
        return -static_cast<std::int64_t>(nanos);
    }
    return static_cast<std::int64_t>(nanos);
}

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

std::optional<std::int64_t>
unix_nanoseconds(std::filesystem::file_time_type value) noexcept {
    if (value == std::filesystem::file_time_type{}) {
        return std::int64_t{0};
    }

    using Duration = std::filesystem::file_time_type::duration;
    const auto origin = std::chrono::clock_cast<std::chrono::file_clock>(
                            std::chrono::system_clock::time_point{})
                            .time_since_epoch();
    const auto current_count = value.time_since_epoch().count();
    const auto origin_count = origin.count();
    if ((origin_count > 0 &&
         current_count <
             std::numeric_limits<typename Duration::rep>::lowest() +
                 origin_count) ||
        (origin_count < 0 &&
         current_count >
             std::numeric_limits<typename Duration::rep>::max() +
                 origin_count)) {
        return std::nullopt;
    }
    return duration_to_nanoseconds(Duration{current_count - origin_count});
}

std::optional<std::filesystem::file_time_type>
file_time_from_unix_nanoseconds(std::int64_t value) noexcept {
    if (value == 0) {
        return std::filesystem::file_time_type{};
    }

    using Duration = std::filesystem::file_time_type::duration;
    using Rep = Duration::rep;
    static_assert(std::is_integral_v<Rep> && std::is_signed_v<Rep>);
    static_assert(std::ratio_greater_equal_v<typename Duration::period,
                                             std::nano>);

    const auto delta = std::chrono::duration_cast<Duration>(
        std::chrono::nanoseconds{value});
    const auto origin = std::chrono::clock_cast<std::chrono::file_clock>(
                            std::chrono::system_clock::time_point{})
                            .time_since_epoch();
    if ((delta.count() > 0 &&
         origin.count() > std::numeric_limits<Rep>::max() - delta.count()) ||
        (delta.count() < 0 &&
         origin.count() <
             std::numeric_limits<Rep>::lowest() - delta.count())) {
        return std::nullopt;
    }
    return std::filesystem::file_time_type{
        Duration{origin.count() + delta.count()}};
}

bool filesystem_equivalent(std::int64_t left_ns,
                           std::int64_t right_ns) noexcept {
    if (left_ns == right_ns) {
        return true;
    }
    const auto left = file_time_from_unix_nanoseconds(left_ns);
    const auto right = file_time_from_unix_nanoseconds(right_ns);
    return left && right && *left == *right;
}

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
