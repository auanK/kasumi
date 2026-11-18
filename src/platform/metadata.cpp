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

template <typename TimePoint> constexpr auto file_clock_to_sys(TimePoint tp) {
#if defined(_LIBCPP_VERSION)
    return std::chrono::file_clock::to_sys(tp);
#else
    return std::chrono::clock_cast<std::chrono::system_clock>(tp);
#endif
}

template <typename TimePoint> constexpr auto file_clock_from_sys(TimePoint tp) {
#if defined(_LIBCPP_VERSION)
    return std::chrono::file_clock::from_sys(tp);
#else
    return std::chrono::clock_cast<std::chrono::file_clock>(tp);
#endif
}

std::optional<std::filesystem::file_time_type>
add_nanoseconds_to_unix_epoch(std::int64_t unix_ns) noexcept {
    using Duration = std::filesystem::file_time_type::duration;
    using Rep = Duration::rep;
    static_assert(std::is_integral_v<Rep> && std::is_signed_v<Rep>);
    static_assert(
        std::ratio_greater_equal_v<typename Duration::period, std::nano>);

    const auto origin =
        file_clock_from_sys(std::chrono::system_clock::time_point{})
            .time_since_epoch();
    using Factor = std::ratio_divide<typename Duration::period, std::nano>;
    static_assert(Factor::num > 0 && Factor::den > 0);
    Rep delta_count = 0;
    if constexpr (Factor::den == 1) {
        const auto q = unix_ns / static_cast<std::int64_t>(Factor::num);
        const auto r = unix_ns % static_cast<std::int64_t>(Factor::num);
        if (r < 0 && q == std::numeric_limits<std::int64_t>::lowest()) {
            return std::nullopt;
        }
        const std::int64_t floored = r < 0 ? (q - 1) : q;
        if (floored > static_cast<std::int64_t>(std::numeric_limits<Rep>::max()) ||
            floored < static_cast<std::int64_t>(std::numeric_limits<Rep>::lowest())) {
            return std::nullopt;
        }
        delta_count = static_cast<Rep>(floored);
    } else {
        delta_count =
            std::chrono::floor<Duration>(std::chrono::nanoseconds{unix_ns})
                .count();
    }
    const Duration delta{delta_count};
    if ((delta.count() > 0 &&
         origin.count() > std::numeric_limits<Rep>::max() - delta.count()) ||
        (delta.count() < 0 &&
         origin.count() < std::numeric_limits<Rep>::lowest() - delta.count())) {
        return std::nullopt;
    }
    return std::filesystem::file_time_type{
        Duration{origin.count() + delta.count()}};
}

} // namespace

#if defined(_WIN32)
namespace detail {

std::expected<std::filesystem::file_time_type, std::string>
from_windows_ticks(std::uint64_t ticks) noexcept {
    if (ticks >
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        return std::unexpected(
            "ticks value exceeds maximum signed 64-bit integer");
    }
#if defined(_MSC_VER)
    using file_ticks =
        std::chrono::duration<std::int64_t, std::ratio<1, 10000000>>;
    return std::filesystem::file_time_type{
        file_ticks{static_cast<std::int64_t>(ticks)}};
#else
    constexpr std::uint64_t unix_to_windows_epoch_ticks = 116444736000000000ULL;
    const auto signed_ticks = static_cast<std::int64_t>(ticks);
    const auto diff_ticks =
        signed_ticks - static_cast<std::int64_t>(unix_to_windows_epoch_ticks);
    constexpr auto max_diff_ticks =
        std::numeric_limits<std::int64_t>::max() / 100LL;
    constexpr auto min_diff_ticks =
        std::numeric_limits<std::int64_t>::min() / 100LL;
    if (diff_ticks > max_diff_ticks || diff_ticks < min_diff_ticks) {
        return std::unexpected(
            "timestamp outside representable nanosecond range");
    }
    const auto result = add_nanoseconds_to_unix_epoch(diff_ticks * 100LL);
    if (!result) {
        return std::unexpected(
            "timestamp outside representable file_time_type range");
    }
    return *result;
#endif
}

std::expected<std::uint64_t, std::string>
to_windows_ticks(std::filesystem::file_time_type value) noexcept {
    using file_ticks =
        std::chrono::duration<std::int64_t, std::ratio<1, 10000000>>;
#if defined(_MSC_VER)
    const auto ticks =
        std::chrono::duration_cast<file_ticks>(value.time_since_epoch())
            .count();
#else
    constexpr std::int64_t unix_to_windows_epoch_ticks = 116444736000000000LL;
    const auto sys_ticks = std::chrono::floor<file_ticks>(
                               file_clock_to_sys(value).time_since_epoch())
                               .count();
    if (sys_ticks > std::numeric_limits<std::int64_t>::max() -
                        unix_to_windows_epoch_ticks ||
        sys_ticks < -unix_to_windows_epoch_ticks) {
        return std::unexpected("timestamp out of valid Windows FILETIME range");
    }
    const auto ticks = sys_ticks + unix_to_windows_epoch_ticks;
#endif
    if (ticks <= 0) {
        return std::unexpected("timestamp out of valid Windows FILETIME range");
    }
    return static_cast<std::uint64_t>(ticks);
}

} // namespace detail
#endif

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
template <typename Fn>
auto with_windows_metadata_handle(const std::filesystem::path& path,
                                  DWORD access,
                                  std::string_view open_error_prefix,
                                  Fn&& fn) -> decltype(fn(HANDLE{})) {
    const auto handle =
        CreateFileW(path.c_str(),
                    access,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return std::unexpected(
            std::string{open_error_prefix} +
            std::system_category().message(static_cast<int>(GetLastError())));
    }
    auto result = fn(handle);
    CloseHandle(handle);
    return result;
}

FILETIME to_file_time(std::uint64_t ticks) {
    FILETIME result{};
    result.dwLowDateTime = static_cast<DWORD>(ticks);
    result.dwHighDateTime =
        static_cast<DWORD>(ticks >> std::numeric_limits<DWORD>::digits);
    return result;
}

std::expected<std::uint64_t, std::string>
set_windows_time(const std::filesystem::path& path,
                 std::filesystem::file_time_type value) {
    auto ticks = detail::to_windows_ticks(value);
    if (!ticks) {
        return std::unexpected(ticks.error());
    }
    const auto file_time = to_file_time(*ticks);
    return with_windows_metadata_handle(
        path,
        FILE_WRITE_ATTRIBUTES,
        "CreateFileW failed: ",
        [&](HANDLE handle) -> std::expected<std::uint64_t, std::string> {
            if (!SetFileTime(handle, nullptr, nullptr, &file_time)) {
                return std::unexpected("SetFileTime failed: " +
                                       std::system_category().message(
                                           static_cast<int>(GetLastError())));
            }
            return *ticks;
        });
}

std::expected<std::uint64_t, std::string>
read_windows_ticks(const std::filesystem::path& path) {
    return with_windows_metadata_handle(
        path,
        FILE_READ_ATTRIBUTES,
        "CreateFileW read failed: ",
        [&](HANDLE handle) -> std::expected<std::uint64_t, std::string> {
            FILETIME file_time{};
            if (!GetFileTime(handle, nullptr, nullptr, &file_time)) {
                return std::unexpected("GetFileTime failed: " +
                                       std::system_category().message(
                                           static_cast<int>(GetLastError())));
            }
            return (static_cast<std::uint64_t>(file_time.dwHighDateTime)
                    << 32) |
                   file_time.dwLowDateTime;
        });
}
#endif

} // namespace

std::optional<std::int64_t>
unix_nanoseconds(std::filesystem::file_time_type value) noexcept {
    if (value == std::filesystem::file_time_type{}) {
        return std::int64_t{0};
    }

    using Duration = std::filesystem::file_time_type::duration;
    const auto origin =
        file_clock_from_sys(std::chrono::system_clock::time_point{})
            .time_since_epoch();
    const auto current_count = value.time_since_epoch().count();
    const auto origin_count = origin.count();
    if ((origin_count > 0 &&
         current_count < std::numeric_limits<typename Duration::rep>::lowest() +
                             origin_count) ||
        (origin_count < 0 &&
         current_count > std::numeric_limits<typename Duration::rep>::max() +
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
    return add_nanoseconds_to_unix_epoch(value);
}

bool filesystem_equivalent(std::int64_t left_ns,
                           std::int64_t right_ns) noexcept {
    if (left_ns == right_ns) {
        return true;
    }
#if defined(_WIN32)
    // Windows NTFS resolution is 100-nanosecond ticks (FILETIME).
    // In MSVC, file_time_type is 100ns; in libstdc++ on Windows it is 1ns.
    // Two timestamps are equivalent on Windows if they map to the same 100ns
    // tick.
    const auto to_ticks = [](std::int64_t ns) noexcept -> std::int64_t {
        const auto q = ns / 100LL;
        const auto r = ns % 100LL;
        return (r < 0) ? (q - 1) : q;
    };
    return to_ticks(left_ns) == to_ticks(right_ns);
#else
    const auto left = file_time_from_unix_nanoseconds(left_ns);
    const auto right = file_time_from_unix_nanoseconds(right_ns);
    return left && right && *left == *right;
#endif
}

std::expected<std::filesystem::file_time_type, std::string>
last_write_time(const std::filesystem::path& path) {
    auto status = read_status(path);
    if (!status) {
        return std::unexpected(status.error());
    }

#if defined(_WIN32)
    const auto ticks = read_windows_ticks(path);
    if (!ticks) {
        return std::unexpected(ticks.error());
    }
    return detail::from_windows_ticks(*ticks);
#else
    std::error_code error;
    const auto value = std::filesystem::last_write_time(path, error);
    if (error) {
        return std::unexpected("failed to read timestamp: " + error.message());
    }
    return value;
#endif
}

std::expected<void, std::string>
set_last_write_time(const std::filesystem::path& path,
                    std::filesystem::file_time_type value) {
    auto status = read_status(path);
    if (!status) {
        return std::unexpected(status.error());
    }

#if defined(_WIN32)
    const auto written = set_windows_time(path, value);
    if (!written) {
        return std::unexpected(written.error());
    }
    const auto actual = read_windows_ticks(path);
    if (!actual) {
        return std::unexpected("failed to confirm timestamp: " +
                               actual.error());
    }
    const bool matches = (*written == *actual);
#else
    std::error_code error;
    std::filesystem::last_write_time(path, value, error);
    if (error) {
        return std::unexpected("failed to set timestamp: " + error.message());
    }
    const auto actual = std::filesystem::last_write_time(path, error);
    if (error) {
        return std::unexpected("failed to confirm timestamp: " +
                               error.message());
    }
    const bool matches = (value == actual);
#endif
    if (!matches) {
        return std::unexpected("timestamp verification failed for " +
                               kasumi::platform::path::to_utf8(path));
    }
    return {};
}

} // namespace kasumi::platform::metadata
