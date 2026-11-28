#ifndef KASUMI_PLATFORM_CLOCK_HPP
#define KASUMI_PLATFORM_CLOCK_HPP

#include <cstdint>
#include <expected>
#include <optional>
#include <string>

namespace kasumi::platform::clock {

// Returns the current timestamp in seconds since the Unix epoch.
std::expected<std::int64_t, std::string> unix_seconds();

// Formats a Unix timestamp in UTC with explicit "+00:00" offset.
// Returns "-" when unix_seconds <= 0.
std::string format_utc_timestamp(std::int64_t unix_seconds,
                                 bool include_seconds = true);

// Formats a Unix timestamp in local time with explicit "±HH:MM" UTC offset.
// Falls back to UTC ("+00:00") if local conversion fails. Returns "-" when <=
// 0.
std::string format_local_timestamp(std::int64_t unix_seconds,
                                   bool include_seconds = true);

namespace testing {

struct ScopedUnixSecondsOverride {
    std::optional<std::int64_t> previous{};

    explicit ScopedUnixSecondsOverride(
        std::optional<std::int64_t> value) noexcept;
    ~ScopedUnixSecondsOverride() noexcept;

    ScopedUnixSecondsOverride(const ScopedUnixSecondsOverride&) = delete;
    ScopedUnixSecondsOverride&
    operator=(const ScopedUnixSecondsOverride&) = delete;
};

} // namespace testing

} // namespace kasumi::platform::clock

#endif
