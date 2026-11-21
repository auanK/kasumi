#include "platform/clock.hpp"

#include <chrono>
#include <cmath>
#include <ctime>
#include <format>
#include <limits>
#include <utility>

namespace kasumi::platform::clock {
namespace {

bool to_utc_tm(std::time_t value, std::tm& output) noexcept {
#if defined(_WIN32)
    return ::gmtime_s(&output, &value) == 0;
#else
    return ::gmtime_r(&value, &output) != nullptr;
#endif
}

bool to_local_tm(std::time_t value, std::tm& output) noexcept {
#if defined(_WIN32)
    return ::localtime_s(&output, &value) == 0;
#else
    return ::localtime_r(&value, &output) != nullptr;
#endif
}

// Howard Hinnant's civil-to-days algorithm avoids mktime DST/overflow quirks.
constexpr std::int64_t days_from_civil(std::int64_t year,
                                       unsigned month,
                                       unsigned day) noexcept {
    year -= month <= 2 ? 1 : 0;
    const std::int64_t era = (year >= 0 ? year : year - 399) / 400;
    const auto yoe = static_cast<unsigned>(year - era * 400);
    const unsigned doy =
        (153U * (month + (month > 2 ? static_cast<unsigned>(-3) : 9U)) + 2U) /
            5U +
        day - 1U;
    const unsigned doe = yoe * 365U + yoe / 4U - yoe / 100U + doy;
    return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

std::int64_t tm_minutes_since_epoch(const std::tm& value) noexcept {
    const auto year = static_cast<std::int64_t>(value.tm_year) + 1900;
    const auto month = static_cast<unsigned>(value.tm_mon + 1);
    const auto day = static_cast<unsigned>(value.tm_mday);
    const auto days = days_from_civil(year, month, day);
    return days * 1440 + static_cast<std::int64_t>(value.tm_hour) * 60 +
           static_cast<std::int64_t>(value.tm_min);
}

std::string format_tm_with_offset(const std::tm& value,
                                  int offset_minutes,
                                  bool include_seconds) {
    const int year = value.tm_year + 1900;
    const int month = value.tm_mon + 1;
    const int day = value.tm_mday;
    const int hour = value.tm_hour;
    const int minute = value.tm_min;
    const int second = value.tm_sec;

    const char sign = offset_minutes >= 0 ? '+' : '-';
    const int abs_minutes =
        offset_minutes >= 0 ? offset_minutes : -offset_minutes;
    const int off_hours = abs_minutes / 60;
    const int off_mins = abs_minutes % 60;

    if (include_seconds) {
        return std::format("{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d} {}{:02d}:{:02d}",
                           year,
                           month,
                           day,
                           hour,
                           minute,
                           second,
                           sign,
                           off_hours,
                           off_mins);
    }
    return std::format("{:04d}-{:02d}-{:02d} {:02d}:{:02d} {}{:02d}:{:02d}",
                       year,
                       month,
                       day,
                       hour,
                       minute,
                       sign,
                       off_hours,
                       off_mins);
}

} // namespace

std::expected<std::int64_t, std::string> unix_seconds() {
    using seconds = std::chrono::seconds;
    const auto elapsed = std::chrono::system_clock::now().time_since_epoch();
    const auto value = std::chrono::duration_cast<seconds>(elapsed).count();
    if (value < 0) {
        return std::unexpected("invalid Unix clock");
    }
    if (!std::in_range<std::int64_t>(value)) {
        return std::unexpected("clock value out of representable range");
    }

    return static_cast<std::int64_t>(value);
}

std::string format_utc_timestamp(std::int64_t timestamp,
                                 bool include_seconds) {
    if (timestamp <= 0 || !std::in_range<std::time_t>(timestamp)) {
        return "-";
    }
    const auto tt = static_cast<std::time_t>(timestamp);
    std::tm utc_tm{};
    if (!to_utc_tm(tt, utc_tm)) {
        return "-";
    }
    return format_tm_with_offset(utc_tm, 0, include_seconds);
}

std::string format_local_timestamp(std::int64_t timestamp,
                                   bool include_seconds) {
    if (timestamp <= 0 || !std::in_range<std::time_t>(timestamp)) {
        return "-";
    }
    const auto tt = static_cast<std::time_t>(timestamp);
    std::tm utc_tm{};
    if (!to_utc_tm(tt, utc_tm)) {
        return "-";
    }
    std::tm local_tm{};
    if (!to_local_tm(tt, local_tm)) {
        return format_tm_with_offset(utc_tm, 0, include_seconds);
    }
    const auto diff_minutes =
        tm_minutes_since_epoch(local_tm) - tm_minutes_since_epoch(utc_tm);
    if (diff_minutes < -1440 || diff_minutes > 1440) {
        return format_tm_with_offset(utc_tm, 0, include_seconds);
    }
    return format_tm_with_offset(
        local_tm, static_cast<int>(diff_minutes), include_seconds);
}

} // namespace kasumi::platform::clock
