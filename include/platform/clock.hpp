#ifndef KASUMI_PLATFORM_CLOCK_HPP
#define KASUMI_PLATFORM_CLOCK_HPP

#include <cstdint>
#include <expected>
#include <string>

namespace kasumi::platform::clock {

// Returns the current timestamp in seconds since the Unix epoch.
std::expected<std::int64_t, std::string> unix_seconds();

} // namespace kasumi::platform::clock

#endif
