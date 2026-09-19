#include "platform/clock.hpp"

#include <chrono>
#include <utility>

namespace kasumi::platform::clock {

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

} // namespace kasumi::platform::clock
