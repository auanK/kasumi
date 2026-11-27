#ifndef KASUMI_PLATFORM_CANCELLATION_HPP
#define KASUMI_PLATFORM_CANCELLATION_HPP

#include <cstddef>
#include <stop_token>

namespace kasumi::platform::cancellation {

void reset() noexcept;
void request() noexcept;
bool requested() noexcept;
bool ignoring() noexcept;

std::stop_token current_stop_token() noexcept;

struct ScopedStopToken {
    std::stop_token previous{};

    explicit ScopedStopToken(std::stop_token token) noexcept;
    ~ScopedStopToken() noexcept;

    ScopedStopToken(const ScopedStopToken&) = delete;
    ScopedStopToken& operator=(const ScopedStopToken&) = delete;
};

struct ScopedIgnoreCancellation {
    ScopedIgnoreCancellation() noexcept;
    ~ScopedIgnoreCancellation() noexcept;

    ScopedIgnoreCancellation(const ScopedIgnoreCancellation&) = delete;
    ScopedIgnoreCancellation&
    operator=(const ScopedIgnoreCancellation&) = delete;
};

} // namespace kasumi::platform::cancellation

#endif
