#ifndef KASUMI_PLATFORM_CANCELLATION_HPP
#define KASUMI_PLATFORM_CANCELLATION_HPP

#include <stop_token>

namespace kasumi::platform::cancellation {

void reset() noexcept;
void request() noexcept;
bool requested() noexcept;

std::stop_token current_stop_token() noexcept;

class ScopedStopToken {
public:
    explicit ScopedStopToken(std::stop_token token) noexcept;
    ~ScopedStopToken() noexcept;

    ScopedStopToken(const ScopedStopToken&) = delete;
    ScopedStopToken& operator=(const ScopedStopToken&) = delete;

private:
    std::stop_token previous_;
};

} // namespace kasumi::platform::cancellation

#endif
