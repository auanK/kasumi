#ifndef KASUMI_PLATFORM_CANCELLATION_HPP
#define KASUMI_PLATFORM_CANCELLATION_HPP

namespace kasumi::platform::cancellation {

void reset() noexcept;
void request() noexcept;
bool requested() noexcept;

} // namespace kasumi::platform::cancellation

#endif
