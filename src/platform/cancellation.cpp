#include "platform/cancellation.hpp"

#include <atomic>

namespace kasumi::platform::cancellation {
namespace {

std::atomic_flag cancelled;

} // namespace

void reset() noexcept {
    cancelled.clear(std::memory_order_relaxed);
}

void request() noexcept {
    cancelled.test_and_set(std::memory_order_relaxed);
}

bool requested() noexcept {
    return cancelled.test(std::memory_order_relaxed);
}

} // namespace kasumi::platform::cancellation
