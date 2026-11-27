#include "platform/cancellation.hpp"

#include <atomic>
#include <cstddef>
#include <utility>

namespace kasumi::platform::cancellation {
namespace {

std::atomic_flag cancelled;
thread_local std::stop_token thread_stop_token{};
thread_local std::size_t ignore_cancellation_depth = 0;

} // namespace

void reset() noexcept {
    cancelled.clear(std::memory_order_relaxed);
}

void request() noexcept {
    cancelled.test_and_set(std::memory_order_relaxed);
}

bool requested() noexcept {
    if (ignore_cancellation_depth > 0U) {
        return false;
    }
    return cancelled.test(std::memory_order_relaxed) ||
           thread_stop_token.stop_requested();
}

bool ignoring() noexcept {
    return ignore_cancellation_depth > 0U;
}

std::stop_token current_stop_token() noexcept {
    if (ignore_cancellation_depth > 0U) {
        return {};
    }
    return thread_stop_token;
}

ScopedStopToken::ScopedStopToken(std::stop_token token) noexcept
    : previous(std::exchange(thread_stop_token, std::move(token))) {
}

ScopedStopToken::~ScopedStopToken() noexcept {
    thread_stop_token = std::move(previous);
}

ScopedIgnoreCancellation::ScopedIgnoreCancellation() noexcept {
    ++ignore_cancellation_depth;
}

ScopedIgnoreCancellation::~ScopedIgnoreCancellation() noexcept {
    if (ignore_cancellation_depth > 0U) {
        --ignore_cancellation_depth;
    }
}

} // namespace kasumi::platform::cancellation
