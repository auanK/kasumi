#include "platform/cancellation.hpp"

#include <atomic>
#include <utility>

namespace kasumi::platform::cancellation {
namespace {

std::atomic_flag cancelled;
thread_local std::stop_token thread_stop_token{};

} // namespace

void reset() noexcept {
    cancelled.clear(std::memory_order_relaxed);
}

void request() noexcept {
    cancelled.test_and_set(std::memory_order_relaxed);
}

bool requested() noexcept {
    return cancelled.test(std::memory_order_relaxed) ||
           thread_stop_token.stop_requested();
}

std::stop_token current_stop_token() noexcept {
    return thread_stop_token;
}

ScopedStopToken::ScopedStopToken(std::stop_token token) noexcept
    : previous_(std::exchange(thread_stop_token, std::move(token))) {
}

ScopedStopToken::~ScopedStopToken() noexcept {
    thread_stop_token = std::move(previous_);
}

} // namespace kasumi::platform::cancellation
