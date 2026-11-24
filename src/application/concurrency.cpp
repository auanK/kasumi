#include "application/concurrency.hpp"

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <string_view>
#include <utility>

namespace kasumi::application {
namespace {

thread_local std::optional<std::size_t> thread_concurrency_override{};

std::optional<std::size_t> env_content_concurrency() noexcept {
    const char* setting = std::getenv("KASUMI_CONTENT_CONCURRENCY");
    if (setting == nullptr) {
        return std::nullopt;
    }
    const std::string_view text{setting};
    unsigned value = 0;
    const auto parsed =
        std::from_chars(text.data(), text.data() + text.size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
        value == 0) {
        return std::nullopt;
    }
    return std::min<std::size_t>(value,
                                 maximum_experimental_content_concurrency);
}

std::size_t clamp_concurrency(std::size_t value) noexcept {
    return std::clamp<std::size_t>(
        value, 1, maximum_experimental_content_concurrency);
}

} // namespace

std::size_t resolve_content_concurrency(
    std::optional<std::size_t> request_override,
    std::optional<std::size_t> profile_override) noexcept {
    if (request_override && *request_override > 0) {
        return clamp_concurrency(*request_override);
    }
    if (profile_override && *profile_override > 0) {
        return clamp_concurrency(*profile_override);
    }
    if (const auto env_value = env_content_concurrency()) {
        return *env_value;
    }
    return default_content_concurrency;
}

std::size_t content_concurrency() noexcept {
    if (thread_concurrency_override && *thread_concurrency_override > 0) {
        return clamp_concurrency(*thread_concurrency_override);
    }
    return resolve_content_concurrency();
}

std::optional<std::size_t> current_content_concurrency_override() noexcept {
    return thread_concurrency_override;
}

ScopedContentConcurrency::ScopedContentConcurrency(
    std::optional<std::size_t> override_value) noexcept
    : previous_(std::exchange(
          thread_concurrency_override,
          (override_value && *override_value > 0)
              ? std::optional<std::size_t>{clamp_concurrency(*override_value)}
              : std::nullopt)) {
}

ScopedContentConcurrency::~ScopedContentConcurrency() noexcept {
    thread_concurrency_override = previous_;
}

} // namespace kasumi::application
