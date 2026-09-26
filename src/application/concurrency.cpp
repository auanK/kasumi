#include "application/concurrency.hpp"

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <string_view>

namespace kasumi::application {

std::size_t content_concurrency() noexcept {
    const char* setting = std::getenv("KASUMI_CONTENT_CONCURRENCY");
    if (setting == nullptr) {
        return default_content_concurrency;
    }
    const std::string_view text{setting};
    unsigned value = 0;
    const auto parsed =
        std::from_chars(text.data(), text.data() + text.size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
        value == 0) {
        return default_content_concurrency;
    }
    return std::min<std::size_t>(value,
                                 maximum_experimental_content_concurrency);
}

} // namespace kasumi::application
