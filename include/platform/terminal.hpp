#ifndef KASUMI_PLATFORM_TERMINAL_HPP
#define KASUMI_PLATFORM_TERMINAL_HPP

#include <cstddef>
#include <string_view>

namespace kasumi::platform {

struct Terminal {
    bool interactive = false;
    bool ansi = false;
    // A fixed width is useful for rendering tests.
    std::size_t fixed_width = 0;
};

Terminal stdout_terminal() noexcept;
std::size_t terminal_width(Terminal terminal) noexcept;
std::string_view fit_terminal_text(std::string_view text,
                                   std::size_t columns) noexcept;

} // namespace kasumi::platform

#endif
