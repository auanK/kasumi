#include "platform/terminal.hpp"

#include <cstdio>
#include <utf8proc.h>

#if defined(_WIN32)
#include <io.h>
#include <windows.h>
#else
#include <sys/ioctl.h>
#include <unistd.h>
#endif

namespace kasumi::platform {

#if defined(_WIN32)
namespace {
HANDLE stdout_handle() noexcept {
    const int descriptor = ::_fileno(stdout);
    return descriptor >= 0
               ? reinterpret_cast<HANDLE>(::_get_osfhandle(descriptor))
               : INVALID_HANDLE_VALUE;
}
} // namespace
#endif

Terminal stdout_terminal() noexcept {
#if defined(_WIN32)
    const auto output = stdout_handle();
    DWORD mode = 0;
    if (!GetConsoleMode(output, &mode)) {
        return {};
    }
    const bool ansi =
        (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0 ||
        SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    return {.interactive = true, .ansi = ansi};
#else
    const bool tty = ::isatty(STDOUT_FILENO) != 0;
    return {.interactive = tty, .ansi = tty};
#endif
}

std::size_t terminal_width(Terminal terminal) noexcept {
    if (terminal.fixed_width != 0) {
        return terminal.fixed_width;
    }
#if defined(_WIN32)
    CONSOLE_SCREEN_BUFFER_INFO buffer{};
    if (GetConsoleScreenBufferInfo(stdout_handle(), &buffer) &&
        buffer.srWindow.Right >= buffer.srWindow.Left) {
        return static_cast<std::size_t>(buffer.srWindow.Right -
                                        buffer.srWindow.Left + 1);
    }
#else
    struct winsize size{};
    if (::ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0 && size.ws_col != 0) {
        return size.ws_col;
    }
#endif
    return 80;
}

std::string_view fit_terminal_text(std::string_view text,
                                   std::size_t columns) noexcept {
    std::size_t offset = 0;
    while (offset < text.size()) {
        utf8proc_int32_t character = 0;
        const auto length = utf8proc_iterate(
            reinterpret_cast<const utf8proc_uint8_t*>(text.data() + offset),
            static_cast<utf8proc_ssize_t>(text.size() - offset),
            &character);
        if (length <= 0) {
            break;
        }
        const auto width = static_cast<unsigned>(utf8proc_charwidth(character));
        if (width > columns) {
            break;
        }
        columns -= width;
        offset += static_cast<std::size_t>(length);
    }
    return text.substr(0, offset);
}

} // namespace kasumi::platform
