#include "cli/app.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include "platform/path.hpp"

#include <string>
#include <vector>
#include <windows.h>

namespace {
struct ConsoleUtf8Guard {
    UINT out_cp = GetConsoleOutputCP();
    UINT in_cp = GetConsoleCP();
    ConsoleUtf8Guard() noexcept {
        if (out_cp != 0 && out_cp != CP_UTF8) {
            SetConsoleOutputCP(CP_UTF8);
        }
        if (in_cp != 0 && in_cp != CP_UTF8) {
            SetConsoleCP(CP_UTF8);
        }
    }
    ~ConsoleUtf8Guard() {
        if (out_cp != 0 && out_cp != CP_UTF8) {
            SetConsoleOutputCP(out_cp);
        }
        if (in_cp != 0 && in_cp != CP_UTF8) {
            SetConsoleCP(in_cp);
        }
    }
};
} // namespace

// Narrow Windows argv uses the system code page and can lose Unicode operands.
int wmain(int argc, wchar_t* wide_argv[]) {
    const ConsoleUtf8Guard console_utf8;
    std::vector<std::string> arguments;
    try {
        for (int index = 0; index < argc; ++index) {
            arguments.push_back(
                kasumi::platform::path::to_utf8(wide_argv[index]));
        }
    } catch (const std::filesystem::filesystem_error&) {
        return kasumi::cli::run(0, nullptr);
    }
    std::vector<char*> argv;
    for (auto& argument : arguments)
        argv.push_back(argument.data());
    return kasumi::cli::run(argc, argv.data());
}
#else
int main(int argc, char* argv[]) {
    return kasumi::cli::run(argc, argv);
}
#endif
