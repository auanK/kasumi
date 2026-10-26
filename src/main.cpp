#include "cli/app.hpp"

#if defined(_WIN32)
#include "platform/path.hpp"

#include <string>
#include <vector>

// Narrow Windows argv uses the system code page and can lose Unicode operands.
int wmain(int argc, wchar_t* wide_argv[]) {
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
