#ifndef KASUMI_PLATFORM_PROCESS_CRASH_TEST_HOOK_HPP
#define KASUMI_PLATFORM_PROCESS_CRASH_TEST_HOOK_HPP

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string_view>
#include <thread>

namespace kasumi::platform::process_crash_test_hook {

inline void pause_at(std::string_view point,
                     std::string_view subject = {}) noexcept {
#if defined(KASUMI_PROCESS_CRASH_TESTS)
    const char* selected_point = std::getenv("KASUMI_CRASH_TEST_POINT");
    const char* selected_subject = std::getenv("KASUMI_CRASH_TEST_SUBJECT");
    if (selected_point == nullptr || selected_point != point ||
        (selected_subject != nullptr && selected_subject[0] != '\0' &&
         selected_subject != subject)) {
        return;
    }

    try {
#if defined(_WIN32)
        const auto* signal_value = _wgetenv(L"KASUMI_CRASH_TEST_SIGNAL");
        if (signal_value == nullptr || signal_value[0] == L'\0') {
            return;
        }
        const std::filesystem::path signal_path{signal_value};
#else
        const char* signal_value = std::getenv("KASUMI_CRASH_TEST_SIGNAL");
        if (signal_value == nullptr || signal_value[0] == '\0') {
            return;
        }
        const std::filesystem::path signal_path{signal_value};
#endif
        std::ofstream signal{signal_path, std::ios::binary | std::ios::trunc};
        if (!signal) {
            return;
        }
        signal << point << '\n' << subject << '\n';
        signal.close();
        if (!signal) {
            return;
        }

        for (;;) {
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
    } catch (...) {
    }
#else
    static_cast<void>(point);
    static_cast<void>(subject);
#endif
}

} // namespace kasumi::platform::process_crash_test_hook

#endif
