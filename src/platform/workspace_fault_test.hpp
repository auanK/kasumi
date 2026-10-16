#ifndef KASUMI_PLATFORM_WORKSPACE_FAULT_TEST_HPP
#define KASUMI_PLATFORM_WORKSPACE_FAULT_TEST_HPP

#include <cstddef>
#include <filesystem>
#include <system_error>

#ifdef KASUMI_WORKSPACE_FAULT_TESTS
#include <functional>
#include <utility>
#endif

namespace kasumi::platform::workspace_fault_test {

#ifdef KASUMI_WORKSPACE_FAULT_TESTS
using RetryHook = std::function<void(
    const std::filesystem::path&, std::size_t, std::error_code)>;

inline RetryHook& retry_hook() {
    static thread_local RetryHook hook;
    return hook;
}

inline void set_retry_hook(RetryHook hook) {
    retry_hook() = std::move(hook);
}

inline void clear_retry_hook() {
    retry_hook() = nullptr;
}

inline void before_retry(const std::filesystem::path& path,
                         std::size_t attempt,
                         std::error_code error) {
    if (retry_hook()) {
        retry_hook()(path, attempt, error);
    }
}
#else
inline void before_retry(const std::filesystem::path&,
                         std::size_t,
                         std::error_code) noexcept {}
#endif

} // namespace kasumi::platform::workspace_fault_test

#endif
