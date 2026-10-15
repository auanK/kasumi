#ifndef KASUMI_APPLICATION_SYNC_MUTATION_FAULT_TEST_HPP
#define KASUMI_APPLICATION_SYNC_MUTATION_FAULT_TEST_HPP

#include <filesystem>
#include <string_view>

#ifdef KASUMI_MUTATION_FAULT_TESTS
#include <functional>
#include <mutex>
#include <utility>
#endif

namespace kasumi::application::sync::mutation_fault_test {

#ifdef KASUMI_MUTATION_FAULT_TESTS
using Hook = std::function<void(std::string_view point, const std::filesystem::path& path)>;

inline Hook& global_hook_instance() {
    static Hook hook;
    return hook;
}

inline std::mutex& global_hook_mutex() {
    static std::mutex mutex;
    return mutex;
}

inline void set_hook(Hook hook) {
    std::lock_guard lock(global_hook_mutex());
    global_hook_instance() = std::move(hook);
}

inline void clear_hook() {
    std::lock_guard lock(global_hook_mutex());
    global_hook_instance() = nullptr;
}

inline void hit(std::string_view point, const std::filesystem::path& path = {}) {
    // Test builds only: serialize callbacks and their installation/removal.
    std::lock_guard lock(global_hook_mutex());
    if (global_hook_instance())
        global_hook_instance()(point, path);
}
#else
inline void hit(std::string_view, const std::filesystem::path& = {}) noexcept {
}
#endif

} // namespace kasumi::application::sync::mutation_fault_test

#endif
