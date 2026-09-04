#ifndef KASUMI_TEST_SCOPED_ENVIRONMENT_HPP
#define KASUMI_TEST_SCOPED_ENVIRONMENT_HPP

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace kasumi::test {

struct EnvironmentVariableData {
    std::string name;
    std::unique_lock<std::recursive_mutex> lock;
    std::optional<std::string> previous_value;
};

using ScopedEnvironmentVariable =
    std::unique_ptr<EnvironmentVariableData,
                    void (*)(EnvironmentVariableData*)>;

ScopedEnvironmentVariable
scoped_environment_variable(std::string name, std::optional<std::string> value);
void restore_environment_variable(EnvironmentVariableData* data) noexcept;

#if defined(_WIN32)
struct WindowsEnvironmentVariableData {
    std::wstring name;
    std::unique_lock<std::recursive_mutex> lock;
    std::optional<std::wstring> previous_value;
};

using ScopedWindowsEnvironmentVariable =
    std::unique_ptr<WindowsEnvironmentVariableData,
                    void (*)(WindowsEnvironmentVariableData*)>;

ScopedWindowsEnvironmentVariable
scoped_windows_environment_variable(std::wstring name,
                                    std::optional<std::wstring> value);
void restore_windows_environment_variable(
    WindowsEnvironmentVariableData* data) noexcept;
#endif

} // namespace kasumi::test

#endif
