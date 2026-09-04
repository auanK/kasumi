#include "kasumi/test/scoped_environment.hpp"

#include <cerrno>
#include <cstdlib>
#include <stdexcept>
#include <system_error>
#include <utility>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace kasumi::test {
namespace {

#if defined(_WIN32)
std::optional<std::wstring> read_windows_env_unlocked(const wchar_t* name) {
    ::SetLastError(0);
    DWORD required_size = ::GetEnvironmentVariableW(name, nullptr, 0);
    if (required_size == 0) {
        if (::GetLastError() == ERROR_ENVVAR_NOT_FOUND) {
            return std::nullopt;
        }
        return std::wstring{};
    }

    std::wstring buffer;
    while (required_size > 0) {
        buffer.resize(required_size);
        ::SetLastError(0);
        const DWORD actual =
            ::GetEnvironmentVariableW(name, buffer.data(), required_size);
        if (actual == 0) {
            if (::GetLastError() == ERROR_ENVVAR_NOT_FOUND) {
                return std::nullopt;
            }
            return std::wstring{};
        }
        if (actual < required_size) {
            buffer.resize(actual);
            return buffer;
        }
        required_size = actual;
    }
    return std::nullopt;
}

void write_windows_env_unlocked(const wchar_t* name,
                                const std::optional<std::wstring>& value) {
    if (value.has_value()) {
        ::SetEnvironmentVariableW(name, value->c_str());
    } else {
        ::SetEnvironmentVariableW(name, nullptr);
    }
}
#endif

std::recursive_mutex& environment_mutex() {
    static std::recursive_mutex mutex;
    return mutex;
}

void validate_name(std::string_view name) {
    if (name.empty() || name.find('=') != std::string_view::npos ||
        name.find('\0') != std::string_view::npos) {
        throw std::invalid_argument("invalid environment variable name");
    }
}

std::optional<std::string> read_environment_unlocked(const std::string& name) {
    const char* value = std::getenv(name.c_str());
    if (value == nullptr) {
        return std::nullopt;
    }
    return std::string(value);
}

int set_environment_unlocked(const std::string& name,
                             const std::optional<std::string>& value) {
#if defined(_WIN32)
    return _putenv_s(name.c_str(), value ? value->c_str() : "");
#else
    if (value) {
        return setenv(name.c_str(), value->c_str(), 1) == 0 ? 0 : errno;
    }
    return unsetenv(name.c_str()) == 0 ? 0 : errno;
#endif
}

} // namespace

ScopedEnvironmentVariable
scoped_environment_variable(std::string name,
                            std::optional<std::string> value) {
    validate_name(name);
    auto data = ScopedEnvironmentVariable{
        new EnvironmentVariableData{.name = std::move(name),
                                    .lock =
                                        std::unique_lock{environment_mutex()},
                                    .previous_value = std::nullopt},
        restore_environment_variable};
    data->previous_value = read_environment_unlocked(data->name);
    const int error = set_environment_unlocked(data->name, value);
    if (error != 0) {
        throw std::system_error(error,
                                std::generic_category(),
                                "could not update environment variable");
    }
    return data;
}

void restore_environment_variable(EnvironmentVariableData* data) noexcept {
    if (data != nullptr) {
        static_cast<void>(
            set_environment_unlocked(data->name, data->previous_value));
    }
    delete data;
}

#if defined(_WIN32)
ScopedWindowsEnvironmentVariable
scoped_windows_environment_variable(std::wstring name,
                                    std::optional<std::wstring> value) {
    auto data = ScopedWindowsEnvironmentVariable{
        new WindowsEnvironmentVariableData{
            .name = std::move(name),
            .lock = std::unique_lock{environment_mutex()},
            .previous_value = std::nullopt},
        restore_windows_environment_variable};
    data->previous_value = read_windows_env_unlocked(data->name.c_str());
    write_windows_env_unlocked(data->name.c_str(), value);
    return data;
}

void restore_windows_environment_variable(
    WindowsEnvironmentVariableData* data) noexcept {
    if (data != nullptr) {
        write_windows_env_unlocked(data->name.c_str(), data->previous_value);
    }
    delete data;
}
#endif

} // namespace kasumi::test
