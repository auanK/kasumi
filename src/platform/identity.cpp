#include "platform/identity.hpp"

#include <string>
#include <string_view>
#include <utility>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cerrno>
#include <unistd.h>
#endif

namespace kasumi::platform::identity {

namespace {

bool allowed(char value) noexcept {
    return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
           (value >= '0' && value <= '9') || value == '-' || value == '_' ||
           value == '.';
}

std::string sanitize(std::string_view value) {
    std::string result;
    result.reserve(value.size());
    for (const char character : value) {
        result.push_back(allowed(character) ? character : '_');
    }
    return result;
}

#if defined(_WIN32)
std::expected<std::string, std::string> machine_name() {
    std::wstring buffer(MAX_COMPUTERNAME_LENGTH + 1, L'\0');
    DWORD size = static_cast<DWORD>(buffer.size());
    if (GetComputerNameW(buffer.data(), &size) == 0) {
        const auto native_code = GetLastError();
        return std::unexpected(
            "falha ao obter nome da máquina (native_code=" +
            std::to_string(static_cast<unsigned long>(native_code)) + ")");
    }

    std::string result;
    result.reserve(size);
    for (DWORD index = 0; index < size; ++index) {
        const auto codepoint = buffer[index];
        result.push_back(codepoint <= 0x7f &&
                                 allowed(static_cast<char>(codepoint))
                             ? static_cast<char>(codepoint)
                             : '_');
    }
    return result;
}
#else
std::expected<std::string, std::string> machine_name() {
    char buffer[256]{};
    if (::gethostname(buffer, sizeof(buffer) - 1) != 0) {
        const auto native_code = errno;
        return std::unexpected("falha ao obter nome da máquina (native_code=" +
                               std::to_string(native_code) + ")");
    }
    buffer[sizeof(buffer) - 1] = '\0';
    return std::string{buffer};
}
#endif

} // namespace

bool valid(const Identity& identity) noexcept {
    if (identity.machine_id.empty() ||
        identity.machine_id.size() > maximum_machine_id_size ||
        identity.process_id == 0) {
        return false;
    }

    for (const char character : identity.machine_id) {
        if (!allowed(character)) {
            return false;
        }
    }
    return true;
}

std::expected<Identity, std::string> current() {
#if defined(_WIN32)
    const auto process_id = static_cast<std::uint64_t>(GetCurrentProcessId());
    if (process_id == 0) {
        return std::unexpected("PID do processo inválido");
    }
#else
    const auto native_process_id = ::getpid();
    if (native_process_id <= 0) {
        return std::unexpected("PID do processo inválido");
    }
    const auto process_id = static_cast<std::uint64_t>(native_process_id);
#endif

    auto machine = machine_name();
    if (!machine) {
        return std::unexpected(machine.error());
    }
    auto machine_id = sanitize(*machine);
    if (machine_id.empty()) {
        machine_id = "unknown";
    }

    Identity result{
        .machine_id = std::move(machine_id),
        .process_id = process_id,
    };
    if (!valid(result)) {
        return std::unexpected("identidade do processo inválida");
    }
    return result;
}

} // namespace kasumi::platform::identity
