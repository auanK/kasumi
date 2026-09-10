#include "cli/credentials.hpp"

#include "cli/i18n.hpp"
#include "cli/style.hpp"
#include "platform/cancellation.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string_view>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <conio.h>
#include <windows.h>
#else
#include <cerrno>
#include <poll.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace kasumi::cli::credentials {
namespace {

constexpr std::size_t maximum_secret_size = 4096;

void wipe(std::string& value) noexcept {
    auto* bytes = reinterpret_cast<volatile char*>(value.data());
    for (std::size_t index = 0; index < value.size(); ++index) {
        bytes[index] = '\0';
    }
    value.clear();
}

#if defined(_WIN32)

std::string utf8(std::wstring_view text) {
    if (text.empty()) {
        return {};
    }
    if (text.size() >
        static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
        return {};
    }
    const auto size = WideCharToMultiByte(CP_UTF8,
                                          WC_ERR_INVALID_CHARS,
                                          text.data(),
                                          static_cast<int>(text.size()),
                                          nullptr,
                                          0,
                                          nullptr,
                                          nullptr);
    if (size <= 0) {
        return {};
    }
    std::string result(static_cast<std::size_t>(size), '\0');
    if (WideCharToMultiByte(CP_UTF8,
                            WC_ERR_INVALID_CHARS,
                            text.data(),
                            static_cast<int>(text.size()),
                            result.data(),
                            size,
                            nullptr,
                            nullptr) != size) {
        return {};
    }
    return result;
}

std::string read_console_secret() {
    std::wstring secret;
    while (!platform::cancellation::requested()) {
        if (_kbhit() == 0) {
            Sleep(25);
            continue;
        }
        const auto character = _getwch();
        if (character == L'\r' || character == L'\n') {
            break;
        }
        if (character == 3 || platform::cancellation::requested()) {
            platform::cancellation::request();
            break;
        }
        if (character == L'\b') {
            if (!secret.empty()) {
                const auto last = secret.back();
                secret.pop_back();
                if (last >= 0xDC00 && last <= 0xDFFF && !secret.empty() &&
                    secret.back() >= 0xD800 && secret.back() <= 0xDBFF) {
                    secret.pop_back();
                }
            }
            continue;
        }
        if (character == 0 || character == 0xE0) {
            static_cast<void>(_getwch());
            continue;
        }
        if (secret.size() < maximum_secret_size) {
            secret.push_back(static_cast<wchar_t>(character));
        }
    }
    auto result =
        platform::cancellation::requested() ? std::string{} : utf8(secret);
    if (!secret.empty()) {
        SecureZeroMemory(secret.data(), secret.size() * sizeof(wchar_t));
    }
    return result;
}

#else

bool hide_echo(termios& original) noexcept {
    if (::isatty(STDIN_FILENO) == 0 ||
        ::tcgetattr(STDIN_FILENO, &original) != 0) {
        return false;
    }
    auto hidden = original;
    hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
    return ::tcsetattr(STDIN_FILENO, TCSANOW, &hidden) == 0;
}

void restore_echo(const termios& original) noexcept {
    static_cast<void>(::tcsetattr(STDIN_FILENO, TCSANOW, &original));
}

std::string read_console_secret() {
    termios original{};
    if (!hide_echo(original)) {
        platform::cancellation::request();
        return {};
    }

    std::string secret;
    try {
        while (!platform::cancellation::requested()) {
            pollfd input{.fd = STDIN_FILENO, .events = POLLIN, .revents = 0};
            const auto ready = ::poll(&input, 1, 50);
            if (ready < 0) {
                if (errno == EINTR) {
                    continue;
                }
                platform::cancellation::request();
                break;
            }
            if (ready == 0) {
                continue;
            }
            if ((input.revents & (POLLERR | POLLNVAL)) != 0) {
                platform::cancellation::request();
                break;
            }
            char buffer[512]{};
            const auto count = ::read(STDIN_FILENO, buffer, sizeof(buffer));
            if (count <= 0) {
                platform::cancellation::request();
                break;
            }
            const std::string_view bytes{buffer,
                                         static_cast<std::size_t>(count)};
            const auto newline = bytes.find('\n');
            const auto available =
                newline == std::string_view::npos ? bytes.size() : newline;
            const auto remaining = maximum_secret_size - secret.size();
            secret.append(bytes.substr(0, std::min(available, remaining)));
            if (newline != std::string_view::npos) {
                break;
            }
        }
    } catch (...) {
        restore_echo(original);
        throw;
    }
    if (!secret.empty() && secret.back() == '\r') {
        secret.pop_back();
    }
    if (platform::cancellation::requested()) {
        for (volatile char& byte : secret) {
            byte = '\0';
        }
        secret.clear();
    }
    restore_echo(original);
    return secret;
}

#endif

bool interactive_terminal() noexcept {
#if defined(_WIN32)
    DWORD mode = 0;
    const auto input = GetStdHandle(STD_INPUT_HANDLE);
    return input != nullptr && input != INVALID_HANDLE_VALUE &&
           GetConsoleMode(input, &mode) != 0;
#else
    return ::isatty(STDIN_FILENO) != 0;
#endif
}

} // namespace

std::string read_secret(const char* environment_name,
                        const std::string& prompt) {
    if (environment_name != nullptr) {
        if (const char* env_p = std::getenv(environment_name)) {
            return std::string(env_p);
        }
    }
    const bool interactive = interactive_terminal();
    std::cout << prompt << std::flush;
    auto secret = interactive ? read_console_secret() : [&] {
        std::string value;
        std::getline(std::cin, value);
        return value;
    }();
    std::cout << "\n\n";
    return secret;
}

application::Credentials from_environment() {
    if (const char* env = std::getenv("KASUMI_MASTER_KEY")) {
        return application::MasterKeyHex{std::string(env)};
    }
    return application::NoCredentials{};
}

application::PasswordPair read_password_pair() {
    return read_password_pair([](const std::string& prompt) {
        return read_secret(nullptr, prompt);
    });
}

application::PasswordPair read_password_pair(const SecretPrompt& prompt) {
    const auto confirmed = [&](const char* environment_name,
                               const std::string& first_prompt,
                               const std::string& confirmation_prompt,
                               const std::string& mismatch) {
        if (const char* value = std::getenv(environment_name)) {
            return std::string{value};
        }
        while (!platform::cancellation::requested()) {
            auto first = prompt(first_prompt);
            if (platform::cancellation::requested()) {
                wipe(first);
                return std::string{};
            }
            auto confirmation = prompt(confirmation_prompt);
            if (platform::cancellation::requested()) {
                wipe(first);
                wipe(confirmation);
                return std::string{};
            }
            if (first == confirmation) {
                wipe(confirmation);
                return first;
            }
            wipe(first);
            wipe(confirmation);
            std::cout << style::red << mismatch << style::reset << '\n';
        }
        return std::string{};
    };

    auto password =
        confirmed("KASUMI_PASSWORD",
                  std::string{i18n::tr(i18n::Key::PromptPassword)},
                  std::string{i18n::tr(i18n::Key::PromptConfirmPassword)},
                  std::string{i18n::tr(i18n::Key::PasswordsDoNotMatch)});
    if (platform::cancellation::requested()) {
        return application::PasswordPair{};
    }
    auto salt = confirmed("KASUMI_PASSWORD2",
                          std::string{i18n::tr(i18n::Key::PromptSalt)},
                          std::string{i18n::tr(i18n::Key::PromptConfirmSalt)},
                          std::string{i18n::tr(i18n::Key::SaltsDoNotMatch)});

    return application::PasswordPair{std::move(password), std::move(salt)};
}

} // namespace kasumi::cli::credentials
