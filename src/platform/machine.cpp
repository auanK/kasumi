#include "platform/machine.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/utsname.h>
#include <unistd.h>
#endif

namespace kasumi::platform::machine {
namespace {

bool is_ascii_whitespace(unsigned char ch) noexcept {
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '\v' ||
           ch == '\f';
}

// Returns length of next valid UTF-8 codepoint and sets codepoint value.
// Returns 0 on invalid UTF-8 sequence.
std::size_t decode_utf8_codepoint(std::string_view input,
                                  std::uint32_t& codepoint) noexcept {
    if (input.empty()) {
        return 0;
    }
    const auto b0 = static_cast<unsigned char>(input[0]);
    if (b0 < 0x80U) {
        codepoint = b0;
        return 1;
    }
    if (b0 >= 0xC2U && b0 <= 0xDFU) {
        if (input.size() < 2) {
            return 0;
        }
        const auto b1 = static_cast<unsigned char>(input[1]);
        if ((b1 & 0xC0U) != 0x80U) {
            return 0;
        }
        codepoint = ((static_cast<std::uint32_t>(b0) & 0x1FU) << 6U) |
                    (static_cast<std::uint32_t>(b1) & 0x3FU);
        return 2;
    }
    if (b0 >= 0xE0U && b0 <= 0xEFU) {
        if (input.size() < 3) {
            return 0;
        }
        const auto b1 = static_cast<unsigned char>(input[1]);
        const auto b2 = static_cast<unsigned char>(input[2]);
        if ((b1 & 0xC0U) != 0x80U || (b2 & 0xC0U) != 0x80U) {
            return 0;
        }
        if (b0 == 0xE0U && b1 < 0xA0U) {
            return 0;
        }
        if (b0 == 0xEDU && b1 >= 0xA0U) {
            return 0;
        }
        codepoint = ((static_cast<std::uint32_t>(b0) & 0x0FU) << 12U) |
                    ((static_cast<std::uint32_t>(b1) & 0x3FU) << 6U) |
                    (static_cast<std::uint32_t>(b2) & 0x3FU);
        return 3;
    }
    if (b0 >= 0xF0U && b0 <= 0xF4U) {
        if (input.size() < 4) {
            return 0;
        }
        const auto b1 = static_cast<unsigned char>(input[1]);
        const auto b2 = static_cast<unsigned char>(input[2]);
        const auto b3 = static_cast<unsigned char>(input[3]);
        if ((b1 & 0xC0U) != 0x80U || (b2 & 0xC0U) != 0x80U ||
            (b3 & 0xC0U) != 0x80U) {
            return 0;
        }
        if (b0 == 0xF0U && b1 < 0x90U) {
            return 0;
        }
        if (b0 == 0xF4U && b1 > 0x8FU) {
            return 0;
        }
        codepoint = ((static_cast<std::uint32_t>(b0) & 0x07U) << 18U) |
                    ((static_cast<std::uint32_t>(b1) & 0x3FU) << 12U) |
                    ((static_cast<std::uint32_t>(b2) & 0x3FU) << 6U) |
                    (static_cast<std::uint32_t>(b3) & 0x3FU);
        return 4;
    }
    return 0;
}

std::string query_os_host_name() {
#if defined(_WIN32)
    auto read_wide_name = [](COMPUTER_NAME_FORMAT format) -> std::wstring {
        DWORD length = 0;
        GetComputerNameExW(format, nullptr, &length);
        if (length == 0 && GetLastError() != ERROR_MORE_DATA) {
            return {};
        }
        std::wstring wide(length, L'\0');
        if (!GetComputerNameExW(format, wide.data(), &length)) {
            return {};
        }
        wide.resize(length);
        return wide;
    };

    std::wstring wide = read_wide_name(ComputerNamePhysicalDnsHostname);
    if (wide.empty()) {
        wide = read_wide_name(ComputerNameNetBIOS);
    }
    if (wide.empty()) {
        DWORD length = MAX_COMPUTERNAME_LENGTH + 1;
        std::wstring fallback(length, L'\0');
        if (GetComputerNameW(fallback.data(), &length)) {
            fallback.resize(length);
            wide = std::move(fallback);
        }
    }
    if (wide.empty()) {
        return {};
    }
    const int needed = WideCharToMultiByte(CP_UTF8,
                                           WC_ERR_INVALID_CHARS,
                                           wide.data(),
                                           static_cast<int>(wide.size()),
                                           nullptr,
                                           0,
                                           nullptr,
                                           nullptr);
    if (needed <= 0) {
        return {};
    }
    std::string utf8(static_cast<std::size_t>(needed), '\0');
    const int converted = WideCharToMultiByte(CP_UTF8,
                                              WC_ERR_INVALID_CHARS,
                                              wide.data(),
                                              static_cast<int>(wide.size()),
                                              utf8.data(),
                                              needed,
                                              nullptr,
                                              nullptr);
    if (converted <= 0) {
        return {};
    }
    return utf8;
#else
    std::array<char, 256> buffer{};
    if (::gethostname(buffer.data(), buffer.size()) == 0) {
        buffer.back() = '\0';
        std::string result(buffer.data());
        if (!result.empty()) {
            return result;
        }
    }
    struct utsname info{};
    if (::uname(&info) == 0) {
        info.nodename[sizeof(info.nodename) - 1] = '\0';
        return std::string(info.nodename);
    }
    return {};
#endif
}

} // namespace

std::string sanitize_machine_name(std::string_view raw) {
    while (!raw.empty() &&
           is_ascii_whitespace(static_cast<unsigned char>(raw.front()))) {
        raw.remove_prefix(1);
    }
    while (!raw.empty() &&
           is_ascii_whitespace(static_cast<unsigned char>(raw.back()))) {
        raw.remove_suffix(1);
    }

    std::string sanitized;
    sanitized.reserve(std::min(raw.size(), maximum_machine_name_bytes));
    std::size_t offset = 0;
    while (offset < raw.size()) {
        std::uint32_t codepoint = 0;
        const std::size_t seq_len =
            decode_utf8_codepoint(raw.substr(offset), codepoint);
        if (seq_len == 0) {
            ++offset;
            continue;
        }
        const bool is_control = codepoint < 0x20U || codepoint == 0x7FU ||
                                (codepoint >= 0x80U && codepoint <= 0x9FU);
        if (is_control) {
            if (!sanitized.empty() && sanitized.back() != ' ' &&
                sanitized.size() < maximum_machine_name_bytes) {
                sanitized.push_back(' ');
            }
            offset += seq_len;
            continue;
        }
        if (sanitized.size() + seq_len > maximum_machine_name_bytes) {
            break;
        }
        sanitized.append(raw.substr(offset, seq_len));
        offset += seq_len;
    }

    while (!sanitized.empty() &&
           is_ascii_whitespace(static_cast<unsigned char>(sanitized.back()))) {
        sanitized.pop_back();
    }
    return sanitized.empty() ? std::string{"unknown"} : sanitized;
}

std::string host_name() {
    return sanitize_machine_name(query_os_host_name());
}

} // namespace kasumi::platform::machine
