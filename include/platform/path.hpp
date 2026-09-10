#ifndef KASUMI_PLATFORM_PATH_HPP
#define KASUMI_PLATFORM_PATH_HPP

#include <cstring>
#include <filesystem>
#include <string>
#include <string_view>

namespace kasumi::platform::path {

namespace detail {

inline std::string utf8_bytes(std::u8string_view value) {
    std::string result(value.size(), '\0');
    if (!value.empty()) {
        std::memcpy(result.data(), value.data(), value.size());
    }
    return result;
}

} // namespace detail

inline std::string to_logical_utf8(const std::filesystem::path& value) {
    return detail::utf8_bytes(value.generic_u8string());
}

inline std::string to_utf8(const std::filesystem::path& value) {
    return detail::utf8_bytes(value.u8string());
}

inline std::filesystem::path from_utf8(std::string_view value) {
    std::u8string bytes(value.size(), u8'\0');
    if (!value.empty()) {
        std::memcpy(bytes.data(), value.data(), value.size());
    }
    return std::filesystem::path{bytes};
}

inline std::filesystem::path
temporary_sibling_path(const std::filesystem::path& destination,
                       std::string_view prefix,
                       std::string_view suffix) {
    auto filename = from_utf8(prefix).native();
    filename += destination.filename().native();
    filename += from_utf8(suffix).native();
    return destination.parent_path() / std::filesystem::path{filename};
}

} // namespace kasumi::platform::path

#endif
