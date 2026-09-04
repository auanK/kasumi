#ifndef KASUMI_PLATFORM_DURABILITY_HPP
#define KASUMI_PLATFORM_DURABILITY_HPP

#include <expected>
#include <filesystem>
#include <string>
#include <string_view>

namespace kasumi::platform::durability {

// Flushes file data to durable storage.
std::expected<void, std::string> sync_file(const std::filesystem::path& path);

// Flushes parent directory when supported by the platform.
std::expected<void, std::string>
sync_parent_directory(const std::filesystem::path& path);

// Atomically replaces target with source.
std::expected<void, std::string>
replace_atomically(const std::filesystem::path& source,
                   const std::filesystem::path& target);

} // namespace kasumi::platform::durability

#endif
