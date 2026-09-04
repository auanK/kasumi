#ifndef KASUMI_PLATFORM_PRIVATE_STORAGE_HPP
#define KASUMI_PLATFORM_PRIVATE_STORAGE_HPP

#include <expected>
#include <filesystem>
#include <string>
#include <string_view>

namespace kasumi::platform::private_storage {

std::expected<void, std::string>
create_directory(const std::filesystem::path& path);

std::expected<void, std::string>
ensure_directory(const std::filesystem::path& path);

std::expected<void, std::string>
protect_directory(const std::filesystem::path& path);

std::expected<void, std::string>
protect_tree(const std::filesystem::path& root);

std::expected<void, std::string> create_file(const std::filesystem::path& path);

std::expected<void, std::string>
protect_file(const std::filesystem::path& path);

std::expected<void, std::string>
write_atomically(const std::filesystem::path& path, std::string_view bytes);

} // namespace kasumi::platform::private_storage

#endif
