#ifndef KASUMI_PLATFORM_METADATA_HPP
#define KASUMI_PLATFORM_METADATA_HPP

#include <expected>
#include <filesystem>
#include <string>

namespace kasumi::platform::metadata {

// Sets and verifies last write time; rejects symbolic links.
std::expected<void, std::string>
set_last_write_time(const std::filesystem::path& path,
                    std::filesystem::file_time_type value);

} // namespace kasumi::platform::metadata

#endif
