#ifndef KASUMI_PLATFORM_FOLDER_ICON_HPP
#define KASUMI_PLATFORM_FOLDER_ICON_HPP

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace kasumi::platform {

struct ThumbnailResult {
    std::vector<std::uint8_t> bytes;
    std::string_view mime;
};

// Extracts the OS shell or desktop.ini folder icon as PNG bytes.
// When resource_path is empty, queries the OS shell icon for folder_path
// (handling Windows Known Folders such as Pictures or Screenshots).
// Rejects path traversal ("..") and non-icon binary/file extensions.
std::optional<std::vector<std::uint8_t>>
extract_folder_icon_png(const std::filesystem::path& folder_path,
                        std::optional<std::string_view> resource_path,
                        std::optional<int> resource_index);

// Decodes and downscales an encoded raster image to fit within max_dimension,
// never upscaling. Returns std::nullopt when unsupported or invalid.
std::optional<ThumbnailResult>
scale_image_thumbnail(std::span<const std::uint8_t> encoded_image,
                      std::uint32_t max_dimension,
                      bool prefer_jpeg);

// Extracts an OS shell thumbnail (e.g., video keyframes or Shell-supported
// media formats) from a regular file and encodes it as JPEG.
std::optional<ThumbnailResult>
extract_shell_thumbnail(const std::filesystem::path& file_path,
                        std::uint32_t max_dimension);

} // namespace kasumi::platform

#endif
