#ifndef KASUMI_PLATFORM_METADATA_HPP
#define KASUMI_PLATFORM_METADATA_HPP

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>

namespace kasumi::platform::metadata {

// Converts filesystem-clock time to canonical Unix nanoseconds; zero is the
// existing unspecified timestamp sentinel.
std::optional<std::int64_t>
unix_nanoseconds(std::filesystem::file_time_type value) noexcept;

// Converts canonical Unix nanoseconds to the nearest supported file-clock
// value. Zero maps to the unspecified sentinel.
std::optional<std::filesystem::file_time_type>
file_time_from_unix_nanoseconds(std::int64_t value) noexcept;

// Whether two canonical timestamps materialize to the same filesystem time.
bool filesystem_equivalent(std::int64_t left_ns,
                           std::int64_t right_ns) noexcept;

// Sets and verifies last write time; rejects symbolic links.
std::expected<void, std::string>
set_last_write_time(const std::filesystem::path& path,
                    std::filesystem::file_time_type value);

} // namespace kasumi::platform::metadata

#endif
