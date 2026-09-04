#ifndef KASUMI_PLATFORM_FILE_FINGERPRINT_HPP
#define KASUMI_PLATFORM_FILE_FINGERPRINT_HPP

#include <array>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>

namespace kasumi::platform {

// File system identity formats.
enum class FileFingerprintKind : std::uint8_t {
    WindowsFileIdentity = 1,
    PosixFileIdentity = 2
};

// File identity used for hash reuse.
struct FileFingerprint {
    FileFingerprintKind kind{};
    // Components defined by the format indicated by kind.
    std::array<std::uint64_t, 4> value{};
};

// Optional result of reading file identity.
using FileFingerprintResult =
    std::expected<std::optional<FileFingerprint>, std::string>;

// Returns std::nullopt when identity cannot be securely determined.
FileFingerprintResult
regular_file_fingerprint(const std::filesystem::path& path);

// Returns the native directory reference, when available.
std::expected<std::optional<std::uint64_t>, std::string>
directory_file_reference(const std::filesystem::path& path);

} // namespace kasumi::platform

#endif
