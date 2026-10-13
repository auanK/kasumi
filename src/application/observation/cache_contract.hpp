#ifndef KASUMI_APPLICATION_OBSERVATION_CACHE_CONTRACT_HPP
#define KASUMI_APPLICATION_OBSERVATION_CACHE_CONTRACT_HPP

#include <cstdint>
#include <optional>
#include <string_view>

namespace kasumi::application::observation::cache {

// File system entry kind.
enum class EntryKind : std::uint8_t {
    RegularFile = 1,
    Directory = 2,
    Symlink = 3,
    Other = 4
};

// 192-bit file system identity (volume + 128-bit file ID).
// On Linux: volume = st_dev, file_low = st_ino, file_high = 0.
// On Windows: volume = VolumeSerialNumber, file_low/file_high = FILE_ID_128.
struct FileIdentity {
    std::uint64_t volume = 0;
    std::uint64_t file_low = 0;
    std::uint64_t file_high = 0;

    constexpr bool operator==(const FileIdentity&) const = default;
};

// Detailed outcome of evaluating cache reuse.
enum class CacheReuseResult : std::uint8_t {
    Reusable = 0,
    InvalidCachedEntry,
    InvalidCurrentMetadata,
    PathMismatch,
    NotRegularFile,
    SizeMismatch,
    MtimeMismatch,
    IdentityMismatch,
    MissingRequiredIdentity
};

// Formats the decision outcome as a human-readable string.
const char* describe_result(CacheReuseResult result) noexcept;

// Unified format-independent file metadata.
// Defaults are explicitly invalid to prevent uninitialized / partial reuse.
struct FileMetadata {
    std::string_view path{};
    EntryKind kind = EntryKind::Other;
    std::uint64_t size = 0;
    std::int64_t mtime_nanoseconds = 0;
    std::optional<FileIdentity> identity = std::nullopt;
    bool is_valid = false;
};

// Pure decision function: evaluates whether cached entry can be reused for current file.
CacheReuseResult evaluate_cache_reuse(
    const FileMetadata& cached,
    const FileMetadata& current) noexcept;

// Convenience boolean predicate.
inline bool can_reuse_cached_hash(
    const FileMetadata& cached,
    const FileMetadata& current) noexcept {
    return evaluate_cache_reuse(cached, current) == CacheReuseResult::Reusable;
}

} // namespace kasumi::application::observation::cache

#endif
