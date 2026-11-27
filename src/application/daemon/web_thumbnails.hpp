#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <list>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

namespace kasumi::application::daemon_detail {

struct ThumbnailMeta {
    bool supported = false;
    bool prefer_jpeg = false;
    bool is_video = false;
};

ThumbnailMeta classify_thumbnail_ext(std::string_view path);

inline constexpr std::uint32_t kGridThumbnailSize = 160U;
inline constexpr std::uint64_t kMaxRemoteGridThumbSourceBytes =
    5ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t kMaxRemotePreviewThumbSourceBytes =
    32ULL * 1024ULL * 1024ULL;

struct RemoteThumbnailKey {
    std::string logical_hash;
    std::uint32_t size = kGridThumbnailSize;

    bool operator==(const RemoteThumbnailKey&) const noexcept = default;
};

struct RemoteThumbnailKeyHash {
    std::size_t operator()(const RemoteThumbnailKey& key) const noexcept;
};

struct RemoteThumbnailValue {
    std::string mime;
    std::string bytes;
};

struct RemoteThumbnailEntry {
    RemoteThumbnailValue value;
    std::list<RemoteThumbnailKey>::iterator lru_it;
};

// Bounded in-memory LRU cache of already-scaled thumbnails keyed by
// immutable (logical_hash, size). Cleared immediately on profile lock or key
// change and never stores unencrypted image bytes on disk.
struct RemoteThumbnailCache {
    std::mutex mutex;
    std::size_t max_entries = 512U;
    std::size_t max_bytes = 32ULL * 1024ULL * 1024ULL;
    std::size_t current_bytes = 0;
    std::list<RemoteThumbnailKey> lru_order;
    std::unordered_map<RemoteThumbnailKey,
                       RemoteThumbnailEntry,
                       RemoteThumbnailKeyHash>
        entries;
};

std::optional<RemoteThumbnailValue>
lookup_remote_thumbnail(RemoteThumbnailCache& cache,
                        std::string_view logical_hash,
                        std::uint32_t size);

bool has_remote_thumbnail(RemoteThumbnailCache& cache,
                          std::string_view logical_hash,
                          std::uint32_t size);

void store_remote_thumbnail(RemoteThumbnailCache& cache,
                            std::string_view logical_hash,
                            std::uint32_t size,
                            std::string mime,
                            std::string bytes);

void clear_remote_thumbnail_cache(RemoteThumbnailCache& cache) noexcept;

void try_cache_grid_thumbnail_from_bytes(
    RemoteThumbnailCache& cache,
    std::string_view path,
    std::string_view logical_hash,
    std::span<const std::uint8_t> raw_bytes) noexcept;

void try_cache_grid_thumbnail_from_file(
    RemoteThumbnailCache& cache,
    std::string_view path,
    std::string_view logical_hash,
    const std::filesystem::path& file_path,
    std::uint64_t file_size) noexcept;

} // namespace kasumi::application::daemon_detail
