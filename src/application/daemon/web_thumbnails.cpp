#include "application/daemon/web_thumbnails.hpp"

#include "core/hasher.hpp"
#include "platform/folder_icon.hpp"
#include "platform/private_storage.hpp"

#include <algorithm>
#include <cctype>
#include <utility>
#include <vector>

namespace kasumi::application::daemon_detail {
namespace {

bool valid_thumb_hash(std::string_view hash) noexcept {
    return is_lowercase_hex(hash);
}

std::size_t combine_hash(std::size_t seed, std::size_t value) noexcept {
    return seed ^ (value + 0x9e3779b97f4a7c15ULL + (seed << 6U) + (seed >> 2U));
}

} // namespace

ThumbnailMeta classify_thumbnail_ext(std::string_view path) {
    const auto slash = path.find_last_of('/');
    const auto dot = path.find_last_of('.');
    if (dot == path.npos || (slash != path.npos && dot < slash))
        return {};
    std::string ext(path.substr(dot));
    std::ranges::transform(ext, ext.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    if (ext == ".jpg" || ext == ".jpeg" || ext == ".jfif")
        return {.supported = true, .prefer_jpeg = true};
    if (ext == ".png" || ext == ".webp" || ext == ".bmp" || ext == ".gif" ||
        ext == ".ico" || ext == ".cur" || ext == ".tif" || ext == ".tiff" ||
        ext == ".avif")
        return {.supported = true, .prefer_jpeg = false};
    if (ext == ".mp4" || ext == ".mov" || ext == ".webm" || ext == ".mkv" ||
        ext == ".m4v" || ext == ".ogv" || ext == ".avi")
        return {.supported = true, .prefer_jpeg = true, .is_video = true};
    return {};
}

std::size_t RemoteThumbnailKeyHash::operator()(
    const RemoteThumbnailKey& key) const noexcept {
    std::size_t seed = std::hash<std::string>{}(key.logical_hash);
    seed = combine_hash(seed, std::hash<std::uint32_t>{}(key.size));
    return seed;
}

std::optional<RemoteThumbnailValue>
lookup_remote_thumbnail(RemoteThumbnailCache& cache,
                        std::string_view logical_hash,
                        std::uint32_t size) {
    if (!valid_thumb_hash(logical_hash)) {
        return std::nullopt;
    }
    std::lock_guard lock(cache.mutex);
    const RemoteThumbnailKey key{
        .logical_hash = std::string{logical_hash},
        .size = size,
    };
    const auto it = cache.entries.find(key);
    if (it == cache.entries.end()) {
        return std::nullopt;
    }
    cache.lru_order.splice(
        cache.lru_order.begin(), cache.lru_order, it->second.lru_it);
    return it->second.value;
}

bool has_remote_thumbnail(RemoteThumbnailCache& cache,
                          std::string_view logical_hash,
                          std::uint32_t size) {
    if (!valid_thumb_hash(logical_hash)) {
        return false;
    }
    std::lock_guard lock(cache.mutex);
    const RemoteThumbnailKey key{
        .logical_hash = std::string{logical_hash},
        .size = size,
    };
    return cache.entries.contains(key);
}

void store_remote_thumbnail(RemoteThumbnailCache& cache,
                            std::string_view logical_hash,
                            std::uint32_t size,
                            std::string mime,
                            std::string bytes) {
    if (!valid_thumb_hash(logical_hash) || bytes.empty() ||
        cache.max_entries == 0 || cache.max_bytes == 0 ||
        bytes.size() > cache.max_bytes) {
        return;
    }
    try {
        std::lock_guard lock(cache.mutex);
        const RemoteThumbnailKey key{
            .logical_hash = std::string{logical_hash},
            .size = size,
        };
        if (const auto existing = cache.entries.find(key);
            existing != cache.entries.end()) {
            cache.current_bytes -= existing->second.value.bytes.size();
            cache.lru_order.erase(existing->second.lru_it);
            cache.entries.erase(existing);
        }
        const auto byte_size = bytes.size();
        while (!cache.lru_order.empty() &&
               (cache.entries.size() >= cache.max_entries ||
                cache.current_bytes + byte_size > cache.max_bytes)) {
            const auto victim_key = cache.lru_order.back();
            cache.lru_order.pop_back();
            if (const auto victim = cache.entries.find(victim_key);
                victim != cache.entries.end()) {
                cache.current_bytes -= victim->second.value.bytes.size();
                cache.entries.erase(victim);
            }
        }
        cache.lru_order.push_front(key);
        cache.current_bytes += byte_size;
        cache.entries.emplace(
            key,
            RemoteThumbnailEntry{
                .value = RemoteThumbnailValue{.mime = std::move(mime),
                                              .bytes = std::move(bytes)},
                .lru_it = cache.lru_order.begin(),
            });
    } catch (...) {
    }
}

void clear_remote_thumbnail_cache(RemoteThumbnailCache& cache) noexcept {
    std::lock_guard lock(cache.mutex);
    cache.entries.clear();
    cache.lru_order.clear();
    cache.current_bytes = 0;
}

void try_cache_grid_thumbnail_from_bytes(
    RemoteThumbnailCache& cache,
    std::string_view path,
    std::string_view logical_hash,
    std::span<const std::uint8_t> raw_bytes) noexcept {
    try {
        if (!valid_thumb_hash(logical_hash) || raw_bytes.empty() ||
            raw_bytes.size() > kMaxRemotePreviewThumbSourceBytes) {
            return;
        }
        const auto meta = classify_thumbnail_ext(path);
        if (!meta.supported || meta.is_video) {
            return;
        }
        if (has_remote_thumbnail(cache, logical_hash, kGridThumbnailSize)) {
            return;
        }
        const auto scaled = platform::scale_image_thumbnail(
            raw_bytes, kGridThumbnailSize, meta.prefer_jpeg);
        if (!scaled || scaled->bytes.empty()) {
            return;
        }
        std::string body(reinterpret_cast<const char*>(scaled->bytes.data()),
                         scaled->bytes.size());
        store_remote_thumbnail(cache,
                               logical_hash,
                               kGridThumbnailSize,
                               std::string{scaled->mime},
                               std::move(body));
    } catch (...) {
    }
}

void try_cache_grid_thumbnail_from_file(
    RemoteThumbnailCache& cache,
    std::string_view path,
    std::string_view logical_hash,
    const std::filesystem::path& file_path,
    std::uint64_t file_size) noexcept {
    try {
        if (!valid_thumb_hash(logical_hash) || file_size == 0 ||
            file_size > kMaxRemotePreviewThumbSourceBytes) {
            return;
        }
        const auto meta = classify_thumbnail_ext(path);
        if (!meta.supported || meta.is_video) {
            return;
        }
        if (has_remote_thumbnail(cache, logical_hash, kGridThumbnailSize)) {
            return;
        }
        auto input = platform::private_storage::open_regular_file(file_path);
        if (!input || input->size != file_size) {
            return;
        }
        std::vector<std::uint8_t> raw(static_cast<std::size_t>(file_size));
        if (!platform::private_storage::read_regular_file_exact(*input, raw)) {
            return;
        }
        try_cache_grid_thumbnail_from_bytes(cache, path, logical_hash, raw);
    } catch (...) {
    }
}

} // namespace kasumi::application::daemon_detail
