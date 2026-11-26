#include "application/daemon/web_file.hpp"
#include "application/daemon/web_routes.hpp"
#include "core/hasher.hpp"
#include "core/node.hpp"
#include "platform/folder_icon.hpp"
#include "platform/path.hpp"
#include "runtime/resolver.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <condition_variable>
#include <filesystem>
#include <list>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace kasumi::application::daemon_detail {
namespace {
using namespace platform::private_storage;

runtime::RuntimeData resolve_local_runtime(const WebContext& ctx,
                                           const httplib::Request& req) {
    const auto name = req.matches[1].str();
    if (!runtime::is_valid_profile_name(name))
        throw HttpError{400, "invalid profile name"};
    auto resolved = runtime::resolve(ctx.environment.app_data_dir,
                                     name,
                                     runtime::AccessMode::ReadOnly,
                                     false);
    if (!resolved) {
        using ErrorCode = runtime::ErrorCode;
        if (resolved.error().code == ErrorCode::ProfileNotFound ||
            resolved.error().code == ErrorCode::ConfigNotFound)
            throw HttpError{404, "profile unavailable"};
        throw HttpError{422, "cannot resolve local synchronization map"};
    }
    return std::move(*resolved);
}

Json local_tree(const WebContext& ctx, const httplib::Request& req) {
    const auto resolved = resolve_local_runtime(ctx, req);
    const auto snapshot =
        state_storage::load_local_tree_snapshot(resolved.database_path);
    if (!snapshot)
        throw HttpError{422, "cannot read local synchronization map"};
    Json rows = Json::array();
    if (!snapshot->has_state)
        return {{"entries", std::move(rows)}};

    for (const auto& row : snapshot->entries) {
        rows.push_back({{"path", row.path},
                        {"type", row.is_directory ? "directory" : "file"},
                        {"size", row.is_directory ? 0 : row.size}});
    }
    Json result{{"entries", std::move(rows)},
                {"commit_id", snapshot->commit_id},
                {"height", snapshot->height}};
    if (snapshot->activity && snapshot->activity->accepted_commit &&
        snapshot->activity->accepted_commit->commit_id == snapshot->commit_id)
        result["created_at"] = snapshot->activity->accepted_commit->created_at;
    return result;
}

void local_download(const WebContext& ctx,
                    const httplib::Request& req,
                    httplib::Response& res) {
    const auto path = req.get_param_value("path");
    if (!valid_logical_path(path))
        throw HttpError{400, "invalid local path"};
    const auto resolved = resolve_local_runtime(ctx, req);
    const auto entry =
        state_storage::lookup_mapped_path(resolved.database_path, path);
    if (!entry)
        throw HttpError{422, "cannot read local synchronization map"};
    if (!*entry || (*entry)->is_directory)
        throw HttpError{404, "local file is not mapped"};
    const auto relative = platform::path::from_utf8(path);
    auto file =
        open_browsed_file(resolved.local_dir.lexically_normal(), relative);
    if (!file)
        throw HttpError{404, "local file is unavailable"};
    std::optional<FileSlice> slice;
    if (!prepare_file_range(req, res, file->size, slice))
        return;
    const auto size = file->size;
    set_file_stream(
        res, path, size, std::make_shared<RegularFileInput>(std::move(*file)));
}

struct ThumbnailMeta {
    bool supported = false;
    bool prefer_jpeg = false;
    bool is_video = false;
};

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

std::uint32_t parse_thumbnail_size(const httplib::Request& req) {
    if (!req.has_param("size"))
        return 160U;
    const auto raw = req.get_param_value("size");
    std::uint32_t parsed = 0;
    const auto [end, ec] =
        std::from_chars(raw.data(), raw.data() + raw.size(), parsed);
    if (ec != std::errc{} || end != raw.data() + raw.size())
        return 160U;
    return std::clamp<std::uint32_t>(parsed, 48U, 1400U);
}

struct CachedThumbEntry {
    std::int64_t mtime = 0;
    std::uint64_t file_size = 0;
    std::string mime;
    std::string bytes;
};

struct ThumbnailDecodeGate {
    std::mutex mutex;
    std::condition_variable cv;
    unsigned active = 0;
};

ThumbnailDecodeGate& thumbnail_decode_gate() {
    static ThumbnailDecodeGate gate;
    return gate;
}

struct ThumbnailDecodePermit {
    ThumbnailDecodeGate& gate;

    ThumbnailDecodePermit() : gate(thumbnail_decode_gate()) {
        std::unique_lock lock(gate.mutex);
        gate.cv.wait(lock, [&] { return gate.active < 4U; });
        ++gate.active;
    }

    ~ThumbnailDecodePermit() {
        {
            std::lock_guard lock(gate.mutex);
            if (gate.active > 0U)
                --gate.active;
        }
        gate.cv.notify_one();
    }

    ThumbnailDecodePermit(const ThumbnailDecodePermit&) = delete;
    ThumbnailDecodePermit& operator=(const ThumbnailDecodePermit&) = delete;
};

void serve_mapped_thumbnail(const WebContext& ctx,
                            const httplib::Request& req,
                            httplib::Response& res,
                            std::optional<std::string_view> expected_hash) {
    const auto path = req.get_param_value("path");
    if (!valid_logical_path(path))
        throw HttpError{400, "invalid local path"};
    if (expected_hash &&
        (expected_hash->size() != HASH_HEX_SIZE ||
         !is_lowercase_hex(*expected_hash))) {
        res.status = 204;
        return;
    }
    const auto meta = classify_thumbnail_ext(path);
    if (!meta.supported) {
        res.status = 204;
        return;
    }
    const auto resolved = resolve_local_runtime(ctx, req);
    const auto entry =
        state_storage::lookup_mapped_path(resolved.database_path, path);
    if (!entry)
        throw HttpError{422, "cannot read local synchronization map"};
    if (!*entry || (*entry)->is_directory) {
        if (expected_hash) {
            res.status = 204;
            return;
        }
        throw HttpError{404, "local file is not mapped"};
    }
    if (expected_hash && (*entry)->hash_hex != *expected_hash) {
        res.status = 204;
        return;
    }

    const auto relative = platform::path::from_utf8(path);
    const auto root = resolved.local_dir.lexically_normal();
    auto file = open_browsed_file(root, relative);
    if (!file) {
        if (expected_hash) {
            res.status = 204;
            return;
        }
        throw HttpError{404, "local file is unavailable"};
    }
    const auto full_path = root / relative;
    if (file->size == 0) {
        res.status = 204;
        return;
    }
    if (is_reparse_or_symlink(full_path)) {
        if (expected_hash) {
            res.status = 204;
            return;
        }
        throw HttpError{404, "local file is unavailable"};
    }
    constexpr std::uint64_t kMaxRasterSourceBytes = 32ULL * 1024ULL * 1024ULL;
    const bool use_shell_directly =
        meta.is_video || file->size > kMaxRasterSourceBytes;

    const auto target_size = parse_thumbnail_size(req);
    std::error_code ec;
    const auto lwt = std::filesystem::last_write_time(full_path, ec);
    const std::int64_t mtime =
        ec ? 0 : static_cast<std::int64_t>(lwt.time_since_epoch().count());

    static std::mutex cache_mutex;
    static std::unordered_map<std::string, CachedThumbEntry> cache;
    static std::list<std::string> cache_order;
    static std::size_t cache_total_bytes = 0;
    constexpr std::size_t kMaxCacheEntries = 192U;
    constexpr std::size_t kMaxCacheBytes = 24ULL * 1024ULL * 1024ULL;

    const std::string key = req.matches[1].str() + "|" + path + "|" +
                            std::to_string(target_size);
    {
        std::lock_guard lock(cache_mutex);
        if (const auto it = cache.find(key);
            it != cache.end() && it->second.mtime == mtime &&
            it->second.file_size == file->size) {
            res.headers.erase("Cache-Control");
            res.set_header("Cache-Control", "private, max-age=300");
            res.headers.erase("Content-Security-Policy");
            res.set_header("Content-Security-Policy",
                           "sandbox; default-src 'none'");
            res.set_content(it->second.bytes, it->second.mime);
            return;
        }
    }

    std::optional<platform::ThumbnailResult> scaled;
    {
        ThumbnailDecodePermit permit;
        if (use_shell_directly) {
            scaled = platform::extract_shell_thumbnail(full_path, target_size);
        } else {
            std::vector<std::uint8_t> raw(static_cast<std::size_t>(file->size));
            if (!read_regular_file_exact(*file, raw)) {
                res.status = 204;
                return;
            }
            scaled = platform::scale_image_thumbnail(
                raw, target_size, meta.prefer_jpeg);
            if (!scaled) {
                scaled =
                    platform::extract_shell_thumbnail(full_path, target_size);
            }
        }
    }
    if (!scaled) {
        res.status = 204;
        return;
    }
    std::string body(reinterpret_cast<const char*>(scaled->bytes.data()),
                     scaled->bytes.size());
    std::string mime(scaled->mime);

    {
        std::lock_guard lock(cache_mutex);
        if (const auto old = cache.find(key); old != cache.end()) {
            cache_total_bytes -= old->second.bytes.size();
            cache_order.remove(key);
            cache.erase(old);
        }
        cache_total_bytes += body.size();
        cache.insert_or_assign(
            key,
            CachedThumbEntry{
                .mtime = mtime,
                .file_size = file->size,
                .mime = mime,
                .bytes = body,
            });
        cache_order.push_back(key);
        while ((cache.size() > kMaxCacheEntries ||
                cache_total_bytes > kMaxCacheBytes) &&
               !cache_order.empty()) {
            const auto oldest_key = std::move(cache_order.front());
            cache_order.pop_front();
            if (const auto doomed = cache.find(oldest_key);
                doomed != cache.end()) {
                cache_total_bytes -= doomed->second.bytes.size();
                cache.erase(doomed);
            }
        }
    }

    res.headers.erase("Cache-Control");
    res.set_header("Cache-Control", "private, max-age=300");
    res.headers.erase("Content-Security-Policy");
    res.set_header("Content-Security-Policy", "sandbox; default-src 'none'");
    res.set_content(std::move(body), std::move(mime));
}
} // namespace

void register_local_routes(httplib::Server& server, const WebContext& ctx) {
    server.Get("/v1/local/([^/]+)/tree", json_route([ctx](const auto& req) {
                   return local_tree(ctx, req);
               }));
    server.Get("/v1/local/([^/]+)/download", [ctx](const auto& req, auto& res) {
        local_download(ctx, req, res);
    });
    server.Get("/v1/local/([^/]+)/thumbnail",
               [ctx](const auto& req, auto& res) {
                   serve_mapped_thumbnail(ctx, req, res, std::nullopt);
               });
    server.Get("/v1/remote/([^/]+)/thumbnail",
               [ctx](const auto& req, auto& res) {
                   if (!req.has_param("hash")) {
                       res.status = 204;
                       return;
                   }
                   serve_mapped_thumbnail(
                       ctx, req, res, req.get_param_value("hash"));
               });
}
} // namespace kasumi::application::daemon_detail
