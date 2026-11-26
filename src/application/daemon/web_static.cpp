#include "application/daemon/web_static.hpp"

#include "application/webui_embedded.hpp"

#include <algorithm>
#include <string>
#include <string_view>

namespace kasumi::application::daemon_detail {
namespace {

const webui_embedded::Asset* find_asset(std::string_view path) noexcept {
    const auto all = webui_embedded::assets();
    const auto it = std::ranges::find(all, path, &webui_embedded::Asset::path);
    return it == all.end() ? nullptr : &(*it);
}

void write_asset(httplib::Response& res, const webui_embedded::Asset& asset) {
    res.status = 200;
    if (asset.immutable) {
        res.set_header("Cache-Control", "public, max-age=31536000, immutable");
    } else {
        res.set_header("Cache-Control", "no-store");
    }
    res.set_content(reinterpret_cast<const char*>(asset.data.data()),
                    asset.data.size(),
                    std::string{asset.content_type});
}

bool is_api_path(std::string_view path) noexcept {
    return path == "/v1" || path.starts_with("/v1/");
}

bool is_safe_static_path(std::string_view path) noexcept {
    if (path.empty() || path.front() != '/' || path.size() > 512)
        return false;
    if (path.find("..") != std::string_view::npos ||
        path.find("//") != std::string_view::npos ||
        path.find('\\') != std::string_view::npos)
        return false;
    for (const char raw_ch : path) {
        const auto ch = static_cast<unsigned char>(raw_ch);
        if (ch < 0x20 || ch == 0x7f)
            return false;
    }
    return true;
}

bool is_static_asset_path(std::string_view path) noexcept {
    return path.starts_with("/assets/") || path == "/favicon.ico";
}

} // namespace

void register_web_static_routes(httplib::Server& server) {
    server.Get(
        R"(/(.*))", [](const httplib::Request& req, httplib::Response& res) {
            if (!is_safe_static_path(req.path)) {
                res.status = 400;
                res.set_content("bad request", "text/plain; charset=utf-8");
                return;
            }
            if (is_api_path(req.path)) {
                res.status = 404;
                res.set_content(R"({"error":"not found"})", "application/json");
                return;
            }
            if (!webui_embedded::kAvailable) {
                res.status = 503;
                res.set_content(
                    "<!doctype html><meta "
                    "charset=\"utf-8\"><title>Kasumi</title>"
                    "<body><h1>Kasumi Web UI not bundled</h1>"
                    "<p>This binary was built without embedded Web UI assets. "
                    "Build <code>web/</code> with <code>npm run build</code> "
                    "and reconfigure with "
                    "<code>-DKASUMI_ENABLE_WEBUI=ON</code>.</p></body>",
                    "text/html; charset=utf-8");
                return;
            }

            const std::string_view lookup =
                req.path == "/" ? "/index.html" : std::string_view{req.path};
            if (const auto* asset = find_asset(lookup)) {
                write_asset(res, *asset);
                return;
            }
            if (is_static_asset_path(req.path)) {
                res.status = 404;
                res.set_content("not found", "text/plain; charset=utf-8");
                return;
            }
            if (const auto* index = find_asset("/index.html")) {
                write_asset(res, *index);
                return;
            }
            res.status = 404;
            res.set_content("not found", "text/plain; charset=utf-8");
        });
}

} // namespace kasumi::application::daemon_detail
