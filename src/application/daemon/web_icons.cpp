#include "application/daemon/web_icons.hpp"

#include "application/daemon/web_http.hpp"
#include "core/hasher.hpp"
#include "core/node.hpp"
#include "platform/folder_icon.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "runtime/paths.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <filesystem>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <vector>

namespace kasumi::application::daemon_detail {
namespace {

std::mutex& custom_icon_mutex() {
    static std::mutex mutex;
    return mutex;
}

Profile find_icon_profile(const ExecutionEnvironment& env,
                          const std::string& name) {
    auto profiles = require(list_profiles(env));
    const auto it = std::ranges::find(profiles, name, &Profile::name);
    if (it == profiles.end())
        throw HttpError{404, "profile not found"};
    return *it;
}

std::string ascii_lower(std::string_view text) {
    std::string out(text);
    std::ranges::transform(out, out.begin(), [](char raw_ch) {
        return static_cast<char>(
            std::tolower(static_cast<unsigned char>(raw_ch)));
    });
    return out;
}

std::string_view trim_ascii(std::string_view text) {
    while (!text.empty() &&
           std::isspace(static_cast<unsigned char>(text.front())) != 0)
        text.remove_prefix(1);
    while (!text.empty() &&
           std::isspace(static_cast<unsigned char>(text.back())) != 0)
        text.remove_suffix(1);
    return text;
}

std::string decode_ini_bytes(const std::vector<std::uint8_t>& raw) {
    auto decode_utf16le = [&](std::size_t start) {
        std::string out;
        out.reserve(raw.size() / 2);
        for (std::size_t i = start; i + 1 < raw.size(); i += 2) {
            const auto ch = static_cast<std::uint16_t>(
                static_cast<unsigned>(raw[i]) |
                (static_cast<unsigned>(raw[i + 1]) << 8U));
            if (ch == 0)
                continue;
            if (ch < 0x80U) {
                out.push_back(static_cast<char>(ch));
            } else if (ch < 0x800U) {
                out.push_back(static_cast<char>(0xC0U | (ch >> 6)));
                out.push_back(static_cast<char>(0x80U | (ch & 0x3FU)));
            } else {
                out.push_back(static_cast<char>(0xE0U | (ch >> 12)));
                out.push_back(static_cast<char>(0x80U | ((ch >> 6) & 0x3FU)));
                out.push_back(static_cast<char>(0x80U | (ch & 0x3FU)));
            }
        }
        return out;
    };
    if (raw.size() >= 2 && raw[0] == 0xFF && raw[1] == 0xFE)
        return decode_utf16le(2);
    if (raw.size() >= 2 && raw.size() % 2 == 0 && raw[1] == 0x00 &&
        raw[0] != 0x00)
        return decode_utf16le(0);
    std::size_t offset = 0;
    if (raw.size() >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF)
        offset = 3;
    return std::string(reinterpret_cast<const char*>(raw.data() + offset),
                       raw.size() - offset);
}

struct IniIconValue {
    std::string value;
    std::optional<int> index;
};

bool parse_ini_int(std::string_view text, int& out) noexcept {
    if (text.empty())
        return false;
    bool neg = false;
    if (text.front() == '-') {
        neg = true;
        text.remove_prefix(1);
    } else if (text.front() == '+') {
        text.remove_prefix(1);
    }
    if (text.empty() || !std::ranges::all_of(text, [](char raw_ch) {
            return std::isdigit(static_cast<unsigned char>(raw_ch)) != 0;
        }))
        return false;
    long long acc = 0;
    for (const char raw_ch : text) {
        const auto ch = static_cast<unsigned char>(raw_ch);
        acc = acc * 10 + (ch - '0');
        if (acc > 100000000LL)
            return false;
    }
    out = static_cast<int>(neg ? -acc : acc);
    return true;
}

std::optional<IniIconValue>
extract_ini_section_value(std::string_view ini,
                          std::string_view target_section,
                          std::initializer_list<std::string_view> target_keys,
                          bool parse_resource_index) {
    bool in_section = false;
    std::optional<std::string> found_value;
    std::optional<int> found_index;
    std::optional<int> separate_icon_index;
    std::size_t pos = 0;
    while (pos <= ini.size()) {
        const auto next = ini.find('\n', pos);
        const auto len = next == ini.npos ? ini.size() - pos : next - pos;
        auto line = trim_ascii(ini.substr(pos, len));
        pos = next == ini.npos ? ini.size() + 1 : next + 1;
        if (line.empty() || line.front() == ';' || line.front() == '#')
            continue;
        if (line.front() == '[' && line.back() == ']') {
            in_section =
                ascii_lower(trim_ascii(line.substr(1, line.size() - 2))) ==
                target_section;
            continue;
        }
        if (!in_section)
            continue;
        const auto eq = line.find('=');
        if (eq == line.npos)
            continue;
        const auto key = ascii_lower(trim_ascii(line.substr(0, eq)));
        auto val = trim_ascii(line.substr(eq + 1));
        if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
            val = val.substr(1, val.size() - 2);
        if (parse_resource_index && key == "iconindex") {
            int parsed = 0;
            if (parse_ini_int(val, parsed))
                separate_icon_index = parsed;
            continue;
        }
        if (found_value)
            continue;
        if (std::ranges::find(target_keys, std::string_view(key)) ==
            target_keys.end())
            continue;
        std::optional<int> inline_index;
        if (parse_resource_index) {
            const auto comma = val.rfind(',');
            if (comma != val.npos) {
                const auto suffix = trim_ascii(val.substr(comma + 1));
                int parsed = 0;
                if (parse_ini_int(suffix, parsed)) {
                    inline_index = parsed;
                    val = trim_ascii(val.substr(0, comma));
                }
            }
        }
        if (!val.empty()) {
            found_value = std::string(val);
            found_index = inline_index;
        }
    }
    if (!found_value)
        return std::nullopt;
    return IniIconValue{std::move(*found_value),
                        found_index ? found_index : separate_icon_index};
}

bool contains_traversal_component(std::string_view raw) noexcept {
    std::size_t start = 0;
    while (start <= raw.size()) {
        const auto sep = raw.find_first_of("/\\", start);
        const auto len = sep == raw.npos ? raw.size() - start : sep - start;
        if (raw.substr(start, len) == "..")
            return true;
        if (sep == raw.npos)
            break;
        start = sep + 1;
    }
    return false;
}

bool has_allowed_icon_extension(std::string_view rel) {
    const auto dot = rel.find_last_of('.');
    const auto slash = rel.find_last_of('/');
    if (dot == rel.npos || (slash != rel.npos && dot < slash))
        return false;
    const auto ext = ascii_lower(rel.substr(dot));
    return ext == ".png" || ext == ".ico" || ext == ".webp" || ext == ".jpg" ||
           ext == ".jpeg" || ext == ".bmp";
}

struct ImageFormatInfo {
    std::string_view ext;
    std::string_view mime;
};

std::optional<ImageFormatInfo>
detect_icon_image_format(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.size() >= 8 && bytes[0] == 0x89 && bytes[1] == 'P' &&
        bytes[2] == 'N' && bytes[3] == 'G' && bytes[4] == '\r' &&
        bytes[5] == '\n' && bytes[6] == 0x1A && bytes[7] == '\n') {
        return ImageFormatInfo{".png", "image/png"};
    }
    if (bytes.size() >= 4 && bytes[0] == 0x00 && bytes[1] == 0x00 &&
        bytes[2] == 0x01 && bytes[3] == 0x00) {
        return ImageFormatInfo{".ico", "image/x-icon"};
    }
    if (bytes.size() >= 3 && bytes[0] == 0xFF && bytes[1] == 0xD8 &&
        bytes[2] == 0xFF) {
        return ImageFormatInfo{".jpg", "image/jpeg"};
    }
    if (bytes.size() >= 12 && bytes[0] == 'R' && bytes[1] == 'I' &&
        bytes[2] == 'F' && bytes[3] == 'F' && bytes[8] == 'W' &&
        bytes[9] == 'E' && bytes[10] == 'B' && bytes[11] == 'P') {
        return ImageFormatInfo{".webp", "image/webp"};
    }
    if (bytes.size() >= 2 && bytes[0] == 'B' && bytes[1] == 'M') {
        return ImageFormatInfo{".bmp", "image/bmp"};
    }
    return std::nullopt;
}

std::optional<std::vector<std::uint8_t>>
decode_base64(std::string_view input) {
    static constexpr auto decode_char = [](unsigned char ch) -> int {
        if (ch >= 'A' && ch <= 'Z')
            return ch - 'A';
        if (ch >= 'a' && ch <= 'z')
            return ch - 'a' + 26;
        if (ch >= '0' && ch <= '9')
            return ch - '0' + 52;
        if (ch == '+')
            return 62;
        if (ch == '/')
            return 63;
        return -1;
    };
    if (input.empty() || input.size() % 4 != 0)
        return std::nullopt;
    std::vector<std::uint8_t> out;
    out.reserve((input.size() / 4) * 3);
    for (std::size_t i = 0; i < input.size(); i += 4) {
        int v[4]{};
        int pad = 0;
        for (std::size_t j = 0; j < 4; ++j) {
            const unsigned char ch = static_cast<unsigned char>(input[i + j]);
            if (ch == '=') {
                if (j < 2 || (j == 2 && input[i + 3] != '='))
                    return std::nullopt;
                v[j] = 0;
                ++pad;
            } else {
                if (pad > 0)
                    return std::nullopt;
                v[j] = decode_char(ch);
                if (v[j] < 0)
                    return std::nullopt;
            }
        }
        out.push_back(static_cast<std::uint8_t>((v[0] << 2) | (v[1] >> 4)));
        if (pad < 2)
            out.push_back(
                static_cast<std::uint8_t>(((v[1] & 0x0F) << 4) | (v[2] >> 2)));
        if (pad == 0)
            out.push_back(
                static_cast<std::uint8_t>(((v[2] & 0x03) << 6) | v[3]));
    }
    return out;
}

constexpr std::array<std::string_view, 5> kCustomIconExts{
    ".png", ".ico", ".webp", ".jpg", ".bmp"};

std::optional<std::string> normalize_safe_relative_icon(std::string_view raw) {
    raw = trim_ascii(raw);
    if (raw.empty() || raw.find('%') != raw.npos ||
        raw.find('\0') != raw.npos)
        return std::nullopt;
    std::string norm;
    norm.reserve(raw.size());
    for (char ch : raw)
        norm.push_back(ch == '\\' ? '/' : ch);
    while (norm.starts_with("./"))
        norm.erase(0, 2);
    if (norm.empty() || norm.front() == '/' || norm.find(':') != norm.npos ||
        contains_traversal_component(norm))
        return std::nullopt;
    if (!valid_logical_path(norm))
        return std::nullopt;
    return norm;
}

struct CachedFolderIcon {
    std::string ini_hash;
    std::uint64_t ini_size = 0;
    bool has_png = false;
    std::string png_bytes;
};

std::optional<std::string>
extract_cached_folder_icon(const std::filesystem::path& folder,
                           const std::string& ini_hash,
                           std::uint64_t ini_size,
                           std::optional<std::string_view> resource_path,
                           std::optional<int> resource_index) {
    static std::mutex cache_mutex;
    static std::unordered_map<std::string, CachedFolderIcon> cache;

    std::string key = platform::path::to_utf8(folder);
    key.push_back('|');
    if (resource_path)
        key.append(*resource_path);
    key.push_back('|');
    if (resource_index)
        key.append(std::to_string(*resource_index));

    {
        std::lock_guard lock(cache_mutex);
        if (const auto it = cache.find(key);
            it != cache.end() && it->second.ini_hash == ini_hash &&
            it->second.ini_size == ini_size) {
            return it->second.has_png ? std::optional{it->second.png_bytes}
                                      : std::nullopt;
        }
    }

    auto extracted =
        platform::extract_folder_icon_png(folder, resource_path, resource_index);
    CachedFolderIcon entry{
        .ini_hash = ini_hash,
        .ini_size = ini_size,
        .has_png = extracted.has_value(),
    };
    if (extracted) {
        entry.png_bytes.assign(
            reinterpret_cast<const char*>(extracted->data()), extracted->size());
    }

    {
        std::lock_guard lock(cache_mutex);
        if (cache.size() >= 64U)
            cache.clear();
        cache.insert_or_assign(std::move(key), entry);
    }
    return entry.has_png ? std::optional{entry.png_bytes} : std::nullopt;
}

void ensure_private_profile_dir(const std::filesystem::path& profile_dir) {
    const auto profiles_dir = profile_dir.parent_path();
    const auto app_data_dir = profiles_dir.parent_path();
    for (const auto& dir : {app_data_dir, profiles_dir, profile_dir}) {
        if (dir.empty())
            continue;
        if (!platform::private_storage::ensure_directory(dir))
            throw HttpError{500, "cannot prepare profile metadata folder"};
    }
}

void serve_profile_icon(const WebContext& ctx,
                        const httplib::Request& req,
                        httplib::Response& res) {
    const auto name = req.matches[1].str();
    if (!runtime::is_valid_profile_name(name))
        throw HttpError{400, "invalid profile name"};
    const auto prof = runtime::load_profile(
        ctx.environment.app_data_dir / "config.toml", name);
    if (!prof)
        throw HttpError{404, "profile not found"};

    constexpr std::uint64_t kMaxIconBytes = 512ULL * 1024ULL;
    const auto set_cache = [&](std::string& body, std::string_view mime) {
        res.headers.erase("Cache-Control");
        res.set_header("Cache-Control",
                       req.has_param("v") ? "private, max-age=300"
                                          : "private, max-age=60");
        res.headers.erase("Content-Security-Policy");
        res.set_header("Content-Security-Policy",
                       "sandbox; default-src 'none'");
        res.set_content(std::move(body), std::string{mime});
    };

    if (prof->icon.starts_with("preset:")) {
        res.status = 204;
        return;
    }

    if (prof->icon.starts_with("custom:")) {
        const auto paths = runtime::resolve_profile_paths(
            ctx.environment.app_data_dir, name);
        if (!paths) {
            res.status = 204;
            return;
        }
        for (const auto ext : kCustomIconExts) {
            const auto filename = std::string("custom-icon").append(ext);
            auto icon_file = platform::private_storage::open_browsed_file(
                paths->profile_dir, platform::path::from_utf8(filename));
            if (!icon_file || icon_file->size == 0 ||
                icon_file->size > kMaxIconBytes)
                continue;
            std::string body(static_cast<std::size_t>(icon_file->size), '\0');
            if (!platform::private_storage::read_regular_file_exact(
                    *icon_file,
                    std::span<std::uint8_t>(
                        reinterpret_cast<std::uint8_t*>(body.data()),
                        body.size())))
                continue;
            const auto fmt = detect_icon_image_format(std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(body.data()),
                body.size()));
            if (!fmt)
                continue;
            set_cache(body, fmt->mime);
            return;
        }
        res.status = 204;
        return;
    }

    const auto root = prof->local_dir.lexically_normal();

    struct IniRead {
        std::string text;
        std::string hash_hex;
        std::uint64_t size = 0;
    };
    auto read_ini = [&](std::string_view filename) -> std::optional<IniRead> {
        auto file = platform::private_storage::open_browsed_file(
            root, platform::path::from_utf8(filename));
        if (!file || file->size == 0 || file->size > 16384U)
            return std::nullopt;
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(file->size));
        if (!platform::private_storage::read_regular_file_exact(*file, bytes))
            return std::nullopt;
        const auto digest = hasher::hash_bytes(bytes.data(), bytes.size());
        return IniRead{decode_ini_bytes(bytes), hash_hex(digest), file->size};
    };

    auto try_serve_relative = [&](std::string_view raw) -> bool {
        const auto normalized = normalize_safe_relative_icon(raw);
        if (!normalized || !has_allowed_icon_extension(*normalized))
            return false;
        auto icon_file = platform::private_storage::open_browsed_file(
            root, platform::path::from_utf8(*normalized));
        if (!icon_file || icon_file->size == 0 ||
            icon_file->size > kMaxIconBytes)
            return false;
        std::string body(static_cast<std::size_t>(icon_file->size), '\0');
        if (!platform::private_storage::read_regular_file_exact(
                *icon_file,
                std::span<std::uint8_t>(
                    reinterpret_cast<std::uint8_t*>(body.data()), body.size())))
            return false;
        const auto fmt = detect_icon_image_format(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(body.data()), body.size()));
        if (!fmt)
            return false;
        set_cache(body, fmt->mime);
        return true;
    };

    if (const auto desktop_ini = read_ini("desktop.ini")) {
        if (const auto icon_val = extract_ini_section_value(
                desktop_ini->text,
                ".shellclassinfo",
                {"iconresource", "iconfile"},
                true)) {
            if (contains_traversal_component(icon_val->value)) {
                res.status = 204;
                return;
            }
            if (try_serve_relative(icon_val->value))
                return;
            if (auto png = extract_cached_folder_icon(root,
                                                      desktop_ini->hash_hex,
                                                      desktop_ini->size,
                                                      icon_val->value,
                                                      icon_val->index)) {
                set_cache(*png, "image/png");
                return;
            }
            res.status = 204;
            return;
        }
        if (const auto localized = extract_ini_section_value(
                desktop_ini->text,
                ".shellclassinfo",
                {"localizedresourcename"},
                false)) {
            if (auto png = extract_cached_folder_icon(root,
                                                      desktop_ini->hash_hex,
                                                      desktop_ini->size,
                                                      std::nullopt,
                                                      std::nullopt)) {
                set_cache(*png, "image/png");
                return;
            }
        }
        res.status = 204;
        return;
    }

    if (const auto dot_dir = read_ini(".directory")) {
        if (const auto icon_val = extract_ini_section_value(
                dot_dir->text, "desktop entry", {"icon"}, false)) {
            if (try_serve_relative(icon_val->value))
                return;
        }
    }

    res.status = 204;
}

} // namespace

void remove_custom_icon_files(const std::filesystem::path& profile_dir,
                              std::string_view keep_ext) {
    if (platform::private_storage::is_reparse_or_symlink(profile_dir))
        return;
    std::error_code ec;
    for (const auto ext : kCustomIconExts) {
        if (!keep_ext.empty() && ext == keep_ext)
            continue;
        std::filesystem::remove(
            profile_dir / std::string("custom-icon").append(ext), ec);
    }
}

void register_icon_routes(httplib::Server& server, const WebContext& ctx) {
    server.Get("/v1/profiles/([^/]+)/icon", [ctx](const auto& req, auto& res) {
        serve_profile_icon(ctx, req, res);
    });
    server.Post(
        "/v1/profiles/([^/]+)/icon", json_route([ctx](const auto& req) -> Json {
            const auto name = req.matches[1].str();
            const auto original = find_icon_profile(ctx.environment, name);
            auto body = parse_body(req, 750000U);
            if (!body->contains("data_base64") ||
                !(*body)["data_base64"].is_string())
                throw HttpError{400, "missing base64 icon payload"};
            const auto decoded = decode_base64(
                (*body)["data_base64"].template get_ref<const std::string&>());
            constexpr std::size_t kMaxIconBytes = 512ULL * 1024ULL;
            if (!decoded || decoded->empty() || decoded->size() > kMaxIconBytes)
                throw HttpError{400, "invalid or oversized icon image"};
            const auto fmt = detect_icon_image_format(*decoded);
            if (!fmt)
                throw HttpError{400, "unsupported icon image format"};
            const auto paths = runtime::resolve_profile_paths(
                ctx.environment.app_data_dir, name);
            if (!paths)
                throw HttpError{500, paths.error().detail};

            const auto digest =
                hasher::hash_bytes(decoded->data(), decoded->size());
            auto p = original;
            p.icon = "custom:" + hash_hex(digest).substr(0, 16);

            {
                InternalProfileLockGuard lock_guard(ctx.track_internal_lock,
                                                    name);
                std::lock_guard icon_lock(custom_icon_mutex());
                ensure_private_profile_dir(paths->profile_dir);
                const auto dest =
                    paths->profile_dir /
                    std::string("custom-icon").append(fmt->ext);
                std::error_code ec;
                const bool created_new = !std::filesystem::exists(dest, ec);
                const std::string_view raw_view(
                    reinterpret_cast<const char*>(decoded->data()),
                    decoded->size());
                if (!platform::private_storage::write_atomically(dest, raw_view))
                    throw HttpError{500, "cannot store custom icon"};
                try {
                    require(
                        update_profile(ctx.environment, p, false, &original));
                } catch (...) {
                    if (created_new) {
                        std::filesystem::remove(dest, ec);
                    }
                    throw;
                }
                remove_custom_icon_files(paths->profile_dir, fmt->ext);
            }
            ctx.reload();
            return {{"icon", p.icon}};
        }));
    server.Delete(
        "/v1/profiles/([^/]+)/icon", json_route([ctx](const auto& req) -> Json {
            const auto name = req.matches[1].str();
            const auto original = find_icon_profile(ctx.environment, name);
            auto p = original;
            p.icon.clear();
            {
                InternalProfileLockGuard lock_guard(ctx.track_internal_lock,
                                                    name);
                std::lock_guard icon_lock(custom_icon_mutex());
                require(update_profile(ctx.environment, p, false, &original));
                if (const auto paths = runtime::resolve_profile_paths(
                        ctx.environment.app_data_dir, name)) {
                    remove_custom_icon_files(paths->profile_dir);
                }
            }
            ctx.reload();
            return {{"icon", p.icon}};
        }));
}

} // namespace kasumi::application::daemon_detail
