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
#include <fstream>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
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

bool has_allowed_icon_extension(std::string_view path_text) {
    const auto dot = path_text.find_last_of('.');
    const auto sep = path_text.find_last_of("/\\");
    if (dot == path_text.npos || (sep != path_text.npos && dot < sep))
        return false;
    const auto ext = ascii_lower(path_text.substr(dot));
    return ext == ".png" || ext == ".svg" || ext == ".ico" || ext == ".webp" ||
           ext == ".jpg" || ext == ".jpeg" || ext == ".bmp";
}

struct ImageFormatInfo {
    std::string_view ext;
    std::string_view mime;
};

bool is_safe_svg(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 7 || bytes.size() > 512ULL * 1024ULL)
        return false;
    if (std::ranges::find(bytes, std::uint8_t{0}) != bytes.end())
        return false;
    std::string_view text(reinterpret_cast<const char*>(bytes.data()),
                          bytes.size());
    if (text.size() >= 3 && static_cast<unsigned char>(text[0]) == 0xEF &&
        static_cast<unsigned char>(text[1]) == 0xBB &&
        static_cast<unsigned char>(text[2]) == 0xBF) {
        text.remove_prefix(3);
    }
    auto head = trim_ascii(text);
    for (int iter = 0; iter < 16 && !head.empty(); ++iter) {
        if (head.starts_with("<?")) {
            const auto end = head.find("?>");
            if (end == head.npos)
                return false;
            head = trim_ascii(head.substr(end + 2));
            continue;
        }
        if (head.starts_with("<!--")) {
            const auto end = head.find("-->");
            if (end == head.npos)
                return false;
            head = trim_ascii(head.substr(end + 3));
            continue;
        }
        if (head.size() >= 9 && ascii_lower(head.substr(0, 9)) == "<!doctype") {
            const auto end = head.find('>');
            if (end == head.npos)
                return false;
            head = trim_ascii(head.substr(end + 1));
            continue;
        }
        break;
    }
    if (head.size() < 5 || ascii_lower(head.substr(0, 4)) != "<svg")
        return false;
    const unsigned char after = static_cast<unsigned char>(head[4]);
    if (!(std::isspace(after) != 0 || after == '>' || after == '/'))
        return false;

    const std::string lower = ascii_lower(text);
    if (lower.find("</svg>") == std::string::npos &&
        lower.find("/>") == std::string::npos) {
        return false;
    }
    for (const std::string_view forbidden : {"<script",
                                             "</script",
                                             "<foreignobject",
                                             "<!entity",
                                             "javascript:",
                                             "vbscript:",
                                             "data:text/html"}) {
        if (lower.find(forbidden) != std::string::npos)
            return false;
    }
    for (std::size_t i = 1; i + 3 < lower.size(); ++i) {
        const unsigned char prev = static_cast<unsigned char>(lower[i - 1]);
        if (!(std::isspace(prev) != 0 || prev == '/'))
            continue;
        if (lower[i] == 'o' && lower[i + 1] == 'n') {
            std::size_t j = i + 2;
            while (j < lower.size() && lower[j] >= 'a' && lower[j] <= 'z')
                ++j;
            if (j > i + 2) {
                while (j < lower.size() &&
                       std::isspace(static_cast<unsigned char>(lower[j])) != 0)
                    ++j;
                if (j < lower.size() && lower[j] == '=')
                    return false;
            }
        }
    }
    return true;
}

std::optional<ImageFormatInfo>
detect_icon_image_format(std::span<const std::uint8_t> bytes) {
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
    if (is_safe_svg(bytes)) {
        return ImageFormatInfo{".svg", "image/svg+xml"};
    }
    return std::nullopt;
}

std::optional<std::vector<std::uint8_t>> decode_base64(std::string_view input) {
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

constexpr std::array<std::string_view, 6> kCustomIconExts{
    ".png", ".svg", ".ico", ".webp", ".jpg", ".bmp"};

std::optional<std::string> normalize_safe_relative_icon(std::string_view raw) {
    raw = trim_ascii(raw);
    if (raw.empty() || raw.find('%') != raw.npos || raw.find('\0') != raw.npos)
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

int hex_nibble(char ch) noexcept {
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'a' && ch <= 'f')
        return 10 + (ch - 'a');
    if (ch >= 'A' && ch <= 'F')
        return 10 + (ch - 'A');
    return -1;
}

std::optional<std::string> decode_file_uri_or_abs(std::string_view raw) {
    raw = trim_ascii(raw);
    if (raw.empty() || raw.find('\0') != raw.npos)
        return std::nullopt;
    std::string decoded;
    if (raw.size() >= 7 && ascii_lower(raw.substr(0, 7)) == "file://") {
        auto rest = raw.substr(7);
        if (rest.size() >= 10 &&
            ascii_lower(rest.substr(0, 10)) == "localhost/") {
            rest.remove_prefix(9);
        }
        if (rest.empty() || rest.front() != '/')
            return std::nullopt;
        decoded.reserve(rest.size());
        for (std::size_t i = 0; i < rest.size(); ++i) {
            if (rest[i] == '%') {
                if (i + 2 >= rest.size())
                    return std::nullopt;
                const int hi = hex_nibble(rest[i + 1]);
                const int lo = hex_nibble(rest[i + 2]);
                if (hi < 0 || lo < 0)
                    return std::nullopt;
                const auto byte = static_cast<unsigned char>((hi << 4) | lo);
                if (byte < 0x20U)
                    return std::nullopt;
                decoded.push_back(static_cast<char>(byte));
                i += 2;
            } else {
                const auto byte = static_cast<unsigned char>(rest[i]);
                if (byte < 0x20U)
                    return std::nullopt;
                decoded.push_back(rest[i]);
            }
        }
#ifdef _WIN32
        if (decoded.size() >= 3 && decoded[0] == '/' &&
            std::isalpha(static_cast<unsigned char>(decoded[1])) != 0 &&
            decoded[2] == ':') {
            decoded.erase(0, 1);
        }
#endif
    } else {
        if (raw.starts_with("\\\\") || raw.starts_with("//"))
            return std::nullopt;
        for (const char ch : raw) {
            if (static_cast<unsigned char>(ch) < 0x20U)
                return std::nullopt;
        }
        decoded.assign(raw);
    }
    if (decoded.empty() || contains_traversal_component(decoded))
        return std::nullopt;
    const auto path = platform::path::from_utf8(decoded);
    if (!path.is_absolute())
        return std::nullopt;
    return decoded;
}

bool is_valid_theme_icon_name(std::string_view raw) noexcept {
    if (raw.empty() || raw.size() > 128 || raw == "." || raw == ".." ||
        raw.find("..") != raw.npos) {
        return false;
    }
    return std::ranges::all_of(raw, [](char raw_ch) {
        const auto ch = static_cast<unsigned char>(raw_ch);
        return std::isalnum(ch) != 0 || ch == '-' || ch == '_' || ch == '.';
    });
}

std::optional<std::string> read_bounded_file(const std::filesystem::path& path,
                                             std::uint64_t max_bytes,
                                             bool allow_symlinks) {
    std::error_code ec;
    std::filesystem::path target = path;
    if (allow_symlinks) {
        target = std::filesystem::canonical(path, ec);
        if (ec)
            return std::nullopt;
    } else {
        const auto st = std::filesystem::symlink_status(path, ec);
        if (ec || std::filesystem::is_symlink(st))
            return std::nullopt;
    }
    if (!std::filesystem::is_regular_file(target, ec) || ec)
        return std::nullopt;
    const auto size = std::filesystem::file_size(target, ec);
    if (ec || size == 0 || size > max_bytes)
        return std::nullopt;
    std::ifstream in(target, std::ios::binary);
    if (!in)
        return std::nullopt;
    std::string body(static_cast<std::size_t>(size), '\0');
    in.read(body.data(), static_cast<std::streamsize>(size));
    if (in.gcount() != static_cast<std::streamsize>(size))
        return std::nullopt;
    return body;
}

std::optional<std::string> read_text_small(const std::filesystem::path& path) {
    return read_bounded_file(path, 65536ULL, true);
}

std::vector<std::filesystem::path> split_path_list(std::string_view text,
                                                   char sep) {
    std::vector<std::filesystem::path> out;
    std::size_t start = 0;
    while (start <= text.size()) {
        const auto next = text.find(sep, start);
        const auto len = next == text.npos ? text.size() - start : next - start;
        const auto part = trim_ascii(text.substr(start, len));
        if (!part.empty())
            out.push_back(platform::path::from_utf8(part));
        if (next == text.npos)
            break;
        start = next + 1;
    }
    return out;
}

void push_unique_theme(std::vector<std::string>& themes,
                       std::unordered_set<std::string>& seen,
                       std::string_view candidate) {
    const auto trimmed = trim_ascii(candidate);
    if (trimmed.empty() || trimmed.size() > 128 ||
        trimmed.find('/') != trimmed.npos ||
        trimmed.find('\\') != trimmed.npos ||
        contains_traversal_component(trimmed)) {
        return;
    }
    std::string value(trimmed);
    if (seen.insert(value).second)
        themes.push_back(std::move(value));
}

std::vector<std::filesystem::path> freedesktop_icon_search_dirs() {
    std::vector<std::filesystem::path> dirs;
    if (const auto custom =
            platform::path::environment_value("KASUMI_ICON_DIRS")) {
#ifdef _WIN32
        constexpr char kPathSep = ';';
#else
        constexpr char kPathSep = ':';
#endif
        return split_path_list(platform::path::to_utf8(*custom), kPathSep);
    }
#ifndef _WIN32
    const auto home = platform::path::environment_value("HOME");
    if (const auto xdg_data_home =
            platform::path::environment_value("XDG_DATA_HOME")) {
        dirs.push_back(*xdg_data_home / "icons");
    } else if (home) {
        dirs.push_back(*home / ".local" / "share" / "icons");
    }
    if (home)
        dirs.push_back(*home / ".icons");
    const auto xdg_data_dirs =
        platform::path::environment_value("XDG_DATA_DIRS");
    const std::string data_dirs_text =
        xdg_data_dirs ? platform::path::to_utf8(*xdg_data_dirs)
                      : std::string("/usr/local/share:/usr/share");
    for (const auto& base : split_path_list(data_dirs_text, ':')) {
        dirs.push_back(base / "icons");
    }
    dirs.emplace_back("/usr/share/pixmaps");
#endif
    return dirs;
}

std::vector<std::string>
freedesktop_icon_themes(const std::vector<std::filesystem::path>& roots) {
    std::vector<std::string> themes;
    std::unordered_set<std::string> seen;
    if (const auto env_theme =
            platform::path::environment_value("KASUMI_ICON_THEME")) {
        push_unique_theme(themes, seen, platform::path::to_utf8(*env_theme));
    }
#ifndef _WIN32
    std::optional<std::filesystem::path> cfg_home =
        platform::path::environment_value("XDG_CONFIG_HOME");
    if (!cfg_home) {
        if (const auto home = platform::path::environment_value("HOME"))
            cfg_home = *home / ".config";
    }
    if (cfg_home) {
        if (const auto kde = read_text_small(*cfg_home / "kdeglobals")) {
            if (const auto val =
                    extract_ini_section_value(*kde, "icons", {"theme"}, false))
                push_unique_theme(themes, seen, val->value);
        }
        for (const auto& gtk_ver : {"gtk-3.0", "gtk-4.0"}) {
            if (const auto gtk =
                    read_text_small(*cfg_home / gtk_ver / "settings.ini")) {
                if (const auto val = extract_ini_section_value(
                        *gtk, "settings", {"gtk-icon-theme-name"}, false)) {
                    push_unique_theme(themes, seen, val->value);
                }
            }
        }
    }
#endif
    for (const std::string_view fallback : {"breeze-dark",
                                            "breeze",
                                            "Papirus-Dark",
                                            "Papirus",
                                            "Adwaita",
                                            "hicolor"}) {
        push_unique_theme(themes, seen, fallback);
    }

    constexpr std::size_t kMaxExpandedThemes = 16;
    for (std::size_t idx = 0;
         idx < themes.size() && themes.size() < kMaxExpandedThemes;
         ++idx) {
        const std::string theme_name = themes[idx];
        for (const auto& root : roots) {
            const auto index_file = root / theme_name / "index.theme";
            const auto text = read_text_small(index_file);
            if (!text)
                continue;
            const auto inherits = extract_ini_section_value(
                *text, "icon theme", {"inherits"}, false);
            if (!inherits)
                break;
            std::size_t pos = 0;
            const std::string_view list = inherits->value;
            while (pos <= list.size() && themes.size() < kMaxExpandedThemes) {
                const auto comma = list.find(',', pos);
                const auto len =
                    comma == list.npos ? list.size() - pos : comma - pos;
                push_unique_theme(themes, seen, list.substr(pos, len));
                if (comma == list.npos)
                    break;
                pos = comma + 1;
            }
            break;
        }
    }
    return themes;
}

std::optional<std::filesystem::path>
resolve_freedesktop_theme_icon(std::string_view icon_name) {
    if (!is_valid_theme_icon_name(icon_name))
        return std::nullopt;
    const auto roots = freedesktop_icon_search_dirs();
    if (roots.empty())
        return std::nullopt;

    const auto env_dirs = platform::path::environment_value("KASUMI_ICON_DIRS");
    const auto env_theme =
        platform::path::environment_value("KASUMI_ICON_THEME");
    std::string cache_key(icon_name);
    cache_key.push_back('|');
    if (env_dirs)
        cache_key.append(platform::path::to_utf8(*env_dirs));
    cache_key.push_back('|');
    if (env_theme)
        cache_key.append(platform::path::to_utf8(*env_theme));

    static std::mutex theme_cache_mutex;
    static std::unordered_map<std::string, std::optional<std::filesystem::path>>
        theme_cache;
    {
        std::lock_guard lock(theme_cache_mutex);
        if (const auto it = theme_cache.find(cache_key);
            it != theme_cache.end()) {
            if (!it->second)
                return std::nullopt;
            std::error_code ec;
            if (std::filesystem::exists(*it->second, ec) && !ec)
                return it->second;
        }
    }

    static constexpr std::array<std::string_view, 12> kSizes{"64x64",
                                                             "48x48",
                                                             "32x32",
                                                             "scalable",
                                                             "64",
                                                             "48",
                                                             "32",
                                                             "128x128",
                                                             "256x256",
                                                             "24x24",
                                                             "22x22",
                                                             "16x16"};
    static constexpr std::array<std::string_view, 7> kCategories{"places",
                                                                 "apps",
                                                                 "mimetypes",
                                                                 "categories",
                                                                 "status",
                                                                 "devices",
                                                                 "actions"};
    static constexpr std::array<std::string_view, 2> kThemeExts{".svg", ".png"};

    const auto themes = freedesktop_icon_themes(roots);
    std::optional<std::filesystem::path> resolved;
    auto probe_candidate = [&](const std::filesystem::path& candidate) -> bool {
        std::error_code ec;
        if (!std::filesystem::exists(candidate, ec) || ec)
            return false;
        const auto canon = std::filesystem::canonical(candidate, ec);
        if (ec || !std::filesystem::is_regular_file(canon, ec) || ec)
            return false;
        resolved = canon;
        return true;
    };

    for (const auto& theme : themes) {
        for (const auto& root : roots) {
            const auto theme_dir = root / theme;
            std::error_code ec;
            if (!std::filesystem::is_directory(theme_dir, ec) || ec)
                continue;
            for (const auto cat : kCategories) {
                const auto cat_dir = theme_dir / cat;
                if (std::filesystem::is_directory(cat_dir, ec) && !ec) {
                    for (const auto size : kSizes) {
                        const auto size_dir = cat_dir / size;
                        if (!std::filesystem::is_directory(size_dir, ec) || ec)
                            continue;
                        for (const auto ext : kThemeExts) {
                            if (probe_candidate(
                                    size_dir /
                                    (std::string(icon_name).append(ext)))) {
                                break;
                            }
                        }
                        if (resolved)
                            break;
                    }
                }
                if (resolved)
                    break;
            }
            if (resolved)
                break;
            for (const auto size : kSizes) {
                const auto size_dir = theme_dir / size;
                if (!std::filesystem::is_directory(size_dir, ec) || ec)
                    continue;
                for (const auto cat : kCategories) {
                    const auto cat_dir = size_dir / cat;
                    if (!std::filesystem::is_directory(cat_dir, ec) || ec)
                        continue;
                    for (const auto ext : kThemeExts) {
                        if (probe_candidate(
                                cat_dir /
                                (std::string(icon_name).append(ext)))) {
                            break;
                        }
                    }
                    if (resolved)
                        break;
                }
                if (resolved)
                    break;
            }
            if (resolved)
                break;
        }
        if (resolved)
            break;
    }

    if (!resolved) {
        for (const auto& root : roots) {
            for (const auto ext : kThemeExts) {
                if (probe_candidate(root /
                                    (std::string(icon_name).append(ext)))) {
                    break;
                }
            }
            if (resolved)
                break;
        }
    }

    {
        std::lock_guard lock(theme_cache_mutex);
        if (theme_cache.size() >= 128U)
            theme_cache.clear();
        theme_cache.insert_or_assign(std::move(cache_key), resolved);
    }
    return resolved;
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
        if (const auto it = cache.find(key); it != cache.end() &&
                                             it->second.ini_hash == ini_hash &&
                                             it->second.ini_size == ini_size) {
            return it->second.has_png ? std::optional{it->second.png_bytes}
                                      : std::nullopt;
        }
    }

    auto extracted = platform::extract_folder_icon_png(
        folder, resource_path, resource_index);
    CachedFolderIcon entry{
        .ini_hash = ini_hash,
        .ini_size = ini_size,
        .has_png = extracted.has_value(),
    };
    if (extracted) {
        entry.png_bytes.assign(reinterpret_cast<const char*>(extracted->data()),
                               extracted->size());
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
    const bool force_auto = req.get_param_value("mode") == "auto";
    const auto set_cache =
        [&](std::string& body, std::string_view mime, bool immutable_version) {
            res.headers.erase("Cache-Control");
            res.set_header("Cache-Control",
                           immutable_version ? "private, max-age=300"
                                             : "private, no-cache");
            res.headers.erase("Content-Security-Policy");
            res.set_header("Content-Security-Policy",
                           "sandbox; default-src 'none'");
            res.set_content(std::move(body), std::string{mime});
        };

    if (!force_auto && prof->icon.starts_with("preset:")) {
        res.status = 204;
        return;
    }

    if (!force_auto && prof->icon.starts_with("custom:")) {
        const auto paths =
            runtime::resolve_profile_paths(ctx.environment.app_data_dir, name);
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
            const auto fmt =
                detect_icon_image_format(std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t*>(body.data()),
                    body.size()));
            if (!fmt)
                continue;
            set_cache(body, fmt->mime, req.has_param("v"));
            return;
        }
        res.status = 204;
        return;
    }

    std::error_code root_ec;
    auto root = std::filesystem::weakly_canonical(prof->local_dir, root_ec);
    if (root_ec || root.empty())
        root = prof->local_dir.lexically_normal();

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
        set_cache(body, fmt->mime, false);
        return true;
    };

    auto try_serve_filesystem_icon =
        [&](const std::filesystem::path& file_path) -> bool {
        const auto path_utf8 = platform::path::to_utf8(file_path);
        if (!has_allowed_icon_extension(path_utf8))
            return false;
        auto body = read_bounded_file(file_path, kMaxIconBytes, true);
        if (!body)
            return false;
        const auto fmt = detect_icon_image_format(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(body->data()), body->size()));
        if (!fmt)
            return false;
        set_cache(*body, fmt->mime, false);
        return true;
    };

    auto try_serve_desktop_ini = [&]() -> bool {
        const auto desktop_ini = read_ini("desktop.ini");
        if (!desktop_ini)
            return false;
        if (const auto icon_val =
                extract_ini_section_value(desktop_ini->text,
                                          ".shellclassinfo",
                                          {"iconresource", "iconfile"},
                                          true)) {
            if (contains_traversal_component(icon_val->value))
                return false;
            if (try_serve_relative(icon_val->value))
                return true;
            if (auto png = extract_cached_folder_icon(root,
                                                      desktop_ini->hash_hex,
                                                      desktop_ini->size,
                                                      icon_val->value,
                                                      icon_val->index)) {
                set_cache(*png, "image/png", false);
                return true;
            }
            return false;
        }
        if (const auto localized =
                extract_ini_section_value(desktop_ini->text,
                                          ".shellclassinfo",
                                          {"localizedresourcename"},
                                          false)) {
            if (auto png = extract_cached_folder_icon(root,
                                                      desktop_ini->hash_hex,
                                                      desktop_ini->size,
                                                      std::nullopt,
                                                      std::nullopt)) {
                set_cache(*png, "image/png", false);
                return true;
            }
        }
        return false;
    };

    auto try_serve_dot_directory = [&]() -> bool {
        const auto dot_dir = read_ini(".directory");
        if (!dot_dir)
            return false;
        const auto icon_val = extract_ini_section_value(
            dot_dir->text, "desktop entry", {"icon"}, false);
        if (!icon_val)
            return false;
        if (try_serve_relative(icon_val->value))
            return true;
        if (const auto abs = decode_file_uri_or_abs(icon_val->value)) {
            if (try_serve_filesystem_icon(platform::path::from_utf8(*abs)))
                return true;
        }
        if (const auto themed =
                resolve_freedesktop_theme_icon(icon_val->value)) {
            if (try_serve_filesystem_icon(*themed))
                return true;
        }
        return false;
    };

#ifdef _WIN32
    if (try_serve_desktop_ini())
        return;
    if (try_serve_dot_directory())
        return;
#else
    if (try_serve_dot_directory())
        return;
    if (try_serve_desktop_ini())
        return;
#endif

    res.headers.erase("Cache-Control");
    res.set_header("Cache-Control", "private, no-cache");
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
                const auto dest = paths->profile_dir /
                                  std::string("custom-icon").append(fmt->ext);
                std::error_code ec;
                const bool created_new = !std::filesystem::exists(dest, ec);
                const std::string_view raw_view(
                    reinterpret_cast<const char*>(decoded->data()),
                    decoded->size());
                if (!platform::private_storage::write_atomically(dest,
                                                                 raw_view))
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
