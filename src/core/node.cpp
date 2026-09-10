#include "core/node.hpp"

#include <algorithm>
#include <blake3.h>
#include <utf8proc.h>
#include <utility>
#include <vector>

namespace kasumi {

static_assert(UTF8PROC_VERSION_MAJOR == 2);
static_assert(UTF8PROC_VERSION_MINOR == 11);
static_assert(UTF8PROC_VERSION_PATCH == 3);
static_assert(BLAKE3_OUT_LEN == HASH_SIZE);

namespace {

bool is_windows_reserved_device_name(std::string_view base) noexcept {
    auto ascii_lower = [](char c) noexcept -> char {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
    };

    if (base.size() == 3) {
        char c0 = ascii_lower(base[0]);
        char c1 = ascii_lower(base[1]);
        char c2 = ascii_lower(base[2]);
        if (c0 == 'c' && c1 == 'o' && c2 == 'n')
            return true;
        if (c0 == 'p' && c1 == 'r' && c2 == 'n')
            return true;
        if (c0 == 'a' && c1 == 'u' && c2 == 'x')
            return true;
        if (c0 == 'n' && c1 == 'u' && c2 == 'l')
            return true;
        return false;
    }

    if (base.size() == 4) {
        char c0 = ascii_lower(base[0]);
        char c1 = ascii_lower(base[1]);
        char c2 = ascii_lower(base[2]);
        char c3 = base[3];
        if ((c0 == 'c' && c1 == 'o' && c2 == 'm') ||
            (c0 == 'l' && c1 == 'p' && c2 == 't')) {
            return c3 >= '1' && c3 <= '9';
        }
        return false;
    }

    if (base.size() == 5) {
        char c0 = ascii_lower(base[0]);
        char c1 = ascii_lower(base[1]);
        char c2 = ascii_lower(base[2]);
        auto b3 = static_cast<unsigned char>(base[3]);
        auto b4 = static_cast<unsigned char>(base[4]);
        if ((c0 == 'c' && c1 == 'o' && c2 == 'm') ||
            (c0 == 'l' && c1 == 'p' && c2 == 't')) {
            return b3 == 0xC2 && (b4 == 0xB9 || b4 == 0xB2 || b4 == 0xB3);
        }
        return false;
    }

    return false;
}

} // namespace

bool valid_logical_path_component(std::string_view name) noexcept {
    if (name.empty() || name == "." || name == ".." ||
        name.size() > maximum_logical_component_length) {
        return false;
    }

    if (name.back() == '.' || name.back() == ' ') {
        return false;
    }

    for (std::size_t i = 0; i < name.size(); ++i) {
        const auto b0 = static_cast<unsigned char>(name[i]);
        if (b0 <= 0x7F) {
            if (b0 < 0x20 || b0 == 0x7F) {
                return false;
            }
            switch (b0) {
                case '<':
                case '>':
                case ':':
                case '"':
                case '/':
                case '\\':
                case '|':
                case '?':
                case '*':
                    return false;
                default:
                    break;
            }
        } else if (b0 >= 0xC2 && b0 <= 0xDF) {
            if (i + 1 >= name.size()) {
                return false;
            }
            const auto b1 = static_cast<unsigned char>(name[++i]);
            if (b1 < 0x80 || b1 > 0xBF) {
                return false;
            }
        } else if (b0 >= 0xE0 && b0 <= 0xEF) {
            if (i + 2 >= name.size()) {
                return false;
            }
            const auto b1 = static_cast<unsigned char>(name[++i]);
            if (b0 == 0xE0) {
                if (b1 < 0xA0 || b1 > 0xBF) {
                    return false;
                }
            } else if (b0 == 0xED) {
                if (b1 < 0x80 || b1 > 0x9F) {
                    return false;
                }
            } else {
                if (b1 < 0x80 || b1 > 0xBF) {
                    return false;
                }
            }
            const auto b2 = static_cast<unsigned char>(name[++i]);
            if (b2 < 0x80 || b2 > 0xBF) {
                return false;
            }
        } else if (b0 >= 0xF0 && b0 <= 0xF4) {
            if (i + 3 >= name.size()) {
                return false;
            }
            const auto b1 = static_cast<unsigned char>(name[++i]);
            if (b0 == 0xF0) {
                if (b1 < 0x90 || b1 > 0xBF) {
                    return false;
                }
            } else if (b0 == 0xF4) {
                if (b1 < 0x80 || b1 > 0x8F) {
                    return false;
                }
            } else {
                if (b1 < 0x80 || b1 > 0xBF) {
                    return false;
                }
            }
            const auto b2 = static_cast<unsigned char>(name[++i]);
            if (b2 < 0x80 || b2 > 0xBF) {
                return false;
            }
            const auto b3 = static_cast<unsigned char>(name[++i]);
            if (b3 < 0x80 || b3 > 0xBF) {
                return false;
            }
        } else {
            return false;
        }
    }

    const auto dot = name.find('.');
    const auto base =
        dot == std::string_view::npos ? name : name.substr(0, dot);
    if (is_windows_reserved_device_name(base)) {
        return false;
    }

    return true;
}

std::string portable_case_key(std::string_view logical_path) {
    std::string key;
    key.reserve(logical_path.size());
    const auto* ptr =
        reinterpret_cast<const utf8proc_uint8_t*>(logical_path.data());
    utf8proc_ssize_t remaining =
        static_cast<utf8proc_ssize_t>(logical_path.size());

    while (remaining > 0) {
        utf8proc_int32_t codepoint = 0;
        utf8proc_ssize_t bytes_read =
            utf8proc_iterate(ptr, remaining, &codepoint);
        if (bytes_read <= 0) {
            key.push_back(static_cast<char>(*ptr));
            ptr += 1;
            remaining -= 1;
            continue;
        }
        ptr += bytes_read;
        remaining -= bytes_read;

        utf8proc_int32_t upper = utf8proc_toupper(codepoint);
        utf8proc_uint8_t encoded[4];
        utf8proc_ssize_t encoded_bytes = utf8proc_encode_char(upper, encoded);
        if (encoded_bytes > 0) {
            key.append(reinterpret_cast<const char*>(encoded),
                       static_cast<std::size_t>(encoded_bytes));
        } else {
            key.append(reinterpret_cast<const char*>(ptr - bytes_read),
                       static_cast<std::size_t>(bytes_read));
        }
    }
    return key;
}

std::string_view unicode_version() noexcept {
    return utf8proc_unicode_version();
}

std::string make_conflict_path(std::string_view original_path,
                               std::string_view suffix) {
    const auto parent = row_parent(original_path);
    const auto orig_name = row_name(original_path);

    const std::size_t suffix_len =
        std::min(suffix.size(), maximum_logical_component_length);
    const std::size_t max_orig_len =
        maximum_logical_component_length - suffix_len;

    auto truncate_utf8 = [](std::string_view s,
                            std::size_t max_bytes) -> std::string_view {
        if (s.size() <= max_bytes) {
            return s;
        }
        std::size_t len = max_bytes;
        while (len > 0 && (static_cast<unsigned char>(s[len]) & 0xC0) == 0x80) {
            --len;
        }
        return s.substr(0, len);
    };

    auto orig_truncated = truncate_utf8(orig_name, max_orig_len);
    std::string candidate_name =
        std::string(orig_truncated) + std::string(suffix);

    const auto dot = candidate_name.find('.');
    const auto base = dot == std::string_view::npos
                          ? std::string_view(candidate_name)
                          : std::string_view(candidate_name).substr(0, dot);
    if (is_windows_reserved_device_name(base)) {
        const std::size_t safe_max_orig_len =
            max_orig_len > 1 ? max_orig_len - 1 : 0;
        orig_truncated = truncate_utf8(orig_name, safe_max_orig_len);
        candidate_name =
            "_" + std::string(orig_truncated) + std::string(suffix);
    }

    if (parent.empty()) {
        return candidate_name;
    }
    return std::string(parent) + '/' + candidate_name;
}

bool path_less(std::string_view left, std::string_view right) {
    std::size_t left_offset = 0;
    std::size_t right_offset = 0;
    while (true) {
        const auto left_end = left.find('/', left_offset);
        const auto right_end = right.find('/', right_offset);
        const auto left_part = left.substr(left_offset, left_end - left_offset);
        const auto right_part =
            right.substr(right_offset, right_end - right_offset);
        if (left_part < right_part)
            return true;
        if (right_part < left_part)
            return false;
        if (left_end == std::string_view::npos ||
            right_end == std::string_view::npos)
            return right_end != std::string_view::npos;
        left_offset = left_end + 1;
        right_offset = right_end + 1;
    }
}

bool valid_snapshot(const Snapshot& snapshot, bool allow_empty) {
    if (snapshot.rows.empty()) {
        return allow_empty;
    }

    const auto& root = snapshot.rows.front();
    if (!root.path.empty() || !root.is_directory ||
        !std::ranges::is_sorted(snapshot.rows, path_less, &NodeRow::path)) {
        return false;
    }

    std::vector<std::string> case_keys;
    case_keys.reserve(snapshot.rows.size());

    for (std::size_t index = 0; index < snapshot.rows.size(); ++index) {
        const auto& row = snapshot.rows[index];
        if (index != 0 &&
            (row.path.empty() || row.path == snapshot.rows[index - 1].path)) {
            return false;
        }

        if (index != 0) {
            const auto parent = row_parent(row.path);
            const auto* parent_row = find_row(snapshot, parent);
            if (parent_row == nullptr || !parent_row->is_directory) {
                return false;
            }

            if (row.path.front() == '/' || row.path.back() == '/') {
                return false;
            }
            std::size_t start = 0;
            while (start < row.path.size()) {
                const auto slash = row.path.find('/', start);
                const auto component =
                    slash == std::string_view::npos
                        ? std::string_view(row.path).substr(start)
                        : std::string_view(row.path).substr(start,
                                                            slash - start);
                if (!valid_logical_path_component(component)) {
                    return false;
                }
                if (slash == std::string_view::npos) {
                    break;
                }
                start = slash + 1;
            }
        }

        case_keys.push_back(portable_case_key(row.path));
    }

    std::ranges::sort(case_keys);
    if (std::ranges::adjacent_find(case_keys) != case_keys.end()) {
        return false;
    }

    return true;
}

const NodeRow* find_row(const Snapshot& snapshot, std::string_view path) {
    const auto row = std::ranges::lower_bound(
        snapshot.rows, path, path_less, &NodeRow::path);
    return row != snapshot.rows.end() && row->path == path ? &*row : nullptr;
}

NodeRow* find_row(Snapshot& snapshot, std::string_view path) {
    return const_cast<NodeRow*>(find_row(std::as_const(snapshot), path));
}

bool is_descendant(std::string_view path, std::string_view parent) {
    if (parent.empty())
        return !path.empty();
    return path.size() > parent.size() && path.starts_with(parent) &&
           path[parent.size()] == '/';
}

std::string_view row_name(std::string_view path) {
    const auto separator = path.rfind('/');
    return separator == std::string_view::npos ? path
                                               : path.substr(separator + 1);
}

std::string_view row_parent(std::string_view path) {
    const auto separator = path.rfind('/');
    return separator == std::string_view::npos ? std::string_view{}
                                               : path.substr(0, separator);
}

void finalize_snapshot(Snapshot& snapshot) {
    std::ranges::sort(snapshot.rows, path_less, &NodeRow::path);
    std::vector<std::size_t> directories;
    std::vector<blake3_hasher> states;
    const auto append = [&](blake3_hasher& state, const NodeRow& row) {
        const auto name = row_name(row.path);
        blake3_hasher_update(&state, name.data(), name.size());
        char text[HASH_HEX_SIZE];
        hash_hex(row.hash, text);
        blake3_hasher_update(&state, text, sizeof(text));
    };
    const auto close = [&] {
        auto& row = snapshot.rows[directories.back()];
        blake3_hasher_finalize(&states.back(),
                               reinterpret_cast<uint8_t*>(row.hash.data()),
                               row.hash.size());
        directories.pop_back();
        states.pop_back();
        if (!states.empty()) {
            append(states.back(), row);
            snapshot.rows[directories.back()].size += row.size;
        }
    };

    for (std::size_t i = 0; i < snapshot.rows.size(); ++i) {
        auto& row = snapshot.rows[i];
        while (!directories.empty() &&
               row_parent(row.path) != snapshot.rows[directories.back()].path)
            close();
        if (row.is_directory) {
            row.size = 0;
            directories.push_back(i);
            states.emplace_back();
            blake3_hasher_init(&states.back());
        } else if (!states.empty()) {
            append(states.back(), row);
            snapshot.rows[directories.back()].size += row.size;
        }
    }
    while (!directories.empty())
        close();
}

} // namespace kasumi
