#include "core/ignore.hpp"

#include "core/hasher.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <fstream>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kasumi::ignore {
namespace {

void close_glob_states(std::string_view pattern,
                       std::span<unsigned char> states) {
    for (std::size_t index = 0; index < pattern.size(); ++index) {
        if (!states[index] || pattern[index] != '*')
            continue;
        if (index + 1 < pattern.size() && pattern[index + 1] == '*') {
            states[index + 2] = 1;
            if (index + 2 < pattern.size() && pattern[index + 2] == '/') {
                states[index + 3] = 1;
            }
        } else {
            states[index + 1] = 1;
        }
    }
}

bool glob_matches_with_buffers(std::string_view pattern,
                               std::string_view text,
                               std::span<unsigned char> states,
                               std::span<unsigned char> next) {
    std::ranges::fill(states, 0);
    states[0] = 1;
    for (const char character : text) {
        close_glob_states(pattern, states);
        std::ranges::fill(next, 0);
        for (std::size_t index = 0; index < pattern.size(); ++index) {
            if (!states[index])
                continue;
            const char token = pattern[index];
            if (token == '*') {
                if ((index + 1 < pattern.size() && pattern[index + 1] == '*') ||
                    character != '/') {
                    next[index] = 1;
                }
            } else if ((token == '?' && character != '/') ||
                       token == character) {
                next[index + 1] = 1;
            }
        }
        std::ranges::copy(next, states.begin());
    }
    close_glob_states(pattern, states);
    return states[pattern.size()] != 0;
}

bool glob_matches(std::string_view pattern, std::string_view text) {
    // Iterative buffers avoid recursion in the NFA while keeping small globs
    // stack-only.
    if (pattern.size() > max_ignore_pattern_size) {
        return false;
    }
    if (pattern.size() <= 256) {
        std::array<unsigned char, 257> states{};
        std::array<unsigned char, 257> next{};
        return glob_matches_with_buffers(
            pattern,
            text,
            std::span<unsigned char>{states.data(), pattern.size() + 1},
            std::span<unsigned char>{next.data(), pattern.size() + 1});
    }
    std::vector<unsigned char> states(pattern.size() + 1, 0);
    std::vector<unsigned char> next(pattern.size() + 1, 0);
    return glob_matches_with_buffers(pattern, text, states, next);
}

bool generated_internal_name(std::string_view name) noexcept {
    const auto marker = name.rfind(".kasumi-");
    if (marker == std::string_view::npos || marker == 0)
        return false;

    auto suffix = name.substr(marker + 8);
    constexpr std::array kinds{
        std::string_view{"custody-delete"},
        std::string_view{"rollback-remove"},
        std::string_view{"rollback-candidate"},
        std::string_view{"rollback-custody"},
        std::string_view{"custody"},
        std::string_view{"copy"},
        std::string_view{"new"},
    };
    bool known_kind = false;
    for (const auto kind : kinds) {
        if (suffix.starts_with(kind) && suffix.size() > kind.size() &&
            suffix[kind.size()] == '-') {
            suffix.remove_prefix(kind.size() + 1);
            known_kind = true;
            break;
        }
    }
    if (!known_kind)
        return false;

    constexpr std::size_t transaction_id_size = 32;
    if (suffix.size() <= transaction_id_size + 1 ||
        suffix[transaction_id_size] != '-' ||
        !is_lowercase_hex(suffix.substr(0, transaction_id_size))) {
        return false;
    }
    const auto index = suffix.substr(transaction_id_size + 1);
    return std::ranges::all_of(index, [](char character) {
        return character >= '0' && character <= '9';
    });
}

bool slice_matches(const IgnoreRule& rule,
                   std::string_view text,
                   bool is_directory) {
    if (rule.directory_only && !is_directory) {
        return false;
    }
    if (rule.pattern.find('/') == std::string::npos &&
        rule.pattern.find("**") == std::string::npos &&
        text.find('/') != std::string_view::npos) {
        return false;
    }
    const auto first_star = rule.pattern.find('*');
    const auto first_qmark = rule.pattern.find('?');
    if (first_star == std::string::npos && first_qmark == std::string::npos) {
        return text == rule.pattern;
    }
    if (first_star == 0 && first_qmark == std::string::npos &&
        rule.pattern.find('*', 1) == std::string::npos) {
        const std::string_view suffix =
            std::string_view(rule.pattern).substr(1);
        return text.size() >= suffix.size() && text.ends_with(suffix);
    }
    return glob_matches(rule.pattern, text);
}

bool rule_matches(const IgnoreRule& rule,
                  std::string_view path,
                  bool is_directory) {
    const bool prefix_only =
        rule.anchored || rule.pattern.find('/') != std::string_view::npos;
    const bool component_only =
        !prefix_only && rule.pattern.find("**") == std::string::npos;
    for (std::size_t start = 0; start <= path.size();) {
        const auto first_slash = path.find('/', start);
        for (std::size_t end = start;; ++end) {
            const auto slash = path.find('/', end);
            end = slash == std::string_view::npos ? path.size() : slash;
            if (slice_matches(rule,
                              path.substr(start, end - start),
                              end < path.size() || is_directory)) {
                return true;
            }
            if (component_only || slash == std::string_view::npos) {
                break;
            }
        }
        if (prefix_only || first_slash == std::string_view::npos) {
            break;
        }
        start = first_slash + 1;
    }
    return false;
}

void parse_rule_line(std::string line,
                     IgnoreList& result,
                     std::size_t line_number) {
    if (line.starts_with("\xEF\xBB\xBF"))
        line.erase(0, 3);
    if (!line.empty() && line.back() == '\r')
        line.pop_back();
    while (!line.empty() && line.back() == ' ') {
        std::size_t slashes = 0;
        for (std::size_t index = line.size() - 1;
             index > 0 && line[index - 1] == '\\';
             --index) {
            ++slashes;
        }
        if (slashes % 2 == 1) {
            line.erase(line.end() - 2);
            break;
        }
        line.pop_back();
    }
    if (line.empty() || line[0] == '#')
        return;

    std::string trimmed_raw = line;
    IgnoreRule rule;
    rule.line = line_number;
    rule.raw = trimmed_raw;
    if (line[0] == '!') {
        rule.negated = true;
        line.erase(0, 1);
    } else if (line.starts_with("\\#") || line.starts_with("\\!")) {
        line.erase(0, 1);
    }
    if (line.empty())
        return;

    if (line.starts_with("(?d)")) {
        if (rule.negated) {
            result.parse_error = IgnoreParseError{
                line_number, "disposable rules cannot be negated"};
            return;
        }
        rule.disposable = true;
        line.erase(0, 4);
        if (line.empty()) {
            result.parse_error =
                IgnoreParseError{line_number, "(?d) requires a pattern"};
            return;
        }
        if (line.starts_with('!')) {
            result.parse_error =
                IgnoreParseError{line_number, "(?d)!pattern is not supported"};
            return;
        }
        if (line.starts_with("(?")) {
            result.parse_error = IgnoreParseError{
                line_number, "combined ignore modifiers are not supported"};
            return;
        }
        if (line.back() == '/') {
            result.parse_error = IgnoreParseError{
                line_number, "disposable directory rules are not supported"};
            return;
        }
    } else if (line.starts_with("(?")) {
        result.parse_error =
            IgnoreParseError{line_number, "unsupported ignore modifier"};
        return;
    }

    rule.directory_only = line.back() == '/';
    if (rule.directory_only)
        line.pop_back();
    rule.anchored = !line.empty() && line.front() == '/';
    if (rule.anchored)
        line.erase(0, 1);
    if (line.empty()) {
        if (rule.disposable) {
            result.parse_error =
                IgnoreParseError{line_number, "(?d) requires a pattern"};
        }
        return;
    }
    if (line.size() > max_ignore_pattern_size) {
        result.parse_error =
            IgnoreParseError{line_number,
                             "pattern exceeds the maximum size of " +
                                 std::to_string(max_ignore_pattern_size)};
        return;
    }
    rule.pattern = std::move(line);
    result.rules.push_back(std::move(rule));
}

const IgnoreRule* last_matching_rule(const IgnoreList& list,
                                     std::string_view path,
                                     bool is_directory) {
    // Evaluating rules in reverse order: the first matching rule is the
    // last applicable rule in forward order and dictates the final result.
    for (auto it = list.rules.rbegin(); it != list.rules.rend(); ++it) {
        if (rule_matches(*it, path, is_directory)) {
            return &*it;
        }
    }
    return nullptr;
}

} // namespace

bool is_reserved_internal(std::string_view path) {
    if (path == "kasumi.db" || path == "kasumi.db-shm" ||
        path == "kasumi.db-wal" || path == "kasumi.lock" ||
        path == ".kasumi_sync_buffer") {
        return true;
    }
    for (auto pos = path.find(conflict_recovery_prefix);
         pos != std::string_view::npos;
         pos = path.find(conflict_recovery_prefix, pos + conflict_recovery_prefix.size())) {
        if (pos != 0 && path[pos - 1] != '/' && path[pos - 1] != '\\') continue;
        const auto tail = path.substr(pos + conflict_recovery_prefix.size());
        const auto id = tail.substr(0, tail.find_first_of("/\\"));
        if (id.size() == 32 && is_lowercase_hex(id)) return true;
    }
    const auto slash = path.find_last_of("/\\");
    const auto name =
        slash == std::string_view::npos ? path : path.substr(slash + 1);
    return generated_internal_name(name);
}

bool is_kasumiignore_path(std::string_view path) {
    const auto slash = path.find_last_of("/\\");
    const auto name =
        slash == std::string_view::npos ? path : path.substr(slash + 1);
    return std::ranges::equal(
        name, std::string_view{".kasumiignore"}, [](char a, char b) {
            if (a >= 'A' && a <= 'Z') {
                a = static_cast<char>(a - 'A' + 'a');
            }
            return a == b;
        });
}

IgnoreList parse_ignore_rules(std::string_view content) {
    IgnoreList result;
    std::string_view remaining = content;
    std::size_t line_number = 1;
    while (!remaining.empty()) {
        const auto newline = remaining.find('\n');
        const auto line = newline == std::string_view::npos
                              ? remaining
                              : remaining.substr(0, newline);
        parse_rule_line(std::string(line), result, line_number);
        if (result.parse_error) {
            result.rules.clear();
            return result;
        }
        if (newline == std::string_view::npos)
            break;
        remaining = remaining.substr(newline + 1);
        ++line_number;
    }
    return result;
}

IgnoreList load_ignore_list(const std::filesystem::path& file_path) {
    IgnoreList result;
    std::error_code error;
    const auto status = std::filesystem::symlink_status(file_path, error);
    if (error == std::errc::no_such_file_or_directory ||
        error == std::errc::not_a_directory ||
        (!error && status.type() == std::filesystem::file_type::not_found)) {
        return result;
    }
    if (error) {
        result.parse_error = IgnoreParseError{
            0, "could not inspect ignore file: " + error.message()};
        return result;
    }
    if (std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        result.parse_error = IgnoreParseError{
            0, "ignore file must be a regular non-symlink file"};
        return result;
    }
    std::ifstream input(file_path);
    if (!input) {
        result.parse_error = IgnoreParseError{0, "could not open ignore file"};
        return result;
    }
    std::string line;
    std::size_t line_number = 0;
    while (std::getline(input, line)) {
        parse_rule_line(std::move(line), result, ++line_number);
        if (result.parse_error) {
            result.rules.clear();
            return result;
        }
    }
    if (input.bad()) {
        result.rules.clear();
        result.parse_error =
            IgnoreParseError{line_number + 1, "could not read ignore file"};
    }
    return result;
}

bool is_ignored(std::string_view path,
                const IgnoreList& ignore_list,
                bool is_directory) {
    return classify_ignore(path, is_directory, ignore_list) !=
           IgnoreDisposition::Managed;
}

IgnoreMatch inspect_ignore(std::string_view logical_path,
                           bool is_directory,
                           const IgnoreList& rules) {
    if (rules.parse_error) {
        return IgnoreMatch{
            .disposition = IgnoreDisposition::IgnoredProtected,
            .reserved_internal = false,
            .matched = false,
        };
    }
    if (is_reserved_internal(logical_path)) {
        return IgnoreMatch{
            .disposition = IgnoreDisposition::IgnoredProtected,
            .reserved_internal = true,
            .matched = true,
        };
    }
    const auto* rule = last_matching_rule(rules, logical_path, is_directory);
    if (rule == nullptr) {
        return IgnoreMatch{
            .disposition = IgnoreDisposition::Managed,
            .matched = false,
        };
    }
    IgnoreMatch match{
        .disposition = IgnoreDisposition::IgnoredProtected,
        .reserved_internal = false,
        .matched = true,
        .line = rule->line,
        .raw = rule->raw,
        .negated = rule->negated,
        .directory_only = rule->directory_only,
        .disposable = rule->disposable,
    };
    if (rule->negated) {
        match.disposition = IgnoreDisposition::Managed;
        return match;
    }
    if (rule->disposable && is_kasumiignore_path(logical_path)) {
        match.disposition =
            logical_path.find_first_of("/\\") == std::string_view::npos
                ? IgnoreDisposition::Managed
                : IgnoreDisposition::IgnoredProtected;
        return match;
    }
    if (rule->disposable && !is_directory) {
        match.disposition = IgnoreDisposition::IgnoredDisposable;
        return match;
    }
    return match;
}

IgnoreDisposition classify_ignore(std::string_view logical_path,
                                  bool is_directory,
                                  const IgnoreList& rules) {
    return inspect_ignore(logical_path, is_directory, rules).disposition;
}

} // namespace kasumi::ignore
