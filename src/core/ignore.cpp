#include "core/ignore.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace kasumi::ignore {
namespace {

void close_glob_states(
    std::string_view pattern,
    std::array<unsigned char, max_ignore_pattern_size + 1>& states) {
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

bool glob_matches(std::string_view pattern, std::string_view text) {
    // Iterative arrays avoid recursion in the NFA.
    if (pattern.size() > max_ignore_pattern_size)
        return false;
    std::array<unsigned char, max_ignore_pattern_size + 1> states{};
    std::array<unsigned char, max_ignore_pattern_size + 1> next{};
    states[0] = 1;
    for (const char character : text) {
        close_glob_states(pattern, states);
        next.fill(0);
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
        states = next;
    }
    close_glob_states(pattern, states);
    return states[pattern.size()] != 0;
}

bool rule_matches(const IgnoreRule& rule,
                  std::string_view path,
                  bool is_directory) {
    for (std::size_t start = 0; start <= path.size();) {
        if (start == 0 ||
            (!rule.anchored && rule.pattern.find('/') == std::string::npos)) {
            for (std::size_t end = start;; ++end) {
                const auto slash = path.find('/', end);
                end = slash == std::string_view::npos ? path.size() : slash;
                const bool directory = end < path.size() || is_directory;
                if ((!rule.directory_only || directory) &&
                    glob_matches(rule.pattern,
                                 path.substr(start, end - start))) {
                    return true;
                }
                if (slash == std::string_view::npos)
                    break;
            }
        }
        const auto slash = path.find('/', start);
        if (slash == std::string_view::npos)
            break;
        start = slash + 1;
    }
    return false;
}

void parse_rule_line(std::string line, IgnoreList& result) {
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

    IgnoreRule rule;
    if (line[0] == '!') {
        rule.negated = true;
        line.erase(0, 1);
    } else if (line.starts_with("\\#") || line.starts_with("\\!")) {
        line.erase(0, 1);
    }
    if (line.empty())
        return;
    rule.directory_only = line.back() == '/';
    if (rule.directory_only)
        line.pop_back();
    rule.anchored = !line.empty() && line.front() == '/';
    if (rule.anchored)
        line.erase(0, 1);
    if (line.empty() || line.size() > max_ignore_pattern_size)
        return;
    rule.pattern = std::move(line);
    result.rules.push_back(std::move(rule));
}

bool ignores(const IgnoreList& list, std::string_view path, bool is_directory) {
    bool ignored = false;
    for (const auto& rule : list.rules) {
        if (rule_matches(rule, path, is_directory))
            ignored = !rule.negated;
    }
    return ignored;
}

} // namespace

bool is_reserved_internal(std::string_view path) {
    return path == "kasumi.db" || path == "kasumi.db-shm" ||
           path == "kasumi.db-wal" || path == "kasumi.lock" ||
           path == ".kasumi_sync_buffer";
}

IgnoreList parse_ignore_rules(std::string_view content) {
    IgnoreList result;
    std::string_view remaining = content;
    while (!remaining.empty()) {
        const auto newline = remaining.find('\n');
        const auto line = newline == std::string_view::npos
                              ? remaining
                              : remaining.substr(0, newline);
        parse_rule_line(std::string(line), result);
        if (newline == std::string_view::npos)
            break;
        remaining = remaining.substr(newline + 1);
    }
    return result;
}

IgnoreList load_ignore_list(const std::filesystem::path& file_path) {
    IgnoreList result;
    std::error_code error;
    if (!std::filesystem::exists(file_path, error) || error)
        return result;
    std::ifstream input(file_path);
    std::string line;
    while (std::getline(input, line)) {
        parse_rule_line(std::move(line), result);
    }
    return result;
}

bool is_ignored(std::string_view path,
                const IgnoreList& ignore_list,
                bool is_directory) {
    if (is_reserved_internal(path)) {
        return true;
    }
    if (ignore_list.rules.empty()) {
        return false;
    }
    return ignores(ignore_list, path, is_directory);
}

} // namespace kasumi::ignore
