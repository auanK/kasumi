#include "core/ignore.hpp"

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

struct PathSlice {
    std::string_view text;
    bool is_directory = false;
};

inline bool slice_matches(const IgnoreRule& rule, const PathSlice& slice) {
    if (rule.directory_only && !slice.is_directory) {
        return false;
    }
    if (rule.pattern.find('/') == std::string::npos &&
        rule.pattern.find("**") == std::string::npos &&
        slice.text.find('/') != std::string_view::npos) {
        return false;
    }
    const auto first_star = rule.pattern.find('*');
    const auto first_qmark = rule.pattern.find('?');
    // Fast path: literal pattern without wildcards
    if (first_star == std::string::npos && first_qmark == std::string::npos) {
        return slice.text == rule.pattern;
    }
    // Fast path: *.extension pattern (starts with '*', no other wildcards)
    if (first_star == 0 && first_qmark == std::string::npos &&
        rule.pattern.find('*', 1) == std::string::npos) {
        const std::string_view suffix =
            std::string_view(rule.pattern).substr(1);
        return slice.text.size() >= suffix.size() &&
               slice.text.ends_with(suffix);
    }
    return glob_matches(rule.pattern, slice.text);
}

// Fallback algorithm for patterns with unanchored '**' and no '/'
bool fallback_rule_matches(const IgnoreRule& rule,
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

bool rule_matches(const IgnoreRule& rule,
                  std::string_view path,
                  bool is_directory,
                  std::span<const PathSlice> prefixes,
                  std::span<const PathSlice> components) {
    const bool has_slash = rule.pattern.find('/') != std::string::npos;

    // Case 1: Anchored rule OR pattern contains '/'
    // Only prefixes (start == 0) can ever match.
    if (rule.anchored || has_slash) {
        for (const auto& prefix : prefixes) {
            if (slice_matches(rule, prefix)) {
                return true;
            }
        }
        return false;
    }

    // Case 2: Not anchored, pattern has no '/'
    // If pattern has no '**', it can never match any string containing '/'!
    // Therefore only single components can match.
    if (rule.pattern.find("**") == std::string::npos) {
        for (const auto& comp : components) {
            if (slice_matches(rule, comp)) {
                return true;
            }
        }
        return false;
    }

    // Case 3: Not anchored, no '/', but contains '**'
    return fallback_rule_matches(rule, path, is_directory);
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
    // Stack-allocated buffers for zero heap allocation for paths with depth <= 32
    std::array<PathSlice, 32> stack_prefixes{};
    std::array<PathSlice, 32> stack_components{};
    std::vector<PathSlice> heap_prefixes;
    std::vector<PathSlice> heap_components;

    std::span<const PathSlice> prefixes;
    std::span<const PathSlice> components;

    std::size_t count = 0;
    std::size_t start = 0;
    while (start <= path.size() && count < stack_prefixes.size()) {
        const auto slash = path.find('/', start);
        const auto end =
            (slash == std::string_view::npos) ? path.size() : slash;
        const bool comp_is_dir = (end < path.size()) || is_directory;

        stack_components[count] = {path.substr(start, end - start), comp_is_dir};
        stack_prefixes[count] = {path.substr(0, end), comp_is_dir};
        ++count;

        if (slash == std::string_view::npos)
            break;
        start = slash + 1;
    }

    if (start <= path.size() && count == stack_prefixes.size()) {
        // Fallback for paths deeper than 32 components
        heap_components.assign(stack_components.begin(), stack_components.end());
        heap_prefixes.assign(stack_prefixes.begin(), stack_prefixes.end());
        while (start <= path.size()) {
            const auto slash = path.find('/', start);
            const auto end =
                (slash == std::string_view::npos) ? path.size() : slash;
            const bool comp_is_dir = (end < path.size()) || is_directory;
            heap_components.push_back(
                {path.substr(start, end - start), comp_is_dir});
            heap_prefixes.push_back({path.substr(0, end), comp_is_dir});
            if (slash == std::string_view::npos)
                break;
            start = slash + 1;
        }
        prefixes = heap_prefixes;
        components = heap_components;
    } else {
        prefixes = std::span<const PathSlice>(stack_prefixes.data(), count);
        components = std::span<const PathSlice>(stack_components.data(), count);
    }

    // Evaluating rules in reverse order: the first matching rule is the
    // last applicable rule in forward order and dictates the final result.
    for (auto it = list.rules.rbegin(); it != list.rules.rend(); ++it) {
        if (rule_matches(*it, path, is_directory, prefixes, components)) {
            return !it->negated;
        }
    }
    return false;
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
