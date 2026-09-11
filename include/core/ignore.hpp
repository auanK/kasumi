#ifndef KASUMI_CORE_IGNORE_HPP
#define KASUMI_CORE_IGNORE_HPP

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::ignore {

inline constexpr std::size_t max_ignore_pattern_size = 255;

struct IgnoreRule {
    std::string pattern;
    bool negated = false;
    bool anchored = false;
    bool directory_only = false;

    bool operator==(const IgnoreRule&) const = default;
};

struct IgnoreList {
    std::vector<IgnoreRule> rules;

    bool operator==(const IgnoreList&) const = default;
};

// Checks if a path matches internal metadata files reserved by Kasumi.
bool is_reserved_internal(std::string_view path);

// Parses ignore rules from raw text (e.g. .kasumiignore file content).
IgnoreList parse_ignore_rules(std::string_view content);

// Loads ignore rules from a file if it exists.
IgnoreList load_ignore_list(const std::filesystem::path& file_path);

// Checks if a relative path is ignored according to internal rules and ignore
// list.
bool is_ignored(std::string_view path,
                const IgnoreList& ignore_list,
                bool is_directory);

} // namespace kasumi::ignore

#endif
