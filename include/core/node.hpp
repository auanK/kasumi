#ifndef KASUMI_NODE_HPP
#define KASUMI_NODE_HPP

#include "hasher.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi {

// File or directory in a snapshot.
struct NodeRow {
    // Relative path; snapshot root uses an empty string.
    std::string path;
    // Content hash or directory composition hash.
    Hash hash{};
    // Files use byte length; directories sum descendant content sizes.
    uint64_t size = 0;
    // Observed last modification time.
    std::filesystem::file_time_type mtime{};
    // Distinguishes directories from regular files.
    bool is_directory = false;
};

// Compares all fields of two nodes.
inline bool operator==(const NodeRow& left, const NodeRow& right) noexcept {
    return left.path == right.path && left.hash == right.hash &&
           left.size == right.size && left.mtime == right.mtime &&
           left.is_directory == right.is_directory;
}

// Linearized tree; when present, empty root precedes descendants.
struct Snapshot {
    // Nodes ordered by path hierarchy.
    std::vector<NodeRow> rows;
};

// Compares all rows of two snapshots.
inline bool operator==(const Snapshot& left, const Snapshot& right) noexcept {
    return left.rows == right.rows;
}

// Maximum byte length of a single logical path component.
inline constexpr std::size_t maximum_logical_component_length = 255;

// Validates that a single path component is safe, portable, and valid UTF-8.
bool valid_logical_path_component(std::string_view name) noexcept;

// Generates a deterministic, platform-independent Unicode case key for collision detection.
std::string portable_case_key(std::string_view logical_path);

// Returns the Unicode version used for portable case keys.
std::string_view unicode_version() noexcept;

// Generates a length-bounded, valid, portable conflict path.
std::string make_conflict_path(std::string_view original_path,
                               std::string_view suffix);

// Orders paths by components, placing parents before descendants.
bool path_less(std::string_view left, std::string_view right);

// Validates root, ordering, hierarchy, and path security.
bool valid_snapshot(const Snapshot& snapshot, bool allow_empty);

// Looks up a node by exact path in a sorted snapshot.
const NodeRow* find_row(const Snapshot& snapshot, std::string_view path);

// Looks up a mutable node by exact path in a sorted snapshot.
NodeRow* find_row(Snapshot& snapshot, std::string_view path);

// Indicates whether path is strictly below parent.
bool is_descendant(std::string_view path, std::string_view parent);

// Returns the last component of the path.
std::string_view row_name(std::string_view path);

// Returns the parent directory path.
std::string_view row_parent(std::string_view path);

// Sorts and recomputes hash and size for directories.
void finalize_snapshot(Snapshot& snapshot);

} // namespace kasumi

#endif
