#ifndef KASUMI_TEST_FILESYSTEM_HPP
#define KASUMI_TEST_FILESYSTEM_HPP

#include <cstddef>
#include <filesystem>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::test {

using BinaryData = std::vector<std::byte>;

void write_text(const std::filesystem::path& path, std::string_view contents);
[[nodiscard]] std::string read_text(const std::filesystem::path& path);

void write_binary(const std::filesystem::path& path,
                  std::span<const std::byte> contents);
void write_binary(const std::filesystem::path& path,
                  std::initializer_list<std::byte> contents);
[[nodiscard]] BinaryData read_binary(const std::filesystem::path& path);

[[nodiscard]] bool
has_temporary_history_workspace(const std::filesystem::path& root);

enum class TreeEntryKind {
    Directory,
    RegularFile,
    Symlink,
    Other,
};

struct TreeEntry {
    std::string relative_path;
    TreeEntryKind kind = TreeEntryKind::Other;
    BinaryData contents;
    std::string symlink_target;
    bool operator==(const TreeEntry&) const = default;
};

using TreeSnapshot = std::vector<TreeEntry>;

[[nodiscard]] TreeSnapshot snapshot_tree(const std::filesystem::path& root);

} // namespace kasumi::test

#endif
