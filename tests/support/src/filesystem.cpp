#include "kasumi/test/filesystem.hpp"

#include <algorithm>
#include <cstddef>
#include <fstream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace kasumi::test {
namespace {

void create_parent_directories(const std::filesystem::path& path) {
    const auto parent = path.parent_path();
    if (parent.empty()) {
        return;
    }

    std::error_code error;
    std::filesystem::create_directories(parent, error);
    if (error) {
        throw std::filesystem::filesystem_error(
            "could not create parent directories", parent, error);
    }
}

std::ifstream open_input(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("could not open file for reading: " +
                                 path.string());
    }
    return input;
}

std::ofstream open_output(const std::filesystem::path& path) {
    create_parent_directories(path);
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("could not open file for writing: " +
                                 path.string());
    }
    return output;
}

std::string generic_utf8(const std::filesystem::path& path) {
    const auto value = path.generic_u8string();
    return {reinterpret_cast<const char*>(value.data()), value.size()};
}

} // namespace

void write_text(const std::filesystem::path& path, std::string_view contents) {
    auto output = open_output(path);
    if (contents.size() >
        static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
        throw std::length_error("text content is too large to write");
    }

    if (!contents.empty()) {
        output.write(contents.data(),
                     static_cast<std::streamsize>(contents.size()));
    }
    output.close();
    if (!output) {
        throw std::runtime_error("could not write file: " + path.string());
    }
}

std::string read_text(const std::filesystem::path& path) {
    auto input = open_input(path);
    std::string contents{std::istreambuf_iterator<char>(input),
                         std::istreambuf_iterator<char>()};
    if (input.bad()) {
        throw std::runtime_error("could not read file: " + path.string());
    }
    return contents;
}

void write_binary(const std::filesystem::path& path,
                  std::span<const std::byte> contents) {
    auto output = open_output(path);
    if (contents.size() >
        static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
        throw std::length_error("binary content is too large to write");
    }

    if (!contents.empty()) {
        output.write(reinterpret_cast<const char*>(contents.data()),
                     static_cast<std::streamsize>(contents.size()));
    }
    output.close();
    if (!output) {
        throw std::runtime_error("could not write file: " + path.string());
    }
}

void write_binary(const std::filesystem::path& path,
                  std::initializer_list<std::byte> contents) {
    write_binary(path,
                 std::span<const std::byte>(contents.begin(), contents.size()));
}

BinaryData read_binary(const std::filesystem::path& path) {
    const auto text = read_text(path);
    BinaryData contents;
    contents.reserve(text.size());
    for (const char value : text) {
        contents.push_back(
            static_cast<std::byte>(static_cast<unsigned char>(value)));
    }
    return contents;
}

TreeSnapshot snapshot_tree(const std::filesystem::path& root) {
    std::error_code status_error;
    if (!std::filesystem::is_directory(root, status_error)) {
        if (status_error) {
            throw std::filesystem::filesystem_error(
                "could not inspect directory tree", root, status_error);
        }
        throw std::invalid_argument("tree root is not a directory: " +
                                    root.string());
    }

    TreeSnapshot snapshot;
    std::error_code iterator_error;
    std::filesystem::recursive_directory_iterator iterator(root,
                                                           iterator_error);
    const std::filesystem::recursive_directory_iterator end;
    if (iterator_error) {
        throw std::filesystem::filesystem_error(
            "could not enumerate directory tree", root, iterator_error);
    }

    while (iterator != end) {
        const auto entry_path = iterator->path();
        std::error_code entry_error;
        const auto status = iterator->symlink_status(entry_error);
        if (entry_error) {
            throw std::filesystem::filesystem_error(
                "could not inspect directory entry", entry_path, entry_error);
        }

        TreeEntry entry;
        entry.relative_path = generic_utf8(entry_path.lexically_relative(root));
        if (std::filesystem::is_symlink(status)) {
            entry.kind = TreeEntryKind::Symlink;
            const auto target =
                std::filesystem::read_symlink(entry_path, entry_error);
            if (entry_error) {
                throw std::filesystem::filesystem_error(
                    "could not read symbolic link", entry_path, entry_error);
            }
            entry.symlink_target = generic_utf8(target);
        } else if (std::filesystem::is_directory(status)) {
            entry.kind = TreeEntryKind::Directory;
        } else if (std::filesystem::is_regular_file(status)) {
            entry.kind = TreeEntryKind::RegularFile;
            entry.contents = read_binary(entry_path);
        } else {
            entry.kind = TreeEntryKind::Other;
        }
        snapshot.push_back(std::move(entry));

        iterator.increment(iterator_error);
        if (iterator_error) {
            throw std::filesystem::filesystem_error(
                "could not enumerate directory tree", root, iterator_error);
        }
    }

    std::ranges::sort(snapshot, {}, &TreeEntry::relative_path);
    return snapshot;
}

bool has_temporary_history_workspace(const std::filesystem::path& root) {
    std::error_code error;
    for (const auto& entry : std::filesystem::directory_iterator(root, error)) {
        if (entry.path().filename().string().starts_with(".kasumi-history-")) {
            return true;
        }
    }
    return static_cast<bool>(error);
}

} // namespace kasumi::test
