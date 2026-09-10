#ifndef KASUMI_PLATFORM_WORKSPACE_HPP
#define KASUMI_PLATFORM_WORKSPACE_HPP

#include <cstddef>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>

namespace kasumi::platform {

// Isolated temporary directory used by an operation.
struct Workspace {
    std::filesystem::path root;
};

// Creates an exclusive temporary directory for the specified purpose.
std::expected<Workspace, std::string>
create_workspace(std::string_view purpose);

// Builds an indexed path; returns empty path if extension is unsafe.
std::filesystem::path workspace_file(const Workspace& workspace,
                                     std::size_t index,
                                     std::string_view extension);

// Builds a named path; returns empty path if name is unsafe.
std::filesystem::path workspace_file(const Workspace& workspace,
                                     std::string_view name);

// Removes only validated directories, never symbolic links.
std::expected<void, std::string> remove_workspace(const Workspace& workspace);

// Attempts to remove directory without propagating errors.
void cleanup_workspace(const Workspace& workspace) noexcept;

// Validates that the path exists, is a directory, and is not a redirector
// (symlink/junction).
std::expected<void, std::string>
validate_non_redirecting_directory(const std::filesystem::path& path);

} // namespace kasumi::platform

#endif
