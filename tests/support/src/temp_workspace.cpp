#include "kasumi/test/temp_workspace.hpp"

#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <random>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

namespace kasumi::test {
namespace {

std::atomic<std::uint64_t> workspace_sequence{0};

std::string unique_suffix() {
    const auto random_value = std::random_device{}();
    return std::to_string(random_value) + "-" +
           std::to_string(
               std::chrono::steady_clock::now().time_since_epoch().count());
}

std::string sanitize_label(std::string_view label) {
    constexpr std::size_t max_label_size = 40;
    std::string sanitized;
    sanitized.reserve(label.size());
    for (const char value : label) {
        const auto byte = static_cast<unsigned char>(value);
        sanitized.push_back(
            std::isalnum(byte) != 0 || value == '-' || value == '_' ? value
                                                                    : '-');
        if (sanitized.size() == max_label_size) {
            break;
        }
    }
    return sanitized.empty() ? "workspace" : sanitized;
}

} // namespace

TempWorkspace make_temp_workspace(std::string_view label) {
    const auto temporary_directory = std::filesystem::temp_directory_path();
    const auto safe_label = sanitize_label(label);
    constexpr std::size_t maximum_attempts = 64;
    for (std::size_t attempt = 0; attempt < maximum_attempts; ++attempt) {
        const auto sequence =
            workspace_sequence.fetch_add(1, std::memory_order_relaxed);
#if defined(_WIN32)
        const auto name =
            "k-" + std::to_string(sequence) + "-" + unique_suffix();
#else
        const auto name = "kasumi-test-" + safe_label + "-" +
                          std::to_string(sequence) + "-" + unique_suffix();
#endif
        auto candidate = temporary_directory / name;
        std::error_code error;
        if (std::filesystem::create_directory(candidate, error)) {
            return TempWorkspace{new TempWorkspaceData{std::move(candidate)},
                                 remove_temp_workspace};
        }
        if (error) {
            throw std::filesystem::filesystem_error(
                "could not create temporary test workspace", candidate, error);
        }
    }
    throw std::runtime_error("could not allocate a unique test workspace");
}

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void clean_windows_tree(const std::filesystem::path& root) noexcept {
    std::error_code ec;
    for (std::filesystem::recursive_directory_iterator
             it(root, std::filesystem::directory_options::none, ec),
         end;
         it != end && !ec;) {
        const auto path = it->path();
        const auto attrs = GetFileAttributesW(path.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES &&
            (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            it.disable_recursion_pending();
            it.increment(ec);
            if ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                RemoveDirectoryW(path.c_str());
            } else {
                DeleteFileW(path.c_str());
            }
            continue;
        }
        if (attrs != INVALID_FILE_ATTRIBUTES &&
            (attrs & FILE_ATTRIBUTE_READONLY) != 0) {
            SetFileAttributesW(
                path.c_str(),
                attrs & ~static_cast<DWORD>(FILE_ATTRIBUTE_READONLY));
        }
        it.increment(ec);
    }
}
#endif

void remove_temp_workspace(TempWorkspaceData* workspace) noexcept {
    if (workspace != nullptr && !workspace->root.empty()) {
#if defined(_WIN32)
        clean_windows_tree(workspace->root);
#endif
        std::error_code ignored;
        std::filesystem::remove_all(workspace->root, ignored);
    }
    delete workspace;
}

const std::filesystem::path&
workspace_root(const TempWorkspace& workspace) noexcept {
    return workspace->root;
}

std::filesystem::path workspace_path(const TempWorkspace& workspace,
                                     const std::filesystem::path& relative) {
    if (relative.is_absolute() || relative.has_root_name() ||
        relative.has_root_directory()) {
        throw std::invalid_argument("workspace path must be relative");
    }
    for (const auto& component : relative) {
        if (component == "..") {
            throw std::invalid_argument(
                "workspace path cannot contain a parent traversal");
        }
    }
    const auto normalized = relative.lexically_normal();
    return normalized.empty() || normalized == "."
               ? workspace->root
               : workspace->root / normalized;
}

} // namespace kasumi::test
