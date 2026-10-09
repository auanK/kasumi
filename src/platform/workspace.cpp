#include "platform/workspace.hpp"

#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"

#include <algorithm>
#include <chrono>
#include <exception>
#include <system_error>
#include <thread>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace kasumi::platform {

namespace {

bool valid_purpose(std::string_view purpose) noexcept {
    return !purpose.empty() && std::ranges::all_of(purpose, [](char value) {
        const bool ascii_letter =
            (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z');
        const bool ascii_digit = value >= '0' && value <= '9';
        return ascii_letter || ascii_digit || value == '-' || value == '_';
    });
}

bool valid_extension(std::string_view extension) noexcept {
    return extension.find('/') == std::string_view::npos &&
           extension.find('\\') == std::string_view::npos &&
           extension.find("..") == std::string_view::npos;
}

bool valid_name(std::string_view name) noexcept {
    const auto path = platform::path::from_utf8(name);
    return !name.empty() && path == path.filename() && !path.is_absolute() &&
           !path.has_root_name() && !path.has_root_directory() && path != "." &&
           path != "..";
}

#ifdef _WIN32

std::string windows_error(DWORD code) {
    return std::error_code{static_cast<int>(code), std::system_category()}
        .message();
}

std::filesystem::path extended_path(const std::filesystem::path& path,
                                    std::error_code& error) {
    if (path.native().starts_with(L"\\\\?\\")) {
        return path;
    }
    auto absolute =
        path.is_absolute() ? path : std::filesystem::absolute(path, error);
    if (error) {
        return {};
    }
    absolute = absolute.lexically_normal();
    auto native = absolute.native();
    if (native.starts_with(L"\\\\")) {
        native.replace(0, 2, L"\\\\?\\UNC\\");
    } else {
        native.insert(0, L"\\\\?\\");
    }
    return std::filesystem::path{std::move(native)};
}

std::expected<void, std::string>
clear_read_only(const std::filesystem::path& root) {
    std::error_code error;
    const auto native_root = extended_path(root, error);
    if (error) {
        return std::unexpected("could not resolve workspace '" +
                               platform::path::to_utf8(root) +
                               "': " + error.message());
    }

    const auto clear_attribute =
        [](const std::filesystem::path& path,
           DWORD attributes) -> std::expected<void, std::string> {
        if ((attributes & FILE_ATTRIBUTE_READONLY) != 0 &&
            !SetFileAttributesW(
                path.c_str(),
                attributes & ~static_cast<DWORD>(FILE_ATTRIBUTE_READONLY))) {
            const auto code = GetLastError();
            if (code != ERROR_FILE_NOT_FOUND && code != ERROR_PATH_NOT_FOUND) {
                return std::unexpected(
                    "could not clear read-only attribute on '" +
                    platform::path::to_utf8(path) +
                    "': " + windows_error(code));
            }
        }
        return {};
    };

    auto attributes = GetFileAttributesW(native_root.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return std::unexpected("could not inspect workspace '" +
                               platform::path::to_utf8(root) +
                               "': " + windows_error(GetLastError()));
    }
    if (auto cleared = clear_attribute(native_root, attributes); !cleared) {
        return cleared;
    }

    std::vector<std::filesystem::path> directories{native_root};
    while (!directories.empty()) {
        auto directory = std::move(directories.back());
        directories.pop_back();
        WIN32_FIND_DATAW entry{};
        auto pattern = directory.native();
        pattern.append(L"\\*");
        const auto search = FindFirstFileW(pattern.c_str(), &entry);
        if (search == INVALID_HANDLE_VALUE) {
            const auto code = GetLastError();
            if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) {
                continue;
            }
            return std::unexpected("could not enumerate workspace '" +
                                   platform::path::to_utf8(directory) +
                                   "': " + windows_error(code));
        }

        std::string failure;
        do {
            const std::wstring_view name{entry.cFileName};
            if (name == L"." || name == L"..") {
                continue;
            }
            auto native_path = directory.native();
            native_path.push_back(L'\\');
            native_path.append(entry.cFileName);
            const std::filesystem::path path{std::move(native_path)};
            if ((entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                failure = "invalid workspace path '" +
                          platform::path::to_utf8(path) +
                          "': reparse point is not allowed";
                break;
            }
            auto cleared = clear_attribute(path, entry.dwFileAttributes);
            if (!cleared) {
                failure = cleared.error();
                break;
            }
            if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                directories.push_back(path);
            }
        } while (FindNextFileW(search, &entry));

        const auto enumeration_error = GetLastError();
        FindClose(search);
        if (!failure.empty()) {
            return std::unexpected(std::move(failure));
        }
        if (enumeration_error != ERROR_NO_MORE_FILES &&
            enumeration_error != ERROR_FILE_NOT_FOUND &&
            enumeration_error != ERROR_PATH_NOT_FOUND) {
            return std::unexpected("could not advance in workspace '" +
                                   platform::path::to_utf8(directory) +
                                   "': " + windows_error(enumeration_error));
        }
    }
    return {};
}

std::error_code remove_tree_windows(const std::filesystem::path& root) {
    std::vector<std::pair<std::filesystem::path, bool>> pending{{root, false}};
    while (!pending.empty()) {
        auto [path, postorder] = std::move(pending.back());
        pending.pop_back();
        if (postorder) {
            if (!RemoveDirectoryW(path.c_str())) {
                const auto code = GetLastError();
                if (code != ERROR_FILE_NOT_FOUND &&
                    code != ERROR_PATH_NOT_FOUND) {
                    return {static_cast<int>(code), std::system_category()};
                }
            }
            continue;
        }

        auto pattern = path.native();
        pattern.append(L"\\*");
        WIN32_FIND_DATAW entry{};
        const auto search = FindFirstFileW(pattern.c_str(), &entry);
        if (search == INVALID_HANDLE_VALUE) {
            const auto code = GetLastError();
            if (code != ERROR_FILE_NOT_FOUND && code != ERROR_PATH_NOT_FOUND) {
                return {static_cast<int>(code), std::system_category()};
            }
            pending.emplace_back(std::move(path), true);
            continue;
        }

        pending.emplace_back(path, true);
        std::error_code failure;
        do {
            const std::wstring_view name{entry.cFileName};
            if (name == L"." || name == L"..") {
                continue;
            }
            auto native_child = path.native();
            native_child.push_back(L'\\');
            native_child.append(entry.cFileName);
            std::filesystem::path child{std::move(native_child)};
            if ((entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                failure =
                    std::make_error_code(std::errc::operation_not_permitted);
                break;
            }
            if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                pending.emplace_back(std::move(child), false);
            } else if (!DeleteFileW(child.c_str())) {
                const auto code = GetLastError();
                if (code != ERROR_FILE_NOT_FOUND &&
                    code != ERROR_PATH_NOT_FOUND) {
                    failure = {static_cast<int>(code), std::system_category()};
                    break;
                }
            }
        } while (FindNextFileW(search, &entry));

        const auto enumeration_error = GetLastError();
        FindClose(search);
        if (failure) {
            return failure;
        }
        if (enumeration_error != ERROR_NO_MORE_FILES &&
            enumeration_error != ERROR_FILE_NOT_FOUND &&
            enumeration_error != ERROR_PATH_NOT_FOUND) {
            return {static_cast<int>(enumeration_error),
                    std::system_category()};
        }
    }
    return {};
}

bool retryable_lock(std::error_code error) noexcept {
    return error.value() == ERROR_SHARING_VIOLATION ||
           error.value() == ERROR_LOCK_VIOLATION;
}

#endif

} // namespace

std::expected<Workspace, std::string>
create_workspace(std::string_view purpose) {
    if (!valid_purpose(purpose)) {
        return std::unexpected("workspace purpose contains invalid characters");
    }

    try {
        const auto base = std::filesystem::temp_directory_path();
        for (std::size_t attempt = 0; attempt < 32; ++attempt) {
            auto id = random::hex_id();
            if (!id) {
                return std::unexpected(id.error());
            }

            const auto root =
                base / ("kasumi-" + std::string{purpose} + "-" + *id);
            auto created = private_storage::create_directory(root);
            if (created) {
                return Workspace{.root = root};
            }
            std::error_code exists_error;
            if (!std::filesystem::exists(root, exists_error) || exists_error) {
                return std::unexpected(
                    "could not create temporary workspace: " + created.error());
            }
        }
    } catch (const std::exception& exception) {
        return std::unexpected(
            std::string{"could not create temporary workspace: "} +
            exception.what());
    }

    return std::unexpected("could not create unique temporary workspace");
}

std::filesystem::path workspace_file(const Workspace& workspace,
                                     std::size_t index,
                                     std::string_view extension) {
    if (!valid_extension(extension)) {
        return {};
    }
    return workspace.root / platform::path::from_utf8(std::to_string(index) +
                                                      std::string{extension});
}

std::filesystem::path workspace_file(const Workspace& workspace,
                                     std::string_view name) {
    if (!valid_name(name)) {
        return {};
    }
    return workspace.root / platform::path::from_utf8(name);
}

std::expected<void, std::string> remove_workspace(const Workspace& workspace) {
    if (workspace.root.empty()) {
        return {};
    }
    std::error_code error;
#ifdef _WIN32
    const auto native_root = extended_path(workspace.root, error);
    if (error) {
        return std::unexpected("could not resolve workspace '" +
                               platform::path::to_utf8(workspace.root) +
                               "': " + error.message());
    }
#else
    const auto& native_root = workspace.root;
#endif
    const auto status = std::filesystem::symlink_status(native_root, error);
    if (error == std::errc::no_such_file_or_directory) {
        return {};
    }
    if (error) {
        return std::unexpected("could not inspect workspace '" +
                               platform::path::to_utf8(workspace.root) +
                               "': " + error.message());
    }
    if (std::filesystem::is_symlink(status) ||
        !std::filesystem::is_directory(status)) {
        return std::unexpected("invalid workspace '" +
                               platform::path::to_utf8(workspace.root) + "'");
    }
    auto secured = private_storage::protect_tree(native_root);
    if (!secured) {
        return std::unexpected(secured.error());
    }

#ifdef _WIN32
    const auto attributes = GetFileAttributesW(native_root.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return std::unexpected("could not inspect workspace '" +
                               platform::path::to_utf8(workspace.root) +
                               "': " + windows_error(GetLastError()));
    }
    if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return std::unexpected("invalid workspace '" +
                               platform::path::to_utf8(workspace.root) + "'");
    }
    auto writable = clear_read_only(native_root);
    if (!writable) {
        return std::unexpected(writable.error());
    }

    constexpr std::size_t maximum_attempts = 4;
    for (std::size_t attempt = 0; attempt < maximum_attempts; ++attempt) {
        error.clear();
        error = remove_tree_windows(native_root);
        if (!error) {
            return {};
        }
        if (!retryable_lock(error) || attempt + 1 == maximum_attempts) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
#else
    std::filesystem::remove_all(native_root, error);
#endif
    if (error) {
        return std::unexpected("could not remove workspace '" +
                               platform::path::to_utf8(workspace.root) +
                               "': " + error.message());
    }
    return {};
}

void cleanup_workspace(const Workspace& workspace) noexcept {
    const auto trace = perf_trace::begin();
    static_cast<void>(remove_workspace(workspace));
    perf_trace::finish("workspace cleanup", trace);
}

std::expected<void, std::string>
validate_non_redirecting_directory(const std::filesystem::path& path) {
    return private_storage::protect_directory(path);
}

} // namespace kasumi::platform
