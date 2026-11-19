#include "platform/workspace.hpp"

#include "detail.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"
#include "workspace_fault_test.hpp"

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

std::string quarantine_label(const std::filesystem::path& root) {
    constexpr std::string_view prefix = ".kasumi-cleanup-";
    const auto name = platform::path::to_utf8(root.filename());
    if (name.starts_with(prefix)) {
        const auto separator = name.find('-', prefix.size());
        if (separator == prefix.size() + 32) {
            return name.substr(prefix.size(), 32);
        }
    }
    return name.size() == 32 ? name : "workspace";
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
    auto clear_attr = [](const std::filesystem::path& path,
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
    const auto attributes = GetFileAttributesW(native_root.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return std::unexpected("could not inspect workspace '" +
                               platform::path::to_utf8(root) +
                               "': " + windows_error(GetLastError()));
    }
    if (auto cleared = clear_attr(native_root, attributes); !cleared) {
        return cleared;
    }
    return detail::walk_windows_tree(
        native_root,
        false,
        [](void* ctx, const std::filesystem::path& path, std::uint32_t attrs) {
            return (*static_cast<decltype(clear_attr)*>(ctx))(path, attrs);
        },
        &clear_attr);
}

std::error_code remove_tree_windows(const std::filesystem::path& root) {
    std::error_code result;
    auto walked = detail::walk_windows_tree(
        root,
        true,
        [](void* ctx,
           const std::filesystem::path& path,
           std::uint32_t attrs) -> std::expected<void, std::string> {
            const BOOL ok = (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0
                                ? RemoveDirectoryW(path.c_str())
                                : DeleteFileW(path.c_str());
            if (!ok) {
                const auto code = GetLastError();
                if (code != ERROR_FILE_NOT_FOUND &&
                    code != ERROR_PATH_NOT_FOUND) {
                    *static_cast<std::error_code*>(ctx) = {
                        static_cast<int>(code), std::system_category()};
                    return std::unexpected(std::string{"remove"});
                }
            }
            return {};
        },
        &result);
    if (!walked && !result) {
        return std::make_error_code(std::errc::operation_not_permitted);
    }
    return result;
}

bool retryable_lock(std::error_code error) noexcept {
    return error.value() == ERROR_SHARING_VIOLATION ||
           error.value() == ERROR_LOCK_VIOLATION;
}

std::error_code rename_no_replace(const std::filesystem::path& source,
                                  const std::filesystem::path& destination) {
    std::error_code error;
    const auto native_source = extended_path(source, error);
    if (error) {
        return error;
    }
    const auto native_destination = extended_path(destination, error);
    if (error) {
        return error;
    }
    return detail::rename_no_replace(native_source, native_destination);
}

#else

std::error_code rename_no_replace(const std::filesystem::path& source,
                                  const std::filesystem::path& destination) {
    return detail::rename_no_replace(source, destination);
}

#endif

std::expected<Workspace, std::string>
identify_created_workspace(std::filesystem::path root) {
    const auto identity = private_storage::query_directory_identity(root);
    if (!identity.valid) {
        return std::unexpected("could not identify newly created workspace '" +
                               platform::path::to_utf8(root) + "'");
    }
    return Workspace{.root = std::move(root), .identity = identity};
}

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

            std::string name{"kasumi-"};
            name += purpose;
            name += '-';
            name += *id;
            const auto root = base / name;
            auto created = private_storage::create_directory(root);
            if (created) {
                return identify_created_workspace(root);
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

std::expected<Workspace, std::string>
create_workspace_at(const std::filesystem::path& root) {
    if (root.empty() || root.filename().empty()) {
        return std::unexpected("workspace path must name a directory");
    }
    auto created = private_storage::create_directory(root);
    if (!created) {
        return std::unexpected("could not create workspace '" +
                               platform::path::to_utf8(root) +
                               "': " + created.error());
    }
    return identify_created_workspace(root);
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
    if (error == std::errc::no_such_file_or_directory ||
        status.type() == std::filesystem::file_type::not_found) {
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
    if (!workspace.identity.valid) {
        return std::unexpected(
            "workspace ownership identity is unavailable for '" +
            platform::path::to_utf8(workspace.root) + "'");
    }
    if (private_storage::query_directory_identity(native_root) !=
        workspace.identity) {
        return std::unexpected("workspace identity changed before cleanup: '" +
                               platform::path::to_utf8(workspace.root) + "'");
    }

    std::filesystem::path quarantine;
    std::error_code quarantine_error;
    constexpr std::size_t maximum_attempts = 4;
    for (std::size_t attempt = 0; attempt < maximum_attempts; ++attempt) {
        auto id = random::hex_id();
        if (!id) {
            return std::unexpected(id.error());
        }
        quarantine =
            workspace.root.parent_path() /
            (".kasumi-cleanup-" + quarantine_label(workspace.root) + "-" + *id);
        quarantine_error = rename_no_replace(native_root, quarantine);
        if (!quarantine_error) {
            break;
        }
#ifdef _WIN32
        if (quarantine_error.value() == ERROR_ACCESS_DENIED &&
            attempt + 1 < maximum_attempts) {
#ifdef KASUMI_WORKSPACE_FAULT_TESTS
            workspace_fault_test::before_retry(
                workspace.root, attempt, quarantine_error);
#endif
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
            continue;
        }
#endif
        if (quarantine_error != std::errc::file_exists &&
            quarantine_error != std::errc::directory_not_empty) {
            return std::unexpected(
                "could not isolate workspace before cleanup '" +
                platform::path::to_utf8(workspace.root) +
                "': " + quarantine_error.message());
        }
    }
    if (quarantine_error) {
        return std::unexpected(
            "could not reserve a cleanup path for workspace '" +
            platform::path::to_utf8(workspace.root) + "'");
    }
    const auto restore = [&]() {
        return rename_no_replace(quarantine, native_root);
    };
    const auto fail_restoring = [&](std::string msg) {
        const auto restored = restore();
        if (restored) {
            msg += "; could not restore workspace path";
        }
        return std::unexpected(std::move(msg));
    };
#ifdef _WIN32
    const auto native_quarantine = extended_path(quarantine, error);
    if (error) {
        return fail_restoring("could not resolve quarantined workspace: " +
                              error.message());
    }
#else
    const auto& native_quarantine = quarantine;
#endif
    if (private_storage::query_directory_identity(native_quarantine) !=
        workspace.identity) {
        const auto restored = restore();
        return std::unexpected(
            "workspace identity changed during cleanup" +
            (restored ? "; unowned entry remains at '" +
                            platform::path::to_utf8(quarantine) + "'"
                      : std::string{}));
    }

    // shortcut: same-user writers can race inside quarantine; use
    // handle-relative recursive deletion if that threat is in scope.
    auto secured = private_storage::protect_tree(native_quarantine);
    if (!secured) {
        return fail_restoring(secured.error());
    }

#ifdef KASUMI_WORKSPACE_FAULT_TESTS
    if (workspace_fault_test::interrupt_cleanup(quarantine)) {
        return std::unexpected("workspace cleanup interrupted by test fault");
    }
#endif

#ifdef _WIN32
    const auto attributes = GetFileAttributesW(native_quarantine.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return fail_restoring("could not inspect workspace '" +
                              platform::path::to_utf8(workspace.root) +
                              "': " + windows_error(GetLastError()));
    }
    if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return fail_restoring("invalid workspace '" +
                              platform::path::to_utf8(workspace.root) + "'");
    }
    auto writable = clear_read_only(native_quarantine);
    if (!writable) {
        return fail_restoring(writable.error());
    }

    for (std::size_t attempt = 0; attempt < maximum_attempts; ++attempt) {
        error.clear();
        error = remove_tree_windows(native_quarantine);
        if (!error) {
            return {};
        }
        if (!retryable_lock(error) || attempt + 1 == maximum_attempts) {
            break;
        }
#ifdef KASUMI_WORKSPACE_FAULT_TESTS
        workspace_fault_test::before_retry(quarantine, attempt, error);
#endif
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
#else
    std::filesystem::remove_all(quarantine, error);
#endif
    if (error) {
        const auto restored = restore();
        auto detail = "could not remove workspace '" +
                      platform::path::to_utf8(workspace.root) +
                      "': " + error.message();
        if (restored) {
            detail += "; could not restore partial workspace from '" +
                      platform::path::to_utf8(quarantine) +
                      "': " + restored.message();
        } else {
            detail += "; partial workspace restored at original path";
        }
        return std::unexpected(std::move(detail));
    }
    return {};
}

void cleanup_workspace(const Workspace& workspace) noexcept {
    static_cast<void>(remove_workspace(workspace));
}

std::expected<void, std::string>
validate_non_redirecting_directory(const std::filesystem::path& path) {
    return private_storage::protect_directory(path);
}

} // namespace kasumi::platform
