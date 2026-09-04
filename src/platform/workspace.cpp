#include "platform/workspace.hpp"

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
    const std::filesystem::path path{std::string{name}};
    return !name.empty() && path == path.filename() && !path.is_absolute() &&
           !path.has_root_name() && !path.has_root_directory() && path != "." &&
           path != "..";
}

#ifdef _WIN32

std::string windows_error(DWORD code) {
    return std::error_code{static_cast<int>(code), std::system_category()}
        .message();
}

std::expected<void, std::string>
clear_read_only(const std::filesystem::path& root) {
    std::vector<std::filesystem::path> paths{root};
    std::error_code error;
    {
        std::filesystem::recursive_directory_iterator entries(root, error);
        if (error) {
            return std::unexpected("não foi possível enumerar o espaço de trabalho '" +
                                   root.string() + "': " + error.message());
        }
        const std::filesystem::recursive_directory_iterator end;
        while (entries != end) {
            const auto path = entries->path();
            const auto attributes = GetFileAttributesW(path.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES) {
                return std::unexpected("não foi possível inspecionar o caminho do espaço de trabalho '" +
                                       path.string() +
                                       "': " + windows_error(GetLastError()));
            }
            if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                return std::unexpected("caminho inválido do espaço de trabalho '" +
                                       path.string() +
                                       "': ponto de nova análise (reparse point) não é permitido");
            }
            paths.push_back(path);
            entries.increment(error);
            if (error) {
                return std::unexpected("não foi possível enumerar o espaço de trabalho '" +
                                       root.string() + "': " + error.message());
            }
        }
    }

    for (const auto& path : paths) {
        const auto attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            const auto code = GetLastError();
            if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) {
                continue;
            }
            return std::unexpected("não foi possível inspecionar o caminho do espaço de trabalho '" +
                                   path.string() + "': " + windows_error(code));
        }
        if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            continue;
        }
        if ((attributes & FILE_ATTRIBUTE_READONLY) != 0 &&
            !SetFileAttributesW(
                path.c_str(),
                attributes & ~static_cast<DWORD>(FILE_ATTRIBUTE_READONLY))) {
            return std::unexpected("não foi possível limpar o atributo somente leitura em '" +
                                   path.string() +
                                   "': " + windows_error(GetLastError()));
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
        return std::unexpected(
            "o propósito do workspace contém caracteres inválidos");
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
                    "não foi possível criar workspace temporário: " +
                    created.error());
            }
        }
    } catch (const std::exception& exception) {
        return std::unexpected(
            std::string{"não foi possível criar workspace temporário: "} +
            exception.what());
    }

    return std::unexpected("não foi possível criar workspace temporário único");
}

std::filesystem::path workspace_file(const Workspace& workspace,
                                     std::size_t index,
                                     std::string_view extension) {
    if (!valid_extension(extension)) {
        return {};
    }
    return workspace.root / (std::to_string(index) + std::string{extension});
}

std::filesystem::path workspace_file(const Workspace& workspace,
                                     std::string_view name) {
    if (!valid_name(name)) {
        return {};
    }
    return workspace.root / std::filesystem::path{std::string{name}};
}

std::expected<void, std::string> remove_workspace(const Workspace& workspace) {
    if (workspace.root.empty()) {
        return {};
    }
    std::error_code error;
    const auto status = std::filesystem::symlink_status(workspace.root, error);
    if (error == std::errc::no_such_file_or_directory) {
        return {};
    }
    if (error) {
        return std::unexpected("não foi possível inspecionar o espaço de trabalho '" +
                               workspace.root.string() +
                               "': " + error.message());
    }
    if (std::filesystem::is_symlink(status) ||
        !std::filesystem::is_directory(status)) {
        return std::unexpected("espaço de trabalho inválido '" + workspace.root.string() +
                               "'");
    }
    auto secured = private_storage::protect_tree(workspace.root);
    if (!secured) {
        return std::unexpected(secured.error());
    }

#ifdef _WIN32
    const auto attributes = GetFileAttributesW(workspace.root.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return std::unexpected("não foi possível inspecionar o espaço de trabalho '" +
                               workspace.root.string() +
                               "': " + windows_error(GetLastError()));
    }
    if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return std::unexpected("espaço de trabalho inválido '" + workspace.root.string() +
                               "'");
    }
    auto writable = clear_read_only(workspace.root);
    if (!writable) {
        return std::unexpected(writable.error());
    }

    constexpr std::size_t maximum_attempts = 4;
    for (std::size_t attempt = 0; attempt < maximum_attempts; ++attempt) {
        error.clear();
        std::filesystem::remove_all(workspace.root, error);
        if (!error) {
            return {};
        }
        if (!retryable_lock(error) || attempt + 1 == maximum_attempts) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
#else
    std::filesystem::remove_all(workspace.root, error);
#endif
    if (error) {
        return std::unexpected("não foi possível remover o espaço de trabalho '" +
                               workspace.root.string() +
                               "': " + error.message());
    }
    return {};
}

void cleanup_workspace(const Workspace& workspace) noexcept {
    const auto trace = perf_trace::begin();
    static_cast<void>(remove_workspace(workspace));
    perf_trace::finish("workspace cleanup", trace);
}

std::expected<void, std::string> validate_non_redirecting_directory(const std::filesystem::path& path) {
    return private_storage::protect_directory(path);
}

} // namespace kasumi::platform
