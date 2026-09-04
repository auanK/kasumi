#include "runtime/paths.hpp"

#include "runtime/profile.hpp"

#include "platform/private_storage.hpp"

#include <cstdlib>
#include <optional>
#include <string>
#include <utility>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace kasumi::runtime {

namespace {

#if defined(_WIN32)
std::optional<std::filesystem::path>
get_windows_environment_path(const wchar_t* name) {
    DWORD required_size = ::GetEnvironmentVariableW(name, nullptr, 0);
    if (required_size == 0) {
        return std::nullopt;
    }

    std::wstring buffer;
    while (required_size > 0) {
        buffer.resize(required_size);
        const DWORD actual =
            ::GetEnvironmentVariableW(name, buffer.data(), required_size);
        if (actual == 0) {
            return std::nullopt;
        }
        if (actual < required_size) {
            buffer.resize(actual);
            if (buffer.empty()) {
                return std::nullopt;
            }
            return std::filesystem::path(std::move(buffer));
        }
        required_size = actual;
    }
    return std::nullopt;
}
#endif

} // namespace

GlobalPaths global_paths_from_root(const std::filesystem::path& app_data_dir) {
    return GlobalPaths{.app_data_dir = app_data_dir,
                       .config_path = app_data_dir / "config.toml",
                       .profiles_dir = app_data_dir / "profiles"};
}

GlobalPaths default_global_paths() {
    std::filesystem::path app_dir;

#if defined(_WIN32)
    const auto appdata = get_windows_environment_path(L"APPDATA");
    if (appdata.has_value() && !appdata->empty()) {
        app_dir = *appdata / "kasumi";
    } else {
        app_dir = std::filesystem::current_path() / ".kasumi_data";
    }
#else
    const char* xdg_config_home = std::getenv("XDG_CONFIG_HOME");
    if (xdg_config_home && *xdg_config_home) {
        app_dir = std::filesystem::path(xdg_config_home) / "kasumi";
    } else {
        const char* home = std::getenv("HOME");
        if (home) {
            app_dir = std::filesystem::path(home) / ".config" / "kasumi";
        } else {
            app_dir = std::filesystem::current_path() / ".kasumi_data";
        }
    }
#endif

    return global_paths_from_root(app_dir);
}

std::expected<ProfilePaths, Error>
resolve_profile_paths(const std::filesystem::path& app_data_dir,
                      std::string_view profile_name) {
    if (!is_valid_profile_name(profile_name)) {
        return std::unexpected(Error{.code = ErrorCode::InvalidProfileName,
                                     .detail = "nome de perfil inválido"});
    }

    auto paths = global_paths_from_root(app_data_dir);

    std::error_code error;
    const auto absolute_root =
        std::filesystem::absolute(paths.profiles_dir, error);
    if (error)
        return std::unexpected(
            Error{.code = ErrorCode::IoFailure, .detail = error.message()});
    const auto root = absolute_root.lexically_normal();
    const auto candidate = (root / std::string(profile_name)).lexically_normal();
    const auto relative = std::filesystem::relative(candidate, root, error);
    if (error || relative.empty() || relative.is_absolute() ||
        *relative.begin() == "..") {
        return std::unexpected(
            Error{.code = ErrorCode::PathEscape,
                  .detail = "diretório do perfil escapa da pasta profiles"});
    }

    return ProfilePaths{.profile_dir = candidate,
                        .database_path = candidate / "db.sqlite",
                        .key_path = candidate / "key.bin"};
}

std::expected<void, Error> ensure_profile_directory(const ProfilePaths& paths) {
    const auto profiles = paths.profile_dir.parent_path();
    const auto application = profiles.parent_path();
    for (const auto& directory : {application, profiles, paths.profile_dir}) {
        auto secured = platform::private_storage::ensure_directory(directory);
        if (!secured) {
            return std::unexpected(Error{.code = ErrorCode::IoFailure,
                                         .detail = secured.error()});
        }
    }
    return {};
}

std::expected<void, Error> remove_profile_directory(const ProfilePaths& paths) {
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(paths.profile_dir, ec);
    if (ec == std::errc::no_such_file_or_directory ||
        status.type() == std::filesystem::file_type::not_found) {
        return {};
    }
    if (ec) {
        return std::unexpected(
            Error{.code = ErrorCode::IoFailure, .detail = ec.message()});
    }
    auto secured = platform::private_storage::protect_tree(paths.profile_dir);
    if (!secured) {
        return std::unexpected(Error{.code = ErrorCode::IoFailure,
                                     .detail = secured.error()});
    }
    std::filesystem::remove_all(paths.profile_dir, ec);
    if (ec)
        return std::unexpected(
            Error{.code = ErrorCode::IoFailure, .detail = ec.message()});
    return {};
}

std::expected<void, Error>
rename_profile_directory(const ProfilePaths& source,
                         const ProfilePaths& destination) {
    std::error_code ec;
    if (std::filesystem::exists(source.profile_dir, ec)) {
        auto secured =
            platform::private_storage::protect_tree(source.profile_dir);
        if (!secured) {
            return std::unexpected(Error{.code = ErrorCode::IoFailure,
                                         .detail = secured.error()});
        }
        auto parent = platform::private_storage::protect_directory(
            destination.profile_dir.parent_path());
        if (!parent) {
            return std::unexpected(Error{.code = ErrorCode::IoFailure,
                                         .detail = parent.error()});
        }
        std::filesystem::rename(
            source.profile_dir, destination.profile_dir, ec);
        if (ec)
            return std::unexpected(
                Error{.code = ErrorCode::IoFailure, .detail = ec.message()});
    }
    return {};
}

} // namespace kasumi::runtime
