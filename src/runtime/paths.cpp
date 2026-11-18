#include "runtime/paths.hpp"

#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "runtime/profile.hpp"
#include "runtime/vault.hpp"

#if !defined(_WIN32)
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <string>
#include <system_error>
#include <vector>

namespace kasumi::runtime {

GlobalPaths global_paths_from_root(const std::filesystem::path& app_data_dir) {
    return GlobalPaths{.app_data_dir = app_data_dir,
                       .config_path = app_data_dir / "config.toml",
                       .profiles_dir = app_data_dir / "profiles"};
}

GlobalPaths default_global_paths() {
    std::filesystem::path app_dir;
#if defined(_WIN32)
    if (const auto appdata = platform::path::environment_value("APPDATA");
        appdata && appdata->is_absolute()) {
        app_dir = *appdata / "kasumi";
    }
#else
    if (const auto xdg = platform::path::environment_value("XDG_CONFIG_HOME");
        xdg && xdg->is_absolute()) {
        app_dir = *xdg / "kasumi";
    } else if (const auto home = platform::path::environment_value("HOME");
               home && home->is_absolute()) {
        app_dir = *home / ".config" / "kasumi";
    } else {
        long size = ::sysconf(_SC_GETPW_R_SIZE_MAX);
        if (size <= 0 || size > 65536L) {
            size = 16384L;
        }
        std::vector<char> buffer(static_cast<std::size_t>(size));
        struct passwd pwd{};
        struct passwd* result = nullptr;
        if (::getpwuid_r(::geteuid(), &pwd, buffer.data(), buffer.size(), &result) == 0 &&
            result != nullptr && pwd.pw_dir != nullptr && pwd.pw_dir[0] == '/') {
            app_dir = std::filesystem::path{pwd.pw_dir} / ".config" / "kasumi";
        }
    }
#endif
    if (app_dir.empty()) {
        std::error_code ec;
        const auto current = std::filesystem::current_path(ec);
        if (!ec && !current.empty()) {
            app_dir = current / ".kasumi_data";
        } else {
            return {};
        }
    }
    return global_paths_from_root(app_dir);
}

std::expected<ProfilePaths, Error>
resolve_profile_paths(const std::filesystem::path& app_data_dir,
                      std::string_view profile_name) {
    if (!is_valid_profile_name(profile_name)) {
        return fail(ErrorCode::InvalidProfileName, "invalid profile name");
    }

    auto paths = global_paths_from_root(app_data_dir);
    std::error_code error;
    const auto absolute_root =
        std::filesystem::absolute(paths.profiles_dir, error);
    if (error) {
        return fail(ErrorCode::IoFailure, error.message());
    }
    const auto root = absolute_root.lexically_normal();
    const auto candidate =
        (root / std::string(profile_name)).lexically_normal();
    const auto relative = std::filesystem::relative(candidate, root, error);
    if (error || relative.empty() || relative.is_absolute() ||
        *relative.begin() == "..") {
        return fail(ErrorCode::PathEscape,
                    "profile directory escapes profiles directory");
    }

    return ProfilePaths{.profile_dir = candidate,
                        .database_path = candidate / "db.sqlite",
                        .key_path = candidate / "key.bin"};
}

std::expected<void, Error> ensure_profile_directory(const ProfilePaths& paths) {
    const auto profiles = paths.profile_dir.parent_path();
    const auto application = profiles.parent_path();
    for (const auto& directory : {application, profiles, paths.profile_dir}) {
        if (auto secured =
                platform::private_storage::ensure_directory(directory);
            !secured) {
            return fail(ErrorCode::IoFailure, secured.error());
        }
    }
    return {};
}

std::expected<void, Error> remove_profile_directory(const ProfilePaths& paths) {
    auto vault_removed = vault::delete_vault(paths.key_path);
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(paths.profile_dir, ec);
    if (ec == std::errc::no_such_file_or_directory ||
        status.type() == std::filesystem::file_type::not_found) {
        return vault_removed;
    }
    if (ec) {
        return fail(ErrorCode::IoFailure, ec.message());
    }
    if (auto secured =
            platform::private_storage::protect_tree(paths.profile_dir);
        !secured) {
        return fail(ErrorCode::IoFailure, secured.error());
    }
    std::filesystem::remove_all(paths.profile_dir, ec);
    if (ec) {
        return fail(ErrorCode::IoFailure, ec.message());
    }
    return vault_removed;
}

std::expected<void, Error>
rename_profile_directory(const ProfilePaths& source,
                         const ProfilePaths& destination) {
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(source.profile_dir, ec);
    if (!ec && status.type() != std::filesystem::file_type::not_found) {
        if (std::filesystem::is_symlink(status)) {
            return fail(ErrorCode::IoFailure,
                        "source profile directory cannot be a symlink");
        }
        if (auto secured =
                platform::private_storage::protect_tree(source.profile_dir);
            !secured) {
            return fail(ErrorCode::IoFailure, secured.error());
        }
        if (auto parent = platform::private_storage::protect_directory(
                destination.profile_dir.parent_path());
            !parent) {
            return fail(ErrorCode::IoFailure, parent.error());
        }
        std::filesystem::rename(
            source.profile_dir, destination.profile_dir, ec);
        if (ec) {
            return fail(ErrorCode::IoFailure, ec.message());
        }
    }
    return {};
}

} // namespace kasumi::runtime
