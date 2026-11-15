#include "runtime/paths.hpp"

#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "runtime/profile.hpp"

#include <string>

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
    }
#endif
    if (app_dir.empty()) {
        app_dir = std::filesystem::current_path() / ".kasumi_data";
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
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(paths.profile_dir, ec);
    if (ec == std::errc::no_such_file_or_directory ||
        status.type() == std::filesystem::file_type::not_found) {
        return {};
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
    return {};
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
