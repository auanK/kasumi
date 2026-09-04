#ifndef KASUMI_RUNTIME_PATHS_HPP
#define KASUMI_RUNTIME_PATHS_HPP

#include "runtime/error.hpp"

#include <expected>
#include <filesystem>
#include <string_view>

namespace kasumi::runtime {

// Paths shared across all profiles.
struct GlobalPaths {
    // Root directory for application data.
    std::filesystem::path app_data_dir;
    // Global profiles configuration file.
    std::filesystem::path config_path;
    // Directory containing per-profile state.
    std::filesystem::path profiles_dir;
};

// Uses the system default directory.
GlobalPaths default_global_paths();

// Derives paths from app_data_dir.
GlobalPaths global_paths_from_root(const std::filesystem::path& app_data_dir);

// Internal paths for a profile.
struct ProfilePaths {
    // Directory for internal profile state.
    std::filesystem::path profile_dir;
    // Profile state database.
    std::filesystem::path database_path;
    // Local profile key.
    std::filesystem::path key_path;
};

// Resolves secure paths under app_data_dir.
std::expected<ProfilePaths, Error>
resolve_profile_paths(const std::filesystem::path& app_data_dir,
                      std::string_view profile_name);

// Creates the internal profile directory when absent.
std::expected<void, Error> ensure_profile_directory(const ProfilePaths& paths);

// Removes internal profile state.
std::expected<void, Error> remove_profile_directory(const ProfilePaths& paths);

// Moves internal state to the new profile.
std::expected<void, Error>
rename_profile_directory(const ProfilePaths& source,
                         const ProfilePaths& destination);

} // namespace kasumi::runtime

#endif
