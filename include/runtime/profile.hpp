#ifndef KASUMI_RUNTIME_PROFILE_HPP
#define KASUMI_RUNTIME_PROFILE_HPP

#include "runtime/error.hpp"

#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::runtime {

// Record persisted in the global configuration.
struct ProfileData {
    std::string name;
    // Synchronized directory.
    std::filesystem::path local_dir;
    // Local or remote rclone destination.
    std::string remote_dir;
    // Retention policy.
    std::uint32_t min_history_depth = 5;
    std::uint32_t min_history_age_hours = 6;
};

// Accepts alphanumeric characters, '-', and '_', excluding empty, ".", and "..".
bool is_valid_profile_name(std::string_view name);

// Loads a profile by name.
std::expected<ProfileData, Error>
load_profile(const std::filesystem::path& config_path,
             std::string_view profile_name);

// Loads all configured profiles.
std::expected<std::vector<ProfileData>, Error>
load_profiles(const std::filesystem::path& config_path);

// Replaces the global configuration.
std::expected<void, Error>
save_profiles(const std::filesystem::path& config_path,
              std::span<const ProfileData> profiles);

} // namespace kasumi::runtime

#endif
