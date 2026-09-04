#ifndef KASUMI_APPLICATION_PROFILE_HPP
#define KASUMI_APPLICATION_PROFILE_HPP

#include "application/credentials.hpp"
#include "application/environment.hpp"

#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::application {

// Configuration for a synchronization profile.
struct Profile {
    std::string name;
    // Local synchronized directory.
    std::filesystem::path local_dir;
    // Local or remote rclone destination.
    std::string remote_dir;
    // Retention policy.
    std::uint32_t min_history_depth = 5;
    std::uint32_t min_history_age_hours = 6;
};

// Possible failures in profile management.
enum class ProfileErrorCode {
    InvalidName,
    AlreadyExists,
    NotFound,
    ConfigFailure,
    CredentialFailure,
    StorageFailure
};

// Error encountered while managing a profile.
struct ProfileError {
    ProfileErrorCode code = ProfileErrorCode::ConfigFailure;
    std::string detail;
};

// Lists configured profiles.
std::expected<std::vector<Profile>, ProfileError>
list_profiles(const ExecutionEnvironment& environment);

// Creates the profile and persists its local key.
std::expected<void, ProfileError>
create_profile(const ExecutionEnvironment& environment,
               Profile profile,
               ProfileCredentials credentials);

// Updates profile directories.
std::expected<void, ProfileError>
update_profile(const ExecutionEnvironment& environment, Profile profile);

// Removes configuration, key, and state; preserves synchronized directory.
std::expected<void, ProfileError>
delete_profile(const ExecutionEnvironment& environment,
               std::string_view profile_name);

// Renames configuration and moves local key and state.
std::expected<void, ProfileError>
rename_profile(const ExecutionEnvironment& environment,
               std::string_view current_name,
               std::string_view new_name);

} // namespace kasumi::application

#endif
