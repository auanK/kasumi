#ifndef KASUMI_RUNTIME_PROFILE_HPP
#define KASUMI_RUNTIME_PROFILE_HPP

#include "runtime/error.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::runtime {

enum class KeyStorage {
    Vault,
    File,
    Memory,
};

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
    // Key storage mechanism.
    KeyStorage key_storage = KeyStorage::Vault;
    // Optional per-profile network & transport settings (append-only for
    // aggregate init compatibility).
    std::optional<std::string> bandwidth_limit = std::nullopt;
    std::optional<std::uint32_t> transfer_concurrency = std::nullopt;
    std::optional<std::filesystem::path> rclone_config = std::nullopt;
};

std::string_view to_string(KeyStorage storage) noexcept;
std::optional<KeyStorage> parse_key_storage(std::string_view value) noexcept;

// Accepts alphanumeric characters, '-', and '_', excluding empty, ".", and
// "..".
bool is_valid_profile_name(std::string_view name);
std::string fold_profile_name(std::string_view name);

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
