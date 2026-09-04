#ifndef KASUMI_PLATFORM_PROFILE_LOCK_HPP
#define KASUMI_PLATFORM_PROFILE_LOCK_HPP

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>

namespace kasumi::platform {

inline constexpr std::intptr_t invalid_profile_lock = -1;

// Prevents concurrent executions on the same profile.
std::expected<std::intptr_t, std::string>
acquire_profile_lock(const std::filesystem::path& lock_path);

void release_profile_lock(std::intptr_t& handle) noexcept;

} // namespace kasumi::platform

#endif
