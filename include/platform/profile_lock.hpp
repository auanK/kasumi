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

// Non-blocking read-only probe checking whether lock_path is currently held by
// another process. Never creates or modifies lock_path.
bool is_profile_lock_held(const std::filesystem::path& lock_path) noexcept;

void release_profile_lock(std::intptr_t& handle) noexcept;

} // namespace kasumi::platform

#endif
