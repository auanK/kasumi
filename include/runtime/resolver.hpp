#ifndef KASUMI_RUNTIME_RESOLVER_HPP
#define KASUMI_RUNTIME_RESOLVER_HPP

#include "runtime/error.hpp"

#include <expected>
#include <filesystem>
#include <string>
#include <string_view>

namespace kasumi::runtime {

// Controls whether missing directories may be created.
enum class AccessMode {
    ReadOnly,
    ReadWrite
};

// Resolved paths; transport is chosen by the application.
struct RuntimeData {
    // Synchronized directory.
    std::filesystem::path local_dir;
    // Profile state database.
    std::filesystem::path database_path;
    // Local profile key.
    std::filesystem::path key_path;
    // Destination accepted by transport.
    std::string storage_location;
    // History retention policy.
    std::uint32_t min_history_depth = 5;
    std::uint32_t min_history_age_hours = 6;
};

// Validates the profile and resolves its paths.
std::expected<RuntimeData, Error>
resolve(const std::filesystem::path& app_data_dir,
        std::string_view profile_name,
        AccessMode access_mode,
        // Strict observers may bypass permission normalization.
        bool protect_existing_profile = true);

} // namespace kasumi::runtime

#endif
