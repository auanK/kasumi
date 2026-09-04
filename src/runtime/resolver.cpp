#include "runtime/resolver.hpp"

#include "runtime/paths.hpp"
#include "runtime/profile.hpp"

#include "platform/private_storage.hpp"

namespace kasumi::runtime {

std::expected<RuntimeData, Error>
resolve(const std::filesystem::path& app_data_dir,
        std::string_view profile_name,
        AccessMode access_mode,
        bool protect_existing_profile) {
    auto paths = global_paths_from_root(app_data_dir);
    const auto config_path = paths.config_path;

    auto profile = load_profile(config_path, profile_name);
    if (!profile) {
        return std::unexpected(profile.error());
    }
    if (!profile->local_dir.is_absolute()) {
        return std::unexpected(Error{
            .code = ErrorCode::ProfileInvalid,
            .detail = "o caminho local do perfil deve ser absoluto"});
    }

    auto profile_paths = resolve_profile_paths(app_data_dir, profile_name);
    if (!profile_paths) {
        return std::unexpected(profile_paths.error());
    }
    const auto& key_path = profile_paths->key_path;
    const auto& database_path = profile_paths->database_path;

    if (access_mode == AccessMode::ReadWrite) {
        auto ensure_res = ensure_profile_directory(*profile_paths);
        if (!ensure_res) {
            return std::unexpected(ensure_res.error());
        }
        std::error_code error;
        const bool local_exists =
            std::filesystem::exists(profile->local_dir, error);
        if (error) {
            return std::unexpected(
                Error{.code = ErrorCode::IoFailure, .detail = error.message()});
        }
        if (!local_exists) {
            std::filesystem::create_directories(profile->local_dir, error);
        }
        if (error) {
            return std::unexpected(
                Error{.code = ErrorCode::IoFailure, .detail = error.message()});
        }
    }

    std::error_code profile_error;
    const auto profile_status =
        std::filesystem::symlink_status(profile_paths->profile_dir,
                                        profile_error);
    if (profile_error) {
        if (profile_error != std::errc::no_such_file_or_directory) {
            return std::unexpected(
                Error{.code = ErrorCode::IoFailure,
                      .detail = profile_error.message()});
        }
    } else if (protect_existing_profile &&
               profile_status.type() !=
                   std::filesystem::file_type::not_found) {
        auto secured =
            platform::private_storage::protect_tree(profile_paths->profile_dir);
        if (!secured) {
            return std::unexpected(Error{.code = ErrorCode::IoFailure,
                                         .detail = secured.error()});
        }
    }

    return RuntimeData{
        .local_dir = profile->local_dir,
        .database_path = database_path,
        .key_path = key_path,
        .storage_location = profile->remote_dir,
        .min_history_depth = profile->min_history_depth,
        .min_history_age_hours = profile->min_history_age_hours,
    };
}

} // namespace kasumi::runtime
