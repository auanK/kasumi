#include "application/profile.hpp"

#include "core/history.hpp"
#include "crypto/secure_memory.hpp"
#include "runtime/error.hpp"
#include "runtime/paths.hpp"
#include "runtime/profile.hpp"
#include "runtime/vault.hpp"
#include "transport/transport.hpp"

#include <algorithm>

namespace kasumi::application {

namespace {

bool valid_retention_policy(const Profile& profile) noexcept {
    return profile.min_history_depth > 0 &&
           profile.min_history_depth <= history::maximum_graph_depth &&
           profile.min_history_age_hours > 0;
}

ProfileError map_runtime_error(const runtime::Error& err) {
    ProfileErrorCode code = ProfileErrorCode::ConfigFailure;
    switch (err.code) {
        case runtime::ErrorCode::InvalidProfileName:
            code = ProfileErrorCode::InvalidName;
            break;
        case runtime::ErrorCode::ProfileNotFound:
            code = ProfileErrorCode::NotFound;
            break;
        case runtime::ErrorCode::KeyNotFound:
        case runtime::ErrorCode::KeyInvalid:
        case runtime::ErrorCode::KeyDerivationFailure:
        case runtime::ErrorCode::KeyWriteFailure:
            code = ProfileErrorCode::CredentialFailure;
            break;
        case runtime::ErrorCode::IoFailure:
        case runtime::ErrorCode::PathEscape:
            code = ProfileErrorCode::StorageFailure;
            break;
        case runtime::ErrorCode::ConfigNotFound:
        case runtime::ErrorCode::ConfigInvalid:
        case runtime::ErrorCode::ProfileInvalid:
            code = ProfileErrorCode::ConfigFailure;
            break;
    }
    return ProfileError{.code = code, .detail = err.detail};
}
} // namespace

std::expected<std::vector<Profile>, ProfileError>
list_profiles(const ExecutionEnvironment& environment) {
    auto config_path = environment.app_data_dir / "config.toml";
    auto profiles_res = runtime::load_profiles(config_path);

    if (!profiles_res) {
        if (profiles_res.error().code == runtime::ErrorCode::ConfigNotFound) {
            return std::vector<Profile>{};
        }
        return std::unexpected(map_runtime_error(profiles_res.error()));
    }

    std::vector<Profile> result;
    result.reserve(profiles_res->size());
    for (const auto& p : *profiles_res) {
        result.push_back(
            Profile{.name = p.name,
                    .local_dir = p.local_dir,
                    .remote_dir = p.remote_dir,
                    .min_history_depth = p.min_history_depth,
                    .min_history_age_hours = p.min_history_age_hours});
    }
    return result;
}

std::expected<void, ProfileError>
create_profile(const ExecutionEnvironment& environment,
               Profile profile,
               ProfileCredentials credentials) {
    std::expected<runtime::vault::KeyBytes, runtime::Error> master_key_res =
        std::unexpected(runtime::Error{.code = runtime::ErrorCode::KeyInvalid,
                                       .detail = "uninitialized"});

    auto do_create = [&]() -> std::expected<void, ProfileError> {
        if (!runtime::is_valid_profile_name(profile.name)) {
            return std::unexpected(
                ProfileError{.code = ProfileErrorCode::InvalidName,
                             .detail = "nome de perfil inválido"});
        }
        if (!valid_retention_policy(profile)) {
            return std::unexpected(
                ProfileError{.code = ProfileErrorCode::ConfigFailure,
                             .detail = "política de retenção inválida"});
        }
        if (!profile.local_dir.is_absolute()) {
            return std::unexpected(
                ProfileError{.code = ProfileErrorCode::StorageFailure,
                             .detail = "o caminho local deve ser absoluto"});
        }

        const auto valid_storage =
            transport::validate_transport_location(profile.remote_dir);
        if (!valid_storage) {
            return std::unexpected(ProfileError{
                .code = ProfileErrorCode::StorageFailure,
                .detail = transport::describe(valid_storage.error()),
            });
        }

        if (const auto* hex = std::get_if<MasterKeyHex>(&credentials)) {
            master_key_res = runtime::vault::decode_hex(hex->value);
        } else if (const auto* pair = std::get_if<PasswordPair>(&credentials)) {
            master_key_res =
                runtime::vault::derive(pair->password, pair->salt_password);
        }

        if (!master_key_res) {
            return std::unexpected(map_runtime_error(master_key_res.error()));
        }

        auto config_path = environment.app_data_dir / "config.toml";
        auto profiles_res = runtime::load_profiles(config_path);
        std::vector<runtime::ProfileData> profiles;
        if (!profiles_res) {
            if (profiles_res.error().code !=
                runtime::ErrorCode::ConfigNotFound) {
                return std::unexpected(map_runtime_error(profiles_res.error()));
            }
        } else {
            profiles = std::move(*profiles_res);
        }

        auto it = std::ranges::find_if(profiles, [&](const auto& p) {
            return p.name == profile.name;
        });
        if (it != profiles.end()) {
            return std::unexpected(
                ProfileError{.code = ProfileErrorCode::AlreadyExists,
                             .detail = "perfil já existe"});
        }

        auto paths_res = runtime::resolve_profile_paths(
            environment.app_data_dir, profile.name);
        if (!paths_res) {
            return std::unexpected(map_runtime_error(paths_res.error()));
        }

        std::error_code ec;
        if (std::filesystem::exists(paths_res->profile_dir, ec) ||
            std::filesystem::exists(paths_res->key_path, ec)) {
            return std::unexpected(ProfileError{
                .code = ProfileErrorCode::StorageFailure,
                .detail = "infraestrutura de perfil já existe no disco"});
        }

        auto ensure_res = runtime::ensure_profile_directory(*paths_res);
        if (!ensure_res) {
            return std::unexpected(map_runtime_error(ensure_res.error()));
        }

        if (!runtime::vault::write(paths_res->key_path, *master_key_res)) {
            (void)runtime::remove_profile_directory(*paths_res);
            return std::unexpected(
                ProfileError{.code = ProfileErrorCode::StorageFailure,
                             .detail = "não foi possível salvar o cofre"});
        }

        profiles.push_back(runtime::ProfileData{profile.name,
                                                profile.local_dir,
                                                profile.remote_dir,
                                                profile.min_history_depth,
                                                profile.min_history_age_hours});
        auto save_res = runtime::save_profiles(config_path, profiles);
        if (!save_res) {
            auto original_err = save_res.error();
            (void)runtime::remove_profile_directory(*paths_res);
            return std::unexpected(map_runtime_error(original_err));
        }

        return {};
    };

    auto result = do_create();

    wipe_credentials(credentials);
    if (master_key_res) {
        crypto::secure_memory::wipe(master_key_res->data(),
                                    master_key_res->size());
    }

    return result;
}

std::expected<void, ProfileError>
update_profile(const ExecutionEnvironment& environment, Profile profile) {
    if (!profile.local_dir.is_absolute()) {
        return std::unexpected(
            ProfileError{.code = ProfileErrorCode::StorageFailure,
                         .detail = "o caminho local deve ser absoluto"});
    }
    const auto valid_storage =
        transport::validate_transport_location(profile.remote_dir);
    if (!valid_storage) {
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::StorageFailure,
            .detail = transport::describe(valid_storage.error()),
        });
    }

    auto config_path = environment.app_data_dir / "config.toml";
    auto profiles_res = runtime::load_profiles(config_path);
    if (!profiles_res) {
        return std::unexpected(map_runtime_error(profiles_res.error()));
    }

    auto it = std::ranges::find_if(*profiles_res, [&](const auto& p) {
        return p.name == profile.name;
    });
    if (it == profiles_res->end()) {
        return std::unexpected(ProfileError{.code = ProfileErrorCode::NotFound,
                                            .detail = "perfil não encontrado"});
    }

    it->local_dir = profile.local_dir;
    it->remote_dir = profile.remote_dir;

    auto save_res = runtime::save_profiles(config_path, *profiles_res);
    if (!save_res) {
        return std::unexpected(map_runtime_error(save_res.error()));
    }

    return {};
}

std::expected<void, ProfileError>
delete_profile(const ExecutionEnvironment& environment,
               std::string_view profile_name) {
    auto config_path = environment.app_data_dir / "config.toml";
    auto profiles_res = runtime::load_profiles(config_path);
    if (!profiles_res) {
        return std::unexpected(map_runtime_error(profiles_res.error()));
    }

    auto it = std::ranges::find_if(*profiles_res, [&](const auto& p) {
        return p.name == profile_name;
    });
    if (it == profiles_res->end()) {
        return std::unexpected(ProfileError{.code = ProfileErrorCode::NotFound,
                                            .detail = "perfil não encontrado"});
    }

    auto original_profiles = *profiles_res;
    profiles_res->erase(it);

    auto save_res = runtime::save_profiles(config_path, *profiles_res);
    if (!save_res) {
        return std::unexpected(map_runtime_error(save_res.error()));
    }

    auto paths_res =
        runtime::resolve_profile_paths(environment.app_data_dir, profile_name);
    if (paths_res) {
        auto remove_res = runtime::remove_profile_directory(*paths_res);
        if (!remove_res) {
            auto rollback_res =
                runtime::save_profiles(config_path, original_profiles);
            std::string detail = remove_res.error().detail;
            if (!rollback_res) {
                detail += " (rollback da config falhou: " +
                          rollback_res.error().detail + ")";
            }
            return std::unexpected(ProfileError{
                .code = ProfileErrorCode::StorageFailure, .detail = detail});
        }
    }

    return {};
}

std::expected<void, ProfileError>
rename_profile(const ExecutionEnvironment& environment,
               std::string_view current_name,
               std::string_view new_name) {
    if (!runtime::is_valid_profile_name(new_name)) {
        return std::unexpected(
            ProfileError{.code = ProfileErrorCode::InvalidName,
                         .detail = "nome de perfil inválido"});
    }

    auto config_path = environment.app_data_dir / "config.toml";
    auto profiles_res = runtime::load_profiles(config_path);
    if (!profiles_res) {
        return std::unexpected(map_runtime_error(profiles_res.error()));
    }

    auto it_current = std::ranges::find_if(*profiles_res, [&](const auto& p) {
        return p.name == current_name;
    });
    if (it_current == profiles_res->end()) {
        return std::unexpected(ProfileError{.code = ProfileErrorCode::NotFound,
                                            .detail = "perfil não encontrado"});
    }

    auto it_new = std::ranges::find_if(*profiles_res, [&](const auto& p) {
        return p.name == new_name;
    });
    if (it_new != profiles_res->end()) {
        return std::unexpected(
            ProfileError{.code = ProfileErrorCode::AlreadyExists,
                         .detail = "já existe um perfil com esse nome"});
    }

    auto old_paths_res =
        runtime::resolve_profile_paths(environment.app_data_dir, current_name);
    auto new_paths_res =
        runtime::resolve_profile_paths(environment.app_data_dir, new_name);

    if (!old_paths_res || !new_paths_res) {
        return std::unexpected(
            ProfileError{.code = ProfileErrorCode::StorageFailure,
                         .detail = "erro ao resolver caminhos"});
    }

    std::error_code ec;
    if (std::filesystem::exists(new_paths_res->profile_dir, ec)) {
        return std::unexpected(
            ProfileError{.code = ProfileErrorCode::StorageFailure,
                         .detail = "destino físico já existe"});
    }

    bool phys_renamed = false;
    if (std::filesystem::exists(old_paths_res->profile_dir, ec)) {
        auto ren_res =
            runtime::rename_profile_directory(*old_paths_res, *new_paths_res);
        if (!ren_res) {
            return std::unexpected(map_runtime_error(ren_res.error()));
        }
        phys_renamed = true;
    }

    it_current->name = std::string(new_name);

    auto save_res = runtime::save_profiles(config_path, *profiles_res);
    if (!save_res) {
        std::string detail = save_res.error().detail;
        if (phys_renamed) {
            auto rb_res = runtime::rename_profile_directory(*new_paths_res,
                                                            *old_paths_res);
            if (!rb_res) {
                detail +=
                    " (rollback do dir falhou: " + rb_res.error().detail + ")";
            }
        }
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::StorageFailure, .detail = detail});
    }

    return {};
}

} // namespace kasumi::application
