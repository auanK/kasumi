#include "runtime/profile.hpp"

#include "platform/path.hpp"
#include "platform/private_storage.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <limits>
#include <sstream>
#include <toml++/toml.h>

namespace kasumi::runtime {

namespace {

std::expected<std::uint32_t, Error>
read_retention_value(const toml::table& profile, std::string_view name) {
    const auto field = profile[name];
    if (!field) {
        return std::unexpected(Error{
            .code = ErrorCode::ProfileInvalid,
            .detail = "campo de retenção obrigatório: " + std::string{name}});
    }
    if (!field.is_integer()) {
        return std::unexpected(
            Error{.code = ErrorCode::ProfileInvalid,
                  .detail = "campo de retenção deve ser um inteiro positivo: " +
                            std::string{name}});
    }
    const auto value = field.value_exact<std::int64_t>();
    if (!value || *value <= 0 ||
        static_cast<std::uint64_t>(*value) >
            std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(
            Error{.code = ErrorCode::ProfileInvalid,
                  .detail = "campo de retenção fora do intervalo: " +
                            std::string{name}});
    }
    return static_cast<std::uint32_t>(*value);
}

} // namespace

bool is_valid_profile_name(std::string_view name) {
    if (name.empty() || name == "." || name == "..")
        return false;
    return std::ranges::all_of(name, [](unsigned char character) {
        return std::isalnum(character) || character == '_' || character == '-';
    });
}

std::expected<ProfileData, Error>
load_profile(const std::filesystem::path& config_path,
             std::string_view profile_name) {
    if (!is_valid_profile_name(profile_name)) {
        return std::unexpected(Error{.code = ErrorCode::InvalidProfileName,
                                     .detail = "nome de perfil inválido"});
    }

    auto profiles = load_profiles(config_path);
    if (!profiles)
        return std::unexpected(profiles.error());

    for (const auto& prof : *profiles) {
        if (prof.name == profile_name)
            return prof;
    }

    return std::unexpected(Error{.code = ErrorCode::ProfileNotFound,
                                 .detail = "perfil não encontrado"});
}

std::expected<std::vector<ProfileData>, Error>
load_profiles(const std::filesystem::path& config_path) {
    std::error_code status_error;
    const auto status =
        std::filesystem::symlink_status(config_path, status_error);
    if (status.type() == std::filesystem::file_type::not_found) {
        return std::unexpected(Error{
            .code = ErrorCode::ConfigNotFound,
            .detail =
                "arquivo global não existe; use primeiro: kasumi config"});
    }
    if (status_error) {
        return std::unexpected(
            Error{.code = ErrorCode::IoFailure,
                  .detail = "falha ao inspecionar a configuração global: " +
                            status_error.message()});
    }
    auto parent =
        platform::private_storage::protect_directory(config_path.parent_path());
    if (!parent) {
        return std::unexpected(
            Error{.code = ErrorCode::IoFailure, .detail = parent.error()});
    }
    auto secured = platform::private_storage::protect_file(config_path);
    if (!secured) {
        return std::unexpected(
            Error{.code = ErrorCode::IoFailure, .detail = secured.error()});
    }
    toml::table config;
    try {
        std::ifstream input(config_path, std::ios::binary);
        if (!input) {
            return std::unexpected(
                Error{.code = ErrorCode::IoFailure,
                      .detail = "falha ao abrir a configuração global"});
        }
        config = toml::parse(input, platform::path::to_utf8(config_path));
    } catch (const toml::parse_error& error) {
        return std::unexpected(
            Error{.code = ErrorCode::ConfigInvalid,
                  .detail = "falha ao ler a configuração global: " +
                            std::string(error.description())});
    }

    std::vector<ProfileData> result;
    if (auto* profiles = config["profiles"].as_table()) {
        for (const auto& [key, value] : *profiles) {
            if (auto* prof = value.as_table()) {
                const auto local = (*prof)["local_dir"].value<std::string>();
                const auto remote = (*prof)["remote_dir"].value<std::string>();

                if (local && remote) {
                    ProfileData pd{std::string(key.str()),
                                   platform::path::from_utf8(*local),
                                   *remote};
                    auto min_depth =
                        read_retention_value(*prof, "min_history_depth");
                    if (!min_depth) {
                        return std::unexpected(min_depth.error());
                    }
                    auto min_age =
                        read_retention_value(*prof, "min_history_age_hours");
                    if (!min_age) {
                        return std::unexpected(min_age.error());
                    }
                    pd.min_history_depth = *min_depth;
                    pd.min_history_age_hours = *min_age;
                    result.push_back(std::move(pd));
                } else {
                    return std::unexpected(Error{
                        .code = ErrorCode::ProfileInvalid,
                        .detail =
                            "perfil precisa ter 'local_dir' e 'remote_dir'"});
                }
            } else {
                return std::unexpected(
                    Error{.code = ErrorCode::ProfileInvalid,
                          .detail = "perfil possui formato inválido"});
            }
        }
    }
    return result;
}

std::expected<void, Error>
save_profiles(const std::filesystem::path& config_path,
              std::span<const ProfileData> profiles) {
    for (const auto& prof : profiles) {
        if (prof.min_history_depth == 0 || prof.min_history_age_hours == 0) {
            return std::unexpected(
                Error{.code = ErrorCode::ProfileInvalid,
                      .detail = "política de retenção deve ser positiva"});
        }
    }
    toml::table config;
    toml::table profiles_table;
    for (const auto& prof : profiles) {
        toml::table prof_data;
        prof_data.insert("local_dir", platform::path::to_utf8(prof.local_dir));
        prof_data.insert("remote_dir", prof.remote_dir);
        prof_data.insert("min_history_depth", prof.min_history_depth);
        prof_data.insert("min_history_age_hours", prof.min_history_age_hours);
        profiles_table.insert(prof.name, prof_data);
    }
    config.insert("profiles", profiles_table);

    auto parent =
        platform::private_storage::ensure_directory(config_path.parent_path());
    if (!parent) {
        return std::unexpected(
            Error{.code = ErrorCode::IoFailure, .detail = parent.error()});
    }
    std::ostringstream output;
    output << config;
    if (!output)
        return std::unexpected(Error{.code = ErrorCode::IoFailure,
                                     .detail = "falha ao escrever config"});
    auto saved =
        platform::private_storage::write_atomically(config_path, output.str());
    if (!saved) {
        return std::unexpected(
            Error{.code = ErrorCode::IoFailure, .detail = saved.error()});
    }
    return {};
}

} // namespace kasumi::runtime
