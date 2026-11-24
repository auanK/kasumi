#include "runtime/profile.hpp"

#include "platform/path.hpp"
#include "platform/private_storage.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <limits>
#include <sstream>
#include <toml++/toml.h>
#include <unordered_set>

namespace kasumi::runtime {

namespace {

std::expected<std::uint32_t, Error>
read_retention_value(const toml::table& profile, std::string_view name) {
    const auto field = profile[name];
    if (!field) {
        return fail(ErrorCode::ProfileInvalid,
                    "retention field is required: " + std::string{name});
    }
    if (!field.is_integer()) {
        return fail(ErrorCode::ProfileInvalid,
                    "retention field must be a positive integer: " +
                        std::string{name});
    }
    const auto value = field.value_exact<std::int64_t>();
    if (!value || *value <= 0 ||
        static_cast<std::uint64_t>(*value) >
            std::numeric_limits<std::uint32_t>::max()) {
        return fail(ErrorCode::ProfileInvalid,
                    "retention field out of range: " + std::string{name});
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

std::string fold_profile_name(std::string_view name) {
    std::string folded{name};
    for (char& ch : folded) {
        if (ch >= 'A' && ch <= 'Z') {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }
    return folded;
}

std::string_view to_string(KeyStorage storage) noexcept {
    switch (storage) {
        case KeyStorage::Vault:
            return "vault";
        case KeyStorage::File:
            return "file";
        case KeyStorage::Memory:
            return "memory";
    }
    return "vault";
}

std::optional<KeyStorage> parse_key_storage(std::string_view value) noexcept {
    if (value == "vault") {
        return KeyStorage::Vault;
    }
    if (value == "file") {
        return KeyStorage::File;
    }
    if (value == "memory") {
        return KeyStorage::Memory;
    }
    return std::nullopt;
}

std::expected<ProfileData, Error>
load_profile(const std::filesystem::path& config_path,
             std::string_view profile_name) {
    if (!is_valid_profile_name(profile_name)) {
        return fail(ErrorCode::InvalidProfileName, "invalid profile name");
    }

    auto profiles = load_profiles(config_path);
    if (!profiles)
        return std::unexpected(profiles.error());

    for (auto& prof : *profiles) {
        if (prof.name == profile_name)
            return std::move(prof);
    }

    return fail(ErrorCode::ProfileNotFound, "profile not found");
}

std::expected<std::vector<ProfileData>, Error>
load_profiles(const std::filesystem::path& config_path) {
    std::error_code status_error;
    const auto status =
        std::filesystem::symlink_status(config_path, status_error);
    if (status.type() == std::filesystem::file_type::not_found) {
        return fail(ErrorCode::ConfigNotFound,
                    "global configuration file does not exist; run "
                    "'kasumi config' first");
    }
    if (status_error) {
        return fail(ErrorCode::IoFailure,
                    "failed to inspect global configuration: " +
                        status_error.message());
    }
    auto parent =
        platform::private_storage::protect_directory(config_path.parent_path());
    if (!parent) {
        return fail(ErrorCode::IoFailure, parent.error());
    }
    auto secured = platform::private_storage::protect_file(config_path);
    if (!secured) {
        return fail(ErrorCode::IoFailure, secured.error());
    }
    toml::table config;
    try {
        std::string snapshot;
        std::array<std::uint8_t, 4096> buffer{};
        auto streamed = platform::private_storage::stream_regular_file(
            config_path, buffer, [&](std::span<const std::uint8_t> chunk) {
                snapshot.append(reinterpret_cast<const char*>(chunk.data()),
                                chunk.size());
            });
        if (!streamed) {
            using Kind = platform::private_storage::StreamErrorKind;
            const auto& err = streamed.error();
            if (err.kind == Kind::Symlink || err.kind == Kind::NotRegular) {
                return fail(
                    ErrorCode::IoFailure,
                    "global configuration is not an accessible regular file");
            }
            return fail(ErrorCode::IoFailure,
                        "failed to read global configuration: " + err.detail);
        }
        config = toml::parse(snapshot, platform::path::to_utf8(config_path));
    } catch (const toml::parse_error& error) {
        return fail(ErrorCode::ConfigInvalid,
                    "failed to read global configuration: " +
                        std::string(error.description()));
    }

    if (config.empty()) {
        return std::vector<ProfileData>{};
    }

    for (const auto& [name, val] : config) {
        if (name == "version") {
            if (!val.is_integer()) {
                return fail(ErrorCode::ConfigInvalid,
                            "configuration version must be an integer");
            }
            const auto ver = val.value_exact<std::int64_t>();
            if (!ver || *ver != 1) {
                return fail(ErrorCode::ConfigInvalid,
                            "unsupported configuration version");
            }
            continue;
        }
        if (name != "profiles") {
            return fail(ErrorCode::ConfigInvalid,
                        "unsupported top-level configuration field: " +
                            std::string{name.str()});
        }
    }

    if (!config.contains("profiles")) {
        return std::vector<ProfileData>{};
    }
    auto* profiles = config["profiles"].as_table();
    if (profiles == nullptr) {
        return fail(ErrorCode::ConfigInvalid,
                    "configuration must contain a profiles table");
    }

    std::vector<ProfileData> result;
#if defined(_WIN32) || defined(__APPLE__)
    std::unordered_set<std::string> names;
#endif
    for (const auto& [key, value] : *profiles) {
        if (!is_valid_profile_name(key.str())) {
            return fail(ErrorCode::InvalidProfileName, "invalid profile name");
        }
#if defined(_WIN32) || defined(__APPLE__)
        if (!names.insert(fold_profile_name(key.str())).second) {
            return fail(ErrorCode::ConfigInvalid, "duplicate profile name");
        }
#endif
        auto* prof = value.as_table();
        if (prof == nullptr) {
            return fail(ErrorCode::ProfileInvalid,
                        "profile has invalid format");
        }
        for (const auto& [field, _] : *prof) {
            if (field != "local_dir" && field != "remote_dir" &&
                field != "min_history_depth" &&
                field != "min_history_age_hours" && field != "key_storage" &&
                field != "bandwidth_limit" && field != "transfer_concurrency" &&
                field != "rclone_config" && field != "watch_enabled" &&
                field != "sync_interval_seconds" &&
                field != "gc_interval_hours" && field != "paused") {
                return fail(ErrorCode::ProfileInvalid,
                            "unsupported profile field: " +
                                std::string{field.str()});
            }
        }
        const auto local = (*prof)["local_dir"].value<std::string>();
        const auto remote = (*prof)["remote_dir"].value<std::string>();
        if (!local || !remote) {
            return fail(ErrorCode::ProfileInvalid,
                        "profile must have 'local_dir' and 'remote_dir'");
        }

        ProfileData pd{
            std::string(key.str()), platform::path::from_utf8(*local), *remote};
        auto min_depth = read_retention_value(*prof, "min_history_depth");
        if (!min_depth) {
            return std::unexpected(min_depth.error());
        }
        auto min_age = read_retention_value(*prof, "min_history_age_hours");
        if (!min_age) {
            return std::unexpected(min_age.error());
        }
        pd.min_history_depth = *min_depth;
        pd.min_history_age_hours = *min_age;
        const auto key_storage_field = (*prof)["key_storage"];
        if (!key_storage_field) {
            return fail(ErrorCode::ProfileInvalid,
                        "profile must have 'key_storage'");
        }
        const auto storage_value = key_storage_field.value<std::string>();
        if (!storage_value) {
            return fail(
                ErrorCode::ProfileInvalid,
                "invalid key_storage value (expected 'vault', 'file', or "
                "'memory')");
        }
        const auto parsed = parse_key_storage(*storage_value);
        if (!parsed) {
            return fail(
                ErrorCode::ProfileInvalid,
                "invalid key_storage value (expected 'vault', 'file', or "
                "'memory')");
        }
        pd.key_storage = *parsed;
        if (const auto bw_field = (*prof)["bandwidth_limit"]) {
            const auto bw = bw_field.value<std::string>();
            if (!bw || bw->empty() || bw->size() > 256 ||
                std::isspace(static_cast<unsigned char>(bw->front())) != 0 ||
                std::isspace(static_cast<unsigned char>(bw->back())) != 0 ||
                !std::ranges::all_of(*bw, [](unsigned char ch) {
                    return ch >= 0x20U && ch <= 0x7eU;
                })) {
                return fail(ErrorCode::ProfileInvalid,
                            "invalid bandwidth_limit value");
            }
            pd.bandwidth_limit = *bw;
        }
        if (const auto conc_field = (*prof)["transfer_concurrency"]) {
            if (!conc_field.is_integer()) {
                return fail(ErrorCode::ProfileInvalid,
                            "transfer_concurrency must be an integer");
            }
            const auto conc = conc_field.value_exact<std::int64_t>();
            if (!conc || *conc < 1 || *conc > 16) {
                return fail(ErrorCode::ProfileInvalid,
                            "transfer_concurrency must be between 1 and 16");
            }
            pd.transfer_concurrency = static_cast<std::uint32_t>(*conc);
        }
        if (const auto rc_field = (*prof)["rclone_config"]) {
            const auto rc = rc_field.value<std::string>();
            if (!rc || rc->empty() ||
                std::isspace(static_cast<unsigned char>(rc->front())) != 0 ||
                std::isspace(static_cast<unsigned char>(rc->back())) != 0 ||
                std::ranges::any_of(*rc, [](unsigned char ch) {
                    return ch <= 0x1fU || ch == 0x7fU;
                })) {
                return fail(ErrorCode::ProfileInvalid,
                            "invalid rclone_config value");
            }
            const auto rc_path = platform::path::from_utf8(*rc);
            if (!rc_path.is_absolute()) {
                return fail(ErrorCode::ProfileInvalid,
                            "rclone_config must be an absolute path");
            }
            pd.rclone_config = rc_path;
        }
        if (const auto watch_field = (*prof)["watch_enabled"]) {
            if (!watch_field.is_boolean()) {
                return fail(ErrorCode::ProfileInvalid,
                            "watch_enabled must be a boolean");
            }
            pd.watch_enabled = watch_field.value<bool>();
        }
        if (const auto sync_int_field = (*prof)["sync_interval_seconds"]) {
            if (!sync_int_field.is_integer()) {
                return fail(ErrorCode::ProfileInvalid,
                            "sync_interval_seconds must be an integer");
            }
            const auto sec = sync_int_field.value_exact<std::int64_t>();
            if (!sec || (*sec != 0 && (*sec < 10 || *sec > 86400))) {
                return fail(
                    ErrorCode::ProfileInvalid,
                    "sync_interval_seconds must be 0 or between 10 and 86400");
            }
            pd.sync_interval_seconds = static_cast<std::uint32_t>(*sec);
        }
        if (const auto gc_int_field = (*prof)["gc_interval_hours"]) {
            if (!gc_int_field.is_integer()) {
                return fail(ErrorCode::ProfileInvalid,
                            "gc_interval_hours must be an integer");
            }
            const auto hrs = gc_int_field.value_exact<std::int64_t>();
            if (!hrs || (*hrs != 0 && (*hrs < 1 || *hrs > 8760))) {
                return fail(
                    ErrorCode::ProfileInvalid,
                    "gc_interval_hours must be 0 or between 1 and 8760");
            }
            pd.gc_interval_hours = static_cast<std::uint32_t>(*hrs);
        }
        if (const auto paused_field = (*prof)["paused"]) {
            if (!paused_field.is_boolean()) {
                return fail(ErrorCode::ProfileInvalid,
                            "paused must be a boolean");
            }
            pd.paused = paused_field.value<bool>().value_or(false);
        }
        result.push_back(std::move(pd));
    }
    return result;
}

std::expected<void, Error>
save_profiles(const std::filesystem::path& config_path,
              std::span<const ProfileData> profiles) {
    std::unordered_set<std::string> names;
    for (const auto& prof : profiles) {
        if (!is_valid_profile_name(prof.name)) {
            return fail(ErrorCode::InvalidProfileName, "invalid profile name");
        }
        if (!names.insert(fold_profile_name(prof.name)).second) {
            return fail(ErrorCode::ConfigInvalid, "duplicate profile name");
        }
        if (prof.min_history_depth == 0 || prof.min_history_age_hours == 0) {
            return fail(ErrorCode::ProfileInvalid,
                        "retention policy must be positive");
        }
        if (prof.bandwidth_limit) {
            const auto& bw = *prof.bandwidth_limit;
            if (bw.empty() || bw.size() > 256 ||
                std::isspace(static_cast<unsigned char>(bw.front())) != 0 ||
                std::isspace(static_cast<unsigned char>(bw.back())) != 0 ||
                !std::ranges::all_of(bw, [](unsigned char ch) {
                    return ch >= 0x20U && ch <= 0x7eU;
                })) {
                return fail(ErrorCode::ProfileInvalid,
                            "invalid bandwidth_limit value");
            }
        }
        if (prof.transfer_concurrency && (*prof.transfer_concurrency < 1 ||
                                          *prof.transfer_concurrency > 16)) {
            return fail(ErrorCode::ProfileInvalid,
                        "transfer_concurrency must be between 1 and 16");
        }
        if (prof.rclone_config) {
            const auto rc = platform::path::to_utf8(*prof.rclone_config);
            if (rc.empty() ||
                std::isspace(static_cast<unsigned char>(rc.front())) != 0 ||
                std::isspace(static_cast<unsigned char>(rc.back())) != 0 ||
                std::ranges::any_of(rc,
                                    [](unsigned char ch) {
                                        return ch <= 0x1fU || ch == 0x7fU;
                                    }) ||
                !prof.rclone_config->is_absolute()) {
                return fail(ErrorCode::ProfileInvalid,
                            "rclone_config must be an absolute path");
            }
        }
        if (prof.sync_interval_seconds &&
            (*prof.sync_interval_seconds != 0U &&
             (*prof.sync_interval_seconds < 10U ||
              *prof.sync_interval_seconds > 86400U))) {
            return fail(
                ErrorCode::ProfileInvalid,
                "sync_interval_seconds must be 0 or between 10 and 86400");
        }
        if (prof.gc_interval_hours && (*prof.gc_interval_hours != 0U &&
                                       (*prof.gc_interval_hours < 1U ||
                                        *prof.gc_interval_hours > 8760U))) {
            return fail(ErrorCode::ProfileInvalid,
                        "gc_interval_hours must be 0 or between 1 and 8760");
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
        prof_data.insert("key_storage", to_string(prof.key_storage));
        if (prof.bandwidth_limit) {
            prof_data.insert("bandwidth_limit", *prof.bandwidth_limit);
        }
        if (prof.transfer_concurrency) {
            prof_data.insert("transfer_concurrency",
                             *prof.transfer_concurrency);
        }
        if (prof.rclone_config) {
            prof_data.insert("rclone_config",
                             platform::path::to_utf8(*prof.rclone_config));
        }
        if (prof.watch_enabled) {
            prof_data.insert("watch_enabled", *prof.watch_enabled);
        }
        if (prof.sync_interval_seconds) {
            prof_data.insert("sync_interval_seconds",
                             *prof.sync_interval_seconds);
        }
        if (prof.gc_interval_hours) {
            prof_data.insert("gc_interval_hours", *prof.gc_interval_hours);
        }
        if (prof.paused) {
            prof_data.insert("paused", true);
        }
        profiles_table.insert(prof.name, prof_data);
    }
    config.insert("version", 1);
    config.insert("profiles", profiles_table);

    const auto app_dir = config_path.parent_path();
    if (const auto app_parent = app_dir.parent_path(); !app_parent.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(app_parent, ec);
        if (ec) {
            return fail(ErrorCode::IoFailure, ec.message());
        }
    }
    auto parent = platform::private_storage::ensure_directory(app_dir);
    if (!parent) {
        return fail(ErrorCode::IoFailure, parent.error());
    }
    std::ostringstream output;
    output << config;
    if (!output)
        return fail(ErrorCode::IoFailure, "failed to write config");
    auto saved =
        platform::private_storage::write_atomically(config_path, output.str());
    if (!saved) {
        return fail(ErrorCode::IoFailure, saved.error());
    }
    return {};
}

} // namespace kasumi::runtime
