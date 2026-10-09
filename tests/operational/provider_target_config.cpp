#include "provider_target_config.hpp"

#include "transport/transport.hpp"

#include <fstream>
#include <toml++/toml.h>
#include <unordered_set>

namespace kasumi::operational::provider_target_config {

std::expected<LiveProviderConfig, std::string>
load_config(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::unexpected("could not open provider certification config");
    }

    toml::table document;
    try {
        document = toml::parse(input, path.string());
    } catch (const toml::parse_error& error) {
        return std::unexpected("invalid provider certification TOML: " +
                               std::string{error.description()});
    }

    for (const auto& [key, unused] : document) {
        (void)unused;
        if (key.str() != "targets") {
            return std::unexpected(
                "unknown provider certification config field");
        }
    }
    const auto* targets = document["targets"].as_array();
    if (targets == nullptr || targets->empty()) {
        return std::unexpected(
            "provider certification config requires targets");
    }

    LiveProviderConfig result;
    std::unordered_set<std::string> ids;
    for (const auto& node : *targets) {
        const auto* table = node.as_table();
        if (table == nullptr) {
            return std::unexpected("each provider target must be a table");
        }
        for (const auto& [key, unused] : *table) {
            (void)unused;
            if (key.str() != "id" && key.str() != "provider_id" &&
                key.str() != "remote" && key.str() != "authorized_parent") {
                return std::unexpected("unknown provider target field");
            }
        }

        const auto id = (*table)["id"].value<std::string>();
        const auto provider_id = (*table)["provider_id"].value<std::string>();
        const auto remote = (*table)["remote"].value<std::string>();
        const auto authorized_parent =
            (*table)["authorized_parent"].value<std::string>();
        if (!id || id->empty() || !provider_id || provider_id->empty() ||
            !remote || remote->empty() || !authorized_parent ||
            authorized_parent->empty()) {
            return std::unexpected(
                "provider target requires nonempty id, provider_id, remote, "
                "and authorized_parent");
        }
        if (!ids.insert(*id).second) {
            return std::unexpected("provider target ids must be unique");
        }

        const auto separator = authorized_parent->find(':');
        if (separator == std::string::npos || separator != remote->size() ||
            authorized_parent->substr(0, separator) != *remote ||
            authorized_parent->find(':', separator + 1) != std::string::npos) {
            return std::unexpected("authorized_parent must use the configured "
                                   "remote and a relative path");
        }
        const auto valid_parent =
            transport::validate_transport_location(*authorized_parent);
        if (!valid_parent) {
            return std::unexpected(
                "authorized_parent is not a safe remote location");
        }

        result.targets.push_back(LiveProviderTargetConfig{
            .id = *id,
            .provider_id = *provider_id,
            .remote = *remote,
            .authorized_parent = *authorized_parent,
        });
    }
    return result;
}

std::expected<LiveProviderTargetConfig, std::string>
select_target(const LiveProviderConfig& config, std::string_view id) {
    if (id.empty()) {
        return std::unexpected("provider target id is required");
    }
    const LiveProviderTargetConfig* selected = nullptr;
    for (const auto& target : config.targets) {
        if (target.id == id) {
            if (selected != nullptr) {
                return std::unexpected("provider target id is ambiguous");
            }
            selected = &target;
        }
    }
    if (selected == nullptr) {
        return std::unexpected("unknown provider target id");
    }
    return *selected;
}

std::expected<LiveProviderTargetConfig, std::string>
load_selected_target(const std::filesystem::path& path, std::string_view id) {
    auto config = load_config(path);
    if (!config) {
        return std::unexpected(config.error());
    }
    return select_target(*config, id);
}

std::expected<TargetSelectionArguments, std::string>
parse_target_selection_arguments(std::span<const std::string_view> args) {
    TargetSelectionArguments result;
    bool target_seen = false;
    for (std::size_t index = 1; index < args.size(); ++index) {
        const auto option = args[index];
        if (option == "--provider-id" || option == "--remote" ||
            option == "--remote-parent" || option == "--authorized-parent") {
            return std::unexpected("raw live target values are not accepted; "
                                   "use --config and --target-id");
        }
        if (option != "--target" && option != "--config" &&
            option != "--target-id") {
            continue;
        }
        if (index + 1 >= args.size()) {
            return std::unexpected("missing value for " + std::string{option});
        }
        const auto value = args[++index];
        if (option == "--target") {
            if (target_seen) {
                return std::unexpected("duplicate --target");
            }
            target_seen = true;
            result.target_kind = std::string{value};
        } else if (option == "--config") {
            if (result.config_path) {
                return std::unexpected("duplicate --config");
            }
            result.config_path = std::filesystem::path{value};
        } else {
            if (result.target_id) {
                return std::unexpected("duplicate --target-id");
            }
            result.target_id = std::string{value};
        }
    }
    return result;
}

std::expected<std::optional<LiveProviderTargetConfig>, std::string>
resolve_target(const TargetSelectionArguments& selection) {
    if (selection.target_kind == "local") {
        if (selection.target_id) {
            return std::unexpected(
                "--target-id is only valid for --target rclone");
        }
        return std::optional<LiveProviderTargetConfig>{};
    }
    if (selection.target_kind != "rclone") {
        return std::unexpected("unsupported target: " + selection.target_kind);
    }
    if (!selection.config_path || selection.config_path->empty()) {
        return std::unexpected("Rclone target requires --config");
    }
    if (!selection.target_id || selection.target_id->empty()) {
        return std::unexpected("Rclone target requires --target-id");
    }
    auto selected =
        load_selected_target(*selection.config_path, *selection.target_id);
    if (!selected) {
        return std::unexpected(selected.error());
    }
    return std::optional<LiveProviderTargetConfig>{std::move(*selected)};
}

bool authorized_live_parent(const LiveTargetAuthorization& authorization,
                            std::string_view requested_parent) noexcept {
    return !authorization.authorized_parent.empty() &&
           authorization.authorized_parent == requested_parent;
}

} // namespace kasumi::operational::provider_target_config
