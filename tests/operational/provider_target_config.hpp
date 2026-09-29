#ifndef KASUMI_PROVIDER_TARGET_CONFIG_HPP
#define KASUMI_PROVIDER_TARGET_CONFIG_HPP

#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::operational::provider_target_config {

struct LiveProviderTargetConfig {
    std::string id;
    std::string provider_id;
    std::string remote;
    std::string authorized_parent;
};

struct LiveProviderConfig {
    std::vector<LiveProviderTargetConfig> targets;
};

struct LiveTargetAuthorization {
    std::string authorized_parent;
};

struct TargetSelectionArguments {
    std::string target_kind = "local";
    std::optional<std::filesystem::path> config_path;
    std::optional<std::string> target_id;
};

std::expected<LiveProviderConfig, std::string>
load_config(const std::filesystem::path& path);

std::expected<LiveProviderTargetConfig, std::string>
select_target(const LiveProviderConfig& config, std::string_view id);

std::expected<LiveProviderTargetConfig, std::string>
load_selected_target(const std::filesystem::path& path, std::string_view id);

std::expected<TargetSelectionArguments, std::string>
parse_target_selection_arguments(std::span<const std::string_view> args);

std::expected<std::optional<LiveProviderTargetConfig>, std::string>
resolve_target(const TargetSelectionArguments& selection);

bool authorized_live_parent(const LiveTargetAuthorization& authorization,
                            std::string_view requested_parent) noexcept;

} // namespace kasumi::operational::provider_target_config

#endif
