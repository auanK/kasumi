#ifndef KASUMI_PROVIDER_CERTIFICATION_SUPPORT_HPP
#define KASUMI_PROVIDER_CERTIFICATION_SUPPORT_HPP

#include "transport/transport.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::operational::provider_certification {

enum class CapabilityStatus {
    Supported,
    Unsupported,
    Failed
};
enum class ScenarioStatus {
    Pass,
    Fail,
    Blocked,
    NotRun
};

struct Capability {
    std::string name;
    CapabilityStatus status = CapabilityStatus::Unsupported;
    std::optional<transport::ErrorCode> error;
    std::string detail;
};

struct Scenario {
    std::string name;
    ScenarioStatus status = ScenarioStatus::NotRun;
    std::map<std::string, std::uint64_t> requests;
    std::vector<std::string> diagnostics;
};

struct LocalTarget {
    std::filesystem::path authorized_parent;
    std::filesystem::path root;
    std::string ownership_token;
};

struct ProviderTarget {
    std::string provider_id;
    std::string transport;
    std::string locator;
    std::filesystem::path workspace_root;
};

struct Report {
    int schema_version = 1;
    std::string provider_id = "local-filesystem";
    std::string transport = "Local";
    std::string platform;
    std::string status = "FAIL";
    std::string cleanup = "NOT_RUN";
    std::filesystem::path target_root;
    std::vector<Capability> capabilities;
    std::vector<Scenario> scenarios;
    std::map<std::string, std::uint64_t> harness_requests;
    std::vector<std::string> diagnostics;
};

std::expected<LocalTarget, std::string>
create_local_target(const std::filesystem::path& authorized_parent);
std::expected<void, std::string> cleanup_local_target(LocalTarget& target);
std::expected<std::filesystem::path, std::string>
target_path(const LocalTarget& target, const std::filesystem::path& relative);

Report run_local_certification(const std::filesystem::path& owned_root);
std::vector<std::string> scenario_registry(const ProviderTarget& target);
std::string derive_status(const Report& report);
nlohmann::json to_json(const Report& report);
nlohmann::json aggregate_reports(const std::vector<Report>& reports);

std::string_view name(CapabilityStatus status) noexcept;
std::string_view name(ScenarioStatus status) noexcept;

} // namespace kasumi::operational::provider_certification

#endif
