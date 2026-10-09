#ifndef KASUMI_PROVIDER_CERTIFICATION_SUPPORT_HPP
#define KASUMI_PROVIDER_CERTIFICATION_SUPPORT_HPP

#include "application/result.hpp"
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
    std::optional<LocalTarget> local_ownership;
    std::optional<LocalTarget> workspace_ownership;
    std::string authorized_remote_parent;
    std::string remote_root;
    std::string remote_ownership_token;
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
    std::map<std::string, std::uint64_t> transport_requests;
    std::vector<std::string> diagnostics;
};

struct FsckCorruptEvidence {
    bool corruption_installed = false;
    bool fsck_failed = false;
    application::ErrorCode error_code = application::ErrorCode::RuntimeFailure;
    std::uint64_t audit_get_calls = 0;
    std::uint64_t audit_decrypt_calls = 0;
};

std::expected<LocalTarget, std::string>
create_local_target(const std::filesystem::path& authorized_parent);
std::expected<void, std::string> cleanup_local_target(LocalTarget& target);
std::expected<ProviderTarget, std::string>
create_rclone_target(std::string provider_id,
                     std::string remote_name,
                     std::string authorized_parent);
std::expected<void, std::string> cleanup_rclone_target(ProviderTarget& target);
std::expected<std::filesystem::path, std::string>
target_path(const LocalTarget& target, const std::filesystem::path& relative);

Report run_certification(const ProviderTarget& target);
Report run_local_certification(const std::filesystem::path& owned_root);
bool fsck_corrupt_evidence_passes(const FsckCorruptEvidence& evidence) noexcept;
std::expected<void, std::string>
install_verified_object(Report& report,
                        transport::Transport& storage,
                        const std::filesystem::path& source,
                        std::string_view identifier,
                        const std::filesystem::path& readback);
std::vector<std::string> scenario_registry(const ProviderTarget& target);
std::string derive_status(const Report& report);
nlohmann::json to_json(const Report& report);
nlohmann::json aggregate_reports(const std::vector<Report>& reports);

std::string_view name(CapabilityStatus status) noexcept;
std::string_view name(ScenarioStatus status) noexcept;

} // namespace kasumi::operational::provider_certification

#endif
