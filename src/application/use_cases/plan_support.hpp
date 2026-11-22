#ifndef KASUMI_APPLICATION_USE_CASES_PLAN_SUPPORT_HPP
#define KASUMI_APPLICATION_USE_CASES_PLAN_SUPPORT_HPP

#include "application/execute.hpp"
#include "core/reconciliation/types.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>

namespace kasumi::application::detail {

// Translates a reconciliation failure into user-facing text.
std::string describe_reconciliation_error(const reconciliation::Error& error);

using DiskSpaceQuery =
    std::function<std::optional<std::uint64_t>(const std::filesystem::path&)>;

std::optional<std::uint64_t>
query_available_disk_space(const std::filesystem::path& path) noexcept;

// Verifies local destination and staging workspace have sufficient free space
// for planned downloads and local copies before mutations begin.
std::expected<void, std::string>
check_sync_disk_space(const std::filesystem::path& local_dir,
                      const std::filesystem::path& profile_dir,
                      const SyncPlan& plan,
                      const DiskSpaceQuery& query = {});

} // namespace kasumi::application::detail

#endif
