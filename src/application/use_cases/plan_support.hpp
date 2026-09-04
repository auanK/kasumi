#ifndef KASUMI_APPLICATION_USE_CASES_PLAN_SUPPORT_HPP
#define KASUMI_APPLICATION_USE_CASES_PLAN_SUPPORT_HPP

#include "application/execute.hpp"
#include "core/reconciliation/types.hpp"

#include <filesystem>
#include <span>
#include <string>

namespace kasumi::application::detail {

// Translates a reconciliation failure into user-facing text.
std::string describe_reconciliation_error(const reconciliation::Error& error);

// Summarizes paths that cannot be recovered.
std::string
describe_unrecoverable_paths(std::span<const std::filesystem::path> paths);

} // namespace kasumi::application::detail

#endif
