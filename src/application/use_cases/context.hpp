#ifndef KASUMI_APPLICATION_USE_CASES_CONTEXT_HPP
#define KASUMI_APPLICATION_USE_CASES_CONTEXT_HPP

#include "application/execute.hpp"
#include "application/history_storage/activity.hpp"
#include "core/history.hpp"
#include "platform/profile_lock.hpp"
#include "runtime/machine.hpp"
#include "runtime/resolver.hpp"
#include "runtime/vault.hpp"
#include "transport/transport.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace kasumi::application::detail {

// Resolved resources for an application execution.
struct OperationContext {
    Operation operation;
    std::filesystem::path app_data_dir;
    runtime::RuntimeData runtime;
    RuntimeSummary summary;
    std::optional<runtime::MachineIdentity> machine_identity;
    bool initial_sync = false;
    bool audit_inventory = false;
    bool repair = false;
    bool dry_run = false;
    bool reclaim_dirty = false;
    std::optional<std::uint32_t> gc_min_age_hours = std::nullopt;
    bool has_remote_history_objects = false;
    bool recovered_transaction = false;
    bool sync_mutated = false;
    bool remote_observed = false;
    std::string accepted_commit_id;
    std::intptr_t profile_lock = platform::invalid_profile_lock;
    runtime::vault::KeyBytes key{};
    std::string writer_identifier;
    std::optional<std::string> barrier_identifier = std::nullopt;
    transport::Transport storage;
    ProgressCallback on_progress{};
    std::function<void()> on_sync_mutation_start{};
    std::optional<history_storage::activity::ActivityOutcome>
        maintenance_failure_outcome;
    std::string maintenance_failure_stage;
    std::string maintenance_failure_detail;
    std::uint64_t maintenance_metric_primary = 0;
    std::uint64_t maintenance_metric_secondary = 0;
    std::uint32_t maintenance_flags = 0;
    std::vector<history_storage::activity::LoadedActivity> gc_kept_activities;
};

[[nodiscard]] inline history::CommitAuthorship
make_commit_authorship(history::CommitOriginOperation origin,
                       const runtime::MachineIdentity& machine) {
    return history::CommitAuthorship{
        .operation = origin,
        .machine_id = machine.id,
        .machine_name = machine.name,
    };
}

inline Error make_error(const OperationContext& context,
                        ErrorCode code,
                        std::string detail,
                        std::optional<SyncStage> stage = std::nullopt) {
    return Error{.operation = context.operation,
                 .code = code,
                 .detail = std::move(detail),
                 .runtime = context.summary,
                 .stage = stage};
}

inline std::unexpected<Error>
fail_app(const OperationContext& context,
         ErrorCode code,
         std::string detail,
         std::optional<SyncStage> stage = std::nullopt) {
    return std::unexpected(make_error(context, code, std::move(detail), stage));
}

inline Response make_response(const OperationContext& context,
                              ResponseData data) {
    return Response{.operation = context.operation,
                    .runtime = context.summary,
                    .data = std::move(data)};
}

// Validates input and prepares profile, key, and transport.
std::expected<void, Error> prepare_operation(const ExecutionInput& input,
                                             OperationContext& output);

// Wipes key material and releases the profile lock.
void wipe_operation(OperationContext& context) noexcept;

} // namespace kasumi::application::detail

#endif
