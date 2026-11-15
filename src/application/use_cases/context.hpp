#ifndef KASUMI_APPLICATION_USE_CASES_CONTEXT_HPP
#define KASUMI_APPLICATION_USE_CASES_CONTEXT_HPP

#include "application/execute.hpp"
#include "platform/profile_lock.hpp"
#include "runtime/resolver.hpp"
#include "runtime/vault.hpp"
#include "transport/transport.hpp"

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>

namespace kasumi::application::detail {

// Resolved resources for an application execution.
struct OperationContext {
    Operation operation;
    runtime::RuntimeData runtime;
    RuntimeSummary summary;
    bool initial_sync = false;
    bool audit_inventory = false;
    bool trust_existing_content = false;
    bool has_remote_history_objects = false;
    std::intptr_t profile_lock = platform::invalid_profile_lock;
    runtime::vault::KeyBytes key{};
    std::string writer_identifier;
    transport::Transport storage;
    ProgressCallback on_progress{};
    std::unordered_set<std::string> initial_content_identifiers;
};

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
