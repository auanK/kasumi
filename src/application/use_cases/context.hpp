#ifndef KASUMI_APPLICATION_USE_CASES_CONTEXT_HPP
#define KASUMI_APPLICATION_USE_CASES_CONTEXT_HPP

#include "application/execute.hpp"
#include "platform/profile_lock.hpp"
#include "runtime/resolver.hpp"
#include "runtime/vault.hpp"
#include "transport/transport.hpp"

#include <cstdint>
#include <expected>

namespace kasumi::application::detail {

// Resolved resources for an application execution.
struct OperationContext {
    Operation operation;
    runtime::RuntimeData runtime;
    RuntimeSummary summary;
    std::intptr_t profile_lock = platform::invalid_profile_lock;
    runtime::vault::KeyBytes key{};
    transport::Transport storage;
};

// Validates input and prepares profile, key, and transport.
std::expected<void, Error> prepare_operation(const ExecutionInput& input,
                                             OperationContext& output);

// Wipes key material and releases the profile lock.
void wipe_operation(OperationContext& context) noexcept;

} // namespace kasumi::application::detail

#endif
