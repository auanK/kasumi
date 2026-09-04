#ifndef KASUMI_APPLICATION_USE_CASES_ERROR_MAPPING_HPP
#define KASUMI_APPLICATION_USE_CASES_ERROR_MAPPING_HPP

#include "application/execute.hpp"
#include "application/integrity/maintenance.hpp"
#include "application/sync/coordinator.hpp"
#include "crypto/file_crypto.hpp"
#include "runtime/vault.hpp"

#include <expected>
#include <string>

namespace kasumi::application::detail {

// Maps execution-layer categories to the application API.
ErrorCode runtime_error_to_application_error(runtime::ErrorCode code);

// Resolves and validates the key from the provided credentials.
std::expected<void, Error>
resolve_key_into(Operation operation,
                 const Credentials& credentials,
                 const runtime::RuntimeData& runtime_data,
                 const RuntimeSummary& summary,
                 runtime::vault::KeyBytes& output);

// Converts a transaction failure into an application error.
Error transaction_error(Operation operation,
                        const sync::coordinator::Error& error,
                        const RuntimeSummary& summary);

// Converts a maintenance failure into an application error.
Error maintenance_error(Operation operation,
                        const integrity::Error& error,
                        const RuntimeSummary& summary);

// Converts a recovery failure into a maintenance error.
Error maintenance_recovery_error(Operation operation,
                                 const sync::coordinator::Error& error,
                                 const RuntimeSummary& summary);

// Creates an error when computing the plan.
Error plan_error(Operation operation,
                 std::string detail,
                 const RuntimeSummary& summary);

// Creates an error during synchronization.
Error synchronization_error(Operation operation,
                            std::string detail,
                            const RuntimeSummary& summary);

} // namespace kasumi::application::detail

#endif
