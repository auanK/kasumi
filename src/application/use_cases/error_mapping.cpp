#include "application/use_cases/error_mapping.hpp"

#include "application/detail.hpp"
#include "runtime/resolver.hpp"
#include "runtime/vault.hpp"

#include <string>
#include <utility>

namespace kasumi::application::detail {

ErrorCode runtime_error_to_application_error(runtime::ErrorCode code) {
    return map_runtime_error_code(code,
                                  ErrorCode::InvalidProfile,
                                  ErrorCode::ProfileNotFound,
                                  ErrorCode::CredentialFailure,
                                  ErrorCode::RuntimeFailure,
                                  ErrorCode::RuntimeFailure);
}

std::expected<void, Error>
resolve_key_into(Operation operation,
                 const Credentials& credentials,
                 const runtime::RuntimeData& runtime_data,
                 const RuntimeSummary& summary,
                 runtime::vault::KeyBytes& output) {
    return resolve_vault_key<Error>(
        credentials,
        runtime_data,
        output,
        VaultKeyPolicy<Error>{
            .read_only = false,
            .missing_code = ErrorCode::CredentialFailure,
            .mismatch_code = ErrorCode::RuntimeFailure,
            .io_code = ErrorCode::CredentialFailure,
            .credential_code = ErrorCode::CredentialFailure,
            .missing_detail = "key not found and credentials not provided",
        },
        [&](ErrorCode code, std::string detail) {
            return Error{.operation = operation,
                         .code = code,
                         .detail = std::move(detail),
                         .runtime = summary};
        });
}

namespace {

Error build_error(Operation operation,
                  ErrorCode code,
                  std::string detail,
                  const RuntimeSummary& summary,
                  std::optional<GarbageCollectFailure> gc = std::nullopt) {
    return Error{.operation = operation,
                 .code = code,
                 .detail = std::move(detail),
                 .runtime = summary,
                 .garbage_collection = std::move(gc)};
}

} // namespace

Error transaction_error(Operation operation,
                        const sync::coordinator::Error& error,
                        const RuntimeSummary& summary) {
    return build_error(operation,
                       ErrorCode::SynchronizationFailure,
                       sync::coordinator::describe(error),
                       summary);
}

Error maintenance_error(Operation operation,
                        const integrity::Error& error,
                        const RuntimeSummary& summary) {
    return build_error(operation,
                       operation == Operation::Fsck
                           ? ErrorCode::FsckFailure
                           : ErrorCode::GarbageCollectionFailure,
                       integrity::describe(error),
                       summary,
                       error.garbage_collection);
}

Error maintenance_recovery_error(Operation operation,
                                 const sync::coordinator::Error& error,
                                 const RuntimeSummary& summary) {
    return build_error(operation,
                       operation == Operation::Fsck
                           ? ErrorCode::FsckFailure
                           : ErrorCode::GarbageCollectionFailure,
                       sync::coordinator::describe(error),
                       summary);
}

Error plan_error(Operation operation,
                 std::string detail,
                 const RuntimeSummary& summary) {
    return build_error(
        operation, ErrorCode::PlanFailure, std::move(detail), summary);
}

Error synchronization_error(Operation operation,
                            std::string detail,
                            const RuntimeSummary& summary) {
    return build_error(operation,
                       ErrorCode::SynchronizationFailure,
                       std::move(detail),
                       summary);
}

} // namespace kasumi::application::detail
