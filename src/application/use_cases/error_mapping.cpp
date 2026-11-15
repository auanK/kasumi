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

Error transaction_error(Operation operation,
                        const sync::coordinator::Error& error,
                        const RuntimeSummary& summary) {
    return Error{.operation = operation,
                 .code = ErrorCode::SynchronizationFailure,
                 .detail = sync::coordinator::describe(error),
                 .runtime = summary};
}

Error maintenance_error(Operation operation,
                        const integrity::Error& error,
                        const RuntimeSummary& summary) {
    ErrorCode code = ErrorCode::GarbageCollectionFailure;
    if (operation == Operation::Fsck) {
        code = ErrorCode::FsckFailure;
    }
    return Error{.operation = operation,
                 .code = code,
                 .detail = integrity::describe(error),
                 .runtime = summary,
                 .garbage_collection = error.garbage_collection};
}

Error maintenance_recovery_error(Operation operation,
                                 const sync::coordinator::Error& error,
                                 const RuntimeSummary& summary) {
    return Error{.operation = operation,
                 .code = operation == Operation::Fsck
                             ? ErrorCode::FsckFailure
                             : ErrorCode::GarbageCollectionFailure,
                 .detail = sync::coordinator::describe(error),
                 .runtime = summary};
}

Error plan_error(Operation operation,
                 std::string detail,
                 const RuntimeSummary& summary) {
    return Error{.operation = operation,
                 .code = ErrorCode::PlanFailure,
                 .detail = std::move(detail),
                 .runtime = summary};
}

Error synchronization_error(Operation operation,
                            std::string detail,
                            const RuntimeSummary& summary) {
    return Error{.operation = operation,
                 .code = ErrorCode::SynchronizationFailure,
                 .detail = std::move(detail),
                 .runtime = summary};
}

} // namespace kasumi::application::detail
