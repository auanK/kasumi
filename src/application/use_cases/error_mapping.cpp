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

Error make_error(const OperationContext& context,
                 ErrorCode code,
                 std::string detail,
                 std::optional<SyncStage> stage) {
    return Error{.operation = context.operation,
                 .code = code,
                 .detail = std::move(detail),
                 .runtime = context.summary,
                 .stage = stage};
}

} // namespace kasumi::application::detail
