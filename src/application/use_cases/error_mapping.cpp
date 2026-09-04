#include "application/use_cases/error_mapping.hpp"

#include "crypto/secure_memory.hpp"
#include "runtime/resolver.hpp"
#include "runtime/vault.hpp"

#include <filesystem>
#include <string>
#include <utility>

namespace kasumi::application::detail {

ErrorCode runtime_error_to_application_error(runtime::ErrorCode code) {
    switch (code) {
        case runtime::ErrorCode::InvalidProfileName:
            return ErrorCode::InvalidProfile;
        case runtime::ErrorCode::ProfileNotFound:
            return ErrorCode::ProfileNotFound;
        case runtime::ErrorCode::KeyNotFound:
        case runtime::ErrorCode::KeyInvalid:
        case runtime::ErrorCode::KeyDerivationFailure:
        case runtime::ErrorCode::KeyWriteFailure:
            return ErrorCode::CredentialFailure;
        case runtime::ErrorCode::ConfigNotFound:
        case runtime::ErrorCode::ConfigInvalid:
        case runtime::ErrorCode::ProfileInvalid:
        case runtime::ErrorCode::PathEscape:
        case runtime::ErrorCode::IoFailure:
            return ErrorCode::RuntimeFailure;
    }
    std::unreachable();
}

std::expected<void, Error>
resolve_key_into(Operation operation,
                 const Credentials& credentials,
                 const runtime::RuntimeData& runtime_data,
                 const RuntimeSummary& summary,
                 runtime::vault::KeyBytes& output) {
    crypto::secure_memory::wipe(output.data(), output.size());

    if (std::holds_alternative<NoCredentials>(credentials)) {
        if (!std::filesystem::exists(runtime_data.key_path)) {
            return std::unexpected(Error{
                .operation = operation,
                .code = ErrorCode::CredentialFailure,
                .detail = "chave não encontrada e credenciais não fornecidas",
                .runtime = summary,
            });
        }

        auto result = runtime::vault::read(runtime_data.key_path);
        if (!result) {
            return std::unexpected(Error{
                .operation = operation,
                .code = ErrorCode::CredentialFailure,
                .detail = result.error().detail,
                .runtime = summary,
            });
        }
        output = *result;
        crypto::secure_memory::wipe(result->data(), result->size());
        return {};
    }

    const auto& master_key = std::get<MasterKeyHex>(credentials);
    auto result = runtime::vault::decode_hex(master_key.value);
    if (!result) {
        return std::unexpected(Error{
            .operation = operation,
            .code = ErrorCode::CredentialFailure,
            .detail = result.error().detail,
            .runtime = summary,
        });
    }
    if (std::filesystem::exists(runtime_data.key_path)) {
        auto stored = runtime::vault::read(runtime_data.key_path);
        if (!stored) {
            crypto::secure_memory::wipe(result->data(), result->size());
            return std::unexpected(Error{
                .operation = operation,
                .code = ErrorCode::CredentialFailure,
                .detail = stored.error().detail,
                .runtime = summary,
            });
        }
        const bool matches = *stored == *result;
        crypto::secure_memory::wipe(stored->data(), stored->size());
        if (!matches) {
            crypto::secure_memory::wipe(result->data(), result->size());
            return std::unexpected(Error{
                .operation = operation,
                .code = ErrorCode::RuntimeFailure,
                .detail = "a credencial não corresponde ao perfil",
                .runtime = summary,
            });
        }
    }
    output = *result;
    crypto::secure_memory::wipe(result->data(), result->size());
    return {};
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
                 .runtime = summary};
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
