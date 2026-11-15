#ifndef KASUMI_APPLICATION_USE_CASES_ERROR_MAPPING_HPP
#define KASUMI_APPLICATION_USE_CASES_ERROR_MAPPING_HPP

#include "application/execute.hpp"
#include "application/use_cases/context.hpp"
#include "crypto/file_crypto.hpp"
#include "runtime/vault.hpp"

#include <expected>
#include <string>
#include <utility>

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

Error make_error(const OperationContext& context,
                 ErrorCode code,
                 std::string detail,
                 std::optional<SyncStage> stage = std::nullopt);

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

} // namespace kasumi::application::detail

#endif
