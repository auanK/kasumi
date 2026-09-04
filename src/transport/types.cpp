#include "transport/types.hpp"

namespace kasumi::transport {

std::string_view error_code_name(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::InvalidContext:
            return "invalid_context";

        case ErrorCode::InvalidIdentifier:
            return "invalid_identifier";

        case ErrorCode::StorageNotFound:
            return "storage_not_found";

        case ErrorCode::ObjectNotFound:
            return "object_not_found";
        case ErrorCode::Unsupported:
            return "unsupported";

        case ErrorCode::PermissionDenied:
            return "permission_denied";

        case ErrorCode::Io:
            return "io";

        case ErrorCode::BackendUnavailable:
            return "backend_unavailable";

        case ErrorCode::ProcessFailure:
            return "process_failure";

        case ErrorCode::ProtocolFailure:
            return "protocol_failure";

        case ErrorCode::Timeout:
            return "timeout";

        case ErrorCode::Cancelled:
            return "cancelled";

        case ErrorCode::Unknown:
            return "unknown";
    }

    return "unknown";
}

bool mutation_result_is_ambiguous(const Error& error) noexcept {
    return error.code == ErrorCode::Io || error.code == ErrorCode::Timeout ||
           error.code == ErrorCode::Cancelled ||
           error.code == ErrorCode::BackendUnavailable ||
           error.code == ErrorCode::ProcessFailure;
}

std::string describe(const Error& error) {
    std::string description{error_code_name(error.code)};

    if (!error.message.empty()) {
        description += ": ";
        description += error.message;
    }

    if (error.native_code != 0) {
        description += " (native_code=";
        description += std::to_string(error.native_code);
        description += ')';
    }

    return description;
}

} // namespace kasumi::transport
