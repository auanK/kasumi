#ifndef KASUMI_RUNTIME_ERROR_HPP
#define KASUMI_RUNTIME_ERROR_HPP

#include <expected>
#include <string>

namespace kasumi::runtime {

// Failure categories for the runtime layer.
enum class ErrorCode {
    InvalidProfileName,
    ConfigNotFound,
    ConfigInvalid,
    ProfileNotFound,
    ProfileInvalid,
    PathEscape,
    IoFailure,
    KeyNotFound,
    KeyInvalid,
    KeyDerivationFailure,
    KeyWriteFailure
};

// Error produced by the runtime layer.
struct Error {
    ErrorCode code = ErrorCode::IoFailure;
    std::string detail;
};

inline std::unexpected<Error> fail(ErrorCode code, std::string detail) {
    return std::unexpected(Error{.code = code, .detail = std::move(detail)});
}

} // namespace kasumi::runtime

#endif
