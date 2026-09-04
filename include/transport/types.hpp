#ifndef KASUMI_TRANSPORT_TYPES_HPP
#define KASUMI_TRANSPORT_TYPES_HPP

#include <cstddef>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::transport {

// Failure categories for transport.
enum class ErrorCode {
    InvalidContext,
    InvalidIdentifier,
    StorageNotFound,
    ObjectNotFound,
    Unsupported,
    PermissionDenied,
    Io,
    ProcessFailure,
    ProtocolFailure,
    Timeout,
    Cancelled,
    BackendUnavailable,
    Unknown
};

// Normalized error across storage implementations.
struct Error {
    ErrorCode code = ErrorCode::Unknown;
    std::string message;
    // Native platform error code, when available.
    int native_code = 0;
};

// Result of an operation without a return value.
using Result = std::expected<void, Error>;

// Existence state of an object.
enum class Presence {
    Present,
    Absent
};

// Result of an object existence query.
using PresenceResult = std::expected<Presence, Error>;

// Idempotent result of an object removal.
enum class Removal {
    Removed,
    AlreadyAbsent
};

// Result of an object removal attempt.
using RemovalResult = std::expected<Removal, Error>;

// List of identifiers or transport error.
using ListingResult = std::expected<std::vector<std::string>, Error>;

// Returns the stable name of the error code category.
std::string_view error_code_name(ErrorCode code) noexcept;

// Indicates that a mutation may have been applied despite the observed failure.
bool mutation_result_is_ambiguous(const Error& error) noexcept;

// Formats error category, message, and native code.
std::string describe(const Error& error);

} // namespace kasumi::transport

#endif
