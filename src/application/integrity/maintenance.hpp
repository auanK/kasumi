#ifndef KASUMI_APPLICATION_INTEGRITY_MAINTENANCE_HPP
#define KASUMI_APPLICATION_INTEGRITY_MAINTENANCE_HPP

#include "application/execute.hpp"
#include "crypto/file_crypto.hpp"
#include "runtime/resolver.hpp"
#include "transport/transport.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <span>
#include <string>

namespace kasumi::application::integrity {

// Failure categories for integrity routines.
enum class ErrorCode {
    InvalidInput,
    StateFailure,
    WorkspaceFailure,
    TransportFailure,
    CryptoFailure,
    IntegrityFailure,
    Unrecoverable,
    ConcurrentChange
};

// Detailed failure of an integrity routine.
struct Error {
    ErrorCode code = ErrorCode::InvalidInput;
    std::string detail;
    // Object associated with the failure, when applicable.
    std::optional<std::string> object_identifier;
};

// Formats an integrity failure.
std::string describe(const Error& error);

// Counts produced by the integrity audit.
struct FsckResult {
    std::size_t checked_objects = 0;
    std::size_t repaired_objects = 0;
};

using FsckProgressCallback = std::function<void(const FsckProgress&)>;

// Audits the history and reachable content objects.
std::expected<FsckResult, Error>
fsck(const runtime::RuntimeData& runtime_data,
     transport::Transport& storage,
     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
     std::size_t audit_concurrency = 1,
     FsckProgressCallback on_progress = {});

} // namespace kasumi::application::integrity

#endif
