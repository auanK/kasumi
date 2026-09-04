#ifndef KASUMI_APPLICATION_INTEGRITY_MAINTENANCE_HPP
#define KASUMI_APPLICATION_INTEGRITY_MAINTENANCE_HPP

#include "crypto/file_crypto.hpp"
#include "runtime/resolver.hpp"
#include "transport/transport.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
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

// Counts produced by recoverable garbage collection.
struct GarbageCollectResult {
    std::size_t candidate_objects = 0;
    std::size_t quarantined_objects = 0;
    std::size_t restored_objects = 0;
    std::size_t purged_objects = 0;
    bool analysis_only = false;
};

// Audits the history and reachable content objects.
std::expected<FsckResult, Error>
fsck(const runtime::RuntimeData& runtime_data,
     transport::Transport& storage,
     std::span<const std::uint8_t, crypto::KEY_SIZE> key);

// Moves unreachable objects to quarantine after two stable observations.
std::expected<GarbageCollectResult, Error>
garbage_collect(const runtime::RuntimeData& runtime_data,
                transport::Transport& storage,
                std::span<const std::uint8_t, crypto::KEY_SIZE> key);

} // namespace kasumi::application::integrity

#endif
