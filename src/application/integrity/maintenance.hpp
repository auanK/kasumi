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
    // Original transport failure, including its native code, when available.
    std::optional<transport::Error> transport_failure;
    // Partial-result and cleanup diagnostics for garbage collection.
    std::optional<GarbageCollectFailure> garbage_collection;
};

// Formats an integrity failure.
std::string describe(const Error& error);

// Counts produced by the integrity audit.
struct FsckResult {
    std::size_t checked_objects = 0;
    std::size_t repaired_objects = 0;
};

using FsckProgressCallback = std::function<void(const FsckProgress&)>;

// Counts produced by direct, individually validated garbage collection.
struct GarbageCollectResult {
    std::size_t candidate_objects = 0;
    std::size_t removed_objects = 0;
    bool analysis_only = false;
};

using GarbageCollectProgressCallback =
    std::function<void(const GarbageCollectProgress&)>;

// Removes authenticated, unreachable content and redundant commit variants.
// Analysis is stable only when two complete observations agree. Candidates are
// revalidated individually and removed with exactly one backend attempt each.
std::expected<GarbageCollectResult, Error>
garbage_collect(const runtime::RuntimeData& runtime_data,
                transport::Transport& storage,
                std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                GarbageCollectProgressCallback on_progress = {});

// Compatibility overload retaining the historical maintenance call shape.
// Collection remains sequential; the concurrency hints are validated but the
// direct-removal runner never batches removals.
std::expected<GarbageCollectResult, Error>
garbage_collect(const runtime::RuntimeData& runtime_data,
                transport::Transport& storage,
                std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                std::size_t copy_batch_concurrency,
                std::size_t metadata_batch_concurrency,
                std::size_t source_removal_concurrency,
                GarbageCollectProgressCallback on_progress = {});

// Audits the history and reachable content objects.
std::expected<FsckResult, Error>
fsck(const runtime::RuntimeData& runtime_data,
     transport::Transport& storage,
     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
     std::size_t audit_concurrency = 1,
     FsckProgressCallback on_progress = {});

} // namespace kasumi::application::integrity

#endif
