#ifndef KASUMI_APPLICATION_SYNC_COORDINATOR_HPP
#define KASUMI_APPLICATION_SYNC_COORDINATOR_HPP

#include "application/observation/state.hpp"
#include "core/reconciliation/types.hpp"
#include "crypto/file_crypto.hpp"
#include "runtime/resolver.hpp"
#include "transport/transport.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>

namespace kasumi::application::sync::coordinator {

// Result of recovering an interrupted transaction.
enum class RecoveryResult {
    // No pending transaction journal was found.
    NoJournal,
    // Incomplete changes were rolled back.
    RolledBack,
    // Committed changes were completed.
    RolledForward,
    // Incomplete upload transaction is valid and ready to be resumed.
    ResumableTransaction
};

// Failure categories for transactional execution.
enum class ErrorCode {
    InvalidInput,
    JournalFailure,
    WorkspaceFailure,
    MutationFailure,
    PublicationFailure,
    DatabaseFailure,
    CompositionMismatch,
    ObservationFailure,
    ConcurrentModification,
    RecoveryIndeterminate,
    RecoveryConflict,
    RecoveryRequired
};

// Detailed failure of synchronization coordination.
struct Error {
    ErrorCode code = ErrorCode::InvalidInput;
    std::string detail;
    // Operation index in the plan, when applicable.
    std::optional<std::size_t> operation_index;
};

// Formats a coordinator failure.
std::string describe(const Error& error);

// Transactionally executes the result of the provided observation.
std::expected<void, Error>
execute(const runtime::RuntimeData& runtime_data,
        transport::Transport& storage,
        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
        const reconciliation::Input& observed_input,
        const reconciliation::Result& reconciliation_result,
        observation::LocalObservationSession* session = nullptr);

// Recovers an interrupted transaction, if any.
std::expected<RecoveryResult, Error>
recover_if_needed(const runtime::RuntimeData& runtime_data,
                  transport::Transport& storage,
                  std::span<const std::uint8_t, crypto::KEY_SIZE> key);

} // namespace kasumi::application::sync::coordinator

#endif
