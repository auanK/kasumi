#ifndef KASUMI_APPLICATION_SYNC_COORDINATOR_HPP
#define KASUMI_APPLICATION_SYNC_COORDINATOR_HPP

#include "application/observation/state.hpp"
#include "core/history.hpp"
#include "core/reconciliation/types.hpp"
#include "core/transaction/types.hpp"
#include "crypto/file_crypto.hpp"
#include "platform/workspace.hpp"
#include "runtime/resolver.hpp"
#include "transport/transport.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

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
    RemoteContentMissing,
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
    bool empty_local_blocked = false;
};

// Staging workspace and backup progress carried from stabilize into execute.
struct StagedExecutionHandoff {
    std::string operation_id;
    std::vector<transaction::OperationProgress> progress;
    std::optional<platform::Workspace> workspace;
};

// Removes an unused staged execution workspace if still present.
std::expected<void, Error>
discard_staged_handoff(std::optional<StagedExecutionHandoff>& staged,
                       std::span<const std::uint8_t, crypto::KEY_SIZE> key);

// Controls whether a sync may advance an existing remote pruning Epoch.
enum class EpochAdvancementPolicy {
    DeferMultiWriter,
    ExclusivePublisher,
};

// Formats a coordinator failure.
std::string describe(const Error& error);

// Blocks unintended bulk remote deletions when an already-populated local
// directory becomes empty and the plan would delete every remote entry.
std::expected<void, Error>
check_empty_local_deletion_guard(const std::filesystem::path& local_dir,
                                 const reconciliation::Input& input,
                                 const reconciliation::Result& result);

// Transactionally executes the result of the provided observation.
std::expected<void, Error>
execute(const runtime::RuntimeData& runtime_data,
        transport::Transport& storage,
        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
        const reconciliation::Input& observed_input,
        const reconciliation::Result& reconciliation_result,
        observation::LocalObservationSession* session = nullptr,
        StagedExecutionHandoff* staged_handoff = nullptr,
        bool enable_micro_packs = false,
        history::CommitAuthorship authorship = {},
        std::string* accepted_commit_id = nullptr,
        bool enforce_empty_local_guard = false,
        EpochAdvancementPolicy epoch_advancement =
            EpochAdvancementPolicy::DeferMultiWriter);

// Recovers an interrupted transaction, if any.
std::expected<RecoveryResult, Error>
recover_if_needed(const runtime::RuntimeData& runtime_data,
                  transport::Transport& storage,
                  std::span<const std::uint8_t, crypto::KEY_SIZE> key);

} // namespace kasumi::application::sync::coordinator

#endif
