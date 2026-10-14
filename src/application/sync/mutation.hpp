#ifndef KASUMI_APPLICATION_SYNC_MUTATION_HPP
#define KASUMI_APPLICATION_SYNC_MUTATION_HPP

#include "core/operation.hpp"
#include "core/transaction/types.hpp"
#include "crypto/file_crypto.hpp"
#include "platform/workspace.hpp"
#include "transport/transport.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace kasumi::application::sync::mutation {

// Failure categories when applying an operation.
enum class MutationErrorCode {
    InvalidOperation,
    UnsafePath,
    LocalIo,
    TransportFailure,
    RemoteContentMissing,
    RemoteResultUnknown,
    CryptoFailure,
    IntegrityMismatch,
    DestinationConflict
};

// Contextualized mutation failure.
struct MutationError {
    MutationErrorCode code = MutationErrorCode::LocalIo;

    std::string detail;

    // Path associated with the failure, when applicable.
    std::filesystem::path path;

    // Operation index in the plan.
    std::size_t operation_index = 0;
};

// Result of a local or remote mutation.
using MutationResult = std::expected<void, MutationError>;

// Result of preparing for rollback.
using PreparationResult =
    std::expected<transaction::OperationProgress, MutationError>;

// Execution state transferred by a confirmed rename; rollback keeps its
// original progress.
struct DestinationPrecondition {
    std::string hash;
    std::optional<transaction::OperationProgress> backup;
};

// Policy for reusing downloaded and verified content.
enum class DownloadCacheMode {
    // Uses exclusive temporary files.
    None,
    // Retains reusable files without trusting previous ones.
    Populate,
    // Revalidates previous files before reusing them.
    Reuse
};

// Prepares the operation and its potential rollback.
PreparationResult
prepare_operation(const Operation& operation,
                  std::size_t operation_index,
                  const std::filesystem::path& local_root,
                  const platform::Workspace& workspace,
                  const transaction::OperationProgress& current_progress,
                  std::span<const Operation> plan_operations = {});

// Restores previous state of a prepared operation.
std::expected<void, MutationError>
rollback_operation(const Operation& operation,
                   std::size_t operation_index,
                   const std::filesystem::path& local_root,
                   const platform::Workspace& workspace,
                   const transaction::OperationProgress& progress,
                   const DestinationPrecondition* destination = nullptr);

// Applies local effects or transfers and verifies the result.
MutationResult
apply_operation(const Operation& operation,
                std::size_t operation_index,
                const std::filesystem::path& local_root,
                transport::Transport& storage,
                std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                const platform::Workspace& workspace,
                const transaction::OperationProgress& progress,
                DownloadCacheMode download_cache = DownloadCacheMode::None,
                const DestinationPrecondition* destination = nullptr);

// Formats a mutation failure.
std::string describe(const MutationError& error);

} // namespace kasumi::application::sync::mutation

#endif
