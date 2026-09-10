#ifndef KASUMI_APPLICATION_SYNC_COORDINATOR_DETAIL_HPP
#define KASUMI_APPLICATION_SYNC_COORDINATOR_DETAIL_HPP

#include "application/history_storage/epoch.hpp"
#include "application/sync/coordinator.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/mutation_batch.hpp"
#include "application/sync/publication.hpp"
#include "core/transaction/types.hpp"
#include "crypto/file_crypto.hpp"
#include "platform/workspace.hpp"
#include "runtime/resolver.hpp"
#include "transport/transport.hpp"

#include <chrono>
#include <cstddef>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>

namespace kasumi::application::sync::coordinator::detail {

// Sizing and TTL limits for chunked sub-batch uploads
inline constexpr std::size_t upload_batch_max_items = 256;
inline constexpr std::uint64_t upload_batch_max_bytes =
    256 * 1024 * 1024; // 256 MiB
inline constexpr auto transaction_resumption_ttl = std::chrono::hours(24);

// Creates a coordinator failure with optional operation context.
Error make_error(ErrorCode code,
                 std::string detail,
                 std::optional<std::size_t> operation_index = std::nullopt);
// Creates a failure related to the transaction journal.
Error journal_error(std::string detail);
// Indicates that the remote publication state could not be proven.
Error indeterminate_publication(const publication::Error& error,
                                std::string_view operation);
// Indicates that the file status represents a missing path.
bool missing(std::filesystem::file_status status) noexcept;

// Reads path status and converts any failure.
std::expected<std::filesystem::file_status, Error>
read_status(const std::filesystem::path& path);
// Resolves the internal profile directory.
std::expected<std::filesystem::path, Error>
profile_directory(const runtime::RuntimeData& runtime_data);
// Resolves or creates the transactions directory.
std::expected<std::filesystem::path, Error>
transactions_directory(const std::filesystem::path& profile, bool create);
// Creates an isolated temporary workspace for a transaction.
std::expected<platform::Workspace, Error>
create_transaction_workspace(const std::filesystem::path& profile,
                             std::string_view id);
// Removes the temporary transaction workspace, if it exists.
std::expected<void, Error> remove_transaction_workspace(
    const std::optional<platform::Workspace>& workspace);
// Cleans up the journal and temporary workspace after completion.
std::expected<void, Error>
finish_transaction_cleanup(const journal::Paths& paths,
                           const std::optional<platform::Workspace>& workspace);
// Cleans up orphan workspaces without a matching transaction.
std::expected<void, Error>
cleanup_orphan_workspaces(const std::filesystem::path& profile);
// Resolves transaction journal paths within the profile.
std::expected<journal::Paths, Error>
make_journal_paths(const runtime::RuntimeData& runtime_data);
// Persists the current transaction record.
std::expected<void, Error>
save_record(const journal::Paths& paths,
            const transaction::Record& record,
            std::span<const std::uint8_t, crypto::KEY_SIZE> key);

// Reconstructs the genesis Epoch solely from durable journal fields.
history_storage::epoch::Epoch genesis_epoch(const transaction::Record& record);

// Initializes identity/timestamp once and deterministically seals the Epoch.
std::expected<history_storage::epoch::SealedEpoch, Error>
prepare_genesis_epoch(transaction::Record& record,
                      history_storage::epoch::RetentionPolicy policy,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key);

std::expected<history_storage::epoch::SealedEpoch, Error>
prepare_pruning_epoch(transaction::Record& record,
                      history_storage::epoch::RetentionPolicy policy,
                      const history_storage::epoch::EpochPlan& plan,
                      const std::string& previous_vault_id,
                      std::uint64_t previous_sequence,
                      const std::string& previous_epoch_id,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key);

// Constructs the final transaction state after the batch is applied, without
// modifying the original.
transaction::Record
make_upload_batch_checkpoint(const transaction::Record& original,
                             const mutation::StagedUploadBatch& batch);

// Applies batch operations to the record, saves a durable checkpoint, and
// assigns changes to the current record on success.
std::expected<void, Error>
checkpoint_upload_batch(const journal::Paths& paths,
                        transaction::Record& record,
                        const mutation::StagedUploadBatch& batch,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key);

// Rolls back the transaction and updates its persisted record.
std::expected<void, Error>
rollback_transaction(const journal::Paths& paths,
                     transaction::Record& record,
                     const std::optional<platform::Workspace>& workspace,
                     const std::filesystem::path& local_root,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key);

// Rolls back only mutations applied to the local directory.
std::expected<void, Error>
rollback_local_mutations(transaction::Record& record,
                         const std::optional<platform::Workspace>& workspace,
                         const std::filesystem::path& local_root);

// Resolves the configured concurrency level for batch uploads.
std::size_t content_concurrency() noexcept;

} // namespace kasumi::application::sync::coordinator::detail

#endif
