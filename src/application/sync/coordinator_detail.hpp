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
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace kasumi::application {
class ProgressMeter;
}

namespace kasumi::application::sync::coordinator::detail {

// Sizing and TTL limits for chunked sub-batch uploads
inline constexpr std::size_t upload_batch_max_items = 256;
inline constexpr std::uint64_t upload_batch_max_bytes =
    256 * 1024 * 1024; // 256 MiB
inline constexpr auto transaction_resumption_ttl = std::chrono::hours(24);

enum class TypeChangeStep {
    Unrelated,
    RemoveFile,
    RemoveDirectory,
    Install
};

std::vector<TypeChangeStep>
local_type_changes(std::span<const transaction::Operation> operations);

void order_local_type_changes(std::span<const TypeChangeStep> steps,
                              std::vector<std::size_t>& order);

std::expected<void, Error>
prepare_type_change_install(transaction::Record& record,
                            std::size_t index,
                            const std::filesystem::path& root,
                            const platform::Workspace& workspace);

inline void
order_local_copies(std::span<const transaction::Operation> operations,
                   std::vector<std::size_t>& order) {
    // Keep setup in plan order; copy before source mutations.
    const auto first = std::ranges::find_if(order, [&](std::size_t index) {
        return action_index(operations[index].action) >=
               action_index(Action::MoveLocal);
    });
    std::stable_partition(first, order.end(), [&](std::size_t index) {
        return operations[index].action == Action::CopyLocal;
    });
}

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
std::expected<platform::Workspace, Error> create_transaction_workspace(
    const std::filesystem::path& profile,
    std::string_view id,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key);
// Opens a persisted workspace only when its owner marker authenticates; older
// workspaces are returned without deletion authority for recovery
// compatibility.
std::expected<std::optional<platform::Workspace>, Error>
open_transaction_workspace(const std::filesystem::path& profile,
                           std::string_view id,
                           std::span<const std::uint8_t, crypto::KEY_SIZE> key);
// Removes the temporary transaction workspace, if it exists.
std::expected<void, Error> remove_transaction_workspace(
    const std::optional<platform::Workspace>& workspace,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key);
// Cleans up the journal and temporary workspace after completion.
std::expected<void, Error>
finish_transaction_cleanup(const journal::Paths& paths,
                           const std::optional<platform::Workspace>& workspace,
                           std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                           journal::Session* session = nullptr);
// Cleans up orphan workspaces without a matching transaction.
std::expected<void, Error>
cleanup_orphan_workspaces(const std::filesystem::path& profile,
                          std::span<const std::uint8_t, crypto::KEY_SIZE> key);
// Resolves transaction journal paths within the profile.
std::expected<journal::Paths, Error>
make_journal_paths(const runtime::RuntimeData& runtime_data);
// Persists the current transaction record.
std::expected<void, Error>
save_record(const journal::Paths& paths,
            const transaction::Record& record,
            std::span<const std::uint8_t, crypto::KEY_SIZE> key,
            journal::SaveMode mode = journal::SaveMode::Advance,
            journal::Session* session = nullptr);

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
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        journal::Session* session = nullptr);

// Returns true when any local mutation requires workspace/backup rollback.
bool has_local_rollback_work(const transaction::Record& record) noexcept;

// Extracts the next upload sub-batch bounded by item count and total bytes.
std::vector<std::size_t>
next_upload_batch_chunk(std::span<const std::size_t> pending_uploads,
                        std::size_t& cursor,
                        std::span<const transaction::Operation> operations);

// Rolls back the transaction and updates its persisted record.
std::expected<void, Error>
rollback_transaction(const journal::Paths& paths,
                     transaction::Record& record,
                     const std::optional<platform::Workspace>& workspace,
                     const std::filesystem::path& local_root,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                     journal::Session* session = nullptr);

// Rolls back only mutations applied to the local directory.
std::expected<void, Error>
rollback_local_mutations(transaction::Record& record,
                         const std::optional<platform::Workspace>& workspace,
                         const std::filesystem::path& local_root);

struct ScopedUploadBatchCleanup {
    const mutation::StagedUploadBatch& batch;
    bool dismissed = false;
    ~ScopedUploadBatchCleanup() noexcept {
        if (!dismissed) {
            static_cast<void>(mutation::cleanup_upload_batch(batch));
        }
    }
};

struct UploadBatchError {
    bool transport_after_unknown_transfer = false;
    mutation::MutationError mutation;
};

// Transfers an upload sub-batch and verifies every uploaded object on storage.
std::expected<void, UploadBatchError> transfer_and_verify_upload_batch(
    const mutation::StagedUploadBatch& batch,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const platform::Workspace& workspace,
    std::size_t parallelism,
    ProgressMeter* meter = nullptr);

// Authenticates an existing object against the expected plaintext identity.
std::expected<bool, Error>
verify_existing_content(transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        std::string_view identifier,
                        std::string_view plaintext_hash,
                        std::optional<std::uint64_t> size,
                        const platform::Workspace& workspace,
                        std::size_t operation_index,
                        bool is_pack = false);

std::expected<void, Error>
resume_manifest_repairs(const journal::Paths& paths,
                        transaction::Record& record,
                        const history::StorageManifest& manifest,
                        const std::filesystem::path& local_root,
                        transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        const platform::Workspace& workspace);

std::expected<std::unordered_map<std::string, std::filesystem::path>,
              mutation::MutationError>
prefetch_manifest_downloads(const history::StorageManifest& manifest,
                            std::span<const std::size_t> apply_order,
                            const transaction::Record& record,
                            const std::filesystem::path& local_root,
                            transport::Transport& storage,
                            std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                            const platform::Workspace& workspace,
                            std::size_t parallelism,
                            ProgressMeter* meter = nullptr);

// Initializes state.db (if needed) and persists the committed StoredState.
std::expected<void, Error>
save_state_checked(const std::filesystem::path& database_path,
                   const state_storage::StoredState& state);

// Publishes and verifies an Epoch checkpointed via EpochUploaded ->
// EpochVerified.
std::expected<void, Error> publish_and_verify_epoch(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const std::filesystem::path& workspace_dir,
    const journal::Paths& paths,
    transaction::Record& record,
    const history_storage::epoch::Epoch& expected_epoch,
    const history_storage::epoch::SealedEpoch& sealed_epoch,
    std::string_view epoch_kind,
    ErrorCode publish_error_code,
    ErrorCode verify_error_code,
    journal::Session* session = nullptr);

} // namespace kasumi::application::sync::coordinator::detail

#endif
