#ifndef KASUMI_APPLICATION_SYNC_COORDINATOR_DETAIL_HPP
#define KASUMI_APPLICATION_SYNC_COORDINATOR_DETAIL_HPP

#include "application/history_storage/epoch.hpp"
#include "application/sync/coordinator.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/mutation.hpp"
#include "application/sync/mutation_batch.hpp"
#include "application/sync/publication.hpp"
#include "core/hasher.hpp"
#include "core/history.hpp"
#include "core/reconciliation/types.hpp"
#include "core/transaction/types.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/pack.hpp"
#include "platform/private_storage.hpp"
#include "platform/workspace.hpp"
#include "runtime/resolver.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <expected>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
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
// Maps a mutation failure into a coordinator error.
Error mutation_error(const mutation::MutationError& error);
// Maps a publication failure into a coordinator error.
Error publication_error(const publication::Error& error);
// Indicates that the file status represents a missing path.
bool missing(std::filesystem::file_status status) noexcept;
// Creates a filesystem/workspace error scoped to a local path.
Error workspace_error(std::string_view operation,
                      const std::filesystem::path& path,
                      std::string detail);
// Verifies that an observed status denotes a physical directory.
std::expected<void, Error>
require_physical_directory(std::filesystem::file_status status,
                           const std::filesystem::path& path,
                           std::string_view error_title);
// Returns rollback failure first when rollback fails; otherwise original.
std::unexpected<Error> fail_after_rollback(std::expected<void, Error> rolled,
                                           Error original);

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
    ProgressMeter* meter = nullptr,
    const std::filesystem::path* item = nullptr,
    std::string_view progress_identifier = {});

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

struct ChunkHashKey {
    std::size_t operator()(const Hash& value) const noexcept {
        std::size_t seed = 0;
        static_assert(sizeof(seed) <= sizeof(Hash));
        std::memcpy(&seed, value.data(), sizeof(seed));
        return seed;
    }
};

struct ChunkSource {
    std::filesystem::path source_path;
    platform::private_storage::FileIdentity identity{};
    std::uint64_t offset = 0;
    std::uint32_t size = 0;
};

struct ChunkDownloadSession {
    bool directories_ready = false;
    std::filesystem::path chunk_dl_dir;
    std::unordered_map<Hash, ChunkSource, ChunkHashKey> local_seeds;
    std::unordered_map<Hash, ChunkSource, ChunkHashKey> downloaded_slices;
    std::unordered_set<std::string> seeded_paths;
};

// Downloads FastCDC chunks in bounded windows, assembles directly into the
// destination staging candidate, and registers verified slices for reuse.
mutation::MutationResult apply_chunked_download(
    const history::ChunkedFileEntry& entry,
    const kasumi::Operation& operation,
    std::size_t operation_index,
    const std::filesystem::path& local_root,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const platform::Workspace& workspace,
    std::size_t parallelism,
    const transaction::OperationProgress& progress,
    const mutation::DestinationPrecondition* destination,
    ChunkDownloadSession& session,
    ProgressMeter* meter = nullptr);

using CheckpointCallback = std::function<std::expected<void, Error>()>;
using AppliedOpsCallback = std::function<void(std::span<const std::size_t>)>;

// Fetches Micro-Packs in bounded windows (<= 64 packs, <= 256 MiB), decodes
// and authenticates in memory, deletes .enc immediately, and installs members
// directly into destination candidates with per-window checkpointing.
std::expected<std::optional<mutation::MutationError>, Error>
apply_packed_downloads(
    const history::StorageManifest& manifest,
    std::span<const std::size_t> op_indices,
    transaction::Record& record,
    const std::filesystem::path& local_root,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const platform::Workspace& workspace,
    std::span<const std::optional<mutation::DestinationPrecondition>>
        destinations,
    std::size_t parallelism,
    const CheckpointCallback& checkpoint = {},
    const AppliedOpsCallback& on_applied = {},
    ProgressMeter* meter = nullptr);

// Initializes state.db (if needed) and persists the committed StoredState,
// optionally updating accepted_commit_meta in the same SQLite transaction.
std::expected<void, Error> save_state_checked(
    const std::filesystem::path& database_path,
    const state_storage::StoredState& state,
    const std::optional<state_storage::AcceptedCommitMeta>& accepted_meta =
        std::nullopt);

// Extracts the next bounded upload/download chunk window (<= 64 items,
// <= upload_batch_max_bytes).
template <typename Chunk>
std::span<const Chunk> next_chunk_window(std::span<const Chunk> pending) {
    constexpr std::size_t max_items = 64;
    std::size_t count = 0;
    std::uint64_t bytes = 0;
    for (const auto& chunk :
         pending.first(std::min(max_items, pending.size()))) {
        if (count != 0 && bytes + chunk.size > upload_batch_max_bytes) {
            break;
        }
        ++count;
        bytes += chunk.size;
    }
    return pending.first(count);
}

struct PlannedSmallUpload {
    Hash hash{};
    std::uint32_t size = 0;
    std::size_t op_index = 0;
};

struct PlannedPack {
    Hash pack_hash{};
    std::string pack_identifier;
    std::vector<PlannedSmallUpload> blobs;
    std::vector<std::size_t> operation_indices;
};

inline constexpr std::size_t pack_upload_window_size = std::min(
    upload_batch_max_items,
    static_cast<std::size_t>(upload_batch_max_bytes /
                             crypto::pack::MAXIMUM_PACK_PLAINTEXT_SIZE));

struct PlannedChunkUpload {
    Hash file_hash{};
    std::uint64_t file_size = 0;
    std::size_t primary_op_index = 0;
    std::vector<crypto::pack::FastCdcChunk> chunks;
    std::vector<std::size_t> operation_indices;
};

struct UploadLayoutPlan {
    history::StorageManifest target_manifest;
    std::vector<PlannedPack> packs;
    std::vector<PlannedChunkUpload> chunked_uploads;
    std::unordered_map<Hash, std::size_t, decltype(&hash_key)> pack_by_hash{
        0, hash_key};
    std::unordered_map<Hash, std::size_t, decltype(&hash_key)> chunked_by_hash{
        0, hash_key};
};

// Plans Micro-Pack and FastCDC chunk upload layout for a sync transaction.
std::expected<UploadLayoutPlan, Error>
build_upload_layout_plan(const runtime::RuntimeData& runtime_data,
                         const transport::Transport& storage,
                         std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                         const reconciliation::Input& observed_input,
                         const reconciliation::Result& reconciliation_result,
                         const transaction::Record& record,
                         const std::vector<bool>& content_upload_required,
                         bool enable_micro_packs);

// Builds, uploads, and authenticates a window of Micro-Packs.
std::expected<void, UploadBatchError>
execute_packed_upload_batch(std::span<const PlannedPack* const> packs,
                            const transaction::Record& record,
                            const std::filesystem::path& local_root,
                            transport::Transport& storage,
                            std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                            const platform::Workspace& workspace,
                            std::size_t parallelism,
                            ProgressMeter* meter);

// Probes existing chunks, stages missing FastCDC slices, and verifies uploads.
std::expected<void, UploadBatchError> execute_chunked_upload_batch(
    std::span<const PlannedChunkUpload* const> uploads,
    const transaction::Record& record,
    const history::StorageManifest& live_manifest,
    const HashSet& missing_files,
    const HashSet& invalid_chunks,
    const std::filesystem::path& local_root,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const platform::Workspace& workspace,
    std::size_t parallelism,
    ProgressMeter* meter);

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
