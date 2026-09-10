#include "application/history_storage/epoch.hpp"
#include "application/history_storage/history_storage.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/sync/coordinator.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/mutation.hpp"
#include "application/sync/mutation_batch.hpp"
#include "application/sync/publication.hpp"
#include "coordinator_detail.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <chrono>
#include <exception>
#include <filesystem>
#include <optional>

namespace kasumi::application::sync::coordinator {
namespace {

std::expected<std::optional<platform::Workspace>, Error>
open_workspace(const std::filesystem::path& profile, std::string_view id) {
    auto directory = detail::transactions_directory(profile, false);
    if (!directory)
        return std::unexpected(directory.error());
    auto status = detail::read_status(*directory);
    if (!status)
        return std::unexpected(status.error());
    if (detail::missing(*status))
        return std::optional<platform::Workspace>{};
    auto root = *directory / platform::path::from_utf8(id);
    status = detail::read_status(root);
    if (!status)
        return std::unexpected(status.error());
    if (detail::missing(*status))
        return std::optional<platform::Workspace>{};
    if (std::filesystem::is_symlink(*status) ||
        !std::filesystem::is_directory(*status)) {
        return std::unexpected(detail::make_error(
            ErrorCode::WorkspaceFailure,
            "invalid transaction workspace '" + platform::path::to_utf8(root) +
                "': expected a physical directory"));
    }
    return std::optional<platform::Workspace>{
        platform::Workspace{.root = root}};
}

std::expected<void, Error>
save_phase(const journal::Paths& paths,
           transaction::Record& record,
           transaction::Phase phase,
           std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    if (phase < record.phase) {
        return std::unexpected(detail::make_error(
            ErrorCode::JournalFailure, "recovery phase would regress"));
    }
    if (phase == record.phase) {
        return {};
    }
    record.phase = phase;
    return detail::save_record(paths, record, key);
}

std::expected<RecoveryResult, Error>
cleanup_completed(const journal::Paths& paths,
                  const std::optional<platform::Workspace>& workspace) {
    auto cleaned = detail::finish_transaction_cleanup(paths, workspace);
    if (!cleaned)
        return std::unexpected(cleaned.error());
    return RecoveryResult::RolledForward;
}

std::expected<RecoveryResult, Error> rollback_before_publication(
    const journal::Paths& paths,
    transaction::Record& record,
    const std::optional<platform::Workspace>& workspace,
    const runtime::RuntimeData& runtime_data,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    auto rolled = detail::rollback_transaction(
        paths, record, workspace, runtime_data.local_dir, key);
    if (!rolled)
        return std::unexpected(rolled.error());
    return RecoveryResult::RolledBack;
}

bool same_tree(const Snapshot& left, const Snapshot& right) noexcept {
    if (left.rows.size() != right.rows.size()) {
        return false;
    }
    for (std::size_t index = 0; index < left.rows.size(); ++index) {
        const auto& a = left.rows[index];
        const auto& b = right.rows[index];
        if (a.path != b.path || a.hash != b.hash || a.size != b.size ||
            a.mtime != b.mtime || a.is_directory != b.is_directory) {
            return false;
        }
    }
    return true;
}

std::expected<void, Error>
ensure_state(const runtime::RuntimeData& runtime_data,
             const history::LoadedCommit& commit,
             const std::string& ciphertext_id,
             const std::string& epoch_id,
             std::uint64_t epoch_sequence) {
    if (!state_storage::initialize(runtime_data.database_path)) {
        return std::unexpected(
            detail::make_error(ErrorCode::DatabaseFailure,
                               "não foi possível inicializar state.db"));
    }
    auto current = state_storage::load_state(runtime_data.database_path);
    if (!current) {
        return std::unexpected(
            detail::make_error(ErrorCode::DatabaseFailure, current.error()));
    }
    if (*current && !(*current)->epoch_id.empty() &&
        (epoch_id.empty() || epoch_sequence < (*current)->epoch_sequence ||
         (epoch_sequence == (*current)->epoch_sequence &&
          epoch_id != (*current)->epoch_id))) {
        return std::unexpected(detail::make_error(
            ErrorCode::RecoveryConflict,
            "o Epoch remoto regrediu em relação ao Epoch aceito localmente"));
    }
    if (*current && (*current)->commit_id == commit.id &&
        (*current)->height == commit.commit.height &&
        same_tree((*current)->tree, commit.commit.tree) &&
        (epoch_id.empty() || (*current)->epoch_id == epoch_id)) {
        return {};
    }
    if (!state_storage::save_state(
            runtime_data.database_path,
            state_storage::StoredState{.tree = commit.commit.tree,
                                       .height = commit.commit.height,
                                       .commit_id = commit.id,
                                       .ciphertext_id = ciphertext_id,
                                       .epoch_id = epoch_id,
                                       .epoch_sequence = epoch_sequence})) {
        return std::unexpected(detail::make_error(
            ErrorCode::DatabaseFailure, "não foi possível salvar state.db"));
    }
    return {};
}

std::expected<history::LoadedCommit, Error>
load_published_commit(const journal::Paths& paths,
                      transaction::Record& record,
                      const runtime::RuntimeData& runtime_data,
                      transport::Transport& storage,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    const history_storage::HeadReference reference{
        .commit_id = record.commit_id, .ciphertext_id = record.ciphertext_id};
    auto reachable = publication::find_reachable_commit(
        storage,
        key,
        runtime_data.database_path.parent_path(),
        record.commit_id);
    if (!reachable) {
        return std::unexpected(detail::indeterminate_publication(
            reachable.error(), "published commit"));
    }
    if (!*reachable) {
        return std::unexpected(detail::make_error(
            ErrorCode::RecoveryConflict, "published commit is not reachable"));
    }
    if ((*reachable)->commit.parents != record.parent_ids) {
        return std::unexpected(detail::make_error(
            ErrorCode::RecoveryConflict, "published commit parents mismatch"));
    }
    const publication::PreparedCommit prepared{.commit = (*reachable)->commit,
                                               .commit_id = record.commit_id};
    auto verified = publication::verify_commit_object(
        storage,
        key,
        prepared,
        reference,
        runtime_data.database_path.parent_path());
    if (!verified) {
        return std::unexpected(detail::indeterminate_publication(
            verified.error(), "published commit verification"));
    }
    static_cast<void>(paths);
    return **reachable;
}

std::expected<RecoveryResult, Error>
roll_forward_local_only(const journal::Paths& paths,
                        transaction::Record& record,
                        const std::optional<platform::Workspace>& workspace,
                        const runtime::RuntimeData& runtime_data,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    if (record.phase < transaction::Phase::DatabaseCommitted) {
        auto current = state_storage::load_state(runtime_data.database_path);
        if (!current) {
            return std::unexpected(detail::make_error(
                ErrorCode::DatabaseFailure, current.error()));
        }
        if (*current && (*current)->commit_id == record.observed_head_id &&
            (*current)->height == record.storage_generation) {
            // Database advanced before new phase was persisted in the journal.
        } else {
            return rollback_before_publication(
                paths, record, workspace, runtime_data, key);
        }
        if (auto saved = save_phase(
                paths, record, transaction::Phase::DatabaseCommitted, key);
            !saved) {
            return std::unexpected(saved.error());
        }
    }
    if (record.phase < transaction::Phase::CleanupCompleted) {
        if (auto saved = save_phase(
                paths, record, transaction::Phase::CleanupCompleted, key);
            !saved) {
            return std::unexpected(saved.error());
        }
    }
    return cleanup_completed(paths, workspace);
}

bool has_pending_storage_repair(const transaction::Record& record) noexcept {
    if (record.publication_required) {
        return false;
    }
    for (std::size_t index = 0; index < record.plan.operations.size();
         ++index) {
        if (record.plan.operations[index].action == Action::Upload &&
            record.progress[index].state !=
                transaction::OperationState::Applied) {
            return true;
        }
    }
    return false;
}

bool has_applied_local_mutation(const transaction::Record& record) noexcept {
    for (std::size_t index = 0; index < record.plan.operations.size();
         ++index) {
        if (is_local_mutation(record.plan.operations[index].action) &&
            record.progress[index].state >=
                transaction::OperationState::BackupCreated) {
            return true;
        }
    }
    return false;
}

bool is_publication_transaction_resumable(
    const journal::Paths& paths,
    const transaction::Record& record,
    const std::optional<platform::Workspace>& workspace,
    const runtime::RuntimeData& runtime_data,
    transport::Transport& storage) {
    if (!record.publication_required || !workspace) {
        return false;
    }
    if (record.phase > transaction::Phase::CommitPrepared) {
        return false;
    }
    if (has_applied_local_mutation(record)) {
        return false;
    }
    bool has_applied_uploads = false;
    for (std::size_t index = 0; index < record.plan.operations.size();
         ++index) {
        if (record.plan.operations[index].action == Action::Upload &&
            record.progress[index].state ==
                transaction::OperationState::Applied) {
            has_applied_uploads = true;
            break;
        }
    }
    if (!has_applied_uploads) {
        return false;
    }

    // 1. Check TTL (24 hours) via last_write_time of the transaction record
    std::error_code ec;
    const auto mtime = std::filesystem::last_write_time(paths.final_path, ec);
    if (ec) {
        return false;
    }
    const auto age = std::chrono::file_clock::now() - mtime;
    if (age > detail::transaction_resumption_ttl) {
        return false;
    }

    // 2. Check that all planned upload files exist locally with unchanged size
    for (const auto& op : record.plan.operations) {
        if (op.action != Action::Upload) {
            continue;
        }
        auto local_path = runtime_data.local_dir / op.path;
        auto status = std::filesystem::symlink_status(local_path, ec);
        if (ec || std::filesystem::is_symlink(status) ||
            !std::filesystem::is_regular_file(status)) {
            return false;
        }
        const auto current_size = std::filesystem::file_size(local_path, ec);
        if (ec || current_size != op.size) {
            return false;
        }
    }

    // 3. Check that remote heads have not advanced concurrently
    auto remote_heads = publication::list_remote_head_commit_ids(storage);
    if (!remote_heads) {
        return false;
    }
    auto expected_heads = record.parent_ids;
    std::ranges::sort(expected_heads);
    expected_heads.erase(std::ranges::unique(expected_heads).begin(),
                         expected_heads.end());

    if (*remote_heads != expected_heads) {
        return false;
    }

    return true;
}

std::expected<void, Error> resume_pending_local_mutations(
    const journal::Paths& paths,
    transaction::Record& record,
    const platform::Workspace& workspace,
    const runtime::RuntimeData& runtime_data,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    for (std::size_t index = 0; index < record.plan.operations.size();
         ++index) {
        const auto& operation = record.plan.operations[index];
        if (!is_local_mutation(operation.action) ||
            record.progress[index].state ==
                transaction::OperationState::Applied) {
            continue;
        }
        if (record.progress[index].state ==
            transaction::OperationState::Pending) {
            auto prepared = mutation::prepare_operation(operation,
                                                        index,
                                                        runtime_data.local_dir,
                                                        workspace,
                                                        record.progress[index]);
            if (!prepared) {
                return std::unexpected(detail::make_error(
                    ErrorCode::MutationFailure,
                    "falha ao preparar mutação local pendente: " +
                        prepared.error().detail,
                    index));
            }
            record.progress[index] = *prepared;
            if (auto saved = detail::save_record(paths, record, key); !saved) {
                return std::unexpected(saved.error());
            }
        }
        auto applied = mutation::apply_operation(
            operation, index, runtime_data.local_dir, storage, key, workspace);
        if (!applied) {
            return std::unexpected(detail::make_error(
                ErrorCode::MutationFailure,
                "falha ao repetir mutação local: " + applied.error().detail,
                index));
        }
        record.progress[index].state = transaction::OperationState::Applied;
        if (auto saved = detail::save_record(paths, record, key); !saved) {
            return std::unexpected(saved.error());
        }
    }
    if (record.phase < transaction::Phase::LocalChangesApplied) {
        record.phase = transaction::Phase::LocalChangesApplied;
        return detail::save_record(paths, record, key);
    }
    return {};
}

std::expected<void, Error> resume_pending_storage_repairs(
    const journal::Paths& paths,
    transaction::Record& record,
    const std::optional<platform::Workspace>& workspace,
    const runtime::RuntimeData& runtime_data,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    if (!workspace) {
        return std::unexpected(detail::make_error(
            ErrorCode::RecoveryConflict,
            "reparo pendente não possui workspace de recuperação"));
    }

    std::vector<std::size_t> pending_uploads;

    for (std::size_t index = 0; index < record.plan.operations.size();
         ++index) {
        if (record.plan.operations[index].action == Action::Upload &&
            record.progress[index].state !=
                transaction::OperationState::Applied) {
            pending_uploads.push_back(index);
        }
    }

    if (pending_uploads.empty()) {
        return {};
    }

    const auto parallelism = detail::content_concurrency();

    for (std::size_t chunk_start = 0; chunk_start < pending_uploads.size();) {
        std::vector<std::size_t> chunk;
        std::uint64_t chunk_bytes = 0;
        while (chunk_start + chunk.size() < pending_uploads.size() &&
               chunk.size() < detail::upload_batch_max_items &&
               (chunk.empty() ||
                chunk_bytes + record.plan
                                  .operations[pending_uploads[chunk_start +
                                                              chunk.size()]]
                                  .size <=
                    detail::upload_batch_max_bytes)) {
            const auto op_index = pending_uploads[chunk_start + chunk.size()];
            chunk_bytes += record.plan.operations[op_index].size;
            chunk.push_back(op_index);
        }
        chunk_start += chunk.size();

        const auto stage_trace = platform::perf_trace::begin();
        auto staged_batch = mutation::stage_upload_batch(
            chunk, record, runtime_data.local_dir, key, *workspace);
        platform::perf_trace::finish("content stage", stage_trace);

        if (!staged_batch) {
            return std::unexpected(detail::make_error(
                ErrorCode::MutationFailure,
                "falha ao preparar batch de reparos pendentes",
                staged_batch.error().operation_index));
        }

        const auto transfer_trace = platform::perf_trace::begin();
        auto transferred = mutation::transfer_upload_batch(
            *staged_batch, storage, parallelism);
        platform::perf_trace::finish("content transfer", transfer_trace);

        const bool transfer_unknown =
            !transferred &&
            transferred.error().code ==
                mutation::MutationErrorCode::RemoteResultUnknown;
        if (!transferred && !transfer_unknown) {
            return std::unexpected(detail::make_error(
                ErrorCode::MutationFailure,
                "falha ao transferir batch de reparos pendentes",
                transferred.error().operation_index));
        }

        const auto verification_trace = platform::perf_trace::begin();
        auto verified = mutation::verify_upload_batch(
            *staged_batch, storage, key, *workspace, parallelism);
        platform::perf_trace::finish("content verification wall",
                                     verification_trace);

        if (!verified) {
            return std::unexpected(detail::make_error(
                ErrorCode::MutationFailure,
                "falha ao verificar batch de reparos pendentes",
                verified.error().operation_index));
        }

        const auto checkpoint_trace = platform::perf_trace::begin();
        auto checkpointed =
            detail::checkpoint_upload_batch(paths, record, *staged_batch, key);
        platform::perf_trace::finish("batch checkpoint", checkpoint_trace);

        if (!checkpointed) {
            return std::unexpected(checkpointed.error());
        }

        auto cleaned = mutation::cleanup_upload_batch(*staged_batch);

        if (!cleaned) {
            /*
             * Checkpoint is already durable.
             * DO NOT revert Applied.
             */
            return std::unexpected(detail::make_error(
                ErrorCode::MutationFailure,
                "falha ao limpar staging do batch de reparos",
                cleaned.error().operation_index));
        }
    }
    return {};
}

std::expected<RecoveryResult, Error>
roll_forward(const journal::Paths& paths,
             transaction::Record& record,
             const std::optional<platform::Workspace>& workspace,
             const runtime::RuntimeData& runtime_data,
             transport::Transport& storage,
             std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    std::optional<history_storage::epoch::VerifiedEpoch>
        recovered_pruning_epoch;
    if (!record.parent_ids.empty() && !record.epoch_id.empty() &&
        record.phase >= transaction::Phase::EpochUploaded &&
        record.phase < transaction::Phase::DatabaseCommitted) {
        auto recovered = history_storage::epoch::load_by_id(
            storage,
            key,
            runtime_data.database_path.parent_path(),
            record.epoch_id);
        if (!recovered) {
            const auto code =
                recovered.error().code ==
                        history_storage::epoch::ErrorCode::TransportFailure
                    ? ErrorCode::RecoveryIndeterminate
                    : ErrorCode::RecoveryConflict;
            return std::unexpected(detail::make_error(
                code,
                "não foi possível carregar o Epoch de poda: " +
                    recovered.error().detail));
        }
        if (!*recovered) {
            return std::unexpected(
                detail::make_error(ErrorCode::RecoveryConflict,
                                   "o Epoch de poda enviado está ausente"));
        }
        if ((**recovered).value.vault_id != record.epoch_vault_id ||
            (**recovered).reference.sequence == 0) {
            return std::unexpected(
                detail::make_error(ErrorCode::RecoveryConflict,
                                   "o Epoch de poda diverge do journal"));
        }
        auto latest_epoch = history_storage::epoch::load_latest(
            storage,
            key,
            runtime_data.database_path.parent_path(),
            std::optional<history_storage::epoch::Reference>{
                (**recovered).reference});
        if (!latest_epoch) {
            const auto code =
                latest_epoch.error().code ==
                        history_storage::epoch::ErrorCode::TransportFailure
                    ? ErrorCode::RecoveryIndeterminate
                    : ErrorCode::RecoveryConflict;
            return std::unexpected(detail::make_error(
                code,
                "não foi possível validar a cadeia do Epoch de poda: " +
                    latest_epoch.error().detail));
        }
        if (!*latest_epoch) {
            return std::unexpected(
                detail::make_error(ErrorCode::RecoveryConflict,
                                   "a cadeia remota de Epoch está vazia"));
        }
        recovered_pruning_epoch = std::move(**recovered);
    }

    const history_storage::HeadReference reference{
        .commit_id = record.commit_id, .ciphertext_id = record.ciphertext_id};
    auto commit =
        load_published_commit(paths, record, runtime_data, storage, key);
    if (!commit) {
        return std::unexpected(commit.error());
    }

    if (record.phase < transaction::Phase::CommitVerified) {
        if (auto saved = save_phase(
                paths, record, transaction::Phase::CommitVerified, key);
            !saved) {
            return std::unexpected(saved.error());
        }
    }
    if (record.phase < transaction::Phase::HeadPublished) {
        if (auto saved = save_phase(
                paths, record, transaction::Phase::HeadPublished, key);
            !saved) {
            return std::unexpected(saved.error());
        }
    }
    if (record.phase < transaction::Phase::HeadVerified) {
        auto marker_verified = publication::verify_head_marker(
            storage, reference, runtime_data.database_path.parent_path());
        if (!marker_verified) {
            return std::unexpected(detail::indeterminate_publication(
                marker_verified.error(), "published head marker"));
        }
        if (auto saved = save_phase(
                paths, record, transaction::Phase::HeadVerified, key);
            !saved) {
            return std::unexpected(saved.error());
        }
    }
    std::optional<history_storage::epoch::Reference> recovered_epoch_reference;
    if (record.parent_ids.empty() &&
        record.phase < transaction::Phase::EpochVerified) {
        history_storage::epoch::RetentionPolicy policy{
            .min_history_depth = runtime_data.min_history_depth,
            .min_history_age_hours = runtime_data.min_history_age_hours};
        auto epoch = detail::prepare_genesis_epoch(record, policy, key);
        if (!epoch) {
            return std::unexpected(epoch.error());
        }
        if (record.phase < transaction::Phase::EpochPrepared) {
            if (auto saved = save_phase(
                    paths, record, transaction::Phase::EpochPrepared, key);
                !saved) {
                return std::unexpected(saved.error());
            }
        }
        if (record.phase < transaction::Phase::EpochUploaded) {
            auto published = history_storage::epoch::publish(
                storage, *epoch, runtime_data.database_path.parent_path());
            if (!published) {
                auto visible = history_storage::epoch::verify(
                    storage,
                    detail::genesis_epoch(record),
                    epoch->reference,
                    key,
                    runtime_data.database_path.parent_path());
                if (!visible) {
                    return std::unexpected(detail::make_error(
                        ErrorCode::RecoveryIndeterminate,
                        "não foi possível publicar o Epoch gênesis: " +
                            published.error().detail));
                }
            }
            if (auto saved = save_phase(
                    paths, record, transaction::Phase::EpochUploaded, key);
                !saved) {
                return std::unexpected(saved.error());
            }
        }
        auto verified = history_storage::epoch::verify(
            storage,
            detail::genesis_epoch(record),
            epoch->reference,
            key,
            runtime_data.database_path.parent_path());
        if (!verified) {
            return std::unexpected(
                detail::make_error(ErrorCode::RecoveryConflict,
                                   "falha na verificação do Epoch gênesis: " +
                                       verified.error().detail));
        }
        if (auto saved = save_phase(
                paths, record, transaction::Phase::EpochVerified, key);
            !saved) {
            return std::unexpected(saved.error());
        }
        recovered_epoch_reference = history_storage::epoch::Reference{
            .sequence = 0, .epoch_id = record.epoch_id};
    } else if (!record.parent_ids.empty() && !record.epoch_id.empty() &&
               record.phase >= transaction::Phase::EpochPrepared &&
               record.phase < transaction::Phase::EpochUploaded) {
        return std::unexpected(
            detail::make_error(ErrorCode::RecoveryConflict,
                               "o Epoch de poda não possui um ponto de "
                               "verificação durável de upload"));
    } else if (recovered_pruning_epoch) {
        if (record.phase < transaction::Phase::EpochVerified) {
            if (auto saved = save_phase(
                    paths, record, transaction::Phase::EpochVerified, key);
                !saved) {
                return std::unexpected(saved.error());
            }
        }
        recovered_epoch_reference = recovered_pruning_epoch->reference;
    }
    if (record.phase < transaction::Phase::DatabaseCommitted) {
        std::optional<history_storage::epoch::Reference> accepted_epoch =
            recovered_epoch_reference;
        if (!accepted_epoch && record.epoch_id.empty()) {
            auto latest_epoch = history_storage::epoch::load_latest(
                storage, key, runtime_data.database_path.parent_path());
            if (!latest_epoch) {
                return std::unexpected(detail::make_error(
                    ErrorCode::RecoveryIndeterminate,
                    "não foi possível carregar o Epoch mais recente: " +
                        latest_epoch.error().detail));
            }
            if (*latest_epoch) {
                accepted_epoch = (**latest_epoch).reference;
            }
        }
        if (!accepted_epoch && !record.epoch_id.empty()) {
            if (record.parent_ids.empty() &&
                record.phase >= transaction::Phase::EpochVerified) {
                accepted_epoch = history_storage::epoch::Reference{
                    .sequence = 0, .epoch_id = record.epoch_id};
            } else {
                return std::unexpected(
                    detail::make_error(ErrorCode::RecoveryConflict,
                                       "pruning Epoch was not authenticated"));
            }
        }
        if (auto state = ensure_state(
                runtime_data,
                *commit,
                record.ciphertext_id,
                accepted_epoch ? accepted_epoch->epoch_id : std::string{},
                accepted_epoch ? accepted_epoch->sequence : 0);
            !state) {
            return std::unexpected(state.error());
        }
        if (auto saved = save_phase(
                paths, record, transaction::Phase::DatabaseCommitted, key);
            !saved) {
            return std::unexpected(saved.error());
        }
    }
    if (record.phase < transaction::Phase::CleanupCompleted) {
        auto pruned = publication::prune_current_ancestral_markers(
            storage, key, runtime_data.database_path.parent_path());
        if (!pruned) {
            return std::unexpected(detail::indeterminate_publication(
                pruned.error(), "marker cleanup"));
        }
        if (auto saved = save_phase(
                paths, record, transaction::Phase::CleanupCompleted, key);
            !saved) {
            return std::unexpected(saved.error());
        }
    }
    return cleanup_completed(paths, workspace);
}

} // namespace

std::expected<RecoveryResult, Error>
recover_if_needed(const runtime::RuntimeData& runtime_data,
                  transport::Transport& storage,
                  std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    auto paths = detail::make_journal_paths(runtime_data);
    if (!paths)
        return std::unexpected(paths.error());
    journal::discard_temporary(*paths);
    auto record = journal::load(*paths, key);
    if (!record)
        return std::unexpected(detail::journal_error(record.error()));
    if (!*record) {
        auto profile = detail::profile_directory(runtime_data);
        if (!profile)
            return std::unexpected(profile.error());
        auto cleaned = detail::cleanup_orphan_workspaces(*profile);
        if (!cleaned)
            return std::unexpected(cleaned.error());
        return RecoveryResult::NoJournal;
    }

    auto profile = detail::profile_directory(runtime_data);
    if (!profile)
        return std::unexpected(profile.error());
    auto workspace = open_workspace(*profile, (*record)->operation_id);
    if (!workspace)
        return std::unexpected(workspace.error());
    if ((*record)->phase == transaction::Phase::CleanupCompleted) {
        return cleanup_completed(*paths, *workspace);
    }

    history_storage::maintenance_protocol::RegistrationState writer;
    const bool remote_write_required =
        has_pending_storage_repair(**record) ||
        ((*record)->publication_required &&
         (*record)->phase > transaction::Phase::CommitPrepared);
    if (remote_write_required) {
        auto registered =
            history_storage::maintenance_protocol::register_writer(
                storage, runtime_data.database_path.parent_path());
        if (!registered) {
            return std::unexpected(detail::make_error(
                registered.error().code ==
                        history_storage::maintenance_protocol::ErrorCode::
                            Blocked
                    ? ErrorCode::ConcurrentModification
                    : ErrorCode::ObservationFailure,
                registered.error().detail));
        }
        writer = std::move(*registered);
    }

    auto outcome = [&]() -> std::expected<RecoveryResult, Error> {
        try {
            if (!(*record)->publication_required) {
                if (has_pending_storage_repair(**record)) {
                    auto resumed = resume_pending_storage_repairs(*paths,
                                                                  **record,
                                                                  *workspace,
                                                                  runtime_data,
                                                                  storage,
                                                                  key);
                    if (!resumed) {
                        if (has_applied_local_mutation(**record)) {
                            auto rolled = detail::rollback_local_mutations(
                                **record, *workspace, runtime_data.local_dir);
                            if (!rolled) {
                                return std::unexpected(detail::make_error(
                                    ErrorCode::RecoveryConflict,
                                    resumed.error().detail +
                                        "; rollback failed: " +
                                        rolled.error().detail));
                            }
                            if (auto saved =
                                    detail::save_record(*paths, **record, key);
                                !saved) {
                                return std::unexpected(saved.error());
                            }
                        }
                        return std::unexpected(resumed.error());
                    }
                    auto local = resume_pending_local_mutations(*paths,
                                                                **record,
                                                                **workspace,
                                                                runtime_data,
                                                                storage,
                                                                key);
                    if (!local) {
                        return std::unexpected(local.error());
                    }
                }
                return roll_forward_local_only(
                    *paths, **record, *workspace, runtime_data, key);
            }

            if ((*record)->phase <= transaction::Phase::CommitPrepared) {
                if (is_publication_transaction_resumable(
                        *paths, **record, *workspace, runtime_data, storage)) {
                    std::error_code ec;
                    std::filesystem::remove_all(
                        (*workspace)->root / "upload-batches", ec);
                    return RecoveryResult::ResumableTransaction;
                }
                return rollback_before_publication(
                    *paths, **record, *workspace, runtime_data, key);
            }

            const history_storage::HeadReference reference{
                .commit_id = (*record)->commit_id,
                .ciphertext_id = (*record)->ciphertext_id};
            auto marker = publication::inspect_head_marker(
                storage, reference, runtime_data.database_path.parent_path());
            if (!marker) {
                return std::unexpected(detail::indeterminate_publication(
                    marker.error(), "head marker visibility"));
            }
            if (*marker != publication::HeadMarkerState::Valid) {
                if ((*record)->phase < transaction::Phase::HeadPublished) {
                    return rollback_before_publication(
                        *paths, **record, *workspace, runtime_data, key);
                }
                return std::unexpected(detail::make_error(
                    ErrorCode::RecoveryConflict,
                    "journal says head was published but marker is not valid"));
            }
            return roll_forward(
                *paths, **record, *workspace, runtime_data, storage, key);
        } catch (const std::exception& exception) {
            return std::unexpected(detail::make_error(
                ErrorCode::ObservationFailure, exception.what()));
        }
    }();
    auto released =
        history_storage::maintenance_protocol::release_registration(writer);
    if (!outcome) {
        return outcome;
    }
    if (!released) {
        return std::unexpected(detail::make_error(ErrorCode::ObservationFailure,
                                                  released.error().detail));
    }
    return outcome;
}

} // namespace kasumi::application::sync::coordinator
