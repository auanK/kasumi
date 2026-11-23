#include "application/concurrency.hpp"
#include "application/history_storage/epoch.hpp"
#include "application/history_storage/history_storage.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/sync/coordinator.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/mutation.hpp"
#include "application/sync/mutation_batch.hpp"
#include "application/sync/mutation_detail.hpp"
#include "application/sync/publication.hpp"
#include "coordinator_detail.hpp"
#include "platform/path.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <chrono>
#include <exception>
#include <filesystem>
#include <optional>

namespace kasumi::application::sync::coordinator {
namespace {

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
                  const std::optional<platform::Workspace>& workspace,
                  std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                  journal::Session* session = nullptr) {
    auto cleaned =
        detail::finish_transaction_cleanup(paths, workspace, key, session);
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

bool same_pending_paths(std::span<const NodeRow> rows,
                        std::span<const std::string> paths) noexcept {
    if (rows.size() != paths.size()) {
        return false;
    }
    for (std::size_t index = 0; index < rows.size(); ++index) {
        if (rows[index].path != paths[index]) {
            return false;
        }
    }
    return true;
}

std::expected<std::vector<NodeRow>, Error>
resolve_pending_paths(const Snapshot& tree,
                      std::span<const std::string> paths) {
    std::vector<NodeRow> rows;
    rows.reserve(paths.size());
    for (const auto& path : paths) {
        const auto* row = find_row(tree, path);
        if (row == nullptr || row->is_directory) {
            return std::unexpected(detail::make_error(
                ErrorCode::RecoveryConflict,
                "journal pending path is absent from authenticated commit"));
        }
        rows.push_back(*row);
    }
    return rows;
}

bool matches_observed_base_state(
    const std::optional<state_storage::StoredState>& current,
    const transaction::Record& record) noexcept {
    return current ? !record.observed_base_id.empty() &&
                         current->commit_id == record.observed_base_id &&
                         current->height == record.local_generation &&
                         same_pending_paths(current->pending_materializations,
                                            record.observed_pending_paths)
                   : record.observed_base_id.empty() &&
                         record.observed_pending_paths.empty();
}

std::expected<void, Error>
ensure_state(const runtime::RuntimeData& runtime_data,
             const transaction::Record& record,
             const history::LoadedCommit& commit,
             const std::string& ciphertext_id,
             const std::string& epoch_id,
             std::uint64_t epoch_sequence) {
    if (!state_storage::initialize(runtime_data.database_path)) {
        return std::unexpected(detail::make_error(
            ErrorCode::DatabaseFailure, "failed to initialize state.db"));
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
            "remote Epoch regressed relative to locally accepted Epoch"));
    }
    auto target_pending =
        resolve_pending_paths(commit.commit.tree, record.pending_paths);
    if (!target_pending) {
        return std::unexpected(target_pending.error());
    }
    if (*current && (*current)->commit_id == commit.id &&
        (*current)->height == commit.commit.height &&
        (*current)->tree == commit.commit.tree &&
        same_pending_paths((*current)->pending_materializations,
                           record.pending_paths) &&
        (epoch_id.empty() || (*current)->epoch_id == epoch_id)) {
        return {};
    }
    if (!matches_observed_base_state(*current, record)) {
        return std::unexpected(detail::make_error(
            ErrorCode::RecoveryConflict,
            "state.db does not match the pending publication transition"));
    }
    return detail::save_state_checked(
        runtime_data.database_path,
        state_storage::StoredState{.tree = commit.commit.tree,
                                   .height = commit.commit.height,
                                   .commit_id = commit.id,
                                   .ciphertext_id = ciphertext_id,
                                   .epoch_id = epoch_id,
                                   .epoch_sequence = epoch_sequence,
                                   .pending_materializations =
                                       std::move(*target_pending),
                                   .storage_manifest = commit.commit.storage},
        publication::make_accepted_commit_meta(commit.id, commit.commit));
}

std::expected<history::LoadedCommit, Error>
load_published_commit(const transaction::Record& record,
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
    const auto layout = history_storage::derive_remote_layout(key);
    auto verified = publication::verify_commit_object(
        storage,
        layout,
        key,
        prepared,
        reference,
        runtime_data.database_path.parent_path());
    if (!verified) {
        return std::unexpected(detail::indeterminate_publication(
            verified.error(), "published commit verification"));
    }
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
        const bool target_committed =
            *current && (*current)->commit_id == record.observed_head_id &&
            (*current)->height == record.storage_generation &&
            same_pending_paths((*current)->pending_materializations,
                               record.pending_paths);
        if (target_committed) {
            // Database advanced before the journal phase was saved.
        } else if (matches_observed_base_state(*current, record)) {
            return rollback_before_publication(
                paths, record, workspace, runtime_data, key);
        } else {
            return std::unexpected(detail::make_error(
                ErrorCode::RecoveryConflict,
                "state.db matches neither old nor target pending state"));
        }
        if (auto saved = save_phase(
                paths, record, transaction::Phase::DatabaseCommitted, key);
            !saved) {
            return std::unexpected(saved.error());
        }
    }
    auto current = state_storage::load_state(runtime_data.database_path);
    if (!current || !*current ||
        (*current)->commit_id != record.observed_head_id ||
        (*current)->height != record.storage_generation ||
        !same_pending_paths((*current)->pending_materializations,
                            record.pending_paths)) {
        return std::unexpected(detail::make_error(
            ErrorCode::RecoveryConflict,
            "committed state does not match journal pending intent"));
    }
    if (record.phase < transaction::Phase::CleanupCompleted) {
        if (auto saved = save_phase(
                paths, record, transaction::Phase::CleanupCompleted, key);
            !saved) {
            return std::unexpected(saved.error());
        }
    }
    return cleanup_completed(paths, workspace, key);
}

std::expected<history::StorageManifest, Error>
load_repair_manifest(const transaction::Record& record,
                     const runtime::RuntimeData& runtime_data,
                     transport::Transport& storage,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    auto accepted = state_storage::load_state(runtime_data.database_path);
    if (!accepted) {
        return std::unexpected(
            detail::make_error(ErrorCode::DatabaseFailure, accepted.error()));
    }
    if (*accepted && (*accepted)->commit_id == record.observed_head_id &&
        (*accepted)->height == record.storage_generation) {
        return std::move((*accepted)->storage_manifest);
    }
    auto pinned = publication::find_reachable_commit(
        storage,
        key,
        runtime_data.database_path.parent_path(),
        record.observed_head_id);
    if (!pinned) {
        return std::unexpected(detail::indeterminate_publication(
            pinned.error(), "pinned repair commit"));
    }
    if (!*pinned || (*pinned)->commit.height != record.storage_generation) {
        return std::unexpected(
            detail::make_error(ErrorCode::RecoveryConflict,
                               "pinned repair commit is unavailable"));
    }
    return std::move((*pinned)->commit.storage);
}

bool is_publication_transaction_resumable(
    const journal::Paths& paths,
    const transaction::Record& record,
    const std::optional<platform::Workspace>& workspace,
    const runtime::RuntimeData& runtime_data,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    if (!record.publication_required || !workspace) {
        return false;
    }
    if (record.phase >= transaction::Phase::CommitPrepared) {
        return false;
    }
    if (detail::has_local_rollback_work(record)) {
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
    const auto mtime = std::filesystem::last_write_time(
        paths.final_path.parent_path() / "confirmed.enc", ec);
    if (ec)
        return false;
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
    const auto layout = history_storage::derive_remote_layout(key);
    auto remote_heads =
        publication::list_remote_head_commit_ids(storage, layout);
    if (!remote_heads) {
        return false;
    }
    if (!record.observed_head_id.empty()) {
        if (remote_heads->size() != 1 ||
            remote_heads->front() != record.observed_head_id) {
            return false;
        }
    } else if (record.storage_generation > 0) {
        if (remote_heads->empty()) {
            return false;
        }
    } else if (!remote_heads->empty()) {
        return false;
    }

    return true;
}

std::expected<void, Error> resume_pending_local_mutations(
    const journal::Paths& paths,
    transaction::Record& record,
    const std::optional<platform::Workspace>& workspace,
    const history::StorageManifest& manifest,
    const runtime::RuntimeData& runtime_data,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    const auto dependencies =
        mutation::detail::destination_dependencies(record.plan.operations);
    const auto type_changes =
        detail::local_type_changes(record.plan.operations);
    std::vector<std::size_t> replay_order;
    replay_order.reserve(record.plan.operations.size());
    for (std::size_t index = 0; index < record.plan.operations.size();
         ++index) {
        const auto& operation = record.plan.operations[index];
        if (!is_local_mutation(operation.action) ||
            record.progress[index].state ==
                transaction::OperationState::Applied) {
            continue;
        }
        if (!workspace) {
            return std::unexpected(detail::make_error(
                ErrorCode::RecoveryConflict,
                "pending local mutation is missing recovery workspace",
                index));
        }
        if (record.progress[index].state ==
                transaction::OperationState::Pending &&
            type_changes[index] != detail::TypeChangeStep::Install) {
            if (operation.action == Action::Download ||
                operation.action == Action::DeleteLocal ||
                operation.action == Action::MoveLocal ||
                operation.action == Action::CopyLocal) {
                return std::unexpected(detail::make_error(
                    ErrorCode::RecoveryConflict,
                    "unprepared destination cannot be authorized during replay",
                    index));
            }
            auto prepared = mutation::prepare_operation(operation,
                                                        index,
                                                        runtime_data.local_dir,
                                                        *workspace,
                                                        record.progress[index],
                                                        record.plan.operations);
            if (!prepared) {
                return std::unexpected(detail::make_error(
                    ErrorCode::MutationFailure,
                    "failed to prepare pending local mutation: " +
                        prepared.error().detail,
                    index));
            }
            record.progress[index] = *prepared;
            if (auto saved = detail::save_record(paths, record, key); !saved) {
                return std::unexpected(saved.error());
            }
        }
        replay_order.push_back(index);
    }
    detail::order_local_copies(record.plan.operations, replay_order);
    detail::order_local_type_changes(type_changes, replay_order);
    detail::ChunkDownloadSession chunk_session;
    const auto parallelism = application::content_concurrency();
    std::vector<std::optional<mutation::DestinationPrecondition>> destinations(
        record.plan.operations.size());
    const auto replay_failure = [](std::size_t op_index,
                                   const mutation::MutationError& err) {
        return detail::make_error(
            err.code == mutation::MutationErrorCode::DestinationConflict
                ? ErrorCode::RecoveryConflict
                : ErrorCode::MutationFailure,
            "failed to replay local mutation: " + err.detail,
            op_index);
    };
    const auto prepare_replay_op =
        [&](std::size_t index) -> std::expected<void, Error> {
        const auto& operation = record.plan.operations[index];
        if (type_changes[index] == detail::TypeChangeStep::Install &&
            record.progress[index].state ==
                transaction::OperationState::Pending) {
            auto prepared = detail::prepare_type_change_install(
                record, index, runtime_data.local_dir, *workspace);
            if (!prepared) {
                return prepared;
            }
            if (auto checkpoint = detail::save_record(paths, record, key);
                !checkpoint) {
                return checkpoint;
            }
        }
        auto condition = mutation::detail::effective_destination(
            record, index, dependencies);
        if (!condition) {
            return std::unexpected(
                detail::make_error(ErrorCode::RecoveryConflict,
                                   mutation::describe(condition.error()),
                                   index));
        }
        destinations[index] = std::move(*condition);
        if (operation.action == Action::Download) {
            auto destination = mutation::detail::resolve_local_path(
                runtime_data.local_dir, operation.path, index);
            if (!destination) {
                return std::unexpected(
                    detail::make_error(ErrorCode::RecoveryConflict,
                                       destination.error().detail,
                                       index));
            }
            if (auto cleaned =
                    mutation::detail::remove_download_candidate_if_present(
                        *destination, *workspace, index);
                !cleaned) {
                return std::unexpected(detail::make_error(
                    cleaned.error().code ==
                            mutation::MutationErrorCode::DestinationConflict
                        ? ErrorCode::RecoveryConflict
                        : ErrorCode::MutationFailure,
                    cleaned.error().detail,
                    index));
            }
        }
        return {};
    };
    const auto mark_replayed =
        [&](std::size_t index) -> std::expected<void, Error> {
        record.progress[index].state = transaction::OperationState::Applied;
        return detail::save_record(paths, record, key);
    };

    for (std::size_t position = 0; position < replay_order.size();) {
        const auto index = replay_order[position];
        const auto& operation = record.plan.operations[index];
        if (operation.action == Action::Download) {
            std::size_t end = position + 1;
            while (end < replay_order.size() &&
                   record.plan.operations[replay_order[end]].action ==
                       Action::Download) {
                ++end;
            }
            for (std::size_t i = position; i < end; ++i) {
                if (auto prepared = prepare_replay_op(replay_order[i]);
                    !prepared) {
                    return prepared;
                }
            }
            std::vector<std::size_t> packed_indices;
            std::vector<std::size_t> chunked_indices;
            std::vector<std::size_t> loose_indices;
            for (std::size_t i = position; i < end; ++i) {
                const auto op_idx = replay_order[i];
                if (manifest.empty()) {
                    loose_indices.push_back(op_idx);
                    continue;
                }
                const auto h =
                    hash_from_hex(record.plan.operations[op_idx].hash);
                if (h && history::find_packed_blob(manifest, *h) != nullptr) {
                    packed_indices.push_back(op_idx);
                } else if (h && history::find_chunked_file(manifest, *h) !=
                                    nullptr) {
                    chunked_indices.push_back(op_idx);
                } else {
                    loose_indices.push_back(op_idx);
                }
            }
            if (!packed_indices.empty()) {
                auto packed_result = detail::apply_packed_downloads(
                    manifest,
                    packed_indices,
                    record,
                    runtime_data.local_dir,
                    storage,
                    key,
                    *workspace,
                    destinations,
                    parallelism,
                    [&]() -> std::expected<void, Error> {
                        return detail::save_record(paths, record, key);
                    });
                if (!packed_result) {
                    return std::unexpected(packed_result.error());
                }
                if (*packed_result) {
                    return std::unexpected(replay_failure(
                        (*packed_result)->operation_index, **packed_result));
                }
            }
            for (const auto op_idx : chunked_indices) {
                const auto& op = record.plan.operations[op_idx];
                const auto h = hash_from_hex(op.hash);
                const auto* chunked =
                    h ? history::find_chunked_file(manifest, *h) : nullptr;
                if (!chunked) {
                    continue;
                }
                auto applied = detail::apply_chunked_download(
                    *chunked,
                    op,
                    op_idx,
                    runtime_data.local_dir,
                    storage,
                    key,
                    *workspace,
                    parallelism,
                    record.progress[op_idx],
                    destinations[op_idx] ? &*destinations[op_idx] : nullptr,
                    chunk_session);
                if (!applied) {
                    return std::unexpected(
                        replay_failure(op_idx, applied.error()));
                }
                if (auto saved = mark_replayed(op_idx); !saved) {
                    return std::unexpected(saved.error());
                }
            }
            for (const auto op_idx : loose_indices) {
                auto applied = mutation::apply_operation(
                    record.plan.operations[op_idx],
                    op_idx,
                    runtime_data.local_dir,
                    storage,
                    key,
                    *workspace,
                    record.progress[op_idx],
                    mutation::DownloadCacheMode::None,
                    destinations[op_idx] ? &*destinations[op_idx] : nullptr);
                if (!applied) {
                    return std::unexpected(
                        replay_failure(op_idx, applied.error()));
                }
                if (auto saved = mark_replayed(op_idx); !saved) {
                    return std::unexpected(saved.error());
                }
            }
            position = end;
            continue;
        }
        if (auto prepared = prepare_replay_op(index); !prepared) {
            return prepared;
        }
        auto applied = mutation::apply_operation(
            operation,
            index,
            runtime_data.local_dir,
            storage,
            key,
            *workspace,
            record.progress[index],
            mutation::DownloadCacheMode::None,
            destinations[index] ? &*destinations[index] : nullptr);
        if (!applied) {
            return std::unexpected(replay_failure(index, applied.error()));
        }
        if (auto saved = mark_replayed(index); !saved) {
            return std::unexpected(saved.error());
        }
        ++position;
    }
    if (record.phase < transaction::Phase::LocalChangesApplied) {
        record.phase = transaction::Phase::LocalChangesApplied;
        return detail::save_record(paths, record, key);
    }
    return {};
}

std::expected<history::StorageManifest, Error> resume_pending_storage_repairs(
    const journal::Paths& paths,
    transaction::Record& record,
    const std::optional<platform::Workspace>& workspace,
    const runtime::RuntimeData& runtime_data,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    if (!workspace) {
        return std::unexpected(
            detail::make_error(ErrorCode::RecoveryConflict,
                               "pending repair is missing recovery workspace"));
    }
    auto manifest = load_repair_manifest(record, runtime_data, storage, key);
    if (!manifest) {
        return std::unexpected(manifest.error());
    }
    if (auto repaired = detail::resume_manifest_repairs(paths,
                                                        record,
                                                        *manifest,
                                                        runtime_data.local_dir,
                                                        storage,
                                                        key,
                                                        *workspace);
        !repaired) {
        return std::unexpected(repaired.error());
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
        return std::move(*manifest);
    }

    const auto parallelism = application::content_concurrency();

    for (std::size_t chunk_start = 0; chunk_start < pending_uploads.size();) {
        const auto chunk = detail::next_upload_batch_chunk(
            pending_uploads, chunk_start, record.plan.operations);

        auto staged_batch = mutation::stage_upload_batch(
            chunk, record, runtime_data.local_dir, key, *workspace);

        if (!staged_batch) {
            return std::unexpected(
                detail::make_error(ErrorCode::MutationFailure,
                                   "failed to prepare pending repairs batch",
                                   staged_batch.error().operation_index));
        }

        detail::ScopedUploadBatchCleanup batch_cleanup{*staged_batch};

        mutation::StagedUploadBatch missing_batch{.root = staged_batch->root};
        auto listing = transport::list(storage);
        if (!listing) {
            return std::unexpected(detail::make_error(
                ErrorCode::ObservationFailure,
                "failed to list remote objects before pending repair: " +
                    transport::describe(listing.error())));
        }

        for (const auto& object : staged_batch->objects) {
            const bool listed =
                std::ranges::find(*listing, object.identifier) !=
                listing->end();
            auto presence = transport::presence(storage, object.identifier);
            if (!presence) {
                return std::unexpected(detail::make_error(
                    ErrorCode::ObservationFailure,
                    "failed to verify pending repair availability: " +
                        transport::describe(presence.error())));
            }
            if (listed != (*presence == transport::Presence::Present)) {
                return std::unexpected(detail::make_error(
                    ErrorCode::ConcurrentModification,
                    "remote LIST and PRESENCE disagree for pending repair"));
            }
            if (*presence == transport::Presence::Absent) {
                missing_batch.objects.push_back(object);
                continue;
            }

            const auto index = object.operation_indices.front();
            const auto verified =
                detail::verify_existing_content(storage,
                                                key,
                                                object.identifier,
                                                object.plaintext_hash,
                                                object.plaintext_size,
                                                *workspace,
                                                index);
            if (!verified) {
                return std::unexpected(verified.error());
            }
            if (!*verified) {
                missing_batch.objects.push_back(object);
                continue;
            }
            std::error_code ec;
            std::filesystem::remove(
                staged_batch->root /
                    platform::path::from_utf8(object.identifier),
                ec);
            if (ec) {
                return std::unexpected(detail::make_error(
                    ErrorCode::MutationFailure,
                    "failed to clear staging for verified repair: " +
                        ec.message(),
                    index));
            }
        }

        if (!missing_batch.objects.empty()) {
            if (auto batch_ok = detail::transfer_and_verify_upload_batch(
                    missing_batch, storage, key, *workspace, parallelism);
                !batch_ok) {
                return std::unexpected(detail::make_error(
                    ErrorCode::MutationFailure,
                    "failed to repair pending repairs batch",
                    batch_ok.error().mutation.operation_index));
            }
        }

        auto checkpointed =
            detail::checkpoint_upload_batch(paths, record, *staged_batch, key);

        if (!checkpointed) {
            return std::unexpected(checkpointed.error());
        }
        batch_cleanup.dismissed = true;

        auto cleaned = mutation::cleanup_upload_batch(*staged_batch);

        if (!cleaned) {
            /*
             * Checkpoint is already durable.
             * DO NOT revert Applied.
             */
            return std::unexpected(
                detail::make_error(ErrorCode::MutationFailure,
                                   "failed to clean repairs batch staging",
                                   cleaned.error().operation_index));
        }
    }
    return std::move(*manifest);
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
                "failed to load pruning Epoch: " + recovered.error().detail));
        }
        if (!*recovered) {
            return std::unexpected(
                detail::make_error(ErrorCode::RecoveryConflict,
                                   "uploaded pruning Epoch is missing"));
        }
        if ((**recovered).value.vault_id != record.epoch_vault_id ||
            (**recovered).reference.sequence == 0) {
            return std::unexpected(
                detail::make_error(ErrorCode::RecoveryConflict,
                                   "pruning Epoch diverges from journal"));
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
            return std::unexpected(
                detail::make_error(code,
                                   "failed to validate pruning Epoch chain: " +
                                       latest_epoch.error().detail));
        }
        if (!*latest_epoch) {
            return std::unexpected(detail::make_error(
                ErrorCode::RecoveryConflict, "remote Epoch chain is empty"));
        }
        recovered_pruning_epoch = std::move(**recovered);
    }

    const history_storage::HeadReference reference{
        .commit_id = record.commit_id, .ciphertext_id = record.ciphertext_id};
    auto commit = load_published_commit(record, runtime_data, storage, key);
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
        const auto layout = history_storage::derive_remote_layout(key);
        auto marker_verified = publication::verify_head_marker(
            storage,
            layout,
            reference,
            runtime_data.database_path.parent_path());
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
        if (auto ok = detail::publish_and_verify_epoch(
                storage,
                key,
                runtime_data.database_path.parent_path(),
                paths,
                record,
                detail::genesis_epoch(record),
                *epoch,
                "genesis",
                ErrorCode::RecoveryIndeterminate,
                ErrorCode::RecoveryConflict);
            !ok) {
            return std::unexpected(ok.error());
        }
        recovered_epoch_reference = history_storage::epoch::Reference{
            .sequence = 0, .epoch_id = record.epoch_id};
    } else if (!record.parent_ids.empty() && !record.epoch_id.empty() &&
               record.phase >= transaction::Phase::EpochPrepared &&
               record.phase < transaction::Phase::EpochUploaded) {
        return std::unexpected(
            detail::make_error(ErrorCode::RecoveryConflict,
                               "pruning Epoch is missing a durable upload "
                               "checkpoint"));
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
                return std::unexpected(
                    detail::make_error(ErrorCode::RecoveryIndeterminate,
                                       "failed to load latest Epoch: " +
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
                record,
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
    auto current = state_storage::load_state(runtime_data.database_path);
    if (!current || !*current || (*current)->commit_id != commit->id ||
        (*current)->height != commit->commit.height ||
        (*current)->tree != commit->commit.tree ||
        !same_pending_paths((*current)->pending_materializations,
                            record.pending_paths)) {
        return std::unexpected(detail::make_error(
            ErrorCode::RecoveryConflict,
            "committed state does not match journal pending intent"));
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
    return cleanup_completed(paths, workspace, key);
}

Error protocol_error(
    const history_storage::maintenance_protocol::Error& error) {
    return detail::make_error(
        error.code == history_storage::maintenance_protocol::ErrorCode::Blocked
            ? ErrorCode::ConcurrentModification
            : ErrorCode::ObservationFailure,
        error.detail);
}

} // namespace

std::expected<RecoveryResult, Error>
recover_if_needed(const runtime::RuntimeData& runtime_data,
                  transport::Transport& storage,
                  std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    auto paths = detail::make_journal_paths(runtime_data);
    if (!paths)
        return std::unexpected(paths.error());
    journal::Session session;
    auto record = journal::load(*paths, key, &session);
    if (!record)
        return std::unexpected(detail::journal_error(record.error()));
    if (!*record) {
        auto profile = detail::profile_directory(runtime_data);
        if (!profile)
            return std::unexpected(profile.error());
        auto cleaned = detail::cleanup_orphan_workspaces(*profile, key);
        if (!cleaned)
            return std::unexpected(cleaned.error());
        return RecoveryResult::NoJournal;
    }

    auto profile = detail::profile_directory(runtime_data);
    if (!profile)
        return std::unexpected(profile.error());
    auto workspace = detail::open_transaction_workspace(
        *profile, (*record)->operation_id, key);
    if (!workspace)
        return std::unexpected(workspace.error());
    if ((*record)->phase == transaction::Phase::CleanupCompleted) {
        return cleanup_completed(*paths, *workspace, key, &session);
    }

    history_storage::maintenance_protocol::RegistrationState writer;
    const auto layout = history_storage::derive_remote_layout(key);
    const bool has_repairs =
        !(*record)->publication_required &&
        (*record)->phase < transaction::Phase::DatabaseCommitted &&
        std::ranges::any_of((*record)->plan.operations,
                            [](const auto& operation) {
                                return operation.action == Action::Upload;
                            });
    const bool remote_write_required =
        has_repairs || ((*record)->publication_required &&
                        (*record)->phase > transaction::Phase::CommitPrepared);
    if (remote_write_required) {
        auto registered =
            history_storage::maintenance_protocol::register_writer(
                storage, layout, runtime_data.database_path.parent_path());
        if (!registered) {
            return std::unexpected(protocol_error(registered.error()));
        }
        writer = std::move(*registered);
    }

    auto outcome = [&]() -> std::expected<RecoveryResult, Error> {
        try {
            if (remote_write_required) {
                auto admission = history_storage::maintenance_protocol::
                    verify_writer_admission(writer, layout);
                if (!admission) {
                    return std::unexpected(protocol_error(admission.error()));
                }
            }
            if (!(*record)->publication_required) {
                if (has_repairs) {
                    auto resumed = resume_pending_storage_repairs(*paths,
                                                                  **record,
                                                                  *workspace,
                                                                  runtime_data,
                                                                  storage,
                                                                  key);
                    if (!resumed) {
                        if (detail::has_local_rollback_work(**record)) {
                            auto rolled = detail::rollback_local_mutations(
                                **record, *workspace, runtime_data.local_dir);
                            if (!rolled) {
                                return std::unexpected(detail::make_error(
                                    ErrorCode::RecoveryConflict,
                                    resumed.error().detail +
                                        "; rollback failed: " +
                                        rolled.error().detail));
                            }
                            if (auto saved = detail::save_record(
                                    *paths,
                                    **record,
                                    key,
                                    journal::SaveMode::Rollback);
                                !saved) {
                                return std::unexpected(saved.error());
                            }
                        }
                        return std::unexpected(resumed.error());
                    }
                    auto local = resume_pending_local_mutations(*paths,
                                                                **record,
                                                                *workspace,
                                                                *resumed,
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
                if (is_publication_transaction_resumable(*paths,
                                                         **record,
                                                         *workspace,
                                                         runtime_data,
                                                         storage,
                                                         key)) {
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
                storage,
                layout,
                reference,
                runtime_data.database_path.parent_path());
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
