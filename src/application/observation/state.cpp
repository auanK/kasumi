#include "application/observation/state.hpp"

#include "application/observation/history.hpp"
#include "application/observation/patch.hpp"
#include "application/observation/scanner.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <chrono>
#include <exception>
#include <thread>

namespace kasumi::application::observation {
namespace {

std::expected<Snapshot, std::string>
scan_local_tree(const std::filesystem::path& local_root) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(local_root, error);
    if (error || std::filesystem::is_symlink(status) ||
        !std::filesystem::is_directory(status)) {
        return std::unexpected("diretório local ausente ou inválido");
    }
    auto current =
        scanner::scan_result(local_root, {}, scanner::ScanPolicy::FullHash);
    if (!current) {
        return std::unexpected(scanner::describe(current.error()));
    }
    if (!valid_snapshot(current->snapshot, false)) {
        return std::unexpected("o snapshot local não possui raiz válida");
    }
    return std::move(current->snapshot);
}

reconciliation::Error state_error(reconciliation::ErrorCode code,
                                  std::string detail) {
    return reconciliation::Error{
        .code = code, .detail = std::move(detail), .paths = {}};
}

bool same_cache(
    const std::vector<state_storage::FileCacheRow>& left,
    const std::vector<state_storage::FileCacheRow>& right) noexcept {
    if (left.size() != right.size()) {
        return false;
    }
    for (std::size_t index = 0; index < left.size(); ++index) {
        const auto& a = left[index];
        const auto& b = right[index];
        if (a.path != b.path || a.hash != b.hash || a.size != b.size ||
            a.fingerprint.kind != b.fingerprint.kind ||
            a.fingerprint.value != b.fingerprint.value) {
            return false;
        }
    }
    return true;
}

bool checkpoint_matches(const state_storage::ObservationCheckpoint& checkpoint,
                        const Snapshot& snapshot) noexcept {
    return checkpoint.row_count == snapshot.rows.size() &&
           !snapshot.rows.empty() &&
           checkpoint.tree_root_hash == snapshot.rows.front().hash;
}

void set_checkpoint_tree(state_storage::ObservationCheckpoint& checkpoint,
                         const Snapshot& snapshot) noexcept {
    checkpoint.tree_root_hash = snapshot.rows.front().hash;
    checkpoint.row_count = snapshot.rows.size();
}

const state_storage::FileCacheRow*
find_cached_row(const LocalObservationSession& session,
                std::string_view path) noexcept {
    const auto found = std::ranges::lower_bound(
        session.cache, path, path_less, &state_storage::FileCacheRow::path);
    return found != session.cache.end() && found->path == path ? &*found
                                                               : nullptr;
}

std::optional<reconciliation::EpochRetentionPolicy> epoch_policy(
    const std::optional<history_storage::epoch::VerifiedEpoch>& epoch) {
    if (!epoch) {
        return std::nullopt;
    }
    return reconciliation::EpochRetentionPolicy{
        .min_history_depth = epoch->value.policy.min_history_depth,
        .min_history_age_hours = epoch->value.policy.min_history_age_hours};
}

std::vector<reconciliation::EpochAnchor> epoch_anchors(
    const std::optional<history_storage::epoch::VerifiedEpoch>& epoch) {
    std::vector<reconciliation::EpochAnchor> result;
    if (!epoch) {
        return result;
    }
    result.reserve(epoch->value.anchors.size());
    for (const auto& anchor : epoch->value.anchors) {
        result.push_back(
            {.commit_id = anchor.commit_id, .height = anchor.height});
    }
    return result;
}

void upsert_cached_row(LocalObservationSession& session,
                       const state_storage::FileCacheRow& row) {
    const auto found = std::ranges::lower_bound(
        session.cache, row.path, path_less, &state_storage::FileCacheRow::path);
    if (found == session.cache.end() || found->path != row.path)
        session.cache.insert(found, row);
    else
        *found = row;
}

void ensure_file_cache_loaded(LocalObservationSession& session);

constexpr std::size_t maximum_selective_entries = 1024;

std::expected<Snapshot, std::string>
apply_selective_delta(const std::filesystem::path& local_root,
                      LocalObservationSession& session,
                      const platform::LocalDeltaProbe& delta) {
    if (delta.entries.empty() ||
        delta.entries.size() > maximum_selective_entries)
        return std::unexpected("delta seletivo excede o limite");
    ensure_file_cache_loaded(session);
    std::vector<ObservedFileDelta> observations;
    observations.reserve(delta.entries.size());
    std::vector<state_storage::FileCacheRow> cache_updates;
    cache_updates.reserve(delta.entries.size());
    for (const auto& entry : delta.entries) {
        if (entry.kind != platform::LocalDeltaKind::ModifyExistingFile ||
            entry.current_relative_path.empty())
            return std::unexpected("delta não suportado");
        const auto relative =
            platform::path::to_logical_utf8(entry.current_relative_path);
        const auto* cached = find_cached_row(session, relative);
        ++session.targeted_file_observations;
        auto observed = scanner::observe_file(
            local_root,
            relative,
            cached == nullptr
                ? std::nullopt
                : std::optional<state_storage::FileCacheRow>{*cached});
        if (!observed)
            return std::unexpected(scanner::describe(observed.error()));
        observations.push_back(ObservedFileDelta{
            .path = observed->row.path, .row = std::move(observed->row)});
        if (observed->cache)
            cache_updates.push_back(std::move(*observed->cache));
    }
    auto patched = apply_local_delta(*session.last_snapshot, observations);
    if (!patched)
        return std::unexpected(patched.error());
    const auto post = platform::probe_change_journal_delta(
        local_root,
        delta.next,
        platform::DirectoryLineageView{.inside_directory_frns =
                                           session.directory_file_references,
                                       .complete = true,
                                       .checkpoint_bound = true});
    if (!post || post->disposition != platform::LocalDeltaDisposition::Clean)
        return std::unexpected("janela seletiva mudou durante a observação");

    for (const auto& row : cache_updates)
        upsert_cached_row(session, row);
    session.last_snapshot = *patched;
    session.cache_loaded = true;
    session.cache_dirty = true;
    session.last_evidence = platform::ChangeEvidence::Dirty;
    session.last_delta_entry_count = delta.entries.size();
    if (session.checkpoint) {
        session.checkpoint->journal = post->next;
        set_checkpoint_tree(*session.checkpoint, *patched);
    }
    return std::move(*patched);
}

void remember_scan(
    LocalObservationSession& session,
    const Snapshot& snapshot,
    const std::optional<platform::ChangeJournalCheckpoint>& scan_start,
    const std::optional<platform::ChangeJournalCheckpoint>& scan_end,
    std::vector<std::uint64_t> directory_file_references,
    bool lineage_complete,
    bool lineage_window_safe) {
    session.last_snapshot = snapshot;
    session.cache_loaded = true;
    session.cache_dirty = true;
    const bool stable_journal =
        scan_start && scan_end && scan_start->kind == scan_end->kind &&
        scan_start->volume_serial == scan_end->volume_serial &&
        scan_start->journal_id == scan_end->journal_id &&
        scan_start->root_file_reference == scan_end->root_file_reference &&
        scan_start->next_usn == scan_end->next_usn;
    session.lineage_complete =
        lineage_complete && (stable_journal || lineage_window_safe);
    session.directory_file_references =
        session.lineage_complete ? std::move(directory_file_references)
                                 : std::vector<std::uint64_t>{};
    if (scan_start) {
        session.checkpoint = state_storage::ObservationCheckpoint{
            .journal = session.lineage_complete ? *scan_end : *scan_start,
            .directory_file_references = session.directory_file_references,
            .lineage_complete = session.lineage_complete};
        set_checkpoint_tree(*session.checkpoint, snapshot);
    } else {
        session.checkpoint.reset();
    }
}

void ensure_file_cache_loaded(LocalObservationSession& session) {
    if (session.cache_loaded) {
        return;
    }
    if (!session.database_path.empty()) {
        if (auto cache = state_storage::load_file_cache(session.database_path);
            cache) {
            session.cache = std::move(*cache);
        }
    }
    session.cache_loaded = true;
}

std::optional<platform::ChangeJournalCheckpoint>
capture_settled_checkpoint(const std::filesystem::path& local_root) {
    auto previous = platform::capture_change_journal_checkpoint(local_root);
    if (!previous)
        return std::nullopt;
    for (int attempt = 0; attempt != 4; ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        auto current = platform::capture_change_journal_checkpoint(local_root);
        if (!current)
            return std::nullopt;
        if (current->kind == previous->kind &&
            current->volume_serial == previous->volume_serial &&
            current->journal_id == previous->journal_id &&
            current->root_file_reference == previous->root_file_reference &&
            current->next_usn == previous->next_usn)
            return *current;
        previous = std::move(current);
    }
    return *previous;
}

} // namespace

std::expected<Snapshot, std::string>
collect_local_tree(const std::filesystem::path& local_root) {
    return collect_local_tree(local_root, nullptr);
}

std::expected<Snapshot, std::string>
collect_local_tree(const std::filesystem::path& local_root,
                   LocalObservationSession* session) {
    try {
        if (session == nullptr)
            return scan_local_tree(local_root);

        if (session->checkpoint && session->last_snapshot &&
            checkpoint_matches(*session->checkpoint, *session->last_snapshot)) {
            if (session->lineage_complete &&
                session->checkpoint->lineage_complete) {
                const auto delta = platform::probe_change_journal_delta(
                    local_root,
                    session->checkpoint->journal,
                    platform::DirectoryLineageView{
                        .inside_directory_frns =
                            session->directory_file_references,
                        .complete = true,
                        .checkpoint_bound = true});
                if (delta && delta->disposition ==
                                 platform::LocalDeltaDisposition::Clean) {
                    session->last_evidence = platform::ChangeEvidence::Clean;
                    session->last_delta_entry_count = 0;
                    session->last_delta_record_count = delta->records_read;
                    platform::perf_trace::count("USN clean fast paths");
                    platform::perf_trace::count("local scanner avoided");
                    platform::perf_trace::count("file cache load avoided");
                    // Preserves bytes; next observation saves the cursor.
                    return *session->last_snapshot;
                }
                if (delta && delta->disposition ==
                                 platform::LocalDeltaDisposition::Patchable) {
                    session->last_delta_record_count = delta->records_read;
                    ++session->selective_patch_attempts;
                    auto patched =
                        apply_selective_delta(local_root, *session, *delta);
                    if (patched) {
                        ++session->selective_patch_successes;
                        platform::perf_trace::count(
                            "selective patch successes");
                        return std::move(*patched);
                    }
                    ++session->selective_patch_fallbacks;
                    platform::perf_trace::count("selective patch fallbacks");
                } else {
                    ++session->selective_patch_fallbacks;
                }
                session->last_evidence =
                    delta && delta->relevant_records != 0
                        ? std::optional{platform::ChangeEvidence::Dirty}
                        : std::optional{
                              platform::ChangeEvidence::Indeterminate};
                platform::perf_trace::count("USN selective fallbacks");
            } else {
                const auto probed = platform::probe_change_journal(
                    local_root, session->checkpoint->journal);
                session->last_evidence =
                    probed ? std::optional{probed->evidence}
                           : std::optional{
                                 platform::ChangeEvidence::Indeterminate};
                if (probed &&
                    probed->evidence == platform::ChangeEvidence::Clean) {
                    platform::perf_trace::count("USN clean fast paths");
                    platform::perf_trace::count("local scanner avoided");
                    platform::perf_trace::count("file cache load avoided");
                    return *session->last_snapshot;
                }
            }
        }

        ensure_file_cache_loaded(*session);
        ++session->scanner_invocations;
        platform::perf_trace::count("local scanner invocations");
        std::optional<platform::ChangeJournalCheckpoint> scan_start;
        scan_start = capture_settled_checkpoint(local_root);
        auto previous = std::move(session->cache);
        const bool cache_was_dirty = session->cache_dirty;
        auto scanned = scanner::scan_result(
            local_root, previous, scanner::ScanPolicy::ReuseStrongFingerprint);
        if (!scanned) {
            session->cache = std::move(previous);
            return std::unexpected(scanner::describe(scanned.error()));
        }
        std::optional<platform::ChangeJournalCheckpoint> scan_end;
        scan_end = capture_settled_checkpoint(local_root);
        const bool cache_changed = !same_cache(previous, scanned->cache);
        session->cache = std::move(scanned->cache);
        bool lineage_window_safe = false;
        if (scanned->directory_lineage_complete && scan_start && scan_end &&
            scan_start->next_usn != scan_end->next_usn) {
            const auto window = platform::probe_change_journal(
                local_root,
                *scan_start,
                platform::DirectoryLineageView{
                    .inside_directory_frns = scanned->directory_file_references,
                    .complete = true,
                    .checkpoint_bound = true});
            lineage_window_safe =
                window && window->evidence == platform::ChangeEvidence::Clean;
        }
        remember_scan(*session,
                      scanned->snapshot,
                      scan_start,
                      scan_end,
                      std::move(scanned->directory_file_references),
                      scanned->directory_lineage_complete,
                      lineage_window_safe);
        if (!cache_changed && !cache_was_dirty) {
            session->cache_dirty = false;
        }
        return std::move(scanned->snapshot);
    } catch (const std::exception& exception) {
        return std::unexpected(exception.what());
    }
}

std::expected<reconciliation::StorageState, std::string>
collect_storage_state(transport::Transport& storage,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                      const std::filesystem::path& workspace_root,
                      bool audit_storage_objects) {
    auto observed =
        history::observe(storage, key, workspace_root, audit_storage_objects);
    if (!observed) {
        return std::unexpected(observed.error().detail);
    }
    reconciliation::StorageState state{
        .tree = std::move(observed->effective_tree),
        .object_identifiers = std::move(observed->content_identifiers),
        .reachable_commits = std::move(observed->reachable_commits),
        .reachable_commit_ids = std::move(observed->reachable_commit_ids),
        .marked_heads = std::move(observed->marked_heads),
        .marked_head_identifiers = std::move(observed->marked_head_identifiers),
        .logical_heads = std::move(observed->logical_heads),
        .ancestral_marked_heads = std::move(observed->ancestral_marked_heads),
        .epoch_vault_id = observed->epoch
                              ? std::move(observed->epoch->value.vault_id)
                              : std::string{},
        .epoch_id = observed->epoch
                        ? std::move(observed->epoch->reference.epoch_id)
                        : std::string{},
        .epoch_sequence = observed->epoch ? observed->epoch->value.sequence : 0,
        .epoch_policy = epoch_policy(observed->epoch),
        .epoch_anchors = epoch_anchors(observed->epoch),
        .generation = observed->observed_height,
        .history_present = observed->history_present,
        .history_has_conflicts = observed->has_conflicts,
    };
    return state;
}

std::expected<reconciliation::Input, reconciliation::Error>
collect_reconciliation_input(
    const runtime::RuntimeData& runtime_data,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    bool audit_storage_objects,
    std::span<const std::string> trusted_marker_identifiers,
    LocalObservationSession* session,
    const std::function<void()>& on_proven_local_change) {
    std::expected<Snapshot, std::string> local_tree;
    if (session != nullptr && !session->checkpoint) {
        if (auto checkpoint = state_storage::load_observation_checkpoint(
                runtime_data.database_path);
            checkpoint && *checkpoint) {
            session->checkpoint = std::move(**checkpoint);
            session->directory_file_references =
                session->checkpoint->directory_file_references;
            session->lineage_complete = session->checkpoint->lineage_complete;
        }
    }
    auto persisted = state_storage::load_state(runtime_data.database_path);
    if (session != nullptr && session->checkpoint &&
        (!persisted || !*persisted ||
         !checkpoint_matches(session->checkpoint.value(),
                             (*persisted)->tree))) {
        session->checkpoint.reset();
        session->directory_file_references.clear();
        session->lineage_complete = false;
    }

    reconciliation::Input input;
    if (persisted && *persisted) {
        input.base_tree = std::move((*persisted)->tree);
        if (session != nullptr && session->checkpoint) {
            session->last_snapshot = input.base_tree;
        }
        input.local_generation = (*persisted)->height;
        input.base_commit_id = std::move((*persisted)->commit_id);
        input.base_ciphertext_id = std::move((*persisted)->ciphertext_id);
        input.base_state_present = true;
    }

    std::jthread local_scan([&] {
        const auto scan_trace = platform::perf_trace::begin();
        if (session == nullptr) {
            local_tree = collect_local_tree(runtime_data.local_dir);
        } else {
            local_tree = collect_local_tree(runtime_data.local_dir, session);
        }
        platform::perf_trace::finish("local filesystem scan", scan_trace);
        if (local_tree && input.base_state_present &&
            !local_tree->rows.empty() && !input.base_tree.rows.empty() &&
            local_tree->rows.front().hash !=
                input.base_tree.rows.front().hash &&
            on_proven_local_change) {
            on_proven_local_change();
        }
    });

    if (!persisted) {
        local_scan.join();
        if (!local_tree) {
            return std::unexpected(
                state_error(reconciliation::ErrorCode::InvalidLocalTree,
                            local_tree.error()));
        }
        return std::unexpected(
            state_error(reconciliation::ErrorCode::InvalidLocalBaseState,
                        persisted.error()));
    }
    auto history_workspace = runtime_data.database_path.parent_path();
    std::error_code workspace_error;
    if (history_workspace.empty() ||
        !std::filesystem::exists(history_workspace, workspace_error)) {
        history_workspace = runtime_data.local_dir.parent_path();
    }
    const history_storage::KnownHistoryFrontier* frontier = nullptr;
    std::optional<history_storage::KnownHistoryFrontier> known_frontier;
    std::vector<std::string> derived_trusted_markers;
    if (input.base_state_present) {
        known_frontier.emplace();
        known_frontier->anchors.push_back(history_storage::KnownHistoryAnchor{
            .commit_id = input.base_commit_id,
            .height = input.local_generation,
            .tree = input.base_tree,
        });
        if (!(*persisted)->epoch_id.empty()) {
            known_frontier->accepted_epoch = history_storage::epoch::Reference{
                .sequence = (*persisted)->epoch_sequence,
                .epoch_id = (*persisted)->epoch_id,
            };
        }
        frontier = &*known_frontier;
        if (!audit_storage_objects && !input.base_ciphertext_id.empty()) {
            const history_storage::HeadReference persisted_reference{
                .commit_id = input.base_commit_id,
                .ciphertext_id = input.base_ciphertext_id};
            if (history_storage::valid(persisted_reference)) {
                derived_trusted_markers.push_back(
                    history_storage::marker_object(persisted_reference));
            }
        }
    }
    const auto remote_trace = platform::perf_trace::begin();
    const auto remote_history_trace = platform::perf_trace::begin();
    std::span<const std::string> effective_trusted_markers{};
    if (!audit_storage_objects) {
        effective_trusted_markers =
            derived_trusted_markers.empty()
                ? trusted_marker_identifiers
                : std::span<const std::string>{derived_trusted_markers};
    }
    auto observed = history::observe(storage,
                                     key,
                                     history_workspace,
                                     audit_storage_objects,
                                     frontier,
                                     effective_trusted_markers);
    platform::perf_trace::finish("remote observation", remote_trace);
    // Preserves the historical metric name in reports.
    platform::perf_trace::finish("remote history observation",
                                 remote_history_trace);
    local_scan.join();
    if (!local_tree) {
        return std::unexpected(state_error(
            reconciliation::ErrorCode::InvalidLocalTree, local_tree.error()));
    }
    input.local_tree = std::move(*local_tree);
    if (!observed) {
        return std::unexpected(
            state_error(reconciliation::ErrorCode::InvalidStorageTree,
                        observed.error().detail));
    }
    input.storage = reconciliation::StorageState{
        .tree = std::move(observed->effective_tree),
        .object_identifiers = std::move(observed->content_identifiers),
        .reachable_commits = std::move(observed->reachable_commits),
        .reachable_commit_ids = std::move(observed->reachable_commit_ids),
        .marked_heads = std::move(observed->marked_heads),
        .marked_head_identifiers = std::move(observed->marked_head_identifiers),
        .logical_heads = std::move(observed->logical_heads),
        .ancestral_marked_heads = std::move(observed->ancestral_marked_heads),
        .epoch_vault_id =
            observed->epoch ? observed->epoch->value.vault_id : std::string{},
        .epoch_id = observed->epoch ? observed->epoch->reference.epoch_id
                                    : std::string{},
        .epoch_sequence = observed->epoch ? observed->epoch->value.sequence : 0,
        .epoch_policy = epoch_policy(observed->epoch),
        .epoch_anchors = epoch_anchors(observed->epoch),
        .generation = observed->observed_height,
        .history_present = observed->history_present,
        .history_has_conflicts = observed->has_conflicts,
    };
    if (input.base_state_present) {
        if (!input.storage.history_present) {
            return std::unexpected(state_error(
                reconciliation::ErrorCode::MissingStorageHistory,
                "remote history is missing for the persisted local base"));
        }
        const auto found =
            std::ranges::find(input.storage.reachable_commits,
                              input.base_commit_id,
                              &kasumi::history::LoadedCommit::id);
        if (found == input.storage.reachable_commits.end()) {
            const bool epoch_advanced =
                observed->epoch && ((*persisted)->epoch_id.empty() ||
                                    observed->epoch->value.sequence >
                                        (*persisted)->epoch_sequence);
            if (!epoch_advanced) {
                return std::unexpected(state_error(
                    reconciliation::ErrorCode::StorageHistoryRegression,
                    "local base commit is not reachable from storage"));
            }
            input.base_tree = {};
            input.base_commit_id.clear();
            input.base_ciphertext_id.clear();
            input.base_state_present = false;
            input.local_generation = 0;
        } else if (found->commit.height != input.local_generation ||
                   found->commit.tree != input.base_tree) {
            return std::unexpected(state_error(
                reconciliation::ErrorCode::InvalidLocalBaseState,
                "persisted local base identity does not match its commit"));
        }
    }
    input.audit_storage_objects = audit_storage_objects;
    return input;
}

} // namespace kasumi::application::observation
