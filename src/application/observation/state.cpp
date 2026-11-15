#include "application/observation/state.hpp"

#include "application/history_storage/detail.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/observation/file_metadata.hpp"
#include "application/observation/history.hpp"
#include "application/observation/scanner.hpp"
#include "core/ignore.hpp"
#include "core/reconciliation/plan.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "platform/path.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <exception>
#include <optional>
#include <thread>

namespace kasumi::application::observation {
namespace {

std::expected<LocalTreeObservation, std::string>
scan_local_tree(const std::filesystem::path& local_root,
                const kasumi::ignore::IgnoreList* ignore_list = nullptr) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(local_root, error);
    if (error || std::filesystem::is_symlink(status) ||
        !std::filesystem::is_directory(status)) {
        return std::unexpected("missing or invalid local directory");
    }
    auto current = ignore_list != nullptr
                       ? scanner::scan_result(local_root,
                                              {},
                                              scanner::ScanPolicy::FullHash,
                                              cache::read_file_metadata,
                                              *ignore_list)
                       : scanner::scan_result(
                             local_root, {}, scanner::ScanPolicy::FullHash);
    if (!current) {
        return std::unexpected(scanner::describe(current.error()));
    }
    if (!valid_snapshot(current->snapshot, false)) {
        return std::unexpected("local snapshot has no valid root");
    }
    return LocalTreeObservation{
        .snapshot = std::move(current->snapshot),
        .physical_evidence = std::move(current->physical_evidence),
    };
}

struct IgnoreIdentity {
    bool present = false;
    bool directory = false;
    bool regular_file = false;
    Hash hash{};
    std::uint64_t size = 0;
    bool operator==(const IgnoreIdentity&) const noexcept = default;
};

IgnoreIdentity ignore_identity(const Snapshot& tree) {
    const auto* row = find_row(tree, ".kasumiignore");
    if (row == nullptr) {
        return {};
    }
    return IgnoreIdentity{.present = true,
                          .directory = row->is_directory,
                          .regular_file = !row->is_directory,
                          .hash = row->hash,
                          .size = row->size};
}

std::expected<IgnoreIdentity, std::string>
local_ignore_identity(const std::filesystem::path& local_root) {
    const auto path = local_root / ".kasumiignore";
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error == std::errc::no_such_file_or_directory ||
        (!error && !std::filesystem::exists(status))) {
        return IgnoreIdentity{};
    }
    if (error) {
        return std::unexpected("could not inspect local .kasumiignore: " +
                               error.message());
    }
    IgnoreIdentity identity{.present = true,
                            .directory = std::filesystem::is_directory(status),
                            .regular_file =
                                std::filesystem::is_regular_file(status)};
    if (!identity.regular_file) {
        return identity;
    }
    auto hash = crypto::content::hash_file(path);
    if (!hash) {
        return std::unexpected("could not hash local .kasumiignore: " +
                               hash.error());
    }
    identity.hash = *hash;
    identity.size = std::filesystem::file_size(path, error);
    if (error) {
        return std::unexpected("could not read local .kasumiignore size: " +
                               error.message());
    }
    return identity;
}

std::expected<kasumi::ignore::IgnoreList, std::string>
load_remote_ignore_list(transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        const NodeRow& row,
                        const std::filesystem::path& workspace_root) {
    auto temporary = history_storage::detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(temporary.error().detail);
    }
    const auto encrypted = temporary->get()->workspace.root / "ignore.enc";
    const auto plaintext = temporary->get()->workspace.root / "ignore.txt";
    const auto identifier = crypto::content_identifier(key, row.hash);
    const auto downloaded = transport::get(storage, identifier, encrypted);
    if (!downloaded) {
        return std::unexpected("could not read authenticated remote "
                               ".kasumiignore: " +
                               downloaded.error().message);
    }
    if (!crypto::decrypt_file(encrypted, plaintext, key) ||
        !crypto::content::verify_file(
            plaintext, hash_hex(row.hash), row.size)) {
        return std::unexpected(
            "authenticated remote .kasumiignore failed content verification");
    }
    return kasumi::ignore::load_ignore_list(plaintext);
}

std::expected<kasumi::ignore::IgnoreList, std::string>
effective_ignore_list(const std::filesystem::path& local_root,
                      const IgnoreIdentity& base_version,
                      const Snapshot& remote_tree,
                      transport::Transport& storage,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                      const std::filesystem::path& workspace_root,
                      const kasumi::ignore::IgnoreList& local_rules) {
    auto local_version = local_ignore_identity(local_root);
    if (!local_version) {
        return std::unexpected(local_version.error());
    }
    const auto remote_version = ignore_identity(remote_tree);
    const bool local_changed = *local_version != base_version;
    const bool remote_changed = remote_version != base_version;

    // Preserve local-wins behavior for local edits and simultaneous changes.
    if (local_changed) {
        return local_rules;
    }
    if (remote_version.regular_file &&
        (remote_changed || !local_version->regular_file)) {
        const auto* row = find_row(remote_tree, ".kasumiignore");
        auto rules =
            load_remote_ignore_list(storage, key, *row, workspace_root);
        if (!rules) {
            return std::unexpected(rules.error());
        }
        return *rules;
    }
    if (remote_changed) {
        return kasumi::ignore::IgnoreList{};
    }
    return local_rules;
}

reconciliation::Error state_error(reconciliation::ErrorCode code,
                                  std::string detail) {
    return reconciliation::Error{
        .code = code, .detail = std::move(detail), .paths = {}};
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

reconciliation::StorageState to_storage_state(history::StorageView& observed) {
    reconciliation::StorageState result{
        .tree = std::move(observed.effective_tree),
        .object_identifiers = std::move(observed.content_identifiers),
        .reachable_commits = std::move(observed.reachable_commits),
        .reachable_commit_ids = std::move(observed.reachable_commit_ids),
        .marked_heads = std::move(observed.marked_heads),
        .marked_head_identifiers = std::move(observed.marked_head_identifiers),
        .logical_heads = std::move(observed.logical_heads),
        .ancestral_marked_heads = std::move(observed.ancestral_marked_heads),
        .generation = observed.observed_height,
        .history_present = observed.history_present,
        .history_has_conflicts = observed.has_conflicts,
    };
    if (observed.epoch) {
        result.epoch_vault_id = observed.epoch->value.vault_id;
        result.epoch_id = observed.epoch->reference.epoch_id;
        result.epoch_sequence = observed.epoch->value.sequence;
        result.epoch_policy = reconciliation::EpochRetentionPolicy{
            .min_history_depth = observed.epoch->value.policy.min_history_depth,
            .min_history_age_hours =
                observed.epoch->value.policy.min_history_age_hours};
        result.epoch_anchors.reserve(observed.epoch->value.anchors.size());
        for (const auto& anchor : observed.epoch->value.anchors) {
            result.epoch_anchors.push_back(
                {.commit_id = anchor.commit_id, .height = anchor.height});
        }
    }
    return result;
}

} // namespace

std::expected<LocalTreeObservation, std::string>
collect_local_observation(const std::filesystem::path& local_root,
                          const kasumi::ignore::IgnoreList& ignore_list) {
    return scan_local_tree(local_root, &ignore_list);
}

std::expected<LocalTreeObservation, std::string>
collect_local_observation(const std::filesystem::path& local_root,
                          LocalObservationSession* session,
                          const kasumi::ignore::IgnoreList& ignore_list) {
    if (ignore_list ==
        kasumi::ignore::load_ignore_list(local_root / ".kasumiignore")) {
        return collect_local_observation(local_root, session);
    }
    return collect_local_observation(local_root, ignore_list);
}

std::expected<LocalTreeObservation, std::string>
collect_local_observation(const std::filesystem::path& local_root,
                          LocalObservationSession* session) {
    try {
        if (session == nullptr)
            return scan_local_tree(local_root);

        ensure_file_cache_loaded(*session);
        auto previous = std::move(session->cache);
        const bool cache_was_dirty = session->cache_dirty;
        auto scanned = scanner::scan_result(
            local_root, previous, scanner::ScanPolicy::ReuseStrongFingerprint);
        if (!scanned) {
            session->cache = std::move(previous);
            return std::unexpected(scanner::describe(scanned.error()));
        }
        session->cache_dirty = cache_was_dirty || previous != scanned->cache;
        session->cache = std::move(scanned->cache);
        return LocalTreeObservation{
            .snapshot = std::move(scanned->snapshot),
            .physical_evidence = std::move(scanned->physical_evidence),
        };
    } catch (const std::exception& exception) {
        return std::unexpected(exception.what());
    }
}

std::expected<Snapshot, std::string>
collect_local_tree(const std::filesystem::path& local_root,
                   LocalObservationSession* session) {
    auto observed = collect_local_observation(local_root, session);
    if (!observed) {
        return std::unexpected(observed.error());
    }
    return std::move(observed->snapshot);
}

std::expected<StorageObservation, std::string>
collect_storage_observation(transport::Transport& storage,
                            std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                            const std::filesystem::path& workspace_root,
                            bool audit_storage_objects) {
    auto observed =
        history::observe(storage, key, workspace_root, audit_storage_objects);
    if (!observed) {
        return std::unexpected(observed.error().detail);
    }
    return StorageObservation{
        .state = to_storage_state(*observed),
        .physical_identifiers = std::move(observed->physical_identifiers),
    };
}

std::expected<reconciliation::StorageState, std::string>
collect_storage_state(transport::Transport& storage,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                      const std::filesystem::path& workspace_root,
                      bool audit_storage_objects) {
    auto observation = collect_storage_observation(
        storage, key, workspace_root, audit_storage_objects);
    if (!observation) {
        return std::unexpected(observation.error());
    }
    return std::move(observation->state);
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
    std::expected<LocalTreeObservation, std::string> local_observation;
    auto persisted = state_storage::load_state(runtime_data.database_path);

    reconciliation::Input input;
    history::ObservationHints hints;
    if (persisted && *persisted) {
        hints = history::make_observation_hints(
            **persisted, history_storage::derive_remote_layout(key));
        input.base_tree = std::move((*persisted)->tree);
        input.pending_materializations =
            std::move((*persisted)->pending_materializations);
        input.local_generation = (*persisted)->height;
        input.base_commit_id = std::move((*persisted)->commit_id);
        input.base_ciphertext_id = std::move((*persisted)->ciphertext_id);
        input.base_state_present = true;
    }
    const auto accepted_ignore_version = ignore_identity(input.base_tree);
    const auto local_ignore_list = kasumi::ignore::load_ignore_list(
        runtime_data.local_dir / ".kasumiignore");
    input.ignore_list = local_ignore_list;

    std::jthread local_scan([&] {
        local_observation =
            collect_local_observation(runtime_data.local_dir, session);
        if (local_observation && input.base_state_present &&
            !local_observation->snapshot.rows.empty() &&
            !input.base_tree.rows.empty() &&
            local_observation->snapshot.rows.front().hash !=
                input.base_tree.rows.front().hash &&
            on_proven_local_change) {
            on_proven_local_change();
        }
    });

    if (!persisted) {
        local_scan.join();
        if (!local_observation) {
            return std::unexpected(
                state_error(reconciliation::ErrorCode::InvalidLocalTree,
                            local_observation.error()));
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
    const auto& derived_trusted_markers = hints.trusted_marker_identifiers;
    std::span<const std::string> effective_trusted_markers{};
    if (!audit_storage_objects) {
        effective_trusted_markers =
            derived_trusted_markers.empty()
                ? trusted_marker_identifiers
                : std::span<const std::string>{derived_trusted_markers};
    }
    auto observed =
        history::observe(storage,
                         key,
                         history_workspace,
                         audit_storage_objects,
                         hints.frontier ? &*hints.frontier : nullptr,
                         effective_trusted_markers);
    local_scan.join();
    if (!local_observation) {
        return std::unexpected(
            state_error(reconciliation::ErrorCode::InvalidLocalTree,
                        local_observation.error()));
    }
    input.local_tree = std::move(local_observation->snapshot);
    input.local_physical_evidence =
        std::move(local_observation->physical_evidence);
    if (!observed) {
        return std::unexpected(
            state_error(reconciliation::ErrorCode::InvalidStorageTree,
                        observed.error().detail));
    }
    input.storage = to_storage_state(*observed);
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
    auto effective_rules = effective_ignore_list(runtime_data.local_dir,
                                                 accepted_ignore_version,
                                                 input.storage.tree,
                                                 storage,
                                                 key,
                                                 history_workspace,
                                                 local_ignore_list);
    if (!effective_rules) {
        return std::unexpected(
            state_error(reconciliation::ErrorCode::InvalidStorageTree,
                        effective_rules.error()));
    }
    input.ignore_list = std::move(*effective_rules);
    if (input.ignore_list != local_ignore_list) {
        auto projected = collect_local_observation(runtime_data.local_dir,
                                                   input.ignore_list);
        if (!projected) {
            return std::unexpected(
                state_error(reconciliation::ErrorCode::InvalidLocalTree,
                            projected.error()));
        }
        input.local_tree = std::move(projected->snapshot);
        input.local_physical_evidence = std::move(projected->physical_evidence);
    }
    input.audit_storage_objects = audit_storage_objects;
    const bool maybe_disposable_removal =
        input.base_state_present && input.storage.history_present &&
        !input.storage.history_has_conflicts &&
        std::ranges::any_of(
            input.local_physical_evidence.directories,
            [&](const reconciliation::LocalDirectoryEvidence& directory) {
                const auto* base = find_row(input.base_tree, directory.path);
                return !directory.path.empty() && !directory.ignored_entry &&
                       directory.has_disposable_descendants &&
                       base != nullptr && base->is_directory &&
                       find_row(input.storage.tree, directory.path) == nullptr;
            });
    if (maybe_disposable_removal) {
        auto initial_plan = reconciliation::reconcile(input);
        if (initial_plan && !initial_plan->disposable_paths_to_hash.empty()) {
            auto content = scanner::hash_disposable_candidates(
                runtime_data.local_dir,
                input.local_physical_evidence,
                initial_plan->disposable_paths_to_hash,
                input.ignore_list);
            if (!content) {
                return std::unexpected(
                    state_error(reconciliation::ErrorCode::InvalidLocalTree,
                                scanner::describe(content.error())));
            }
            input.disposable_ignored_content = std::move(*content);
        }
    }
    return input;
}

} // namespace kasumi::application::observation
