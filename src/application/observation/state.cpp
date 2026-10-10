#include "application/observation/state.hpp"

#include "application/history_storage/detail.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/observation/file_metadata.hpp"
#include "application/observation/history.hpp"
#include "application/observation/scanner.hpp"
#include "core/ignore.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <exception>
#include <optional>
#include <thread>

namespace kasumi::application::observation {
namespace {

std::expected<Snapshot, std::string>
scan_local_tree(const std::filesystem::path& local_root) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(local_root, error);
    if (error || std::filesystem::is_symlink(status) ||
        !std::filesystem::is_directory(status)) {
        return std::unexpected("missing or invalid local directory");
    }
    auto current =
        scanner::scan_result(local_root, {}, scanner::ScanPolicy::FullHash);
    if (!current) {
        return std::unexpected(scanner::describe(current.error()));
    }
    if (!valid_snapshot(current->snapshot, false)) {
        return std::unexpected("local snapshot has no valid root");
    }
    return std::move(current->snapshot);
}

struct IgnoreIdentity {
    bool present = false;
    bool directory = false;
    bool regular_file = false;
    Hash hash{};
    std::uint64_t size = 0;
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

bool same_ignore_identity(const IgnoreIdentity& left,
                          const IgnoreIdentity& right) noexcept {
    return left.present == right.present && left.directory == right.directory &&
           left.regular_file == right.regular_file &&
           (!left.regular_file ||
            (left.hash == right.hash && left.size == right.size));
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
    const auto encrypted = temporary->get()->root / "ignore.enc";
    const auto plaintext = temporary->get()->root / "ignore.txt";
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
    const bool local_changed =
        !same_ignore_identity(*local_version, base_version);
    const bool remote_changed =
        !same_ignore_identity(remote_version, base_version);

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
            a.mtime_nanoseconds != b.mtime_nanoseconds ||
            a.volume != b.volume || a.file_low != b.file_low ||
            a.file_high != b.file_high) {
            return false;
        }
    }
    return true;
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

} // namespace

std::expected<Snapshot, std::string>
collect_local_tree(const std::filesystem::path& local_root) {
    return collect_local_tree(local_root, nullptr);
}

std::expected<Snapshot, std::string>
collect_local_tree(const std::filesystem::path& local_root,
                   const kasumi::ignore::IgnoreList& ignore_list) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(local_root, error);
    if (error || std::filesystem::is_symlink(status) ||
        !std::filesystem::is_directory(status)) {
        return std::unexpected("missing or invalid local directory");
    }
    auto current = scanner::scan_result(local_root,
                                        {},
                                        scanner::ScanPolicy::FullHash,
                                        cache::read_file_metadata,
                                        ignore_list);
    if (!current) {
        return std::unexpected(scanner::describe(current.error()));
    }
    if (!valid_snapshot(current->snapshot, false)) {
        return std::unexpected("local snapshot has no valid root");
    }
    return std::move(current->snapshot);
}

std::expected<Snapshot, std::string>
collect_local_tree(const std::filesystem::path& local_root,
                   LocalObservationSession* session,
                   const kasumi::ignore::IgnoreList& ignore_list) {
    if (ignore_list ==
        kasumi::ignore::load_ignore_list(local_root / ".kasumiignore")) {
        return collect_local_tree(local_root, session);
    }
    return collect_local_tree(local_root, ignore_list);
}

std::expected<Snapshot, std::string>
collect_local_tree(const std::filesystem::path& local_root,
                   LocalObservationSession* session) {
    try {
        if (session == nullptr)
            return scan_local_tree(local_root);

        ensure_file_cache_loaded(*session);
        platform::perf_trace::count("local scanner invocations");
        auto previous = std::move(session->cache);
        const bool cache_was_dirty = session->cache_dirty;
        auto scanned = scanner::scan_result(
            local_root, previous, scanner::ScanPolicy::ReuseStrongFingerprint);
        if (!scanned) {
            session->cache = std::move(previous);
            return std::unexpected(scanner::describe(scanned.error()));
        }
        session->cache_dirty =
            cache_was_dirty || !same_cache(previous, scanned->cache);
        session->cache = std::move(scanned->cache);
        return std::move(scanned->snapshot);
    } catch (const std::exception& exception) {
        return std::unexpected(exception.what());
    }
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
    return StorageObservation{
        .state = std::move(state),
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
    std::expected<Snapshot, std::string> local_tree;
    auto persisted = state_storage::load_state(runtime_data.database_path);

    reconciliation::Input input;
    if (persisted && *persisted) {
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
                const auto layout = history_storage::derive_remote_layout(key);
                derived_trusted_markers.push_back(
                    history_storage::marker_object(layout,
                                                   persisted_reference));
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
        auto projected = collect_local_tree(
            runtime_data.local_dir, session, input.ignore_list);
        if (!projected) {
            return std::unexpected(
                state_error(reconciliation::ErrorCode::InvalidLocalTree,
                            projected.error()));
        }
        input.local_tree = std::move(*projected);
    }
    input.audit_storage_objects = audit_storage_objects;
    return input;
}

} // namespace kasumi::application::observation
