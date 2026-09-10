#include "core/reconciliation/plan.hpp"

#include "core/diff.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <cstddef>
#include <expected>
#include <filesystem>
#include <functional>
#include <iterator>
#include <limits>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace kasumi::reconciliation {

namespace {

using LocalSources = std::unordered_map<Hash, NodeRow, decltype(&hash_key)>;

bool is_conflict(const Operation& operation) {
    const auto marked = [](const std::filesystem::path& path) {
        return platform::path::to_logical_utf8(path).find(".kasumiconflict_") !=
               std::string::npos;
    };

    return operation.action == Action::RenameLocal ||
           ((operation.action == Action::Upload ||
             operation.action == Action::Download) &&
            (marked(operation.path) || marked(operation.alt_path)));
}

bool has_conflicts(const SyncPlan& plan) {
    return std::ranges::any_of(sync_plan_operations(plan), is_conflict);
}

void collect_local_sources(const Snapshot& snapshot, LocalSources& sources) {
    for (const auto& row : snapshot.rows) {
        if (!row.is_directory) {
            sources.try_emplace(row.hash, row);
        }
    }
}

void erase_subtree(Snapshot& snapshot, std::string_view path) {
    const auto first = std::ranges::lower_bound(
        snapshot.rows, path, path_less, &NodeRow::path);

    auto last = first;

    while (last != snapshot.rows.end() &&
           (last->path == path || is_descendant(last->path, path))) {
        ++last;
    }

    snapshot.rows.erase(first, last);
}

void upsert_row(Snapshot& snapshot, NodeRow row) {
    auto position = std::ranges::lower_bound(
        snapshot.rows, row.path, path_less, &NodeRow::path);

    if (position != snapshot.rows.end() && position->path == row.path) {
        *position = std::move(row);
    } else {
        snapshot.rows.insert(position, std::move(row));
    }
}

std::expected<void, Error>
synchronize_ancestor_rows(Snapshot& candidate,
                          const Snapshot& local_tree,
                          std::string_view path,
                          bool include_target,
                          const Snapshot* fallback = nullptr) {
    std::vector<std::string> directories;
    directories.emplace_back();
    for (std::size_t end = path.find('/'); end != std::string_view::npos;
         end = path.find('/', end + 1)) {
        directories.emplace_back(path.substr(0, end));
    }
    if (include_target && !path.empty()) {
        directories.emplace_back(path);
    }

    for (const auto& directory : directories) {
        const auto* local_row = find_row(local_tree, directory);
        if (local_row == nullptr && fallback != nullptr) {
            local_row = find_row(*fallback, directory);
        }
        if (local_row == nullptr || !local_row->is_directory) {
            return std::unexpected(Error{
                .code = ErrorCode::UnsafePlan,
                .detail = "ancestor não observado como diretório",
                .paths = {platform::path::from_utf8(directory)},
            });
        }
        auto row = *local_row;
        row.path = directory;
        row.hash = {};
        row.size = 0;
        row.is_directory = true;
        upsert_row(candidate, std::move(row));
    }
    return {};
}

std::filesystem::path
reserve_conflict_path(const std::filesystem::path& preferred,
                      std::unordered_set<std::string>& reserved,
                      std::unordered_set<std::string>& reserved_case_keys) {
    const auto preferred_text = platform::path::to_logical_utf8(preferred);
    auto candidate = preferred_text;
    std::size_t suffix = 0;

    while (reserved_case_keys.contains(portable_case_key(candidate))) {
        candidate =
            make_conflict_path(preferred_text, "." + std::to_string(++suffix));
    }

    reserved.insert(candidate);
    reserved_case_keys.insert(portable_case_key(candidate));

    return platform::path::from_utf8(candidate);
}

void reserve_conflict_destinations(const Snapshot& local_tree,
                                   std::vector<Operation>& operations) {
    std::unordered_set<std::string> reserved;
    std::unordered_set<std::string> reserved_case_keys;

    const std::size_t estimated_size =
        local_tree.rows.size() + operations.size();
    reserved.reserve(estimated_size);
    reserved_case_keys.reserve(estimated_size);

    auto add_reserved = [&](const std::string& path) {
        reserved.insert(path);
        reserved_case_keys.insert(portable_case_key(path));
    };

    for (const auto& row : local_tree.rows) {
        if (!row.path.empty()) {
            add_reserved(row.path);
        }
    }

    for (const auto& operation : operations) {
        if (operation.action == Action::Download &&
            !operation.exclusive_destination) {
            add_reserved(platform::path::to_logical_utf8(operation.path));
        }

        if (operation.action == Action::RenameLocal &&
            !operation.exclusive_destination) {
            add_reserved(platform::path::to_logical_utf8(operation.alt_path));
        }
    }

    for (auto& operation : operations) {
        if (operation.action == Action::RenameLocal &&
            operation.exclusive_destination) {
            const auto preferred = operation.alt_path;

            const auto selected =
                reserve_conflict_path(preferred, reserved, reserved_case_keys);

            operation.alt_path = selected;

            for (auto& related : operations) {
                if (related.action == Action::Upload &&
                    related.path == preferred) {
                    related.path = selected;
                }
            }
        } else if (operation.action == Action::Download &&
                   operation.exclusive_destination) {
            operation.path = reserve_conflict_path(
                operation.path, reserved, reserved_case_keys);
        }
    }
}

void collect_pending_rows(const Snapshot& storage_tree,
                          const HashSet& missing_objects,
                          const LocalSources& local_sources,
                          std::vector<NodeRow>& pending,
                          std::vector<std::filesystem::path>& unrecoverable) {
    for (const auto& row : storage_tree.rows) {
        if (row.is_directory) {
            continue;
        }

        if (!missing_objects.contains(row.hash)) {
            continue;
        }

        pending.push_back(row);

        if (!local_sources.contains(row.hash)) {
            unrecoverable.push_back(platform::path::from_utf8(row.path));
        }
    }

    std::ranges::sort(unrecoverable, {}, [](const auto& path) {
        return platform::path::to_logical_utf8(path);
    });
}

void append_recovery_uploads(const HashSet& missing_objects,
                             const LocalSources& local_sources,
                             std::vector<Operation>& operations,
                             std::vector<std::string>& repair_paths) {
    for (const auto& hash : missing_objects) {
        const auto source = local_sources.find(hash);

        if (source == local_sources.end()) {
            continue;
        }

        const auto hash_identifier = hash_hex(hash);

        const bool already_scheduled =
            std::ranges::any_of(operations, [&](const Operation& operation) {
                return operation.action == Action::Upload &&
                       operation.hash == hash_identifier;
            });

        if (already_scheduled) {
            continue;
        }

        operations.push_back(Operation{
            .action = Action::Upload,
            .path = platform::path::from_utf8(source->second.path),
            .hash = hash_identifier,
            .alt_path = {},
            .size = source->second.size,
            .exclusive_destination = false,
        });
        repair_paths.push_back(source->second.path);
    }
}

bool is_repair_upload(const Operation& operation,
                      std::span<const std::string> repair_paths,
                      const Snapshot& storage_tree) {
    if (operation.action != Action::Upload) {
        return false;
    }

    const auto logical_path = platform::path::to_logical_utf8(operation.path);
    if (std::ranges::binary_search(repair_paths, logical_path)) {
        return true;
    }

    const auto row = find_row(storage_tree, logical_path);
    const auto hash = hash_from_hex(operation.hash);
    return row != nullptr && !row->is_directory && hash.has_value() &&
           row->hash == *hash;
}

struct CandidateTree {
    Snapshot tree;
    bool changed = false;
};

void synchronize_common_local_rows(Snapshot& candidate,
                                   const Snapshot& local_tree) {
    for (auto& candidate_row : candidate.rows) {
        const auto* local_row = find_row(local_tree, candidate_row.path);
        if (local_row == nullptr ||
            local_row->is_directory != candidate_row.is_directory ||
            (!local_row->is_directory &&
             (local_row->hash != candidate_row.hash ||
              local_row->size != candidate_row.size))) {
            continue;
        }
        candidate_row = *local_row;
        if (candidate_row.is_directory) {
            candidate_row.hash = {};
            candidate_row.size = 0;
        }
    }
}

std::expected<CandidateTree, Error>
candidate_shared_tree(const Input& input,
                      const SyncPlan& plan,
                      std::span<const std::string> repair_paths) {
    CandidateTree result{
        .tree = input.storage.history_present ? input.storage.tree
                                              : input.local_tree,
        .changed = false,
    };

    const auto find_local_row =
        [&](const Operation& operation) -> const NodeRow* {
        const auto direct = find_row(
            input.local_tree, platform::path::to_logical_utf8(operation.path));
        if (direct != nullptr) {
            return direct;
        }
        if (operation.hash.empty()) {
            return static_cast<const NodeRow*>(nullptr);
        }
        const auto hash = hash_from_hex(operation.hash);
        if (!hash) {
            return static_cast<const NodeRow*>(nullptr);
        }
        const auto found = std::ranges::find_if(
            input.local_tree.rows, [&](const NodeRow& row) {
                return !row.is_directory && row.hash == *hash;
            });
        return found == input.local_tree.rows.end() ? nullptr : &*found;
    };

    for (const auto& operation : sync_plan_operations(plan)) {
        switch (operation.action) {
            case Action::Upload: {
                if (is_repair_upload(
                        operation, repair_paths, input.storage.tree)) {
                    continue;
                }

                const auto expected_hash = hash_from_hex(operation.hash);
                if (!expected_hash) {
                    return std::unexpected(Error{
                        .code = ErrorCode::UnsafePlan,
                        .detail = "upload contém hash inválido",
                        .paths = {operation.path},
                    });
                }

                const auto source = find_local_row(operation);
                if (source == nullptr || source->is_directory ||
                    source->hash != *expected_hash ||
                    source->size != operation.size) {
                    return std::unexpected(Error{
                        .code = ErrorCode::UnsafePlan,
                        .detail =
                            "upload não corresponde à linha local observada",
                        .paths = {operation.path},
                    });
                }
                auto row = *source;
                row.path = platform::path::to_logical_utf8(operation.path);
                auto parents = synchronize_ancestor_rows(
                    result.tree, input.local_tree, row.path, false);
                if (!parents) {
                    return std::unexpected(std::move(parents.error()));
                }
                upsert_row(result.tree, std::move(row));
                break;
            }
            case Action::CreateRemoteDirectory: {
                const auto path =
                    platform::path::to_logical_utf8(operation.path);
                const auto* local_row = find_row(input.local_tree, path);
                if (local_row == nullptr || !local_row->is_directory ||
                    !operation.hash.empty() || operation.size != 0) {
                    return std::unexpected(Error{
                        .code = ErrorCode::UnsafePlan,
                        .detail =
                            "diretório remoto não corresponde à árvore local",
                        .paths = {operation.path},
                    });
                }
                const auto existing = find_row(result.tree, path);
                if (existing != nullptr && !existing->is_directory) {
                    return std::unexpected(Error{
                        .code = ErrorCode::UnsafePlan,
                        .detail =
                            "criação de diretório remoto conflita com arquivo",
                        .paths = {operation.path},
                    });
                }
                auto parents = synchronize_ancestor_rows(
                    result.tree, input.local_tree, path, true);
                if (!parents) {
                    return std::unexpected(std::move(parents.error()));
                }
                auto row = *local_row;
                row.path = path;
                row.hash = {};
                row.size = 0;
                row.is_directory = true;
                upsert_row(result.tree, std::move(row));
                break;
            }
            case Action::DeleteRemote:
            case Action::DeleteRemoteDirectory: {
                const auto path =
                    platform::path::to_logical_utf8(operation.path);
                if (find_row(result.tree, path) == nullptr) {
                    return std::unexpected(Error{
                        .code = ErrorCode::UnsafePlan,
                        .detail = "remoção remota não corresponde à árvore",
                        .paths = {operation.path},
                    });
                }
                erase_subtree(result.tree, path);
                auto ancestors = synchronize_ancestor_rows(
                    result.tree, input.local_tree, path, false);
                if (!ancestors) {
                    return std::unexpected(std::move(ancestors.error()));
                }
                break;
            }
            default:
                break;
        }
    }

    if (input.storage.history_present &&
        (input.storage.logical_heads.size() != 1 ||
         result.tree != input.storage.tree)) {
        synchronize_common_local_rows(result.tree, input.local_tree);
    }

    finalize_snapshot(result.tree);
    result.changed = result.tree != input.storage.tree;
    return result;
}

void order_directory_operations(SyncPlan& plan) {
    const auto depth = [](const Operation& operation) {
        return static_cast<std::size_t>(
            std::distance(operation.path.begin(), operation.path.end()));
    };

    auto creations = sync_plan_phase(plan, Action::CreateLocalDirectory);

    auto deletions = sync_plan_phase(plan, Action::DeleteLocalDirectory);

    std::ranges::sort(creations, {}, depth);

    std::ranges::sort(deletions, std::greater{}, depth);
}

std::expected<void, Error>
merge_pending_references(Snapshot& publication_tree,
                         std::span<const NodeRow> pending_rows,
                         const Snapshot& candidate_shared_tree) {
    for (const auto& pending : pending_rows) {
        if (pending.is_directory) {
            return std::unexpected(Error{
                .code = ErrorCode::InvalidStorageTree,
                .detail = "referência pendente não "
                          "pode representar diretório",
                .paths = {platform::path::from_utf8(pending.path)},
            });
        }

        erase_subtree(publication_tree, pending.path);

        auto ancestors = synchronize_ancestor_rows(publication_tree,
                                                   publication_tree,
                                                   pending.path,
                                                   false,
                                                   &candidate_shared_tree);
        if (!ancestors) {
            return std::unexpected(std::move(ancestors.error()));
        }

        upsert_row(publication_tree, pending);
    }

    finalize_snapshot(publication_tree);

    return {};
}

Error invalid_tree_error(ErrorCode code, std::string detail) {
    return Error{
        .code = code,
        .detail = std::move(detail),
        .paths = {},
    };
}

} // namespace

bool has_safe_paths(const SyncPlan& plan) {
    return std::ranges::all_of(sync_plan_operations(plan),
                               [](const Operation& operation) {
                                   return kasumi::has_safe_paths(operation);
                               });
}

std::expected<Snapshot, Error>
build_publication_tree(Snapshot publication_tree,
                       std::span<const NodeRow> pending_storage_rows,
                       const Snapshot& candidate_shared_tree) {
    if (!kasumi::valid_snapshot(publication_tree, false)) {
        return std::unexpected(Error{
            .code = ErrorCode::InvalidExecutedTree,
            .detail = "árvore local observada "
                      "após a execução é inválida",
            .paths = {},
        });
    }

    if (!kasumi::valid_snapshot(candidate_shared_tree, false)) {
        return std::unexpected(Error{
            .code = ErrorCode::UnsafePlan,
            .detail = "árvore candidata inválida",
            .paths = {},
        });
    }

    auto merged = merge_pending_references(
        publication_tree, pending_storage_rows, candidate_shared_tree);

    if (!merged) {
        return std::unexpected(std::move(merged.error()));
    }

    return publication_tree;
}

ReconcileResult reconcile(const Input& input) {
    if (!kasumi::valid_snapshot(input.local_tree, false)) {
        return std::unexpected(invalid_tree_error(ErrorCode::InvalidLocalTree,
                                                  "árvore local inválida"));
    }

    if (!kasumi::valid_snapshot(input.base_tree, true)) {
        return std::unexpected(invalid_tree_error(ErrorCode::InvalidBaseTree,
                                                  "árvore base inválida"));
    }

    if (input.storage.history_present &&
        !kasumi::valid_snapshot(input.storage.tree, false)) {
        return std::unexpected(invalid_tree_error(ErrorCode::InvalidStorageTree,
                                                  "árvore do armazenamento "
                                                  "inválida"));
    }

    if (!input.storage.history_present &&
        !kasumi::valid_snapshot(input.storage.tree, true)) {
        return std::unexpected(invalid_tree_error(ErrorCode::InvalidStorageTree,
                                                  "árvore do armazenamento "
                                                  "inválida"));
    }

    if (input.base_state_present && !input.storage.history_present) {
        return std::unexpected(Error{
            .code = ErrorCode::MissingStorageHistory,
            .detail = "remote history is missing for the persisted local base",
            .paths = {},
        });
    }
    if (input.base_state_present && input.storage.history_present) {
        const auto found =
            std::ranges::find(input.storage.reachable_commits,
                              input.base_commit_id,
                              &kasumi::history::LoadedCommit::id);
        if (found == input.storage.reachable_commits.end()) {
            return std::unexpected(Error{
                .code = ErrorCode::StorageHistoryRegression,
                .detail = "local base commit is not reachable from storage",
                .paths = {},
            });
        }
        if (found->commit.height != input.local_generation ||
            found->commit.tree != input.base_tree) {
            return std::unexpected(Error{
                .code = ErrorCode::InvalidLocalBaseState,
                .detail =
                    "persisted local base identity does not match its commit",
                .paths = {},
            });
        }
    }

    const Snapshot& effective_storage_tree = input.storage.tree;

    const std::uint64_t observed_storage_generation = input.storage.generation;

    if (input.storage.history_present &&
        observed_storage_generation ==
            std::numeric_limits<std::uint64_t>::max()) {
        return std::unexpected(Error{
            .code = ErrorCode::StorageGenerationOverflow,
            .detail = "a altura máxima não pode receber outro commit",
            .paths = {},
        });
    }

    HashSet missing_objects{0, hash_key};

    if (input.audit_storage_objects && !effective_storage_tree.rows.empty()) {
        diff::detail::find_missing_blocks(effective_storage_tree,
                                          input.storage.object_identifiers,
                                          missing_objects);
    }

    LocalSources local_sources{0, hash_key};

    collect_local_sources(input.local_tree, local_sources);

    std::vector<NodeRow> pending_storage_rows;

    std::vector<std::filesystem::path> unrecoverable_paths;

    collect_pending_rows(effective_storage_tree,
                         missing_objects,
                         local_sources,
                         pending_storage_rows,
                         unrecoverable_paths);

    auto operations = diff::compare_trees(input.local_tree,
                                          input.base_tree,
                                          effective_storage_tree,
                                          missing_objects);

    reserve_conflict_destinations(input.local_tree, operations);

    std::vector<std::string> repair_upload_paths;
    append_recovery_uploads(
        missing_objects, local_sources, operations, repair_upload_paths);

    for (const auto& operation : operations) {
        if (is_repair_upload(
                operation, repair_upload_paths, effective_storage_tree)) {
            repair_upload_paths.push_back(
                platform::path::to_logical_utf8(operation.path));
        }
    }
    std::ranges::sort(repair_upload_paths);
    repair_upload_paths.erase(std::ranges::unique(repair_upload_paths).begin(),
                              repair_upload_paths.end());

    const bool requires_local_mutation =
        std::ranges::any_of(operations, [](const Operation& operation) {
            return is_local_mutation(operation.action);
        });
    auto plan = make_sync_plan(std::move(operations), 0);

    order_directory_operations(plan);

    if (!valid_sync_plan(plan) || !has_safe_paths(plan)) {
        return std::unexpected(Error{
            .code = ErrorCode::UnsafePlan,
            .detail = "plano contém caminhos "
                      "ou fases inválidas",
            .paths = {},
        });
    }

    auto candidate = candidate_shared_tree(
        input, plan, std::span<const std::string>{repair_upload_paths});
    if (!candidate) {
        return std::unexpected(std::move(candidate.error()));
    }
    const bool shared_tree_changed = candidate->changed;
    const bool requires_storage_repair = !repair_upload_paths.empty();
    const bool requires_publication = !input.storage.history_present ||
                                      input.storage.logical_heads.size() != 1 ||
                                      shared_tree_changed;
    const auto target_generation =
        requires_publication
            ? (input.storage.history_present ? observed_storage_generation + 1
                                             : std::uint64_t{0})
            : observed_storage_generation;

    plan.target_generation = target_generation;

    const bool conflict = has_conflicts(plan);

    const bool requires_state_commit =
        input.storage.history_present &&
        (!input.base_state_present || input.storage.logical_heads.empty() ||
         input.base_commit_id != input.storage.logical_heads.front());

    return Result{
        .plan = std::move(plan),
        .missing_objects = std::move(missing_objects),
        .pending_storage_rows = std::move(pending_storage_rows),
        .unrecoverable_paths = std::move(unrecoverable_paths),
        .observed_storage_generation = observed_storage_generation,
        .target_generation = target_generation,
        .recovering_missing_history = !input.storage.history_present,
        .has_conflicts = conflict || input.storage.history_has_conflicts,
        .requires_local_mutation = requires_local_mutation,
        .requires_storage_repair = requires_storage_repair,
        .candidate_shared_tree = candidate->tree,
        .shared_tree_changed = shared_tree_changed,
        .requires_publication = requires_publication,
        .requires_state_commit = requires_state_commit,
    };
}

} // namespace kasumi::reconciliation
