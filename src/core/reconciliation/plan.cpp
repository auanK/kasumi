#include "core/reconciliation/plan.hpp"

#include "core/diff.hpp"
#include "core/hasher.hpp"
#include "core/ignore.hpp"
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

bool same_node(const NodeRow& left, const NodeRow& right) {
    return left.path == right.path && left.hash == right.hash &&
           left.size == right.size && left.mtime == right.mtime &&
           left.is_directory == right.is_directory;
}

bool valid_pending_rows(const Input& input) {
    if (!input.base_state_present && !input.pending_materializations.empty()) {
        return false;
    }
    const NodeRow* previous = nullptr;
    for (const auto& pending : input.pending_materializations) {
        const auto* base = find_row(input.base_tree, pending.path);
        if (pending.is_directory || base == nullptr || base->is_directory ||
            !same_node(*base, pending) ||
            (previous != nullptr && !path_less(previous->path, pending.path))) {
            return false;
        }
        previous = &pending;
    }
    return true;
}

bool is_eligible_for_deletion(const Input& input,
                              const NodeRow& pending,
                              const HashSet& missing_objects,
                              const LocalSources& local_sources) {
    if (input.pending_deletion_authority.empty()) {
        return false;
    }
    const auto it = std::ranges::find_if(input.pending_deletion_authority,
                                         [&](const NodeRow& auth) {
                                             return auth == pending;
                                         });
    if (it == input.pending_deletion_authority.end()) {
        return false;
    }
    const auto* remote = find_row(input.storage.tree, pending.path);
    if (remote == nullptr || remote->is_directory ||
        remote->hash != pending.hash || remote->size != pending.size) {
        return false;
    }
    if (find_row(input.local_tree, pending.path) != nullptr) {
        return false;
    }
    if (local_sources.contains(pending.hash)) {
        return false;
    }
    if (!missing_objects.contains(pending.hash)) {
        return false;
    }
    return true;
}

Snapshot logical_local_view(const Input& input,
                            const HashSet& missing_objects,
                            const LocalSources& local_sources) {
    Snapshot result = input.local_tree;
    std::unordered_set<std::string> additions;
    for (const auto& pending : input.pending_materializations) {
        if (find_row(input.local_tree, pending.path) != nullptr) {
            continue;
        }
        if (is_eligible_for_deletion(
                input, pending, missing_objects, local_sources)) {
            continue;
        }
        bool safe = true;
        for (auto parent = row_parent(pending.path); !parent.empty();
             parent = row_parent(parent)) {
            const auto* actual = find_row(input.local_tree, parent);
            if (actual != nullptr) {
                if (!actual->is_directory) {
                    safe = false;
                    break;
                }
                continue;
            }
            const auto* accepted = find_row(input.base_tree, parent);
            if (accepted == nullptr || !accepted->is_directory) {
                safe = false;
                break;
            }
            additions.emplace(parent);
        }
        if (safe) {
            additions.emplace(pending.path);
        }
    }
    for (const auto& path : additions) {
        if (const auto* accepted = find_row(input.base_tree, path)) {
            result.rows.push_back(*accepted);
        }
    }
    std::ranges::sort(result.rows, path_less, &NodeRow::path);
    finalize_snapshot(result);
    return result;
}

void append_pending_materialization_downloads(
    const Input& input,
    const HashSet& missing_objects,
    std::vector<Operation>& operations) {
    for (const auto& pending : input.pending_materializations) {
        if (find_row(input.local_tree, pending.path) != nullptr) {
            continue;
        }
        const auto* remote = find_row(input.storage.tree, pending.path);
        if (remote == nullptr || remote->is_directory ||
            remote->hash != pending.hash || remote->size != pending.size ||
            missing_objects.contains(remote->hash)) {
            continue;
        }
        const auto already_scheduled =
            std::ranges::any_of(operations, [&](const Operation& operation) {
                return operation.action == Action::Download &&
                       operation.path ==
                           platform::path::from_utf8(remote->path) &&
                       operation.hash == hash_hex(remote->hash);
            });
        if (!already_scheduled) {
            operations.push_back(Operation{
                .action = Action::Download,
                .path = platform::path::from_utf8(remote->path),
                .hash = hash_hex(remote->hash),
                .alt_path = {},
                .size = remote->size,
                .exclusive_destination = false,
            });
        }
    }
}

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
                .detail = "ancestor not observed as directory",
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
                                   const Snapshot& storage_tree,
                                   std::vector<Operation>& operations) {
    std::unordered_set<std::string> reserved;
    std::unordered_set<std::string> reserved_case_keys;

    const std::size_t estimated_size =
        local_tree.rows.size() + storage_tree.rows.size() + operations.size();
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

    for (const auto& row : storage_tree.rows) {
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

void collect_pending_rows(
    const Snapshot& storage_tree,
    const HashSet& missing_objects,
    const LocalSources& local_sources,
    std::vector<NodeRow>& pending,
    std::vector<std::filesystem::path>& pending_without_local_source) {
    for (const auto& row : storage_tree.rows) {
        if (row.is_directory) {
            continue;
        }

        if (!missing_objects.contains(row.hash)) {
            continue;
        }

        pending.push_back(row);

        if (!local_sources.contains(row.hash)) {
            pending_without_local_source.push_back(
                platform::path::from_utf8(row.path));
        }
    }

    std::ranges::sort(pending_without_local_source, {}, [](const auto& path) {
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
                        .detail = "upload contains invalid hash",
                        .paths = {operation.path},
                    });
                }

                const auto source = find_local_row(operation);
                if (source == nullptr || source->is_directory ||
                    source->hash != *expected_hash ||
                    source->size != operation.size) {
                    return std::unexpected(Error{
                        .code = ErrorCode::UnsafePlan,
                        .detail = "upload does not match observed local row",
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
            case Action::MoveLocal: {
                const auto expected_hash = hash_from_hex(operation.hash);
                const auto source_path =
                    platform::path::to_logical_utf8(operation.path);
                const auto dest_path =
                    platform::path::to_logical_utf8(operation.alt_path);
                const auto* local_row = find_row(input.local_tree, source_path);
                const auto* storage_row =
                    find_row(input.storage.tree, dest_path);
                if (!expected_hash || local_row == nullptr ||
                    local_row->is_directory ||
                    local_row->hash != *expected_hash ||
                    local_row->size != operation.size ||
                    storage_row == nullptr || storage_row->is_directory ||
                    storage_row->hash != *expected_hash ||
                    storage_row->size != operation.size) {
                    return std::unexpected(Error{
                        .code = ErrorCode::UnsafePlan,
                        .detail = "local move does not match observed trees",
                        .paths = {operation.path, operation.alt_path},
                    });
                }
                break;
            }
            case Action::CopyLocal: {
                const auto expected_hash = hash_from_hex(operation.hash);
                const auto source_path =
                    platform::path::to_logical_utf8(operation.path);
                const auto dest_path =
                    platform::path::to_logical_utf8(operation.alt_path);
                const auto* local_row = find_row(input.local_tree, source_path);
                const auto* storage_row =
                    find_row(input.storage.tree, dest_path);
                if (!expected_hash || local_row == nullptr ||
                    local_row->is_directory ||
                    local_row->hash != *expected_hash ||
                    local_row->size != operation.size ||
                    storage_row == nullptr || storage_row->is_directory ||
                    storage_row->hash != *expected_hash ||
                    storage_row->size != operation.size) {
                    return std::unexpected(Error{
                        .code = ErrorCode::UnsafePlan,
                        .detail = "local copy does not match observed trees",
                        .paths = {operation.path, operation.alt_path},
                    });
                }
                break;
            }
            case Action::Download: {
                if (!operation.exclusive_destination) {
                    break;
                }

                const auto expected_hash = hash_from_hex(operation.hash);
                if (!expected_hash) {
                    return std::unexpected(Error{
                        .code = ErrorCode::UnsafePlan,
                        .detail = "conflict download contains invalid hash",
                        .paths = {operation.path},
                    });
                }

                const auto source_path =
                    platform::path::to_logical_utf8(operation.alt_path);
                const auto* source = find_row(input.storage.tree, source_path);
                if (source == nullptr || source->is_directory ||
                    source->hash != *expected_hash ||
                    source->size != operation.size) {
                    return std::unexpected(Error{
                        .code = ErrorCode::UnsafePlan,
                        .detail = "conflict download does not match observed "
                                  "storage row",
                        .paths = {operation.path},
                    });
                }

                auto row = *source;
                row.path = platform::path::to_logical_utf8(operation.path);
                auto parents = synchronize_ancestor_rows(result.tree,
                                                         input.local_tree,
                                                         row.path,
                                                         false,
                                                         &input.storage.tree);
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
                        .detail = "remote directory does not match local tree",
                        .paths = {operation.path},
                    });
                }
                const auto existing = find_row(result.tree, path);
                if (existing != nullptr && !existing->is_directory) {
                    const bool preserved_as_conflict = std::ranges::any_of(
                        sync_plan_operations(plan), [&](const Operation& op) {
                            return op.action == Action::Download &&
                                   op.exclusive_destination &&
                                   platform::path::to_logical_utf8(
                                       op.alt_path) == path;
                        });
                    if (!preserved_as_conflict) {
                        return std::unexpected(Error{
                            .code = ErrorCode::UnsafePlan,
                            .detail =
                                "remote directory creation conflicts with file",
                            .paths = {operation.path},
                        });
                    }
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
                        .detail = "remote removal does not match tree",
                        .paths = {operation.path},
                    });
                }
                erase_subtree(result.tree, path);
                auto ancestors = synchronize_ancestor_rows(result.tree,
                                                           input.local_tree,
                                                           path,
                                                           false,
                                                           &input.storage.tree);
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

const LocalDirectoryEvidence* find_directory_evidence(
    const LocalPhysicalEvidence& evidence,
    std::string_view path) {
    const auto found = std::ranges::lower_bound(
        evidence.directories, path, path_less, &LocalDirectoryEvidence::path);
    return found != evidence.directories.end() && found->path == path
               ? &*found
               : nullptr;
}

std::expected<Snapshot, Error> project_local_tree(
    Snapshot local_tree,
    const LocalPhysicalEvidence& physical_evidence,
    const Snapshot& desired_tree,
    ErrorCode error_code) {
    if (!kasumi::valid_snapshot(local_tree, false)) {
        return std::unexpected(Error{
            .code = error_code,
            .detail = "invalid local tree for managed projection",
            .paths = {},
        });
    }
    if (!kasumi::valid_snapshot(desired_tree, true)) {
        return std::unexpected(Error{
            .code = ErrorCode::InvalidStorageTree,
            .detail = "invalid desired tree for managed projection",
            .paths = {},
        });
    }

    std::unordered_set<std::string> retained_directories;
    std::vector<std::uint8_t> retained(local_tree.rows.size(), 0);
    for (std::size_t index = local_tree.rows.size(); index > 0; --index) {
        const auto row_index = index - 1;
        const auto& row = local_tree.rows[row_index];
        bool keep = !row.is_directory;
        if (row.is_directory) {
            const auto* evidence =
                find_directory_evidence(physical_evidence, row.path);
            const auto* desired = find_row(desired_tree, row.path);
            if (!row.path.empty() && evidence != nullptr &&
                evidence->has_unexpected_descendants &&
                (desired == nullptr || !desired->is_directory) &&
                !evidence->has_managed_descendants) {
                return std::unexpected(Error{
                    .code = error_code,
                    .detail =
                        "unexpected local entries prevent directory projection",
                    .paths = {platform::path::from_utf8(row.path)},
                });
            }
            keep = row.path.empty() || retained_directories.contains(row.path) ||
                   (desired != nullptr && desired->is_directory) ||
                   evidence == nullptr || !evidence->has_ignored_descendants ||
                   evidence->has_managed_descendants ||
                   evidence->physically_empty;
        }
        if (!keep) {
            continue;
        }
        retained[row_index] = 1;
        if (row.is_directory) {
            retained_directories.emplace(row.path);
        }
        if (!row.path.empty()) {
            retained_directories.emplace(row_parent(row.path));
        }
    }

    Snapshot projected;
    projected.rows.reserve(local_tree.rows.size());
    for (std::size_t index = 0; index < local_tree.rows.size(); ++index) {
        if (retained[index] != 0) {
            projected.rows.push_back(std::move(local_tree.rows[index]));
        }
    }
    finalize_snapshot(projected);
    if (!kasumi::valid_snapshot(projected, false)) {
        return std::unexpected(Error{
            .code = error_code,
            .detail = "managed local projection is invalid",
            .paths = {},
        });
    }
    return projected;
}

void suppress_protected_directory_deletions(
    std::vector<Operation>& operations,
    const LocalPhysicalEvidence& physical_evidence) {
    std::erase_if(operations, [&](const Operation& operation) {
        if (operation.action != Action::DeleteLocalDirectory) {
            return false;
        }
        const auto path =
            platform::path::to_logical_utf8(operation.path);
        const auto* evidence = find_directory_evidence(physical_evidence, path);
        return evidence != nullptr && evidence->has_ignored_descendants &&
               !evidence->has_unexpected_descendants;
    });
}

bool snapshot_contains_subtree(const Snapshot& tree, std::string_view path) {
    return std::ranges::any_of(tree.rows, [&](const NodeRow& row) {
        return row.path == path || is_descendant(row.path, path);
    });
}

struct DisposableSelection {
    std::vector<Operation> operations;
    std::vector<std::filesystem::path> paths_to_hash;
};

std::expected<DisposableSelection, Error> select_disposable_operations(
    const Input& input,
    const Snapshot& candidate_tree,
    const SyncPlan& current_plan) {
    DisposableSelection selection;
    if (!input.base_state_present || !input.storage.history_present ||
        input.storage.history_has_conflicts || has_conflicts(current_plan)) {
        if (!input.disposable_ignored_content.empty()) {
            return std::unexpected(Error{
                .code = ErrorCode::UnsafePlan,
                .detail = "disposable evidence has no authorized removal",
                .paths = {},
            });
        }
        return selection;
    }

    std::unordered_map<std::string, const DisposableIgnoredContent*> content;
    for (const auto& item : input.disposable_ignored_content) {
        if (item.path.empty() || !content.emplace(item.path, &item).second) {
            return std::unexpected(Error{
                .code = ErrorCode::UnsafePlan,
                .detail = "duplicate or empty disposable content evidence",
                .paths = {platform::path::from_utf8(item.path)},
            });
        }
    }

    std::vector<std::string> removal_roots;
    for (const auto& directory : input.local_physical_evidence.directories) {
        const auto* base = find_row(input.base_tree, directory.path);
        if (directory.path.empty() || directory.ignored_entry || base == nullptr ||
            !base->is_directory ||
            snapshot_contains_subtree(input.storage.tree, directory.path) ||
            snapshot_contains_subtree(candidate_tree, directory.path)) {
            continue;
        }
        removal_roots.push_back(directory.path);
    }
    std::ranges::sort(removal_roots, path_less);

    std::unordered_set<std::string> selected_files;
    std::unordered_set<std::string> selected_directories;
    std::vector<std::string> considered_roots;
    for (const auto& root : removal_roots) {
        if (std::ranges::any_of(considered_roots, [&](std::string_view parent) {
                return is_descendant(root, parent);
            })) {
            continue;
        }
        considered_roots.push_back(root);
        const auto* root_evidence =
            find_directory_evidence(input.local_physical_evidence, root);
        if (root_evidence == nullptr ||
            root_evidence->has_protected_descendants ||
            root_evidence->has_unexpected_descendants) {
            continue;
        }

        bool viable = true;
        bool has_disposable = false;
        std::unordered_set<std::string> root_files;
        std::unordered_set<std::string> root_directories;
        for (const auto& directory : input.local_physical_evidence.directories) {
            if (directory.path != root && !is_descendant(directory.path, root)) {
                continue;
            }
            const auto* base = find_row(input.base_tree, directory.path);
            if (directory.ignored_entry ||
                directory.has_protected_descendants ||
                directory.has_unexpected_descendants || base == nullptr ||
                !base->is_directory) {
                viable = false;
                break;
            }
            root_directories.insert(directory.path);
        }
        if (!viable) {
            continue;
        }

        for (const auto& ignored : input.local_physical_evidence.ignored_entries) {
            if (!is_descendant(ignored.path, root)) {
                continue;
            }
            if (ignored.kind != PhysicalEntryKind::RegularFile ||
                ignored.disposition !=
                    ignore::IgnoreDisposition::IgnoredDisposable ||
                ignore::classify_ignore(ignored.path, false, input.ignore_list) !=
                    ignore::IgnoreDisposition::IgnoredDisposable ||
                ignore::is_kasumiignore_path(ignored.path) ||
                ignore::is_reserved_internal(ignored.path)) {
                viable = false;
                break;
            }
            has_disposable = true;
            root_files.insert(ignored.path);
        }

        if (viable) {
            for (const auto& row : input.local_tree.rows) {
                if (row.is_directory || !is_descendant(row.path, root)) {
                    continue;
                }
                const bool removed_or_moved = std::ranges::any_of(
                    sync_plan_operations(current_plan), [&](const Operation& op) {
                        return (op.action == Action::DeleteLocal ||
                                op.action == Action::MoveLocal ||
                                op.action == Action::RenameLocal) &&
                               platform::path::to_logical_utf8(op.path) ==
                                   row.path;
                    });
                if (!removed_or_moved) {
                    viable = false;
                    break;
                }
            }
        }
        if (!viable || !has_disposable) {
            continue;
        }
        selected_files.insert(root_files.begin(), root_files.end());
        selected_directories.insert(root_directories.begin(),
                                    root_directories.end());
    }

    std::vector<std::string> candidate_paths(selected_files.begin(),
                                             selected_files.end());
    std::ranges::sort(candidate_paths, path_less);
    for (const auto& path : candidate_paths) {
        const auto found = content.find(path);
        if (found == content.end()) {
            selection.paths_to_hash.push_back(platform::path::from_utf8(path));
            continue;
        }
        const auto evidence = std::ranges::find(
            input.local_physical_evidence.ignored_entries,
            path,
            &IgnoredEntryEvidence::path);
        const auto hash = hash_from_hex(found->second->hash);
        if (evidence == input.local_physical_evidence.ignored_entries.end() ||
            !hash || hash_hex(*hash) != found->second->hash ||
            found->second->size != evidence->size ||
            found->second->identity != evidence->identity ||
            !found->second->identity.valid) {
            return std::unexpected(Error{
                .code = ErrorCode::UnsafePlan,
                .detail = "disposable content no longer matches physical evidence",
                .paths = {platform::path::from_utf8(path)},
            });
        }
    }
    if (!selection.paths_to_hash.empty()) {
        if (content.size() > candidate_paths.size()) {
            return std::unexpected(Error{
                .code = ErrorCode::UnsafePlan,
                .detail = "disposable evidence contains an unselected file",
                .paths = {},
            });
        }
        return selection;
    }
    if (content.size() != candidate_paths.size()) {
        return std::unexpected(Error{
            .code = ErrorCode::UnsafePlan,
            .detail = "disposable content evidence no longer matches candidates",
            .paths = {},
        });
    }

    for (const auto& path : candidate_paths) {
        const auto& item = *content.at(path);
        selection.operations.push_back(Operation{
            .action = Action::DeleteIgnoredLocalFile,
            .path = platform::path::from_utf8(path),
            .hash = item.hash,
            .size = item.size,
            .expected_source_identity = item.identity,
        });
    }
    for (const auto& path : selected_directories) {
        selection.operations.push_back(Operation{
            .action = Action::DeleteLocalDirectory,
            .path = platform::path::from_utf8(path),
        });
    }
    return selection;
}

std::expected<void, Error>
merge_pending_references(Snapshot& publication_tree,
                         std::span<const NodeRow> pending_rows,
                         const Snapshot& candidate_shared_tree) {
    for (const auto& pending : pending_rows) {
        if (pending.is_directory) {
            return std::unexpected(Error{
                .code = ErrorCode::InvalidStorageTree,
                .detail = "pending reference cannot "
                          "represent directory",
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

struct ContentIdentityKey {
    std::string hash;
    std::uint64_t size = 0;

    bool operator==(const ContentIdentityKey&) const noexcept = default;
};

struct ContentIdentityKeyHash {
    std::size_t operator()(const ContentIdentityKey& key) const noexcept {
        return std::hash<std::string>{}(key.hash) ^
               (std::hash<std::uint64_t>{}(key.size) << 1);
    }
};

struct SourceBucket {
    std::vector<std::size_t> indices;
    std::size_t cursor = 0;
};

void plan_local_moves(std::vector<Operation>& operations,
                      const Snapshot& local_tree) {
    const auto is_eligible_destination = [&](const Operation& op) {
        if (op.action != Action::Download || op.exclusive_destination ||
            !op.alt_path.empty() || op.path.empty() || op.hash.empty() ||
            !kasumi::has_safe_paths(op)) {
            return false;
        }
        const auto utf8_dest = platform::path::to_logical_utf8(op.path);
        if (utf8_dest.empty() ||
            utf8_dest.find(".kasumiconflict_") != std::string::npos ||
            find_row(local_tree, utf8_dest) != nullptr) {
            return false;
        }
        for (std::size_t slash = utf8_dest.find('/');
             slash != std::string::npos;
             slash = utf8_dest.find('/', slash + 1)) {
            const auto* ancestor =
                find_row(local_tree, utf8_dest.substr(0, slash));
            if (ancestor != nullptr && !ancestor->is_directory) {
                return false;
            }
        }
        return true;
    };

    bool has_eligible_destination = false;
    bool has_delete_local = false;
    for (const auto& op : operations) {
        if (op.action == Action::DeleteLocal) {
            has_delete_local = true;
        } else if (!has_eligible_destination && is_eligible_destination(op)) {
            has_eligible_destination = true;
        }
    }
    if (!has_eligible_destination || !has_delete_local) {
        return;
    }

    std::unordered_set<std::string> reserved_paths;
    for (const auto& op : operations) {
        if (op.action != Action::DeleteLocal &&
            op.action != Action::DeleteLocalDirectory) {
            reserved_paths.insert(platform::path::to_logical_utf8(op.path));
            if (!op.alt_path.empty()) {
                reserved_paths.insert(
                    platform::path::to_logical_utf8(op.alt_path));
            }
        }
    }

    std::unordered_map<ContentIdentityKey, SourceBucket, ContentIdentityKeyHash>
        candidates;
    std::unordered_set<std::string> seen_sources;
    for (std::size_t index = 0; index < operations.size(); ++index) {
        const auto& op = operations[index];
        if (op.action != Action::DeleteLocal || op.path.empty() ||
            !op.alt_path.empty() || op.exclusive_destination ||
            !kasumi::has_safe_paths(op)) {
            continue;
        }
        const auto utf8_path = platform::path::to_logical_utf8(op.path);
        if (utf8_path.empty() ||
            utf8_path.find(".kasumiconflict_") != std::string::npos ||
            reserved_paths.contains(utf8_path) ||
            !seen_sources.insert(utf8_path).second) {
            continue;
        }
        const auto* row = find_row(local_tree, utf8_path);
        if (row == nullptr || row->is_directory || row->hash == Hash{}) {
            continue;
        }
        candidates[ContentIdentityKey{.hash = hash_hex(row->hash),
                                      .size = row->size}]
            .indices.push_back(index);
    }
    if (candidates.empty()) {
        return;
    }

    for (auto& [key, bucket] : candidates) {
        std::ranges::sort(bucket.indices, [&](std::size_t a, std::size_t b) {
            return path_less(
                platform::path::to_logical_utf8(operations[a].path),
                platform::path::to_logical_utf8(operations[b].path));
        });
    }

    std::vector<std::uint8_t> consumed(operations.size(), 0);
    std::unordered_set<std::string> used_destinations;
    bool any_matched = false;
    for (std::size_t index = 0; index < operations.size(); ++index) {
        auto& op = operations[index];
        if (!is_eligible_destination(op)) {
            continue;
        }
        const auto utf8_dest = platform::path::to_logical_utf8(op.path);
        if (!used_destinations.insert(utf8_dest).second) {
            continue;
        }
        auto found = candidates.find(
            ContentIdentityKey{.hash = op.hash, .size = op.size});
        if (found == candidates.end() ||
            found->second.cursor >= found->second.indices.size()) {
            continue;
        }
        const auto source_index = found->second.indices[found->second.cursor++];
        auto source_path = std::move(operations[source_index].path);
        auto dest_path = std::move(op.path);
        auto expected_hash = std::move(op.hash);
        const auto expected_size = op.size;
        op = Operation{
            .action = Action::MoveLocal,
            .path = std::move(source_path),
            .hash = std::move(expected_hash),
            .alt_path = std::move(dest_path),
            .size = expected_size,
            .exclusive_destination = false,
        };
        consumed[source_index] = 1;
        any_matched = true;
    }

    if (any_matched) {
        std::size_t write_index = 0;
        for (std::size_t read_index = 0; read_index < operations.size();
             ++read_index) {
            if (consumed[read_index] != 0) {
                continue;
            }
            if (write_index != read_index) {
                operations[write_index] = std::move(operations[read_index]);
            }
            ++write_index;
        }
        operations.resize(write_index);
    }
}

void plan_local_copies(std::vector<Operation>& operations,
                       const Snapshot& local_tree) {
    const auto is_eligible_destination = [&](const Operation& op) {
        if (op.action != Action::Download || op.exclusive_destination ||
            !op.alt_path.empty() || op.path.empty() || op.hash.empty() ||
            !kasumi::has_safe_paths(op)) {
            return false;
        }
        const auto utf8_dest = platform::path::to_logical_utf8(op.path);
        if (utf8_dest.empty() ||
            utf8_dest.find(".kasumiconflict_") != std::string::npos ||
            find_row(local_tree, utf8_dest) != nullptr) {
            return false;
        }
        for (std::size_t slash = utf8_dest.find('/');
             slash != std::string::npos;
             slash = utf8_dest.find('/', slash + 1)) {
            const auto* ancestor =
                find_row(local_tree, utf8_dest.substr(0, slash));
            if (ancestor != nullptr && !ancestor->is_directory) {
                return false;
            }
        }
        return true;
    };

    bool has_eligible_destination = false;
    for (const auto& op : operations) {
        if (is_eligible_destination(op)) {
            has_eligible_destination = true;
            break;
        }
    }
    if (!has_eligible_destination) {
        return;
    }

    std::vector<std::string> renamed_sources;
    for (const auto& operation : operations) {
        if (operation.action == Action::RenameLocal)
            renamed_sources.push_back(
                platform::path::to_logical_utf8(operation.path));
    }

    std::unordered_map<ContentIdentityKey,
                       std::vector<std::string>,
                       ContentIdentityKeyHash>
        candidates;
    for (const auto& row : local_tree.rows) {
        if (row.is_directory || row.hash == Hash{} || row.path.empty() ||
            row.path.find(".kasumiconflict_") != std::string::npos) {
            continue;
        }
        // Copies run after conflict renames, so their sources must survive.
        if (std::ranges::any_of(renamed_sources, [&](std::string_view source) {
                return row.path == source || is_descendant(row.path, source);
            })) {
            continue;
        }
        Operation check_op{
            .action = Action::CopyLocal,
            .path = platform::path::from_utf8(row.path),
            .hash = hash_hex(row.hash),
            .alt_path = "dest.txt",
            .size = row.size,
        };
        if (!kasumi::has_safe_paths(check_op)) {
            continue;
        }
        candidates[ContentIdentityKey{.hash = hash_hex(row.hash),
                                      .size = row.size}]
            .push_back(row.path);
    }
    if (candidates.empty()) {
        return;
    }

    for (auto& [key, paths] : candidates) {
        std::ranges::sort(paths, path_less);
    }

    std::unordered_set<std::string> used_destinations;
    for (auto& op : operations) {
        if (!is_eligible_destination(op)) {
            continue;
        }
        const auto utf8_dest = platform::path::to_logical_utf8(op.path);
        if (!used_destinations.insert(utf8_dest).second) {
            continue;
        }
        auto found = candidates.find(
            ContentIdentityKey{.hash = op.hash, .size = op.size});
        if (found == candidates.end() || found->second.empty()) {
            continue;
        }
        const auto& best_source = found->second.front();
        auto dest_path = std::move(op.path);
        auto expected_hash = std::move(op.hash);
        const auto expected_size = op.size;
        op = Operation{
            .action = Action::CopyLocal,
            .path = platform::path::from_utf8(best_source),
            .hash = std::move(expected_hash),
            .alt_path = std::move(dest_path),
            .size = expected_size,
            .exclusive_destination = false,
        };
    }
}

} // namespace

bool has_safe_paths(const SyncPlan& plan) {
    const auto operations = sync_plan_operations(plan);
    if (!std::ranges::all_of(operations, [](const Operation& operation) {
            return kasumi::has_safe_paths(operation);
        })) {
        return false;
    }

    std::unordered_set<std::string> move_sources;
    std::unordered_set<std::string> move_destinations;
    for (const auto& operation : operations) {
        if (operation.action != Action::MoveLocal) {
            continue;
        }
        if (operation.path.empty() || operation.alt_path.empty() ||
            operation.path == operation.alt_path || operation.hash.empty() ||
            operation.exclusive_destination) {
            return false;
        }
        const auto source = platform::path::to_logical_utf8(operation.path);
        const auto destination =
            platform::path::to_logical_utf8(operation.alt_path);
        if (source.empty() || destination.empty() || source == destination ||
            !move_sources.insert(source).second ||
            !move_destinations.insert(destination).second) {
            return false;
        }
    }

    std::unordered_set<std::string> copy_destinations;
    for (const auto& operation : operations) {
        if (operation.action != Action::CopyLocal) {
            continue;
        }
        if (operation.path.empty() || operation.alt_path.empty() ||
            operation.path == operation.alt_path || operation.hash.empty() ||
            operation.exclusive_destination) {
            return false;
        }
        const auto source = platform::path::to_logical_utf8(operation.path);
        const auto destination =
            platform::path::to_logical_utf8(operation.alt_path);
        if (source.empty() || destination.empty() || source == destination ||
            !copy_destinations.insert(destination).second) {
            return false;
        }
    }
    return true;
}

std::expected<Snapshot, Error>
build_publication_tree(Snapshot publication_tree,
                       std::span<const NodeRow> pending_storage_rows,
                       const Snapshot& candidate_shared_tree,
                       const LocalPhysicalEvidence& local_physical_evidence) {
    if (!kasumi::valid_snapshot(publication_tree, false)) {
        return std::unexpected(Error{
            .code = ErrorCode::InvalidExecutedTree,
            .detail = "observed local tree "
                      "after execution is invalid",
            .paths = {},
        });
    }

    if (!kasumi::valid_snapshot(candidate_shared_tree, false)) {
        return std::unexpected(Error{
            .code = ErrorCode::UnsafePlan,
            .detail = "invalid candidate tree",
            .paths = {},
        });
    }

    auto projected = project_local_tree(std::move(publication_tree),
                                        local_physical_evidence,
                                        candidate_shared_tree,
                                        ErrorCode::InvalidExecutedTree);
    if (!projected) {
        return std::unexpected(std::move(projected.error()));
    }
    publication_tree = std::move(*projected);

    auto merged = merge_pending_references(
        publication_tree, pending_storage_rows, candidate_shared_tree);

    if (!merged) {
        return std::unexpected(std::move(merged.error()));
    }

    return publication_tree;
}

ReconcileResult reconcile(const Input& input) {
    if (input.ignore_list.parse_error) {
        const auto& parse_error = *input.ignore_list.parse_error;
        return std::unexpected(Error{
            .code = ErrorCode::InvalidLocalTree,
            .detail = parse_error.line == 0
                          ? ".kasumiignore: " + parse_error.detail
                          : ".kasumiignore line " +
                                std::to_string(parse_error.line) + ": " +
                                parse_error.detail,
            .paths = {platform::path::from_utf8(".kasumiignore")},
        });
    }
    if (!kasumi::valid_snapshot(input.local_tree, false)) {
        return std::unexpected(invalid_tree_error(ErrorCode::InvalidLocalTree,
                                                  "invalid local tree"));
    }

    if (!kasumi::valid_snapshot(input.base_tree, true)) {
        return std::unexpected(invalid_tree_error(ErrorCode::InvalidBaseTree,
                                                  "invalid base tree"));
    }

    if (input.storage.history_present &&
        !kasumi::valid_snapshot(input.storage.tree, false)) {
        return std::unexpected(invalid_tree_error(ErrorCode::InvalidStorageTree,
                                                  "invalid storage tree"));
    }

    if (!input.storage.history_present &&
        !kasumi::valid_snapshot(input.storage.tree, true)) {
        return std::unexpected(invalid_tree_error(ErrorCode::InvalidStorageTree,
                                                  "invalid storage tree"));
    }

    if (input.base_state_present && !input.storage.history_present) {
        return std::unexpected(Error{
            .code = ErrorCode::MissingStorageHistory,
            .detail = "remote history is missing for the persisted local base",
            .paths = {},
        });
    }

    if (!valid_pending_rows(input)) {
        return std::unexpected(invalid_tree_error(
            ErrorCode::InvalidLocalBaseState,
            "pending materializations do not match the accepted base"));
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
            .detail = "maximum height cannot receive another commit",
            .paths = {},
        });
    }

    HashSet missing_objects{0, hash_key};

    if (input.audit_storage_objects && !effective_storage_tree.rows.empty()) {
        diff::detail::find_missing_blocks(effective_storage_tree,
                                          input.storage.object_identifiers,
                                          missing_objects);
    }
    missing_objects.insert(input.known_missing_content_objects.begin(),
                           input.known_missing_content_objects.end());

    LocalSources local_sources{0, hash_key};

    collect_local_sources(input.local_tree, local_sources);

    std::vector<NodeRow> pending_storage_rows;

    std::vector<std::filesystem::path> pending_without_local_source;

    collect_pending_rows(effective_storage_tree,
                         missing_objects,
                         local_sources,
                         pending_storage_rows,
                         pending_without_local_source);
    if (!input.pending_deletion_authority.empty()) {
        for (const auto& pending : input.pending_materializations) {
            const auto* remote = find_row(effective_storage_tree, pending.path);
            if (remote != nullptr && !remote->is_directory &&
                remote->hash == pending.hash && remote->size == pending.size &&
                find_row(input.local_tree, pending.path) == nullptr &&
                !local_sources.contains(pending.hash) &&
                std::ranges::none_of(pending_storage_rows,
                                     [&](const NodeRow& row) {
                                         return row.path == pending.path;
                                     })) {
                pending_storage_rows.push_back(*remote);
            }
        }
        std::ranges::sort(pending_storage_rows, path_less, &NodeRow::path);
    }

    auto logical_local =
        logical_local_view(input, missing_objects, local_sources);
    auto projected_local = project_local_tree(
        std::move(logical_local),
        input.local_physical_evidence,
        effective_storage_tree,
        ErrorCode::InvalidLocalTree);
    if (!projected_local) {
        return std::unexpected(std::move(projected_local.error()));
    }
    Input projected_input = input;
    projected_input.local_tree = *projected_local;
    const std::unordered_set<std::string>* authorized_deletions_ptr = nullptr;
    std::unordered_set<std::string> authorized_deletion_paths;
    if (!input.pending_deletion_authority.empty()) {
        for (const auto& pending : input.pending_materializations) {
            if (is_eligible_for_deletion(
                    input, pending, missing_objects, local_sources)) {
                authorized_deletion_paths.insert(pending.path);
            }
        }
        authorized_deletions_ptr = &authorized_deletion_paths;
    }
    auto operations = diff::compare_trees(*projected_local,
                                          input.base_tree,
                                          effective_storage_tree,
                                          missing_objects,
                                          &input.ignore_list,
                                          authorized_deletions_ptr);

    std::erase_if(operations, [&](const Operation& operation) {
        if (operation.action != Action::Upload ||
            find_row(input.local_tree,
                     platform::path::to_logical_utf8(operation.path)) !=
                nullptr) {
            return false;
        }
        return std::ranges::any_of(
            input.pending_materializations, [&](const NodeRow& pending) {
                return pending.path ==
                       platform::path::to_logical_utf8(operation.path);
            });
    });
    if (input.pending_deletion_authority.empty()) {
        append_pending_materialization_downloads(
            input, missing_objects, operations);
    }

    reserve_conflict_destinations(
        input.local_tree, effective_storage_tree, operations);

    std::vector<std::string> repair_upload_paths;
    if (input.pending_deletion_authority.empty()) {
        append_recovery_uploads(
            missing_objects, local_sources, operations, repair_upload_paths);
        // A repairable remote gap must not discard local materializations.
        for (const auto& row : pending_storage_rows) {
            const auto source = local_sources.find(row.hash);
            if (find_row(input.local_tree, row.path) == nullptr &&
                source != local_sources.end() && source->second.size == row.size) {
                operations.push_back(Operation{
                    .action = Action::Download,
                    .path = platform::path::from_utf8(row.path),
                    .hash = hash_hex(row.hash),
                    .size = row.size,
                });
            }
        }
    }

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

    plan_local_moves(operations, input.local_tree);
    plan_local_copies(operations, input.local_tree);
    suppress_protected_directory_deletions(
        operations, input.local_physical_evidence);

    auto plan = make_sync_plan(std::move(operations), 0);

    order_directory_operations(plan);

    if (!valid_sync_plan(plan) || !has_safe_paths(plan)) {
        return std::unexpected(Error{
            .code = ErrorCode::UnsafePlan,
            .detail = "plan contains invalid paths "
                      "or phases",
            .paths = {},
        });
    }

    auto candidate = candidate_shared_tree(
        projected_input, plan, std::span<const std::string>{repair_upload_paths});
    if (!candidate) {
        return std::unexpected(std::move(candidate.error()));
    }
    auto disposable = select_disposable_operations(
        input, candidate->tree, plan);
    if (!disposable) {
        return std::unexpected(std::move(disposable.error()));
    }
    auto disposable_paths_to_hash = std::move(disposable->paths_to_hash);
    if (!disposable->operations.empty()) {
        auto final_operations = plan.operations;
        final_operations.insert(final_operations.end(),
                                std::make_move_iterator(
                                    disposable->operations.begin()),
                                std::make_move_iterator(
                                    disposable->operations.end()));
        plan = make_sync_plan(std::move(final_operations), 0);
        order_directory_operations(plan);
        if (!valid_sync_plan(plan) || !has_safe_paths(plan)) {
            return std::unexpected(Error{
                .code = ErrorCode::UnsafePlan,
                .detail = "disposable plan contains invalid paths or phases",
                .paths = {},
            });
        }
        candidate = candidate_shared_tree(
            projected_input,
            plan,
            std::span<const std::string>{repair_upload_paths});
        if (!candidate) {
            return std::unexpected(std::move(candidate.error()));
        }
    }
    std::erase_if(pending_storage_rows, [&](NodeRow& pending) {
        const auto* candidate_row = find_row(candidate->tree, pending.path);
        if (candidate_row == nullptr || candidate_row->is_directory ||
            candidate_row->hash != pending.hash ||
            candidate_row->size != pending.size) {
            return true;
        }
        pending = *candidate_row;
        return false;
    });
    std::vector<NodeRow> pending_materializations;
    for (const auto& row : pending_storage_rows) {
        if (!local_sources.contains(row.hash)) {
            pending_materializations.push_back(row);
        }
    }
    std::erase_if(pending_without_local_source, [&](const auto& path) {
        const auto utf8 = platform::path::to_logical_utf8(path);
        return std::ranges::none_of(pending_storage_rows, [&](const auto& r) {
            return r.path == utf8;
        });
    });
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
    const bool requires_local_mutation = std::ranges::any_of(
        sync_plan_operations(plan), [](const Operation& operation) {
            return is_local_mutation(operation.action);
        });

    const bool requires_state_commit =
        input.storage.history_present &&
        (!input.base_state_present || input.storage.logical_heads.size() != 1 ||
         input.base_commit_id != input.storage.logical_heads.front() ||
         input.pending_materializations != pending_materializations);

    return Result{
        .plan = std::move(plan),
        .missing_objects = std::move(missing_objects),
        .disposable_paths_to_hash = std::move(disposable_paths_to_hash),
        .pending_storage_rows = std::move(pending_storage_rows),
        .pending_materializations = std::move(pending_materializations),
        .missing_content_paths_without_local_source =
            std::move(pending_without_local_source),
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
