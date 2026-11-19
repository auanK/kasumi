#include "core/diff.hpp"

#include "platform/path.hpp"

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <ranges>

namespace kasumi::diff {

namespace detail {

void find_missing_blocks(const Snapshot& snapshot,
                         const std::unordered_set<std::string>& physical_blocks,
                         HashSet& missing) {
    for (const auto& row : snapshot.rows) {
        if (!row.is_directory &&
            !physical_blocks.contains(hash_hex(row.hash))) {
            missing.insert(row.hash);
        }
    }
}

} // namespace detail

namespace {

struct ChildCursor {
    const Snapshot* snapshot = nullptr;
    std::size_t index = 0;
    std::string_view parent;
};

ChildCursor children(const Snapshot* snapshot, std::string_view parent) {
    if (!snapshot)
        return {};
    auto position = std::ranges::lower_bound(
        snapshot->rows, parent, path_less, &NodeRow::path);
    if (position != snapshot->rows.end() && position->path == parent)
        ++position;
    return {snapshot,
            static_cast<std::size_t>(position - snapshot->rows.begin()),
            parent};
}

const NodeRow* peek(const ChildCursor& cursor) {
    if (!cursor.snapshot || cursor.index >= cursor.snapshot->rows.size())
        return nullptr;
    const auto& row = cursor.snapshot->rows[cursor.index];
    return is_descendant(row.path, cursor.parent) &&
                   row_parent(row.path) == cursor.parent
               ? &row
               : nullptr;
}

void advance(ChildCursor& cursor) {
    const auto* row = peek(cursor);
    if (!row)
        return;
    const std::string_view path = row->path;
    const auto begin = cursor.snapshot->rows.begin();
    const auto next = std::ranges::partition_point(
        std::ranges::subrange(begin +
                                  static_cast<std::ptrdiff_t>(cursor.index + 1),
                              cursor.snapshot->rows.end()),
        [&](const NodeRow& candidate) {
            return is_descendant(candidate.path, path);
        });
    cursor.index = static_cast<std::size_t>(next - begin);
}

bool same_hash(const NodeRow* left, const NodeRow* right) {
    return (!left && !right) ||
           (left && right && left->is_directory == right->is_directory &&
            left->hash == right->hash);
}

void compare_nodes_3way(
    const Snapshot* local_snapshot,
    const Snapshot* base_snapshot,
    const Snapshot* cloud_snapshot,
    const NodeRow* local,
    const NodeRow* base,
    const NodeRow* cloud,
    std::string_view current_path,
    const HashSet& missing_blocks,
    std::vector<SyncOperation>& ops,
    const ignore::IgnoreList* ignore_list,
    const std::unordered_set<std::string>* authorized_deletions) {
    if (!local && !base && !cloud)
        return;
    if (same_hash(local, cloud) && missing_blocks.empty())
        return;

    auto local_children = children(
        local && local->is_directory ? local_snapshot : nullptr, current_path);
    auto base_children = children(
        base && base->is_directory ? base_snapshot : nullptr, current_path);
    auto cloud_children = children(
        cloud && cloud->is_directory ? cloud_snapshot : nullptr, current_path);
    while (true) {
        const auto* next_l = peek(local_children);
        const auto* next_b = peek(base_children);
        const auto* next_c = peek(cloud_children);
        if (!next_l && !next_b && !next_c)
            break;

        std::string_view name = next_l   ? row_name(next_l->path)
                                : next_b ? row_name(next_b->path)
                                         : row_name(next_c->path);
        if (next_b && row_name(next_b->path) < name)
            name = row_name(next_b->path);
        if (next_c && row_name(next_c->path) < name)
            name = row_name(next_c->path);
        const auto* l =
            next_l && row_name(next_l->path) == name ? next_l : nullptr;
        const auto* b =
            next_b && row_name(next_b->path) == name ? next_b : nullptr;
        const auto* c =
            next_c && row_name(next_c->path) == name ? next_c : nullptr;
        if (l)
            advance(local_children);
        if (b)
            advance(base_children);
        if (c)
            advance(cloud_children);
        const std::string_view path = l ? l->path : b ? b->path : c->path;
        const auto target = platform::path::from_utf8(path);
        const bool is_dir = (c && c->is_directory) || (l && l->is_directory) ||
                            (b && b->is_directory);
        const auto recurse =
            [&](const NodeRow* nl, const NodeRow* nb, const NodeRow* nc) {
                compare_nodes_3way(local_snapshot,
                                   base_snapshot,
                                   cloud_snapshot,
                                   nl,
                                   nb,
                                   nc,
                                   path,
                                   missing_blocks,
                                   ops,
                                   ignore_list,
                                   authorized_deletions);
            };

        const auto add_op = [&](Action action,
                                const std::filesystem::path& op_path,
                                std::string op_hash = {},
                                const std::filesystem::path& alt = {},
                                std::uint64_t op_size = 0,
                                bool exclusive = false) {
            ops.push_back(SyncOperation{.action = action,
                                        .path = op_path,
                                        .hash = std::move(op_hash),
                                        .alt_path = alt,
                                        .size = op_size,
                                        .exclusive_destination = exclusive});
        };
        const auto ignored =
            ignore_list != nullptr
                ? kasumi::ignore::is_ignored(path, *ignore_list, is_dir)
                : kasumi::ignore::is_reserved_internal(path);

        if (ignored) {
            if (c) {
                add_op(c->is_directory ? Action::DeleteRemoteDirectory
                                       : Action::DeleteRemote,
                       target,
                       c->is_directory ? "" : hash_hex(c->hash));
            }
            continue;
        }

        if (c && !c->is_directory && missing_blocks.contains(c->hash)) {
            if (authorized_deletions != nullptr &&
                authorized_deletions->contains(std::string(path))) {
                // Authorized for deletion: allow 3-way merge to emit
                // DeleteRemote
            } else {
                if (authorized_deletions == nullptr && l && !l->is_directory) {
                    add_op(
                        Action::Upload, target, hash_hex(l->hash), {}, l->size);
                }
                continue;
            }
        }
        if (same_hash(l, c)) {
            if (l && c && l->is_directory && c->is_directory)
                recurse(l, b, c);
            continue;
        }
        if (same_hash(l, b)) {
            if (!c) {
                if (l && l->is_directory) {
                    recurse(l, b, nullptr);
                }
                add_op(l && l->is_directory ? Action::DeleteLocalDirectory
                                            : Action::DeleteLocal,
                       target);
            } else {
                if (c->is_directory) {
                    if (!l || !l->is_directory) {
                        const NodeRow* conflict_artifact = nullptr;
                        if (l && cloud_snapshot) {
                            for (const auto& row : cloud_snapshot->rows) {
                                if (!row.is_directory && row.hash == l->hash &&
                                    row.path.starts_with(path) &&
                                    std::string_view(row.path)
                                        .substr(path.size())
                                        .starts_with(".kasumiconflict_")) {
                                    conflict_artifact = &row;
                                    break;
                                }
                            }
                        }
                        if (conflict_artifact != nullptr) {
                            add_op(Action::RenameLocal,
                                   target,
                                   "",
                                   platform::path::from_utf8(
                                       conflict_artifact->path));
                        } else if (l != nullptr) {
                            add_op(Action::DeleteLocal, target);
                        }
                        add_op(Action::CreateLocalDirectory, target);
                    }
                } else {
                    if (l && l->is_directory) {
                        recurse(l, b, nullptr);
                        add_op(Action::DeleteLocalDirectory, target);
                    }
                    add_op(Action::Download,
                           target,
                           hash_hex(c->hash),
                           {},
                           c->size);
                }
                if (c->is_directory)
                    recurse(l, b, c);
            }
        } else if (same_hash(c, b)) {
            if (!l) {
                add_op(b && b->is_directory ? Action::DeleteRemoteDirectory
                                            : Action::DeleteRemote,
                       target,
                       b ? hash_hex(b->hash) : "");
            } else {
                if (l->is_directory) {
                    if (c && !c->is_directory)
                        add_op(Action::DeleteRemote, target, hash_hex(c->hash));
                    if (!c || !c->is_directory)
                        add_op(Action::CreateRemoteDirectory, target);
                } else {
                    if (c && c->is_directory)
                        add_op(Action::DeleteRemoteDirectory, target);
                    add_op(
                        Action::Upload, target, hash_hex(l->hash), {}, l->size);
                }
                if (l->is_directory)
                    recurse(l, b, c);
            }
        } else if (!l && c) {
            const bool already_relocated =
                std::ranges::any_of(ops, [&](const SyncOperation& op) {
                    return op.action == Action::RenameLocal &&
                           op.alt_path == target;
                });
            if (already_relocated) {
                continue;
            }
            add_op(c->is_directory ? Action::CreateLocalDirectory
                                   : Action::Download,
                   target,
                   c->is_directory ? "" : hash_hex(c->hash),
                   {},
                   c->size);
            recurse(l, b, c);
        } else if (l && !c) {
            add_op(l->is_directory ? Action::CreateRemoteDirectory
                                   : Action::Upload,
                   target,
                   l->is_directory ? "" : hash_hex(l->hash),
                   {},
                   l->is_directory ? 0 : l->size);
            recurse(l, b, c);
        } else if (l && c && l->is_directory != c->is_directory) {
            const auto conflict_path = [&](const char* suffix) {
                return platform::path::from_utf8(
                    make_conflict_path(path, suffix));
            };
            const auto download_remote_conflict =
                [&](const std::filesystem::path& conflict_target) {
                    add_op(Action::Download,
                           conflict_path(".kasumiconflict_remote"),
                           hash_hex(c->hash),
                           conflict_target,
                           c->size,
                           true);
                };
            if (l->is_directory) {
                add_op(Action::CreateRemoteDirectory, target);
                download_remote_conflict(target);
                recurse(l, nullptr, nullptr);
            } else {
                const auto conflict = conflict_path(".kasumiconflict_local");
                add_op(Action::RenameLocal, target, "", conflict, 0, true);
                add_op(
                    Action::Upload, conflict, hash_hex(l->hash), {}, l->size);
                add_op(Action::CreateLocalDirectory, target);
                recurse(nullptr, nullptr, c);
            }
        } else if (l && c && !l->is_directory) {
            if (l->mtime > c->mtime) {
                add_op(Action::Upload, target, hash_hex(l->hash), {}, l->size);
                add_op(Action::Download,
                       platform::path::from_utf8(
                           make_conflict_path(path, ".kasumiconflict_remote")),
                       hash_hex(c->hash),
                       target,
                       c->size,
                       true);
            } else {
                const auto conflict = platform::path::from_utf8(
                    make_conflict_path(path, ".kasumiconflict_local"));
                add_op(Action::RenameLocal, target, "", conflict, 0, true);
                add_op(
                    Action::Download, target, hash_hex(c->hash), {}, c->size);
                add_op(
                    Action::Upload, conflict, hash_hex(l->hash), {}, l->size);
            }
        } else {
            recurse(l, b, c);
        }
    }
}

} // namespace

std::vector<SyncOperation>
compare_trees(const Snapshot& local,
              const Snapshot& base,
              const Snapshot& cloud,
              const HashSet& missing_blocks,
              const ignore::IgnoreList* ignore_list,
              const std::unordered_set<std::string>* authorized_deletions) {
    std::vector<SyncOperation> operations;
    compare_nodes_3way(&local,
                       &base,
                       &cloud,
                       find_row(local, ""),
                       find_row(base, ""),
                       find_row(cloud, ""),
                       "",
                       missing_blocks,
                       operations,
                       ignore_list,
                       authorized_deletions);
    return operations;
}

std::vector<SyncOperation>
compare_trees(const Snapshot& local,
              const Snapshot& base,
              const Snapshot& cloud,
              const ignore::IgnoreList* ignore_list) {
    const HashSet missing_blocks(0, hash_key);
    return compare_trees(local, base, cloud, missing_blocks, ignore_list);
}

} // namespace kasumi::diff
