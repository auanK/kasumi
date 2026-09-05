#include "core/diff.hpp"

#include "platform/path.hpp"

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <ranges>

namespace kasumi::diff {

namespace detail {

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
    return (!left && !right) || (left && right && left->hash == right->hash);
}

void find_missing_blocks(const Snapshot& snapshot,
                         const std::unordered_set<std::string>& physical_blocks,
                         HashSet& missing) {
    for (const auto& row : snapshot.rows) {
        if (row.is_directory)
            continue;
        if (!physical_blocks.contains(hash_hex(row.hash)))
            missing.insert(row.hash);
    }
}

void compare_nodes_3way(const Snapshot* local_snapshot,
                        const Snapshot* base_snapshot,
                        const Snapshot* cloud_snapshot,
                        const NodeRow* local,
                        const NodeRow* base,
                        const NodeRow* cloud,
                        std::string_view current_path,
                        const HashSet& missing_blocks,
                        std::vector<SyncOperation>& ops) {
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

        if (c && !c->is_directory && missing_blocks.contains(c->hash)) {
            if (l && !l->is_directory)
                ops.push_back(
                    {Action::Upload, target, hash_hex(l->hash), {}, l->size});
            continue;
        }
        if (same_hash(l, c)) {
            if (l && c && l->is_directory && c->is_directory)
                compare_nodes_3way(local_snapshot,
                                   base_snapshot,
                                   cloud_snapshot,
                                   l,
                                   b,
                                   c,
                                   path,
                                   missing_blocks,
                                   ops);
            continue;
        }
        if (same_hash(l, b)) {
            if (!c) {
                if (l && l->is_directory) {
                    compare_nodes_3way(local_snapshot,
                                       base_snapshot,
                                       cloud_snapshot,
                                       l,
                                       b,
                                       nullptr,
                                       path,
                                       missing_blocks,
                                       ops);
                }
                ops.push_back({l && l->is_directory
                                   ? Action::DeleteLocalDirectory
                                   : Action::DeleteLocal,
                               target,
                               "",
                               {}});
            } else {
                if (c->is_directory) {
                    if (!l || !l->is_directory)
                        ops.push_back(
                            {Action::CreateLocalDirectory, target, "", {}});
                } else {
                    ops.push_back({Action::Download,
                                   target,
                                   hash_hex(c->hash),
                                   {},
                                   c->size});
                }
                if ((l && l->is_directory) || c->is_directory)
                    compare_nodes_3way(local_snapshot,
                                       base_snapshot,
                                       cloud_snapshot,
                                       l,
                                       b,
                                       c,
                                       path,
                                       missing_blocks,
                                       ops);
            }
        } else if (same_hash(c, b)) {
            if (!l) {
                ops.push_back({b && b->is_directory
                                   ? Action::DeleteRemoteDirectory
                                   : Action::DeleteRemote,
                               target,
                               b ? hash_hex(b->hash) : "",
                               {}});
            } else {
                if (l->is_directory) {
                    if (!c || !c->is_directory)
                        ops.push_back(
                            {Action::CreateRemoteDirectory, target, "", {}});
                } else {
                    ops.push_back({Action::Upload,
                                   target,
                                   hash_hex(l->hash),
                                   {},
                                   l->size});
                }
                if ((c && c->is_directory) || l->is_directory)
                    compare_nodes_3way(local_snapshot,
                                       base_snapshot,
                                       cloud_snapshot,
                                       l,
                                       b,
                                       c,
                                       path,
                                       missing_blocks,
                                       ops);
            }
        } else if (!l && c) {
            ops.push_back({c->is_directory ? Action::CreateLocalDirectory
                                           : Action::Download,
                           target,
                           c->is_directory ? "" : hash_hex(c->hash),
                           {},
                           c->size});
            compare_nodes_3way(local_snapshot,
                               base_snapshot,
                               cloud_snapshot,
                               l,
                               b,
                               c,
                               path,
                               missing_blocks,
                               ops);
        } else if (l && !c) {
            ops.push_back({l->is_directory ? Action::CreateRemoteDirectory
                                           : Action::Upload,
                           target,
                           l->is_directory ? "" : hash_hex(l->hash),
                           {},
                           l->is_directory ? 0 : l->size});
            compare_nodes_3way(local_snapshot,
                               base_snapshot,
                               cloud_snapshot,
                               l,
                               b,
                               c,
                               path,
                               missing_blocks,
                               ops);
        } else if (l && c && l->is_directory != c->is_directory) {
            if (l->mtime > c->mtime) {
                ops.push_back(
                    {Action::DeleteRemote, target, hash_hex(c->hash), {}});
                compare_nodes_3way(local_snapshot,
                                   base_snapshot,
                                   cloud_snapshot,
                                   l,
                                   nullptr,
                                   nullptr,
                                   path,
                                   missing_blocks,
                                   ops);
            } else if (l->is_directory) {
                ops.push_back({Action::Download,
                               platform::path::from_utf8(make_conflict_path(
                                   path, ".kasumiconflict_remote")),
                               hash_hex(c->hash),
                               {},
                               c->size,
                               true});
                compare_nodes_3way(local_snapshot,
                                   base_snapshot,
                                   cloud_snapshot,
                                   l,
                                   nullptr,
                                   nullptr,
                                   path,
                                   missing_blocks,
                                   ops);
            } else {
                if (c->is_directory)
                    ops.push_back(
                        {Action::CreateLocalDirectory, target, "", {}});
                else {
                    ops.push_back({Action::DeleteLocal, target, "", {}});
                    ops.push_back({Action::Download,
                                   target,
                                   hash_hex(c->hash),
                                   {},
                                   c->size});
                }
                compare_nodes_3way(local_snapshot,
                                   base_snapshot,
                                   cloud_snapshot,
                                   nullptr,
                                   nullptr,
                                   c,
                                   path,
                                   missing_blocks,
                                   ops);
            }
        } else if (l && c && !l->is_directory) {
            if (l->mtime > c->mtime) {
                ops.push_back(
                    {Action::Upload, target, hash_hex(l->hash), {}, l->size});
                ops.push_back({Action::Download,
                               platform::path::from_utf8(make_conflict_path(
                                   path, ".kasumiconflict_remote")),
                               hash_hex(c->hash),
                               {},
                               c->size,
                               true});
            } else {
                const auto conflict = platform::path::from_utf8(
                    make_conflict_path(path, ".kasumiconflict_local"));
                ops.push_back(
                    {Action::RenameLocal, target, "", conflict, 0, true});
                ops.push_back(
                    {Action::Download, target, hash_hex(c->hash), {}, c->size});
                ops.push_back(
                    {Action::Upload, conflict, hash_hex(l->hash), {}, l->size});
            }
        } else {
            compare_nodes_3way(local_snapshot,
                               base_snapshot,
                               cloud_snapshot,
                               l,
                               b,
                               c,
                               path,
                               missing_blocks,
                               ops);
        }
    }
}

} // namespace detail

std::vector<SyncOperation> compare_trees(const Snapshot& local,
                                         const Snapshot& base,
                                         const Snapshot& cloud,
                                         const HashSet& missing_blocks) {
    std::vector<SyncOperation> operations;
    detail::compare_nodes_3way(&local,
                               &base,
                               &cloud,
                               find_row(local, ""),
                               find_row(base, ""),
                               find_row(cloud, ""),
                               "",
                               missing_blocks,
                               operations);
    return operations;
}

std::vector<SyncOperation> compare_trees(const Snapshot& local,
                                         const Snapshot& base,
                                         const Snapshot& cloud) {
    const HashSet missing_blocks(0, hash_key);
    return compare_trees(local, base, cloud, missing_blocks);
}

} // namespace kasumi::diff
