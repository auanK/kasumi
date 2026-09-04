#ifndef KASUMI_DIFF_HPP
#define KASUMI_DIFF_HPP

#include "node.hpp"
#include "operation.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace kasumi::diff {

// Action type used by diff computation.
using Action = kasumi::Action;

// Synchronization operation produced by diff computation.
using SyncOperation = kasumi::Operation;

namespace detail {

// Cursor over direct children of a directory.
struct ChildCursor {
    // Traversed snapshot; nullptr represents absence.
    const Snapshot* snapshot = nullptr;
    // Index of the next direct child.
    std::size_t index = 0;
    // Path of the traversed directory.
    std::string_view parent;
};

// Positions a cursor at the first direct child of parent.
ChildCursor children(const Snapshot* snapshot, std::string_view parent);

// Returns current child without advancing, or nullptr at end.
const NodeRow* peek(const ChildCursor& cursor);

// Advances to next direct child, skipping descendants of current child.
void advance(ChildCursor& cursor);

// Compares hashes and treats two absent nodes as equivalent.
bool same_hash(const NodeRow* left, const NodeRow* right);

// Accumulates content objects referenced but missing in storage.
void find_missing_blocks(const Snapshot& snapshot,
                         const std::unordered_set<std::string>& physical_blocks,
                         HashSet& missing);

// Produces operations via three-way comparison of the node and descendants.
void compare_nodes_3way(const Snapshot* local_snapshot,
                        const Snapshot* base_snapshot,
                        const Snapshot* cloud_snapshot,
                        const NodeRow* local,
                        const NodeRow* base,
                        const NodeRow* cloud,
                        std::string_view current_path,
                        const HashSet& missing_blocks,
                        std::vector<SyncOperation>& operations);

} // namespace detail

// Compares local, base, and remote considering missing physical objects.
std::vector<SyncOperation> compare_trees(const Snapshot& local,
                                         const Snapshot& base,
                                         const Snapshot& cloud,
                                         const HashSet& missing_blocks);

// Compares local, base, and remote assuming referenced objects are available.
std::vector<SyncOperation> compare_trees(const Snapshot& local,
                                         const Snapshot& base,
                                         const Snapshot& cloud);

} // namespace kasumi::diff

#endif
