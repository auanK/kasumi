#ifndef KASUMI_DIFF_HPP
#define KASUMI_DIFF_HPP

#include "core/ignore.hpp"
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

// Accumulates content objects referenced but missing in storage.
void find_missing_blocks(const Snapshot& snapshot,
                         const std::unordered_set<std::string>& physical_blocks,
                         HashSet& missing);

} // namespace detail

// Compares local, base, and remote considering missing physical objects.
std::vector<SyncOperation> compare_trees(
    const Snapshot& local,
    const Snapshot& base,
    const Snapshot& cloud,
    const HashSet& missing_blocks,
    const ignore::IgnoreList* ignore_list = nullptr,
    const std::unordered_set<std::string>* authorized_deletions = nullptr,
    const Snapshot* expired_base = nullptr);

// Compares local, base, and remote assuming referenced objects are available.
std::vector<SyncOperation>
compare_trees(const Snapshot& local,
              const Snapshot& base,
              const Snapshot& cloud,
              const ignore::IgnoreList* ignore_list = nullptr);

} // namespace kasumi::diff

#endif
