#ifndef KASUMI_APPLICATION_SYNC_METADATA_HPP
#define KASUMI_APPLICATION_SYNC_METADATA_HPP

#include "core/node.hpp"
#include "core/transaction/types.hpp"

#include <expected>
#include <string>
#include <vector>

namespace kasumi::application::sync {

// Returns paths to restore metadata, from leaves to root.
std::expected<std::vector<std::string>, std::string>
metadata_restore_paths(const transaction::Record& record,
                       const Snapshot& expected_tree,
                       const Snapshot* observed_tree = nullptr);

} // namespace kasumi::application::sync

#endif
