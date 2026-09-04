#ifndef KASUMI_APPLICATION_OBSERVATION_PATCH_HPP
#define KASUMI_APPLICATION_OBSERVATION_PATCH_HPP

#include "core/node.hpp"

#include <expected>
#include <span>
#include <string>
#include <vector>

namespace kasumi::application::observation {

// Observed change for a known file.
struct ObservedFileDelta {
    // Must match row.path.
    std::string path;
    NodeRow row;
};

// Updates only files already present in the snapshot tree.
std::expected<Snapshot, std::string>
apply_local_delta(const Snapshot& previous,
                  std::span<const ObservedFileDelta> delta);

} // namespace kasumi::application::observation

#endif
