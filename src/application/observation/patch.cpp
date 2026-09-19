#include "application/observation/patch.hpp"

#include "platform/perf_trace.hpp"

#include <algorithm>

namespace kasumi::application::observation {

std::expected<Snapshot, std::string>
apply_local_delta(const Snapshot& previous,
                  std::span<const ObservedFileDelta> delta) {
    if (!valid_snapshot(previous, false))
        return std::unexpected("invalid previous snapshot");
    const auto copy_trace = platform::perf_trace::begin();
    Snapshot result = previous;
    platform::perf_trace::finish("snapshot patch copy wall", copy_trace);
    platform::perf_trace::count("snapshot patch rows", result.rows.size());
    for (const auto& change : delta) {
        if (change.path.empty() || change.row.path != change.path ||
            change.row.is_directory) {
            return std::unexpected("invalid file delta");
        }
        const auto position = std::ranges::lower_bound(
            result.rows, change.path, path_less, &NodeRow::path);
        if (position != result.rows.end() && position->path == change.path) {
            if (position->is_directory)
                return std::unexpected("delta points to directory");
            *position = change.row;
        } else {
            return std::unexpected("delta file does not exist in snapshot");
        }
    }
    const auto finalize_trace = platform::perf_trace::begin();
    finalize_snapshot(result);
    platform::perf_trace::finish("snapshot finalize wall", finalize_trace);
    if (!valid_snapshot(result, false))
        return std::unexpected("produced patch snapshot is invalid");
    return result;
}

} // namespace kasumi::application::observation
