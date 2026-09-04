#include "application/history_storage/detail.hpp"
#include "platform/perf_trace.hpp"

#include <algorithm>
#include <new>

namespace kasumi::application::history_storage {

using namespace detail;

namespace {

RemoveMarkersResult remove_marker_variants_impl(
    transport::Transport& storage,
    std::span<const std::string> commit_ids,
    std::optional<std::span<const std::string>> identifiers) {
    try {
        std::vector<std::string> requested(commit_ids.begin(),
                                           commit_ids.end());
        if (!std::ranges::all_of(requested, history::valid_commit_id)) {
            return std::unexpected(
                error(ErrorCode::InvalidIdentifier, "invalid commit ID"));
        }
        std::ranges::sort(requested);
        requested.erase(std::ranges::unique(requested).begin(),
                        requested.end());
        if (requested.empty()) {
            return RemovedMarkers{};
        }

        std::vector<std::string> listing;
        if (identifiers) {
            listing.assign(identifiers->begin(), identifiers->end());
        } else {
            auto observed = transport::list(
                storage, heads_prefix.substr(0, heads_prefix.size() - 1));
            if (!observed) {
                if (observed.error().code !=
                    transport::ErrorCode::StorageNotFound) {
                    return std::unexpected(transport_error(observed.error()));
                }
            } else {
                listing.reserve(observed->size());
                for (const auto& child : *observed) {
                    if (child.empty() || child.find('/') != std::string::npos ||
                        child.find('\\') != std::string::npos) {
                        return std::unexpected(error(
                            ErrorCode::InvalidIdentifier,
                            "scoped listing returned a non-direct child"));
                    }
                    listing.push_back(std::string(heads_prefix) + child);
                }
            }
        }

        std::vector<std::string> markers;
        for (const auto& identifier : listing) {
            const auto reference = parse_marker_object(identifier);
            if (reference &&
                std::ranges::binary_search(requested, reference->commit_id)) {
                markers.push_back(identifier);
            }
        }
        std::ranges::sort(markers);

        RemovedMarkers result;
        for (const auto& marker : markers) {
            const auto remove_trace = platform::perf_trace::begin();
            auto removed = transport::remove(storage, marker);
            platform::perf_trace::finish("rc/delete_marker", remove_trace);
            if (!removed) {
                return std::unexpected(transport_error(removed.error()));
            }
            if (*removed == transport::Removal::Removed) {
                ++result.removed;
            }
        }
        return result;
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

} // namespace

RemoveMarkersResult
remove_marker_variants(transport::Transport& storage,
                       std::span<const std::string> commit_ids) {
    return remove_marker_variants_impl(storage, commit_ids, std::nullopt);
}

RemoveMarkersResult
remove_marker_variants(transport::Transport& storage,
                       std::span<const std::string> commit_ids,
                       std::span<const std::string> identifiers) {
    return remove_marker_variants_impl(storage, commit_ids, identifiers);
}

} // namespace kasumi::application::history_storage
