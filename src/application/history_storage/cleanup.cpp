#include "application/history_storage/detail.hpp"
#include "application/history_storage/remote_layout.hpp"

#include <algorithm>
#include <new>

namespace kasumi::application::history_storage {

using namespace detail;

namespace {

RemoveMarkersResult remove_marker_variants_impl(
    transport::Transport& storage,
    const RemoteLayout& layout,
    std::span<const std::string> commit_ids,
    std::optional<std::span<const std::string>> identifiers) {
    return guard_alloc([&]() -> RemoveMarkersResult {
        std::vector<std::string> requested(commit_ids.begin(),
                                           commit_ids.end());
        if (!std::ranges::all_of(requested, history::valid_commit_id)) {
            return std::unexpected(
                error(ErrorCode::InvalidIdentifier, "invalid commit ID"));
        }
        sort_unique(requested);
        if (requested.empty()) {
            return RemovedMarkers{};
        }

        std::vector<std::string> listing;
        if (identifiers) {
            listing.assign(identifiers->begin(), identifiers->end());
        } else {
            auto observed = list_identifiers(storage, layout.heads_prefix);
            if (!observed) {
                return std::unexpected(observed.error());
            }
            listing.reserve(observed->size());
            for (const auto& child : *observed) {
                if (child.empty() || child.find('/') != std::string::npos ||
                    child.find('\\') != std::string::npos) {
                    return std::unexpected(
                        error(ErrorCode::InvalidIdentifier,
                              "scoped listing returned a non-direct child"));
                }
                listing.push_back(layout.heads_prefix + child);
            }
        }

        std::vector<std::string> markers;
        for (const auto& identifier : listing) {
            const auto reference = parse_marker_object(layout, identifier);
            if (reference &&
                std::ranges::binary_search(requested, reference->commit_id)) {
                markers.push_back(identifier);
            }
        }
        std::ranges::sort(markers);

        RemovedMarkers result;
        constexpr std::size_t kRemoveBatchChunk = 64;
        constexpr std::size_t kRemoveBatchConcurrency = 8;
        bool batch_unsupported = false;
        std::size_t offset = 0;
        while (offset < markers.size() && !batch_unsupported) {
            const auto count =
                std::min(kRemoveBatchChunk, markers.size() - offset);
            transport::RemoveBatch batch{
                .concurrency = kRemoveBatchConcurrency,
            };
            batch.items.reserve(count);
            for (std::size_t i = 0; i < count; ++i) {
                batch.items.push_back(
                    transport::RemoveBatchItem{.identifier = markers[offset + i]});
            }
            auto removed_batch = transport::remove_batch(storage, batch);
            if (!removed_batch) {
                if (removed_batch.error().code ==
                    transport::ErrorCode::Unsupported) {
                    batch_unsupported = true;
                    break;
                }
                return std::unexpected(transport_error(removed_batch.error()));
            }
            for (const auto& item : removed_batch->items) {
                if (!item.result) {
                    return std::unexpected(
                        transport_error(item.result.error()));
                }
                if (*item.result == transport::Removal::Removed) {
                    ++result.removed;
                }
            }
            offset += count;
        }
        while (offset < markers.size()) {
            auto removed = transport::remove(storage, markers[offset]);
            if (!removed) {
                return std::unexpected(transport_error(removed.error()));
            }
            if (*removed == transport::Removal::Removed) {
                ++result.removed;
            }
            ++offset;
        }
        return result;
    });
}

} // namespace

RemoveMarkersResult
remove_marker_variants(transport::Transport& storage,
                       const RemoteLayout& layout,
                       std::span<const std::string> commit_ids) {
    return remove_marker_variants_impl(
        storage, layout, commit_ids, std::nullopt);
}

RemoveMarkersResult
remove_marker_variants(transport::Transport& storage,
                       const RemoteLayout& layout,
                       std::span<const std::string> commit_ids,
                       std::span<const std::string> identifiers) {
    return remove_marker_variants_impl(
        storage, layout, commit_ids, identifiers);
}

} // namespace kasumi::application::history_storage
