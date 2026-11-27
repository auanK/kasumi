#include "application/history_storage/detail.hpp"
#include "application/history_storage/maintenance_protocol.hpp"

#include <algorithm>
#include <utility>

namespace kasumi::application::history_storage::detail {

Error error(ErrorCode code, std::string detail) {
    return Error{.code = code, .detail = std::move(detail)};
}

Error transport_error(const transport::Error& source) {
    return error(ErrorCode::TransportFailure, transport::describe(source));
}

Error history_error(const history::Error& source) {
    const auto code = source.code == history::ErrorCode::LimitExceeded
                          ? ErrorCode::LimitExceeded
                          : ErrorCode::InvalidCommit;
    return error(code, source.detail);
}

bool valid_hex_id(std::string_view id) noexcept {
    return history::valid_commit_id(id);
}

void sort_unique(std::vector<HeadReference>& references) {
    std::ranges::sort(references);
    references.erase(std::ranges::unique(references).begin(), references.end());
}

void sort_unique(std::vector<std::string>& values) {
    std::ranges::sort(values);
    values.erase(std::ranges::unique(values).begin(), values.end());
}

transport::ListingResult
list_transport_identifiers(transport::Transport& storage,
                           std::string_view prefix) {
    const auto trimmed = trim_trailing_slash(prefix);
    const bool fallback =
        !trimmed.empty() && storage.storage.list_prefix == nullptr;
    auto listed = trimmed.empty() || fallback
                      ? transport::list(storage)
                      : transport::list(storage, trimmed);
    if (!listed) {
        if (listed.error().code == transport::ErrorCode::StorageNotFound) {
            return std::vector<std::string>{};
        }
        return std::unexpected(listed.error());
    }
    if (fallback) {
        const auto full_prefix = std::string{trimmed} + '/';
        std::vector<std::string> children;
        for (const auto& identifier : *listed) {
            if (!identifier.starts_with(full_prefix)) {
                continue;
            }
            const auto name = identifier.substr(full_prefix.size());
            if (name.find('/') == std::string::npos) {
                children.push_back(name);
            }
        }
        std::ranges::sort(children);
        return children;
    }
    return std::move(*listed);
}

std::expected<std::vector<std::string>, Error>
list_identifiers(transport::Transport& storage, std::string_view prefix) {
    auto listed = list_transport_identifiers(storage, prefix);
    if (!listed) {
        return std::unexpected(transport_error(listed.error()));
    }
    return std::move(*listed);
}

std::expected<void, Error>
finalize_history_inventory(HistoryInventory& inventory) {
    if (inventory.identifiers.size() > maximum_history_object_count) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "too many storage objects"));
    }
    for (auto* objects :
         {&inventory.commit_variants, &inventory.marker_variants}) {
        for (auto& entry : *objects) {
            sort_unique(entry.second);
            if (entry.second.size() > maximum_ciphertext_variants_per_commit) {
                return std::unexpected(error(ErrorCode::LimitExceeded,
                                             "too many ciphertext variants"));
            }
        }
    }
    if (inventory.marker_variants.size() > history::maximum_marked_head_count) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "too many logical heads"));
    }
    return {};
}

std::expected<HistoryInventory, Error>
build_history_inventory(transport::Transport& storage,
                        const RemoteLayout& layout) {
    auto listing = list_identifiers(storage);
    if (!listing || listing->empty()) {
        return listing ? std::expected<HistoryInventory, Error>{HistoryInventory{
                             .all_commits_listed = true}}
                       : std::unexpected(listing.error());
    }
    return build_history_inventory(*listing, layout);
}

std::expected<HistoryInventory, Error>
build_history_inventory(std::span<const std::string> identifiers,
                        const RemoteLayout& layout) {
    HistoryInventory inventory;
    inventory.all_commits_listed = true;
    inventory.identifiers.reserve(identifiers.size());
    for (const auto& identifier : identifiers) {
        if (is_history_object(layout, identifier) &&
            !is_control_object(layout, identifier)) {
            inventory.identifiers.push_back(identifier);
        }
    }
    sort_unique(inventory.identifiers);
    if (inventory.identifiers.size() > maximum_history_object_count) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "too many storage objects"));
    }
    for (const auto& identifier : inventory.identifiers) {
        if (auto commit_reference = parse_commit_object(layout, identifier)) {
            inventory.commit_variants[commit_reference->commit_id].push_back(
                std::move(*commit_reference));
        } else if (auto marker_reference =
                       parse_marker_object(layout, identifier)) {
            inventory.marker_variants[marker_reference->commit_id].push_back(
                std::move(*marker_reference));
        }
    }
    if (auto finalized = finalize_history_inventory(inventory); !finalized) {
        return std::unexpected(finalized.error());
    }
    return inventory;
}

PublicationDelta publication_delta(const HistoryInventory& inventory,
                                   const HeadReference& reference,
                                   const RemoteLayout& layout) {
    const bool adds_commit_object =
        !inventory_contains(inventory, commit_object(layout, reference));
    const bool adds_marker_object =
        !inventory_contains(inventory, marker_object(layout, reference));
    return PublicationDelta{
        .adds_commit_object = adds_commit_object,
        .adds_marker_object = adds_marker_object,
        .adds_marked_commit =
            adds_marker_object &&
            !inventory.marker_variants.contains(reference.commit_id),
    };
}

std::expected<void, Error>
validate_publication_budget(const HistoryInventory& inventory,
                            const HeadReference& reference,
                            const PublicationDelta& delta,
                            bool check_global_count) {
    const auto additions = static_cast<std::size_t>(delta.adds_commit_object) +
                           static_cast<std::size_t>(delta.adds_marker_object);
    if (check_global_count && (additions > maximum_history_object_count ||
                               inventory.identifiers.size() >
                                   maximum_history_object_count - additions)) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded,
                  "publication exceeds history object limit"));
    }

    if (delta.adds_commit_object) {
        const auto it = inventory.commit_variants.find(reference.commit_id);
        if (it != inventory.commit_variants.end() &&
            it->second.size() >= maximum_ciphertext_variants_per_commit) {
            return std::unexpected(
                error(ErrorCode::LimitExceeded,
                      "publication exceeds commit variant limit"));
        }
    }

    if (delta.adds_marker_object) {
        const auto it = inventory.marker_variants.find(reference.commit_id);
        if (it != inventory.marker_variants.end() &&
            it->second.size() >= maximum_ciphertext_variants_per_commit) {
            return std::unexpected(
                error(ErrorCode::LimitExceeded,
                      "publication exceeds marker variant limit"));
        }
    }

    if (delta.adds_marked_commit && inventory.marker_variants.size() >=
                                        history::maximum_marked_head_count) {
        return std::unexpected(error(ErrorCode::LimitExceeded,
                                     "publication exceeds marked head limit"));
    }
    return {};
}

} // namespace kasumi::application::history_storage::detail
