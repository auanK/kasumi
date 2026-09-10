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

std::string commit_object(const HeadReference& reference) {
    return std::string{commit_prefix} + reference.commit_id + "/" +
           reference.ciphertext_id + std::string{commit_suffix};
}

} // namespace kasumi::application::history_storage::detail

namespace kasumi::application::history_storage {

std::string marker_object(const HeadReference& reference) {
    return std::string{detail::heads_prefix} + reference.commit_id + "-" +
           reference.ciphertext_id + std::string{detail::head_suffix};
}

} // namespace kasumi::application::history_storage

namespace kasumi::application::history_storage::detail {

std::optional<HeadReference> parse_commit_object(std::string_view identifier) {
    if (!identifier.starts_with(commit_prefix) ||
        !identifier.ends_with(commit_suffix)) {
        return std::nullopt;
    }

    const auto body = identifier.substr(
        commit_prefix.size(),
        identifier.size() - commit_prefix.size() - commit_suffix.size());
    const auto separator = body.find('/');
    if (separator != 64 ||
        body.find('/', separator + 1) != std::string_view::npos) {
        return std::nullopt;
    }

    HeadReference result{
        .commit_id = std::string{body.substr(0, separator)},
        .ciphertext_id = std::string{body.substr(separator + 1)},
    };
    return valid(result) ? std::optional{std::move(result)} : std::nullopt;
}

} // namespace kasumi::application::history_storage::detail

namespace kasumi::application::history_storage {

std::optional<HeadReference> parse_marker_object(std::string_view identifier) {
    if (!identifier.starts_with(detail::heads_prefix) ||
        !identifier.ends_with(detail::head_suffix)) {
        return std::nullopt;
    }

    const auto body =
        identifier.substr(detail::heads_prefix.size(),
                          identifier.size() - detail::heads_prefix.size() -
                              detail::head_suffix.size());
    if (body.size() != 129 || body[64] != '-') {
        return std::nullopt;
    }

    HeadReference result{
        .commit_id = std::string{body.substr(0, 64)},
        .ciphertext_id = std::string{body.substr(65)},
    };
    return valid(result) ? std::optional{std::move(result)} : std::nullopt;
}

} // namespace kasumi::application::history_storage

namespace kasumi::application::history_storage::detail {

void sort_unique(std::vector<HeadReference>& references) {
    std::ranges::sort(references);
    references.erase(std::ranges::unique(references).begin(), references.end());
}

std::expected<HistoryInventory, Error>
build_history_inventory(transport::Transport& storage) {
    auto listing = transport::list(storage);
    if (!listing) {
        if (listing.error().code == transport::ErrorCode::StorageNotFound) {
            return HistoryInventory{};
        }
        return std::unexpected(transport_error(listing.error()));
    }

    return build_history_inventory(*listing);
}

std::expected<HistoryInventory, Error>
build_history_inventory(std::span<const std::string> identifiers) {
    HistoryInventory inventory;
    for (const auto& identifier : identifiers) {
        if (identifier.starts_with("history/") &&
            !maintenance_protocol::is_control_object(identifier)) {
            inventory.identifiers.insert(identifier);
        }
    }
    if (inventory.identifiers.size() > maximum_history_object_count) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "too many storage objects"));
    }

    for (const auto& identifier : inventory.identifiers) {
        if (auto commit_reference = parse_commit_object(identifier)) {
            inventory.commit_variants[commit_reference->commit_id].push_back(
                std::move(*commit_reference));
        } else if (auto marker_reference = parse_marker_object(identifier)) {
            inventory.marker_variants[marker_reference->commit_id].push_back(
                std::move(*marker_reference));
        }
    }
    for (auto* objects :
         {&inventory.commit_variants, &inventory.marker_variants}) {
        for (auto& [unused, variants] : *objects) {
            static_cast<void>(unused);
            sort_unique(variants);
            if (variants.size() > maximum_ciphertext_variants_per_commit) {
                return std::unexpected(error(ErrorCode::LimitExceeded,
                                             "too many ciphertext variants"));
            }
        }
    }
    if (inventory.marker_variants.size() > history::maximum_marked_head_count) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded, "too many logical heads"));
    }
    return inventory;
}

PublicationDelta publication_delta(const HistoryInventory& inventory,
                                   const HeadReference& reference) {
    const bool adds_commit_object =
        !inventory.identifiers.contains(commit_object(reference));
    const bool adds_marker_object =
        !inventory.identifiers.contains(marker_object(reference));
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

    const auto commit_count =
        inventory.commit_variants.contains(reference.commit_id)
            ? inventory.commit_variants.at(reference.commit_id).size()
            : 0U;
    const auto commit_capacity =
        maximum_ciphertext_variants_per_commit -
        std::min(commit_count, maximum_ciphertext_variants_per_commit);
    if ((delta.adds_commit_object ? 1U : 0U) > commit_capacity) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded,
                  "publication exceeds commit variant limit"));
    }

    const auto marker_count =
        inventory.marker_variants.contains(reference.commit_id)
            ? inventory.marker_variants.at(reference.commit_id).size()
            : 0U;
    const auto marker_capacity =
        maximum_ciphertext_variants_per_commit -
        std::min(marker_count, maximum_ciphertext_variants_per_commit);
    if ((delta.adds_marker_object ? 1U : 0U) > marker_capacity) {
        return std::unexpected(
            error(ErrorCode::LimitExceeded,
                  "publication exceeds marker variant limit"));
    }

    if (delta.adds_marked_commit && inventory.marker_variants.size() >=
                                        history::maximum_marked_head_count) {
        return std::unexpected(error(ErrorCode::LimitExceeded,
                                     "publication exceeds marked head limit"));
    }
    return {};
}

} // namespace kasumi::application::history_storage::detail
