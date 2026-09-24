#include "application/history_storage/content_reachability.hpp"

#include "application/history_storage/remote_layout.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "platform/perf_trace.hpp"

#include <algorithm>
#include <map>
#include <new>
#include <set>
#include <utility>

namespace kasumi::application::history_storage {
namespace {

constexpr std::size_t maximum_content_object_count = 1'000'000;

struct ReferencedContent {
    std::string remote_id;
    std::string plaintext_hash;
    std::vector<ContentReference> references;
};

struct RawReference {
    std::string remote_id;
    std::string plaintext_hash;
    ContentReference reference;
};

bool valid_content_id(std::string_view identifier) noexcept {
    const auto decoded = hash_from_hex(identifier);
    return decoded && hash_hex(*decoded) == identifier;
}

void sort_unique(std::vector<std::string>& values) {
    std::ranges::sort(values);
    values.erase(std::ranges::unique(values).begin(), values.end());
}

std::expected<ContentObjectState, Error>
audit_object(transport::Transport& storage,
             std::span<const std::uint8_t, crypto::KEY_SIZE> key,
             std::string_view content_id,
             std::optional<std::string_view> expected_plaintext_hash,
             std::optional<std::uint64_t> expected_size,
             const std::filesystem::path& workspace,
             std::size_t sequence) {
    const auto encrypted =
        workspace / ("content-" + std::to_string(sequence) + ".enc");
    const auto plaintext =
        workspace / ("content-" + std::to_string(sequence) + ".plain");
    const auto cleanup = [&] {
        detail::remove_file(encrypted);
        detail::remove_file(plaintext);
    };
    cleanup();

    const auto downloaded = transport::get(storage, content_id, encrypted);
    if (!downloaded) {
        cleanup();
        if (downloaded.error().code == transport::ErrorCode::ObjectNotFound) {
            return ContentObjectState::Missing;
        }
        return std::unexpected(detail::transport_error(downloaded.error()));
    }

    ContentObjectState state = ContentObjectState::Corrupt;
    if (crypto::decrypt_file(encrypted, plaintext, key)) {
        const auto actual_hash = crypto::content::hash_file(plaintext);
        std::error_code size_error;
        const auto actual_size =
            std::filesystem::file_size(plaintext, size_error);
        if (actual_hash && !size_error &&
            (!expected_size || actual_size == *expected_size) &&
            (!expected_plaintext_hash ||
             hash_hex(*actual_hash) == *expected_plaintext_hash) &&
            crypto::content_identifier(key, *actual_hash) == content_id) {
            state = ContentObjectState::Present;
        }
    }
    cleanup();
    return state;
}

} // namespace

ContentReachabilityResult
inventory_impl(transport::Transport& storage,
               std::span<const std::uint8_t, crypto::KEY_SIZE> key,
               std::optional<std::span<const std::string>> identifiers,
               const ReachabilityInventory& history_inventory,
               const std::filesystem::path& workspace_root,
               bool audit_payloads) {
    try {
        if (!transport::valid(storage)) {
            return std::unexpected(
                detail::error(ErrorCode::InvalidInput, "invalid transport"));
        }
        detail::TemporaryWorkspace temporary{nullptr, detail::remove_workspace};
        if (audit_payloads) {
            auto ws = detail::make_workspace(workspace_root);
            if (!ws) {
                return std::unexpected(ws.error());
            }
            temporary = std::move(*ws);
        }

        std::vector<RawReference> raw_references;
        std::size_t reference_count = 0;
        for (const auto& commit : history_inventory.commits) {
            if (!commit.valid || !commit.reachable) {
                continue;
            }
            if (!commit.tree.has_value() ||
                !kasumi::valid_snapshot(commit.tree->tree, false)) {
                return std::unexpected(
                    detail::error(ErrorCode::InvalidCommit,
                                  "reachable commit has no valid tree"));
            }
            const auto required_capacity =
                raw_references.size() + commit.tree->tree.rows.size();
            if (required_capacity > raw_references.capacity()) {
                platform::perf_trace::count(
                    "rc/content_reference_capacity_growth_events");
            }
            raw_references.reserve(required_capacity);
            for (const auto& row : commit.tree->tree.rows) {
                if (row.is_directory) {
                    continue;
                }
                const auto plaintext_hash = hash_hex(row.hash);
                const auto remote_id =
                    crypto::content_identifier(key, row.hash);
                if (++reference_count > maximum_content_object_count) {
                    return std::unexpected(
                        detail::error(ErrorCode::LimitExceeded,
                                      "too many content references"));
                }
                raw_references.push_back(RawReference{
                    .remote_id = remote_id,
                    .plaintext_hash = plaintext_hash,
                    .reference = ContentReference{
                        .commit_id = commit.commit_id,
                        .path = row.path,
                        .size = row.size,
                    },
                });
            }
        }

        std::ranges::sort(raw_references, {}, &RawReference::remote_id);

        std::vector<ReferencedContent> references;
        references.reserve(raw_references.size());
        for (auto& item : raw_references) {
            if (references.empty() ||
                references.back().remote_id != item.remote_id) {
                references.push_back(ReferencedContent{
                    .remote_id = std::move(item.remote_id),
                    .plaintext_hash = std::move(item.plaintext_hash),
                    .references = {},
                });
                references.back().references.push_back(
                    std::move(item.reference));
            } else {
                auto& current = references.back();
                if (!current.references.empty() &&
                    current.references.front().size != item.reference.size) {
                    return std::unexpected(
                        detail::error(ErrorCode::VerificationFailure,
                                      "content reference sizes conflict"));
                }
                current.references.push_back(std::move(item.reference));
            }
        }

        std::span<const std::string> listing_span;
        std::vector<std::string> fallback_listing;
        if (identifiers) {
            listing_span = *identifiers;
        } else {
            auto listing = transport::list(storage);
            if (!listing) {
                if (listing.error().code !=
                    transport::ErrorCode::StorageNotFound) {
                    return std::unexpected(
                        detail::transport_error(listing.error()));
                }
            } else {
                fallback_listing = std::move(*listing);
                listing_span = fallback_listing;
            }
        }

        std::vector<std::string> physical;
        std::vector<std::string> unknown;
        if (!listing_span.empty()) {
            const auto layout = derive_remote_layout(key);
            std::size_t object_count = 0;
            physical.reserve(listing_span.size());
            for (const auto& identifier : listing_span) {
                if (is_history_object(layout, identifier)) {
                    continue;
                }
                if (++object_count > maximum_content_object_count) {
                    return std::unexpected(
                        detail::error(ErrorCode::LimitExceeded,
                                      "too many content storage objects"));
                }
                if (valid_content_id(identifier)) {
                    physical.push_back(identifier);
                } else {
                    unknown.push_back(identifier);
                }
            }
        }
        sort_unique(physical);

        const auto is_referenced = [&](std::string_view id) {
            const auto it = std::ranges::lower_bound(
                references, id, {}, &ReferencedContent::remote_id);
            return it != references.end() && it->remote_id == id;
        };

        ContentReachabilityInventory result;
        result.reachable_content_ids.reserve(references.size());
        result.contents.reserve(references.size() + physical.size());

        std::size_t sequence = 0;
        for (auto& content : references) {
            std::ranges::sort(content.references);
            const bool found =
                std::ranges::binary_search(physical, content.remote_id);
            ContentObjectState state = ContentObjectState::Missing;
            if (found) {
                if (audit_payloads) {
                    auto audited = audit_object(storage,
                                                key,
                                                content.remote_id,
                                                content.plaintext_hash,
                                                content.references.front().size,
                                                temporary->root,
                                                sequence++);
                    if (!audited) {
                        return std::unexpected(audited.error());
                    }
                    state = *audited;
                } else {
                    state = ContentObjectState::Present;
                }
            }
            result.reachable_content_ids.push_back(content.remote_id);
            if (state == ContentObjectState::Missing) {
                result.missing_content_ids.push_back(content.remote_id);
            } else if (state == ContentObjectState::Corrupt) {
                result.corrupt_content_ids.push_back(content.remote_id);
            }
            result.contents.push_back(
                ContentEntry{.content_id = content.remote_id,
                             .state = state,
                             .reachable = true,
                             .references = std::move(content.references)});
        }

        for (const auto& content_id : physical) {
            if (is_referenced(content_id)) {
                continue;
            }
            result.orphan_content_ids.push_back(content_id);
            ContentObjectState state = ContentObjectState::Present;
            if (audit_payloads) {
                auto audited = audit_object(storage,
                                            key,
                                            content_id,
                                            std::nullopt,
                                            std::nullopt,
                                            temporary->root,
                                            sequence++);
                if (!audited) {
                    return std::unexpected(audited.error());
                }
                state = *audited;
                if (state == ContentObjectState::Corrupt) {
                    result.corrupt_content_ids.push_back(content_id);
                }
            }
            result.contents.push_back(
                ContentEntry{.content_id = content_id,
                             .state = state,
                             .reachable = false,
                             .references = {}});
        }

        sort_unique(unknown);
        sort_unique(result.reachable_content_ids);
        sort_unique(result.missing_content_ids);
        sort_unique(result.corrupt_content_ids);
        sort_unique(result.orphan_content_ids);
        result.unknown_storage_objects = std::move(unknown);
        std::ranges::sort(result.contents, {}, &ContentEntry::content_id);
        return result;
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            detail::error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

ContentReachabilityResult inventory_content_reachability(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const ReachabilityInventory& history_inventory,
    const std::filesystem::path& workspace_root,
    bool audit_payloads) {
    return inventory_impl(storage,
                          key,
                          std::nullopt,
                          history_inventory,
                          workspace_root,
                          audit_payloads);
}

ContentReachabilityResult inventory_content_reachability(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    std::span<const std::string> identifiers,
    const ReachabilityInventory& history_inventory,
    const std::filesystem::path& workspace_root,
    bool audit_payloads) {
    return inventory_impl(storage,
                          key,
                          identifiers,
                          history_inventory,
                          workspace_root,
                          audit_payloads);
}

} // namespace kasumi::application::history_storage
