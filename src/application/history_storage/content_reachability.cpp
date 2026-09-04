#include "application/history_storage/content_reachability.hpp"

#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"

#include <algorithm>
#include <map>
#include <new>
#include <set>
#include <utility>

namespace kasumi::application::history_storage {
namespace {

constexpr std::size_t maximum_content_object_count = 1'000'000;

struct ReferencedContent {
    std::string plaintext_hash;
    std::vector<ContentReference> references;
};

using ReferenceMap = std::map<std::string, ReferencedContent>;

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
               const std::filesystem::path& workspace_root) {
    try {
        if (!transport::valid(storage)) {
            return std::unexpected(
                detail::error(ErrorCode::InvalidInput, "invalid transport"));
        }
        auto temporary = detail::make_workspace(workspace_root);
        if (!temporary) {
            return std::unexpected(temporary.error());
        }

        ReferenceMap references;
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
            for (const auto& row : commit.tree->tree.rows) {
                if (row.is_directory) {
                    continue;
                }
                const auto plaintext_hash = hash_hex(row.hash);
                const auto remote_id =
                    crypto::content_identifier(key, row.hash);
                auto& content = references[remote_id];
                if (!content.references.empty() &&
                    content.references.front().size != row.size) {
                    return std::unexpected(
                        detail::error(ErrorCode::VerificationFailure,
                                      "content reference sizes conflict"));
                }
                if (++reference_count > maximum_content_object_count) {
                    return std::unexpected(
                        detail::error(ErrorCode::LimitExceeded,
                                      "too many content references"));
                }
                content.plaintext_hash = plaintext_hash;
                content.references.push_back(ContentReference{
                    .commit_id = commit.commit_id,
                    .path = row.path,
                    .size = row.size,
                });
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

        std::set<std::string> physical;
        std::vector<std::string> unknown;
        if (!listing_span.empty()) {
            std::size_t object_count = 0;
            for (const auto& identifier : listing_span) {
                if (identifier.starts_with("history/")) {
                    continue;
                }
                if (++object_count > maximum_content_object_count) {
                    return std::unexpected(
                        detail::error(ErrorCode::LimitExceeded,
                                      "too many content storage objects"));
                }
                if (valid_content_id(identifier)) {
                    physical.insert(identifier);
                } else {
                    unknown.push_back(identifier);
                }
            }
        }

        ContentReachabilityInventory result;
        std::size_t sequence = 0;
        std::map<std::string, ContentEntry> entries;
        for (auto& [content_id, content] : references) {
            std::ranges::sort(content.references);
            const auto found = physical.find(content_id);
            ContentObjectState state = ContentObjectState::Missing;
            if (found != physical.end()) {
                auto audited = audit_object(storage,
                                            key,
                                            content_id,
                                            content.plaintext_hash,
                                            content.references.front().size,
                                            (*temporary)->root,
                                            sequence++);
                if (!audited) {
                    return std::unexpected(audited.error());
                }
                state = *audited;
            }
            result.reachable_content_ids.push_back(content_id);
            if (state == ContentObjectState::Missing) {
                result.missing_content_ids.push_back(content_id);
            } else if (state == ContentObjectState::Corrupt) {
                result.corrupt_content_ids.push_back(content_id);
            }
            entries.emplace(
                content_id,
                ContentEntry{.content_id = content_id,
                             .state = state,
                             .reachable = true,
                             .references = std::move(content.references)});
        }

        for (const auto& content_id : physical) {
            if (references.contains(content_id)) {
                continue;
            }
            // An orphan does not authorize deletion; GC must revalidate reachability
            // and the object.
            result.orphan_content_ids.push_back(content_id);
            auto audited = audit_object(storage,
                                        key,
                                        content_id,
                                        std::nullopt,
                                        std::nullopt,
                                        (*temporary)->root,
                                        sequence++);
            if (!audited) {
                return std::unexpected(audited.error());
            }
            entries.emplace(content_id,
                            ContentEntry{.content_id = content_id,
                                         .state = *audited,
                                         .reachable = false,
                                         .references = {}});
            if (*audited == ContentObjectState::Corrupt) {
                result.corrupt_content_ids.push_back(content_id);
            }
        }

        std::ranges::sort(unknown);
        unknown.erase(std::ranges::unique(unknown).begin(), unknown.end());
        sort_unique(result.reachable_content_ids);
        sort_unique(result.missing_content_ids);
        sort_unique(result.corrupt_content_ids);
        sort_unique(result.orphan_content_ids);
        result.unknown_storage_objects = std::move(unknown);
        for (auto& [unused, entry] : entries) {
            static_cast<void>(unused);
            result.contents.push_back(std::move(entry));
        }
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
    const std::filesystem::path& workspace_root) {
    return inventory_impl(
        storage, key, std::nullopt, history_inventory, workspace_root);
}

ContentReachabilityResult inventory_content_reachability(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    std::span<const std::string> identifiers,
    const ReachabilityInventory& history_inventory,
    const std::filesystem::path& workspace_root) {
    return inventory_impl(
        storage, key, identifiers, history_inventory, workspace_root);
}

} // namespace kasumi::application::history_storage
