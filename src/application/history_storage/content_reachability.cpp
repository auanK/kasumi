#include "application/history_storage/content_reachability.hpp"

#include "application/history_storage/remote_layout.hpp"
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
    std::string remote_id;
    std::string plaintext_hash;
    std::vector<ContentReference> references;
};

} // namespace

std::expected<ContentAuditResult, Error>
audit_content_object(transport::Transport& storage,
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
            return ContentAuditResult{.state = ContentObjectState::Missing};
        }
        return std::unexpected(detail::transport_error(downloaded.error()));
    }

    ContentAuditResult result{.state = ContentObjectState::Corrupt};
    if (crypto::decrypt_file(encrypted, plaintext, key)) {
        std::error_code plain_size_error;
        const auto plain_size =
            std::filesystem::file_size(plaintext, plain_size_error);
        const auto actual_hash = crypto::content::hash_file(plaintext);
        if (actual_hash && !plain_size_error &&
            (!expected_size || plain_size == *expected_size) &&
            (!expected_plaintext_hash ||
             hash_hex(*actual_hash) == *expected_plaintext_hash) &&
            crypto::content_identifier(key, *actual_hash) == content_id) {
            result.state = ContentObjectState::Present;
            result.plaintext_hash = hash_hex(*actual_hash);
            result.size = plain_size;
        }
    }
    cleanup();
    return result;
}

namespace {} // namespace

ContentReachabilityResult
inventory_impl(transport::Transport& storage,
               std::span<const std::uint8_t, crypto::KEY_SIZE> key,
               std::optional<std::span<const std::string>> identifiers,
               const ReachabilityInventory& history_inventory,
               const std::filesystem::path& workspace_root,
               bool audit_payloads) {
    return detail::guard_alloc([&]() -> ContentReachabilityResult {
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

        std::map<std::string, ReferencedContent> by_remote_id;
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
                if (++reference_count > maximum_content_object_count) {
                    return std::unexpected(
                        detail::error(ErrorCode::LimitExceeded,
                                      "too many content references"));
                }
                const auto remote_id =
                    crypto::content_identifier(key, row.hash);
                auto [it, inserted] = by_remote_id.try_emplace(
                    remote_id,
                    ReferencedContent{.remote_id = remote_id,
                                      .plaintext_hash = hash_hex(row.hash),
                                      .references = {}});
                if (!inserted && !it->second.references.empty() &&
                    it->second.references.front().size != row.size) {
                    return std::unexpected(
                        detail::error(ErrorCode::VerificationFailure,
                                      "content reference sizes conflict"));
                }
                it->second.references.push_back(ContentReference{
                    .commit_id = commit.commit_id,
                    .path = row.path,
                    .size = row.size,
                });
            }
        }

        std::vector<ReferencedContent> references;
        references.reserve(by_remote_id.size());
        for (auto& [unused, entry] : by_remote_id) {
            static_cast<void>(unused);
            references.push_back(std::move(entry));
        }

        std::vector<std::string> fallback_listing;
        if (!identifiers) {
            auto listing = detail::list_identifiers(storage);
            if (!listing) {
                return std::unexpected(listing.error());
            }
            fallback_listing = std::move(*listing);
        }
        const std::span<const std::string> listing_span =
            identifiers ? *identifiers
                        : std::span<const std::string>{fallback_listing};

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
                if (detail::valid_hex_id(identifier)) {
                    physical.push_back(identifier);
                } else {
                    unknown.push_back(identifier);
                }
            }
        }
        detail::sort_unique(physical);

        const auto is_referenced = [&](std::string_view id) {
            const auto it = std::ranges::lower_bound(
                references, id, {}, &ReferencedContent::remote_id);
            return it != references.end() && it->remote_id == id;
        };

        ContentReachabilityInventory result;
        result.reachable_content_ids.reserve(references.size());
        result.contents.reserve(references.size() + physical.size());

        std::size_t sequence = 0;
        auto audit = [&](std::string_view id,
                         std::optional<std::string_view> plaintext_hash,
                         std::optional<std::uint64_t> expected_size)
            -> std::expected<ContentObjectState, Error> {
            if (!audit_payloads) {
                return ContentObjectState::Present;
            }
            auto audited = audit_content_object(storage,
                                                key,
                                                id,
                                                plaintext_hash,
                                                expected_size,
                                                temporary->workspace.root,
                                                sequence++);
            if (!audited) {
                return std::unexpected(audited.error());
            }
            return audited->state;
        };

        for (auto& content : references) {
            std::ranges::sort(content.references);
            auto state = ContentObjectState::Missing;
            if (std::ranges::binary_search(physical, content.remote_id)) {
                auto audited = audit(content.remote_id,
                                     content.plaintext_hash,
                                     content.references.front().size);
                if (!audited) {
                    return std::unexpected(audited.error());
                }
                state = *audited;
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
            auto audited = audit(content_id, std::nullopt, std::nullopt);
            if (!audited) {
                return std::unexpected(audited.error());
            }
            if (*audited == ContentObjectState::Corrupt) {
                result.corrupt_content_ids.push_back(content_id);
            }
            result.contents.push_back(ContentEntry{.content_id = content_id,
                                                   .state = *audited,
                                                   .reachable = false,
                                                   .references = {}});
        }

        detail::sort_unique(unknown);
        detail::sort_unique(result.reachable_content_ids);
        detail::sort_unique(result.missing_content_ids);
        detail::sort_unique(result.corrupt_content_ids);
        detail::sort_unique(result.orphan_content_ids);
        result.unknown_storage_objects = std::move(unknown);
        std::ranges::sort(result.contents, {}, &ContentEntry::content_id);
        return result;
    });
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
