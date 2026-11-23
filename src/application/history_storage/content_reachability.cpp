#include "application/history_storage/content_reachability.hpp"

#include "application/history_storage/remote_layout.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/key_derivation.hpp"
#include "crypto/pack.hpp"

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
    bool is_pack = false;
    std::uint64_t size = 0;
    std::vector<ContentReference> references;
};

} // namespace

namespace {

std::unexpected<Error> ws_fail(std::string detail) {
    return std::unexpected(
        detail::error(ErrorCode::WorkspaceFailure, std::move(detail)));
}

std::expected<void, Error> check_temp_file(const std::filesystem::path& path,
                                           bool remove_if_present,
                                           std::string_view detail) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if ((remove_if_present && error == std::errc::no_such_file_or_directory) ||
        status.type() == std::filesystem::file_type::not_found) {
        return remove_if_present ? std::expected<void, Error>{}
                                 : ws_fail(std::string{detail});
    }
    if (error || std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        return ws_fail(error ? std::string{detail} + ": " + error.message()
                             : std::string{detail});
    }
    if (remove_if_present && !std::filesystem::remove(path, error) && error) {
        return ws_fail("failed to remove temporary file: " + error.message());
    }
    return {};
}

std::expected<void, Error>
remove_temp_pair(const std::filesystem::path& enc,
                 const std::filesystem::path& plain) {
    for (const auto& path : {enc, plain}) {
        std::error_code error;
        std::filesystem::remove(path, error);
        if (error) {
            return ws_fail("failed to remove temporary file: " +
                           error.message());
        }
    }
    return {};
}

} // namespace

std::expected<ContentAuditResult, Error>
audit_content_object(transport::Transport& storage,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                     std::string_view content_id,
                     std::optional<std::string_view> expected_plaintext_hash,
                     std::optional<std::uint64_t> expected_size,
                     const std::filesystem::path& workspace,
                     std::size_t sequence,
                     bool expect_pack,
                     const std::filesystem::path* retain_plaintext_at) {
    const auto encrypted =
        workspace / ("content-" + std::to_string(sequence) + ".enc");
    const auto plaintext =
        retain_plaintext_at != nullptr
            ? *retain_plaintext_at
            : workspace / ("content-" + std::to_string(sequence) + ".plain");
    for (const auto& path : {encrypted, plaintext}) {
        if (auto ok =
                check_temp_file(path, true, "temporary file has invalid type");
            !ok) {
            return std::unexpected(ok.error());
        }
    }

    const auto downloaded = transport::get(storage, content_id, encrypted);
    if (!downloaded) {
        if (auto cleaned = remove_temp_pair(encrypted, plaintext); !cleaned) {
            return std::unexpected(cleaned.error());
        }
        if (downloaded.error().code == transport::ErrorCode::ObjectNotFound) {
            return ContentAuditResult{.state = ContentObjectState::Missing};
        }
        return std::unexpected(detail::transport_error(downloaded.error()));
    }
    if (auto ok =
            check_temp_file(encrypted, false, "invalid temporary download");
        !ok) {
        return std::unexpected(ok.error());
    }

    ContentAuditResult result{.state = ContentObjectState::Corrupt};
    if (!expect_pack && crypto::decrypt_file(encrypted, plaintext, key)) {
        if (auto ok = check_temp_file(
                plaintext, false, "file is not regular for verification");
            !ok) {
            return std::unexpected(ok.error());
        }
        std::error_code plain_size_error;
        const auto plain_size =
            std::filesystem::file_size(plaintext, plain_size_error);
        if (plain_size_error) {
            return ws_fail("could not read file size: " +
                           plain_size_error.message());
        }
        const auto actual_hash = crypto::content::hash_file(plaintext);
        if (!actual_hash) {
            return ws_fail(actual_hash.error());
        }
        const auto actual_hex = hash_hex(*actual_hash);
        if ((!expected_size || plain_size == *expected_size) &&
            (!expected_plaintext_hash ||
             actual_hex == *expected_plaintext_hash) &&
            crypto::content_identifier(key, *actual_hash) == content_id) {
            result.state = ContentObjectState::Present;
            result.plaintext_hash = actual_hex;
            result.size = plain_size;
        }
    } else if (expect_pack || !expected_plaintext_hash) {
        std::optional<Hash> expected_pack_hash;
        bool hash_valid = true;
        if (expected_plaintext_hash) {
            auto parsed = hash_from_hex(*expected_plaintext_hash);
            if (!parsed) {
                hash_valid = false;
            } else {
                expected_pack_hash = *parsed;
            }
        }
        Hash actual_pack_hash{};
        if (hash_valid) {
            auto verified = crypto::pack::decrypt_and_verify_pack(
                encrypted, key, expected_pack_hash, nullptr, &actual_pack_hash);
            if (verified &&
                crypto::pack_identifier(key, actual_pack_hash) == content_id) {
                std::uint64_t member_sum = 0;
                for (const auto& member : *verified) {
                    member_sum += member.size;
                }
                result.state = ContentObjectState::Present;
                result.plaintext_hash = hash_hex(actual_pack_hash);
                result.size = member_sum;
            }
        }
    }
    const auto cleaned =
        retain_plaintext_at != nullptr && !expect_pack &&
                result.state == ContentObjectState::Present
            ? check_temp_file(encrypted, true, "invalid temporary download")
            : remove_temp_pair(encrypted, plaintext);
    if (!cleaned) {
        return std::unexpected(cleaned.error());
    }
    return result;
}

namespace {} // namespace

ContentReachabilityResult
inventory_impl(transport::Transport& storage,
               std::span<const std::uint8_t, crypto::KEY_SIZE> key,
               std::optional<std::span<const std::string>> identifiers,
               const ReachabilityInventory& history_inventory,
               const std::filesystem::path& workspace_root,
               bool audit_payloads,
               bool include_references) {
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
            const auto record_object =
                [&](const std::string& remote_id,
                    const Hash& obj_hash,
                    bool is_pack,
                    std::string_view logical_path,
                    std::uint64_t ref_size) -> std::expected<void, Error> {
                auto [it, inserted] = by_remote_id.try_emplace(remote_id);
                auto& content = it->second;
                if (inserted) {
                    if (by_remote_id.size() > maximum_content_object_count) {
                        return std::unexpected(
                            detail::error(ErrorCode::LimitExceeded,
                                          "too many unique content objects"));
                    }
                    content.remote_id = remote_id;
                    content.plaintext_hash = hash_hex(obj_hash);
                    content.is_pack = is_pack;
                    content.size = ref_size;
                } else if (content.is_pack != is_pack ||
                           (!is_pack && content.size != ref_size)) {
                    return std::unexpected(
                        detail::error(ErrorCode::VerificationFailure,
                                      "content reference sizes conflict"));
                }
                auto& refs = content.references;
                if (include_references &&
                    (refs.empty() ||
                     refs.back().commit_id != commit.commit_id ||
                     refs.back().path != logical_path ||
                     refs.back().size != ref_size)) {
                    refs.push_back(ContentReference{
                        .commit_id = commit.commit_id,
                        .path = std::string{logical_path},
                        .size = ref_size,
                    });
                }
                return {};
            };
            for (const auto& row : commit.tree->tree.rows) {
                if (row.is_directory) {
                    continue;
                }
                if (const auto* packed = history::find_packed_blob(
                        commit.tree->storage, row.hash)) {
                    const auto remote_id =
                        crypto::pack_identifier(key, packed->pack_hash);
                    if (auto ok = record_object(remote_id,
                                                packed->pack_hash,
                                                true,
                                                row.path,
                                                row.size);
                        !ok) {
                        return std::unexpected(ok.error());
                    }
                } else if (const auto* chunked = history::find_chunked_file(
                               commit.tree->storage, row.hash)) {
                    for (const auto& chunk : chunked->chunks) {
                        const auto remote_id =
                            crypto::content_identifier(key, chunk.hash);
                        if (auto ok = record_object(remote_id,
                                                    chunk.hash,
                                                    false,
                                                    row.path,
                                                    chunk.size);
                            !ok) {
                            return std::unexpected(ok.error());
                        }
                    }
                } else {
                    const auto remote_id =
                        crypto::content_identifier(key, row.hash);
                    if (auto ok = record_object(
                            remote_id, row.hash, false, row.path, row.size);
                        !ok) {
                        return std::unexpected(ok.error());
                    }
                }
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
                if (is_history_object(layout, identifier) ||
                    is_activity_object(layout, identifier)) {
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
        auto audit =
            [&](std::string_view id,
                std::optional<std::string_view> plaintext_hash,
                std::optional<std::uint64_t> expected_size,
                bool expect_pack) -> std::expected<ContentObjectState, Error> {
            if (!audit_payloads) {
                return ContentObjectState::Present;
            }
            auto audited = audit_content_object(storage,
                                                key,
                                                id,
                                                plaintext_hash,
                                                expected_size,
                                                temporary->workspace.root,
                                                sequence++,
                                                expect_pack);
            if (!audited) {
                return std::unexpected(audited.error());
            }
            return audited->state;
        };

        for (auto& content : references) {
            auto& refs = content.references;
            std::ranges::sort(refs);
            refs.erase(std::ranges::unique(refs).begin(), refs.end());
            auto state = ContentObjectState::Missing;
            if (std::ranges::binary_search(physical, content.remote_id)) {
                auto audited =
                    audit(content.remote_id,
                          content.plaintext_hash,
                          content.is_pack
                              ? std::nullopt
                              : std::optional<std::uint64_t>{content.size},
                          content.is_pack);
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
            auto audited = audit(content_id, std::nullopt, std::nullopt, false);
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
    bool audit_payloads,
    bool include_references) {
    return inventory_impl(storage,
                          key,
                          std::nullopt,
                          history_inventory,
                          workspace_root,
                          audit_payloads,
                          include_references);
}

ContentReachabilityResult inventory_content_reachability(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    std::span<const std::string> identifiers,
    const ReachabilityInventory& history_inventory,
    const std::filesystem::path& workspace_root,
    bool audit_payloads,
    bool include_references) {
    return inventory_impl(storage,
                          key,
                          identifiers,
                          history_inventory,
                          workspace_root,
                          audit_payloads,
                          include_references);
}

} // namespace kasumi::application::history_storage
