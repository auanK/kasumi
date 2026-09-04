#include "application/history_storage/publication.hpp"

#include "application/history_storage/detail.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/physical_hash.hpp"
#include "platform/perf_trace.hpp"

#include <algorithm>
#include <limits>
#include <new>
#include <string_view>
#include <utility>

namespace kasumi::application::history_storage::detail {

PublishResult publish_impl(transport::Transport& storage,
                           std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                           const history::Commit& commit,
                           const std::filesystem::path& workspace_root) {
    auto object = publish_commit_object(storage, key, commit, workspace_root);
    if (!object) {
        return std::unexpected(object.error());
    }
    auto object_verified = verify_commit_object(storage,
                                                key,
                                                commit,
                                                object->head,
                                                workspace_root,
                                                object->physical_hash);
    if (!object_verified) {
        return std::unexpected(object_verified.error());
    }
    auto marker = publish_head_marker(storage, object->head, workspace_root);
    if (!marker) {
        return std::unexpected(marker.error());
    }
    auto marker_verified = verify_head_marker(
        storage, object->head, workspace_root, marker->physical_hash);
    if (!marker_verified) {
        return std::unexpected(marker_verified.error());
    }
    return PublishedCommit{.head = object->head,
                           .reused_existing_ciphertext =
                               object->reused_existing_ciphertext};
}

} // namespace kasumi::application::history_storage::detail

namespace kasumi::application::history_storage {

namespace {

inline constexpr std::string_view physical_hash_algorithm = "sha256";

std::expected<bool, Error>
verify_remote_physical_hash(transport::Transport& storage,
                            std::string_view identifier,
                            std::string_view local_hash,
                            std::string_view trace_name) {
    if (local_hash.empty()) {
        return false;
    }
    const auto trace = platform::perf_trace::begin();
    auto remote_hash =
        transport::physical_hash(storage, identifier, physical_hash_algorithm);
    platform::perf_trace::finish(trace_name, trace);
    if (!remote_hash) {
        if (remote_hash.error().code == transport::ErrorCode::Unsupported) {
            return false;
        }
        return std::unexpected(detail::transport_error(remote_hash.error()));
    }
    if (*remote_hash != local_hash) {
        return std::unexpected(detail::error(
            ErrorCode::VerificationFailure,
            "remote physical hash does not match published object"));
    }
    return true;
}

std::expected<void, Error>
verify_commit_object_impl(transport::Transport& storage,
                          std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                          const history::Commit& commit,
                          const HeadReference& reference,
                          const std::filesystem::path& workspace_root,
                          std::string_view local_physical_hash);

std::expected<void, Error>
verify_head_marker_impl(transport::Transport& storage,
                        const HeadReference& reference,
                        const std::filesystem::path& workspace_root,
                        std::string_view local_physical_hash);

PublishObjectResult
publish_commit_object_impl(transport::Transport& storage,
                           std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                           const history::Commit& commit,
                           const std::filesystem::path& workspace_root,
                           bool scoped) {
    if (!transport::valid(storage)) {
        return std::unexpected(
            detail::error(ErrorCode::InvalidInput, "invalid transport"));
    }
    if (commit.height == std::numeric_limits<std::uint64_t>::max()) {
        return std::unexpected(detail::error(
            ErrorCode::LimitExceeded, "commit height cannot have a child"));
    }

    const auto serialization_trace = platform::perf_trace::begin();
    auto canonical = history::serialize(commit);
    if (!canonical) {
        return std::unexpected(detail::history_error(canonical.error()));
    }
    const auto commit_id = crypto::commit_identifier(key, *canonical);
    platform::perf_trace::finish("commit serialization", serialization_trace);
    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(temporary.error());
    }
    const auto plaintext = (*temporary)->root / "commit.kcom";
    const auto ciphertext = (*temporary)->root / "commit.ciphertext";
    if (auto written = detail::write_file(plaintext, *canonical); !written) {
        return std::unexpected(written.error());
    }

    auto inventory = scoped ? std::expected<detail::HistoryInventory,
                                            Error>{detail::HistoryInventory{}}
                            : detail::build_history_inventory(storage);
    if (!inventory) {
        return std::unexpected(inventory.error());
    }

    HeadReference reference{.commit_id = commit_id, .ciphertext_id = {}};
    bool reused = false;
    std::string physical_hash;
    std::size_t sequence = 0;
    if (const auto found = inventory->commit_variants.find(commit_id);
        found != inventory->commit_variants.end()) {
        for (const auto& candidate : found->second) {
            auto loaded = detail::try_load_variant(
                storage, key, candidate, (*temporary)->root, sequence++);
            if (!loaded) {
                return std::unexpected(loaded.error());
            }
            if (loaded->state != detail::VariantState::Valid ||
                !loaded->commit.has_value()) {
                continue;
            }
            auto loaded_bytes = history::serialize(loaded->commit->commit);
            if (loaded_bytes && *loaded_bytes == *canonical) {
                auto marker_state = detail::inspect_marker(
                    storage, candidate, (*temporary)->root, sequence);
                if (!marker_state) {
                    return std::unexpected(marker_state.error());
                }
                if (*marker_state == detail::MarkerState::Invalid) {
                    continue;
                }
                auto candidate_delta =
                    detail::publication_delta(*inventory, candidate);
                auto budget = detail::validate_publication_budget(
                    *inventory, candidate, candidate_delta, !scoped);
                if (!budget) {
                    return std::unexpected(budget.error());
                }
                reference = candidate;
                reused = true;
                break;
            }
        }
    }

    if (!reused) {
        const auto encryption_trace = platform::perf_trace::begin();
        const bool encrypted_commit = crypto::encrypt_file(
            plaintext, ciphertext, key, crypto::FilePurpose::History);
        platform::perf_trace::finish("commit encryption", encryption_trace);
        if (!encrypted_commit) {
            return std::unexpected(detail::error(ErrorCode::CryptoFailure,
                                                 "could not encrypt commit"));
        }
        auto ciphertext_hash = crypto::content::hash_file(ciphertext);
        if (!ciphertext_hash) {
            return std::unexpected(detail::error(ErrorCode::CryptoFailure,
                                                 ciphertext_hash.error()));
        }
        reference.ciphertext_id = hash_hex(*ciphertext_hash);
        auto local_physical_hash =
            crypto::physical::hash_file(ciphertext, physical_hash_algorithm);
        if (!local_physical_hash) {
            return std::unexpected(detail::error(ErrorCode::CryptoFailure,
                                                 local_physical_hash.error()));
        }
        physical_hash = std::move(*local_physical_hash);
        auto delta = detail::publication_delta(*inventory, reference);
        auto budget = detail::validate_publication_budget(
            *inventory, reference, delta, !scoped);
        if (!budget) {
            return std::unexpected(budget.error());
        }
        const auto put_trace = platform::perf_trace::begin();
        auto published = transport::put(
            storage, ciphertext, detail::commit_object(reference));
        platform::perf_trace::finish("rc/put_commit", put_trace);
        if (!published) {
            if (!transport::mutation_result_is_ambiguous(published.error())) {
                return std::unexpected(
                    detail::transport_error(published.error()));
            }
            auto verified = verify_commit_object_impl(
                storage, key, commit, reference, workspace_root, physical_hash);
            if (!verified) {
                return std::unexpected(verified.error());
            }
        }
    }

    return PublishedCommitObject{.head = reference,
                                 .marker_id = marker_object(reference),
                                 .physical_hash = std::move(physical_hash),
                                 .reused_existing_ciphertext = reused};
}

std::expected<void, Error>
verify_commit_object_impl(transport::Transport& storage,
                          std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                          const history::Commit& commit,
                          const HeadReference& reference,
                          const std::filesystem::path& workspace_root,
                          std::string_view local_physical_hash) {
    if (!valid(reference)) {
        return std::unexpected(detail::error(ErrorCode::InvalidIdentifier,
                                             "invalid head reference"));
    }
    const auto canonical = history::serialize(commit);
    if (!canonical ||
        crypto::commit_identifier(key, *canonical) != reference.commit_id) {
        return std::unexpected(
            detail::error(ErrorCode::InvalidCommit, "commit ID mismatch"));
    }
    if (!local_physical_hash.empty()) {
        platform::perf_trace::count("commit physical hash calls");
    }
    auto physical =
        verify_remote_physical_hash(storage,
                                    detail::commit_object(reference),
                                    local_physical_hash,
                                    "commit remote hash verification");
    if (!physical) {
        return std::unexpected(physical.error());
    }
    if (*physical) {
        return {};
    }
    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(temporary.error());
    }
    std::size_t sequence = 0;
    return detail::verify_published_commit(
        storage, key, commit, reference, (*temporary)->root, sequence);
}

PublishHeadResult
publish_head_marker_impl(transport::Transport& storage,
                         const HeadReference& reference,
                         const std::filesystem::path& workspace_root,
                         bool scoped) {
    if (!transport::valid(storage) || !valid(reference)) {
        return std::unexpected(detail::error(
            ErrorCode::InvalidInput, "invalid transport or head reference"));
    }
    auto inventory = scoped ? std::expected<detail::HistoryInventory,
                                            Error>{detail::HistoryInventory{}}
                            : detail::build_history_inventory(storage);
    if (!inventory) {
        return std::unexpected(inventory.error());
    }
    auto delta = detail::publication_delta(*inventory, reference);
    auto budget = detail::validate_publication_budget(
        *inventory, reference, delta, !scoped);
    if (!budget) {
        return std::unexpected(budget.error());
    }

    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(temporary.error());
    }
    const auto marker = (*temporary)->root / "marker.head";
    auto marker_bytes = encode_marker(reference);
    if (!marker_bytes) {
        return std::unexpected(marker_bytes.error());
    }
    if (auto written = detail::write_file(marker, *marker_bytes); !written) {
        return std::unexpected(written.error());
    }

    auto state = detail::MarkerState::Absent;
    if (!delta.adds_marker_object) {
        std::size_t sequence = 0;
        auto inspected = detail::inspect_marker(
            storage, reference, (*temporary)->root, sequence);
        if (!inspected) {
            return std::unexpected(inspected.error());
        }
        state = *inspected;
        if (state == detail::MarkerState::Invalid) {
            return std::unexpected(detail::error(ErrorCode::InvalidMarker,
                                                 "existing marker is invalid"));
        }
    }
    std::string physical_hash;
    if (state == detail::MarkerState::Absent) {
        auto local_physical_hash =
            crypto::physical::hash_file(marker, physical_hash_algorithm);
        if (!local_physical_hash) {
            return std::unexpected(detail::error(ErrorCode::CryptoFailure,
                                                 local_physical_hash.error()));
        }
        physical_hash = std::move(*local_physical_hash);
        const auto put_trace = platform::perf_trace::begin();
        auto uploaded =
            transport::put(storage, marker, marker_object(reference));
        platform::perf_trace::finish("rc/put_marker", put_trace);
        if (!uploaded) {
            if (!transport::mutation_result_is_ambiguous(uploaded.error())) {
                return std::unexpected(
                    detail::transport_error(uploaded.error()));
            }
            auto verified = verify_head_marker_impl(
                storage, reference, workspace_root, physical_hash);
            if (!verified) {
                return std::unexpected(verified.error());
            }
        }
    }
    return PublishedHeadMarker{.marker_id = marker_object(reference),
                               .physical_hash = std::move(physical_hash)};
}

std::expected<void, Error>
verify_head_marker_impl(transport::Transport& storage,
                        const HeadReference& reference,
                        const std::filesystem::path& workspace_root,
                        std::string_view local_physical_hash) {
    if (!transport::valid(storage) || !valid(reference)) {
        return std::unexpected(detail::error(
            ErrorCode::InvalidInput, "invalid transport or head reference"));
    }
    if (!local_physical_hash.empty()) {
        platform::perf_trace::count("head physical hash calls");
    }
    auto physical =
        verify_remote_physical_hash(storage,
                                    marker_object(reference),
                                    local_physical_hash,
                                    "head remote hash verification");
    if (!physical) {
        return std::unexpected(physical.error());
    }
    if (*physical) {
        return {};
    }
    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(temporary.error());
    }
    std::size_t sequence = 0;
    auto state = detail::inspect_marker(
        storage, reference, (*temporary)->root, sequence);
    if (!state) {
        return std::unexpected(state.error());
    }
    if (*state != detail::MarkerState::Valid) {
        return std::unexpected(detail::error(ErrorCode::VerificationFailure,
                                             "head marker is not valid"));
    }
    return {};
}

HeadMarkerInspection
inspect_head_marker_impl(transport::Transport& storage,
                         const HeadReference& reference,
                         const std::filesystem::path& workspace_root) {
    if (!transport::valid(storage) || !valid(reference)) {
        return std::unexpected(detail::error(
            ErrorCode::InvalidInput, "invalid transport or head reference"));
    }
    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(temporary.error());
    }
    std::size_t sequence = 0;
    auto state = detail::inspect_marker(
        storage, reference, (*temporary)->root, sequence);
    if (!state) {
        return std::unexpected(state.error());
    }
    switch (*state) {
        case detail::MarkerState::Absent:
            return HeadMarkerState::Absent;
        case detail::MarkerState::Valid:
            return HeadMarkerState::Valid;
        case detail::MarkerState::Invalid:
            return HeadMarkerState::Invalid;
    }
    return std::unexpected(
        detail::error(ErrorCode::InvalidMarker, "unknown marker state"));
}

} // namespace

PublishObjectResult
publish_commit_object(transport::Transport& storage,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                      const history::Commit& commit,
                      const std::filesystem::path& workspace_root) {
    try {
        return publish_commit_object_impl(
            storage, key, commit, workspace_root, false);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            detail::error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

PublishObjectResult publish_commit_object_scoped(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const history::Commit& commit,
    const std::filesystem::path& workspace_root) {
    try {
        return publish_commit_object_impl(
            storage, key, commit, workspace_root, true);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            detail::error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

std::expected<void, Error>
verify_commit_object(transport::Transport& storage,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                     const history::Commit& commit,
                     const HeadReference& reference,
                     const std::filesystem::path& workspace_root,
                     std::string_view local_physical_hash) {
    try {
        return verify_commit_object_impl(storage,
                                         key,
                                         commit,
                                         reference,
                                         workspace_root,
                                         local_physical_hash);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            detail::error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

PublishHeadResult
publish_head_marker(transport::Transport& storage,
                    const HeadReference& reference,
                    const std::filesystem::path& workspace_root) {
    try {
        return publish_head_marker_impl(
            storage, reference, workspace_root, false);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            detail::error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

PublishHeadResult
publish_head_marker_scoped(transport::Transport& storage,
                           const HeadReference& reference,
                           const std::filesystem::path& workspace_root) {
    try {
        return publish_head_marker_impl(
            storage, reference, workspace_root, true);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            detail::error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

std::expected<void, Error>
verify_head_marker(transport::Transport& storage,
                   const HeadReference& reference,
                   const std::filesystem::path& workspace_root,
                   std::string_view local_physical_hash) {
    try {
        return verify_head_marker_impl(
            storage, reference, workspace_root, local_physical_hash);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            detail::error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

HeadMarkerInspection
inspect_head_marker(transport::Transport& storage,
                    const HeadReference& reference,
                    const std::filesystem::path& workspace_root) {
    try {
        return inspect_head_marker_impl(storage, reference, workspace_root);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            detail::error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

std::string marker_identifier(const HeadReference& reference) {
    return marker_object(reference);
}

std::expected<std::vector<std::string>, Error>
list_remote_head_commit_ids(transport::Transport& storage) {
    if (!transport::valid(storage)) {
        return std::unexpected(
            detail::error(ErrorCode::InvalidInput, "invalid transport"));
    }
    auto listing = transport::list(storage, detail::heads_prefix);
    if (!listing) {
        if (listing.error().code == transport::ErrorCode::StorageNotFound) {
            return std::vector<std::string>{};
        }
        return std::unexpected(detail::transport_error(listing.error()));
    }
    std::vector<std::string> heads;
    for (const auto& name : *listing) {
        const auto object_path = std::string{detail::heads_prefix} + name;
        if (maintenance_protocol::is_control_object(object_path)) {
            continue;
        }
        auto ref = parse_marker_object(object_path);
        if (ref) {
            heads.push_back(ref->commit_id);
        }
    }
    std::ranges::sort(heads);
    heads.erase(std::ranges::unique(heads).begin(), heads.end());
    return heads;
}

} // namespace kasumi::application::history_storage
