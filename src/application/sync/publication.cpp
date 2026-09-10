#include "application/sync/publication.hpp"

#include "application/observation/history.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace kasumi::application::sync::publication {
namespace {

Error history_error(const history::Error& source) {
    return Error{.code = source.code == history::ErrorCode::LimitExceeded
                             ? ErrorCode::LimitExceeded
                             : ErrorCode::InvalidCommit,
                 .detail = source.detail};
}

Error storage_error(const history_storage::Error& source) {
    ErrorCode code = ErrorCode::HistoryStorageFailure;
    switch (source.code) {
        case history_storage::ErrorCode::TransportFailure:
            code = ErrorCode::TransportFailure;
            break;
        case history_storage::ErrorCode::WorkspaceFailure:
            code = ErrorCode::WorkspaceFailure;
            break;
        case history_storage::ErrorCode::LimitExceeded:
            code = ErrorCode::LimitExceeded;
            break;
        case history_storage::ErrorCode::VerificationFailure:
            code = ErrorCode::VerificationFailure;
            break;
        case history_storage::ErrorCode::InvalidCommit:
        case history_storage::ErrorCode::InvalidIdentifier:
            code = ErrorCode::InvalidCommit;
            break;
        default:
            break;
    }
    return Error{.code = code, .detail = source.detail};
}

std::optional<std::string>
commit_identifier(std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                  const history::Commit& commit) {
    auto canonical = history::serialize(commit);
    if (!canonical) {
        return std::nullopt;
    }
    return crypto::commit_identifier(key, *canonical);
}

} // namespace

PublishObjectResult
publish_commit_object(transport::Transport& storage,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                      const PreparedCommit& prepared,
                      const std::filesystem::path& workspace_root) {
    auto computed = commit_identifier(key, prepared.commit);
    if (!computed || !history::valid_commit_id(prepared.commit_id) ||
        *computed != prepared.commit_id) {
        return std::unexpected(Error{.code = ErrorCode::InvalidCommit,
                                     .detail = "invalid commit"});
    }
    auto published = history_storage::publish_commit_object_scoped(
        storage, key, prepared.commit, workspace_root);
    if (!published) {
        return std::unexpected(storage_error(published.error()));
    }
    if (published->head.commit_id != prepared.commit_id) {
        return std::unexpected(Error{.code = ErrorCode::InvalidCommit,
                                     .detail = "published commit ID mismatch"});
    }
    return std::move(*published);
}

PublishHeadResult
publish_head_marker(transport::Transport& storage,
                    const history_storage::HeadReference& reference,
                    const std::filesystem::path& workspace_root) {
    auto published = history_storage::publish_head_marker_scoped(
        storage, reference, workspace_root);
    if (!published) {
        return std::unexpected(storage_error(published.error()));
    }
    return std::move(*published);
}

PrepareResult
prepare_commit(Snapshot tree,
               bool history_present,
               std::uint64_t observed_height,
               std::span<const std::string> logical_heads,
               std::int64_t created_at,
               std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    if (created_at <= 0) {
        return std::unexpected(Error{.code = ErrorCode::InvalidInput,
                                     .detail = "invalid commit timestamp"});
    }
    if (!valid_snapshot(tree, false)) {
        return std::unexpected(
            Error{.code = ErrorCode::InvalidInput, .detail = "invalid tree"});
    }
    history::CommitResult commit;
    if (!history_present) {
        if (!logical_heads.empty() || observed_height != 0) {
            return std::unexpected(
                Error{.code = ErrorCode::InvalidInput,
                      .detail = "invalid bootstrap history state"});
        }
        commit = history::make_bootstrap(std::move(tree), 0, created_at);
    } else {
        if (logical_heads.empty() || !std::ranges::is_sorted(logical_heads) ||
            std::ranges::adjacent_find(logical_heads) != logical_heads.end() ||
            logical_heads.size() > history::maximum_parent_count ||
            std::ranges::any_of(logical_heads,
                                [](std::string_view id) {
                                    return !history::valid_commit_id(id);
                                }) ||
            observed_height == std::numeric_limits<std::uint64_t>::max()) {
            return std::unexpected(
                Error{.code = ErrorCode::InvalidInput,
                      .detail = "invalid history heads or height"});
        }
        commit =
            history::make_commit(observed_height + 1,
                                 std::vector<std::string>{logical_heads.begin(),
                                                          logical_heads.end()},
                                 std::move(tree),
                                 created_at);
    }
    if (!commit) {
        return std::unexpected(history_error(commit.error()));
    }
    auto id = commit_identifier(key, *commit);
    if (!id) {
        return std::unexpected(Error{.code = ErrorCode::InvalidCommit,
                                     .detail = "could not encode commit"});
    }
    return PreparedCommit{.commit = std::move(*commit),
                          .commit_id = std::move(*id)};
}

std::expected<void, Error>
verify_commit_object(transport::Transport& storage,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                     const PreparedCommit& prepared,
                     const history_storage::HeadReference& reference,
                     const std::filesystem::path& workspace_root,
                     std::string_view local_physical_hash) {
    auto verified = history_storage::verify_commit_object(storage,
                                                          key,
                                                          prepared.commit,
                                                          reference,
                                                          workspace_root,
                                                          local_physical_hash);
    if (!verified) {
        return std::unexpected(storage_error(verified.error()));
    }
    return {};
}

std::expected<void, Error>
verify_head_marker(transport::Transport& storage,
                   const history_storage::HeadReference& reference,
                   const std::filesystem::path& workspace_root,
                   std::string_view local_physical_hash) {
    auto verified = history_storage::verify_head_marker(
        storage, reference, workspace_root, local_physical_hash);
    if (!verified) {
        return std::unexpected(storage_error(verified.error()));
    }
    return {};
}

HeadMarkerInspection
inspect_head_marker(transport::Transport& storage,
                    const history_storage::HeadReference& reference,
                    const std::filesystem::path& workspace_root) {
    auto inspected = history_storage::inspect_head_marker(
        storage, reference, workspace_root);
    if (!inspected) {
        return std::unexpected(storage_error(inspected.error()));
    }
    return std::move(*inspected);
}

PublishResult
publish_commit(transport::Transport& storage,
               std::span<const std::uint8_t, crypto::KEY_SIZE> key,
               const PreparedCommit& prepared,
               const std::filesystem::path& workspace_root) {
    auto computed = commit_identifier(key, prepared.commit);
    if (!computed || !history::valid_commit_id(prepared.commit_id) ||
        *computed != prepared.commit_id) {
        return std::unexpected(Error{.code = ErrorCode::InvalidCommit,
                                     .detail = "invalid commit"});
    }
    auto object = publish_commit_object(storage, key, prepared, workspace_root);
    if (!object) {
        return std::unexpected(object.error());
    }
    if (auto verified = verify_commit_object(storage,
                                             key,
                                             prepared,
                                             object->head,
                                             workspace_root,
                                             object->physical_hash);
        !verified) {
        return std::unexpected(verified.error());
    }
    auto marker = kasumi::application::sync::publication::publish_head_marker(
        storage, object->head, workspace_root);
    if (!marker) {
        return std::unexpected(marker.error());
    }
    if (auto verified =
            kasumi::application::sync::publication::verify_head_marker(
                storage, object->head, workspace_root, marker->physical_hash);
        !verified) {
        return std::unexpected(verified.error());
    }
    return history_storage::PublishedCommit{
        .head = object->head,
        .reused_existing_ciphertext = object->reused_existing_ciphertext};
}

ReachableResult
find_reachable_commit(transport::Transport& storage,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                      const std::filesystem::path& workspace_root,
                      std::string_view commit_id) {
    if (!history::valid_commit_id(commit_id)) {
        return std::unexpected(Error{.code = ErrorCode::InvalidInput,
                                     .detail = "invalid commit ID"});
    }
    auto loaded = history_storage::load_history(storage, key, workspace_root);
    if (!loaded) {
        return std::unexpected(storage_error(loaded.error()));
    }
    const auto found = std::ranges::find(
        loaded->commits, commit_id, &history::LoadedCommit::id);
    if (found == loaded->commits.end()) {
        return std::optional<history::LoadedCommit>{};
    }
    return std::move(*found);
}

PruneMarkersResult prune_current_ancestral_markers(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const std::filesystem::path& workspace_root) {
    // A marked ancestor does not become a head again upon receiving
    // descendants.
    auto observed =
        observation::history::observe(storage, key, workspace_root, false);
    if (!observed) {
        ErrorCode code = ErrorCode::ObservationFailure;
        if (observed.error().code ==
            observation::history::ErrorCode::TransportFailure)
            code = ErrorCode::TransportFailure;
        else if (observed.error().code ==
                 observation::history::ErrorCode::WorkspaceFailure)
            code = ErrorCode::WorkspaceFailure;
        else if (observed.error().code ==
                 observation::history::ErrorCode::LimitExceeded)
            code = ErrorCode::LimitExceeded;
        return std::unexpected(
            Error{.code = code, .detail = observed.error().detail});
    }
    if (observed->ancestral_marked_heads.empty()) {
        return PruneResult{};
    }
    auto removed = history_storage::remove_marker_variants(
        storage, observed->ancestral_marked_heads);
    if (!removed) {
        return std::unexpected(storage_error(removed.error()));
    }
    return PruneResult{.removed_markers = removed->removed};
}

PruneMarkersResult prune_observed_parent_markers(
    transport::Transport& storage,
    std::span<const std::string> parent_ids,
    std::span<const std::string> observed_marker_identifiers) {
    auto removed = history_storage::remove_marker_variants(
        storage, parent_ids, observed_marker_identifiers);
    if (!removed) {
        return std::unexpected(storage_error(removed.error()));
    }
    return PruneResult{.removed_markers = removed->removed};
}

} // namespace kasumi::application::sync::publication
