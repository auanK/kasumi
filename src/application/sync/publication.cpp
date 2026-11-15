#include "application/sync/publication.hpp"

#include "application/history_storage/remote_layout.hpp"
#include "application/observation/history.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace kasumi::application::sync::publication {
namespace {

std::optional<std::string>
commit_identifier(std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                  const history::Commit& commit) {
    auto canonical = history::serialize(commit);
    return canonical ? std::optional{crypto::commit_identifier(key, *canonical)}
                     : std::nullopt;
}

} // namespace

PublishObjectResult
publish_commit_object(transport::Transport& storage,
                      const history_storage::RemoteLayout& layout,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                      const PreparedCommit& prepared,
                      const std::filesystem::path& workspace_root) {
    auto computed = commit_identifier(key, prepared.commit);
    if (!computed || !history::valid_commit_id(prepared.commit_id) ||
        *computed != prepared.commit_id) {
        return std::unexpected(
            Error{ErrorCode::InvalidCommit, "invalid commit"});
    }
    auto published = history_storage::publish_commit_object_scoped(
        storage, layout, key, prepared.commit, workspace_root);
    if (!published) {
        return published;
    }
    if (published->head.commit_id != prepared.commit_id) {
        return std::unexpected(
            Error{ErrorCode::InvalidCommit, "published commit ID mismatch"});
    }
    return published;
}

PublishObjectResult
publish_commit_object(transport::Transport& storage,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                      const PreparedCommit& prepared,
                      const std::filesystem::path& workspace_root) {
    return publish_commit_object(storage,
                                 history_storage::derive_remote_layout(key),
                                 key,
                                 prepared,
                                 workspace_root);
}

PrepareResult
prepare_commit(Snapshot tree,
               bool history_present,
               std::uint64_t observed_height,
               std::span<const std::string> logical_heads,
               std::int64_t created_at,
               std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    if (created_at <= 0) {
        return std::unexpected(
            Error{ErrorCode::InvalidInput, "invalid commit timestamp"});
    }
    if (!valid_snapshot(tree, false)) {
        return std::unexpected(Error{ErrorCode::InvalidInput, "invalid tree"});
    }
    history::CommitResult commit;
    if (!history_present) {
        if (!logical_heads.empty() || observed_height != 0) {
            return std::unexpected(Error{ErrorCode::InvalidInput,
                                         "invalid bootstrap history state"});
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
            return std::unexpected(Error{ErrorCode::InvalidInput,
                                         "invalid history heads or height"});
        }
        commit =
            history::make_commit(observed_height + 1,
                                 std::vector<std::string>{logical_heads.begin(),
                                                          logical_heads.end()},
                                 std::move(tree),
                                 created_at);
    }
    if (!commit) {
        return std::unexpected(
            Error{commit.error().code == history::ErrorCode::LimitExceeded
                      ? ErrorCode::LimitExceeded
                      : ErrorCode::InvalidCommit,
                  commit.error().detail});
    }
    auto id = commit_identifier(key, *commit);
    if (!id) {
        return std::unexpected(
            Error{ErrorCode::InvalidCommit, "could not encode commit"});
    }
    return PreparedCommit{.commit = std::move(*commit),
                          .commit_id = std::move(*id)};
}

std::expected<void, Error>
verify_commit_object(transport::Transport& storage,
                     const history_storage::RemoteLayout& layout,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                     const PreparedCommit& prepared,
                     const history_storage::HeadReference& reference,
                     const std::filesystem::path& workspace_root,
                     std::string_view local_physical_hash) {
    return history_storage::verify_commit_object(storage,
                                                 layout,
                                                 key,
                                                 prepared.commit,
                                                 reference,
                                                 workspace_root,
                                                 local_physical_hash);
}

std::expected<void, Error>
verify_commit_object(transport::Transport& storage,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                     const PreparedCommit& prepared,
                     const history_storage::HeadReference& reference,
                     const std::filesystem::path& workspace_root,
                     std::string_view local_physical_hash) {
    return history_storage::verify_commit_object(storage,
                                                 key,
                                                 prepared.commit,
                                                 reference,
                                                 workspace_root,
                                                 local_physical_hash);
}

PublishResult
publish_commit(transport::Transport& storage,
               std::span<const std::uint8_t, crypto::KEY_SIZE> key,
               const PreparedCommit& prepared,
               const std::filesystem::path& workspace_root) {
    const auto layout = history_storage::derive_remote_layout(key);
    auto object =
        publish_commit_object(storage, layout, key, prepared, workspace_root);
    if (!object) {
        return std::unexpected(object.error());
    }
    if (auto verified = verify_commit_object(storage,
                                             layout,
                                             key,
                                             prepared,
                                             object->head,
                                             workspace_root,
                                             object->physical_hash);
        !verified) {
        return std::unexpected(verified.error());
    }
    auto marker = history_storage::publish_head_marker_scoped(
        storage, layout, object->head, workspace_root);
    if (!marker) {
        return std::unexpected(marker.error());
    }
    if (auto verified = verify_head_marker(storage,
                                           layout,
                                           object->head,
                                           workspace_root,
                                           marker->physical_hash);
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
        return std::unexpected(
            Error{ErrorCode::InvalidInput, "invalid commit ID"});
    }
    auto loaded = history_storage::load_history(storage, key, workspace_root);
    if (!loaded) {
        return std::unexpected(loaded.error());
    }
    const auto found = std::ranges::find(
        loaded->commits, commit_id, &history::LoadedCommit::id);
    return found == loaded->commits.end()
               ? std::optional<history::LoadedCommit>{}
               : std::optional<history::LoadedCommit>{std::move(*found)};
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
        using ObsCode = observation::history::ErrorCode;
        ErrorCode code = ErrorCode::InvalidCommit;
        if (observed.error().code == ObsCode::TransportFailure)
            code = ErrorCode::TransportFailure;
        else if (observed.error().code == ObsCode::WorkspaceFailure)
            code = ErrorCode::WorkspaceFailure;
        else if (observed.error().code == ObsCode::LimitExceeded)
            code = ErrorCode::LimitExceeded;
        return std::unexpected(Error{code, observed.error().detail});
    }
    if (observed->ancestral_marked_heads.empty()) {
        return PruneResult{};
    }
    const auto layout = history_storage::derive_remote_layout(key);
    auto removed = history_storage::remove_marker_variants(
        storage, layout, observed->ancestral_marked_heads);
    if (!removed) {
        return std::unexpected(removed.error());
    }
    return PruneResult{.removed_markers = removed->removed};
}

PruneMarkersResult prune_observed_parent_markers(
    transport::Transport& storage,
    const history_storage::RemoteLayout& layout,
    std::span<const std::string> parent_ids,
    std::span<const std::string> observed_marker_identifiers) {
    auto removed = history_storage::remove_marker_variants(
        storage, layout, parent_ids, observed_marker_identifiers);
    if (!removed) {
        return std::unexpected(removed.error());
    }
    return PruneResult{.removed_markers = removed->removed};
}

} // namespace kasumi::application::sync::publication
