#include "application/observation/history.hpp"

#include "application/history_storage/history_storage.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "core/hasher.hpp"
#include "core/history.hpp"
#include "crypto/key_derivation.hpp"
#include "history_detail.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <exception>
#include <iterator>
#include <limits>
#include <new>
#include <optional>
#include <string_view>
#include <system_error>
#include <utility>

namespace kasumi::application::observation::history {
ObservationHints
make_observation_hints(state_storage::StoredState state,
                       const history_storage::RemoteLayout& layout,
                       bool use_frontier) {
    ObservationHints hints;
    if (use_frontier) {
        hints.frontier.emplace();
        hints.frontier->anchors.push_back(
            history_storage::KnownHistoryAnchor{
                .commit_id = state.commit_id,
                .height = state.height,
                .tree = std::move(state.tree),
                .storage = std::move(state.storage_manifest)});
        if (!state.epoch_id.empty()) {
            hints.frontier->accepted_epoch = history_storage::epoch::Reference{
                .sequence = state.epoch_sequence,
                .epoch_id = std::move(state.epoch_id)};
        }
    }
    const history_storage::HeadReference reference{
        .commit_id = std::move(state.commit_id),
        .ciphertext_id = std::move(state.ciphertext_id)};
    if (!reference.ciphertext_id.empty() && history_storage::valid(reference)) {
        hints.trusted_marker_identifiers.push_back(
            history_storage::marker_object(layout, reference));
    }
    return hints;
}

namespace {

constexpr std::size_t maximum_audited_content_object_count = 1'000'000;

bool valid_content_identifier(std::string_view identifier) noexcept {
    return kasumi::history::valid_commit_id(identifier);
}

Error storage_error(const kasumi::application::history_storage::Error& source) {
    const auto code = [&] {
        switch (source.code) {
            case kasumi::application::history_storage::ErrorCode::LimitExceeded:
                return ErrorCode::LimitExceeded;
            case kasumi::application::history_storage::ErrorCode::
                TransportFailure:
                return ErrorCode::TransportFailure;
            case kasumi::application::history_storage::ErrorCode::
                WorkspaceFailure:
                return ErrorCode::WorkspaceFailure;
            default:
                return ErrorCode::HistoryStorageFailure;
        }
    }();
    return Error{.code = code, .detail = source.detail};
}

Error resolution_error(const kasumi::history::Error& source) {
    return Error{
        .code = source.code == kasumi::history::ErrorCode::LimitExceeded
                    ? ErrorCode::LimitExceeded
                    : ErrorCode::ResolutionFailure,
        .detail = source.detail,
    };
}

Error invalid_input(std::string detail) {
    return Error{.code = ErrorCode::InvalidInput, .detail = std::move(detail)};
}

bool collect_content_identifiers_into(std::span<const std::string> identifiers,
                                      std::size_t maximum_count,
                                      std::unordered_set<std::string>& result) {
    result.reserve(std::min(identifiers.size(), maximum_count));
    for (const auto& identifier : identifiers) {
        if (!valid_content_identifier(identifier)) {
            continue;
        }
        if (result.size() >= maximum_count && !result.contains(identifier)) {
            return false;
        }
        result.insert(identifier);
    }
    return true;
}

std::expected<void, Error>
validate_workspace_root(const std::filesystem::path& root) {
    if (root.empty()) {
        return std::unexpected(Error{.code = ErrorCode::InvalidInput,
                                     .detail = "workspace root is empty"});
    }
    const auto fail = [](std::string detail) {
        return std::unexpected(Error{.code = ErrorCode::WorkspaceFailure,
                                     .detail = std::move(detail)});
    };
    std::error_code filesystem_error;
    const auto status = std::filesystem::symlink_status(root, filesystem_error);
    if (filesystem_error) {
        return fail(filesystem_error == std::errc::no_such_file_or_directory
                        ? "workspace root does not exist"
                        : "could not inspect workspace root: " +
                              filesystem_error.message());
    }
    if (std::filesystem::is_symlink(status)) {
        return fail("workspace root is a symbolic link");
    }
    if (!std::filesystem::exists(status)) {
        return fail("workspace root does not exist");
    }
    if (!std::filesystem::is_directory(status)) {
        return fail("workspace root is not a directory");
    }
    return {};
}

bool sorted_unique_ids(const std::vector<std::string>& ids) noexcept {
    if (!std::ranges::is_sorted(ids) ||
        std::ranges::adjacent_find(ids) != ids.end()) {
        return false;
    }
    return std::ranges::all_of(ids, kasumi::history::valid_commit_id);
}

std::expected<std::vector<std::string>, Error>
ancestral_heads(const std::vector<std::string>& marked,
                const std::vector<std::string>& logical) {
    if (!sorted_unique_ids(marked) || !sorted_unique_ids(logical) ||
        logical.empty() ||
        logical.size() > kasumi::history::maximum_parent_count ||
        !std::ranges::includes(marked, logical)) {
        return std::unexpected(Error{
            .code = ErrorCode::ResolutionFailure,
            .detail = "resolution has invalid heads",
        });
    }

    std::vector<std::string> result;
    std::ranges::set_difference(marked, logical, std::back_inserter(result));
    return result;
}

std::expected<std::vector<std::string>, Error>
validate_resolution(const kasumi::history::Resolution& resolution,
                    const std::vector<std::string>& marked) {
    if (!kasumi::valid_snapshot(resolution.tree, false) ||
        resolution.height == std::numeric_limits<std::uint64_t>::max()) {
        return std::unexpected(
            Error{.code = resolution.height ==
                                  std::numeric_limits<std::uint64_t>::max()
                              ? ErrorCode::LimitExceeded
                              : ErrorCode::ResolutionFailure,
                  .detail = "resolution produces an invalid tree or height"});
    }
    return ancestral_heads(marked, resolution.heads);
}

} // namespace

namespace detail {

std::expected<std::unordered_set<std::string>, Error>
collect_content_identifiers(std::span<const std::string> identifiers,
                            std::size_t maximum_count) {
    std::unordered_set<std::string> result;
    if (!collect_content_identifiers_into(identifiers, maximum_count, result)) {
        return std::unexpected(Error{
            .code = ErrorCode::LimitExceeded,
            .detail = "too many content identifiers",
        });
    }
    return result;
}

} // namespace detail

ObserveResult observe(transport::Transport& storage,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                      const std::filesystem::path& workspace_root,
                      bool audit_content_objects_requested,
                      const history_storage::KnownHistoryFrontier* frontier,
                      std::span<const std::string> trusted_marker_identifiers,
                      bool complete_history) {
    try {
        if (!transport::valid(storage)) {
            return std::unexpected(invalid_input("invalid transport"));
        }

        if (auto workspace = validate_workspace_root(workspace_root);
            !workspace) {
            return std::unexpected(workspace.error());
        }

        std::optional<std::vector<std::string>> remote_inventory;
        if (audit_content_objects_requested || complete_history) {
            auto listing = transport::list(storage);
            if (!listing) {
                if (listing.error().code ==
                    transport::ErrorCode::StorageNotFound) {
                    remote_inventory.emplace();
                } else {
                    return std::unexpected(Error{
                        .code = ErrorCode::TransportFailure,
                        .detail = transport::describe(listing.error()),
                    });
                }
            } else {
                remote_inventory = std::move(*listing);
            }
        }

        StorageView result;
        auto loaded = remote_inventory && frontier
                          ? history_storage::load_history(storage,
                                                          key,
                                                          workspace_root,
                                                          *remote_inventory,
                                                          *frontier)
                      : remote_inventory
                          ? history_storage::load_history(
                                storage, key, workspace_root, *remote_inventory)
                          : history_storage::load_history_scoped(
                                storage,
                                key,
                                workspace_root,
                                frontier,
                                trusted_marker_identifiers);
        if (!loaded) {
            return std::unexpected(storage_error(loaded.error()));
        }
        std::unordered_set<std::string> remote_content_identifiers;
        std::unordered_set<std::string> referenced_content_identifiers;
        if (audit_content_objects_requested) {
            if (!collect_content_identifiers_into(
                    *remote_inventory,
                    maximum_audited_content_object_count,
                    remote_content_identifiers)) {
                return std::unexpected(Error{
                    .code = ErrorCode::LimitExceeded,
                    .detail = "too many content identifiers",
                });
            }
            result.content_object_identifiers.assign(
                remote_content_identifiers.begin(),
                remote_content_identifiers.end());
            std::ranges::sort(result.content_object_identifiers);
        }
        if (remote_inventory) {
            result.physical_identifiers = std::move(*remote_inventory);
        }
        if (loaded->marked_heads.empty()) {
            result.orphan_content_count = remote_content_identifiers.size();
            return result;
        }
        if (audit_content_objects_requested) {
            std::vector<std::string> phys_ids;
            for (const auto& loaded_commit : loaded->commits) {
                for (const auto& row : loaded_commit.commit.tree.rows) {
                    if (row.is_directory) {
                        continue;
                    }
                    phys_ids.clear();
                    if (const auto* packed = kasumi::history::find_packed_blob(
                            loaded_commit.commit.storage, row.hash)) {
                        phys_ids.push_back(
                            crypto::pack_identifier(key, packed->pack_hash));
                    } else if (const auto* chunked =
                                   kasumi::history::find_chunked_file(
                                       loaded_commit.commit.storage,
                                       row.hash)) {
                        phys_ids.reserve(chunked->chunks.size());
                        for (const auto& chunk : chunked->chunks) {
                            phys_ids.push_back(
                                crypto::content_identifier(key, chunk.hash));
                        }
                    } else {
                        phys_ids.push_back(
                            crypto::content_identifier(key, row.hash));
                    }
                    bool all_present = true;
                    for (const auto& identifier : phys_ids) {
                        if (referenced_content_identifiers.size() >=
                                maximum_audited_content_object_count &&
                            !referenced_content_identifiers.contains(
                                identifier)) {
                            return std::unexpected(Error{
                                .code = ErrorCode::LimitExceeded,
                                .detail =
                                    "too many referenced content identifiers",
                            });
                        }
                        referenced_content_identifiers.insert(identifier);
                        if (!remote_content_identifiers.contains(identifier)) {
                            all_present = false;
                        }
                    }
                    if (all_present) {
                        result.content_identifiers.insert(hash_hex(row.hash));
                    }
                }
            }
            result.missing_content_count =
                static_cast<std::size_t>(std::ranges::count_if(
                    referenced_content_identifiers,
                    [&](const auto& identifier) {
                        return !remote_content_identifiers.contains(identifier);
                    }));
            result.orphan_content_count =
                static_cast<std::size_t>(std::ranges::count_if(
                    remote_content_identifiers, [&](const auto& identifier) {
                        return !referenced_content_identifiers.contains(
                            identifier);
                    }));
        }
        auto resolved =
            loaded->trusted_anchor_ids.empty()
                ? kasumi::history::resolve_authenticated(loaded->commits,
                                                         loaded->marked_heads)
                : kasumi::history::resolve_from_frontier_authenticated(
                      loaded->commits,
                      loaded->marked_heads,
                      loaded->trusted_anchor_ids);
        if (!resolved) {
            return std::unexpected(resolution_error(resolved.error()));
        }
        auto ancestors = validate_resolution(*resolved, loaded->marked_heads);
        if (!ancestors) {
            return std::unexpected(ancestors.error());
        }

        result.reachable_commits = std::move(loaded->commits);
        result.authenticated_commit_variants =
            std::move(loaded->authenticated_commit_variants);
        result.reachable_commit_ids.reserve(result.reachable_commits.size());
        for (const auto& commit : result.reachable_commits) {
            result.reachable_commit_ids.push_back(commit.id);
        }
        result.effective_tree = std::move(resolved->tree);
        result.storage_manifest = std::move(resolved->storage);
        result.observed_height = resolved->height;
        result.marked_heads = std::move(loaded->marked_heads);
        result.marked_head_identifiers =
            std::move(loaded->marked_head_identifiers);
        result.logical_heads = std::move(resolved->heads);
        result.ancestral_marked_heads = std::move(*ancestors);
        result.history_present = true;
        result.has_conflicts = resolved->has_conflicts;
        result.epoch = std::move(loaded->epoch);
        return result;
    } catch (const std::bad_alloc&) {
        return std::unexpected(Error{.code = ErrorCode::LimitExceeded,
                                     .detail = "memory allocation failure"});
    } catch (const std::exception& exception) {
        return std::unexpected(Error{.code = ErrorCode::HistoryStorageFailure,
                                     .detail = exception.what()});
    }
}

} // namespace kasumi::application::observation::history
