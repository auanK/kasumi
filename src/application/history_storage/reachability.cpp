#include "application/history_storage/reachability.hpp"

#include "application/history_storage/epoch.hpp"
#include "platform/perf_trace.hpp"

#include <algorithm>
#include <map>
#include <new>
#include <set>
#include <utility>

namespace kasumi::application::history_storage {
namespace {

using CommitMap = std::map<std::string, ReachabilityCommit>;

enum class ParentAvailability {
    Valid,
    Missing,
    Invalid,
};

ReachabilityVariant* find_variant(ReachabilityCommit& commit,
                                  const HeadReference& reference) {
    const auto found = std::ranges::find(
        commit.variants, reference, &ReachabilityVariant::reference);
    return found == commit.variants.end() ? nullptr : &*found;
}

void add_missing_variant(CommitMap& commits, const HeadReference& reference) {
    auto& commit = commits[reference.commit_id];
    commit.commit_id = reference.commit_id;
    if (find_variant(commit, reference) == nullptr) {
        commit.variants.push_back(
            ReachabilityVariant{.reference = reference, .identifier = {}});
    }
}

ParentAvailability classify_parent(const ReachabilityCommit* commit) {
    if (commit == nullptr) {
        return ParentAvailability::Missing;
    }

    for (const auto& variant : commit->variants) {
        if (variant.state == detail::VariantState::Valid) {
            return ParentAvailability::Valid;
        }
    }
    for (const auto& variant : commit->variants) {
        if (variant.state == detail::VariantState::InvalidCiphertext ||
            variant.state == detail::VariantState::InvalidCommit) {
            return ParentAvailability::Invalid;
        }
    }
    return ParentAvailability::Missing;
}

ReachabilityMarkerState marker_state(detail::VariantState state) {
    switch (state) {
        case detail::VariantState::Missing:
            return ReachabilityMarkerState::MissingCommit;
        case detail::VariantState::InvalidCiphertext:
            return ReachabilityMarkerState::InvalidCiphertext;
        case detail::VariantState::InvalidCommit:
            return ReachabilityMarkerState::InvalidCommit;
        case detail::VariantState::Valid:
            return ReachabilityMarkerState::Valid;
    }
    return ReachabilityMarkerState::InvalidCommit;
}

void sort_unique(std::vector<std::string>& values) {
    std::ranges::sort(values);
    values.erase(std::ranges::unique(values).begin(), values.end());
}

ReachabilityResult inventory_impl(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const std::filesystem::path& workspace_root,
    std::optional<std::span<const std::string>> identifiers = std::nullopt,
    std::optional<std::span<const epoch::VerifiedEpoch>> verified_epochs =
        std::nullopt) {
    if (!transport::valid(storage)) {
        return std::unexpected(
            detail::error(ErrorCode::InvalidInput, "invalid transport"));
    }
    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(temporary.error());
    }
    // The listing freezes the observation; new markers are deferred to the next run.
    auto listed = identifiers ? detail::build_history_inventory(*identifiers)
                              : detail::build_history_inventory(storage);
    if (!listed) {
        return std::unexpected(listed.error());
    }

    CommitMap commits;
    std::size_t sequence = 0;
    for (const auto& [commit_id, references] : listed->commit_variants) {
        auto& commit = commits[commit_id];
        commit.commit_id = commit_id;
        for (const auto& reference : references) {
            auto loaded = detail::try_load_variant(
                storage, key, reference, (*temporary)->root, sequence++);
            if (!loaded) {
                return std::unexpected(loaded.error());
            }
            commit.variants.push_back(ReachabilityVariant{
                .reference = reference,
                .identifier = detail::commit_object(reference),
                .state = loaded->state});
            if (loaded->state == detail::VariantState::Valid &&
                loaded->commit.has_value() && !commit.valid) {
                commit.valid = true;
                commit.parents = loaded->commit->commit.parents;
                commit.tree = loaded->commit->commit;
            }
        }
    }

    ReachabilityInventory result;
    std::vector<std::pair<std::string, epoch::VerifiedEpoch>> loaded_epochs;
    if (verified_epochs) {
        loaded_epochs.reserve(verified_epochs->size());
        for (const auto& value : *verified_epochs) {
            auto identifier = epoch::object_identifier(value.reference);
            if (!identifier) {
                return std::unexpected(detail::error(
                    ErrorCode::InvalidInput, identifier.error().detail));
            }
            loaded_epochs.emplace_back(std::move(*identifier), value);
        }
    }
    for (const auto& identifier : listed->identifiers) {
        if (identifier.starts_with(detail::heads_prefix)) {
            const auto parsed = parse_marker_object(identifier);
            if (!parsed) {
                result.unknown_history_objects.push_back(identifier);
                continue;
            }
            add_missing_variant(commits, *parsed);
            result.markers.push_back(
                ReachabilityMarker{.identifier = identifier,
                                   .reference = *parsed,
                                   .state = ReachabilityMarkerState::Missing});
        } else if (!detail::parse_commit_object(identifier)) {
            auto epoch_reference = epoch::parse_object_identifier(identifier);
            if (!epoch_reference) {
                result.unknown_history_objects.push_back(identifier);
                continue;
            }
            if (verified_epochs) {
                const auto known =
                    std::ranges::find_if(loaded_epochs, [&](const auto& value) {
                        return value.first == identifier;
                    });
                if (known == loaded_epochs.end()) {
                    result.unknown_history_objects.push_back(identifier);
                }
                continue;
            }
            const auto path =
                (*temporary)->root / ("epoch-" + std::to_string(sequence++));
            const auto get_trace = platform::perf_trace::begin();
            auto downloaded = detail::download(storage, identifier, path);
            platform::perf_trace::finish("rc/get_epoch", get_trace);
            if (!downloaded) {
                return std::unexpected(downloaded.error());
            }
            auto bytes =
                detail::read_file(path, epoch::maximum_encoded_size + 64U);
            if (bytes) {
                auto opened = epoch::open(*bytes, *epoch_reference, key);
                if (opened) {
                    loaded_epochs.push_back(
                        std::make_pair(identifier, std::move(*opened)));
                } else {
                    result.unknown_history_objects.push_back(identifier);
                }
            } else {
                result.unknown_history_objects.push_back(identifier);
            }
        }
    }

    std::unordered_set<std::string> epoch_anchors;
    if (!loaded_epochs.empty()) {
        std::vector<epoch::VerifiedEpoch> epoch_values;
        for (const auto& [_, ep] : loaded_epochs) {
            epoch_values.push_back(ep);
        }
        auto latest_epoch = epoch::select_latest(epoch_values);
        if (!latest_epoch) {
            return std::unexpected(detail::error(ErrorCode::InvalidInput,
                                                 latest_epoch.error().detail));
        }
        for (const auto& anchor : latest_epoch->value.anchors) {
            epoch_anchors.insert(anchor.commit_id);
        }
        for (const auto& [id, ep] : loaded_epochs) {
            if (ep.reference == latest_epoch->reference) {
                result.valid_epochs.push_back(id);
            } else {
                result.orphan_epochs.push_back(id);
            }
        }
    }

    for (const auto& [commit_id, references] : listed->marker_variants) {
        static_cast<void>(commit_id);
        for (const auto& reference : references) {
            add_missing_variant(commits, reference);
        }
    }
    if (commits.size() > history::maximum_loaded_commit_count) {
        return std::unexpected(detail::error(
            ErrorCode::LimitExceeded, "history contains too many commits"));
    }

    for (auto& marker : result.markers) {
        if (!marker.reference.has_value()) {
            continue;
        }
        auto inspected = detail::inspect_marker(
            storage, *marker.reference, (*temporary)->root, sequence);
        if (!inspected) {
            return std::unexpected(inspected.error());
        }
        if (*inspected == detail::MarkerState::Absent) {
            marker.state = ReachabilityMarkerState::Missing;
            continue;
        }
        if (*inspected == detail::MarkerState::Invalid) {
            marker.state = ReachabilityMarkerState::InvalidMarker;
            continue;
        }
        auto& commit = commits.at(marker.reference->commit_id);
        const auto* variant = find_variant(commit, *marker.reference);
        marker.state = variant == nullptr
                           ? ReachabilityMarkerState::MissingCommit
                           : marker_state(variant->state);
        if (marker.state == ReachabilityMarkerState::Valid) {
            result.logical_heads.push_back(marker.reference->commit_id);
        }
    }

    for (auto& [unused, commit] : commits) {
        static_cast<void>(unused);
        std::ranges::sort(commit.variants, {}, &ReachabilityVariant::reference);
        if (commit.valid) {
            for (const auto& parent : commit.parents) {
                if (!history::valid_commit_id(parent)) {
                    result.invalid_parent_ids.push_back(parent);
                    continue;
                }
                if (epoch_anchors.contains(parent)) {
                    continue;
                }
                const auto found = commits.find(parent);
                switch (classify_parent(
                    found == commits.end() ? nullptr : &found->second)) {
                    case ParentAvailability::Valid:
                        break;
                    case ParentAvailability::Missing:
                        result.missing_parent_ids.push_back(parent);
                        break;
                    case ParentAvailability::Invalid:
                        result.invalid_parent_ids.push_back(parent);
                        break;
                }
            }
        }
    }

    std::set<std::string> visited;
    std::set<std::string> reachable;
    std::vector<std::pair<std::string, std::size_t>> pending;
    for (const auto& root : result.logical_heads) {
        pending.emplace_back(root, 0);
    }
    while (!pending.empty()) {
        auto [commit_id, depth] = std::move(pending.back());
        pending.pop_back();
        if (depth > history::maximum_graph_depth) {
            return std::unexpected(detail::error(ErrorCode::LimitExceeded,
                                                 "history graph is too deep"));
        }
        if (!visited.insert(commit_id).second) {
            continue;
        }
        const auto found = commits.find(commit_id);
        if (found == commits.end() || !found->second.valid) {
            continue;
        }
        reachable.insert(commit_id);
        if (epoch_anchors.contains(commit_id)) {
            continue;
        }
        for (const auto& parent : found->second.parents) {
            pending.emplace_back(parent, depth + 1);
        }
    }

    sort_unique(result.logical_heads);
    result.reachable_commits.assign(reachable.begin(), reachable.end());
    sort_unique(result.missing_parent_ids);
    sort_unique(result.invalid_parent_ids);
    sort_unique(result.unknown_history_objects);
    for (auto& [commit_id, commit] : commits) {
        commit.reachable = reachable.contains(commit_id);
        if (commit.valid && !commit.reachable) {
            result.orphan_commits.push_back(commit_id);
        }
        result.commits.push_back(std::move(commit));
    }
    return result;
}

} // namespace

ReachabilityResult
inventory_reachability(transport::Transport& storage,
                       std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                       const std::filesystem::path& workspace_root) {
    try {
        return inventory_impl(
            storage, key, workspace_root, std::nullopt, std::nullopt);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            detail::error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

ReachabilityResult
inventory_reachability(transport::Transport& storage,
                       std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                       std::span<const std::string> identifiers,
                       const std::filesystem::path& workspace_root) {
    try {
        return inventory_impl(
            storage, key, workspace_root, identifiers, std::nullopt);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            detail::error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

ReachabilityResult
inventory_reachability(transport::Transport& storage,
                       std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                       std::span<const std::string> identifiers,
                       std::span<const epoch::VerifiedEpoch> verified_epochs,
                       const std::filesystem::path& workspace_root) {
    try {
        return inventory_impl(
            storage, key, workspace_root, identifiers, verified_epochs);
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            detail::error(ErrorCode::LimitExceeded, "allocation failed"));
    }
}

} // namespace kasumi::application::history_storage
