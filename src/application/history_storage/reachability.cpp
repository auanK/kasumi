#include "application/history_storage/reachability.hpp"

#include "application/history_storage/epoch.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "platform/perf_trace.hpp"

#include <algorithm>
#include <map>
#include <new>
#include <set>
#include <utility>

namespace kasumi::application::history_storage {
namespace {

using CommitList = std::vector<ReachabilityCommit>;

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

ReachabilityCommit* find_commit(CommitList& commits, std::string_view commit_id) {
    const auto it = std::ranges::lower_bound(
        commits, commit_id, {}, &ReachabilityCommit::commit_id);
    if (it != commits.end() && it->commit_id == commit_id) {
        return &*it;
    }
    return nullptr;
}

void add_missing_variant(CommitList& commits, const HeadReference& reference) {
    auto* commit = find_commit(commits, reference.commit_id);
    if (commit == nullptr) {
        const auto it = std::ranges::lower_bound(
            commits, reference.commit_id, {}, &ReachabilityCommit::commit_id);
        commit = &*commits.insert(
            it, ReachabilityCommit{.commit_id = reference.commit_id});
    }
    if (find_variant(*commit, reference) == nullptr) {
        commit->variants.push_back(
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

struct TraceGuard {
    std::string_view name;
    platform::perf_trace::Token token;
    bool active = true;
    void stop() noexcept {
        if (active) {
            platform::perf_trace::finish(name, token);
            active = false;
        }
    }
    ~TraceGuard() noexcept { stop(); }
};

ReachabilityResult inventory_impl(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const std::filesystem::path& workspace_root,
    std::optional<std::span<const std::string>> identifiers = std::nullopt,
    std::optional<std::span<const epoch::VerifiedEpoch>> verified_epochs =
        std::nullopt,
    std::string_view trace_scope = {}) {
    std::string scoped_build_inventory_name;
    std::string scoped_load_commits_name;
    std::string scoped_inspect_history_name;
    std::string scoped_dag_traversal_name;
    const auto metric_name = [trace_scope](std::string_view name,
                                           std::string& scoped_name) {
        if (trace_scope.empty()) {
            return name;
        }
        scoped_name.assign(trace_scope);
        scoped_name.append("/");
        scoped_name.append(name);
        return std::string_view{scoped_name};
    };
    const auto build_inventory_name =
        metric_name("rc/build_history_inventory", scoped_build_inventory_name);
    const auto load_commits_name =
        metric_name("rc/load_and_auth_commits", scoped_load_commits_name);
    const auto inspect_history_name =
        metric_name("rc/inspect_markers_epochs", scoped_inspect_history_name);
    const auto dag_traversal_name =
        metric_name("rc/dag_traversal", scoped_dag_traversal_name);
    if (!transport::valid(storage)) {
        return std::unexpected(
            detail::error(ErrorCode::InvalidInput, "invalid transport"));
    }
    auto temporary = detail::make_workspace(workspace_root);
    if (!temporary) {
        return std::unexpected(temporary.error());
    }
    const auto layout = derive_remote_layout(key);
    // The listing freezes the observation; new markers are deferred to the next
    // run.
    const auto inventory_trace = platform::perf_trace::begin();
    auto listed = identifiers
                      ? detail::build_history_inventory(*identifiers, layout)
                      : detail::build_history_inventory(storage, layout);
    platform::perf_trace::finish(build_inventory_name, inventory_trace);
    if (!listed) {
        return std::unexpected(listed.error());
    }

    if (storage.storage.get_batch != nullptr) {
        const auto commits_dir = layout.commits_prefix.ends_with('/')
                                     ? layout.commits_prefix.substr(
                                           0, layout.commits_prefix.size() - 1)
                                     : layout.commits_prefix;
        transport::GetBatch batch{
            .source_prefix = std::string{commits_dir},
            .destination_root = (*temporary)->root,
        };
        for (const auto& [unused, references] : listed->commit_variants) {
            static_cast<void>(unused);
            for (const auto& reference : references) {
                batch.identifiers.push_back(reference.commit_id + "/" +
                                            reference.ciphertext_id);
            }
        }
        if (batch.identifiers.size() > 1) {
            auto prefetched = transport::get_batch(storage, batch);
            if (!prefetched) {
                return std::unexpected(
                    detail::transport_error(prefetched.error()));
            }
        }
    }

    TraceGuard load_commits_guard{load_commits_name,
                                  platform::perf_trace::begin()};
    CommitList commits;
    commits.reserve(listed->commit_variants.size() + listed->marker_variants.size());
    std::size_t sequence = 0;
    for (const auto& [commit_id, references] : listed->commit_variants) {
        commits.push_back(ReachabilityCommit{.commit_id = commit_id});
        auto& commit = commits.back();
        commit.variants.reserve(references.size());
        for (const auto& reference : references) {
            auto loaded = detail::try_load_variant(
                storage, key, reference, (*temporary)->root, sequence++);
            if (!loaded) {
                return std::unexpected(loaded.error());
            }
            commit.variants.push_back(ReachabilityVariant{
                .reference = reference,
                .identifier = commit_object(layout, reference),
                .state = loaded->state});
            if (loaded->state == detail::VariantState::Valid &&
                loaded->commit.has_value() && !commit.valid) {
                commit.valid = true;
                commit.parents = loaded->commit->commit.parents;
                commit.tree = loaded->commit->commit;
            }
        }
    }
    load_commits_guard.stop();

    TraceGuard inspect_guard{inspect_history_name,
                             platform::perf_trace::begin()};
    ReachabilityInventory result;
    std::vector<std::pair<std::string, epoch::VerifiedEpoch>> loaded_epochs;
    if (verified_epochs) {
        loaded_epochs.reserve(verified_epochs->size());
        for (const auto& value : *verified_epochs) {
            auto identifier = epoch::object_identifier(layout, value.reference);
            if (!identifier) {
                return std::unexpected(detail::error(
                    ErrorCode::InvalidInput, identifier.error().detail));
            }
            loaded_epochs.emplace_back(std::move(*identifier), value);
        }
    }
    for (const auto& identifier : listed->identifiers) {
        if (identifier.starts_with(layout.heads_prefix) ||
            identifier.starts_with("history/heads/")) {
            const auto parsed = parse_marker_object(layout, identifier);
            if (!parsed) {
                result.unknown_history_objects.push_back(identifier);
                continue;
            }
            add_missing_variant(commits, *parsed);
            result.markers.push_back(
                ReachabilityMarker{.identifier = identifier,
                                   .reference = *parsed,
                                   .state = ReachabilityMarkerState::Missing});
        } else if (!parse_commit_object(layout, identifier)) {
            auto epoch_reference =
                epoch::parse_object_identifier(layout, identifier);
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

    std::map<std::string, std::uint64_t> epoch_anchors;
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
            epoch_anchors.emplace(anchor.commit_id, anchor.height);
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
            storage, layout, *marker.reference, (*temporary)->root, sequence);
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
        auto* commit = find_commit(commits, marker.reference->commit_id);
        const auto* variant =
            commit == nullptr ? nullptr : find_variant(*commit, *marker.reference);
        marker.state = variant == nullptr
                           ? ReachabilityMarkerState::MissingCommit
                           : marker_state(variant->state);
        if (marker.state == ReachabilityMarkerState::Valid) {
            result.logical_heads.push_back(marker.reference->commit_id);
        }
    }

    for (auto& commit : commits) {
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
                const auto* found = find_commit(commits, parent);
                switch (classify_parent(found)) {
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
    inspect_guard.stop();

    TraceGuard dag_guard{dag_traversal_name, platform::perf_trace::begin()};
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
        auto* found = find_commit(commits, commit_id);
        if (found == nullptr || !found->valid || found->reachable) {
            continue;
        }
        found->reachable = true;
        if (epoch_anchors.contains(commit_id)) {
            continue;
        }
        for (const auto& parent : found->parents) {
            pending.emplace_back(parent, depth + 1);
        }
    }
    dag_guard.stop();

    for (const auto& [anchor_id, height] : epoch_anchors) {
        const auto* anchor = find_commit(commits, anchor_id);
        if (anchor == nullptr || !anchor->valid || !anchor->reachable ||
            !anchor->tree || anchor->tree->height != height) {
            return std::unexpected(detail::error(
                ErrorCode::InvalidCommit,
                "Epoch anchor is missing, invalid, unreachable, or has a mismatched height"));
        }
    }

    sort_unique(result.logical_heads);
    sort_unique(result.missing_parent_ids);
    sort_unique(result.invalid_parent_ids);
    sort_unique(result.unknown_history_objects);
    for (auto& commit : commits) {
        if (commit.reachable) {
            result.reachable_commits.push_back(commit.commit_id);
        } else if (commit.valid) {
            result.orphan_commits.push_back(commit.commit_id);
        }
    }
    result.commits = std::move(commits);
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
                       const std::filesystem::path& workspace_root,
                       std::string_view trace_scope) {
    try {
        return inventory_impl(
            storage, key, workspace_root, identifiers, std::nullopt,
            trace_scope);
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
