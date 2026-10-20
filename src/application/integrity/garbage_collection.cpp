#include "application/history_storage/content_reachability.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/reachability.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/maintenance.hpp"
#include "platform/cancellation.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <new>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace kasumi::application::integrity {
namespace {

namespace history_storage = application::history_storage;
namespace protocol = application::history_storage::maintenance_protocol;
using KeySpan = std::span<const std::uint8_t, crypto::KEY_SIZE>;

enum class CandidateKind {
    CommitVariant,
    Content,
};

struct Candidate {
    CandidateKind kind = CandidateKind::Content;
    std::string identifier;
    std::string commit_id;

    bool operator==(const Candidate&) const = default;
};

struct Observation {
    std::vector<std::string> logical_heads;
    std::vector<std::string> reachable_commits;
    std::vector<std::string> required_commit_objects;
    std::vector<std::string> reachable_content;
    std::vector<std::string> orphan_contents;
    std::vector<Candidate> candidates;
    std::vector<std::string> physical_namespace;
};

Error make_error(ErrorCode code,
                 std::string detail,
                 std::optional<std::string> object = std::nullopt) {
    return Error{.code = code,
                 .detail = std::move(detail),
                 .object_identifier = std::move(object)};
}

std::string join_values(const std::vector<std::string>& values) {
    std::string result;
    for (const auto& value : values) {
        if (!result.empty()) {
            result += ", ";
        }
        result += value;
    }
    return result;
}

Error transport_error(const transport::Error& error,
                      std::string_view operation) {
    auto result = make_error(ErrorCode::TransportFailure,
                             std::string{operation} + ": " + error.message);
    result.transport_failure = error;
    return result;
}

Error history_error(const history_storage::Error& error) {
    ErrorCode code = ErrorCode::IntegrityFailure;
    if (error.code == history_storage::ErrorCode::TransportFailure) {
        code = ErrorCode::TransportFailure;
    } else if (error.code == history_storage::ErrorCode::WorkspaceFailure) {
        code = ErrorCode::WorkspaceFailure;
    } else if (error.code == history_storage::ErrorCode::CryptoFailure) {
        code = ErrorCode::CryptoFailure;
    } else if (error.code == history_storage::ErrorCode::InvalidInput) {
        code = ErrorCode::InvalidInput;
    }
    return make_error(code, error.detail);
}

Error protocol_error(const protocol::Error& error) {
    ErrorCode code = ErrorCode::StateFailure;
    switch (error.code) {
        case protocol::ErrorCode::InvalidInput:
            code = ErrorCode::InvalidInput;
            break;
        case protocol::ErrorCode::WorkspaceFailure:
            code = ErrorCode::WorkspaceFailure;
            break;
        case protocol::ErrorCode::TransportFailure:
            code = ErrorCode::TransportFailure;
            break;
        case protocol::ErrorCode::VerificationFailure:
        case protocol::ErrorCode::Blocked:
            code = ErrorCode::ConcurrentChange;
            break;
        case protocol::ErrorCode::BackendUnsafe:
            code = ErrorCode::Unrecoverable;
            break;
        case protocol::ErrorCode::InvalidControlObject:
            code = ErrorCode::IntegrityFailure;
            break;
    }
    auto result = make_error(code, error.detail);
    result.transport_failure = error.transport_failure;
    return result;
}

// Owns the only path allowed to release the maintenance barrier. A failed
// release is never retried by the destructor or by the result path.
struct BarrierCleanup {
    protocol::RegistrationState registration;
    transport::Transport* storage = nullptr;
    bool cleanup_started = false;
    bool release_attempted = false;
    bool release_confirmed = false;
    std::optional<Error> failure;

    explicit BarrierCleanup(protocol::RegistrationState value)
        : registration(std::move(value)), storage(registration.storage) {
    }

    ~BarrierCleanup() noexcept {
        if (!cleanup_started) {
            try {
                static_cast<void>(release_once());
            } catch (...) {
                // Exception safety must not open a second release path.
            }
        }
    }

    std::expected<void, Error> release_once() {
        if (cleanup_started) {
            if (release_confirmed) {
                return {};
            }
            return std::unexpected(
                failure.value_or(make_error(ErrorCode::ConcurrentChange,
                                            "barrier cleanup is unconfirmed")));
        }
        cleanup_started = true;

        if (storage == nullptr ||
            !protocol::registration_active(registration)) {
            failure = make_error(ErrorCode::ConcurrentChange,
                                 "maintenance barrier ownership was lost");
            return std::unexpected(*failure);
        }

        auto ownership = protocol::verify_registration(registration);
        if (!ownership) {
            failure = protocol_error(ownership.error());
            failure->detail =
                "barrier ownership could not be confirmed during cleanup: " +
                failure->detail;
            registration.storage = nullptr;
            return std::unexpected(*failure);
        }

        release_attempted = true;
        auto released = protocol::release_registration(registration);
        if (!released) {
            failure = protocol_error(released.error());
            failure->detail = "barrier release failed: " + failure->detail;
            return std::unexpected(*failure);
        }

        auto presence = transport::presence(*storage, registration.identifier);
        if (!presence) {
            failure = transport_error(
                presence.error(), "barrier cleanup visibility is uncertain");
            return std::unexpected(*failure);
        }
        if (*presence != transport::Presence::Absent) {
            failure = make_error(ErrorCode::ConcurrentChange,
                                 "barrier remained present after release",
                                 registration.identifier);
            return std::unexpected(*failure);
        }

        release_confirmed = true;
        return {};
    }
};

std::filesystem::path
maintenance_workspace_root(const runtime::RuntimeData& runtime_data) {
    auto root = runtime_data.database_path.parent_path();
    std::error_code error;
    if (root.empty() || !std::filesystem::exists(root, error)) {
        root = runtime_data.local_dir.parent_path();
    }
    return root;
}

void notify(const GarbageCollectProgressCallback& on_progress,
            GarbageCollectStage stage,
            std::optional<std::size_t> candidate_count,
            std::size_t removed_objects) noexcept {
    if (!on_progress) {
        return;
    }
    try {
        on_progress(GarbageCollectProgress{
            .stage = stage,
            .candidate_count = candidate_count,
            .removed_objects = removed_objects,
        });
    } catch (...) {
        // Progress is observational and must not alter the operation.
    }
}

std::optional<Error> cancellation_error() {
    if (!platform::cancellation::requested()) {
        return std::nullopt;
    }
    return make_error(ErrorCode::StateFailure, "garbage collection cancelled");
}

std::expected<void, Error>
validate_history(const history_storage::ReachabilityInventory& inventory) {
    if (inventory.logical_heads.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure, "remote history absent"));
    }
    if (!inventory.unknown_history_objects.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       "unknown history objects: " +
                           join_values(inventory.unknown_history_objects)));
    }
    if (!inventory.missing_parent_ids.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       "missing parent commits: " +
                           join_values(inventory.missing_parent_ids)));
    }
    if (!inventory.invalid_parent_ids.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       "invalid parent commits: " +
                           join_values(inventory.invalid_parent_ids)));
    }

    std::vector<std::string> invalid_markers;
    for (const auto& marker : inventory.markers) {
        if (marker.state != history_storage::ReachabilityMarkerState::Valid) {
            invalid_markers.push_back(marker.identifier);
        }
    }
    if (!invalid_markers.empty()) {
        return std::unexpected(make_error(ErrorCode::IntegrityFailure,
                                          "invalid head markers: " +
                                              join_values(invalid_markers)));
    }

    std::vector<std::string> invalid_commits;
    for (const auto& commit : inventory.commits) {
        if (!commit.valid &&
            std::ranges::any_of(commit.variants, [](const auto& variant) {
                return !variant.identifier.empty();
            })) {
            invalid_commits.push_back(commit.commit_id);
        }
    }
    if (!invalid_commits.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       "invalid commits: " + join_values(invalid_commits)));
    }
    return {};
}

std::expected<void, Error> validate_content(
    const history_storage::ContentReachabilityInventory& inventory) {
    if (!inventory.unknown_storage_objects.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       "unknown physical identifiers: " +
                           join_values(inventory.unknown_storage_objects)));
    }
    std::vector<std::string> damaged;
    for (const auto& content : inventory.contents) {
        if (content.reachable &&
            content.state != history_storage::ContentObjectState::Present) {
            damaged.push_back(content.content_id);
        }
    }
    if (!damaged.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       "reachable contents missing or corrupted: " +
                           join_values(damaged)));
    }
    return {};
}

std::vector<std::string>
required_variants(const history_storage::ReachabilityInventory& inventory,
                  const history_storage::RemoteLayout& layout) {
    std::vector<std::string> required;
    std::vector<std::string> marked_commits;
    for (const auto& marker : inventory.markers) {
        if (marker.state != history_storage::ReachabilityMarkerState::Valid ||
            !marker.reference.has_value()) {
            continue;
        }
        marked_commits.push_back(marker.reference->commit_id);
        required.push_back(
            history_storage::commit_object(layout, *marker.reference));
    }
    std::ranges::sort(marked_commits);
    marked_commits.erase(std::ranges::unique(marked_commits).begin(),
                         marked_commits.end());

    for (const auto& commit : inventory.commits) {
        if (!commit.reachable ||
            std::ranges::binary_search(marked_commits, commit.commit_id)) {
            continue;
        }
        const auto variant =
            std::ranges::find_if(commit.variants, [](const auto& value) {
                return !value.identifier.empty() &&
                       value.state ==
                           history_storage::detail::VariantState::Valid;
            });
        if (variant != commit.variants.end()) {
            required.push_back(variant->identifier);
        }
    }

    std::ranges::sort(required);
    required.erase(std::ranges::unique(required).begin(), required.end());
    return required;
}

std::expected<Observation, Error>
observe(transport::Transport& storage,
        KeySpan key,
        const std::filesystem::path& workspace_root) {
    auto listing = transport::list(storage);
    if (!listing) {
        return std::unexpected(
            transport_error(listing.error(), "could not list remote objects"));
    }
    std::ranges::sort(*listing);

    const auto layout = history_storage::derive_remote_layout(key);
    auto history = history_storage::inventory_reachability(
        storage, key, *listing, workspace_root);
    if (!history) {
        return std::unexpected(history_error(history.error()));
    }
    if (auto valid = validate_history(*history); !valid) {
        return std::unexpected(valid.error());
    }

    auto content = history_storage::inventory_content_reachability(
        storage, key, *listing, *history, workspace_root, false);
    if (!content) {
        return std::unexpected(history_error(content.error()));
    }
    if (auto valid = validate_content(*content); !valid) {
        return std::unexpected(valid.error());
    }

    Observation result{
        .logical_heads = history->logical_heads,
        .reachable_commits = history->reachable_commits,
        .required_commit_objects = required_variants(*history, layout),
        .reachable_content = content->reachable_content_ids,
        .orphan_contents = {},
        .candidates = {},
        .physical_namespace = std::move(*listing),
    };

    std::vector<std::string> orphan_ids = content->orphan_content_ids;
    std::ranges::sort(orphan_ids);
    orphan_ids.erase(std::ranges::unique(orphan_ids).begin(), orphan_ids.end());
    if (!orphan_ids.empty()) {
        auto audited = history_storage::inventory_content_reachability(
            storage,
            key,
            std::span<const std::string>{orphan_ids},
            *history,
            workspace_root,
            true);
        if (!audited) {
            return std::unexpected(history_error(audited.error()));
        }
        for (const auto& entry : audited->contents) {
            if (!entry.reachable &&
                entry.state == history_storage::ContentObjectState::Present &&
                std::ranges::binary_search(orphan_ids, entry.content_id)) {
                result.orphan_contents.push_back(entry.content_id);
                result.candidates.push_back(Candidate{
                    .kind = CandidateKind::Content,
                    .identifier = entry.content_id,
                    .commit_id = {},
                });
            }
        }
    }

    for (const auto& commit : history->commits) {
        if (!commit.reachable) {
            continue;
        }
        for (const auto& variant : commit.variants) {
            if (variant.identifier.empty() ||
                variant.state != history_storage::detail::VariantState::Valid ||
                std::ranges::binary_search(result.required_commit_objects,
                                           variant.identifier)) {
                continue;
            }
            result.candidates.push_back(Candidate{
                .kind = CandidateKind::CommitVariant,
                .identifier = variant.identifier,
                .commit_id = commit.commit_id,
            });
        }
    }

    std::ranges::sort(result.candidates,
                      [](const auto& left, const auto& right) {
                          return std::tie(left.kind, left.identifier) <
                                 std::tie(right.kind, right.identifier);
                      });
    result.candidates.erase(
        std::ranges::unique(result.candidates,
                            [](const auto& left, const auto& right) {
                                return left.kind == right.kind &&
                                       left.identifier == right.identifier;
                            })
            .begin(),
        result.candidates.end());
    return result;
}

bool same_observation(const Observation& left,
                      const Observation& right) noexcept {
    return left.logical_heads == right.logical_heads &&
           left.reachable_commits == right.reachable_commits &&
           left.required_commit_objects == right.required_commit_objects &&
           left.reachable_content == right.reachable_content &&
           left.orphan_contents == right.orphan_contents &&
           left.candidates == right.candidates &&
           left.physical_namespace == right.physical_namespace;
}

std::expected<std::vector<std::string>, Error>
fresh_namespace(transport::Transport& storage,
                const std::vector<std::string>& expected) {
    auto listing = transport::list(storage);
    if (!listing) {
        return std::unexpected(
            transport_error(listing.error(), "could not list remote objects"));
    }
    std::ranges::sort(*listing);
    if (*listing != expected) {
        return std::unexpected(
            make_error(ErrorCode::ConcurrentChange,
                       "physical namespace changed during garbage collection"));
    }
    return *listing;
}

std::expected<void, Error>
require_no_writers(transport::Transport& storage,
                   const history_storage::RemoteLayout& layout) {
    auto writers = protocol::active_writers(storage, layout);
    if (!writers) {
        return std::unexpected(protocol_error(writers.error()));
    }
    if (!writers->empty()) {
        return std::unexpected(
            make_error(ErrorCode::ConcurrentChange,
                       "active writers block garbage collection: " +
                           join_values(*writers)));
    }
    return {};
}

std::expected<void, Error>
require_barrier_ownership(const protocol::RegistrationState& barrier) {
    if (!protocol::registration_active(barrier)) {
        return std::unexpected(make_error(ErrorCode::ConcurrentChange,
                                          "maintenance barrier lost"));
    }
    auto verified = protocol::verify_registration(barrier);
    if (!verified) {
        return std::unexpected(protocol_error(verified.error()));
    }
    return {};
}

std::expected<void, Error>
revalidate_variant(transport::Transport& storage,
                   KeySpan key,
                   const std::filesystem::path& workspace_root,
                   const std::vector<std::string>& namespace_snapshot,
                   const history_storage::RemoteLayout& layout,
                   const Candidate& candidate) {
    auto history = history_storage::inventory_reachability(
        storage, key, namespace_snapshot, workspace_root);
    if (!history) {
        return std::unexpected(history_error(history.error()));
    }
    if (auto valid = validate_history(*history); !valid) {
        return std::unexpected(valid.error());
    }
    const auto required = required_variants(*history, layout);
    if (std::ranges::binary_search(required, candidate.identifier)) {
        return std::unexpected(
            make_error(ErrorCode::ConcurrentChange,
                       "commit variant became required during collection",
                       candidate.identifier));
    }
    const auto commit =
        std::ranges::find(history->commits,
                          candidate.commit_id,
                          &history_storage::ReachabilityCommit::commit_id);
    if (commit == history->commits.end() || !commit->reachable) {
        return std::unexpected(
            make_error(ErrorCode::ConcurrentChange,
                       "commit variant is no longer reachable",
                       candidate.identifier));
    }
    const auto variant =
        std::ranges::find(commit->variants,
                          candidate.identifier,
                          &history_storage::ReachabilityVariant::identifier);
    if (variant == commit->variants.end() ||
        variant->state != history_storage::detail::VariantState::Valid) {
        return std::unexpected(make_error(ErrorCode::ConcurrentChange,
                                          "commit variant is no longer valid",
                                          candidate.identifier));
    }
    return {};
}

std::expected<void, Error>
revalidate_content(transport::Transport& storage,
                   KeySpan key,
                   const std::filesystem::path& workspace_root,
                   const std::vector<std::string>& expected_namespace,
                   const Candidate& candidate) {
    auto listing = transport::list(storage);
    if (!listing) {
        return std::unexpected(
            transport_error(listing.error(), "could not list remote objects"));
    }
    std::ranges::sort(*listing);

    auto history = history_storage::inventory_reachability(
        storage, key, *listing, workspace_root);
    if (!history) {
        return std::unexpected(history_error(history.error()));
    }
    if (auto valid = validate_history(*history); !valid) {
        return std::unexpected(valid.error());
    }

    const std::array<std::string, 1> identifiers{candidate.identifier};
    auto audited = history_storage::inventory_content_reachability(
        storage,
        key,
        std::span<const std::string>{identifiers},
        *history,
        workspace_root,
        true);
    if (!audited) {
        return std::unexpected(history_error(audited.error()));
    }
    if (!audited->unknown_storage_objects.empty()) {
        return std::unexpected(
            make_error(ErrorCode::ConcurrentChange,
                       "content candidate changed classification",
                       candidate.identifier));
    }
    const auto entry =
        std::ranges::find(audited->contents,
                          candidate.identifier,
                          &history_storage::ContentEntry::content_id);
    if (entry == audited->contents.end()) {
        return std::unexpected(
            make_error(ErrorCode::ConcurrentChange,
                       "content candidate disappeared during revalidation",
                       candidate.identifier));
    }
    if (entry->reachable) {
        return std::unexpected(
            make_error(ErrorCode::ConcurrentChange,
                       "content candidate became reachable during collection",
                       candidate.identifier));
    }
    if (entry->state != history_storage::ContentObjectState::Present ||
        !std::ranges::binary_search(audited->orphan_content_ids,
                                    candidate.identifier)) {
        return std::unexpected(
            make_error(ErrorCode::ConcurrentChange,
                       "content candidate is no longer an authenticated orphan",
                       candidate.identifier));
    }
    if (*listing != expected_namespace) {
        return std::unexpected(
            make_error(ErrorCode::ConcurrentChange,
                       "physical namespace changed during content revalidation",
                       candidate.identifier));
    }
    return {};
}

std::expected<void, Error>
revalidate_candidate(transport::Transport& storage,
                     KeySpan key,
                     const std::filesystem::path& workspace_root,
                     const history_storage::RemoteLayout& layout,
                     const std::vector<std::string>& namespace_snapshot,
                     const Candidate& candidate) {
    if (candidate.kind == CandidateKind::CommitVariant) {
        return revalidate_variant(storage,
                                  key,
                                  workspace_root,
                                  namespace_snapshot,
                                  layout,
                                  candidate);
    }
    return revalidate_content(
        storage, key, workspace_root, namespace_snapshot, candidate);
}

std::expected<void, Error>
require_candidate_present(transport::Transport& storage,
                          const Candidate& candidate) {
    auto presence = transport::presence(storage, candidate.identifier);
    if (!presence) {
        return std::unexpected(
            transport_error(presence.error(), "could not verify candidate"));
    }
    if (*presence != transport::Presence::Present) {
        return std::unexpected(
            make_error(ErrorCode::ConcurrentChange,
                       "candidate disappeared before removal",
                       candidate.identifier));
    }
    return {};
}

std::expected<void, Error> confirm_removal(transport::Transport& storage,
                                           const Candidate& candidate) {
    auto presence = transport::presence(storage, candidate.identifier);
    if (!presence) {
        return std::unexpected(transport_error(
            presence.error(), "removal visibility is uncertain"));
    }
    if (*presence != transport::Presence::Absent) {
        return std::unexpected(make_error(ErrorCode::ConcurrentChange,
                                          "removal was not visible",
                                          candidate.identifier));
    }
    return {};
}

std::expected<GarbageCollectResult, Error>
garbage_collect_impl(const runtime::RuntimeData& runtime_data,
                     transport::Transport& storage,
                     KeySpan key,
                     GarbageCollectProgressCallback on_progress) {
    if (!transport::valid(storage)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidInput, "invalid transport"));
    }
    const auto workspace_root = maintenance_workspace_root(runtime_data);
    if (workspace_root.empty()) {
        return std::unexpected(
            make_error(ErrorCode::InvalidInput, "invalid workspace"));
    }

    GarbageCollectFailure failure_diagnostic{};
    failure_diagnostic.stage = GarbageCollectStage::Preparing;
    notify(on_progress, GarbageCollectStage::Preparing, std::nullopt, 0);
    if (auto cancelled = cancellation_error(); cancelled.has_value()) {
        return std::unexpected(std::move(*cancelled));
    }

    const auto layout = history_storage::derive_remote_layout(key);
    auto barrier_presence =
        transport::presence(storage, layout.barrier_identifier);
    if (!barrier_presence) {
        return std::unexpected(transport_error(
            barrier_presence.error(), "could not inspect maintenance barrier"));
    }
    if (*barrier_presence == transport::Presence::Present) {
        return std::unexpected(
            make_error(ErrorCode::ConcurrentChange,
                       "another maintenance barrier is already present"));
    }

    auto barrier = protocol::establish_barrier(storage, layout, workspace_root);
    if (!barrier) {
        return std::unexpected(protocol_error(barrier.error()));
    }
    BarrierCleanup cleanup{std::move(*barrier)};

    const auto finish = [&cleanup, &failure_diagnostic](
                            std::expected<GarbageCollectResult, Error> outcome)
        -> std::expected<GarbageCollectResult, Error> {
        std::optional<Error> cleanup_failure;
        try {
            auto released = cleanup.release_once();
            if (!released) {
                cleanup_failure = std::move(released.error());
            }
        } catch (const std::exception& exception) {
            cleanup_failure = make_error(
                ErrorCode::StateFailure,
                std::string{"barrier cleanup threw: "} + exception.what());
        } catch (...) {
            cleanup_failure =
                make_error(ErrorCode::StateFailure, "barrier cleanup threw");
        }
        failure_diagnostic.barrier_release_attempted =
            cleanup.release_attempted;
        failure_diagnostic.barrier_release_confirmed =
            cleanup.release_confirmed;
        if (cleanup_failure.has_value()) {
            failure_diagnostic.barrier_cleanup_error = cleanup_failure->detail;
            failure_diagnostic.barrier_cleanup_transport_error =
                cleanup_failure->transport_failure;
        }

        if (!outcome.has_value()) {
            if (!failure_diagnostic.transport_error.has_value()) {
                failure_diagnostic.transport_error =
                    outcome.error().transport_failure;
            }
            outcome.error().garbage_collection = failure_diagnostic;
            return outcome;
        }
        if (cleanup_failure.has_value()) {
            auto error = std::move(*cleanup_failure);
            if (!failure_diagnostic.transport_error.has_value()) {
                failure_diagnostic.transport_error = error.transport_failure;
            }
            error.garbage_collection = failure_diagnostic;
            return std::unexpected(std::move(error));
        }
        return outcome;
    };

    bool mutation_in_flight = false;
    try {
        if (auto verified = require_barrier_ownership(cleanup.registration);
            !verified) {
            return finish(std::unexpected(verified.error()));
        }
        if (auto writers = require_no_writers(storage, layout); !writers) {
            return finish(std::unexpected(writers.error()));
        }

        auto online = protocol::supports_online_collection(
            storage, layout, workspace_root);
        if (!online) {
            return finish(std::unexpected(protocol_error(online.error())));
        }

        failure_diagnostic.stage = GarbageCollectStage::Analyzing;
        notify(on_progress, GarbageCollectStage::Analyzing, std::nullopt, 0);
        if (!*online) {
            auto snapshot = observe(storage, key, workspace_root);
            if (!snapshot) {
                return finish(std::unexpected(snapshot.error()));
            }
            failure_diagnostic.stage = GarbageCollectStage::Finalizing;
            failure_diagnostic.candidate_objects = snapshot->candidates.size();
            notify(on_progress,
                   GarbageCollectStage::Finalizing,
                   snapshot->candidates.size(),
                   0);
            return finish(GarbageCollectResult{
                .candidate_objects = snapshot->candidates.size(),
                .removed_objects = 0,
                .analysis_only = true,
            });
        }

        auto first = observe(storage, key, workspace_root);
        if (!first) {
            return finish(std::unexpected(first.error()));
        }
        if (auto cancelled = cancellation_error(); cancelled.has_value()) {
            return finish(std::unexpected(std::move(*cancelled)));
        }
        if (auto writers = require_no_writers(storage, layout); !writers) {
            return finish(std::unexpected(writers.error()));
        }
        if (auto verified = require_barrier_ownership(cleanup.registration);
            !verified) {
            return finish(std::unexpected(verified.error()));
        }

        auto second = observe(storage, key, workspace_root);
        if (!second) {
            return finish(std::unexpected(second.error()));
        }
        if (!same_observation(*first, *second)) {
            return finish(
                std::unexpected(make_error(ErrorCode::ConcurrentChange,
                                           "remote observation changed during "
                                           "garbage collection analysis")));
        }

        auto expected_namespace =
            fresh_namespace(storage, second->physical_namespace);
        if (!expected_namespace) {
            return finish(std::unexpected(expected_namespace.error()));
        }
        if (auto writers = require_no_writers(storage, layout); !writers) {
            return finish(std::unexpected(writers.error()));
        }
        if (auto verified = require_barrier_ownership(cleanup.registration);
            !verified) {
            return finish(std::unexpected(verified.error()));
        }

        const auto candidate_count = second->candidates.size();
        failure_diagnostic.candidate_objects = candidate_count;
        failure_diagnostic.stage = GarbageCollectStage::Applying;
        notify(on_progress, GarbageCollectStage::Applying, candidate_count, 0);
        std::size_t removed_objects = 0;
        for (const auto& candidate : second->candidates) {
            failure_diagnostic.failed_identifier.reset();
            failure_diagnostic.mutation_state =
                GarbageCollectMutationState::NotAttempted;
            failure_diagnostic.transport_error.reset();

            if (auto cancelled = cancellation_error(); cancelled.has_value()) {
                return finish(std::unexpected(std::move(*cancelled)));
            }
            failure_diagnostic.failed_identifier = candidate.identifier;
            auto namespace_check =
                fresh_namespace(storage, *expected_namespace);
            if (!namespace_check) {
                return finish(std::unexpected(namespace_check.error()));
            }
            if (auto writers = require_no_writers(storage, layout); !writers) {
                return finish(std::unexpected(writers.error()));
            }
            if (auto eligible = revalidate_candidate(storage,
                                                     key,
                                                     workspace_root,
                                                     layout,
                                                     *expected_namespace,
                                                     candidate);
                !eligible) {
                return finish(std::unexpected(eligible.error()));
            }
            if (auto present = require_candidate_present(storage, candidate);
                !present) {
                return finish(std::unexpected(present.error()));
            }
            if (auto verified = require_barrier_ownership(cleanup.registration);
                !verified) {
                return finish(std::unexpected(verified.error()));
            }
            if (auto cancelled = cancellation_error(); cancelled.has_value()) {
                return finish(std::unexpected(std::move(*cancelled)));
            }

            mutation_in_flight = true;
            auto removed = transport::remove(storage, candidate.identifier);
            mutation_in_flight = false;
            if (!removed) {
                failure_diagnostic.mutation_state =
                    transport::mutation_result_is_ambiguous(removed.error())
                        ? GarbageCollectMutationState::Uncertain
                        : GarbageCollectMutationState::NotAttempted;
                return finish(std::unexpected(
                    transport_error(removed.error(), "object removal failed")));
            }
            if (*removed != transport::Removal::Removed) {
                failure_diagnostic.mutation_state =
                    GarbageCollectMutationState::NotAttempted;
                return finish(std::unexpected(
                    make_error(ErrorCode::ConcurrentChange,
                               "candidate disappeared during removal",
                               candidate.identifier)));
            }

            failure_diagnostic.mutation_state =
                GarbageCollectMutationState::Uncertain;
            if (auto confirmed = confirm_removal(storage, candidate);
                !confirmed) {
                failure_diagnostic.mutation_state =
                    GarbageCollectMutationState::Uncertain;
                return finish(std::unexpected(confirmed.error()));
            }

            ++removed_objects;
            failure_diagnostic.confirmed_removed = removed_objects;
            failure_diagnostic.mutation_state =
                GarbageCollectMutationState::Confirmed;
            failure_diagnostic.transport_error.reset();

            const auto found =
                std::ranges::find(*expected_namespace, candidate.identifier);
            if (found == expected_namespace->end()) {
                return finish(std::unexpected(make_error(
                    ErrorCode::ConcurrentChange,
                    "removed object was absent from the expected namespace",
                    candidate.identifier)));
            }
            expected_namespace->erase(found);
            notify(on_progress,
                   GarbageCollectStage::Applying,
                   candidate_count,
                   removed_objects);
        }

        failure_diagnostic.stage = GarbageCollectStage::Finalizing;
        failure_diagnostic.failed_identifier.reset();
        failure_diagnostic.transport_error.reset();
        failure_diagnostic.mutation_state =
            removed_objects == 0 ? GarbageCollectMutationState::NotAttempted
                                 : GarbageCollectMutationState::Confirmed;
        notify(on_progress,
               GarbageCollectStage::Finalizing,
               candidate_count,
               removed_objects);
        auto final_namespace = fresh_namespace(storage, *expected_namespace);
        if (!final_namespace) {
            return finish(std::unexpected(final_namespace.error()));
        }
        if (auto verified = require_barrier_ownership(cleanup.registration);
            !verified) {
            return finish(std::unexpected(verified.error()));
        }

        return finish(GarbageCollectResult{
            .candidate_objects = candidate_count,
            .removed_objects = removed_objects,
            .analysis_only = false,
        });
    } catch (const std::exception& error) {
        if (mutation_in_flight) {
            failure_diagnostic.mutation_state =
                GarbageCollectMutationState::Uncertain;
        }
        auto detail = std::string{"garbage collection failed: "};
        if (failure_diagnostic.stage == GarbageCollectStage::Applying) {
            detail = "garbage collection failed during apply: ";
        }
        detail += error.what();
        return finish(std::unexpected(
            make_error(ErrorCode::StateFailure, std::move(detail))));
    } catch (...) {
        if (mutation_in_flight) {
            failure_diagnostic.mutation_state =
                GarbageCollectMutationState::Uncertain;
        }
        if (failure_diagnostic.stage == GarbageCollectStage::Applying) {
            return finish(std::unexpected(
                make_error(ErrorCode::StateFailure,
                           "garbage collection failed during apply")));
        }
        return finish(std::unexpected(
            make_error(ErrorCode::StateFailure, "garbage collection failed")));
    }
}

} // namespace

std::expected<GarbageCollectResult, Error>
garbage_collect(const runtime::RuntimeData& runtime_data,
                transport::Transport& storage,
                std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                GarbageCollectProgressCallback on_progress) {
    try {
        return garbage_collect_impl(
            runtime_data, storage, key, std::move(on_progress));
    } catch (const std::bad_alloc&) {
        return std::unexpected(
            make_error(ErrorCode::StateFailure, "allocation failed"));
    } catch (const std::exception& exception) {
        return std::unexpected(make_error(
            ErrorCode::StateFailure,
            std::string{"garbage collection failed: "} + exception.what()));
    } catch (...) {
        return std::unexpected(
            make_error(ErrorCode::StateFailure, "garbage collection failed"));
    }
}

std::expected<GarbageCollectResult, Error>
garbage_collect(const runtime::RuntimeData& runtime_data,
                transport::Transport& storage,
                std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                std::size_t copy_batch_concurrency,
                std::size_t metadata_batch_concurrency,
                std::size_t source_removal_concurrency,
                GarbageCollectProgressCallback on_progress) {
    if (copy_batch_concurrency == 0 || metadata_batch_concurrency == 0 ||
        source_removal_concurrency == 0) {
        return std::unexpected(make_error(
            ErrorCode::InvalidInput,
            "garbage collection concurrency hints must be positive"));
    }
    return garbage_collect(runtime_data, storage, key, std::move(on_progress));
}

} // namespace kasumi::application::integrity
