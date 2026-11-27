#include "application/detail.hpp"
#include "application/history_storage/activity.hpp"
#include "application/history_storage/content_reachability.hpp"
#include "application/history_storage/detail.hpp"
#include "application/history_storage/epoch.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/reachability.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/maintenance.hpp"
#include "platform/cancellation.hpp"
#include "platform/clock.hpp"
#include "platform/machine.hpp"

#include <algorithm>
#include <array>
#include <chrono>
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
constexpr std::size_t gc_delete_batch_size = 8;

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
        const platform::cancellation::ScopedIgnoreCancellation ignore_cancel;

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

struct ProgressState {
    const GarbageCollectProgressCallback& on_progress;
    std::uint32_t min_age_hours = 0;
    std::optional<std::size_t> listed_objects;
    std::optional<std::size_t> commits_processed;
    std::optional<std::size_t> commits_total;
    std::optional<std::size_t> candidate_count;
    std::optional<std::size_t> candidate_content_objects;
    std::optional<std::size_t> candidate_commit_variants;
    std::optional<std::size_t> candidate_expired_commits;
    std::optional<std::size_t> candidate_activities;
    std::optional<std::size_t> deferred_recent_objects;
    std::optional<std::uint64_t> candidate_bytes;
    std::size_t removed_objects = 0;
    std::uint64_t removed_bytes = 0;
    std::chrono::nanoseconds removal_elapsed{};
};

void emit_gc_progress(const ProgressState& state,
                      GarbageCollectStage stage,
                      GarbageCollectSubStage sub_stage) noexcept {
    if (!state.on_progress) {
        return;
    }
    try {
        state.on_progress(GarbageCollectProgress{
            .stage = stage,
            .sub_stage = sub_stage,
            .candidate_count = state.candidate_count,
            .removed_objects = state.removed_objects,
            .removal_elapsed = state.removal_elapsed,
            .listed_objects = state.listed_objects,
            .commits_processed = state.commits_processed,
            .commits_total = state.commits_total,
            .candidate_content_objects = state.candidate_content_objects,
            .candidate_commit_variants = state.candidate_commit_variants,
            .candidate_expired_commits = state.candidate_expired_commits,
            .candidate_activities = state.candidate_activities,
            .deferred_recent_objects = state.deferred_recent_objects,
            .candidate_bytes = state.candidate_bytes,
            .removed_bytes = state.removed_bytes,
            .min_age_hours = state.min_age_hours,
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
fail_if_nonempty(const std::vector<std::string>& items,
                 std::string_view label) {
    if (items.empty()) {
        return {};
    }
    return std::unexpected(
        make_error(ErrorCode::IntegrityFailure,
                   std::string(label) + ": " + join_values(items)));
}

std::expected<void, Error>
validate_history(const history_storage::ReachabilityInventory& inventory) {
    if (inventory.logical_heads.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure, "remote history absent"));
    }
    if (auto ok = fail_if_nonempty(inventory.unknown_history_objects,
                                   "unknown history objects");
        !ok) {
        return ok;
    }
    if (auto ok = fail_if_nonempty(inventory.missing_parent_ids,
                                   "missing parent commits");
        !ok) {
        return ok;
    }
    if (auto ok = fail_if_nonempty(inventory.invalid_parent_ids,
                                   "invalid parent commits");
        !ok) {
        return ok;
    }

    std::vector<std::string> invalid_markers;
    for (const auto& marker : inventory.markers) {
        if (marker.state != history_storage::ReachabilityMarkerState::Valid) {
            invalid_markers.push_back(marker.identifier);
        }
    }
    if (auto ok = fail_if_nonempty(invalid_markers, "invalid head markers");
        !ok) {
        return ok;
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
    return fail_if_nonempty(invalid_commits, "invalid commits");
}

std::expected<void, Error> validate_content(
    const history_storage::ContentReachabilityInventory& inventory) {
    if (auto ok = fail_if_nonempty(inventory.unknown_storage_objects,
                                   "unknown physical identifiers");
        !ok) {
        return ok;
    }
    std::vector<std::string> damaged;
    for (const auto& content : inventory.contents) {
        if (content.reachable &&
            content.state != history_storage::ContentObjectState::Present) {
            damaged.push_back(content.content_id);
        }
    }
    return fail_if_nonempty(damaged, "reachable contents missing or corrupted");
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
    history_storage::detail::sort_unique(marked_commits);

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

    history_storage::detail::sort_unique(required);
    return required;
}

struct ObservePlan {
    std::vector<std::string> candidates;
    std::vector<std::uint64_t> candidate_sizes;
    std::vector<history_storage::activity::LoadedActivity> kept_activities;
    std::size_t candidate_content_objects = 0;
    std::size_t candidate_commit_variants = 0;
    std::size_t candidate_expired_commits = 0;
    std::size_t candidate_activities = 0;
    std::size_t deferred_recent_objects = 0;
    std::uint64_t candidate_bytes = 0;
    std::size_t pruned_activities = 0;
};

std::expected<ObservePlan, Error>
observe(transport::Transport& storage,
        KeySpan key,
        const history_storage::epoch::RetentionPolicy& retention,
        std::chrono::seconds effective_grace,
        std::uint32_t effective_min_age_hours,
        std::optional<std::string_view> barrier_identifier,
        const std::filesystem::path& workspace_root,
        history_storage::CommitCache* commit_cache,
        ProgressState& progress) {
    emit_gc_progress(progress,
                     GarbageCollectStage::Analyzing,
                     GarbageCollectSubStage::ListingRemote);

    std::vector<std::string> listing;
    std::vector<transport::ObjectMetadata> metadata_entries;
    bool list_done = false;
    if (storage.storage.list_metadata != nullptr) {
        auto meta = transport::list_metadata(storage);
        if (meta) {
            metadata_entries = std::move(*meta);
            listing.reserve(metadata_entries.size());
            for (const auto& obj : metadata_entries) {
                listing.push_back(obj.identifier);
            }
            list_done = true;
        } else if (meta.error().code != transport::ErrorCode::Unsupported) {
            return std::unexpected(
                transport_error(meta.error(), "could not list remote objects"));
        }
    }
    if (!list_done) {
        auto plain = transport::list(storage);
        if (!plain) {
            return std::unexpected(transport_error(
                plain.error(), "could not list remote objects"));
        }
        listing = std::move(*plain);
    }

    std::ranges::sort(listing);
    std::ranges::sort(
        metadata_entries, {}, &transport::ObjectMetadata::identifier);
    progress.listed_objects = listing.size();
    emit_gc_progress(progress,
                     GarbageCollectStage::Analyzing,
                     GarbageCollectSubStage::AuthenticatingHistory);

    const auto find_metadata =
        [&](std::string_view identifier) -> const transport::ObjectMetadata* {
        const auto it =
            std::ranges::lower_bound(metadata_entries,
                                     identifier,
                                     {},
                                     &transport::ObjectMetadata::identifier);
        if (it != metadata_entries.end() && it->identifier == identifier) {
            return &*it;
        }
        return nullptr;
    };

    const auto layout = history_storage::derive_remote_layout(key);
    auto history = history_storage::inventory_reachability(
        storage,
        key,
        listing,
        workspace_root,
        [&](std::size_t done, std::size_t total) {
            progress.commits_processed = done;
            progress.commits_total = total;
            emit_gc_progress(progress,
                             GarbageCollectStage::Analyzing,
                             GarbageCollectSubStage::AuthenticatingHistory);
        },
        commit_cache);
    if (!history) {
        return std::unexpected(history_error(history.error()));
    }
    if (auto valid = validate_history(*history); !valid) {
        return std::unexpected(valid.error());
    }

    emit_gc_progress(progress,
                     GarbageCollectStage::Analyzing,
                     GarbageCollectSubStage::AnalyzingReachability);
    auto content = history_storage::inventory_content_reachability(
        storage,
        key,
        listing,
        *history,
        workspace_root,
        /*audit_payloads=*/false,
        /*include_references=*/false);
    if (!content) {
        return std::unexpected(history_error(content.error()));
    }
    if (auto valid = validate_content(*content); !valid) {
        return std::unexpected(valid.error());
    }

    emit_gc_progress(progress,
                     GarbageCollectStage::Analyzing,
                     GarbageCollectSubStage::LoadingActivities);
    auto activities = history_storage::activity::load_all(
        storage, layout, key, workspace_root, listing);
    if (!activities) {
        return std::unexpected(history_error(activities.error()));
    }
    if (!activities->invalid_objects.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       "remote contains invalid operational activity objects",
                       activities->invalid_objects.front()));
    }
    const auto now_unix = platform::clock::unix_seconds();
    if (!now_unix) {
        return std::unexpected(
            make_error(ErrorCode::StateFailure,
                       "failed to read system clock for retention check: " +
                           now_unix.error()));
    }

    // Fail-closed remote clock clamping: when running a mutating GC with
    // positive grace period, clamp effective_now to min(local_now, remote_now)
    // observed from the backend-assigned timestamp on our published barrier.
    std::optional<std::int64_t> effective_now_unix = *now_unix;
    if (effective_grace > std::chrono::seconds{0} &&
        barrier_identifier.has_value()) {
        const auto* barrier_meta = find_metadata(*barrier_identifier);
        if (barrier_meta == nullptr ||
            !barrier_meta->modified_at_unix.has_value() ||
            *barrier_meta->modified_at_unix <= 0) {
            effective_now_unix.reset();
        } else {
            effective_now_unix =
                std::min(*now_unix, *barrier_meta->modified_at_unix);
        }
    }

    const auto is_old_enough =
        [&](std::string_view identifier,
            std::optional<std::int64_t> commit_created_at) -> bool {
        if (effective_grace == std::chrono::seconds{0}) {
            return true;
        }
        if (!effective_now_unix.has_value()) {
            return false;
        }
        const auto effective_now = *effective_now_unix;
        const auto* meta = find_metadata(identifier);
        if (meta == nullptr || !meta->modified_at_unix.has_value()) {
            return false;
        }
        const auto mtime = *meta->modified_at_unix;
        if (mtime <= 0 || mtime > effective_now ||
            (effective_now - mtime) < effective_grace.count()) {
            return false;
        }
        if (commit_created_at.has_value()) {
            const auto created = *commit_created_at;
            if (created <= 0 || created > effective_now ||
                (effective_now - created) < effective_grace.count()) {
                return false;
            }
        }
        return true;
    };

    auto activity_retention = retention;
    if (effective_grace > std::chrono::seconds{0}) {
        activity_retention.min_history_age_hours = std::max(
            activity_retention.min_history_age_hours, effective_min_age_hours);
    }
    std::vector<std::string> planned_activities;
    if (effective_now_unix.has_value()) {
        planned_activities = history_storage::activity::plan_pruning(
            activities->valid, activity_retention, *effective_now_unix);
        history_storage::detail::sort_unique(planned_activities);
    }

    std::size_t deferred_recent_objects = 0;
    std::vector<std::string> prunable_activities;
    prunable_activities.reserve(planned_activities.size());
    std::vector<history_storage::activity::LoadedActivity> kept_activities;
    kept_activities.reserve(activities->valid.size());

    auto protected_objects = required_variants(*history, layout);
    protected_objects.insert(protected_objects.end(),
                             content->reachable_content_ids.begin(),
                             content->reachable_content_ids.end());
    protected_objects.insert(protected_objects.end(),
                             history->valid_epochs.begin(),
                             history->valid_epochs.end());
    protected_objects.insert(protected_objects.end(),
                             history->orphan_epochs.begin(),
                             history->orphan_epochs.end());
    for (const auto& entry : activities->valid) {
        if (!std::ranges::binary_search(planned_activities, entry.identifier)) {
            kept_activities.push_back(entry);
            protected_objects.push_back(entry.identifier);
        } else if (!is_old_enough(entry.identifier, std::nullopt)) {
            ++deferred_recent_objects;
            kept_activities.push_back(entry);
            protected_objects.push_back(entry.identifier);
        } else {
            prunable_activities.push_back(entry.identifier);
        }
    }
    history_storage::detail::sort_unique(protected_objects);
    history_storage::detail::sort_unique(prunable_activities);

    std::vector<std::string> orphan_ids = content->orphan_content_ids;
    history_storage::detail::sort_unique(orphan_ids);

    std::vector<std::pair<std::string, std::uint64_t>> planned;
    std::size_t candidate_content_objects = 0;
    std::size_t candidate_commit_variants = 0;
    std::size_t candidate_expired_commits = 0;
    std::size_t candidate_activities = 0;

    const auto validate_unprotected =
        [&](std::string_view identifier) -> std::expected<void, Error> {
        if (identifier.empty() ||
            protocol::is_control_object(layout, identifier) ||
            std::ranges::binary_search(protected_objects, identifier)) {
            return std::unexpected(make_error(
                ErrorCode::IntegrityFailure,
                "deletion candidate intersects protected or control objects",
                std::string{identifier}));
        }
        return {};
    };
    const auto object_size = [&](std::string_view identifier) -> std::uint64_t {
        const auto* meta = find_metadata(identifier);
        return (meta != nullptr && meta->size.has_value()) ? *meta->size : 0U;
    };

    for (const auto& commit : history->commits) {
        if (!commit.valid) {
            continue;
        }
        std::optional<std::int64_t> expired_created_at;
        if (!commit.reachable) {
            expired_created_at =
                commit.tree ? commit.tree->created_at : std::int64_t{0};
        }
        for (const auto& variant : commit.variants) {
            if (variant.identifier.empty() ||
                variant.state != history_storage::detail::VariantState::Valid ||
                std::ranges::binary_search(protected_objects,
                                           variant.identifier)) {
                continue;
            }
            if (protocol::is_control_object(layout, variant.identifier)) {
                return std::unexpected(
                    make_error(ErrorCode::IntegrityFailure,
                               "deletion candidate intersects control objects",
                               variant.identifier));
            }
            if (!is_old_enough(variant.identifier, expired_created_at)) {
                ++deferred_recent_objects;
                continue;
            }
            planned.emplace_back(variant.identifier,
                                 object_size(variant.identifier));
            if (commit.reachable) {
                ++candidate_commit_variants;
            } else {
                ++candidate_expired_commits;
            }
        }
    }

    for (const auto& identifier : orphan_ids) {
        if (auto ok = validate_unprotected(identifier); !ok) {
            return std::unexpected(ok.error());
        }
        if (!is_old_enough(identifier, std::nullopt)) {
            ++deferred_recent_objects;
            continue;
        }
        planned.emplace_back(identifier, object_size(identifier));
        ++candidate_content_objects;
    }

    for (const auto& identifier : prunable_activities) {
        if (auto ok = validate_unprotected(identifier); !ok) {
            return std::unexpected(ok.error());
        }
        planned.emplace_back(identifier, object_size(identifier));
        ++candidate_activities;
    }

    std::ranges::sort(
        planned, {}, &std::pair<std::string, std::uint64_t>::first);
    const auto dup = std::ranges::unique(
        planned, {}, &std::pair<std::string, std::uint64_t>::first);
    planned.erase(dup.begin(), dup.end());

    std::vector<std::string> candidates;
    std::vector<std::uint64_t> candidate_sizes;
    candidates.reserve(planned.size());
    candidate_sizes.reserve(planned.size());
    std::uint64_t candidate_bytes = 0;
    for (auto& [id, size] : planned) {
        candidate_bytes += size;
        candidates.push_back(std::move(id));
        candidate_sizes.push_back(size);
    }

    return ObservePlan{
        .candidates = std::move(candidates),
        .candidate_sizes = std::move(candidate_sizes),
        .kept_activities = std::move(kept_activities),
        .candidate_content_objects = candidate_content_objects,
        .candidate_commit_variants = candidate_commit_variants,
        .candidate_expired_commits = candidate_expired_commits,
        .candidate_activities = candidate_activities,
        .deferred_recent_objects = deferred_recent_objects,
        .candidate_bytes = candidate_bytes,
        .pruned_activities = candidate_activities,
    };
}

std::expected<void, Error>
reject_if_writers_present(const std::vector<std::string>& writers) {
    if (!writers.empty()) {
        return std::unexpected(
            make_error(ErrorCode::ConcurrentChange,
                       "active writers block garbage collection: " +
                           join_values(writers)));
    }
    return {};
}

std::expected<void, Error>
require_no_writers(transport::Transport& storage,
                   const history_storage::RemoteLayout& layout) {
    auto writers = protocol::active_writers(storage, layout);
    if (!writers) {
        return std::unexpected(protocol_error(writers.error()));
    }
    return reject_if_writers_present(*writers);
}

std::expected<void, Error>
check_pre_barrier_controls(transport::Transport& storage,
                           const history_storage::RemoteLayout& layout) {
    bool use_fallback = (storage.storage.control_read_batch == nullptr);
    std::vector<std::string> listed_writers;
    std::vector<std::string> listed_barriers;
    transport::Presence legacy_barrier = transport::Presence::Absent;

    if (!use_fallback) {
        const auto writers_dir =
            history_storage::detail::trim_trailing_slash(layout.writers_prefix);
        const auto barriers_dir = history_storage::detail::trim_trailing_slash(
            layout.barriers_prefix);
        auto batch = transport::control_read_batch(
            storage,
            transport::ControlReadBatchRequest{
                .list_prefixes = {std::string{writers_dir},
                                  std::string{barriers_dir}},
                .presence_identifiers = {layout.barrier_identifier},
            });
        if (!batch) {
            if (batch.error().code == transport::ErrorCode::Unsupported) {
                use_fallback = true;
            } else {
                return std::unexpected(transport_error(
                    batch.error(), "could not inspect maintenance controls"));
            }
        } else {
            if (batch->listings.size() != 2 || batch->presences.size() != 1) {
                return std::unexpected(make_error(
                    ErrorCode::TransportFailure,
                    "invalid control read batch response cardinality"));
            }
            listed_writers = std::move(batch->listings[0]);
            listed_barriers = std::move(batch->listings[1]);
            legacy_barrier = batch->presences.front();
        }
    }

    if (use_fallback) {
        auto barriers = protocol::active_barriers(storage, layout);
        if (!barriers) {
            return std::unexpected(protocol_error(barriers.error()));
        }
        if (!barriers->empty()) {
            return std::unexpected(
                make_error(ErrorCode::ConcurrentChange,
                           "another maintenance barrier is already present"));
        }
        return require_no_writers(storage, layout);
    }

    if (legacy_barrier == transport::Presence::Present ||
        !listed_barriers.empty()) {
        return std::unexpected(
            make_error(ErrorCode::ConcurrentChange,
                       "another maintenance barrier is already present"));
    }

    std::vector<std::string> writers;
    writers.reserve(listed_writers.size());
    for (const auto& name : listed_writers) {
        const bool valid_hex32 =
            name.size() == 32 && std::ranges::all_of(name, [](char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            });
        if (!valid_hex32) {
            return std::unexpected(make_error(
                ErrorCode::IntegrityFailure, "invalid writer marker: " + name));
        }
        writers.push_back(layout.writers_prefix + name);
    }
    return reject_if_writers_present(writers);
}

std::expected<void, Error>
require_barrier_exclusivity(const protocol::RegistrationState& barrier,
                            const history_storage::RemoteLayout& layout) {
    if (!protocol::registration_active(barrier)) {
        return std::unexpected(make_error(ErrorCode::ConcurrentChange,
                                          "maintenance barrier lost"));
    }
    auto verified = protocol::verify_barrier_exclusivity(barrier, layout);
    if (!verified) {
        return std::unexpected(protocol_error(verified.error()));
    }
    return {};
}

std::expected<GarbageCollectResult, Error>
garbage_collect_impl(const runtime::RuntimeData& runtime_data,
                     transport::Transport& storage,
                     KeySpan key,
                     const GarbageCollectOptions& options,
                     GarbageCollectProgressCallback on_progress) {
    if (!transport::valid(storage)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidInput, "invalid transport"));
    }
    if (options.min_orphan_age.has_value() &&
        *options.min_orphan_age < std::chrono::seconds{0}) {
        return std::unexpected(make_error(
            ErrorCode::InvalidInput,
            "garbage collection min_orphan_age must be non-negative"));
    }
    const auto workspace_root =
        application::detail::maintenance_workspace_root(runtime_data);
    if (workspace_root.empty()) {
        return std::unexpected(
            make_error(ErrorCode::InvalidInput, "invalid workspace"));
    }

    const std::chrono::seconds effective_grace =
        options.min_orphan_age.has_value()
            ? *options.min_orphan_age
            : std::chrono::duration_cast<std::chrono::seconds>(
                  std::chrono::hours{runtime_data.min_history_age_hours});
    const std::uint32_t effective_min_age_hours =
        static_cast<std::uint32_t>(effective_grace.count() / 3600);

    GarbageCollectFailure failure_diagnostic{};
    failure_diagnostic.stage = GarbageCollectStage::Preparing;
    ProgressState progress{
        .on_progress = on_progress,
        .min_age_hours = effective_min_age_hours,
    };
    emit_gc_progress(
        progress, GarbageCollectStage::Preparing, GarbageCollectSubStage::None);
    if (auto cancelled = cancellation_error(); cancelled.has_value()) {
        return std::unexpected(std::move(*cancelled));
    }

    const auto layout = history_storage::derive_remote_layout(key);
    emit_gc_progress(progress,
                     GarbageCollectStage::Preparing,
                     GarbageCollectSubStage::CheckingControls);
    if (auto controls = check_pre_barrier_controls(storage, layout);
        !controls) {
        auto err = controls.error();
        if (!failure_diagnostic.transport_error.has_value()) {
            failure_diagnostic.transport_error = err.transport_failure;
        }
        err.garbage_collection = failure_diagnostic;
        return std::unexpected(std::move(err));
    }

    const history_storage::epoch::RetentionPolicy retention{
        .min_history_depth = runtime_data.min_history_depth,
        .min_history_age_hours = runtime_data.min_history_age_hours,
    };

    if (options.dry_run) {
        failure_diagnostic.stage = GarbageCollectStage::Analyzing;
        auto observed_plan = observe(storage,
                                     key,
                                     retention,
                                     effective_grace,
                                     effective_min_age_hours,
                                     std::nullopt,
                                     workspace_root,
                                     options.commit_cache,
                                     progress);
        if (!observed_plan) {
            auto err = observed_plan.error();
            if (!failure_diagnostic.transport_error.has_value()) {
                failure_diagnostic.transport_error = err.transport_failure;
            }
            err.garbage_collection = failure_diagnostic;
            return std::unexpected(std::move(err));
        }

        const auto candidate_count = observed_plan->candidates.size();
        failure_diagnostic.candidate_objects = candidate_count;
        progress.candidate_count = candidate_count;
        progress.candidate_content_objects =
            observed_plan->candidate_content_objects;
        progress.candidate_commit_variants =
            observed_plan->candidate_commit_variants;
        progress.candidate_expired_commits =
            observed_plan->candidate_expired_commits;
        progress.candidate_activities = observed_plan->candidate_activities;
        progress.deferred_recent_objects =
            observed_plan->deferred_recent_objects;
        progress.candidate_bytes = observed_plan->candidate_bytes;
        emit_gc_progress(progress,
                         GarbageCollectStage::Analyzing,
                         GarbageCollectSubStage::None);

        failure_diagnostic.stage = GarbageCollectStage::Finalizing;
        emit_gc_progress(progress,
                         GarbageCollectStage::Finalizing,
                         GarbageCollectSubStage::None);
        return GarbageCollectResult{
            .candidate_objects = candidate_count,
            .removed_objects = 0,
            .analysis_only = false,
            .dry_run = true,
            .candidate_content_objects =
                observed_plan->candidate_content_objects,
            .candidate_commit_variants =
                observed_plan->candidate_commit_variants,
            .candidate_expired_commits =
                observed_plan->candidate_expired_commits,
            .candidate_activities = observed_plan->candidate_activities,
            .deferred_recent_objects = observed_plan->deferred_recent_objects,
            .candidate_bytes = observed_plan->candidate_bytes,
            .removed_bytes = 0,
            .effective_min_age_hours = effective_min_age_hours,
            .pruned_activities = observed_plan->pruned_activities,
            .kept_activities = std::move(observed_plan->kept_activities),
        };
    }

    emit_gc_progress(progress,
                     GarbageCollectStage::Preparing,
                     GarbageCollectSubStage::EstablishingBarrier);
    protocol::BarrierOptions barrier_options{
        .settle_delay = options.barrier_settle_delay,
    };
    if (options.machine_name.has_value()) {
        const auto now_sec =
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count();
        barrier_options.metadata = protocol::MarkerMetadata{
            .machine_name = *options.machine_name,
            .pid = platform::machine::current_process_id(),
            .started_at_unix = static_cast<std::int64_t>(now_sec),
        };
    }
    auto barrier = protocol::establish_barrier(
        storage, layout, workspace_root, barrier_options);
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
    const auto fail_exception = [&](std::string_view what) {
        if (mutation_in_flight) {
            failure_diagnostic.mutation_state =
                GarbageCollectMutationState::Uncertain;
        }
        std::string detail =
            failure_diagnostic.stage == GarbageCollectStage::Applying
                ? "garbage collection failed during apply"
                : "garbage collection failed";
        if (!what.empty()) {
            detail += ": ";
            detail += what;
        }
        return finish(std::unexpected(
            make_error(ErrorCode::StateFailure, std::move(detail))));
    };

    try {
        if (auto verified =
                require_barrier_exclusivity(cleanup.registration, layout);
            !verified) {
            return finish(std::unexpected(verified.error()));
        }

        failure_diagnostic.stage = GarbageCollectStage::Analyzing;
        auto observed_plan = observe(storage,
                                     key,
                                     retention,
                                     effective_grace,
                                     effective_min_age_hours,
                                     cleanup.registration.identifier,
                                     workspace_root,
                                     options.commit_cache,
                                     progress);
        if (!observed_plan) {
            return finish(std::unexpected(observed_plan.error()));
        }

        const auto& candidates = observed_plan->candidates;
        const auto& candidate_sizes = observed_plan->candidate_sizes;
        const auto candidate_count = candidates.size();
        failure_diagnostic.candidate_objects = candidate_count;
        progress.candidate_count = candidate_count;
        progress.candidate_content_objects =
            observed_plan->candidate_content_objects;
        progress.candidate_commit_variants =
            observed_plan->candidate_commit_variants;
        progress.candidate_expired_commits =
            observed_plan->candidate_expired_commits;
        progress.candidate_activities = observed_plan->candidate_activities;
        progress.deferred_recent_objects =
            observed_plan->deferred_recent_objects;
        progress.candidate_bytes = observed_plan->candidate_bytes;
        emit_gc_progress(progress,
                         GarbageCollectStage::Analyzing,
                         GarbageCollectSubStage::None);

        if (candidates.empty()) {
            failure_diagnostic.stage = GarbageCollectStage::Finalizing;
            failure_diagnostic.mutation_state =
                GarbageCollectMutationState::NotAttempted;
            emit_gc_progress(progress,
                             GarbageCollectStage::Finalizing,
                             GarbageCollectSubStage::ReleasingBarrier);
            return finish(GarbageCollectResult{
                .candidate_objects = 0,
                .removed_objects = 0,
                .analysis_only = false,
                .dry_run = false,
                .candidate_content_objects =
                    observed_plan->candidate_content_objects,
                .candidate_commit_variants =
                    observed_plan->candidate_commit_variants,
                .candidate_expired_commits =
                    observed_plan->candidate_expired_commits,
                .candidate_activities = observed_plan->candidate_activities,
                .deferred_recent_objects =
                    observed_plan->deferred_recent_objects,
                .candidate_bytes = observed_plan->candidate_bytes,
                .removed_bytes = 0,
                .effective_min_age_hours = effective_min_age_hours,
                .pruned_activities = observed_plan->pruned_activities,
                .kept_activities = std::move(observed_plan->kept_activities),
            });
        }

        emit_gc_progress(progress,
                         GarbageCollectStage::Analyzing,
                         GarbageCollectSubStage::ProbingConsistency);
        auto online = protocol::supports_online_collection(
            storage, layout, workspace_root);
        if (!online) {
            return finish(std::unexpected(protocol_error(online.error())));
        }

        if (!*online) {
            failure_diagnostic.stage = GarbageCollectStage::Finalizing;
            emit_gc_progress(progress,
                             GarbageCollectStage::Finalizing,
                             GarbageCollectSubStage::ReleasingBarrier);
            return finish(GarbageCollectResult{
                .candidate_objects = candidate_count,
                .removed_objects = 0,
                .analysis_only = true,
                .dry_run = false,
                .candidate_content_objects =
                    observed_plan->candidate_content_objects,
                .candidate_commit_variants =
                    observed_plan->candidate_commit_variants,
                .candidate_expired_commits =
                    observed_plan->candidate_expired_commits,
                .candidate_activities = observed_plan->candidate_activities,
                .deferred_recent_objects =
                    observed_plan->deferred_recent_objects,
                .candidate_bytes = observed_plan->candidate_bytes,
                .removed_bytes = 0,
                .effective_min_age_hours = effective_min_age_hours,
                .pruned_activities = observed_plan->pruned_activities,
                .kept_activities = std::move(observed_plan->kept_activities),
            });
        }

        failure_diagnostic.stage = GarbageCollectStage::Applying;
        const auto removal_started = std::chrono::steady_clock::now();
        emit_gc_progress(progress,
                         GarbageCollectStage::Applying,
                         GarbageCollectSubStage::RemovingObjects);
        auto apply = [&]() -> std::expected<std::size_t, Error> {
            auto verified =
                require_barrier_exclusivity(cleanup.registration, layout);
            if (!verified) {
                return std::unexpected(verified.error());
            }
            std::size_t acknowledged_removals = 0;
            bool fallback_sequential =
                (storage.storage.remove_batch == nullptr);

            std::size_t chunk_start = 0;
            const std::size_t total_candidates = candidates.size();
            const std::size_t revalidation_object_interval =
                options.apply_revalidation_batch_interval > 0
                    ? options.apply_revalidation_batch_interval *
                          gc_delete_batch_size
                    : 0;
            std::size_t objects_since_revalidation = 0;
            auto last_revalidation = std::chrono::steady_clock::now();

            const auto fail_uncertain = [&](std::optional<std::string> id,
                                            transport::Error error,
                                            std::string_view detail) {
                failure_diagnostic.failed_identifier = std::move(id);
                failure_diagnostic.transport_error = error;
                failure_diagnostic.mutation_state =
                    GarbageCollectMutationState::Uncertain;
                return std::unexpected(transport_error(error, detail));
            };
            const auto record_acknowledged = [&](std::size_t count,
                                                 std::uint64_t bytes) {
                acknowledged_removals += count;
                failure_diagnostic.confirmed_removed = acknowledged_removals;
                failure_diagnostic.mutation_state =
                    GarbageCollectMutationState::Confirmed;
                progress.removed_objects = acknowledged_removals;
                progress.removed_bytes += bytes;
                progress.removal_elapsed =
                    std::chrono::steady_clock::now() - removal_started;
                emit_gc_progress(progress,
                                 GarbageCollectStage::Applying,
                                 GarbageCollectSubStage::RemovingObjects);
            };

            while (chunk_start < total_candidates) {
                failure_diagnostic.failed_identifier.reset();
                failure_diagnostic.mutation_state =
                    GarbageCollectMutationState::NotAttempted;
                failure_diagnostic.transport_error.reset();

                if (auto cancelled = cancellation_error();
                    cancelled.has_value()) {
                    return std::unexpected(std::move(*cancelled));
                }

                const auto now_steady = std::chrono::steady_clock::now();
                const bool batch_due =
                    revalidation_object_interval > 0 &&
                    objects_since_revalidation >= revalidation_object_interval;
                const bool time_due =
                    options.apply_revalidation_time_interval >
                        std::chrono::seconds{0} &&
                    (now_steady - last_revalidation) >=
                        options.apply_revalidation_time_interval;
                if (chunk_start > 0 && (batch_due || time_due)) {
                    auto revalidated = require_barrier_exclusivity(
                        cleanup.registration, layout);
                    if (!revalidated) {
                        return std::unexpected(revalidated.error());
                    }
                    objects_since_revalidation = 0;
                    last_revalidation = now_steady;
                }

                if (!fallback_sequential) {
                    const std::size_t chunk_size = std::min(
                        gc_delete_batch_size, total_candidates - chunk_start);

                    transport::RemoveBatch batch;
                    batch.concurrency = gc_delete_batch_size;
                    batch.items.reserve(chunk_size);
                    for (std::size_t i = 0; i < chunk_size; ++i) {
                        batch.items.push_back(transport::RemoveBatchItem{
                            .identifier = candidates[chunk_start + i],
                        });
                    }

                    mutation_in_flight = true;
                    auto batch_result = transport::remove_batch(storage, batch);
                    mutation_in_flight = false;

                    if (!batch_result) {
                        const auto err = batch_result.error();
                        if (err.code == transport::ErrorCode::Unsupported) {
                            fallback_sequential = true;
                            continue;
                        }
                        return fail_uncertain(
                            std::nullopt, err, "batch object removal failed");
                    }

                    const auto& report = *batch_result;
                    const auto requested =
                        std::span{candidates}.subspan(chunk_start, chunk_size);
                    const bool report_valid =
                        report.items.size() == chunk_size &&
                        std::ranges::all_of(requested, [&](const auto& id) {
                            return std::ranges::count(
                                       report.items,
                                       id,
                                       &transport::RemoveBatchItemResult::
                                           identifier) == 1;
                        });

                    if (!report_valid) {
                        return fail_uncertain(
                            std::nullopt,
                            transport::Error{
                                .code = transport::ErrorCode::ProtocolFailure,
                                .message =
                                    "invalid or incomplete remove batch report",
                            },
                            "invalid remove batch report");
                    }

                    std::size_t batch_acknowledged = 0;
                    std::uint64_t batch_bytes = 0;
                    const transport::RemoveBatchItemResult* first_failure =
                        nullptr;
                    std::string first_failed_identifier;

                    for (std::size_t i = 0; i < chunk_size; ++i) {
                        const auto& cand_id = candidates[chunk_start + i];
                        const auto* res = &*std::ranges::find(
                            report.items,
                            cand_id,
                            &transport::RemoveBatchItemResult::identifier);
                        if (res->result.has_value()) {
                            ++batch_acknowledged;
                            batch_bytes += candidate_sizes[chunk_start + i];
                        } else if (first_failure == nullptr) {
                            first_failure = res;
                            first_failed_identifier = cand_id;
                        }
                    }

                    if (batch_acknowledged > 0) {
                        record_acknowledged(batch_acknowledged, batch_bytes);
                    }
                    if (first_failure != nullptr) {
                        return fail_uncertain(first_failed_identifier,
                                              first_failure->result.error(),
                                              "object removal failed");
                    }
                    chunk_start += chunk_size;
                    objects_since_revalidation += chunk_size;
                } else {
                    const auto& candidate = candidates[chunk_start];
                    failure_diagnostic.failed_identifier = candidate;
                    mutation_in_flight = true;
                    auto removed = transport::remove(storage, candidate);
                    mutation_in_flight = false;
                    if (!removed) {
                        return fail_uncertain(candidate,
                                              removed.error(),
                                              "object removal failed");
                    }
                    record_acknowledged(1, candidate_sizes[chunk_start]);
                    ++chunk_start;
                    ++objects_since_revalidation;
                }
            }
            return acknowledged_removals;
        }();
        if (!apply) {
            return finish(std::unexpected(apply.error()));
        }
        const auto removed_objects = *apply;
        const auto removal_elapsed =
            std::chrono::steady_clock::now() - removal_started;

        failure_diagnostic.stage = GarbageCollectStage::Finalizing;
        failure_diagnostic.failed_identifier.reset();
        failure_diagnostic.transport_error.reset();
        failure_diagnostic.mutation_state =
            removed_objects == 0 ? GarbageCollectMutationState::NotAttempted
                                 : GarbageCollectMutationState::Confirmed;
        progress.removed_objects = removed_objects;
        progress.removal_elapsed = removal_elapsed;
        emit_gc_progress(progress,
                         GarbageCollectStage::Finalizing,
                         GarbageCollectSubStage::ReleasingBarrier);

        return finish(GarbageCollectResult{
            .candidate_objects = candidate_count,
            .removed_objects = removed_objects,
            .analysis_only = false,
            .dry_run = false,
            .candidate_content_objects =
                observed_plan->candidate_content_objects,
            .candidate_commit_variants =
                observed_plan->candidate_commit_variants,
            .candidate_expired_commits =
                observed_plan->candidate_expired_commits,
            .candidate_activities = observed_plan->candidate_activities,
            .deferred_recent_objects = observed_plan->deferred_recent_objects,
            .candidate_bytes = observed_plan->candidate_bytes,
            .removed_bytes = progress.removed_bytes,
            .effective_min_age_hours = effective_min_age_hours,
            .removal_elapsed = removal_elapsed,
            .pruned_activities = observed_plan->pruned_activities,
            .kept_activities = std::move(observed_plan->kept_activities),
        });
    } catch (const std::exception& error) {
        return fail_exception(error.what());
    } catch (...) {
        return fail_exception({});
    }
}

} // namespace

std::expected<GarbageCollectResult, Error>
garbage_collect(const runtime::RuntimeData& runtime_data,
                transport::Transport& storage,
                std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                GarbageCollectOptions options,
                GarbageCollectProgressCallback on_progress) {
    try {
        return garbage_collect_impl(
            runtime_data, storage, key, options, std::move(on_progress));
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
                GarbageCollectProgressCallback on_progress) {
    return garbage_collect(runtime_data,
                           storage,
                           key,
                           GarbageCollectOptions{},
                           std::move(on_progress));
}

std::expected<GarbageCollectResult, Error>
garbage_collect(const runtime::RuntimeData& runtime_data,
                transport::Transport& storage,
                std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                bool dry_run,
                GarbageCollectProgressCallback on_progress) {
    return garbage_collect(runtime_data,
                           storage,
                           key,
                           GarbageCollectOptions{.dry_run = dry_run},
                           std::move(on_progress));
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
