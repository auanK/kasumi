#include "application/history_storage/content_reachability.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/reachability.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/maintenance.hpp"
#include "platform/cancellation.hpp"
#include "platform/perf_trace.hpp"

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
#include <tuple>
#include <unordered_set>
#include <utility>
#include <vector>

namespace kasumi::application::integrity {
namespace {

namespace history_storage = application::history_storage;
namespace protocol = application::history_storage::maintenance_protocol;
using KeySpan = std::span<const std::uint8_t, crypto::KEY_SIZE>;

std::string_view phase_metric(GarbageCollectStage stage) noexcept {
    switch (stage) {
        case GarbageCollectStage::Preparing:
            return "gc.preparing_us";
        case GarbageCollectStage::Analyzing:
            return "gc.analyzing_us";
        case GarbageCollectStage::Applying:
            return "gc.applying_us";
        case GarbageCollectStage::Finalizing:
            return "gc.finalizing_us";
    }
    return "gc.unknown_stage_us";
}

class PerfTimer {
public:
    explicit PerfTimer(std::string_view name) noexcept
        : name_(name), token_(platform::perf_trace::begin()) {
    }

    ~PerfTimer() {
        platform::perf_trace::finish(name_, token_);
    }

    PerfTimer(const PerfTimer&) = delete;
    PerfTimer& operator=(const PerfTimer&) = delete;

private:
    std::string_view name_;
    platform::perf_trace::Token token_;
};

class GarbageCollectionTrace {
public:
    GarbageCollectionTrace() noexcept
        : total_(platform::perf_trace::begin()),
          phase_(platform::perf_trace::begin()) {
    }

    ~GarbageCollectionTrace() { finish(); }

    void enter(GarbageCollectStage stage) noexcept {
        if (stage == stage_ || finished_) {
            return;
        }
        platform::perf_trace::finish(phase_metric(stage_), phase_);
        stage_ = stage;
        phase_ = platform::perf_trace::begin();
    }

    void finish() noexcept {
        if (finished_) {
            return;
        }
        platform::perf_trace::finish(phase_metric(stage_), phase_);
        platform::perf_trace::finish("gc.total_us", total_);
        finished_ = true;
    }

private:
    platform::perf_trace::Token total_;
    platform::perf_trace::Token phase_;
    GarbageCollectStage stage_ = GarbageCollectStage::Preparing;
    bool finished_ = false;
};

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

// Built once from the authenticated observation and consumed as-is by Apply.
// The maintenance barrier excludes cooperative writers; there is no distributed
// CAS, so later non-cooperative mutation is outside this contract.
struct DeletionPlan {
    std::vector<Candidate> candidates;
    std::vector<std::string> protected_objects;
};

struct Observation {
    std::vector<std::string> logical_heads;
    std::vector<std::string> reachable_commits;
    std::vector<std::string> reachable_content;
    DeletionPlan plan;
};

// Attributes transport reads to the phase that performed them. Perf tracing is
// optional; when disabled every read returns zero.
class PhaseTraffic {
public:
    explicit PhaseTraffic(std::string_view prefix)
        : prefix_(prefix),
          get_start_(platform::perf_trace::get_count("transport get")),
          list_start_(platform::perf_trace::get_count("transport list") +
                      platform::perf_trace::get_count("transport list prefix")),
          presence_start_(
              platform::perf_trace::get_count("transport presence")) {
    }

    ~PhaseTraffic() { finish(); }

    PhaseTraffic(const PhaseTraffic&) = delete;
    PhaseTraffic& operator=(const PhaseTraffic&) = delete;

    void finish() noexcept {
        if (finished_) {
            return;
        }
        finished_ = true;
        platform::perf_trace::count(
            std::string{prefix_} + "get_calls",
            platform::perf_trace::get_count("transport get") - get_start_);
        platform::perf_trace::count(
            std::string{prefix_} + "list_calls",
            platform::perf_trace::get_count("transport list") +
                platform::perf_trace::get_count("transport list prefix") -
                list_start_);
        platform::perf_trace::count(
            std::string{prefix_} + "presence_calls",
            platform::perf_trace::get_count("transport presence") -
                presence_start_);
    }

private:
    std::string_view prefix_;
    std::uint64_t get_start_ = 0;
    std::uint64_t list_start_ = 0;
    std::uint64_t presence_start_ = 0;
    bool finished_ = false;
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
        platform::perf_trace::count("gc.barrier_cleanup_attempts");
        PerfTimer cleanup_trace{"gc.barrier_cleanup_us"};
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

std::expected<void, Error> validate_deletion_plan(
    const DeletionPlan& plan,
    const history_storage::ReachabilityInventory& history,
    const std::vector<std::string>& orphan_contents,
    const history_storage::RemoteLayout& layout) {
    platform::perf_trace::count("gc.plan_validations");
    for (std::size_t index = 1; index < plan.candidates.size(); ++index) {
        const auto& previous = plan.candidates[index - 1];
        const auto& current = plan.candidates[index];
        if (!(std::tie(previous.kind, previous.identifier) <
              std::tie(current.kind, current.identifier))) {
            return std::unexpected(make_error(
                ErrorCode::IntegrityFailure,
                "deletion plan candidates are not sorted and unique"));
        }
    }

    const std::unordered_set<std::string> protected_objects(
        plan.protected_objects.begin(), plan.protected_objects.end());
    std::unordered_set<std::string> deletions;
    deletions.reserve(plan.candidates.size());
    for (const auto& candidate : plan.candidates) {
        if (candidate.identifier.empty() ||
            history_storage::maintenance_protocol::is_control_object(
                layout, candidate.identifier) ||
            protected_objects.contains(candidate.identifier) ||
            !deletions.insert(candidate.identifier).second) {
            return std::unexpected(make_error(
                ErrorCode::IntegrityFailure,
                "deletion plan intersects protected or control objects",
                candidate.identifier));
        }
        if (candidate.kind == CandidateKind::Content) {
            if (!std::ranges::binary_search(orphan_contents,
                                            candidate.identifier)) {
                return std::unexpected(make_error(
                    ErrorCode::IntegrityFailure,
                    "deletion plan contains an unclassified content object",
                    candidate.identifier));
            }
            continue;
        }
        const auto commit =
            std::ranges::find(history.commits,
                              candidate.commit_id,
                              &history_storage::ReachabilityCommit::commit_id);
        if (commit == history.commits.end() || !commit->reachable ||
            !commit->valid) {
            return std::unexpected(make_error(
                ErrorCode::IntegrityFailure,
                "deletion plan contains an unclassified commit variant",
                candidate.identifier));
        }
        const auto variant =
            std::ranges::find(commit->variants,
                              candidate.identifier,
                              &history_storage::ReachabilityVariant::identifier);
        if (variant == commit->variants.end() ||
            variant->state != history_storage::detail::VariantState::Valid) {
            return std::unexpected(make_error(
                ErrorCode::IntegrityFailure,
                "deletion plan contains an unclassified commit variant",
                candidate.identifier));
        }
    }

    for (const auto& commit : history.commits) {
        if (!commit.reachable) {
            continue;
        }
        const bool preserves_alternative = std::ranges::any_of(
            commit.variants, [&](const auto& variant) {
                return !variant.identifier.empty() &&
                       variant.state ==
                           history_storage::detail::VariantState::Valid &&
                       !deletions.contains(variant.identifier);
            });
        if (!preserves_alternative) {
            return std::unexpected(make_error(
                ErrorCode::IntegrityFailure,
                "deletion plan removes every valid variant of a reachable commit",
                commit.commit_id));
        }
    }

    for (const auto& marker : history.markers) {
        if (marker.state != history_storage::ReachabilityMarkerState::Valid ||
            !marker.reference.has_value()) {
            continue;
        }
        const auto identifier =
            history_storage::commit_object(layout, *marker.reference);
        if (deletions.contains(identifier)) {
            return std::unexpected(make_error(
                ErrorCode::IntegrityFailure,
                "deletion plan removes a head-selected variant", identifier));
        }
    }
    return {};
}

std::expected<Observation, Error>
observe(transport::Transport& storage,
        KeySpan key,
        const std::filesystem::path& workspace_root) {
    PhaseTraffic analysis_traffic{"gc.analysis_"};
    platform::perf_trace::count("gc.analysis_observations");
    PerfTimer observation_trace{"gc.observation_us"};
    auto listing = [&] {
        PerfTimer trace{"gc.analysis_list_us"};
        return transport::list(storage);
    }();
    if (!listing) {
        return std::unexpected(
            transport_error(listing.error(), "could not list remote objects"));
    }
    std::ranges::sort(*listing);

    const auto layout = history_storage::derive_remote_layout(key);
    platform::perf_trace::count("gc.history_reconstruction_attempts");
    auto history = [&] {
        PerfTimer trace{"gc.history_reconstruction_us"};
        return history_storage::inventory_reachability(
            storage, key, *listing, workspace_root);
    }();
    if (!history) {
        return std::unexpected(history_error(history.error()));
    }
    platform::perf_trace::count("gc.history_reconstructions");
    if (auto valid = validate_history(*history); !valid) {
        return std::unexpected(valid.error());
    }

    auto content = [&] {
        PerfTimer trace{"gc.content_classification_us"};
        return history_storage::inventory_content_reachability(
            storage, key, *listing, *history, workspace_root, false);
    }();
    if (!content) {
        return std::unexpected(history_error(content.error()));
    }
    if (auto valid = validate_content(*content); !valid) {
        return std::unexpected(valid.error());
    }

    std::vector<std::string> orphan_ids = content->orphan_content_ids;
    std::ranges::sort(orphan_ids);
    orphan_ids.erase(std::ranges::unique(orphan_ids).begin(), orphan_ids.end());

    DeletionPlan plan;
    plan.protected_objects = required_variants(*history, layout);
    plan.protected_objects.insert(plan.protected_objects.end(),
                                  content->reachable_content_ids.begin(),
                                  content->reachable_content_ids.end());
    plan.protected_objects.insert(plan.protected_objects.end(),
                                  history->valid_epochs.begin(),
                                  history->valid_epochs.end());
    plan.protected_objects.insert(plan.protected_objects.end(),
                                  history->orphan_epochs.begin(),
                                  history->orphan_epochs.end());
    std::ranges::sort(plan.protected_objects);
    plan.protected_objects.erase(
        std::ranges::unique(plan.protected_objects).begin(),
        plan.protected_objects.end());

    for (const auto& identifier : orphan_ids) {
        plan.candidates.push_back(Candidate{
            .kind = CandidateKind::Content,
            .identifier = identifier,
            .commit_id = {},
        });
    }
    for (const auto& commit : history->commits) {
        if (!commit.reachable) {
            continue;
        }
        for (const auto& variant : commit.variants) {
            if (variant.identifier.empty() ||
                variant.state != history_storage::detail::VariantState::Valid ||
                std::ranges::binary_search(plan.protected_objects,
                                           variant.identifier)) {
                continue;
            }
            plan.candidates.push_back(Candidate{
                .kind = CandidateKind::CommitVariant,
                .identifier = variant.identifier,
                .commit_id = commit.commit_id,
            });
        }
    }
    std::ranges::sort(plan.candidates,
                      [](const auto& left, const auto& right) {
                          return std::tie(left.kind, left.identifier) <
                                 std::tie(right.kind, right.identifier);
                      });
    plan.candidates.erase(
        std::ranges::unique(plan.candidates)
            .begin(),
        plan.candidates.end());

    if (auto valid =
            validate_deletion_plan(plan, *history, orphan_ids, layout);
        !valid) {
        return std::unexpected(valid.error());
    }

    return Observation{
        .logical_heads = std::move(history->logical_heads),
        .reachable_commits = std::move(history->reachable_commits),
        .reachable_content = std::move(content->reachable_content_ids),
        .plan = std::move(plan),
    };
}

std::expected<void, Error>
require_no_writers(transport::Transport& storage,
                   const history_storage::RemoteLayout& layout) {
    platform::perf_trace::count("gc.writer_checks");
    PerfTimer writers_trace{"gc.writer_check_us"};
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
    platform::perf_trace::count("gc.barrier_ownership_checks");
    PerfTimer ownership_trace{"gc.barrier_ownership_check_us"};
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

std::expected<GarbageCollectResult, Error>
garbage_collect_impl(const runtime::RuntimeData& runtime_data,
                     transport::Transport& storage,
                     KeySpan key,
                     GarbageCollectProgressCallback on_progress) {
    GarbageCollectionTrace trace;
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
    platform::perf_trace::count("gc.initial_barrier_presence_checks");
    auto barrier_presence = [&] {
        PerfTimer timer{"gc.initial_barrier_presence_us"};
        return transport::presence(storage, layout.barrier_identifier);
    }();
    if (!barrier_presence) {
        return std::unexpected(transport_error(
            barrier_presence.error(), "could not inspect maintenance barrier"));
    }
    if (*barrier_presence == transport::Presence::Present) {
        return std::unexpected(
            make_error(ErrorCode::ConcurrentChange,
                       "another maintenance barrier is already present"));
    }

    platform::perf_trace::count("gc.barrier_acquisition_attempts");
    auto barrier = [&] {
        PerfTimer timer{"gc.barrier_acquisition_us"};
        return protocol::establish_barrier(storage, layout, workspace_root);
    }();
    if (!barrier) {
        return std::unexpected(protocol_error(barrier.error()));
    }
    BarrierCleanup cleanup{std::move(*barrier)};

    bool candidate_count_known = false;
    const auto finish = [&cleanup,
                         &failure_diagnostic,
                         &trace,
                         &candidate_count_known](
                            std::expected<GarbageCollectResult, Error> outcome)
        -> std::expected<GarbageCollectResult, Error> {
        trace.enter(GarbageCollectStage::Finalizing);
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
        if (candidate_count_known) {
            platform::perf_trace::count("gc.candidate_count",
                                        failure_diagnostic.candidate_objects);
            platform::perf_trace::count("gc.confirmed_removed",
                                        failure_diagnostic.confirmed_removed);
        }
        trace.finish();

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

        platform::perf_trace::count("gc.visibility_probe_attempts");
        auto online = [&] {
            PerfTimer timer{"gc.visibility_probe_us"};
            return protocol::supports_online_collection(
                storage, layout, workspace_root);
        }();
        if (!online) {
            return finish(std::unexpected(protocol_error(online.error())));
        }

        failure_diagnostic.stage = GarbageCollectStage::Analyzing;
        trace.enter(GarbageCollectStage::Analyzing);
        notify(on_progress, GarbageCollectStage::Analyzing, std::nullopt, 0);
        auto snapshot = [&] {
            PerfTimer timer{"gc.first_observation_us"};
            return observe(storage, key, workspace_root);
        }();
        if (!snapshot) {
            return finish(std::unexpected(snapshot.error()));
        }

        const auto candidate_count = snapshot->plan.candidates.size();
        failure_diagnostic.candidate_objects = candidate_count;
        candidate_count_known = true;
        if (platform::perf_trace::enabled()) {
            platform::perf_trace::count(
                "gc.candidate_content_count",
                static_cast<std::uint64_t>(std::ranges::count_if(
                    snapshot->plan.candidates, [](const auto& candidate) {
                        return candidate.kind == CandidateKind::Content;
                    })));
            platform::perf_trace::count(
                "gc.candidate_variant_count",
                static_cast<std::uint64_t>(std::ranges::count_if(
                    snapshot->plan.candidates, [](const auto& candidate) {
                        return candidate.kind == CandidateKind::CommitVariant;
                    })));
        }

        if (!*online) {
            failure_diagnostic.stage = GarbageCollectStage::Finalizing;
            notify(on_progress,
                   GarbageCollectStage::Finalizing,
                   candidate_count,
                   0);
            return finish(GarbageCollectResult{
                .candidate_objects = candidate_count,
                .removed_objects = 0,
                .analysis_only = true,
            });
        }

        failure_diagnostic.stage = GarbageCollectStage::Applying;
        trace.enter(GarbageCollectStage::Applying);
        notify(on_progress, GarbageCollectStage::Applying, candidate_count, 0);
        auto apply = [&]() -> std::expected<std::size_t, Error> {
            PhaseTraffic apply_traffic{"gc.apply_"};
            std::size_t acknowledged_removals = 0;
            for (const auto& candidate : snapshot->plan.candidates) {
                failure_diagnostic.failed_identifier.reset();
                failure_diagnostic.mutation_state =
                    GarbageCollectMutationState::NotAttempted;
                failure_diagnostic.transport_error.reset();

                if (auto cancelled = cancellation_error();
                    cancelled.has_value()) {
                    return std::unexpected(std::move(*cancelled));
                }
                failure_diagnostic.failed_identifier = candidate.identifier;
                platform::perf_trace::count("gc.remove_attempts");
                platform::perf_trace::count("gc.candidate_remove_attempts");
                mutation_in_flight = true;
                auto removed = [&] {
                    PerfTimer timer{"gc.remove_us"};
                    return transport::remove(storage, candidate.identifier);
                }();
                mutation_in_flight = false;
                if (!removed) {
                    failure_diagnostic.mutation_state =
                        transport::mutation_result_is_ambiguous(removed.error())
                            ? GarbageCollectMutationState::Uncertain
                            : GarbageCollectMutationState::NotAttempted;
                    return std::unexpected(transport_error(
                        removed.error(), "object removal failed"));
                }
                // Both outcomes acknowledge the transport-level REMOVE; the
                // collector does not read the object back to prove absence.
                ++acknowledged_removals;
                platform::perf_trace::count("gc.candidate_remove_acknowledged");
                failure_diagnostic.confirmed_removed = acknowledged_removals;
                failure_diagnostic.mutation_state =
                    GarbageCollectMutationState::Confirmed;
                notify(on_progress,
                       GarbageCollectStage::Applying,
                       candidate_count,
                       acknowledged_removals);
            }
            return acknowledged_removals;
        }();
        if (!apply) {
            return finish(std::unexpected(apply.error()));
        }
        const auto removed_objects = *apply;

        failure_diagnostic.stage = GarbageCollectStage::Finalizing;
        trace.enter(GarbageCollectStage::Finalizing);
        failure_diagnostic.failed_identifier.reset();
        failure_diagnostic.transport_error.reset();
        failure_diagnostic.mutation_state =
            removed_objects == 0 ? GarbageCollectMutationState::NotAttempted
                                 : GarbageCollectMutationState::Confirmed;
        notify(on_progress,
               GarbageCollectStage::Finalizing,
               candidate_count,
               removed_objects);

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
