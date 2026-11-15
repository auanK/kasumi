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
#include <unordered_map>
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

std::expected<std::vector<std::string>, Error>
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

    std::vector<std::string> orphan_ids = content->orphan_content_ids;
    std::ranges::sort(orphan_ids);
    orphan_ids.erase(std::ranges::unique(orphan_ids).begin(), orphan_ids.end());

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
    std::ranges::sort(protected_objects);
    protected_objects.erase(std::ranges::unique(protected_objects).begin(),
                            protected_objects.end());

    std::vector<std::string> candidates;
    for (const auto& commit : history->commits) {
        if (!commit.reachable) {
            continue;
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
            candidates.push_back(variant.identifier);
        }
    }
    std::ranges::sort(candidates);
    candidates.erase(std::ranges::unique(candidates).begin(), candidates.end());

    for (const auto& identifier : orphan_ids) {
        if (identifier.empty() ||
            protocol::is_control_object(layout, identifier) ||
            std::ranges::binary_search(protected_objects, identifier)) {
            return std::unexpected(make_error(
                ErrorCode::IntegrityFailure,
                "deletion candidate intersects protected or control objects",
                identifier));
        }
        candidates.push_back(identifier);
    }

    return candidates;
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
        auto observed_candidates = observe(storage, key, workspace_root);
        if (!observed_candidates) {
            return finish(std::unexpected(observed_candidates.error()));
        }

        const auto& candidates = *observed_candidates;
        const auto candidate_count = candidates.size();
        failure_diagnostic.candidate_objects = candidate_count;

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
        notify(on_progress, GarbageCollectStage::Applying, candidate_count, 0);
        auto apply = [&]() -> std::expected<std::size_t, Error> {
            auto verified = require_barrier_ownership(cleanup.registration);
            if (!verified) {
                return std::unexpected(verified.error());
            }
            std::size_t acknowledged_removals = 0;
            bool fallback_sequential =
                (storage.storage.remove_batch == nullptr);

            std::size_t chunk_start = 0;
            const std::size_t total_candidates = candidates.size();

            while (chunk_start < total_candidates) {
                failure_diagnostic.failed_identifier.reset();
                failure_diagnostic.mutation_state =
                    GarbageCollectMutationState::NotAttempted;
                failure_diagnostic.transport_error.reset();

                if (auto cancelled = cancellation_error();
                    cancelled.has_value()) {
                    return std::unexpected(std::move(*cancelled));
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

                        failure_diagnostic.failed_identifier.reset();
                        failure_diagnostic.transport_error = err;
                        failure_diagnostic.mutation_state =
                            GarbageCollectMutationState::Uncertain;
                        return std::unexpected(transport_error(
                            err, "batch object removal failed"));
                    }

                    const auto& report = *batch_result;
                    bool report_valid = (report.items.size() == chunk_size);
                    std::unordered_map<std::string_view,
                                       const transport::RemoveBatchItemResult*>
                        result_by_id;
                    if (report_valid) {
                        result_by_id.reserve(chunk_size);
                        for (const auto& item_result : report.items) {
                            if (!result_by_id
                                     .emplace(item_result.identifier,
                                              &item_result)
                                     .second) {
                                report_valid = false;
                                break;
                            }
                        }
                        if (report_valid) {
                            for (std::size_t i = 0; i < chunk_size; ++i) {
                                if (!result_by_id.contains(
                                        candidates[chunk_start + i])) {
                                    report_valid = false;
                                    break;
                                }
                            }
                        }
                    }

                    if (!report_valid) {
                        failure_diagnostic.failed_identifier.reset();
                        failure_diagnostic.transport_error = transport::Error{
                            .code = transport::ErrorCode::ProtocolFailure,
                            .message =
                                "invalid or incomplete remove batch report",
                        };
                        failure_diagnostic.mutation_state =
                            GarbageCollectMutationState::Uncertain;
                        return std::unexpected(
                            transport_error(*failure_diagnostic.transport_error,
                                            "invalid remove batch report"));
                    }

                    std::size_t batch_acknowledged = 0;
                    std::size_t batch_errors = 0;
                    const transport::RemoveBatchItemResult* first_failure =
                        nullptr;
                    std::string first_failed_identifier;

                    for (std::size_t i = 0; i < chunk_size; ++i) {
                        const auto& cand_id = candidates[chunk_start + i];
                        const auto* res = result_by_id.at(cand_id);
                        if (res->result.has_value()) {
                            ++batch_acknowledged;
                        } else {
                            ++batch_errors;
                            if (first_failure == nullptr) {
                                first_failure = res;
                                first_failed_identifier = cand_id;
                            }
                        }
                    }

                    acknowledged_removals += batch_acknowledged;
                    if (batch_acknowledged > 0) {
                        failure_diagnostic.confirmed_removed =
                            acknowledged_removals;
                        failure_diagnostic.mutation_state =
                            GarbageCollectMutationState::Confirmed;
                        notify(on_progress,
                               GarbageCollectStage::Applying,
                               candidate_count,
                               acknowledged_removals);
                    }

                    if (batch_errors > 0) {
                        failure_diagnostic.failed_identifier =
                            first_failed_identifier;
                        failure_diagnostic.transport_error =
                            first_failure->result.error();
                        failure_diagnostic.mutation_state =
                            GarbageCollectMutationState::Uncertain;
                        return std::unexpected(
                            transport_error(first_failure->result.error(),
                                            "object removal failed"));
                    }

                    chunk_start += chunk_size;
                } else {
                    const auto& candidate = candidates[chunk_start];
                    failure_diagnostic.failed_identifier = candidate;
                    mutation_in_flight = true;
                    auto removed = transport::remove(storage, candidate);
                    mutation_in_flight = false;
                    if (!removed) {
                        failure_diagnostic.mutation_state =
                            GarbageCollectMutationState::Uncertain;
                        return std::unexpected(transport_error(
                            removed.error(), "object removal failed"));
                    }

                    ++acknowledged_removals;
                    failure_diagnostic.confirmed_removed =
                        acknowledged_removals;
                    failure_diagnostic.mutation_state =
                        GarbageCollectMutationState::Confirmed;
                    notify(on_progress,
                           GarbageCollectStage::Applying,
                           candidate_count,
                           acknowledged_removals);
                    ++chunk_start;
                }
            }
            return acknowledged_removals;
        }();
        if (!apply) {
            return finish(std::unexpected(apply.error()));
        }
        const auto removed_objects = *apply;

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
