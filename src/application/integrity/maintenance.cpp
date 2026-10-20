#include "application/integrity/maintenance.hpp"

#include "application/history_storage/content_reachability.hpp"
#include "application/history_storage/detail.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/fsck_checkpoint.hpp"
#include "application/integrity/maintenance_test.hpp"
#include "application/observation/state.hpp"
#include "core/maintenance.hpp"
#include "crypto/content.hpp"
#include "crypto/physical_hash.hpp"
#include "platform/cancellation.hpp"
#include "platform/clock.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "platform/workspace.hpp"

#include <algorithm>
#include <condition_variable>
#include <exception>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <limits>
#include <mutex>
#include <optional>
#include <ranges>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace kasumi::application::integrity {

namespace {

using KeySpan = std::span<const std::uint8_t, crypto::KEY_SIZE>;

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
    ~TraceGuard() noexcept {
        stop();
    }
};

struct SnapshotTraceNames {
    std::string_view physical_listing;
    std::string_view history_reconstruction;
    std::string_view history_validation;
    std::string_view content_reachability;
    std::string_view candidate_selection;
    std::string_view history_scope;
};

constexpr SnapshotTraceNames analysis_snapshot_traces{
    "gc.snapshot.analysis.physical_listing_us",
    "gc.snapshot.analysis.history_reconstruction_us",
    "gc.snapshot.analysis.validate_history_us",
    "gc.snapshot.analysis.content_reachability_us",
    "gc.snapshot.analysis.candidate_selection_us",
    "gc.snapshot.analysis"};
constexpr SnapshotTraceNames first_snapshot_traces{
    "gc.snapshot.first.physical_listing_us",
    "gc.snapshot.first.history_reconstruction_us",
    "gc.snapshot.first.validate_history_us",
    "gc.snapshot.first.content_reachability_us",
    "gc.snapshot.first.candidate_selection_us",
    "gc.snapshot.first"};
constexpr SnapshotTraceNames second_snapshot_traces{
    "gc.snapshot.second.physical_listing_us",
    "gc.snapshot.second.history_reconstruction_us",
    "gc.snapshot.second.validate_history_us",
    "gc.snapshot.second.content_reachability_us",
    "gc.snapshot.second.candidate_selection_us",
    "gc.snapshot.second"};

enum class AuditState {
    Healthy,
    Missing,
    Corrupt
};

struct GarbageCollectionSnapshot {
    std::vector<std::string> logical_heads;
    std::vector<std::string> reachable_commits;
    std::vector<std::string> required_commit_objects;
    std::vector<std::string> reachable_content;
    std::vector<std::string> candidates;
    std::vector<std::string> physical_namespace;
};

Error make_error(ErrorCode code,
                 std::string detail,
                 std::optional<std::string> object = std::nullopt) {
    return Error{
        .code = code,
        .detail = std::move(detail),
        .object_identifier = std::move(object),
    };
}

Error transport_error(const transport::Error& error,
                      std::string identifier = {}) {
    return make_error(ErrorCode::TransportFailure,
                      transport::describe(error),
                      identifier.empty()
                          ? std::nullopt
                          : std::optional<std::string>{std::move(identifier)});
}

Error history_storage_error(const history_storage::Error& error) {
    ErrorCode code = ErrorCode::IntegrityFailure;
    switch (error.code) {
        case history_storage::ErrorCode::TransportFailure:
            code = ErrorCode::TransportFailure;
            break;
        case history_storage::ErrorCode::WorkspaceFailure:
            code = ErrorCode::WorkspaceFailure;
            break;
        case history_storage::ErrorCode::CryptoFailure:
            code = ErrorCode::CryptoFailure;
            break;
        default:
            break;
    }
    return make_error(code, error.detail);
}

bool not_found(const std::error_code& error) noexcept {
    return error == std::errc::no_such_file_or_directory;
}

std::vector<std::string>
physical_identifiers(const reconciliation::StorageState& state) {
    return {state.object_identifiers.begin(), state.object_identifiers.end()};
}

std::expected<kasumi::maintenance::Inventory, Error>
analyze_inventory(const Snapshot& history_tree,
                  const Snapshot& local_tree,
                  const reconciliation::StorageState& storage_state) {
    auto physical = physical_identifiers(storage_state);
    auto analyzed = kasumi::maintenance::analyze(
        history_tree, local_tree, std::span<const std::string>{physical});
    if (!analyzed) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure, analyzed.error().detail));
    }
    return std::move(*analyzed);
}

std::string list_detail(std::string_view prefix,
                        const std::vector<std::string>& values) {
    constexpr std::size_t limit = 20;
    const auto displayed = std::min(values.size(), limit);
    std::string result{prefix};
    for (std::size_t index = 0; index < displayed; ++index) {
        result += index == 0 ? "" : ", ";
        result += values[index];
    }
    if (values.size() > limit) {
        result += "; and ";
        result += std::to_string(values.size() - limit);
        result += " more";
    }
    return result;
}

std::string path_detail(const std::vector<std::filesystem::path>& paths) {
    constexpr std::size_t limit = 20;
    const auto displayed = std::min(paths.size(), limit);
    std::string result = "referenced objects missing or corrupted; fsck repair "
                         "unavailable at this stage (paths: ";
    for (std::size_t index = 0; index < displayed; ++index) {
        if (index != 0) {
            result += ", ";
        }
        result += platform::path::to_utf8(paths[index]);
    }
    if (paths.size() > limit) {
        result += "; and ";
        result += std::to_string(paths.size() - limit);
        result += " more";
    }
    result += ')';
    return result;
}

std::filesystem::path
maintenance_workspace_root(const runtime::RuntimeData& runtime_data) {
    auto root = runtime_data.database_path.parent_path();
    std::error_code error;
    if (root.empty() || !std::filesystem::exists(root, error)) {
        root = runtime_data.local_dir.parent_path();
    }
    return root;
}

std::expected<void, Error> validate_history_inventory(
    const history_storage::ReachabilityInventory& inventory) {
    if (inventory.logical_heads.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure, "remote history absent"));
    }
    if (!inventory.unknown_history_objects.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("unknown history objects: ",
                                   inventory.unknown_history_objects)));
    }
    if (!inventory.missing_parent_ids.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("commits pais ausentes: ",
                                   inventory.missing_parent_ids)));
    }
    if (!inventory.invalid_parent_ids.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("invalid parent commits: ",
                                   inventory.invalid_parent_ids)));
    }

    std::vector<std::string> invalid_markers;
    for (const auto& marker : inventory.markers) {
        if (marker.state != history_storage::ReachabilityMarkerState::Valid) {
            invalid_markers.push_back(marker.identifier);
        }
    }
    if (!invalid_markers.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("invalid or unstable head markers: ",
                                   invalid_markers)));
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
                       list_detail("invalid commits: ", invalid_commits)));
    }
    return {};
}

std::expected<void, Error> validate_content_inventory(
    const history_storage::ContentReachabilityInventory& inventory) {
    if (!inventory.unknown_storage_objects.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("unknown physical identifiers: ",
                                   inventory.unknown_storage_objects)));
    }

    std::vector<std::string> damaged;
    for (const auto& content : inventory.contents) {
        if (content.reachable &&
            content.state != history_storage::ContentObjectState::Present) {
            damaged.push_back(content.content_id);
        }
    }
    if (!damaged.empty()) {
        return std::unexpected(make_error(
            ErrorCode::IntegrityFailure,
            list_detail("reachable contents missing or corrupted: ", damaged)));
    }
    return {};
}

std::expected<GarbageCollectionSnapshot, Error>
collect_garbage_collection_snapshot(transport::Transport& storage,
                                    KeySpan key,
                                    const std::filesystem::path& workspace_root,
                                    const SnapshotTraceNames& traces) {
    TraceGuard list_guard{traces.physical_listing,
                          platform::perf_trace::begin()};
    auto listing = transport::list(storage);
    if (!listing) {
        return std::unexpected(transport_error(listing.error()));
    }
    std::ranges::sort(*listing);
    list_guard.stop();

    TraceGuard history_guard{traces.history_reconstruction,
                             platform::perf_trace::begin()};
    auto history = history_storage::inventory_reachability(
        storage,
        key,
        *listing,
        workspace_root,
        platform::perf_trace::enabled() ? traces.history_scope
                                        : std::string_view{});
    if (!history) {
        return std::unexpected(history_storage_error(history.error()));
    }
    history_guard.stop();
    TraceGuard val_hist_guard{traces.history_validation,
                              platform::perf_trace::begin()};
    if (auto valid = validate_history_inventory(*history); !valid) {
        return std::unexpected(valid.error());
    }
    val_hist_guard.stop();

    TraceGuard content_guard{traces.content_reachability,
                             platform::perf_trace::begin()};
    auto content = history_storage::inventory_content_reachability(
        storage, key, *listing, *history, workspace_root, false);
    if (!content) {
        return std::unexpected(history_storage_error(content.error()));
    }
    content_guard.stop();

    TraceGuard cand_guard{traces.candidate_selection,
                          platform::perf_trace::begin()};
    if (auto valid = validate_content_inventory(*content); !valid) {
        return std::unexpected(valid.error());
    }

    GarbageCollectionSnapshot result{
        .logical_heads = history->logical_heads,
        .reachable_commits = history->reachable_commits,
        .required_commit_objects = {},
        .reachable_content = content->reachable_content_ids,
        .candidates = {},
        .physical_namespace = std::move(*listing),
    };

    const auto layout = history_storage::derive_remote_layout(key);
    std::vector<std::string> marked_commits;
    for (const auto& marker : history->markers) {
        if (marker.state != history_storage::ReachabilityMarkerState::Valid ||
            !marker.reference) {
            continue;
        }
        marked_commits.push_back(marker.reference->commit_id);
        result.required_commit_objects.push_back(
            history_storage::commit_object(layout, *marker.reference));
    }
    std::ranges::sort(marked_commits);
    marked_commits.erase(std::ranges::unique(marked_commits).begin(),
                         marked_commits.end());

    for (const auto& commit : history->commits) {
        if (!commit.reachable ||
            std::ranges::binary_search(marked_commits, commit.commit_id)) {
            continue;
        }
        const auto variant =
            std::ranges::find_if(commit.variants, [](const auto& candidate) {
                return !candidate.identifier.empty() &&
                       candidate.state ==
                           history_storage::detail::VariantState::Valid;
            });
        if (variant != commit.variants.end()) {
            result.required_commit_objects.push_back(variant->identifier);
        }
    }
    std::ranges::sort(result.required_commit_objects);
    result.required_commit_objects.erase(
        std::ranges::unique(result.required_commit_objects).begin(),
        result.required_commit_objects.end());

    for (const auto& commit : history->commits) {
        for (const auto& variant : commit.variants) {
            if (!variant.identifier.empty() &&
                !std::ranges::binary_search(result.required_commit_objects,
                                            variant.identifier)) {
                result.candidates.push_back(variant.identifier);
            }
        }
    }
    std::ranges::sort(result.candidates);
    result.candidates.erase(std::ranges::unique(result.candidates).begin(),
                            result.candidates.end());
    result.candidates.insert(result.candidates.end(),
                             content->orphan_content_ids.begin(),
                             content->orphan_content_ids.end());
    std::ranges::sort(result.candidates);
    result.candidates.erase(std::ranges::unique(result.candidates).begin(),
                            result.candidates.end());
    return result;
}

bool same_reachable_state(const GarbageCollectionSnapshot& left,
                          const GarbageCollectionSnapshot& right) noexcept {
    return left.logical_heads == right.logical_heads &&
           left.reachable_commits == right.reachable_commits &&
           left.required_commit_objects == right.required_commit_objects &&
           left.reachable_content == right.reachable_content &&
           left.candidates == right.candidates &&
           left.physical_namespace == right.physical_namespace;
}

std::expected<void, Error>
prepare_workspace_file(const std::filesystem::path& path) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (not_found(error) ||
        status.type() == std::filesystem::file_type::not_found) {
        return {};
    }
    if (error) {
        return std::unexpected(
            make_error(ErrorCode::WorkspaceFailure,
                       "could not inspect temporary file: " + error.message()));
    }
    if (std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        return std::unexpected(make_error(ErrorCode::WorkspaceFailure,
                                          "temporary file has invalid type"));
    }
    std::filesystem::remove(path, error);
    if (error) {
        return std::unexpected(
            make_error(ErrorCode::WorkspaceFailure,
                       "could not clean temporary file: " + error.message()));
    }
    return {};
}

std::expected<void, Error>
require_regular_file(const std::filesystem::path& path,
                     ErrorCode failure_code,
                     std::string detail) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error) {
        return std::unexpected(make_error(
            failure_code, std::move(detail) + ": " + error.message()));
    }
    if (status.type() == std::filesystem::file_type::not_found ||
        std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        return std::unexpected(make_error(failure_code, std::move(detail)));
    }
    return {};
}

std::expected<void, Error>
remove_temporary_file(const std::filesystem::path& path) {
    std::error_code error;
    std::filesystem::remove(path, error);
    if (error) {
        return std::unexpected(
            make_error(ErrorCode::WorkspaceFailure,
                       "failed to remove temporary file: " + error.message()));
    }
    return {};
}

std::expected<void, Error> verify_content(const std::filesystem::path& path,
                                          std::string_view identifier,
                                          std::uint64_t expected_size,
                                          ErrorCode io_failure) {
    auto regular = require_regular_file(
        path, io_failure, "file is not regular for verification");
    if (!regular) {
        return regular;
    }
    std::error_code error;
    const auto actual_size = std::filesystem::file_size(path, error);
    if (error) {
        return std::unexpected(make_error(
            io_failure, "could not read file size: " + error.message()));
    }
    if (actual_size != expected_size) {
        return std::unexpected(make_error(
            ErrorCode::IntegrityFailure, "object size does not match history"));
    }
    auto actual_hash = crypto::content::hash_file(path);
    if (!actual_hash) {
        return std::unexpected(make_error(io_failure, actual_hash.error()));
    }
    if (hash_hex(*actual_hash) != identifier) {
        return std::unexpected(make_error(
            ErrorCode::IntegrityFailure, "object hash does not match history"));
    }
    return {};
}

struct AuditObjectResult {
    AuditState state = AuditState::Healthy;
    std::string remote_content_id;
    std::string physical_sha256;
};

std::expected<AuditObjectResult, Error>
audit_object(transport::Transport& storage,
             KeySpan key,
             const kasumi::maintenance::ObjectReference& reference,
             const platform::Workspace& workspace,
             std::size_t index) {
    platform::perf_trace::count("fsck.audit_objects");
    const auto plaintext_hash = hash_from_hex(reference.identifier);
    if (!plaintext_hash) {
        return std::unexpected(make_error(ErrorCode::IntegrityFailure,
                                          "invalid content identifier"));
    }
    const auto remote_identifier =
        crypto::content_identifier(key, *plaintext_hash);
    const auto encrypted =
        platform::workspace_file(workspace, index, ".audit.enc");
    const auto plaintext =
        platform::workspace_file(workspace, index, ".audit.plain");
    auto prepared = prepare_workspace_file(encrypted);
    if (!prepared)
        return std::unexpected(prepared.error());
    prepared = prepare_workspace_file(plaintext);
    if (!prepared)
        return std::unexpected(prepared.error());

    platform::perf_trace::count("fsck.audit_get_calls");
    const auto get_token = platform::perf_trace::begin();
    auto downloaded = transport::get(storage, remote_identifier, encrypted);
    platform::perf_trace::finish("fsck.audit_get_duration_us", get_token);
    if (!downloaded) {
        auto removed = remove_temporary_file(encrypted);
        if (!removed)
            return std::unexpected(removed.error());
        removed = remove_temporary_file(plaintext);
        if (!removed)
            return std::unexpected(removed.error());
        if (downloaded.error().code == transport::ErrorCode::ObjectNotFound) {
            return AuditObjectResult{.state = AuditState::Missing};
        }
        return std::unexpected(
            transport_error(downloaded.error(), reference.identifier));
    }

    std::error_code enc_size_error;
    const auto enc_size = std::filesystem::file_size(encrypted, enc_size_error);
    if (!enc_size_error) {
        platform::perf_trace::count("fsck.encrypted_bytes_downloaded",
                                    enc_size);
    }

    auto regular = require_regular_file(
        encrypted, ErrorCode::WorkspaceFailure, "invalid temporary download");
    if (!regular)
        return std::unexpected(regular.error());

    AuditState result = AuditState::Healthy;
    platform::perf_trace::count("fsck.audit_decrypt_calls");
    const auto decrypt_token = platform::perf_trace::begin();
    const bool decrypted = crypto::decrypt_file(encrypted, plaintext, key);
    platform::perf_trace::finish("fsck.audit_decrypt_duration_us",
                                 decrypt_token);
    if (!decrypted) {
        result = AuditState::Corrupt;
    } else {
        std::error_code plain_size_error;
        const auto plain_size =
            std::filesystem::file_size(plaintext, plain_size_error);
        if (!plain_size_error) {
            platform::perf_trace::count("fsck.plaintext_bytes_verified",
                                        plain_size);
        }
        platform::perf_trace::count("fsck.audit_verify_calls");
        const auto verify_token = platform::perf_trace::begin();
        auto verified = verify_content(plaintext,
                                       reference.identifier,
                                       reference.size,
                                       ErrorCode::WorkspaceFailure);
        platform::perf_trace::finish("fsck.audit_verify_duration_us",
                                     verify_token);
        if (!verified) {
            if (verified.error().code != ErrorCode::IntegrityFailure) {
                return std::unexpected(verified.error());
            }
            result = AuditState::Corrupt;
        }
    }

    std::string physical_sha256;
    if (result == AuditState::Healthy) {
        auto hash_res = crypto::physical::hash_file(encrypted, "sha256");
        if (hash_res) {
            physical_sha256 = std::move(*hash_res);
        }
    }

    auto removed = remove_temporary_file(encrypted);
    if (!removed)
        return std::unexpected(removed.error());
    removed = remove_temporary_file(plaintext);
    if (!removed)
        return std::unexpected(removed.error());
    return AuditObjectResult{.state = result,
                             .remote_content_id = remote_identifier,
                             .physical_sha256 = std::move(physical_sha256)};
}

struct AuditWorkResult {
    enum class Disposition {
        Completed,
        HardFailure,
        AbortedByWindowStop,
        UserCancelled
    };

    std::size_t index = 0;
    Disposition disposition = Disposition::Completed;
    AuditState state = AuditState::Healthy;
    std::optional<Error> error;
    std::string remote_content_id;
    std::string physical_sha256;
};

struct AuditWindowState {
    std::mutex mutex;
    std::condition_variable_any changed;
    std::vector<std::optional<std::size_t>> tasks;
    std::vector<std::optional<AuditWorkResult>> completions;
    std::size_t in_flight = 0;
    std::size_t peak_in_flight = 0;
    bool stop_requested = false;
};

void run_audit_worker(
    std::stop_token stop,
    std::size_t slot,
    AuditWindowState& state,
    transport::Transport& storage,
    KeySpan key,
    const std::vector<kasumi::maintenance::ObjectReference>& references,
    const platform::Workspace& workspace,
    const testing::FsckWorkerEventCallback& on_worker_event) {
    while (true) {
        std::size_t index = 0;
        {
            std::unique_lock lock(state.mutex);
            state.changed.wait(lock, [&] {
                return state.tasks[slot].has_value() || state.stop_requested ||
                       stop.stop_requested();
            });
            if (!state.tasks[slot].has_value()) {
                return;
            }
            index = *state.tasks[slot];
            state.tasks[slot].reset();
            ++state.in_flight;
            state.peak_in_flight =
                std::max(state.peak_in_flight, state.in_flight);
        }

        AuditWorkResult result{.index = index};
        try {
            if (on_worker_event) {
                try {
                    on_worker_event(testing::FsckWorkerEvent::BeforeAudit,
                                    index);
                } catch (...) {
                    // Test observation cannot alter the audit result.
                }
            }
            bool window_stop_requested = false;
            {
                std::lock_guard lock(state.mutex);
                window_stop_requested =
                    state.stop_requested || stop.stop_requested();
            }
            if (platform::cancellation::requested()) {
                result.disposition =
                    AuditWorkResult::Disposition::UserCancelled;
            } else if (window_stop_requested) {
                result.disposition =
                    AuditWorkResult::Disposition::AbortedByWindowStop;
            } else {
                auto audited = audit_object(
                    storage, key, references[index], workspace, index);
                if (!audited) {
                    result.disposition =
                        AuditWorkResult::Disposition::HardFailure;
                    result.error = audited.error();
                } else {
                    result.state = audited->state;
                    result.remote_content_id =
                        std::move(audited->remote_content_id);
                    result.physical_sha256 =
                        std::move(audited->physical_sha256);
                }
            }
        } catch (const std::exception& exception) {
            result.disposition = AuditWorkResult::Disposition::HardFailure;
            result.error =
                make_error(ErrorCode::StateFailure, exception.what());
        } catch (...) {
            result.disposition = AuditWorkResult::Disposition::HardFailure;
            result.error =
                make_error(ErrorCode::StateFailure, "audit worker failed");
        }

        {
            std::lock_guard lock(state.mutex);
            --state.in_flight;
            state.completions[slot] = std::move(result);
        }
        state.changed.notify_all();
    }
}

} // namespace

std::string describe(const Error& error) {
    std::string result;
    switch (error.code) {
        case ErrorCode::InvalidInput:
            result = "invalid_input";
            break;
        case ErrorCode::StateFailure:
            result = "state_failure";
            break;
        case ErrorCode::WorkspaceFailure:
            result = "workspace_failure";
            break;
        case ErrorCode::TransportFailure:
            result = "transport_failure";
            break;
        case ErrorCode::CryptoFailure:
            result = "crypto_failure";
            break;
        case ErrorCode::IntegrityFailure:
            result = "integrity_failure";
            break;
        case ErrorCode::Unrecoverable:
            result = "unrecoverable";
            break;
        case ErrorCode::ConcurrentChange:
            result = "concurrent_change";
            break;
    }
    if (error.object_identifier) {
        result += " no objeto ";
        result += *error.object_identifier;
    }
    if (!error.detail.empty()) {
        result += ": ";
        result += error.detail;
    }
    return result;
}

namespace {

std::expected<FsckResult, Error>
fsck_impl(const runtime::RuntimeData& runtime_data,
          transport::Transport& storage,
          KeySpan key,
          std::size_t audit_concurrency,
          FsckProgressCallback on_progress,
          const testing::FsckWorkerEventCallback& on_worker_event) {
    std::size_t completed_objects = 0;
    std::optional<std::size_t> progress_total_objects;
    std::optional<std::uint64_t> completed_plaintext_bytes =
        on_progress ? std::optional<std::uint64_t>{0} : std::nullopt;
    std::optional<std::uint64_t> total_plaintext_bytes;
    const auto report_progress = [&](application::FsckStage stage) noexcept {
        if (!on_progress) {
            return;
        }
        try {
            on_progress(application::FsckProgress{
                .stage = stage,
                .completed_objects = completed_objects,
                .total_objects = progress_total_objects,
                .completed_plaintext_bytes = completed_plaintext_bytes,
                .total_plaintext_bytes = total_plaintext_bytes,
            });
        } catch (...) {
            // Progress is observational and must not alter the audit result.
        }
    };
    TraceGuard total_guard{"fsck.total_duration_us",
                           platform::perf_trace::begin()};
    if (runtime_data.local_dir.empty() || !transport::valid(storage)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidInput, "invalid fsck context"));
    }
    report_progress(application::FsckStage::Observing);
    const auto history_workspace = maintenance_workspace_root(runtime_data);
    auto observation = [&]() {
        TraceGuard guard{"fsck.collect_storage_state_duration_us",
                         platform::perf_trace::begin()};
        return observation::collect_storage_observation(
            storage, key, history_workspace, true);
    }();
    if (!observation) {
        return std::unexpected(
            make_error(ErrorCode::StateFailure, observation.error()));
    }
    report_progress(application::FsckStage::Analyzing);
    const auto& storage_state = observation->state;
    if (!storage_state.history_present) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure, "remote history absent"));
    }
    const auto layout = history_storage::derive_remote_layout(key);
    std::vector<std::string> unknown_storage_identifiers;
    for (const auto& identifier : observation->physical_identifiers) {
        if (history_storage::is_history_object(layout, identifier) ||
            kasumi::hash_from_hex(identifier).has_value()) {
            continue;
        }
        unknown_storage_identifiers.push_back(identifier);
    }
    if (!unknown_storage_identifiers.empty()) {
        std::ranges::sort(unknown_storage_identifiers);
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("unknown physical identifiers: ",
                                   unknown_storage_identifiers)));
    }
    auto local_tree = [&]() {
        TraceGuard guard{"fsck.local_tree_duration_us",
                         platform::perf_trace::begin()};
        return observation::collect_local_tree(runtime_data.local_dir);
    }();
    if (!local_tree) {
        return std::unexpected(
            make_error(ErrorCode::StateFailure, local_tree.error()));
    }
    auto inventory = [&]() {
        TraceGuard guard{"fsck.inventory_analysis_duration_us",
                         platform::perf_trace::begin()};
        return analyze_inventory(
            storage_state.tree, *local_tree, storage_state);
    }();
    if (!inventory)
        return std::unexpected(inventory.error());
    if (!inventory->unknown_identifiers.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("unknown physical identifiers: ",
                                   inventory->unknown_identifiers)));
    }

    if (on_progress) {
        progress_total_objects = inventory->referenced_objects.size();
        total_plaintext_bytes = 0;
        for (const auto& reference : inventory->referenced_objects) {
            if (reference.size > std::numeric_limits<std::uint64_t>::max() -
                                     *total_plaintext_bytes) {
                total_plaintext_bytes.reset();
                break;
            }
            *total_plaintext_bytes += reference.size;
        }
    }

    const auto ws_token = platform::perf_trace::begin();
    auto workspace = platform::create_workspace("fsck");
    platform::perf_trace::finish("fsck.workspace_duration_us", ws_token);
    if (!workspace) {
        return std::unexpected(
            make_error(ErrorCode::WorkspaceFailure, workspace.error()));
    }
    auto result = [&]() -> std::expected<FsckResult, Error> {
        TraceGuard referenced_guard{"fsck.referenced_audit_duration_us",
                                    platform::perf_trace::begin()};
        try {
            const auto total_objects = inventory->referenced_objects.size();
            if (on_progress) {
                report_progress(application::FsckStage::AuditingContent);
            }
            FsckResult fsck_result{
                .checked_objects = total_objects,
            };

            const auto effective_concurrency =
                std::max<std::size_t>(1, audit_concurrency);
            const auto worker_count =
                std::min<std::size_t>(effective_concurrency, total_objects);

            platform::perf_trace::count("fsck.audit_configured_concurrency",
                                        effective_concurrency);
            platform::perf_trace::count("fsck.audit_worker_count",
                                        worker_count);

            if (total_objects == 0) {
                platform::perf_trace::count("fsck.audit_peak_in_flight", 0);
                report_progress(application::FsckStage::Finalizing);
                return fsck_result;
            }

            const auto determine_vault_identity =
                [](const reconciliation::StorageState& state) -> std::string {
                if (!state.epoch_vault_id.empty()) {
                    return state.epoch_vault_id;
                }
                if (!state.reachable_commit_ids.empty()) {
                    return "genesis:" + state.reachable_commit_ids.front();
                }
                return {};
            };

            const auto profile_dir = runtime_data.database_path.parent_path();
            const auto vault_identity = determine_vault_identity(storage_state);
            std::optional<FsckCheckpoint> loaded_checkpoint;
            if (!profile_dir.empty() && !vault_identity.empty()) {
                const auto checkpoint_load_trace =
                    platform::perf_trace::begin();
                auto loaded = load_checkpoint(profile_dir, key);
                platform::perf_trace::finish("fsck.checkpoint_load_wall_us",
                                             checkpoint_load_trace);
                if (loaded && loaded->has_value()) {
                    if ((*loaded)->header.vault_id != vault_identity) {
                        platform::perf_trace::count(
                            "fsck.checkpoint_vault_mismatch");
                        platform::perf_trace::count("fsck.checkpoint_rejected");
                    } else {
                        loaded_checkpoint = std::move(*loaded);
                    }
                }
            }

            std::unordered_map<std::string, const VerifiedObjectEntry*>
                candidate_entries;
            if (loaded_checkpoint) {
                for (const auto& entry : loaded_checkpoint->entries) {
                    candidate_entries[entry.logical_content_hash] = &entry;
                }
            }

            for (const auto& ref : inventory->referenced_objects) {
                const auto p_hash = hash_from_hex(ref.identifier);
                if (!p_hash) {
                    continue;
                }
                const auto remote_id = crypto::content_identifier(key, *p_hash);
                auto it = candidate_entries.find(ref.identifier);
                if (it != candidate_entries.end() &&
                    it->second->remote_content_id == remote_id &&
                    it->second->plaintext_size == ref.size) {
                    platform::perf_trace::count("fsck.resume_candidates");
                    if (storage.storage.physical_hash != nullptr) {
                        platform::perf_trace::count(
                            "fsck.resume_physical_hash_checks");
                        auto hash_res = storage.storage.physical_hash(
                            storage.state.get(), remote_id, "sha256");
                        if (!hash_res) {
                            if (hash_res.error().code ==
                                transport::ErrorCode::Unsupported) {
                                platform::perf_trace::count(
                                    "fsck.resume_hash_unsupported");
                            } else {
                                platform::perf_trace::count(
                                    "fsck.resume_hash_errors");
                            }
                            platform::perf_trace::count(
                                "fsck.resume_full_audit_fallbacks");
                        } else if (*hash_res !=
                                   it->second->physical_ciphertext_sha256) {
                            platform::perf_trace::count(
                                "fsck.resume_hash_mismatches");
                            platform::perf_trace::count(
                                "fsck.resume_full_audit_fallbacks");
                        } else {
                            // Under Threat A (untrusted remote storage),
                            // unauthenticated provider hash cannot eliminate
                            // cryptographic verification of bytes. Fail-closed
                            // fall back to full audit.
                            platform::perf_trace::count(
                                "fsck.resume_full_audit_fallbacks");
                        }
                    } else {
                        platform::perf_trace::count(
                            "fsck.resume_hash_unsupported");
                        platform::perf_trace::count(
                            "fsck.resume_full_audit_fallbacks");
                    }
                }
            }

            AuditWindowState state;
            state.tasks.resize(worker_count);
            state.completions.resize(worker_count);

            std::vector<std::jthread> workers;
            workers.reserve(worker_count);
            for (std::size_t slot = 0; slot < worker_count; ++slot) {
                workers.emplace_back(run_audit_worker,
                                     slot,
                                     std::ref(state),
                                     std::ref(storage),
                                     key,
                                     std::cref(inventory->referenced_objects),
                                     std::cref(*workspace),
                                     std::cref(on_worker_event));
            }

            std::size_t next = 0;
            std::size_t outstanding = 0;
            const auto admit = [&](std::size_t slot) {
                {
                    std::lock_guard lock(state.mutex);
                    state.tasks[slot] = next++;
                    ++outstanding;
                }
                state.changed.notify_all();
            };

            for (std::size_t slot = 0; slot < worker_count; ++slot) {
                admit(slot);
            }

            std::optional<std::pair<std::size_t, Error>> lowest_hard_failure;
            std::vector<std::filesystem::path> unrecoverable;
            std::map<std::string, VerifiedObjectEntry> verified_map;
            std::size_t unpersisted_verified = 0;
            bool cancelled = false;
            bool stop_event_notified = false;
            const auto request_window_stop = [&] {
                {
                    std::lock_guard lock(state.mutex);
                    state.stop_requested = true;
                }
                state.changed.notify_all();
                for (auto& worker : workers) {
                    worker.request_stop();
                }
                if (!stop_event_notified) {
                    stop_event_notified = true;
                    if (on_worker_event) {
                        try {
                            on_worker_event(
                                testing::FsckWorkerEvent::WindowStopRequested,
                                0);
                        } catch (...) {
                            // Test observation cannot alter the audit result.
                        }
                    }
                }
            };

            while (outstanding != 0) {
                std::size_t slot = 0;
                AuditWorkResult work_result;
                {
                    std::unique_lock lock(state.mutex);
                    state.changed.wait(lock, [&] {
                        return std::ranges::any_of(state.completions,
                                                   [](const auto& item) {
                                                       return item.has_value();
                                                   });
                    });
                    auto it = std::ranges::find_if(state.completions,
                                                   [](const auto& item) {
                                                       return item.has_value();
                                                   });
                    slot = static_cast<std::size_t>(it -
                                                    state.completions.begin());
                    work_result = std::move(**it);
                    it->reset();
                }
                --outstanding;
                platform::perf_trace::count("fsck.audit_completion_count");
                bool object_classified = false;
                std::uint64_t classified_size = 0;

                if (platform::cancellation::requested()) {
                    cancelled = true;
                    request_window_stop();
                }

                using Disposition = AuditWorkResult::Disposition;
                if (work_result.disposition == Disposition::HardFailure) {
                    if (work_result.error &&
                        (!lowest_hard_failure ||
                         work_result.index < lowest_hard_failure->first)) {
                        lowest_hard_failure = std::pair{
                            work_result.index, std::move(*work_result.error)};
                    }
                    request_window_stop();
                } else if (work_result.disposition ==
                           Disposition::UserCancelled) {
                    cancelled = true;
                    request_window_stop();
                } else if (work_result.disposition == Disposition::Completed) {
                    const auto& reference =
                        inventory->referenced_objects[work_result.index];
                    classified_size = reference.size;
                    if (work_result.state != AuditState::Healthy) {
                        unrecoverable.insert(unrecoverable.end(),
                                             reference.referenced_paths.begin(),
                                             reference.referenced_paths.end());
                    } else {
                        verified_map[reference.identifier] =
                            VerifiedObjectEntry{
                                .logical_content_hash = reference.identifier,
                                .remote_content_id =
                                    std::move(work_result.remote_content_id),
                                .plaintext_size = reference.size,
                                .physical_ciphertext_sha256 =
                                    std::move(work_result.physical_sha256),
                            };
                        platform::perf_trace::count(
                            "fsck.checkpoint_verified_entries_recorded");
                        ++unpersisted_verified;

                        if (unpersisted_verified >= 64 &&
                            !profile_dir.empty() && !vault_identity.empty()) {
                            FsckCheckpoint partial_checkpoint{
                                .header =
                                    {
                                        .format_version =
                                            checkpoint_format_version_1,
                                        .audit_semantics_version =
                                            checkpoint_audit_semantics_version_1,
                                        .vault_id = vault_identity,
                                        .entry_count = verified_map.size(),
                                    },
                            };
                            partial_checkpoint.entries.reserve(
                                verified_map.size());
                            for (const auto& [_, entry] : verified_map) {
                                partial_checkpoint.entries.push_back(entry);
                            }
                            (void)save_checkpoint(
                                profile_dir, partial_checkpoint, key);
                            unpersisted_verified = 0;
                        }
                    }
                    object_classified = true;
                }

                if (!state.stop_requested && !cancelled &&
                    !lowest_hard_failure && next < total_objects) {
                    if (platform::cancellation::requested()) {
                        cancelled = true;
                        request_window_stop();
                    } else {
                        admit(slot);
                    }
                }
                if (object_classified && on_progress) {
                    ++completed_objects;
                    if (completed_plaintext_bytes) {
                        if (classified_size >
                            std::numeric_limits<std::uint64_t>::max() -
                                *completed_plaintext_bytes) {
                            completed_plaintext_bytes.reset();
                        } else {
                            *completed_plaintext_bytes += classified_size;
                        }
                    }
                    report_progress(application::FsckStage::AuditingContent);
                }
            }

            request_window_stop();
            workers.clear();
            report_progress(application::FsckStage::Finalizing);

            platform::perf_trace::count("fsck.audit_peak_in_flight",
                                        state.peak_in_flight);

            if (!profile_dir.empty() && !vault_identity.empty() &&
                unrecoverable.empty() && !cancelled && !lowest_hard_failure) {
                FsckCheckpoint final_checkpoint{
                    .header =
                        {
                            .format_version = checkpoint_format_version_1,
                            .audit_semantics_version =
                                checkpoint_audit_semantics_version_1,
                            .vault_id = vault_identity,
                            .entry_count = verified_map.size(),
                        },
                };
                final_checkpoint.entries.reserve(verified_map.size());
                for (auto& [_, entry] : verified_map) {
                    final_checkpoint.entries.push_back(std::move(entry));
                }
                (void)save_checkpoint(profile_dir, final_checkpoint, key);
            }

            if (lowest_hard_failure) {
                return std::unexpected(std::move(lowest_hard_failure->second));
            }
            if (cancelled || platform::cancellation::requested()) {
                return std::unexpected(
                    make_error(ErrorCode::StateFailure, "operation cancelled"));
            }

            std::ranges::sort(unrecoverable, {}, [](const auto& path) {
                return platform::path::to_logical_utf8(path);
            });
            unrecoverable.erase(std::ranges::unique(unrecoverable).begin(),
                                unrecoverable.end());
            if (!unrecoverable.empty()) {
                return std::unexpected(make_error(ErrorCode::Unrecoverable,
                                                  path_detail(unrecoverable)));
            }
            return fsck_result;
        } catch (const std::exception& exception) {
            return std::unexpected(
                make_error(ErrorCode::StateFailure, exception.what()));
        }
    }();
    const auto ws_cleanup_token = platform::perf_trace::begin();
    platform::cleanup_workspace(*workspace);
    platform::perf_trace::finish("fsck.workspace_duration_us",
                                 ws_cleanup_token);
    return result;
}

} // namespace

std::expected<FsckResult, Error> fsck(const runtime::RuntimeData& runtime_data,
                                      transport::Transport& storage,
                                      KeySpan key,
                                      std::size_t audit_concurrency,
                                      FsckProgressCallback on_progress) {
    return fsck_impl(runtime_data,
                     storage,
                     key,
                     audit_concurrency,
                     std::move(on_progress),
                     {});
}

std::expected<FsckResult, Error> testing::fsck_with_worker_events(
    const runtime::RuntimeData& runtime_data,
    transport::Transport& storage,
    KeySpan key,
    std::size_t audit_concurrency,
    FsckProgressCallback on_progress,
    testing::FsckWorkerEventCallback on_worker_event) {
    return fsck_impl(runtime_data,
                     storage,
                     key,
                     audit_concurrency,
                     std::move(on_progress),
                     on_worker_event);
}

} // namespace kasumi::application::integrity
