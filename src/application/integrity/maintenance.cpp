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

bool is_hex_sha256(std::string_view value) noexcept {
    return value.size() == 64 && std::ranges::all_of(value, [](char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f');
           });
}

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

enum class AuditState {
    Healthy,
    Missing,
    Corrupt
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

Error protocol_error(
    const history_storage::maintenance_protocol::Error& error) {
    using ProtocolErrorCode = history_storage::maintenance_protocol::ErrorCode;
    ErrorCode code = ErrorCode::IntegrityFailure;
    switch (error.code) {
        case ProtocolErrorCode::WorkspaceFailure:
            code = ErrorCode::WorkspaceFailure;
            break;
        case ProtocolErrorCode::TransportFailure:
            code = ErrorCode::TransportFailure;
            break;
        case ProtocolErrorCode::Blocked:
            code = ErrorCode::ConcurrentChange;
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

namespace {

transport::RemovalResult raw_remove(transport::Transport& transport,
                                    std::string_view identifier) {
    if (!transport::valid(transport) || transport.storage.remove == nullptr) {
        return std::unexpected(
            transport::Error{.code = transport::ErrorCode::InvalidContext,
                             .message = "invalid transport"});
    }
    return transport.storage.remove(transport.state.get(), identifier);
}

} // namespace

std::expected<std::size_t, Error>
purge_quarantine(const runtime::RuntimeData& runtime_data,
                 transport::Transport& storage,
                 std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    if (!transport::valid(storage)) {
        return std::unexpected(make_error(
            ErrorCode::InvalidInput, "invalid transport for quarantine purge"));
    }

    if (platform::cancellation::requested()) {
        return std::unexpected(
            make_error(ErrorCode::StateFailure, "operation cancelled by user"));
    }

    const auto layout = history_storage::derive_remote_layout(key);
    const auto workspace_root = maintenance_workspace_root(runtime_data);

    // 1. Acquire barrier (checking for existing barrier first)
    auto existing_barrier =
        transport::presence(storage, layout.barrier_identifier);
    if (!existing_barrier) {
        return std::unexpected(transport_error(existing_barrier.error(),
                                               layout.barrier_identifier));
    }
    if (*existing_barrier == transport::Presence::Present) {
        return std::unexpected(
            make_error(ErrorCode::ConcurrentChange,
                       "existing maintenance barrier present",
                       layout.barrier_identifier));
    }

    auto barrier = history_storage::maintenance_protocol::establish_barrier(
        storage, layout, workspace_root);
    if (!barrier) {
        return std::unexpected(protocol_error(barrier.error()));
    }

    auto outcome = [&]() -> std::expected<std::size_t, Error> {
        auto check_barrier = [&]() -> std::expected<void, Error> {
            auto owned =
                history_storage::maintenance_protocol::verify_registration(
                    *barrier);
            if (!owned) {
                return std::unexpected(protocol_error(owned.error()));
            }
            return {};
        };

        // 2. Verify writers (2 observations)
        for (int observation = 0; observation < 2; ++observation) {
            auto writers =
                history_storage::maintenance_protocol::active_writers(storage,
                                                                      layout);
            if (!writers) {
                return std::unexpected(protocol_error(writers.error()));
            }
            if (!writers->empty()) {
                return std::unexpected(make_error(
                    ErrorCode::ConcurrentChange,
                    list_detail("active or abandoned writers: ", *writers)));
            }
            auto owned = check_barrier();
            if (!owned) {
                return std::unexpected(owned.error());
            }
        }

        // 3. Verify backend online consistency support
        auto online =
            history_storage::maintenance_protocol::supports_online_collection(
                storage, layout, workspace_root);
        if (!online) {
            return std::unexpected(protocol_error(online.error()));
        }
        if (!*online) {
            return std::unexpected(
                make_error(ErrorCode::IntegrityFailure,
                           "backend lacks required online-consistency "
                           "guarantees for quarantine purge"));
        }

        auto owned_after_probe = check_barrier();
        if (!owned_after_probe) {
            return std::unexpected(owned_after_probe.error());
        }

        // 4. Capture inventory once
        auto inventory =
            history_storage::maintenance_protocol::inventory_quarantine(
                storage, key, workspace_root);
        if (!inventory) {
            return std::unexpected(protocol_error(inventory.error()));
        }

        if (inventory->empty()) {
            return 0;
        }

        // 5. Complete preflight validation before any mutation
        for (const auto& entry : *inventory) {
            if (platform::cancellation::requested()) {
                return std::unexpected(make_error(
                    ErrorCode::StateFailure, "operation cancelled by user"));
            }

            // Validate metadata presence
            if (!entry.quarantined_at.has_value() ||
                entry.physical_sha256.empty()) {
                return std::unexpected(make_error(
                    ErrorCode::IntegrityFailure,
                    "quarantine entry missing authenticated metadata",
                    entry.quarantine_identifier));
            }

            // Reject epoch-derived targets
            if (history_storage::maintenance_protocol::is_epoch_object(
                    layout, entry.original_identifier)) {
                return std::unexpected(
                    make_error(ErrorCode::IntegrityFailure,
                               "epoch object blocked from quarantine purge",
                               entry.quarantine_identifier));
            }

            // Check required original-object absence
            auto original =
                transport::presence(storage, entry.original_identifier);
            if (!original) {
                return std::unexpected(transport_error(
                    original.error(), entry.original_identifier));
            }
            if (*original == transport::Presence::Present) {
                return std::unexpected(make_error(
                    ErrorCode::ConcurrentChange,
                    "original object reappeared for quarantine entry",
                    entry.original_identifier));
            }

            // Verify physical payload against metadata
            auto verified =
                history_storage::maintenance_protocol::verify_quarantine(
                    storage, entry, workspace_root);
            if (!verified) {
                return std::unexpected(protocol_error(verified.error()));
            }
            if (!*verified) {
                return std::unexpected(
                    make_error(ErrorCode::IntegrityFailure,
                               "quarantine payload physical hash mismatch",
                               entry.quarantine_identifier));
            }

            auto barrier_ok = check_barrier();
            if (!barrier_ok) {
                return std::unexpected(barrier_ok.error());
            }
        }

        // 6. Execute captured purge entry by entry
        std::size_t completed_count = 0;
        for (const auto& entry : *inventory) {
            // Step 1: Check cancellation
            if (platform::cancellation::requested()) {
                return std::unexpected(make_error(
                    ErrorCode::StateFailure,
                    "operation cancelled by user; completed entries: " +
                        std::to_string(completed_count)));
            }

            // Step 2: Verify barrier ownership
            auto barrier_ok1 = check_barrier();
            if (!barrier_ok1) {
                auto err = barrier_ok1.error();
                err.detail +=
                    "; completed entries: " + std::to_string(completed_count);
                return std::unexpected(err);
            }

            // Step 3: Revalidate the selected entry's current identity,
            // metadata and physical content
            std::array<std::string, 2> entry_identifiers{
                entry.quarantine_identifier, entry.metadata_identifier};
            auto reloaded_inventory =
                history_storage::maintenance_protocol::inventory_quarantine(
                    storage, key, entry_identifiers, workspace_root);
            if (!reloaded_inventory || reloaded_inventory->empty()) {
                return std::unexpected(
                    make_error(ErrorCode::ConcurrentChange,
                               "quarantine metadata changed or disappeared "
                               "concurrently; completed entries: " +
                                   std::to_string(completed_count),
                               entry.metadata_identifier));
            }
            const auto& reloaded = reloaded_inventory->front();
            if (reloaded.quarantine_identifier != entry.quarantine_identifier ||
                reloaded.metadata_identifier != entry.metadata_identifier ||
                reloaded.quarantined_at != entry.quarantined_at ||
                reloaded.physical_sha256 != entry.physical_sha256) {
                return std::unexpected(
                    make_error(ErrorCode::ConcurrentChange,
                               "quarantine metadata modified concurrently; "
                               "completed entries: " +
                                   std::to_string(completed_count),
                               entry.metadata_identifier));
            }

            auto reloaded_hash =
                history_storage::maintenance_protocol::verify_quarantine(
                    storage, reloaded, workspace_root);
            if (!reloaded_hash) {
                auto err = protocol_error(reloaded_hash.error());
                err.detail +=
                    "; completed entries: " + std::to_string(completed_count);
                return std::unexpected(err);
            }
            if (!*reloaded_hash) {
                return std::unexpected(
                    make_error(ErrorCode::ConcurrentChange,
                               "quarantine payload modified concurrently; "
                               "completed entries: " +
                                   std::to_string(completed_count),
                               entry.quarantine_identifier));
            }

            // Step 4: Confirm required original-object absence
            auto recheck_original =
                transport::presence(storage, entry.original_identifier);
            if (!recheck_original) {
                auto err = transport_error(recheck_original.error(),
                                           entry.original_identifier);
                err.detail +=
                    "; completed entries: " + std::to_string(completed_count);
                return std::unexpected(err);
            }
            if (*recheck_original == transport::Presence::Present) {
                return std::unexpected(
                    make_error(ErrorCode::ConcurrentChange,
                               "original object reappeared for quarantine "
                               "entry; completed entries: " +
                                   std::to_string(completed_count),
                               entry.original_identifier));
            }

            // Step 5: Verify barrier ownership immediately before deletion
            auto barrier_ok2 = check_barrier();
            if (!barrier_ok2) {
                auto err = barrier_ok2.error();
                err.detail +=
                    "; completed entries: " + std::to_string(completed_count);
                return std::unexpected(err);
            }

            // Step 6: Remove the quarantine PAYLOAD
            auto payload_removed =
                raw_remove(storage, entry.quarantine_identifier);
            if (!payload_removed) {
                auto err = transport_error(payload_removed.error(),
                                           entry.quarantine_identifier);
                err.detail =
                    "transport failure removing quarantine payload (mutation "
                    "uncertain): " +
                    err.detail +
                    "; completed entries: " + std::to_string(completed_count) +
                    "; affected object: " + entry.quarantine_identifier;
                return std::unexpected(err);
            }
            if (*payload_removed != transport::Removal::Removed) {
                return std::unexpected(
                    make_error(ErrorCode::ConcurrentChange,
                               "quarantine payload already removed or missing; "
                               "completed entries: " +
                                   std::to_string(completed_count),
                               entry.quarantine_identifier));
            }

            // Step 7: If successful, check cancellation and barrier ownership
            if (platform::cancellation::requested()) {
                return std::unexpected(make_error(
                    ErrorCode::StateFailure,
                    "operation cancelled by user after payload removal "
                    "(incomplete quarantine pair); completed entries: " +
                        std::to_string(completed_count) +
                        "; affected object: " + entry.metadata_identifier,
                    entry.metadata_identifier));
            }
            auto barrier_ok3 = check_barrier();
            if (!barrier_ok3) {
                auto err = barrier_ok3.error();
                err.detail = "lost barrier ownership after payload removal "
                             "(incomplete quarantine pair): " +
                             err.detail + "; completed entries: " +
                             std::to_string(completed_count) +
                             "; affected object: " + entry.metadata_identifier;
                return std::unexpected(err);
            }

            // Step 8: Remove the associated authenticated METADATA
            auto metadata_removed =
                raw_remove(storage, entry.metadata_identifier);
            if (!metadata_removed) {
                auto err = transport_error(metadata_removed.error(),
                                           entry.metadata_identifier);
                err.detail =
                    "transport failure removing quarantine metadata after "
                    "payload removed (incomplete quarantine pair): " +
                    err.detail +
                    "; completed entries: " + std::to_string(completed_count) +
                    "; affected object: " + entry.metadata_identifier;
                return std::unexpected(err);
            }
            if (*metadata_removed != transport::Removal::Removed) {
                return std::unexpected(make_error(
                    ErrorCode::ConcurrentChange,
                    "quarantine metadata already removed or missing after "
                    "payload removed (incomplete quarantine pair); completed "
                    "entries: " +
                        std::to_string(completed_count) +
                        "; affected object: " + entry.metadata_identifier,
                    entry.metadata_identifier));
            }

            // Step 9: Count the entry completed only after both removals are
            // confirmed
            ++completed_count;
        }

        return completed_count;
    }();

    auto released =
        history_storage::maintenance_protocol::release_registration(*barrier);
    if (!outcome) {
        if (!released) {
            auto err = outcome.error();
            err.detail += "; failed to release maintenance barrier: " +
                          released.error().detail +
                          "; barrier: " + layout.barrier_identifier;
            return std::unexpected(err);
        }
        return outcome;
    }
    if (!released) {
        auto err = protocol_error(released.error());
        err.detail = "failed to release maintenance barrier: " + err.detail +
                     "; completed entries: " + std::to_string(*outcome) +
                     "; barrier: " + layout.barrier_identifier;
        return std::unexpected(err);
    }
    return outcome;
}

std::expected<std::size_t, Error>
repair_quarantine(const runtime::RuntimeData& runtime_data,
                  transport::Transport& storage,
                  std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    if (!transport::valid(storage)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidInput,
                       "invalid transport for quarantine repair"));
    }

    if (platform::cancellation::requested()) {
        return std::unexpected(
            make_error(ErrorCode::StateFailure, "operation cancelled by user"));
    }

    const auto layout = history_storage::derive_remote_layout(key);
    const auto workspace_root = maintenance_workspace_root(runtime_data);

    // 1. Acquire barrier (checking for existing barrier first)
    auto existing_barrier =
        transport::presence(storage, layout.barrier_identifier);
    if (!existing_barrier) {
        return std::unexpected(transport_error(existing_barrier.error(),
                                               layout.barrier_identifier));
    }
    if (*existing_barrier == transport::Presence::Present) {
        return std::unexpected(
            make_error(ErrorCode::ConcurrentChange,
                       "existing maintenance barrier present",
                       layout.barrier_identifier));
    }

    auto barrier = history_storage::maintenance_protocol::establish_barrier(
        storage, layout, workspace_root);
    if (!barrier) {
        return std::unexpected(protocol_error(barrier.error()));
    }

    auto outcome = [&]() -> std::expected<std::size_t, Error> {
        auto check_barrier = [&]() -> std::expected<void, Error> {
            auto owned =
                history_storage::maintenance_protocol::verify_registration(
                    *barrier);
            if (!owned) {
                return std::unexpected(protocol_error(owned.error()));
            }
            return {};
        };

        // 2. Verify writers (2 observations)
        for (int observation = 0; observation < 2; ++observation) {
            auto writers =
                history_storage::maintenance_protocol::active_writers(storage,
                                                                      layout);
            if (!writers) {
                return std::unexpected(protocol_error(writers.error()));
            }
            if (!writers->empty()) {
                return std::unexpected(make_error(
                    ErrorCode::ConcurrentChange,
                    list_detail("active or abandoned writers: ", *writers)));
            }
            auto owned = check_barrier();
            if (!owned) {
                return std::unexpected(owned.error());
            }
        }

        // 3. Verify backend online consistency support
        auto online =
            history_storage::maintenance_protocol::supports_online_collection(
                storage, layout, workspace_root);
        if (!online) {
            return std::unexpected(protocol_error(online.error()));
        }
        if (!*online) {
            return std::unexpected(
                make_error(ErrorCode::IntegrityFailure,
                           "backend lacks required online-consistency "
                           "guarantees for quarantine repair"));
        }

        auto owned_after_probe = check_barrier();
        if (!owned_after_probe) {
            return std::unexpected(owned_after_probe.error());
        }

        // 4. Classify quarantine inventory once
        auto classified = history_storage::maintenance_protocol::
            classify_quarantine_for_repair(storage, layout);
        if (!classified) {
            return std::unexpected(protocol_error(classified.error()));
        }

        // Fail closed on any invalid or ambiguous objects in quarantine
        // namespace
        if (!classified->invalid_identifiers.empty()) {
            return std::unexpected(
                make_error(ErrorCode::IntegrityFailure,
                           "malformed or invalid quarantine object: " +
                               classified->invalid_identifiers.front(),
                           classified->invalid_identifiers.front()));
        }

        // Fail closed on any payload-only objects
        if (!classified->payload_only_identifiers.empty()) {
            return std::unexpected(
                make_error(ErrorCode::IntegrityFailure,
                           "unsupported payload-only quarantine object: " +
                               classified->payload_only_identifiers.front(),
                           classified->payload_only_identifiers.front()));
        }

        struct RepairCandidate {
            std::string original_identifier;
            std::string quarantine_identifier;
            std::string metadata_identifier;
            std::int64_t quarantined_at = 0;
            std::string payload_sha256;
            std::string ciphertext_sha256;
        };

        // 5. Complete preflight validation for healthy pairs and all
        // metadata-only candidates before any mutation
        for (const auto& healthy : classified->healthy_pairs) {
            if (platform::cancellation::requested()) {
                return std::unexpected(make_error(
                    ErrorCode::StateFailure, "operation cancelled by user"));
            }
            auto authenticated = history_storage::maintenance_protocol::
                authenticate_quarantine_metadata(
                    storage, healthy.metadata_identifier, key, workspace_root);
            if (!authenticated) {
                return std::unexpected(
                    make_error(ErrorCode::IntegrityFailure,
                               "cryptographically invalid quarantine metadata "
                               "in healthy pair: " +
                                   authenticated.error().detail,
                               healthy.metadata_identifier));
            }
            auto barrier_ok = check_barrier();
            if (!barrier_ok) {
                return std::unexpected(barrier_ok.error());
            }
        }

        if (classified->metadata_only_candidates.empty()) {
            return 0;
        }

        std::vector<RepairCandidate> candidates;
        candidates.reserve(classified->metadata_only_candidates.size());
        for (const auto& candidate_entry :
             classified->metadata_only_candidates) {
            if (platform::cancellation::requested()) {
                return std::unexpected(make_error(
                    ErrorCode::StateFailure, "operation cancelled by user"));
            }

            // Reject epoch-derived targets
            if (history_storage::maintenance_protocol::is_epoch_object(
                    layout, candidate_entry.original_identifier)) {
                return std::unexpected(
                    make_error(ErrorCode::IntegrityFailure,
                               "epoch object blocked from quarantine repair",
                               candidate_entry.quarantine_identifier));
            }

            // Check required original-object absence
            auto original = transport::presence(
                storage, candidate_entry.original_identifier);
            if (!original) {
                return std::unexpected(transport_error(
                    original.error(), candidate_entry.original_identifier));
            }
            if (*original == transport::Presence::Present) {
                return std::unexpected(make_error(
                    ErrorCode::ConcurrentChange,
                    "original object reappeared for quarantine entry",
                    candidate_entry.original_identifier));
            }

            // Confirm payload absence
            auto payload_presence = transport::presence(
                storage, candidate_entry.quarantine_identifier);
            if (!payload_presence) {
                return std::unexpected(
                    transport_error(payload_presence.error(),
                                    candidate_entry.quarantine_identifier));
            }
            if (*payload_presence == transport::Presence::Present) {
                return std::unexpected(make_error(
                    ErrorCode::ConcurrentChange,
                    "quarantine payload present for metadata-only candidate",
                    candidate_entry.quarantine_identifier));
            }

            // Authenticate candidate metadata and capture ciphertext identity
            auto authenticated = history_storage::maintenance_protocol::
                authenticate_quarantine_metadata(
                    storage,
                    candidate_entry.metadata_identifier,
                    key,
                    workspace_root);
            if (!authenticated) {
                return std::unexpected(protocol_error(authenticated.error()));
            }
            candidates.push_back(RepairCandidate{
                .original_identifier = candidate_entry.original_identifier,
                .quarantine_identifier = candidate_entry.quarantine_identifier,
                .metadata_identifier = candidate_entry.metadata_identifier,
                .quarantined_at = authenticated->quarantined_at,
                .payload_sha256 = std::move(authenticated->payload_sha256),
                .ciphertext_sha256 =
                    std::move(authenticated->ciphertext_sha256),
            });

            auto barrier_ok = check_barrier();
            if (!barrier_ok) {
                return std::unexpected(barrier_ok.error());
            }
        }

        // 6. Execute captured repair candidate by candidate
        std::size_t completed_count = 0;
        for (const auto& candidate : candidates) {
            // Step 1: Check cancellation
            if (platform::cancellation::requested()) {
                return std::unexpected(make_error(
                    ErrorCode::StateFailure,
                    "operation cancelled by user; completed entries: " +
                        std::to_string(completed_count)));
            }

            // Step 2: Verify barrier ownership
            auto barrier_ok1 = check_barrier();
            if (!barrier_ok1) {
                auto err = barrier_ok1.error();
                err.detail +=
                    "; completed entries: " + std::to_string(completed_count);
                return std::unexpected(err);
            }

            // Step 3: Reconfirm required payload absence
            auto recheck_payload =
                transport::presence(storage, candidate.quarantine_identifier);
            if (!recheck_payload) {
                auto err = transport_error(recheck_payload.error(),
                                           candidate.quarantine_identifier);
                err.detail +=
                    "; completed entries: " + std::to_string(completed_count);
                return std::unexpected(err);
            }
            if (*recheck_payload == transport::Presence::Present) {
                return std::unexpected(
                    make_error(ErrorCode::ConcurrentChange,
                               "quarantine payload reappeared for quarantine "
                               "entry; completed entries: " +
                                   std::to_string(completed_count),
                               candidate.quarantine_identifier));
            }

            // Step 4: Reconfirm required original-object absence
            auto recheck_original =
                transport::presence(storage, candidate.original_identifier);
            if (!recheck_original) {
                auto err = transport_error(recheck_original.error(),
                                           candidate.original_identifier);
                err.detail +=
                    "; completed entries: " + std::to_string(completed_count);
                return std::unexpected(err);
            }
            if (*recheck_original == transport::Presence::Present) {
                return std::unexpected(
                    make_error(ErrorCode::ConcurrentChange,
                               "original object reappeared for quarantine "
                               "entry; completed entries: " +
                                   std::to_string(completed_count),
                               candidate.original_identifier));
            }

            // Step 5: Re-authenticate candidate metadata and verify ciphertext
            // identity
            auto re_auth = history_storage::maintenance_protocol::
                authenticate_quarantine_metadata(storage,
                                                 candidate.metadata_identifier,
                                                 key,
                                                 workspace_root);
            if (!re_auth) {
                return std::unexpected(
                    make_error(ErrorCode::ConcurrentChange,
                               "quarantine metadata modified or corrupted "
                               "concurrently; completed entries: " +
                                   std::to_string(completed_count),
                               candidate.metadata_identifier));
            }
            if (re_auth->quarantined_at != candidate.quarantined_at ||
                re_auth->payload_sha256 != candidate.payload_sha256 ||
                re_auth->ciphertext_sha256 != candidate.ciphertext_sha256) {
                return std::unexpected(
                    make_error(ErrorCode::ConcurrentChange,
                               "quarantine metadata content or identity "
                               "modified concurrently; completed entries: " +
                                   std::to_string(completed_count),
                               candidate.metadata_identifier));
            }

            // Step 6: Verify barrier ownership immediately before deletion
            auto barrier_ok2 = check_barrier();
            if (!barrier_ok2) {
                auto err = barrier_ok2.error();
                err.detail +=
                    "; completed entries: " + std::to_string(completed_count);
                return std::unexpected(err);
            }

            // Step 7: Remove the quarantine METADATA only
            auto metadata_removed =
                raw_remove(storage, candidate.metadata_identifier);
            if (!metadata_removed) {
                auto err = transport_error(metadata_removed.error(),
                                           candidate.metadata_identifier);
                err.detail =
                    "transport failure removing quarantine metadata (mutation "
                    "uncertain): " +
                    err.detail +
                    "; completed entries: " + std::to_string(completed_count) +
                    "; affected object: " + candidate.metadata_identifier;
                return std::unexpected(err);
            }
            if (*metadata_removed != transport::Removal::Removed) {
                return std::unexpected(make_error(
                    ErrorCode::ConcurrentChange,
                    "quarantine metadata already removed or missing; completed "
                    "entries: " +
                        std::to_string(completed_count) +
                        "; affected object: " + candidate.metadata_identifier,
                    candidate.metadata_identifier));
            }

            // Step 8: Count the candidate completed
            ++completed_count;
        }

        return completed_count;
    }();

    auto released =
        history_storage::maintenance_protocol::release_registration(*barrier);
    if (!outcome) {
        if (!released) {
            auto err = outcome.error();
            err.detail += "; failed to release maintenance barrier: " +
                          released.error().detail +
                          "; barrier: " + layout.barrier_identifier;
            return std::unexpected(err);
        }
        return outcome;
    }
    if (!released) {
        auto err = protocol_error(released.error());
        err.detail = "failed to release maintenance barrier: " + err.detail +
                     "; completed entries: " + std::to_string(*outcome) +
                     "; barrier: " + layout.barrier_identifier;
        return std::unexpected(err);
    }
    return outcome;
}

std::expected<std::vector<GcCandidate>, Error>
select_gc_candidates(std::span<const std::string> commit_variant_ids,
                     std::span<const std::string> orphan_content_ids) {
    std::vector<GcCandidate> candidates;
    candidates.reserve(commit_variant_ids.size() + orphan_content_ids.size());
    for (const auto& identifier : commit_variant_ids) {
        if (identifier.empty()) {
            return std::unexpected(make_error(
                ErrorCode::InvalidInput, "empty GC candidate identifier"));
        }
        candidates.push_back(GcCandidate{
            .identifier = identifier,
            .kind = GcCandidateKind::CommitVariant,
        });
    }
    for (const auto& identifier : orphan_content_ids) {
        if (identifier.empty()) {
            return std::unexpected(make_error(
                ErrorCode::InvalidInput, "empty GC candidate identifier"));
        }
        if (!is_hex_sha256(identifier)) {
            return std::unexpected(make_error(
                ErrorCode::IntegrityFailure,
                "invalid content candidate identifier",
                identifier));
        }
        candidates.push_back(GcCandidate{
            .identifier = identifier,
            .kind = GcCandidateKind::Content,
        });
    }
    std::ranges::sort(candidates,
                      [](const GcCandidate& left,
                         const GcCandidate& right) noexcept {
                          if (left.identifier != right.identifier) {
                              return left.identifier < right.identifier;
                          }
                          return left.kind < right.kind;
                      });
    candidates.erase(std::ranges::unique(candidates).begin(), candidates.end());
    for (std::size_t i = 1; i < candidates.size(); ++i) {
        if (candidates[i - 1].identifier == candidates[i].identifier) {
            return std::unexpected(make_error(
                ErrorCode::IntegrityFailure,
                "contradictory GC candidate classification",
                candidates[i].identifier));
        }
    }
    return candidates;
}

bool same_gc_candidates(std::span<const GcCandidate> left,
                        std::span<const GcCandidate> right) noexcept {
    return std::ranges::equal(left, right);
}

std::expected<GcSnapshot, Error>
collect_gc_snapshot(transport::Transport& storage,
                    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                    const std::filesystem::path& workspace_root) {
    if (!transport::valid(storage)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidInput, "invalid storage transport"));
    }
    std::error_code ws_err;
    if (workspace_root.empty() || !std::filesystem::exists(workspace_root, ws_err)) {
        return std::unexpected(make_error(
            ErrorCode::WorkspaceFailure, "invalid or non-existent workspace root"));
    }

    auto listing = transport::list(storage);
    if (!listing) {
        return std::unexpected(transport_error(listing.error()));
    }
    for (const auto& identifier : *listing) {
        if (identifier.empty()) {
            return std::unexpected(make_error(
                ErrorCode::IntegrityFailure,
                "storage listing contains empty identifier"));
        }
    }
    std::ranges::sort(*listing);
    listing->erase(std::ranges::unique(*listing).begin(), listing->end());

    auto history = history_storage::inventory_reachability(
        storage, key, *listing, workspace_root);
    if (!history) {
        return std::unexpected(history_storage_error(history.error()));
    }

    if (history->logical_heads.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure, "remote history absent"));
    }
    if (!history->unknown_history_objects.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("unknown history objects: ",
                                   history->unknown_history_objects)));
    }
    if (!history->missing_parent_ids.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("commits pais ausentes: ",
                                   history->missing_parent_ids)));
    }
    if (!history->invalid_parent_ids.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("invalid parent commits: ",
                                   history->invalid_parent_ids)));
    }

    std::vector<std::string> invalid_markers;
    for (const auto& marker : history->markers) {
        if (marker.state != history_storage::ReachabilityMarkerState::Valid) {
            invalid_markers.push_back(marker.identifier);
        }
    }
    if (!invalid_markers.empty()) {
        std::ranges::sort(invalid_markers);
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("invalid or unstable head markers: ",
                                   invalid_markers)));
    }

    std::vector<std::string> invalid_commits;
    for (const auto& commit : history->commits) {
        if (!commit.valid &&
            std::ranges::any_of(commit.variants, [](const auto& variant) {
                return !variant.identifier.empty();
            })) {
            invalid_commits.push_back(commit.commit_id);
        }
    }
    if (!invalid_commits.empty()) {
        std::ranges::sort(invalid_commits);
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("invalid commits: ", invalid_commits)));
    }

    std::vector<std::string> invalid_variants;
    for (const auto& commit : history->commits) {
        for (const auto& variant : commit.variants) {
            if (variant.state ==
                    history_storage::detail::VariantState::InvalidCiphertext ||
                variant.state ==
                    history_storage::detail::VariantState::InvalidCommit) {
                invalid_variants.push_back(
                    variant.identifier.empty() ? commit.commit_id : variant.identifier);
            }
        }
    }
    if (!invalid_variants.empty()) {
        std::ranges::sort(invalid_variants);
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("invalid commit variants: ", invalid_variants)));
    }

    auto content = history_storage::inventory_content_reachability(
        storage, key, *listing, *history, workspace_root, false);
    if (!content) {
        return std::unexpected(history_storage_error(content.error()));
    }

    if (!content->unknown_storage_objects.empty()) {
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("unknown physical identifiers: ",
                                   content->unknown_storage_objects)));
    }

    std::vector<std::string> damaged;
    for (const auto& entry : content->contents) {
        if (entry.reachable &&
            entry.state != history_storage::ContentObjectState::Present) {
            damaged.push_back(entry.content_id);
        }
    }
    if (!damaged.empty()) {
        std::ranges::sort(damaged);
        return std::unexpected(
            make_error(ErrorCode::IntegrityFailure,
                       list_detail("reachable contents missing or corrupted: ",
                                   damaged)));
    }

    GcSnapshot snapshot;
    snapshot.logical_heads = history->logical_heads;
    std::ranges::sort(snapshot.logical_heads);
    snapshot.logical_heads.erase(
        std::ranges::unique(snapshot.logical_heads).begin(),
        snapshot.logical_heads.end());

    snapshot.reachable_commits = history->reachable_commits;
    std::ranges::sort(snapshot.reachable_commits);
    snapshot.reachable_commits.erase(
        std::ranges::unique(snapshot.reachable_commits).begin(),
        snapshot.reachable_commits.end());

    snapshot.reachable_content = content->reachable_content_ids;
    std::ranges::sort(snapshot.reachable_content);
    snapshot.reachable_content.erase(
        std::ranges::unique(snapshot.reachable_content).begin(),
        snapshot.reachable_content.end());

    snapshot.physical_namespace = std::move(*listing);

    const auto layout = history_storage::derive_remote_layout(key);
    std::vector<std::string> marked_commits;
    for (const auto& marker : history->markers) {
        if (marker.state != history_storage::ReachabilityMarkerState::Valid ||
            !marker.reference) {
            continue;
        }
        marked_commits.push_back(marker.reference->commit_id);
        snapshot.required_commit_objects.push_back(
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
            snapshot.required_commit_objects.push_back(variant->identifier);
        } else {
            return std::unexpected(make_error(
                ErrorCode::IntegrityFailure,
                "reachable commit has no valid physical variant: " +
                    commit.commit_id));
        }
    }
    std::ranges::sort(snapshot.required_commit_objects);
    snapshot.required_commit_objects.erase(
        std::ranges::unique(snapshot.required_commit_objects).begin(),
        snapshot.required_commit_objects.end());

    std::vector<std::string> dispensable_variants;
    for (const auto& commit : history->commits) {
        for (const auto& variant : commit.variants) {
            if (!variant.identifier.empty() &&
                !std::ranges::binary_search(snapshot.required_commit_objects,
                                            variant.identifier)) {
                dispensable_variants.push_back(variant.identifier);
            }
        }
    }
    std::ranges::sort(dispensable_variants);
    dispensable_variants.erase(
        std::ranges::unique(dispensable_variants).begin(),
        dispensable_variants.end());

    auto selected_candidates = select_gc_candidates(
        dispensable_variants, content->orphan_content_ids);
    if (!selected_candidates) {
        return std::unexpected(selected_candidates.error());
    }
    snapshot.candidates = std::move(*selected_candidates);

    return snapshot;
}

bool same_gc_snapshot(const GcSnapshot& left,
                      const GcSnapshot& right) noexcept {
    return left.logical_heads == right.logical_heads &&
           left.reachable_commits == right.reachable_commits &&
           left.required_commit_objects == right.required_commit_objects &&
           left.reachable_content == right.reachable_content &&
           left.physical_namespace == right.physical_namespace &&
           same_gc_candidates(left.candidates, right.candidates);
}

} // namespace kasumi::application::integrity
