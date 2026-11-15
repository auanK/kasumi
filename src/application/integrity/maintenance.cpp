#include "application/integrity/maintenance.hpp"

#include "application/concurrency.hpp"
#include "application/detail.hpp"
#include "application/history_storage/content_reachability.hpp"
#include "application/history_storage/detail.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/maintenance_test.hpp"
#include "application/observation/state.hpp"
#include "core/maintenance.hpp"
#include "crypto/content.hpp"
#include "platform/cancellation.hpp"
#include "platform/clock.hpp"
#include "platform/path.hpp"
#include "platform/workspace.hpp"

#include <algorithm>
#include <atomic>
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
    std::vector<std::string> utf8_paths;
    utf8_paths.reserve(paths.size());
    for (const auto& path : paths) {
        utf8_paths.push_back(platform::path::to_utf8(path));
    }
    return list_detail("referenced objects missing or corrupted; fsck repair "
                       "unavailable at this stage (paths: ",
                       utf8_paths) +
           ')';
}

std::expected<bool, Error> check_regular_file(const std::filesystem::path& path,
                                              ErrorCode failure_code,
                                              bool allow_absent,
                                              std::string_view detail) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if ((allow_absent && not_found(error)) ||
        status.type() == std::filesystem::file_type::not_found) {
        if (allow_absent) {
            return false;
        }
        return std::unexpected(make_error(failure_code, std::string{detail}));
    }
    if (error) {
        return std::unexpected(make_error(
            failure_code, std::string{detail} + ": " + error.message()));
    }
    if (std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        return std::unexpected(make_error(failure_code, std::string{detail}));
    }
    return true;
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

std::expected<void, Error>
prepare_workspace_file(const std::filesystem::path& path) {
    auto present = check_regular_file(path,
                                      ErrorCode::WorkspaceFailure,
                                      true,
                                      "temporary file has invalid type");
    if (!present) {
        return std::unexpected(present.error());
    }
    return *present ? remove_temporary_file(path)
                    : std::expected<void, Error>{};
}

std::expected<void, Error> verify_content(const std::filesystem::path& path,
                                          std::string_view identifier,
                                          std::uint64_t expected_size,
                                          ErrorCode io_failure) {
    if (auto regular = check_regular_file(
            path, io_failure, false, "file is not regular for verification");
        !regular) {
        return std::unexpected(regular.error());
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

std::expected<AuditState, Error>
audit_object(transport::Transport& storage,
             KeySpan key,
             const kasumi::maintenance::ObjectReference& reference,
             const platform::Workspace& workspace,
             std::size_t index) {
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
    if (auto p = prepare_workspace_file(encrypted); !p)
        return std::unexpected(p.error());
    if (auto p = prepare_workspace_file(plaintext); !p)
        return std::unexpected(p.error());

    const auto cleanup_temporaries = [&]() -> std::expected<void, Error> {
        for (const auto& path : {encrypted, plaintext}) {
            if (auto removed = remove_temporary_file(path); !removed) {
                return std::unexpected(removed.error());
            }
        }
        return {};
    };

    auto downloaded = transport::get(storage, remote_identifier, encrypted);
    if (!downloaded) {
        if (auto cleaned = cleanup_temporaries(); !cleaned)
            return std::unexpected(cleaned.error());
        if (downloaded.error().code == transport::ErrorCode::ObjectNotFound) {
            return AuditState::Missing;
        }
        return std::unexpected(
            transport_error(downloaded.error(), reference.identifier));
    }

    if (auto regular = check_regular_file(encrypted,
                                          ErrorCode::WorkspaceFailure,
                                          false,
                                          "invalid temporary download");
        !regular) {
        return std::unexpected(regular.error());
    }

    AuditState result = AuditState::Healthy;
    if (!crypto::decrypt_file(encrypted, plaintext, key)) {
        result = AuditState::Corrupt;
    } else {
        auto verified = verify_content(plaintext,
                                       reference.identifier,
                                       reference.size,
                                       ErrorCode::WorkspaceFailure);
        if (!verified) {
            if (verified.error().code != ErrorCode::IntegrityFailure) {
                return std::unexpected(verified.error());
            }
            result = AuditState::Corrupt;
        }
    }

    if (auto cleaned = cleanup_temporaries(); !cleaned)
        return std::unexpected(cleaned.error());
    return result;
}

} // namespace

std::string describe(const Error& error) {
    static constexpr std::array<std::pair<ErrorCode, std::string_view>, 8>
        labels{{
            {ErrorCode::InvalidInput, "invalid_input"},
            {ErrorCode::StateFailure, "state_failure"},
            {ErrorCode::WorkspaceFailure, "workspace_failure"},
            {ErrorCode::TransportFailure, "transport_failure"},
            {ErrorCode::CryptoFailure, "crypto_failure"},
            {ErrorCode::IntegrityFailure, "integrity_failure"},
            {ErrorCode::Unrecoverable, "unrecoverable"},
            {ErrorCode::ConcurrentChange, "concurrent_change"},
        }};
    std::string result{"unknown_error"};
    for (const auto& [code, label] : labels) {
        if (code == error.code) {
            result = label;
            break;
        }
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
    if (runtime_data.local_dir.empty() || !transport::valid(storage)) {
        return std::unexpected(
            make_error(ErrorCode::InvalidInput, "invalid fsck context"));
    }
    report_progress(application::FsckStage::Observing);
    const auto history_workspace =
        application::detail::maintenance_workspace_root(runtime_data);
    auto observation = observation::collect_storage_observation(
        storage, key, history_workspace, true);
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
    auto local_tree = observation::collect_local_tree(runtime_data.local_dir);
    if (!local_tree) {
        return std::unexpected(
            make_error(ErrorCode::StateFailure, local_tree.error()));
    }
    auto inventory =
        analyze_inventory(storage_state.tree, *local_tree, storage_state);
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

    auto workspace = platform::create_workspace("fsck");
    if (!workspace) {
        return std::unexpected(
            make_error(ErrorCode::WorkspaceFailure, workspace.error()));
    }
    auto result = [&]() -> std::expected<FsckResult, Error> {
        try {
            const auto total_objects = inventory->referenced_objects.size();
            if (on_progress) {
                report_progress(application::FsckStage::AuditingContent);
            }
            FsckResult fsck_result{
                .checked_objects = total_objects,
            };

            const auto worker_count = std::min<std::size_t>(
                std::max<std::size_t>(1, audit_concurrency), total_objects);
            if (total_objects == 0) {
                report_progress(application::FsckStage::Finalizing);
                return fsck_result;
            }

            std::mutex state_mutex;
            std::atomic<bool> stop_requested{false};
            std::atomic<bool> stop_event_notified{false};
            std::optional<std::pair<std::size_t, Error>> lowest_hard_failure;
            std::vector<std::filesystem::path> unrecoverable;
            bool cancelled = false;

            const auto request_window_stop = [&] {
                stop_requested.store(true, std::memory_order_release);
                if (on_worker_event && !stop_event_notified.exchange(true)) {
                    try {
                        on_worker_event(
                            testing::FsckWorkerEvent::WindowStopRequested, 0);
                    } catch (...) {
                        // Test observation cannot alter the audit result.
                    }
                }
            };
            const auto record_hard_failure = [&](std::size_t index, Error err) {
                {
                    std::lock_guard lock(state_mutex);
                    if (!lowest_hard_failure ||
                        index < lowest_hard_failure->first) {
                        lowest_hard_failure = std::pair{index, std::move(err)};
                    }
                }
                request_window_stop();
            };

            std::condition_variable progress_cv;
            std::condition_variable progress_ack_cv;
            std::vector<std::uint64_t> completed_sizes;
            std::size_t acked_completions = 0;
            bool workers_done = false;
            bool progress_aborted = false;

            const auto run_workers = [&] {
                application::parallel_for_indexed(
                    total_objects, worker_count, [&](std::size_t index) {
                        if (stop_requested.load(std::memory_order_acquire)) {
                            return;
                        }
                        try {
                            if (on_worker_event) {
                                try {
                                    on_worker_event(
                                        testing::FsckWorkerEvent::BeforeAudit,
                                        index);
                                } catch (...) {
                                }
                            }
                            if (platform::cancellation::requested()) {
                                {
                                    std::lock_guard lock(state_mutex);
                                    cancelled = true;
                                }
                                request_window_stop();
                                return;
                            }
                            if (stop_requested.load(
                                    std::memory_order_acquire)) {
                                return;
                            }
                            auto audited = audit_object(
                                storage,
                                key,
                                inventory->referenced_objects[index],
                                *workspace,
                                index);
                            if (!audited) {
                                record_hard_failure(index,
                                                    std::move(audited.error()));
                                return;
                            }
                            std::size_t ticket = 0;
                            {
                                std::lock_guard lock(state_mutex);
                                const auto& reference =
                                    inventory->referenced_objects[index];
                                if (*audited != AuditState::Healthy) {
                                    unrecoverable.insert(
                                        unrecoverable.end(),
                                        reference.referenced_paths.begin(),
                                        reference.referenced_paths.end());
                                }
                                if (!on_progress) {
                                    return;
                                }
                                completed_sizes.push_back(reference.size);
                                ticket = completed_sizes.size();
                            }
                            progress_cv.notify_one();
                            std::unique_lock lock(state_mutex);
                            progress_ack_cv.wait(lock, [&] {
                                return acked_completions >= ticket ||
                                       progress_aborted;
                            });
                        } catch (const std::exception& exception) {
                            record_hard_failure(
                                index,
                                make_error(ErrorCode::StateFailure,
                                           exception.what()));
                        } catch (...) {
                            record_hard_failure(
                                index,
                                make_error(ErrorCode::StateFailure,
                                           "audit worker failed"));
                        }
                    });
            };

            if (on_progress) {
                std::jthread driver([&] {
                    run_workers();
                    {
                        std::lock_guard lock(state_mutex);
                        workers_done = true;
                    }
                    progress_cv.notify_one();
                });
                try {
                    std::size_t cursor = 0;
                    for (;;) {
                        std::vector<std::uint64_t> batch;
                        bool done = false;
                        {
                            std::unique_lock lock(state_mutex);
                            progress_cv.wait(lock, [&] {
                                return cursor < completed_sizes.size() ||
                                       workers_done;
                            });
                            done = workers_done &&
                                   cursor == completed_sizes.size();
                            while (cursor < completed_sizes.size()) {
                                batch.push_back(completed_sizes[cursor++]);
                            }
                        }
                        for (const std::uint64_t size : batch) {
                            ++completed_objects;
                            if (completed_plaintext_bytes) {
                                if (size >
                                    std::numeric_limits<std::uint64_t>::max() -
                                        *completed_plaintext_bytes) {
                                    completed_plaintext_bytes.reset();
                                } else {
                                    *completed_plaintext_bytes += size;
                                }
                            }
                            report_progress(
                                application::FsckStage::AuditingContent);
                            {
                                std::lock_guard lock(state_mutex);
                                ++acked_completions;
                            }
                            progress_ack_cv.notify_all();
                        }
                        if (done) {
                            break;
                        }
                    }
                } catch (...) {
                    {
                        std::lock_guard lock(state_mutex);
                        progress_aborted = true;
                    }
                    request_window_stop();
                    progress_ack_cv.notify_all();
                    throw;
                }
            } else {
                run_workers();
            }

            request_window_stop();
            report_progress(application::FsckStage::Finalizing);

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
    platform::cleanup_workspace(*workspace);
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
