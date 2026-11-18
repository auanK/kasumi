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
#include "crypto/key_derivation.hpp"
#include "crypto/pack.hpp"
#include "platform/cancellation.hpp"
#include "platform/clock.hpp"
#include "platform/path.hpp"
#include "platform/workspace.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
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
#include <unordered_map>
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

struct PhysicalAuditUnit {
    std::string remote_id;
    std::string plaintext_hash_hex;
    std::optional<std::uint64_t> expected_size;
    bool is_pack = false;
    std::once_flag once;
    std::expected<AuditState, Error> outcome{AuditState::Healthy};
};

std::expected<AuditState, Error>
audit_physical_unit(transport::Transport& storage,
                    KeySpan key,
                    const PhysicalAuditUnit& unit,
                    std::string_view logical_identifier,
                    const platform::Workspace& workspace,
                    std::size_t sequence) {
    auto audited = history_storage::audit_content_object(
        storage,
        key,
        unit.remote_id,
        unit.plaintext_hash_hex,
        unit.expected_size,
        workspace.root,
        sequence,
        unit.is_pack);
    if (!audited) {
        const auto code =
            audited.error().code == history_storage::ErrorCode::TransportFailure
                ? ErrorCode::TransportFailure
                : ErrorCode::WorkspaceFailure;
        return std::unexpected(make_error(
            code,
            audited.error().detail,
            code == ErrorCode::TransportFailure
                ? std::optional<std::string>{std::string{logical_identifier}}
                : std::nullopt));
    }
    if (audited->state == history_storage::ContentObjectState::Missing) {
        return AuditState::Missing;
    }
    if (audited->state == history_storage::ContentObjectState::Corrupt) {
        return AuditState::Corrupt;
    }
    return AuditState::Healthy;
}

std::expected<AuditState, Error>
audit_object(transport::Transport& storage,
             KeySpan key,
             const kasumi::maintenance::ObjectReference& reference,
             std::span<PhysicalAuditUnit* const> units,
             std::span<const std::size_t> unit_sequences,
             const platform::Workspace& workspace) {
    AuditState combined = AuditState::Healthy;
    for (std::size_t i = 0; i < units.size(); ++i) {
        PhysicalAuditUnit* unit = units[i];
        const std::size_t seq = unit_sequences[i];
        std::call_once(unit->once, [&]() {
            unit->outcome = audit_physical_unit(
                storage, key, *unit, reference.identifier, workspace, seq);
        });
        if (!unit->outcome) {
            return std::unexpected(unit->outcome.error());
        }
        if (*unit->outcome == AuditState::Corrupt) {
            return AuditState::Corrupt;
        }
        if (*unit->outcome == AuditState::Missing) {
            combined = AuditState::Missing;
        }
    }
    return combined;
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

            std::deque<PhysicalAuditUnit> physical_units;
            std::unordered_map<std::string, std::size_t> unit_index_by_id;
            std::vector<std::vector<std::size_t>> ref_unit_indices(total_objects);

            for (std::size_t i = 0; i < total_objects; ++i) {
                const auto& ref = inventory->referenced_objects[i];
                const auto logical_hash = hash_from_hex(ref.identifier);
                if (!logical_hash) {
                    return std::unexpected(
                        make_error(ErrorCode::IntegrityFailure,
                                   "invalid content identifier"));
                }
                const auto add_unit = [&](std::string remote_id,
                                          std::string plaintext_hex,
                                          std::optional<std::uint64_t> exp_size,
                                          bool is_pack) {
                    auto [it, inserted] = unit_index_by_id.try_emplace(
                        remote_id, physical_units.size());
                    if (inserted) {
                        auto& added = physical_units.emplace_back();
                        added.remote_id = std::move(remote_id);
                        added.plaintext_hash_hex = std::move(plaintext_hex);
                        added.expected_size = exp_size;
                        added.is_pack = is_pack;
                    }
                    ref_unit_indices[i].push_back(it->second);
                };
                if (const auto* packed = history::find_packed_blob(
                        storage_state.storage_manifest, *logical_hash)) {
                    add_unit(crypto::pack_identifier(key, packed->pack_hash),
                             hash_hex(packed->pack_hash),
                             std::nullopt,
                             true);
                } else if (const auto* chunked = history::find_chunked_file(
                               storage_state.storage_manifest,
                               *logical_hash)) {
                    for (const auto& chunk : chunked->chunks) {
                        add_unit(crypto::content_identifier(key, chunk.hash),
                                 hash_hex(chunk.hash),
                                 chunk.size,
                                 false);
                    }
                } else {
                    add_unit(crypto::content_identifier(key, *logical_hash),
                             ref.identifier,
                             ref.size,
                             false);
                }
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
            std::vector<std::uint64_t> completed_sizes;
            bool workers_done = false;

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
                            const auto& unit_idxs = ref_unit_indices[index];
                            std::vector<PhysicalAuditUnit*> unit_ptrs;
                            unit_ptrs.reserve(unit_idxs.size());
                            for (const auto u : unit_idxs) {
                                unit_ptrs.push_back(&physical_units[u]);
                            }
                            auto audited = audit_object(
                                storage,
                                key,
                                inventory->referenced_objects[index],
                                unit_ptrs,
                                unit_idxs,
                                *workspace);
                            if (!audited) {
                                record_hard_failure(index,
                                                    std::move(audited.error()));
                                return;
                            }
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
                            }
                            progress_cv.notify_one();
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
                        }
                        if (done) {
                            break;
                        }
                    }
                } catch (...) {
                    request_window_stop();
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
