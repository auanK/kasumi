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
#include "crypto/secure_memory.hpp"
#include "platform/cancellation.hpp"
#include "platform/clock.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "platform/workspace.hpp"

#include <algorithm>
#include <atomic>
#include <blake3.h>
#include <deque>
#include <exception>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <limits>
#include <mutex>
#include <optional>
#include <ranges>
#include <semaphore>
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
    std::filesystem::path retained_chunk;
    std::atomic<std::size_t> remaining_uses{0};
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
        unit.is_pack,
        unit.retained_chunk.empty() ? nullptr : &unit.retained_chunk);
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
             const history::ChunkedFileEntry* chunked,
             const platform::Workspace& workspace) {
    struct ReleaseChunks {
        std::span<PhysicalAuditUnit* const> pending;
        void release_one() {
            auto* unit = pending.front();
            pending = pending.subspan(1);
            if (!unit->retained_chunk.empty() &&
                unit->remaining_uses.fetch_sub(1) == 1) {
                std::error_code ignored;
                std::filesystem::remove(unit->retained_chunk, ignored);
            }
        }
        ~ReleaseChunks() {
            while (!pending.empty()) {
                release_one();
            }
        }
    } release{units};

    std::vector<std::uint8_t> buffer(chunked != nullptr ? 256U * 1024U : 0U);
    crypto::secure_memory::WipeGuard wipe_buffer{buffer};
    blake3_hasher hasher{};
    blake3_hasher_init(&hasher);
    crypto::secure_memory::WipeGuard wipe_hasher{hasher};

    AuditState combined = AuditState::Healthy;
    std::uint64_t size = 0;
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
        if (combined == AuditState::Healthy && chunked != nullptr) {
            const auto streamed = platform::private_storage::stream_regular_file(
                unit->retained_chunk,
                buffer,
                [&](std::span<const std::uint8_t> slab) {
                    blake3_hasher_update(&hasher, slab.data(), slab.size());
                },
                chunked->chunks[i].size);
            if (!streamed) {
                if (streamed.error().kind ==
                    platform::private_storage::StreamErrorKind::SizeMismatch) {
                    return AuditState::Corrupt;
                }
                return std::unexpected(make_error(ErrorCode::WorkspaceFailure,
                                                  streamed.error().detail));
            }
            if (*streamed > reference.size - size) {
                return AuditState::Corrupt;
            }
            size += *streamed;
        }
        release.release_one();
    }
    if (combined == AuditState::Healthy && chunked != nullptr) {
        Hash digest{};
        blake3_hasher_finalize(&hasher,
                               reinterpret_cast<std::uint8_t*>(digest.data()),
                               digest.size());
        if (size != reference.size || hash_hex(digest) != reference.identifier) {
            return AuditState::Corrupt;
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
    transport::TransferMetrics metrics;
    struct RestoreMetrics {
        transport::Transport& storage;
        transport::TransferMetrics* previous;
        ~RestoreMetrics() {
            storage.metrics = previous;
        }
    } restore{storage, storage.metrics};
    if (on_progress) {
        storage.metrics = &metrics;
    }
    std::atomic<std::uint64_t> files_reassembled{0};
    std::uint64_t last_wire_bytes = 0;
    std::size_t physical_objects = 0;
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
            last_wire_bytes =
                metrics.download.bytes.load(std::memory_order_relaxed);
            const auto total = metrics.download.known_total_bytes.load(
                std::memory_order_relaxed);
            const auto known_objects =
                metrics.download.known_total_objects.load(
                    std::memory_order_relaxed);
            on_progress(application::FsckProgress{
                .stage = stage,
                .completed_objects = completed_objects,
                .total_objects = progress_total_objects,
                .completed_plaintext_bytes = completed_plaintext_bytes,
                .total_plaintext_bytes = total_plaintext_bytes,
                .wire_download_bytes = last_wire_bytes,
                .total_wire_bytes = total >= last_wire_bytes && total > 0 &&
                                            known_objects >= physical_objects
                                        ? std::optional<std::uint64_t>{total}
                                        : std::nullopt,
                .physical_objects_downloaded =
                    metrics.download.objects.load(std::memory_order_relaxed),
                .files_reassembled =
                    files_reassembled.load(std::memory_order_relaxed),
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
            std::vector<const history::ChunkedFileEntry*> ref_chunks(total_objects);

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
                                          bool is_pack,
                                          bool retain_chunk = false) {
                    auto [it, inserted] = unit_index_by_id.try_emplace(
                        remote_id, physical_units.size());
                    if (inserted) {
                        auto& added = physical_units.emplace_back();
                        added.remote_id = std::move(remote_id);
                        added.plaintext_hash_hex = std::move(plaintext_hex);
                        added.expected_size = exp_size;
                        added.is_pack = is_pack;
                    }
                    auto& unit = physical_units[it->second];
                    ++unit.remaining_uses;
                    if (retain_chunk && unit.retained_chunk.empty()) {
                        unit.retained_chunk = workspace->root /
                            ("fsck-chunk-" + std::to_string(it->second) + ".plain");
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
                    ref_chunks[i] = chunked;
                    for (const auto& chunk : chunked->chunks) {
                        add_unit(crypto::content_identifier(key, chunk.hash),
                                 hash_hex(chunk.hash),
                                 chunk.size,
                                 false,
                                 true);
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

            physical_objects = physical_units.size();
            struct CompletedObject {
                std::uint64_t size = 0;
                std::atomic<bool> ready{false};
            };
            std::counting_semaphore<> progress_signal{0};
            std::vector<CompletedObject> completed(on_progress ? total_objects
                                                               : 0);
            std::atomic<std::size_t> next_completion{0};
            std::atomic<bool> workers_done{false};

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
                                ref_chunks[index],
                                *workspace);
                            if (!audited) {
                                record_hard_failure(index,
                                                    std::move(audited.error()));
                                return;
                            }
                            if (platform::cancellation::requested()) {
                                request_window_stop();
                                return;
                            }
                            if (ref_chunks[index] &&
                                *audited == AuditState::Healthy) {
                                files_reassembled.fetch_add(
                                    1, std::memory_order_relaxed);
                            }
                            const auto& reference =
                                inventory->referenced_objects[index];
                            if (*audited != AuditState::Healthy) {
                                std::lock_guard lock(state_mutex);
                                unrecoverable.insert(
                                    unrecoverable.end(),
                                    reference.referenced_paths.begin(),
                                    reference.referenced_paths.end());
                            }
                            if (on_progress) {
                                auto& completion =
                                    completed[next_completion.fetch_add(
                                        1, std::memory_order_relaxed)];
                                completion.size = reference.size;
                                completion.ready.store(
                                    true, std::memory_order_release);
                                progress_signal.release();
                            }
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
                    workers_done.store(true, std::memory_order_release);
                    progress_signal.release();
                });
                try {
                    std::size_t cursor = 0;
                    const auto ready = [&] {
                        return cursor < completed.size() &&
                               completed[cursor].ready.load(
                                   std::memory_order_acquire);
                    };
                    for (;;) {
                        while (ready()) {
                            const auto size = completed[cursor++].size;
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
                        if (workers_done.load(std::memory_order_acquire)) {
                            if (ready()) {
                                continue;
                            }
                            break;
                        }
                        if (!progress_signal.try_acquire_for(
                                std::chrono::milliseconds(200)) &&
                            metrics.download.bytes.load(
                                std::memory_order_relaxed) != last_wire_bytes) {
                            report_progress(
                                application::FsckStage::AuditingContent);
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
