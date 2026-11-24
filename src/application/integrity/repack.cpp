#include "application/integrity/repack.hpp"

#include "application/concurrency.hpp"
#include "application/history_storage/history_storage.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/observation/state.hpp"
#include "application/progress.hpp"
#include "application/sync/coordinator.hpp"
#include "application/sync/journal.hpp"
#include "application/sync/mutation_batch.hpp"
#include "application/sync/mutation_detail.hpp"
#include "application/sync/publication.hpp"
#include "core/reconciliation/plan.hpp"
#include "crypto/pack.hpp"
#include "platform/cancellation.hpp"
#include "platform/clock.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "platform/workspace.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

namespace kasumi::application::integrity::repack {
namespace {

namespace protocol = application::history_storage::maintenance_protocol;

integrity::Error make_error(integrity::ErrorCode code, std::string detail) {
    return integrity::Error{.code = code, .detail = std::move(detail)};
}

integrity::Error cancelled_error() {
    return make_error(integrity::ErrorCode::TransportFailure,
                      "operation cancelled by user");
}

integrity::Error map_protocol_error(const protocol::Error& err) {
    integrity::ErrorCode code = integrity::ErrorCode::IntegrityFailure;
    switch (err.code) {
        case protocol::ErrorCode::InvalidInput:
            code = integrity::ErrorCode::InvalidInput;
            break;
        case protocol::ErrorCode::WorkspaceFailure:
            code = integrity::ErrorCode::WorkspaceFailure;
            break;
        case protocol::ErrorCode::TransportFailure:
            code = integrity::ErrorCode::TransportFailure;
            break;
        case protocol::ErrorCode::VerificationFailure:
        case protocol::ErrorCode::Blocked:
            code = integrity::ErrorCode::ConcurrentChange;
            break;
        case protocol::ErrorCode::BackendUnsafe:
            code = integrity::ErrorCode::Unrecoverable;
            break;
        case protocol::ErrorCode::InvalidControlObject:
            code = integrity::ErrorCode::IntegrityFailure;
            break;
    }
    auto out = make_error(code, err.detail);
    out.transport_failure = err.transport_failure;
    return out;
}

integrity::Error map_history_error(const history_storage::Error& err) {
    integrity::ErrorCode code = integrity::ErrorCode::IntegrityFailure;
    switch (err.code) {
        case history_storage::ErrorCode::InvalidInput:
        case history_storage::ErrorCode::InvalidIdentifier:
            code = integrity::ErrorCode::InvalidInput;
            break;
        case history_storage::ErrorCode::WorkspaceFailure:
            code = integrity::ErrorCode::WorkspaceFailure;
            break;
        case history_storage::ErrorCode::TransportFailure:
            code = integrity::ErrorCode::TransportFailure;
            break;
        case history_storage::ErrorCode::CryptoFailure:
            code = integrity::ErrorCode::CryptoFailure;
            break;
        default:
            code = integrity::ErrorCode::IntegrityFailure;
            break;
    }
    return make_error(code, err.detail);
}

integrity::Error map_mutation_error(const sync::mutation::MutationError& err) {
    integrity::ErrorCode code = integrity::ErrorCode::IntegrityFailure;
    switch (err.code) {
        case sync::mutation::MutationErrorCode::TransportFailure:
        case sync::mutation::MutationErrorCode::RemoteResultUnknown:
            code = integrity::ErrorCode::TransportFailure;
            break;
        case sync::mutation::MutationErrorCode::IntegrityMismatch:
        case sync::mutation::MutationErrorCode::DestinationConflict:
            code = integrity::ErrorCode::ConcurrentChange;
            break;
        case sync::mutation::MutationErrorCode::CryptoFailure:
            code = integrity::ErrorCode::CryptoFailure;
            break;
        case sync::mutation::MutationErrorCode::RemoteContentMissing:
            code = integrity::ErrorCode::IntegrityFailure;
            break;
        case sync::mutation::MutationErrorCode::LocalIo:
        case sync::mutation::MutationErrorCode::UnsafePath:
        case sync::mutation::MutationErrorCode::InvalidOperation:
            code = integrity::ErrorCode::StateFailure;
            break;
    }
    return make_error(code, err.detail);
}

struct ScopedMetrics {
    transport::Transport& storage;
    transport::TransferMetrics local_metrics{};
    bool attached_local = false;
    std::uint64_t initial_upload_bytes = 0;
    std::uint64_t initial_upload_objects = 0;

    explicit ScopedMetrics(transport::Transport& target) noexcept
        : storage(target) {
        if (storage.metrics == nullptr) {
            storage.metrics = &local_metrics;
            attached_local = true;
        }
        initial_upload_bytes =
            storage.metrics->upload.bytes.load(std::memory_order_relaxed);
        initial_upload_objects =
            storage.metrics->upload.objects.load(std::memory_order_relaxed);
    }

    ~ScopedMetrics() {
        if (attached_local) {
            storage.metrics = nullptr;
        }
    }
};

std::uint64_t uploaded_bytes_delta(const ScopedMetrics& scope) noexcept {
    if (scope.storage.metrics == nullptr) {
        return 0;
    }
    const auto now =
        scope.storage.metrics->upload.bytes.load(std::memory_order_relaxed);
    return now >= scope.initial_upload_bytes
               ? (now - scope.initial_upload_bytes)
               : 0;
}

std::uint64_t uploaded_objects_delta(const ScopedMetrics& scope) noexcept {
    if (scope.storage.metrics == nullptr) {
        return 0;
    }
    const auto now =
        scope.storage.metrics->upload.objects.load(std::memory_order_relaxed);
    return now >= scope.initial_upload_objects
               ? (now - scope.initial_upload_objects)
               : 0;
}

struct WriterGuard {
    protocol::RegistrationState state{};

    ~WriterGuard() noexcept {
        if (protocol::registration_active(state)) {
            static_cast<void>(protocol::release_registration(state));
        }
    }
};

struct WorkspaceGuard {
    std::optional<platform::Workspace> workspace;

    ~WorkspaceGuard() noexcept {
        if (workspace) {
            platform::cleanup_workspace(*workspace);
        }
    }
};

struct UploadBatchGuard {
    sync::mutation::StagedUploadBatch& batch;

    ~UploadBatchGuard() noexcept {
        if (!batch.root.empty()) {
            static_cast<void>(sync::mutation::cleanup_upload_batch(batch));
        }
    }
};

std::expected<void, integrity::Error> validate_clean_preconditions(
    const runtime::RuntimeData& runtime_data,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const std::filesystem::path& profile_dir,
    bool dry_run) {
    if (dry_run) {
        const auto paths = sync::journal::make_paths(profile_dir);
        if (!paths) {
            return std::unexpected(
                make_error(integrity::ErrorCode::StateFailure, paths.error()));
        }
        if (sync::journal::inspect(*paths, key) !=
            sync::journal::InspectionResult::Absent) {
            return std::unexpected(
                make_error(integrity::ErrorCode::StateFailure,
                           "complete the pending sync transaction before "
                           "repack"));
        }
        return {};
    }

    const auto recovery =
        sync::coordinator::recover_if_needed(runtime_data, storage, key);
    if (!recovery) {
        return std::unexpected(
            make_error(integrity::ErrorCode::StateFailure,
                       sync::coordinator::describe(recovery.error())));
    }
    if (*recovery == sync::coordinator::RecoveryResult::ResumableTransaction) {
        return std::unexpected(
            make_error(integrity::ErrorCode::StateFailure,
                       "complete the interrupted upload with sync before "
                       "repack"));
    }
    return {};
}

std::expected<void, integrity::Error>
verify_synchronized_state(reconciliation::Input& collected,
                          ProgressMeter* meter) {
    if (!collected.storage.history_present) {
        return std::unexpected(
            make_error(integrity::ErrorCode::StateFailure,
                       "remote history is empty; run sync first"));
    }
    if (!collected.base_state_present) {
        return std::unexpected(
            make_error(integrity::ErrorCode::StateFailure,
                       "local base state is missing; run sync first"));
    }
    if (collected.storage.history_has_conflicts ||
        collected.storage.logical_heads.size() != 1U) {
        return std::unexpected(
            make_error(integrity::ErrorCode::StateFailure,
                       "remote history has unresolved concurrent heads or "
                       "conflicts; run sync first"));
    }
    if (collected.base_commit_id != collected.storage.logical_heads.front() ||
        !collected.pending_materializations.empty()) {
        return std::unexpected(
            make_error(integrity::ErrorCode::StateFailure,
                       "local state is not synchronized with remote head; run "
                       "sync first"));
    }
    if (meter) {
        begin_progress_phase(*meter, Activity::ComparingSnapshots);
    }
    auto reconciled = reconciliation::reconcile(collected);
    if (!reconciled) {
        return std::unexpected(make_error(integrity::ErrorCode::StateFailure,
                                          reconciled.error().detail));
    }
    if (reconciled->requires_publication ||
        reconciled->requires_local_mutation ||
        reconciled->requires_storage_repair ||
        reconciled->requires_state_commit) {
        return std::unexpected(
            make_error(integrity::ErrorCode::StateFailure,
                       "workspace has pending local or remote changes; run "
                       "sync before repack"));
    }
    return {};
}

std::expected<std::vector<std::vector<crypto::pack::PackMemberSource>>,
              integrity::Error>
resolve_pack_sources(const std::filesystem::path& local_root,
                     const Snapshot& local_tree,
                     std::span<const PlannedPack> packs) {
    struct LocalSourceEntry {
        std::string path;
        std::uint64_t size = 0;
    };
    std::unordered_map<Hash, LocalSourceEntry, decltype(&hash_key)> by_hash{
        0, hash_key};
    by_hash.reserve(local_tree.rows.size());
    for (const auto& row : local_tree.rows) {
        if (row.is_directory || row.path == ".kasumiignore") {
            continue;
        }
        auto [it, inserted] = by_hash.emplace(
            row.hash, LocalSourceEntry{.path = row.path, .size = row.size});
        if (!inserted) {
            if (it->second.size != row.size) {
                return std::unexpected(make_error(
                    integrity::ErrorCode::StateFailure,
                    "local tree contains conflicting sizes for the same hash"));
            }
            if (path_less(row.path, it->second.path)) {
                it->second.path = row.path;
            }
        }
    }

    std::vector<std::vector<crypto::pack::PackMemberSource>> resolved_packs;
    resolved_packs.reserve(packs.size());
    for (std::size_t pack_idx = 0; pack_idx < packs.size(); ++pack_idx) {
        const auto& pack = packs[pack_idx];
        std::vector<crypto::pack::PackMemberSource> sources;
        sources.reserve(pack.members.size());
        for (const auto& member : pack.members) {
            const auto found = by_hash.find(member.hash);
            if (found == by_hash.end() || found->second.size != member.size) {
                return std::unexpected(
                    make_error(integrity::ErrorCode::StateFailure,
                               "required local file is missing for repack"));
            }
            auto physical = sync::mutation::detail::resolve_local_path(
                local_root,
                platform::path::from_utf8(found->second.path),
                pack_idx);
            if (!physical) {
                return std::unexpected(
                    make_error(integrity::ErrorCode::StateFailure,
                               physical.error().detail));
            }
            sources.push_back(crypto::pack::PackMemberSource{
                .hash = member.hash,
                .size = member.size,
                .source_path = std::move(*physical),
            });
        }
        resolved_packs.push_back(std::move(sources));
    }
    return resolved_packs;
}

std::expected<std::int64_t, integrity::Error>
choose_repack_commit_time(const reconciliation::StorageState& storage) {
    const auto local_now = platform::clock::unix_seconds();
    if (!local_now || *local_now <= 0) {
        return std::unexpected(make_error(integrity::ErrorCode::StateFailure,
                                          "invalid local commit timestamp"));
    }
    if (storage.logical_heads.empty()) {
        return std::unexpected(make_error(integrity::ErrorCode::StateFailure,
                                          "history has no logical head"));
    }
    const auto found = std::ranges::find(storage.reachable_commits,
                                         storage.logical_heads.front(),
                                         &history::LoadedCommit::id);
    if (found == storage.reachable_commits.end()) {
        return std::unexpected(
            make_error(integrity::ErrorCode::StateFailure,
                       "logical head missing from reachable commits"));
    }
    return std::max(*local_now, found->commit.created_at);
}

} // namespace

std::expected<Result, integrity::Error>
execute(const runtime::RuntimeData& runtime_data,
        transport::Transport& storage,
        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
        const Options& options,
        ProgressMeter* meter) {
    const auto started = std::chrono::steady_clock::now();
    if (platform::cancellation::requested()) {
        return std::unexpected(cancelled_error());
    }
    if (!transport::valid(storage)) {
        return std::unexpected(make_error(integrity::ErrorCode::InvalidInput,
                                          "invalid transport"));
    }
    if (runtime_data.local_dir.empty() || runtime_data.database_path.empty() ||
        runtime_data.database_path.parent_path().empty()) {
        return std::unexpected(make_error(integrity::ErrorCode::InvalidInput,
                                          "invalid profile runtime paths"));
    }

    const auto profile_dir = runtime_data.database_path.parent_path();
    ScopedMetrics metrics_scope{storage};

    if (auto pre = validate_clean_preconditions(
            runtime_data, storage, key, profile_dir, options.dry_run);
        !pre) {
        return std::unexpected(pre.error());
    }
    if (platform::cancellation::requested()) {
        return std::unexpected(cancelled_error());
    }

    observation::LocalObservationSession session;
    session.database_path = runtime_data.database_path;
    session.progress = meter;
    struct CacheDeltaGuard {
        const std::filesystem::path& db_path;
        observation::LocalObservationSession& session;
        bool persist;
        ~CacheDeltaGuard() noexcept {
            if (persist && session.cache_dirty) {
                static_cast<void>(state_storage::save_file_cache_delta(
                    db_path, session.cache));
            }
        }
    } cache_guard{runtime_data.database_path, session, !options.dry_run};

    if (meter) {
        begin_progress_phase(*meter, Activity::Scanning);
    }
    auto collected = observation::collect_reconciliation_input(
        runtime_data, storage, key, false, {}, &session);
    if (platform::cancellation::requested()) {
        return std::unexpected(cancelled_error());
    }
    if (!collected) {
        const auto code = collected.error().code ==
                                  reconciliation::ErrorCode::InvalidStorageTree
                              ? integrity::ErrorCode::TransportFailure
                              : integrity::ErrorCode::StateFailure;
        return std::unexpected(make_error(code, collected.error().detail));
    }

    if (auto clean = verify_synchronized_state(*collected, meter); !clean) {
        return std::unexpected(clean.error());
    }

    auto planned = plan(collected->storage.tree,
                        collected->storage.storage_manifest,
                        options.policy);
    if (!planned) {
        return std::unexpected(make_error(
            integrity::ErrorCode::IntegrityFailure, planned.error()));
    }
    if (options.dry_run || !planned->actionable) {
        return Result{
            .plan = std::move(*planned),
            .dry_run = options.dry_run,
            .published = false,
            .wire_upload_bytes = uploaded_bytes_delta(metrics_scope),
            .physical_objects_uploaded = uploaded_objects_delta(metrics_scope),
            .duration = std::chrono::steady_clock::now() - started,
        };
    }

    auto pack_sources = resolve_pack_sources(
        runtime_data.local_dir, collected->local_tree, planned->new_packs);
    if (!pack_sources) {
        return std::unexpected(pack_sources.error());
    }

    const auto layout = history_storage::derive_remote_layout(key);
    if (meter) {
        begin_progress_phase(*meter, Activity::PreparingRemote);
    }
    auto registered = protocol::register_writer(storage, layout, profile_dir);
    if (!registered) {
        return std::unexpected(map_protocol_error(registered.error()));
    }
    WriterGuard writer_guard{.state = std::move(*registered)};

    auto workspace = platform::create_workspace("repack");
    if (!workspace) {
        return std::unexpected(make_error(
            integrity::ErrorCode::WorkspaceFailure, workspace.error()));
    }
    WorkspaceGuard workspace_guard{.workspace = std::move(*workspace)};

    const std::size_t parallelism = std::max<std::size_t>(
        1U,
        options.max_parallelism > 0 ? options.max_parallelism
                                    : application::content_concurrency());
    const std::size_t window_packs = options.upload_window_packs > 0
                                         ? options.upload_window_packs
                                         : DEFAULT_UPLOAD_WINDOW_PACKS;
    const std::size_t total_packs = planned->new_packs.size();

    for (std::size_t offset = 0; offset < total_packs;) {
        if (platform::cancellation::requested()) {
            return std::unexpected(cancelled_error());
        }
        const std::size_t count = std::min(window_packs, total_packs - offset);

        sync::mutation::StagedUploadBatch batch;
        batch.root = workspace_guard.workspace->root / "packs";
        if (auto dir_ok =
                platform::private_storage::ensure_directory(batch.root);
            !dir_ok) {
            return std::unexpected(make_error(
                integrity::ErrorCode::WorkspaceFailure, dir_ok.error()));
        }
        UploadBatchGuard batch_guard{batch};
        batch.objects.resize(count);

        if (meter) {
            begin_progress_phase(*meter, Activity::Staging, count);
        }
        std::vector<std::optional<integrity::Error>> stage_errors(count);
        application::parallel_for_indexed(
            count, std::min(parallelism, count), [&](std::size_t slot) {
                if (platform::cancellation::requested()) {
                    stage_errors[slot] = cancelled_error();
                    return;
                }
                const std::size_t idx = offset + slot;
                const auto& planned_pack = planned->new_packs[idx];
                const auto pack_id =
                    crypto::pack_identifier(key, planned_pack.pack_hash);
                const auto dest =
                    batch.root / platform::path::from_utf8(pack_id);
                auto res = crypto::pack::write_encrypted_pack(
                    (*pack_sources)[idx], dest, key);
                if (!res) {
                    const bool local_changed =
                        res.error().find("changed") != std::string::npos ||
                        res.error().find("mismatch") != std::string::npos ||
                        res.error().find("missing") != std::string::npos;
                    stage_errors[slot] = make_error(
                        local_changed ? integrity::ErrorCode::ConcurrentChange
                                      : integrity::ErrorCode::CryptoFailure,
                        res.error());
                    return;
                }
                if (res->pack_hash != planned_pack.pack_hash) {
                    stage_errors[slot] =
                        make_error(integrity::ErrorCode::IntegrityFailure,
                                   "staged pack identifier mismatch");
                    return;
                }
                if (meter) {
                    record_progress_staged(
                        *meter, dest, res->pack_plaintext_size);
                }
                batch.objects[slot] = sync::mutation::StagedUploadObject{
                    .identifier = pack_id,
                    .plaintext_hash = hash_hex(res->pack_hash),
                    .plaintext_size = res->pack_plaintext_size,
                    .ciphertext_sha256 = std::move(res->ciphertext_sha256),
                    .operation_indices = {idx},
                    .is_pack = true,
                };
            });

        for (const auto& err : stage_errors) {
            if (err) {
                return std::unexpected(*err);
            }
        }
        if (platform::cancellation::requested()) {
            return std::unexpected(cancelled_error());
        }

        if (auto admission =
                protocol::verify_writer_admission(writer_guard.state, layout);
            !admission) {
            return std::unexpected(map_protocol_error(admission.error()));
        }

        if (meter) {
            begin_progress_phase(
                *meter, Activity::Uploading, batch.objects.size());
        }
        auto transferred =
            sync::mutation::transfer_upload_batch(batch, storage, parallelism);
        const bool transfer_unknown =
            !transferred &&
            transferred.error().code ==
                sync::mutation::MutationErrorCode::RemoteResultUnknown;
        if (!transferred && !transfer_unknown) {
            return std::unexpected(map_mutation_error(transferred.error()));
        }
        if (platform::cancellation::requested()) {
            return std::unexpected(cancelled_error());
        }

        if (meter) {
            begin_progress_phase(
                *meter, Activity::Verifying, batch.objects.size());
        }
        if (auto verified =
                sync::mutation::verify_upload_batch(batch,
                                                    storage,
                                                    key,
                                                    *workspace_guard.workspace,
                                                    parallelism,
                                                    meter);
            !verified) {
            return std::unexpected(map_mutation_error(verified.error()));
        }

        if (auto cleaned = sync::mutation::cleanup_upload_batch(batch);
            !cleaned) {
            return std::unexpected(map_mutation_error(cleaned.error()));
        }
        batch.root.clear();
        offset += count;
    }

    if (platform::cancellation::requested()) {
        return std::unexpected(cancelled_error());
    }
    if (auto admission =
            protocol::verify_writer_admission(writer_guard.state, layout);
        !admission) {
        return std::unexpected(map_protocol_error(admission.error()));
    }

    auto current_heads =
        sync::publication::list_remote_head_commit_ids(storage, layout);
    if (!current_heads) {
        return std::unexpected(map_history_error(current_heads.error()));
    }
    const auto& expected_head = collected->storage.logical_heads.front();
    auto observed_marked = collected->storage.marked_heads;
    std::ranges::sort(observed_marked);
    if (!std::ranges::binary_search(*current_heads, expected_head) ||
        !std::ranges::includes(observed_marked, *current_heads)) {
        return std::unexpected(
            make_error(integrity::ErrorCode::ConcurrentChange,
                       "remote history changed concurrently during repack; "
                       "run sync and retry"));
    }

    const auto created_at = choose_repack_commit_time(collected->storage);
    if (!created_at) {
        return std::unexpected(created_at.error());
    }
    auto prepared =
        sync::publication::prepare_commit(collected->storage.tree,
                                          true,
                                          collected->storage.generation,
                                          collected->storage.logical_heads,
                                          *created_at,
                                          key,
                                          planned->target_manifest,
                                          options.authorship);
    if (!prepared) {
        return std::unexpected(map_history_error(prepared.error()));
    }

    auto published_obj = sync::publication::publish_commit_object(
        storage, layout, key, *prepared, workspace_guard.workspace->root);
    if (!published_obj) {
        return std::unexpected(map_history_error(published_obj.error()));
    }
    if (auto verified_obj = sync::publication::verify_commit_object(
            storage,
            layout,
            key,
            *prepared,
            published_obj->head,
            workspace_guard.workspace->root,
            published_obj->physical_hash);
        !verified_obj) {
        return std::unexpected(map_history_error(verified_obj.error()));
    }
    auto published_head = sync::publication::publish_head_marker(
        storage, layout, published_obj->head, workspace_guard.workspace->root);
    if (!published_head) {
        return std::unexpected(map_history_error(published_head.error()));
    }
    if (auto verified_head = sync::publication::verify_head_marker(
            storage,
            layout,
            published_obj->head,
            workspace_guard.workspace->root,
            published_head->physical_hash);
        !verified_head) {
        return std::unexpected(map_history_error(verified_head.error()));
    }

    if (!state_storage::save_state(
            runtime_data.database_path,
            state_storage::StoredState{
                .tree = prepared->commit.tree,
                .height = prepared->commit.height,
                .commit_id = prepared->commit_id,
                .ciphertext_id = published_obj->head.ciphertext_id,
                .epoch_id = collected->storage.epoch_id,
                .epoch_sequence = collected->storage.epoch_sequence,
                .pending_materializations = {},
                .storage_manifest = prepared->commit.storage,
            },
            sync::publication::make_accepted_commit_meta(prepared->commit_id,
                                                         prepared->commit))) {
        return std::unexpected(
            make_error(integrity::ErrorCode::StateFailure,
                       "repack published remote commit but failed to update "
                       "local database"));
    }

    auto cleanup_ids = prepared->commit.parents;
    cleanup_ids.insert(cleanup_ids.end(),
                       collected->storage.ancestral_marked_heads.begin(),
                       collected->storage.ancestral_marked_heads.end());
    std::size_t pruned_markers = 0;
    if (auto post_prune = sync::publication::prune_observed_parent_markers(
            storage,
            layout,
            cleanup_ids,
            collected->storage.marked_head_identifiers);
        post_prune) {
        pruned_markers = post_prune->removed_markers;
    }

    if (auto released = protocol::release_registration(writer_guard.state);
        !released) {
        return std::unexpected(map_protocol_error(released.error()));
    }

    return Result{
        .plan = std::move(*planned),
        .dry_run = false,
        .published = true,
        .published_commit_id = std::move(prepared->commit_id),
        .published_height = prepared->commit.height,
        .pruned_markers = pruned_markers,
        .wire_upload_bytes = uploaded_bytes_delta(metrics_scope),
        .physical_objects_uploaded = uploaded_objects_delta(metrics_scope),
        .duration = std::chrono::steady_clock::now() - started,
    };
}

} // namespace kasumi::application::integrity::repack
