#include "application/sync/coordinator.hpp"

#include "application/concurrency.hpp"
#include "application/history_storage/content_reachability.hpp"
#include "application/progress.hpp"
#include "application/sync/mutation.hpp"
#include "application/sync/mutation_batch.hpp"
#include "application/sync/mutation_detail.hpp"
#include "coordinator_detail.hpp"
#include "core/hasher.hpp"
#include "core/history.hpp"
#include "core/transaction/types.hpp"
#include "crypto/content.hpp"
#include "crypto/pack.hpp"
#include "platform/cancellation.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "platform/private_storage.hpp"
#include "platform/workspace.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace kasumi::application::sync::coordinator {
namespace {

using detail::PlannedChunkUpload;
using detail::PlannedPack;
using detail::PlannedSmallUpload;
using detail::UploadLayoutPlan;
using detail::mutation_error;
using detail::next_chunk_window;
using detail::pack_upload_window_size;

std::filesystem::path
resolve_pre_mutation_source_path(const std::filesystem::path& local_root,
                                 const kasumi::Operation& operation,
                                 const Hash& expected_hash,
                                 const Snapshot& observed_local_tree,
                                 std::size_t op_index) {
    auto resolved =
        mutation::detail::resolve_local_path(local_root, operation.path, op_index);
    if (resolved) {
        std::error_code ec;
        const auto status = std::filesystem::symlink_status(*resolved, ec);
        if (!ec && !std::filesystem::is_symlink(status) &&
            !platform::private_storage::is_reparse_or_symlink(*resolved) &&
            std::filesystem::is_regular_file(status)) {
            return *resolved;
        }
    }
    for (const auto& row : observed_local_tree.rows) {
        if (!row.is_directory && row.hash == expected_hash &&
            row.size == operation.size) {
            auto candidate = mutation::detail::resolve_local_path(
                local_root, platform::path::from_utf8(row.path), op_index);
            if (candidate) {
                return *candidate;
            }
        }
    }
    return resolved ? *resolved : (local_root / operation.path);
}

using RepairOperations =
    std::unordered_map<Hash, std::vector<std::size_t>, decltype(&hash_key)>;

std::expected<void, Error>
plan_manifest_repairs(UploadLayoutPlan& layout,
                      const history::StorageManifest& manifest,
                      const transaction::Record& record,
                      const RepairOperations& repair_ops_by_hash,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    HashSet handled_packs{0, hash_key};
    std::optional<std::size_t> incomplete_pack;
    for (const auto& [op_hash, indices] : repair_ops_by_hash) {
        if (const auto* chunked =
                history::find_chunked_file(manifest, op_hash)) {
            PlannedChunkUpload upload{
                .file_hash = chunked->file_hash,
                .file_size = chunked->file_size,
                .primary_op_index = indices.front(),
                .chunks = {},
                .operation_indices = indices,
            };
            upload.chunks.reserve(chunked->chunks.size());
            std::uint64_t offset = 0;
            for (const auto& c : chunked->chunks) {
                upload.chunks.push_back(crypto::pack::FastCdcChunk{
                    .hash = c.hash,
                    .offset = offset,
                    .size = c.size,
                });
                offset += c.size;
            }
            layout.chunked_uploads.push_back(std::move(upload));
        } else if (const auto* packed =
                       history::find_packed_blob(manifest, op_hash)) {
            if (!handled_packs.insert(packed->pack_hash).second) {
                continue;
            }
            PlannedPack pack{.pack_hash = packed->pack_hash,
                             .pack_identifier = crypto::pack_identifier(
                                 key, packed->pack_hash),
                             .blobs = {},
                             .operation_indices = {}};
            std::vector<crypto::pack::PackMemberDescriptor> descriptors;
            bool complete = true;
            auto first_pack_operation = indices.front();
            for (const auto& entry : manifest.packed_blobs) {
                if (entry.pack_hash != packed->pack_hash) {
                    continue;
                }
                const auto found = repair_ops_by_hash.find(entry.blob_hash);
                if (found == repair_ops_by_hash.end()) {
                    complete = false;
                    continue;
                }
                const auto op_index = found->second.front();
                first_pack_operation = std::min(first_pack_operation, op_index);
                if (record.plan.operations[op_index].size != entry.size) {
                    complete = false;
                    continue;
                }
                descriptors.push_back(
                    {entry.blob_hash, static_cast<std::uint32_t>(entry.size)});
                pack.blobs.push_back(PlannedSmallUpload{
                    .hash = entry.blob_hash,
                    .size = static_cast<std::uint32_t>(entry.size),
                    .op_index = op_index,
                });
                pack.operation_indices.insert(pack.operation_indices.end(),
                                              found->second.begin(),
                                              found->second.end());
            }
            if (complete && crypto::pack::compute_pack_hash(descriptors) ==
                                packed->pack_hash) {
                std::ranges::sort(pack.operation_indices);
                layout.packs.push_back(std::move(pack));
            } else {
                incomplete_pack =
                    std::min(incomplete_pack.value_or(first_pack_operation),
                             first_pack_operation);
            }
        }
    }
    if (incomplete_pack) {
        return std::unexpected(detail::make_error(
            ErrorCode::MutationFailure,
            "cannot reconstruct the original absent pack from local sources",
            incomplete_pack));
    }
    return {};
}

} // namespace

std::expected<void, detail::UploadBatchError> detail::transfer_and_verify_upload_batch(
    const mutation::StagedUploadBatch& batch,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const platform::Workspace& workspace,
    std::size_t parallelism,
    ProgressMeter* meter,
    const std::filesystem::path* item,
    std::string_view progress_identifier) {
    const auto* single = progress_identifier.empty() ? item : nullptr;
    if (meter)
        meter->phase(Activity::Uploading, batch.objects.size(), 0, single);
    transport::TransportProgressCallback progress;
    if (meter && item && !progress_identifier.empty() && meter->observing()) {
        progress = [meter, item](const auto& event) {
            meter->transfer_item(*item, event.item);
        };
    }
    auto transferred = mutation::transfer_upload_batch(
        batch,
        storage,
        parallelism,
        progress ? progress_identifier : std::string_view{},
        progress);
    const bool transfer_unknown =
        !transferred && transferred.error().code ==
                            mutation::MutationErrorCode::RemoteResultUnknown;
    if (!transferred && !transfer_unknown) {
        return std::unexpected(detail::UploadBatchError{
            .transport_after_unknown_transfer = false,
            .mutation = std::move(transferred.error()),
        });
    }
    if (meter)
        meter->phase(Activity::Verifying, batch.objects.size(), 0, single);
    auto verified = mutation::verify_upload_batch(
        batch, storage, key, workspace, parallelism, meter);
    if (!verified) {
        return std::unexpected(detail::UploadBatchError{
            .transport_after_unknown_transfer =
                transfer_unknown &&
                verified.error().code ==
                    mutation::MutationErrorCode::TransportFailure,
            .mutation = std::move(verified.error()),
        });
    }
    return {};
}

std::expected<bool, Error>
detail::verify_existing_content(transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        std::string_view identifier,
                        std::string_view plaintext_hash,
                        std::optional<std::uint64_t> size,
                        const platform::Workspace& workspace,
                        std::size_t operation_index,
                        bool is_pack) {
    const auto checked = history_storage::audit_content_object(storage,
                                                               key,
                                                               identifier,
                                                               plaintext_hash,
                                                               size,
                                                               workspace.root,
                                                               operation_index,
                                                               is_pack);
    if (!checked) {
        return std::unexpected(
            detail::make_error(ErrorCode::ObservationFailure,
                       "could not authenticate existing content: " +
                           checked.error().detail,
                       operation_index));
    }
    return checked->state == history_storage::ContentObjectState::Present;
}

std::expected<UploadLayoutPlan, Error>
detail::build_upload_layout_plan(const runtime::RuntimeData& runtime_data,
                         const transport::Transport& storage,
                         std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                         const reconciliation::Input& observed_input,
                         const reconciliation::Result& reconciliation_result,
                         const transaction::Record& record,
                         const std::vector<bool>& content_upload_required,
                         bool enable_micro_packs) {
    UploadLayoutPlan layout;

    const auto& observed_manifest = observed_input.storage.storage_manifest;
    const auto& missing = reconciliation_result.missing_objects;
    RepairOperations repair_ops_by_hash{0, hash_key};
    if (!observed_manifest.empty() && !missing.empty()) {
        for (std::size_t index = 0; index < record.plan.operations.size();
             ++index) {
            const auto& op = record.plan.operations[index];
            if (op.action == Action::Upload && content_upload_required[index]) {
                if (const auto h = hash_from_hex(op.hash);
                    h && missing.contains(*h)) {
                    repair_ops_by_hash[*h].push_back(index);
                }
            }
        }
    }

    const auto& ref_tree = record.publication_required
                               ? reconciliation_result.candidate_shared_tree
                               : observed_input.storage.tree;
    std::unordered_map<Hash, std::uint64_t, decltype(&hash_key)> live_files{
        0, hash_key};
    live_files.reserve(ref_tree.rows.size());
    for (const auto& row : ref_tree.rows) {
        if (row.is_directory) {
            continue;
        }
        if (missing.contains(row.hash)) {
            if (record.publication_required &&
                history::find_packed_blob(observed_manifest, row.hash) &&
                !repair_ops_by_hash.contains(row.hash)) {
                return std::unexpected(detail::make_error(
                    ErrorCode::MutationFailure,
                    "cannot replace an absent pack without a local source for " +
                        row.path));
            }
        } else if (row.path != ".kasumiignore") {
            live_files.emplace(row.hash, row.size);
        }
    }

    for (const auto& entry : observed_input.storage.storage_manifest.packed_blobs) {
        const auto found = live_files.find(entry.blob_hash);
        if (found != live_files.end() && found->second == entry.size) {
            layout.target_manifest.packed_blobs.push_back(entry);
        }
    }
    for (const auto& entry :
         observed_input.storage.storage_manifest.chunked_files) {
        const auto found = live_files.find(entry.file_hash);
        if (found != live_files.end() && found->second == entry.file_size) {
            layout.target_manifest.chunked_files.push_back(entry);
        }
    }

    if (record.publication_required && enable_micro_packs) {
        std::vector<PlannedSmallUpload> small_candidates;
        HashSet seen_upload{0, hash_key};
        for (std::size_t index = 0; index < record.plan.operations.size();
             ++index) {
            const auto& op = record.plan.operations[index];
            if (op.action != Action::Upload || !content_upload_required[index] ||
                platform::path::to_logical_utf8(op.path) == ".kasumiignore") {
                continue;
            }
            const auto op_hash = hash_from_hex(op.hash);
            if (!op_hash || !seen_upload.insert(*op_hash).second) {
                continue;
            }
            if (history::find_packed_blob(layout.target_manifest, *op_hash) ||
                history::find_chunked_file(layout.target_manifest, *op_hash)) {
                continue;
            }

            if (op.size > crypto::pack::FASTCDC_FILE_THRESHOLD) {
                layout.chunked_uploads.push_back(PlannedChunkUpload{
                    .file_hash = *op_hash,
                    .file_size = op.size,
                    .primary_op_index = index,
                    .chunks = {},
                    .operation_indices = {index},
                });
            } else if (op.size <= crypto::pack::MAX_MICRO_PACK_BLOB_SIZE) {
                small_candidates.push_back(PlannedSmallUpload{
                    .hash = *op_hash,
                    .size = static_cast<std::uint32_t>(op.size),
                    .op_index = index,
                });
            }
        }

        auto& chunked = layout.chunked_uploads;
        if (!chunked.empty()) {
            std::vector<std::optional<Error>> errors(chunked.size());
            const auto started = platform::perf_trace::begin();
            application::parallel_for_indexed(
                chunked.size(),
                application::content_concurrency(),
                [&](std::size_t slot) {
                    auto& job = chunked[slot];
                    const auto index = job.primary_op_index;
                    const auto src = resolve_pre_mutation_source_path(
                        runtime_data.local_dir,
                        record.plan.operations[index],
                        job.file_hash,
                        observed_input.local_tree,
                        index);
                    auto cdc = crypto::pack::chunk_file_fastcdc(
                        src,
                        crypto::pack::fastcdc_profile_for_size(job.file_size));
                    if (!cdc) {
                        errors[slot] = detail::make_error(
                            ErrorCode::ConcurrentModification,
                            "failed to chunk upload source: " + cdc.error(),
                            index);
                    } else if (cdc->file_hash != job.file_hash ||
                               cdc->file_size != job.file_size ||
                               cdc->chunks.empty() ||
                               cdc->chunks.size() >
                                   history::maximum_chunks_per_file) {
                        errors[slot] = detail::make_error(
                            ErrorCode::ConcurrentModification,
                            "large upload source changed before publication",
                            index);
                    } else {
                        job.chunks = std::move(cdc->chunks);
                    }
                });
            platform::perf_trace::finish("sync/fastcdc-layout", started);

            for (std::size_t slot = 0; slot < chunked.size(); ++slot) {
                if (errors[slot]) {
                    return std::unexpected(std::move(*errors[slot]));
                }
                const auto& job = chunked[slot];
                history::ChunkedFileEntry entry{.file_hash = job.file_hash,
                                                .file_size = job.file_size,
                                                .chunks = {}};
                entry.chunks.reserve(job.chunks.size());
                for (const auto& chunk : job.chunks) {
                    entry.chunks.push_back(
                        {.hash = chunk.hash, .size = chunk.size});
                }
                layout.target_manifest.chunked_files.push_back(
                    std::move(entry));
            }
        }

        std::ranges::sort(small_candidates, {}, &PlannedSmallUpload::hash);
        const std::size_t min_pack_blobs =
            (storage.storage.physical_hash_batch != nullptr) ? 2U : 16U;
        if (small_candidates.size() >= min_pack_blobs) {
            std::size_t cursor = 0;
            while (cursor < small_candidates.size()) {
                std::uint64_t bin_bytes = 0;
                std::size_t end = cursor;
                while (end < small_candidates.size() &&
                       (end - cursor) < crypto::pack::MAXIMUM_PACK_MEMBERS &&
                       (end == cursor ||
                        bin_bytes + small_candidates[end].size <=
                            crypto::pack::TARGET_MICRO_PACK_SIZE)) {
                    bin_bytes += small_candidates[end].size;
                    ++end;
                }
                if (end - cursor >= 2) {
                    std::vector<crypto::pack::PackMemberDescriptor> descriptors;
                    descriptors.reserve(end - cursor);
                    PlannedPack pack;
                    pack.blobs.reserve(end - cursor);
                    pack.operation_indices.reserve(end - cursor);
                    for (std::size_t k = cursor; k < end; ++k) {
                        descriptors.push_back(
                            crypto::pack::PackMemberDescriptor{
                                .hash = small_candidates[k].hash,
                                .size = small_candidates[k].size,
                            });
                        pack.blobs.push_back(small_candidates[k]);
                        pack.operation_indices.push_back(
                            small_candidates[k].op_index);
                    }
                    std::ranges::sort(pack.operation_indices);
                    if (const auto pack_hash =
                            crypto::pack::compute_pack_hash(descriptors)) {
                        pack.pack_hash = *pack_hash;
                        pack.pack_identifier =
                            crypto::pack_identifier(key, *pack_hash);
                        for (const auto& d : descriptors) {
                            layout.target_manifest.packed_blobs.push_back(
                                history::PackedBlobEntry{
                                    .blob_hash = d.hash,
                                    .size = d.size,
                                    .pack_hash = *pack_hash,
                                });
                        }
                        layout.packs.push_back(std::move(pack));
                    }
                }
                cursor = end;
            }
        }
    } else if (!record.publication_required &&
               reconciliation_result.requires_storage_repair &&
               !observed_input.storage.storage_manifest.empty()) {
        if (auto planned = plan_manifest_repairs(
                layout, observed_manifest, record, repair_ops_by_hash, key);
            !planned) {
            return std::unexpected(planned.error());
        }
    }

    std::ranges::sort(
        layout.target_manifest.packed_blobs, {}, &history::PackedBlobEntry::blob_hash);
    std::ranges::sort(layout.target_manifest.chunked_files,
                      {},
                      &history::ChunkedFileEntry::file_hash);

    for (std::size_t i = 0; i < layout.packs.size(); ++i) {
        for (const auto op_idx : layout.packs[i].operation_indices) {
            if (const auto h =
                    hash_from_hex(record.plan.operations[op_idx].hash)) {
                layout.pack_by_hash.emplace(*h, i);
            }
        }
    }
    for (std::size_t i = 0; i < layout.chunked_uploads.size(); ++i) {
        layout.chunked_by_hash.emplace(layout.chunked_uploads[i].file_hash, i);
    }
    return layout;
}

std::expected<void, detail::UploadBatchError>
detail::execute_packed_upload_batch(std::span<const PlannedPack* const> packs,
                            const transaction::Record& record,
                            const std::filesystem::path& local_root,
                            transport::Transport& storage,
                            std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                            const platform::Workspace& workspace,
                            std::size_t parallelism,
                            ProgressMeter* meter) {
    if (packs.empty()) {
        return {};
    }
    if (meter)
        meter->phase(Activity::Staging, packs.size());
    const auto first_op = packs.front()->operation_indices.front();
    auto staging = platform::create_workspace("pack-upload-batch");
    if (!staging) {
        return std::unexpected(detail::UploadBatchError{
            .transport_after_unknown_transfer = false,
            .mutation = mutation::MutationError{
                .code = mutation::MutationErrorCode::LocalIo,
                .detail = staging.error(),
                .path = local_root,
                .operation_index = first_op,
            }});
    }
    mutation::StagedUploadBatch batch;
    batch.root = staging->root;
    batch.objects.resize(packs.size());
    detail::ScopedUploadBatchCleanup cleanup{batch};

    std::vector<std::optional<mutation::MutationError>> stage_errors(
        packs.size());
    application::parallel_for_indexed(
        packs.size(),
        std::min<std::size_t>(parallelism, packs.size()),
        [&](std::size_t i) {
            const auto& pack = *packs[i];
            std::vector<crypto::pack::PackMemberSource> sources;
            sources.reserve(pack.blobs.size());
            for (const auto& blob : pack.blobs) {
                auto resolved = mutation::detail::resolve_local_path(
                    local_root,
                    record.plan.operations[blob.op_index].path,
                    blob.op_index);
                if (!resolved) {
                    stage_errors[i] = resolved.error();
                    return;
                }
                sources.push_back(crypto::pack::PackMemberSource{
                    .hash = blob.hash,
                    .size = blob.size,
                    .source_path = std::move(*resolved),
                });
            }
            const auto dest = batch.root / pack.pack_identifier;
            auto res =
                crypto::pack::write_encrypted_pack(sources, dest, key);
            if (!res || res->pack_hash != pack.pack_hash) {
                stage_errors[i] = mutation::MutationError{
                    .code = mutation::MutationErrorCode::IntegrityMismatch,
                    .detail = res ? "staged pack identifier mismatch" : res.error(),
                    .path = local_root,
                    .operation_index = pack.operation_indices.front(),
                };
                return;
            }
            if (meter) {
                meter->record_staged(dest, res->pack_plaintext_size);
            }
            batch.objects[i] = mutation::StagedUploadObject{
                .identifier = pack.pack_identifier,
                .plaintext_hash = hash_hex(res->pack_hash),
                .plaintext_size = res->pack_plaintext_size,
                .ciphertext_sha256 = std::move(res->ciphertext_sha256),
                .operation_indices = pack.operation_indices,
                .is_pack = true,
            };
        });

    std::optional<mutation::MutationError> lowest_err;
    for (const auto& err : stage_errors) {
        if (err &&
            (!lowest_err || err->operation_index < lowest_err->operation_index)) {
            lowest_err = *err;
        }
    }
    if (lowest_err) {
        return std::unexpected(detail::UploadBatchError{
            .transport_after_unknown_transfer = false,
            .mutation = std::move(*lowest_err),
        });
    }

    auto transferred = detail::transfer_and_verify_upload_batch(
        batch, storage, key, workspace, parallelism, meter);
    if (!transferred) {
        if (!transferred.error().transport_after_unknown_transfer) {
            return transferred;
        }
        cleanup.dismissed = true;
        static_cast<void>(mutation::cleanup_upload_batch(batch));
        return transferred;
    }
    cleanup.dismissed = true;
    static_cast<void>(mutation::cleanup_upload_batch(batch));
    return {};
}

std::expected<void, detail::UploadBatchError> detail::execute_chunked_upload_batch(
    std::span<const PlannedChunkUpload* const> uploads,
    const transaction::Record& record,
    const history::StorageManifest& live_manifest,
    const HashSet& missing_files,
    const HashSet& invalid_chunks,
    const std::filesystem::path& local_root,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const platform::Workspace& workspace,
    std::size_t parallelism,
    ProgressMeter* meter) {
    if (uploads.empty()) {
        return {};
    }

    HashSet known_live_chunks{0, hash_key};
    for (const auto& entry : live_manifest.chunked_files) {
        if (!missing_files.contains(entry.file_hash)) {
            for (const auto& c : entry.chunks) {
                if (!invalid_chunks.contains(c.hash)) {
                    known_live_chunks.insert(c.hash);
                }
            }
        }
    }

    struct PendingChunkWork {
        Hash chunk_hash{};
        std::string chunk_id;
        std::string chunk_hex;
        std::uint64_t offset = 0;
        std::uint32_t size = 0;
        std::filesystem::path source_path;
        std::size_t operation_index = 0;
    };

    std::vector<PendingChunkWork> unique_chunks;
    HashSet seen_chunks{0, hash_key};
    std::vector<std::string> candidate_present_ids;

    for (const auto* upload : uploads) {
        const auto op_idx = upload->primary_op_index;
        auto resolved = mutation::detail::resolve_local_path(
            local_root, record.plan.operations[op_idx].path, op_idx);
        if (!resolved) {
            return std::unexpected(detail::UploadBatchError{
                .transport_after_unknown_transfer = false,
                .mutation = resolved.error(),
            });
        }
        for (const auto& chunk : upload->chunks) {
            if (!seen_chunks.insert(chunk.hash).second) {
                continue;
            }
            auto id = crypto::content_identifier(key, chunk.hash);
            candidate_present_ids.push_back(id);
            unique_chunks.push_back(PendingChunkWork{
                .chunk_hash = chunk.hash,
                .chunk_id = std::move(id),
                .chunk_hex = hash_hex(chunk.hash),
                .offset = chunk.offset,
                .size = chunk.size,
                .source_path = *resolved,
                .operation_index = op_idx,
            });
        }
    }

    std::unordered_set<std::string> present_chunk_ids;
    if (!candidate_present_ids.empty()) {
        std::ranges::sort(candidate_present_ids);
        candidate_present_ids.erase(
            std::ranges::unique(candidate_present_ids).begin(),
            candidate_present_ids.end());
        bool probed = false;
        constexpr std::size_t bulk_list_probe_threshold = 256U;
        if (candidate_present_ids.size() >= bulk_list_probe_threshold &&
            storage.storage.list != nullptr) {
            if (auto listed = transport::list(storage)) {
                const std::unordered_set<std::string> remote_set(
                    listed->begin(), listed->end());
                for (const auto& id : candidate_present_ids) {
                    if (remote_set.contains(id)) {
                        present_chunk_ids.insert(id);
                    }
                }
                probed = true;
            }
        }
        if (!probed && storage.storage.control_read_batch != nullptr) {
            transport::ControlReadBatchRequest req;
            req.presence_identifiers = candidate_present_ids;
            auto batch = transport::control_read_batch(storage, req);
            if (batch &&
                batch->presences.size() == candidate_present_ids.size()) {
                for (std::size_t i = 0; i < candidate_present_ids.size(); ++i) {
                    if (batch->presences[i] == transport::Presence::Present) {
                        present_chunk_ids.insert(candidate_present_ids[i]);
                    }
                }
                probed = true;
            }
        }
        if (!probed && storage.storage.presence != nullptr) {
            for (const auto& cid : candidate_present_ids) {
                if (auto res = transport::presence(storage, cid);
                    res && *res == transport::Presence::Present) {
                    present_chunk_ids.insert(cid);
                }
            }
        }
    }

    {
        std::vector<const PendingChunkWork*> orphan_candidates;
        for (const auto& chunk : unique_chunks) {
            if (present_chunk_ids.contains(chunk.chunk_id) &&
                !known_live_chunks.contains(chunk.chunk_hash)) {
                orphan_candidates.push_back(&chunk);
            }
        }
        if (!orphan_candidates.empty()) {
            if (meter)
                meter->phase(Activity::Verifying, orphan_candidates.size());
            std::vector<std::uint8_t> verified(orphan_candidates.size());
            application::parallel_for_indexed(
                orphan_candidates.size(), parallelism, [&](std::size_t i) {
                    const auto& chunk = *orphan_candidates[i];
                    const auto audit =
                        history_storage::audit_content_object(storage,
                                                              key,
                                                              chunk.chunk_id,
                                                              chunk.chunk_hex,
                                                              chunk.size,
                                                              workspace.root,
                                                              i);
                    if (audit &&
                        audit->state ==
                            history_storage::ContentObjectState::Present) {
                        verified[i] = 1;
                    }
                    if (meter)
                        ProgressMeter::add(meter->work);
                });
            for (std::size_t i = 0; i < orphan_candidates.size(); ++i) {
                if (!verified[i]) {
                    present_chunk_ids.erase(orphan_candidates[i]->chunk_id);
                }
            }
        }
    }

    std::vector<PendingChunkWork> to_upload;
    to_upload.reserve(unique_chunks.size());
    for (auto& chunk : unique_chunks) {
        if (!present_chunk_ids.contains(chunk.chunk_id)) {
            to_upload.push_back(std::move(chunk));
        } else if (meter) {
            ProgressMeter::add(meter->bytes_reused, chunk.size);
        }
    }
    if (to_upload.empty()) {
        return {};
    }

    for (std::span<const PendingChunkWork> pending{to_upload};
         !pending.empty();) {
        const auto window = next_chunk_window(pending);
        pending = pending.subspan(window.size());
        const auto first_op = window.front().operation_index;
        if (platform::cancellation::requested()) {
            return std::unexpected(detail::UploadBatchError{
                .transport_after_unknown_transfer = false,
                .mutation = mutation::detail::make_error(
                    mutation::MutationErrorCode::TransportFailure,
                    "FastCDC upload cancelled",
                    local_root,
                    first_op),
            });
        }
        if (meter)
            meter->phase(Activity::Staging, window.size());
        auto staging = platform::create_workspace("chunk-upload-batch");
        if (!staging) {
            return std::unexpected(detail::UploadBatchError{
                .transport_after_unknown_transfer = false,
                .mutation = mutation::MutationError{
                    .code = mutation::MutationErrorCode::LocalIo,
                    .detail = staging.error(),
                    .path = local_root,
                    .operation_index = first_op,
                }});
        }

        mutation::StagedUploadBatch batch;
        batch.root = staging->root;
        batch.objects.resize(window.size());
        detail::ScopedUploadBatchCleanup cleanup{batch};

        std::vector<std::optional<mutation::MutationError>> stage_errors(
            window.size());
        application::parallel_for_indexed(
            window.size(),
            std::min<std::size_t>(parallelism, window.size()),
            [&](std::size_t i) {
                const auto& chunk = window[i];
                std::string detail_err;
                const auto dest = batch.root / chunk.chunk_id;
                auto enc = crypto::pack::encrypt_file_slice_with_hashes(
                    chunk.source_path,
                    chunk.offset,
                    chunk.size,
                    chunk.chunk_hash,
                    dest,
                    key,
                    &detail_err);
                if (!enc) {
                    stage_errors[i] = mutation::MutationError{
                        .code = mutation::MutationErrorCode::IntegrityMismatch,
                        .detail =
                            detail_err.empty()
                                ? "failed to encrypt FastCDC chunk slice"
                                : std::move(detail_err),
                        .path = chunk.source_path,
                        .operation_index = chunk.operation_index,
                    };
                    return;
                }
                if (meter) {
                    meter->record_staged(dest, chunk.size);
                }
                batch.objects[i] = mutation::StagedUploadObject{
                    .identifier = chunk.chunk_id,
                    .plaintext_hash = chunk.chunk_hex,
                    .plaintext_size = chunk.size,
                    .ciphertext_sha256 = std::move(enc->ciphertext_sha256),
                    .operation_indices = {chunk.operation_index},
                    .is_pack = false,
                };
            });

        std::optional<mutation::MutationError> lowest_err;
        for (const auto& err : stage_errors) {
            if (err &&
                (!lowest_err ||
                 err->operation_index < lowest_err->operation_index)) {
                lowest_err = *err;
            }
        }
        if (lowest_err) {
            return std::unexpected(detail::UploadBatchError{
                .transport_after_unknown_transfer = false,
                .mutation = std::move(*lowest_err),
            });
        }

        const auto* item =
            uploads.size() == 1 &&
                    uploads.front()->operation_indices.size() == 1 &&
                    window.size() == to_upload.size()
                ? &record.plan.operations[first_op].path
                : nullptr;
        auto transferred = detail::transfer_and_verify_upload_batch(
            batch, storage, key, workspace, parallelism, meter, item);
        if (!transferred) {
            if (!transferred.error().transport_after_unknown_transfer) {
                return transferred;
            }
            cleanup.dismissed = true;
            static_cast<void>(mutation::cleanup_upload_batch(batch));
            return transferred;
        }
        cleanup.dismissed = true;
        static_cast<void>(mutation::cleanup_upload_batch(batch));
    }
    return {};
}

std::expected<void, Error> detail::resume_manifest_repairs(
    const journal::Paths& paths,
    transaction::Record& record,
    const history::StorageManifest& manifest,
    const std::filesystem::path& local_root,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const platform::Workspace& workspace) {
    if (manifest.empty()) {
        return {};
    }

    RepairOperations repairs{0, hash_key};
    for (std::size_t index = 0; index < record.plan.operations.size();
         ++index) {
        const auto& operation = record.plan.operations[index];
        if (operation.action == Action::Upload) {
            if (const auto hash = hash_from_hex(operation.hash);
                hash && (history::find_packed_blob(manifest, *hash) ||
                         history::find_chunked_file(manifest, *hash))) {
                repairs[*hash].push_back(index);
            }
        }
    }
    if (repairs.empty()) {
        return {};
    }

    UploadLayoutPlan pending;
    if (auto planned =
            plan_manifest_repairs(pending, manifest, record, repairs, key);
        !planned) {
        return planned;
    }
    std::vector<const PlannedPack*> packs;
    for (const auto& pack : pending.packs) {
        const auto verified =
            verify_existing_content(storage,
                                    key,
                                    pack.pack_identifier,
                                    hash_hex(pack.pack_hash),
                                    std::nullopt,
                                    workspace,
                                    pack.operation_indices.front(),
                                    true);
        if (!verified) {
            return std::unexpected(verified.error());
        }
        if (!*verified) {
            packs.push_back(&pack);
        }
    }
    const auto parallelism = application::content_concurrency();
    for (std::span<const PlannedPack* const> remaining{packs};
         !remaining.empty();) {
        const auto window = remaining.first(
            std::min(remaining.size(), pack_upload_window_size));
        if (auto result = execute_packed_upload_batch(window,
                                                      record,
                                                      local_root,
                                                      storage,
                                                      key,
                                                      workspace,
                                                      parallelism,
                                                      nullptr);
            !result) {
            return std::unexpected(mutation_error(result.error().mutation));
        }
        for (const auto* pack : window) {
            for (const auto index : pack->operation_indices) {
                record.progress[index].state =
                    transaction::OperationState::Applied;
            }
        }
        if (auto checkpoint = save_record(paths, record, key); !checkpoint) {
            return checkpoint;
        }
        remaining = remaining.subspan(window.size());
    }

    std::vector<const PlannedChunkUpload*> chunks;
    for (const auto& upload : pending.chunked_uploads) {
        chunks.push_back(&upload);
    }
    const HashSet none{0, hash_key};
    // A repair checkpoint may have been written by a client that used loose
    // objects.
    if (auto result = execute_chunked_upload_batch(chunks,
                                                   record,
                                                   history::StorageManifest{},
                                                   none,
                                                   none,
                                                   local_root,
                                                   storage,
                                                   key,
                                                   workspace,
                                                   parallelism,
                                                   nullptr);
        !result) {
        return std::unexpected(mutation_error(result.error().mutation));
    }

    for (const auto& [hash, indices] : repairs) {
        for (const auto index : indices) {
            record.progress[index].state = transaction::OperationState::Applied;
        }
    }
    return save_record(paths, record, key);
}

} // namespace kasumi::application::sync::coordinator
