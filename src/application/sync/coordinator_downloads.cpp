#include "application/sync/coordinator.hpp"

#include "application/concurrency.hpp"
#include "application/progress.hpp"
#include "application/sync/mutation.hpp"
#include "application/sync/mutation_detail.hpp"
#include "application/sync/mutation_fault_test.hpp"
#include "coordinator_detail.hpp"
#include "core/hasher.hpp"
#include "core/history.hpp"
#include "core/transaction/types.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/pack.hpp"
#include "crypto/secure_memory.hpp"
#include "platform/cancellation.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"

#include <algorithm>
#include <blake3.h>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace kasumi::application::sync::coordinator {
namespace {

using detail::next_chunk_window;

bool batch_fetch_objects(transport::Transport& storage,
                         const std::filesystem::path& dir,
                         const std::vector<std::string>& ids,
                         std::size_t transfers = 0) {
    if (ids.size() >= 2 && storage.storage.get_batch != nullptr) {
        transport::GetBatch req;
        req.destination_root = dir;
        req.identifiers = ids;
        req.max_parallel_transfers = transfers;
        if (transport::get_batch(storage, req)) {
            return true;
        }
    }
    return false;
}

bool seed_source_matches(const detail::ChunkSource& seed,
                         std::uint32_t expected_size) noexcept {
    namespace ps = platform::private_storage;
    return seed.size == expected_size &&
           !ps::is_reparse_or_symlink(seed.source_path) &&
           ps::query_file_identity(seed.source_path) == seed.identity;
}

void maybe_seed_local_fastcdc_source(const history::ChunkedFileEntry& entry,
                                     const std::filesystem::path& cand,
                                     detail::ChunkDownloadSession& session) {
    namespace ps = platform::private_storage;
    const auto key_path = platform::path::to_utf8(cand);
    if (key_path.empty() || session.seeded_paths.contains(key_path)) {
        return;
    }
    std::error_code ec;
    const auto st = std::filesystem::symlink_status(cand, ec);
    if (ec || std::filesystem::is_symlink(st) ||
        !std::filesystem::is_regular_file(st) ||
        ps::is_reparse_or_symlink(cand)) {
        return;
    }
    const auto fsize = std::filesystem::file_size(cand, ec);
    if (ec || fsize < crypto::pack::FASTCDC_MIN_CHUNK) {
        return;
    }
    const auto id = ps::query_file_identity(cand);
    if (!id.valid) {
        return;
    }
    session.seeded_paths.insert(key_path);
    auto cdc = crypto::pack::chunk_file_fastcdc(
        cand, crypto::pack::fastcdc_profile_for_size(entry.file_size));
    if (!cdc) {
        return;
    }
    const auto post_id = ps::query_file_identity(cand);
    if (!post_id.valid || !(post_id == id)) {
        return;
    }
    for (const auto& sc : cdc->chunks) {
        session.local_seeds.try_emplace(sc.hash,
                                        detail::ChunkSource{
                                            .source_path = cand,
                                            .identity = id,
                                            .offset = sc.offset,
                                            .size = sc.size,
                                        });
    }
}

template <typename AppendFn>
bool stream_verified_seed_slice(const detail::ChunkSource& seed,
                                const history::ChunkSlice& chunk,
                                std::vector<std::uint8_t>& copy_buf,
                                AppendFn&& append) {
    namespace ps = platform::private_storage;
    if (!seed_source_matches(seed, chunk.size)) {
        return false;
    }
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    crypto::secure_memory::WipeGuard wipe_hasher{hasher};
    const auto streamed = ps::stream_regular_file(
        seed.source_path,
        copy_buf,
        [&](std::span<const std::uint8_t> slab) {
            blake3_hasher_update(&hasher, slab.data(), slab.size());
            return append(slab);
        },
        std::nullopt,
        ps::FileSlice{seed.offset, seed.size});
    if (!seed_source_matches(seed, chunk.size) || !streamed) {
        return false;
    }
    Hash digest{};
    blake3_hasher_finalize(&hasher,
                           reinterpret_cast<std::uint8_t*>(digest.data()),
                           digest.size());
    return digest == chunk.hash;
}

} // namespace

mutation::MutationResult detail::apply_chunked_download(
    const history::ChunkedFileEntry& entry,
    const kasumi::Operation& operation,
    std::size_t operation_index,
    const std::filesystem::path& local_root,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const platform::Workspace& workspace,
    std::size_t parallelism,
    const transaction::OperationProgress& progress,
    const mutation::DestinationPrecondition* destination_condition,
    ChunkDownloadSession& session,
    ProgressMeter* meter) {
    namespace ps = platform::private_storage;
    if (!session.directories_ready) {
        session.chunk_dl_dir = workspace.root / "chunk-dl";
        if (auto ok = ps::ensure_directory(session.chunk_dl_dir); !ok) {
            return std::unexpected(mutation::detail::make_error(
                mutation::MutationErrorCode::LocalIo,
                ok.error(),
                session.chunk_dl_dir,
                operation_index));
        }
        session.directories_ready = true;
    }

    struct InstalledSlice {
        Hash hash{};
        std::uint64_t offset = 0;
        std::uint32_t size = 0;
    };
    std::vector<InstalledSlice> installed_slices;
    installed_slices.reserve(entry.chunks.size());
    std::optional<std::filesystem::path> resolved_destination;

    auto installed = mutation::apply_streamed_download(
        operation,
        operation_index,
        local_root,
        workspace,
        progress,
        destination_condition,
        [&](const std::filesystem::path& candidate_path,
            const std::filesystem::path& destination_path,
            const std::filesystem::path* backup_path)
            -> mutation::MutationResult {
            resolved_destination = destination_path;
            const auto fail = [&](mutation::MutationErrorCode code,
                                  std::string reason) {
                return std::unexpected(mutation::detail::make_error(
                    code, std::move(reason), candidate_path, operation_index));
            };

            if (backup_path != nullptr && !backup_path->empty()) {
                maybe_seed_local_fastcdc_source(entry, *backup_path, session);
            }
            maybe_seed_local_fastcdc_source(entry, destination_path, session);

            auto private_out = ps::create_private_file(candidate_path);
            if (!private_out) {
                return fail(mutation::MutationErrorCode::LocalIo,
                            "failed to create staged FastCDC download file: " +
                                private_out.error().message);
            }
            struct OutputCleanup {
                ps::PrivateOutputFile* file = nullptr;
                bool dismissed = false;
                ~OutputCleanup() noexcept {
                    if (!dismissed && file != nullptr) {
                        static_cast<void>(
                            ps::remove_private_file_if_owned(*file));
                    }
                }
            } out_cleanup{&*private_out, false};

            std::vector<std::uint8_t> copy_buf(256U * 1024U);
            crypto::secure_memory::WipeGuard wipe_buffer{copy_buf};
            blake3_hasher file_hash;
            blake3_hasher_init(&file_hash);
            crypto::secure_memory::WipeGuard wipe_hash{file_hash};
            bool write_failed = false;
            auto append = [&](std::span<const std::uint8_t> slab) {
                if (!ps::write_private_file(
                        *private_out, slab.data(), slab.size())) {
                    write_failed = true;
                    return false;
                }
                blake3_hasher_update(&file_hash, slab.data(), slab.size());
                return true;
            };

            std::unordered_map<Hash,
                               std::pair<std::uint64_t, std::uint32_t>,
                               ChunkHashKey>
                current_file_slices;
            std::uint64_t offset = 0;
            for (std::span<const history::ChunkSlice> pending{entry.chunks};
                 !pending.empty();) {
                const auto window = next_chunk_window(pending);
                pending = pending.subspan(window.size());
                if (platform::cancellation::requested()) {
                    return fail(mutation::MutationErrorCode::TransportFailure,
                                "FastCDC download cancelled");
                }

                HashSet scheduled{0, hash_key};
                std::vector<const history::ChunkSlice*> fetch;
                std::vector<std::string> ids;
                for (const auto& chunk : window) {
                    if (current_file_slices.contains(chunk.hash)) {
                        continue;
                    }
                    if (const auto local_it =
                            session.local_seeds.find(chunk.hash);
                        local_it != session.local_seeds.end()) {
                        if (seed_source_matches(local_it->second, chunk.size)) {
                            continue;
                        }
                        session.local_seeds.erase(local_it);
                    }
                    if (const auto prior_it =
                            session.downloaded_slices.find(chunk.hash);
                        prior_it != session.downloaded_slices.end()) {
                        if (seed_source_matches(prior_it->second, chunk.size)) {
                            continue;
                        }
                        session.downloaded_slices.erase(prior_it);
                    }
                    if (scheduled.insert(chunk.hash).second) {
                        fetch.push_back(&chunk);
                        ids.push_back(
                            crypto::content_identifier(key, chunk.hash));
                    }
                }

                struct WindowDlCleanup {
                    const std::filesystem::path& dir;
                    const std::vector<std::string>& ids;
                    ~WindowDlCleanup() noexcept {
                        std::error_code ignored;
                        for (const auto& id : ids) {
                            std::filesystem::remove(dir / id, ignored);
                        }
                    }
                } dl_cleanup{session.chunk_dl_dir, ids};

                if (!fetch.empty()) {
                    if (meter)
                        meter->phase(
                            Activity::Downloading,
                            fetch.size(),
                            0,
                            window.size() == entry.chunks.size()
                                ? &operation.path
                                : nullptr);
                    batch_fetch_objects(
                        storage, session.chunk_dl_dir, ids, parallelism);
                    if (platform::cancellation::requested()) {
                        return fail(
                            mutation::MutationErrorCode::TransportFailure,
                            "FastCDC download cancelled");
                    }

                    std::vector<std::optional<mutation::MutationError>> errors(
                        fetch.size());
                    application::parallel_for_indexed(
                        fetch.size(), parallelism, [&](std::size_t i) {
                            const auto enc = session.chunk_dl_dir / ids[i];
                            std::error_code status_error;
                            const auto status = std::filesystem::symlink_status(
                                enc, status_error);
                            const bool absent =
                                status_error ==
                                    std::errc::no_such_file_or_directory ||
                                (!status_error &&
                                 status.type() ==
                                     std::filesystem::file_type::not_found);
                            if (absent) {
                                auto fetched =
                                    transport::get(storage, ids[i], enc);
                                if (!fetched) {
                                    errors[i] = mutation::detail::make_error(
                                        fetched.error().code ==
                                                transport::ErrorCode::
                                                    ObjectNotFound
                                            ? mutation::MutationErrorCode::
                                                  RemoteContentMissing
                                            : mutation::MutationErrorCode::
                                                  TransportFailure,
                                        transport::describe(fetched.error()),
                                        operation.path,
                                        operation_index);
                                    return;
                                }
                            } else if (status_error ||
                                       !std::filesystem::is_regular_file(
                                           status) ||
                                       ps::is_reparse_or_symlink(enc)) {
                                errors[i] = mutation::detail::make_error(
                                    mutation::MutationErrorCode::LocalIo,
                                    status_error
                                        ? status_error.message()
                                        : "downloaded chunk is not a regular "
                                          "file",
                                    enc,
                                    operation_index);
                                return;
                            }
                        });
                    for (auto& error : errors) {
                        if (error) {
                            return std::unexpected(std::move(*error));
                        }
                    }
                }

                if (meter)
                    meter->phase(Activity::Installing, window.size());
                mutation_fault_test::hit("fastcdc_chunks_ready",
                                         session.chunk_dl_dir);
                for (const auto& chunk : window) {
                    if (const auto local_it =
                            session.local_seeds.find(chunk.hash);
                        local_it != session.local_seeds.end()) {
                        if (!stream_verified_seed_slice(
                                local_it->second, chunk, copy_buf, append)) {
                            return fail(
                                mutation::MutationErrorCode::IntegrityMismatch,
                                "local FastCDC seed changed or could not be "
                                "staged");
                        }
                        if (meter)
                            ProgressMeter::add(meter->bytes_reused, chunk.size);
                    } else if (const auto cur_it =
                                   current_file_slices.find(chunk.hash);
                               cur_it != current_file_slices.end()) {
                        const ChunkSource intra{
                            .source_path = candidate_path,
                            .identity = private_out->identity,
                            .offset = cur_it->second.first,
                            .size = cur_it->second.second,
                        };
                        if (!stream_verified_seed_slice(
                                intra, chunk, copy_buf, append)) {
                            return fail(
                                mutation::MutationErrorCode::IntegrityMismatch,
                                "previously staged FastCDC chunk changed");
                        }
                    } else if (const auto prior_it =
                                   session.downloaded_slices.find(chunk.hash);
                               prior_it != session.downloaded_slices.end()) {
                        if (!stream_verified_seed_slice(
                                prior_it->second, chunk, copy_buf, append)) {
                            return fail(
                                mutation::MutationErrorCode::IntegrityMismatch,
                                "previously staged FastCDC chunk changed");
                        }
                    } else {
                        const auto enc = session.chunk_dl_dir /
                                         crypto::content_identifier(
                                             key, chunk.hash);
                        write_failed = false;
                        const bool decrypted = crypto::decrypt_file_to_sink(
                            enc,
                            key,
                            append,
                            crypto::FilePurpose::Content,
                            chunk.size,
                            &chunk.hash);
                        std::error_code ec;
                        std::filesystem::remove(enc, ec);
                        if (!decrypted) {
                            return fail(
                                write_failed
                                    ? mutation::MutationErrorCode::LocalIo
                                    : mutation::MutationErrorCode::
                                          CryptoFailure,
                                write_failed
                                    ? "failed to write FastCDC chunk to "
                                      "destination"
                                    : "FastCDC chunk failed authentication");
                        }
                        if (ec) {
                            return fail(
                                mutation::MutationErrorCode::LocalIo,
                                "failed to remove encrypted FastCDC chunk: " +
                                    ec.message());
                        }
                    }
                    current_file_slices.try_emplace(
                        chunk.hash, offset, chunk.size);
                    installed_slices.push_back(InstalledSlice{
                        .hash = chunk.hash,
                        .offset = offset,
                        .size = chunk.size,
                    });
                    offset += chunk.size;
                    if (meter)
                        ProgressMeter::add(meter->work);
                }
            }

            ps::close_private_file(*private_out);
            out_cleanup.dismissed = true;
            Hash digest{};
            blake3_hasher_finalize(
                &file_hash,
                reinterpret_cast<std::uint8_t*>(digest.data()),
                digest.size());
            if (offset != entry.file_size || digest != entry.file_hash) {
                return fail(mutation::MutationErrorCode::IntegrityMismatch,
                            "reassembled FastCDC file failed verification");
            }
            mutation_fault_test::hit("fastcdc_file_ready", candidate_path);
            return {};
        });
    if (!installed) {
        return installed;
    }
    if (resolved_destination) {
        const auto installed_id =
            ps::query_file_identity(*resolved_destination);
        if (installed_id.valid) {
            for (const auto& slice : installed_slices) {
                session.downloaded_slices.try_emplace(
                    slice.hash,
                    ChunkSource{
                        .source_path = *resolved_destination,
                        .identity = installed_id,
                        .offset = slice.offset,
                        .size = slice.size,
                    });
            }
        }
    }
    return {};
}

std::expected<std::optional<mutation::MutationError>, Error>
detail::apply_packed_downloads(
    const history::StorageManifest& manifest,
    std::span<const std::size_t> op_indices,
    transaction::Record& record,
    const std::filesystem::path& local_root,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const platform::Workspace& workspace,
    std::span<const std::optional<mutation::DestinationPrecondition>>
        destinations,
    std::size_t parallelism,
    const CheckpointCallback& checkpoint,
    const AppliedOpsCallback& on_applied,
    ProgressMeter* meter) {
    if (manifest.empty() || op_indices.empty()) {
        return std::optional<mutation::MutationError>{};
    }

    struct PackDownloadJob {
        Hash pack_hash{};
        std::string identifier;
        std::size_t first_op_index = 0;
        std::uint64_t size = 0;
        std::vector<std::size_t> op_indices;
    };

    std::vector<PackDownloadJob> pack_jobs;
    std::unordered_map<Hash, std::size_t, decltype(&hash_key)>
        pack_index_by_hash{0, hash_key};
    HashSet seen_blobs{0, hash_key};

    for (const auto op_idx : op_indices) {
        if (record.progress[op_idx].state ==
            transaction::OperationState::Applied) {
            continue;
        }
        const auto& op = record.plan.operations[op_idx];
        if (op.action != Action::Download) {
            continue;
        }
        const auto h = hash_from_hex(op.hash);
        if (!h) {
            continue;
        }
        const auto* packed = history::find_packed_blob(manifest, *h);
        if (!packed) {
            continue;
        }
        auto [it, inserted] =
            pack_index_by_hash.emplace(packed->pack_hash, pack_jobs.size());
        if (inserted) {
            pack_jobs.push_back(PackDownloadJob{
                .pack_hash = packed->pack_hash,
                .identifier = crypto::pack_identifier(key, packed->pack_hash),
                .first_op_index = op_idx,
            });
        }
        auto& job = pack_jobs[it->second];
        job.first_op_index = std::min(job.first_op_index, op_idx);
        job.op_indices.push_back(op_idx);
        if (seen_blobs.insert(*h).second) {
            job.size += packed->size;
        }
    }

    if (pack_jobs.empty()) {
        return std::optional<mutation::MutationError>{};
    }

    const auto dl_dir = workspace.root / "pack-dl";
    if (auto ok = platform::private_storage::ensure_directory(dl_dir); !ok) {
        return std::optional<mutation::MutationError>{
            mutation::detail::make_error(mutation::MutationErrorCode::LocalIo,
                                         ok.error(),
                                         dl_dir,
                                         pack_jobs.front().first_op_index)};
    }

    const auto concurrency = std::max<std::size_t>(1, parallelism);
    for (std::span<const PackDownloadJob> pending{pack_jobs};
         !pending.empty();) {
        const auto window = next_chunk_window(pending);
        pending = pending.subspan(window.size());
        if (platform::cancellation::requested()) {
            const auto first_op = window.front().first_op_index;
            return std::optional<mutation::MutationError>{
                mutation::detail::make_error(
                    mutation::MutationErrorCode::TransportFailure,
                    "Micro-Pack download cancelled",
                    record.plan.operations[first_op].path,
                    first_op)};
        }

        std::vector<std::string> ids;
        ids.reserve(window.size());
        for (const auto& p : window) {
            ids.push_back(p.identifier);
        }
        if (meter) {
            meter->phase(Activity::Downloading, ids.size());
        }
        const bool batch_ok =
            batch_fetch_objects(storage, dl_dir, ids, concurrency);
        if (platform::cancellation::requested()) {
            const auto first_op = window.front().first_op_index;
            return std::optional<mutation::MutationError>{
                mutation::detail::make_error(
                    mutation::MutationErrorCode::TransportFailure,
                    "Micro-Pack download cancelled",
                    record.plan.operations[first_op].path,
                    first_op)};
        }
        if (meter && batch_ok) {
            meter->phase(Activity::Installing, window.size());
        }

        std::vector<std::optional<mutation::MutationError>> errors(
            window.size());
        std::vector<std::vector<std::size_t>> installed(window.size());
        application::parallel_for_indexed(
            window.size(),
            std::min<std::size_t>(concurrency, window.size()),
            [&](std::size_t i) {
                const auto& job = window[i];
                const auto enc_path = dl_dir / job.identifier;
                std::error_code status_error;
                const auto status =
                    std::filesystem::symlink_status(enc_path, status_error);
                const bool absent =
                    status_error == std::errc::no_such_file_or_directory ||
                    (!status_error &&
                     status.type() == std::filesystem::file_type::not_found);
                if (absent) {
                    auto fetched =
                        transport::get(storage, job.identifier, enc_path);
                    if (!fetched) {
                        errors[i] = mutation::detail::make_error(
                            fetched.error().code ==
                                    transport::ErrorCode::ObjectNotFound
                                ? mutation::MutationErrorCode::
                                      RemoteContentMissing
                                : mutation::MutationErrorCode::TransportFailure,
                            transport::describe(fetched.error()),
                            record.plan.operations[job.first_op_index].path,
                            job.first_op_index);
                        return;
                    }
                } else if (status_error ||
                           !std::filesystem::is_regular_file(status) ||
                           platform::private_storage::is_reparse_or_symlink(
                               enc_path)) {
                    errors[i] = mutation::detail::make_error(
                        mutation::MutationErrorCode::LocalIo,
                        status_error ? status_error.message()
                                     : "downloaded pack is not a regular file",
                        enc_path,
                        job.first_op_index);
                    return;
                }
                auto verified = crypto::pack::load_verified_pack(
                    enc_path, key, job.pack_hash);
                std::error_code ignored;
                std::filesystem::remove(enc_path, ignored);
                if (!verified) {
                    errors[i] = mutation::detail::make_error(
                        mutation::MutationErrorCode::CryptoFailure,
                        "Micro-Pack authentication/extraction failed: " +
                            verified.error(),
                        record.plan.operations[job.first_op_index].path,
                        job.first_op_index);
                    return;
                }
                for (const auto op_idx : job.op_indices) {
                    const auto& op = record.plan.operations[op_idx];
                    const auto blob_hash = hash_from_hex(op.hash);
                    const auto member =
                        blob_hash ? verified->member_bytes(*blob_hash)
                                  : std::nullopt;
                    if (!member) {
                        errors[i] = mutation::detail::make_error(
                            mutation::MutationErrorCode::IntegrityMismatch,
                            "blob missing from authenticated Micro-Pack: " +
                                op.hash,
                            op.path,
                            op_idx);
                        return;
                    }
                    const auto* condition =
                        op_idx < destinations.size() && destinations[op_idx]
                            ? &*destinations[op_idx]
                            : nullptr;
                    auto applied = mutation::apply_preverified_bytes_download(
                        op,
                        op_idx,
                        local_root,
                        *member,
                        workspace,
                        record.progress[op_idx],
                        condition);
                    if (!applied) {
                        errors[i] = std::move(applied.error());
                        return;
                    }
                    installed[i].push_back(op_idx);
                }
                if (meter && batch_ok) {
                    ProgressMeter::add(meter->work);
                }
            });

        std::vector<std::size_t> applied_in_window;
        for (const auto& ops : installed) {
            applied_in_window.insert(
                applied_in_window.end(), ops.begin(), ops.end());
        }
        if (!applied_in_window.empty()) {
            for (const auto op_idx : applied_in_window) {
                record.progress[op_idx].state =
                    transaction::OperationState::Applied;
            }
            if (checkpoint) {
                if (auto saved = checkpoint(); !saved) {
                    return std::unexpected(saved.error());
                }
            }
            if (on_applied) {
                on_applied(applied_in_window);
            }
        }

        std::optional<mutation::MutationError> first_err;
        for (const auto& e : errors) {
            if (e && (!first_err ||
                      e->operation_index < first_err->operation_index)) {
                first_err = *e;
            }
        }
        if (first_err) {
            return first_err;
        }
    }

    return std::optional<mutation::MutationError>{};
}

} // namespace kasumi::application::sync::coordinator
