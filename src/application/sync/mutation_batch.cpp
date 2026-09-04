#include "application/sync/mutation_batch.hpp"

#include "application/sync/mutation_detail.hpp"
#include "crypto/content.hpp"
#include "platform/perf_trace.hpp"
#include "platform/private_storage.hpp"
#include "platform/workspace.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <system_error>
#include <thread>
#include <unordered_set>

namespace kasumi::application::sync::mutation {

namespace {

using detail::make_error;
using detail::read_status;
using detail::resolve_local_path;

std::expected<std::filesystem::path, MutationError>
create_batch_staging_directory(const platform::Workspace& workspace,
                               std::size_t first_index) {
    if (auto valid =
            platform::validate_non_redirecting_directory(workspace.root);
        !valid) {
        return std::unexpected(
            make_error(MutationErrorCode::UnsafePath,
                       "workspace root is unsafe: " + valid.error(),
                       workspace.root,
                       first_index));
    }

    const auto upload_batches_root = workspace.root / "upload-batches";
    std::error_code error;
    if (std::filesystem::exists(upload_batches_root, error)) {
        if (auto valid = platform::validate_non_redirecting_directory(
                upload_batches_root);
            !valid) {
            return std::unexpected(
                make_error(MutationErrorCode::UnsafePath,
                           "upload-batches is unsafe: " + valid.error(),
                           upload_batches_root,
                           first_index));
        }
    } else {
        auto created =
            platform::private_storage::create_directory(upload_batches_root);
        if (!created) {
            return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                              created.error(),
                                              upload_batches_root,
                                              first_index));
        }
    }

    if (auto valid =
            platform::validate_non_redirecting_directory(upload_batches_root);
        !valid) {
        return std::unexpected(
            make_error(MutationErrorCode::UnsafePath,
                       "upload-batches became unsafe: " + valid.error(),
                       upload_batches_root,
                       first_index));
    }

    const auto batch_root = upload_batches_root / std::to_string(first_index);
    if (std::filesystem::exists(batch_root, error)) {
        if (auto valid =
                platform::validate_non_redirecting_directory(batch_root);
            !valid) {
            return std::unexpected(make_error(
                MutationErrorCode::UnsafePath,
                "existing batch staging directory is unsafe: " + valid.error(),
                batch_root,
                first_index));
        }
        auto removed =
            platform::remove_workspace(platform::Workspace{batch_root});
        if (!removed) {
            return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                              removed.error(),
                                              batch_root,
                                              first_index));
        }
    }

    auto created = platform::private_storage::create_directory(batch_root);
    if (!created) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          created.error(),
                                          batch_root,
                                          first_index));
    }

    if (auto valid = platform::validate_non_redirecting_directory(batch_root);
        !valid) {
        return std::unexpected(make_error(
            MutationErrorCode::UnsafePath,
            "batch staging directory became unsafe: " + valid.error(),
            batch_root,
            first_index));
    }

    return batch_root;
}

std::expected<StagedUploadObject, MutationError>
stage_upload_to_path(const Operation& operation,
                     std::size_t operation_index,
                     const std::filesystem::path& local_root,
                     const std::filesystem::path& destination,
                     std::string identifier,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    auto source =
        detail::resolve_local_path(local_root, operation.path, operation_index);
    if (!source) {
        return std::unexpected(source.error());
    }

    auto prepared = detail::prepare_upload_ciphertext(
        operation, operation_index, *source, destination, key);
    if (!prepared) {
        return std::unexpected(prepared.error());
    }

    return StagedUploadObject{.identifier = std::move(identifier),
                              .plaintext_hash = operation.hash,
                              .plaintext_size = prepared->plaintext_size,
                              .ciphertext_sha256 = prepared->ciphertext_sha256,
                              .operation_indices = {operation_index}};
}

} // namespace

std::expected<StagedUploadBatch, MutationError>
stage_upload_batch(std::span<const std::size_t> operation_indices,
                   const transaction::Record& record,
                   const std::filesystem::path& local_root,
                   std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                   const platform::Workspace& workspace) {
    if (operation_indices.empty()) {
        return StagedUploadBatch{};
    }

    const auto first_index = operation_indices.front();
    auto root = create_batch_staging_directory(workspace, first_index);
    if (!root) {
        return std::unexpected(root.error());
    }

    StagedUploadBatch batch;
    batch.root = *root;

    for (const auto index : operation_indices) {
        const auto& operation = record.plan.operations[index];
        const auto plaintext_hash = hash_from_hex(operation.hash);
        if (!plaintext_hash) {
            return std::unexpected(
                make_error(MutationErrorCode::InvalidOperation,
                           "identificador de conteúdo inválido",
                           {},
                           index));
        }
        const auto identifier =
            crypto::content_identifier(key, *plaintext_hash);

        auto it = std::ranges::find_if(batch.objects, [&](const auto& obj) {
            return obj.plaintext_hash == operation.hash;
        });

        if (it != batch.objects.end()) {
            if (it->plaintext_size != operation.size) {
                return std::unexpected(make_error(
                    MutationErrorCode::IntegrityMismatch,
                    "operações duplicadas possuem tamanhos diferentes",
                    {},
                    index));
            }

            auto source = resolve_local_path(local_root, operation.path, index);
            if (!source) {
                return std::unexpected(source.error());
            }

            auto source_status = read_status(*source, index);
            if (!source_status || std::filesystem::is_symlink(*source_status) ||
                !std::filesystem::is_regular_file(*source_status)) {
                return std::unexpected(
                    make_error(MutationErrorCode::IntegrityMismatch,
                               "a origem duplicada não é arquivo regular",
                               *source,
                               index));
            }

            auto verified = crypto::content::verify_file(
                *source, operation.hash, operation.size);
            if (!verified) {
                return std::unexpected(
                    make_error(MutationErrorCode::IntegrityMismatch,
                               "conteúdo mudou: " + verified.error(),
                               *source,
                               index));
            }

            it->operation_indices.push_back(index);
        } else {
            const auto destination = batch.root / identifier;
            auto staged = stage_upload_to_path(
                operation, index, local_root, destination, identifier, key);
            if (!staged) {
                static_cast<void>(cleanup_upload_batch(batch));
                return std::unexpected(staged.error());
            }
            batch.objects.push_back(std::move(*staged));
        }
    }

    return batch;
}

MutationResult transfer_upload_batch(const StagedUploadBatch& batch,
                                     transport::Transport& storage,
                                     std::size_t max_parallel_transfers) {
    if (batch.objects.empty()) {
        return {};
    }
    platform::perf_trace::count("content transfer strategy batch");
    platform::perf_trace::count("content transfer selected objects",
                                batch.objects.size());

    transport::PutBatch request;
    request.source_root = batch.root;
    request.max_parallel_transfers = max_parallel_transfers;
    for (const auto& obj : batch.objects) {
        request.identifiers.push_back(obj.identifier);
    }
    std::ranges::sort(request.identifiers);

    auto result = transport::put_batch(storage, request);

    if (!result) {
        return std::unexpected(
            make_error(transport::mutation_result_is_ambiguous(result.error())
                           ? MutationErrorCode::RemoteResultUnknown
                           : MutationErrorCode::TransportFailure,
                       transport::describe(result.error()),
                       batch.root,
                       batch.objects.front().operation_indices.front()));
    }

    return {};
}

struct VerificationState {
    std::mutex mutex;
    std::size_t next_index = 0;
    std::size_t active_workers = 0;
    std::size_t peak_in_flight = 0;
    std::vector<std::optional<MutationError>> errors;
};

MutationResult verify_upload_batch_individually(
    const StagedUploadBatch& batch,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const platform::Workspace& workspace,
    std::size_t parallelism) {
    if (batch.objects.empty()) {
        return {};
    }

    VerificationState state;
    state.errors.resize(batch.objects.size());

    const auto effective_parallelism = std::max<std::size_t>(1, parallelism);
    const auto worker_count =
        std::min(effective_parallelism, batch.objects.size());
    std::vector<std::jthread> threads;
    threads.reserve(worker_count);

    for (std::size_t w = 0; w < worker_count; ++w) {
        threads.emplace_back([&, w](std::stop_token stop) {
            while (!stop.stop_requested()) {
                std::size_t index = 0;
                {
                    std::lock_guard lock(state.mutex);
                    if (state.next_index >= batch.objects.size()) {
                        break;
                    }
                    index = state.next_index++;
                    ++state.active_workers;
                    state.peak_in_flight =
                        std::max(state.peak_in_flight, state.active_workers);
                }

                const auto& object = batch.objects[index];
                const auto operation_index = object.operation_indices.front();
                auto result = detail::verify_uploaded_content_object(
                    storage,
                    key,
                    object.identifier,
                    object.plaintext_hash,
                    object.plaintext_size,
                    workspace,
                    operation_index,
                    object.ciphertext_sha256);

                {
                    std::lock_guard lock(state.mutex);
                    --state.active_workers;
                    if (!result) {
                        state.errors[index] = result.error();
                    }
                }
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    // Deterministically finds the error with the smallest operation_index.
    std::optional<MutationError> deterministic_error;
    for (const auto& opt_error : state.errors) {
        if (opt_error) {
            if (!deterministic_error ||
                opt_error->operation_index <
                    deterministic_error->operation_index) {
                deterministic_error = *opt_error;
            }
        }
    }

    if (deterministic_error) {
        return std::unexpected(*deterministic_error);
    }

    return {};
}

std::optional<MutationError>
bulk_verification_error(const StagedUploadBatch& batch,
                        const transport::PhysicalHashBatchReport& report) {
    if (batch.objects.empty()) {
        return std::nullopt;
    }

    std::unordered_set<std::string> identifiers;
    for (const auto& object : batch.objects) {
        identifiers.insert(object.identifier);
    }
    for (const auto* failures :
         {&report.mismatched, &report.missing, &report.errors}) {
        for (const auto& identifier : *failures) {
            if (!identifiers.contains(identifier)) {
                return make_error(
                    MutationErrorCode::TransportFailure,
                    "rclone retornou identificador inesperado na verificação "
                    "em lote",
                    {},
                    batch.objects.front().operation_indices.front());
            }
        }
    }

    std::optional<MutationError> selected;
    const auto choose = [&](const StagedUploadObject& object,
                            MutationErrorCode code,
                            std::string detail) {
        auto candidate = make_error(
            code, std::move(detail), {}, object.operation_indices.front());
        if (!selected ||
            candidate.operation_index < selected->operation_index) {
            selected = std::move(candidate);
        }
    };

    for (const auto& object : batch.objects) {
        const auto has = [&](const std::vector<std::string>& values) {
            return std::ranges::find(values, object.identifier) != values.end();
        };
        if (has(report.mismatched)) {
            choose(
                object,
                MutationErrorCode::IntegrityMismatch,
                "o hash físico remoto não corresponde ao ciphertext publicado");
        } else if (has(report.missing)) {
            choose(object,
                   MutationErrorCode::IntegrityMismatch,
                   "objeto remoto ausente após upload em batch");
        } else if (has(report.errors)) {
            choose(
                object,
                MutationErrorCode::TransportFailure,
                "rclone não conseguiu verificar fisicamente o objeto remoto");
        }
    }
    return selected;
}

MutationResult
verify_upload_batch(const StagedUploadBatch& batch,
                    transport::Transport& storage,
                    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                    const platform::Workspace& workspace,
                    std::size_t parallelism) {
    if (batch.objects.empty()) {
        return {};
    }

    if (!transport::prefers_physical_hash_batch(storage,
                                                batch.objects.size())) {
        platform::perf_trace::count("content verification strategy individual");
        platform::perf_trace::count("content verification selected objects",
                                    batch.objects.size());
        return verify_upload_batch_individually(
            batch, storage, key, workspace, parallelism);
    }

    platform::perf_trace::count("content verification strategy bulk");
    platform::perf_trace::count("content verification selected objects",
                                batch.objects.size());

    transport::PhysicalHashBatchRequest request;
    request.scratch_root = batch.root;
    request.algorithm = "sha256";
    request.objects.reserve(batch.objects.size());
    for (const auto& object : batch.objects) {
        request.objects.push_back(transport::PhysicalHashExpectation{
            .identifier = object.identifier,
            .expected_hash = object.ciphertext_sha256,
        });
    }

    platform::perf_trace::count("content bulk check calls");
    auto bulk = transport::physical_hash_batch(storage, request);
    if (bulk) {
        if (auto failure = bulk_verification_error(batch, *bulk)) {
            return std::unexpected(*failure);
        }
        return {};
    }
    if (bulk.error().code != transport::ErrorCode::Unsupported) {
        return std::unexpected(
            make_error(MutationErrorCode::TransportFailure,
                       transport::describe(bulk.error()),
                       {},
                       batch.objects.front().operation_indices.front()));
    }

    return verify_upload_batch_individually(
        batch, storage, key, workspace, parallelism);
}

MutationResult cleanup_upload_batch(const StagedUploadBatch& batch) {
    if (batch.root.empty()) {
        return {};
    }

    std::error_code ec;
    if (!std::filesystem::exists(batch.root, ec)) {
        if (ec) {
            return std::unexpected(detail::make_error(
                MutationErrorCode::LocalIo,
                "stat failed before cleanup",
                batch.root,
                batch.objects.empty()
                    ? 0
                    : batch.objects.front().operation_indices.front()));
        }
        return {};
    }

    auto safe = platform::validate_non_redirecting_directory(batch.root);
    if (!safe) {
        return std::unexpected(detail::make_error(
            MutationErrorCode::UnsafePath,
            "directory is redirected (TOCTOU violation detected)",
            batch.root,
            batch.objects.empty()
                ? 0
                : batch.objects.front().operation_indices.front()));
    }

    std::filesystem::remove_all(batch.root, ec);
    if (ec) {
        return std::unexpected(detail::make_error(
            MutationErrorCode::LocalIo,
            "failed to safely cleanup batch staging directory",
            batch.root,
            batch.objects.empty()
                ? 0
                : batch.objects.front().operation_indices.front()));
    }

    return {};
}

} // namespace kasumi::application::sync::mutation
