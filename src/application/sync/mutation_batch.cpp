#include "application/sync/mutation_batch.hpp"

#include "application/concurrency.hpp"
#include "application/progress.hpp"
#include "application/sync/mutation_detail.hpp"
#include "crypto/content.hpp"
#include "platform/workspace.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <system_error>
#include <thread>
#include <unordered_map>
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

    // shortcut: process death can leave encrypted temp batches; add journal
    // ownership if crash cleanup becomes a requirement.
    auto staging = platform::create_workspace("upload-batch");
    if (!staging) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          staging.error(),
                                          workspace.root,
                                          first_index));
    }
    if (auto valid =
            platform::validate_non_redirecting_directory(staging->root);
        !valid) {
        platform::cleanup_workspace(*staging);
        return std::unexpected(
            make_error(MutationErrorCode::UnsafePath,
                       "batch staging directory is unsafe: " + valid.error(),
                       staging->root,
                       first_index));
    }
    return staging->root;
}

std::expected<StagedUploadObject, MutationError>
stage_upload_to_path(const kasumi::Operation& operation,
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
                   const platform::Workspace& workspace,
                   ProgressMeter* meter) {
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
    bool commit_batch = false;
    struct BatchGuard {
        StagedUploadBatch& batch;
        bool& commit_batch;
        ~BatchGuard() noexcept {
            if (!commit_batch) {
                static_cast<void>(cleanup_upload_batch(batch));
            }
        }
    } batch_guard{batch, commit_batch};

    struct UniqueUploadPlan {
        std::size_t primary_index = 0;
        std::string identifier;
        std::uint64_t expected_size = 0;
        std::vector<std::size_t> duplicate_indices;
    };

    std::vector<UniqueUploadPlan> plans;
    plans.reserve(operation_indices.size());
    std::unordered_map<std::string_view, std::size_t> plan_by_hash;
    plan_by_hash.reserve(operation_indices.size());

    for (const auto index : operation_indices) {
        const auto& operation = record.plan.operations[index];
        const auto plaintext_hash = hash_from_hex(operation.hash);
        if (!plaintext_hash) {
            return std::unexpected(
                make_error(MutationErrorCode::InvalidOperation,
                           "invalid content identifier",
                           {},
                           index));
        }
        const auto existing = plan_by_hash.find(operation.hash);
        if (existing != plan_by_hash.end()) {
            auto& target_plan = plans[existing->second];
            if (target_plan.expected_size != operation.size) {
                return std::unexpected(
                    make_error(MutationErrorCode::IntegrityMismatch,
                               "duplicate operations have different sizes",
                               {},
                               index));
            }
            target_plan.duplicate_indices.push_back(index);
        } else {
            plan_by_hash.emplace(operation.hash, plans.size());
            plans.push_back(UniqueUploadPlan{
                .primary_index = index,
                .identifier = crypto::content_identifier(key, *plaintext_hash),
                .expected_size = operation.size,
                .duplicate_indices = {},
            });
        }
    }

    if (meter)
        meter->phase(Activity::Staging, plans.size());
    const auto execute_plan =
        [&](const UniqueUploadPlan& plan)
        -> std::expected<StagedUploadObject, MutationError> {
        const auto& primary_op = record.plan.operations[plan.primary_index];
        const auto destination = batch.root / plan.identifier;
        auto staged = stage_upload_to_path(primary_op,
                                           plan.primary_index,
                                           local_root,
                                           destination,
                                           plan.identifier,
                                           key);
        if (!staged) {
            return std::unexpected(staged.error());
        }
        if (meter) {
            meter->record_staged(destination, staged->plaintext_size);
        }
        for (const auto dup_index : plan.duplicate_indices) {
            const auto& dup_op = record.plan.operations[dup_index];
            auto source =
                resolve_local_path(local_root, dup_op.path, dup_index);
            if (!source) {
                return std::unexpected(source.error());
            }
            if (auto ok = detail::require_regular_file(
                    *source,
                    MutationErrorCode::IntegrityMismatch,
                    "duplicate source is not a regular file",
                    dup_index);
                !ok) {
                return std::unexpected(ok.error());
            }
            auto verified = crypto::content::verify_file(
                *source, dup_op.hash, dup_op.size);
            if (!verified) {
                return std::unexpected(
                    make_error(MutationErrorCode::IntegrityMismatch,
                               "content changed: " + verified.error(),
                               *source,
                               dup_index));
            }
            staged->operation_indices.push_back(dup_index);
        }
        return staged;
    };

    if (plans.size() == 1) {
        auto staged = execute_plan(plans.front());
        if (!staged) {
            return std::unexpected(staged.error());
        }
        batch.objects.push_back(std::move(*staged));
    } else {
        std::vector<std::expected<StagedUploadObject, MutationError>> outcomes;
        outcomes.reserve(plans.size());
        for (std::size_t i = 0; i < plans.size(); ++i) {
            outcomes.emplace_back(std::unexpected(MutationError{}));
        }
        const auto hw = std::thread::hardware_concurrency();
        const auto workers =
            std::clamp<std::size_t>(hw == 0 ? 4 : hw, 2, 8);
        application::parallel_for_indexed(
            plans.size(), workers, [&](std::size_t slot) {
                outcomes[slot] = execute_plan(plans[slot]);
            });

        std::optional<MutationError> deterministic_error;
        for (const auto& outcome : outcomes) {
            if (!outcome &&
                (!deterministic_error ||
                 outcome.error().operation_index <
                     deterministic_error->operation_index)) {
                deterministic_error = outcome.error();
            }
        }
        if (deterministic_error) {
            return std::unexpected(*deterministic_error);
        }
        batch.objects.reserve(outcomes.size());
        for (auto& outcome : outcomes) {
            batch.objects.push_back(std::move(*outcome));
        }
    }

    commit_batch = true;
    return batch;
}

MutationResult transfer_upload_batch(const StagedUploadBatch& batch,
                                     transport::Transport& storage,
                                     std::size_t max_parallel_transfers) {
    if (batch.objects.empty()) {
        return {};
    }

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

MutationResult verify_upload_batch_individually(
    const StagedUploadBatch& batch,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const platform::Workspace& workspace,
    std::size_t parallelism,
    ProgressMeter* meter) {
    if (batch.objects.empty()) {
        return {};
    }

    std::vector<std::optional<MutationError>> errors(batch.objects.size());
    application::parallel_for_indexed(
        batch.objects.size(), parallelism, [&](std::size_t index) {
            const auto& object = batch.objects[index];
            auto result = detail::verify_uploaded_content_object(
                storage,
                key,
                object.identifier,
                object.plaintext_hash,
                object.plaintext_size,
                workspace,
                object.operation_indices.front(),
                object.ciphertext_sha256,
                object.is_pack,
                index);
            if (!result) {
                errors[index] = std::move(result.error());
            } else if (meter) {
                ProgressMeter::add(meter->work);
            }
        });

    // Deterministically finds the error with the smallest operation_index.
    std::optional<MutationError> deterministic_error;
    for (const auto& opt_error : errors) {
        if (opt_error && (!deterministic_error ||
                          opt_error->operation_index <
                              deterministic_error->operation_index)) {
            deterministic_error = *opt_error;
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
                    "rclone returned unexpected identifier during batch "
                    "verification",
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
            choose(object,
                   MutationErrorCode::IntegrityMismatch,
                   "remote physical hash does not match published ciphertext");
        } else if (has(report.missing)) {
            choose(object,
                   MutationErrorCode::IntegrityMismatch,
                   "remote object missing after batch upload");
        } else if (has(report.errors)) {
            choose(object,
                   MutationErrorCode::TransportFailure,
                   "rclone failed to physically verify remote object");
        } else if (!has(report.matched)) {
            choose(object,
                   MutationErrorCode::IntegrityMismatch,
                   "remote object unconfirmed in batch verification");
        }
    }
    return selected;
}

MutationResult
verify_upload_batch(const StagedUploadBatch& batch,
                    transport::Transport& storage,
                    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                    const platform::Workspace& workspace,
                    std::size_t parallelism,
                    ProgressMeter* meter) {
    if (batch.objects.empty()) {
        return {};
    }

    if (!transport::prefers_physical_hash_batch(storage,
                                                batch.objects.size())) {
        return verify_upload_batch_individually(
            batch, storage, key, workspace, parallelism, meter);
    }

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

    auto bulk = transport::physical_hash_batch(storage, request);
    if (bulk) {
        if (auto failure = bulk_verification_error(batch, *bulk)) {
            return std::unexpected(*failure);
        }
        if (meter)
            ProgressMeter::add(meter->work, batch.objects.size());
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
        batch, storage, key, workspace, parallelism, meter);
}

MutationResult cleanup_upload_batch(const StagedUploadBatch& batch) {
    if (batch.root.empty()) {
        return {};
    }

    const std::size_t operation_index =
        batch.objects.empty() ? 0
                              : batch.objects.front().operation_indices.front();
    std::error_code ec;
    if (!std::filesystem::exists(batch.root, ec)) {
        if (ec) {
            return std::unexpected(
                detail::make_error(MutationErrorCode::LocalIo,
                                   "stat failed before cleanup",
                                   batch.root,
                                   operation_index));
        }
        return {};
    }

    auto safe = platform::validate_non_redirecting_directory(batch.root);
    if (!safe) {
        return std::unexpected(detail::make_error(
            MutationErrorCode::UnsafePath,
            "directory is redirected (TOCTOU violation detected)",
            batch.root,
            operation_index));
    }

    std::filesystem::remove_all(batch.root, ec);
    if (ec) {
        return std::unexpected(detail::make_error(
            MutationErrorCode::LocalIo,
            "failed to safely cleanup batch staging directory",
            batch.root,
            operation_index));
    }

    return {};
}

} // namespace kasumi::application::sync::mutation
