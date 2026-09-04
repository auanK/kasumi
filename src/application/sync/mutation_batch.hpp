#ifndef KASUMI_APPLICATION_SYNC_MUTATION_BATCH_HPP
#define KASUMI_APPLICATION_SYNC_MUTATION_BATCH_HPP

#include "application/sync/mutation.hpp"
#include "core/transaction/types.hpp"
#include "crypto/file_crypto.hpp"
#include "platform/workspace.hpp"
#include "transport/transport.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace kasumi::application::sync::mutation {

// Represents staged content ready (encrypted) for upload.
struct StagedUploadObject {
    std::string identifier;
    std::string plaintext_hash;
    std::uint64_t plaintext_size = 0;
    std::string ciphertext_sha256;
    std::vector<std::size_t> operation_indices;
};

// Collection of pending encrypted contents grouped under a staging root.
struct StagedUploadBatch {
    std::filesystem::path root;
    std::vector<StagedUploadObject> objects;
};

// Sequentially encrypts upload operations into staging, handling
// potential duplicates. Returns the batch on success or the first failure.
std::expected<StagedUploadBatch, MutationError>
stage_upload_batch(std::span<const std::size_t> operation_indices,
                   const transaction::Record& record,
                   const std::filesystem::path& local_root,
                   std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                   const platform::Workspace& workspace);

// Constructs the request and uploads the batch objects.
MutationResult transfer_upload_batch(const StagedUploadBatch& batch,
                                     transport::Transport& storage,
                                     std::size_t max_parallel_transfers);

// Verifies remote integrity of batch objects concurrently, bounding
// in-flight requests by parallelism. Fails deterministically on the lowest-index error.
MutationResult
verify_upload_batch(const StagedUploadBatch& batch,
                    transport::Transport& storage,
                    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                    const platform::Workspace& workspace,
                    std::size_t parallelism);

// Removes files from upload staging in a fault-tolerant manner,
// returning errors if encountered.
MutationResult cleanup_upload_batch(const StagedUploadBatch& batch);

} // namespace kasumi::application::sync::mutation

#endif
