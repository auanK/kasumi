#ifndef KASUMI_APPLICATION_SYNC_MUTATION_DETAIL_HPP
#define KASUMI_APPLICATION_SYNC_MUTATION_DETAIL_HPP

#include "application/sync/mutation.hpp"
#include "core/transaction/types.hpp"
#include "crypto/file_crypto.hpp"
#include "platform/workspace.hpp"
#include "transport/transport.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::application::sync::mutation::detail {

// Creates a mutation failure with operation context.
MutationError make_error(MutationErrorCode code,
                         std::string detail,
                         const std::filesystem::path& path,
                         std::size_t operation_index);

// Removes a temporary file without propagating failures.
void remove_temporary_file(const std::filesystem::path& path) noexcept;

// Constructs the deterministic, transaction-namespaced rollback candidate.
std::filesystem::path
rollback_candidate_path(const std::filesystem::path& destination,
                        std::string_view transaction_id,
                        std::size_t operation_index);

// Computes cryptographic hash of a file and formats as hex string.
std::expected<std::string, MutationError>
file_hash(const std::filesystem::path& path, std::size_t operation_index);

// Reads path status and contextualizes any failure.
std::expected<std::filesystem::file_status, MutationError>
read_status(const std::filesystem::path& path, std::size_t operation_index);

// Indicates that the file status represents a missing path.
bool missing(std::filesystem::file_status status) noexcept;

// Checks progress and workspace/backup structure without reading content.
MutationResult
validate_prepared_operation(const Operation& operation,
                            std::size_t operation_index,
                            const std::filesystem::path& destination,
                            const platform::Workspace& workspace,
                            const transaction::OperationProgress& progress);

// Checks backup integrity and current authority before a download/delete
// effect.
MutationResult validate_prepared_destination(
    const Operation& operation,
    std::size_t operation_index,
    const std::filesystem::path& destination,
    const platform::Workspace& workspace,
    const transaction::OperationProgress& progress,
    const DestinationPrecondition* condition = nullptr);

// Indexes path transitions once; unrelated operations have no predecessor.
std::vector<std::size_t>
destination_dependencies(std::span<const Operation> operations);

// Derives execution authority only from an earlier, confirmed original rename.
std::expected<std::optional<DestinationPrecondition>, MutationError>
effective_destination(const transaction::Record& record,
                      std::size_t index,
                      std::span<const std::size_t> dependencies);

MutationResult
validate_prepared_rename(const Operation& operation,
                         std::size_t index,
                         const std::filesystem::path& source,
                         const std::filesystem::path& destination,
                         const platform::Workspace& workspace,
                         const transaction::OperationProgress& progress);

std::filesystem::path
download_candidate_path(const std::filesystem::path& destination,
                        const platform::Workspace& workspace,
                        std::size_t operation_index);

// Resolves a relative path without allowing escape from the root.
std::expected<std::filesystem::path, MutationError>
resolve_local_path(const std::filesystem::path& local_root,
                   const std::filesystem::path& relative,
                   std::size_t operation_index,
                   std::span<const Operation> plan_operations = {});

// Verifies the integrity of a newly uploaded object via physical hash or
// get/decrypt.
std::expected<void, MutationError> verify_uploaded_content_object(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    std::string_view identifier,
    std::string_view plaintext_hash,
    std::uint64_t expected_size,
    const platform::Workspace& workspace,
    std::size_t operation_index,
    std::string_view local_physical_hash);

struct PreparedUploadCiphertext {
    std::uint64_t plaintext_size = 0;
    std::string ciphertext_sha256;
};

std::expected<PreparedUploadCiphertext, MutationError>
prepare_upload_ciphertext(const transaction::Operation& operation,
                          std::size_t operation_index,
                          const std::filesystem::path& local_root,
                          const std::filesystem::path& destination,
                          std::span<const std::uint8_t, crypto::KEY_SIZE> key);

} // namespace kasumi::application::sync::mutation::detail

#endif
