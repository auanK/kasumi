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

namespace kasumi::application::sync::mutation::detail {

// Creates a mutation failure with operation context.
MutationError make_error(MutationErrorCode code,
                         std::string detail,
                         const std::filesystem::path& path,
                         std::size_t operation_index);

// Removes a temporary file without propagating failures.
void remove_temporary_file(const std::filesystem::path& path) noexcept;

// Reads path status and contextualizes any failure.
std::expected<std::filesystem::file_status, MutationError>
read_status(const std::filesystem::path& path, std::size_t operation_index);

// Indicates that the file status represents a missing path.
bool missing(std::filesystem::file_status status) noexcept;

// Resolves a relative path without allowing escape from the root.
std::expected<std::filesystem::path, MutationError>
resolve_local_path(const std::filesystem::path& local_root,
                   const std::filesystem::path& relative,
                   std::size_t operation_index);

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
