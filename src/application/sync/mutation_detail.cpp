#include "mutation_detail.hpp"

#include "platform/perf_trace.hpp"

#include <algorithm>
#include <iterator>
#include <system_error>
#include <utility>

namespace kasumi::application::sync::mutation::detail {

namespace {

bool path_not_found(const std::error_code& error) noexcept {
    return error == std::errc::no_such_file_or_directory;
}

} // namespace

MutationError make_error(MutationErrorCode code,
                         std::string detail,
                         const std::filesystem::path& path,
                         std::size_t operation_index) {
    return MutationError{
        .code = code,
        .detail = std::move(detail),
        .path = path,
        .operation_index = operation_index,
    };
}

void remove_temporary_file(const std::filesystem::path& path) noexcept {
    std::error_code error;
    std::filesystem::remove(path, error);
}

std::expected<std::filesystem::file_status, MutationError>
read_status(const std::filesystem::path& path, std::size_t operation_index) {
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (path_not_found(error)) {
        return std::filesystem::file_status{
            std::filesystem::file_type::not_found};
    }

    if (error) {
        return std::unexpected(make_error(
            MutationErrorCode::LocalIo,
            "não foi possível consultar o caminho: " + error.message(),
            path,
            operation_index));
    }
    return status;
}

bool missing(std::filesystem::file_status status) noexcept {
    return status.type() == std::filesystem::file_type::not_found;
}

std::expected<std::filesystem::path, MutationError>
resolve_local_path(const std::filesystem::path& local_root,
                   const std::filesystem::path& relative,
                   std::size_t operation_index) {
    if (relative.empty() || relative == "." || relative.is_absolute() ||
        relative.has_root_name() || relative.has_root_directory() ||
        std::ranges::find(relative, std::filesystem::path{".."}) !=
            relative.end()) {
        return std::unexpected(make_error(MutationErrorCode::UnsafePath,
                                          "caminho relativo inválido",
                                          relative,
                                          operation_index));
    }

    auto root_status = read_status(local_root, operation_index);
    if (!root_status) {
        return std::unexpected(root_status.error());
    }
    if (std::filesystem::is_symlink(*root_status)) {
        return std::unexpected(make_error(MutationErrorCode::UnsafePath,
                                          "a raiz local é um symlink",
                                          local_root,
                                          operation_index));
    }
    if (!std::filesystem::is_directory(*root_status)) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "a raiz local não é um diretório",
                                          local_root,
                                          operation_index));
    }

    const auto normalized_root = local_root.lexically_normal();
    const auto candidate = (normalized_root / relative).lexically_normal();
    const auto relative_candidate =
        candidate.lexically_relative(normalized_root);
    if (relative_candidate.empty() || relative_candidate.is_absolute() ||
        relative_candidate.has_root_name() ||
        relative_candidate.has_root_directory() ||
        std::ranges::find(relative_candidate, std::filesystem::path{".."}) !=
            relative_candidate.end()) {
        return std::unexpected(make_error(MutationErrorCode::UnsafePath,
                                          "caminho escapa da raiz local",
                                          relative,
                                          operation_index));
    }

    auto current = normalized_root;
    const auto component_count = static_cast<std::size_t>(
        std::distance(relative.begin(), relative.end()));
    std::size_t component_index = 0;
    for (const auto& component : relative) {
        current /= component;
        auto status = read_status(current, operation_index);
        if (!status) {
            return std::unexpected(status.error());
        }
        if (missing(*status)) {
            break;
        }
        if (std::filesystem::is_symlink(*status)) {
            return std::unexpected(make_error(MutationErrorCode::UnsafePath,
                                              "o caminho contém um symlink",
                                              current,
                                              operation_index));
        }
        const bool is_last = component_index + 1 == component_count;
        if (!is_last && !std::filesystem::is_directory(*status)) {
            return std::unexpected(
                make_error(MutationErrorCode::LocalIo,
                           "componente intermediário não é um diretório",
                           current,
                           operation_index));
        }
        ++component_index;
    }

    return candidate;
}

std::expected<PreparedUploadCiphertext, MutationError>
prepare_upload_ciphertext(const transaction::Operation& operation,
                          std::size_t operation_index,
                          const std::filesystem::path& source,
                          const std::filesystem::path& destination,
                          std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    auto expected_hash = hash_from_hex(operation.hash);
    if (!expected_hash) {
        return std::unexpected(
            make_error(MutationErrorCode::InvalidOperation,
                       "identificador de objeto de conteúdo inválido",
                       {},
                       operation_index));
    }

    auto source_status = read_status(source, operation_index);
    if (!source_status || std::filesystem::is_symlink(*source_status) ||
        !std::filesystem::is_regular_file(*source_status)) {
        return std::unexpected(
            make_error(MutationErrorCode::IntegrityMismatch,
                       "a origem do upload não é um arquivo regular válido",
                       source,
                       operation_index));
    }

    const auto encryption_trace = platform::perf_trace::begin();
    auto encrypted_file = crypto::encrypt_file_with_hashes(source, destination, key);
    platform::perf_trace::finish("content encryption", encryption_trace);
    if (!encrypted_file) {
        return std::unexpected(
            make_error(MutationErrorCode::CryptoFailure,
                       "não foi possível criptografar a origem para upload",
                       source,
                       operation_index));
    }

    if (encrypted_file->plaintext_hash != *expected_hash ||
        encrypted_file->plaintext_size != operation.size) {
        remove_temporary_file(destination);
        return std::unexpected(make_error(MutationErrorCode::IntegrityMismatch,
                                          "a origem mudou durante o upload",
                                          source,
                                          operation_index));
    }

    auto encrypted_status = read_status(destination, operation_index);
    if (!encrypted_status || std::filesystem::is_symlink(*encrypted_status) ||
        !std::filesystem::is_regular_file(*encrypted_status)) {
        remove_temporary_file(destination);
        return std::unexpected(
            make_error(MutationErrorCode::LocalIo,
                       "o arquivo criptografado não foi criado corretamente",
                       destination,
                       operation_index));
    }

    return PreparedUploadCiphertext{
        .plaintext_size = operation.size,
        .ciphertext_sha256 = encrypted_file->ciphertext_sha256};
}

} // namespace kasumi::application::sync::mutation::detail
