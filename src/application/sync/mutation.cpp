#include "application/sync/mutation.hpp"

#include "crypto/content.hpp"
#include "mutation_detail.hpp"
#include "platform/perf_trace.hpp"
#include "platform/random.hpp"

#include <limits>
#include <optional>
#include <system_error>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace kasumi::application::sync::mutation {

namespace {

using detail::make_error;
using detail::missing;
using detail::read_status;
using detail::remove_temporary_file;
using detail::resolve_local_path;

std::expected<void, MutationError>
replace_local_file(const std::filesystem::path& source,
                   const std::filesystem::path& destination,
                   std::size_t operation_index) {
#if defined(_WIN32)
    if (MoveFileExW(source.wstring().c_str(),
                    destination.wstring().c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
        return std::unexpected(
            make_error(MutationErrorCode::LocalIo,
                       "falha ao substituir arquivo local atomicamente",
                       destination,
                       operation_index));
    }
#else
    std::error_code error;
    std::filesystem::rename(source, destination, error);
    if (error) {
        return std::unexpected(
            make_error(MutationErrorCode::LocalIo,
                       "falha ao substituir arquivo local atomicamente: " +
                           error.message(),
                       destination,
                       operation_index));
    }
#endif
    return {};
}

std::expected<void, MutationError>
move_local_without_replace(const std::filesystem::path& source,
                           const std::filesystem::path& destination,
                           std::size_t operation_index) {
#if defined(_WIN32)
    const bool moved = MoveFileExW(source.wstring().c_str(),
                                   destination.wstring().c_str(),
                                   MOVEFILE_WRITE_THROUGH) != 0;
    if (!moved) {
        const auto native_error = GetLastError();
        const auto code = native_error == ERROR_ALREADY_EXISTS ||
                                  native_error == ERROR_FILE_EXISTS
                              ? MutationErrorCode::DestinationConflict
                              : MutationErrorCode::LocalIo;
        return std::unexpected(
            make_error(code,
                       "falha ao mover arquivo sem substituição (native_code=" +
                           std::to_string(native_error) + ")",
                       destination,
                       operation_index));
    }
#else
    auto source_status = read_status(source, operation_index);
    if (!source_status) {
        return std::unexpected(source_status.error());
    }
    if (std::filesystem::is_symlink(*source_status) ||
        !std::filesystem::is_regular_file(*source_status)) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "a origem não é um arquivo regular sem symlink",
                       source,
                       operation_index));
    }

    std::error_code error;
    std::filesystem::create_hard_link(source, destination, error);
    if (error) {
        if (error == std::errc::file_exists) {
            return std::unexpected(
                make_error(MutationErrorCode::DestinationConflict,
                           "o destino do rename já existe",
                           destination,
                           operation_index));
        }
        return std::unexpected(make_error(
            MutationErrorCode::LocalIo,
            "não foi possível criar link do rename: " + error.message(),
            destination,
            operation_index));
    }

    std::error_code remove_error;
    const bool removed = std::filesystem::remove(source, remove_error);
    if (!removed || remove_error) {
        remove_temporary_file(destination);
        return std::unexpected(
            make_error(MutationErrorCode::LocalIo,
                       "não foi possível remover a origem do rename: " +
                           (remove_error ? remove_error.message()
                                         : std::string{"origem ausente"}),
                       source,
                       operation_index));
    }
#endif
    return {};
}

std::expected<void, MutationError>
verify_local_file(const std::filesystem::path& path,
                  const Operation& operation,
                  std::size_t operation_index) {
    auto result =
        crypto::content::verify_file(path, operation.hash, operation.size);
    if (!result) {
        return std::unexpected(make_error(MutationErrorCode::IntegrityMismatch,
                                          result.error(),
                                          path,
                                          operation_index));
    }
    return {};
}

} // namespace

namespace detail {

std::optional<std::uintmax_t>
encoded_content_size(std::uint64_t plaintext_size) noexcept {
    constexpr auto header_size =
        static_cast<std::uintmax_t>(crypto::FILE_HEADER_SIZE);
    constexpr auto maximum = std::numeric_limits<std::uintmax_t>::max();

    if (plaintext_size > maximum - header_size) {
        return std::nullopt;
    }

    const auto chunks = plaintext_size / crypto::CHUNK_SIZE +
                        (plaintext_size % crypto::CHUNK_SIZE != 0 ? 1 : 0);
    auto encoded_size = header_size + plaintext_size;
    if (chunks > (maximum - encoded_size) / crypto::MAC_SIZE) {
        return std::nullopt;
    }
    encoded_size += chunks * crypto::MAC_SIZE;
    return encoded_size;
}

std::expected<void, MutationError> verify_uploaded_content_object(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    std::string_view identifier,
    std::string_view plaintext_hash,
    std::uint64_t expected_size,
    const platform::Workspace& workspace,
    std::size_t operation_index,
    std::string_view local_physical_hash) {
    constexpr std::string_view physical_hash_algorithm = "sha256";

    platform::perf_trace::count("content individual hash calls");
    const auto remote_hash_trace = platform::perf_trace::begin();
    auto remote_hash =
        transport::physical_hash(storage, identifier, physical_hash_algorithm);
    platform::perf_trace::finish("content remote hash verification",
                                 remote_hash_trace);
    if (remote_hash) {
        if (*remote_hash == local_physical_hash) {
            return {};
        }
        return std::unexpected(make_error(
            MutationErrorCode::IntegrityMismatch,
            "o hash físico remoto não corresponde ao ciphertext publicado",
            {},
            operation_index));
    }
    if (remote_hash.error().code != transport::ErrorCode::Unsupported) {
        if (remote_hash.error().code == transport::ErrorCode::ObjectNotFound) {
            return std::unexpected(
                make_error(MutationErrorCode::IntegrityMismatch,
                           "objeto remoto ausente após upload",
                           {},
                           operation_index));
        }
        return std::unexpected(
            make_error(MutationErrorCode::TransportFailure,
                       transport::describe(remote_hash.error()),
                       {},
                       operation_index));
    }

    // Without reliable remote hash, validates via GET, decryption, and BLAKE3.
    const auto encrypted = platform::workspace_file(
        workspace, operation_index, ".upload.verify.enc");
    const auto plaintext = platform::workspace_file(
        workspace, operation_index, ".upload.verify.plain");
    if (encrypted.empty() || plaintext.empty()) {
        return std::unexpected(
            make_error(MutationErrorCode::LocalIo,
                       "caminho temporário inválido para verificar upload",
                       encrypted,
                       operation_index));
    }

    const auto cleanup = [&] {
        remove_temporary_file(encrypted);
        remove_temporary_file(plaintext);
    };
    cleanup();

    if (!hash_from_hex(identifier) || !hash_from_hex(plaintext_hash)) {
        return std::unexpected(
            make_error(MutationErrorCode::IntegrityMismatch,
                       "identificador do objeto criptografado inválido",
                       encrypted,
                       operation_index));
    }

    const auto get_trace = platform::perf_trace::begin();
    auto downloaded = transport::get(storage, identifier, encrypted);
    platform::perf_trace::finish("rc/get_content", get_trace);
    if (!downloaded) {
        cleanup();
        if (downloaded.error().code == transport::ErrorCode::ObjectNotFound) {
            return std::unexpected(
                make_error(MutationErrorCode::IntegrityMismatch,
                           "objeto remoto ausente após upload",
                           encrypted,
                           operation_index));
        }
        return std::unexpected(
            make_error(MutationErrorCode::TransportFailure,
                       transport::describe(downloaded.error()),
                       encrypted,
                       operation_index));
    }

    auto status = read_status(encrypted, operation_index);
    if (!status || std::filesystem::is_symlink(*status) ||
        !std::filesystem::is_regular_file(*status)) {
        cleanup();
        return std::unexpected(make_error(
            MutationErrorCode::IntegrityMismatch,
            "o objeto criptografado baixado não é um arquivo regular",
            encrypted,
            operation_index));
    }

    const auto expected_ciphertext_size = encoded_content_size(expected_size);
    std::error_code size_error;
    const auto actual_ciphertext_size =
        std::filesystem::file_size(encrypted, size_error);
    if (size_error || !expected_ciphertext_size ||
        actual_ciphertext_size != *expected_ciphertext_size) {
        cleanup();
        return std::unexpected(make_error(
            MutationErrorCode::IntegrityMismatch,
            "o tamanho do ciphertext não corresponde ao plaintext esperado",
            encrypted,
            operation_index));
    }

    if (!crypto::decrypt_file(encrypted, plaintext, key)) {
        cleanup();
        return std::unexpected(
            make_error(MutationErrorCode::CryptoFailure,
                       "não foi possível descriptografar o objeto publicado",
                       encrypted,
                       operation_index));
    }

    auto plaintext_status = read_status(plaintext, operation_index);
    if (!plaintext_status || std::filesystem::is_symlink(*plaintext_status) ||
        !std::filesystem::is_regular_file(*plaintext_status)) {
        cleanup();
        return std::unexpected(
            make_error(MutationErrorCode::IntegrityMismatch,
                       "o plaintext descriptografado não é um arquivo regular",
                       plaintext,
                       operation_index));
    }

    auto verified =
        crypto::content::verify_file(plaintext, plaintext_hash, expected_size);
    if (!verified) {
        cleanup();
        return std::unexpected(make_error(MutationErrorCode::IntegrityMismatch,
                                          verified.error(),
                                          plaintext,
                                          operation_index));
    }

    cleanup();
    return {};
}

} // namespace detail

namespace {

MutationResult
apply_upload(const Operation& operation,
             std::size_t operation_index,
             const std::filesystem::path& source,
             transport::Transport& storage,
             const platform::Workspace& workspace,
             std::span<const std::uint8_t, crypto::KEY_SIZE> key) {
    auto expected_hash = hash_from_hex(operation.hash);
    auto source_status = read_status(source, operation_index);
    if (!expected_hash || !source_status ||
        std::filesystem::is_symlink(*source_status) ||
        !std::filesystem::is_regular_file(*source_status)) {
        return std::unexpected(
            make_error(MutationErrorCode::IntegrityMismatch,
                       "a origem do upload não é um arquivo regular válido",
                       source,
                       operation_index));
    }
    const auto remote_identifier =
        crypto::content_identifier(key, *expected_hash);

    const auto encrypted =
        platform::workspace_file(workspace, operation_index, ".upload.enc");
    if (encrypted.empty()) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "caminho temporário inválido",
                                          source,
                                          operation_index));
    }

    std::error_code cleanup_error;
    std::filesystem::remove(encrypted, cleanup_error);
    if (cleanup_error) {
        remove_temporary_file(encrypted);
        return std::unexpected(
            make_error(MutationErrorCode::LocalIo,
                       "não foi possível remover ciphertext anterior: " +
                           cleanup_error.message(),
                       encrypted,
                       operation_index));
    }

    auto prepared = detail::prepare_upload_ciphertext(
        operation, operation_index, source, encrypted, key);

    if (!prepared) {
        remove_temporary_file(encrypted);
        return std::unexpected(prepared.error());
    }

    const auto put_trace = platform::perf_trace::begin();
    auto uploaded = transport::put(storage, encrypted, remote_identifier);
    platform::perf_trace::finish("content PUT", put_trace);
    platform::perf_trace::finish("rc/put_content", put_trace);
    if (!uploaded &&
        !transport::mutation_result_is_ambiguous(uploaded.error())) {
        remove_temporary_file(encrypted);
        return std::unexpected(make_error(MutationErrorCode::TransportFailure,
                                          transport::describe(uploaded.error()),
                                          source,
                                          operation_index));
    }

    const auto verification_trace = platform::perf_trace::begin();
    auto uploaded_verification =
        detail::verify_uploaded_content_object(storage,
                                               key,
                                               remote_identifier,
                                               operation.hash,
                                               operation.size,
                                               workspace,
                                               operation_index,
                                               prepared->ciphertext_sha256);
    platform::perf_trace::finish("content verification", verification_trace);
    std::error_code encrypted_remove_error;
    std::filesystem::remove(encrypted, encrypted_remove_error);
    if (!uploaded_verification) {
        remove_temporary_file(encrypted);
        return std::unexpected(uploaded_verification.error());
    }

    if (encrypted_remove_error) {
        remove_temporary_file(encrypted);
        return std::unexpected(
            make_error(MutationErrorCode::LocalIo,
                       "não foi possível remover o arquivo temporário: " +
                           encrypted_remove_error.message(),
                       encrypted,
                       operation_index));
    }

    return {};
}

MutationResult
apply_download(const Operation& operation,
               std::size_t operation_index,
               const std::filesystem::path& destination,
               transport::Transport& storage,
               const platform::Workspace& workspace,
               std::span<const std::uint8_t, crypto::KEY_SIZE> key,
               DownloadCacheMode download_cache) {
    auto expected_hash = hash_from_hex(operation.hash);
    if (!expected_hash) {
        return std::unexpected(make_error(MutationErrorCode::IntegrityMismatch,
                                          expected_hash.error(),
                                          destination,
                                          operation_index));
    }
    const auto remote_identifier =
        crypto::content_identifier(key, *expected_hash);

    auto destination_status = read_status(destination, operation_index);
    if (!destination_status) {
        return std::unexpected(destination_status.error());
    }
    if (std::filesystem::is_symlink(*destination_status)) {
        return std::unexpected(make_error(MutationErrorCode::UnsafePath,
                                          "o destino é um symlink",
                                          destination,
                                          operation_index));
    }
    if (std::filesystem::is_regular_file(*destination_status)) {
        auto verified =
            verify_local_file(destination, operation, operation_index);
        if (verified) {
            return {};
        }
    } else if (!missing(*destination_status)) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "o destino não é um arquivo regular",
                       destination,
                       operation_index));
    }

    const auto parent = destination.parent_path();
    auto parent_status = read_status(parent, operation_index);
    if (!parent_status) {
        return std::unexpected(parent_status.error());
    }
    if (std::filesystem::is_symlink(*parent_status) ||
        !std::filesystem::is_directory(*parent_status)) {
        return std::unexpected(
            make_error(MutationErrorCode::UnsafePath,
                       "o diretório pai do destino é inválido",
                       parent,
                       operation_index));
    }

    auto id = platform::random::hex_id();
    if (!id) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          id.error(),
                                          destination,
                                          operation_index));
    }
    const auto candidate =
        parent / ("." + destination.filename().string() + ".kasumi-new-" + *id);
    auto candidate_status = read_status(candidate, operation_index);
    if (!candidate_status) {
        return std::unexpected(candidate_status.error());
    }
    if (!missing(*candidate_status)) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "o candidato local já existe",
                       candidate,
                       operation_index));
    }

    const bool cache_plaintext = download_cache != DownloadCacheMode::None &&
                                 operation.size >= crypto::CHUNK_SIZE;
    const auto plaintext =
        cache_plaintext
            ? platform::workspace_file(workspace,
                                       "download-" + operation.hash + ".plain")
            : std::filesystem::path{};
    if (cache_plaintext && plaintext.empty()) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "caminho temporário inválido",
                                          destination,
                                          operation_index));
    }

    bool candidate_ready = false;
    if (cache_plaintext) {
        auto plaintext_status = read_status(plaintext, operation_index);
        if (!plaintext_status) {
            return std::unexpected(plaintext_status.error());
        }
        if (std::filesystem::is_symlink(*plaintext_status) ||
            (!missing(*plaintext_status) &&
             !std::filesystem::is_regular_file(*plaintext_status))) {
            return std::unexpected(
                make_error(MutationErrorCode::UnsafePath,
                           "o cache plaintext transacional é inválido",
                           plaintext,
                           operation_index));
        }
        if (download_cache == DownloadCacheMode::Reuse &&
            std::filesystem::is_regular_file(*plaintext_status)) {
            const auto copy_trace = platform::perf_trace::begin();
            std::error_code copy_error;
            std::filesystem::copy_file(plaintext, candidate, copy_error);
            platform::perf_trace::finish("download plaintext copy", copy_trace);
            if (!copy_error) {
                auto verified =
                    verify_local_file(candidate, operation, operation_index);
                if (verified) {
                    platform::perf_trace::count("content plaintext reused");
                    candidate_ready = true;
                }
            }
            if (!candidate_ready) {
                std::error_code cleanup_error;
                std::filesystem::remove(candidate, cleanup_error);
                std::filesystem::remove(plaintext, cleanup_error);
            }
        }
    }

    const auto encrypted =
        download_cache == DownloadCacheMode::None
            ? platform::workspace_file(
                  workspace, operation_index, ".download.enc")
            : platform::workspace_file(workspace,
                                       "download-" + operation.hash + ".enc");
    if (encrypted.empty()) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "caminho temporário inválido",
                                          destination,
                                          operation_index));
    }

    if (!candidate_ready) {
        auto encrypted_status = read_status(encrypted, operation_index);
        if (!encrypted_status) {
            return std::unexpected(encrypted_status.error());
        }
        if (std::filesystem::is_symlink(*encrypted_status)) {
            return std::unexpected(
                make_error(MutationErrorCode::UnsafePath,
                           "o arquivo temporário criptografado é um symlink",
                           encrypted,
                           operation_index));
        }

        const bool reuse_cached =
            download_cache == DownloadCacheMode::Reuse &&
            std::filesystem::is_regular_file(*encrypted_status);
        if (reuse_cached) {
            platform::perf_trace::count("content downloads reused");
        } else {
            const auto get_trace = platform::perf_trace::begin();
            auto downloaded =
                transport::get(storage, remote_identifier, encrypted);
            platform::perf_trace::finish("rc/get_content", get_trace);
            if (!downloaded) {
                std::error_code cleanup_error;
                std::filesystem::remove(encrypted, cleanup_error);
                return std::unexpected(
                    make_error(MutationErrorCode::TransportFailure,
                               transport::describe(downloaded.error()),
                               destination,
                               operation_index));
            }
        }

        auto encrypted_after_get = read_status(encrypted, operation_index);
        if (!encrypted_after_get ||
            std::filesystem::is_symlink(*encrypted_after_get) ||
            !std::filesystem::is_regular_file(*encrypted_after_get)) {
            std::error_code cleanup_error;
            std::filesystem::remove(encrypted, cleanup_error);
            return std::unexpected(
                make_error(MutationErrorCode::LocalIo,
                           "o objeto criptografado baixado é inválido",
                           encrypted,
                           operation_index));
        }

        const auto decrypt_trace = platform::perf_trace::begin();
        const bool decrypted = crypto::decrypt_file(encrypted, candidate, key);
        platform::perf_trace::finish("download decryption", decrypt_trace);
        if (!decrypted) {
            std::error_code encrypted_cleanup_error;
            std::filesystem::remove(encrypted, encrypted_cleanup_error);
            std::error_code candidate_cleanup_error;
            std::filesystem::remove(candidate, candidate_cleanup_error);
            return std::unexpected(
                make_error(MutationErrorCode::CryptoFailure,
                           "não foi possível descriptografar o objeto",
                           destination,
                           operation_index));
        }

        auto verified =
            verify_local_file(candidate, operation, operation_index);
        if (!verified) {
            std::error_code encrypted_cleanup_error;
            std::filesystem::remove(encrypted, encrypted_cleanup_error);
            std::error_code candidate_cleanup_error;
            std::filesystem::remove(candidate, candidate_cleanup_error);
            return std::unexpected(
                make_error(MutationErrorCode::IntegrityMismatch,
                           verified.error().detail,
                           destination,
                           operation_index));
        }

        if (cache_plaintext) {
            const auto copy_trace = platform::perf_trace::begin();
            std::error_code copy_error;
            std::filesystem::copy_file(candidate, plaintext, copy_error);
            platform::perf_trace::finish("download plaintext copy", copy_trace);
            if (!copy_error) {
                auto cache_verified =
                    verify_local_file(plaintext, operation, operation_index);
                if (!cache_verified) {
                    std::filesystem::remove(plaintext, copy_error);
                }
            } else {
                std::filesystem::remove(plaintext, copy_error);
            }
        }
    }

    auto replaced = replace_local_file(candidate, destination, operation_index);
    if (!replaced) {
        std::error_code candidate_cleanup_error;
        std::filesystem::remove(candidate, candidate_cleanup_error);
        return std::unexpected(replaced.error());
    }
    if (download_cache == DownloadCacheMode::None) {
        std::error_code encrypted_cleanup_error;
        std::filesystem::remove(encrypted, encrypted_cleanup_error);
        if (encrypted_cleanup_error) {
            return std::unexpected(
                make_error(MutationErrorCode::LocalIo,
                           "não foi possível remover o objeto temporário: " +
                               encrypted_cleanup_error.message(),
                           encrypted,
                           operation_index));
        }
    }

    return {};
}

MutationResult apply_rename(const Operation& operation,
                            std::size_t operation_index,
                            const std::filesystem::path& source,
                            const std::filesystem::path& destination) {
    auto source_status = read_status(source, operation_index);
    if (!source_status) {
        return std::unexpected(source_status.error());
    }
    auto destination_status = read_status(destination, operation_index);
    if (!destination_status) {
        return std::unexpected(destination_status.error());
    }
    if (std::filesystem::is_symlink(*source_status) ||
        std::filesystem::is_symlink(*destination_status)) {
        return std::unexpected(make_error(
            MutationErrorCode::UnsafePath,
            "rename não aceita symlink",
            std::filesystem::is_symlink(*source_status) ? source : destination,
            operation_index));
    }

    const bool source_missing = missing(*source_status);
    const bool destination_missing = missing(*destination_status);
    if (!source_missing && destination_missing) {
        auto result =
            move_local_without_replace(source, destination, operation_index);
        if (!result) {
            return std::unexpected(result.error());
        }
        return {};
    }
    if (source_missing && !destination_missing) {
        return {};
    }
    if (!source_missing && !destination_missing) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "o destino do rename já existe",
                       destination,
                       operation_index));
    }
    return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                      "origem e destino do rename não existem",
                                      operation.path,
                                      operation_index));
}

std::string mutation_code_name(MutationErrorCode code) noexcept {
    switch (code) {
        case MutationErrorCode::InvalidOperation:
            return "invalid_operation";
        case MutationErrorCode::UnsafePath:
            return "unsafe_path";
        case MutationErrorCode::LocalIo:
            return "local_io";
        case MutationErrorCode::TransportFailure:
            return "transport_failure";
        case MutationErrorCode::RemoteResultUnknown:
            return "remote_result_unknown";
        case MutationErrorCode::CryptoFailure:
            return "crypto_failure";
        case MutationErrorCode::IntegrityMismatch:
            return "integrity_mismatch";
        case MutationErrorCode::DestinationConflict:
            return "destination_conflict";
    }
    return "local_io";
}

} // namespace

MutationResult
apply_operation(const Operation& operation,
                std::size_t operation_index,
                const std::filesystem::path& local_root,
                transport::Transport& storage,
                std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                const platform::Workspace& workspace,
                DownloadCacheMode download_cache) {
    if (!is_valid_action(operation.action) || !has_safe_paths(operation)) {
        return std::unexpected(
            make_error(!is_valid_action(operation.action)
                           ? MutationErrorCode::InvalidOperation
                           : MutationErrorCode::UnsafePath,
                       "operação ou caminho inválido",
                       operation.path,
                       operation_index));
    }

    switch (operation.action) {
        case Action::RenameLocal: {
            auto source =
                resolve_local_path(local_root, operation.path, operation_index);
            if (!source) {
                return std::unexpected(source.error());
            }
            auto destination = resolve_local_path(
                local_root, operation.alt_path, operation_index);
            if (!destination) {
                return std::unexpected(destination.error());
            }
            return apply_rename(
                operation, operation_index, *source, *destination);
        }

        case Action::Upload: {
            auto source =
                resolve_local_path(local_root, operation.path, operation_index);
            if (!source) {
                return std::unexpected(source.error());
            }
            return apply_upload(
                operation, operation_index, *source, storage, workspace, key);
        }

        case Action::CreateLocalDirectory: {
            auto path =
                resolve_local_path(local_root, operation.path, operation_index);
            if (!path) {
                return std::unexpected(path.error());
            }
            auto status = read_status(*path, operation_index);
            if (!status) {
                return std::unexpected(status.error());
            }
            if (!missing(*status)) {
                if (std::filesystem::is_symlink(*status)) {
                    return std::unexpected(
                        make_error(MutationErrorCode::UnsafePath,
                                   "o diretório de destino é um symlink",
                                   *path,
                                   operation_index));
                }
                if (std::filesystem::is_directory(*status)) {
                    return {};
                }
                return std::unexpected(
                    make_error(MutationErrorCode::DestinationConflict,
                               "o destino não é um diretório",
                               *path,
                               operation_index));
            }
            std::error_code error;
            std::filesystem::create_directories(*path, error);
            if (error) {
                return std::unexpected(make_error(
                    MutationErrorCode::LocalIo,
                    "não foi possível criar diretório: " + error.message(),
                    *path,
                    operation_index));
            }
            return {};
        }

        case Action::CreateRemoteDirectory:
            if (operation.path.empty() || operation.path == ".") {
                return std::unexpected(
                    make_error(MutationErrorCode::InvalidOperation,
                               "diretório remoto sem caminho",
                               operation.path,
                               operation_index));
            }
            return {};

        case Action::Download: {
            auto destination =
                resolve_local_path(local_root, operation.path, operation_index);
            if (!destination) {
                return std::unexpected(destination.error());
            }
            return apply_download(operation,
                                  operation_index,
                                  *destination,
                                  storage,
                                  workspace,
                                  key,
                                  download_cache);
        }

        case Action::DeleteLocal: {
            auto path =
                resolve_local_path(local_root, operation.path, operation_index);
            if (!path) {
                return std::unexpected(path.error());
            }
            auto status = read_status(*path, operation_index);
            if (!status) {
                return std::unexpected(status.error());
            }
            if (missing(*status)) {
                return {};
            }
            if (std::filesystem::is_symlink(*status)) {
                return std::unexpected(
                    make_error(MutationErrorCode::UnsafePath,
                               "não é permitido remover symlink",
                               *path,
                               operation_index));
            }
            if (!std::filesystem::is_regular_file(*status)) {
                return std::unexpected(
                    make_error(MutationErrorCode::DestinationConflict,
                               "o caminho não é um arquivo regular",
                               *path,
                               operation_index));
            }
            std::error_code error;
            std::filesystem::remove(*path, error);
            if (error) {
                return std::unexpected(make_error(
                    MutationErrorCode::LocalIo,
                    "não foi possível remover arquivo: " + error.message(),
                    *path,
                    operation_index));
            }
            return {};
        }

        case Action::DeleteLocalDirectory: {
            auto path =
                resolve_local_path(local_root, operation.path, operation_index);
            if (!path) {
                return std::unexpected(path.error());
            }
            auto status = read_status(*path, operation_index);
            if (!status) {
                return std::unexpected(status.error());
            }
            if (missing(*status)) {
                return {};
            }
            if (std::filesystem::is_symlink(*status)) {
                return std::unexpected(
                    make_error(MutationErrorCode::UnsafePath,
                               "não é permitido remover symlink",
                               *path,
                               operation_index));
            }
            if (!std::filesystem::is_directory(*status)) {
                return std::unexpected(
                    make_error(MutationErrorCode::DestinationConflict,
                               "o caminho não é um diretório",
                               *path,
                               operation_index));
            }
            std::error_code error;
            std::filesystem::remove(*path, error);
            if (error) {
                return std::unexpected(make_error(
                    MutationErrorCode::LocalIo,
                    "não foi possível remover diretório: " + error.message(),
                    *path,
                    operation_index));
            }
            return {};
        }

        case Action::DeleteRemote:
            return {};

        case Action::DeleteRemoteDirectory:
            if (operation.path.empty() || operation.path == ".") {
                return std::unexpected(
                    make_error(MutationErrorCode::InvalidOperation,
                               "diretório remoto sem caminho",
                               operation.path,
                               operation_index));
            }
            return {};

        case Action::Count:
            break;
    }

    return std::unexpected(
        make_error(MutationErrorCode::InvalidOperation,
                   "ação de contagem não é uma operação mutável",
                   operation.path,
                   operation_index));
}

std::string describe(const MutationError& error) {
    std::string result = mutation_code_name(error.code);
    result += " na operação ";
    result += std::to_string(error.operation_index);
    if (!error.path.empty()) {
        result += " ('";
        result += error.path.string();
        result += "')";
    }
    if (!error.detail.empty()) {
        result += ": ";
        result += error.detail;
    }
    return result;
}

} // namespace kasumi::application::sync::mutation
