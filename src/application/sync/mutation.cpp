#include "application/sync/mutation.hpp"

#include "crypto/content.hpp"
#include "crypto/key_derivation.hpp"
#include "crypto/pack.hpp"
#include "mutation_detail.hpp"
#include "mutation_fault_test.hpp"
#include "platform/durability.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"

#include <array>
#include <fstream>
#include <limits>
#include <optional>
#include <system_error>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace kasumi::application::sync::mutation {

namespace {

using detail::file_hash;
using detail::identity_matches;
using detail::make_error;
using detail::missing;
using detail::read_status;
using detail::remove_temporary_file;
using detail::require_regular_file;
using detail::resolve_local_path;
using detail::sync_file_checked;
using detail::sync_parent_checked;

std::expected<void, MutationError>
validate_parent_directory(const std::filesystem::path& destination,
                          std::size_t operation_index) {
    const auto parent = destination.parent_path();
    auto parent_status = read_status(parent, operation_index);
    if (!parent_status) {
        return std::unexpected(parent_status.error());
    }
    if (missing(*parent_status) ||
        std::filesystem::is_symlink(*parent_status) ||
        !std::filesystem::is_directory(*parent_status)) {
        return std::unexpected(
            make_error(MutationErrorCode::UnsafePath,
                       "destination parent directory is invalid",
                       parent,
                       operation_index));
    }
    return {};
}

std::expected<void, MutationError>
install_without_overwrite_checked(const std::filesystem::path& candidate,
                                  const std::filesystem::path& destination,
                                  std::size_t operation_index) {
    auto installed =
        platform::durability::install_without_overwrite(candidate, destination);
    if (!installed) {
        return std::unexpected(make_error(
            installed.error() == std::errc::file_exists
                ? MutationErrorCode::DestinationConflict
            : installed.error() == std::errc::too_many_symbolic_link_levels
                ? MutationErrorCode::UnsafePath
                : MutationErrorCode::LocalIo,
            "conditional install failed: " + installed.error().message(),
            destination,
            operation_index));
    }
    return {};
}

std::expected<std::pair<std::filesystem::path, std::filesystem::path>,
              MutationError>
resolve_pair(const std::filesystem::path& local_root,
             const Operation& operation,
             std::size_t operation_index) {
    auto source =
        resolve_local_path(local_root, operation.path, operation_index);
    if (!source) {
        return std::unexpected(source.error());
    }
    auto destination =
        resolve_local_path(local_root, operation.alt_path, operation_index);
    if (!destination) {
        return std::unexpected(destination.error());
    }
    return std::pair{std::move(*source), std::move(*destination)};
}

std::expected<void, MutationError>
move_local_without_replace(const std::filesystem::path& source,
                           const std::filesystem::path& destination,
                           std::size_t operation_index) {
#if defined(_WIN32)
    const bool moved = MoveFileExW(source.wstring().c_str(),
                                   destination.wstring().c_str(),
                                   MOVEFILE_WRITE_THROUGH) != 0;
    const DWORD native_error = moved ? ERROR_SUCCESS : GetLastError();
    if (!moved) {
        const auto code = native_error == ERROR_ALREADY_EXISTS ||
                                  native_error == ERROR_FILE_EXISTS
                              ? MutationErrorCode::DestinationConflict
                              : MutationErrorCode::LocalIo;
        return std::unexpected(
            make_error(code,
                       "failed to move file without replacement (native_code=" +
                           std::to_string(native_error) + ")",
                       destination,
                       operation_index));
    }
#elif defined(__linux__) && defined(SYS_renameat2)
    auto source_status = read_status(source, operation_index);
    if (!source_status) {
        return std::unexpected(source_status.error());
    }
    if (std::filesystem::is_symlink(*source_status) ||
        !std::filesystem::is_regular_file(*source_status)) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "source is not a regular file without symlink",
                       source,
                       operation_index));
    }

    const auto linux_rename_result = ::syscall(SYS_renameat2,
                                               AT_FDCWD,
                                               source.c_str(),
                                               AT_FDCWD,
                                               destination.c_str(),
                                               RENAME_NOREPLACE);
    const int linux_error = (linux_rename_result != 0) ? errno : 0;
    if (linux_rename_result != 0) {
        const int err = linux_error;
        const auto code = (err == EEXIST)
                              ? MutationErrorCode::DestinationConflict
                              : MutationErrorCode::LocalIo;
        return std::unexpected(make_error(
            code,
            "failed to rename without replace (errno=" + std::to_string(err) +
                ": " + std::strerror(err) + ")",
            destination,
            operation_index));
    }
#else
    return std::unexpected(
        make_error(MutationErrorCode::LocalIo,
                   "atomic rename without replace not supported on platform",
                   destination,
                   operation_index));
#endif
    return {};
}

std::expected<void, MutationError>
verify_local_file(const std::filesystem::path& path,
                  std::string_view hash,
                  std::uint64_t size,
                  std::size_t operation_index) {
    auto result = crypto::content::verify_file(path, hash, size);
    if (!result) {
        return std::unexpected(make_error(MutationErrorCode::IntegrityMismatch,
                                          result.error(),
                                          path,
                                          operation_index));
    }
    return {};
}

std::expected<void, MutationError>
verify_local_file(const std::filesystem::path& path,
                  const Operation& operation,
                  std::size_t operation_index) {
    return verify_local_file(
        path, operation.hash, operation.size, operation_index);
}

MutationResult check_ciphertext_size(const std::filesystem::path& path,
                                     std::uint64_t expected,
                                     std::size_t operation_index) {
    std::error_code ec;
    const auto actual = std::filesystem::file_size(path, ec);
    if (ec) {
        return std::unexpected(make_error(
            MutationErrorCode::LocalIo, ec.message(), path, operation_index));
    }
    if (actual != expected) {
        return std::unexpected(
            make_error(MutationErrorCode::IntegrityMismatch,
                       "ciphertext size does not match staged envelope",
                       path,
                       operation_index));
    }
    return {};
}

std::expected<void, MutationError>
fetch_decrypt_and_verify(transport::Transport& storage,
                         std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                         std::string_view identifier,
                         const std::filesystem::path& encrypted,
                         const std::filesystem::path& plaintext,
                         std::string_view plaintext_hash,
                         std::uint64_t expected_size,
                         std::size_t operation_index,
                         bool skip_get,
                         std::optional<std::uintmax_t> expected_ciphertext_size,
                         const std::filesystem::path& error_path,
                         MutationErrorCode not_found_code,
                         std::string_view not_found_detail,
                         std::string_view decrypt_detail) {
    if (!skip_get) {
        auto downloaded = transport::get(storage, identifier, encrypted);
        if (!downloaded) {
            return std::unexpected(make_error(
                downloaded.error().code == transport::ErrorCode::ObjectNotFound
                    ? not_found_code
                    : MutationErrorCode::TransportFailure,
                downloaded.error().code ==
                            transport::ErrorCode::ObjectNotFound &&
                        !not_found_detail.empty()
                    ? std::string(not_found_detail)
                    : transport::describe(downloaded.error()),
                error_path,
                operation_index));
        }
    }

    if (auto ok = require_regular_file(
            encrypted,
            expected_ciphertext_size ? MutationErrorCode::IntegrityMismatch
                                     : MutationErrorCode::LocalIo,
            "downloaded encrypted object is invalid",
            operation_index);
        !ok) {
        return ok;
    }

    if (expected_ciphertext_size) {
        if (auto ok = check_ciphertext_size(
                encrypted, *expected_ciphertext_size, operation_index);
            !ok) {
            return ok;
        }
    }

    if (!crypto::decrypt_file(encrypted, plaintext, key)) {
        return std::unexpected(make_error(MutationErrorCode::CryptoFailure,
                                          std::string(decrypt_detail),
                                          error_path,
                                          operation_index));
    }

    if (expected_ciphertext_size) {
        if (auto ok = require_regular_file(
                plaintext,
                MutationErrorCode::IntegrityMismatch,
                "decrypted plaintext is not a regular file",
                operation_index);
            !ok) {
            return ok;
        }
    }

    return verify_local_file(
        plaintext, plaintext_hash, expected_size, operation_index);
}

} // namespace

namespace detail {

MutationResult validate_staged_digest(const std::filesystem::path& path,
                                      const crypto::physical::Digest& digest,
                                      std::size_t operation_index) {
    if (digest.algorithm != crypto::physical::Algorithm::Sha256 ||
        digest.hex.size() != 64 || !is_lowercase_hex(digest.hex)) {
        return std::unexpected(make_error(MutationErrorCode::IntegrityMismatch,
                                          "invalid staged ciphertext digest",
                                          path,
                                          operation_index));
    }
    return check_ciphertext_size(path, digest.size, operation_index);
}

std::expected<void, MutationError> verify_uploaded_content_object(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    std::string_view identifier,
    std::string_view plaintext_hash,
    std::uint64_t expected_size,
    const platform::Workspace& workspace,
    std::size_t operation_index,
    const crypto::physical::Digest& ciphertext_digest,
    bool is_pack,
    std::optional<std::size_t> scratch_slot) {
    auto remote_hash = transport::physical_hash(
        storage,
        identifier,
        crypto::physical::algorithm_name(ciphertext_digest.algorithm));
    if (remote_hash) {
        if (*remote_hash == ciphertext_digest.hex) {
            return {};
        }
        return std::unexpected(make_error(
            MutationErrorCode::IntegrityMismatch,
            "remote physical hash does not match published ciphertext",
            {},
            operation_index));
    }
    if (remote_hash.error().code != transport::ErrorCode::Unsupported) {
        if (remote_hash.error().code == transport::ErrorCode::ObjectNotFound) {
            return std::unexpected(
                make_error(MutationErrorCode::IntegrityMismatch,
                           "remote object missing after upload",
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
    const auto verify_slot = scratch_slot.value_or(operation_index);
    const auto encrypted =
        platform::workspace_file(workspace, verify_slot, ".upload.verify.enc");
    const auto plaintext = platform::workspace_file(
        workspace, verify_slot, ".upload.verify.plain");
    if (encrypted.empty() || plaintext.empty()) {
        return std::unexpected(
            make_error(MutationErrorCode::LocalIo,
                       "invalid temporary path to verify upload",
                       encrypted,
                       operation_index));
    }

    const auto cleanup = [&] {
        remove_temporary_file(encrypted);
        remove_temporary_file(plaintext);
    };
    cleanup();

    const auto expected_hash = hash_from_hex(plaintext_hash);
    if (!hash_from_hex(identifier) || !expected_hash) {
        return std::unexpected(make_error(MutationErrorCode::IntegrityMismatch,
                                          "invalid encrypted object identifier",
                                          encrypted,
                                          operation_index));
    }

    if (is_pack) {
        if (crypto::pack_identifier(key, *expected_hash) != identifier) {
            return std::unexpected(
                make_error(MutationErrorCode::IntegrityMismatch,
                           "pack object identifier mismatch",
                           encrypted,
                           operation_index));
        }
        auto downloaded = transport::get(storage, identifier, encrypted);
        if (!downloaded) {
            cleanup();
            return std::unexpected(make_error(
                downloaded.error().code == transport::ErrorCode::ObjectNotFound
                    ? MutationErrorCode::IntegrityMismatch
                    : MutationErrorCode::TransportFailure,
                downloaded.error().code == transport::ErrorCode::ObjectNotFound
                    ? "remote pack object missing after upload"
                    : transport::describe(downloaded.error()),
                encrypted,
                operation_index));
        }
        if (auto ok = check_ciphertext_size(
                encrypted, ciphertext_digest.size, operation_index);
            !ok) {
            cleanup();
            return ok;
        }
        auto verified_pack = crypto::pack::decrypt_and_verify_pack(
            encrypted, key, *expected_hash, nullptr);
        cleanup();
        if (!verified_pack) {
            return std::unexpected(
                make_error(MutationErrorCode::IntegrityMismatch,
                           verified_pack.error(),
                           encrypted,
                           operation_index));
        }
        return {};
    }

    auto verified =
        fetch_decrypt_and_verify(storage,
                                 key,
                                 identifier,
                                 encrypted,
                                 plaintext,
                                 plaintext_hash,
                                 expected_size,
                                 operation_index,
                                 false,
                                 ciphertext_digest.size,
                                 encrypted,
                                 MutationErrorCode::IntegrityMismatch,
                                 "remote object missing after upload",
                                 "failed to decrypt published object");
    cleanup();
    return verified;
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
    if (!expected_hash) {
        return std::unexpected(
            make_error(MutationErrorCode::IntegrityMismatch,
                       "upload source is not a valid regular file",
                       source,
                       operation_index));
    }
    const auto remote_identifier =
        crypto::content_identifier(key, *expected_hash);

    const auto encrypted =
        platform::workspace_file(workspace, operation_index, ".upload.enc");
    if (encrypted.empty()) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "invalid temporary path",
                                          source,
                                          operation_index));
    }

    std::error_code cleanup_error;
    std::filesystem::remove(encrypted, cleanup_error);
    if (cleanup_error) {
        return std::unexpected(make_error(
            MutationErrorCode::LocalIo,
            "failed to remove previous ciphertext: " + cleanup_error.message(),
            encrypted,
            operation_index));
    }

    auto prepared = detail::prepare_upload_ciphertext(
        operation, operation_index, source, encrypted, key);

    if (!prepared) {
        remove_temporary_file(encrypted);
        return std::unexpected(prepared.error());
    }

    if (auto ok = detail::validate_staged_digest(
            encrypted, prepared->ciphertext_digest, operation_index);
        !ok) {
        remove_temporary_file(encrypted);
        return ok;
    }

    auto uploaded = transport::put(storage, encrypted, remote_identifier);
    if (!uploaded &&
        !transport::mutation_result_is_ambiguous(uploaded.error())) {
        remove_temporary_file(encrypted);
        return std::unexpected(make_error(MutationErrorCode::TransportFailure,
                                          transport::describe(uploaded.error()),
                                          source,
                                          operation_index));
    }

    auto uploaded_verification =
        detail::verify_uploaded_content_object(storage,
                                               key,
                                               remote_identifier,
                                               operation.hash,
                                               operation.size,
                                               workspace,
                                               operation_index,
                                               prepared->ciphertext_digest);
    std::error_code encrypted_remove_error;
    std::filesystem::remove(encrypted, encrypted_remove_error);
    if (!uploaded_verification) {
        remove_temporary_file(encrypted);
        return std::unexpected(uploaded_verification.error());
    }

    if (encrypted_remove_error) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "failed to remove temporary file: " +
                                              encrypted_remove_error.message(),
                                          encrypted,
                                          operation_index));
    }

    return {};
}

struct PreparedDownloadCandidate {
    bool already_applied = false;
    std::string_view prepared_hash;
    std::filesystem::path candidate;
};

std::expected<PreparedDownloadCandidate, MutationError>
prepare_download_candidate(const Operation& operation,
                           std::size_t operation_index,
                           const std::filesystem::path& destination,
                           const platform::Workspace& workspace,
                           const transaction::OperationProgress& progress,
                           const DestinationPrecondition* condition) {
    const std::string_view prepared_hash =
        condition ? condition->hash : progress.previous_hash;

    auto prepared = detail::validate_prepared_operation(
        operation, operation_index, destination, workspace, progress);
    if (!prepared) {
        return std::unexpected(prepared.error());
    }
    auto destination_status = read_status(destination, operation_index);
    if (!destination_status) {
        return std::unexpected(destination_status.error());
    }
    if (std::filesystem::is_symlink(*destination_status)) {
        return std::unexpected(make_error(MutationErrorCode::UnsafePath,
                                          "destination is a symlink",
                                          destination,
                                          operation_index));
    }
    if (std::filesystem::is_regular_file(*destination_status)) {
        if (progress.state == transaction::OperationState::Applied ||
            prepared_hash == operation.hash) {
            prepared = detail::validate_prepared_destination(operation,
                                                             operation_index,
                                                             destination,
                                                             workspace,
                                                             progress,
                                                             condition);
            if (!prepared) {
                return std::unexpected(prepared.error());
            }
            std::error_code error;
            const auto size = std::filesystem::file_size(destination, error);
            if (error || size != operation.size) {
                return std::unexpected(
                    make_error(MutationErrorCode::IntegrityMismatch,
                               error ? error.message()
                                     : "file size does not match expected size",
                               destination,
                               operation_index));
            }
            return PreparedDownloadCandidate{.already_applied = true};
        }
    } else if (!missing(*destination_status)) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "destination is not a regular file",
                       destination,
                       operation_index));
    }

    if (auto parent_ok =
            validate_parent_directory(destination, operation_index);
        !parent_ok) {
        return std::unexpected(parent_ok.error());
    }

    const auto candidate = detail::download_candidate_path(
        destination, workspace, operation_index);
    auto candidate_status = read_status(candidate, operation_index);
    if (!candidate_status) {
        return std::unexpected(candidate_status.error());
    }
    if (!missing(*candidate_status)) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "local candidate already exists",
                       candidate,
                       operation_index));
    }
    return PreparedDownloadCandidate{
        .already_applied = false,
        .prepared_hash = prepared_hash,
        .candidate = candidate,
    };
}

MutationResult
install_download_candidate(const Operation& operation,
                           std::size_t operation_index,
                           const std::filesystem::path& destination,
                           const platform::Workspace& workspace,
                           const transaction::OperationProgress& progress,
                           std::string_view prepared_hash,
                           const std::filesystem::path& candidate,
                           const DestinationPrecondition* condition) {
    using platform::private_storage::PrivateOutputFile;
    struct CandidateGuard {
        PrivateOutputFile file;
        ~CandidateGuard() noexcept {
            static_cast<void>(
                platform::private_storage::remove_private_file_if_owned(file));
        }
    } cleanup{{.path = candidate,
               .identity =
                   platform::private_storage::query_file_identity(candidate)}};
    // shortcut: validation and replace are separate; upgrade if external-writer
    // isolation becomes required.
    auto prepared = detail::validate_prepared_destination(operation,
                                                          operation_index,
                                                          destination,
                                                          workspace,
                                                          progress,
                                                          condition);
    if (!prepared) {
        return prepared;
    }
    if (!prepared_hash.empty()) {
        mutation_fault_test::hit("before_download_replace", destination);
        if (auto synced = sync_file_checked(candidate, operation_index);
            !synced) {
            return synced;
        }
        auto installed =
            platform::durability::replace_atomically(candidate, destination);
        if (!installed) {
            return std::unexpected(
                make_error(MutationErrorCode::LocalIo,
                           "failed to replace local file: " + installed.error(),
                           destination,
                           operation_index));
        }
        mutation_fault_test::hit("after_download_replace", destination);
    } else {
        mutation_fault_test::hit("before_download_install", destination);
        if (auto synced = sync_file_checked(candidate, operation_index);
            !synced) {
            return synced;
        }
        if (auto installed = install_without_overwrite_checked(
                candidate, destination, operation_index);
            !installed) {
            return installed;
        }
    }
    return sync_parent_checked(destination, operation_index);
}

MutationResult
apply_download(const Operation& operation,
               std::size_t operation_index,
               const std::filesystem::path& destination,
               transport::Transport& storage,
               const platform::Workspace& workspace,
               std::span<const std::uint8_t, crypto::KEY_SIZE> key,
               const transaction::OperationProgress& progress,
               DownloadCacheMode download_cache,
               const DestinationPrecondition* condition) {
    auto expected_hash = hash_from_hex(operation.hash);
    if (!expected_hash) {
        return std::unexpected(make_error(MutationErrorCode::IntegrityMismatch,
                                          expected_hash.error(),
                                          destination,
                                          operation_index));
    }
    const auto remote_identifier =
        crypto::content_identifier(key, *expected_hash);

    auto prep = prepare_download_candidate(operation,
                                           operation_index,
                                           destination,
                                           workspace,
                                           progress,
                                           condition);
    if (!prep) {
        return std::unexpected(prep.error());
    }
    if (prep->already_applied) {
        return {};
    }
    const auto& candidate = prep->candidate;

    const bool cache_plaintext = download_cache != DownloadCacheMode::None &&
                                 operation.size >= crypto::CHUNK_SIZE;
    const auto plaintext =
        cache_plaintext
            ? platform::workspace_file(workspace,
                                       "download-" + operation.hash + ".plain")
            : std::filesystem::path{};
    if (cache_plaintext && plaintext.empty()) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "invalid temporary path",
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
                           "transactional plaintext cache is invalid",
                           plaintext,
                           operation_index));
        }
        if (download_cache == DownloadCacheMode::Reuse &&
            std::filesystem::is_regular_file(*plaintext_status)) {
            std::error_code copy_error;
            std::filesystem::copy_file(plaintext, candidate, copy_error);
            if (!copy_error && verify_local_file(candidate,
                                                 operation.hash,
                                                 operation.size,
                                                 operation_index)) {
                candidate_ready = true;
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
                                          "invalid temporary path",
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
                           "temporary encrypted file is a symlink",
                           encrypted,
                           operation_index));
        }

        const bool reuse_cached =
            download_cache == DownloadCacheMode::Reuse &&
            std::filesystem::is_regular_file(*encrypted_status);
        auto fetched =
            fetch_decrypt_and_verify(storage,
                                     key,
                                     remote_identifier,
                                     encrypted,
                                     candidate,
                                     operation.hash,
                                     operation.size,
                                     operation_index,
                                     reuse_cached,
                                     std::nullopt,
                                     destination,
                                     MutationErrorCode::RemoteContentMissing,
                                     {},
                                     "failed to decrypt object");
        if (!fetched) {
            remove_temporary_file(encrypted);
            remove_temporary_file(candidate);
            if (fetched.error().code ==
                    MutationErrorCode::RemoteContentMissing ||
                fetched.error().code == MutationErrorCode::TransportFailure) {
                auto prepared =
                    detail::validate_prepared_destination(operation,
                                                          operation_index,
                                                          destination,
                                                          workspace,
                                                          progress,
                                                          condition);
                if (!prepared) {
                    return prepared;
                }
            }
            return fetched;
        }

        if (cache_plaintext) {
            std::error_code copy_error;
            std::filesystem::copy_file(candidate, plaintext, copy_error);
            if (copy_error || !verify_local_file(plaintext,
                                                 operation.hash,
                                                 operation.size,
                                                 operation_index)) {
                std::filesystem::remove(plaintext, copy_error);
            }
        }
    }

    if (auto installed = install_download_candidate(operation,
                                                    operation_index,
                                                    destination,
                                                    workspace,
                                                    progress,
                                                    prep->prepared_hash,
                                                    candidate,
                                                    condition);
        !installed) {
        return installed;
    }
    if (download_cache == DownloadCacheMode::None) {
        std::error_code encrypted_cleanup_error;
        std::filesystem::remove(encrypted, encrypted_cleanup_error);
        if (encrypted_cleanup_error) {
            return std::unexpected(
                make_error(MutationErrorCode::LocalIo,
                           "failed to remove temporary object: " +
                               encrypted_cleanup_error.message(),
                           encrypted,
                           operation_index));
        }
    }

    return {};
}

MutationResult
apply_rename_or_move(const Operation& operation,
                     std::size_t operation_index,
                     const std::filesystem::path& source,
                     const std::filesystem::path& destination,
                     const platform::Workspace& workspace,
                     const transaction::OperationProgress& progress,
                     bool is_move) {
    if (is_move) {
        if (auto parent_ok =
                validate_parent_directory(destination, operation_index);
            !parent_ok) {
            return parent_ok;
        }
        mutation_fault_test::hit("before_rename_move", source);
    }

    auto source_status = read_status(source, operation_index);
    auto destination_status = read_status(destination, operation_index);
    if (!source_status || !destination_status) {
        return std::unexpected(!source_status ? source_status.error()
                                              : destination_status.error());
    }
    if (std::filesystem::is_symlink(*source_status) ||
        std::filesystem::is_symlink(*destination_status)) {
        return std::unexpected(make_error(
            MutationErrorCode::UnsafePath,
            is_move ? "move does not accept symlink"
                    : "rename does not accept symlink",
            std::filesystem::is_symlink(*source_status) ? source : destination,
            operation_index));
    }

    const bool source_missing = missing(*source_status);
    const bool destination_missing = missing(*destination_status);
    if (is_move) {
        if (source_missing && destination_missing) {
            return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                              "move source does not exist",
                                              source,
                                              operation_index));
        }
        if (!source_missing) {
            if (!std::filesystem::is_regular_file(*source_status)) {
                return std::unexpected(
                    make_error(MutationErrorCode::DestinationConflict,
                               "move source is not a regular file",
                               source,
                               operation_index));
            }
            if (auto verified = verify_local_file(
                    source, operation.hash, operation.size, operation_index);
                !verified) {
                return verified;
            }
            if (!destination_missing) {
                return std::unexpected(
                    make_error(MutationErrorCode::DestinationConflict,
                               "move destination already exists",
                               destination,
                               operation_index));
            }
        }
        if (auto prepared = detail::validate_prepared_rename(operation,
                                                             operation_index,
                                                             source,
                                                             destination,
                                                             workspace,
                                                             progress);
            !prepared) {
            return prepared;
        }
    }

    if (!source_missing && destination_missing) {
        if (!is_move) {
            mutation_fault_test::hit("before_rename_move", source);
        }
        if (auto moved = move_local_without_replace(
                source, destination, operation_index);
            !moved) {
            return moved;
        }
        mutation_fault_test::hit("after_rename_move", destination);
    } else if (source_missing && !destination_missing) {
        if (is_move) {
            if (auto verified = verify_local_file(destination,
                                                  operation.hash,
                                                  operation.size,
                                                  operation_index);
                !verified) {
                return std::unexpected(
                    make_error(MutationErrorCode::DestinationConflict,
                               verified.error().detail,
                               destination,
                               operation_index));
            }
        }
    } else if (!is_move) {
        return std::unexpected(make_error(
            !source_missing ? MutationErrorCode::DestinationConflict
                            : MutationErrorCode::LocalIo,
            !source_missing ? "rename destination already exists"
                            : "rename source and destination do not exist",
            !source_missing ? destination : operation.path,
            operation_index));
    }

    if (!is_move) {
        return {};
    }
    if (auto synced = sync_parent_checked(destination, operation_index);
        !synced) {
        return synced;
    }
    return sync_parent_checked(source, operation_index);
}

MutationResult
apply_copy_local(const Operation& operation,
                 std::size_t operation_index,
                 const std::filesystem::path& source,
                 const std::filesystem::path& destination,
                 const platform::Workspace& workspace,
                 const transaction::OperationProgress& progress) {
    (void)progress;

    if (destination.empty()) {
        return std::unexpected(make_error(MutationErrorCode::InvalidOperation,
                                          "copy destination is empty",
                                          destination,
                                          operation_index));
    }
    if (auto parent_ok =
            validate_parent_directory(destination, operation_index);
        !parent_ok) {
        return parent_ok;
    }

    auto source_status = read_status(source, operation_index);
    if (!source_status) {
        return std::unexpected(source_status.error());
    }
    if (std::filesystem::is_symlink(*source_status)) {
        return std::unexpected(make_error(MutationErrorCode::UnsafePath,
                                          "copy does not accept symlink",
                                          source,
                                          operation_index));
    }
    if (missing(*source_status)) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "copy source does not exist",
                                          source,
                                          operation_index));
    }
    if (!std::filesystem::is_regular_file(*source_status)) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "copy source is not a regular file",
                       source,
                       operation_index));
    }

    auto verified_source = detail::verify_file_size_and_hash(
        source,
        operation.size,
        operation.hash,
        true,
        "copy source does not match expected size",
        "copy source content mismatch",
        operation_index);
    if (!verified_source) {
        return std::unexpected(verified_source.error());
    }

    auto destination_status = read_status(destination, operation_index);
    if (!destination_status) {
        return std::unexpected(destination_status.error());
    }
    if (std::filesystem::is_symlink(*destination_status)) {
        return std::unexpected(make_error(MutationErrorCode::UnsafePath,
                                          "destination is a symlink",
                                          destination,
                                          operation_index));
    }
    if (!missing(*destination_status)) {
        const auto recorded_identity_res =
            detail::read_copy_installed_identity(workspace, operation_index);
        if (!recorded_identity_res) {
            return std::unexpected(recorded_identity_res.error());
        }
        const auto& recorded_identity = *recorded_identity_res;
        if (recorded_identity.has_value()) {
            const auto current_identity =
                platform::private_storage::query_file_identity(destination);
            if (current_identity.valid &&
                current_identity == *recorded_identity) {
                auto verified_dest =
                    verify_local_file(destination, operation, operation_index);
                if (verified_dest) {
                    return {};
                }
            }
        }
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "copy destination already exists",
                       destination,
                       operation_index));
    }

    mutation_fault_test::hit("before_copy_local_staging", source);

    const auto candidate =
        detail::copy_candidate_path(destination, workspace, operation_index);
    auto candidate_status = read_status(candidate, operation_index);
    if (!candidate_status) {
        return std::unexpected(candidate_status.error());
    }
    if (!missing(*candidate_status)) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "local copy candidate already exists",
                       candidate,
                       operation_index));
    }

    mutation_fault_test::hit("during_copy_local_staging_race", candidate);

    auto staged_file =
        platform::private_storage::create_private_file(candidate);
    if (!staged_file) {
        return std::unexpected(
            make_error(staged_file.error().is_collision
                           ? MutationErrorCode::DestinationConflict
                           : MutationErrorCode::LocalIo,
                       staged_file.error().message,
                       candidate,
                       operation_index));
    }

    struct StagingGuard {
        platform::private_storage::PrivateOutputFile* file = nullptr;
        bool keep = false;
        ~StagingGuard() {
            if (!keep && file != nullptr) {
                platform::private_storage::remove_private_file_if_owned(*file);
            }
        }
    } staging_guard{&staged_file.value()};

    auto recorded_id = detail::record_copy_installed_identity(
        workspace, operation_index, staging_guard.file->identity);
    if (!recorded_id) {
        return std::unexpected(recorded_id.error());
    }

    std::array<std::uint8_t, 64 * 1024> buffer;
    std::optional<MutationError> write_error;
    auto streamed = platform::private_storage::stream_regular_file(
        source, buffer, [&](std::span<const std::uint8_t> chunk) {
            mutation_fault_test::hit("during_copy_local_write", candidate);
            if (auto written = platform::private_storage::write_private_file(
                    *staging_guard.file, chunk.data(), chunk.size());
                !written) {
                write_error = make_error(MutationErrorCode::LocalIo,
                                         "failed to write staging bytes: " +
                                             written.error(),
                                         candidate,
                                         operation_index);
                return false;
            }
            return true;
        });
    if (write_error)
        return std::unexpected(std::move(*write_error));
    if (!streamed) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          streamed.error().detail,
                                          source,
                                          operation_index));
    }

    auto flushed = platform::private_storage::flush_and_close_private_file(
        *staging_guard.file);
    if (!flushed) {
        return std::unexpected(
            make_error(MutationErrorCode::LocalIo,
                       "failed closing staging file: " + flushed.error(),
                       candidate,
                       operation_index));
    }

    auto verified_staging =
        detail::verify_file_size_and_hash(candidate,
                                          operation.size,
                                          operation.hash,
                                          true,
                                          "staging file size mismatch",
                                          "staging file content mismatch",
                                          operation_index);
    if (!verified_staging) {
        return std::unexpected(verified_staging.error());
    }

    mutation_fault_test::hit("before_copy_local_durability", candidate);
    auto synced = sync_file_checked(candidate, operation_index);
    if (!synced) {
        return synced;
    }

    mutation_fault_test::hit("before_copy_local_install", destination);
    auto installed = install_without_overwrite_checked(
        candidate, destination, operation_index);
    if (!installed) {
        return installed;
    }
    staging_guard.keep = true;
    mutation_fault_test::hit("after_copy_local_install", destination);

    const auto dest_id =
        platform::private_storage::query_file_identity(destination);
    if (!dest_id.valid || !(dest_id == staging_guard.file->identity)) {
        return std::unexpected(make_error(
            MutationErrorCode::DestinationConflict,
            "installed destination identity mismatch / externally replaced",
            destination,
            operation_index));
    }

    auto dir_synced = platform::durability::sync_parent_directory(destination);
#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (mutation_fault_test::g_fail_copy_post_install_dir_sync_return) {
        dir_synced = std::unexpected(
            "simulated destination directory sync return error");
    }
#endif
    if (!dir_synced) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          dir_synced.error(),
                                          destination,
                                          operation_index));
    }
    return {};
}

std::string_view mutation_code_name(MutationErrorCode code) noexcept {
    constexpr std::array<std::string_view, 9> names{
        "invalid_operation",
        "unsafe_path",
        "local_io",
        "transport_failure",
        "remote_content_missing",
        "remote_result_unknown",
        "crypto_failure",
        "integrity_mismatch",
        "destination_conflict",
    };
    const auto idx = static_cast<std::size_t>(code);
    return idx < names.size() ? names[idx] : "local_io";
}

} // namespace

MutationResult
apply_operation(const Operation& operation,
                std::size_t operation_index,
                const std::filesystem::path& local_root,
                transport::Transport& storage,
                std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                const platform::Workspace& workspace,
                const transaction::OperationProgress& progress,
                DownloadCacheMode download_cache,
                const DestinationPrecondition* condition) {
    if (auto meta_valid =
            detail::validate_operation_metadata(operation, operation_index);
        !meta_valid) {
        return meta_valid;
    }

    switch (operation.action) {
        case Action::RenameLocal: {
            auto pair = resolve_pair(local_root, operation, operation_index);
            if (!pair) {
                return std::unexpected(pair.error());
            }
            auto prepared = detail::validate_prepared_rename(operation,
                                                             operation_index,
                                                             pair->first,
                                                             pair->second,
                                                             workspace,
                                                             progress);
            if (!prepared) {
                return prepared;
            }
            return apply_rename_or_move(operation,
                                        operation_index,
                                        pair->first,
                                        pair->second,
                                        workspace,
                                        progress,
                                        false);
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
                if (std::filesystem::is_symlink(*status) ||
                    platform::private_storage::is_reparse_or_symlink(*path)) {
                    return std::unexpected(
                        make_error(MutationErrorCode::UnsafePath,
                                   "destination directory is a symlink",
                                   *path,
                                   operation_index));
                }
                if (std::filesystem::is_directory(*status)) {
                    return {};
                }
                return std::unexpected(
                    make_error(MutationErrorCode::DestinationConflict,
                               "destination is not a directory",
                               *path,
                               operation_index));
            }
            std::error_code error;
            std::filesystem::create_directories(*path, error);
            if (error) {
                return std::unexpected(
                    make_error(MutationErrorCode::LocalIo,
                               "failed to create directory: " + error.message(),
                               *path,
                               operation_index));
            }
            return {};
        }

        case Action::CreateRemoteDirectory:
        case Action::DeleteRemoteDirectory:
            if (operation.path.empty() || operation.path == ".") {
                return std::unexpected(
                    make_error(MutationErrorCode::InvalidOperation,
                               "remote directory without path",
                               operation.path,
                               operation_index));
            }
            return {};

        case Action::MoveLocal: {
            auto pair = resolve_pair(local_root, operation, operation_index);
            if (!pair) {
                return std::unexpected(pair.error());
            }
            return apply_rename_or_move(operation,
                                        operation_index,
                                        pair->first,
                                        pair->second,
                                        workspace,
                                        progress,
                                        true);
        }

        case Action::CopyLocal: {
            auto pair = resolve_pair(local_root, operation, operation_index);
            if (!pair) {
                return std::unexpected(pair.error());
            }
            return apply_copy_local(operation,
                                    operation_index,
                                    pair->first,
                                    pair->second,
                                    workspace,
                                    progress);
        }

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
                                  progress,
                                  download_cache,
                                  condition);
        }

        case Action::DeleteIgnoredLocalFile: {
            auto path =
                resolve_local_path(local_root, operation.path, operation_index);
            if (!path) {
                return std::unexpected(path.error());
            }
            auto prepared = detail::validate_prepared_operation(
                operation, operation_index, *path, workspace, progress);
            if (!prepared) {
                return prepared;
            }
            if (!progress.had_original ||
                progress.previous_hash != operation.hash ||
                progress.state < transaction::OperationState::BackupCreated) {
                return std::unexpected(make_error(
                    MutationErrorCode::InvalidOperation,
                    "disposable removal lacks a verified transaction backup",
                    *path,
                    operation_index));
            }
            mutation_fault_test::hit("before_delete_ignored_local_file", *path);
            if (auto verified = detail::verify_disposable_source(
                    *path,
                    operation,
                    operation_index,
                    "disposable source changed before removal");
                !verified) {
                return verified;
            }
            platform::private_storage::PrivateOutputFile source{
                .path = *path,
                .identity =
                    {
                        .volume_or_dev =
                            operation.expected_source_identity.volume_or_dev,
                        .file_id_low =
                            operation.expected_source_identity.file_id_low,
                        .file_id_high =
                            operation.expected_source_identity.file_id_high,
                        .valid = true,
                    },
            };
            mutation_fault_test::hit("before_disposable_owned_remove", *path);
            const auto removed =
                platform::private_storage::remove_private_file_if_owned(source);
            using platform::private_storage::CleanupResult;
            if (removed != CleanupResult::Removed) {
                return std::unexpected(make_error(
                    removed == CleanupResult::AlreadyAbsent ||
                            removed == CleanupResult::IdentityMismatch
                        ? MutationErrorCode::DestinationConflict
                        : MutationErrorCode::LocalIo,
                    removed == CleanupResult::AlreadyAbsent
                        ? "disposable source disappeared before verified "
                          "removal"
                    : removed == CleanupResult::IdentityMismatch
                        ? "disposable source identity changed during removal"
                        : "failed to remove disposable source",
                    *path,
                    operation_index));
            }
            mutation_fault_test::hit("after_delete_ignored_local_file", *path);
            return sync_parent_checked(*path, operation_index);
        }

        case Action::DeleteLocal:
        case Action::DeleteLocalDirectory: {
            const bool directory =
                operation.action == Action::DeleteLocalDirectory;
            auto path =
                resolve_local_path(local_root, operation.path, operation_index);
            if (!path) {
                return std::unexpected(path.error());
            }
            if (!directory) {
                auto prepared =
                    detail::validate_prepared_destination(operation,
                                                          operation_index,
                                                          *path,
                                                          workspace,
                                                          progress,
                                                          condition);
                if (!prepared) {
                    return prepared;
                }
                mutation_fault_test::hit("before_delete_local", *path);
            }
            // shortcut: validation and removal are separate; upgrade if
            // external-writer isolation becomes required.
            auto status = read_status(*path, operation_index);
            if (!status) {
                return std::unexpected(status.error());
            }
            if (missing(*status)) {
                return {};
            }
            if (std::filesystem::is_symlink(*status) ||
                platform::private_storage::is_reparse_or_symlink(*path)) {
                return std::unexpected(
                    make_error(MutationErrorCode::UnsafePath,
                               "removing symlinks is not allowed",
                               *path,
                               operation_index));
            }
            if (directory ? !std::filesystem::is_directory(*status)
                          : !std::filesystem::is_regular_file(*status)) {
                return std::unexpected(
                    make_error(MutationErrorCode::DestinationConflict,
                               directory ? "path is not a directory"
                                         : "path is not a regular file",
                               *path,
                               operation_index));
            }
            std::error_code error;
            std::filesystem::remove(*path, error);
            if (error) {
                bool directory_not_empty =
                    directory && error == std::errc::directory_not_empty;
                if (directory && !directory_not_empty) {
                    std::error_code inspection_error;
                    const bool empty =
                        std::filesystem::is_empty(*path, inspection_error);
                    directory_not_empty = !inspection_error && !empty;
                }
                return std::unexpected(make_error(
                    directory_not_empty ? MutationErrorCode::DestinationConflict
                                        : MutationErrorCode::LocalIo,
                    directory_not_empty
                        ? "directory contains entries not observed as ignored "
                          "or managed"
                        : std::string{"failed to remove "} +
                              (directory ? "directory: " : "file: ") +
                              error.message(),
                    *path,
                    operation_index));
            }
            return directory ? std::expected<void, MutationError>{}
                             : sync_parent_checked(*path, operation_index);
        }

        case Action::DeleteRemote:
            return {};

        case Action::Count:
            break;
    }

    return std::unexpected(make_error(MutationErrorCode::InvalidOperation,
                                      "count action is not a mutable operation",
                                      operation.path,
                                      operation_index));
}

MutationResult
apply_streamed_download(const Operation& operation,
                        std::size_t operation_index,
                        const std::filesystem::path& local_root,
                        const platform::Workspace& workspace,
                        const transaction::OperationProgress& progress,
                        const DestinationPrecondition* destination_condition,
                        const DownloadCandidatePopulator& populate) {
    if (operation.action != Action::Download) {
        return std::unexpected(
            make_error(MutationErrorCode::InvalidOperation,
                       "streamed download requires a download operation",
                       operation.path,
                       operation_index));
    }
    if (!populate) {
        return std::unexpected(
            make_error(MutationErrorCode::InvalidOperation,
                       "streamed download requires a candidate populator",
                       operation.path,
                       operation_index));
    }
    auto destination =
        resolve_local_path(local_root, operation.path, operation_index);
    if (!destination) {
        return std::unexpected(destination.error());
    }
    auto prep = prepare_download_candidate(operation,
                                           operation_index,
                                           *destination,
                                           workspace,
                                           progress,
                                           destination_condition);
    if (!prep) {
        return std::unexpected(prep.error());
    }
    if (prep->already_applied) {
        return {};
    }

    std::filesystem::path backup_file;
    if (progress.had_original &&
        progress.backup_slot != (std::numeric_limits<std::uint32_t>::max)()) {
        backup_file = platform::workspace_file(
            workspace, progress.backup_slot, ".backup");
    }
    if (auto populated = populate(prep->candidate,
                                  *destination,
                                  backup_file.empty() ? nullptr : &backup_file);
        !populated) {
        remove_temporary_file(prep->candidate);
        return populated;
    }
    return install_download_candidate(operation,
                                      operation_index,
                                      *destination,
                                      workspace,
                                      progress,
                                      prep->prepared_hash,
                                      prep->candidate,
                                      destination_condition);
}

MutationResult apply_preverified_bytes_download(
    const Operation& operation,
    std::size_t operation_index,
    const std::filesystem::path& local_root,
    std::span<const std::uint8_t> verified_plaintext,
    const platform::Workspace& workspace,
    const transaction::OperationProgress& progress,
    const DestinationPrecondition* destination_condition) {
    if (verified_plaintext.size() != operation.size) {
        return std::unexpected(make_error(
            MutationErrorCode::IntegrityMismatch,
            "verified download byte count does not match operation size",
            operation.path,
            operation_index));
    }
    return apply_streamed_download(
        operation,
        operation_index,
        local_root,
        workspace,
        progress,
        destination_condition,
        [&](const std::filesystem::path& candidate_path,
            const std::filesystem::path&,
            const std::filesystem::path*) -> MutationResult {
            auto private_out =
                platform::private_storage::create_private_file(candidate_path);
            if (!private_out) {
                return std::unexpected(
                    make_error(MutationErrorCode::LocalIo,
                               "failed to create staged download file: " +
                                   private_out.error().message,
                               candidate_path,
                               operation_index));
            }
            if (auto written = platform::private_storage::write_private_file(
                    *private_out,
                    verified_plaintext.data(),
                    verified_plaintext.size());
                !written) {
                static_cast<void>(
                    platform::private_storage::remove_private_file_if_owned(
                        *private_out));
                return std::unexpected(
                    make_error(MutationErrorCode::LocalIo,
                               "failed to write verified download bytes: " +
                                   written.error(),
                               candidate_path,
                               operation_index));
            }
            platform::private_storage::close_private_file(*private_out);
            return {};
        });
}

std::string describe(const MutationError& error) {
    std::string result{mutation_code_name(error.code)};
    result += " in operation ";
    result += std::to_string(error.operation_index);
    if (!error.path.empty()) {
        result += " ('";
        result += platform::path::to_utf8(error.path);
        result += "')";
    }
    if (!error.detail.empty()) {
        result += ": ";
        result += error.detail;
    }
    return result;
}

} // namespace kasumi::application::sync::mutation
