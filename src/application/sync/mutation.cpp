#include "application/sync/mutation.hpp"

#include "crypto/content.hpp"
#include "mutation_detail.hpp"
#include "mutation_fault_test.hpp"
#include "platform/durability.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"

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
using detail::make_error;
using detail::missing;
using detail::read_status;
using detail::remove_temporary_file;
using detail::resolve_local_path;

std::expected<void, MutationError>
move_local_without_replace(const std::filesystem::path& source,
                           const std::filesystem::path& destination,
                           std::size_t operation_index) {
    platform::perf_trace::count("native rename calls");
    const auto rename_trace = platform::perf_trace::begin();
#if defined(_WIN32)
    const bool moved = MoveFileExW(source.wstring().c_str(),
                                   destination.wstring().c_str(),
                                   MOVEFILE_WRITE_THROUGH) != 0;
    const DWORD native_error = moved ? ERROR_SUCCESS : GetLastError();
    platform::perf_trace::finish("move native rename wall", rename_trace);
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
    platform::perf_trace::finish("move native rename wall", rename_trace);
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
    const auto encrypted = platform::workspace_file(
        workspace, operation_index, ".upload.verify.enc");
    const auto plaintext = platform::workspace_file(
        workspace, operation_index, ".upload.verify.plain");
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

    if (!hash_from_hex(identifier) || !hash_from_hex(plaintext_hash)) {
        return std::unexpected(make_error(MutationErrorCode::IntegrityMismatch,
                                          "invalid encrypted object identifier",
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
                           "remote object missing after upload",
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
        return std::unexpected(
            make_error(MutationErrorCode::IntegrityMismatch,
                       "downloaded encrypted object is not a regular file",
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
        return std::unexpected(
            make_error(MutationErrorCode::IntegrityMismatch,
                       "ciphertext size does not match expected plaintext",
                       encrypted,
                       operation_index));
    }

    if (!crypto::decrypt_file(encrypted, plaintext, key)) {
        cleanup();
        return std::unexpected(make_error(MutationErrorCode::CryptoFailure,
                                          "failed to decrypt published object",
                                          encrypted,
                                          operation_index));
    }

    auto plaintext_status = read_status(plaintext, operation_index);
    if (!plaintext_status || std::filesystem::is_symlink(*plaintext_status) ||
        !std::filesystem::is_regular_file(*plaintext_status)) {
        cleanup();
        return std::unexpected(
            make_error(MutationErrorCode::IntegrityMismatch,
                       "decrypted plaintext is not a regular file",
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
        remove_temporary_file(encrypted);
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
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "failed to remove temporary file: " +
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
    const std::string_view prepared_hash =
        condition ? condition->hash : progress.previous_hash;

    auto prepared = detail::validate_prepared_operation(
        operation, operation_index, destination, workspace, progress);
    if (!prepared)
        return prepared;
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
            if (!prepared)
                return prepared;
            std::error_code error;
            const auto size = std::filesystem::file_size(destination, error);
            if (error || size != operation.size)
                return std::unexpected(
                    make_error(MutationErrorCode::IntegrityMismatch,
                               error ? error.message()
                                     : "file size does not match expected size",
                               destination,
                               operation_index));
            return {};
        }
    } else if (!missing(*destination_status)) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "destination is not a regular file",
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
                       "destination parent directory is invalid",
                       parent,
                       operation_index));
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
                prepared =
                    detail::validate_prepared_destination(operation,
                                                          operation_index,
                                                          destination,
                                                          workspace,
                                                          progress,
                                                          condition);
                if (!prepared)
                    return prepared;
                return std::unexpected(
                    make_error(downloaded.error().code ==
                                       transport::ErrorCode::ObjectNotFound
                                   ? MutationErrorCode::RemoteContentMissing
                                   : MutationErrorCode::TransportFailure,
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
                           "downloaded encrypted object is invalid",
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
            return std::unexpected(make_error(MutationErrorCode::CryptoFailure,
                                              "failed to decrypt object",
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

    // shortcut: validation and replace are separate; upgrade if external-writer
    // isolation becomes required.
    prepared = detail::validate_prepared_destination(operation,
                                                     operation_index,
                                                     destination,
                                                     workspace,
                                                     progress,
                                                     condition);
    if (!prepared)
        return prepared;
    MutationResult replaced;
    if (!prepared_hash.empty()) {
        mutation_fault_test::hit("before_download_replace", destination);
        auto synced = platform::durability::sync_file(candidate);
        if (!synced) {
            remove_temporary_file(candidate);
            return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                              synced.error(),
                                              candidate,
                                              operation_index));
        }
        auto installed =
            platform::durability::replace_atomically(candidate, destination);
        if (!installed) {
            remove_temporary_file(candidate);
            return std::unexpected(
                make_error(MutationErrorCode::LocalIo,
                           "failed to replace local file: " + installed.error(),
                           destination,
                           operation_index));
        }
        mutation_fault_test::hit("after_download_replace", destination);
        synced = platform::durability::sync_parent_directory(destination);
        if (!synced) {
            return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                              synced.error(),
                                              destination,
                                              operation_index));
        }

        replaced = {};
    } else {
        mutation_fault_test::hit("before_download_install", destination);
        auto synced = platform::durability::sync_file(candidate);
        if (!synced)
            return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                              synced.error(),
                                              candidate,
                                              operation_index));
        auto installed = platform::durability::install_without_overwrite(
            candidate, destination);
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
        synced = platform::durability::sync_parent_directory(destination);
        if (!synced)
            return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                              synced.error(),
                                              destination,
                                              operation_index));
    }
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
                           "failed to remove temporary object: " +
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
            "rename does not accept symlink",
            std::filesystem::is_symlink(*source_status) ? source : destination,
            operation_index));
    }

    const bool source_missing = missing(*source_status);
    const bool destination_missing = missing(*destination_status);
    if (!source_missing && destination_missing) {
        mutation_fault_test::hit("before_rename_move", source);
        auto result =
            move_local_without_replace(source, destination, operation_index);
        if (!result) {
            return std::unexpected(result.error());
        }
        mutation_fault_test::hit("after_rename_move", destination);
        return {};
    }
    if (source_missing && !destination_missing) {
        return {};
    }
    if (!source_missing && !destination_missing) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "rename destination already exists",
                       destination,
                       operation_index));
    }
    return std::unexpected(
        make_error(MutationErrorCode::LocalIo,
                   "rename source and destination do not exist",
                   operation.path,
                   operation_index));
}

MutationResult
apply_move_local(const Operation& operation,
                 std::size_t operation_index,
                 const std::filesystem::path& source,
                 const std::filesystem::path& destination,
                 const platform::Workspace& workspace,
                 const transaction::OperationProgress& progress) {
    struct MoveApplyGuard {
        platform::perf_trace::Token token;
        ~MoveApplyGuard() {
            platform::perf_trace::finish("move apply wall", token);
        }
    } move_apply_guard{platform::perf_trace::begin()};
    const auto parent = destination.parent_path();
    auto parent_status = read_status(parent, operation_index);
    if (!parent_status) {
        return std::unexpected(parent_status.error());
    }
    if (std::filesystem::is_symlink(*parent_status) ||
        !std::filesystem::is_directory(*parent_status)) {
        return std::unexpected(
            make_error(MutationErrorCode::UnsafePath,
                       "destination parent directory is invalid",
                       parent,
                       operation_index));
    }

    mutation_fault_test::hit("before_rename_move", source);

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
            "move does not accept symlink",
            std::filesystem::is_symlink(*source_status) ? source : destination,
            operation_index));
    }

    const bool source_missing = missing(*source_status);
    const bool destination_missing = missing(*destination_status);
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
        platform::perf_trace::count("source hash calls");
        auto verified_source =
            verify_local_file(source, operation, operation_index);
        if (!verified_source) {
            return std::unexpected(verified_source.error());
        }
        if (!destination_missing) {
            return std::unexpected(
                make_error(MutationErrorCode::DestinationConflict,
                           "move destination already exists",
                           destination,
                           operation_index));
        }
    }

    auto prepared = detail::validate_prepared_rename(
        operation, operation_index, source, destination, workspace, progress);
    if (!prepared) {
        return prepared;
    }

    if (!source_missing && destination_missing) {
        auto moved =
            move_local_without_replace(source, destination, operation_index);
        if (!moved) {
            return std::unexpected(moved.error());
        }
        mutation_fault_test::hit("after_rename_move", destination);
    } else if (source_missing && !destination_missing) {
        const auto dest_verif_trace = platform::perf_trace::begin();
        auto verified_dest =
            verify_local_file(destination, operation, operation_index);
        platform::perf_trace::finish("move destination verification wall", dest_verif_trace);
        if (!verified_dest) {
            return std::unexpected(
                make_error(MutationErrorCode::DestinationConflict,
                           verified_dest.error().detail,
                           destination,
                           operation_index));
        }
    }

    auto dest_synced = platform::durability::sync_parent_directory(destination);
    if (!dest_synced) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          dest_synced.error(),
                                          destination,
                                          operation_index));
    }
    auto source_synced = platform::durability::sync_parent_directory(source);
    if (!source_synced) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          source_synced.error(),
                                          source,
                                          operation_index));
    }
    return {};
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
        case MutationErrorCode::RemoteContentMissing:
            return "remote_content_missing";
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
                const transaction::OperationProgress& progress,
                DownloadCacheMode download_cache,
                const DestinationPrecondition* condition) {
    if (operation_index == std::numeric_limits<std::size_t>::max() ||
        !is_valid_action(operation.action) || !has_safe_paths(operation)) {
        return std::unexpected(make_error(
            operation_index == std::numeric_limits<std::size_t>::max() ||
                    !is_valid_action(operation.action)
                ? MutationErrorCode::InvalidOperation
                : MutationErrorCode::UnsafePath,
            "invalid operation or path",
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
            auto prepared = detail::validate_prepared_rename(operation,
                                                             operation_index,
                                                             *source,
                                                             *destination,
                                                             workspace,
                                                             progress);
            if (!prepared)
                return prepared;
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
            if (operation.path.empty() || operation.path == ".") {
                return std::unexpected(
                    make_error(MutationErrorCode::InvalidOperation,
                               "remote directory without path",
                               operation.path,
                               operation_index));
            }
            return {};

        case Action::MoveLocal: {
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
            return apply_move_local(operation,
                                    operation_index,
                                    *source,
                                    *destination,
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

        case Action::DeleteLocal: {
            auto path =
                resolve_local_path(local_root, operation.path, operation_index);
            if (!path) {
                return std::unexpected(path.error());
            }
            auto prepared =
                detail::validate_prepared_destination(operation,
                                                      operation_index,
                                                      *path,
                                                      workspace,
                                                      progress,
                                                      condition);
            if (!prepared)
                return prepared;
            mutation_fault_test::hit("before_delete_local", *path);
            // shortcut: validation and removal are separate; upgrade if
            // external-writer isolation becomes required.
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
                               "removing symlinks is not allowed",
                               *path,
                               operation_index));
            }
            if (!std::filesystem::is_regular_file(*status)) {
                return std::unexpected(
                    make_error(MutationErrorCode::DestinationConflict,
                               "path is not a regular file",
                               *path,
                               operation_index));
            }
            std::error_code error;
            std::filesystem::remove(*path, error);
            if (error)
                return std::unexpected(
                    make_error(MutationErrorCode::LocalIo,
                               "failed to remove file: " + error.message(),
                               *path,
                               operation_index));
            auto synced = platform::durability::sync_parent_directory(*path);
            if (!synced) {
                return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                                  synced.error(),
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
                               "removing symlinks is not allowed",
                               *path,
                               operation_index));
            }
            if (!std::filesystem::is_directory(*status)) {
                return std::unexpected(
                    make_error(MutationErrorCode::DestinationConflict,
                               "path is not a directory",
                               *path,
                               operation_index));
            }
            std::error_code error;
            std::filesystem::remove(*path, error);
            if (error) {
                return std::unexpected(
                    make_error(MutationErrorCode::LocalIo,
                               "failed to remove directory: " + error.message(),
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
                               "remote directory without path",
                               operation.path,
                               operation_index));
            }
            return {};

        case Action::Count:
            break;
    }

    return std::unexpected(make_error(MutationErrorCode::InvalidOperation,
                                      "count action is not a mutable operation",
                                      operation.path,
                                      operation_index));
}

std::string describe(const MutationError& error) {
    std::string result = mutation_code_name(error.code);
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
