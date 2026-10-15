#include "mutation_detail.hpp"

#include "core/hasher.hpp"
#include "crypto/content.hpp"
#include "mutation_fault_test.hpp"
#include "platform/durability.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"

#include <algorithm>
#include <iterator>
#include <system_error>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace kasumi::application::sync::mutation::detail {

namespace {

bool path_not_found(const std::error_code& error) noexcept {
    return error == std::errc::no_such_file_or_directory ||
           error == std::errc::not_a_directory;
}

} // namespace

std::filesystem::path
make_custody_path(const std::filesystem::path& destination,
                  std::string_view transaction_id,
                  std::size_t operation_index,
                  std::string_view prefix) {
    const std::string suffix = std::string(".kasumi-") + std::string(prefix) +
                               "-" + std::string(transaction_id) + "-" +
                               std::to_string(operation_index);
    return platform::path::temporary_sibling_path(destination, ".", suffix);
}

MutationResult safe_remove_custody(const std::filesystem::path& custody,
                                   std::string_view expected_hash,
                                   std::size_t operation_index) {
#if defined(_WIN32)
    HANDLE h = CreateFileW(custody.c_str(),
                           GENERIC_READ | DELETE,
                           0, // Exclusive access (dwShareMode = 0)
                           nullptr,
                           OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
            return {};
        }
        const auto code =
            error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION
                ? MutationErrorCode::DestinationConflict
                : MutationErrorCode::LocalIo;
        return std::unexpected(make_error(
            code,
            "CreateFileW for custody cleanup failed (Win32 error " +
                std::to_string(error) +
                "): " + std::system_category().message(static_cast<int>(error)),
            custody,
            operation_index));
    }

    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(h, &info)) {
        const DWORD error = GetLastError();
        CloseHandle(h);
        return std::unexpected(make_error(
            MutationErrorCode::LocalIo,
            "GetFileInformationByHandle failed (Win32 error " +
                std::to_string(error) +
                "): " + std::system_category().message(static_cast<int>(error)),
            custody,
            operation_index));
    }

    if (info.nNumberOfLinks > 1) {
        CloseHandle(h);
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       "custody file has multiple hard links",
                       custody,
                       operation_index));
    }

    auto hash_res = crypto::content::hash_file_handle(h);
    if (!hash_res) {
        CloseHandle(h);
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          hash_res.error(),
                                          custody,
                                          operation_index));
    }
    std::string current_hash = hash_hex(*hash_res);

    if (current_hash != expected_hash) {
        CloseHandle(h);
        return std::unexpected(make_error(
            MutationErrorCode::DestinationConflict,
            "custody file content was externally modified before cleanup",
            custody,
            operation_index));
    }

    FILE_DISPOSITION_INFO disposition{TRUE};
    if (!SetFileInformationByHandle(
            h, FileDispositionInfo, &disposition, sizeof(disposition))) {
        const DWORD error = GetLastError();
        CloseHandle(h);
        const auto code =
            error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION
                ? MutationErrorCode::DestinationConflict
                : MutationErrorCode::LocalIo;
        return std::unexpected(make_error(
            code,
            "SetFileInformationByHandle(FileDispositionInfo) failed "
            "(Win32 error " +
                std::to_string(error) +
                "): " + std::system_category().message(static_cast<int>(error)),
            custody,
            operation_index));
    }
    if (!CloseHandle(h)) {
        const DWORD error = GetLastError();
        return std::unexpected(make_error(
            MutationErrorCode::LocalIo,
            "CloseHandle after custody disposition failed (Win32 error " +
                std::to_string(error) +
                "): " + std::system_category().message(static_cast<int>(error)),
            custody,
            operation_index));
    }
    return {};
#else
    auto status = read_status(custody, operation_index);
    if (!status)
        return std::unexpected(status.error());
    if (missing(*status))
        return {};
    if (std::filesystem::is_symlink(*status) ||
        !std::filesystem::is_regular_file(*status)) {
        return std::unexpected(make_error(
            MutationErrorCode::DestinationConflict,
            "custody path is not a regular file",
            custody,
            operation_index));
    }
    auto current_hash = file_hash(custody, operation_index);
    if (!current_hash) {
        return std::unexpected(current_hash.error());
    }
    if (*current_hash != expected_hash) {
        return std::unexpected(make_error(
            MutationErrorCode::DestinationConflict,
            "custody file content was externally modified before cleanup",
            custody,
            operation_index));
    }
    std::error_code ec;
    mutation_fault_test::hit("before_custody_unlink", custody);
    if (!std::filesystem::remove(custody, ec) || ec) {
        return std::unexpected(make_error(
            MutationErrorCode::LocalIo,
            ec ? "failed to remove custody file: " + ec.message()
               : "custody file disappeared during cleanup",
            custody,
            operation_index));
    }
    auto synced = platform::durability::sync_parent_directory(custody);
    if (!synced)
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          synced.error(),
                                          custody,
                                          operation_index));
    return {};
#endif
}

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

std::expected<std::string, MutationError>
file_hash(const std::filesystem::path& path, std::size_t operation_index) {
    auto hash = crypto::content::hash_file(path);
    if (!hash) {
        return std::unexpected(make_error(
            MutationErrorCode::LocalIo, hash.error(), path, operation_index));
    }
    return hash_hex(*hash);
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
        return std::unexpected(
            make_error(MutationErrorCode::LocalIo,
                       "failed to query path: " + error.message(),
                       path,
                       operation_index));
    }
    return status;
}

bool missing(std::filesystem::file_status status) noexcept {
    return status.type() == std::filesystem::file_type::not_found;
}

std::filesystem::path
download_candidate_path(const std::filesystem::path& destination,
                        const platform::Workspace& workspace,
                        std::size_t operation_index) {
    return platform::path::temporary_sibling_path(
        destination,
        ".",
        ".kasumi-new-" + platform::path::to_utf8(workspace.root.filename()) +
            "-" + std::to_string(operation_index));
}

std::expected<std::filesystem::path, MutationError>
resolve_local_path(const std::filesystem::path& local_root,
                   const std::filesystem::path& relative,
                   std::size_t operation_index,
                   std::span<const Operation> plan_operations) {
    if (relative.empty() || relative == "." || relative.is_absolute() ||
        relative.has_root_name() || relative.has_root_directory() ||
        std::ranges::find(relative, std::filesystem::path{".."}) !=
            relative.end()) {
        return std::unexpected(make_error(MutationErrorCode::UnsafePath,
                                          "invalid relative path",
                                          relative,
                                          operation_index));
    }

    auto root_status = read_status(local_root, operation_index);
    if (!root_status) {
        return std::unexpected(root_status.error());
    }
    if (std::filesystem::is_symlink(*root_status)) {
        return std::unexpected(make_error(MutationErrorCode::UnsafePath,
                                          "local root is a symlink",
                                          local_root,
                                          operation_index));
    }
    if (!std::filesystem::is_directory(*root_status)) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "local root is not a directory",
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
                                          "path escapes local root",
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
                                              "path contains a symlink",
                                              current,
                                              operation_index));
        }
        const bool is_last = component_index + 1 == component_count;
        if (!is_last && !std::filesystem::is_directory(*status)) {
            bool intermediate_will_become_directory = false;
            if (!plan_operations.empty()) {
                const auto intermediate_rel =
                    current.lexically_relative(normalized_root);
                bool has_rename = false;
                bool has_create_dir = false;
                for (std::size_t i = 0;
                     i < operation_index && i < plan_operations.size();
                     ++i) {
                    if (plan_operations[i].action == Action::RenameLocal &&
                        plan_operations[i].path.lexically_normal() ==
                            intermediate_rel.lexically_normal()) {
                        has_rename = true;
                    }
                    if (plan_operations[i].action ==
                            Action::CreateLocalDirectory &&
                        plan_operations[i].path.lexically_normal() ==
                            intermediate_rel.lexically_normal()) {
                        has_create_dir = true;
                    }
                }
                if (has_rename && has_create_dir) {
                    intermediate_will_become_directory = true;
                }
            }
            if (!intermediate_will_become_directory) {
                return std::unexpected(
                    make_error(MutationErrorCode::LocalIo,
                               "intermediate component is not a directory",
                               current,
                               operation_index));
            }
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
        return std::unexpected(make_error(MutationErrorCode::InvalidOperation,
                                          "invalid content object identifier",
                                          {},
                                          operation_index));
    }

    auto source_status = read_status(source, operation_index);
    if (!source_status || std::filesystem::is_symlink(*source_status) ||
        !std::filesystem::is_regular_file(*source_status)) {
        return std::unexpected(
            make_error(MutationErrorCode::IntegrityMismatch,
                       "upload source is not a valid regular file",
                       source,
                       operation_index));
    }

    const auto encryption_trace = platform::perf_trace::begin();
    auto encrypted_file =
        crypto::encrypt_file_with_hashes(source, destination, key);
    platform::perf_trace::finish("content encryption", encryption_trace);
    if (!encrypted_file) {
        return std::unexpected(make_error(MutationErrorCode::CryptoFailure,
                                          "failed to encrypt source for upload",
                                          source,
                                          operation_index));
    }

    if (encrypted_file->plaintext_hash != *expected_hash ||
        encrypted_file->plaintext_size != operation.size) {
        remove_temporary_file(destination);
        return std::unexpected(make_error(MutationErrorCode::IntegrityMismatch,
                                          "source changed during upload",
                                          source,
                                          operation_index));
    }

    auto encrypted_status = read_status(destination, operation_index);
    if (!encrypted_status || std::filesystem::is_symlink(*encrypted_status) ||
        !std::filesystem::is_regular_file(*encrypted_status)) {
        remove_temporary_file(destination);
        return std::unexpected(
            make_error(MutationErrorCode::LocalIo,
                       "encrypted file was not created properly",
                       destination,
                       operation_index));
    }

    return PreparedUploadCiphertext{.plaintext_size = operation.size,
                                    .ciphertext_sha256 =
                                        encrypted_file->ciphertext_sha256};
}

} // namespace kasumi::application::sync::mutation::detail
