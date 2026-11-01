#include "mutation_detail.hpp"

#include "core/hasher.hpp"
#include "crypto/content.hpp"
#include "platform/durability.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "mutation_fault_test.hpp"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <system_error>
#include <utility>

namespace kasumi::application::sync::mutation::detail {

namespace {

bool path_not_found(const std::error_code& error) noexcept {
    return error == std::errc::no_such_file_or_directory ||
           error == std::errc::not_a_directory;
}

} // namespace

std::filesystem::path
rollback_candidate_path(const std::filesystem::path& destination,
                        std::string_view transaction_id,
                        std::size_t operation_index) {
    const std::string suffix = ".kasumi-rollback-candidate-" +
                               std::string(transaction_id) + "-" +
                               std::to_string(operation_index);
    return platform::path::temporary_sibling_path(destination, ".", suffix);
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

std::filesystem::path
copy_candidate_path(const std::filesystem::path& destination,
                    const platform::Workspace& workspace,
                    std::size_t operation_index) {
    return platform::path::temporary_sibling_path(
        destination,
        ".",
        ".kasumi-copy-" + platform::path::to_utf8(workspace.root.filename()) +
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

    auto normalized_root = local_root.lexically_normal();
#if !defined(_WIN32)
    if (normalized_root.filename().empty()) {
        const auto root_link = normalized_root.parent_path();
        auto link_status = read_status(root_link, operation_index);
        if (!link_status) {
            return std::unexpected(link_status.error());
        }
        if (std::filesystem::is_symlink(*link_status)) {
            std::error_code error;
            auto physical_root = std::filesystem::canonical(normalized_root, error);
            if (error) {
                return std::unexpected(make_error(
                    MutationErrorCode::UnsafePath,
                    "configured root symlink could not be resolved: " +
                        error.message(),
                    local_root,
                    operation_index));
            }
            auto physical_status = read_status(physical_root, operation_index);
            if (!physical_status) {
                return std::unexpected(physical_status.error());
            }
            if (std::filesystem::is_symlink(*physical_status) ||
                !std::filesystem::is_directory(*physical_status)) {
                return std::unexpected(make_error(
                    MutationErrorCode::UnsafePath,
                    "configured root does not resolve to a physical directory",
                    local_root,
                    operation_index));
            }
            normalized_root = std::move(physical_root);
        }
    }
#endif
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
    std::string encryption_error;
    auto encrypted_file = crypto::encrypt_file_with_hashes(
        source, destination, key, crypto::FilePurpose::Content, &encryption_error);
    platform::perf_trace::finish("content encryption", encryption_trace);
    if (!encrypted_file) {
        return std::unexpected(make_error(MutationErrorCode::CryptoFailure,
                                          "failed to encrypt source for upload: " +
                                              encryption_error,
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

namespace {

#pragma pack(push, 1)
struct DiskCopyIdentity {
    std::uint32_t magic{0x49445043}; // 'CPDI'
    std::uint16_t version{1};
    std::uint16_t reserved{0};
    std::uint64_t volume_or_dev{0};
    std::uint64_t file_id_low{0};
    std::uint64_t file_id_high{0};
    std::uint32_t valid{1};
};
#pragma pack(pop)

} // namespace

std::expected<void, MutationError>
record_copy_installed_identity(const platform::Workspace& workspace,
                               std::size_t operation_index,
                               const platform::private_storage::FileIdentity& identity) {
    if (!identity.valid) {
        return std::unexpected(make_error(MutationErrorCode::InvalidOperation,
                                          "cannot record invalid copy identity",
                                          workspace.root,
                                          operation_index));
    }
    if (workspace.root.empty()) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "workspace root is empty",
                                          workspace.root,
                                          operation_index));
    }
    const auto marker_path =
        platform::workspace_file(workspace, operation_index, ".copy_identity");
    if (marker_path.empty()) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "marker path is empty",
                                          workspace.root,
                                          operation_index));
    }

    std::ofstream out(marker_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "failed to create copy identity marker",
                                          marker_path,
                                          operation_index));
    }
    const DiskCopyIdentity disk{
        .magic = 0x49445043,
        .version = 1,
        .reserved = 0,
        .volume_or_dev = identity.volume_or_dev,
        .file_id_low = identity.file_id_low,
        .file_id_high = identity.file_id_high,
        .valid = 1,
    };
    out.write(reinterpret_cast<const char*>(&disk), sizeof(disk));
    out.flush();
    if (out.fail()) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "failed writing copy identity marker",
                                          marker_path,
                                          operation_index));
    }
    out.close();
    if (out.fail()) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "failed closing copy identity marker",
                                          marker_path,
                                          operation_index));
    }

    mutation_fault_test::hit("before_copy_identity_sync", marker_path);
    auto synced = platform::durability::sync_file(marker_path);
#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (mutation_fault_test::g_fail_copy_identity_sync_return) {
        synced = std::unexpected("simulated sync_file return error");
    }
#endif
    if (!synced) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          synced.error(),
                                          marker_path,
                                          operation_index));
    }

    mutation_fault_test::hit("before_copy_identity_dir_sync", marker_path);
    auto dir_synced = platform::durability::sync_parent_directory(marker_path);
#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (mutation_fault_test::g_fail_copy_identity_dir_sync_return) {
        dir_synced = std::unexpected("simulated sync_parent_directory return error");
    }
#endif
    if (!dir_synced) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          dir_synced.error(),
                                          marker_path,
                                          operation_index));
    }
    return {};
}

std::expected<std::optional<platform::private_storage::FileIdentity>, MutationError>
read_copy_installed_identity(const platform::Workspace& workspace,
                             std::size_t operation_index) {
    if (workspace.root.empty()) {
        return std::optional<platform::private_storage::FileIdentity>{std::nullopt};
    }
    const auto marker_path =
        platform::workspace_file(workspace, operation_index, ".copy_identity");
    if (marker_path.empty()) {
        return std::optional<platform::private_storage::FileIdentity>{std::nullopt};
    }
    std::error_code ec;
    const bool exists = std::filesystem::exists(marker_path, ec);
    if (ec) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "failed checking copy marker existence: " + ec.message(),
                                          marker_path,
                                          operation_index));
    }
    if (!exists) {
        return std::optional<platform::private_storage::FileIdentity>{std::nullopt};
    }

    const auto sz = std::filesystem::file_size(marker_path, ec);
    if (ec) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "failed reading marker file size: " + ec.message(),
                                          marker_path,
                                          operation_index));
    }
    if (sz != sizeof(DiskCopyIdentity)) {
        return std::unexpected(make_error(MutationErrorCode::IntegrityMismatch,
                                          "corrupted copy identity marker size",
                                          marker_path,
                                          operation_index));
    }

    std::ifstream in(marker_path, std::ios::binary);
    if (!in) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "failed opening copy identity marker",
                                          marker_path,
                                          operation_index));
    }
    DiskCopyIdentity disk{};
    in.read(reinterpret_cast<char*>(&disk), sizeof(disk));
    if (in.gcount() != sizeof(disk)) {
        return std::unexpected(make_error(MutationErrorCode::IntegrityMismatch,
                                          "incomplete read of copy identity marker",
                                          marker_path,
                                          operation_index));
    }
    if (disk.magic != 0x49445043 || disk.version != 1 || disk.valid != 1) {
        return std::unexpected(make_error(MutationErrorCode::IntegrityMismatch,
                                          "invalid copy identity marker header or content",
                                          marker_path,
                                          operation_index));
    }

    return std::optional<platform::private_storage::FileIdentity>{
        platform::private_storage::FileIdentity{
            .volume_or_dev = disk.volume_or_dev,
            .file_id_low = disk.file_id_low,
            .file_id_high = disk.file_id_high,
            .valid = true,
        }};
}

std::expected<void, MutationError>
clear_copy_installed_identity(const platform::Workspace& workspace,
                              std::size_t operation_index) {
    const auto marker =
        platform::workspace_file(workspace, operation_index, ".copy_identity");
    std::error_code error;
    std::filesystem::remove(marker, error);
    if (error)
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          error.message(),
                                          marker,
                                          operation_index));
    auto synced = platform::durability::sync_parent_directory(marker);
    if (!synced)
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          synced.error(),
                                          marker,
                                          operation_index));
    return {};
}

} // namespace kasumi::application::sync::mutation::detail
