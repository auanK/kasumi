#include "mutation_detail.hpp"

#include "core/hasher.hpp"
#include "core/wire.hpp"
#include "crypto/content.hpp"
#include "mutation_fault_test.hpp"
#include "platform/durability.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <iterator>
#include <limits>
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

std::expected<void, MutationError>
sync_file_checked(const std::filesystem::path& path,
                  std::size_t operation_index) {
    if (auto synced = platform::durability::sync_file(path); !synced) {
        return std::unexpected(make_error(
            MutationErrorCode::LocalIo, synced.error(), path, operation_index));
    }
    return {};
}

std::expected<void, MutationError>
sync_parent_checked(const std::filesystem::path& path,
                    std::size_t operation_index) {
    if (auto synced = platform::durability::sync_parent_directory(path);
        !synced) {
        return std::unexpected(make_error(
            MutationErrorCode::LocalIo, synced.error(), path, operation_index));
    }
    return {};
}

std::expected<void, MutationError>
validate_operation_metadata(const Operation& operation,
                            std::size_t operation_index) {
    if (operation_index == std::numeric_limits<std::size_t>::max() ||
        !is_valid_action(operation.action) || !has_safe_paths(operation)) {
        return std::unexpected(make_error(
            operation_index == std::numeric_limits<std::size_t>::max() ||
                    !is_valid_action(operation.action)
                ? MutationErrorCode::InvalidOperation
                : MutationErrorCode::UnsafePath,
            "invalid operation or index",
            operation.path,
            operation_index));
    }
    return {};
}

std::expected<void, MutationError>
require_regular_file(const std::filesystem::path& path,
                     MutationErrorCode invalid_code,
                     std::string_view invalid_message,
                     std::size_t operation_index) {
    auto status = read_status(path, operation_index);
    if (!status || std::filesystem::is_symlink(*status) ||
        !std::filesystem::is_regular_file(*status)) {
        return std::unexpected(make_error(
            invalid_code, std::string(invalid_message), path, operation_index));
    }
    return {};
}

bool identity_matches(const platform::private_storage::FileIdentity& actual,
                      const kasumi::PhysicalFileIdentity& expected) noexcept {
    return actual.valid && actual.volume_or_dev == expected.volume_or_dev &&
           actual.file_id_low == expected.file_id_low &&
           actual.file_id_high == expected.file_id_high;
}

std::expected<std::string, MutationError>
verify_file_size_and_hash(const std::filesystem::path& path,
                          std::uint64_t expected_size,
                          std::string_view expected_hash,
                          bool check_size,
                          std::string_view size_message,
                          std::string_view hash_message,
                          std::size_t operation_index,
                          MutationErrorCode mismatch_code) {
    if (check_size) {
        std::error_code size_error;
        const auto actual_size = std::filesystem::file_size(path, size_error);
        if (size_error || actual_size != expected_size) {
            return std::unexpected(make_error(
                size_error ? MutationErrorCode::LocalIo : mismatch_code,
                size_error ? size_error.message() : std::string(size_message),
                path,
                operation_index));
        }
    }
    auto actual = file_hash(path, operation_index);
    if (!actual) {
        return std::unexpected(actual.error());
    }
    if (!expected_hash.empty() && *actual != expected_hash) {
        return std::unexpected(make_error(
            mismatch_code, std::string(hash_message), path, operation_index));
    }
    return actual;
}

std::expected<void, MutationError>
verify_disposable_source(const std::filesystem::path& path,
                         const Operation& operation,
                         std::size_t operation_index,
                         std::string_view changed_message) {
    if (auto ok = require_regular_file(
            path,
            MutationErrorCode::DestinationConflict,
            "disposable source is missing or not a regular file",
            operation_index);
        !ok) {
        return ok;
    }
    const auto before_identity =
        platform::private_storage::query_file_identity(path);
    std::error_code size_error;
    const auto size = std::filesystem::file_size(path, size_error);
    if (size_error ||
        !identity_matches(before_identity,
                          operation.expected_source_identity) ||
        size != operation.size) {
        return std::unexpected(make_error(
            size_error ? MutationErrorCode::LocalIo
                       : MutationErrorCode::DestinationConflict,
            size_error ? size_error.message()
                       : "disposable source identity or size changed",
            path,
            operation_index));
    }
    auto verified =
        verify_file_size_and_hash(path,
                                  operation.size,
                                  operation.hash,
                                  false,
                                  {},
                                  changed_message,
                                  operation_index,
                                  MutationErrorCode::DestinationConflict);
    if (!verified) {
        return std::unexpected(verified.error());
    }
    const auto after_identity =
        platform::private_storage::query_file_identity(path);
    if (!identity_matches(after_identity, operation.expected_source_identity)) {
        return std::unexpected(
            make_error(MutationErrorCode::DestinationConflict,
                       std::string(changed_message),
                       path,
                       operation_index));
    }
    return {};
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
    if (std::filesystem::is_symlink(*root_status) ||
        platform::private_storage::is_reparse_or_symlink(local_root)) {
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
            auto physical_root =
                std::filesystem::canonical(normalized_root, error);
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
        if (std::filesystem::is_symlink(*status) ||
            platform::private_storage::is_reparse_or_symlink(current)) {
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

    if (auto ok =
            require_regular_file(source,
                                 MutationErrorCode::IntegrityMismatch,
                                 "upload source is not a valid regular file",
                                 operation_index);
        !ok) {
        return std::unexpected(ok.error());
    }

    std::string encryption_error;
    auto encrypted_file =
        crypto::encrypt_file_with_hashes(source,
                                         destination,
                                         key,
                                         crypto::FilePurpose::Content,
                                         &encryption_error);
    if (!encrypted_file) {
        return std::unexpected(make_error(
            MutationErrorCode::CryptoFailure,
            "failed to encrypt source for upload: " + encryption_error,
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

    if (auto ok =
            require_regular_file(destination,
                                 MutationErrorCode::LocalIo,
                                 "encrypted file was not created properly",
                                 operation_index);
        !ok) {
        remove_temporary_file(destination);
        return std::unexpected(ok.error());
    }

    return PreparedUploadCiphertext{.plaintext_size = operation.size,
                                    .ciphertext_sha256 =
                                        encrypted_file->ciphertext_sha256};
}

namespace {

constexpr std::uint32_t copy_identity_magic = 0x49445043; // 'CPDI'
constexpr std::uint16_t copy_identity_version = 1;
constexpr std::size_t copy_identity_bytes = 36;

std::filesystem::path
copy_identity_marker_path(const platform::Workspace& workspace,
                          std::size_t operation_index) {
    return workspace.root.empty() ? std::filesystem::path{}
                                  : platform::workspace_file(workspace,
                                                             operation_index,
                                                             ".copy_identity");
}

} // namespace

std::expected<void, MutationError> record_copy_installed_identity(
    const platform::Workspace& workspace,
    std::size_t operation_index,
    const platform::private_storage::FileIdentity& identity) {
    if (!identity.valid) {
        return std::unexpected(make_error(MutationErrorCode::InvalidOperation,
                                          "cannot record invalid copy identity",
                                          workspace.root,
                                          operation_index));
    }
    const auto marker_path =
        copy_identity_marker_path(workspace, operation_index);
    if (marker_path.empty()) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          "workspace or marker path is empty",
                                          workspace.root,
                                          operation_index));
    }

    wire::Writer writer;
    wire::write<std::uint32_t>(writer, copy_identity_magic);
    wire::write<std::uint16_t>(writer, copy_identity_version);
    wire::write<std::uint16_t>(writer, 0);
    wire::write<std::uint64_t>(writer, identity.volume_or_dev);
    wire::write<std::uint64_t>(writer, identity.file_id_low);
    wire::write<std::uint64_t>(writer, identity.file_id_high);
    wire::write<std::uint32_t>(writer, 1);

    const auto bytes =
        std::string_view{reinterpret_cast<const char*>(writer.buffer.data()),
                         writer.buffer.size()};
    if (auto written =
            platform::private_storage::write_atomically(marker_path, bytes);
        !written) {
        return std::unexpected(make_error(MutationErrorCode::LocalIo,
                                          written.error(),
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
        dir_synced =
            std::unexpected("simulated sync_parent_directory return error");
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

std::expected<std::optional<platform::private_storage::FileIdentity>,
              MutationError>
read_copy_installed_identity(const platform::Workspace& workspace,
                             std::size_t operation_index) {
    const auto marker_path =
        copy_identity_marker_path(workspace, operation_index);
    if (marker_path.empty()) {
        return std::optional<platform::private_storage::FileIdentity>{
            std::nullopt};
    }
    std::error_code ec;
    const auto sz = std::filesystem::file_size(marker_path, ec);
    if (ec == std::errc::no_such_file_or_directory) {
        return std::optional<platform::private_storage::FileIdentity>{
            std::nullopt};
    }
    if (ec) {
        return std::unexpected(
            make_error(MutationErrorCode::LocalIo,
                       "failed reading marker file size: " + ec.message(),
                       marker_path,
                       operation_index));
    }
    if (sz != copy_identity_bytes) {
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
    std::array<std::byte, copy_identity_bytes> raw{};
    in.read(reinterpret_cast<char*>(raw.data()),
            static_cast<std::streamsize>(raw.size()));
    if (in.gcount() != static_cast<std::streamsize>(raw.size())) {
        return std::unexpected(
            make_error(MutationErrorCode::IntegrityMismatch,
                       "incomplete read of copy identity marker",
                       marker_path,
                       operation_index));
    }

    wire::Reader reader{raw};
    const auto magic = wire::read<std::uint32_t>(reader);
    const auto version = wire::read<std::uint16_t>(reader);
    const auto reserved = wire::read<std::uint16_t>(reader);
    const auto vol = wire::read<std::uint64_t>(reader);
    const auto low = wire::read<std::uint64_t>(reader);
    const auto high = wire::read<std::uint64_t>(reader);
    const auto valid = wire::read<std::uint32_t>(reader);
    if (!magic || !version || !reserved || !vol || !low || !high || !valid ||
        *magic != copy_identity_magic || *version != copy_identity_version ||
        *valid != 1) {
        return std::unexpected(
            make_error(MutationErrorCode::IntegrityMismatch,
                       "invalid copy identity marker header or content",
                       marker_path,
                       operation_index));
    }

    return std::optional<platform::private_storage::FileIdentity>{
        platform::private_storage::FileIdentity{
            .volume_or_dev = *vol,
            .file_id_low = *low,
            .file_id_high = *high,
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
