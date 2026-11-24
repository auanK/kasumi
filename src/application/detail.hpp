#ifndef KASUMI_APPLICATION_DETAIL_HPP
#define KASUMI_APPLICATION_DETAIL_HPP

#include "application/credentials.hpp"
#include "crypto/secure_memory.hpp"
#include "runtime/error.hpp"
#include "runtime/resolver.hpp"
#include "runtime/vault.hpp"

#include <array>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <system_error>
#include <variant>

namespace kasumi::application::detail {

template <std::size_t N> struct WipedBytes {
    std::array<std::uint8_t, N> data{};
    WipedBytes() = default;
    ~WipedBytes() noexcept {
        crypto::secure_memory::wipe(data.data(), data.size());
    }
    WipedBytes(const WipedBytes&) = delete;
    WipedBytes& operator=(const WipedBytes&) = delete;
};

template <typename ErrorCodeT>
ErrorCodeT map_runtime_error_code(runtime::ErrorCode source,
                                  ErrorCodeT invalid_name,
                                  ErrorCodeT not_found,
                                  ErrorCodeT credential,
                                  ErrorCodeT io_or_escape,
                                  ErrorCodeT config) noexcept {
    switch (source) {
        case runtime::ErrorCode::InvalidProfileName:
            return invalid_name;
        case runtime::ErrorCode::ProfileNotFound:
            return not_found;
        case runtime::ErrorCode::KeyNotFound:
        case runtime::ErrorCode::KeyInvalid:
        case runtime::ErrorCode::KeyDerivationFailure:
        case runtime::ErrorCode::KeyWriteFailure:
            return credential;
        case runtime::ErrorCode::IoFailure:
        case runtime::ErrorCode::PathEscape:
            return io_or_escape;
        case runtime::ErrorCode::ConfigNotFound:
        case runtime::ErrorCode::ConfigInvalid:
        case runtime::ErrorCode::ProfileInvalid:
            return config;
    }
    return config;
}

template <typename ErrorT> struct VaultKeyPolicy {
    bool read_only = false;
    decltype(ErrorT::code) missing_code{};
    decltype(ErrorT::code) mismatch_code{};
    decltype(ErrorT::code) io_code{};
    decltype(ErrorT::code) credential_code{};
    const char* missing_detail = "";
};

template <typename ErrorT, typename MakeErrorFn>
std::expected<void, ErrorT>
resolve_vault_key(const Credentials& credentials,
                  const runtime::RuntimeData& runtime_data,
                  runtime::vault::KeyBytes& output,
                  const VaultKeyPolicy<ErrorT>& policy,
                  MakeErrorFn&& make_error) {
    crypto::secure_memory::wipe(output.data(), output.size());

    WipedBytes<runtime::vault::KEY_SIZE> candidate;
    bool has_master = false;
    if (const auto* master_key = std::get_if<MasterKeyHex>(&credentials)) {
        auto decoded = runtime::vault::decode_hex(master_key->value);
        if (!decoded) {
            return std::unexpected(
                make_error(policy.credential_code, decoded.error().detail));
        }
        candidate.data = *decoded;
        crypto::secure_memory::wipe(decoded->data(), decoded->size());
        has_master = true;
    } else if (const auto* master_bytes =
                   std::get_if<MasterKeyBytes>(&credentials)) {
        candidate.data = master_bytes->bytes;
        has_master = true;
    } else if (const auto* pair = std::get_if<PasswordPair>(&credentials)) {
        auto derived =
            runtime::vault::derive(pair->password, pair->salt_password);
        if (!derived) {
            return std::unexpected(
                make_error(policy.credential_code, derived.error().detail));
        }
        candidate.data = *derived;
        crypto::secure_memory::wipe(derived->data(), derived->size());
        has_master = true;
    }

    if (runtime_data.key_storage == runtime::KeyStorage::Memory) {
        if (!has_master) {
            return std::unexpected(make_error(
                policy.missing_code,
                std::string{policy.missing_detail} +
                    " (profile uses in-memory key storage; password and salt "
                    "are required)"));
        }
        output = candidate.data;
        return {};
    }

    const auto match_or_return_stored =
        [&](runtime::vault::KeyBytes& raw_stored)
        -> std::expected<void, ErrorT> {
        WipedBytes<runtime::vault::KEY_SIZE> stored_wiped;
        stored_wiped.data = raw_stored;
        crypto::secure_memory::wipe(raw_stored.data(), raw_stored.size());
        if (has_master && stored_wiped.data != candidate.data) {
            return std::unexpected(make_error(
                policy.mismatch_code, "credential does not match profile"));
        }
        output = has_master ? candidate.data : stored_wiped.data;
        return {};
    };

    if (runtime_data.key_storage == runtime::KeyStorage::Vault) {
        auto stored = runtime::vault::read_vault(runtime_data.key_path);
        if (stored) {
            return match_or_return_stored(*stored);
        }
        if (stored.error().code == runtime::ErrorCode::KeyNotFound) {
            if (!has_master) {
                return std::unexpected(
                    make_error(policy.missing_code,
                               std::string{policy.missing_detail} + "; " +
                                   stored.error().detail));
            }
            output = candidate.data;
            return {};
        }
        return std::unexpected(
            make_error(policy.credential_code, stored.error().detail));
    }

    std::error_code fs_err;
    const auto status =
        std::filesystem::symlink_status(runtime_data.key_path, fs_err);
    if (fs_err && fs_err != std::errc::no_such_file_or_directory) {
        return std::unexpected(
            make_error(policy.io_code, "failed to verify persisted key"));
    }
    const bool present = status.type() != std::filesystem::file_type::not_found;
    if (!has_master && !present) {
        return std::unexpected(
            make_error(policy.missing_code,
                       std::string{policy.missing_detail} +
                           "; key.bin not found, run 'kasumi key <profile>' to "
                           "re-enter the key"));
    }

    if (present) {
        auto stored = policy.read_only
                          ? runtime::vault::read_only(runtime_data.key_path)
                          : runtime::vault::read(runtime_data.key_path);
        if (!stored) {
            return std::unexpected(make_error(
                policy.credential_code,
                policy.read_only ? "failed to read profile persisted key"
                                 : stored.error().detail));
        }
        return match_or_return_stored(*stored);
    }

    output = candidate.data;
    return {};
}

inline std::filesystem::path
maintenance_workspace_root(const runtime::RuntimeData& runtime) {
    std::error_code ec;
    auto root = runtime.database_path.parent_path();
    if (!root.empty() && std::filesystem::exists(root, ec)) {
        return root;
    }
    root = runtime.local_dir.parent_path();
    if (!root.empty() && std::filesystem::exists(root, ec)) {
        return root;
    }
    return std::filesystem::temp_directory_path();
}

inline std::array<std::filesystem::path, 3>
sqlite_sidecar_paths(const std::filesystem::path& db_path) {
    const auto with_suffix = [&](std::string_view suffix) {
        auto path = db_path;
        path += suffix;
        return path;
    };
    return {with_suffix("-wal"), with_suffix("-shm"), with_suffix("-journal")};
}

} // namespace kasumi::application::detail

#endif
