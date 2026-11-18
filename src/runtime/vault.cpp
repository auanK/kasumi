#include "runtime/vault.hpp"

#include "platform/durability.hpp"
#include "platform/private_storage.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <monocypher.h>
#include <string>
#include <string_view>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// clang-format off
#include <windows.h>
#include <wincred.h>
// clang-format on
#endif

namespace kasumi::runtime::vault {

namespace {

template <typename T> struct WipeGuard {
    T& value;
    bool* skip = nullptr;
    ~WipeGuard() noexcept {
        if (skip == nullptr || !*skip) {
            crypto_wipe(value.data(), value.size());
        }
    }
};

} // namespace

constexpr std::string_view MAGIC = "KASUMI_EDGE_SYNC_V1_MASK";

std::expected<KeyBytes, runtime::Error> decode_hex(std::string_view text) {
    if (text.size() != KEY_SIZE * 2) {
        return fail(ErrorCode::KeyInvalid,
                    "KASUMI_MASTER_KEY must be 64 hexadecimal characters");
    }
    const auto digit = [](char value) -> int {
        if (value >= '0' && value <= '9')
            return value - '0';
        if (value >= 'a' && value <= 'f')
            return value - 'a' + 10;
        if (value >= 'A' && value <= 'F')
            return value - 'A' + 10;
        return -1;
    };
    KeyBytes key{};
    bool success = false;
    WipeGuard guard{key, &success};
    for (std::size_t index = 0; index < key.size(); ++index) {
        const int high = digit(text[index * 2]);
        const int low = digit(text[index * 2 + 1]);
        if (high < 0 || low < 0) {
            return fail(ErrorCode::KeyInvalid,
                        "KASUMI_MASTER_KEY contains non-hexadecimal character");
        }
        key[index] = static_cast<uint8_t>((high << 4) | low);
    }
    success = true;
    return key;
}

void obscure(std::span<std::uint8_t, KEY_SIZE> key) {
    for (std::size_t i = 0; i < KEY_SIZE; ++i) {
        key[i] ^= static_cast<uint8_t>(MAGIC[i % MAGIC.size()]);
    }
}

std::expected<KeyBytes, runtime::Error>
read_impl(const std::filesystem::path& path, bool protect) {
    if (protect) {
        if (auto secured = platform::private_storage::protect_file(path);
            !secured) {
            return fail(ErrorCode::KeyNotFound, secured.error());
        }
    } else {
        std::error_code filesystem_error;
        const auto status =
            std::filesystem::symlink_status(path, filesystem_error);
        if (filesystem_error ||
            status.type() == std::filesystem::file_type::not_found ||
            std::filesystem::is_symlink(status) ||
            !std::filesystem::is_regular_file(status)) {
            return fail(ErrorCode::KeyNotFound,
                        "key.bin file is missing or invalid; run 'kasumi key "
                        "<profile>' to re-enter the key");
        }
    }
    KeyBytes key{};
    bool success = false;
    WipeGuard key_guard{key, &success};
    std::array<std::uint8_t, KEY_SIZE + 1> buf{};
    WipeGuard buf_guard{buf};
    std::size_t total = 0;

    auto streamed = platform::private_storage::stream_regular_file(
        path, buf, [&](std::span<const std::uint8_t> chunk) -> bool {
            const std::size_t copy = std::min(chunk.size(), key.size() - total);
            if (copy > 0) {
                std::memcpy(key.data() + total, chunk.data(), copy);
            }
            total += chunk.size();
            return total <= key.size();
        });
    if (!streamed) {
        if (streamed.error().kind ==
            platform::private_storage::StreamErrorKind::Aborted) {
            return fail(ErrorCode::KeyInvalid, "key.bin file has invalid size");
        }
        return fail(ErrorCode::KeyNotFound,
                    "key.bin file is missing or corrupted; run 'kasumi key "
                    "<profile>' to re-enter the key");
    }
    if (total != key.size()) {
        return fail(ErrorCode::KeyNotFound,
                    "key.bin file is missing or corrupted; run 'kasumi key "
                    "<profile>' to re-enter the key");
    }
    obscure(key);
    success = true;
    return key;
}

std::expected<KeyBytes, runtime::Error>
read(const std::filesystem::path& path) {
    return read_impl(path, true);
}

std::expected<KeyBytes, runtime::Error>
read_only(const std::filesystem::path& path) {
    return read_impl(path, false);
}

namespace {

std::expected<KeyBytes, Error>
prepare_write_key(const std::filesystem::path& path,
                  const KeyBytes& clear_key) {
    if (auto parent =
            platform::private_storage::ensure_directory(path.parent_path());
        !parent) {
        return fail(ErrorCode::IoFailure, parent.error());
    }
    KeyBytes stored = clear_key;
    obscure(stored);
    return stored;
}

} // namespace

std::expected<void, runtime::Error> write(const std::filesystem::path& path,
                                          const KeyBytes& clear_key) {
    auto stored = prepare_write_key(path, clear_key);
    if (!stored) {
        return std::unexpected(stored.error());
    }
    WipeGuard guard{*stored};
    const std::string_view bytes{reinterpret_cast<const char*>(stored->data()),
                                 stored->size()};
    if (auto saved = platform::private_storage::write_atomically(path, bytes);
        !saved) {
        return fail(ErrorCode::KeyWriteFailure, saved.error());
    }
    return {};
}

std::expected<void, runtime::Error>
write_new(const std::filesystem::path& path,
          const KeyBytes& clear_key,
          platform::private_storage::FileIdentity& identity) {
    identity = {};
    auto stored = prepare_write_key(path, clear_key);
    if (!stored) {
        return std::unexpected(stored.error());
    }
    WipeGuard guard{*stored};
    auto file = platform::private_storage::create_private_file(path);
    if (!file) {
        return fail(ErrorCode::KeyWriteFailure, file.error().message);
    }
    identity = file->identity;
    if (auto written = platform::private_storage::write_private_file(
            *file, stored->data(), stored->size());
        !written) {
        return fail(ErrorCode::KeyWriteFailure, written.error());
    }
    if (auto flushed =
            platform::private_storage::flush_and_close_private_file(*file);
        !flushed) {
        return fail(ErrorCode::KeyWriteFailure, flushed.error());
    }
    if (auto synced = platform::durability::sync_parent_directory(path);
        !synced) {
        return fail(ErrorCode::KeyWriteFailure, synced.error());
    }
    return {};
}

namespace {

#if defined(_WIN32)
std::wstring vault_target_name(const std::filesystem::path& key_path) {
    std::error_code ec;
    const auto abs = std::filesystem::absolute(key_path, ec);
    const auto normalized = (ec ? key_path : abs).lexically_normal();
    std::wstring target = L"kasumi:" + normalized.generic_wstring();
    for (auto& ch : target) {
        if (ch >= L'A' && ch <= L'Z') {
            ch = static_cast<wchar_t>(ch - L'A' + L'a');
        }
    }
    return target;
}
#endif

} // namespace

std::expected<KeyBytes, runtime::Error>
read_vault(const std::filesystem::path& key_path) {
#if defined(_WIN32)
    const auto target = vault_target_name(key_path);
    PCREDENTIALW cred = nullptr;
    if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &cred)) {
        if (GetLastError() == ERROR_NOT_FOUND) {
            return fail(ErrorCode::KeyNotFound,
                        "profile key is missing in OS vault; run 'kasumi key "
                        "<profile>' to re-enter the key");
        }
        return fail(ErrorCode::KeyNotFound,
                    "failed to read key from Windows Credential Manager");
    }
    struct CredGuard {
        PCREDENTIALW ptr;
        ~CredGuard() noexcept {
            if (ptr != nullptr) {
                if (ptr->CredentialBlob != nullptr &&
                    ptr->CredentialBlobSize > 0) {
                    crypto_wipe(ptr->CredentialBlob, ptr->CredentialBlobSize);
                }
                CredFree(ptr);
            }
        }
    } cred_guard{cred};

    if (cred->CredentialBlob == nullptr ||
        cred->CredentialBlobSize != static_cast<DWORD>(KEY_SIZE)) {
        return fail(ErrorCode::KeyInvalid, "OS vault key has invalid size");
    }
    KeyBytes key{};
    std::memcpy(key.data(), cred->CredentialBlob, KEY_SIZE);
    obscure(key);
    return key;
#else
    static_cast<void>(key_path);
    return fail(ErrorCode::KeyNotFound,
                "OS credential vault is not supported on this platform yet");
#endif
}

std::expected<void, runtime::Error>
write_vault(const std::filesystem::path& key_path, const KeyBytes& clear_key) {
#if defined(_WIN32)
    auto target = vault_target_name(key_path);
    KeyBytes stored = clear_key;
    obscure(stored);
    WipeGuard guard{stored};

    CREDENTIALW cred{};
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = target.data();
    cred.CredentialBlobSize = static_cast<DWORD>(stored.size());
    cred.CredentialBlob = stored.data();
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;

    if (!CredWriteW(&cred, 0)) {
        return fail(ErrorCode::KeyWriteFailure,
                    "failed to store key in Windows Credential Manager");
    }
    return {};
#else
    static_cast<void>(key_path);
    static_cast<void>(clear_key);
    return fail(ErrorCode::KeyWriteFailure,
                "OS credential vault is not supported on this platform yet");
#endif
}

std::expected<void, runtime::Error>
delete_vault(const std::filesystem::path& key_path) {
#if defined(_WIN32)
    const auto target = vault_target_name(key_path);
    if (!CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0) &&
        GetLastError() != ERROR_NOT_FOUND) {
        return fail(ErrorCode::IoFailure,
                    "failed to delete key from Windows Credential Manager");
    }
    return {};
#else
    static_cast<void>(key_path);
    return {};
#endif
}

std::expected<KeyBytes, runtime::Error> derive(std::string_view password,
                                               std::string_view salt_password) {
    if (password.size() < MINIMUM_PASSWORD_SIZE ||
        salt_password.size() < MINIMUM_PASSWORD_SALT_SIZE ||
        password.size() > std::numeric_limits<std::uint32_t>::max() ||
        salt_password.size() > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(Error{
            .code = ErrorCode::KeyDerivationFailure,
            .detail = "password must be at least 12 characters and salt must "
                      "be at least 16 characters"});
    }
    crypto_argon2_config config = {.algorithm = CRYPTO_ARGON2_ID,
                                   .nb_blocks = ARGON2_MEMORY_BLOCKS,
                                   .nb_passes = ARGON2_PASSES,
                                   .nb_lanes = 1};

    void* work_area = std::malloc(config.nb_blocks * 1024);
    if (!work_area) {
        return std::unexpected(
            Error{.code = ErrorCode::KeyDerivationFailure,
                  .detail = "memory allocation failed in Argon2"});
    }

    crypto_argon2_inputs inputs = {
        .pass = reinterpret_cast<const uint8_t*>(password.data()),
        .salt = reinterpret_cast<const uint8_t*>(salt_password.data()),
        .pass_size = static_cast<uint32_t>(password.size()),
        .salt_size = static_cast<uint32_t>(salt_password.size())};

    KeyBytes key{};
    crypto_argon2(key.data(),
                  KEY_SIZE,
                  work_area,
                  config,
                  inputs,
                  crypto_argon2_no_extras);

    crypto_wipe(work_area, config.nb_blocks * 1024);
    std::free(work_area);
    return key;
}

} // namespace kasumi::runtime::vault
