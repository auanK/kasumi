#include "runtime/vault.hpp"
#include "vault_wipe.hpp"

#include <cstring>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>

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

namespace kasumi::runtime::vault {
namespace {

// Keep verification in the same critical section as its write or delete.
std::mutex& credential_mutex() noexcept {
    static std::mutex mutex;
    return mutex;
}

template <typename Operation> DWORD credential_call(Operation operation) {
    for (unsigned attempt = 0;; ++attempt) {
        if (operation()) {
            return ERROR_SUCCESS;
        }
        const auto error = GetLastError();
        if (attempt == 5 ||
            (error != ERROR_SHARING_VIOLATION &&
             error != ERROR_LOCK_VIOLATION && error != ERROR_BUSY &&
             error != ERROR_ACCESS_DENIED && error != ERROR_RETRY &&
             error != RPC_S_SERVER_TOO_BUSY)) {
            return error;
        }
        Sleep(10UL << attempt);
    }
}

struct Credential {
    PCREDENTIALW value = nullptr;
    Credential() = default;
    Credential(const Credential&) = delete;
    Credential& operator=(const Credential&) = delete;

    ~Credential() noexcept {
        if (value != nullptr) {
            if (value->CredentialBlob != nullptr &&
                value->CredentialBlobSize > 0) {
                crypto_wipe(value->CredentialBlob, value->CredentialBlobSize);
            }
            CredFree(value);
        }
    }

    DWORD read(const std::wstring& target) {
        return credential_call([&] {
            return CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &value);
        });
    }

    bool has_key() const noexcept {
        return value != nullptr && value->CredentialBlob != nullptr &&
               value->CredentialBlobSize == static_cast<DWORD>(KEY_SIZE);
    }
};

std::string credential_error(std::string_view operation, DWORD error) {
    return "Windows Credential Manager: " + std::string{operation} + " (" +
           std::to_string(error) + "): " +
           std::error_code{static_cast<int>(error), std::system_category()}
               .message();
}

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

} // namespace

std::expected<void, runtime::Error> check_vault_available() {
    return {};
}

std::expected<KeyBytes, runtime::Error>
read_vault(const std::filesystem::path& key_path) {
    const auto target = vault_target_name(key_path);
    const std::lock_guard lock{credential_mutex()};
    Credential credential;
    DWORD error = credential.read(target);
    for (unsigned attempt = 0; error == ERROR_NOT_FOUND && attempt < 4U;
         ++attempt) {
        Sleep(10UL << attempt);
        error = credential.read(target);
    }
    if (error == ERROR_NOT_FOUND) {
        return fail(ErrorCode::KeyNotFound,
                    "profile key is missing in OS vault; run 'kasumi key "
                    "<profile>' to re-enter the key");
    }
    if (error != ERROR_SUCCESS) {
        return fail(ErrorCode::IoFailure, credential_error("read key", error));
    }
    if (!credential.has_key()) {
        return fail(ErrorCode::KeyInvalid, "OS vault key has invalid size");
    }
    KeyBytes key{};
    WipeGuard guard{key};
    std::memcpy(key.data(), credential.value->CredentialBlob, KEY_SIZE);
    obscure(key);
    return key;
}

std::expected<void, runtime::Error>
write_vault(const std::filesystem::path& key_path, const KeyBytes& clear_key) {
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

    const std::lock_guard lock{credential_mutex()};
    for (unsigned attempt = 0;; ++attempt) {
        const auto error = credential_call([&] {
            return CredWriteW(&cred, 0);
        });
        if (error != ERROR_SUCCESS) {
            return fail(ErrorCode::KeyWriteFailure,
                        credential_error("store key", error));
        }
        Credential verify;
        auto read_error = verify.read(target);
        if (read_error == ERROR_SUCCESS) {
            if (verify.has_key() &&
                crypto_verify32(verify.value->CredentialBlob, stored.data()) ==
                    0) {
                return {};
            }
            read_error = ERROR_INVALID_DATA;
        }
        if (attempt < 5U) {
            Sleep(10UL << attempt);
            continue;
        }
        return fail(ErrorCode::KeyWriteFailure,
                    credential_error("verify stored key", read_error));
    }
}

std::expected<void, runtime::Error>
delete_vault(const std::filesystem::path& key_path) {
    const auto target = vault_target_name(key_path);
    const std::lock_guard lock{credential_mutex()};
    DWORD read_error = ERROR_SUCCESS;
    for (unsigned attempt = 0; attempt < 6U; ++attempt) {
        const auto error = credential_call([&] {
            return CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0);
        });
        if (error != ERROR_SUCCESS && error != ERROR_NOT_FOUND) {
            return fail(ErrorCode::IoFailure,
                        credential_error("delete key", error));
        }
        Credential verify;
        read_error = verify.read(target);
        if (read_error == ERROR_NOT_FOUND) {
            return {};
        }
        if (attempt < 5U) {
            Sleep(10UL << attempt);
        }
    }
    return fail(
        ErrorCode::IoFailure,
        read_error == ERROR_SUCCESS
            ? "Windows Credential Manager: key still present after deletion"
            : credential_error("verify deleted key", read_error));
}

} // namespace kasumi::runtime::vault
