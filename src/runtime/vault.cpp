#include "runtime/vault.hpp"

#include "platform/durability.hpp"
#include "platform/private_storage.hpp"
#include "vault_wipe.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <monocypher.h>
#include <string>
#include <string_view>
#include <system_error>

namespace kasumi::runtime::vault {

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
    WipeGuard guard{key};
    for (std::size_t index = 0; index < key.size(); ++index) {
        const int high = digit(text[index * 2]);
        const int low = digit(text[index * 2 + 1]);
        if (high < 0 || low < 0) {
            return fail(ErrorCode::KeyInvalid,
                        "KASUMI_MASTER_KEY contains non-hexadecimal character");
        }
        key[index] = static_cast<uint8_t>((high << 4) | low);
    }
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
    WipeGuard key_guard{key};
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

#if !defined(_WIN32) && !defined(__linux__)
std::expected<void, runtime::Error> check_vault_available() {
    return fail(ErrorCode::KeyWriteFailure,
                "OS credential vault is not supported on this platform yet");
}

std::expected<KeyBytes, runtime::Error>
read_vault(const std::filesystem::path& key_path) {
    static_cast<void>(key_path);
    return fail(ErrorCode::KeyNotFound,
                "OS credential vault is not supported on this platform yet");
}

std::expected<void, runtime::Error>
write_vault(const std::filesystem::path& key_path, const KeyBytes& clear_key) {
    static_cast<void>(key_path);
    static_cast<void>(clear_key);
    return fail(ErrorCode::KeyWriteFailure,
                "OS credential vault is not supported on this platform yet");
}

std::expected<void, runtime::Error>
delete_vault(const std::filesystem::path& key_path) {
    static_cast<void>(key_path);
    return {};
}
#endif

namespace {

std::expected<KeyBytes, runtime::Error>
derive_argon2id(std::string_view password, std::string_view salt_password) {
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
    WipeGuard key_guard{key};
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

bool valid_derivation_input(std::string_view password,
                            std::string_view salt,
                            std::size_t minimum) noexcept {
    constexpr auto max_input = std::numeric_limits<std::uint32_t>::max();
    return password.size() >= minimum && password.size() <= max_input &&
           salt.size() >= MINIMUM_PASSWORD_SALT_SIZE && salt.size() <= max_input;
}

} // namespace

std::expected<KeyBytes, runtime::Error>
derive(std::string_view password, std::string_view salt_password) {
    if (!valid_derivation_input(password, salt_password, MINIMUM_PASSWORD_SIZE))
        return fail(ErrorCode::KeyDerivationFailure,
                    "password must be at least 12 characters and salt must "
                    "be at least 16 characters");
    return derive_argon2id(password, salt_password);
}

std::expected<KeyBytes, runtime::Error>
derive_web_password_verifier(std::string_view password, std::string_view salt) {
    if (!valid_derivation_input(password, salt, MINIMUM_WEB_PASSWORD_SIZE))
        return fail(ErrorCode::KeyDerivationFailure,
                    "invalid Web UI password or verifier salt");
    return derive_argon2id(password, salt);
}

} // namespace kasumi::runtime::vault
