#include "runtime/vault.hpp"

#include "platform/private_storage.hpp"

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <monocypher.h>

namespace kasumi::runtime::vault {

constexpr const char* MAGIC = "KASUMI_EDGE_SYNC_V1_MASK";

std::expected<KeyBytes, runtime::Error> decode_hex(std::string_view text) {
    if (text.size() != KEY_SIZE * 2) {
        return std::unexpected(Error{
            .code = ErrorCode::KeyInvalid,
            .detail =
                "KASUMI_MASTER_KEY deve possuir 64 caracteres hexadecimais"});
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
    for (std::size_t index = 0; index < key.size(); ++index) {
        const int high = digit(text[index * 2]);
        const int low = digit(text[index * 2 + 1]);
        if (high < 0 || low < 0) {
            return std::unexpected(Error{
                .code = ErrorCode::KeyInvalid,
                .detail =
                    "KASUMI_MASTER_KEY contém caractere não hexadecimal"});
        }
        key[index] = static_cast<uint8_t>((high << 4) | low);
    }
    return key;
}

void obscure(std::span<std::uint8_t, KEY_SIZE> key) {
    size_t magic_len = std::strlen(MAGIC);
    for (size_t i = 0; i < KEY_SIZE; ++i) {
        key[i] ^= static_cast<uint8_t>(MAGIC[i % magic_len]);
    }
}

std::expected<KeyBytes, runtime::Error>
read_impl(const std::filesystem::path& path, bool protect) {
    if (protect) {
        auto secured = platform::private_storage::protect_file(path);
        if (!secured) {
            return std::unexpected(Error{.code = ErrorCode::KeyNotFound,
                                         .detail = secured.error()});
        }
    } else {
        std::error_code filesystem_error;
        const auto status =
            std::filesystem::symlink_status(path, filesystem_error);
        if (filesystem_error ||
            status.type() == std::filesystem::file_type::not_found ||
            std::filesystem::is_symlink(status) ||
            !std::filesystem::is_regular_file(status)) {
            return std::unexpected(
                Error{.code = ErrorCode::KeyNotFound,
                      .detail = "arquivo key.bin ausente ou inválido"});
        }
    }
    std::ifstream input(path, std::ios::binary);
    KeyBytes key{};
    if (!input.read(reinterpret_cast<char*>(key.data()),
                    static_cast<std::streamsize>(key.size()))) {
        return std::unexpected(
            Error{.code = ErrorCode::KeyNotFound,
                  .detail = "arquivo key.bin ausente ou corrompido"});
    }
    if (input.peek() != std::ifstream::traits_type::eof()) {
        return std::unexpected(
            Error{.code = ErrorCode::KeyInvalid,
                  .detail = "arquivo key.bin possui tamanho inválido"});
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

std::expected<void, runtime::Error> write(const std::filesystem::path& path,
                                          const KeyBytes& clear_key) {
    auto parent =
        platform::private_storage::ensure_directory(path.parent_path());
    if (!parent) {
        return std::unexpected(
            Error{.code = ErrorCode::IoFailure, .detail = parent.error()});
    }
    KeyBytes stored = clear_key;
    obscure(stored);
    const std::string_view bytes{reinterpret_cast<const char*>(stored.data()),
                                 stored.size()};
    auto saved = platform::private_storage::write_atomically(path, bytes);
    crypto_wipe(stored.data(), stored.size());
    if (!saved) {
        return std::unexpected(
            Error{.code = ErrorCode::KeyWriteFailure, .detail = saved.error()});
    }
    return {};
}

std::expected<KeyBytes, runtime::Error> derive(std::string_view password,
                                               std::string_view salt_password) {
    if (password.size() < MINIMUM_PASSWORD_SIZE ||
        salt_password.size() < MINIMUM_PASSWORD_SALT_SIZE ||
        password.size() > std::numeric_limits<std::uint32_t>::max() ||
        salt_password.size() > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(Error{
            .code = ErrorCode::KeyDerivationFailure,
            .detail = "a senha precisa ter ao menos 12 caracteres e o salto da "
                      "senha, 16 caracteres"});
    }
    crypto_argon2_config config = {.algorithm = CRYPTO_ARGON2_ID,
                                   .nb_blocks = ARGON2_MEMORY_BLOCKS,
                                   .nb_passes = ARGON2_PASSES,
                                   .nb_lanes = 1};

    void* work_area = std::malloc(config.nb_blocks * 1024);
    if (!work_area) {
        return std::unexpected(Error{.code = ErrorCode::KeyDerivationFailure,
                                     .detail = "falha de memória no Argon2"});
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
