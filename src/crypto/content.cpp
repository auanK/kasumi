#include "crypto/content.hpp"

#include "platform/path.hpp"
#include <blake3.h>
#include <fstream>
#include <stdexcept>
#include <system_error>
#include <vector>

namespace kasumi::crypto::content {

std::expected<Hash, std::string> hash_file(const std::filesystem::path& path) {
    try {
        std::ifstream input(path, std::ios::binary);
        if (!input) {
            return std::unexpected(
                "não foi possível abrir o arquivo para hash: " + platform::path::to_utf8(path));
        }

        blake3_hasher state;
        blake3_hasher_init(&state);
        std::vector<char> buffer(1024U * 1024U);

        while (input) {
            input.read(buffer.data(),
                       static_cast<std::streamsize>(buffer.size()));
            const auto count = input.gcount();
            if (count > 0) {
                blake3_hasher_update(
                    &state, buffer.data(), static_cast<std::size_t>(count));
            }
        }

        if (input.bad()) {
            return std::unexpected("falha ao ler o arquivo para hash: " +
                                   platform::path::to_utf8(path));
        }

        Hash result{};
        blake3_hasher_finalize(&state,
                               reinterpret_cast<std::uint8_t*>(result.data()),
                               result.size());
        return result;
    } catch (const std::exception& exception) {
        return std::unexpected(
            std::string{"não foi possível calcular o hash do arquivo: "} +
            exception.what());
    }
}

std::expected<void, std::string>
verify_file(const std::filesystem::path& path,
            std::string_view expected_hash,
            std::optional<std::uint64_t> expected_size) {
    auto decoded_hash = hash_from_hex(expected_hash);
    if (!decoded_hash) {
        return std::unexpected("hash esperado inválido: " +
                               decoded_hash.error());
    }

    try {
        std::error_code error;
        const auto file_status = std::filesystem::symlink_status(path, error);
        if (error) {
            return std::unexpected("não foi possível consultar o arquivo: " +
                                   error.message());
        }
        if (std::filesystem::is_symlink(file_status)) {
            return std::unexpected(
                "o caminho é um symlink e não pode ser verificado");
        }
        if (file_status.type() == std::filesystem::file_type::not_found) {
            return std::unexpected("o arquivo não existe");
        }
        if (!std::filesystem::is_regular_file(file_status)) {
            return std::unexpected("o caminho não é um arquivo regular");
        }

        if (expected_size) {
            const auto actual_size = std::filesystem::file_size(path, error);
            if (error) {
                return std::unexpected(
                    "não foi possível ler o tamanho do arquivo: " +
                    error.message());
            }
            if (actual_size != *expected_size) {
                return std::unexpected(
                    "o tamanho do arquivo não corresponde ao esperado");
            }
        }

        auto actual_hash = hash_file(path);
        if (!actual_hash) {
            return std::unexpected(actual_hash.error());
        }
        if (*actual_hash != *decoded_hash) {
            return std::unexpected(
                "o conteúdo do arquivo não corresponde ao hash esperado");
        }
        return {};
    } catch (const std::exception& exception) {
        return std::unexpected(
            std::string{"não foi possível verificar o arquivo: "} +
            exception.what());
    }
}

} // namespace kasumi::crypto::content
