#include "crypto/file_crypto.hpp"

#include "crypto/physical_hash.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"

#include <algorithm>
#include <array>
#include <blake3.h>
#include <fstream>
#include <limits>
#include <monocypher.h>
#include <system_error>
#include <vector>

namespace kasumi::crypto {

namespace {

inline constexpr std::array<std::uint8_t, 8> format_magic{
    'K', 'A', 'S', 'U', 'M', 'I', 2, 0};
inline constexpr std::size_t header_ad_size =
    format_magic.size() + NONCE_SIZE + sizeof(std::uint64_t);
inline constexpr std::size_t header_size = FILE_HEADER_SIZE;
inline constexpr std::size_t chunk_ad_size =
    header_ad_size + 2 * sizeof(std::uint64_t);

void encode_u64_le(std::uint64_t value, std::uint8_t* output) noexcept {
    for (std::size_t index = 0; index < sizeof(value); ++index) {
        output[index] =
            static_cast<std::uint8_t>((value >> (index * 8)) & 0xffU);
    }
}

std::uint64_t decode_u64_le(const std::uint8_t* input) noexcept {
    std::uint64_t result = 0;
    for (std::size_t index = 0; index < sizeof(result); ++index) {
        result |= static_cast<std::uint64_t>(input[index]) << (index * 8);
    }
    return result;
}

std::array<std::uint8_t, header_ad_size>
make_header_ad(const std::uint8_t* base_nonce,
               std::uint64_t plaintext_size) noexcept {
    std::array<std::uint8_t, header_ad_size> result{};
    std::copy(format_magic.begin(), format_magic.end(), result.begin());
    std::copy_n(base_nonce,
                NONCE_SIZE,
                result.begin() +
                    static_cast<std::ptrdiff_t>(format_magic.size()));
    encode_u64_le(plaintext_size,
                  result.data() + format_magic.size() + NONCE_SIZE);
    return result;
}

std::array<std::uint8_t, chunk_ad_size>
make_chunk_ad(const std::array<std::uint8_t, header_ad_size>& header,
              std::uint64_t chunk_index,
              std::uint64_t chunk_size) noexcept {
    std::array<std::uint8_t, chunk_ad_size> result{};
    std::copy(header.begin(), header.end(), result.begin());
    encode_u64_le(chunk_index, result.data() + header.size());
    encode_u64_le(chunk_size,
                  result.data() + header.size() + sizeof(chunk_index));
    return result;
}

void remove_partial_output(const std::filesystem::path& path) noexcept {
    std::error_code error;
    std::filesystem::remove(path, error);
}

void close_and_remove_partial_output(
    std::ofstream& output, const std::filesystem::path& path) noexcept {
    if (output.is_open()) {
        output.close();
    }

    remove_partial_output(path);
}

void wipe_encrypt_buffers(std::array<std::uint8_t, NONCE_SIZE>& base_nonce,
                          std::array<std::uint8_t, NONCE_SIZE>& chunk_nonce,
                          std::array<std::uint8_t, MAC_SIZE>& header_mac,
                          std::array<std::uint8_t, MAC_SIZE>& mac,
                          std::vector<std::uint8_t>& plain_buffer,
                          std::vector<std::uint8_t>& cipher_buffer) noexcept {
    crypto_wipe(base_nonce.data(), base_nonce.size());
    crypto_wipe(chunk_nonce.data(), chunk_nonce.size());
    crypto_wipe(header_mac.data(), header_mac.size());
    crypto_wipe(mac.data(), mac.size());
    if (!plain_buffer.empty()) {
        crypto_wipe(plain_buffer.data(), plain_buffer.size());
    }
    if (!cipher_buffer.empty()) {
        crypto_wipe(cipher_buffer.data(), cipher_buffer.size());
    }
}

void cleanup_encryption_failure(
    std::ofstream& output,
    const std::filesystem::path& path,
    std::array<std::uint8_t, NONCE_SIZE>& base_nonce,
    std::array<std::uint8_t, NONCE_SIZE>& chunk_nonce,
    std::array<std::uint8_t, MAC_SIZE>& header_mac,
    std::array<std::uint8_t, MAC_SIZE>& mac,
    std::vector<std::uint8_t>& plain_buffer,
    std::vector<std::uint8_t>& cipher_buffer) noexcept {
    close_and_remove_partial_output(output, path);
    wipe_encrypt_buffers(
        base_nonce, chunk_nonce, header_mac, mac, plain_buffer, cipher_buffer);
}

void derive_chunk_nonce(const std::uint8_t* base_nonce,
                        std::uint64_t chunk_index,
                        std::uint8_t* out_nonce) noexcept {
    std::copy_n(base_nonce, NONCE_SIZE, out_nonce);

    for (std::size_t index = 0; index < 8; ++index) {
        out_nonce[NONCE_SIZE - 1 - index] ^=
            static_cast<std::uint8_t>((chunk_index >> (index * 8)) & 0xFFU);
    }
}

void derive_header_nonce(const std::uint8_t* base_nonce,
                         std::uint8_t* out_nonce) noexcept {
    std::copy_n(base_nonce, NONCE_SIZE, out_nonce);
    out_nonce[0] ^= 0x80U;
}

void create_header_mac(std::uint8_t* mac,
                       const std::uint8_t* base_nonce,
                       std::span<const std::uint8_t, header_ad_size> header,
                       const std::uint8_t* key) noexcept {
    std::array<std::uint8_t, NONCE_SIZE> header_nonce{};
    derive_header_nonce(base_nonce, header_nonce.data());
    std::uint8_t empty = 0;
    crypto_aead_lock(&empty,
                     mac,
                     key,
                     header_nonce.data(),
                     header.data(),
                     header.size(),
                     &empty,
                     0);
    crypto_wipe(header_nonce.data(), header_nonce.size());
}

bool valid_header_mac(const std::uint8_t* mac,
                      const std::uint8_t* base_nonce,
                      std::span<const std::uint8_t, header_ad_size> header,
                      const std::uint8_t* key) noexcept {
    std::array<std::uint8_t, NONCE_SIZE> header_nonce{};
    derive_header_nonce(base_nonce, header_nonce.data());
    std::uint8_t empty = 0;
    return crypto_aead_unlock(&empty,
                              mac,
                              key,
                              header_nonce.data(),
                              header.data(),
                              header.size(),
                              &empty,
                              0) == 0;
}

bool encoded_size_matches(std::uint64_t plaintext_size,
                          std::uintmax_t input_size) noexcept {
    constexpr std::uint64_t maximum = std::numeric_limits<std::uint64_t>::max();
    const auto chunks = plaintext_size / CHUNK_SIZE +
                        (plaintext_size % CHUNK_SIZE != 0 ? 1 : 0);

    if (plaintext_size > maximum - header_size) {
        return false;
    }

    auto encoded_size = header_size + plaintext_size;
    if (chunks > (maximum - encoded_size) / MAC_SIZE) {
        return false;
    }

    encoded_size += chunks * MAC_SIZE;
    return input_size == encoded_size;
}

} // namespace

std::optional<EncryptionResult>
encrypt_file_with_key(const std::filesystem::path& input_path,
                      const std::filesystem::path& output_path,
                      const Key& key) {
    std::array<std::uint8_t, NONCE_SIZE> base_nonce{};
    std::array<std::uint8_t, NONCE_SIZE> chunk_nonce{};
    std::array<std::uint8_t, MAC_SIZE> header_mac{};
    std::array<std::uint8_t, MAC_SIZE> mac{};
    std::vector<std::uint8_t> plain_buffer;
    std::vector<std::uint8_t> cipher_buffer;

    try {
        remove_partial_output(output_path);

        std::ifstream input(input_path, std::ios::binary | std::ios::ate);
        if (!input) {
            return std::nullopt;
        }

        const auto end_position = input.tellg();
        if (end_position < std::streampos{0}) {
            return std::nullopt;
        }

        const auto stream_size = static_cast<std::streamoff>(end_position);
        if (stream_size < 0) {
            return std::nullopt;
        }
        const auto input_size = static_cast<std::uintmax_t>(stream_size);
        if (input_size > static_cast<std::uintmax_t>(
                             std::numeric_limits<std::uint64_t>::max())) {
            return std::nullopt;
        }
        const auto plaintext_size = static_cast<std::uint64_t>(input_size);

        input.seekg(0, std::ios::beg);
        if (!input) {
            return std::nullopt;
        }

        auto random_result = platform::random::fill_bytes(base_nonce);
        if (!random_result) {
            wipe_encrypt_buffers(base_nonce,
                                 chunk_nonce,
                                 header_mac,
                                 mac,
                                 plain_buffer,
                                 cipher_buffer);
            return std::nullopt;
        }

        const auto header = make_header_ad(base_nonce.data(), plaintext_size);
        create_header_mac(
            header_mac.data(), base_nonce.data(), header, key.data());

        plain_buffer.resize(CHUNK_SIZE);
        cipher_buffer.resize(CHUNK_SIZE);

        if (!platform::private_storage::create_file(output_path)) {
            wipe_encrypt_buffers(base_nonce,
                                 chunk_nonce,
                                 header_mac,
                                 mac,
                                 plain_buffer,
                                 cipher_buffer);
            return std::nullopt;
        }
        std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
        if (!output) {
            cleanup_encryption_failure(output,
                                       output_path,
                                       base_nonce,
                                       chunk_nonce,
                                       header_mac,
                                       mac,
                                       plain_buffer,
                                       cipher_buffer);
            return std::nullopt;
        }

        auto ciphertext_hash = physical::sha256_init();
        const auto write = [&](const auto* data, std::size_t size) {
            output.write(reinterpret_cast<const char*>(data),
                         static_cast<std::streamsize>(size));
            physical::sha256_update(
                ciphertext_hash,
                {reinterpret_cast<const std::uint8_t*>(data), size});
            return static_cast<bool>(output);
        };
        if (!write(header.data(), header.size()) ||
            !write(header_mac.data(), header_mac.size())) {
            cleanup_encryption_failure(output,
                                       output_path,
                                       base_nonce,
                                       chunk_nonce,
                                       header_mac,
                                       mac,
                                       plain_buffer,
                                       cipher_buffer);
            return std::nullopt;
        }

        blake3_hasher plaintext_hash;
        blake3_hasher_init(&plaintext_hash);
        std::uint64_t total_read = 0;
        std::uint64_t chunk_index = 0;
        while (total_read < plaintext_size) {
            const auto chunk_size =
                static_cast<std::size_t>(std::min<std::uint64_t>(
                    CHUNK_SIZE, plaintext_size - total_read));

            input.read(reinterpret_cast<char*>(plain_buffer.data()),
                       static_cast<std::streamsize>(chunk_size));
            if (input.gcount() != static_cast<std::streamsize>(chunk_size) ||
                input.bad()) {
                cleanup_encryption_failure(output,
                                           output_path,
                                           base_nonce,
                                           chunk_nonce,
                                           header_mac,
                                           mac,
                                           plain_buffer,
                                           cipher_buffer);
                return std::nullopt;
            }
            blake3_hasher_update(
                &plaintext_hash, plain_buffer.data(), chunk_size);

            derive_chunk_nonce(
                base_nonce.data(), chunk_index, chunk_nonce.data());
            const auto chunk_ad =
                make_chunk_ad(header, chunk_index, chunk_size);
            crypto_aead_lock(cipher_buffer.data(),
                             mac.data(),
                             key.data(),
                             chunk_nonce.data(),
                             chunk_ad.data(),
                             chunk_ad.size(),
                             plain_buffer.data(),
                             chunk_size);

            if (!write(mac.data(), mac.size()) ||
                !write(cipher_buffer.data(), chunk_size)) {
                cleanup_encryption_failure(output,
                                           output_path,
                                           base_nonce,
                                           chunk_nonce,
                                           header_mac,
                                           mac,
                                           plain_buffer,
                                           cipher_buffer);
                return std::nullopt;
            }

            total_read += chunk_size;
            ++chunk_index;
        }

        if (total_read != plaintext_size) {
            cleanup_encryption_failure(output,
                                       output_path,
                                       base_nonce,
                                       chunk_nonce,
                                       header_mac,
                                       mac,
                                       plain_buffer,
                                       cipher_buffer);
            return std::nullopt;
        }

        char trailing = 0;
        input.read(&trailing, 1);
        if (input.gcount() != 0 || input.bad()) {
            cleanup_encryption_failure(output,
                                       output_path,
                                       base_nonce,
                                       chunk_nonce,
                                       header_mac,
                                       mac,
                                       plain_buffer,
                                       cipher_buffer);
            return std::nullopt;
        }

        input.clear();
        input.close();
        if (input.fail()) {
            cleanup_encryption_failure(output,
                                       output_path,
                                       base_nonce,
                                       chunk_nonce,
                                       header_mac,
                                       mac,
                                       plain_buffer,
                                       cipher_buffer);
            return std::nullopt;
        }

        output.flush();
        if (!output) {
            cleanup_encryption_failure(output,
                                       output_path,
                                       base_nonce,
                                       chunk_nonce,
                                       header_mac,
                                       mac,
                                       plain_buffer,
                                       cipher_buffer);
            return std::nullopt;
        }

        output.close();
        if (output.fail()) {
            remove_partial_output(output_path);
            wipe_encrypt_buffers(base_nonce,
                                 chunk_nonce,
                                 header_mac,
                                 mac,
                                 plain_buffer,
                                 cipher_buffer);
            return std::nullopt;
        }

        EncryptionResult result{.plaintext_size = plaintext_size,
                                .ciphertext_sha256 =
                                    physical::sha256_finish(ciphertext_hash)};
        blake3_hasher_finalize(
            &plaintext_hash,
            reinterpret_cast<std::uint8_t*>(result.plaintext_hash.data()),
            result.plaintext_hash.size());
        wipe_encrypt_buffers(base_nonce,
                             chunk_nonce,
                             header_mac,
                             mac,
                             plain_buffer,
                             cipher_buffer);
        return result;
    } catch (...) {
        remove_partial_output(output_path);
        wipe_encrypt_buffers(base_nonce,
                             chunk_nonce,
                             header_mac,
                             mac,
                             plain_buffer,
                             cipher_buffer);
        return std::nullopt;
    }
}

std::optional<EncryptionResult>
encrypt_file_with_hashes(const std::filesystem::path& input_path,
                         const std::filesystem::path& output_path,
                         std::span<const std::uint8_t, KEY_SIZE> master_key,
                         FilePurpose purpose) {
    auto key =
        derive_key(master_key,
                   purpose == FilePurpose::Content ? KeyPurpose::Content
                                                   : KeyPurpose::History);
    auto result = encrypt_file_with_key(input_path, output_path, key);
    crypto_wipe(key.data(), key.size());
    return result;
}

bool encrypt_file(const std::filesystem::path& input_path,
                  const std::filesystem::path& output_path,
                  std::span<const std::uint8_t, KEY_SIZE> master_key,
                  FilePurpose purpose) {
    return encrypt_file_with_hashes(
               input_path, output_path, master_key, purpose)
        .has_value();
}

bool decrypt_file_with_key(const std::filesystem::path& input_path,
                           const std::filesystem::path& output_path,
                           const Key& key) {
    try {
        remove_partial_output(output_path);

        std::ifstream input(input_path, std::ios::binary | std::ios::ate);
        if (!input) {
            return false;
        }

        const auto end_position = input.tellg();
        if (end_position < std::streampos{0}) {
            return false;
        }

        const auto input_size = static_cast<std::uintmax_t>(
            static_cast<std::streamoff>(end_position));
        input.seekg(0, std::ios::beg);
        if (!input) {
            return false;
        }

        std::array<std::uint8_t, header_ad_size> header{};
        input.read(reinterpret_cast<char*>(header.data()),
                   static_cast<std::streamsize>(header.size()));
        if (input.gcount() != static_cast<std::streamsize>(header.size()) ||
            !std::equal(
                format_magic.begin(), format_magic.end(), header.begin())) {
            return false;
        }

        std::array<std::uint8_t, NONCE_SIZE> base_nonce{};
        std::copy_n(header.data() + format_magic.size(),
                    base_nonce.size(),
                    base_nonce.data());
        const auto expected_size =
            decode_u64_le(header.data() + format_magic.size() + NONCE_SIZE);

        std::array<std::uint8_t, MAC_SIZE> header_mac{};
        input.read(reinterpret_cast<char*>(header_mac.data()),
                   static_cast<std::streamsize>(header_mac.size()));
        if (input.gcount() != static_cast<std::streamsize>(header_mac.size()) ||
            !encoded_size_matches(expected_size, input_size) ||
            !valid_header_mac(
                header_mac.data(), base_nonce.data(), header, key.data())) {
            return false;
        }

        if (!platform::private_storage::create_file(output_path)) {
            crypto_wipe(base_nonce.data(), base_nonce.size());
            crypto_wipe(header_mac.data(), header_mac.size());
            return false;
        }
        std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
        if (!output) {
            close_and_remove_partial_output(output, output_path);
            return false;
        }

        std::vector<std::uint8_t> cipher_buffer(CHUNK_SIZE);
        std::vector<std::uint8_t> plain_buffer(CHUNK_SIZE);
        std::uint64_t chunk_index = 0;
        std::uint64_t total_decrypted = 0;

        while (total_decrypted < expected_size) {
            const auto chunk_size =
                static_cast<std::size_t>(std::min<std::uint64_t>(
                    CHUNK_SIZE, expected_size - total_decrypted));

            std::array<std::uint8_t, MAC_SIZE> mac{};
            input.read(reinterpret_cast<char*>(mac.data()),
                       static_cast<std::streamsize>(mac.size()));
            if (input.gcount() != static_cast<std::streamsize>(mac.size())) {
                close_and_remove_partial_output(output, output_path);
                return false;
            }

            input.read(reinterpret_cast<char*>(cipher_buffer.data()),
                       static_cast<std::streamsize>(chunk_size));
            if (input.gcount() != static_cast<std::streamsize>(chunk_size)) {
                close_and_remove_partial_output(output, output_path);
                return false;
            }

            std::array<std::uint8_t, NONCE_SIZE> chunk_nonce{};
            derive_chunk_nonce(
                base_nonce.data(), chunk_index, chunk_nonce.data());
            const auto chunk_ad =
                make_chunk_ad(header, chunk_index, chunk_size);

            if (crypto_aead_unlock(plain_buffer.data(),
                                   mac.data(),
                                   key.data(),
                                   chunk_nonce.data(),
                                   chunk_ad.data(),
                                   chunk_ad.size(),
                                   cipher_buffer.data(),
                                   chunk_size) != 0) {
                close_and_remove_partial_output(output, output_path);
                return false;
            }

            output.write(reinterpret_cast<const char*>(plain_buffer.data()),
                         static_cast<std::streamsize>(chunk_size));
            if (!output) {
                close_and_remove_partial_output(output, output_path);
                return false;
            }

            total_decrypted += chunk_size;
            ++chunk_index;
        }

        char trailing = 0;
        input.read(&trailing, 1);
        if (input.gcount() != 0 || input.bad()) {
            close_and_remove_partial_output(output, output_path);
            return false;
        }

        input.clear();
        input.close();
        if (input.fail()) {
            close_and_remove_partial_output(output, output_path);
            return false;
        }

        output.flush();
        if (!output) {
            close_and_remove_partial_output(output, output_path);
            return false;
        }

        output.close();
        if (output.fail()) {
            remove_partial_output(output_path);
            return false;
        }

        return true;
    } catch (...) {
        remove_partial_output(output_path);
        return false;
    }
}

bool decrypt_file(const std::filesystem::path& input_path,
                  const std::filesystem::path& output_path,
                  std::span<const std::uint8_t, KEY_SIZE> master_key,
                  FilePurpose purpose) {
    auto key =
        derive_key(master_key,
                   purpose == FilePurpose::Content ? KeyPurpose::Content
                                                   : KeyPurpose::History);
    const auto result = decrypt_file_with_key(input_path, output_path, key);
    crypto_wipe(key.data(), key.size());
    return result;
}

} // namespace kasumi::crypto
