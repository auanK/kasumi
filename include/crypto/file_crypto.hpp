#ifndef KASUMI_CRYPTO_FILE_CRYPTO_HPP
#define KASUMI_CRYPTO_FILE_CRYPTO_HPP

#include "core/hasher.hpp"
#include "crypto/key_derivation.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace kasumi::crypto {

// Maximum plaintext size of each authenticated chunk in Protocol v3 (1 MiB).
inline constexpr std::size_t CHUNK_SIZE = 1U * 1024U * 1024U;

// Fixed key, nonce, prefix, and MAC sizes for the encrypted format.
inline constexpr std::size_t NONCE_SIZE = 24;
inline constexpr std::size_t MAC_SIZE = 16;
inline constexpr std::size_t CHUNK_PREFIX_SIZE = 5;
inline constexpr std::size_t FILE_MAGIC_SIZE = 8;
inline constexpr std::size_t FILE_HEADER_SIZE =
    FILE_MAGIC_SIZE + 1 + NONCE_SIZE + sizeof(std::uint64_t) + MAC_SIZE;

enum class FilePurpose : std::uint8_t {
    Content = 0,
    History = 1,
    Pack = 2,
};

// Metadata computed during file encryption.
struct EncryptionResult {
    // BLAKE3 hash of the original plaintext content.
    Hash plaintext_hash{};
    // Original plaintext size in bytes.
    std::uint64_t plaintext_size = 0;
    // Hexadecimal SHA-256 of the encrypted file.
    std::string ciphertext_sha256;
};

// Upper-bound encoded size (header + uncompressed chunk framing and MACs);
// rejects overflow. Compressed chunks are smaller than this bound.
std::optional<std::uint64_t>
encoded_file_size(std::uint64_t plaintext_size) noexcept;

// Encrypts and authenticates an in-memory buffer using KASUMI v3 framing.
std::optional<std::vector<std::uint8_t>>
encrypt_bytes(std::span<const std::uint8_t> plaintext,
              std::span<const std::uint8_t, KEY_SIZE> master_key,
              FilePurpose purpose = FilePurpose::Content);

// Authenticates and decrypts an in-memory buffer (v3 or legacy v2).
std::optional<std::vector<std::uint8_t>>
decrypt_bytes(std::span<const std::uint8_t> ciphertext,
              std::span<const std::uint8_t, KEY_SIZE> master_key,
              FilePurpose purpose = FilePurpose::Content);

// Encrypts and computes hashes; removes partial output on failure.
std::optional<EncryptionResult>
encrypt_file_with_hashes(const std::filesystem::path& input_path,
                         const std::filesystem::path& output_path,
                         std::span<const std::uint8_t, KEY_SIZE> master_key,
                         FilePurpose purpose = FilePurpose::Content,
                         std::string* error_detail = nullptr);

// Streams and encrypts a [offset, offset + length) file slice using KASUMI v3
// framing, verifying its plaintext BLAKE3 before publishing output_path.
std::optional<EncryptionResult>
encrypt_file_slice(const std::filesystem::path& input_path,
                   std::uint64_t offset,
                   std::uint64_t length,
                   const Hash& expected_slice_hash,
                   const std::filesystem::path& output_path,
                   std::span<const std::uint8_t, KEY_SIZE> master_key,
                   FilePurpose purpose = FilePurpose::Content,
                   std::string* error_detail = nullptr);

// Encrypts with chunk-level authentication; removes partial output on failure.
bool encrypt_file(const std::filesystem::path& input_path,
                  const std::filesystem::path& output_path,
                  std::span<const std::uint8_t, KEY_SIZE> master_key,
                  FilePurpose purpose = FilePurpose::Content);

using DecryptedSink = std::function<bool(std::span<const std::uint8_t>)>;

// Authenticates and decrypts the file; removes partial output on failure.
bool decrypt_file(const std::filesystem::path& input_path,
                  const std::filesystem::path& output_path,
                  std::span<const std::uint8_t, KEY_SIZE> master_key,
                  FilePurpose purpose = FilePurpose::Content);

// Streams and authenticates a KASUMI v3 encrypted regular file directly into
// sink without creating a plaintext scratch file; verifies optional size and
// BLAKE3 digest when supplied.
bool decrypt_file_to_sink(
    const std::filesystem::path& input_path,
    std::span<const std::uint8_t, KEY_SIZE> master_key,
    const DecryptedSink& sink,
    FilePurpose purpose = FilePurpose::Content,
    std::optional<std::uint64_t> expected_plaintext_size = std::nullopt,
    const Hash* expected_plaintext_hash = nullptr);

} // namespace kasumi::crypto

#endif
