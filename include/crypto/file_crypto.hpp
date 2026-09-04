#ifndef KASUMI_CRYPTO_FILE_CRYPTO_HPP
#define KASUMI_CRYPTO_FILE_CRYPTO_HPP

#include "core/hasher.hpp"
#include "crypto/key_derivation.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>

namespace kasumi::crypto {

// Maximum size of each authenticated chunk.
inline constexpr std::size_t CHUNK_SIZE = 4U * 1024U * 1024U;

// Fixed key, nonce, and MAC sizes for the encrypted format.
inline constexpr std::size_t NONCE_SIZE = 24;
inline constexpr std::size_t MAC_SIZE = 16;
inline constexpr std::size_t FILE_MAGIC_SIZE = 8;
inline constexpr std::size_t FILE_HEADER_SIZE =
    FILE_MAGIC_SIZE + NONCE_SIZE + sizeof(std::uint64_t) + MAC_SIZE;

enum class FilePurpose {
    Content,
    History,
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

// Encrypts and computes hashes; removes partial output on failure.
std::optional<EncryptionResult>
encrypt_file_with_hashes(const std::filesystem::path& input_path,
                         const std::filesystem::path& output_path,
                         std::span<const std::uint8_t, KEY_SIZE> master_key,
                         FilePurpose purpose = FilePurpose::Content);

// Encrypts with chunk-level authentication; removes partial output on failure.
bool encrypt_file(const std::filesystem::path& input_path,
                  const std::filesystem::path& output_path,
                  std::span<const std::uint8_t, KEY_SIZE> master_key,
                  FilePurpose purpose = FilePurpose::Content);

// Authenticates and decrypts the file; removes partial output on failure.
bool decrypt_file(const std::filesystem::path& input_path,
                  const std::filesystem::path& output_path,
                  std::span<const std::uint8_t, KEY_SIZE> master_key,
                  FilePurpose purpose = FilePurpose::Content);

} // namespace kasumi::crypto

#endif
