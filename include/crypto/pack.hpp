#ifndef KASUMI_CRYPTO_PACK_HPP
#define KASUMI_CRYPTO_PACK_HPP

#include "core/hasher.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/key_derivation.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace kasumi::crypto::pack {

inline constexpr std::uint64_t MAX_MICRO_PACK_BLOB_SIZE = 256ULL * 1024ULL;
inline constexpr std::uint64_t TARGET_MICRO_PACK_SIZE = 4ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t FASTCDC_FILE_THRESHOLD = 8ULL * 1024ULL * 1024ULL;
inline constexpr std::uint32_t FASTCDC_MIN_CHUNK = 256U * 1024U;
inline constexpr std::uint32_t FASTCDC_AVG_CHUNK = 1U * 1024U * 1024U;
inline constexpr std::uint32_t FASTCDC_MAX_CHUNK = 4U * 1024U * 1024U;
inline constexpr std::size_t MAXIMUM_PACK_MEMBERS = 65536U;
inline constexpr std::uint64_t MAXIMUM_PACK_PLAINTEXT_SIZE =
    16ULL * 1024ULL * 1024ULL;

// Metadata for a single blob stored inside a KPAK v1 Micro-Pack.
struct PackMemberDescriptor {
    Hash hash{};
    std::uint32_t size = 0;

    bool operator==(const PackMemberDescriptor&) const noexcept = default;
};

// Local source file bound to an expected member hash and byte count.
struct PackMemberSource {
    Hash hash{};
    std::uint32_t size = 0;
    std::filesystem::path source_path;
};

// Result of packing and encrypting a Micro-Pack object.
struct PackEncryptionResult {
    Hash pack_hash{};
    std::uint64_t pack_plaintext_size = 0;
    std::string ciphertext_sha256;
};

// Content-defined slice produced by FastCDC chunking.
struct FastCdcChunk {
    Hash hash{};
    std::uint64_t offset = 0;
    std::uint32_t size = 0;

    bool operator==(const FastCdcChunk&) const noexcept = default;
};

// Whole-file hash, byte size, and ordered FastCDC chunks.
struct FastCdcResult {
    Hash file_hash{};
    std::uint64_t file_size = 0;
    std::vector<FastCdcChunk> chunks;
};

// Computes canonical pack hash from strictly sorted unique member descriptors.
std::optional<Hash>
compute_pack_hash(std::span<const PackMemberDescriptor> sorted_members) noexcept;

// Bundles, verifies, encrypts (KPAK v1 + FilePurpose::Pack), and hashes a pack.
std::expected<PackEncryptionResult, std::string>
write_encrypted_pack(std::span<const PackMemberSource> members,
                     const std::filesystem::path& output_path,
                     std::span<const std::uint8_t, KEY_SIZE> master_key);

// Decrypts and authenticates a KPAK v1 object, verifying pack_hash and every
// member's BLAKE3 digest; optionally writes <hash_hex>.plain to extract_dir.
std::expected<std::vector<PackMemberDescriptor>, std::string>
decrypt_and_verify_pack(const std::filesystem::path& encrypted_path,
                        std::span<const std::uint8_t, KEY_SIZE> master_key,
                        std::optional<Hash> expected_pack_hash,
                        const std::filesystem::path* extract_dir = nullptr,
                        Hash* out_pack_hash = nullptr);

// Splits a regular non-symlink file into deterministic FastCDC chunks in one pass.
std::expected<FastCdcResult, std::string>
chunk_file_fastcdc(const std::filesystem::path& path);

// Encrypts a verified file slice [offset, offset + length) using FilePurpose::Content.
std::optional<EncryptionResult>
encrypt_file_slice_with_hashes(const std::filesystem::path& input_path,
                               std::uint64_t offset,
                               std::uint32_t length,
                               const Hash& expected_slice_hash,
                               const std::filesystem::path& output_path,
                               std::span<const std::uint8_t, KEY_SIZE> master_key,
                               std::string* error_detail = nullptr);

} // namespace kasumi::crypto::pack

#endif
