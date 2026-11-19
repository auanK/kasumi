#ifndef KASUMI_CRYPTO_PACK_HPP
#define KASUMI_CRYPTO_PACK_HPP

#include "core/hasher.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/key_derivation.hpp"
#include "crypto/secure_memory.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace kasumi::crypto::pack {

inline constexpr std::uint64_t MAX_MICRO_PACK_BLOB_SIZE = 256ULL * 1024ULL;
inline constexpr std::uint64_t TARGET_MICRO_PACK_SIZE = 4ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t FASTCDC_FILE_THRESHOLD = 8ULL * 1024ULL * 1024ULL;
inline constexpr std::uint32_t FASTCDC_MIN_CHUNK = 256U * 1024U;
inline constexpr std::uint32_t FASTCDC_AVG_CHUNK = 1U * 1024U * 1024U;
inline constexpr std::uint32_t FASTCDC_MAX_CHUNK = 32U * 1024U * 1024U;
inline constexpr std::uint64_t FASTCDC_TIER2_THRESHOLD =
    64ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t FASTCDC_TIER3_THRESHOLD =
    512ULL * 1024ULL * 1024ULL;
inline constexpr std::size_t MAXIMUM_PACK_MEMBERS = 65536U;
inline constexpr std::uint64_t MAXIMUM_PACK_PLAINTEXT_SIZE =
    16ULL * 1024ULL * 1024ULL;

struct FastCdcProfile {
    std::uint32_t min_chunk = FASTCDC_MIN_CHUNK;
    std::uint32_t avg_chunk = FASTCDC_AVG_CHUNK;
    std::uint32_t max_chunk = 4U * 1024U * 1024U;
    std::uint64_t mask_s = 0xFFFFF80000000000ULL;
    std::uint64_t mask_l = 0xFFFFE00000000000ULL;

    bool operator==(const FastCdcProfile&) const noexcept = default;
};

// Selects normalized Gear FastCDC chunk parameters for a file size:
//   <= 64 MiB  : 256 KiB -  4 MiB ( 1 MiB avg)
//   <= 512 MiB :   1 MiB - 16 MiB ( 4 MiB avg)
//    > 512 MiB :   4 MiB - 32 MiB (16 MiB avg)
[[nodiscard]] constexpr FastCdcProfile
fastcdc_profile_for_size(std::uint64_t file_size) noexcept {
    constexpr auto top_bits = [](unsigned bits) constexpr noexcept {
        return ~std::uint64_t{0} << (64U - bits);
    };
    if (file_size > FASTCDC_TIER3_THRESHOLD) {
        return FastCdcProfile{
            .min_chunk = 4U * 1024U * 1024U,
            .avg_chunk = 16U * 1024U * 1024U,
            .max_chunk = 32U * 1024U * 1024U,
            .mask_s = top_bits(25U),
            .mask_l = top_bits(23U),
        };
    }
    if (file_size > FASTCDC_TIER2_THRESHOLD) {
        return FastCdcProfile{
            .min_chunk = 1U * 1024U * 1024U,
            .avg_chunk = 4U * 1024U * 1024U,
            .max_chunk = 16U * 1024U * 1024U,
            .mask_s = top_bits(23U),
            .mask_l = top_bits(21U),
        };
    }
    return FastCdcProfile{};
}

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

// Authenticated KPAK v1 pack payload held in memory for direct installation.
struct VerifiedPackSlice {
    std::size_t offset = 0;
    std::uint32_t size = 0;
};

struct VerifiedPack {
    Hash pack_hash{};
    std::vector<PackMemberDescriptor> members;
    std::vector<std::uint8_t> plaintext;
    std::vector<VerifiedPackSlice> slices;

    VerifiedPack() = default;
    VerifiedPack(const VerifiedPack&) = delete;
    VerifiedPack& operator=(const VerifiedPack&) = delete;
    VerifiedPack(VerifiedPack&&) noexcept = default;
    VerifiedPack& operator=(VerifiedPack&& other) noexcept {
        if (this != &other) {
            wipe();
            pack_hash = other.pack_hash;
            members = std::move(other.members);
            plaintext = std::move(other.plaintext);
            slices = std::move(other.slices);
        }
        return *this;
    }
    ~VerifiedPack() noexcept {
        wipe();
    }

    [[nodiscard]] std::optional<std::span<const std::uint8_t>>
    member_bytes(const Hash& member_hash) const noexcept {
        const auto it = std::ranges::lower_bound(
            members, member_hash, {}, &PackMemberDescriptor::hash);
        if (it == members.end() || it->hash != member_hash) {
            return std::nullopt;
        }
        const auto index = static_cast<std::size_t>(it - members.begin());
        if (index >= slices.size() ||
            slices[index].offset > plaintext.size() ||
            slices[index].size > plaintext.size() - slices[index].offset) {
            return std::nullopt;
        }
        return std::span<const std::uint8_t>{
            plaintext.data() + slices[index].offset, slices[index].size};
    }

private:
    void wipe() noexcept {
        if (!plaintext.empty()) {
            secure_memory::wipe(plaintext.data(), plaintext.size());
        }
    }
};

// Decrypts and authenticates a KPAK v1 object in memory, verifying pack_hash
// and every member's BLAKE3 digest.
std::expected<VerifiedPack, std::string>
load_verified_pack(const std::filesystem::path& encrypted_path,
                   std::span<const std::uint8_t, KEY_SIZE> master_key,
                   std::optional<Hash> expected_pack_hash);

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

std::expected<FastCdcResult, std::string>
chunk_file_fastcdc(const std::filesystem::path& path, FastCdcProfile profile);

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
