#ifndef KASUMI_APPLICATION_INTEGRITY_FSCK_CHECKPOINT_HPP
#define KASUMI_APPLICATION_INTEGRITY_FSCK_CHECKPOINT_HPP

#include "crypto/file_crypto.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::application::integrity {

inline constexpr std::string_view fsck_checkpoint_file_name = "fsck_checkpoint.bin.enc";
inline constexpr std::array<std::uint8_t, 8> checkpoint_magic{'K', 'A', 'S', 'U', 'M', 'I', 'C', 'K'};
inline constexpr std::uint32_t checkpoint_format_version_1 = 1;
inline constexpr std::uint32_t checkpoint_audit_semantics_version_1 = 1;
inline constexpr std::uint64_t max_checkpoint_payload_size = 64ULL * 1024ULL * 1024ULL;
inline constexpr std::uint64_t max_checkpoint_entries = 1'000'000ULL;

struct VerifiedObjectEntry {
    std::string logical_content_hash;
    std::string remote_content_id;
    std::uint64_t plaintext_size = 0;
    std::string physical_ciphertext_sha256;

    bool operator==(const VerifiedObjectEntry&) const = default;
    auto operator<=>(const VerifiedObjectEntry&) const = default;
};

struct CheckpointHeader {
    std::uint32_t format_version = checkpoint_format_version_1;
    std::uint32_t audit_semantics_version = checkpoint_audit_semantics_version_1;
    std::string vault_id;
    std::uint64_t entry_count = 0;

    bool operator==(const CheckpointHeader&) const = default;
};

struct FsckCheckpoint {
    CheckpointHeader header;
    std::vector<VerifiedObjectEntry> entries;

    bool operator==(const FsckCheckpoint&) const = default;
};

// Pure serialization of the inner payload.
std::expected<std::vector<std::uint8_t>, std::string>
encode_checkpoint_payload(const FsckCheckpoint& checkpoint);

// Pure deserialization of the inner payload.
std::expected<FsckCheckpoint, std::string>
decode_checkpoint_payload(std::span<const std::uint8_t> bytes,
                          const CheckpointHeader& header);

// Encrypts and wraps in authenticated envelope.
std::expected<std::vector<std::uint8_t>, std::string>
encrypt_checkpoint(const FsckCheckpoint& checkpoint,
                   std::span<const std::uint8_t, crypto::KEY_SIZE> master_key);

// Decrypts authenticated envelope and decodes checkpoint.
std::expected<FsckCheckpoint, std::string>
decrypt_checkpoint(std::span<const std::uint8_t> envelope_bytes,
                   std::span<const std::uint8_t, crypto::KEY_SIZE> master_key);

// Computes the checkpoint path for a profile directory.
std::filesystem::path
checkpoint_path(const std::filesystem::path& profile_directory);

// Crash-safe atomic save.
std::expected<void, std::string>
save_checkpoint(const std::filesystem::path& profile_directory,
                const FsckCheckpoint& checkpoint,
                std::span<const std::uint8_t, crypto::KEY_SIZE> master_key);

// Loads checkpoint if present; returns std::nullopt if absent.
// Fails closed on any corruption, auth failure, or version mismatch.
std::expected<std::optional<FsckCheckpoint>, std::string>
load_checkpoint(const std::filesystem::path& profile_directory,
                std::span<const std::uint8_t, crypto::KEY_SIZE> master_key);

} // namespace kasumi::application::integrity

#endif
