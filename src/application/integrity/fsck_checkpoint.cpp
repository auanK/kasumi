#include "application/integrity/fsck_checkpoint.hpp"

#include "crypto/key_derivation.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <monocypher.h>
#include <unordered_set>

namespace kasumi::application::integrity {

namespace {

void encode_u32_le(std::uint32_t value, std::uint8_t* output) noexcept {
    for (std::size_t i = 0; i < sizeof(value); ++i) {
        output[i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xffU);
    }
}

std::uint32_t decode_u32_le(const std::uint8_t* input) noexcept {
    std::uint32_t value = 0;
    for (std::size_t i = 0; i < sizeof(value); ++i) {
        value |= static_cast<std::uint32_t>(input[i]) << (i * 8);
    }
    return value;
}

void encode_u64_le(std::uint64_t value, std::uint8_t* output) noexcept {
    for (std::size_t i = 0; i < sizeof(value); ++i) {
        output[i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xffU);
    }
}

std::uint64_t decode_u64_le(const std::uint8_t* input) noexcept {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < sizeof(value); ++i) {
        value |= static_cast<std::uint64_t>(input[i]) << (i * 8);
    }
    return value;
}

} // namespace

std::expected<std::vector<std::uint8_t>, std::string>
encode_checkpoint_payload(const FsckCheckpoint& checkpoint) {
    if (checkpoint.entries.size() > max_checkpoint_entries) {
        return std::unexpected("checkpoint entry count exceeds maximum limit");
    }

    std::vector<VerifiedObjectEntry> sorted_entries = checkpoint.entries;
    std::ranges::sort(sorted_entries);

    // Verify no duplicates
    std::unordered_set<std::string> seen_hashes;
    seen_hashes.reserve(sorted_entries.size());
    for (const auto& entry : sorted_entries) {
        if (!seen_hashes.insert(entry.logical_content_hash).second) {
            return std::unexpected("duplicate entry for logical content hash: " +
                                   entry.logical_content_hash);
        }
    }

    std::vector<std::uint8_t> buffer;
    buffer.reserve(8 + sorted_entries.size() * 128);

    const auto start_pos = buffer.size();
    buffer.resize(start_pos + 8);
    encode_u64_le(sorted_entries.size(), buffer.data() + start_pos);

    for (const auto& entry : sorted_entries) {
        if (entry.logical_content_hash.empty() || entry.logical_content_hash.size() > 256) {
            return std::unexpected("invalid logical content hash size in checkpoint entry");
        }
        if (entry.remote_content_id.empty() || entry.remote_content_id.size() > 1024) {
            return std::unexpected("invalid remote content id size in checkpoint entry");
        }
        if (entry.physical_ciphertext_sha256.empty() || entry.physical_ciphertext_sha256.size() > 256) {
            return std::unexpected("invalid physical ciphertext sha256 size in checkpoint entry");
        }

        const auto offset = buffer.size();
        const auto entry_wire_size =
            4 + entry.logical_content_hash.size() +
            4 + entry.remote_content_id.size() +
            8 +
            4 + entry.physical_ciphertext_sha256.size();
        buffer.resize(offset + entry_wire_size);

        auto* ptr = buffer.data() + offset;

        encode_u32_le(static_cast<std::uint32_t>(entry.logical_content_hash.size()), ptr);
        ptr += 4;
        std::copy(entry.logical_content_hash.begin(), entry.logical_content_hash.end(), ptr);
        ptr += entry.logical_content_hash.size();

        encode_u32_le(static_cast<std::uint32_t>(entry.remote_content_id.size()), ptr);
        ptr += 4;
        std::copy(entry.remote_content_id.begin(), entry.remote_content_id.end(), ptr);
        ptr += entry.remote_content_id.size();

        encode_u64_le(entry.plaintext_size, ptr);
        ptr += 8;

        encode_u32_le(static_cast<std::uint32_t>(entry.physical_ciphertext_sha256.size()), ptr);
        ptr += 4;
        std::copy(entry.physical_ciphertext_sha256.begin(), entry.physical_ciphertext_sha256.end(), ptr);
    }

    if (buffer.size() > max_checkpoint_payload_size) {
        return std::unexpected("serialized checkpoint exceeds maximum payload size");
    }

    return buffer;
}

std::expected<FsckCheckpoint, std::string>
decode_checkpoint_payload(std::span<const std::uint8_t> bytes,
                          const CheckpointHeader& header) {
    if (bytes.size() < 8) {
        return std::unexpected("checkpoint payload truncated: missing entry count");
    }

    const auto count = decode_u64_le(bytes.data());
    if (count > max_checkpoint_entries) {
        return std::unexpected("checkpoint entry count exceeds maximum limit");
    }

    // Minimum wire size per entry is 4 + 4 + 8 + 4 = 20 bytes
    if (bytes.size() - 8 < count * 20) {
        return std::unexpected("checkpoint payload truncated for specified entry count");
    }

    FsckCheckpoint checkpoint{.header = header};
    checkpoint.header.entry_count = count;
    checkpoint.entries.reserve(static_cast<std::size_t>(count));

    std::size_t offset = 8;
    std::unordered_set<std::string> seen_hashes;
    seen_hashes.reserve(static_cast<std::size_t>(count));

    for (std::uint64_t i = 0; i < count; ++i) {
        if (offset + 4 > bytes.size()) {
            return std::unexpected("checkpoint payload truncated before logical hash length");
        }
        const auto hash_len = decode_u32_le(bytes.data() + offset);
        offset += 4;
        if (hash_len == 0 || hash_len > 256 || offset + hash_len > bytes.size()) {
            return std::unexpected("invalid or truncated logical content hash");
        }
        std::string logical_hash(reinterpret_cast<const char*>(bytes.data() + offset), hash_len);
        offset += hash_len;

        if (offset + 4 > bytes.size()) {
            return std::unexpected("checkpoint payload truncated before remote id length");
        }
        const auto remote_id_len = decode_u32_le(bytes.data() + offset);
        offset += 4;
        if (remote_id_len == 0 || remote_id_len > 1024 || offset + remote_id_len > bytes.size()) {
            return std::unexpected("invalid or truncated remote content id");
        }
        std::string remote_content_id(reinterpret_cast<const char*>(bytes.data() + offset), remote_id_len);
        offset += remote_id_len;

        if (offset + 8 > bytes.size()) {
            return std::unexpected("checkpoint payload truncated before plaintext size");
        }
        const auto plaintext_size = decode_u64_le(bytes.data() + offset);
        offset += 8;

        if (offset + 4 > bytes.size()) {
            return std::unexpected("checkpoint payload truncated before physical sha256 length");
        }
        const auto sha256_len = decode_u32_le(bytes.data() + offset);
        offset += 4;
        if (sha256_len == 0 || sha256_len > 256 || offset + sha256_len > bytes.size()) {
            return std::unexpected("invalid or truncated physical ciphertext sha256");
        }
        std::string physical_sha256(reinterpret_cast<const char*>(bytes.data() + offset), sha256_len);
        offset += sha256_len;

        if (!seen_hashes.insert(logical_hash).second) {
            return std::unexpected("duplicate entry for logical content hash: " + logical_hash);
        }

        checkpoint.entries.push_back(VerifiedObjectEntry{
            .logical_content_hash = std::move(logical_hash),
            .remote_content_id = std::move(remote_content_id),
            .plaintext_size = plaintext_size,
            .physical_ciphertext_sha256 = std::move(physical_sha256),
        });
    }

    if (offset != bytes.size()) {
        return std::unexpected("unexpected trailing bytes in checkpoint payload");
    }

    std::ranges::sort(checkpoint.entries);
    return checkpoint;
}

std::expected<std::vector<std::uint8_t>, std::string>
encrypt_checkpoint(const FsckCheckpoint& checkpoint,
                   std::span<const std::uint8_t, crypto::KEY_SIZE> master_key) {
    if (checkpoint.header.format_version != checkpoint_format_version_1) {
        return std::unexpected("unsupported checkpoint format version for encryption");
    }
    if (checkpoint.header.audit_semantics_version != checkpoint_audit_semantics_version_1) {
        return std::unexpected("unsupported audit semantics version for encryption");
    }
    if (checkpoint.header.vault_id.empty() || checkpoint.header.vault_id.size() > 1024) {
        return std::unexpected("invalid vault id in checkpoint header");
    }

    auto encoded_payload = encode_checkpoint_payload(checkpoint);
    if (!encoded_payload) {
        return std::unexpected(encoded_payload.error());
    }

    const auto payload_size = encoded_payload->size();
    if (payload_size > max_checkpoint_payload_size) {
        crypto_wipe(encoded_payload->data(), encoded_payload->size());
        return std::unexpected("checkpoint payload exceeds maximum supported limit");
    }

    // Envelope header:
    // magic (8) + format_version (4) + audit_semantics_version (4) + vault_id_len (4) + vault_id (N) + payload_size (8)
    const auto vault_id_len = static_cast<std::uint32_t>(checkpoint.header.vault_id.size());
    const std::size_t aad_size = 8 + 4 + 4 + 4 + vault_id_len + 8;
    const std::size_t total_header_size = aad_size + crypto::NONCE_SIZE + crypto::MAC_SIZE;
    const std::size_t total_size = total_header_size + payload_size;

    std::vector<std::uint8_t> envelope(total_size);

    // Build AAD
    auto* ptr = envelope.data();
    std::copy(checkpoint_magic.begin(), checkpoint_magic.end(), ptr);
    ptr += 8;

    encode_u32_le(checkpoint.header.format_version, ptr);
    ptr += 4;

    encode_u32_le(checkpoint.header.audit_semantics_version, ptr);
    ptr += 4;

    encode_u32_le(vault_id_len, ptr);
    ptr += 4;

    std::copy(checkpoint.header.vault_id.begin(), checkpoint.header.vault_id.end(), ptr);
    ptr += vault_id_len;

    encode_u64_le(payload_size, ptr);
    ptr += 8;

    // Nonce
    std::array<std::uint8_t, crypto::NONCE_SIZE> nonce{};
    auto random_result = platform::random::fill_bytes(nonce);
    if (!random_result) {
        crypto_wipe(encoded_payload->data(), encoded_payload->size());
        return std::unexpected(random_result.error());
    }
    std::copy(nonce.begin(), nonce.end(), ptr);
    ptr += crypto::NONCE_SIZE;

    // MAC placeholder at ptr
    auto* mac_ptr = ptr;
    ptr += crypto::MAC_SIZE;

    // Derive dedicated subkey
    auto subkey = crypto::derive_key(master_key, crypto::KeyPurpose::FsckCheckpoint);

    // Encrypt
    crypto_aead_lock(ptr,
                     mac_ptr,
                     subkey.data(),
                     nonce.data(),
                     envelope.data(),
                     aad_size,
                     encoded_payload->data(),
                     payload_size);

    // Wipe sensitive materials
    crypto_wipe(subkey.data(), subkey.size());
    crypto_wipe(encoded_payload->data(), encoded_payload->size());

    return envelope;
}

std::expected<FsckCheckpoint, std::string>
decrypt_checkpoint(std::span<const std::uint8_t> envelope_bytes,
                   std::span<const std::uint8_t, crypto::KEY_SIZE> master_key) {
    // Minimum header size: 28 + vault_id_len + 40
    if (envelope_bytes.size() < 28 + 40) {
        return std::unexpected("checkpoint envelope truncated: header too small");
    }

    if (!std::equal(checkpoint_magic.begin(), checkpoint_magic.end(), envelope_bytes.begin())) {
        return std::unexpected("invalid checkpoint magic");
    }

    const auto format_version = decode_u32_le(envelope_bytes.data() + 8);
    if (format_version != checkpoint_format_version_1) {
        return std::unexpected("unsupported checkpoint format version: " + std::to_string(format_version));
    }

    const auto audit_semantics_version = decode_u32_le(envelope_bytes.data() + 12);
    if (audit_semantics_version != checkpoint_audit_semantics_version_1) {
        return std::unexpected("unsupported audit semantics version: " + std::to_string(audit_semantics_version));
    }

    const auto vault_id_len = decode_u32_le(envelope_bytes.data() + 16);
    if (vault_id_len == 0 || vault_id_len > 1024) {
        return std::unexpected("invalid checkpoint vault id length");
    }

    const std::size_t aad_size = 28 + vault_id_len;
    const std::size_t total_header_size = aad_size + crypto::NONCE_SIZE + crypto::MAC_SIZE;
    if (envelope_bytes.size() < total_header_size) {
        return std::unexpected("checkpoint envelope truncated: header incomplete");
    }

    std::string vault_id(reinterpret_cast<const char*>(envelope_bytes.data() + 20), vault_id_len);

    const auto payload_size = decode_u64_le(envelope_bytes.data() + 20 + vault_id_len);
    if (payload_size > max_checkpoint_payload_size) {
        return std::unexpected("oversized checkpoint payload in header");
    }

    if (envelope_bytes.size() != total_header_size + payload_size) {
        return std::unexpected("checkpoint envelope size does not match expected payload size");
    }

    const auto* nonce_ptr = envelope_bytes.data() + aad_size;
    const auto* mac_ptr = nonce_ptr + crypto::NONCE_SIZE;
    const auto* ciphertext_ptr = mac_ptr + crypto::MAC_SIZE;

    std::vector<std::uint8_t> plaintext(static_cast<std::size_t>(payload_size));
    auto subkey = crypto::derive_key(master_key, crypto::KeyPurpose::FsckCheckpoint);

    const int unlock_result = crypto_aead_unlock(
        plaintext.data(),
        mac_ptr,
        subkey.data(),
        nonce_ptr,
        envelope_bytes.data(),
        aad_size,
        ciphertext_ptr,
        static_cast<std::size_t>(payload_size));

    crypto_wipe(subkey.data(), subkey.size());

    if (unlock_result != 0) {
        crypto_wipe(plaintext.data(), plaintext.size());
        return std::unexpected("checkpoint authentication failed");
    }

    CheckpointHeader header{
        .format_version = format_version,
        .audit_semantics_version = audit_semantics_version,
        .vault_id = std::move(vault_id),
        .entry_count = 0,
    };

    auto decoded = decode_checkpoint_payload(plaintext, header);
    crypto_wipe(plaintext.data(), plaintext.size());

    if (!decoded) {
        return std::unexpected(decoded.error());
    }

    return std::move(*decoded);
}

std::filesystem::path
checkpoint_path(const std::filesystem::path& profile_directory) {
    return profile_directory / platform::path::from_utf8(fsck_checkpoint_file_name);
}

std::expected<void, std::string>
save_checkpoint(const std::filesystem::path& profile_directory,
                const FsckCheckpoint& checkpoint,
                std::span<const std::uint8_t, crypto::KEY_SIZE> master_key) {
    const auto durable_trace = platform::perf_trace::begin();

    auto encrypted = encrypt_checkpoint(checkpoint, master_key);
    if (!encrypted) {
        platform::perf_trace::count("fsck.checkpoint_write_failures");
        return std::unexpected(encrypted.error());
    }

    const auto destination = checkpoint_path(profile_directory);
    std::string_view bytes(reinterpret_cast<const char*>(encrypted->data()), encrypted->size());

    auto saved = platform::private_storage::write_atomically(destination, bytes);
    if (!saved) {
        platform::perf_trace::count("fsck.checkpoint_write_failures");
        return saved;
    }

    platform::perf_trace::count("fsck.checkpoint_durable_writes");
    platform::perf_trace::count("fsck.checkpoint_entries_persisted", checkpoint.entries.size());
    platform::perf_trace::count("fsck.checkpoint_bytes_written", encrypted->size());
    platform::perf_trace::finish("fsck.checkpoint_durable_write_wall_us", durable_trace);

    return {};
}

std::expected<std::optional<FsckCheckpoint>, std::string>
load_checkpoint(const std::filesystem::path& profile_directory,
                std::span<const std::uint8_t, crypto::KEY_SIZE> master_key) {
    platform::perf_trace::count("fsck.checkpoint_load_attempts");
    const auto destination = checkpoint_path(profile_directory);

    std::error_code error;
    if (!std::filesystem::exists(destination, error) || error) {
        platform::perf_trace::count("fsck.checkpoint_absent");
        return std::optional<FsckCheckpoint>{std::nullopt};
    }

    std::ifstream input(destination, std::ios::binary | std::ios::ate);
    if (!input) {
        platform::perf_trace::count("fsck.checkpoint_rejected");
        return std::unexpected("could not open checkpoint file");
    }

    const auto file_size = input.tellg();
    if (file_size <= 0 || file_size > static_cast<std::streamoff>(max_checkpoint_payload_size + 4096)) {
        platform::perf_trace::count("fsck.checkpoint_rejected");
        return std::unexpected("invalid checkpoint file size");
    }

    input.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> buffer(static_cast<std::size_t>(file_size));
    input.read(reinterpret_cast<char*>(buffer.data()), file_size);
    if (!input) {
        platform::perf_trace::count("fsck.checkpoint_rejected");
        return std::unexpected("could not read checkpoint file");
    }

    auto decrypted = decrypt_checkpoint(buffer, master_key);
    if (!decrypted) {
        platform::perf_trace::count("fsck.checkpoint_rejected");
        if (decrypted.error().find("authentication failed") != std::string::npos) {
            platform::perf_trace::count("fsck.checkpoint_auth_failures");
        } else if (decrypted.error().find("version") != std::string::npos) {
            platform::perf_trace::count("fsck.checkpoint_version_mismatch");
        }
        return std::unexpected(decrypted.error());
    }

    platform::perf_trace::count("fsck.checkpoint_valid");
    platform::perf_trace::count("fsck.checkpoint_entries_loaded", decrypted->entries.size());

    return std::optional<FsckCheckpoint>{std::move(*decrypted)};
}

} // namespace kasumi::application::integrity
