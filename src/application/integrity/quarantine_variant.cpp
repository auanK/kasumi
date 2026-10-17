#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/quarantine_variant.hpp"

#include "core/wire.hpp"
#include "crypto/key_derivation.hpp"
#include "platform/random.hpp"

#include <monocypher.h>
#include <algorithm>
#include <cstring>

namespace kasumi::application::integrity {
namespace {

constexpr std::size_t HASH_HEX_SIZE = 64;
constexpr std::size_t NONCE_SIZE = 24;
constexpr std::size_t MAC_SIZE = 16;
constexpr std::size_t HEADER_PREFIX_SIZE = 8 + 4 + 4 + 4; // magic(8) + version(4) + type(4) + vault_id_len(4)

struct SubkeyGuard {
    std::span<std::uint8_t> span;
    explicit SubkeyGuard(std::span<std::uint8_t> s) noexcept : span(s) {}
    ~SubkeyGuard() noexcept {
        crypto_wipe(span.data(), span.size());
    }
    SubkeyGuard(const SubkeyGuard&) = delete;
    SubkeyGuard& operator=(const SubkeyGuard&) = delete;
};

bool valid_hex_hash(std::string_view value) noexcept {
    return value.size() == HASH_HEX_SIZE &&
           std::ranges::all_of(value, [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}

void write_u32_le(std::uint8_t* dest, std::uint32_t value) noexcept {
    dest[0] = static_cast<std::uint8_t>(value & 0xff);
    dest[1] = static_cast<std::uint8_t>((value >> 8) & 0xff);
    dest[2] = static_cast<std::uint8_t>((value >> 16) & 0xff);
    dest[3] = static_cast<std::uint8_t>((value >> 24) & 0xff);
}

std::uint32_t read_u32_le(const std::uint8_t* src) noexcept {
    return static_cast<std::uint32_t>(src[0]) |
           (static_cast<std::uint32_t>(src[1]) << 8) |
           (static_cast<std::uint32_t>(src[2]) << 16) |
           (static_cast<std::uint32_t>(src[3]) << 24);
}

} // namespace

bool validate_quarantine_record_layout(
    const QuarantineRecord& record,
    const history_storage::RemoteLayout& layout) noexcept {
    if (record.format_version != quarantine_format_version_1 ||
        record.candidate_type != QuarantineCandidateType::CommitVariant ||
        !valid_hex_hash(record.commit_id) || !valid_hex_hash(record.ciphertext_id) ||
        !valid_hex_hash(record.ciphertext_sha256) || record.ciphertext_size_bytes == 0 ||
        record.quarantined_timestamp == 0) {
        return false;
    }

    const history_storage::HeadReference expected_ref{
        .commit_id = record.commit_id,
        .ciphertext_id = record.ciphertext_id,
    };

    const auto expected_original = history_storage::commit_object(layout, expected_ref);
    if (record.original_identifier != expected_original) {
        return false;
    }

    const auto parsed = history_storage::parse_commit_object(layout, record.original_identifier);
    if (!parsed || parsed->commit_id != record.commit_id || parsed->ciphertext_id != record.ciphertext_id) {
        return false;
    }

    const auto expected_payload = quarantine_payload_object(
        layout.quarantine_prefix, record.commit_id, record.ciphertext_id);
    if (record.quarantined_payload_identifier != expected_payload) {
        return false;
    }

    return true;
}

std::expected<std::vector<std::uint8_t>, std::string>
encode_quarantine_record(
    const QuarantineRecord& record,
    std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
    std::string_view vault_identifier) {
    if (record.format_version != quarantine_format_version_1) {
        return std::unexpected("unsupported quarantine format version");
    }
    if (record.candidate_type != QuarantineCandidateType::CommitVariant) {
        return std::unexpected("unsupported quarantine candidate type");
    }
    if (vault_identifier.empty()) {
        return std::unexpected("empty vault identifier");
    }

    const auto layout = history_storage::derive_remote_layout(master_key);
    if (layout.history_prefix != vault_identifier) {
        return std::unexpected("vault identifier mismatch with master key layout");
    }

    if (!validate_quarantine_record_layout(record, layout)) {
        return std::unexpected("quarantine record does not conform to remote layout");
    }

#ifdef KASUMI_MUTATION_FAULT_TESTS
    if (detail::fail_quarantine_rng()) {
        return std::unexpected("injected CSPRNG failure in quarantine encoding");
    }
#endif

    std::array<std::uint8_t, NONCE_SIZE> nonce{};
    auto rng_res = platform::random::fill_bytes(nonce);
    if (!rng_res) {
        return std::unexpected("failed to generate secure random nonce for quarantine record: " + rng_res.error());
    }

    // Canonical serialization of plaintext payload
    wire::Writer writer;
    wire::write_string(writer, record.original_identifier);
    wire::write_string(writer, record.quarantined_payload_identifier);
    wire::write_string(writer, record.commit_id);
    wire::write_string(writer, record.ciphertext_id);
    wire::write(writer, record.ciphertext_size_bytes);
    wire::write_string(writer, record.ciphertext_sha256);
    wire::write(writer, record.quarantined_timestamp);

    auto subkey = crypto::derive_key(master_key, crypto::KeyPurpose::Quarantine);
    SubkeyGuard subkey_guard{subkey};

    const std::size_t aad_size = HEADER_PREFIX_SIZE + vault_identifier.size();
    const std::size_t total_header_size = aad_size + NONCE_SIZE + MAC_SIZE;
    const std::size_t payload_size = writer.buffer.size();
    std::vector<std::uint8_t> envelope(total_header_size + payload_size);

    // Fill AAD
    std::memcpy(envelope.data(), quarantine_magic.data(), 8);
    write_u32_le(envelope.data() + 8, quarantine_format_version_1);
    write_u32_le(envelope.data() + 12, static_cast<std::uint32_t>(QuarantineCandidateType::CommitVariant));
    write_u32_le(envelope.data() + 16, static_cast<std::uint32_t>(vault_identifier.size()));
    std::memcpy(envelope.data() + 20, vault_identifier.data(), vault_identifier.size());

    // Nonce
    std::memcpy(envelope.data() + aad_size, nonce.data(), NONCE_SIZE);

    // Encrypt & Authenticate
    auto* mac_ptr = envelope.data() + aad_size + NONCE_SIZE;
    auto* ciphertext_ptr = mac_ptr + MAC_SIZE;
    crypto_aead_lock(ciphertext_ptr,
                     mac_ptr,
                     subkey.data(),
                     nonce.data(),
                     envelope.data(),
                     aad_size,
                     reinterpret_cast<const std::uint8_t*>(writer.buffer.data()),
                     payload_size);

    return envelope;
}

std::expected<QuarantineRecord, std::string>
decode_quarantine_record(
    std::span<const std::uint8_t> envelope_bytes,
    std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
    std::string_view vault_identifier) {
    if (envelope_bytes.size() < HEADER_PREFIX_SIZE + 1 + NONCE_SIZE + MAC_SIZE + 1) {
        return std::unexpected("quarantine record envelope truncated");
    }
    if (std::memcmp(envelope_bytes.data(), quarantine_magic.data(), 8) != 0) {
        return std::unexpected("invalid quarantine magic");
    }
    const auto format_version = read_u32_le(envelope_bytes.data() + 8);
    if (format_version != quarantine_format_version_1) {
        return std::unexpected("unsupported quarantine format version");
    }
    const auto candidate_type = read_u32_le(envelope_bytes.data() + 12);
    if (candidate_type != static_cast<std::uint32_t>(QuarantineCandidateType::CommitVariant)) {
        return std::unexpected("invalid quarantine candidate type");
    }
    const auto vault_id_len = read_u32_le(envelope_bytes.data() + 16);
    if (vault_id_len == 0 || vault_id_len > 1024) {
        return std::unexpected("invalid quarantine vault identifier length");
    }
    const std::size_t aad_size = HEADER_PREFIX_SIZE + vault_id_len;
    const std::size_t min_envelope_size = aad_size + NONCE_SIZE + MAC_SIZE;
    if (envelope_bytes.size() <= min_envelope_size) {
        return std::unexpected("quarantine record envelope truncated");
    }
    if (vault_id_len != vault_identifier.size() ||
        std::memcmp(envelope_bytes.data() + 20, vault_identifier.data(), vault_id_len) != 0) {
        return std::unexpected("quarantine record vault identifier mismatch");
    }

    const auto layout = history_storage::derive_remote_layout(master_key);
    if (layout.history_prefix != vault_identifier) {
        return std::unexpected("vault identifier mismatch with master key layout");
    }

    const auto* nonce_ptr = envelope_bytes.data() + aad_size;
    const auto* mac_ptr = nonce_ptr + NONCE_SIZE;
    const auto* ciphertext_ptr = mac_ptr + MAC_SIZE;
    const std::size_t ciphertext_size = envelope_bytes.size() - min_envelope_size;

    std::vector<std::uint8_t> plaintext(ciphertext_size);
    auto subkey = crypto::derive_key(master_key, crypto::KeyPurpose::Quarantine);
    SubkeyGuard subkey_guard{subkey};

    const int unlock_result = crypto_aead_unlock(
        plaintext.data(),
        mac_ptr,
        subkey.data(),
        nonce_ptr,
        envelope_bytes.data(),
        aad_size,
        ciphertext_ptr,
        ciphertext_size);

    if (unlock_result != 0) {
        crypto_wipe(plaintext.data(), plaintext.size());
        return std::unexpected("quarantine record authentication failed: invalid tag or data corrupted");
    }

    wire::Reader reader{std::span<const std::byte>{
        reinterpret_cast<const std::byte*>(plaintext.data()), plaintext.size()}};

    auto original_identifier = wire::read_string(reader);
    auto quarantined_payload_identifier = wire::read_string(reader);
    auto commit_id = wire::read_string(reader);
    auto ciphertext_id = wire::read_string(reader);
    auto ciphertext_size_bytes = wire::read<std::uint64_t>(reader);
    auto ciphertext_sha256 = wire::read_string(reader);
    auto quarantined_timestamp = wire::read<std::uint64_t>(reader);

    if (!original_identifier || !quarantined_payload_identifier ||
        !commit_id || !ciphertext_id || !ciphertext_size_bytes ||
        !ciphertext_sha256 || !quarantined_timestamp) {
        crypto_wipe(plaintext.data(), plaintext.size());
        return std::unexpected("truncated quarantine payload");
    }
    if (!reader.data.empty()) {
        crypto_wipe(plaintext.data(), plaintext.size());
        return std::unexpected("prohibited extra bytes in quarantine payload");
    }

    QuarantineRecord record{
        .format_version = format_version,
        .candidate_type = static_cast<QuarantineCandidateType>(candidate_type),
        .original_identifier = *original_identifier,
        .quarantined_payload_identifier = *quarantined_payload_identifier,
        .commit_id = *commit_id,
        .ciphertext_id = *ciphertext_id,
        .ciphertext_size_bytes = *ciphertext_size_bytes,
        .ciphertext_sha256 = *ciphertext_sha256,
        .quarantined_timestamp = *quarantined_timestamp,
    };
    crypto_wipe(plaintext.data(), plaintext.size());

    if (!validate_quarantine_record_layout(record, layout)) {
        return std::unexpected("decoded quarantine record violates remote domain layout");
    }

    return record;
}

std::string quarantine_payload_object(
    std::string_view quarantine_prefix,
    std::string_view commit_id,
    std::string_view ciphertext_id) {
    return std::string{quarantine_prefix} + "variants/" +
           std::string{commit_id} + "/" + std::string{ciphertext_id};
}

std::string quarantine_record_object(
    std::string_view quarantine_prefix,
    std::string_view commit_id,
    std::string_view ciphertext_id) {
    return std::string{quarantine_prefix} + "records/" +
           std::string{commit_id} + "/" + std::string{ciphertext_id} + ".meta";
}

} // namespace kasumi::application::integrity
