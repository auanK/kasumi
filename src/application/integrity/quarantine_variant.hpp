#ifndef KASUMI_APPLICATION_INTEGRITY_QUARANTINE_VARIANT_HPP
#define KASUMI_APPLICATION_INTEGRITY_QUARANTINE_VARIANT_HPP

#include "crypto/key_derivation.hpp"
#include "transport/types.hpp"

#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::application::history_storage {
struct RemoteLayout;
}

namespace kasumi::application::integrity {

#ifdef KASUMI_MUTATION_FAULT_TESTS
namespace detail {
inline bool& fail_quarantine_rng() noexcept {
    static thread_local bool fail = false;
    return fail;
}
inline void set_fail_quarantine_rng(bool fail) noexcept {
    fail_quarantine_rng() = fail;
}
} // namespace detail
#endif

// Format identifier: "KAS_QVAR"
inline constexpr std::array<std::byte, 8> quarantine_magic{
    std::byte{'K'}, std::byte{'A'}, std::byte{'S'}, std::byte{'_'},
    std::byte{'Q'}, std::byte{'V'}, std::byte{'A'}, std::byte{'R'}
};
inline constexpr std::uint32_t quarantine_format_version_1 = 1;

enum class QuarantineCandidateType : std::uint32_t {
    CommitVariant = 1,
};

struct QuarantineRecord {
    std::uint32_t format_version = quarantine_format_version_1;
    QuarantineCandidateType candidate_type = QuarantineCandidateType::CommitVariant;
    std::string original_identifier;
    std::string quarantined_payload_identifier;
    std::string commit_id;
    std::string ciphertext_id;
    std::uint64_t ciphertext_size_bytes = 0;
    std::string ciphertext_sha256;
    std::uint64_t quarantined_timestamp = 0;

    bool operator==(const QuarantineRecord&) const = default;
};

// Encrypts and authenticates a quarantine record using Monocypher AEAD.
// The envelope is cryptographically bound to the specific vault key and vault identifier.
std::expected<std::vector<std::uint8_t>, std::string>
encode_quarantine_record(
    const QuarantineRecord& record,
    std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
    std::string_view vault_identifier);

// Decrypts, authenticates, and validates a quarantine record.
std::expected<QuarantineRecord, std::string>
decode_quarantine_record(
    std::span<const std::uint8_t> envelope_bytes,
    std::span<const std::uint8_t, crypto::KEY_SIZE> master_key,
    std::string_view vault_identifier);

// Validates that a quarantine record strictly conforms to the expected remote layout.
bool validate_quarantine_record_layout(
    const QuarantineRecord& record,
    const history_storage::RemoteLayout& layout) noexcept;

// Deterministic destination path for preserved ciphertext payload.
std::string quarantine_payload_object(
    std::string_view quarantine_prefix,
    std::string_view commit_id,
    std::string_view ciphertext_id);

// Deterministic destination path for authenticated quarantine metadata record.
std::string quarantine_record_object(
    std::string_view quarantine_prefix,
    std::string_view commit_id,
    std::string_view ciphertext_id);

} // namespace kasumi::application::integrity

#endif

