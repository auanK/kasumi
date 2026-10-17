#include "application/history_storage/content_reachability.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/integrity/maintenance.hpp"
#include "application/integrity/quarantine_variant.hpp"
#include "crypto/content.hpp"
#include "crypto/key_derivation.hpp"
#include "crypto/physical_hash.hpp"
#include "kasumi/test/history_storage.hpp"
#include "core/wire.hpp"
#include "platform/cancellation.hpp"

#include <monocypher.h>
#include <algorithm>
#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace {

namespace integrity = kasumi::application::integrity;
namespace history = kasumi::application::history_storage;
namespace protocol = history::maintenance_protocol;
namespace cancellation = kasumi::platform::cancellation;
using Failure = integrity::GcCommitQuarantineErrorCode;

std::vector<std::uint8_t> extract_nonce(
    std::span<const std::uint8_t> envelope,
    std::string_view vault_identifier) {
    const std::size_t aad_size = 20 + vault_identifier.size();
    if (envelope.size() < aad_size + 24) return {};
    auto start = envelope.begin() + static_cast<std::ptrdiff_t>(aad_size);
    return std::vector<std::uint8_t>(start, start + 24);
}

std::vector<std::uint8_t> forge_quarantine_envelope(
    const integrity::QuarantineRecord& record,
    std::span<const std::uint8_t, kasumi::crypto::KEY_SIZE> master_key,
    std::string_view vault_identifier) {
    wire::Writer writer;
    wire::write_string(writer, record.original_identifier);
    wire::write_string(writer, record.quarantined_payload_identifier);
    wire::write_string(writer, record.commit_id);
    wire::write_string(writer, record.ciphertext_id);
    wire::write(writer, record.ciphertext_size_bytes);
    wire::write_string(writer, record.ciphertext_sha256);
    wire::write(writer, record.quarantined_timestamp);

    auto subkey = kasumi::crypto::derive_key(master_key, kasumi::crypto::KeyPurpose::Quarantine);

    const std::size_t aad_size = 20 + vault_identifier.size();
    const std::size_t nonce_size = 24;
    const std::size_t mac_size = 16;
    const std::size_t total_header_size = aad_size + nonce_size + mac_size;
    const std::size_t payload_size = writer.buffer.size();
    std::vector<std::uint8_t> envelope(total_header_size + payload_size);

    std::memcpy(envelope.data(), integrity::quarantine_magic.data(), 8);
    envelope[8] = 1; envelope[9] = 0; envelope[10] = 0; envelope[11] = 0;
    envelope[12] = 1; envelope[13] = 0; envelope[14] = 0; envelope[15] = 0;
    const auto vlen = static_cast<std::uint32_t>(vault_identifier.size());
    envelope[16] = static_cast<std::uint8_t>(vlen & 0xff);
    envelope[17] = static_cast<std::uint8_t>((vlen >> 8) & 0xff);
    envelope[18] = static_cast<std::uint8_t>((vlen >> 16) & 0xff);
    envelope[19] = static_cast<std::uint8_t>((vlen >> 24) & 0xff);
    std::memcpy(envelope.data() + 20, vault_identifier.data(), vault_identifier.size());

    std::array<std::uint8_t, 24> nonce{};
    nonce.fill(0x5a);
    std::memcpy(envelope.data() + aad_size, nonce.data(), nonce_size);

    auto* mac_ptr = envelope.data() + aad_size + nonce_size;
    auto* ciphertext_ptr = mac_ptr + mac_size;
    crypto_aead_lock(ciphertext_ptr,
                     mac_ptr,
                     subkey.data(),
                     nonce.data(),
                     envelope.data(),
                     aad_size,
                     reinterpret_cast<const std::uint8_t*>(writer.buffer.data()),
                     payload_size);
    crypto_wipe(subkey.data(), subkey.size());
    return envelope;
}

// ============================================================================
// Grupo A — Formato autenticado
// ============================================================================

TEST(GcCommitQuarantineTest, A1_ValidRecordSerializesAndDeserializes) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    const std::string sha256_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    const integrity::QuarantineRecord original{
        .format_version = integrity::quarantine_format_version_1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 4096,
        .ciphertext_sha256 = sha256_hash,
        .quarantined_timestamp = 1700000000,
    };

    auto encoded = integrity::encode_quarantine_record(original, key, layout.history_prefix);
    ASSERT_TRUE(encoded.has_value()) << (encoded ? "" : encoded.error());

    auto decoded = integrity::decode_quarantine_record(*encoded, key, layout.history_prefix);
    ASSERT_TRUE(decoded.has_value()) << (decoded ? "" : decoded.error());
    EXPECT_EQ(*decoded, original);
}

TEST(GcCommitQuarantineTest, A2_RepresentationIsCanonicalAndProbabilistic) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    const std::string sha256_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    const integrity::QuarantineRecord record{
        .format_version = integrity::quarantine_format_version_1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = sha256_hash,
        .quarantined_timestamp = 1700000000,
    };

    auto enc1 = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    auto enc2 = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    ASSERT_TRUE(enc1.has_value());
    ASSERT_TRUE(enc2.has_value());
    // Probabilistic encryption: independent encodings produce different envelopes
    EXPECT_NE(*enc1, *enc2);

    // Canonical decoding: both decode to the exact same original record
    auto dec1 = integrity::decode_quarantine_record(*enc1, key, layout.history_prefix);
    auto dec2 = integrity::decode_quarantine_record(*enc2, key, layout.history_prefix);
    ASSERT_TRUE(dec1.has_value());
    ASSERT_TRUE(dec2.has_value());
    EXPECT_EQ(*dec1, record);
    EXPECT_EQ(*dec2, record);
}

TEST(GcCommitQuarantineTest, A3_UnknownVersionIsRejected) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    integrity::QuarantineRecord record{
        .format_version = 99,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    EXPECT_FALSE(enc.has_value());
}

TEST(GcCommitQuarantineTest, A4_IncorrectMagicOrTypeIsRejected) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    const integrity::QuarantineRecord record{
        .format_version = 1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    ASSERT_TRUE(enc.has_value());

    auto corrupted = *enc;
    corrupted[0] = static_cast<std::uint8_t>('X');
    auto dec = integrity::decode_quarantine_record(corrupted, key, layout.history_prefix);
    EXPECT_FALSE(dec.has_value());
}

TEST(GcCommitQuarantineTest, A5_TruncatedRecordIsRejected) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    const integrity::QuarantineRecord record{
        .format_version = 1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    ASSERT_TRUE(enc.has_value());

    std::vector<std::uint8_t> truncated(enc->begin(), enc->end() - 5);
    auto dec = integrity::decode_quarantine_record(truncated, key, layout.history_prefix);
    EXPECT_FALSE(dec.has_value());
}

TEST(GcCommitQuarantineTest, A6_ProhibitedAdditionalBytesAreRejected) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    const integrity::QuarantineRecord record{
        .format_version = 1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    ASSERT_TRUE(enc.has_value());

    auto appended = *enc;
    appended.push_back(0xcc);
    auto dec = integrity::decode_quarantine_record(appended, key, layout.history_prefix);
    EXPECT_FALSE(dec.has_value());
}

TEST(GcCommitQuarantineTest, A7_IncompatiblePhysicalDigestIsRejected) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    integrity::QuarantineRecord record{
        .format_version = 1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "not_a_valid_hex_hash",
        .quarantined_timestamp = 1700000000,
    };

    auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    EXPECT_FALSE(enc.has_value());
}

TEST(GcCommitQuarantineTest, A8_IncompatibleOriginalIdentifierIsRejected) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    integrity::QuarantineRecord record{
        .format_version = 1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = "invalid/path/to/commit",
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    EXPECT_FALSE(enc.has_value());
}

TEST(GcCommitQuarantineTest, A9_RecordAuthenticatedWithOtherVaultKeyIsRejected) {
    const auto key1 = test_key();
    auto key2 = test_key();
    key2[0] ^= 0xff;
    const auto layout = history::derive_remote_layout(key1);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    const integrity::QuarantineRecord record{
        .format_version = 1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    auto enc = integrity::encode_quarantine_record(record, key1, layout.history_prefix);
    ASSERT_TRUE(enc.has_value());

    auto dec = integrity::decode_quarantine_record(*enc, key2, layout.history_prefix);
    EXPECT_FALSE(dec.has_value());
}

TEST(GcCommitQuarantineTest, A10_TamperedRecordIsRejected) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    const integrity::QuarantineRecord record{
        .format_version = 1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    ASSERT_TRUE(enc.has_value());

    auto tampered = *enc;
    tampered[tampered.size() / 2] ^= 0x01;
    auto dec = integrity::decode_quarantine_record(tampered, key, layout.history_prefix);
    EXPECT_FALSE(dec.has_value());
}

TEST(GcCommitQuarantineTest, A11_ReferenceToWrongPayloadIsRejected) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    integrity::QuarantineRecord record{
        .format_version = 1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/different_commit/different_cipher",
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    EXPECT_FALSE(enc.has_value());
}

TEST(GcCommitQuarantineTest, A12_ContradictoryFieldsCauseExplicitFailure) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);

    integrity::QuarantineRecord record{
        .format_version = 1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = "",
        .quarantined_payload_identifier = "",
        .commit_id = "bad",
        .ciphertext_id = "bad",
        .ciphertext_size_bytes = 0,
        .ciphertext_sha256 = "bad",
        .quarantined_timestamp = 0,
    };

    auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    EXPECT_FALSE(enc.has_value());
}

// ============================================================================
// Grupo N — Unicidade de nonce e entropia CSPRNG
// ============================================================================

TEST(GcCommitQuarantineTest, N1_IndependentEncodingsProduceDistinctNoncesAndEnvelopes) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    const integrity::QuarantineRecord record{
        .format_version = integrity::quarantine_format_version_1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    auto enc1 = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    auto enc2 = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    ASSERT_TRUE(enc1.has_value());
    ASSERT_TRUE(enc2.has_value());
    EXPECT_NE(*enc1, *enc2);

    auto nonce1 = extract_nonce(*enc1, layout.history_prefix);
    auto nonce2 = extract_nonce(*enc2, layout.history_prefix);
    EXPECT_EQ(nonce1.size(), 24U);
    EXPECT_EQ(nonce2.size(), 24U);
    EXPECT_NE(nonce1, nonce2);

    auto dec1 = integrity::decode_quarantine_record(*enc1, key, layout.history_prefix);
    auto dec2 = integrity::decode_quarantine_record(*enc2, key, layout.history_prefix);
    ASSERT_TRUE(dec1.has_value());
    ASSERT_TRUE(dec2.has_value());
    EXPECT_EQ(*dec1, record);
    EXPECT_EQ(*dec2, record);
}

TEST(GcCommitQuarantineTest, N2_DifferentPlaintextsWithIdenticalIdentifiersProduceDistinctNonces) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    integrity::QuarantineRecord record1{
        .format_version = integrity::quarantine_format_version_1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "1111111111111111111111111111111111111111111111111111111111111111",
        .quarantined_timestamp = 1700000000,
    };

    integrity::QuarantineRecord record2 = record1;
    record2.ciphertext_sha256 = "2222222222222222222222222222222222222222222222222222222222222222";
    record2.ciphertext_size_bytes = 2048;

    auto enc1 = integrity::encode_quarantine_record(record1, key, layout.history_prefix);
    auto enc2 = integrity::encode_quarantine_record(record2, key, layout.history_prefix);
    ASSERT_TRUE(enc1.has_value());
    ASSERT_TRUE(enc2.has_value());

    auto nonce1 = extract_nonce(*enc1, layout.history_prefix);
    auto nonce2 = extract_nonce(*enc2, layout.history_prefix);
    EXPECT_EQ(nonce1.size(), 24U);
    EXPECT_EQ(nonce2.size(), 24U);
    EXPECT_NE(nonce1, nonce2);
}

TEST(GcCommitQuarantineTest, N3_SecureRandomFailureProducesExplicitError) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    const integrity::QuarantineRecord record{
        .format_version = integrity::quarantine_format_version_1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    integrity::detail::set_fail_quarantine_rng(true);
    auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    integrity::detail::set_fail_quarantine_rng(false);

    EXPECT_FALSE(enc.has_value());
}

TEST(GcCommitQuarantineTest, N4_RoundTripWithIndependentNonces) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);

    for (int i = 0; i < 5; ++i) {
        std::string commit_id(64, static_cast<char>('a' + (i % 6)));
        std::string ciphertext_id(64, static_cast<char>('0' + (i % 10)));
        std::string sha256_hash(64, static_cast<char>('f' - (i % 6)));

        integrity::QuarantineRecord record{
            .format_version = integrity::quarantine_format_version_1,
            .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
            .original_identifier = layout.commits_prefix + commit_id + "/" + ciphertext_id,
            .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
            .commit_id = commit_id,
            .ciphertext_id = ciphertext_id,
            .ciphertext_size_bytes = static_cast<std::uint64_t>(1000 + i),
            .ciphertext_sha256 = sha256_hash,
            .quarantined_timestamp = static_cast<std::uint64_t>(1700000000 + i),
        };

        auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
        ASSERT_TRUE(enc.has_value());

        auto dec = integrity::decode_quarantine_record(*enc, key, layout.history_prefix);
        ASSERT_TRUE(dec.has_value());
        EXPECT_EQ(*dec, record);
    }
}

TEST(GcCommitQuarantineTest, N5_TamperedNonceCausesDecoderRejection) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    const integrity::QuarantineRecord record{
        .format_version = integrity::quarantine_format_version_1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    ASSERT_TRUE(enc.has_value());

    auto tampered = *enc;
    const std::size_t aad_size = 20 + layout.history_prefix.size();
    tampered[aad_size + 3] ^= 0x01;

    auto dec = integrity::decode_quarantine_record(tampered, key, layout.history_prefix);
    EXPECT_FALSE(dec.has_value());
}

// ============================================================================
// Grupo I — Endurecimento de identificadores e validação de layout
// ============================================================================

TEST(GcCommitQuarantineTest, I1_OriginalIdentifierWithExtraPrefixRejected) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    integrity::QuarantineRecord record{
        .format_version = integrity::quarantine_format_version_1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = "extra/" + layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    EXPECT_FALSE(integrity::validate_quarantine_record_layout(record, layout));
    auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    EXPECT_FALSE(enc.has_value());
}

TEST(GcCommitQuarantineTest, I2_OriginalIdentifierWithExtraSuffixRejected) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    integrity::QuarantineRecord record{
        .format_version = integrity::quarantine_format_version_1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + commit_id + "/" + ciphertext_id + "/extra",
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    EXPECT_FALSE(integrity::validate_quarantine_record_layout(record, layout));
    auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    EXPECT_FALSE(enc.has_value());
}

TEST(GcCommitQuarantineTest, I3_PreservedIdentifierOutsideNamespaceRejected) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    integrity::QuarantineRecord record{
        .format_version = integrity::quarantine_format_version_1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.commits_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    EXPECT_FALSE(integrity::validate_quarantine_record_layout(record, layout));
    auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    EXPECT_FALSE(enc.has_value());
}

TEST(GcCommitQuarantineTest, I4_IntermediateSegmentRejected) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    integrity::QuarantineRecord record{
        .format_version = integrity::quarantine_format_version_1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/extra/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    EXPECT_FALSE(integrity::validate_quarantine_record_layout(record, layout));
    auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    EXPECT_FALSE(enc.has_value());
}

TEST(GcCommitQuarantineTest, I5_SwappedIdentifiersRejected) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    integrity::QuarantineRecord record{
        .format_version = integrity::quarantine_format_version_1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + ciphertext_id + "/" + commit_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    EXPECT_FALSE(integrity::validate_quarantine_record_layout(record, layout));
    auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    EXPECT_FALSE(enc.has_value());
}

TEST(GcCommitQuarantineTest, I6_ForeignVaultIdentifierRejected) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    auto other_key = test_key();
    other_key[0] ^= 0x55;
    const auto other_layout = history::derive_remote_layout(other_key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    integrity::QuarantineRecord record{
        .format_version = integrity::quarantine_format_version_1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = other_layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    EXPECT_FALSE(integrity::validate_quarantine_record_layout(record, layout));
    auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    EXPECT_FALSE(enc.has_value());
}

TEST(GcCommitQuarantineTest, I7_PathTraversalRejected) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    integrity::QuarantineRecord record{
        .format_version = integrity::quarantine_format_version_1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + "../commits/" + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    EXPECT_FALSE(integrity::validate_quarantine_record_layout(record, layout));
    auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    EXPECT_FALSE(enc.has_value());
}

TEST(GcCommitQuarantineTest, I8_InvalidHexCharsInIdentifiersRejected) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    integrity::QuarantineRecord record{
        .format_version = integrity::quarantine_format_version_1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    EXPECT_FALSE(integrity::validate_quarantine_record_layout(record, layout));
    auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    EXPECT_FALSE(enc.has_value());
}

TEST(GcCommitQuarantineTest, I9_ValidMacWithInvalidIdentifierRejectedByDecoder) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    integrity::QuarantineRecord invalid_record{
        .format_version = integrity::quarantine_format_version_1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = "extra_prefix/" + layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    auto forged = forge_quarantine_envelope(invalid_record, key, layout.history_prefix);
    auto dec = integrity::decode_quarantine_record(forged, key, layout.history_prefix);
    EXPECT_FALSE(dec.has_value());
}

TEST(GcCommitQuarantineTest, I10_ValidKasumiLayoutAccepted) {
    const auto key = test_key();
    const auto layout = history::derive_remote_layout(key);
    const std::string commit_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string ciphertext_id = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    const integrity::QuarantineRecord record{
        .format_version = integrity::quarantine_format_version_1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = layout.commits_prefix + commit_id + "/" + ciphertext_id,
        .quarantined_payload_identifier = layout.quarantine_prefix + "variants/" + commit_id + "/" + ciphertext_id,
        .commit_id = commit_id,
        .ciphertext_id = ciphertext_id,
        .ciphertext_size_bytes = 1024,
        .ciphertext_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .quarantined_timestamp = 1700000000,
    };

    EXPECT_TRUE(integrity::validate_quarantine_record_layout(record, layout));
    auto enc = integrity::encode_quarantine_record(record, key, layout.history_prefix);
    ASSERT_TRUE(enc.has_value());
    auto dec = integrity::decode_quarantine_record(*enc, key, layout.history_prefix);
    ASSERT_TRUE(dec.has_value());
    EXPECT_EQ(*dec, record);
}

// ============================================================================
// Fixture para Grupos B a G (Quarentena sob barreira)
// ============================================================================

class GcCommitQuarantineFixture : public ::testing::Test {
protected:
    TempWorkspace workspace = kasumi::test::make_temp_workspace("gc-commit-quarantine");
    FakeState* state = nullptr;
    kasumi::transport::Transport storage = make_fake_transport(state);
    history::RemoteLayout layout = history::derive_remote_layout(test_key());
    Commit commit = make_commit(0, {}, "file", "live").value();
    HeadReference head;
    HeadReference redundant_variant;
    std::string live_content = content("live");
    struct MutationRecord {
        std::string type;
        std::string target;
        std::string source;
    };
    std::vector<MutationRecord> physical_mutations;
    std::function<void(std::string_view, std::string_view)> on_operation;
    std::vector<std::string> removed_identifiers;
    std::vector<std::string> copied_sources;
    std::vector<std::string> copied_destinations;
    std::vector<std::string> put_identifiers;

    static std::string content(std::string_view bytes) {
        return kasumi::crypto::content_identifier(
            test_key(), kasumi::hasher::hash_string(bytes));
    }

    HeadReference add_commit(const Commit& value, bool marker = true, std::string_view salt = {}) {
        const auto canonical = kasumi::history::serialize(value).value();
        const auto plain = kasumi::test::workspace_path(workspace, "commit" + std::string{salt} + ".plain");
        const auto encrypted = kasumi::test::workspace_path(workspace, "commit" + std::string{salt} + ".enc");
        kasumi::test::write_binary(plain, std::as_bytes(std::span{canonical}));
        EXPECT_TRUE(kasumi::crypto::encrypt_file(
            plain, encrypted, test_key(), kasumi::crypto::FilePurpose::History));
        std::filesystem::remove(plain);
        const HeadReference reference{
            commit_id(value), kasumi::hash_hex(
                kasumi::crypto::content::hash_file(encrypted).value())};
        EXPECT_TRUE(fake_put(state, encrypted, object_path(reference)));
        if (marker) {
            state->objects[marker_path(reference)] = history::encode_marker(reference).value();
        }
        return reference;
    }

    std::string add_orphan_content(std::string_view name) {
        const auto id = content(name);
        state->objects[id] = {'o', 'r', 'p', 'h', 'a', 'n'};
        return id;
    }

    void SetUp() override {
        cancellation::reset();
        head = add_commit(commit, true, "head");
        state->objects[live_content] = {'c', 'o', 'n', 't', 'e', 'n', 't'};
        state->copy_supported = true;
        reset_fake_traffic(*state);

        storage.storage.put = [](void* context, const std::filesystem::path& path, std::string_view id) {
            auto* current = fake_state(context);
            if (current->on_operation) current->on_operation(*current, "before_put", id);
            auto result = fake_put(context, path, id);
            if (current->on_operation) current->on_operation(*current, "after_put", id);
            return result;
        };
        storage.storage.get = [](void* context, std::string_view id, const std::filesystem::path& path) {
            auto* current = fake_state(context);
            if (current->on_operation) current->on_operation(*current, "before_get", id);
            return fake_get(context, id, path);
        };
        storage.storage.copy = [](void* context, std::string_view src, std::string_view dst) {
            auto* current = fake_state(context);
            if (current->on_operation) current->on_operation(*current, "before_copy", src);
            auto result = fake_copy(context, src, dst);
            if (current->on_operation) current->on_operation(*current, "after_copy", dst);
            return result;
        };
        storage.storage.remove = [](void* context, std::string_view id) {
            auto* current = fake_state(context);
            if (current->on_operation) current->on_operation(*current, "before_remove", id);
            auto result = fake_remove(context, id);
            if (current->on_operation) current->on_operation(*current, "after_remove", id);
            return result;
        };
        storage.storage.list = [](void* context) {
            auto* current = fake_state(context);
            if (current->on_operation) current->on_operation(*current, "before_list", {});
            return fake_list(context);
        };
        storage.storage.presence = [](void* context, std::string_view id) {
            return fake_presence(context, id);
        };
        storage.storage.put_batch = [](void* context, const kasumi::transport::PutBatch& batch) {
            auto* current = fake_state(context);
            for (const auto& id : batch.identifiers) {
                if (current->on_operation) current->on_operation(*current, "before_put_batch", id);
            }
            auto result = fake_put_batch(context, batch);
            for (const auto& id : batch.identifiers) {
                if (current->on_operation) current->on_operation(*current, "after_put_batch", id);
            }
            return result;
        };
        storage.storage.copy_batch = [](void* context, const kasumi::transport::CopyBatch& batch) {
            auto* current = fake_state(context);
            for (const auto& item : batch.items) {
                if (current->on_operation) current->on_operation(*current, "before_copy_batch", item.source_identifier);
            }
            auto result = fake_copy_batch(context, batch);
            for (const auto& item : batch.items) {
                if (current->on_operation) current->on_operation(*current, "after_copy_batch", item.destination_identifier);
            }
            return result;
        };
        storage.storage.remove_batch = [](void* context, const kasumi::transport::RemoveBatch& batch) {
            auto* current = fake_state(context);
            for (const auto& item : batch.items) {
                if (current->on_operation) current->on_operation(*current, "before_remove_batch", item.identifier);
            }
            auto result = fake_remove_batch(context, batch);
            for (const auto& item : batch.items) {
                if (current->on_operation) current->on_operation(*current, "after_remove_batch", item.identifier);
            }
            return result;
        };

        state->on_operation = [this](FakeState& current, std::string_view operation, std::string_view id) {
            if (operation == "after_put") {
                physical_mutations.push_back({"PUT", std::string(id), {}});
                put_identifiers.push_back(std::string(id));
            } else if (operation == "after_copy") {
                physical_mutations.push_back({"COPY", std::string(id), copied_sources.empty() ? "" : copied_sources.back()});
                copied_destinations.push_back(std::string(id));
            } else if (operation == "after_remove") {
                physical_mutations.push_back({"REMOVE", std::string(id), {}});
                if (id != layout.barrier_identifier) {
                    removed_identifiers.push_back(std::string(id));
                }
            } else if (operation == "after_put_batch") {
                physical_mutations.push_back({"PUT_BATCH", std::string(id), {}});
            } else if (operation == "after_copy_batch") {
                physical_mutations.push_back({"COPY_BATCH", std::string(id), {}});
            } else if (operation == "after_remove_batch") {
                physical_mutations.push_back({"REMOVE_BATCH", std::string(id), {}});
            }
            if (operation == "before_copy") {
                copied_sources.push_back(std::string(id));
            }
            if (operation == "before_remove" && id != layout.barrier_identifier) {
                EXPECT_TRUE(current.objects.contains(layout.barrier_identifier));
            }
            if (on_operation) {
                on_operation(operation, id);
            }
        };
    }
};

// ============================================================================
// Grupo B — Quarentena nominal
// ============================================================================

TEST_F(GcCommitQuarantineFixture, B1_ZeroCandidatesCausesZeroMutations) {
    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value()) << (result ? "" : result.error().cause.detail);
    EXPECT_EQ(result->commit_candidates, 0U);
    EXPECT_EQ(result->quarantined, 0U);
    EXPECT_EQ(result->originals_removed, 0U);
    EXPECT_EQ(result->already_absent, 0U);
    EXPECT_TRUE(removed_identifiers.empty());
}

TEST_F(GcCommitQuarantineFixture, B2_OneRedundantVariantQuarantinedAndRemoved) {
    redundant_variant = add_commit(commit, false, "redundant");
    ASSERT_NE(head.ciphertext_id, redundant_variant.ciphertext_id);
    reset_fake_traffic(*state);

    const std::string original_path = object_path(redundant_variant);
    EXPECT_TRUE(state->objects.contains(original_path));

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value()) << (result ? "" : result.error().cause.detail);
    EXPECT_EQ(result->commit_candidates, 1U);
    EXPECT_EQ(result->quarantined, 1U);
    EXPECT_EQ(result->originals_removed, 1U);
    EXPECT_EQ(result->already_absent, 0U);

    // Original removed
    EXPECT_FALSE(state->objects.contains(original_path));

    // Quarantined payload exists and matches original bytes
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    EXPECT_TRUE(state->objects.contains(payload_path));

    // Quarantined record exists and is authentic
    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    EXPECT_TRUE(state->objects.contains(record_path));
    auto dec = integrity::decode_quarantine_record(state->objects[record_path], test_key(), layout.history_prefix);
    ASSERT_TRUE(dec.has_value());
    EXPECT_EQ(dec->commit_id, redundant_variant.commit_id);
    EXPECT_EQ(dec->ciphertext_id, redundant_variant.ciphertext_id);
    EXPECT_EQ(dec->original_identifier, original_path);
    EXPECT_EQ(dec->quarantined_payload_identifier, payload_path);

    // HEAD commit variant preserved
    EXPECT_TRUE(state->objects.contains(object_path(head)));
}

TEST_F(GcCommitQuarantineFixture, B3_MultipleRedundantVariantsProcessedDeterministically) {
    auto v1 = add_commit(commit, false, "red1");
    auto v2 = add_commit(commit, false, "red2");
    reset_fake_traffic(*state);

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value()) << (result ? "" : result.error().cause.detail);
    EXPECT_EQ(result->commit_candidates, 2U);
    EXPECT_EQ(result->quarantined, 2U);
    EXPECT_EQ(result->originals_removed, 2U);

    EXPECT_FALSE(state->objects.contains(object_path(v1)));
    EXPECT_FALSE(state->objects.contains(object_path(v2)));
    EXPECT_TRUE(state->objects.contains(object_path(head)));
}

TEST_F(GcCommitQuarantineFixture, B4_RequiredVariantRemainsUntouched) {
    reset_fake_traffic(*state);

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->commit_candidates, 0U);
    EXPECT_TRUE(state->objects.contains(object_path(head)));
}

TEST_F(GcCommitQuarantineFixture, B5_HeadAndRetainedHistoryRemainValid) {
    redundant_variant = add_commit(commit, false, "redundant");
    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(state->objects.contains(marker_path(head)));
    EXPECT_TRUE(state->objects.contains(object_path(head)));
    auto parsed_marker = history::parse_marker_object(layout, marker_path(head));
    ASSERT_TRUE(parsed_marker.has_value());
    EXPECT_EQ(*parsed_marker, head);
}

TEST_F(GcCommitQuarantineFixture, B6_ContentRemainsUntouched) {
    redundant_variant = add_commit(commit, false, "redundant");
    auto orphan = add_orphan_content("orphan_file");
    reset_fake_traffic(*state);

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(state->objects.contains(live_content));
    EXPECT_TRUE(state->objects.contains(orphan));
}

TEST_F(GcCommitQuarantineFixture, B7_QuarantineRemotePayloadMatchesOriginalCiphertext) {
    redundant_variant = add_commit(commit, false, "redundant");
    const auto original_bytes = state->objects[object_path(redundant_variant)];

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());

    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    ASSERT_TRUE(state->objects.contains(payload_path));
    EXPECT_EQ(state->objects[payload_path], original_bytes);
}

TEST_F(GcCommitQuarantineFixture, B8_AuthenticatedMetadataMatchesPreservedPayload) {
    redundant_variant = add_commit(commit, false, "redundant");
    const auto original_bytes = state->objects[object_path(redundant_variant)];

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());

    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    ASSERT_TRUE(state->objects.contains(record_path));
    auto dec = integrity::decode_quarantine_record(state->objects[record_path], test_key(), layout.history_prefix);
    ASSERT_TRUE(dec.has_value());
    EXPECT_EQ(dec->ciphertext_size_bytes, original_bytes.size());
}

TEST_F(GcCommitQuarantineFixture, B9_MixedCandidatesProcessesOnlyCommitVariant) {
    redundant_variant = add_commit(commit, false, "redundant");
    auto orphan = add_orphan_content("orphan_file");

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->commit_candidates, 1U);
    EXPECT_EQ(result->pending_content_candidates, 1U);
    EXPECT_EQ(result->quarantined, 1U);
    EXPECT_TRUE(state->objects.contains(orphan));
}

TEST_F(GcCommitQuarantineFixture, B10_SecondRunRecognizesQuarantineCreatedByFirst) {
    redundant_variant = add_commit(commit, false, "redundant");
    auto res1 = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(res1.has_value());
    EXPECT_EQ(res1->quarantined, 1U);

    auto res2 = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(res2.has_value());
    EXPECT_EQ(res2->commit_candidates, 0U);
    EXPECT_EQ(res2->quarantined, 0U);
}

// ============================================================================
// Grupo C — Ordem de operações
// ============================================================================

TEST_F(GcCommitQuarantineFixture, C1_OriginalNeverRemovedBeforeCopyConfirmation) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    bool copy_happened = false;
    on_operation = [&](std::string_view op, std::string_view id) {
        if (op == "after_copy" && id == payload_path) {
            copy_happened = true;
        }
        if (op == "before_remove" && id == original_path) {
            EXPECT_TRUE(copy_happened);
        }
    };

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(copy_happened);
}

TEST_F(GcCommitQuarantineFixture, C2_OriginalNeverRemovedBeforeMetadataConfirmation) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    bool meta_put = false;
    on_operation = [&](std::string_view op, std::string_view id) {
        if (op == "after_put" && id == record_path) {
            meta_put = true;
        }
        if (op == "before_remove" && id == original_path) {
            EXPECT_TRUE(meta_put);
        }
    };

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(meta_put);
}

TEST_F(GcCommitQuarantineFixture, C3_CopyFailurePreservesOriginal) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    state->copy_failure = kasumi::transport::ErrorCode::Io;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(original_path));
}

TEST_F(GcCommitQuarantineFixture, C4_PayloadReadbackFailurePreservesOriginal) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    state->fail_get_identifier = payload_path;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(original_path));
}

TEST_F(GcCommitQuarantineFixture, C5_TamperedPayloadAfterCopyPreservesOriginal) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    on_operation = [&](std::string_view op, std::string_view id) {
        if (op == "after_copy" && id == payload_path) {
            state->objects[payload_path][0] ^= 0xff;
        }
    };

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(original_path));
}

TEST_F(GcCommitQuarantineFixture, C6_MetadataPutFailurePreservesOriginal) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    state->fail_put_identifier = record_path;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(original_path));
}

TEST_F(GcCommitQuarantineFixture, C7_MetadataReadbackFailurePreservesOriginal) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    state->fail_get_identifier = record_path;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(original_path));
}

TEST_F(GcCommitQuarantineFixture, C8_InconsistentAuthenticatedMetadataPreservesOriginal) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    on_operation = [&](std::string_view op, std::string_view id) {
        if (op == "after_put" && id == record_path) {
            state->objects[record_path][20] ^= 0x01;
        }
    };

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(original_path));
}

TEST_F(GcCommitQuarantineFixture, C9_DestinationCollisionDoesNotOverwriteDifferentContent) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    state->objects[payload_path] = {'d', 'i', 'f', 'f', 'e', 'r', 'e', 'n', 't'};

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(original_path));
}

TEST_F(GcCommitQuarantineFixture, C10_BarrierRemainsAcquiredThroughoutFlow) {
    redundant_variant = add_commit(commit, false, "redundant");

    on_operation = [&](std::string_view op, std::string_view id) {
        if ((op == "before_copy" || op == "before_put" || op == "before_remove") && id != layout.barrier_identifier) {
            EXPECT_TRUE(state->objects.contains(layout.barrier_identifier));
        }
    };

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
}

TEST_F(GcCommitQuarantineFixture, C11_OwnershipLossHaltsMutations) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    on_operation = [&](std::string_view op, std::string_view id) {
        if (op == "after_copy" && id == payload_path) {
            state->objects[layout.barrier_identifier] = {'f', 'o', 'r', 'e', 'i', 'g', 'n'};
        }
    };

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, C12_ObservedWriterHaltsProcessing) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    on_operation = [&](std::string_view op, std::string_view id) {
        if (op == "after_copy" && id == payload_path) {
            state->objects[layout.writers_prefix + "1234567812345678-0001-12345678-0123456789abcdef0123456789abcdef"] = {'w'};
        }
    };

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
}

// ============================================================================
// Grupo D — Falhas de transporte
// ============================================================================

TEST_F(GcCommitQuarantineFixture, D1_ListFailsBeforeSession) {
    state->fail_list = kasumi::transport::ErrorCode::Io;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
}

TEST_F(GcCommitQuarantineFixture, D2_GetOriginalFails) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    state->fail_get_identifier = original_path;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(original_path));
}

TEST_F(GcCommitQuarantineFixture, D3_CorruptedOriginalCiphertextIsRejected) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    state->objects[original_path][state->objects[original_path].size() / 2] ^= 0xff;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(original_path));
}

TEST_F(GcCommitQuarantineFixture, D4_CopyReturnsErrorBeforeCopy) {
    redundant_variant = add_commit(commit, false, "redundant");
    state->copy_failure = kasumi::transport::ErrorCode::Io;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, D5_CopyAppliesButTransportReturnsError) {
    redundant_variant = add_commit(commit, false, "redundant");
    state->copy_failure_after_effect = kasumi::transport::ErrorCode::Io;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, D6_BackendWithoutCopyFallsBackToGetPutSafely) {
    redundant_variant = add_commit(commit, false, "redundant");
    storage.storage.copy = nullptr;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value()) << (result ? "" : result.error().cause.detail);
    EXPECT_EQ(result->quarantined, 1U);
    EXPECT_EQ(result->originals_removed, 1U);
    EXPECT_FALSE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, D7_PutQuarantineReturnsError) {
    redundant_variant = add_commit(commit, false, "redundant");
    storage.storage.copy = nullptr;
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    state->fail_put_identifier = payload_path;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, D8_PutAppliesButResponseLost) {
    redundant_variant = add_commit(commit, false, "redundant");
    storage.storage.copy = nullptr;
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    state->put_then_fail_identifier = payload_path;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, D9_GetDestinationFails) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    state->fail_get_identifier = payload_path;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, D10_DestinationBytesDoNotMatchOriginal) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    state->corrupt_get_identifier = payload_path;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, D11_MetadataPublicationReturnsAmbiguousError) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    state->put_then_fail_identifier = record_path;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, D12_RemoveOriginalFailsBeforeRemove) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    state->fail_remove_identifier = original_path;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(result.error().uncertain_mutation);
    EXPECT_TRUE(state->objects.contains(original_path));
}

TEST_F(GcCommitQuarantineFixture, D13_RemoveOriginalAppliesButReturnsError) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    state->remove_then_fail_identifier = original_path;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(result.error().uncertain_mutation);
}

TEST_F(GcCommitQuarantineFixture, D14_CleanupFailurePreservesOriginalError) {
    redundant_variant = add_commit(commit, false, "redundant");
    state->copy_failure = kasumi::transport::ErrorCode::Io;

    on_operation = [&](std::string_view op, std::string_view) {
        if (op == "before_copy") {
            state->objects[layout.barrier_identifier] = {'b', 'a', 'd'};
        }
    };

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(result.has_value());
    EXPECT_TRUE(result.error().cleanup_error.has_value());
}

TEST_F(GcCommitQuarantineFixture, D15_NoAmbiguousFailureCausesBlindRetry) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    state->fail_remove_identifier = original_path;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(removed_identifiers.size(), 1U);
}

// ============================================================================
// Grupo E — Interrupção e recuperação
// ============================================================================

TEST_F(GcCommitQuarantineFixture, E1_CancellationBeforeCopy) {
    redundant_variant = add_commit(commit, false, "redundant");
    on_operation = [&](std::string_view op, std::string_view) {
        if (op == "before_copy") {
            cancellation::request();
        }
    };

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, Failure::Cancelled);
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, E2_CancellationAfterCopyBeforeMetadata) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    on_operation = [&](std::string_view op, std::string_view id) {
        if (op == "after_copy" && id == payload_path) {
            cancellation::request();
        }
    };

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, Failure::Cancelled);
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, E3_CancellationDuringMetadataPublication) {
    redundant_variant = add_commit(commit, false, "redundant");
    on_operation = [&](std::string_view op, std::string_view id) {
        if (op == "before_put" && id.find(".meta") != std::string_view::npos) {
            cancellation::request();
        }
    };

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, Failure::Cancelled);
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, E4_CancellationAfterMetadataBeforeRemove) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    on_operation = [&](std::string_view op, std::string_view id) {
        if (op == "after_put" && id == record_path) {
            cancellation::request();
        }
    };

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, Failure::Cancelled);
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, E5_CancellationDuringRemove) {
    redundant_variant = add_commit(commit, false, "redundant");
    on_operation = [&](std::string_view op, std::string_view id) {
        if (op == "before_remove" && id == object_path(redundant_variant)) {
            cancellation::request();
        }
    };

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, Failure::Cancelled);
}

TEST_F(GcCommitQuarantineFixture, E6_RerunWithPartialPayloadPreservesOriginal) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    state->objects[payload_path] = state->objects[object_path(redundant_variant)];

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->quarantined, 1U);
    EXPECT_EQ(result->originals_removed, 1U);
    EXPECT_FALSE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, E7_RerunWithCompleteRecordAndPresentOriginalVerifiesBeforeRemoval) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    state->objects[payload_path] = state->objects[object_path(redundant_variant)];
    const auto sha256_hash = kasumi::crypto::physical::hash_file(
        kasumi::test::workspace_path(workspace, "commitredundant.enc"), "sha256").value();

    const integrity::QuarantineRecord rec{
        .format_version = 1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = object_path(redundant_variant),
        .quarantined_payload_identifier = payload_path,
        .commit_id = redundant_variant.commit_id,
        .ciphertext_id = redundant_variant.ciphertext_id,
        .ciphertext_size_bytes = state->objects[payload_path].size(),
        .ciphertext_sha256 = sha256_hash,
        .quarantined_timestamp = 1700000000,
    };
    state->objects[record_path] = integrity::encode_quarantine_record(rec, test_key(), layout.history_prefix).value();

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->quarantined, 1U);
    EXPECT_EQ(result->originals_removed, 1U);
    EXPECT_FALSE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, E8_RerunAfterOriginalRemovedDoesNotDuplicate) {
    redundant_variant = add_commit(commit, false, "redundant");
    auto res1 = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(res1.has_value());
    EXPECT_EQ(res1->quarantined, 1U);

    auto res2 = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(res2.has_value());
    EXPECT_EQ(res2->quarantined, 0U);
}

TEST_F(GcCommitQuarantineFixture, E9_FailureAfterTwoCompleteQuarantinesPreservesPriorResults) {
    auto v1 = add_commit(commit, false, "v1");
    auto v2 = add_commit(commit, false, "v2");
    auto v3 = add_commit(commit, false, "v3");

    state->fail_remove_at = 3;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().quarantined, 2U);
    EXPECT_EQ(result.error().originals_removed, 2U);
}

TEST_F(GcCommitQuarantineFixture, E10_CancellationWithTransportAndCleanupErrorPreservesSeparately) {
    redundant_variant = add_commit(commit, false, "redundant");
    state->copy_failure = kasumi::transport::ErrorCode::Io;

    on_operation = [&](std::string_view op, std::string_view) {
        if (op == "before_copy") {
            cancellation::request();
            state->objects[layout.barrier_identifier] = {'s', 't', 'o', 'l', 'e', 'n'};
        }
    };

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(result.has_value());
    EXPECT_TRUE(result.error().cleanup_error.has_value());
}

TEST_F(GcCommitQuarantineFixture, E11_CorruptedPreexistingQuarantineNeverTreatedAsValid) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    state->objects[payload_path] = {'b', 'a', 'd'};
    state->objects[record_path] = {'n', 'o', 't', 'v', 'a', 'l', 'i', 'd'};

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, E12_TemporaryFilesDoNotLeakAndCleanedUp) {
    redundant_variant = add_commit(commit, false, "redundant");
    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());

    for (const auto& entry : std::filesystem::directory_iterator(kasumi::test::workspace_root(workspace))) {
        const auto filename = entry.path().filename().string();
        EXPECT_EQ(filename.find(".plain"), std::string::npos);
    }
}

// ============================================================================
// Grupo F — Histórico e integridade
// ============================================================================

TEST_F(GcCommitQuarantineFixture, F1_VariantRequiredByHeadRemainsPresent) {
    redundant_variant = add_commit(commit, false, "redundant");
    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(state->objects.contains(object_path(head)));
}

TEST_F(GcCommitQuarantineFixture, F2_VariantRequiredByRetainedAncestorRemainsPresent) {
    const auto commit_a = make_commit(0, {}, "a.txt", "content_a").value();
    const auto a_head = add_commit(commit_a, false, "a_head");
    const auto a_disp = add_commit(commit_a, false, "a_disp");

    const auto commit_b = make_commit(1, {commit_id(commit_a)}, "b.txt", "content_b").value();
    const auto b_head = add_commit(commit_b, true, "b_head");
    state->objects[content("content_a")] = {'a'};
    state->objects[content("content_b")] = {'b'};

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());

    const bool a_head_exists = state->objects.contains(object_path(a_head));
    const bool a_disp_exists = state->objects.contains(object_path(a_disp));
    EXPECT_TRUE(a_head_exists || a_disp_exists);
    EXPECT_TRUE(state->objects.contains(object_path(b_head)));
}

TEST_F(GcCommitQuarantineFixture, F3_RedundantVariantsNotConfusedWithRequired) {
    redundant_variant = add_commit(commit, false, "redundant");
    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->commit_candidates, 1U);
    EXPECT_EQ(result->quarantined, 1U);
    EXPECT_TRUE(state->objects.contains(object_path(head)));
    EXPECT_FALSE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, F4_HistoryCorruptionPreventsDestructiveQuarantine) {
    redundant_variant = add_commit(commit, false, "redundant");
    state->objects[object_path(head)][10] ^= 0xff;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, F5_SnapshotChangeBetweenObservationsPreventsMutation) {
    redundant_variant = add_commit(commit, false, "redundant");

    on_operation = [&](std::string_view op, std::string_view) {
        if (op == "before_list" && state->full_list_count == 1) {
            state->objects[content("new_orphan_during_scan")] = {'n'};
        }
    };

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, Failure::SnapshotChanged);
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, F6_ListOrderDoesNotAffectSelection) {
    redundant_variant = add_commit(commit, false, "redundant");
    state->reverse_listing = true;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->commit_candidates, 1U);
    EXPECT_EQ(result->quarantined, 1U);
    EXPECT_FALSE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, F7_UnknownObjectsNotTreatedAsCommitVariant) {
    auto orphan = add_orphan_content("orphan_not_variant");

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->commit_candidates, 0U);
    EXPECT_TRUE(state->objects.contains(orphan));
}

TEST_F(GcCommitQuarantineFixture, F8_QuarantinedPayloadVerifiableIndependentlyOfOrigin) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    const auto original_bytes = state->objects[original_path];

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());

    EXPECT_FALSE(state->objects.contains(original_path));

    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    const auto preserved_bytes = state->objects[payload_path];
    EXPECT_EQ(preserved_bytes, original_bytes);
}

TEST_F(GcCommitQuarantineFixture, F9_AuthenticatedMetadataAllowsIdentifyingOriginalVariant) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());

    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    auto dec = integrity::decode_quarantine_record(state->objects[record_path], test_key(), layout.history_prefix);
    ASSERT_TRUE(dec.has_value());
    EXPECT_EQ(dec->original_identifier, original_path);
    EXPECT_EQ(dec->commit_id, redundant_variant.commit_id);
    EXPECT_EQ(dec->ciphertext_id, redundant_variant.ciphertext_id);
}

TEST_F(GcCommitQuarantineFixture, F10_NoOperationAltersLogicalMerkleDAG) {
    redundant_variant = add_commit(commit, false, "redundant");
    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());

    auto loaded = history::load_history(storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->commits.size(), 1U);
    EXPECT_EQ(loaded->commits.front().id, commit_id(commit));
}

TEST_F(GcCommitQuarantineFixture, N6_ReexecutionRecognizesPreexistingWithoutIdenticalEnvelope) {
    redundant_variant = add_commit(commit, false, "redundant");
    auto res1 = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(res1.has_value());
    EXPECT_EQ(res1->quarantined, 1U);
    EXPECT_EQ(res1->originals_removed, 1U);

    // Re-run: storage already contains valid quarantined payload and metadata record
    auto res2 = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(res2.has_value());
    EXPECT_EQ(res2->commit_candidates, 0U);
    EXPECT_EQ(res2->quarantined, 0U);
}

TEST_F(GcCommitQuarantineFixture, I11_PreexistingRecordWithValidLayoutAllowsReexecution) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    // Pre-populate payload
    state->objects[payload_path] = state->objects[object_path(redundant_variant)];

    // Pre-populate valid metadata record
    const auto payload_bytes = state->objects[payload_path];
    kasumi::crypto::physical::Sha256State sha_st1 = kasumi::crypto::physical::sha256_init();
    kasumi::crypto::physical::sha256_update(sha_st1, payload_bytes);
    const auto sha256_hash1 = kasumi::crypto::physical::sha256_finish(sha_st1);

    integrity::QuarantineRecord rec{
        .format_version = integrity::quarantine_format_version_1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = object_path(redundant_variant),
        .quarantined_payload_identifier = payload_path,
        .commit_id = redundant_variant.commit_id,
        .ciphertext_id = redundant_variant.ciphertext_id,
        .ciphertext_size_bytes = payload_bytes.size(),
        .ciphertext_sha256 = sha256_hash1,
        .quarantined_timestamp = 1700000000,
    };
    auto enc = integrity::encode_quarantine_record(rec, test_key(), layout.history_prefix);
    ASSERT_TRUE(enc.has_value());
    state->objects[record_path] = *enc;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->commit_candidates, 1U);
    EXPECT_EQ(result->quarantined, 1U);
    EXPECT_EQ(result->originals_removed, 1U);
    EXPECT_FALSE(state->objects.contains(object_path(redundant_variant)));
}

TEST_F(GcCommitQuarantineFixture, I12_PreexistingRecordWithIncompatibleIdentifierNeverAuthorizesRemoval) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    state->objects[payload_path] = state->objects[object_path(redundant_variant)];

    kasumi::crypto::physical::Sha256State sha_st2 = kasumi::crypto::physical::sha256_init();
    kasumi::crypto::physical::sha256_update(sha_st2, state->objects[payload_path]);
    const auto sha256_hash2 = kasumi::crypto::physical::sha256_finish(sha_st2);

    // Pre-populate quarantine record with incompatible original identifier (e.g. extra prefix), but forged valid AEAD
    integrity::QuarantineRecord mismatched_rec{
        .format_version = integrity::quarantine_format_version_1,
        .candidate_type = integrity::QuarantineCandidateType::CommitVariant,
        .original_identifier = "extra/" + object_path(redundant_variant),
        .quarantined_payload_identifier = payload_path,
        .commit_id = redundant_variant.commit_id,
        .ciphertext_id = redundant_variant.ciphertext_id,
        .ciphertext_size_bytes = state->objects[payload_path].size(),
        .ciphertext_sha256 = sha256_hash2,
        .quarantined_timestamp = 1700000000,
    };
    auto forged = forge_quarantine_envelope(mismatched_rec, test_key(), layout.history_prefix);
    state->objects[record_path] = forged;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    // Incompatible identifier in pre-existing record must FAIL and never remove original
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
}

// ============================================================================
// Grupo G — Isolamento de mutações
// ============================================================================

TEST_F(GcCommitQuarantineFixture, G1_CompleteIsolationOfMutations) {
    redundant_variant = add_commit(commit, false, "redundant");
    auto orphan = add_orphan_content("orphan");

    const history::epoch::Epoch epoch_val{
        .vault_id = std::string(64, 'a'),
        .sequence = 0,
        .issued_at = 1,
        .policy = {},
        .anchors = {{.commit_id = head.commit_id, .height = 0}},
    };
    const auto sealed = history::epoch::seal(epoch_val, test_key()).value();
    ASSERT_TRUE(history::epoch::publish(storage, test_key(), sealed, kasumi::test::workspace_root(workspace)));
    const auto epoch_id = history::epoch_object(layout, sealed.reference);

    const auto before_objects = state->objects;
    physical_mutations.clear();

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(result.has_value()) << (result ? "" : result.error().cause.detail);

    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    const std::string orig_path = object_path(redundant_variant);

    // Whitelist check: only barrier create/delete, payload PUT/COPY, record PUT, and orig REMOVE are allowed
    for (const auto& mut : physical_mutations) {
        const bool is_barrier = (mut.target == layout.barrier_identifier);
        const bool is_payload = (mut.target == payload_path && (mut.type == "COPY" || mut.type == "PUT"));
        const bool is_record = (mut.target == record_path && mut.type == "PUT");
        const bool is_orig_remove = (mut.target == orig_path && mut.type == "REMOVE");

        EXPECT_TRUE(is_barrier || is_payload || is_record || is_orig_remove)
            << "Unauthorized mutation: " << mut.type << " on " << mut.target;
    }

    // Byte-by-byte preservation of protected objects
    EXPECT_EQ(state->objects.at(live_content), before_objects.at(live_content));
    EXPECT_EQ(state->objects.at(orphan), before_objects.at(orphan));
    EXPECT_EQ(state->objects.at(marker_path(head)), before_objects.at(marker_path(head)));
    EXPECT_EQ(state->objects.at(epoch_id), before_objects.at(epoch_id));
    EXPECT_EQ(state->objects.at(object_path(head)), before_objects.at(object_path(head)));

    // Quarantined payload and record exist
    EXPECT_TRUE(state->objects.contains(payload_path));
    EXPECT_TRUE(state->objects.contains(record_path));
    EXPECT_FALSE(state->objects.contains(orig_path));

    for (const auto& [id, bytes] : state->objects) {
        if (bytes.size() >= 4) {
            std::string_view magic(reinterpret_cast<const char*>(bytes.data()), 4);
            EXPECT_NE(magic, "KGQ1");
        }
    }
}

TEST_F(GcCommitQuarantineFixture, G2_AdversarialFailurePayloadPutLeavesProtectedObjectsUntouched) {
    redundant_variant = add_commit(commit, false, "redundant");
    auto orphan = add_orphan_content("orphan");
    const auto before_objects = state->objects;

    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    state->copy_failure = kasumi::transport::ErrorCode::Io;
    state->fail_put_identifier = payload_path;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
    EXPECT_EQ(state->objects.at(live_content), before_objects.at(live_content));
    EXPECT_EQ(state->objects.at(orphan), before_objects.at(orphan));
    EXPECT_EQ(state->objects.at(object_path(head)), before_objects.at(object_path(head)));
}

TEST_F(GcCommitQuarantineFixture, G3_AdversarialFailureRecordPutLeavesProtectedObjectsUntouched) {
    redundant_variant = add_commit(commit, false, "redundant");
    auto orphan = add_orphan_content("orphan");
    const auto before_objects = state->objects;

    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    state->fail_put_identifier = record_path;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
    EXPECT_EQ(state->objects.at(live_content), before_objects.at(live_content));
    EXPECT_EQ(state->objects.at(orphan), before_objects.at(orphan));
    EXPECT_EQ(state->objects.at(object_path(head)), before_objects.at(object_path(head)));
}

TEST_F(GcCommitQuarantineFixture, G4_AdversarialFailureReadbackMismatchLeavesOriginalIntact) {
    redundant_variant = add_commit(commit, false, "redundant");
    auto orphan = add_orphan_content("orphan");
    const auto before_objects = state->objects;

    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    on_operation = [&](std::string_view op, std::string_view id) {
        if (op == "after_copy" && id == payload_path) {
            state->objects[payload_path][0] ^= 0xff;
        }
    };

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
    EXPECT_EQ(state->objects.at(live_content), before_objects.at(live_content));
    EXPECT_EQ(state->objects.at(orphan), before_objects.at(orphan));
    EXPECT_EQ(state->objects.at(object_path(head)), before_objects.at(object_path(head)));
}

TEST_F(GcCommitQuarantineFixture, G5_AdversarialFailureLostOwnershipLeavesOriginalIntact) {
    redundant_variant = add_commit(commit, false, "redundant");
    auto orphan = add_orphan_content("orphan");
    const auto before_objects = state->objects;

    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    on_operation = [&](std::string_view op, std::string_view id) {
        if (op == "after_put" && id == record_path) {
            state->objects[layout.barrier_identifier] = {'f', 'o', 'r', 'e', 'i', 'g', 'n'};
        }
    };

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
    EXPECT_EQ(state->objects.at(live_content), before_objects.at(live_content));
    EXPECT_EQ(state->objects.at(orphan), before_objects.at(orphan));
    EXPECT_EQ(state->objects.at(object_path(head)), before_objects.at(object_path(head)));
}

TEST_F(GcCommitQuarantineFixture, G6_AdversarialCancellationLeavesOriginalIntact) {
    redundant_variant = add_commit(commit, false, "redundant");
    auto orphan = add_orphan_content("orphan");
    const auto before_objects = state->objects;

    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    on_operation = [&](std::string_view op, std::string_view id) {
        if (op == "after_put" && id == record_path) {
            cancellation::request();
        }
    };

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(state->objects.contains(object_path(redundant_variant)));
    EXPECT_EQ(state->objects.at(live_content), before_objects.at(live_content));
    EXPECT_EQ(state->objects.at(orphan), before_objects.at(orphan));
    EXPECT_EQ(state->objects.at(object_path(head)), before_objects.at(object_path(head)));
}

TEST_F(GcCommitQuarantineFixture, G7_AmbiguousRemoveFailureLeavesProtectedObjectsUntouched) {
    redundant_variant = add_commit(commit, false, "redundant");
    auto orphan = add_orphan_content("orphan");
    const auto before_objects = state->objects;

    state->fail_remove_identifier = object_path(redundant_variant);

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(result.error().uncertain_mutation);
    EXPECT_EQ(state->objects.at(live_content), before_objects.at(live_content));
    EXPECT_EQ(state->objects.at(orphan), before_objects.at(orphan));
    EXPECT_EQ(state->objects.at(object_path(head)), before_objects.at(object_path(head)));
}

// ============================================================================
// Grupo R — Fechamento de falhas ambíguas e semântica de uncertain_mutation
// ============================================================================

TEST_F(GcCommitQuarantineFixture, R1_CopyAppliedWithTransportErrorProducesUncertainMutation) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    state->copy_failure_after_effect = kasumi::transport::ErrorCode::Io;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, Failure::PayloadCopyFailed);
    EXPECT_TRUE(result.error().uncertain_mutation);
    EXPECT_EQ(result.error().cause.code, integrity::ErrorCode::TransportFailure);
    EXPECT_EQ(result.error().cause.object_identifier, payload_path);

    EXPECT_TRUE(state->objects.contains(original_path));
    EXPECT_TRUE(state->objects.contains(payload_path));
    EXPECT_FALSE(state->objects.contains(record_path));
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
}

TEST_F(GcCommitQuarantineFixture, R2_PutPayloadAppliedWithTransportErrorProducesUncertainMutation) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    storage.storage.copy = nullptr;
    state->put_then_fail_identifier = payload_path;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, Failure::PayloadCopyFailed);
    EXPECT_TRUE(result.error().uncertain_mutation);
    EXPECT_EQ(result.error().cause.code, integrity::ErrorCode::TransportFailure);
    EXPECT_EQ(result.error().cause.object_identifier, payload_path);

    EXPECT_TRUE(state->objects.contains(original_path));
    EXPECT_TRUE(state->objects.contains(payload_path));
    EXPECT_FALSE(state->objects.contains(record_path));
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
}

TEST_F(GcCommitQuarantineFixture, R3_PutMetadataAppliedWithTransportErrorProducesUncertainMutation) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    state->put_then_fail_identifier = record_path;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, Failure::MetadataPublicationFailed);
    EXPECT_TRUE(result.error().uncertain_mutation);
    EXPECT_EQ(result.error().cause.code, integrity::ErrorCode::TransportFailure);
    EXPECT_EQ(result.error().cause.object_identifier, record_path);

    EXPECT_TRUE(state->objects.contains(original_path));
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
}

TEST_F(GcCommitQuarantineFixture, R4_ObservationFailureBeforeMutationHasNoUncertainty) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);

    state->fail_get_identifier = original_path;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, Failure::Observation);
    EXPECT_FALSE(result.error().uncertain_mutation);
    EXPECT_TRUE(state->objects.contains(original_path));
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
}

TEST_F(GcCommitQuarantineFixture, R5_ConfirmedPayloadPublicationWithFailedReadbackHasNoUncertainty) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    state->fail_get_identifier = payload_path;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, Failure::PayloadVerificationFailed);
    EXPECT_FALSE(result.error().uncertain_mutation);
    EXPECT_TRUE(state->objects.contains(original_path));
    EXPECT_EQ(result.error().quarantined, 0U);
    EXPECT_EQ(result.error().originals_removed, 0U);
    EXPECT_FALSE(state->objects.contains(layout.barrier_identifier));
}

TEST_F(GcCommitQuarantineFixture, R6_PublicationFailureWithCleanupFailurePreservesBoth) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    state->put_then_fail_identifier = record_path;

    on_operation = [&](std::string_view op, std::string_view id) {
        if (op == "after_put" && id == record_path) {
            state->objects[layout.barrier_identifier] = {'c', 'o', 'r', 'r', 'u', 'p', 't'};
        }
    };

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, Failure::MetadataPublicationFailed);
    EXPECT_TRUE(result.error().uncertain_mutation);
    EXPECT_EQ(result.error().cause.code, integrity::ErrorCode::TransportFailure);
    EXPECT_EQ(result.error().cause.object_identifier, record_path);
    ASSERT_TRUE(result.error().cleanup_error.has_value());
    EXPECT_TRUE(state->objects.contains(original_path));
}

TEST_F(GcCommitQuarantineFixture, R7_CancellationDuringPutFailurePreservesAllInformation) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    state->put_then_fail_identifier = record_path;

    on_operation = [&](std::string_view op, std::string_view id) {
        if (op == "after_put" && id == record_path) {
            cancellation::request();
        }
    };

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, Failure::Cancelled);
    EXPECT_TRUE(result.error().uncertain_mutation);
    EXPECT_EQ(result.error().cause.code, integrity::ErrorCode::TransportFailure);
    EXPECT_EQ(result.error().cause.object_identifier, record_path);
    EXPECT_TRUE(state->objects.contains(original_path));
}

TEST_F(GcCommitQuarantineFixture, R8_FirstCandidateFailureHaltsProcessingOfSecondCandidate) {
    auto v1 = add_commit(commit, false, "red1");
    auto v2 = add_commit(commit, false, "red2");
    const auto p1 = object_path(v1);
    const auto p2 = object_path(v2);

    const auto first = std::min(p1, p2);
    const auto second = std::max(p1, p2);

    state->copy_failure_after_effect = kasumi::transport::ErrorCode::Io;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, Failure::PayloadCopyFailed);
    EXPECT_TRUE(result.error().uncertain_mutation);
    EXPECT_EQ(result.error().quarantined, 0U);
    EXPECT_EQ(result.error().originals_removed, 0U);

    EXPECT_TRUE(state->objects.contains(first));
    EXPECT_TRUE(state->objects.contains(second));
}

TEST_F(GcCommitQuarantineFixture, R9_ReexecutionAfterAmbiguousCopySucceedsAndRemovesOriginal) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);
    const std::string payload_path = integrity::quarantine_payload_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);
    const std::string record_path = integrity::quarantine_record_object(
        layout.quarantine_prefix, redundant_variant.commit_id, redundant_variant.ciphertext_id);

    state->copy_failure_after_effect = kasumi::transport::ErrorCode::Io;

    auto res1 = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_FALSE(res1.has_value());
    EXPECT_TRUE(res1.error().uncertain_mutation);
    EXPECT_TRUE(state->objects.contains(original_path));
    EXPECT_TRUE(state->objects.contains(payload_path));
    EXPECT_FALSE(state->objects.contains(record_path));

    auto res2 = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));
    ASSERT_TRUE(res2.has_value()) << (res2 ? "" : res2.error().cause.detail);
    EXPECT_EQ(res2->quarantined, 1U);
    EXPECT_EQ(res2->originals_removed, 1U);
    EXPECT_FALSE(state->objects.contains(original_path));
    EXPECT_TRUE(state->objects.contains(payload_path));
    EXPECT_TRUE(state->objects.contains(record_path));
}

TEST_F(GcCommitQuarantineFixture, R10_RemoveFailureRetainsUncertainMutation) {
    redundant_variant = add_commit(commit, false, "redundant");
    const std::string original_path = object_path(redundant_variant);

    state->fail_remove_identifier = original_path;

    auto result = integrity::quarantine_commit_variants_under_barrier(
        storage, test_key(), kasumi::test::workspace_root(workspace));

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, Failure::OriginalRemovalFailed);
    EXPECT_TRUE(result.error().uncertain_mutation);
    EXPECT_EQ(result.error().cause.code, integrity::ErrorCode::TransportFailure);
    EXPECT_EQ(result.error().cause.object_identifier, original_path);
    EXPECT_TRUE(state->objects.contains(original_path));
}

} // namespace
