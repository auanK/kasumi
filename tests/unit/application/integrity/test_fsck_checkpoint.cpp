#include "application/integrity/fsck_checkpoint.hpp"

#include "crypto/key_derivation.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"

#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::application::integrity {
namespace {

std::array<std::uint8_t, crypto::KEY_SIZE> make_test_key(std::uint8_t seed) {
    std::array<std::uint8_t, crypto::KEY_SIZE> key{};
    key.fill(seed);
    return key;
}

CheckpointHeader make_checkpoint_header(
    std::string_view vault_id,
    std::uint64_t entry_count,
    std::uint32_t format_version = checkpoint_format_version_1,
    std::uint32_t audit_semantics_version = checkpoint_audit_semantics_version_1) {
    CheckpointHeader header{};
    header.format_version = format_version;
    header.audit_semantics_version = audit_semantics_version;
    header.vault_id.assign(vault_id);
    header.entry_count = entry_count;
    return header;
}

class FsckCheckpointTest : public ::testing::Test {
protected:
    void SetUp() override {
        const auto temp_root = std::filesystem::temp_directory_path();
        test_dir = temp_root / ("kasumi_fsck_checkpoint_test_" + std::to_string(std::uintptr_t(this)));
        std::filesystem::remove_all(test_dir);
        ASSERT_TRUE(platform::private_storage::create_directory(test_dir));
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(test_dir, ec);
    }

    std::filesystem::path test_dir;
};

TEST_F(FsckCheckpointTest, RoundTripValidCheckpoint) {
    const auto key = make_test_key(0x42);
    FsckCheckpoint original{
        .header = make_checkpoint_header(std::string(64, 'v'), 2),
        .entries = {
            {
                .logical_content_hash = std::string(64, 'a'),
                .remote_content_id = "content_obj_1",
                .plaintext_size = 1024,
                .physical_ciphertext_sha256 = std::string(64, '1'),
            },
            {
                .logical_content_hash = std::string(64, 'b'),
                .remote_content_id = "content_obj_2",
                .plaintext_size = 2048,
                .physical_ciphertext_sha256 = std::string(64, '2'),
            },
        },
    };

    auto encrypted = encrypt_checkpoint(original, key);
    ASSERT_TRUE(encrypted.has_value()) << encrypted.error();

    auto decrypted = decrypt_checkpoint(*encrypted, key);
    ASSERT_TRUE(decrypted.has_value()) << decrypted.error();

    EXPECT_EQ(decrypted->header.format_version, original.header.format_version);
    EXPECT_EQ(decrypted->header.audit_semantics_version, original.header.audit_semantics_version);
    EXPECT_EQ(decrypted->header.vault_id, original.header.vault_id);
    EXPECT_EQ(decrypted->entries.size(), original.entries.size());
    EXPECT_EQ(decrypted->entries, original.entries);
}

TEST_F(FsckCheckpointTest, RejectsWrongKey) {
    const auto key_a = make_test_key(0x01);
    const auto key_b = make_test_key(0x02);

    FsckCheckpoint checkpoint{
        .header = make_checkpoint_header("test-vault-id", 1),
        .entries = {
            {
                .logical_content_hash = std::string(64, 'f'),
                .remote_content_id = "remote_id",
                .plaintext_size = 512,
                .physical_ciphertext_sha256 = std::string(64, '0'),
            },
        },
    };

    auto encrypted = encrypt_checkpoint(checkpoint, key_a);
    ASSERT_TRUE(encrypted.has_value());

    auto decrypted = decrypt_checkpoint(*encrypted, key_b);
    ASSERT_FALSE(decrypted.has_value());
    EXPECT_NE(decrypted.error().find("authentication failed"), std::string::npos);
}

TEST_F(FsckCheckpointTest, RejectsBitFlipInHeaderOrCiphertext) {
    const auto key = make_test_key(0x55);
    FsckCheckpoint checkpoint{
        .header = make_checkpoint_header("test-vault-id-flip", 1),
        .entries = {
            {
                .logical_content_hash = std::string(64, 'c'),
                .remote_content_id = "remote_id",
                .plaintext_size = 4096,
                .physical_ciphertext_sha256 = std::string(64, '9'),
            },
        },
    };

    auto encrypted = encrypt_checkpoint(checkpoint, key);
    ASSERT_TRUE(encrypted.has_value());

    // Test bit flips across various positions: AAD, nonce, MAC, ciphertext
    for (std::size_t offset : std::initializer_list<std::size_t>{
             2ULL, 8ULL, 14ULL, 24ULL, 40ULL, 55ULL, encrypted->size() - 5ULL, encrypted->size() - 1ULL}) {
        auto tampered = *encrypted;
        tampered[offset] ^= 0x01;
        auto result = decrypt_checkpoint(tampered, key);
        EXPECT_FALSE(result.has_value()) << "Bit flip at offset " << offset << " was not rejected!";
    }
}

TEST_F(FsckCheckpointTest, RejectsTruncatedEnvelope) {
    const auto key = make_test_key(0x77);
    FsckCheckpoint checkpoint{
        .header = make_checkpoint_header("vault-truncation", 1),
        .entries = {
            {
                .logical_content_hash = std::string(64, 'd'),
                .remote_content_id = "remote_d",
                .plaintext_size = 128,
                .physical_ciphertext_sha256 = std::string(64, '8'),
            },
        },
    };

    auto encrypted = encrypt_checkpoint(checkpoint, key);
    ASSERT_TRUE(encrypted.has_value());

    // Truncated by 1 byte, 10 bytes, halfway, almost empty
    for (std::size_t cut : std::initializer_list<std::size_t>{
             1ULL, 5ULL, 16ULL, 25ULL, encrypted->size() / 2ULL, encrypted->size() - 5ULL}) {
        std::span<const std::uint8_t> truncated{encrypted->data(), encrypted->size() - cut};
        auto result = decrypt_checkpoint(truncated, key);
        EXPECT_FALSE(result.has_value()) << "Truncation by " << cut << " bytes was not rejected!";
    }
}

TEST_F(FsckCheckpointTest, RejectsUnknownFormatVersion) {
    const auto key = make_test_key(0x88);
    FsckCheckpoint checkpoint{
        .header = make_checkpoint_header("vault-version", 0, 999),
        .entries = {},
    };

    auto encrypted = encrypt_checkpoint(checkpoint, key);
    EXPECT_FALSE(encrypted.has_value());
    EXPECT_NE(encrypted.error().find("unsupported checkpoint format version"), std::string::npos);
}

TEST_F(FsckCheckpointTest, RejectsUnknownAuditSemanticsVersion) {
    const auto key = make_test_key(0x89);
    FsckCheckpoint checkpoint{
        .header = make_checkpoint_header(
            "vault-semantics", 0, checkpoint_format_version_1, 999),
        .entries = {},
    };

    auto encrypted = encrypt_checkpoint(checkpoint, key);
    EXPECT_FALSE(encrypted.has_value());
    EXPECT_NE(encrypted.error().find("unsupported audit semantics version"), std::string::npos);
}

TEST_F(FsckCheckpointTest, RejectsDuplicateEntries) {
    FsckCheckpoint checkpoint{
        .header = make_checkpoint_header("vault-dup", 2),
        .entries = {
            {
                .logical_content_hash = std::string(64, 'a'),
                .remote_content_id = "content_1",
                .plaintext_size = 100,
                .physical_ciphertext_sha256 = std::string(64, '1'),
            },
            {
                .logical_content_hash = std::string(64, 'a'), // DUPLICATE HASH
                .remote_content_id = "content_2",
                .plaintext_size = 200,
                .physical_ciphertext_sha256 = std::string(64, '2'),
            },
        },
    };

    auto encoded = encode_checkpoint_payload(checkpoint);
    EXPECT_FALSE(encoded.has_value());
    EXPECT_NE(encoded.error().find("duplicate entry"), std::string::npos);
}

TEST_F(FsckCheckpointTest, RejectsOversizedCountBounds) {
    CheckpointHeader header{
        .format_version = checkpoint_format_version_1,
        .audit_semantics_version = checkpoint_audit_semantics_version_1,
        .vault_id = "vault-bounds",
        .entry_count = 0,
    };

    // Buffer with 8 bytes claiming 10,000,000 entries, but total size is only 8 bytes
    std::vector<std::uint8_t> buffer(8, 0);
    // Write 10,000,000 in little endian
    const std::uint64_t huge_count = 10'000'000ULL;
    for (std::size_t i = 0; i < 8; ++i) {
        buffer[i] = static_cast<std::uint8_t>((huge_count >> (i * 8)) & 0xffU);
    }

    auto decoded = decode_checkpoint_payload(buffer, header);
    EXPECT_FALSE(decoded.has_value());
    // Should fail with exceeded limit or truncated entries, without crashing or huge allocations
}

TEST_F(FsckCheckpointTest, RejectsTrailingGarbage) {
    CheckpointHeader header{
        .format_version = checkpoint_format_version_1,
        .audit_semantics_version = checkpoint_audit_semantics_version_1,
        .vault_id = "vault-garbage",
        .entry_count = 1,
    };

    FsckCheckpoint checkpoint{
        .header = header,
        .entries = {
            {
                .logical_content_hash = std::string(64, 'e'),
                .remote_content_id = "remote_e",
                .plaintext_size = 50,
                .physical_ciphertext_sha256 = std::string(64, '5'),
            },
        },
    };

    auto encoded = encode_checkpoint_payload(checkpoint);
    ASSERT_TRUE(encoded.has_value());

    // Append 4 bytes of garbage
    encoded->push_back(0xde);
    encoded->push_back(0xad);
    encoded->push_back(0xbe);
    encoded->push_back(0xef);

    auto decoded = decode_checkpoint_payload(*encoded, header);
    EXPECT_FALSE(decoded.has_value());
    EXPECT_NE(decoded.error().find("trailing bytes"), std::string::npos);
}

TEST_F(FsckCheckpointTest, AtomicDurableSaveAndLoad) {
    const auto key = make_test_key(0x33);
    FsckCheckpoint checkpoint{
        .header = make_checkpoint_header("vault-durable", 1),
        .entries = {
            {
                .logical_content_hash = std::string(64, '7'),
                .remote_content_id = "rem_7",
                .plaintext_size = 777,
                .physical_ciphertext_sha256 = std::string(64, '7'),
            },
        },
    };

    // Load before save -> absent (std::nullopt)
    auto initial_load = load_checkpoint(test_dir, key);
    ASSERT_TRUE(initial_load.has_value());
    EXPECT_FALSE(initial_load->has_value());

    // Save checkpoint
    auto saved = save_checkpoint(test_dir, checkpoint, key);
    ASSERT_TRUE(saved.has_value()) << saved.error();

    // Verify file exists
    const auto path = checkpoint_path(test_dir);
    EXPECT_TRUE(std::filesystem::exists(path));

    // Load checkpoint
    auto loaded = load_checkpoint(test_dir, key);
    ASSERT_TRUE(loaded.has_value()) << loaded.error();
    ASSERT_TRUE(loaded->has_value());
    EXPECT_EQ((*loaded)->header.vault_id, checkpoint.header.vault_id);
    EXPECT_EQ((*loaded)->entries, checkpoint.entries);

    // Overwrite atomically with updated checkpoint
    checkpoint.entries.push_back({
        .logical_content_hash = std::string(64, '8'),
        .remote_content_id = "rem_8",
        .plaintext_size = 888,
        .physical_ciphertext_sha256 = std::string(64, '8'),
    });
    saved = save_checkpoint(test_dir, checkpoint, key);
    ASSERT_TRUE(saved.has_value()) << saved.error();

    auto reloaded = load_checkpoint(test_dir, key);
    ASSERT_TRUE(reloaded.has_value());
    ASSERT_TRUE(reloaded->has_value());
    EXPECT_EQ((*reloaded)->entries.size(), 2U);
}

TEST_F(FsckCheckpointTest, LoadRejectsCorruptedFileFailClosed) {
    const auto key = make_test_key(0x33);
    const auto path = checkpoint_path(test_dir);

    // Write random garbage into checkpoint file
    std::ofstream out(path, std::ios::binary);
    std::string garbage = "not_a_valid_encrypted_checkpoint_file_content_at_all";
    out.write(garbage.data(), static_cast<std::streamsize>(garbage.size()));
    out.close();

    auto loaded = load_checkpoint(test_dir, key);
    // Must fail closed with error (not treat as valid empty checkpoint)
    EXPECT_FALSE(loaded.has_value());
}

} // namespace
} // namespace kasumi::application::integrity
