#include "core/hasher.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/key_derivation.hpp"
#include "crypto/physical_hash.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <vector>

namespace {

TEST(CryptoContentTest, HashesAnEmptyFile) {
    auto workspace = kasumi::test::make_temp_workspace("content-empty");
    const auto file = kasumi::test::workspace_path(workspace, "empty.bin");
    kasumi::test::write_binary(file, std::span<const std::byte>{});

    const auto result = kasumi::crypto::content::hash_file(file);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, kasumi::hasher::hash_string({}));
}

TEST(CryptoContentTest, HashesContentLargerThanTheReadBuffer) {
    auto workspace = kasumi::test::make_temp_workspace("content-large");
    constexpr auto payload_size = 2U * 1024U * 1024U + 257U;
    std::vector<std::byte> payload(payload_size);
    for (std::size_t index = 0; index < payload.size(); ++index) {
        payload[index] = static_cast<std::byte>(index % 251U);
    }
    const auto file = kasumi::test::workspace_path(workspace, "large.bin");
    kasumi::test::write_binary(file, payload);

    const auto expected =
        kasumi::hasher::hash_bytes(payload.data(), payload.size());
    const auto result = kasumi::crypto::content::hash_file(file);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, expected);
}

TEST(CryptoContentTest, MissingFileReturnsAControlledError) {
    auto workspace = kasumi::test::make_temp_workspace("content-missing");
    const auto result = kasumi::crypto::content::hash_file(
        kasumi::test::workspace_path(workspace, "missing.bin"));
    ASSERT_FALSE(result.has_value());
    EXPECT_FALSE(result.error().empty());
    EXPECT_NE(result.error().find("abrir"), std::string::npos);
}

TEST(CryptoPhysicalHashTest, Sha256MatchesKnownVector) {
    auto workspace = kasumi::test::make_temp_workspace("physical-sha256");
    const auto file = kasumi::test::workspace_path(workspace, "payload.bin");
    const std::array<std::byte, 3> payload{static_cast<std::byte>('a'),
                                           static_cast<std::byte>('b'),
                                           static_cast<std::byte>('c')};
    kasumi::test::write_binary(file, payload);

    const auto result = kasumi::crypto::physical::hash_file(file, "sha256");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(
        *result,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(CryptoContentTest, EncryptionReportsHashesOfTheBytesItProcessed) {
    auto workspace = kasumi::test::make_temp_workspace("encrypted-hashes");
    const auto plaintext =
        kasumi::test::workspace_path(workspace, "plaintext.bin");
    const auto ciphertext =
        kasumi::test::workspace_path(workspace, "ciphertext.bin");
    kasumi::test::write_text(plaintext, "exact bytes");
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto encrypted =
        kasumi::crypto::encrypt_file_with_hashes(plaintext, ciphertext, key);

    ASSERT_TRUE(encrypted.has_value());
    EXPECT_EQ(encrypted->plaintext_hash,
              kasumi::hasher::hash_string("exact bytes"));
    EXPECT_EQ(encrypted->plaintext_size, 11U);
    const auto ciphertext_hash =
        kasumi::crypto::physical::hash_file(ciphertext, "sha256");
    ASSERT_TRUE(ciphertext_hash.has_value());
    EXPECT_EQ(encrypted->ciphertext_sha256, *ciphertext_hash);
}

TEST(CryptoFileTest, RoundTripsEmptyAndChunkedFilesWithSeparatedKeys) {
    auto workspace = kasumi::test::make_temp_workspace("crypto-round-trip");
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    auto other_key = key;
    other_key[0] = 1;

    const auto empty = kasumi::test::workspace_path(workspace, "empty");
    const auto empty_cipher =
        kasumi::test::workspace_path(workspace, "empty.enc");
    const auto empty_output =
        kasumi::test::workspace_path(workspace, "empty.out");
    kasumi::test::write_binary(empty, {});
    ASSERT_TRUE(kasumi::crypto::encrypt_file(empty, empty_cipher, key));
    ASSERT_TRUE(kasumi::crypto::decrypt_file(empty_cipher, empty_output, key));
    EXPECT_TRUE(kasumi::test::read_binary(empty_output).empty());

    std::vector<std::byte> payload(kasumi::crypto::CHUNK_SIZE + 257U);
    for (std::size_t index = 0; index < payload.size(); ++index) {
        payload[index] = static_cast<std::byte>(index % 251U);
    }
    const auto plain = kasumi::test::workspace_path(workspace, "plain");
    const auto first = kasumi::test::workspace_path(workspace, "first.enc");
    const auto second = kasumi::test::workspace_path(workspace, "second.enc");
    const auto output = kasumi::test::workspace_path(workspace, "output");
    kasumi::test::write_binary(plain, payload);
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, first, key));
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, second, key));

    const auto first_bytes = kasumi::test::read_binary(first);
    const auto second_bytes = kasumi::test::read_binary(second);
    ASSERT_GE(first_bytes.size(), kasumi::crypto::FILE_HEADER_SIZE);
    ASSERT_GE(second_bytes.size(), kasumi::crypto::FILE_HEADER_SIZE);
    EXPECT_FALSE(std::ranges::equal(
        std::span{first_bytes}.subspan(kasumi::crypto::FILE_MAGIC_SIZE,
                                       kasumi::crypto::NONCE_SIZE),
        std::span{second_bytes}.subspan(kasumi::crypto::FILE_MAGIC_SIZE,
                                        kasumi::crypto::NONCE_SIZE)));

    ASSERT_TRUE(kasumi::crypto::decrypt_file(first, output, key));
    EXPECT_EQ(kasumi::test::read_binary(output), payload);
    EXPECT_FALSE(kasumi::crypto::decrypt_file(first, output, other_key));
    EXPECT_FALSE(std::filesystem::exists(output));

    const auto history = kasumi::test::workspace_path(workspace, "history.enc");
    ASSERT_TRUE(kasumi::crypto::encrypt_file(
        plain, history, key, kasumi::crypto::FilePurpose::History));
    EXPECT_FALSE(kasumi::crypto::decrypt_file(history, output, key));
    ASSERT_TRUE(kasumi::crypto::decrypt_file(
        history, output, key, kasumi::crypto::FilePurpose::History));
    EXPECT_EQ(kasumi::test::read_binary(output), payload);
}

TEST(CryptoFileTest, RejectsTamperingTruncationAppendingAndChunkReordering) {
    auto workspace = kasumi::test::make_temp_workspace("crypto-tampering");
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    std::vector<std::byte> payload(2U * kasumi::crypto::CHUNK_SIZE);
    std::fill_n(payload.begin(), kasumi::crypto::CHUNK_SIZE, std::byte{0x11});
    std::fill(payload.begin() + kasumi::crypto::CHUNK_SIZE,
              payload.end(),
              std::byte{0x22});
    const auto plain = kasumi::test::workspace_path(workspace, "plain");
    const auto cipher = kasumi::test::workspace_path(workspace, "cipher");
    kasumi::test::write_binary(plain, payload);
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, cipher, key));
    const auto original = kasumi::test::read_binary(cipher);

    std::vector<std::pair<std::string, std::vector<std::byte>>> corruptions;
    auto magic = original;
    magic[0] ^= std::byte{1};
    corruptions.emplace_back("magic", std::move(magic));
    auto size = original;
    size[kasumi::crypto::FILE_MAGIC_SIZE + kasumi::crypto::NONCE_SIZE] ^=
        std::byte{1};
    corruptions.emplace_back("size", std::move(size));
    auto header_mac = original;
    header_mac[kasumi::crypto::FILE_HEADER_SIZE - 1] ^= std::byte{1};
    corruptions.emplace_back("header-mac", std::move(header_mac));
    auto chunk = original;
    chunk[kasumi::crypto::FILE_HEADER_SIZE + kasumi::crypto::MAC_SIZE] ^=
        std::byte{1};
    corruptions.emplace_back("chunk", std::move(chunk));
    auto truncated = original;
    truncated.pop_back();
    corruptions.emplace_back("truncated", std::move(truncated));
    auto appended = original;
    appended.push_back(std::byte{0});
    corruptions.emplace_back("appended", std::move(appended));
    auto reordered = original;
    const auto record_size =
        kasumi::crypto::MAC_SIZE + kasumi::crypto::CHUNK_SIZE;
    std::swap_ranges(
        reordered.begin() + kasumi::crypto::FILE_HEADER_SIZE,
        reordered.begin() + kasumi::crypto::FILE_HEADER_SIZE + record_size,
        reordered.begin() + kasumi::crypto::FILE_HEADER_SIZE + record_size);
    corruptions.emplace_back("reordered", std::move(reordered));

    for (const auto& [name, bytes] : corruptions) {
        const auto damaged =
            kasumi::test::workspace_path(workspace, name + ".enc");
        const auto output =
            kasumi::test::workspace_path(workspace, name + ".out");
        kasumi::test::write_binary(damaged, bytes);
        EXPECT_FALSE(kasumi::crypto::decrypt_file(damaged, output, key))
            << name;
        EXPECT_FALSE(std::filesystem::exists(output)) << name;
    }
}

TEST(CryptoKeyDerivationTest, SeparatesEveryDomainAndKeysRemoteIdentifiers) {
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> other_key{};
    other_key[0] = 1;
    const auto content =
        kasumi::crypto::derive_key(key, kasumi::crypto::KeyPurpose::Content);
    const auto history =
        kasumi::crypto::derive_key(key, kasumi::crypto::KeyPurpose::History);
    const auto epoch =
        kasumi::crypto::derive_key(key, kasumi::crypto::KeyPurpose::Epoch);
    const auto journal =
        kasumi::crypto::derive_key(key, kasumi::crypto::KeyPurpose::Journal);
    const auto identifiers = kasumi::crypto::derive_key(
        key, kasumi::crypto::KeyPurpose::RemoteIdentifier);
    EXPECT_NE(content, history);
    EXPECT_NE(content, epoch);
    EXPECT_NE(content, journal);
    EXPECT_NE(content, identifiers);
    EXPECT_NE(history, epoch);
    EXPECT_NE(history, journal);
    EXPECT_NE(history, identifiers);
    EXPECT_NE(epoch, journal);
    EXPECT_NE(epoch, identifiers);
    EXPECT_NE(journal, identifiers);

    const auto plaintext_hash = kasumi::hasher::hash_string("known file");
    const auto first = kasumi::crypto::content_identifier(key, plaintext_hash);
    EXPECT_EQ(first, kasumi::crypto::content_identifier(key, plaintext_hash));
    EXPECT_NE(first, kasumi::hash_hex(plaintext_hash));
    EXPECT_NE(first,
              kasumi::crypto::content_identifier(other_key, plaintext_hash));
    const std::array<std::uint8_t, 32> bytes{};
    EXPECT_NE(first, kasumi::crypto::commit_identifier(key, bytes));
    EXPECT_NE(first, kasumi::crypto::epoch_identifier(key, bytes));
    EXPECT_NE(kasumi::crypto::commit_identifier(key, bytes),
              kasumi::crypto::epoch_identifier(key, bytes));
}

} // namespace
