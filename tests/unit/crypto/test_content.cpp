#include "core/hasher.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/key_derivation.hpp"
#include "crypto/physical_hash.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/perf_trace.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <filesystem>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <vector>

namespace {

// Restores the process-wide tracing state even when an assertion fails.
struct ScopedPerfTrace {
    ScopedPerfTrace() : previous_(kasumi::platform::perf_trace::enabled()) {
        kasumi::platform::perf_trace::force_enable(true);
        kasumi::platform::perf_trace::reset();
    }
    ~ScopedPerfTrace() {
        kasumi::platform::perf_trace::reset();
        kasumi::platform::perf_trace::force_enable(previous_);
    }
    ScopedPerfTrace(const ScopedPerfTrace&) = delete;
    ScopedPerfTrace& operator=(const ScopedPerfTrace&) = delete;

  private:
    bool previous_;
};

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
    EXPECT_NE(result.error().find("could not open file"), std::string::npos);
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

TEST(CryptoFileTest, SmallEncryptionUsesPayloadSizedScratchAndRoundTrips) {
    auto workspace = kasumi::test::make_temp_workspace("crypto-small-scratch");
    const auto plaintext =
        kasumi::test::workspace_path(workspace, "plaintext.bin");
    const auto ciphertext =
        kasumi::test::workspace_path(workspace, "ciphertext.bin");
    const auto restored =
        kasumi::test::workspace_path(workspace, "restored.bin");
    constexpr std::size_t payload_size = 4U * 1024U;
    std::vector<std::byte> payload(payload_size, std::byte{0x42});
    kasumi::test::write_binary(plaintext, payload);
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    ScopedPerfTrace trace;
    const auto encrypted =
        kasumi::crypto::encrypt_file_with_hashes(plaintext, ciphertext, key);
    const auto scratch_bytes = kasumi::platform::perf_trace::get_count(
        "file encryption scratch bytes");
    const auto wipe_bytes =
        kasumi::platform::perf_trace::get_count("file encryption wipe bytes");

    ASSERT_TRUE(encrypted.has_value());
    ASSERT_TRUE(kasumi::crypto::decrypt_file(ciphertext, restored, key));
    EXPECT_EQ(kasumi::test::read_binary(restored), payload);
    EXPECT_EQ(scratch_bytes, payload_size * 2U);
    EXPECT_EQ(wipe_bytes, payload_size * 2U);
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

TEST(CryptoFileTest, CoversEveryChunkBoundaryWithPayloadSizedScratch) {
    auto workspace =
        kasumi::test::make_temp_workspace("crypto-chunk-boundaries");
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const std::array<std::size_t, 7> sizes{
        0U,
        1U,
        4U * 1024U,
        kasumi::crypto::CHUNK_SIZE - 1U,
        kasumi::crypto::CHUNK_SIZE,
        kasumi::crypto::CHUNK_SIZE + 1U,
        2U * kasumi::crypto::CHUNK_SIZE + 257U};

    for (const auto size : sizes) {
        SCOPED_TRACE(std::to_string(size));
        std::vector<std::byte> payload(size);
        for (std::size_t index = 0; index < payload.size(); ++index) {
            payload[index] = static_cast<std::byte>((index * 131U + 7U) % 251U);
        }
        const auto suffix = std::to_string(size);
        const auto plaintext =
            kasumi::test::workspace_path(workspace, "plain-" + suffix);
        const auto ciphertext =
            kasumi::test::workspace_path(workspace, "cipher-" + suffix);
        const auto restored =
            kasumi::test::workspace_path(workspace, "restored-" + suffix);
        kasumi::test::write_binary(plaintext, payload);

        ScopedPerfTrace trace;
        const auto encrypted =
            kasumi::crypto::encrypt_file_with_hashes(plaintext, ciphertext, key);
        const auto scratch_bytes = kasumi::platform::perf_trace::get_count(
            "file encryption scratch bytes");
        const auto wipe_bytes =
            kasumi::platform::perf_trace::get_count(
                "file encryption wipe bytes");

        ASSERT_TRUE(encrypted.has_value());
        const auto expected_hash =
            payload.empty()
                ? kasumi::hasher::hash_string({})
                : kasumi::hasher::hash_bytes(payload.data(), payload.size());
        EXPECT_EQ(encrypted->plaintext_hash, expected_hash);
        EXPECT_EQ(encrypted->plaintext_size, size);
        const auto expected_buffer =
            2U * std::min(kasumi::crypto::CHUNK_SIZE, size);
        EXPECT_EQ(scratch_bytes, expected_buffer);
        EXPECT_EQ(wipe_bytes, expected_buffer);

        const auto chunks =
            size == 0 ? 0U : 1U + (size - 1U) / kasumi::crypto::CHUNK_SIZE;
        const auto expected_ciphertext_size = kasumi::crypto::FILE_HEADER_SIZE +
                                              size +
                                              chunks * kasumi::crypto::MAC_SIZE;
        const auto ciphertext_bytes = kasumi::test::read_binary(ciphertext);
        ASSERT_EQ(ciphertext_bytes.size(), expected_ciphertext_size);
        const std::array<std::byte, kasumi::crypto::FILE_MAGIC_SIZE> magic{
            std::byte{'K'},
            std::byte{'A'},
            std::byte{'S'},
            std::byte{'U'},
            std::byte{'M'},
            std::byte{'I'},
            std::byte{2},
            std::byte{0}};
        EXPECT_TRUE(std::ranges::equal(
            std::span{ciphertext_bytes}.first(magic.size()), magic));

        ASSERT_TRUE(kasumi::crypto::decrypt_file(ciphertext, restored, key));
        EXPECT_EQ(kasumi::test::read_binary(restored), payload);
    }
}

TEST(CryptoContentTest, HashesReadBufferBoundaries) {
    auto workspace =
        kasumi::test::make_temp_workspace("content-read-boundaries");
    constexpr std::size_t read_buffer_size = 1024U * 1024U;
    const std::array<std::size_t, 5> sizes{0U,
                                           1U,
                                           read_buffer_size - 1U,
                                           read_buffer_size,
                                           read_buffer_size + 1U};
    for (const auto size : sizes) {
        SCOPED_TRACE(std::to_string(size));
        std::vector<std::byte> payload(size);
        for (std::size_t index = 0; index < payload.size(); ++index) {
            payload[index] = static_cast<std::byte>((index * 17U + 3U) % 251U);
        }
        const auto file = kasumi::test::workspace_path(
            workspace, "hash-" + std::to_string(size));
        kasumi::test::write_binary(file, payload);

        const auto expected =
            payload.empty()
                ? kasumi::hasher::hash_string({})
                : kasumi::hasher::hash_bytes(payload.data(), payload.size());
        const auto result = kasumi::crypto::content::hash_file(file);
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(*result, expected);
    }
}

TEST(CryptoFileTest, OpenFailuresLeaveNoPartialOutputOrModifiedInput) {
    auto workspace = kasumi::test::make_temp_workspace("crypto-open-failures");
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto missing =
        kasumi::test::workspace_path(workspace, "missing.bin");
    const auto missing_output =
        kasumi::test::workspace_path(workspace, "missing.enc");

    std::string detail;
    auto encrypted = kasumi::crypto::encrypt_file_with_hashes(
        missing, missing_output, key, kasumi::crypto::FilePurpose::Content,
        &detail);
    EXPECT_FALSE(encrypted.has_value());
    EXPECT_NE(detail.find("opening plaintext input failed"), std::string::npos);
    EXPECT_FALSE(std::filesystem::exists(missing_output));

    const auto plaintext =
        kasumi::test::workspace_path(workspace, "plaintext.bin");
    const std::vector<std::byte> payload(4096U, std::byte{0x5a});
    kasumi::test::write_binary(plaintext, payload);
    const auto unavailable_output =
        kasumi::test::workspace_path(workspace, "absent-parent");
    const auto invalid_output = unavailable_output / "ciphertext.bin";

    detail.clear();
    encrypted = kasumi::crypto::encrypt_file_with_hashes(
        plaintext, invalid_output, key, kasumi::crypto::FilePurpose::Content,
        &detail);
    EXPECT_FALSE(encrypted.has_value());
    EXPECT_NE(detail.find("creating ciphertext output failed"),
              std::string::npos);
    EXPECT_FALSE(std::filesystem::exists(invalid_output));
    EXPECT_EQ(kasumi::test::read_binary(plaintext), payload);

    const auto restored =
        kasumi::test::workspace_path(workspace, "restored.bin");
    EXPECT_FALSE(kasumi::crypto::decrypt_file(missing, restored, key));
    EXPECT_FALSE(std::filesystem::exists(restored));
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
    const auto checkpoint = kasumi::crypto::derive_key(
        key, kasumi::crypto::KeyPurpose::FsckCheckpoint);
    EXPECT_NE(content, history);
    EXPECT_NE(content, epoch);
    EXPECT_NE(content, journal);
    EXPECT_NE(content, identifiers);
    EXPECT_NE(content, checkpoint);
    EXPECT_NE(history, epoch);
    EXPECT_NE(history, journal);
    EXPECT_NE(history, identifiers);
    EXPECT_NE(history, checkpoint);
    EXPECT_NE(epoch, journal);
    EXPECT_NE(epoch, identifiers);
    EXPECT_NE(epoch, checkpoint);
    EXPECT_NE(journal, identifiers);
    EXPECT_NE(journal, checkpoint);
    EXPECT_NE(identifiers, checkpoint);

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
