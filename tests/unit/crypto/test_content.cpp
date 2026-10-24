#include "core/hasher.hpp"
#include "crypto/content.hpp"
#if defined(_WIN32)
#include <windows.h>
#endif
#include "crypto/file_crypto.hpp"
#include "crypto/key_derivation.hpp"
#include "crypto/physical_hash.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/perf_trace.hpp"
#include "platform/private_storage.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <filesystem>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <thread>
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

TEST(CryptoContentTest, RecordsConfiguredScratchCapacityAndWipesBuffer) {
    auto workspace = kasumi::test::make_temp_workspace("content-scratch");
    const auto file = kasumi::test::workspace_path(workspace, "payload.bin");
    const std::vector<std::byte> payload(4U * 1024U, std::byte{0x5a});
    kasumi::test::write_binary(file, payload);

    ScopedPerfTrace trace;
    const auto result = kasumi::crypto::content::hash_file(file);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result,
              kasumi::hasher::hash_bytes(payload.data(), payload.size()));
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("content hash scratch bytes"),
        64U * 1024U);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("content hash wipe bytes"),
        64U * 1024U);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("content hash read bytes"),
        payload.size());
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

TEST(CryptoContentTest, DirectoryReadReturnsAControlledError) {
    auto workspace = kasumi::test::make_temp_workspace("content-directory");
    const auto directory = kasumi::test::workspace_path(workspace, "directory");
    std::filesystem::create_directory(directory);

    const auto result = kasumi::crypto::content::hash_file(directory);

    ASSERT_FALSE(result.has_value());
    EXPECT_FALSE(result.error().empty());
}

TEST(CryptoContentTest, AccessDeniedReturnsAControlledError) {
    auto workspace = kasumi::test::make_temp_workspace("content-access-denied");
    const auto file = kasumi::test::workspace_path(workspace, "locked.bin");
    kasumi::test::write_binary(file, {std::byte{0x01}});
#if defined(_WIN32)
    HANDLE lock_handle = ::CreateFileW(file.c_str(),
                                       GENERIC_READ | GENERIC_WRITE,
                                       0,
                                       nullptr,
                                       OPEN_EXISTING,
                                       FILE_ATTRIBUTE_NORMAL,
                                       nullptr);
    ASSERT_NE(lock_handle, INVALID_HANDLE_VALUE);
    const auto result = kasumi::crypto::content::hash_file(file);
    ::CloseHandle(lock_handle);
#else
    std::filesystem::permissions(file,
                                 std::filesystem::perms::none,
                                 std::filesystem::perm_options::replace);
    const auto result = kasumi::crypto::content::hash_file(file);
    std::filesystem::permissions(file,
                                 std::filesystem::perms::all,
                                 std::filesystem::perm_options::replace);
#endif
    ASSERT_FALSE(result.has_value());
    EXPECT_FALSE(result.error().empty());
}

TEST(CryptoContentTest, UsesSixtyFourKilobyteReadChunks) {
    auto workspace = kasumi::test::make_temp_workspace("content-chunks");
    const auto file = kasumi::test::workspace_path(workspace, "chunked.bin");
    constexpr std::size_t payload_size = 64U * 1024U + 1U;
    std::vector<std::byte> payload(payload_size, std::byte{0x7b});
    kasumi::test::write_binary(file, payload);

    ScopedPerfTrace trace;
    const auto result = kasumi::crypto::content::hash_file(file);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result,
              kasumi::hasher::hash_bytes(payload.data(), payload.size()));
    // With a 64 KiB buffer, a (64 KiB + 1 B) payload requires 2 read calls.
    // The 1 MiB buffer reads the entire payload in 1 call.
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("content hash read calls"), 2U);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("content hash read bytes"),
        payload.size());
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
    // Under the transactional safety contract (Etapa 5), a failed decryption
    // must never delete or overwrite a pre-existing destination file.
    EXPECT_FALSE(kasumi::crypto::decrypt_file(first, output, other_key));
    EXPECT_TRUE(std::filesystem::exists(output));
    EXPECT_EQ(kasumi::test::read_binary(output), payload);

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
    const std::array<std::size_t, 7> sizes{0U,
                                           1U,
                                           4U * 1024U,
                                           kasumi::crypto::CHUNK_SIZE - 1U,
                                           kasumi::crypto::CHUNK_SIZE,
                                           kasumi::crypto::CHUNK_SIZE + 1U,
                                           2U * kasumi::crypto::CHUNK_SIZE +
                                               257U};

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
        const auto encrypted = kasumi::crypto::encrypt_file_with_hashes(
            plaintext, ciphertext, key);
        const auto scratch_bytes = kasumi::platform::perf_trace::get_count(
            "file encryption scratch bytes");
        const auto wipe_bytes = kasumi::platform::perf_trace::get_count(
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
        const auto restored_bytes = kasumi::test::read_binary(restored);
        EXPECT_EQ(restored_bytes, payload);
        EXPECT_EQ(kasumi::crypto::content::hash_file(restored), expected_hash);
        EXPECT_EQ(kasumi::test::read_binary(ciphertext), ciphertext_bytes);
        const auto decrypt_scratch_bytes =
            kasumi::platform::perf_trace::get_count(
                "file decryption scratch bytes");
        const auto decrypt_wipe_bytes = kasumi::platform::perf_trace::get_count(
            "file decryption wipe bytes");
        EXPECT_EQ(decrypt_scratch_bytes, expected_buffer);
        EXPECT_EQ(decrypt_wipe_bytes, expected_buffer);
    }
}

TEST(CryptoFileTest, WipesDecryptionBuffersAfterAuthenticatedFailure) {
    auto workspace = kasumi::test::make_temp_workspace("crypto-decrypt-wipe");
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    std::vector<std::byte> payload(kasumi::crypto::CHUNK_SIZE + 257U);
    for (std::size_t index = 0; index < payload.size(); ++index) {
        payload[index] = static_cast<std::byte>((index * 73U + 11U) % 251U);
    }
    const auto plain = kasumi::test::workspace_path(workspace, "plain");
    const auto cipher = kasumi::test::workspace_path(workspace, "cipher");
    kasumi::test::write_binary(plain, payload);
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, cipher, key));
    const auto original = kasumi::test::read_binary(cipher);
    auto corrupted = original;
    corrupted[corrupted.size() - (257U + kasumi::crypto::MAC_SIZE)] ^=
        std::byte{1};
    const auto damaged = kasumi::test::workspace_path(workspace, "damaged");
    const auto output = kasumi::test::workspace_path(workspace, "output");
    kasumi::test::write_binary(damaged, corrupted);

    ScopedPerfTrace trace;
    EXPECT_FALSE(kasumi::crypto::decrypt_file(damaged, output, key));
    EXPECT_FALSE(std::filesystem::exists(output));
    EXPECT_EQ(kasumi::test::read_binary(damaged), corrupted);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "file decryption scratch bytes"),
              2U * kasumi::crypto::CHUNK_SIZE);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("file decryption wipe bytes"),
        2U * kasumi::crypto::CHUNK_SIZE);
}

TEST(CryptoFileTest, WipesDecryptionBuffersAfterOutputCreationFailure) {
    auto workspace =
        kasumi::test::make_temp_workspace("crypto-decrypt-create-failure");
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto plain = kasumi::test::workspace_path(workspace, "plain");
    const auto cipher = kasumi::test::workspace_path(workspace, "cipher");
    kasumi::test::write_text(plain, "output creation failure");
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, cipher, key));
    const auto output =
        kasumi::test::workspace_path(workspace, "absent") / "restored";

    ScopedPerfTrace trace;
    EXPECT_FALSE(kasumi::crypto::decrypt_file(cipher, output, key));
    EXPECT_FALSE(std::filesystem::exists(output));
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "file decryption scratch bytes"),
              2U * 23U);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("file decryption wipe bytes"),
        2U * 23U);
}

TEST(CryptoFileTest, RejectsHeaderMacWithoutAllocatingScratch) {
    auto workspace =
        kasumi::test::make_temp_workspace("crypto-decrypt-header-failure");
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto plain = kasumi::test::workspace_path(workspace, "plain");
    const auto cipher = kasumi::test::workspace_path(workspace, "cipher");
    kasumi::test::write_text(plain, "header authentication");
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, cipher, key));
    auto damaged = kasumi::test::read_binary(cipher);
    damaged[kasumi::crypto::FILE_HEADER_SIZE - 1] ^= std::byte{1};
    const auto damaged_path =
        kasumi::test::workspace_path(workspace, "damaged");
    const auto output = kasumi::test::workspace_path(workspace, "output");
    kasumi::test::write_binary(damaged_path, damaged);

    ScopedPerfTrace trace;
    EXPECT_FALSE(kasumi::crypto::decrypt_file(damaged_path, output, key));
    EXPECT_FALSE(std::filesystem::exists(output));
    EXPECT_EQ(kasumi::platform::perf_trace::get_count(
                  "file decryption scratch bytes"),
              0U);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("file decryption wipe bytes"),
        0U);
}

TEST(CryptoContentTest, HashesReadBufferBoundaries) {
    auto workspace =
        kasumi::test::make_temp_workspace("content-read-boundaries");
    constexpr std::size_t new_buffer_size = 64U * 1024U;
    constexpr std::size_t one_mib = 1024U * 1024U;
    const std::array<std::size_t, 10> sizes{0U,
                                            1U,
                                            4U * 1024U,
                                            new_buffer_size - 1U,
                                            new_buffer_size,
                                            new_buffer_size + 1U,
                                            one_mib - 1U,
                                            one_mib,
                                            one_mib + 1U,
                                            2U * one_mib + 257U};
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
    const auto missing = kasumi::test::workspace_path(workspace, "missing.bin");
    const auto missing_output =
        kasumi::test::workspace_path(workspace, "missing.enc");

    std::string detail;
    auto encrypted = kasumi::crypto::encrypt_file_with_hashes(
        missing,
        missing_output,
        key,
        kasumi::crypto::FilePurpose::Content,
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
        plaintext,
        invalid_output,
        key,
        kasumi::crypto::FilePurpose::Content,
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

TEST(CryptoFileTest, DecryptsLegacyCiphertextFixture) {
    // Produced by the implementation before payload-sized decryption buffers.
    constexpr std::array<std::uint8_t, 98> legacy_ciphertext{
        0x4b, 0x41, 0x53, 0x55, 0x4d, 0x49, 0x02, 0x00, 0x67, 0x01, 0x3a,
        0x08, 0x97, 0x8d, 0x43, 0xb9, 0x26, 0x2a, 0x34, 0x67, 0x59, 0x91,
        0x80, 0x75, 0xa2, 0x60, 0x9d, 0x98, 0x3a, 0x8a, 0x58, 0xcd, 0x1a,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0xfa, 0xfe, 0x81,
        0x23, 0xbe, 0xec, 0xcb, 0x58, 0x71, 0x19, 0x94, 0xa8, 0x17, 0x02,
        0xbe, 0xfa, 0x67, 0x15, 0xff, 0x6d, 0xa2, 0xe0, 0x60, 0xce, 0x82,
        0x63, 0x21, 0xb9, 0x72, 0x56, 0xa3, 0xbd, 0x73, 0x33, 0xab, 0x86,
        0xc7, 0x59, 0x52, 0x42, 0x16, 0x9b, 0x07, 0x4c, 0xfe, 0x94, 0x9c,
        0x81, 0x3e, 0x04, 0xb3, 0xe2, 0xd7, 0xce, 0x99, 0xa8, 0xc4};
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    auto workspace = kasumi::test::make_temp_workspace("crypto-legacy-fixture");
    const auto cipher = kasumi::test::workspace_path(workspace, "cipher");
    const auto restored = kasumi::test::workspace_path(workspace, "restored");
    std::vector<std::byte> fixture;
    fixture.reserve(legacy_ciphertext.size());
    for (const auto byte : legacy_ciphertext) {
        fixture.push_back(static_cast<std::byte>(byte));
    }
    kasumi::test::write_binary(cipher, fixture);

    ASSERT_TRUE(kasumi::crypto::decrypt_file(cipher, restored, key));
    EXPECT_EQ(kasumi::test::read_text(restored), "legacy ciphertext fixture\n");
    EXPECT_EQ(kasumi::test::read_binary(cipher), fixture);
}

TEST(CryptoFileTest, PreservesPreexistingDestinationWhenDecryptionFails) {
    auto workspace =
        kasumi::test::make_temp_workspace("crypto-preserve-preexisting");
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> wrong_key{};
    wrong_key[0] = 0x42;

    const auto plain = kasumi::test::workspace_path(workspace, "plain");
    const auto cipher = kasumi::test::workspace_path(workspace, "cipher.enc");
    const auto destination =
        kasumi::test::workspace_path(workspace, "destination.txt");

    kasumi::test::write_text(plain, "authenticated ciphertext content");
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, cipher, key));

    const std::string sentinel = "important pre-existing user data";
    kasumi::test::write_text(destination, sentinel);

    // Decryption with wrong key must fail and MUST NOT touch or delete the
    // sentinel.
    EXPECT_FALSE(kasumi::crypto::decrypt_file(cipher, destination, wrong_key));
    ASSERT_TRUE(std::filesystem::exists(destination));
    EXPECT_EQ(kasumi::test::read_text(destination), sentinel);
}

TEST(CryptoFileTest,
     RejectsDecryptionWhenInputEqualsOutputWithoutDestroyingCiphertext) {
    auto workspace =
        kasumi::test::make_temp_workspace("crypto-same-input-output");
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto plain = kasumi::test::workspace_path(workspace, "plain");
    const auto cipher = kasumi::test::workspace_path(workspace, "cipher.enc");

    kasumi::test::write_text(plain, "do not destroy self");
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, cipher, key));
    const auto cipher_bytes_before = kasumi::test::read_binary(cipher);

    // In-place decryption where input == output must fail safely without wiping
    // input.
    EXPECT_FALSE(kasumi::crypto::decrypt_file(cipher, cipher, key));
    ASSERT_TRUE(std::filesystem::exists(cipher));
    EXPECT_EQ(kasumi::test::read_binary(cipher), cipher_bytes_before);
}

TEST(CryptoFileTest, PreventsPartialPlaintextPublicationOnMultiChunkFailure) {
    auto workspace =
        kasumi::test::make_temp_workspace("crypto-multi-chunk-failure");
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    std::vector<std::byte> payload(2U * kasumi::crypto::CHUNK_SIZE);
    std::fill_n(payload.begin(), kasumi::crypto::CHUNK_SIZE, std::byte{0xaa});
    std::fill(payload.begin() + kasumi::crypto::CHUNK_SIZE,
              payload.end(),
              std::byte{0xbb});

    const auto plain = kasumi::test::workspace_path(workspace, "plain");
    const auto cipher = kasumi::test::workspace_path(workspace, "cipher.enc");
    const auto destination =
        kasumi::test::workspace_path(workspace, "destination.bin");

    kasumi::test::write_binary(plain, payload);
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, cipher, key));

    auto cipher_bytes = kasumi::test::read_binary(cipher);
    const std::size_t second_chunk_mac_offset =
        kasumi::crypto::FILE_HEADER_SIZE + kasumi::crypto::MAC_SIZE +
        kasumi::crypto::CHUNK_SIZE;
    ASSERT_LT(second_chunk_mac_offset, cipher_bytes.size());
    cipher_bytes[second_chunk_mac_offset] ^= std::byte{0xff};
    kasumi::test::write_binary(cipher, cipher_bytes);

    EXPECT_FALSE(kasumi::crypto::decrypt_file(cipher, destination, key));
    EXPECT_FALSE(std::filesystem::exists(destination));

    for (const auto& entry :
         std::filesystem::directory_iterator(destination.parent_path())) {
        EXPECT_NE(entry.path(), destination);
        EXPECT_TRUE(entry.path() == plain || entry.path() == cipher);
    }
}

TEST(CryptoFileTest,
     SafelyReplacesPreexistingDestinationOnSuccessfulDecryption) {
    auto workspace =
        kasumi::test::make_temp_workspace("crypto-replace-success");
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto plain = kasumi::test::workspace_path(workspace, "plain");
    const auto cipher = kasumi::test::workspace_path(workspace, "cipher.enc");
    const auto destination =
        kasumi::test::workspace_path(workspace, "destination.txt");

    kasumi::test::write_text(plain, "new freshly decrypted data");
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, cipher, key));

    kasumi::test::write_text(destination, "old stale data to be replaced");

    ASSERT_TRUE(kasumi::crypto::decrypt_file(cipher, destination, key));
    EXPECT_TRUE(std::filesystem::exists(destination));
    EXPECT_EQ(kasumi::test::read_text(destination),
              "new freshly decrypted data");
}

TEST(CryptoFileTest,
     PreservesPreexistingDestinationWhenMultiChunkDecryptionFails) {
    auto workspace =
        kasumi::test::make_temp_workspace("crypto-multi-chunk-preserve");
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    std::vector<std::byte> payload(2U * kasumi::crypto::CHUNK_SIZE);
    std::fill_n(payload.begin(), kasumi::crypto::CHUNK_SIZE, std::byte{0x33});
    std::fill(payload.begin() + kasumi::crypto::CHUNK_SIZE,
              payload.end(),
              std::byte{0x44});

    const auto plain = kasumi::test::workspace_path(workspace, "plain");
    const auto cipher = kasumi::test::workspace_path(workspace, "cipher.enc");
    const auto destination =
        kasumi::test::workspace_path(workspace, "destination.bin");

    kasumi::test::write_binary(plain, payload);
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, cipher, key));

    auto cipher_bytes = kasumi::test::read_binary(cipher);
    const std::size_t second_chunk_mac_offset =
        kasumi::crypto::FILE_HEADER_SIZE + kasumi::crypto::MAC_SIZE +
        kasumi::crypto::CHUNK_SIZE;
    ASSERT_LT(second_chunk_mac_offset, cipher_bytes.size());
    cipher_bytes[second_chunk_mac_offset] ^= std::byte{0xff};
    kasumi::test::write_binary(cipher, cipher_bytes);

    const std::vector<std::byte> sentinel_payload{
        std::byte{0xde}, std::byte{0xad}, std::byte{0xbe}, std::byte{0xef}};
    kasumi::test::write_binary(destination, sentinel_payload);

    EXPECT_FALSE(kasumi::crypto::decrypt_file(cipher, destination, key));
    ASSERT_TRUE(std::filesystem::exists(destination));
    EXPECT_EQ(kasumi::test::read_binary(destination), sentinel_payload);
}

TEST(CryptoFileTest, RejectsDecryptionWhenDestinationIsDirectory) {
    auto workspace = kasumi::test::make_temp_workspace("crypto-dest-is-dir");
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto plain = kasumi::test::workspace_path(workspace, "plain");
    const auto cipher = kasumi::test::workspace_path(workspace, "cipher.enc");
    const auto dir_dest = kasumi::test::workspace_path(workspace, "target_dir");

    kasumi::test::write_text(plain, "content for dir test");
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, cipher, key));
    std::filesystem::create_directories(dir_dest);

    EXPECT_FALSE(kasumi::crypto::decrypt_file(cipher, dir_dest, key));
    EXPECT_TRUE(std::filesystem::is_directory(dir_dest));
}

TEST(CryptoFileTest,
     ConcurrentDecryptionsToSameDestinationPreserveIntegrityWithoutColliding) {
    auto workspace =
        kasumi::test::make_temp_workspace("crypto-concurrent-decrypt");
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto plain1 = kasumi::test::workspace_path(workspace, "plain1.txt");
    const auto plain2 = kasumi::test::workspace_path(workspace, "plain2.txt");
    const auto cipher1 = kasumi::test::workspace_path(workspace, "cipher1.enc");
    const auto cipher2 = kasumi::test::workspace_path(workspace, "cipher2.enc");
    const auto destination =
        kasumi::test::workspace_path(workspace, "destination.txt");

    const std::string content1(4096, 'A');
    const std::string content2(4096, 'B');
    kasumi::test::write_text(plain1, content1);
    kasumi::test::write_text(plain2, content2);
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain1, cipher1, key));
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain2, cipher2, key));

    std::atomic<bool> start_gate{false};
    bool res1 = false;
    bool res2 = false;

    std::thread t1([&] {
        while (!start_gate.load(std::memory_order_acquire)) {
        }
        res1 = kasumi::crypto::decrypt_file(cipher1, destination, key);
    });

    std::thread t2([&] {
        while (!start_gate.load(std::memory_order_acquire)) {
        }
        res2 = kasumi::crypto::decrypt_file(cipher2, destination, key);
    });

    start_gate.store(true, std::memory_order_release);
    t1.join();
    t2.join();

    // In a concurrent publication race on the same destination, at least one
    // operation must succeed, and neither operation may corrupt the destination
    // or publish partial plaintext. Any failed publication fails closed.
    EXPECT_TRUE(res1 || res2);
    ASSERT_TRUE(std::filesystem::exists(destination));
    const auto final_content = kasumi::test::read_text(destination);
    EXPECT_TRUE(final_content == content1 || final_content == content2);

    for (const auto& entry :
         std::filesystem::directory_iterator(destination.parent_path())) {
        const auto p = entry.path();
        EXPECT_TRUE(p == plain1 || p == plain2 || p == cipher1 ||
                    p == cipher2 || p == destination);
    }
}

TEST(CryptoFileTest,
     CleanupRefusesToRemoveSubstitutedFileWithMismatchedIdentity) {
    auto workspace =
        kasumi::test::make_temp_workspace("crypto-cleanup-identity");
    const auto temp_path = kasumi::test::workspace_path(workspace, "temp.bin");
    const auto victim_path =
        kasumi::test::workspace_path(workspace, "victim.bin");

    kasumi::test::write_text(victim_path, "do not delete this external file");

    auto created =
        kasumi::platform::private_storage::create_private_file(temp_path);
    ASSERT_TRUE(created.has_value());
    ASSERT_TRUE(created->identity.valid);

    // Close the handle and simulate substitution of temp_path with victim_path
    // (or hard link)
    kasumi::platform::private_storage::close_private_file(*created);
    std::error_code ec;
    std::filesystem::remove(temp_path, ec);
    ASSERT_FALSE(ec);
    std::filesystem::create_hard_link(victim_path, temp_path, ec);
    ASSERT_FALSE(ec);

    // Now invoke cleanup on created:
    const auto cleanup_result =
        kasumi::platform::private_storage::remove_private_file_if_owned(
            *created);
    EXPECT_EQ(
        cleanup_result,
        kasumi::platform::private_storage::CleanupResult::IdentityMismatch);
    ASSERT_TRUE(std::filesystem::exists(victim_path));
    EXPECT_EQ(kasumi::test::read_text(victim_path),
              "do not delete this external file");
    ASSERT_TRUE(std::filesystem::exists(temp_path));
}

TEST(CryptoFileTest,
     MissingDestinationParentFailsWithoutCreatingOutput) {
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    auto workspace = kasumi::test::make_temp_workspace("retry-policy");
    const auto plain = kasumi::test::workspace_path(workspace, "plain.txt");
    const auto cipher = kasumi::test::workspace_path(workspace, "cipher.enc");
    kasumi::test::write_text(plain, "retry test content");
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, cipher, key));
    const auto cipher_before = kasumi::test::read_text(cipher);

    // Target parent directory does not exist
    const auto destination = kasumi::test::workspace_path(
        workspace, "nonexistent_parent_dir/destination.txt");

    EXPECT_FALSE(kasumi::crypto::decrypt_file(cipher, destination, key));
    EXPECT_FALSE(std::filesystem::exists(destination));
    EXPECT_EQ(kasumi::test::read_text(cipher), cipher_before);

    std::size_t entry_count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(
             kasumi::test::workspace_root(workspace))) {
        (void)entry;
        ++entry_count;
    }
    EXPECT_EQ(entry_count, 2U);
}

TEST(CryptoFileTest, DecryptsToNonexistentDestination) {
    auto workspace =
        kasumi::test::make_temp_workspace("crypto-decrypt-nonexistent-dest");
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto plain = kasumi::test::workspace_path(workspace, "plain.txt");
    const auto cipher = kasumi::test::workspace_path(workspace, "cipher.enc");
    const auto destination =
        kasumi::test::workspace_path(workspace, "new_destination.txt");

    kasumi::test::write_text(plain, "freshly decrypted secret message");
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, cipher, key));

    ASSERT_FALSE(std::filesystem::exists(destination));
    ASSERT_TRUE(kasumi::crypto::decrypt_file(cipher, destination, key));
    EXPECT_TRUE(std::filesystem::exists(destination));
    EXPECT_EQ(kasumi::test::read_text(destination),
              "freshly decrypted secret message");
}

TEST(CryptoFileTest, RejectsDestinationInspectionFailureWithoutMutation) {
    auto workspace =
        kasumi::test::make_temp_workspace("crypto-dest-inspection-failure");
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto plain = kasumi::test::workspace_path(workspace, "plain.txt");
    const auto cipher = kasumi::test::workspace_path(workspace, "cipher.enc");
    const auto regular_comp =
        kasumi::test::workspace_path(workspace, "regular_file_as_dir");
    const auto destination = regular_comp / "child.txt";

    kasumi::test::write_text(plain, "plain text payload");
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, cipher, key));
    kasumi::test::write_text(regular_comp, "do not overwrite component");
    const auto cipher_before = kasumi::test::read_text(cipher);

    EXPECT_FALSE(kasumi::crypto::decrypt_file(cipher, destination, key));
    EXPECT_TRUE(std::filesystem::is_regular_file(regular_comp));
    EXPECT_EQ(kasumi::test::read_text(regular_comp),
              "do not overwrite component");
    EXPECT_EQ(kasumi::test::read_text(cipher), cipher_before);
    EXPECT_FALSE(std::filesystem::exists(destination));

    std::size_t entry_count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(
             kasumi::test::workspace_root(workspace))) {
        (void)entry;
        ++entry_count;
    }
    EXPECT_EQ(entry_count, 3U);
}

TEST(CryptoFileTest, RejectsSameFileThroughAlias) {
    auto workspace =
        kasumi::test::make_temp_workspace("crypto-same-file-alias");
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto plain = kasumi::test::workspace_path(workspace, "plain.txt");
    const auto cipher = kasumi::test::workspace_path(workspace, "cipher.enc");
    const auto alias =
        kasumi::test::workspace_path(workspace, "cipher_hardlink.enc");

    kasumi::test::write_text(plain, "alias safety check payload");
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, cipher, key));

    std::error_code link_ec;
    std::filesystem::create_hard_link(cipher, alias, link_ec);
    if (link_ec) {
        GTEST_SKIP() << "Hard links not supported in this filesystem: "
                     << link_ec.message();
    }

    const auto cipher_before = kasumi::test::read_text(cipher);
    EXPECT_FALSE(kasumi::crypto::decrypt_file(cipher, alias, key));
    EXPECT_TRUE(std::filesystem::exists(cipher));
    EXPECT_EQ(kasumi::test::read_text(cipher), cipher_before);
    EXPECT_EQ(kasumi::test::read_text(alias), cipher_before);
}

TEST(CryptoFileTest, RejectsSymlinkDestinationWithoutChangingTarget) {
    auto workspace =
        kasumi::test::make_temp_workspace("crypto-dest-symlink-reject");
    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};

    const auto plain = kasumi::test::workspace_path(workspace, "plain.txt");
    const auto cipher = kasumi::test::workspace_path(workspace, "cipher.enc");
    const auto victim_target =
        kasumi::test::workspace_path(workspace, "victim_target.txt");
    const auto symlink_dest =
        kasumi::test::workspace_path(workspace, "symlink_dest.lnk");

    kasumi::test::write_text(plain, "payload meant for destination");
    ASSERT_TRUE(kasumi::crypto::encrypt_file(plain, cipher, key));
    kasumi::test::write_text(victim_target, "victim content untouched");

    std::error_code symlink_ec;
    std::filesystem::create_symlink(victim_target, symlink_dest, symlink_ec);
    if (symlink_ec) {
        GTEST_SKIP()
            << "Symlink creation not supported without elevated privileges: "
            << symlink_ec.message();
    }

    EXPECT_FALSE(kasumi::crypto::decrypt_file(cipher, symlink_dest, key));
    EXPECT_TRUE(std::filesystem::is_symlink(
        std::filesystem::symlink_status(symlink_dest)));
    EXPECT_EQ(kasumi::test::read_text(victim_target),
              "victim content untouched");
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
