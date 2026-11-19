#include "crypto/file_crypto.hpp"

#include "core/wire.hpp"
#include "crypto/physical_hash.hpp"
#include "crypto/secure_memory.hpp"
#include "platform/durability.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"

#include <algorithm>
#include <array>
#include <blake3.h>
#include <cstring>
#include <limits>
#include <monocypher.h>
#include <system_error>
#include <vector>
#include <zstd.h>

namespace kasumi::crypto {
namespace {

inline constexpr std::array<std::uint8_t, FILE_MAGIC_SIZE> format_magic_v3{
    'K', 'A', 'S', 'U', 'M', 'I', 3, 0};
inline constexpr std::size_t header_ad_size_v3 =
    FILE_MAGIC_SIZE + 1 + NONCE_SIZE + sizeof(std::uint64_t);
inline constexpr std::size_t chunk_ad_size_v3 =
    header_ad_size_v3 + 2 * sizeof(std::uint64_t) + CHUNK_PREFIX_SIZE;

KeyPurpose key_purpose_for(FilePurpose purpose) noexcept {
    switch (purpose) {
        case FilePurpose::Content:
            return KeyPurpose::Content;
        case FilePurpose::History:
            return KeyPurpose::History;
        case FilePurpose::Pack:
            return KeyPurpose::Pack;
    }
    return KeyPurpose::Content;
}

std::array<std::uint8_t, header_ad_size_v3>
make_header_ad_v3(FilePurpose purpose,
                  const std::uint8_t* base_nonce,
                  std::uint64_t plaintext_size) noexcept {
    std::array<std::uint8_t, header_ad_size_v3> result{};
    std::copy(format_magic_v3.begin(), format_magic_v3.end(), result.begin());
    result[FILE_MAGIC_SIZE] = static_cast<std::uint8_t>(purpose);
    std::copy_n(base_nonce,
                NONCE_SIZE,
                result.begin() +
                    static_cast<std::ptrdiff_t>(FILE_MAGIC_SIZE + 1));
    wire::encode_le<std::uint64_t>(
        plaintext_size, result.data() + FILE_MAGIC_SIZE + 1 + NONCE_SIZE);
    return result;
}

std::array<std::uint8_t, chunk_ad_size_v3>
make_chunk_ad_v3(std::span<const std::uint8_t, header_ad_size_v3> header,
                 std::uint64_t chunk_index,
                 std::uint64_t plain_size,
                 std::span<const std::uint8_t, CHUNK_PREFIX_SIZE> prefix) noexcept {
    std::array<std::uint8_t, chunk_ad_size_v3> result{};
    std::copy(header.begin(), header.end(), result.begin());
    auto* ptr = result.data() + header.size();
    wire::encode_le<std::uint64_t>(chunk_index, ptr);
    ptr += sizeof(chunk_index);
    wire::encode_le<std::uint64_t>(plain_size, ptr);
    ptr += sizeof(plain_size);
    std::copy(prefix.begin(), prefix.end(), ptr);
    return result;
}

struct CryptoSession {
    std::array<std::uint8_t, NONCE_SIZE> base_nonce{};
    std::array<std::uint8_t, NONCE_SIZE> chunk_nonce{};
    std::array<std::uint8_t, MAC_SIZE> header_mac{};
    std::array<std::uint8_t, MAC_SIZE> mac{};
    std::vector<std::uint8_t> buffer_a;
    std::vector<std::uint8_t> buffer_b;
    std::vector<std::uint8_t> buffer_comp;
    platform::private_storage::PrivateOutputFile file;
    bool published{false};
    unsigned incompressible_streak{0};

    ~CryptoSession() noexcept {
        crypto_wipe(base_nonce.data(), base_nonce.size());
        crypto_wipe(chunk_nonce.data(), chunk_nonce.size());
        crypto_wipe(header_mac.data(), header_mac.size());
        crypto_wipe(mac.data(), mac.size());
        for (auto* buf : {&buffer_a, &buffer_b, &buffer_comp}) {
            if (!buf->empty()) {
                crypto_wipe(buf->data(), buf->size());
            }
        }
        if (!published && !file.published && !file.path.empty()) {
            static_cast<void>(
                platform::private_storage::remove_private_file_if_owned(file));
        } else {
            platform::private_storage::close_private_file(file);
        }
    }

    void resize_v3_encrypt_buffers(std::uint64_t total_size) {
        const auto size = static_cast<std::size_t>(
            std::min<std::uint64_t>(CHUNK_SIZE, total_size));
        buffer_a.resize(size);
        if (size > 0) {
            const auto bound = ZSTD_compressBound(size);
            buffer_b.resize(bound);
            buffer_comp.resize(bound);
        }
    }
};

std::nullopt_t fail_crypto(std::string* error_detail, std::string_view msg) {
    if (error_detail) {
        *error_detail = std::string(msg);
    }
    return std::nullopt;
}

bool at_end(const platform::private_storage::RegularFileInput& input) {
    std::array<std::uint8_t, 1> trailing{};
    secure_memory::WipeGuard guard{trailing};
    const auto count = input.read(trailing);
    return count && *count == 0;
}

std::optional<std::filesystem::path>
prepare_crypto_paths(const std::filesystem::path& input_path,
                     const std::filesystem::path& output_path,
                     bool check_dest_parent,
                     std::string* error_detail) {
    const auto target_path = output_path.has_parent_path()
                                 ? output_path
                                 : (std::filesystem::path(".") / output_path);
    if (input_path.empty() || output_path.empty() ||
        input_path == output_path || input_path == target_path) {
        return fail_crypto(error_detail,
                           "invalid empty or identical input/output paths");
    }

    std::error_code ec;
    const auto in_status = std::filesystem::symlink_status(input_path, ec);
    if (ec || !std::filesystem::is_regular_file(in_status) ||
        platform::private_storage::is_reparse_or_symlink(input_path)) {
        return fail_crypto(error_detail,
                           "opening plaintext input failed: input path is not "
                           "an accessible regular file");
    }

    const auto dest_status = std::filesystem::symlink_status(target_path, ec);
    if (ec) {
        if (ec != std::errc::no_such_file_or_directory) {
            return fail_crypto(error_detail,
                               "failed to query destination path status");
        }
    } else {
        if (std::filesystem::is_directory(dest_status) ||
            std::filesystem::is_symlink(dest_status)) {
            return fail_crypto(
                error_detail,
                "destination cannot be an existing directory or symlink");
        }
        if (std::filesystem::exists(dest_status)) {
            std::error_code eq_error;
            if (std::filesystem::equivalent(
                    input_path, target_path, eq_error) ||
                eq_error) {
                return fail_crypto(
                    error_detail,
                    "destination is an alias or hardlink to the input file");
            }
        }
    }

    if (check_dest_parent) {
        const auto dest_parent = target_path.parent_path();
        if (!dest_parent.empty()) {
            const auto parent_status = std::filesystem::status(dest_parent, ec);
            if (ec || !std::filesystem::is_directory(parent_status)) {
                return fail_crypto(
                    error_detail,
                    "creating ciphertext output failed: destination parent "
                    "directory does not exist or is not a directory");
            }
        }
    }

    return target_path;
}

bool reserve_temp_output(const std::filesystem::path& target_path,
                         platform::private_storage::PrivateOutputFile& out_file,
                         std::string* error_detail) {
    for (std::size_t attempt = 0; attempt < 32; ++attempt) {
        auto id = platform::random::hex_id();
        if (!id) {
            fail_crypto(error_detail, "generating temporary file id failed");
            return false;
        }
        const auto candidate =
            target_path.native().size() + 16 < 260
                ? platform::path::temporary_sibling_path(
                      target_path, ".k_", "." + id->substr(0, 8))
                : target_path.parent_path() /
                      platform::path::from_utf8(".k_" + id->substr(0, 16));
        auto created =
            platform::private_storage::create_private_file(candidate);
        if (created) {
            out_file = std::move(*created);
            return true;
        }
        if (!created.error().is_collision) {
            fail_crypto(error_detail,
                        "creating ciphertext output failed: " +
                            created.error().message);
            return false;
        }
    }
    fail_crypto(error_detail,
                "creating ciphertext output failed: failed to reserve "
                "exclusive temporary file");
    return false;
}

bool close_and_publish_temp(platform::private_storage::RegularFileInput& input,
                            CryptoSession& session,
                            const std::filesystem::path& target_path,
                            bool check_eof,
                            std::string* error_detail) {
    if (check_eof && !at_end(input)) {
        fail_crypto(error_detail, "checking input end failed");
        return false;
    }
    input.handle.close();
    if (!session.file.identity.valid) {
        fail_crypto(error_detail, "temporary file identity is invalid");
        return false;
    }
    auto published = platform::private_storage::publish_private_file(
        session.file, target_path);
    if (session.file.published) {
        session.published = true;
    }
    if (!published) {
        fail_crypto(error_detail,
                    "publishing ciphertext failed: " + published.error());
        return false;
    }
    return true;
}

template <typename Fn>
auto with_derived_key(std::span<const std::uint8_t, KEY_SIZE> master_key,
                      FilePurpose purpose,
                      Fn&& fn) {
    auto key = derive_key(master_key, key_purpose_for(purpose));
    secure_memory::WipeGuard key_guard{key};
    return fn(key);
}

void derive_chunk_nonce(const std::uint8_t* base_nonce,
                        std::uint64_t chunk_index,
                        std::uint8_t* out_nonce) noexcept {
    std::copy_n(base_nonce, NONCE_SIZE, out_nonce);

    for (std::size_t index = 0; index < 8; ++index) {
        out_nonce[NONCE_SIZE - 1 - index] ^=
            static_cast<std::uint8_t>((chunk_index >> (index * 8)) & 0xFFU);
    }
}

bool header_mac_op(std::uint8_t* mac,
                   const std::uint8_t* base_nonce,
                   std::span<const std::uint8_t> header,
                   const std::uint8_t* key,
                   bool lock) noexcept {
    std::array<std::uint8_t, NONCE_SIZE> header_nonce{};
    std::copy_n(base_nonce, NONCE_SIZE, header_nonce.data());
    header_nonce[0] ^= 0x80U;
    std::uint8_t empty = 0;
    bool ok = true;
    if (lock) {
        crypto_aead_lock(&empty,
                         mac,
                         key,
                         header_nonce.data(),
                         header.data(),
                         header.size(),
                         &empty,
                         0);
    } else {
        ok = crypto_aead_unlock(&empty,
                                mac,
                                key,
                                header_nonce.data(),
                                header.data(),
                                header.size(),
                                &empty,
                                0) == 0;
    }
    crypto_wipe(header_nonce.data(), header_nonce.size());
    return ok;
}

bool encrypt_v3_chunk(CryptoSession& session,
                      const Key& key,
                      std::span<const std::uint8_t, header_ad_size_v3> header,
                      std::uint64_t chunk_index,
                      std::span<const std::uint8_t> plain_chunk,
                      std::array<std::uint8_t, CHUNK_PREFIX_SIZE>& prefix,
                      std::uint32_t& wire_len) {
    const std::uint8_t* payload_ptr = plain_chunk.data();
    std::size_t payload_len = plain_chunk.size();
    std::uint8_t flags = 0;
    constexpr std::size_t incompressible_probe_interval = 16U;
    constexpr unsigned incompressible_skip_streak = 2U;
    const bool try_compress =
        !plain_chunk.empty() && !session.buffer_comp.empty() &&
        (session.incompressible_streak < incompressible_skip_streak ||
         (chunk_index % incompressible_probe_interval) == 0U);
    if (try_compress) {
        const auto compressed_size = ZSTD_compress(session.buffer_comp.data(),
                                                   session.buffer_comp.size(),
                                                   plain_chunk.data(),
                                                   plain_chunk.size(),
                                                   1);
        if (!ZSTD_isError(compressed_size) &&
            compressed_size + 32U < plain_chunk.size() &&
            compressed_size <= std::numeric_limits<std::uint32_t>::max()) {
            payload_ptr = session.buffer_comp.data();
            payload_len = compressed_size;
            flags = 1;
            session.incompressible_streak = 0;
        } else if (plain_chunk.size() >= 64U * 1024U) {
            ++session.incompressible_streak;
        }
    }
    if (payload_len > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }
    wire_len = static_cast<std::uint32_t>(payload_len);
    prefix[0] = flags;
    wire::encode_le<std::uint32_t>(wire_len, prefix.data() + 1);

    derive_chunk_nonce(
        session.base_nonce.data(), chunk_index, session.chunk_nonce.data());
    const auto chunk_ad = make_chunk_ad_v3(
        header, chunk_index, plain_chunk.size(), prefix);
    if (session.buffer_b.size() < wire_len) {
        session.buffer_b.resize(wire_len);
    }
    crypto_aead_lock(session.buffer_b.data(),
                     session.mac.data(),
                     key.data(),
                     session.chunk_nonce.data(),
                     chunk_ad.data(),
                     chunk_ad.size(),
                     payload_ptr,
                     wire_len);
    return true;
}

template <typename ReadFn, typename WriteFn, typename AtEofFn>
bool decode_v3_stream(CryptoSession& session,
                      const Key& key,
                      FilePurpose purpose,
                      std::uint64_t input_size,
                      ReadFn&& read_exact,
                      WriteFn&& write_exact,
                      AtEofFn&& at_eof) {
    std::array<std::uint8_t, header_ad_size_v3> header{};
    std::copy(format_magic_v3.begin(), format_magic_v3.end(), header.begin());
    if (!read_exact(header.data() + FILE_MAGIC_SIZE,
                    header_ad_size_v3 - FILE_MAGIC_SIZE)) {
        return false;
    }
    if (header[FILE_MAGIC_SIZE] != static_cast<std::uint8_t>(purpose)) {
        return false;
    }
    std::copy_n(header.data() + FILE_MAGIC_SIZE + 1,
                NONCE_SIZE,
                session.base_nonce.data());
    const auto expected_size = wire::decode_le<std::uint64_t>(
        header.data() + FILE_MAGIC_SIZE + 1 + NONCE_SIZE);
    if (!read_exact(session.header_mac.data(), session.header_mac.size())) {
        return false;
    }

    const auto max_wire_size = encoded_file_size(expected_size);
    if (!max_wire_size || input_size < FILE_HEADER_SIZE ||
        input_size > *max_wire_size ||
        !header_mac_op(session.header_mac.data(),
                       session.base_nonce.data(),
                       header,
                       key.data(),
                       false)) {
        return false;
    }

    std::uint64_t remaining_wire = input_size - FILE_HEADER_SIZE;
    std::uint64_t chunk_index = 0;
    std::uint64_t total_decrypted = 0;
    while (total_decrypted < expected_size) {
        const auto expected_plain_len = static_cast<std::size_t>(
            std::min<std::uint64_t>(CHUNK_SIZE,
                                    expected_size - total_decrypted));
        if (remaining_wire < CHUNK_PREFIX_SIZE + MAC_SIZE) {
            return false;
        }
        std::array<std::uint8_t, CHUNK_PREFIX_SIZE> prefix{};
        if (!read_exact(prefix.data(), prefix.size()) ||
            !read_exact(session.mac.data(), session.mac.size())) {
            return false;
        }
        remaining_wire -= CHUNK_PREFIX_SIZE + MAC_SIZE;

        const std::uint8_t flags = prefix[0];
        const std::uint32_t wire_len =
            wire::decode_le<std::uint32_t>(prefix.data() + 1);
        if (flags > 1U || wire_len == 0U || wire_len > remaining_wire) {
            return false;
        }
        const std::size_t max_chunk_wire =
            flags == 1U ? ZSTD_compressBound(expected_plain_len)
                        : expected_plain_len;
        if ((flags == 0U && wire_len != expected_plain_len) ||
            wire_len > max_chunk_wire) {
            return false;
        }

        if (session.buffer_a.size() < wire_len) {
            session.buffer_a.resize(wire_len);
        }
        if (!read_exact(session.buffer_a.data(), wire_len)) {
            return false;
        }
        remaining_wire -= wire_len;

        derive_chunk_nonce(
            session.base_nonce.data(), chunk_index, session.chunk_nonce.data());
        const auto chunk_ad = make_chunk_ad_v3(
            header, chunk_index, expected_plain_len, prefix);

        if (flags == 1U) {
            if (session.buffer_comp.size() < wire_len) {
                session.buffer_comp.resize(wire_len);
            }
            if (crypto_aead_unlock(session.buffer_comp.data(),
                                   session.mac.data(),
                                   key.data(),
                                   session.chunk_nonce.data(),
                                   chunk_ad.data(),
                                   chunk_ad.size(),
                                   session.buffer_a.data(),
                                   wire_len) != 0) {
                return false;
            }
            if (session.buffer_b.size() < expected_plain_len) {
                session.buffer_b.resize(expected_plain_len);
            }
            const auto decompressed =
                ZSTD_decompress(session.buffer_b.data(),
                                expected_plain_len,
                                session.buffer_comp.data(),
                                wire_len);
            if (ZSTD_isError(decompressed) ||
                decompressed != expected_plain_len) {
                return false;
            }
        } else {
            if (session.buffer_b.size() < expected_plain_len) {
                session.buffer_b.resize(expected_plain_len);
            }
            if (crypto_aead_unlock(session.buffer_b.data(),
                                   session.mac.data(),
                                   key.data(),
                                   session.chunk_nonce.data(),
                                   chunk_ad.data(),
                                   chunk_ad.size(),
                                   session.buffer_a.data(),
                                   wire_len) != 0) {
                return false;
            }
        }

        if (!write_exact(session.buffer_b.data(), expected_plain_len)) {
            return false;
        }
        total_decrypted += expected_plain_len;
        ++chunk_index;
    }

    return remaining_wire == 0U && at_eof();
}

} // namespace

std::optional<std::uint64_t>
encoded_file_size(std::uint64_t plaintext_size) noexcept {
    constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
    const auto chunks = plaintext_size / CHUNK_SIZE +
                        (plaintext_size % CHUNK_SIZE != 0 ? 1 : 0);
    if (plaintext_size > maximum - FILE_HEADER_SIZE) {
        return std::nullopt;
    }
    const auto base = FILE_HEADER_SIZE + plaintext_size;
    constexpr std::uint64_t per_chunk_overhead = CHUNK_PREFIX_SIZE + MAC_SIZE;
    if (chunks > (maximum - base) / per_chunk_overhead) {
        return std::nullopt;
    }
    return base + chunks * per_chunk_overhead;
}

std::optional<std::vector<std::uint8_t>>
encrypt_bytes(std::span<const std::uint8_t> plaintext,
              std::span<const std::uint8_t, KEY_SIZE> master_key,
              FilePurpose purpose) {
    return with_derived_key(
        master_key,
        purpose,
        [&](const Key& key) -> std::optional<std::vector<std::uint8_t>> {
            CryptoSession session;
            if (!platform::random::fill_bytes(session.base_nonce)) {
                return std::nullopt;
            }
            const auto header =
                make_header_ad_v3(purpose, session.base_nonce.data(), plaintext.size());
            header_mac_op(session.header_mac.data(),
                          session.base_nonce.data(),
                          header,
                          key.data(),
                          true);
            session.resize_v3_encrypt_buffers(plaintext.size());

            std::vector<std::uint8_t> output;
            output.reserve(FILE_HEADER_SIZE + plaintext.size());
            output.insert(output.end(), header.begin(), header.end());
            output.insert(output.end(),
                          session.header_mac.begin(),
                          session.header_mac.end());

            std::size_t offset = 0;
            std::uint64_t chunk_index = 0;
            while (offset < plaintext.size()) {
                const auto chunk_size =
                    std::min<std::size_t>(CHUNK_SIZE, plaintext.size() - offset);
                std::array<std::uint8_t, CHUNK_PREFIX_SIZE> prefix{};
                std::uint32_t wire_len = 0;
                if (!encrypt_v3_chunk(session,
                                      key,
                                      header,
                                      chunk_index,
                                      plaintext.subspan(offset, chunk_size),
                                      prefix,
                                      wire_len)) {
                    return std::nullopt;
                }
                output.insert(output.end(), prefix.begin(), prefix.end());
                output.insert(
                    output.end(), session.mac.begin(), session.mac.end());
                output.insert(
                    output.end(),
                    session.buffer_b.data(),
                    session.buffer_b.data() + wire_len);
                offset += chunk_size;
                ++chunk_index;
            }
            return output;
        });
}

std::optional<std::vector<std::uint8_t>>
decrypt_bytes(std::span<const std::uint8_t> ciphertext,
              std::span<const std::uint8_t, KEY_SIZE> master_key,
              FilePurpose purpose) {
    if (ciphertext.size() < FILE_MAGIC_SIZE) {
        return std::nullopt;
    }
    return with_derived_key(
        master_key,
        purpose,
        [&](const Key& key) -> std::optional<std::vector<std::uint8_t>> {
            CryptoSession session;
            std::array<std::uint8_t, FILE_MAGIC_SIZE> magic{};
            std::copy_n(ciphertext.data(), magic.size(), magic.begin());
            std::size_t cursor = magic.size();
            const auto read_exact = [&](std::uint8_t* dst, std::size_t count) {
                if (count > ciphertext.size() - cursor) {
                    return false;
                }
                if (count > 0) {
                    std::memcpy(dst, ciphertext.data() + cursor, count);
                    cursor += count;
                }
                return true;
            };
            std::vector<std::uint8_t> plaintext;
            const auto write_exact = [&](const std::uint8_t* src,
                                         std::size_t count) {
                plaintext.insert(plaintext.end(), src, src + count);
                return true;
            };
            const auto at_eof = [&]() { return cursor == ciphertext.size(); };

            const bool ok = magic == format_magic_v3 &&
                            decode_v3_stream(session,
                                             key,
                                             purpose,
                                             ciphertext.size(),
                                             read_exact,
                                             write_exact,
                                             at_eof);
            if (!ok) {
                if (!plaintext.empty()) {
                    crypto_wipe(plaintext.data(), plaintext.size());
                }
                return std::nullopt;
            }
            return plaintext;
        });
}

namespace {

std::optional<EncryptionResult>
encrypt_file_range(const std::filesystem::path& input_path,
                   std::uint64_t offset,
                   std::optional<std::uint64_t> slice_length,
                   const Hash* expected_slice_hash,
                   const std::filesystem::path& output_path,
                   std::span<const std::uint8_t, KEY_SIZE> master_key,
                   FilePurpose purpose,
                   std::string* error_detail) {
    return with_derived_key(
        master_key,
        purpose,
        [&](const Key& key) -> std::optional<EncryptionResult> {
            const auto prepared_target = prepare_crypto_paths(
                input_path, output_path, true, error_detail);
            if (!prepared_target) {
                return std::nullopt;
            }
            const auto& target_path = *prepared_target;
            CryptoSession session;

            try {
                auto opened =
                    platform::private_storage::open_regular_file(input_path);
                if (!opened) {
                    return fail_crypto(error_detail, opened.error().detail);
                }
                auto& input = *opened;
                const auto file_size = input.size;
                std::uint64_t plaintext_size = file_size;
                if (slice_length) {
                    if (offset > file_size ||
                        *slice_length > file_size - offset) {
                        return fail_crypto(
                            error_detail, "slice range is outside file bounds");
                    }
                    if (!input.seek(offset)) {
                        return fail_crypto(error_detail,
                                           "failed to seek to slice offset");
                    }
                    plaintext_size = *slice_length;
                }

                auto random_result =
                    platform::random::fill_bytes(session.base_nonce);
                if (!random_result) {
                    return fail_crypto(error_detail,
                                       "generating encryption nonce failed: " +
                                           random_result.error());
                }

                const auto header = make_header_ad_v3(
                    purpose, session.base_nonce.data(), plaintext_size);
                header_mac_op(session.header_mac.data(),
                              session.base_nonce.data(),
                              header,
                              key.data(),
                              true);

                session.resize_v3_encrypt_buffers(plaintext_size);
                if (!reserve_temp_output(
                        target_path, session.file, error_detail)) {
                    return std::nullopt;
                }

                auto ciphertext_hash = physical::sha256_init();
                const auto write = [&](const auto* data, std::size_t size) {
                    if (size == 0) {
                        return true;
                    }
                    auto written =
                        platform::private_storage::write_private_file(
                            session.file, data, size);
                    if (!written) {
                        return false;
                    }
                    physical::sha256_update(
                        ciphertext_hash,
                        {reinterpret_cast<const std::uint8_t*>(data), size});
                    return true;
                };

                if (!write(header.data(), header.size()) ||
                    !write(session.header_mac.data(),
                           session.header_mac.size())) {
                    return fail_crypto(error_detail,
                                       "writing ciphertext header failed");
                }

                blake3_hasher plaintext_hash;
                blake3_hasher_init(&plaintext_hash);
                secure_memory::WipeGuard hasher_guard{plaintext_hash};
                std::uint64_t total_read = 0;
                std::uint64_t chunk_index = 0;
                while (total_read < plaintext_size) {
                    const auto chunk_size =
                        static_cast<std::size_t>(std::min<std::uint64_t>(
                            CHUNK_SIZE, plaintext_size - total_read));

                    if (!input.read_exact(
                            std::span{session.buffer_a}.first(chunk_size))) {
                        return fail_crypto(error_detail,
                                           "reading plaintext chunk failed");
                    }
                    blake3_hasher_update(
                        &plaintext_hash, session.buffer_a.data(), chunk_size);

                    std::array<std::uint8_t, CHUNK_PREFIX_SIZE> prefix{};
                    std::uint32_t wire_len = 0;
                    if (!encrypt_v3_chunk(
                            session,
                            key,
                            header,
                            chunk_index,
                            {session.buffer_a.data(), chunk_size},
                            prefix,
                            wire_len)) {
                        return fail_crypto(error_detail,
                                           "encrypting chunk failed");
                    }

                    if (!write(prefix.data(), prefix.size()) ||
                        !write(session.mac.data(), session.mac.size()) ||
                        !write(session.buffer_b.data(), wire_len)) {
                        return fail_crypto(error_detail,
                                           "writing encrypted chunk failed");
                    }

                    total_read += chunk_size;
                    ++chunk_index;
                }

                if (total_read != plaintext_size) {
                    return fail_crypto(
                        error_detail,
                        "plaintext size changed during encryption");
                }

                EncryptionResult result{
                    .plaintext_size = plaintext_size,
                    .ciphertext_sha256 =
                        physical::sha256_finish(ciphertext_hash)};
                blake3_hasher_finalize(&plaintext_hash,
                                       reinterpret_cast<std::uint8_t*>(
                                           result.plaintext_hash.data()),
                                       result.plaintext_hash.size());

                if (expected_slice_hash != nullptr &&
                    result.plaintext_hash != *expected_slice_hash) {
                    return fail_crypto(
                        error_detail,
                        "slice content changed on disk before encryption");
                }

                if (!close_and_publish_temp(input,
                                            session,
                                            target_path,
                                            !slice_length.has_value(),
                                            error_detail)) {
                    return std::nullopt;
                }
                return result;
            } catch (const std::exception& exception) {
                return fail_crypto(
                    error_detail,
                    std::string{"encryption operation failed: "} +
                        exception.what());
            } catch (...) {
                return fail_crypto(
                    error_detail,
                    "encryption operation failed with an unknown error");
            }
        });
}

} // namespace

std::optional<EncryptionResult>
encrypt_file_with_hashes(const std::filesystem::path& input_path,
                         const std::filesystem::path& output_path,
                         std::span<const std::uint8_t, KEY_SIZE> master_key,
                         FilePurpose purpose,
                         std::string* error_detail) {
    return encrypt_file_range(input_path,
                              0,
                              std::nullopt,
                              nullptr,
                              output_path,
                              master_key,
                              purpose,
                              error_detail);
}

std::optional<EncryptionResult>
encrypt_file_slice(const std::filesystem::path& input_path,
                   std::uint64_t offset,
                   std::uint64_t length,
                   const Hash& expected_slice_hash,
                   const std::filesystem::path& output_path,
                   std::span<const std::uint8_t, KEY_SIZE> master_key,
                   FilePurpose purpose,
                   std::string* error_detail) {
    return encrypt_file_range(input_path,
                              offset,
                              length,
                              &expected_slice_hash,
                              output_path,
                              master_key,
                              purpose,
                              error_detail);
}

bool encrypt_file(const std::filesystem::path& input_path,
                  const std::filesystem::path& output_path,
                  std::span<const std::uint8_t, KEY_SIZE> master_key,
                  FilePurpose purpose) {
    return encrypt_file_with_hashes(
               input_path, output_path, master_key, purpose)
        .has_value();
}

bool decrypt_file(const std::filesystem::path& input_path,
                  const std::filesystem::path& output_path,
                  std::span<const std::uint8_t, KEY_SIZE> master_key,
                  FilePurpose purpose) {
    return with_derived_key(master_key, purpose, [&](const Key& key) {
        const auto prepared_target =
            prepare_crypto_paths(input_path, output_path, false, nullptr);
        if (!prepared_target) {
            return false;
        }
        const auto& target_path = *prepared_target;
        CryptoSession session;

        try {
            auto opened =
                platform::private_storage::open_regular_file(input_path);
            if (!opened) {
                return false;
            }
            auto& input = *opened;

            std::array<std::uint8_t, FILE_MAGIC_SIZE> magic{};
            if (!input.read_exact(magic)) {
                return false;
            }

            if (!reserve_temp_output(target_path, session.file, nullptr)) {
                return false;
            }

            const auto read_exact = [&](std::uint8_t* dst, std::size_t count) {
                return input.read_exact({dst, count});
            };
            const auto write_exact = [&](const std::uint8_t* src,
                                         std::size_t count) {
                return count == 0 ||
                       platform::private_storage::write_private_file(
                           session.file, src, count);
            };
            const auto at_eof = [&]() {
                return at_end(input);
            };

            const bool ok =
                magic == format_magic_v3 && decode_v3_stream(session,
                                                             key,
                                                             purpose,
                                                             input.size,
                                                             read_exact,
                                                             write_exact,
                                                             at_eof);
            if (!ok) {
                return false;
            }
            return close_and_publish_temp(
                input, session, target_path, true, nullptr);
        } catch (...) {
            return false;
        }
    });
}

bool decrypt_file_to_sink(const std::filesystem::path& input_path,
                          std::span<const std::uint8_t, KEY_SIZE> master_key,
                          const DecryptedSink& sink,
                          FilePurpose purpose,
                          std::optional<std::uint64_t> expected_plaintext_size,
                          const Hash* expected_plaintext_hash) {
    if (!sink || input_path.empty()) {
        return false;
    }
    std::error_code ec;
    const auto in_status = std::filesystem::symlink_status(input_path, ec);
    if (ec || !std::filesystem::is_regular_file(in_status) ||
        platform::private_storage::is_reparse_or_symlink(input_path)) {
        return false;
    }
    return with_derived_key(master_key, purpose, [&](const Key& key) {
        CryptoSession session;
        try {
            auto opened =
                platform::private_storage::open_regular_file(input_path);
            if (!opened) {
                return false;
            }
            auto& input = *opened;
            if (expected_plaintext_size) {
                const auto max_wire =
                    encoded_file_size(*expected_plaintext_size);
                if (!max_wire || input.size > *max_wire) {
                    return false;
                }
            }

            std::array<std::uint8_t, FILE_MAGIC_SIZE> magic{};
            if (!input.read_exact(magic) || magic != format_magic_v3) {
                return false;
            }

            blake3_hasher digest_hasher;
            blake3_hasher_init(&digest_hasher);
            secure_memory::WipeGuard digest_guard{digest_hasher};
            std::uint64_t total_written = 0;

            const auto read_exact = [&](std::uint8_t* dst, std::size_t count) {
                return input.read_exact({dst, count});
            };
            const auto write_exact = [&](const std::uint8_t* src,
                                         std::size_t count) {
                if (count == 0) {
                    return true;
                }
                if (expected_plaintext_size &&
                    count > *expected_plaintext_size - total_written) {
                    return false;
                }
                if (expected_plaintext_hash != nullptr) {
                    blake3_hasher_update(&digest_hasher, src, count);
                }
                if (!sink(std::span<const std::uint8_t>{src, count})) {
                    return false;
                }
                total_written += count;
                return true;
            };
            const auto at_eof = [&]() {
                return at_end(input);
            };

            if (!decode_v3_stream(session,
                                  key,
                                  purpose,
                                  input.size,
                                  read_exact,
                                  write_exact,
                                  at_eof)) {
                return false;
            }
            if (expected_plaintext_size &&
                total_written != *expected_plaintext_size) {
                return false;
            }
            if (expected_plaintext_hash != nullptr) {
                Hash digest{};
                blake3_hasher_finalize(
                    &digest_hasher,
                    reinterpret_cast<std::uint8_t*>(digest.data()),
                    digest.size());
                if (digest != *expected_plaintext_hash) {
                    return false;
                }
            }
            return true;
        } catch (...) {
            return false;
        }
    });
}

} // namespace kasumi::crypto
