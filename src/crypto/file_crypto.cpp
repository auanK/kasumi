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
#include <fstream>
#include <limits>
#include <monocypher.h>
#include <system_error>
#include <vector>

namespace kasumi::crypto {

namespace {

inline constexpr std::array<std::uint8_t, 8> format_magic{
    'K', 'A', 'S', 'U', 'M', 'I', 2, 0};
inline constexpr std::size_t header_ad_size =
    format_magic.size() + NONCE_SIZE + sizeof(std::uint64_t);
inline constexpr std::size_t chunk_ad_size =
    header_ad_size + 2 * sizeof(std::uint64_t);

std::array<std::uint8_t, header_ad_size>
make_header_ad(const std::uint8_t* base_nonce,
               std::uint64_t plaintext_size) noexcept {
    std::array<std::uint8_t, header_ad_size> result{};
    std::copy(format_magic.begin(), format_magic.end(), result.begin());
    std::copy_n(base_nonce,
                NONCE_SIZE,
                result.begin() +
                    static_cast<std::ptrdiff_t>(format_magic.size()));
    wire::encode_le<std::uint64_t>(
        plaintext_size, result.data() + format_magic.size() + NONCE_SIZE);
    return result;
}

std::array<std::uint8_t, chunk_ad_size>
make_chunk_ad(const std::array<std::uint8_t, header_ad_size>& header,
              std::uint64_t chunk_index,
              std::uint64_t chunk_size) noexcept {
    std::array<std::uint8_t, chunk_ad_size> result{};
    std::copy(header.begin(), header.end(), result.begin());
    wire::encode_le<std::uint64_t>(chunk_index, result.data() + header.size());
    wire::encode_le<std::uint64_t>(
        chunk_size, result.data() + header.size() + sizeof(chunk_index));
    return result;
}

struct CryptoSession {
    std::array<std::uint8_t, NONCE_SIZE> base_nonce{};
    std::array<std::uint8_t, NONCE_SIZE> chunk_nonce{};
    std::array<std::uint8_t, MAC_SIZE> header_mac{};
    std::array<std::uint8_t, MAC_SIZE> mac{};
    std::vector<char> read_buffer;
    std::vector<std::uint8_t> buffer_a;
    std::vector<std::uint8_t> buffer_b;
    platform::private_storage::PrivateOutputFile file;
    bool published{false};

    ~CryptoSession() noexcept {
        crypto_wipe(base_nonce.data(), base_nonce.size());
        crypto_wipe(chunk_nonce.data(), chunk_nonce.size());
        crypto_wipe(header_mac.data(), header_mac.size());
        crypto_wipe(mac.data(), mac.size());
        for (auto* buf : {&buffer_a, &buffer_b}) {
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

    void resize_buffers(std::uint64_t total_size) {
        const auto size = static_cast<std::size_t>(
            std::min<std::uint64_t>(CHUNK_SIZE, total_size));
        buffer_a.resize(size);
        buffer_b.resize(size);
    }
};

std::nullopt_t fail_crypto(std::string* error_detail, std::string_view msg) {
    if (error_detail) {
        *error_detail = std::string(msg);
    }
    return std::nullopt;
}

std::optional<std::pair<std::ifstream, std::uint64_t>>
open_input_sized(const std::filesystem::path& input_path,
                 std::vector<char>& stream_buffer,
                 std::string* error_detail) {
    constexpr std::size_t io_buffer_size = 256U * 1024U;
    stream_buffer.resize(io_buffer_size);
    std::ifstream input;
    input.rdbuf()->pubsetbuf(
        stream_buffer.data(),
        static_cast<std::streamsize>(stream_buffer.size()));
    input.open(input_path, std::ios::binary | std::ios::ate);
    if (!input) {
        return fail_crypto(error_detail, "opening plaintext input failed");
    }
    const auto end_position = input.tellg();
    const auto stream_size = static_cast<std::streamoff>(end_position);
    if (end_position < std::streampos{0} || stream_size < 0) {
        return fail_crypto(error_detail, "reading plaintext size failed");
    }
    const auto input_size = static_cast<std::uintmax_t>(stream_size);
    if (input_size > static_cast<std::uintmax_t>(
                         std::numeric_limits<std::uint64_t>::max())) {
        return fail_crypto(error_detail, "plaintext size is unsupported");
    }
    input.seekg(0, std::ios::beg);
    if (!input) {
        return fail_crypto(error_detail, "seeking plaintext input failed");
    }
    return std::pair{std::move(input), static_cast<std::uint64_t>(input_size)};
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
    const auto in_status = std::filesystem::status(input_path, ec);
    if (ec || !std::filesystem::is_regular_file(in_status)) {
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

bool close_and_publish_temp(std::ifstream& input,
                            CryptoSession& session,
                            const std::filesystem::path& target_path,
                            std::string* error_detail) {
    char trailing = 0;
    input.read(&trailing, 1);
    if (input.gcount() != 0 || input.bad()) {
        fail_crypto(error_detail, "checking plaintext end failed");
        return false;
    }
    input.clear();
    input.close();
    if (input.fail()) {
        fail_crypto(error_detail, "closing plaintext input failed");
        return false;
    }
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
    auto key =
        derive_key(master_key,
                   purpose == FilePurpose::Content ? KeyPurpose::Content
                                                   : KeyPurpose::History);
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
                   std::span<const std::uint8_t, header_ad_size> header,
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
    if (chunks > (maximum - base) / MAC_SIZE) {
        return std::nullopt;
    }
    return base + chunks * MAC_SIZE;
}

std::optional<EncryptionResult>
encrypt_file_with_hashes(const std::filesystem::path& input_path,
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
                auto opened = open_input_sized(
                    input_path, session.read_buffer, error_detail);
                if (!opened) {
                    return std::nullopt;
                }
                auto& [input, plaintext_size] = *opened;

                auto random_result =
                    platform::random::fill_bytes(session.base_nonce);
                if (!random_result) {
                    return fail_crypto(error_detail,
                                       "generating encryption nonce failed: " +
                                           random_result.error());
                }

                const auto header =
                    make_header_ad(session.base_nonce.data(), plaintext_size);
                header_mac_op(session.header_mac.data(),
                              session.base_nonce.data(),
                              header,
                              key.data(),
                              true);

                session.resize_buffers(plaintext_size);
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

                    input.read(reinterpret_cast<char*>(session.buffer_a.data()),
                               static_cast<std::streamsize>(chunk_size));
                    if (input.gcount() !=
                            static_cast<std::streamsize>(chunk_size) ||
                        input.bad()) {
                        return fail_crypto(error_detail,
                                           "reading plaintext chunk failed");
                    }
                    blake3_hasher_update(
                        &plaintext_hash, session.buffer_a.data(), chunk_size);

                    derive_chunk_nonce(session.base_nonce.data(),
                                       chunk_index,
                                       session.chunk_nonce.data());
                    const auto chunk_ad =
                        make_chunk_ad(header, chunk_index, chunk_size);
                    crypto_aead_lock(session.buffer_b.data(),
                                     session.mac.data(),
                                     key.data(),
                                     session.chunk_nonce.data(),
                                     chunk_ad.data(),
                                     chunk_ad.size(),
                                     session.buffer_a.data(),
                                     chunk_size);

                    if (!write(session.mac.data(), session.mac.size()) ||
                        !write(session.buffer_b.data(), chunk_size)) {
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

                if (!close_and_publish_temp(
                        input, session, target_path, error_detail)) {
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
                open_input_sized(input_path, session.read_buffer, nullptr);
            if (!opened) {
                return false;
            }
            auto& [input, input_size] = *opened;

            std::array<std::uint8_t, header_ad_size> header{};
            input.read(reinterpret_cast<char*>(header.data()),
                       static_cast<std::streamsize>(header.size()));
            if (input.gcount() != static_cast<std::streamsize>(header.size()) ||
                !std::equal(
                    format_magic.begin(), format_magic.end(), header.begin())) {
                return false;
            }

            std::copy_n(header.data() + format_magic.size(),
                        session.base_nonce.size(),
                        session.base_nonce.data());
            const auto expected_size = wire::decode_le<std::uint64_t>(
                header.data() + format_magic.size() + NONCE_SIZE);

            input.read(reinterpret_cast<char*>(session.header_mac.data()),
                       static_cast<std::streamsize>(session.header_mac.size()));
            if (input.gcount() !=
                    static_cast<std::streamsize>(session.header_mac.size()) ||
                encoded_file_size(expected_size) != input_size ||
                !header_mac_op(session.header_mac.data(),
                               session.base_nonce.data(),
                               header,
                               key.data(),
                               false)) {
                return false;
            }

            session.resize_buffers(expected_size);
            if (!reserve_temp_output(target_path, session.file, nullptr)) {
                return false;
            }

            std::uint64_t chunk_index = 0;
            std::uint64_t total_decrypted = 0;

            while (total_decrypted < expected_size) {
                const auto chunk_size =
                    static_cast<std::size_t>(std::min<std::uint64_t>(
                        CHUNK_SIZE, expected_size - total_decrypted));

                input.read(reinterpret_cast<char*>(session.mac.data()),
                           static_cast<std::streamsize>(session.mac.size()));
                if (input.gcount() !=
                    static_cast<std::streamsize>(session.mac.size())) {
                    return false;
                }

                input.read(reinterpret_cast<char*>(session.buffer_a.data()),
                           static_cast<std::streamsize>(chunk_size));
                if (input.gcount() !=
                    static_cast<std::streamsize>(chunk_size)) {
                    return false;
                }

                derive_chunk_nonce(session.base_nonce.data(),
                                   chunk_index,
                                   session.chunk_nonce.data());
                const auto chunk_ad =
                    make_chunk_ad(header, chunk_index, chunk_size);

                if (crypto_aead_unlock(session.buffer_b.data(),
                                       session.mac.data(),
                                       key.data(),
                                       session.chunk_nonce.data(),
                                       chunk_ad.data(),
                                       chunk_ad.size(),
                                       session.buffer_a.data(),
                                       chunk_size) != 0) {
                    return false;
                }

                if (!platform::private_storage::write_private_file(
                        session.file, session.buffer_b.data(), chunk_size)) {
                    return false;
                }

                total_decrypted += chunk_size;
                ++chunk_index;
            }

            return close_and_publish_temp(input, session, target_path, nullptr);
        } catch (...) {
            return false;
        }
    });
}

} // namespace kasumi::crypto
