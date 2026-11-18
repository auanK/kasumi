#include "crypto/pack.hpp"

#include "core/wire.hpp"
#include "crypto/content.hpp"
#include "crypto/physical_hash.hpp"
#include "crypto/secure_memory.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"

#include <algorithm>
#include <array>
#include <blake3.h>
#include <cstring>
#include <fstream>
#include <limits>
#include <system_error>
#include <vector>

namespace kasumi::crypto::pack {
namespace {

inline constexpr std::array<std::uint8_t, 4> kpak_magic{'K', 'P', 'A', 'K'};
inline constexpr std::uint8_t kpak_version = 1;
inline constexpr std::size_t kpak_header_size = 9;
inline constexpr std::size_t kpak_entry_size = HASH_SIZE + 8;
inline constexpr std::uint64_t fastcdc_mask_s = 0xFFFFF80000000000ULL;
inline constexpr std::uint64_t fastcdc_mask_l = 0xFFFFE00000000000ULL;

const std::array<std::uint64_t, 256>& fastcdc_gear_table() noexcept {
    static const auto table = []() {
        std::array<std::uint64_t, 256> result{};
        constexpr std::string_view seed = "KASUMI_FASTCDC_GEAR_V1";
        std::array<std::uint8_t, 256 * sizeof(std::uint64_t)> raw{};
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, seed.data(), seed.size());
        blake3_hasher_finalize(&hasher, raw.data(), raw.size());
        for (std::size_t i = 0; i < result.size(); ++i) {
            result[i] = wire::decode_le<std::uint64_t>(
                raw.data() + i * sizeof(std::uint64_t));
        }
        return result;
    }();
    return table;
}

Hash hash_span(std::span<const std::uint8_t> bytes) noexcept {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    secure_memory::WipeGuard guard{hasher};
    if (!bytes.empty()) {
        blake3_hasher_update(&hasher, bytes.data(), bytes.size());
    }
    Hash digest{};
    blake3_hasher_finalize(
        &hasher, reinterpret_cast<std::uint8_t*>(digest.data()), digest.size());
    return digest;
}

std::expected<std::string, std::string>
write_ciphertext_atomically(const std::filesystem::path& output_path,
                            std::span<const std::uint8_t> ciphertext) {
    if (output_path.empty()) {
        return std::unexpected("output path is empty");
    }
    const auto target_path = output_path.has_parent_path()
                                 ? output_path
                                 : (std::filesystem::path(".") / output_path);
    std::error_code ec;
    const auto dest_status = std::filesystem::symlink_status(target_path, ec);
    if (ec && ec != std::errc::no_such_file_or_directory) {
        return std::unexpected("failed to inspect output path: " + ec.message());
    }
    if (!ec && (std::filesystem::is_directory(dest_status) ||
                std::filesystem::is_symlink(dest_status) ||
                platform::private_storage::is_reparse_or_symlink(target_path))) {
        return std::unexpected("output path is an invalid directory or link");
    }

    auto sha = physical::sha256_init();
    physical::sha256_update(sha, ciphertext);
    auto digest = physical::sha256_finish(sha);

    platform::private_storage::PrivateOutputFile temp_file;
    bool reserved = false;
    for (std::size_t attempt = 0; attempt < 32; ++attempt) {
        auto id = platform::random::hex_id();
        if (!id) {
            return std::unexpected("failed to generate temporary file id");
        }
        const auto candidate =
            target_path.native().size() + 16 < 260
                ? platform::path::temporary_sibling_path(
                      target_path, ".k_", "." + id->substr(0, 8))
                : target_path.parent_path() /
                      platform::path::from_utf8(".k_" + id->substr(0, 16));
        auto created = platform::private_storage::create_private_file(candidate);
        if (created) {
            temp_file = std::move(*created);
            reserved = true;
            break;
        }
        if (!created.error().is_collision) {
            return std::unexpected(created.error().message);
        }
    }
    if (!reserved) {
        return std::unexpected("failed to reserve exclusive temporary file");
    }

    if (!ciphertext.empty()) {
        auto written = platform::private_storage::write_private_file(
            temp_file, ciphertext.data(), ciphertext.size());
        if (!written) {
            static_cast<void>(
                platform::private_storage::remove_private_file_if_owned(
                    temp_file));
            return std::unexpected(written.error());
        }
    }
    auto published =
        platform::private_storage::publish_private_file(temp_file, target_path);
    if (!published) {
        if (!temp_file.published) {
            static_cast<void>(
                platform::private_storage::remove_private_file_if_owned(
                    temp_file));
        }
        return std::unexpected(published.error());
    }
    return digest;
}

std::expected<void, std::string>
read_regular_file_checked(const std::filesystem::path& path,
                          std::uint64_t max_bytes,
                          std::vector<std::uint8_t>& out,
                          std::optional<std::uint64_t> expected_size =
                              std::nullopt) {
    out.clear();
    if (path.empty()) {
        return std::unexpected("input path is empty");
    }
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(path, ec);
    if (ec || std::filesystem::is_symlink(status) ||
        platform::private_storage::is_reparse_or_symlink(path) ||
        !std::filesystem::is_regular_file(status)) {
        return std::unexpected(
            "input path is missing, redirected, or not a regular file");
    }
    const auto size = std::filesystem::file_size(path, ec);
    if (ec) {
        return std::unexpected("failed to read file size: " + ec.message());
    }
    if (size > max_bytes || (expected_size && size != *expected_size)) {
        return std::unexpected("input file size exceeds bounds or mismatches");
    }
    out.reserve(static_cast<std::size_t>(size));
    std::vector<std::uint8_t> scratch(256U * 1024U);
    secure_memory::WipeGuard scratch_guard{scratch};
    auto streamed = platform::private_storage::stream_regular_file(
        path,
        scratch,
        [&](std::span<const std::uint8_t> chunk) {
            if (!chunk.empty()) {
                out.insert(out.end(), chunk.begin(), chunk.end());
            }
        },
        size);
    if (!streamed) {
        return std::unexpected(streamed.error().detail);
    }
    if (*streamed != size || (expected_size && out.size() != *expected_size)) {
        return std::unexpected("input file size changed while reading");
    }
    return {};
}

} // namespace

std::optional<Hash>
compute_pack_hash(std::span<const PackMemberDescriptor> sorted_members) noexcept {
    if (sorted_members.empty() ||
        sorted_members.size() > MAXIMUM_PACK_MEMBERS) {
        return std::nullopt;
    }

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    secure_memory::WipeGuard guard{hasher};
    static constexpr char domain[] = "KASUMI_PACK_V1";
    blake3_hasher_update(&hasher, domain, sizeof(domain));

    std::array<std::uint8_t, 4> count_le{};
    wire::encode_le<std::uint32_t>(
        static_cast<std::uint32_t>(sorted_members.size()), count_le.data());
    blake3_hasher_update(&hasher, count_le.data(), count_le.size());

    std::uint64_t total_payload = 0;
    for (std::size_t i = 0; i < sorted_members.size(); ++i) {
        const auto& member = sorted_members[i];
        if (i > 0 && !(sorted_members[i - 1].hash < member.hash)) {
            return std::nullopt;
        }
        if (member.size > MAXIMUM_PACK_PLAINTEXT_SIZE - total_payload) {
            return std::nullopt;
        }
        total_payload += member.size;
        blake3_hasher_update(&hasher, member.hash.data(), member.hash.size());
        std::array<std::uint8_t, 4> size_le{};
        wire::encode_le<std::uint32_t>(member.size, size_le.data());
        blake3_hasher_update(&hasher, size_le.data(), size_le.size());
    }

    Hash digest{};
    blake3_hasher_finalize(
        &hasher, reinterpret_cast<std::uint8_t*>(digest.data()), digest.size());
    return digest;
}

std::expected<PackEncryptionResult, std::string>
write_encrypted_pack(std::span<const PackMemberSource> members,
                     const std::filesystem::path& output_path,
                     std::span<const std::uint8_t, KEY_SIZE> master_key) {
    if (members.empty() || members.size() > MAXIMUM_PACK_MEMBERS) {
        return std::unexpected("invalid Micro-Pack member count");
    }

    std::vector<PackMemberSource> sorted(members.begin(), members.end());
    std::ranges::sort(sorted, [](const auto& a, const auto& b) {
        return a.hash < b.hash;
    });

    std::vector<PackMemberDescriptor> descriptors;
    descriptors.reserve(sorted.size());
    std::uint64_t total_payload = 0;
    for (std::size_t i = 0; i < sorted.size(); ++i) {
        if (i > 0 && sorted[i - 1].hash == sorted[i].hash) {
            return std::unexpected("duplicate member hash in Micro-Pack");
        }
        if (sorted[i].size > MAXIMUM_PACK_PLAINTEXT_SIZE - total_payload) {
            return std::unexpected("Micro-Pack payload exceeds size budget");
        }
        total_payload += sorted[i].size;
        descriptors.push_back(PackMemberDescriptor{
            .hash = sorted[i].hash,
            .size = sorted[i].size,
        });
    }

    const auto pack_hash = compute_pack_hash(descriptors);
    if (!pack_hash) {
        return std::unexpected("failed to compute canonical pack hash");
    }

    const std::size_t table_offset = kpak_header_size;
    const std::size_t data_offset =
        kpak_header_size + sorted.size() * kpak_entry_size;
    const std::size_t total_size =
        data_offset + static_cast<std::size_t>(total_payload);

    std::vector<std::uint8_t> plain(total_size, 0);
    secure_memory::WipeGuard plain_guard{plain};

    std::memcpy(plain.data(), kpak_magic.data(), kpak_magic.size());
    plain[4] = kpak_version;
    wire::encode_le<std::uint32_t>(
        static_cast<std::uint32_t>(sorted.size()), plain.data() + 5);

    std::uint32_t payload_cursor = 0;
    std::vector<std::uint8_t> member_bytes;
    secure_memory::WipeGuard member_guard{member_bytes};
    for (std::size_t i = 0; i < sorted.size(); ++i) {
        const auto& member = sorted[i];
        auto read = read_regular_file_checked(
            member.source_path, member.size, member_bytes, member.size);
        if (!read) {
            return std::unexpected("failed to read pack member '" +
                                   platform::path::to_utf8(member.source_path) +
                                   "': " + read.error());
        }
        if (hash_span(member_bytes) != member.hash) {
            return std::unexpected("pack member content hash mismatch: " +
                                   platform::path::to_utf8(member.source_path));
        }

        std::uint8_t* entry = plain.data() + table_offset + i * kpak_entry_size;
        std::memcpy(entry, member.hash.data(), HASH_SIZE);
        wire::encode_le<std::uint32_t>(payload_cursor, entry + HASH_SIZE);
        wire::encode_le<std::uint32_t>(member.size, entry + HASH_SIZE + 4);
        if (!member_bytes.empty()) {
            std::memcpy(plain.data() + data_offset + payload_cursor,
                        member_bytes.data(),
                        member_bytes.size());
        }
        payload_cursor += member.size;
    }

    auto cipher = encrypt_bytes(plain, master_key, FilePurpose::Pack);
    if (!cipher) {
        return std::unexpected("failed to encrypt Micro-Pack");
    }
    auto sha256 = write_ciphertext_atomically(output_path, *cipher);
    if (!sha256) {
        return std::unexpected(sha256.error());
    }

    return PackEncryptionResult{
        .pack_hash = *pack_hash,
        .pack_plaintext_size = total_size,
        .ciphertext_sha256 = std::move(*sha256),
    };
}

std::expected<std::vector<PackMemberDescriptor>, std::string>
decrypt_and_verify_pack(const std::filesystem::path& encrypted_path,
                        std::span<const std::uint8_t, KEY_SIZE> master_key,
                        std::optional<Hash> expected_pack_hash,
                        const std::filesystem::path* extract_dir,
                        Hash* out_pack_hash) {
    const auto max_plain_wire =
        kpak_header_size + MAXIMUM_PACK_MEMBERS * kpak_entry_size +
        MAXIMUM_PACK_PLAINTEXT_SIZE;
    const auto max_cipher_wire = encoded_file_size(max_plain_wire);
    if (!max_cipher_wire) {
        return std::unexpected("invalid Micro-Pack size ceiling");
    }

    std::vector<std::uint8_t> cipher;
    if (auto read =
            read_regular_file_checked(encrypted_path, *max_cipher_wire, cipher);
        !read) {
        return std::unexpected("could not read encrypted pack: " + read.error());
    }

    auto plain = decrypt_bytes(cipher, master_key, FilePurpose::Pack);
    if (!plain) {
        return std::unexpected("failed to authenticate and decrypt Micro-Pack");
    }
    secure_memory::WipeGuard plain_guard{*plain};

    if (plain->size() < kpak_header_size ||
        !std::equal(kpak_magic.begin(), kpak_magic.end(), plain->begin()) ||
        (*plain)[4] != kpak_version) {
        return std::unexpected("invalid KPAK header");
    }

    const std::uint32_t count = wire::decode_le<std::uint32_t>(plain->data() + 5);
    if (count == 0 || count > MAXIMUM_PACK_MEMBERS) {
        return std::unexpected("invalid KPAK member count");
    }

    const std::size_t data_offset =
        kpak_header_size + static_cast<std::size_t>(count) * kpak_entry_size;
    if (plain->size() < data_offset) {
        return std::unexpected("truncated KPAK member table");
    }

    std::vector<PackMemberDescriptor> descriptors;
    descriptors.reserve(count);
    struct Slice {
        std::size_t offset = 0;
        std::uint32_t size = 0;
    };
    std::vector<Slice> slices;
    slices.reserve(count);

    std::uint64_t expected_cursor = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        const std::uint8_t* entry =
            plain->data() + kpak_header_size + i * kpak_entry_size;
        Hash hash{};
        std::memcpy(hash.data(), entry, HASH_SIZE);
        const std::uint32_t offset = wire::decode_le<std::uint32_t>(entry + HASH_SIZE);
        const std::uint32_t size =
            wire::decode_le<std::uint32_t>(entry + HASH_SIZE + 4);
        if (i > 0 && !(descriptors.back().hash < hash)) {
            return std::unexpected("KPAK member hashes are not strictly sorted");
        }
        if (offset != expected_cursor ||
            size > MAXIMUM_PACK_PLAINTEXT_SIZE - expected_cursor) {
            return std::unexpected("KPAK member offsets or sizes are invalid");
        }
        expected_cursor += size;
        descriptors.push_back(PackMemberDescriptor{.hash = hash, .size = size});
        slices.push_back(Slice{.offset = data_offset + offset, .size = size});
    }

    if (data_offset + expected_cursor != plain->size()) {
        return std::unexpected("KPAK payload size mismatch");
    }

    const auto pack_hash = compute_pack_hash(descriptors);
    if (!pack_hash || (expected_pack_hash && *pack_hash != *expected_pack_hash)) {
        return std::unexpected("KPAK pack hash verification failed");
    }

    for (std::size_t i = 0; i < descriptors.size(); ++i) {
        const auto slice = std::span<const std::uint8_t>{
            plain->data() + slices[i].offset, slices[i].size};
        if (hash_span(slice) != descriptors[i].hash) {
            return std::unexpected("KPAK member payload BLAKE3 mismatch");
        }
    }

    if (extract_dir != nullptr) {
        auto dir_ok = platform::private_storage::ensure_directory(*extract_dir);
        if (!dir_ok) {
            return std::unexpected("failed to prepare pack extraction dir: " +
                                   dir_ok.error());
        }
        for (std::size_t i = 0; i < descriptors.size(); ++i) {
            const auto hex = hash_hex(descriptors[i].hash);
            const auto out_path = *extract_dir / (hex + ".plain");
            std::error_code ec;
            const auto status = std::filesystem::symlink_status(out_path, ec);
            if (!ec && !std::filesystem::is_symlink(status) &&
                !platform::private_storage::is_reparse_or_symlink(out_path) &&
                std::filesystem::is_regular_file(status) &&
                content::verify_file(out_path, hex, descriptors[i].size)) {
                continue;
            }
            const std::string_view view(
                reinterpret_cast<const char*>(plain->data() + slices[i].offset),
                slices[i].size);
            auto written =
                platform::private_storage::write_atomically(out_path, view);
            if (!written) {
                return std::unexpected("failed to extract pack member: " +
                                       written.error());
            }
        }
    }

    if (out_pack_hash != nullptr) {
        *out_pack_hash = *pack_hash;
    }
    return descriptors;
}

std::expected<FastCdcResult, std::string>
chunk_file_fastcdc(const std::filesystem::path& path) {
    if (path.empty()) {
        return std::unexpected("input path is empty");
    }
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(path, ec);
    if (ec || std::filesystem::is_symlink(status) ||
        platform::private_storage::is_reparse_or_symlink(path) ||
        !std::filesystem::is_regular_file(status)) {
        return std::unexpected(
            "path is missing, redirected, or not a regular file");
    }

    const auto& gear = fastcdc_gear_table();
    blake3_hasher file_hasher;
    blake3_hasher_init(&file_hasher);
    blake3_hasher chunk_hasher;
    blake3_hasher_init(&chunk_hasher);
    secure_memory::WipeGuard file_guard{file_hasher};
    secure_memory::WipeGuard chunk_guard{chunk_hasher};

    FastCdcResult result;
    std::uint64_t chunk_offset = 0;
    std::uint32_t chunk_len = 0;
    std::uint64_t fp = 0;

    const auto flush_chunk = [&]() {
        if (chunk_len == 0) {
            return;
        }
        Hash chunk_hash{};
        blake3_hasher_finalize(&chunk_hasher,
                               reinterpret_cast<std::uint8_t*>(chunk_hash.data()),
                               chunk_hash.size());
        result.chunks.push_back(FastCdcChunk{
            .hash = chunk_hash,
            .offset = chunk_offset,
            .size = chunk_len,
        });
        chunk_offset += chunk_len;
        chunk_len = 0;
        fp = 0;
        blake3_hasher_reset(&chunk_hasher);
    };

    std::vector<std::uint8_t> scratch(256U * 1024U);
    secure_memory::WipeGuard scratch_guard{scratch};
    auto streamed = platform::private_storage::stream_regular_file(
        path, scratch, [&](std::span<const std::uint8_t> slab) {
            if (slab.empty()) {
                return;
            }
            blake3_hasher_update(&file_hasher, slab.data(), slab.size());
            result.file_size += slab.size();

            std::size_t pos = 0;
            while (pos < slab.size()) {
                const std::uint32_t to_max = FASTCDC_MAX_CHUNK - chunk_len;
                const std::size_t avail =
                    std::min<std::size_t>(slab.size() - pos, to_max);
                if (chunk_len < FASTCDC_MIN_CHUNK) {
                    const std::size_t skip = std::min<std::size_t>(
                        avail,
                        static_cast<std::size_t>(FASTCDC_MIN_CHUNK - chunk_len));
                    blake3_hasher_update(
                        &chunk_hasher, slab.data() + pos, skip);
                    chunk_len += static_cast<std::uint32_t>(skip);
                    pos += skip;
                    if (chunk_len < FASTCDC_MIN_CHUNK) {
                        continue;
                    }
                }

                const std::size_t start_pos = pos;
                const std::size_t scan_end =
                    start_pos +
                    std::min<std::size_t>(slab.size() - pos,
                                          FASTCDC_MAX_CHUNK - chunk_len);
                std::size_t cur = start_pos;
                const std::size_t normal_end =
                    chunk_len < FASTCDC_AVG_CHUNK
                        ? std::min(scan_end,
                                   start_pos + static_cast<std::size_t>(
                                                   FASTCDC_AVG_CHUNK - chunk_len))
                        : start_pos;

                bool cut = false;
                for (; cur < normal_end; ++cur) {
                    fp = (fp << 1) + gear[slab[cur]];
                    if ((fp & fastcdc_mask_s) == 0ULL) {
                        ++cur;
                        cut = true;
                        break;
                    }
                }
                if (!cut) {
                    for (; cur < scan_end; ++cur) {
                        fp = (fp << 1) + gear[slab[cur]];
                        if ((fp & fastcdc_mask_l) == 0ULL) {
                            ++cur;
                            cut = true;
                            break;
                        }
                    }
                }
                const std::size_t consumed = cur - start_pos;
                if (consumed > 0) {
                    blake3_hasher_update(
                        &chunk_hasher, slab.data() + start_pos, consumed);
                    chunk_len += static_cast<std::uint32_t>(consumed);
                    pos = cur;
                }
                if (cut || chunk_len == FASTCDC_MAX_CHUNK) {
                    flush_chunk();
                }
            }
        });
    if (!streamed) {
        return std::unexpected(streamed.error().detail);
    }

    flush_chunk();
    blake3_hasher_finalize(
        &file_hasher,
        reinterpret_cast<std::uint8_t*>(result.file_hash.data()),
        result.file_hash.size());
    return result;
}

std::optional<EncryptionResult>
encrypt_file_slice_with_hashes(const std::filesystem::path& input_path,
                               std::uint64_t offset,
                               std::uint32_t length,
                               const Hash& expected_slice_hash,
                               const std::filesystem::path& output_path,
                               std::span<const std::uint8_t, KEY_SIZE> master_key,
                               std::string* error_detail) {
    const auto fail = [&](std::string_view msg) -> std::optional<EncryptionResult> {
        if (error_detail != nullptr) {
            *error_detail = std::string(msg);
        }
        return std::nullopt;
    };

    if (input_path.empty() || output_path.empty() ||
        length == 0 || length > FASTCDC_MAX_CHUNK) {
        return fail("invalid slice parameters");
    }

    std::error_code ec;
    const auto status = std::filesystem::symlink_status(input_path, ec);
    if (ec || std::filesystem::is_symlink(status) ||
        platform::private_storage::is_reparse_or_symlink(input_path) ||
        !std::filesystem::is_regular_file(status)) {
        return fail("slice input is missing, redirected, or not a regular file");
    }
    const auto file_size = std::filesystem::file_size(input_path, ec);
    if (ec || offset > file_size || length > file_size - offset ||
        offset > static_cast<std::uint64_t>(
                     std::numeric_limits<std::streamoff>::max())) {
        return fail("slice range is outside file bounds");
    }

    const auto pre_identity =
        platform::private_storage::query_file_identity(input_path);
    if (!pre_identity.valid) {
        return fail("failed to query slice input file identity");
    }

    std::vector<std::uint8_t> buffer(length);
    secure_memory::WipeGuard buffer_guard{buffer};

    std::ifstream input(input_path, std::ios::binary);
    if (!input) {
        return fail("failed to open input file for slice encryption");
    }
    input.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!input) {
        return fail("failed to seek to slice offset");
    }
    input.read(reinterpret_cast<char*>(buffer.data()),
               static_cast<std::streamsize>(length));
    if (input.gcount() != static_cast<std::streamsize>(length) || input.bad()) {
        return fail("failed to read complete slice from input file");
    }
    input.close();

    const auto post_identity =
        platform::private_storage::query_file_identity(input_path);
    if (!post_identity.valid || !(post_identity == pre_identity) ||
        platform::private_storage::is_reparse_or_symlink(input_path)) {
        return fail("slice input file identity changed during read");
    }

    if (hash_span(buffer) != expected_slice_hash) {
        return fail("slice content changed on disk before encryption");
    }

    auto cipher = encrypt_bytes(buffer, master_key, FilePurpose::Content);
    if (!cipher) {
        return fail("failed to encrypt slice");
    }

    auto sha256 = write_ciphertext_atomically(output_path, *cipher);
    if (!sha256) {
        return fail(sha256.error());
    }

    return EncryptionResult{
        .plaintext_hash = expected_slice_hash,
        .plaintext_size = length,
        .ciphertext_sha256 = std::move(*sha256),
    };
}

} // namespace kasumi::crypto::pack
