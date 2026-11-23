#include "crypto/physical_hash.hpp"

#include "platform/private_storage.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// clang-format off
#include <windows.h>
#include <bcrypt.h>
// clang-format on
#endif

#if defined(__x86_64__) || defined(_M_X64)
#if defined(_MSC_VER)
#define KASUMI_HAS_X86_SHANI 1
#define KASUMI_SHANI_ATTR __declspec(noinline)
#include <immintrin.h>
#include <intrin.h>
#elif defined(__GNUC__) || defined(__clang__)
#define KASUMI_HAS_X86_SHANI 1
#define KASUMI_SHANI_ATTR __attribute__((target("sha,sse4.1"), noinline))
#include <cpuid.h>
#include <immintrin.h>
#endif
#endif

#ifndef KASUMI_HAS_X86_SHANI
#define KASUMI_HAS_X86_SHANI 0
#endif

namespace kasumi::crypto::physical {
namespace {

constexpr std::array<std::uint32_t, 64> round_constants{
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU,
    0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U,
    0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U,
    0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U,
    0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
    0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U,
    0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U, 0x1e376c08U,
    0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU,
    0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

std::uint32_t rotate_right(std::uint32_t value, unsigned count) noexcept {
    return (value >> count) | (value << (32U - count));
}

void compress(std::array<std::uint32_t, 8>& state,
              const std::uint8_t* block) noexcept {
    std::array<std::uint32_t, 64> words{};
    for (std::size_t index = 0; index < 16; ++index) {
        const auto offset = index * 4;
        words[index] = (static_cast<std::uint32_t>(block[offset]) << 24U) |
                       (static_cast<std::uint32_t>(block[offset + 1]) << 16U) |
                       (static_cast<std::uint32_t>(block[offset + 2]) << 8U) |
                       static_cast<std::uint32_t>(block[offset + 3]);
    }
    for (std::size_t index = 16; index < words.size(); ++index) {
        const auto s0 = rotate_right(words[index - 15], 7) ^
                        rotate_right(words[index - 15], 18) ^
                        (words[index - 15] >> 3U);
        const auto s1 = rotate_right(words[index - 2], 17) ^
                        rotate_right(words[index - 2], 19) ^
                        (words[index - 2] >> 10U);
        words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }

    auto working = state;
    for (std::size_t index = 0; index < words.size(); ++index) {
        const auto s1 = rotate_right(working[4], 6) ^
                        rotate_right(working[4], 11) ^
                        rotate_right(working[4], 25);
        const auto choose =
            (working[4] & working[5]) ^ ((~working[4]) & working[6]);
        const auto temporary1 =
            working[7] + s1 + choose + round_constants[index] + words[index];
        const auto s0 = rotate_right(working[0], 2) ^
                        rotate_right(working[0], 13) ^
                        rotate_right(working[0], 22);
        const auto majority = (working[0] & working[1]) ^
                              (working[0] & working[2]) ^
                              (working[1] & working[2]);
        const auto temporary2 = s0 + majority;
        working[7] = working[6];
        working[6] = working[5];
        working[5] = working[4];
        working[4] = working[3] + temporary1;
        working[3] = working[2];
        working[2] = working[1];
        working[1] = working[0];
        working[0] = temporary1 + temporary2;
    }
    for (std::size_t index = 0; index < state.size(); ++index) {
        state[index] += working[index];
    }
}

#if KASUMI_HAS_X86_SHANI
bool cpu_supports_sha_ni() noexcept {
    static const bool supported = []() noexcept {
#if defined(_MSC_VER)
        int regs[4]{};
        __cpuid(regs, 0);
        if (regs[0] < 7) {
            return false;
        }
        __cpuid(regs, 1);
        constexpr int ssse3_bit = 1 << 9;
        constexpr int sse41_bit = 1 << 19;
        if ((regs[2] & (ssse3_bit | sse41_bit)) != (ssse3_bit | sse41_bit)) {
            return false;
        }
        __cpuidex(regs, 7, 0);
        constexpr int sha_bit = 1 << 29;
        return (regs[1] & sha_bit) != 0;
#else
        unsigned int eax = 0;
        unsigned int ebx = 0;
        unsigned int ecx = 0;
        unsigned int edx = 0;
        if (__get_cpuid(0, &eax, &ebx, &ecx, &edx) == 0 || eax < 7U) {
            return false;
        }
        if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) == 0) {
            return false;
        }
        constexpr unsigned int ssse3_bit = 1U << 9U;
        constexpr unsigned int sse41_bit = 1U << 19U;
        if ((ecx & (ssse3_bit | sse41_bit)) != (ssse3_bit | sse41_bit)) {
            return false;
        }
        if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx) == 0) {
            return false;
        }
        constexpr unsigned int sha_bit = 1U << 29U;
        return (ebx & sha_bit) != 0U;
#endif
    }();
    return supported;
}

KASUMI_SHANI_ATTR void
compress_blocks_shani(std::array<std::uint32_t, 8>& state,
                      const std::uint8_t* data,
                      std::size_t block_count) noexcept {
    __m128i tmp;
    __m128i state1;
    std::memcpy(&tmp, state.data(), sizeof(tmp));
    std::memcpy(&state1, state.data() + 4, sizeof(state1));
    tmp = _mm_shuffle_epi32(tmp, 0xB1);
    state1 = _mm_shuffle_epi32(state1, 0x1B);
    __m128i state0 = _mm_alignr_epi8(tmp, state1, 8);
    state1 = _mm_blend_epi16(state1, tmp, 0xF0);

    const __m128i bswap_mask =
        _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);

#define KASUMI_LOAD_MSG(dst, ptr)                                              \
    do {                                                                       \
        __m128i raw_blk;                                                       \
        std::memcpy(&raw_blk, (ptr), sizeof(raw_blk));                         \
        (dst) = _mm_shuffle_epi8(raw_blk, bswap_mask);                         \
    } while (false)

#define KASUMI_SHA256_ROUND4(cur, next, prev, r, has_msg2, has_msg1)           \
    do {                                                                       \
        __m128i kvec;                                                          \
        std::memcpy(&kvec, round_constants.data() + (r), sizeof(kvec));        \
        __m128i msg = _mm_add_epi32((cur), kvec);                              \
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);                   \
        if constexpr (has_msg2) {                                              \
            const __m128i t = _mm_alignr_epi8((cur), (prev), 4);               \
            (next) = _mm_add_epi32((next), t);                                 \
            (next) = _mm_sha256msg2_epu32((next), (cur));                      \
        }                                                                      \
        msg = _mm_shuffle_epi32(msg, 0x0E);                                    \
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);                   \
        if constexpr (has_msg1) {                                              \
            (prev) = _mm_sha256msg1_epu32((prev), (cur));                      \
        }                                                                      \
    } while (false)

    for (std::size_t block_idx = 0; block_idx < block_count; ++block_idx) {
        const std::uint8_t* blk = data + block_idx * 64U;
        const __m128i abef_save = state0;
        const __m128i cdgh_save = state1;

        __m128i m0{};
        __m128i m1{};
        __m128i m2{};
        __m128i m3{};

        KASUMI_LOAD_MSG(m0, blk);
        KASUMI_SHA256_ROUND4(m0, m1, m3, 0U, false, false);
        KASUMI_LOAD_MSG(m1, blk + 16U);
        KASUMI_SHA256_ROUND4(m1, m2, m0, 4U, false, true);
        KASUMI_LOAD_MSG(m2, blk + 32U);
        KASUMI_SHA256_ROUND4(m2, m3, m1, 8U, false, true);
        KASUMI_LOAD_MSG(m3, blk + 48U);
        KASUMI_SHA256_ROUND4(m3, m0, m2, 12U, true, true);
        KASUMI_SHA256_ROUND4(m0, m1, m3, 16U, true, true);
        KASUMI_SHA256_ROUND4(m1, m2, m0, 20U, true, true);
        KASUMI_SHA256_ROUND4(m2, m3, m1, 24U, true, true);
        KASUMI_SHA256_ROUND4(m3, m0, m2, 28U, true, true);
        KASUMI_SHA256_ROUND4(m0, m1, m3, 32U, true, true);
        KASUMI_SHA256_ROUND4(m1, m2, m0, 36U, true, true);
        KASUMI_SHA256_ROUND4(m2, m3, m1, 40U, true, true);
        KASUMI_SHA256_ROUND4(m3, m0, m2, 44U, true, true);
        KASUMI_SHA256_ROUND4(m0, m1, m3, 48U, true, true);
        KASUMI_SHA256_ROUND4(m1, m2, m0, 52U, true, false);
        KASUMI_SHA256_ROUND4(m2, m3, m1, 56U, true, false);
        KASUMI_SHA256_ROUND4(m3, m0, m2, 60U, false, false);

        state0 = _mm_add_epi32(state0, abef_save);
        state1 = _mm_add_epi32(state1, cdgh_save);
    }

#undef KASUMI_SHA256_ROUND4
#undef KASUMI_LOAD_MSG

    tmp = _mm_shuffle_epi32(state0, 0x1B);
    state1 = _mm_shuffle_epi32(state1, 0xB1);
    state0 = _mm_blend_epi16(tmp, state1, 0xF0);
    state1 = _mm_alignr_epi8(state1, tmp, 8);
    std::memcpy(state.data(), &state0, sizeof(state0));
    std::memcpy(state.data() + 4, &state1, sizeof(state1));
}
#endif

void compress_blocks(std::array<std::uint32_t, 8>& state,
                     const std::uint8_t* data,
                     std::size_t block_count) noexcept {
    if (block_count == 0) {
        return;
    }
#if KASUMI_HAS_X86_SHANI
    if (cpu_supports_sha_ni()) {
        compress_blocks_shani(state, data, block_count);
        return;
    }
#endif
    for (std::size_t i = 0; i < block_count; ++i) {
        compress(state, data + i * 64U);
    }
}

std::string hex_digest(const std::array<std::uint32_t, 8>& state) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(64);
    for (const auto word : state) {
        for (int shift = 28; shift >= 0; shift -= 4) {
            output.push_back(digits[(word >> shift) & 0xFU]);
        }
    }
    return output;
}

#if defined(_WIN32)
std::string hex_bytes(std::span<const std::uint8_t> bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(bytes.size() * 2U);
    for (const auto byte : bytes) {
        output.push_back(digits[(byte >> 4U) & 0xFU]);
        output.push_back(digits[byte & 0xFU]);
    }
    return output;
}

struct BcryptHashGuard {
    BCRYPT_HASH_HANDLE handle = nullptr;
    ~BcryptHashGuard() noexcept {
        if (handle != nullptr) {
            BCryptDestroyHash(handle);
        }
    }
    BcryptHashGuard() = default;
    BcryptHashGuard(const BcryptHashGuard&) = delete;
    BcryptHashGuard& operator=(const BcryptHashGuard&) = delete;
};

std::expected<std::optional<std::string>, std::string>
hash_file_bcrypt(const std::filesystem::path& path) {
    static const BCRYPT_ALG_HANDLE alg = []() noexcept {
        BCRYPT_ALG_HANDLE handle = nullptr;
        return BCryptOpenAlgorithmProvider(
                   &handle, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0
                   ? handle
                   : nullptr;
    }();
    if (alg == nullptr) {
        return std::nullopt;
    }

    BcryptHashGuard hash;
    if (BCryptCreateHash(alg, &hash.handle, nullptr, 0, nullptr, 0, 0) != 0) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> buffer(256U * 1024U);
    bool bcrypt_failed = false;
    auto streamed = platform::private_storage::stream_regular_file(
        path, buffer, [&](std::span<const std::uint8_t> chunk) {
            if (chunk.empty()) {
                return true;
            }
            if (BCryptHashData(hash.handle,
                               const_cast<PUCHAR>(chunk.data()),
                               static_cast<ULONG>(chunk.size()),
                               0) != 0) {
                bcrypt_failed = true;
                return false;
            }
            return true;
        });
    if (bcrypt_failed) {
        return std::nullopt;
    }
    if (!streamed) {
        return std::unexpected(
            streamed.error().kind ==
                    platform::private_storage::StreamErrorKind::ReadFailed
                ? "could not read file for physical hash calculation"
                : "could not open file for physical hash calculation");
    }

    std::array<std::uint8_t, 32> digest{};
    if (BCryptFinishHash(
            hash.handle, digest.data(), static_cast<ULONG>(digest.size()), 0) !=
        0) {
        return std::nullopt;
    }
    return hex_bytes(digest);
}
#endif

} // namespace

Sha256State sha256_init() noexcept {
    return Sha256State{.hash = {0x6a09e667U,
                                0xbb67ae85U,
                                0x3c6ef372U,
                                0xa54ff53aU,
                                0x510e527fU,
                                0x9b05688cU,
                                0x1f83d9abU,
                                0x5be0cd19U}};
}

void sha256_update(Sha256State& state,
                   std::span<const std::uint8_t> bytes) noexcept {
    state.size += bytes.size();
    if (state.buffered > 0 && !bytes.empty()) {
        const auto count =
            std::min(bytes.size(), state.block.size() - state.buffered);
        std::memcpy(state.block.data() + state.buffered, bytes.data(), count);
        state.buffered += count;
        bytes = bytes.subspan(count);
        if (state.buffered == state.block.size()) {
            compress_blocks(state.hash, state.block.data(), 1U);
            state.buffered = 0;
        }
    }
    if (const auto full_blocks = bytes.size() / state.block.size();
        full_blocks > 0) {
        compress_blocks(state.hash, bytes.data(), full_blocks);
        bytes = bytes.subspan(full_blocks * state.block.size());
    }
    if (!bytes.empty()) {
        std::memcpy(state.block.data(), bytes.data(), bytes.size());
        state.buffered = bytes.size();
    }
}

std::string sha256_finish(Sha256State state) {
    const auto bits = state.size * 8U;
    state.block[state.buffered++] = 0x80U;
    if (state.buffered > 56) {
        std::fill(state.block.begin() +
                      static_cast<std::ptrdiff_t>(state.buffered),
                  state.block.end(),
                  0);
        compress_blocks(state.hash, state.block.data(), 1U);
        state.block.fill(0);
    } else {
        std::fill(state.block.begin() +
                      static_cast<std::ptrdiff_t>(state.buffered),
                  state.block.begin() + 56,
                  0);
    }
    for (unsigned index = 0; index < 8; ++index) {
        state.block[63U - index] =
            static_cast<std::uint8_t>(bits >> (index * 8U));
    }
    compress_blocks(state.hash, state.block.data(), 1U);
    return hex_digest(state.hash);
}

std::expected<std::string, std::string>
hash_file(const std::filesystem::path& path, std::string_view algorithm) {
    if (algorithm != "sha256") {
        return std::unexpected("unsupported physical hash algorithm");
    }

#if defined(_WIN32)
#if KASUMI_HAS_X86_SHANI
    if (!cpu_supports_sha_ni())
#endif
    {
        auto hw_hashed = hash_file_bcrypt(path);
        if (!hw_hashed) {
            return std::unexpected(hw_hashed.error());
        }
        if (hw_hashed->has_value()) {
            return std::move(**hw_hashed);
        }
    }
#endif

    auto state = sha256_init();
    std::vector<std::uint8_t> buffer(256U * 1024U);
    auto streamed = platform::private_storage::stream_regular_file(
        path, buffer, [&](std::span<const std::uint8_t> chunk) {
            sha256_update(state, chunk);
        });
    if (!streamed) {
        return std::unexpected(
            streamed.error().kind ==
                    platform::private_storage::StreamErrorKind::ReadFailed
                ? "could not read file for physical hash calculation"
                : "could not open file for physical hash calculation");
    }
    return sha256_finish(state);
}

} // namespace kasumi::crypto::physical
