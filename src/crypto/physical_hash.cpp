#include "crypto/physical_hash.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>

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
              const std::array<std::uint8_t, 64>& block) noexcept {
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

std::string hex_digest(const std::array<std::uint32_t, 8>& state) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const auto word : state) {
        output << std::setw(8) << word;
    }
    return output.str();
}

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
    while (!bytes.empty()) {
        const auto count =
            std::min(bytes.size(), state.block.size() - state.buffered);
        std::memcpy(state.block.data() + state.buffered, bytes.data(), count);
        state.buffered += count;
        bytes = bytes.subspan(count);
        if (state.buffered == state.block.size()) {
            compress(state.hash, state.block);
            state.buffered = 0;
        }
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
        compress(state.hash, state.block);
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
    compress(state.hash, state.block);
    return hex_digest(state.hash);
}

std::expected<std::string, std::string>
hash_file(const std::filesystem::path& path, std::string_view algorithm) {
    if (algorithm != "sha256") {
        return std::unexpected("algoritmo de hash físico não suportado");
    }

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::unexpected(
            "não foi possível abrir o arquivo para cálculo de hash físico");
    }

    auto state = sha256_init();
    std::array<std::uint8_t, 64U * 1024U> buffer{};
    while (input) {
        input.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        const auto count = input.gcount();
        if (count > 0) {
            sha256_update(
                state,
                std::span{buffer}.first(static_cast<std::size_t>(count)));
        }
    }

    if (!input.eof() && input.fail()) {
        return std::unexpected(
            "não foi possível ler o arquivo para cálculo de hash físico");
    }

    return sha256_finish(state);
}

} // namespace kasumi::crypto::physical
