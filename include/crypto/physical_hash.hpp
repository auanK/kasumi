#ifndef KASUMI_CRYPTO_PHYSICAL_HASH_HPP
#define KASUMI_CRYPTO_PHYSICAL_HASH_HPP

#include <array>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>

namespace kasumi::crypto::physical {

// Incremental state for SHA-256 computation.
struct Sha256State {
    // Internal state words of the algorithm.
    std::array<std::uint32_t, 8> hash{};
    // Unprocessed partial block.
    std::array<std::uint8_t, 64> block{};
    // Total number of bytes processed.
    std::uint64_t size = 0;
    // Number of valid bytes in block.
    std::size_t buffered = 0;
};

// Creates an empty SHA-256 state.
Sha256State sha256_init() noexcept;

// Appends bytes to the SHA-256 computation.
void sha256_update(Sha256State& state,
                   std::span<const std::uint8_t> bytes) noexcept;

// Finalizes a copy of the state and returns the hexadecimal digest.
std::string sha256_finish(Sha256State state);

// Accepts only "sha256".
std::expected<std::string, std::string>
hash_file(const std::filesystem::path& path, std::string_view algorithm);

} // namespace kasumi::crypto::physical

#endif
