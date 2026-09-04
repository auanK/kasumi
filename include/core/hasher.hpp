#ifndef KASUMI_HASHER_HPP
#define KASUMI_HASHER_HPP

#include <array>
#include <cstddef>
#include <expected>
#include <string>
#include <string_view>
#include <unordered_set>

namespace kasumi {

// BLAKE3 hash size in bytes.
inline constexpr std::size_t HASH_SIZE = 32;

// Size of the hexadecimal hash representation.
inline constexpr std::size_t HASH_HEX_SIZE = HASH_SIZE * 2;

// 32-byte BLAKE3 hash.
using Hash = std::array<std::byte, HASH_SIZE>;

// Computes the lookup hash key used by associative containers.
std::size_t hash_key(const Hash& hash);

// Set of BLAKE3 hashes.
using HashSet = std::unordered_set<Hash, decltype(&hash_key)>;

// Writes HASH_HEX_SIZE characters without a null terminator.
void hash_hex(const Hash& hash, char* output);

// Returns lowercase hexadecimal representation of the hash.
std::string hash_hex(const Hash& hash);

// Accepts exactly HASH_HEX_SIZE hexadecimal digits.
std::expected<Hash, std::string> hash_from_hex(std::string_view text);

namespace hasher {

// Computes the BLAKE3 hash of a memory region.
Hash hash_bytes(const void* data, std::size_t size);

// Computes the BLAKE3 hash of string bytes.
Hash hash_string(std::string_view input);

} // namespace hasher
} // namespace kasumi

#endif
