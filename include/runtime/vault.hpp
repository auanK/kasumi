#ifndef KASUMI_RUNTIME_VAULT_HPP
#define KASUMI_RUNTIME_VAULT_HPP

#include "runtime/error.hpp"

#include <array>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <string_view>

namespace kasumi::runtime::vault {

// Key size in bytes.
inline constexpr std::size_t KEY_SIZE = 32;
inline constexpr std::size_t MINIMUM_PASSWORD_SIZE = 12;
inline constexpr std::size_t MINIMUM_PASSWORD_SALT_SIZE = 16;
inline constexpr std::uint32_t ARGON2_MEMORY_BLOCKS = 65536;
inline constexpr std::uint32_t ARGON2_PASSES = 3;
// 256-bit symmetric key.
using KeyBytes = std::array<std::uint8_t, KEY_SIZE>;

// Accepts exactly 64 hexadecimal digits.
std::expected<KeyBytes, runtime::Error> decode_hex(std::string_view text);

// Reads and unmasks the local key.
std::expected<KeyBytes, runtime::Error> read(const std::filesystem::path& path);

// Reads and unmasks the key without modifying file permissions or attributes.
std::expected<KeyBytes, runtime::Error>
read_only(const std::filesystem::path& path);

// Masks and writes the local key.
std::expected<void, runtime::Error> write(const std::filesystem::path& path,
                                          const KeyBytes& clear_key);

// Derives the key from password and reproducible password salt.
std::expected<KeyBytes, runtime::Error> derive(std::string_view password,
                                               std::string_view salt_password);

// Reversible XOR masking; does not encrypt the key on disk.
void obscure(std::span<std::uint8_t, KEY_SIZE> key);

} // namespace kasumi::runtime::vault

#endif
