#ifndef KASUMI_PLATFORM_RANDOM_HPP
#define KASUMI_PLATFORM_RANDOM_HPP

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>

namespace kasumi::platform::random {

// Fills buffer with bytes from the system cryptographic source.
std::expected<void, std::string> fill_bytes(std::span<std::uint8_t> output);

// Generates a hexadecimal identifier with the requested number of bytes.
std::expected<std::string, std::string> hex_id(std::size_t byte_count = 16);

} // namespace kasumi::platform::random

#endif
