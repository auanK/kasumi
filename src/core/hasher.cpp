#include "core/hasher.hpp"

#include <blake3.h>

namespace kasumi {

static_assert(BLAKE3_OUT_LEN == HASH_SIZE);

std::size_t hash_key(const Hash& hash) {
    std::size_t value = 0;
    for (std::size_t i = 0; i < sizeof(value); ++i)
        value = (value << 8) | std::to_integer<std::size_t>(hash[i]);
    return value;
}

void hash_hex(const Hash& hash, char* output) {
    constexpr char digits[] = "0123456789abcdef";
    for (std::size_t i = 0; i < hash.size(); ++i) {
        const auto value = std::to_integer<unsigned char>(hash[i]);
        output[i * 2] = digits[value >> 4];
        output[i * 2 + 1] = digits[value & 0x0f];
    }
}

std::string hash_hex(const Hash& hash) {
    std::string result(hash.size() * 2, '\0');
    hash_hex(hash, result.data());
    return result;
}

std::expected<Hash, std::string> hash_from_hex(std::string_view text) {
    if (text.size() != HASH_HEX_SIZE)
        return std::unexpected("hash BLAKE3 inválido");
    Hash result{};
    const auto digit = [](char value) -> int {
        if (value >= '0' && value <= '9')
            return value - '0';
        if (value >= 'a' && value <= 'f')
            return value - 'a' + 10;
        if (value >= 'A' && value <= 'F')
            return value - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < result.size(); ++i) {
        const int high = digit(text[i * 2]);
        const int low = digit(text[i * 2 + 1]);
        if (high < 0 || low < 0)
            return std::unexpected("hash BLAKE3 inválido");
        result[i] = static_cast<std::byte>((high << 4) | low);
    }
    return result;
}

namespace hasher {

Hash hash_bytes(const void* data, std::size_t size) {
    Hash output{};
    blake3_hasher state;
    blake3_hasher_init(&state);
    blake3_hasher_update(&state, data, size);
    blake3_hasher_finalize(
        &state, reinterpret_cast<uint8_t*>(output.data()), output.size());
    return output;
}

Hash hash_string(std::string_view input) {
    return hash_bytes(input.data(), input.size());
}

} // namespace hasher
} // namespace kasumi