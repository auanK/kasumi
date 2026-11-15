#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace wire {

template <typename T>
concept WireScalar =
    (std::is_integral_v<T> && !std::is_same_v<std::remove_cv_t<T>, bool>) ||
    (std::is_floating_point_v<T> && (sizeof(T) == 4 || sizeof(T) == 8));

// Possible failures when decoding the binary stream.
enum class Error {
    BufferUnderflow,
    InvalidLength
};

// Accumulator buffer for binary encoding.
struct Writer {
    // Already encoded bytes.
    std::vector<std::byte> buffer;
};

// Window of unconsumed bytes.
struct Reader {
    // Remaining input bytes.
    std::span<const std::byte> data;
};

// Appends raw bytes to the buffer.
void write_bytes(Writer& writer, std::span<const std::byte> bytes);

// Callers provide storage for sizeof(T) bytes.
template <WireScalar T> inline void encode_le(T value, void* output) noexcept {
    auto bytes = std::bit_cast<std::array<std::byte, sizeof(T)>>(value);
    if constexpr (std::endian::native != std::endian::little) {
        std::ranges::reverse(bytes);
    }
    std::memcpy(output, bytes.data(), bytes.size());
}

template <WireScalar T> inline T decode_le(const void* input) noexcept {
    std::array<std::byte, sizeof(T)> bytes;
    std::memcpy(bytes.data(), input, bytes.size());
    if constexpr (std::endian::native != std::endian::little) {
        std::ranges::reverse(bytes);
    }
    return std::bit_cast<T>(bytes);
}

// Encodes a number in little-endian.
template <WireScalar T> inline void write(Writer& writer, T value) {
    std::array<std::byte, sizeof(T)> bytes;
    encode_le(value, bytes.data());
    write_bytes(writer, bytes);
}

// Encodes the underlying value of an enum.
template <typename E>
    requires std::is_enum_v<E>
inline void write_enum(Writer& writer, E value) {
    write(writer, static_cast<std::underlying_type_t<E>>(value));
}

// Encodes uint32_t length followed by string bytes.
void write_string(Writer& writer, std::string_view str);

// Appends a raw byte array without conversion.
template <std::size_t N>
inline void write_array(Writer& writer, const std::array<std::byte, N>& arr) {
    write_bytes(writer, arr);
}

// Consumes n bytes or returns BufferUnderflow.
std::expected<std::span<const std::byte>, Error> read_bytes(Reader& reader,
                                                            std::size_t n);

// Decodes a number in little-endian.
template <WireScalar T> inline std::expected<T, Error> read(Reader& reader) {
    auto bytes = read_bytes(reader, sizeof(T));
    if (!bytes) {
        return std::unexpected(bytes.error());
    }
    return decode_le<T>(bytes->data());
}

// Decodes the underlying value of an enum.
template <typename E>
    requires std::is_enum_v<E>
inline std::expected<E, Error> read_enum(Reader& reader) {
    using U = std::underlying_type_t<E>;
    auto val = read<U>(reader);
    if (!val) {
        return std::unexpected(val.error());
    }
    return static_cast<E>(*val);
}

// Decodes a string capped by max_length.
std::expected<std::string, Error> read_string(Reader& reader,
                                              std::size_t max_length = 4096);

// Encodes a uint32 count followed by each string.
void write_strings(Writer& writer, std::span<const std::string> values);

// Replaces out with a list written by write_strings. Fails when the count
// exceeds max_count or the remaining input (setting *overflow), or when an item
// is truncated or longer than 4096 bytes.
bool read_strings(Reader& reader,
                  std::vector<std::string>& out,
                  std::size_t max_count,
                  bool* overflow = nullptr);

// Consumes an array of N bytes.
template <std::size_t N>
inline std::expected<std::array<std::byte, N>, Error>
read_array(Reader& reader) {
    auto bytes = read_bytes(reader, N);
    if (!bytes) {
        return std::unexpected(bytes.error());
    }

    std::array<std::byte, N> arr;
    std::copy_n(bytes->data(), N, arr.data());
    return arr;
}

} // namespace wire
