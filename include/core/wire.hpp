#pragma once

#include <algorithm>
#include <array>
#include <bit>
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

// Encodes a number in little-endian.
template <typename T>
    requires std::is_integral_v<T> || std::is_floating_point_v<T>
inline void write(Writer& writer, T value) {
    if constexpr (std::is_integral_v<T>) {
        if constexpr (sizeof(T) > 1 &&
                      std::endian::native != std::endian::little) {
            value = std::byteswap(value);
        }
        std::array<std::byte, sizeof(T)> bytes;
        std::memcpy(bytes.data(), &value, sizeof(T));
        write_bytes(writer, bytes);
    } else {
        using UIntType = std::conditional_t<sizeof(T) == 4, uint32_t, uint64_t>;
        auto int_val = std::bit_cast<UIntType>(value);
        if constexpr (std::endian::native != std::endian::little) {
            int_val = std::byteswap(int_val);
        }
        std::array<std::byte, sizeof(T)> bytes;
        std::memcpy(bytes.data(), &int_val, sizeof(T));
        write_bytes(writer, bytes);
    }
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
template <size_t N>
inline void write_array(Writer& writer, const std::array<std::byte, N>& arr) {
    write_bytes(writer, arr);
}

// Consumes n bytes or returns BufferUnderflow.
std::expected<std::span<const std::byte>, Error> read_bytes(Reader& reader,
                                                            size_t n);

// Decodes a number in little-endian.
template <typename T>
    requires std::is_integral_v<T> || std::is_floating_point_v<T>
inline std::expected<T, Error> read(Reader& reader) {
    auto bytes = read_bytes(reader, sizeof(T));
    if (!bytes) {
        return std::unexpected(bytes.error());
    }

    if constexpr (std::is_integral_v<T>) {
        T value;
        std::memcpy(&value, bytes->data(), sizeof(T));
        if constexpr (sizeof(T) > 1 &&
                      std::endian::native != std::endian::little) {
            value = std::byteswap(value);
        }
        return value;
    } else {
        using UIntType = std::conditional_t<sizeof(T) == 4, uint32_t, uint64_t>;
        UIntType int_val;
        std::memcpy(&int_val, bytes->data(), sizeof(T));
        if constexpr (std::endian::native != std::endian::little) {
            int_val = std::byteswap(int_val);
        }
        return std::bit_cast<T>(int_val);
    }
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
                                              size_t max_length = 4096);

// Consumes an array of N bytes.
template <size_t N>
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
