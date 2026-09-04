#include "core/wire.hpp"

namespace wire {

void write_bytes(Writer& writer, std::span<const std::byte> bytes) {
    writer.buffer.insert(writer.buffer.end(), bytes.begin(), bytes.end());
}

void write_string(Writer& writer, std::string_view str) {
    write(writer, static_cast<uint32_t>(str.size()));
    auto bytes = std::as_bytes(std::span{str});
    write_bytes(writer, bytes);
}

std::expected<std::span<const std::byte>, Error> read_bytes(Reader& reader,
                                                            size_t n) {
    if (reader.data.size() < n) {
        return std::unexpected(Error::BufferUnderflow);
    }
    auto result = reader.data.subspan(0, n);
    reader.data = reader.data.subspan(n);
    return result;
}

std::expected<std::string, Error> read_string(Reader& reader,
                                              size_t max_length) {
    auto len = read<uint32_t>(reader);
    if (!len) {
        return std::unexpected(len.error());
    }

    if (*len > max_length) {
        return std::unexpected(Error::InvalidLength);
    }

    auto bytes = read_bytes(reader, *len);
    if (!bytes) {
        return std::unexpected(bytes.error());
    }

    std::string result;
    result.resize(*len);
    if (*len > 0) {
        std::memcpy(result.data(), bytes->data(), *len);
    }
    return result;
}

} // namespace wire