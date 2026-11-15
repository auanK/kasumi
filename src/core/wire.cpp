#include "core/wire.hpp"

#include <limits>
#include <stdexcept>

namespace wire {

void write_bytes(Writer& writer, std::span<const std::byte> bytes) {
    writer.buffer.insert(writer.buffer.end(), bytes.begin(), bytes.end());
}

void write_string(Writer& writer, std::string_view str) {
    if (str.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error("wire string exceeds uint32_t length");
    }
    write(writer, static_cast<std::uint32_t>(str.size()));
    auto bytes = std::as_bytes(std::span{str});
    write_bytes(writer, bytes);
}

std::expected<std::span<const std::byte>, Error> read_bytes(Reader& reader,
                                                            std::size_t n) {
    if (reader.data.size() < n) {
        return std::unexpected(Error::BufferUnderflow);
    }
    auto result = reader.data.subspan(0, n);
    reader.data = reader.data.subspan(n);
    return result;
}

std::expected<std::string, Error> read_string(Reader& reader,
                                              std::size_t max_length) {
    auto len = read<std::uint32_t>(reader);
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

void write_strings(Writer& writer, std::span<const std::string> values) {
    write(writer, static_cast<std::uint32_t>(values.size()));
    for (const auto& value : values) {
        write_string(writer, value);
    }
}

bool read_strings(Reader& reader,
                  std::vector<std::string>& out,
                  std::size_t max_count,
                  bool* overflow) {
    auto count = read<std::uint32_t>(reader);
    if (!count) {
        return false;
    }
    if (*count > max_count ||
        *count > reader.data.size() / sizeof(std::uint32_t)) {
        if (overflow != nullptr) {
            *overflow = true;
        }
        return false;
    }
    out.clear();
    out.reserve(*count);
    for (std::uint32_t index = 0; index < *count; ++index) {
        auto item = read_string(reader);
        if (!item) {
            return false;
        }
        out.push_back(std::move(*item));
    }
    return true;
}

} // namespace wire