#ifndef KASUMI_TRANSACTION_CODEC_HPP
#define KASUMI_TRANSACTION_CODEC_HPP

#include "types.hpp"

#include <cstddef>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace kasumi::transaction::codec {

// Encoded bytes or failure description.
using EncodeResult = std::expected<std::vector<std::byte>, std::string>;

// Encodes and validates in v8 little-endian format with uint32_t strings.
EncodeResult encode(const Record& record);

// Accepts only v8 and rejects trailing bytes or invalid invariants.
std::expected<Record, std::string> decode(std::span<const std::byte> data);

} // namespace kasumi::transaction::codec

#endif
