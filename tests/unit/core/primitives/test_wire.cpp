#include "core/wire.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <limits>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

namespace {

constexpr std::size_t default_string_limit = 4096;

template <typename T, std::size_t N>
void expect_integer_round_trip(const std::array<T, N>& values) {
    static_assert(std::is_integral_v<T>);

    wire::Writer writer;
    for (const auto value : values)
        wire::write<T>(writer, value);

    wire::Reader reader{writer.buffer};
    for (const auto expected : values) {
        const auto actual = wire::read<T>(reader);
        ASSERT_TRUE(actual.has_value());
        EXPECT_EQ(*actual, expected);
    }
    EXPECT_TRUE(reader.data.empty());
}

template <typename T, std::size_t N>
void expect_floating_point_round_trip(const std::array<T, N>& values) {
    static_assert(std::is_floating_point_v<T>);

    wire::Writer writer;
    for (const auto value : values)
        wire::write<T>(writer, value);

    wire::Reader reader{writer.buffer};
    for (const auto expected : values) {
        const auto actual = wire::read<T>(reader);
        ASSERT_TRUE(actual.has_value());
        const auto expected_bits =
            std::bit_cast<std::array<std::byte, sizeof(T)>>(expected);
        const auto actual_bits =
            std::bit_cast<std::array<std::byte, sizeof(T)>>(*actual);
        EXPECT_EQ(actual_bits, expected_bits);
    }
    EXPECT_TRUE(reader.data.empty());
}

enum class CompactState : std::uint8_t {
    Ready = 0xA5,
};

enum class SignedState : std::int16_t {
    Failed = -300,
};

enum class WideState : std::uint32_t {
    Complete = 0x89ABCDEFU,
};

TEST(WireIntegers, RoundTripsEverySignedAndUnsignedWidth) {
    expect_integer_round_trip(std::array<std::uint8_t, 3>{
        std::uint8_t{0},
        std::uint8_t{1},
        std::numeric_limits<std::uint8_t>::max(),
    });
    expect_integer_round_trip(std::array<std::int8_t, 5>{
        std::numeric_limits<std::int8_t>::min(),
        std::int8_t{-1},
        std::int8_t{0},
        std::int8_t{1},
        std::numeric_limits<std::int8_t>::max(),
    });
    expect_integer_round_trip(std::array<std::uint16_t, 3>{
        std::uint16_t{0},
        std::uint16_t{1},
        std::numeric_limits<std::uint16_t>::max(),
    });
    expect_integer_round_trip(std::array<std::int16_t, 5>{
        std::numeric_limits<std::int16_t>::min(),
        std::int16_t{-1},
        std::int16_t{0},
        std::int16_t{1},
        std::numeric_limits<std::int16_t>::max(),
    });
    expect_integer_round_trip(std::array<std::uint32_t, 3>{
        std::uint32_t{0},
        std::uint32_t{1},
        std::numeric_limits<std::uint32_t>::max(),
    });
    expect_integer_round_trip(std::array<std::int32_t, 5>{
        std::numeric_limits<std::int32_t>::min(),
        std::int32_t{-1},
        std::int32_t{0},
        std::int32_t{1},
        std::numeric_limits<std::int32_t>::max(),
    });
    expect_integer_round_trip(std::array<std::uint64_t, 3>{
        std::uint64_t{0},
        std::uint64_t{1},
        std::numeric_limits<std::uint64_t>::max(),
    });
    expect_integer_round_trip(std::array<std::int64_t, 5>{
        std::numeric_limits<std::int64_t>::min(),
        std::int64_t{-1},
        std::int64_t{0},
        std::int64_t{1},
        std::numeric_limits<std::int64_t>::max(),
    });
}

TEST(WireIntegers, UsesObservableLittleEndianEncoding) {
    wire::Writer writer;
    wire::write<std::uint16_t>(writer, std::uint16_t{0x1234U});
    wire::write<std::uint32_t>(writer, std::uint32_t{0x89ABCDEFU});
    wire::write<std::uint64_t>(writer, std::uint64_t{0x0123456789ABCDEFULL});

    const std::vector<std::byte> expected{
        std::byte{0x34},
        std::byte{0x12},
        std::byte{0xEF},
        std::byte{0xCD},
        std::byte{0xAB},
        std::byte{0x89},
        std::byte{0xEF},
        std::byte{0xCD},
        std::byte{0xAB},
        std::byte{0x89},
        std::byte{0x67},
        std::byte{0x45},
        std::byte{0x23},
        std::byte{0x01},
    };
    EXPECT_EQ(writer.buffer, expected);

    wire::Reader reader{expected};
    const auto value16 = wire::read<std::uint16_t>(reader);
    const auto value32 = wire::read<std::uint32_t>(reader);
    const auto value64 = wire::read<std::uint64_t>(reader);
    ASSERT_TRUE(value16.has_value());
    ASSERT_TRUE(value32.has_value());
    ASSERT_TRUE(value64.has_value());
    EXPECT_EQ(*value16, std::uint16_t{0x1234U});
    EXPECT_EQ(*value32, std::uint32_t{0x89ABCDEFU});
    EXPECT_EQ(*value64, std::uint64_t{0x0123456789ABCDEFULL});
    EXPECT_TRUE(reader.data.empty());
}

TEST(WireFloatingPoint, PreservesFiniteValuesExactly) {
    expect_floating_point_round_trip(std::array<float, 7>{
        0.0F,
        -0.0F,
        -1.25F,
        std::numeric_limits<float>::min(),
        std::numeric_limits<float>::denorm_min(),
        std::numeric_limits<float>::max(),
        std::numeric_limits<float>::lowest(),
    });
    expect_floating_point_round_trip(std::array<double, 7>{
        0.0,
        -0.0,
        -1.25,
        std::numeric_limits<double>::min(),
        std::numeric_limits<double>::denorm_min(),
        std::numeric_limits<double>::max(),
        std::numeric_limits<double>::lowest(),
    });
}

TEST(WireEnums, RoundTripsDifferentUnderlyingTypes) {
    wire::Writer writer;
    wire::write_enum(writer, CompactState::Ready);
    wire::write_enum(writer, SignedState::Failed);
    wire::write_enum(writer, WideState::Complete);

    wire::Reader reader{writer.buffer};
    const auto compact = wire::read_enum<CompactState>(reader);
    const auto signed_value = wire::read_enum<SignedState>(reader);
    const auto wide = wire::read_enum<WideState>(reader);
    ASSERT_TRUE(compact.has_value());
    ASSERT_TRUE(signed_value.has_value());
    ASSERT_TRUE(wide.has_value());
    EXPECT_EQ(*compact, CompactState::Ready);
    EXPECT_EQ(*signed_value, SignedState::Failed);
    EXPECT_EQ(*wide, WideState::Complete);
    EXPECT_TRUE(reader.data.empty());
}

TEST(WireBytes, WritesAndReadsBlocksAndFixedArrays) {
    constexpr std::array block{
        std::byte{0x10},
        std::byte{0x20},
        std::byte{0x30},
    };
    constexpr std::array fixed{
        std::byte{0xDE},
        std::byte{0xAD},
        std::byte{0xBE},
        std::byte{0xEF},
    };

    wire::Writer writer;
    wire::write_bytes(writer, block);
    wire::write_array(writer, fixed);

    wire::Reader reader{writer.buffer};
    const auto decoded_block = wire::read_bytes(reader, block.size());
    ASSERT_TRUE(decoded_block.has_value());
    EXPECT_TRUE(std::equal(decoded_block->begin(),
                           decoded_block->end(),
                           block.begin(),
                           block.end()));

    const auto decoded_array = wire::read_array<fixed.size()>(reader);
    ASSERT_TRUE(decoded_array.has_value());
    EXPECT_EQ(*decoded_array, fixed);
    EXPECT_TRUE(reader.data.empty());
}

TEST(WireStrings, RoundTripsEmptyAsciiUtf8AndMaximumLengthStrings) {
    const std::string empty;
    const std::string ascii = "Kasumi wire format";
    const std::string utf8 = "cloud \xE2\x98\x81 sync \xE6\x97\xA5\xE6\x9C\xAC";
    const std::string at_limit(default_string_limit, 'x');

    wire::Writer writer;
    wire::write_string(writer, empty);
    wire::write_string(writer, ascii);
    wire::write_string(writer, utf8);
    wire::write_string(writer, at_limit);

    wire::Reader reader{writer.buffer};
    const auto decoded_empty = wire::read_string(reader, default_string_limit);
    const auto decoded_ascii = wire::read_string(reader, default_string_limit);
    const auto decoded_utf8 = wire::read_string(reader, default_string_limit);
    const auto decoded_at_limit = wire::read_string(reader);
    ASSERT_TRUE(decoded_empty.has_value());
    ASSERT_TRUE(decoded_ascii.has_value());
    ASSERT_TRUE(decoded_utf8.has_value());
    ASSERT_TRUE(decoded_at_limit.has_value());
    EXPECT_EQ(*decoded_empty, empty);
    EXPECT_EQ(*decoded_ascii, ascii);
    EXPECT_EQ(*decoded_utf8, utf8);
    EXPECT_EQ(*decoded_at_limit, at_limit);
    EXPECT_TRUE(reader.data.empty());
}

TEST(WireStrings, RejectsLengthAboveConfiguredLimit) {
    const std::string oversized(default_string_limit + 1, 'y');
    wire::Writer writer;
    wire::write_string(writer, oversized);

    wire::Reader reader{writer.buffer};
    const auto result = wire::read_string(reader, default_string_limit);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), wire::Error::InvalidLength);
}

TEST(WireStrings, RejectsTruncatedLengthPrefix) {
    constexpr std::array truncated_prefix{
        std::byte{0x05},
        std::byte{0x00},
        std::byte{0x00},
    };
    wire::Reader reader{truncated_prefix};

    const auto result = wire::read_string(reader, std::size_t{16});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), wire::Error::BufferUnderflow);
}

TEST(WireStrings, RejectsTruncatedPayload) {
    wire::Writer writer;
    wire::write<std::uint32_t>(writer, std::uint32_t{5});
    constexpr std::array partial_payload{
        std::byte{0x61},
        std::byte{0x62},
        std::byte{0x63},
    };
    wire::write_bytes(writer, partial_payload);
    wire::Reader reader{writer.buffer};

    const auto result = wire::read_string(reader, std::size_t{16});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), wire::Error::BufferUnderflow);
}

TEST(WireReader, SequentialReadsConsumeOnlyRequestedBytes) {
    const std::vector<std::byte> encoded{
        std::byte{0x7A},
        std::byte{0x34},
        std::byte{0x12},
        std::byte{0xAA},
        std::byte{0xBB},
    };
    wire::Reader reader{encoded};

    const auto first = wire::read<std::uint8_t>(reader);
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(*first, std::uint8_t{0x7A});
    ASSERT_EQ(reader.data.size(), std::size_t{4});
    EXPECT_EQ(reader.data.front(), std::byte{0x34});

    const auto second = wire::read<std::uint16_t>(reader);
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(*second, std::uint16_t{0x1234});
    ASSERT_EQ(reader.data.size(), std::size_t{2});
    EXPECT_EQ(reader.data.front(), std::byte{0xAA});

    const auto tail = wire::read_bytes(reader, std::size_t{2});
    ASSERT_TRUE(tail.has_value());
    EXPECT_EQ((*tail)[0], std::byte{0xAA});
    EXPECT_EQ((*tail)[1], std::byte{0xBB});
    EXPECT_TRUE(reader.data.empty());
}

TEST(WireReader, IntegerUnderflowDoesNotConsumeInput) {
    constexpr std::array input{std::byte{0x11}, std::byte{0x22}};
    wire::Reader reader{input};
    const auto* const original_data = reader.data.data();
    const auto original_size = reader.data.size();

    const auto result = wire::read<std::uint32_t>(reader);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), wire::Error::BufferUnderflow);
    EXPECT_EQ(reader.data.data(), original_data);
    EXPECT_EQ(reader.data.size(), original_size);
}

TEST(WireReader, ByteBlockUnderflowDoesNotConsumeInput) {
    constexpr std::array input{std::byte{0x11}, std::byte{0x22}};
    wire::Reader reader{input};
    const auto* const original_data = reader.data.data();
    const auto original_size = reader.data.size();

    const auto result = wire::read_bytes(reader, input.size() + 1);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), wire::Error::BufferUnderflow);
    EXPECT_EQ(reader.data.data(), original_data);
    EXPECT_EQ(reader.data.size(), original_size);
}

TEST(WireReader, FixedArrayUnderflowDoesNotConsumeInput) {
    constexpr std::array input{
        std::byte{0x11},
        std::byte{0x22},
        std::byte{0x33},
    };
    wire::Reader reader{input};
    const auto* const original_data = reader.data.data();
    const auto original_size = reader.data.size();

    const auto result = wire::read_array<4>(reader);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), wire::Error::BufferUnderflow);
    EXPECT_EQ(reader.data.data(), original_data);
    EXPECT_EQ(reader.data.size(), original_size);
}

} // namespace
