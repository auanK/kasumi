#include "core/hasher.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <string_view>

namespace {

using kasumi::Hash;
using kasumi::hash_from_hex;
using kasumi::hash_hex;
using kasumi::HASH_HEX_SIZE;

static_assert(HASH_HEX_SIZE == 64);

constexpr std::string_view empty_blake3_hex =
    "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

std::string uppercase_ascii_hex(std::string text) {
    std::ranges::transform(text, text.begin(), [](const char value) {
        if (value >= 'a' && value <= 'f')
            return static_cast<char>(value - 'a' + 'A');
        return value;
    });
    return text;
}

TEST(HasherDigest, EquivalentBytesAndStringHaveTheSameHash) {
    std::string contents = "Equivalent binary input";
    contents.push_back('\0');
    contents.append("with data after the embedded null byte.");
    const auto bytes =
        std::as_bytes(std::span<const char>{contents.data(), contents.size()});
    const Hash bytes_hash =
        kasumi::hasher::hash_bytes(bytes.data(), bytes.size());
    const Hash string_hash = kasumi::hasher::hash_string(contents);

    EXPECT_EQ(bytes_hash, string_hash);
}

TEST(HasherDigest, MatchesKnownBlake3VectorForEmptyInput) {
    const Hash digest = kasumi::hasher::hash_string({});

    EXPECT_EQ(hash_hex(digest), empty_blake3_hex);
}

TEST(HasherDigest, IsDeterministicForRepeatedInput) {
    constexpr std::string_view contents =
        "Deterministic hashing must not depend on prior calls.";

    const Hash first = kasumi::hasher::hash_string(contents);
    const Hash second = kasumi::hasher::hash_string(contents);

    EXPECT_EQ(first, second);
    EXPECT_EQ(hash_hex(first), hash_hex(second));
}

TEST(HasherHex, ConvertsToLowercaseHexAndBack) {
    const Hash digest = kasumi::hasher::hash_string("hex round trip");

    const std::string encoded = hash_hex(digest);
    const auto decoded = hash_from_hex(encoded);

    EXPECT_EQ(encoded.size(), HASH_HEX_SIZE);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, digest);
}

TEST(HasherHex, BufferOverloadWritesExactlyTheFixedDigestLength) {
    const Hash digest = kasumi::hasher::hash_string("bounded hex output");
    constexpr char sentinel = '!';
    std::array<char, HASH_HEX_SIZE + 1> output{};
    output.fill(sentinel);

    hash_hex(digest, output.data());

    EXPECT_EQ(output.back(), sentinel);
    EXPECT_EQ(std::string_view(output.data(), HASH_HEX_SIZE), hash_hex(digest));
}

TEST(HasherHex, AcceptsUppercaseAndLowercaseDigits) {
    const Hash digest = kasumi::hasher::hash_string("case-insensitive hex");
    const std::string lowercase = hash_hex(digest);
    const std::string uppercase = uppercase_ascii_hex(lowercase);

    const auto decoded_lowercase = hash_from_hex(lowercase);
    const auto decoded_uppercase = hash_from_hex(uppercase);

    ASSERT_TRUE(decoded_lowercase.has_value());
    ASSERT_TRUE(decoded_uppercase.has_value());
    EXPECT_EQ(*decoded_lowercase, digest);
    EXPECT_EQ(*decoded_uppercase, digest);
}

TEST(HasherHex, RejectsIncorrectLengths) {
    const std::string too_short(HASH_HEX_SIZE - 1, '0');
    const std::string too_long(HASH_HEX_SIZE + 1, '0');

    EXPECT_FALSE(hash_from_hex(too_short).has_value());
    EXPECT_FALSE(hash_from_hex(too_long).has_value());
}

TEST(HasherHex, RejectsNonHexadecimalCharacters) {
    std::string invalid(HASH_HEX_SIZE, '0');
    invalid[HASH_HEX_SIZE / 2] = 'g';

    EXPECT_FALSE(hash_from_hex(invalid).has_value());
}

TEST(HasherHashKey, IsStableForTheSameDigest) {
    const Hash digest = kasumi::hasher::hash_string("stable hash key");
    const Hash copy = digest;

    EXPECT_EQ(kasumi::hash_key(digest), kasumi::hash_key(digest));
    EXPECT_EQ(kasumi::hash_key(digest), kasumi::hash_key(copy));
}

} // namespace
