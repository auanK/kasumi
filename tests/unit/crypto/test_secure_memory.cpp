#include "crypto/secure_memory.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>

namespace {

TEST(SecureMemoryTest, WipesEntireRequestedBuffer) {
    std::array<std::uint8_t, 32> bytes;
    bytes.fill(0xA5U);

    kasumi::crypto::secure_memory::wipe(bytes.data(), bytes.size());

    for (const auto byte : bytes) {
        EXPECT_EQ(byte, 0U);
    }
}

TEST(SecureMemoryTest, WipesOnlyRequestedRange) {
    std::array<std::uint8_t, 8> bytes;
    bytes.fill(0xA5U);

    kasumi::crypto::secure_memory::wipe(bytes.data() + 2, 4);

    EXPECT_EQ(bytes[0], 0xA5U);
    EXPECT_EQ(bytes[1], 0xA5U);
    EXPECT_EQ(bytes[2], 0U);
    EXPECT_EQ(bytes[3], 0U);
    EXPECT_EQ(bytes[4], 0U);
    EXPECT_EQ(bytes[5], 0U);
    EXPECT_EQ(bytes[6], 0xA5U);
    EXPECT_EQ(bytes[7], 0xA5U);
}

} // namespace
