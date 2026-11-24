#include "platform/secure_page.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <gtest/gtest.h>

namespace {

TEST(SecurePageTest, AllocatesWritesAndMovesCleanly) {
    auto allocated = kasumi::platform::allocate_secure_page();
    ASSERT_TRUE(allocated.has_value()) << allocated.error();
    EXPECT_TRUE(kasumi::platform::secure_page_valid(*allocated));
    EXPECT_GE(kasumi::platform::secure_page_size(*allocated), 4096U);

    kasumi::platform::secure_page_bytes(*allocated)[0] = 0x5AU;
    kasumi::platform::secure_page_bytes(
        *allocated)[kasumi::platform::secure_page_size(*allocated) - 1U] =
        0xA5U;

    auto moved = std::move(*allocated);
    EXPECT_FALSE(kasumi::platform::secure_page_valid(*allocated));
    EXPECT_TRUE(kasumi::platform::secure_page_valid(moved));
    EXPECT_EQ(kasumi::platform::secure_page_bytes(moved)[0], 0x5AU);
    EXPECT_EQ(kasumi::platform::secure_page_bytes(
                  moved)[kasumi::platform::secure_page_size(moved) - 1U],
              0xA5U);
}

TEST(SecureKeyArenaTest, StoresReadsReplacesAndWipesMultipleKeys) {
    auto arena = kasumi::platform::create_secure_key_arena();
    std::array<std::uint8_t, 32> key_a{};
    std::array<std::uint8_t, 32> key_b{};
    key_a.fill(0x11U);
    key_b.fill(0x22U);

    ASSERT_TRUE(
        kasumi::platform::store_secure_key(arena, "work", key_a).has_value());
    ASSERT_TRUE(kasumi::platform::store_secure_key(arena, "personal", key_b)
                    .has_value());
    EXPECT_EQ(kasumi::platform::secure_key_arena_size(arena), 2U);
    EXPECT_TRUE(kasumi::platform::contains_secure_key(arena, "work"));
    EXPECT_TRUE(kasumi::platform::contains_secure_key(arena, "personal"));

    std::array<std::uint8_t, 32> out{};
    EXPECT_TRUE(kasumi::platform::read_secure_key(arena, "work", out));
    EXPECT_EQ(out, key_a);
    EXPECT_TRUE(kasumi::platform::read_secure_key(arena, "personal", out));
    EXPECT_EQ(out, key_b);

    key_a.fill(0x33U);
    ASSERT_TRUE(
        kasumi::platform::store_secure_key(arena, "work", key_a).has_value());
    EXPECT_EQ(kasumi::platform::secure_key_arena_size(arena), 2U);
    EXPECT_TRUE(kasumi::platform::read_secure_key(arena, "work", out));
    EXPECT_EQ(out, key_a);

    EXPECT_TRUE(kasumi::platform::erase_secure_key(arena, "work"));
    EXPECT_FALSE(kasumi::platform::contains_secure_key(arena, "work"));
    EXPECT_FALSE(kasumi::platform::read_secure_key(arena, "work", out));
    EXPECT_EQ(kasumi::platform::secure_key_arena_size(arena), 1U);

    kasumi::platform::clear_secure_key_arena(arena);
    EXPECT_EQ(kasumi::platform::secure_key_arena_size(arena), 0U);
    EXPECT_FALSE(kasumi::platform::contains_secure_key(arena, "personal"));
}

} // namespace
