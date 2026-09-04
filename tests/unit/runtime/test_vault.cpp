#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "runtime/vault.hpp"

#include <algorithm>
#include <array>
#include <gtest/gtest.h>
#include <vector>

namespace {

using kasumi::runtime::vault::KeyBytes;
using kasumi::test::TempWorkspace;

std::string hex(const KeyBytes& key) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result(key.size() * 2, '0');
    for (std::size_t index = 0; index < key.size(); ++index) {
        result[index * 2] = digits[key[index] >> 4];
        result[index * 2 + 1] = digits[key[index] & 0x0fU];
    }
    return result;
}

TEST(VaultTest, DecodesUpperAndLowerHexAndRejectsMalformedInput) {
    const auto lower = kasumi::runtime::vault::decode_hex(std::string(64, 'a'));
    const auto upper = kasumi::runtime::vault::decode_hex(std::string(64, 'A'));
    ASSERT_TRUE(lower.has_value());
    ASSERT_TRUE(upper.has_value());
    EXPECT_EQ(*lower, *upper);
    EXPECT_FALSE(kasumi::runtime::vault::decode_hex("00").has_value());
    std::string invalid(64, '0');
    invalid[10] = 'z';
    EXPECT_FALSE(kasumi::runtime::vault::decode_hex(invalid).has_value());
}

TEST(VaultTest, ObscureIsDeterministicAndReversible) {
    KeyBytes original{};
    for (std::size_t index = 0; index < original.size(); ++index)
        original[index] = static_cast<std::uint8_t>(index + 1);
    auto stored = original;
    kasumi::runtime::vault::obscure(stored);
    EXPECT_NE(stored, original);
    kasumi::runtime::vault::obscure(stored);
    EXPECT_EQ(stored, original);
}

TEST(VaultTest, WritesObscuredBytesAndReadsExactKey) {
    auto workspace = kasumi::test::make_temp_workspace("vault-roundtrip");
    KeyBytes key{};
    key.fill(0x5a);
    const auto path = kasumi::test::workspace_path(workspace, "nested/key.bin");
    ASSERT_TRUE(kasumi::runtime::vault::write(path, key));
    ASSERT_TRUE(std::filesystem::exists(path));
    const auto restored = kasumi::runtime::vault::read(path);
    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(*restored, key);
    const auto raw = kasumi::test::read_binary(path);
    kasumi::test::BinaryData clear_bytes;
    for (const auto value : key)
        clear_bytes.push_back(static_cast<std::byte>(value));
    EXPECT_NE(raw, clear_bytes);
}

TEST(VaultTest, RejectsMissingShortAndLongFiles) {
    auto workspace = kasumi::test::make_temp_workspace("vault-errors");
    EXPECT_EQ(kasumi::runtime::vault::read(
                  kasumi::test::workspace_path(workspace, "missing"))
                  .error()
                  .code,
              kasumi::runtime::ErrorCode::KeyNotFound);
    kasumi::test::write_binary(kasumi::test::workspace_path(workspace, "short"),
                               {std::byte{1}});
    EXPECT_EQ(kasumi::runtime::vault::read(
                  kasumi::test::workspace_path(workspace, "short"))
                  .error()
                  .code,
              kasumi::runtime::ErrorCode::KeyNotFound);
    const std::vector<std::byte> long_bytes(33, std::byte{1});
    kasumi::test::write_binary(kasumi::test::workspace_path(workspace, "long"),
                               long_bytes);
    EXPECT_EQ(kasumi::runtime::vault::read(
                  kasumi::test::workspace_path(workspace, "long"))
                  .error()
                  .code,
              kasumi::runtime::ErrorCode::KeyInvalid);
}

TEST(VaultTest, DerivationIsDeterministicAndDependsOnInputs) {
    const auto first =
        kasumi::runtime::vault::derive("password-long", "context-secret-1");
    const auto same =
        kasumi::runtime::vault::derive("password-long", "context-secret-1");
    const auto different =
        kasumi::runtime::vault::derive("password-long-2", "context-secret-1");
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(same.has_value());
    ASSERT_TRUE(different.has_value());
    EXPECT_EQ(*first, *same);
    EXPECT_NE(*first, *different);
    EXPECT_NE(*first, KeyBytes{});
    EXPECT_EQ(
        hex(*first),
        "467253d665eb1231255d7d3351a29f22cb846bf75f3f1bdee04c476bed9a1668");
}

TEST(VaultTest, RejectsWeakPasswordInputs) {
    EXPECT_FALSE(kasumi::runtime::vault::derive("short", "context-secret-1"));
    EXPECT_FALSE(kasumi::runtime::vault::derive("password-long", "short"));
}

} // namespace
