#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "runtime/paths.hpp"
#include "runtime/vault.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <gtest/gtest.h>
#include <thread>
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

#if defined(_WIN32) || defined(__linux__)
struct ScopedVaultEntry {
    std::filesystem::path key_path;
    ~ScopedVaultEntry() {
        static_cast<void>(kasumi::runtime::vault::delete_vault(key_path));
    }
};

TEST(VaultTest, OsVaultRoundTripsOverwritesAndDeletes) {
    auto workspace = kasumi::test::make_temp_workspace("vault-os-win");
    const auto key_path =
        kasumi::test::workspace_path(workspace, "app/profiles/demo/key.bin");
    const ScopedVaultEntry cleanup{key_path};

    const auto initial = kasumi::runtime::vault::read_vault(key_path);
    ASSERT_FALSE(initial.has_value());
    EXPECT_EQ(initial.error().code, kasumi::runtime::ErrorCode::KeyNotFound);

    KeyBytes key{};
    key.fill(0x3c);
    ASSERT_TRUE(kasumi::runtime::vault::write_vault(key_path, key));
    EXPECT_FALSE(std::filesystem::exists(key_path));
    const auto restored = kasumi::runtime::vault::read_vault(key_path);
    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(*restored, key);

    KeyBytes updated{};
    updated.fill(0x9a);
    ASSERT_TRUE(kasumi::runtime::vault::write_vault(key_path, updated));
    const auto restored_updated = kasumi::runtime::vault::read_vault(key_path);
    ASSERT_TRUE(restored_updated.has_value());
    EXPECT_EQ(*restored_updated, updated);

    ASSERT_TRUE(kasumi::runtime::vault::delete_vault(key_path));
    const auto after_delete = kasumi::runtime::vault::read_vault(key_path);
    ASSERT_FALSE(after_delete.has_value());
    EXPECT_EQ(after_delete.error().code,
              kasumi::runtime::ErrorCode::KeyNotFound);
    EXPECT_TRUE(kasumi::runtime::vault::delete_vault(key_path));
}

TEST(VaultTest, ProfileRemovalKeepsVaultKeyWhenDirectoryCannotBeRemoved) {
    auto workspace = kasumi::test::make_temp_workspace("vault-remove-profile");
    const auto paths = kasumi::runtime::resolve_profile_paths(
        kasumi::test::workspace_root(workspace), "demo");
    ASSERT_TRUE(paths) << paths.error().detail;
    const ScopedVaultEntry cleanup{paths->key_path};
    kasumi::test::write_text(paths->profile_dir, "blocked");

    KeyBytes key{};
    key.fill(0x3c);
    const auto stored =
        kasumi::runtime::vault::write_vault(paths->key_path, key);
    ASSERT_TRUE(stored) << stored.error().detail;
    EXPECT_FALSE(kasumi::runtime::remove_profile_directory(*paths));
    const auto retained = kasumi::runtime::vault::read_vault(paths->key_path);
    EXPECT_TRUE(retained && *retained == key);

    EXPECT_TRUE(std::filesystem::remove(paths->profile_dir));
    const auto removed = kasumi::runtime::remove_profile_directory(*paths);
    EXPECT_TRUE(removed) << (removed ? "" : removed.error().detail);
    const auto missing = kasumi::runtime::vault::read_vault(paths->key_path);
    ASSERT_FALSE(missing);
    EXPECT_EQ(missing.error().code, kasumi::runtime::ErrorCode::KeyNotFound);
}

TEST(VaultTest, ConcurrentOsVaultWritesAndDeletesSucceed) {
    auto workspace = kasumi::test::make_temp_workspace("vault-os-concurrent");
#if defined(_WIN32)
    constexpr std::size_t worker_count = 8;
    constexpr std::size_t iterations = 25;
#else
    constexpr std::size_t worker_count = 4;
    constexpr std::size_t iterations = 10;
#endif
    std::vector<std::filesystem::path> key_paths;
    key_paths.reserve(worker_count);
    for (std::size_t index = 0; index < worker_count; ++index) {
        key_paths.push_back(kasumi::test::workspace_path(
            workspace,
            "app/profiles/worker-" + std::to_string(index) + "/key.bin"));
    }

    struct BatchVaultCleanup {
        const std::vector<std::filesystem::path>& paths;
        ~BatchVaultCleanup() {
            for (const auto& path : paths) {
                static_cast<void>(kasumi::runtime::vault::delete_vault(path));
            }
        }
    } const cleanup{key_paths};

    std::atomic<std::size_t> ready{0};
    std::atomic<bool> start{false};
    std::atomic<bool> ok{true};
    std::vector<std::thread> workers;
    workers.reserve(worker_count);

    for (std::size_t index = 0; index < worker_count; ++index) {
        workers.emplace_back([&, index] {
            ready.fetch_add(1, std::memory_order_acq_rel);
            while (!start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            for (std::size_t iter = 0; iter < iterations; ++iter) {
                KeyBytes key{};
                key.fill(
                    static_cast<std::uint8_t>((0x21U + index + iter) & 0xFFU));
                if (!kasumi::runtime::vault::write_vault(key_paths[index],
                                                         key)) {
                    ok.store(false, std::memory_order_release);
                    return;
                }
                const auto restored =
                    kasumi::runtime::vault::read_vault(key_paths[index]);
                if (!restored || *restored != key) {
                    ok.store(false, std::memory_order_release);
                    return;
                }
                if (!kasumi::runtime::vault::delete_vault(key_paths[index])) {
                    ok.store(false, std::memory_order_release);
                    return;
                }
            }
        });
    }

    while (ready.load(std::memory_order_acquire) < worker_count) {
        std::this_thread::yield();
    }
    start.store(true, std::memory_order_release);
    for (auto& worker : workers) {
        worker.join();
    }
    EXPECT_TRUE(ok.load(std::memory_order_acquire));
}
#endif

} // namespace
