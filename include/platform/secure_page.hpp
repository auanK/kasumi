#ifndef KASUMI_PLATFORM_SECURE_PAGE_HPP
#define KASUMI_PLATFORM_SECURE_PAGE_HPP

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace kasumi::platform {

inline constexpr std::size_t kSecureKeySlotSize = 32;

struct SecurePageState;
void destroy_secure_page(SecurePageState* state) noexcept;

// Dedicated OS memory page handle pinned best-effort against swapping and core
// dumps, wiping its entire contents before release.
struct SecurePage {
    std::unique_ptr<SecurePageState, void (*)(SecurePageState*) noexcept> state{
        nullptr, &destroy_secure_page};
};

std::expected<SecurePage, std::string> allocate_secure_page();
void release_secure_page(SecurePage& page) noexcept;
[[nodiscard]] bool secure_page_valid(const SecurePage& page) noexcept;
[[nodiscard]] bool secure_page_locked(const SecurePage& page) noexcept;
[[nodiscard]] std::size_t secure_page_size(const SecurePage& page) noexcept;
[[nodiscard]] std::span<std::uint8_t>
secure_page_bytes(SecurePage& page) noexcept;
[[nodiscard]] std::span<const std::uint8_t>
secure_page_bytes(const SecurePage& page) noexcept;

struct SecureKeyArenaState;
void destroy_secure_key_arena(SecureKeyArenaState* state) noexcept;

// Stores named 32-byte keys inside OS-pinned SecurePage SoA slots rather than
// swappable general-purpose heap allocations.
struct SecureKeyArena {
    std::unique_ptr<SecureKeyArenaState,
                    void (*)(SecureKeyArenaState*) noexcept>
        state{nullptr, &destroy_secure_key_arena};
};

[[nodiscard]] SecureKeyArena create_secure_key_arena();

std::expected<void, std::string>
store_secure_key(SecureKeyArena& arena,
                 std::string_view key_name,
                 std::span<const std::uint8_t, kSecureKeySlotSize> key);

bool read_secure_key(
    const SecureKeyArena& arena,
    std::string_view key_name,
    std::span<std::uint8_t, kSecureKeySlotSize> output) noexcept;

[[nodiscard]] bool contains_secure_key(const SecureKeyArena& arena,
                                       std::string_view key_name) noexcept;

bool erase_secure_key(SecureKeyArena& arena,
                      std::string_view key_name) noexcept;

void clear_secure_key_arena(SecureKeyArena& arena) noexcept;
[[nodiscard]] std::size_t
secure_key_arena_size(const SecureKeyArena& arena) noexcept;
[[nodiscard]] bool
secure_key_arena_all_pages_locked(const SecureKeyArena& arena) noexcept;

} // namespace kasumi::platform

#endif
