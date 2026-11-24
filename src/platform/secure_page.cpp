#include "platform/secure_page.hpp"

#include <algorithm>
#include <cstring>
#include <monocypher.h>
#include <mutex>
#include <new>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cerrno>
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace kasumi::platform {

struct SecurePageState {
    std::uint8_t* data = nullptr;
    std::size_t size = 0;
    bool locked = false;
};

struct SecureKeyArenaState {
    mutable std::mutex mutex;
    std::vector<SecurePage> pages;
    // Dense SoA active slot table (linearly scanned, swap-and-popped on erase).
    std::vector<std::string> slot_names;
    std::vector<std::size_t> slot_page_indices;
    std::vector<std::size_t> slot_offsets;
    // Parallel free-slot stacks reusing pinned page offsets after erasures.
    std::vector<std::size_t> free_page_indices;
    std::vector<std::size_t> free_offsets;
};

namespace {

std::size_t system_page_size() noexcept {
#if defined(_WIN32)
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    return info.dwPageSize >= 4096U ? static_cast<std::size_t>(info.dwPageSize)
                                    : 4096U;
#else
    const long page = ::sysconf(_SC_PAGESIZE);
    return page >= 4096L ? static_cast<std::size_t>(page) : 4096U;
#endif
}

std::size_t find_key_slot_locked(const SecureKeyArenaState& state,
                                 std::string_view key_name) noexcept {
    for (std::size_t i = 0; i < state.slot_names.size(); ++i) {
        if (state.slot_names[i] == key_name) {
            return i;
        }
    }
    return state.slot_names.size();
}

void release_page_state(SecurePageState& state) noexcept {
    if (state.data == nullptr || state.size == 0) {
        state.data = nullptr;
        state.size = 0;
        state.locked = false;
        return;
    }
    crypto_wipe(state.data, state.size);
#if defined(_WIN32)
    if (state.locked) {
        static_cast<void>(VirtualUnlock(state.data, state.size));
    }
    static_cast<void>(VirtualFree(state.data, 0, MEM_RELEASE));
#else
    if (state.locked) {
        static_cast<void>(::munlock(state.data, state.size));
    }
    static_cast<void>(::munmap(state.data, state.size));
#endif
    state.data = nullptr;
    state.size = 0;
    state.locked = false;
}

void wipe_and_clear_arena_locked(SecureKeyArenaState& state) noexcept {
    for (std::size_t i = 0; i < state.slot_names.size(); ++i) {
        const std::size_t page_idx = state.slot_page_indices[i];
        const std::size_t offset = state.slot_offsets[i];
        auto bytes = secure_page_bytes(state.pages[page_idx]);
        if (offset + kSecureKeySlotSize <= bytes.size()) {
            crypto_wipe(bytes.data() + offset, kSecureKeySlotSize);
        }
    }
    state.slot_names.clear();
    state.slot_page_indices.clear();
    state.slot_offsets.clear();
    state.free_page_indices.clear();
    state.free_offsets.clear();
    state.pages.clear();
}

} // namespace

void destroy_secure_page(SecurePageState* state) noexcept {
    if (state == nullptr) {
        return;
    }
    release_page_state(*state);
    delete state;
}

std::expected<SecurePage, std::string> allocate_secure_page() {
    const std::size_t page_size = system_page_size();
    std::unique_ptr<SecurePageState, void (*)(SecurePageState*) noexcept>
        state_holder{new (std::nothrow) SecurePageState{},
                     &destroy_secure_page};
    if (!state_holder) {
        return std::unexpected("out of memory allocating SecurePageState");
    }
#if defined(_WIN32)
    void* ptr = VirtualAlloc(
        nullptr, page_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (ptr == nullptr) {
        return std::unexpected(
            "VirtualAlloc failed with error " +
            std::to_string(static_cast<unsigned long>(GetLastError())));
    }
    state_holder->data = static_cast<std::uint8_t*>(ptr);
    state_holder->size = page_size;
    state_holder->locked = VirtualLock(ptr, page_size) != 0;
#else
    void* ptr = ::mmap(nullptr,
                       page_size,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS,
                       -1,
                       0);
    if (ptr == MAP_FAILED) {
        return std::unexpected("mmap failed with errno " +
                               std::to_string(errno));
    }
    state_holder->data = static_cast<std::uint8_t*>(ptr);
    state_holder->size = page_size;
    state_holder->locked = (::mlock(ptr, page_size) == 0);
#ifdef MADV_DONTDUMP
    static_cast<void>(::madvise(ptr, page_size, MADV_DONTDUMP));
#endif
#ifdef MADV_WIPEONFORK
    static_cast<void>(::madvise(ptr, page_size, MADV_WIPEONFORK));
#endif
#endif
    return SecurePage{.state = std::move(state_holder)};
}

void release_secure_page(SecurePage& page) noexcept {
    page.state.reset();
}

bool secure_page_valid(const SecurePage& page) noexcept {
    return page.state != nullptr && page.state->data != nullptr &&
           page.state->size > 0;
}

bool secure_page_locked(const SecurePage& page) noexcept {
    return page.state != nullptr && page.state->locked;
}

std::size_t secure_page_size(const SecurePage& page) noexcept {
    return page.state != nullptr ? page.state->size : 0U;
}

std::span<std::uint8_t> secure_page_bytes(SecurePage& page) noexcept {
    if (!secure_page_valid(page)) {
        return {};
    }
    return {page.state->data, page.state->size};
}

std::span<const std::uint8_t>
secure_page_bytes(const SecurePage& page) noexcept {
    if (!secure_page_valid(page)) {
        return {};
    }
    return {page.state->data, page.state->size};
}

void destroy_secure_key_arena(SecureKeyArenaState* state) noexcept {
    if (state == nullptr) {
        return;
    }
    {
        std::lock_guard lock(state->mutex);
        wipe_and_clear_arena_locked(*state);
    }
    delete state;
}

SecureKeyArena create_secure_key_arena() {
    return SecureKeyArena{
        .state = {new SecureKeyArenaState{}, &destroy_secure_key_arena},
    };
}

std::expected<void, std::string>
store_secure_key(SecureKeyArena& arena,
                 std::string_view key_name,
                 std::span<const std::uint8_t, kSecureKeySlotSize> key) {
    if (key_name.empty()) {
        return std::unexpected("key name cannot be empty");
    }
    if (!arena.state) {
        arena = create_secure_key_arena();
    }
    auto& state = *arena.state;
    std::lock_guard lock(state.mutex);
    const std::size_t existing = find_key_slot_locked(state, key_name);
    if (existing < state.slot_names.size()) {
        const std::size_t page_idx = state.slot_page_indices[existing];
        const std::size_t offset = state.slot_offsets[existing];
        std::memcpy(secure_page_bytes(state.pages[page_idx]).data() + offset,
                    key.data(),
                    kSecureKeySlotSize);
        return {};
    }

    if (state.free_page_indices.empty()) {
        auto page = allocate_secure_page();
        if (!page) {
            return std::unexpected(page.error());
        }
        const std::size_t page_idx = state.pages.size();
        const std::size_t slot_count =
            secure_page_size(*page) / kSecureKeySlotSize;
        if (slot_count == 0) {
            return std::unexpected("secure page is too small for a key slot");
        }
        state.pages.push_back(std::move(*page));
        // Push in reverse so earlier offsets are handed out first.
        for (std::size_t idx = slot_count; idx > 0; --idx) {
            state.free_page_indices.push_back(page_idx);
            state.free_offsets.push_back((idx - 1U) * kSecureKeySlotSize);
        }
    }

    const std::size_t page_idx = state.free_page_indices.back();
    const std::size_t offset = state.free_offsets.back();
    state.free_page_indices.pop_back();
    state.free_offsets.pop_back();
    try {
        state.slot_names.emplace_back(key_name);
        state.slot_page_indices.push_back(page_idx);
        state.slot_offsets.push_back(offset);
    } catch (...) {
        const std::size_t min_len = std::min({state.slot_names.size(),
                                              state.slot_page_indices.size(),
                                              state.slot_offsets.size()});
        state.slot_names.resize(min_len);
        state.slot_page_indices.resize(min_len);
        state.slot_offsets.resize(min_len);
        state.free_page_indices.push_back(page_idx);
        state.free_offsets.push_back(offset);
        return std::unexpected("failed to allocate entry in key arena");
    }

    std::memcpy(secure_page_bytes(state.pages[page_idx]).data() + offset,
                key.data(),
                kSecureKeySlotSize);
    return {};
}

bool read_secure_key(
    const SecureKeyArena& arena,
    std::string_view key_name,
    std::span<std::uint8_t, kSecureKeySlotSize> output) noexcept {
    if (!arena.state) {
        return false;
    }
    auto& state = *arena.state;
    std::lock_guard lock(state.mutex);
    const std::size_t found = find_key_slot_locked(state, key_name);
    if (found >= state.slot_names.size()) {
        return false;
    }
    const std::size_t page_idx = state.slot_page_indices[found];
    const std::size_t offset = state.slot_offsets[found];
    std::memcpy(output.data(),
                secure_page_bytes(state.pages[page_idx]).data() + offset,
                kSecureKeySlotSize);
    return true;
}

bool contains_secure_key(const SecureKeyArena& arena,
                         std::string_view key_name) noexcept {
    if (!arena.state) {
        return false;
    }
    auto& state = *arena.state;
    std::lock_guard lock(state.mutex);
    return find_key_slot_locked(state, key_name) < state.slot_names.size();
}

bool erase_secure_key(SecureKeyArena& arena,
                      std::string_view key_name) noexcept {
    if (!arena.state) {
        return false;
    }
    auto& state = *arena.state;
    std::lock_guard lock(state.mutex);
    const std::size_t found = find_key_slot_locked(state, key_name);
    if (found >= state.slot_names.size()) {
        return false;
    }
    const std::size_t page_idx = state.slot_page_indices[found];
    const std::size_t offset = state.slot_offsets[found];
    crypto_wipe(secure_page_bytes(state.pages[page_idx]).data() + offset,
                kSecureKeySlotSize);

    const std::size_t last = state.slot_names.size() - 1U;
    if (found != last) {
        state.slot_names[found] = std::move(state.slot_names[last]);
        state.slot_page_indices[found] = state.slot_page_indices[last];
        state.slot_offsets[found] = state.slot_offsets[last];
    }
    state.slot_names.pop_back();
    state.slot_page_indices.pop_back();
    state.slot_offsets.pop_back();

    state.free_page_indices.push_back(page_idx);
    state.free_offsets.push_back(offset);
    return true;
}

void clear_secure_key_arena(SecureKeyArena& arena) noexcept {
    if (!arena.state) {
        return;
    }
    auto& state = *arena.state;
    std::lock_guard lock(state.mutex);
    wipe_and_clear_arena_locked(state);
}

std::size_t secure_key_arena_size(const SecureKeyArena& arena) noexcept {
    if (!arena.state) {
        return 0U;
    }
    auto& state = *arena.state;
    std::lock_guard lock(state.mutex);
    return state.slot_names.size();
}

bool secure_key_arena_all_pages_locked(const SecureKeyArena& arena) noexcept {
    if (!arena.state) {
        return true;
    }
    auto& state = *arena.state;
    std::lock_guard lock(state.mutex);
    return std::ranges::all_of(state.pages, [](const SecurePage& page) {
        return secure_page_locked(page);
    });
}

} // namespace kasumi::platform
