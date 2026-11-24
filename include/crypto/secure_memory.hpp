#ifndef KASUMI_CRYPTO_SECURE_MEMORY_HPP
#define KASUMI_CRYPTO_SECURE_MEMORY_HPP

#include <cstddef>
#include <type_traits>

namespace kasumi::crypto::secure_memory {

// Overwrites memory without allowing compiler dead-store elimination.
void wipe(void* memory, std::size_t size) noexcept;

template <typename T> struct WipeGuard {
    T* target = nullptr;
    bool* skip = nullptr;

    explicit WipeGuard(T& target_ref, bool* skip_ptr = nullptr) noexcept
        : target(&target_ref), skip(skip_ptr) {
    }
    WipeGuard(const WipeGuard&) = delete;
    WipeGuard& operator=(const WipeGuard&) = delete;
    ~WipeGuard() noexcept {
        if ((skip == nullptr || !*skip) && target != nullptr) {
            if constexpr (requires {
                              target->data();
                              target->size();
                          }) {
                if (!target->empty()) {
                    wipe(target->data(), target->size() * sizeof((*target)[0]));
                }
            } else {
                wipe(target, sizeof(T));
            }
        }
    }
};

} // namespace kasumi::crypto::secure_memory

#endif
