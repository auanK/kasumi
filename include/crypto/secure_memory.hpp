#ifndef KASUMI_CRYPTO_SECURE_MEMORY_HPP
#define KASUMI_CRYPTO_SECURE_MEMORY_HPP

#include <cstddef>
#include <type_traits>

namespace kasumi::crypto::secure_memory {

// Overwrites memory without allowing compiler dead-store elimination.
void wipe(void* memory, std::size_t size) noexcept;

template <typename T> class WipeGuard {
public:
    explicit WipeGuard(T& target, bool* skip = nullptr) noexcept
        : target_(&target), skip_(skip) {
    }
    WipeGuard(const WipeGuard&) = delete;
    WipeGuard& operator=(const WipeGuard&) = delete;
    ~WipeGuard() noexcept {
        if (skip_ == nullptr || !*skip_) {
            if constexpr (requires {
                              target_->data();
                              target_->size();
                          }) {
                if (!target_->empty()) {
                    wipe(target_->data(),
                         target_->size() * sizeof((*target_)[0]));
                }
            } else {
                wipe(target_, sizeof(T));
            }
        }
    }

private:
    T* target_;
    bool* skip_;
};

} // namespace kasumi::crypto::secure_memory

#endif
