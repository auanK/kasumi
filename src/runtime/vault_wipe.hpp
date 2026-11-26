#ifndef KASUMI_RUNTIME_VAULT_WIPE_HPP
#define KASUMI_RUNTIME_VAULT_WIPE_HPP

#include <monocypher.h>

namespace kasumi::runtime::vault {

template <typename T> struct WipeGuard {
    T& value;

    ~WipeGuard() noexcept {
        crypto_wipe(value.data(), value.size());
    }
};

} // namespace kasumi::runtime::vault

#endif
