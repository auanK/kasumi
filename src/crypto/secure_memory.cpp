#include "crypto/secure_memory.hpp"

#include <monocypher.h>

namespace kasumi::crypto::secure_memory {

void wipe(void* memory, std::size_t size) noexcept {
    crypto_wipe(memory, size);
}

} // namespace kasumi::crypto::secure_memory
