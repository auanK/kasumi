#ifndef KASUMI_CRYPTO_SECURE_MEMORY_HPP
#define KASUMI_CRYPTO_SECURE_MEMORY_HPP

#include <cstddef>

namespace kasumi::crypto::secure_memory {

// Overwrites memory without allowing compiler dead-store elimination.
void wipe(void* memory, std::size_t size) noexcept;

} // namespace kasumi::crypto::secure_memory

#endif
