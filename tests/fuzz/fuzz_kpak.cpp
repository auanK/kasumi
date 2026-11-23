#include "crypto/pack.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    std::vector<std::uint8_t> plaintext(data, data + size);
    static_cast<void>(
        kasumi::crypto::pack::decode_verified_pack_plaintext(
            std::move(plaintext)));
    return 0;
}
