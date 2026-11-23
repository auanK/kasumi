#include "core/transaction/codec.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    const std::span<const std::byte> bytes{
        reinterpret_cast<const std::byte*>(data), size};
    static_cast<void>(kasumi::transaction::codec::decode(bytes));
    return 0;
}
