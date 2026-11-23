#include "application/history_storage/activity.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    static_cast<void>(kasumi::application::history_storage::activity::decode(
        std::span<const std::uint8_t>{data, size}));
    return 0;
}
