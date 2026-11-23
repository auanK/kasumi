#include "application/history_storage/epoch.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    const std::span<const std::uint8_t> bytes{data, size};
    static_cast<void>(
        kasumi::application::history_storage::epoch::decode(bytes));
    static const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    static const kasumi::application::history_storage::epoch::Reference ref{
        .sequence = 0,
        .epoch_id = std::string(64, '0'),
    };
    static_cast<void>(
        kasumi::application::history_storage::epoch::open(bytes, ref, key));
    return 0;
}
