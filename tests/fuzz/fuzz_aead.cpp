#include "crypto/file_crypto.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    if (size == 0U) {
        return 0;
    }
    static constexpr std::array<kasumi::crypto::FilePurpose, 4> purposes{
        kasumi::crypto::FilePurpose::Content,
        kasumi::crypto::FilePurpose::History,
        kasumi::crypto::FilePurpose::Pack,
        kasumi::crypto::FilePurpose::Activity,
    };
    static const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    const auto purpose = purposes[data[0] % purposes.size()];
    static_cast<void>(kasumi::crypto::decrypt_bytes(
        std::span<const std::uint8_t>{data + 1U, size - 1U}, key, purpose));
    return 0;
}
