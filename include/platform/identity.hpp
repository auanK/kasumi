#ifndef KASUMI_PLATFORM_IDENTITY_HPP
#define KASUMI_PLATFORM_IDENTITY_HPP

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>

namespace kasumi::platform::identity {

// Maximum length of machine identification in characters.
inline constexpr std::size_t maximum_machine_id_size = 255;

// Machine and process identity.
struct Identity {
    std::string machine_id;
    std::uint64_t process_id = 0;
};

// Validates format, length, and non-zero process_id.
bool valid(const Identity& identity) noexcept;

// Obtains a valid identity for the current process.
std::expected<Identity, std::string> current();

} // namespace kasumi::platform::identity

#endif
