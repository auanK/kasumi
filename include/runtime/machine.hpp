#ifndef KASUMI_RUNTIME_MACHINE_HPP
#define KASUMI_RUNTIME_MACHINE_HPP

#include "runtime/error.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>

namespace kasumi::runtime {

inline constexpr std::size_t MACHINE_ID_BYTES = 16;
inline constexpr std::size_t MACHINE_ID_HEX_LENGTH = MACHINE_ID_BYTES * 2;

struct MachineIdentity {
    std::array<std::uint8_t, MACHINE_ID_BYTES> id{};
    // Lowercase 32-char hexadecimal ID; empty only when allow_create == false
    // and machine.id has not been initialized yet.
    std::string id_hex;
    std::string name;
};

// Loads or initializes the persistent installation machine identity stored at
// app_data_dir / "machine.id". When allow_create is false, reads an existing
// file (still validating format and rejecting symlinks) without creating any
// directory or file if absent.
std::expected<MachineIdentity, Error>
resolve_machine_identity(const std::filesystem::path& app_data_dir,
                         bool allow_create = true);

} // namespace kasumi::runtime

#endif
