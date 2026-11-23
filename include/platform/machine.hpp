#ifndef KASUMI_PLATFORM_MACHINE_HPP
#define KASUMI_PLATFORM_MACHINE_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace kasumi::platform::machine {

inline constexpr std::size_t maximum_machine_name_bytes = 128;

// Normalizes a candidate machine name into trimmed valid UTF-8 without control
// characters, truncated on a UTF-8 codepoint boundary to <= 128 bytes.
// Falls back to "unknown" when empty.
std::string sanitize_machine_name(std::string_view raw);

// Returns the sanitized local machine hostname obtained from the OS.
std::string host_name();

// Returns the current OS process identifier for diagnostic marker metadata.
std::uint64_t current_process_id() noexcept;

} // namespace kasumi::platform::machine

#endif
