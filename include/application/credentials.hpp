#ifndef KASUMI_APPLICATION_CREDENTIALS_HPP
#define KASUMI_APPLICATION_CREDENTIALS_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <variant>

namespace kasumi::application {

// Indicates absence of credentials for operations not requiring authentication.
struct NoCredentials {};

// Cryptographic master key supplied directly.
struct MasterKeyHex {
    // String containing exactly 64 hexadecimal characters (32 bytes).
    std::string value;
};

// Raw 32-byte cryptographic master key held in memory and wiped on destruction.
struct MasterKeyBytes {
    std::array<std::uint8_t, 32> bytes{};

    MasterKeyBytes() noexcept = default;
    explicit MasterKeyBytes(std::array<std::uint8_t, 32> initial_bytes) noexcept
        : bytes(initial_bytes) {
    }
    MasterKeyBytes(const MasterKeyBytes&) noexcept = default;
    MasterKeyBytes& operator=(const MasterKeyBytes&) noexcept = default;
    MasterKeyBytes(MasterKeyBytes&& other) noexcept;
    MasterKeyBytes& operator=(MasterKeyBytes&& other) noexcept;
    ~MasterKeyBytes() noexcept;
};

// Password pair used to derive the cryptographic master key.
struct PasswordPair {
    // Primary user password.
    std::string password;
    // Reproducible password salt used as Argon2id salt.
    std::string salt_password;
};

// Accepted forms for operations on an existing profile.
using Credentials =
    std::variant<NoCredentials, MasterKeyHex, MasterKeyBytes, PasswordPair>;

// Accepted forms only during profile creation.
using ProfileCredentials =
    std::variant<MasterKeyHex, MasterKeyBytes, PasswordPair>;

std::size_t minimum_password_size() noexcept;
std::size_t minimum_password_salt_size() noexcept;

// Wipes sensitive data from memory by zeroing buffers.
void wipe_credentials(Credentials& credentials) noexcept;
void wipe_credentials(ProfileCredentials& credentials) noexcept;

} // namespace kasumi::application

#endif
