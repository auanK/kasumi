#ifndef KASUMI_APPLICATION_CREDENTIALS_HPP
#define KASUMI_APPLICATION_CREDENTIALS_HPP

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

// Password pair used to derive the cryptographic master key.
struct PasswordPair {
    // Primary user password.
    std::string password;
    // Reproducible password salt used as Argon2id salt.
    std::string salt_password;
};

// Accepted forms for operations on an existing profile.
using Credentials = std::variant<NoCredentials, MasterKeyHex>;

// Accepted forms only during profile creation.
using ProfileCredentials = std::variant<MasterKeyHex, PasswordPair>;

// Wipes sensitive data from memory by zeroing strings.
void wipe_credentials(Credentials& credentials) noexcept;
void wipe_credentials(ProfileCredentials& credentials) noexcept;

} // namespace kasumi::application

#endif
