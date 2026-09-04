#ifndef KASUMI_CRYPTO_KEY_DERIVATION_HPP
#define KASUMI_CRYPTO_KEY_DERIVATION_HPP

#include "core/hasher.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <string>

namespace kasumi::crypto {

inline constexpr std::size_t KEY_SIZE = 32;

enum class KeyPurpose {
    Content,
    History,
    Epoch,
    Journal,
    RemoteIdentifier,
};

enum class IdentifierPurpose {
    Content,
    Commit,
    Epoch,
};

using Key = std::array<std::uint8_t, KEY_SIZE>;

Key derive_key(std::span<const std::uint8_t, KEY_SIZE> master_key,
               KeyPurpose purpose) noexcept;

Hash derive_identifier(std::span<const std::uint8_t, KEY_SIZE> master_key,
                       IdentifierPurpose purpose,
                       std::span<const std::uint8_t> value) noexcept;

std::string
content_identifier(std::span<const std::uint8_t, KEY_SIZE> master_key,
                   const Hash& plaintext_hash);

std::string
commit_identifier(std::span<const std::uint8_t, KEY_SIZE> master_key,
                  std::span<const std::uint8_t> canonical_commit);

std::string epoch_identifier(std::span<const std::uint8_t, KEY_SIZE> master_key,
                             std::span<const std::uint8_t> canonical_epoch);

} // namespace kasumi::crypto

#endif
