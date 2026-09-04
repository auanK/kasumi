#include "crypto/key_derivation.hpp"

#include <monocypher.h>
#include <string_view>

namespace kasumi::crypto {
namespace {

constexpr std::string_view domain(KeyPurpose purpose) noexcept {
    switch (purpose) {
        case KeyPurpose::Content:
            return "kasumi/v2/key/content";
        case KeyPurpose::History:
            return "kasumi/v2/key/history";
        case KeyPurpose::Epoch:
            return "kasumi/v2/key/epoch";
        case KeyPurpose::Journal:
            return "kasumi/v2/key/journal";
        case KeyPurpose::RemoteIdentifier:
            return "kasumi/v2/key/remote-id";
    }
    return {};
}

constexpr std::string_view domain(IdentifierPurpose purpose) noexcept {
    switch (purpose) {
        case IdentifierPurpose::Content:
            return "kasumi/v2/id/content";
        case IdentifierPurpose::Commit:
            return "kasumi/v2/id/commit";
        case IdentifierPurpose::Epoch:
            return "kasumi/v2/id/epoch";
    }
    return {};
}

} // namespace

Key derive_key(std::span<const std::uint8_t, KEY_SIZE> master_key,
               KeyPurpose purpose) noexcept {
    const auto context = domain(purpose);
    Key result{};
    crypto_blake2b_keyed(result.data(),
                         result.size(),
                         master_key.data(),
                         master_key.size(),
                         reinterpret_cast<const std::uint8_t*>(context.data()),
                         context.size());
    return result;
}

Hash derive_identifier(std::span<const std::uint8_t, KEY_SIZE> master_key,
                       IdentifierPurpose purpose,
                       std::span<const std::uint8_t> value) noexcept {
    auto identifier_key = derive_key(master_key, KeyPurpose::RemoteIdentifier);
    const auto context = domain(purpose);
    crypto_blake2b_ctx state;
    crypto_blake2b_keyed_init(
        &state, HASH_SIZE, identifier_key.data(), identifier_key.size());
    crypto_blake2b_update(&state,
                          reinterpret_cast<const std::uint8_t*>(context.data()),
                          context.size());
    crypto_blake2b_update(&state, value.data(), value.size());
    Hash result{};
    crypto_blake2b_final(&state,
                         reinterpret_cast<std::uint8_t*>(result.data()));
    crypto_wipe(identifier_key.data(), identifier_key.size());
    return result;
}

std::string
content_identifier(std::span<const std::uint8_t, KEY_SIZE> master_key,
                   const Hash& plaintext_hash) {
    const std::span<const std::uint8_t> bytes{
        reinterpret_cast<const std::uint8_t*>(plaintext_hash.data()),
        plaintext_hash.size()};
    return hash_hex(
        derive_identifier(master_key, IdentifierPurpose::Content, bytes));
}

std::string
commit_identifier(std::span<const std::uint8_t, KEY_SIZE> master_key,
                  std::span<const std::uint8_t> canonical_commit) {
    return hash_hex(derive_identifier(
        master_key, IdentifierPurpose::Commit, canonical_commit));
}

std::string epoch_identifier(std::span<const std::uint8_t, KEY_SIZE> master_key,
                             std::span<const std::uint8_t> canonical_epoch) {
    return hash_hex(derive_identifier(
        master_key, IdentifierPurpose::Epoch, canonical_epoch));
}

} // namespace kasumi::crypto
