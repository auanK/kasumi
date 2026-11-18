#include "application/credentials.hpp"

#include "crypto/secure_memory.hpp"
#include "runtime/vault.hpp"

namespace kasumi::application {

std::size_t minimum_password_size() noexcept {
    return runtime::vault::MINIMUM_PASSWORD_SIZE;
}
std::size_t minimum_password_salt_size() noexcept {
    return runtime::vault::MINIMUM_PASSWORD_SALT_SIZE;
}

namespace {

void wipe_string(std::string& value) noexcept {
    value.resize(value.capacity(), '\0');
    crypto::secure_memory::wipe(value.data(), value.size());
    value.clear();
}

} // namespace

void wipe_credentials(Credentials& credentials) noexcept {
    if (auto* mk = std::get_if<MasterKeyHex>(&credentials)) {
        wipe_string(mk->value);
    } else if (auto* pp = std::get_if<PasswordPair>(&credentials)) {
        wipe_string(pp->password);
        wipe_string(pp->salt_password);
    }
}

void wipe_credentials(ProfileCredentials& credentials) noexcept {
    if (auto* mk = std::get_if<MasterKeyHex>(&credentials)) {
        wipe_string(mk->value);
    } else if (auto* pp = std::get_if<PasswordPair>(&credentials)) {
        wipe_string(pp->password);
        wipe_string(pp->salt_password);
    }
}

} // namespace kasumi::application
