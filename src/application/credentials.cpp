#include "application/credentials.hpp"

#include "crypto/secure_memory.hpp"

namespace kasumi::application {

void wipe_credentials(Credentials& credentials) noexcept {
    if (auto* mk = std::get_if<MasterKeyHex>(&credentials)) {
        crypto::secure_memory::wipe(mk->value.data(), mk->value.size());
    }
}

void wipe_credentials(ProfileCredentials& credentials) noexcept {
    if (auto* mk = std::get_if<MasterKeyHex>(&credentials)) {
        crypto::secure_memory::wipe(mk->value.data(), mk->value.size());
    } else if (auto* pp = std::get_if<PasswordPair>(&credentials)) {
        crypto::secure_memory::wipe(pp->password.data(), pp->password.size());
        crypto::secure_memory::wipe(pp->salt_password.data(),
                                    pp->salt_password.size());
    }
}

} // namespace kasumi::application
