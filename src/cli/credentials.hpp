#ifndef KASUMI_CLI_CREDENTIALS_HPP
#define KASUMI_CLI_CREDENTIALS_HPP

#include "application/credentials.hpp"

#include <functional>
#include <string>

namespace kasumi::cli::credentials {

// Uses the environment variable or prompts for the value via the terminal.
std::string read_secret(const char* environment_name,
                        const std::string& prompt);

// Reads the master key from the environment or reports absence of credentials.
application::Credentials from_environment();

// Reads the password and salt from the environment or terminal.
application::PasswordPair read_password_pair();

using SecretPrompt = std::function<std::string(const std::string&)>;
application::PasswordPair read_password_pair(const SecretPrompt& prompt);

} // namespace kasumi::cli::credentials

#endif
