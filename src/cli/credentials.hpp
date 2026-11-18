#ifndef KASUMI_CLI_CREDENTIALS_HPP
#define KASUMI_CLI_CREDENTIALS_HPP

#include "application/credentials.hpp"
#include "application/environment.hpp"

#include <functional>
#include <string>
#include <string_view>

namespace kasumi::cli::credentials {

// Uses the environment variable or prompts for the value via the terminal.
std::string read_secret(const char* environment_name,
                        const std::string& prompt);

// Reads the master key from the environment or reports absence of credentials.
application::Credentials from_environment();

// Resolves credentials for operating on an existing profile, prompting when
// the profile uses in-memory key storage.
application::Credentials
for_profile(const application::ExecutionEnvironment& environment,
            std::string_view profile_name);

// Reads the password and salt from the environment or terminal.
application::PasswordPair read_password_pair();

using SecretPrompt = std::function<std::string(const std::string&)>;
application::PasswordPair read_password_pair(const SecretPrompt& prompt);

} // namespace kasumi::cli::credentials

#endif
