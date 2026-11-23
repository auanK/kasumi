#ifndef KASUMI_CLI_WIZARD_HPP
#define KASUMI_CLI_WIZARD_HPP

#include "application/environment.hpp"
#include "cli/parser.hpp"

#include <string>
#include <string_view>

namespace kasumi::cli {

// Interactively creates or edits profiles.
int run_config_wizard(const application::ExecutionEnvironment& environment);
int run_profile_query(const application::ExecutionEnvironment& environment,
                      std::string_view profile_name = {},
                      bool full = false,
                      bool json = false);
int run_profile_key(const application::ExecutionEnvironment& environment,
                    std::string_view profile_name);
int run_profile_command(const application::ExecutionEnvironment& environment,
                        const ProfileInvocation& invocation,
                        bool quiet = false,
                        bool json = false,
                        std::string* log_summary = nullptr);
bool prompt_confirmation(std::string_view message);

} // namespace kasumi::cli

#endif
