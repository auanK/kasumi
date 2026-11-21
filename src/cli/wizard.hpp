#ifndef KASUMI_CLI_WIZARD_HPP
#define KASUMI_CLI_WIZARD_HPP

#include "application/environment.hpp"

#include <string_view>

namespace kasumi::cli {

// Interactively creates or edits profiles.
int run_config_wizard(const application::ExecutionEnvironment& environment);
int run_profile_query(const application::ExecutionEnvironment& environment,
                      std::string_view profile_name = {},
                      bool full = false);
int run_profile_key(const application::ExecutionEnvironment& environment,
                    std::string_view profile_name);

} // namespace kasumi::cli

#endif
