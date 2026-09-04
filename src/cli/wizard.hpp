#ifndef KASUMI_CLI_WIZARD_HPP
#define KASUMI_CLI_WIZARD_HPP

#include "application/environment.hpp"

#include <filesystem>

namespace kasumi::cli {

// Interactively creates or edits profiles.
void run_config_wizard(const application::ExecutionEnvironment& environment);

} // namespace kasumi::cli

#endif
