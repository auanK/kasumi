#ifndef KASUMI_CLI_COMPLETION_HPP
#define KASUMI_CLI_COMPLETION_HPP

#include <string>

namespace kasumi::cli {

enum class CompletionShell {
    Bash,
    Zsh,
    Fish,
    PowerShell,
};

std::string generate_completion_script(CompletionShell shell);

} // namespace kasumi::cli

#endif
