#ifndef KASUMI_CLI_WIZARD_HPP
#define KASUMI_CLI_WIZARD_HPP

#include "application/environment.hpp"
#include "cli/parser.hpp"

#include <functional>
#include <string>
#include <string_view>

namespace kasumi::cli {

// Interactively creates or edits profiles.
int run_config_wizard(const application::ExecutionEnvironment& environment);
int run_overview_command(const application::ExecutionEnvironment& environment,
                         bool full = false,
                         bool quiet = false,
                         bool json = false);
int run_profile_toggle_command(
    const application::ExecutionEnvironment& environment,
    const ProfileToggleInvocation& invocation,
    bool quiet = false,
    bool json = false,
    std::string* log_summary = nullptr);
int run_profile_query(const application::ExecutionEnvironment& environment,
                      std::string_view profile_name = {},
                      bool full = false,
                      bool json = false);
int run_profile_key(const application::ExecutionEnvironment& environment,
                    std::string_view profile_name,
                    bool replace = false,
                    bool quiet = false,
                    bool json = false,
                    std::string* log_summary = nullptr);
int run_profile_command(const application::ExecutionEnvironment& environment,
                        const ProfileInvocation& invocation,
                        bool quiet = false,
                        bool json = false,
                        std::string* log_summary = nullptr);
int run_ignore_command(const application::ExecutionEnvironment& environment,
                       const IgnoreInvocation& invocation,
                       bool quiet = false,
                       bool json = false,
                       std::string* log_summary = nullptr);
bool prompt_confirmation(std::string_view message);

namespace testing {

using BeforeProfileUpdateHook = std::function<void(std::string_view)>;

struct ScopedBeforeProfileUpdateHook {
    BeforeProfileUpdateHook previous{};

    explicit ScopedBeforeProfileUpdateHook(BeforeProfileUpdateHook hook);
    ~ScopedBeforeProfileUpdateHook() noexcept;

    ScopedBeforeProfileUpdateHook(const ScopedBeforeProfileUpdateHook&) =
        delete;
    ScopedBeforeProfileUpdateHook&
    operator=(const ScopedBeforeProfileUpdateHook&) = delete;
};

void invoke_before_profile_update_hook(std::string_view profile_name);

} // namespace testing

} // namespace kasumi::cli

#endif
