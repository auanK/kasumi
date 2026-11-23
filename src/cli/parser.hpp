#ifndef KASUMI_CLI_PARSER_HPP
#define KASUMI_CLI_PARSER_HPP

#include "application/inspection/request.hpp"
#include "application/profile.hpp"
#include "application/request.hpp"
#include "cli/completion.hpp"

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <variant>

namespace kasumi::cli {

// Requests opening the interactive configuration wizard.
struct ConfigureInvocation {};
struct ListInvocation {};
struct ShowInvocation {
    std::string profile_name;
};
struct DiagnosticsInvocation {
    std::string profile_name;
};
struct KeyInvocation {
    std::string profile_name;
};
struct ConflictsInvocation {
    std::string profile_name;
};
struct CompletionInvocation {
    CompletionShell shell = CompletionShell::Bash;
};
enum class ProfileAction {
    Create,
    Edit,
    Clone,
    Storage,
    Rename,
    Delete,
};
struct ProfileInvocation {
    ProfileAction action = ProfileAction::Create;
    std::string profile_name;
    std::optional<std::string> target_name;
    std::optional<std::string> local_dir;
    std::optional<std::string> remote_dir;
    std::optional<application::KeyStorage> key_storage;
    std::optional<std::uint32_t> min_history_depth;
    std::optional<std::uint32_t> min_history_age_hours;
    bool confirm = false;
};
struct HelpInvocation {
    std::string topic;
};

// Valid command-line parsing result.
using Invocation = std::variant<application::Request,
                                application::InspectionRequest,
                                ConfigureInvocation,
                                ListInvocation,
                                ShowInvocation,
                                DiagnosticsInvocation,
                                KeyInvocation,
                                ConflictsInvocation,
                                CompletionInvocation,
                                ProfileInvocation,
                                HelpInvocation>;

// Command-line argument parsing failure.
struct ParseError {
    // Exit code returned to the operating system.
    int exit_code = 1;
    bool unsupported_sync_audit_combination = false;
    bool unsupported_sync_repair_combination = false;
};

// Parses command-line arguments into an application invocation.
std::expected<Invocation, ParseError> parse(int argc, char* argv[]);

// Closest recognized command for Help and parse-error guidance.
std::string help_topic(int argc, char* argv[]);

} // namespace kasumi::cli

#endif
