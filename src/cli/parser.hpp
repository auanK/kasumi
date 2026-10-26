#ifndef KASUMI_CLI_PARSER_HPP
#define KASUMI_CLI_PARSER_HPP

#include "application/inspection/request.hpp"
#include "application/request.hpp"

#include <expected>
#include <string>
#include <variant>

namespace kasumi::cli {

// Requests opening the interactive configuration wizard.
struct ConfigureInvocation {};
struct UpdateInvocation {};
struct HelpInvocation {
    std::string topic;
};

// Valid command-line parsing result.
using Invocation = std::variant<application::Request,
                                application::InspectionRequest,
                                ConfigureInvocation,
                                UpdateInvocation,
                                HelpInvocation>;

// Command-line argument parsing failure.
struct ParseError {
    // Exit code returned to the operating system.
    int exit_code = 1;
    bool unsupported_sync_audit_combination = false;
};

// Parses command-line arguments into an application invocation.
std::expected<Invocation, ParseError> parse(int argc, char* argv[]);

// Closest recognized command for Help and parse-error guidance.
std::string help_topic(int argc, char* argv[]);

} // namespace kasumi::cli

#endif
