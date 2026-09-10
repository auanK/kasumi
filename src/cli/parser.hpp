#ifndef KASUMI_CLI_PARSER_HPP
#define KASUMI_CLI_PARSER_HPP

#include "application/inspection/request.hpp"
#include "application/request.hpp"

#include <expected>
#include <variant>

namespace kasumi::cli {

// Requests opening the interactive configuration wizard.
struct ConfigureInvocation {};

// Valid command-line parsing result.
using Invocation = std::variant<application::Request,
                                application::InspectionRequest,
                                ConfigureInvocation>;

// Command-line argument parsing failure.
struct ParseError {
    // Exit code returned to the operating system.
    int exit_code = 1;
};

// Parses command-line arguments into an application invocation.
std::expected<Invocation, ParseError> parse(int argc, char* argv[]);

} // namespace kasumi::cli

#endif
