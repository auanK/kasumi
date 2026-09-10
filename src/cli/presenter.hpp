#ifndef KASUMI_CLI_PRESENTER_HPP
#define KASUMI_CLI_PRESENTER_HPP

#include "application/inspection/result.hpp"
#include "application/result.hpp"

namespace kasumi::cli {

// Displays success and returns 0.
int present(const application::Response& response);

// Displays the result of a remote inspection and returns 0.
int present(const application::InspectionResponse& response);

// Displays the error and returns 1.
int present(const application::Error& error);

// Displays the error of a remote inspection and returns 1.
int present(const application::InspectionError& error);

} // namespace kasumi::cli

#endif
