#ifndef KASUMI_APPLICATION_EXECUTE_HPP
#define KASUMI_APPLICATION_EXECUTE_HPP

#include "application/credentials.hpp"
#include "application/environment.hpp"
#include "application/request.hpp"
#include "application/result.hpp"

#include <expected>

namespace kasumi::application {

// Inputs required for an execution.
struct ExecutionInput {
    Request request;
    Credentials credentials;
    ExecutionEnvironment environment;
};

// Executes the requested operation.
std::expected<Response, Error> execute(ExecutionInput input);

} // namespace kasumi::application

#endif
