#ifndef KASUMI_APPLICATION_ENVIRONMENT_HPP
#define KASUMI_APPLICATION_ENVIRONMENT_HPP

#include <filesystem>

namespace kasumi::application {

// Environment used by the application layer.
struct ExecutionEnvironment {
    // Absolute path to application data directory.
    std::filesystem::path app_data_dir;
};

// Obtains default environment for the current system.
ExecutionEnvironment default_execution_environment();

} // namespace kasumi::application

#endif
