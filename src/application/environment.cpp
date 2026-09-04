#include "application/environment.hpp"

#include "runtime/paths.hpp"

namespace kasumi::application {

ExecutionEnvironment default_execution_environment() {
    auto paths = runtime::default_global_paths();
    return ExecutionEnvironment{.app_data_dir = paths.app_data_dir};
}

} // namespace kasumi::application
