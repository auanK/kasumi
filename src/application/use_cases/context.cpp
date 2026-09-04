#include "application/use_cases/context.hpp"

#include "application/use_cases/error_mapping.hpp"
#include "crypto/secure_memory.hpp"
#include "core/history.hpp"
#include "platform/perf_trace.hpp"
#include "platform/profile_lock.hpp"
#include "runtime/resolver.hpp"
#include "transport/transport.hpp"

#include <utility>

namespace kasumi::application::detail {

std::expected<void, Error> prepare_operation(const ExecutionInput& input,
                                             OperationContext& output) {
    wipe_operation(output);
    const auto operation = input.request.operation;
    output.operation = operation;
    const auto access_mode = operation == Operation::Sync
                                 ? runtime::AccessMode::ReadWrite
                                 : runtime::AccessMode::ReadOnly;
    const auto resolve_trace = platform::perf_trace::begin();
    auto runtime_data = runtime::resolve(input.environment.app_data_dir,
                                         input.request.profile_name,
                                         access_mode);
    platform::perf_trace::finish("runtime/profile resolve", resolve_trace);
    if (!runtime_data) {
        return std::unexpected(Error{
            .operation = operation,
            .code =
                runtime_error_to_application_error(runtime_data.error().code),
            .detail = runtime_data.error().detail,
            .runtime = std::nullopt,
        });
    }

    output.runtime = *runtime_data;
    output.summary =
        RuntimeSummary{.local_dir = runtime_data->local_dir,
                       .remote_dir = runtime_data->storage_location};
    if (runtime_data->min_history_depth == 0 ||
        runtime_data->min_history_depth > history::maximum_graph_depth ||
        runtime_data->min_history_age_hours == 0) {
        return std::unexpected(Error{
            .operation = operation,
            .code = ErrorCode::RuntimeFailure,
            .detail = "política de retenção inválida",
            .runtime = output.summary,
        });
    }
    const auto preparation_trace = platform::perf_trace::begin();
    auto profile_lock = platform::acquire_profile_lock(
        input.environment.app_data_dir /
        ("profile-" + input.request.profile_name + ".lock"));
    if (!profile_lock) {
        platform::perf_trace::finish("operation preparation",
                                     preparation_trace);
        return std::unexpected(Error{
            .operation = operation,
            .code = ErrorCode::RuntimeFailure,
            .detail = profile_lock.error(),
            .runtime = output.summary,
        });
    }
    output.profile_lock = *profile_lock;
    auto key = resolve_key_into(operation,
                                input.credentials,
                                *runtime_data,
                                output.summary,
                                output.key);
    if (!key) {
        platform::perf_trace::finish("operation preparation",
                                     preparation_trace);
        wipe_operation(output);
        return std::unexpected(key.error());
    }
    platform::perf_trace::finish("operation preparation", preparation_trace);

    const auto transport_trace = platform::perf_trace::begin();
    auto opened_storage = transport::open_transport(
        runtime_data->storage_location, runtime_data->local_dir);
    platform::perf_trace::finish("transport open", transport_trace);
    if (!opened_storage) {
        wipe_operation(output);
        return std::unexpected(Error{
            .operation = operation,
            .code = ErrorCode::RuntimeFailure,
            .detail = transport::describe(opened_storage.error()),
            .runtime = output.summary,
        });
    }

    output.storage = std::move(*opened_storage);
    return {};
}

void wipe_operation(OperationContext& context) noexcept {
    crypto::secure_memory::wipe(context.key.data(), context.key.size());
    platform::release_profile_lock(context.profile_lock);
}

} // namespace kasumi::application::detail
