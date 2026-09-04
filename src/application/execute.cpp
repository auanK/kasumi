#include "application/execute.hpp"

#include "application/use_cases/context.hpp"
#include "platform/perf_trace.hpp"

#include <exception>
#include <optional>
#include <string>
#include <utility>

namespace kasumi::application {
namespace detail {

std::expected<Response, Error> run_sync(OperationContext& context);
std::expected<Response, Error> run_plan(OperationContext& context);
std::expected<Response, Error> run_fsck(OperationContext& context);
std::expected<Response, Error> run_garbage_collect(OperationContext& context);

std::expected<Response, Error> dispatch(OperationContext& context) {
    switch (context.operation) {
        case Operation::Sync:
            return run_sync(context);
        case Operation::Preview:
        case Operation::Status:
            return run_plan(context);
        case Operation::Fsck:
            return run_fsck(context);
        case Operation::GarbageCollect:
            return run_garbage_collect(context);
    }
    std::unreachable();
}

} // namespace detail

std::expected<Response, Error> execute(ExecutionInput input) {
    platform::perf_trace::reset();
    const auto total_trace = platform::perf_trace::begin();
    detail::OperationContext context{};
    auto result = [&]() -> std::expected<Response, Error> {
        try {
            auto prepared = detail::prepare_operation(input, context);
            if (!prepared) {
                return std::unexpected(prepared.error());
            }
            return detail::dispatch(context);
        } catch (const std::exception&) {
            return std::unexpected(Error{
                .operation = context.operation,
                .code = ErrorCode::RuntimeFailure,
                .detail = "application orchestration exception",
                .runtime = context.summary.local_dir.empty() &&
                                   context.summary.remote_dir.empty()
                               ? std::nullopt
                               : std::optional<RuntimeSummary>{context.summary},
            });
        } catch (...) {
            return std::unexpected(Error{
                .operation = context.operation,
                .code = ErrorCode::RuntimeFailure,
                .detail = "application orchestration exception",
                .runtime = context.summary.local_dir.empty() &&
                                   context.summary.remote_dir.empty()
                               ? std::nullopt
                               : std::optional<RuntimeSummary>{context.summary},
            });
        }
    }();

    const auto shutdown_trace = platform::perf_trace::begin();
    context.storage = {};
    platform::perf_trace::finish("transport shutdown", shutdown_trace);
    const auto finalization_trace = platform::perf_trace::begin();
    detail::wipe_operation(context);
    wipe_credentials(input.credentials);
    platform::perf_trace::finish("operation finalization",
                                 finalization_trace);
    platform::perf_trace::finish("total sync", total_trace);
    platform::perf_trace::report(result ? "success" : "error");
    return result;
}

} // namespace kasumi::application
