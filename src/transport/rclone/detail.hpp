#ifndef KASUMI_TRANSPORT_RCLONE_DETAIL_HPP
#define KASUMI_TRANSPORT_RCLONE_DETAIL_HPP

#include "../detail.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <future>
#include <mutex>
#include <reproc++/reproc.hpp>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace kasumi::transport::rclone_detail {

// State of the rclone process and its RC connection.
struct State {
    detail::RcloneConfiguration configuration;
    std::string username;
    std::string password;
    std::string base_url;
    std::uint16_t port = 0;
    reproc::process process;
    std::mutex process_mutex;
    std::future<std::error_code> drain_future;
    std::atomic_bool stop_drain = false;
    std::function<void(std::string_view)> report_status;
    bool process_started = false;
    bool ready = false;
    std::atomic_bool sha256_unsupported = false;
};

using ChildEnvironment = std::vector<std::pair<std::string, std::string>>;

// Resolves only a regular executable, using explicit path or PATH lookup.
std::expected<std::filesystem::path, Error>
resolve_rclone_executable(const detail::RcloneConfiguration& configuration);

// Copies required environment without exposing private Kasumi variables.
std::expected<ChildEnvironment, Error>
make_child_environment(const State& state);

// Starts session; returned state must be freed via destroy_state.
std::expected<State*, Error>
start_state(detail::RcloneConfiguration configuration);

// Terminates process and releases state, if present.
void destroy_state(void* state) noexcept;

// Awaits and validates connection to the RC API.
std::expected<void, Error> establish_rc_connection(State& state, int child_pid);

// Requests shutdown and reports whether RC acknowledged the request.
bool request_core_quit_best_effort(State& state) noexcept;

// Sends an RC request adhering to response size and read timeout limits.
std::expected<std::string, Error>
post_rc(State& state,
        std::string_view endpoint,
        std::string_view request_body,
        std::size_t response_limit,
        std::chrono::milliseconds read_timeout);

// Retries only transient failures of an idempotent read, without exceeding the
// specified total deadline.
std::expected<std::string, Error>
post_rc_read_only(State& state,
                  std::string_view endpoint,
                  std::string_view request_body,
                  std::size_t response_limit,
                  std::chrono::milliseconds deadline);

// Decodes an operations/list response.
ListingResult parse_list_response(std::string_view response_body);

// Decodes an operations/check response against the sent request.
PhysicalHashBatchResult
parse_physical_hash_batch_response(std::string_view response_body,
                                   const PhysicalHashBatchRequest& request);

// Decodes a control-plane read job/batch envelope.
ControlReadBatchResponse
parse_control_read_batch_response(std::string_view response_body,
                                  const ControlReadBatchRequest& request,
                                  std::string_view objects_remote);

// Builds the storage operations table for the rclone transport.
StorageOperations make_storage_operations() noexcept;

} // namespace kasumi::transport::rclone_detail

#endif
