#ifndef KASUMI_APPLICATION_DAEMON_FAST_POLL_HPP
#define KASUMI_APPLICATION_DAEMON_FAST_POLL_HPP

#include "application/environment.hpp"
#include "application/observation/state.hpp"
#include "runtime/resolver.hpp"
#include "transport/transport.hpp"

#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

namespace kasumi::application::daemon_detail {

enum class FastPollVerdict : std::uint8_t {
    NoChanges,
    FullSyncRequired,
};

struct FastPollReport {
    FastPollVerdict verdict = FastPollVerdict::FullSyncRequired;
    std::string reason;
    bool transport_error = false;
    bool profile_locked = false;
};

// Checks whether a periodic poll can safely prove zero local + remote changes
// using only one lightweight ControlReadBatchRequest over a warm Transport
// without walking the local filesystem tree or writing a no-op SQLite row.
FastPollReport try_fast_remote_noop_poll(
    const ExecutionEnvironment& environment,
    std::string_view profile_name,
    const runtime::RuntimeData& runtime_data,
    transport::Transport& borrowed_transport,
    std::span<const std::uint8_t, 32> master_key,
    observation::LocalObservationSession& warm_observation,
    bool ignore_file_present,
    const observation::DatabaseMetadataStamp& expected_ignore_stamp);

} // namespace kasumi::application::daemon_detail

#endif
