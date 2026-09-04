#ifndef KASUMI_APPLICATION_SYNC_REOBSERVATION_HPP
#define KASUMI_APPLICATION_SYNC_REOBSERVATION_HPP

#include "application/observation/state.hpp"
#include "application/sync/coordinator.hpp"
#include "core/reconciliation/types.hpp"
#include "crypto/file_crypto.hpp"
#include "runtime/resolver.hpp"
#include "transport/transport.hpp"

#include <expected>
#include <span>

namespace kasumi::application::sync::coordinator::reobservation {

// Input and plan confirmed by a stable observation.
struct StableExecution {
    reconciliation::Input input;
    reconciliation::Result result;
};

// Compares data used to detect concurrent changes.
bool same_observation(const reconciliation::Input& left,
                      const reconciliation::Input& right) noexcept;

// Re-observes until the plan stabilizes or fails.
std::expected<StableExecution, coordinator::Error>
stabilize(const runtime::RuntimeData& runtime_data,
          transport::Transport& storage,
          std::span<const std::uint8_t, crypto::KEY_SIZE> key,
          reconciliation::Input observed_input,
          reconciliation::Result reconciliation_result,
          observation::LocalObservationSession* session = nullptr);

} // namespace kasumi::application::sync::coordinator::reobservation

#endif
