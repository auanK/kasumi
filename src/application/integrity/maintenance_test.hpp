#ifndef KASUMI_APPLICATION_INTEGRITY_MAINTENANCE_TEST_HPP
#define KASUMI_APPLICATION_INTEGRITY_MAINTENANCE_TEST_HPP

#include "application/integrity/maintenance.hpp"

namespace kasumi::application::integrity::testing {

enum class FsckWorkerEvent {
    BeforeAudit,
    WindowStopRequested
};
using FsckWorkerEventCallback =
    std::function<void(FsckWorkerEvent, std::size_t)>;

std::expected<FsckResult, Error>
fsck_with_worker_events(const runtime::RuntimeData& runtime_data,
                        transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        std::size_t audit_concurrency,
                        FsckProgressCallback on_progress,
                        FsckWorkerEventCallback on_worker_event);

} // namespace kasumi::application::integrity::testing

#endif
