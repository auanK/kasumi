#include "application/integrity/maintenance.hpp"

#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "platform/cancellation.hpp"

#include <algorithm>
#include <utility>

namespace kasumi::application::integrity {
namespace {

namespace protocol = history_storage::maintenance_protocol;
using Failure = GcAnalysisErrorCode;
using Analysis = std::expected<GcSnapshot, GcAnalysisError>;

GcAnalysisError failure(Failure code, Error cause) {
    return {.code = code, .cause = std::move(cause), .cleanup_error = std::nullopt};
}

Error protocol_error(const protocol::Error& source) {
    ErrorCode code = ErrorCode::IntegrityFailure;
    switch (source.code) {
    case protocol::ErrorCode::InvalidInput: code = ErrorCode::InvalidInput; break;
    case protocol::ErrorCode::WorkspaceFailure: code = ErrorCode::WorkspaceFailure; break;
    case protocol::ErrorCode::TransportFailure: code = ErrorCode::TransportFailure; break;
    case protocol::ErrorCode::Blocked: code = ErrorCode::ConcurrentChange; break;
    default: break;
    }
    return {.code = code, .detail = source.detail, .object_identifier = std::nullopt};
}

Error transport_error(const transport::Error& source, std::string identifier = {}) {
    return {.code = ErrorCode::TransportFailure,
            .detail = transport::describe(source),
            .object_identifier = identifier.empty() ? std::nullopt
                : std::optional<std::string>{std::move(identifier)}};
}

GcAnalysisError cancelled() {
    return failure(Failure::Cancelled,
                   {.code = ErrorCode::ConcurrentChange,
                    .detail = "GC analysis cancelled", .object_identifier = std::nullopt});
}

std::expected<void, GcAnalysisError>
check_writers(transport::Transport& storage, const history_storage::RemoteLayout& layout,
              Failure on_error) {
    auto writers = protocol::active_writers(storage, layout);
    if (!writers) return std::unexpected(failure(on_error, protocol_error(writers.error())));
    if (!writers->empty()) {
        return std::unexpected(failure(Failure::WriterPresent,
            {.code = ErrorCode::ConcurrentChange,
             .detail = "registered writers block exclusive GC analysis",
             .object_identifier = writers->front()}));
    }
    return {};
}

std::expected<void, GcAnalysisError>
check_owner(const protocol::RegistrationState& barrier) {
    if (auto verified = protocol::verify_registration(barrier); !verified) {
        return std::unexpected(failure(Failure::OwnershipLost, protocol_error(verified.error())));
    }
    return {};
}

std::expected<void, GcAnalysisError>
check_observed_writers(const GcSnapshot& snapshot, const history_storage::RemoteLayout& layout) {
    const auto writer = std::ranges::find_if(snapshot.physical_namespace,
        [&](const auto& id) { return id.starts_with(layout.writers_prefix); });
    if (writer != snapshot.physical_namespace.end()) {
        return std::unexpected(failure(Failure::WriterPresent,
            {.code = ErrorCode::ConcurrentChange, .detail = "writer observed in GC snapshot",
             .object_identifier = *writer}));
    }
    return {};
}

std::expected<void, Error> release_barrier(protocol::RegistrationState& barrier) {
    // Check explicitly: release_registration alone silently preserves a foreign owner.
    if (auto verified = protocol::verify_registration(barrier); !verified)
        return std::unexpected(protocol_error(verified.error()));
    auto& storage = *barrier.storage;
    if (auto released = protocol::release_registration(barrier); !released)
        return std::unexpected(protocol_error(released.error()));
    auto present = transport::presence(storage, barrier.identifier);
    if (!present) return std::unexpected(transport_error(present.error(), barrier.identifier));
    if (*present != transport::Presence::Absent) {
        return std::unexpected(Error{.code = ErrorCode::ConcurrentChange,
            .detail = "barrier release could not be confirmed",
            .object_identifier = barrier.identifier});
    }
    return {};
}

} // namespace

Analysis analyze_gc_under_barrier(transport::Transport& storage,
                                  std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                                  const std::filesystem::path& workspace_root) {
    std::error_code error;
    if (!transport::valid(storage) || workspace_root.empty() ||
        !std::filesystem::is_directory(workspace_root, error)) {
        return std::unexpected(failure(Failure::Preconditions,
            {.code = ErrorCode::InvalidInput, .detail = "invalid GC analysis context",
             .object_identifier = std::nullopt}));
    }
    if (platform::cancellation::requested()) return std::unexpected(cancelled());
    if (auto initialized = transport::initialize(storage); !initialized)
        return std::unexpected(failure(Failure::Preconditions, transport_error(initialized.error())));
    const auto layout = history_storage::derive_remote_layout(key);
    if (auto writers = check_writers(storage, layout, Failure::Preconditions); !writers)
        return std::unexpected(std::move(writers.error()));
    if (platform::cancellation::requested()) return std::unexpected(cancelled());

    auto barrier = protocol::establish_barrier(storage, layout, workspace_root);
    if (!barrier) {
        auto cause = protocol_error(barrier.error());
        cause.object_identifier = layout.barrier_identifier;
        cause.detail += "; no confirmed registration available for cleanup";
        return std::unexpected(failure(platform::cancellation::requested()
            ? Failure::Cancelled : Failure::BarrierAcquisition, std::move(cause)));
    }

    auto observed = [&]() -> Analysis {
        if (platform::cancellation::requested()) return std::unexpected(cancelled());
        if (auto owner = check_owner(*barrier); !owner) return std::unexpected(std::move(owner.error()));
        if (auto writers = check_writers(storage, layout, Failure::OwnershipLost); !writers)
            return std::unexpected(std::move(writers.error()));
        if (platform::cancellation::requested()) return std::unexpected(cancelled());
        if (auto owner = check_owner(*barrier); !owner) return std::unexpected(std::move(owner.error()));

        auto first = collect_gc_snapshot(storage, key, workspace_root);
        if (!first) return std::unexpected(failure(platform::cancellation::requested()
            ? Failure::Cancelled : Failure::Observation, std::move(first.error())));
        if (platform::cancellation::requested()) return std::unexpected(cancelled());
        if (auto writers = check_observed_writers(*first, layout); !writers)
            return std::unexpected(std::move(writers.error()));
        auto second = collect_gc_snapshot(storage, key, workspace_root);
        if (!second) return std::unexpected(failure(platform::cancellation::requested()
            ? Failure::Cancelled : Failure::Observation, std::move(second.error())));
        if (platform::cancellation::requested()) return std::unexpected(cancelled());
        if (auto writers = check_observed_writers(*second, layout); !writers)
            return std::unexpected(std::move(writers.error()));
        if (!same_gc_snapshot(*first, *second)) {
            return std::unexpected(failure(Failure::SnapshotChanged,
                {.code = ErrorCode::ConcurrentChange, .detail = "GC observations differ",
                 .object_identifier = std::nullopt}));
        }
        if (auto writers = check_writers(storage, layout, Failure::OwnershipLost); !writers)
            return std::unexpected(std::move(writers.error()));
        if (auto owner = check_owner(*barrier); !owner) return std::unexpected(std::move(owner.error()));
        if (platform::cancellation::requested()) return std::unexpected(cancelled());
        return std::move(*second);
    }();

    auto cleanup = release_barrier(*barrier);
    if (!observed) {
        if (!cleanup) observed.error().cleanup_error = std::move(cleanup.error());
        return observed;
    }
    if (!cleanup) return std::unexpected(failure(Failure::BarrierRelease, std::move(cleanup.error())));
    if (platform::cancellation::requested()) return std::unexpected(cancelled());
    return observed;
}

} // namespace kasumi::application::integrity
