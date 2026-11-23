#ifndef KASUMI_APPLICATION_HISTORY_STORAGE_MAINTENANCE_PROTOCOL_HPP
#define KASUMI_APPLICATION_HISTORY_STORAGE_MAINTENANCE_PROTOCOL_HPP

#include "crypto/file_crypto.hpp"
#include "transport/transport.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::application::history_storage {
struct RemoteLayout;
}

namespace kasumi::application::history_storage::maintenance_protocol {

enum class ErrorCode {
    InvalidInput,
    WorkspaceFailure,
    TransportFailure,
    VerificationFailure,
    Blocked,
    BackendUnsafe,
    InvalidControlObject,
};

enum class BarrierRemovalStage : std::uint8_t {
    CheckingPresence,
    DownloadingPayload,
    ValidatingPayload,
    CheckingWriters,
    VerifyingPhysicalIdentity,
    Removing,
    ConfirmingAbsence,
};

// Keep aligned with application::BarrierRemovalMutationState. A REMOVE error
// does not prove absence of effects; confirmation requires a subsequent
// PRESENCE.
enum class BarrierRemovalMutationState : std::uint8_t {
    NotAttempted,
    Confirmed,
    Uncertain,
};

struct Error {
    ErrorCode code = ErrorCode::InvalidInput;
    std::string detail;
    // Preserves the backend category and native code when available.
    std::optional<transport::Error> transport_failure;
    std::optional<std::string> identifier;
    std::optional<BarrierRemovalStage> stage;
    std::optional<BarrierRemovalMutationState> mutation_state;
};

struct MarkerMetadata {
    std::string machine_name;
    std::uint64_t pid = 0;
    std::int64_t started_at_unix = 0;
};

struct BarrierOptions {
    std::chrono::milliseconds settle_delay{0};
    std::optional<MarkerMetadata> metadata = std::nullopt;
};

struct RegistrationState {
    transport::Transport* storage = nullptr;
    std::filesystem::path workspace_root;
    std::string identifier;
    std::string token;
    std::vector<std::uint8_t> payload;
    std::string expected_physical_sha256;
    bool verify_owner = false;
};

using RegistrationResult = std::expected<RegistrationState, Error>;

bool registration_active(const RegistrationState& registration) noexcept;
std::expected<void, Error>
verify_registration(const RegistrationState& registration);
std::expected<void, Error>
verify_writer_admission(const RegistrationState& registration,
                        const RemoteLayout& layout);
std::expected<void, Error>
verify_barrier_exclusivity(const RegistrationState& registration,
                           const RemoteLayout& layout);
std::expected<void, Error>
release_registration(RegistrationState& registration);

// Registers a writer and denies entry when a barrier is present.
RegistrationResult register_writer(transport::Transport& storage,
                                   const RemoteLayout& layout,
                                   const std::filesystem::path& workspace_root);
RegistrationResult register_writer(transport::Transport& storage,
                                   const RemoteLayout& layout,
                                   const std::filesystem::path& workspace_root,
                                   const MarkerMetadata& metadata);

// Publishes the barrier preventing new writers.
RegistrationResult
establish_barrier(transport::Transport& storage,
                  const RemoteLayout& layout,
                  const std::filesystem::path& workspace_root);
RegistrationResult
establish_barrier(transport::Transport& storage,
                  const RemoteLayout& layout,
                  const std::filesystem::path& workspace_root,
                  const BarrierOptions& options);

// Lists active writers; any abandoned marker continues to block maintenance.
std::expected<std::vector<std::string>, Error>
active_writers(transport::Transport& storage, const RemoteLayout& layout);

// Lists active barriers (both legacy single barrier and v0.24.0 multi-barrier
// entries under barriers/).
std::expected<std::vector<std::string>, Error>
active_barriers(transport::Transport& storage, const RemoteLayout& layout);

// Best-effort diagnostic metadata readers for writer and barrier markers.
// Returns std::nullopt for legacy or unreadable payloads without failing.
std::optional<MarkerMetadata> parse_marker_metadata(
    std::span<const std::uint8_t> bytes,
    std::string_view expected_kind,
    std::optional<std::string_view> expected_token = std::nullopt);
std::optional<MarkerMetadata>
read_marker_metadata(transport::Transport& storage,
                     std::string_view identifier,
                     std::string_view expected_kind,
                     std::optional<std::string_view> expected_token,
                     const std::filesystem::path& workspace_root);

// Removes only the explicitly selected writer marker after verifying it is
// listed and present in this vault's keyed writer namespace.
std::expected<void, Error> remove_writer(transport::Transport& storage,
                                         const RemoteLayout& layout,
                                         std::string_view identifier);

enum class BarrierRemovalOutcome : std::uint8_t {
    Removed,
    AlreadyAbsent,
};

struct BarrierRemovalResult {
    BarrierRemovalOutcome outcome = BarrierRemovalOutcome::Removed;
    std::size_t active_writers_count = 0;
    std::size_t remaining_barriers_count = 0;
    std::optional<std::string> barrier_identifier = std::nullopt;
};

// Removes an abandoned maintenance barrier after verifying its structure,
// control token, and observed physical identity. When multiple barriers are
// active, target_barrier must select the barrier identifier or 32-hex token.
std::expected<BarrierRemovalResult, Error>
remove_barrier(transport::Transport& storage,
               const RemoteLayout& layout,
               const std::filesystem::path& workspace_root,
               std::optional<std::string_view> target_barrier = std::nullopt);

// Confirms immediate read-after-write and read-after-delete visibility in
// listings.
std::expected<bool, Error>
supports_online_collection(transport::Transport& storage,
                           const RemoteLayout& layout,
                           const std::filesystem::path& workspace_root);

// Identifies objects reserved for the protocol, outside logical history.
bool is_control_object(const RemoteLayout& layout,
                       std::string_view identifier) noexcept;

namespace testing {
std::vector<std::uint8_t> format_payload(std::string_view kind,
                                         std::string_view token);
std::vector<std::uint8_t> format_payload(std::string_view kind,
                                         std::string_view token,
                                         const MarkerMetadata& metadata);
} // namespace testing

} // namespace kasumi::application::history_storage::maintenance_protocol

#endif
