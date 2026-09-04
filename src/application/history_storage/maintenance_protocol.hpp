#ifndef KASUMI_APPLICATION_HISTORY_STORAGE_MAINTENANCE_PROTOCOL_HPP
#define KASUMI_APPLICATION_HISTORY_STORAGE_MAINTENANCE_PROTOCOL_HPP

#include "crypto/file_crypto.hpp"
#include "transport/transport.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kasumi::application::history_storage::maintenance_protocol {

inline constexpr std::int64_t quarantine_retention_seconds = 10 * 24 * 60 * 60;

enum class ErrorCode {
    InvalidInput,
    WorkspaceFailure,
    TransportFailure,
    VerificationFailure,
    Blocked,
    BackendUnsafe,
    InvalidControlObject,
};

struct Error {
    ErrorCode code = ErrorCode::InvalidInput;
    std::string detail;
};

struct RegistrationState {
    transport::Transport* storage = nullptr;
    std::filesystem::path workspace_root;
    std::string identifier;
    std::vector<std::uint8_t> payload;
    bool verify_owner = false;
};

using RegistrationResult = std::expected<RegistrationState, Error>;

bool registration_active(const RegistrationState& registration) noexcept;
std::expected<void, Error>
verify_registration(const RegistrationState& registration);
std::expected<void, Error>
release_registration(RegistrationState& registration);

// Registers a writer and denies entry when a barrier is present.
RegistrationResult register_writer(transport::Transport& storage,
                                   const std::filesystem::path& workspace_root);

// Publishes the barrier preventing new writers.
RegistrationResult
establish_barrier(transport::Transport& storage,
                  const std::filesystem::path& workspace_root);

// Lists active writers; any abandoned marker continues to block GC.
std::expected<std::vector<std::string>, Error>
active_writers(transport::Transport& storage);

// Confirms immediate read-after-write and read-after-delete visibility in listings.
std::expected<bool, Error>
supports_online_collection(transport::Transport& storage,
                           const std::filesystem::path& workspace_root);

struct QuarantineEntry {
    std::string original_identifier;
    std::string quarantine_identifier;
    std::string metadata_identifier;
    std::optional<std::int64_t> quarantined_at;
    std::string physical_sha256;
};

inline constexpr std::string_view epoch_namespace_prefix = "history/epochs/v1/";

inline bool is_epoch_object(std::string_view identifier) noexcept {
    return identifier.starts_with(epoch_namespace_prefix);
}

// Identifies objects reserved for the protocol, outside logical history.
bool is_control_object(std::string_view identifier) noexcept;

// Builds the deterministic quarantine destination for content or commit.
std::optional<std::string>
quarantine_identifier(std::string_view original_identifier);

// Inventories and authenticates metadata present in quarantine.
std::expected<std::vector<QuarantineEntry>, Error>
inventory_quarantine(transport::Transport& storage,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                     const std::filesystem::path& workspace_root);

std::expected<std::vector<QuarantineEntry>, Error>
inventory_quarantine(transport::Transport& storage,
                     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                     std::span<const std::string> identifiers,
                     const std::filesystem::path& workspace_root);

// Records the authenticated timestamp and hash of the quarantined copy.
std::expected<QuarantineEntry, Error>
record_quarantine(transport::Transport& storage,
                  std::string_view quarantine_identifier,
                  std::int64_t quarantined_at,
                  std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                  const std::filesystem::path& workspace_root,
                  std::string_view verified_sha256 = {});

// Confirms that the copy still matches the authenticated metadata.
std::expected<bool, Error>
verify_quarantine(transport::Transport& storage,
                  const QuarantineEntry& entry,
                  const std::filesystem::path& workspace_root);

// Copies bytes, validates destination SHA-256, and returns the hash.
std::expected<std::string, Error>
copy_verified(transport::Transport& storage,
              std::string_view source_identifier,
              std::string_view destination_identifier,
              const std::filesystem::path& workspace_root);

} // namespace kasumi::application::history_storage::maintenance_protocol

#endif
