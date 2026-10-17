#ifndef KASUMI_APPLICATION_HISTORY_STORAGE_MAINTENANCE_PROTOCOL_HPP
#define KASUMI_APPLICATION_HISTORY_STORAGE_MAINTENANCE_PROTOCOL_HPP

#include "transport/transport.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
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

struct Error {
    ErrorCode code = ErrorCode::InvalidInput;
    std::string detail;
};

struct RegistrationState {
    transport::Transport* storage = nullptr;
    std::filesystem::path workspace_root;
    std::string identifier;
    std::vector<std::uint8_t> payload;
    std::string expected_physical_sha256;
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
                                   const RemoteLayout& layout,
                                   const std::filesystem::path& workspace_root);

// Requires exclusive vault operation; refuses an observed existing barrier and
// publishes the barrier checked by writer admission. Presence/PUT are not atomic.
RegistrationResult
establish_barrier(transport::Transport& storage,
                  const RemoteLayout& layout,
                  const std::filesystem::path& workspace_root);

// Lists active writers; any abandoned marker continues to block GC.
std::expected<std::vector<std::string>, Error>
active_writers(transport::Transport& storage, const RemoteLayout& layout);

// Removes only the explicitly selected writer marker after verifying it is
// listed and present in this vault's keyed writer namespace.
std::expected<void, Error> remove_writer(transport::Transport& storage,
                                         const RemoteLayout& layout,
                                         std::string_view identifier);

// Identifies objects reserved for the protocol, outside logical history.
bool is_control_object(const RemoteLayout& layout,
                       std::string_view identifier) noexcept;

namespace testing {
std::vector<std::uint8_t> format_payload(std::string_view kind,
                                         std::string_view token);
}

} // namespace kasumi::application::history_storage::maintenance_protocol

#endif
