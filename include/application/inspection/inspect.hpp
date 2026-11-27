#ifndef KASUMI_APPLICATION_INSPECTION_INSPECT_HPP
#define KASUMI_APPLICATION_INSPECTION_INSPECT_HPP

#include "application/inspection/request.hpp"
#include "application/inspection/result.hpp"
#include "application/result.hpp"
#include "crypto/key_derivation.hpp"
#include "transport/transport.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>

namespace kasumi::application {

struct RemoteDownloadSessionState;
void destroy_remote_download_session(RemoteDownloadSessionState* state) noexcept;

struct RemoteDownloadSession {
    std::unique_ptr<RemoteDownloadSessionState,
                    decltype(&destroy_remote_download_session)>
        state{nullptr, &destroy_remote_download_session};
};

struct RemoteTreePair {
    RemoteTreeReport from;
    RemoteTreeReport to;
};

std::expected<InspectionResponse, InspectionError>
inspect(InspectionInput input);

// Observes remote history once and returns authenticated trees for two commits.
std::expected<RemoteTreePair, InspectionError>
inspect_commit_pair(InspectionInput input,
                    std::string from_commit_id,
                    std::string to_commit_id);

// Opens a single-observation authenticated download session for one remote file.
std::expected<RemoteDownloadSession, InspectionError>
open_remote_download(InspectionInput input);

// Returns the authenticated metadata resolved when the session was opened.
const RemoteStatReport&
remote_download_stat(const RemoteDownloadSession& session) noexcept;

// Downloads, cryptographically verifies, and installs the full file or byte
// slice from an open download session without re-observing remote history.
std::expected<RemoteFileReport, InspectionError>
read_remote_download_slice(RemoteDownloadSession& session,
                           const std::filesystem::path& destination_path,
                           std::optional<DownloadSlice> slice = std::nullopt,
                           std::stop_token stop = {});

// Transfers ownership of the session's underlying transport back to the caller.
std::optional<transport::Transport>
take_remote_download_transport(RemoteDownloadSession& session) noexcept;

// Audits object presence and reachability from an authenticated remote history.
std::expected<InventoryAuditReport, std::string>
audit_remote_inventory(transport::Transport& storage,
                       std::span<const std::uint8_t, crypto::KEY_SIZE> key);

} // namespace kasumi::application

#endif
