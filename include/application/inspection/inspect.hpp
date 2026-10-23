#ifndef KASUMI_APPLICATION_INSPECTION_INSPECT_HPP
#define KASUMI_APPLICATION_INSPECTION_INSPECT_HPP

#include "application/inspection/request.hpp"
#include "application/inspection/result.hpp"
#include "application/result.hpp"
#include "crypto/key_derivation.hpp"

#include <cstdint>
#include <expected>
#include <span>
#include <string>

namespace kasumi::transport {
struct Transport;
}

namespace kasumi::application {

std::expected<InspectionResponse, InspectionError>
inspect(InspectionInput input);

// Downloads and authenticates a file from the logical tree without modifying
// local profile.
std::expected<InspectionResponse, InspectionError>
read_remote_file(InspectionInput input);

// Audits object presence and reachability from an authenticated remote history.
std::expected<InventoryAuditReport, std::string>
audit_remote_inventory(transport::Transport& storage,
                       std::span<const std::uint8_t, crypto::KEY_SIZE> key);

} // namespace kasumi::application

#endif
