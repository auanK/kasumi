#ifndef KASUMI_APPLICATION_DAEMON_IPC_SECURITY_HPP
#define KASUMI_APPLICATION_DAEMON_IPC_SECURITY_HPP

#include <array>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace httplib {
struct Request;
}

namespace kasumi::application::daemon_detail {

inline constexpr std::size_t kTokenSize = 32;

struct DaemonControlMetadata {
    std::uint32_t api_version = 1;
    std::string kasumi_version;
    std::uint64_t pid = 0;
    std::uint16_t port = 0;
    std::int64_t started_at_unix = 0;
    std::string auth_token_hex;
    std::string ipc_key_hex;
};

void wipe_control_metadata(DaemonControlMetadata& metadata) noexcept;

struct SealedUnlockPayload {
    std::string nonce_hex;
    std::string mac_hex;
    std::string ciphertext_hex;
};

std::filesystem::path
daemon_lock_path(const std::filesystem::path& app_data_dir);
std::filesystem::path
daemon_control_path(const std::filesystem::path& app_data_dir);

std::string encode_hex(std::span<const std::uint8_t> bytes);
std::expected<std::vector<std::uint8_t>, std::string>
decode_hex(std::string_view hex, std::size_t expected_bytes);

bool constant_time_verify_hex_token(
    std::string_view provided_hex,
    std::span<const std::uint8_t, kTokenSize> expected_token) noexcept;

bool validate_ipc_request_headers(
    const httplib::Request& req,
    std::uint16_t bound_port,
    std::span<const std::uint8_t, kTokenSize> expected_token) noexcept;

std::expected<void, std::string>
write_control_metadata(const std::filesystem::path& control_path,
                       const DaemonControlMetadata& metadata);

std::expected<DaemonControlMetadata, std::string>
read_control_metadata(const std::filesystem::path& control_path);

void remove_control_metadata_best_effort(
    const std::filesystem::path& control_path) noexcept;

std::expected<SealedUnlockPayload, std::string>
seal_key_payload(std::span<const std::uint8_t, kTokenSize> ipc_key,
                 std::span<const std::uint8_t, kTokenSize> master_key,
                 std::string_view profile_name);

std::expected<std::array<std::uint8_t, kTokenSize>, std::string>
open_key_payload(std::span<const std::uint8_t, kTokenSize> ipc_key,
                 const SealedUnlockPayload& payload,
                 std::string_view profile_name);

} // namespace kasumi::application::daemon_detail

#endif
