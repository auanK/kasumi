#ifndef KASUMI_TRANSPORT_DETAIL_HPP
#define KASUMI_TRANSPORT_DETAIL_HPP

#include "transport/transport.hpp"

#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace kasumi::transport::detail {

inline Error
make_error(ErrorCode code, std::string message, int native_code = 0) {
    return Error{.code = code,
                 .message = std::move(message),
                 .native_code = native_code};
}

// Validates a non-empty relative slash-separated storage path.
bool valid_relative_identifier(std::string_view identifier,
                               bool require_normal) noexcept;

// Configuration for local directory storage.
struct LocalConfiguration {
    std::filesystem::path root;
};

// Configuration for storage accessed via rclone.
struct RcloneConfiguration {
    std::string remote_name;
    std::string remote_root;
    std::filesystem::path executable{"rclone"};
    std::optional<std::filesystem::path> config_path;
    std::filesystem::path forbidden_executable_root;
};

// Opens a transport backed by the local filesystem.
std::expected<Transport, Error>
open_local_backend(LocalConfiguration configuration);

// Opens a transport managed by rclone.
std::expected<Transport, Error>
open_rclone_backend(RcloneConfiguration configuration);

} // namespace kasumi::transport::detail

#endif
