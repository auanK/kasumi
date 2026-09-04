#ifndef KASUMI_TRANSPORT_DETAIL_HPP
#define KASUMI_TRANSPORT_DETAIL_HPP

#include "transport/transport.hpp"

#include <expected>
#include <filesystem>
#include <optional>
#include <string>

namespace kasumi::transport::detail {

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
