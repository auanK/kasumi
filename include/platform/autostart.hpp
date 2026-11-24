#ifndef KASUMI_PLATFORM_AUTOSTART_HPP
#define KASUMI_PLATFORM_AUTOSTART_HPP

#include <expected>
#include <filesystem>
#include <string>

namespace kasumi::platform {

struct AutostartStatus {
    bool supported = true;
    bool installed = false;
    bool systemd_enabled = false;
    std::string method;
    std::string location;
    std::string command;
    std::string detail;
};

std::expected<std::filesystem::path, std::string> current_executable_path();

std::expected<AutostartStatus, std::string>
install_user_autostart(const std::filesystem::path& executable_path);

std::expected<AutostartStatus, std::string> uninstall_user_autostart();

std::expected<AutostartStatus, std::string> query_user_autostart();

} // namespace kasumi::platform

#endif
