#pragma once

#include "application/daemon/web_routes.hpp"

#include <httplib.h>

#include <filesystem>
#include <string_view>

namespace kasumi::application::daemon_detail {

void remove_custom_icon_files(const std::filesystem::path& profile_dir,
                              std::string_view keep_ext = {});
void register_icon_routes(httplib::Server& server, const WebContext& ctx);

} // namespace kasumi::application::daemon_detail
