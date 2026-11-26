#pragma once

#include <httplib.h>

namespace kasumi::application::daemon_detail {

// Registers embedded static Web UI assets and SPA fallback routes on a
// browser-facing HTTP server. Never intercepts /v1/* API paths.
void register_web_static_routes(httplib::Server& server);

} // namespace kasumi::application::daemon_detail
