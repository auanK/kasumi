#pragma once

#include "application/daemon.hpp"
#include "application/inspection/inspect.hpp"

#include <httplib.h>

#include <functional>
#include <string_view>

namespace kasumi::application::daemon_detail {

struct WebContext {
    ExecutionEnvironment environment;
    std::stop_token stop;
    std::function<Credentials(std::string_view)> credentials;
    std::function<DaemonStatusReport()> status;
    std::function<void()> reload;
    std::function<void(std::string_view, bool)> track_internal_lock;
    std::function<std::expected<InspectionResponse, InspectionError>(
        InspectionRequest)>
        inspect;
    std::function<std::expected<RemoteTreePair, InspectionError>(
        std::string_view, std::string, std::string)>
        inspect_commit_pair;
    std::function<std::expected<std::shared_ptr<RemoteDownloadSession>,
                                InspectionError>(InspectionRequest)>
        open_download;
};

void register_profile_routes(httplib::Server& server,
                             const WebContext& context);
void register_remote_routes(httplib::Server& server, const WebContext& context);
void register_local_routes(httplib::Server& server, const WebContext& context);

} // namespace kasumi::application::daemon_detail
