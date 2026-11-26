#pragma once

#include "application/daemon/web_routes.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <utility>
#include <vector>

namespace kasumi::application::daemon_detail {
struct WebJob {
    std::string profile;
    std::string operation;
    std::string state;
    bool dry_run = false;
    std::int64_t started_at = 0;
    std::int64_t finished_at = 0;
    std::int64_t duration_ms = -1;
    std::chrono::steady_clock::time_point started_steady{};
    nlohmann::json progress;
    nlohmann::json result;
    std::future<void> worker;
};

struct WebJobs {
    std::mutex mutex;
    std::map<std::uint64_t, WebJob> rows;
    std::uint64_t next_id = 1;
    std::atomic_uint streams{};
};

void register_job_routes(httplib::Server& server,
                         const WebContext& ctx,
                         WebJobs& jobs,
                         std::function<void()> on_change = {});
nlohmann::json job_snapshot(WebJobs& jobs);
std::vector<std::pair<std::string, std::string>>
active_job_operations(WebJobs& jobs);
void join_web_jobs(WebJobs& jobs);
} // namespace kasumi::application::daemon_detail
