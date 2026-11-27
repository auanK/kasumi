#include "application/daemon/web_jobs.hpp"

#include "application/daemon/web_http.hpp"
#include "application/daemon/web_job_json.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "platform/clock.hpp"

#include <array>
#include <charconv>
#include <chrono>

namespace kasumi::application::daemon_detail {
namespace {
std::int64_t now_unix_seconds() noexcept {
    return platform::clock::unix_seconds().value_or(0);
}

Json compact_job_summary(const WebJob& job) {
    if (!job.result.is_object())
        return Json(nullptr);
    static constexpr std::array<const char*, 34> kSummaryKeys{
        "error",
        "warning",
        "dry_run",
        "actionable",
        "published",
        "identifier",
        "removed_identifiers",
        "already_absent_identifiers",
        "checked_objects",
        "checked_plaintext_bytes",
        "wire_download_bytes",
        "files_reassembled",
        "candidate_objects",
        "candidate_bytes",
        "candidate_content_objects",
        "candidate_expired_commits",
        "candidate_activities",
        "deferred_recent_objects",
        "removed_objects",
        "removed_bytes",
        "live_small_blobs",
        "dirty_packs_detected",
        "loose_small_blobs_detected",
        "new_packs",
        "repacked_blobs",
        "repacked_plaintext_bytes",
        "resolved_count",
        "total",
        "uploaded",
        "downloaded",
        "removed",
        "upload_bytes",
        "download_bytes",
        "lock_busy"};
    Json summary = Json::object();
    for (const char* key : kSummaryKeys) {
        if (const auto it = job.result.find(key); it != job.result.end())
            summary[key] = *it;
    }
    return summary;
}

Json describe(std::uint64_t id, const WebJob& job, bool full) {
    Json item{{"id", id},
              {"profile", job.profile},
              {"operation", job.operation},
              {"state", job.state},
              {"dry_run", job.dry_run},
              {"started_at", job.started_at},
              {"finished_at", job.finished_at},
              {"duration_ms",
               job.duration_ms >= 0 ? Json(job.duration_ms) : Json(nullptr)},
              {"progress", job.progress}};
    if (full)
        item["result"] = job.result;
    else if (job.state != "running")
        item["summary"] = compact_job_summary(job);
    return item;
}

Json sync_result(const SyncCompleted& sync) {
    Json data = sync;
    data["duration_ms"] =
        sync.duration
            ? Json(std::chrono::duration<double, std::milli>(*sync.duration)
                       .count())
            : Json(nullptr);
    return data;
}

std::uint32_t unsigned_job_field(const Json& body, const char* field) {
    const auto& value = body.at(field);
    if (!value.is_number_unsigned() || value.get<std::uint64_t>() > UINT32_MAX)
        throw HttpError{400, std::string("invalid field: ") + field};
    return value.get<std::uint32_t>();
}

Request
job_request(Operation operation, const std::string& name, const Json& body) {
    Request request{.operation = operation, .profile_name = name};
    switch (operation) {
        case Operation::Sync:
            request.initial = body.value("initial", false);
            request.repair = body.value("repair", false);
            request.audit_inventory = body.value("audit_inventory", false);
            request.allow_empty_local = body.value("allow_empty_local", false);
            if (body.contains("bandwidth_limit"))
                request.bandwidth_limit =
                    body.at("bandwidth_limit").get<std::string>();
            if (body.contains("transfer_concurrency"))
                request.transfer_concurrency =
                    unsigned_job_field(body, "transfer_concurrency");
            break;
        case Operation::RemoveWriter:
            if (body.contains("writer_ids")) {
                const auto& ids = body.at("writer_ids");
                if (!ids.is_array() || ids.empty() || ids.size() > 256U)
                    throw HttpError{400, "invalid writer identifiers"};
                request.writer_identifiers.reserve(ids.size());
                for (const auto& entry : ids) {
                    if (!entry.is_string())
                        throw HttpError{400, "invalid writer identifier"};
                    auto id = entry.get<std::string>();
                    if (!history_storage::valid_writer_identifier(id))
                        throw HttpError{400, "invalid writer identifier"};
                    request.writer_identifiers.push_back(std::move(id));
                }
            } else {
                request.writer_identifier =
                    body.at("writer_id").get<std::string>();
                if (!history_storage::valid_writer_identifier(
                        request.writer_identifier))
                    throw HttpError{400, "invalid writer identifier"};
            }
            break;
        case Operation::RemoveBarrier:
            request.confirm_abandoned = body.value("confirm_abandoned", false);
            if (!request.confirm_abandoned)
                throw HttpError{400, "confirm_abandoned must be true"};
            if (body.contains("barrier_id")) {
                request.barrier_identifier =
                    body.at("barrier_id").get<std::string>();
                if (request.barrier_identifier->empty())
                    throw HttpError{400, "invalid barrier identifier"};
            }
            break;
        case Operation::GarbageCollect:
        case Operation::Repack:
        case Operation::ResolveMissing:
            request.dry_run = body.value("dry_run", true);
            if (!request.dry_run && !body.value("confirm", false))
                throw HttpError{400, "explicit confirmation required"};
            request.confirm =
                operation == Operation::ResolveMissing && !request.dry_run;
            request.reclaim_dirty = body.value("reclaim_dirty", false);
            if (body.contains("min_age_hours"))
                request.gc_min_age_hours =
                    unsigned_job_field(body, "min_age_hours");
            break;
        default:
            break;
    }
    return request;
}

void run_job(const WebContext& ctx,
             WebJobs& jobs,
             std::uint64_t id,
             Request request,
             const std::function<void()>& on_change) {
    Json result;
    std::string state = "failed";
    try {
        auto report = execute(
            {.request = request,
             .credentials = ctx.credentials(request.profile_name),
             .environment = ctx.environment,
             .on_progress =
                 [&](const ExecutionProgress& p) {
                     auto update = std::visit(
                         [](const auto& progress) -> Json {
                             using T = std::decay_t<decltype(progress)>;
                             if constexpr (std::is_same_v<T, SyncProgress>)
                                 return {
                                     {"stage", progress.stage},
                                     {"total_items", progress.total_items},
                                     {"applied_items", progress.applied_items}};
                             else if constexpr (std::is_same_v<
                                                    T,
                                                    GarbageCollectProgress>)
                                 return {{"stage", progress.stage},
                                         {"sub_stage", progress.sub_stage},
                                         {"removed_objects",
                                          progress.removed_objects},
                                         {"candidate_objects",
                                          progress.candidate_count}};
                             else
                                 return Json(progress);
                         },
                         p);
                     {
                         std::lock_guard lock(jobs.mutex);
                         auto& existing = jobs.rows.at(id).progress;
                         if (update.is_object() && existing.is_object()) {
                             if (!update.contains("stage") &&
                                 existing.contains("stage")) {
                                 update["stage"] = existing.at("stage");
                             }
                             if (!update.contains("sub_stage") &&
                                 existing.contains("sub_stage")) {
                                 update["sub_stage"] =
                                     existing.at("sub_stage");
                             }
                         }
                         existing = std::move(update);
                     }
                     if (on_change)
                         on_change();
                 },
             .stop_token = ctx.stop});
        if (report) {
            result = std::visit(
                [](const auto& data) -> Json {
                    if constexpr (std::is_same_v<std::decay_t<decltype(data)>,
                                                 SyncCompleted>)
                        return sync_result(data);
                    else if constexpr (std::is_constructible_v<Json,
                                                               decltype(data)>)
                        return Json(data);
                    else
                        throw HttpError{500, "unsupported job result"};
                },
                report->data);
            if (report->inventory_audit)
                result["inventory_audit"] = *report->inventory_audit;
            if (report->activity_publish_warning)
                result["warning"] = *report->activity_publish_warning;
            state = "completed";
        } else {
            const auto& error = report.error();
            result = {
                {"error", error.detail},
                {"lock_busy", error.lock_busy},
                {"remote_busy", error.remote_busy},
                {"insufficient_disk_space", error.insufficient_disk_space},
                {"empty_local_blocked", error.empty_local_blocked}};
            if (error.sync_completed)
                result["sync"] = sync_result(*error.sync_completed);
            if (error.barrier_removal) {
                const auto& barrier = *error.barrier_removal;
                result["barrier_removal"] = {
                    {"barrier_identifier", barrier.barrier_identifier},
                    {"stage", barrier.stage},
                    {"mutation_state", barrier.mutation_state}};
            }
        }
    } catch (...) {
        result = {{"error", "job failed"}};
    }
    {
        std::lock_guard lock(jobs.mutex);
        auto& row = jobs.rows.at(id);
        row.state = std::move(state);
        row.finished_at = now_unix_seconds();
        row.duration_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - row.started_steady)
                .count();
        row.result = std::move(result);
    }
    if (on_change)
        on_change();
}

} // namespace

void register_job_routes(httplib::Server& server,
                         const WebContext& ctx,
                         WebJobs& jobs,
                         std::function<void()> on_change) {
    auto start = [ctx, &jobs, on_change = std::move(on_change)](
                     const httplib::Request& req, httplib::Response& res) {
        const bool preview = req.path.starts_with("/v1/profiles/");
        auto name = req.matches[1].str();
        auto operation =
            preview ? std::string("preview") : req.matches[2].str();
        static const std::map<std::string, Operation> ops{
            {"preview", Operation::Status},
            {"fsck", Operation::Fsck},
            {"gc", Operation::GarbageCollect},
            {"repack", Operation::Repack},
            {"resolve-missing", Operation::ResolveMissing},
            {"sync", Operation::Sync},
            {"remove-writer", Operation::RemoveWriter},
            {"remove-barrier", Operation::RemoveBarrier}};
        auto request = job_request(ops.at(operation), name, *parse_body(req));
        auto profiles = require(list_profiles(ctx.environment));
        if (std::ranges::find(profiles, name, &Profile::name) == profiles.end())
            throw HttpError{404, "profile not found"};
        Json created_payload;
        std::uint64_t created_id = 0;
        std::future<void> evicted_worker;
        {
            std::lock_guard lock(jobs.mutex);
            unsigned active = 0;
            for (const auto& [id, row] : jobs.rows) {
                if (row.state == "running") {
                    if (row.profile == name)
                        throw HttpError{
                            409,
                            "another job is running for this profile",
                            "lock_busy",
                            row.operation};
                    ++active;
                }
            }
            if (active >= 4)
                throw HttpError{429, "job queue is busy"};
            if (jobs.rows.size() >= 64) {
                auto oldest =
                    std::ranges::find_if(jobs.rows, [](const auto& entry) {
                        return entry.second.state != "running";
                    });
                if (oldest != jobs.rows.end()) {
                    evicted_worker = std::move(oldest->second.worker);
                    jobs.rows.erase(oldest);
                }
            }
            created_id = jobs.next_id++;
            auto& job = jobs.rows[created_id];
            job.profile = name;
            job.operation = operation;
            job.state = "running";
            job.dry_run = request.dry_run;
            job.started_at = now_unix_seconds();
            job.started_steady = std::chrono::steady_clock::now();
            job.duration_ms = -1;
            try {
                job.worker = std::async(
                    std::launch::async,
                    [ctx, &jobs, created_id, request, on_change]() {
                        run_job(ctx, jobs, created_id, request, on_change);
                    });
            } catch (...) {
                jobs.rows.erase(created_id);
                throw;
            }
            created_payload = describe(created_id, job, false);
        }
        if (on_change)
            on_change();
        res.status = 202;
        res.set_header("Location", "/v1/jobs/" + std::to_string(created_id));
        res.set_content(created_payload.dump(), "application/json");
    };
    server.Post("/v1/profiles/([^/]+)/preview", start);
    server.Post(
        "/v1/maintenance/([^/]+)/"
        "(fsck|gc|repack|resolve-missing|sync|remove-writer|remove-barrier)",
        start);
    server.Get(
        "/v1/jobs/([0-9]+)", json_route([&jobs](const auto& req) {
            std::uint64_t id{};
            const auto text = req.matches[1].str();
            if (std::from_chars(text.data(), text.data() + text.size(), id)
                    .ec != std::errc{})
                throw HttpError{400, "invalid job id"};
            std::lock_guard lock(jobs.mutex);
            const auto it = jobs.rows.find(id);
            if (it == jobs.rows.end())
                throw HttpError{404, "job not found"};
            return describe(id, it->second, true);
        }));
}

Json job_snapshot(WebJobs& jobs) {
    std::lock_guard lock(jobs.mutex);
    Json rows = Json::array();
    for (const auto& [id, job] : jobs.rows)
        rows.push_back(describe(id, job, false));
    return rows;
}

std::vector<std::pair<std::string, std::string>>
active_job_operations(WebJobs& jobs) {
    std::lock_guard lock(jobs.mutex);
    std::vector<std::pair<std::string, std::string>> active;
    for (const auto& [id, job] : jobs.rows) {
        if (job.state == "running") {
            active.emplace_back(job.profile, job.operation);
        }
    }
    return active;
}

void join_web_jobs(WebJobs& jobs) {
    // Both listeners have stopped accepting work before shutdown reaches this
    // point.
    std::vector<std::future<void>> workers;
    {
        std::lock_guard lock(jobs.mutex);
        for (auto& [id, job] : jobs.rows)
            workers.push_back(std::move(job.worker));
    }
    for (auto& worker : workers)
        if (worker.valid())
            worker.wait();
}
} // namespace kasumi::application::daemon_detail
