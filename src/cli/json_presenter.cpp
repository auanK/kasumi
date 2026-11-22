#include "cli/json_presenter.hpp"

#include "cli/log_file.hpp"
#include "cli/presenter.hpp"
#include "platform/path.hpp"

#include <nlohmann/json.hpp>
#include <optional>
#include <print>
#include <string>
#include <utility>

namespace kasumi::cli {
namespace {

using json = nlohmann::json;

thread_local const std::filesystem::path* g_json_log_file = nullptr;

void emit_json(const json& doc) {
    const auto line =
        doc.dump(-1, ' ', false, json::error_handler_t::replace);
    std::println("{}", line);
    if (g_json_log_file != nullptr) {
        (void)append_log_line(*g_json_log_file, line);
    }
}

double to_duration_ms(std::chrono::nanoseconds duration) noexcept {
    return std::chrono::duration<double, std::milli>(duration).count();
}

json make_envelope(std::string_view command,
                   std::string_view profile_name,
                   bool ok,
                   int exit_code,
                   std::optional<std::chrono::nanoseconds> duration) {
    json doc{
        {"schema_version", 1},
        {"command", command},
        {"ok", ok},
        {"exit_code", exit_code},
    };
    if (!profile_name.empty()) {
        doc["profile"] = profile_name;
    }
    if (const auto ts = format_utc_iso8601_now(); !ts.empty()) {
        doc["timestamp"] = ts;
    }
    if (duration.has_value()) {
        doc["duration_ms"] = to_duration_ms(*duration);
    }
    return doc;
}

int emit_json_error(std::string_view command,
                    std::string_view profile_name,
                    int exit_code,
                    std::string_view error_code,
                    std::string_view message,
                    std::optional<std::chrono::nanoseconds> duration =
                        std::nullopt,
                    std::optional<json> data = std::nullopt) {
    auto doc = make_envelope(command, profile_name, false, exit_code, duration);
    doc["error"] = json{
        {"code", error_code},
        {"message", message},
    };
    if (data.has_value()) {
        doc["data"] = std::move(*data);
    }
    emit_json(doc);
    return exit_code;
}

std::string_view operation_command_name(application::Operation op) noexcept {
    using Op = application::Operation;
    switch (op) {
    case Op::Sync:
    case Op::Preview:
        return "sync";
    case Op::Status:
        return "status";
    case Op::Fsck:
        return "fsck";
    case Op::GarbageCollect:
        return "gc";
    case Op::ResolveMissing:
        return "resolve-missing";
    case Op::RemoveWriter:
        return "gc remove-writer";
    case Op::RemoveBarrier:
        return "gc remove-barrier";
    case Op::Repack:
        return "repack";
    }
    return "unknown";
}

std::string_view
inspection_command_name(application::InspectionOperation op) noexcept {
    if (op == application::InspectionOperation::RemoteSummary) {
        return "remote summary";
    }
    return "remote";
}

std::string_view plan_action_name(application::PlanAction action) noexcept {
    using A = application::PlanAction;
    switch (action) {
    case A::RenameLocal:
        return "rename_local";
    case A::Upload:
        return "upload";
    case A::CreateLocalDirectory:
        return "create_local_directory";
    case A::CreateRemoteDirectory:
        return "create_remote_directory";
    case A::MoveLocal:
        return "move_local";
    case A::Download:
        return "download";
    case A::DeleteLocal:
        return "delete_local";
    case A::DeleteLocalDirectory:
        return "delete_local_directory";
    case A::DeleteRemote:
        return "delete_remote";
    case A::DeleteRemoteDirectory:
        return "delete_remote_directory";
    case A::CopyLocal:
        return "copy_local";
    case A::DeleteIgnoredLocalFile:
        return "delete_ignored_local_file";
    case A::Count:
        break;
    }
    return "unknown";
}

std::string_view
local_problem_name(application::ProfileLocalProblem problem) noexcept {
    using P = application::ProfileLocalProblem;
    switch (problem) {
    case P::None:
        return "none";
    case P::InvalidName:
        return "invalid_name";
    case P::Paths:
        return "paths";
    case P::Directory:
        return "directory";
    case P::Key:
        return "key";
    case P::Database:
        return "database";
    case P::Lock:
        return "lock";
    case P::Sidecar:
        return "sidecar";
    case P::Journal:
        return "journal";
    case P::Workspace:
        return "workspace";
    case P::Snapshot:
        return "snapshot";
    case P::Cleanup:
        return "cleanup";
    case P::Count:
        break;
    }
    return "unspecified";
}

std::string_view
profile_op_name(application::ProfileOperationKind op) noexcept {
    using K = application::ProfileOperationKind;
    switch (op) {
    case K::Sync:
        return "sync";
    case K::Fsck:
        return "fsck";
    case K::GarbageCollect:
        return "gc";
    case K::Repack:
        return "repack";
    case K::ResolveMissing:
        return "resolve-missing";
    case K::RemoveWriter:
        return "gc remove-writer";
    case K::RemoveBarrier:
        return "gc remove-barrier";
    }
    return "unknown";
}

std::string_view
profile_status_name(application::ProfileExecutionStatus status) noexcept {
    using S = application::ProfileExecutionStatus;
    switch (status) {
    case S::InProgress:
        return "in_progress";
    case S::Succeeded:
        return "ok";
    case S::SucceededNoChanges:
        return "no_changes";
    case S::SucceededDownloadedOnly:
        return "downloaded_only";
    case S::SucceededPartial:
        return "partial";
    case S::IssuesFound:
        return "issues_found";
    case S::Blocked:
        return "blocked";
    case S::Cancelled:
        return "cancelled";
    case S::Failed:
        return "failed";
    case S::Uncertain:
        return "uncertain";
    case S::Interrupted:
        return "interrupted";
    }
    return "unknown";
}

std::string_view
remote_publish_name(application::ProfileRemotePublishState state) noexcept {
    using S = application::ProfileRemotePublishState;
    switch (state) {
    case S::NotApplicable:
        return "not_applicable";
    case S::Published:
        return "published";
    case S::Pending:
        return "pending";
    }
    return "not_applicable";
}

std::string_view remote_op_name(std::uint8_t op) noexcept {
    using O = application::RemoteActivityOperation;
    switch (static_cast<O>(op)) {
    case O::Fsck:
        return "fsck";
    case O::GarbageCollect:
        return "gc";
    case O::RemoveWriter:
        return "gc remove-writer";
    case O::RemoveBarrier:
        return "gc remove-barrier";
    }
    return "unknown";
}

std::string_view remote_outcome_name(std::uint8_t outcome) noexcept {
    using R = application::RemoteActivityOutcome;
    switch (static_cast<R>(outcome)) {
    case R::Succeeded:
        return "ok";
    case R::IssuesFound:
        return "issues_found";
    case R::Blocked:
        return "blocked";
    case R::Cancelled:
        return "cancelled";
    case R::Failed:
        return "failed";
    case R::Uncertain:
        return "uncertain";
    }
    return "unknown";
}

std::string_view commit_origin_name(std::uint8_t origin) noexcept {
    using O = application::RemoteCommitOrigin;
    switch (static_cast<O>(origin)) {
    case O::Sync:
        return "sync";
    case O::Repack:
        return "repack";
    case O::ResolveMissing:
        return "resolve-missing";
    case O::Unknown:
        return "unknown";
    }
    return "unknown";
}

std::string_view error_code_string(const application::Error& error) noexcept {
    if (error.lock_busy) {
        return "lock_busy";
    }
    if (error.insufficient_disk_space) {
        return "insufficient_disk_space";
    }
    if ((error.garbage_collection && error.garbage_collection->transport_error) ||
        (error.barrier_removal && error.barrier_removal->transport_error)) {
        return "transport_error";
    }
    using C = application::ErrorCode;
    switch (error.code) {
    case C::InvalidProfile:
        return "config_error";
    case C::ProfileNotFound:
        return "profile_not_found";
    case C::RuntimeFailure:
        return "runtime_error";
    case C::CredentialsRequired:
        return "credentials_required";
    case C::CredentialFailure:
        return "auth_failed";
    case C::PlanFailure:
        return "plan_failed";
    case C::FsckFailure:
        return "fsck_failed";
    case C::GarbageCollectionFailure:
        return "gc_failed";
    case C::WriterRemovalFailure:
        return "writer_removal_failed";
    case C::BarrierRemovalFailure:
        return "barrier_removal_failed";
    case C::SynchronizationFailure:
        return "sync_failed";
    case C::RecoveryFailure:
        return "recovery_failed";
    case C::InventoryAuditFailure:
        return "inventory_audit_failed";
    case C::RepackFailure:
        return "repack_failed";
    }
    return "runtime_error";
}

std::string_view
inspection_error_code_string(const application::InspectionError& error) noexcept {
    using C = application::InspectionErrorCode;
    switch (error.code) {
    case C::InvalidRequest:
        return "invalid_arguments";
    case C::InvalidProfile:
        return "config_error";
    case C::ProfileNotFound:
        return "profile_not_found";
    case C::CredentialsRequired:
        return "credentials_required";
    case C::CredentialFailure:
        return "auth_failed";
    case C::RuntimeFailure:
        return "runtime_error";
    case C::RemoteObservationFailure:
    case C::HeadSelectionRequired:
    case C::RemoteHeadNotFound:
    case C::RemotePathNotFound:
    case C::RemoteCommitNotFound:
    case C::RemotePathIsDirectory:
    case C::RemoteContentNotFound:
    case C::RemoteContentInvalid:
    case C::DestinationFailure:
    case C::RemoteEpochNotFound:
        return "remote_observation_failed";
    }
    return "runtime_error";
}

std::string_view
profile_error_code_string(application::ProfileErrorCode code) noexcept {
    using C = application::ProfileErrorCode;
    switch (code) {
    case C::InvalidName:
        return "invalid_arguments";
    case C::NotFound:
        return "profile_not_found";
    case C::LockFailure:
        return "lock_busy";
    case C::CredentialFailure:
        return "auth_failed";
    case C::AlreadyExists:
    case C::ConfigFailure:
    case C::StorageFailure:
        return "config_error";
    }
    return "config_error";
}

json serialize_sync_completed(const application::SyncCompleted& sync) {
    json pending = json::array();
    for (const auto& path : sync.pending_paths) {
        pending.push_back(platform::path::to_utf8(path));
    }
    return json{
        {"summary", format_compact_summary(sync)},
        {"total", sync.total},
        {"uploaded", sync.uploaded},
        {"downloaded", sync.downloaded},
        {"removed", sync.removed},
        {"renamed", sync.renamed},
        {"created_dirs", sync.created_dirs},
        {"removed_dirs", sync.removed_dirs},
        {"repaired", sync.repaired},
        {"upload_bytes", sync.upload_bytes},
        {"download_bytes", sync.download_bytes},
        {"published", sync.published},
        {"partial", sync.partial},
        {"pending", sync.pending},
        {"pending_paths", std::move(pending)},
        {"wire_upload_bytes", sync.wire_upload_bytes},
        {"wire_download_bytes", sync.wire_download_bytes},
        {"local_delta_reused_bytes", sync.local_delta_reused_bytes},
        {"physical_objects_uploaded", sync.physical_objects_uploaded},
        {"physical_objects_downloaded", sync.physical_objects_downloaded},
    };
}

json serialize_execution_summary(const application::ProfileExecutionSummary& e) {
    json out{
        {"execution_id", e.execution_id},
        {"operation", profile_op_name(e.operation)},
        {"machine_id", e.machine_id_hex},
        {"machine_name", e.machine_name},
        {"started_at", e.started_at},
        {"duration_ms", e.duration_ms},
        {"status", profile_status_name(e.status)},
        {"recovered", e.recovered},
        {"stage", e.stage},
        {"detail", e.detail},
        {"commit_id", e.commit_id},
        {"summary_a", e.summary_a},
        {"summary_b", e.summary_b},
        {"summary_c", e.summary_c},
        {"summary_bytes", e.summary_bytes},
        {"flags", e.flags},
        {"remote_publish_state", remote_publish_name(e.remote_publish_state)},
    };
    if (e.finished_at.has_value()) {
        out["finished_at"] = *e.finished_at;
    } else {
        out["finished_at"] = nullptr;
    }
    return out;
}

std::string_view
profile_local_state_name(application::ProfileLocalState state) noexcept {
    switch (state) {
    case application::ProfileLocalState::Initialized:
        return "initialized";
    case application::ProfileLocalState::Ready:
        return "ready";
    case application::ProfileLocalState::Pending:
        return "pending";
    case application::ProfileLocalState::Problem:
        return "problem";
    }
    return "problem";
}

} // namespace

ScopedJsonLogFile::ScopedJsonLogFile(
    std::optional<std::filesystem::path> path)
    : path_(std::move(path)), previous_(g_json_log_file) {
    if (path_.has_value()) {
        g_json_log_file = &*path_;
    }
}

ScopedJsonLogFile::~ScopedJsonLogFile() noexcept {
    g_json_log_file = previous_;
}

int present_json_io_error(std::string_view command,
                          std::string_view profile_name,
                          std::string_view detail) {
    return emit_json_error(
        command.empty() ? "kasumi" : command, profile_name, 1, "io_error", detail);
}

std::string_view json_error_code(const application::Error& error) noexcept {
    return error_code_string(error);
}

std::string_view
json_error_code(const application::InspectionError& error) noexcept {
    return inspection_error_code_string(error);
}

std::string_view json_error_code(application::ProfileErrorCode code) noexcept {
    return profile_error_code_string(code);
}

int present_json_parse_error(std::string_view command,
                             std::string_view detail) {
    return emit_json_error(
        command.empty() ? "kasumi" : command, {}, 1, "invalid_arguments", detail);
}

int present_json_cancellation(std::string_view command,
                              std::string_view profile_name) {
    return emit_json_error(command,
                           profile_name,
                           130,
                           "cancelled",
                           "operation cancelled by user");
}

int present_json_list(const std::vector<application::Profile>& profiles) {
    auto doc = make_envelope("list", {}, true, 0, std::nullopt);
    json names = json::array();
    for (const auto& profile : profiles) {
        names.push_back(profile.name);
    }
    doc["data"] = json{{"profiles", std::move(names)}};
    emit_json(doc);
    return 0;
}

int present_json_show(const application::Profile& profile,
                      application::ProfileLocalState state,
                      application::ProfileLocalProblem problem,
                      const application::ProfileActivityReport& activity,
                      bool full) {
    auto doc = make_envelope("show", profile.name, true, 0, std::nullopt);
    const std::string_view state_str = profile_local_state_name(state);

    json data{
        {"name", profile.name},
        {"local_dir", platform::path::to_utf8(profile.local_dir)},
        {"remote_dir", profile.remote_dir},
        {"state", state_str},
        {"problem", local_problem_name(problem)},
        {"key_storage", application::to_string(profile.key_storage)},
        {"min_history_depth", profile.min_history_depth},
        {"min_history_age_hours", profile.min_history_age_hours},
        {"database_present", activity.database_present},
    };
    if (activity.database_present) {
        if (activity.accepted_commit) {
            const auto& c = *activity.accepted_commit;
            data["accepted_commit"] = json{
                {"commit_id", c.commit_id},
                {"height", c.height},
                {"created_at", c.created_at},
                {"origin", commit_origin_name(c.origin_operation)},
                {"machine_id", c.machine_id_hex},
                {"machine_name", c.machine_name},
                {"accepted_at", c.accepted_at},
            };
        } else {
            data["accepted_commit"] = nullptr;
        }
        data["last_complete_sync"] =
            activity.last_complete_sync
                ? serialize_execution_summary(*activity.last_complete_sync)
                : json(nullptr);
        data["last_attempt"] =
            activity.last_attempt
                ? serialize_execution_summary(*activity.last_attempt)
                : json(nullptr);
        json recent = json::array();
        const std::size_t limit =
            full ? activity.recent_executions.size()
                 : std::min<std::size_t>(activity.recent_executions.size(), 5);
        for (std::size_t i = 0; i < limit; ++i) {
            recent.push_back(
                serialize_execution_summary(activity.recent_executions[i]));
        }
        data["recent_executions"] = std::move(recent);
        json cached = json::array();
        const std::size_t cached_limit =
            full ? activity.cached_remote_activities.size()
                 : std::min<std::size_t>(
                       activity.cached_remote_activities.size(), 5);
        for (std::size_t i = 0; i < cached_limit; ++i) {
            const auto& item = activity.cached_remote_activities[i];
            cached.push_back(json{
                {"event_id", item.event_id},
                {"operation", remote_op_name(item.operation)},
                {"outcome", remote_outcome_name(item.outcome)},
                {"machine_id", item.machine_id_hex},
                {"machine_name", item.machine_name},
                {"started_at", item.started_at},
                {"finished_at", item.finished_at},
                {"duration_ms", item.duration_ms},
                {"metric_primary", item.metric_primary},
                {"metric_secondary", item.metric_secondary},
                {"metric_bytes", item.metric_bytes},
                {"flags", item.flags},
                {"stage", item.stage},
                {"detail", item.detail},
                {"cached_at", item.cached_at},
            });
        }
        data["cached_remote_activities"] = std::move(cached);
    }
    doc["data"] = std::move(data);
    emit_json(doc);
    return 0;
}

int present_json_diagnostics(const application::DiagnosticsReport& report,
                             std::string_view version,
                             std::string_view requested_profile,
                             std::chrono::nanoseconds duration) {
    auto doc =
        make_envelope("diagnostics", requested_profile, true, 0, duration);

    json rclone{
        {"found", report.rclone.found},
        {"executable", platform::path::to_utf8(report.rclone.executable)},
        {"version", report.rclone.version},
        {"minimum_version", report.rclone.minimum_version},
        {"meets_minimum", report.rclone.meets_minimum},
        {"detail", report.rclone.detail},
    };

    json profiles = json::array();
    for (const auto& item : report.profiles) {
        json entry{
            {"name", item.profile.name},
            {"local_dir", platform::path::to_utf8(item.profile.local_dir)},
            {"remote_dir", item.profile.remote_dir},
            {"state", profile_local_state_name(item.local_state)},
            {"problem", local_problem_name(item.local_problem)},
            {"key_storage", application::to_string(item.profile.key_storage)},
            {"local_dir_exists", item.local_dir_exists},
            {"local_dir_writable", item.local_dir_writable},
            {"local_free_bytes",
             item.local_free_bytes ? json(*item.local_free_bytes)
                                   : json(nullptr)},
            {"local_capacity_bytes",
             item.local_capacity_bytes ? json(*item.local_capacity_bytes)
                                       : json(nullptr)},
            {"uses_rclone", item.uses_rclone},
            {"lock_active", item.lock_active},
            {"journal_present", item.journal_present},
            {"key_accessible", item.key_accessible},
            {"database_present", item.activity.database_present},
            {"healthy", item.healthy},
            {"detail", item.detail},
            {"last_attempt",
             item.activity.last_attempt
                 ? serialize_execution_summary(*item.activity.last_attempt)
                 : json(nullptr)},
        };
        if (item.activity.accepted_commit) {
            entry["accepted_commit_id"] =
                item.activity.accepted_commit->commit_id;
        } else {
            entry["accepted_commit_id"] = nullptr;
        }
        profiles.push_back(std::move(entry));
    }

    doc["data"] = json{
        {"summary", format_compact_summary(report)},
        {"version", version},
        {"os", report.os_name},
        {"app_data_dir", platform::path::to_utf8(report.app_data_dir)},
        {"config_path", platform::path::to_utf8(report.config_path)},
        {"config_exists", report.config_exists},
        {"app_data_free_bytes",
         report.app_data_free_bytes ? json(*report.app_data_free_bytes)
                                    : json(nullptr)},
        {"rclone", std::move(rclone)},
        {"profiles", std::move(profiles)},
        {"overall_ok", report.overall_ok},
    };
    emit_json(doc);
    return 0;
}

int present_json_profile_error(std::string_view command,
                               std::string_view profile_name,
                               const application::ProfileError& error) {
    return emit_json_error(command,
                           profile_name,
                           1,
                           profile_error_code_string(error.code),
                           error.detail);
}

int present_json_confirmation_required(
    std::string_view profile_name,
    const application::ResolveMissingCompleted& preview,
    std::chrono::nanoseconds duration) {
    json paths = json::array();
    for (const auto& p : preview.resolved_paths) {
        paths.push_back(p);
    }
    return emit_json_error(
        "resolve-missing",
        profile_name,
        1,
        "confirmation_required",
        "resolve-missing requires --confirm in non-interactive --json mode "
        "when pending paths are eligible for deletion",
        duration,
        json{
            {"resolved_count", preview.resolved_paths.size()},
            {"resolved_paths", std::move(paths)},
            {"published", false},
        });
}

int present_json(std::string_view profile_name,
                 const application::Response& response,
                 std::chrono::nanoseconds duration,
                 bool full) {
    const auto op = response.operation;
    const auto cmd = operation_command_name(op);
    int exit_code = 0;
    std::string_view error_code;
    std::string error_message;
    json data;

    std::visit(
        [&](const auto& payload) {
            using T = std::decay_t<decltype(payload)>;
            if constexpr (std::is_same_v<T, application::SyncCompleted>) {
                data = serialize_sync_completed(payload);
                if (payload.partial) {
                    exit_code = 2;
                    error_code = "partial_pending";
                    error_message =
                        "synchronization completed partially with pending "
                        "materializations";
                }
                if (response.inventory_audit) {
                    const auto& audit = *response.inventory_audit;
                    data["inventory_audit"] = json{
                        {"referenced_content", audit.referenced_content},
                        {"present_content", audit.present_content},
                        {"missing_content", audit.missing_content},
                        {"orphan_content", audit.orphan_content},
                        {"unknown_objects", audit.unknown_objects},
                    };
                    if (exit_code == 0 && (audit.missing_content != 0 ||
                                           audit.orphan_content != 0 ||
                                           audit.unknown_objects != 0)) {
                        exit_code = 2;
                        error_code = "audit_findings";
                        error_message =
                            "post-sync inventory audit reported missing, "
                            "orphan, or unknown objects";
                    }
                }
            } else if constexpr (std::is_same_v<T, application::PlanReport>) {
                json counts;
                for (std::size_t i = 0; i < application::PLAN_ACTION_COUNT;
                     ++i) {
                    const auto action = static_cast<application::PlanAction>(i);
                    counts[std::string{plan_action_name(action)}] =
                        payload.action_counts[i];
                }
                json pending = json::array();
                for (const auto& p : payload.pending_paths) {
                    pending.push_back(platform::path::to_utf8(p));
                }
                json items = json::array();
                const std::size_t item_limit =
                    full ? payload.items.size()
                         : std::min<std::size_t>(payload.items.size(), 100);
                for (std::size_t i = 0; i < item_limit; ++i) {
                    const auto& item = payload.items[i];
                    json entry{
                        {"action", plan_action_name(item.action)},
                        {"path", platform::path::to_utf8(item.path)},
                        {"size", item.size},
                    };
                    if (!item.alternative_path.empty()) {
                        entry["alternative_path"] =
                            platform::path::to_utf8(item.alternative_path);
                    }
                    items.push_back(std::move(entry));
                }
                data = json{
                    {"dry_run", op == application::Operation::Preview},
                    {"target_generation", payload.target_generation},
                    {"action_counts", std::move(counts)},
                    {"upload_bytes", payload.upload_bytes},
                    {"download_bytes", payload.download_bytes},
                    {"has_conflicts", payload.has_conflicts},
                    {"total_items", payload.items.size()},
                    {"items", std::move(items)},
                    {"pending_paths", std::move(pending)},
                };
                if (!payload.pending_paths.empty()) {
                    exit_code = 2;
                    error_code = "partial_pending";
                    error_message = "profile has pending materializations";
                }
            } else if constexpr (std::is_same_v<
                                     T,
                                     application::GarbageCollectCompleted>) {
                data = json{
                    {"dry_run", payload.dry_run},
                    {"analysis_only", payload.analysis_only},
                    {"candidate_objects", payload.candidate_objects},
                    {"candidate_content_objects",
                     payload.candidate_content_objects},
                    {"candidate_commit_variants",
                     payload.candidate_commit_variants},
                    {"candidate_activities", payload.candidate_activities},
                    {"removed_objects", payload.removed_objects},
                };
            } else if constexpr (std::is_same_v<T,
                                                application::RepackCompleted>) {
                data = json{
                    {"dry_run", payload.dry_run},
                    {"actionable", payload.actionable},
                    {"published", payload.published},
                    {"live_small_blobs", payload.live_small_blobs},
                    {"existing_packs", payload.existing_packs},
                    {"healthy_packs_kept", payload.healthy_packs_kept},
                    {"dirty_packs_detected", payload.dirty_packs_detected},
                    {"loose_small_blobs_detected",
                     payload.loose_small_blobs_detected},
                    {"source_loose_blobs", payload.source_loose_blobs},
                    {"source_clean_packs", payload.source_clean_packs},
                    {"source_dirty_packs", payload.source_dirty_packs},
                    {"new_packs", payload.new_packs},
                    {"repacked_blobs", payload.repacked_blobs},
                    {"repacked_plaintext_bytes",
                     payload.repacked_plaintext_bytes},
                    {"published_commit_id", payload.published_commit_id},
                    {"published_height", payload.published_height},
                    {"pruned_markers", payload.pruned_markers},
                    {"wire_upload_bytes", payload.wire_upload_bytes},
                    {"physical_objects_uploaded",
                     payload.physical_objects_uploaded},
                };
            } else if constexpr (std::is_same_v<T, application::FsckCompleted>) {
                data = json{
                    {"checked_objects", payload.checked_objects},
                    {"wire_download_bytes", payload.wire_download_bytes},
                    {"physical_objects_downloaded",
                     payload.physical_objects_downloaded},
                    {"files_reassembled", payload.files_reassembled},
                };
                if (payload.checked_plaintext_bytes.has_value()) {
                    data["checked_plaintext_bytes"] =
                        *payload.checked_plaintext_bytes;
                } else {
                    data["checked_plaintext_bytes"] = nullptr;
                }
            } else if constexpr (std::is_same_v<
                                     T,
                                     application::ResolveMissingCompleted>) {
                json paths = json::array();
                for (const auto& p : payload.resolved_paths) {
                    paths.push_back(p);
                }
                data = json{
                    {"dry_run", payload.dry_run},
                    {"resolved_count", payload.resolved_count},
                    {"resolved_paths", std::move(paths)},
                    {"published", payload.published},
                };
            } else {
                data = json::object();
            }
        },
        response.data);

    auto doc = make_envelope(
        cmd, profile_name, exit_code == 0, exit_code, duration);
    if (exit_code != 0) {
        doc["error"] = json{
            {"code", error_code},
            {"message", error_message},
        };
    }
    if (response.activity_publish_warning &&
        !response.activity_publish_warning->empty()) {
        doc["warning"] = *response.activity_publish_warning;
    }
    data["summary"] = format_compact_summary(response);
    doc["data"] = std::move(data);
    emit_json(doc);
    return exit_code;
}

int present_json(std::string_view profile_name,
                 const application::Error& error,
                 std::chrono::nanoseconds duration) {
    std::optional<json> data;
    if (error.code == application::ErrorCode::InventoryAuditFailure &&
        error.sync_completed) {
        data = json{{"sync", serialize_sync_completed(*error.sync_completed)}};
    }
    return emit_json_error(operation_command_name(error.operation),
                           profile_name,
                           1,
                           error_code_string(error),
                           error.detail,
                           duration,
                           std::move(data));
}

int present_json(std::string_view profile_name,
                 const application::InspectionResponse& response,
                 std::chrono::nanoseconds duration,
                 bool full) {
    const auto cmd = inspection_command_name(response.operation);
    auto doc = make_envelope(cmd, profile_name, true, 0, duration);
    if (const auto* summary =
            std::get_if<application::RemoteSummaryReport>(&response.payload)) {
        json activities = json::array();
        const std::size_t limit =
            full ? summary->recent_activities.size()
                 : std::min<std::size_t>(summary->recent_activities.size(), 5);
        for (std::size_t i = 0; i < limit; ++i) {
            const auto& item = summary->recent_activities[i];
            activities.push_back(json{
                {"event_id", item.event_id},
                {"operation",
                 remote_op_name(static_cast<std::uint8_t>(item.operation))},
                {"outcome",
                 remote_outcome_name(static_cast<std::uint8_t>(item.outcome))},
                {"machine_id", item.machine_id_hex},
                {"machine_name", item.machine_name},
                {"started_at", item.started_at},
                {"finished_at", item.finished_at},
                {"duration_ms", item.duration_ms},
                {"metric_primary", item.metric_primary},
                {"metric_secondary", item.metric_secondary},
                {"metric_bytes", item.metric_bytes},
                {"flags", item.flags},
                {"stage", item.stage},
                {"detail", item.detail},
            });
        }
        doc["data"] = json{
            {"history_present", summary->history_present},
            {"observed_height", summary->observed_height},
            {"reachable_commit_count", summary->reachable_commit_count},
            {"logical_head_count", summary->logical_head_count},
            {"has_conflicts", summary->has_conflicts},
            {"missing_content_count", summary->missing_content_count},
            {"orphan_content_count", summary->orphan_content_count},
            {"active_writer_count", summary->active_writer_count},
            {"invalid_activity_count", summary->invalid_activity_count},
            {"recent_activities", std::move(activities)},
        };
    } else {
        doc["data"] = json::object();
    }
    doc["data"]["summary"] = format_compact_summary(response);
    emit_json(doc);
    return 0;
}

int present_json(std::string_view profile_name,
                 const application::InspectionError& error,
                 std::chrono::nanoseconds duration) {
    return emit_json_error(inspection_command_name(error.operation),
                           profile_name,
                           1,
                           inspection_error_code_string(error),
                           error.detail,
                           duration);
}

std::string_view
profile_local_state_name(application::ProfileLocalState state) noexcept {
    switch (state) {
    case application::ProfileLocalState::Initialized:
        return "initialized";
    case application::ProfileLocalState::Ready:
        return "ready";
    case application::ProfileLocalState::Pending:
        return "pending";
    case application::ProfileLocalState::Problem:
        return "problem";
    }
    return "problem";
}

} // namespace kasumi::cli
