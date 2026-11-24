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
    const auto line = doc.dump(-1, ' ', false, json::error_handler_t::replace);
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

int emit_json_error(
    std::string_view command,
    std::string_view profile_name,
    int exit_code,
    std::string_view error_code,
    std::string_view message,
    std::optional<std::chrono::nanoseconds> duration = std::nullopt,
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
    using Op = application::InspectionOperation;
    switch (op) {
        case Op::RemoteSummary:
            return "remote summary";
        case Op::RemoteWriters:
            return "remote writers";
        case Op::RemoteStat:
            return "remote stat";
        case Op::RemoteGet:
            return "remote get";
        case Op::RemoteLog:
            return "remote log";
        case Op::RemoteRestore:
            return "remote restore";
        default:
            return "remote";
    }
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
    if (error.remote_busy) {
        return "remote_busy";
    }
    if (error.empty_local_blocked) {
        return "empty_local_blocked";
    }
    if ((error.garbage_collection &&
         error.garbage_collection->transport_error) ||
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

std::string_view inspection_error_code_string(
    const application::InspectionError& error) noexcept {
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
        case C::InvalidPath:
            return "invalid_path";
        case C::NotFound:
            return "profile_not_found";
        case C::LockFailure:
            return "lock_busy";
        case C::CredentialFailure:
            return "auth_failed";
        case C::AlreadyExists:
            return "already_exists";
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

json serialize_execution_summary(
    const application::ProfileExecutionSummary& e) {
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
        {"origin",
         (e.flags & application::profile_execution_flag_origin_daemon) != 0U
             ? "daemon"
             : "cli"},
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
        case application::ProfileLocalState::Running:
            return "running";
        case application::ProfileLocalState::Problem:
            return "problem";
    }
    return "problem";
}

} // namespace

ScopedJsonLogFile::ScopedJsonLogFile(
    std::optional<std::filesystem::path> log_path)
    : path(std::move(log_path)), previous(g_json_log_file) {
    if (path.has_value()) {
        g_json_log_file = &*path;
    }
}

ScopedJsonLogFile::~ScopedJsonLogFile() noexcept {
    g_json_log_file = previous;
}

int present_json_io_error(std::string_view command,
                          std::string_view profile_name,
                          std::string_view detail) {
    return emit_json_error(command.empty() ? "kasumi" : command,
                           profile_name,
                           1,
                           "io_error",
                           detail);
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

std::string_view json_error_code(application::DaemonErrorCode code) noexcept {
    using C = application::DaemonErrorCode;
    switch (code) {
        case C::AlreadyRunning:
            return "daemon_already_running";
        case C::NotRunning:
            return "daemon_not_running";
        case C::ProfileNotFound:
            return "profile_not_found";
        case C::InvalidCredential:
            return "credentials_invalid";
        case C::LockBusy:
            return "lock_busy";
        case C::IpcFailure:
            return "ipc_failure";
        case C::ConfigFailure:
            return "config_failure";
        case C::StorageFailure:
            return "storage_failure";
        case C::Unsupported:
            return "unsupported";
        case C::Timeout:
            return "timeout";
    }
    return "daemon_error";
}

int present_json_parse_error(std::string_view command,
                             std::string_view detail) {
    return emit_json_error(command.empty() ? "kasumi" : command,
                           {},
                           1,
                           "invalid_arguments",
                           detail);
}

int present_json_cancellation(std::string_view command,
                              std::string_view profile_name) {
    return emit_json_error(
        command, profile_name, 130, "cancelled", "operation cancelled by user");
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

int present_json_show(
    const application::Profile& profile,
    application::ProfileLocalState state,
    application::ProfileLocalProblem problem,
    const application::ProfileActivityReport& activity,
    bool full,
    const std::optional<application::DaemonProfileStatus>& daemon_profile) {
    auto doc = make_envelope("show", profile.name, true, 0, std::nullopt);
    const std::string_view state_str = profile_local_state_name(state);
    const bool lock_active = state == application::ProfileLocalState::Running;
    const auto active_op = lock_active
                               ? application::active_profile_operation(activity)
                               : std::nullopt;
    json daemon_json = nullptr;
    if (daemon_profile.has_value()) {
        daemon_json = json{
            {"state", application::to_string(daemon_profile->state)},
            {"active_stage", daemon_profile->active_stage},
            {"watcher_active", daemon_profile->watcher_active},
            {"watcher_degraded", daemon_profile->watcher_degraded},
            {"dirty_paths_count", daemon_profile->dirty_paths_count},
            {"paused", daemon_profile->paused},
            {"locked", daemon_profile->locked},
            {"warm_transport_active", daemon_profile->warm_transport_active},
            {"sync_runs", daemon_profile->sync_runs},
            {"gc_runs", daemon_profile->gc_runs},
            {"last_error", daemon_profile->last_error},
        };
    }

    json data{
        {"name", profile.name},
        {"local_dir", platform::path::to_utf8(profile.local_dir)},
        {"remote_dir", profile.remote_dir},
        {"state", state_str},
        {"problem", local_problem_name(problem)},
        {"lock_active", lock_active},
        {"active_operation", active_op ? json(*active_op) : json(nullptr)},
        {"key_storage", application::to_string(profile.key_storage)},
        {"min_history_depth", profile.min_history_depth},
        {"min_history_age_hours", profile.min_history_age_hours},
        {"bandwidth_limit",
         profile.bandwidth_limit ? json(*profile.bandwidth_limit)
                                 : json(nullptr)},
        {"transfer_concurrency",
         profile.transfer_concurrency ? json(*profile.transfer_concurrency)
                                      : json(nullptr)},
        {"rclone_config",
         profile.rclone_config
             ? json(platform::path::to_utf8(*profile.rclone_config))
             : json(nullptr)},
        {"watch_enabled",
         profile.watch_enabled ? json(*profile.watch_enabled) : json(nullptr)},
        {"sync_interval_seconds",
         profile.sync_interval_seconds ? json(*profile.sync_interval_seconds)
                                       : json(nullptr)},
        {"gc_interval_hours",
         profile.gc_interval_hours ? json(*profile.gc_interval_hours)
                                   : json(nullptr)},
        {"paused", profile.paused},
        {"daemon", std::move(daemon_json)},
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
        const auto active_op =
            item.lock_active
                ? application::active_profile_operation(item.activity)
                : std::nullopt;
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
            {"active_operation", active_op ? json(*active_op) : json(nullptr)},
            {"journal_present", item.journal_present},
            {"key_accessible", item.key_accessible},
            {"database_present", item.activity.database_present},
            {"ignore_file_present", item.ignore_file_present},
            {"ignore_file_valid", item.ignore_file_valid},
            {"ignore_error_line",
             item.ignore_error_line ? json(*item.ignore_error_line)
                                    : json(nullptr)},
            {"ignore_error_detail",
             item.ignore_error_detail.empty() ? json(nullptr)
                                              : json(item.ignore_error_detail)},
            {"daemon_state",
             item.daemon_state ? json(*item.daemon_state) : json(nullptr)},
            {"daemon_active_stage", item.daemon_active_stage},
            {"daemon_watcher_active", item.daemon_watcher_active},
            {"daemon_error", item.daemon_error},
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
        {"daemon",
         json{
             {"running", report.daemon.running},
             {"pid", report.daemon.pid},
             {"ipc_port", report.daemon.ipc_port},
             {"control_metadata_valid", report.daemon.control_metadata_valid},
             {"secure_pages_locked", report.daemon.secure_pages_locked},
             {"autostart_supported", report.daemon.autostart_supported},
             {"autostart_installed", report.daemon.autostart_installed},
             {"autostart_method", report.daemon.autostart_method},
             {"detail", report.daemon.detail},
         }},
        {"profiles", std::move(profiles)},
        {"overall_ok", report.overall_ok},
    };
    emit_json(doc);
    return 0;
}

int present_json_conflicts(const application::LocalConflictsReport& report,
                           std::chrono::nanoseconds duration) {
    auto doc =
        make_envelope("conflicts", report.profile_name, true, 0, duration);
    json groups = json::array();
    for (const auto& group : report.groups) {
        json artifacts = json::array();
        for (const auto& art : group.artifacts) {
            std::string_view origin_str = "branch";
            if (art.origin == application::ConflictOrigin::Local) {
                origin_str = "local";
            } else if (art.origin == application::ConflictOrigin::Remote) {
                origin_str = "remote";
            }
            artifacts.push_back(json{
                {"path", art.path},
                {"origin", origin_str},
                {"origin_tag", art.origin_tag},
                {"size", art.size},
                {"modified_at", art.modified_at},
            });
        }
        groups.push_back(json{
            {"canonical_path", group.canonical_path},
            {"canonical_exists", group.canonical_exists},
            {"canonical_size", group.canonical_size},
            {"canonical_modified_at", group.canonical_modified_at},
            {"artifacts", std::move(artifacts)},
        });
    }
    doc["data"] = json{
        {"summary", format_compact_summary(report)},
        {"local_dir", platform::path::to_utf8(report.local_dir)},
        {"total_artifacts", report.total_artifacts},
        {"group_count", report.groups.size()},
        {"groups", std::move(groups)},
    };
    emit_json(doc);
    return 0;
}

int present_json_conflict_resolved(
    const application::ResolveConflictReport& report,
    std::chrono::nanoseconds duration) {
    auto doc = make_envelope(
        "conflicts resolve", report.profile_name, true, 0, duration);
    json removed = json::array();
    for (const auto& art : report.removed_artifacts) {
        removed.push_back(art);
    }
    const std::string_view choice =
        report.choice == application::ConflictResolutionChoice::KeepCanonical
            ? "canonical"
            : "artifact";
    doc["data"] = json{
        {"summary", format_compact_summary(report)},
        {"canonical_path", report.canonical_path},
        {"dry_run", report.dry_run},
        {"choice", choice},
        {"selected_artifact",
         report.selected_artifact ? json(*report.selected_artifact)
                                  : json(nullptr)},
        {"removed_count", report.removed_artifacts.size()},
        {"removed_artifacts", std::move(removed)},
    };
    emit_json(doc);
    return 0;
}

int present_json_profile_action(std::string_view command,
                                const application::Profile* profile,
                                std::string_view profile_name,
                                std::string_view summary,
                                bool needs_key,
                                std::chrono::nanoseconds duration) {
    auto doc = make_envelope(command, profile_name, true, 0, duration);
    json data{
        {"summary", summary},
        {"needs_key", needs_key},
    };
    if (profile != nullptr) {
        data["profile"] = json{
            {"name", profile->name},
            {"local_dir", platform::path::to_utf8(profile->local_dir)},
            {"remote_dir", profile->remote_dir},
            {"key_storage", application::to_string(profile->key_storage)},
            {"min_history_depth", profile->min_history_depth},
            {"min_history_age_hours", profile->min_history_age_hours},
            {"bandwidth_limit",
             profile->bandwidth_limit ? json(*profile->bandwidth_limit)
                                      : json(nullptr)},
            {"transfer_concurrency",
             profile->transfer_concurrency
                 ? json(*profile->transfer_concurrency)
                 : json(nullptr)},
            {"rclone_config",
             profile->rclone_config
                 ? json(platform::path::to_utf8(*profile->rclone_config))
                 : json(nullptr)},
            {"watch_enabled",
             profile->watch_enabled ? json(*profile->watch_enabled)
                                    : json(nullptr)},
            {"sync_interval_seconds",
             profile->sync_interval_seconds
                 ? json(*profile->sync_interval_seconds)
                 : json(nullptr)},
            {"gc_interval_hours",
             profile->gc_interval_hours ? json(*profile->gc_interval_hours)
                                        : json(nullptr)},
            {"paused", profile->paused},
        };
    }
    doc["data"] = std::move(data);
    emit_json(doc);
    return 0;
}

int present_json_key_updated(std::string_view profile_name,
                             bool replaced,
                             bool unchanged,
                             std::chrono::nanoseconds duration) {
    auto doc = make_envelope("key", profile_name, true, 0, duration);
    const std::string_view summary =
        unchanged ? "stored key unchanged"
                  : (replaced ? "stored key replaced" : "stored key saved");
    doc["data"] = json{
        {"summary", summary},
        {"replaced", replaced},
        {"unchanged", unchanged},
    };
    emit_json(doc);
    return 0;
}

int present_json_profile_test(
    const application::ProfileConnectionReport& report,
    std::chrono::nanoseconds duration) {
    auto vault_state_name = [](application::RemoteVaultState state) {
        using S = application::RemoteVaultState;
        switch (state) {
            case S::EmptyReadyForInit:
                return "empty_ready_for_init";
            case S::AuthenticatedVault:
                return "authenticated_vault";
            case S::KeyMismatchOrInvalidHistory:
                return "key_mismatch_or_invalid_history";
            case S::TransportFailure:
                return "transport_failure";
        }
        return "transport_failure";
    };
    json payload{
        {"remote_dir", report.remote_dir},
        {"transport_ok", report.transport_ok},
        {"ready", report.ready},
        {"vault_state", vault_state_name(report.vault_state)},
        {"head_count", report.head_count},
        {"epoch_sequence",
         report.epoch_sequence ? json(*report.epoch_sequence) : json(nullptr)},
        {"epoch_id",
         report.epoch_id.empty() ? json(nullptr) : json(report.epoch_id)},
        {"detail", report.detail},
    };
    if (!report.ready) {
        const std::string_view code =
            report.vault_state ==
                    application::RemoteVaultState::KeyMismatchOrInvalidHistory
                ? "auth_failed"
                : "remote_observation_failed";
        return emit_json_error("profile test",
                               report.profile_name,
                               1,
                               code,
                               report.detail,
                               duration,
                               std::move(payload));
    }
    auto doc =
        make_envelope("profile test", report.profile_name, true, 0, duration);
    payload["summary"] = report.detail;
    doc["data"] = std::move(payload);
    emit_json(doc);
    return 0;
}

int present_json_ignore_check(const application::IgnoreCheckReport& report,
                              std::chrono::nanoseconds duration) {
    auto disposition_name = [](application::IgnoreDispositionKind kind) {
        using K = application::IgnoreDispositionKind;
        switch (kind) {
            case K::Managed:
                return "managed";
            case K::IgnoredProtected:
                return "ignored_protected";
            case K::IgnoredDisposable:
                return "ignored_disposable";
        }
        return "managed";
    };
    json items = json::array();
    for (const auto& item : report.items) {
        items.push_back(json{
            {"input_path", item.input_path},
            {"logical_path", item.logical_path},
            {"is_directory", item.is_directory},
            {"disposition", disposition_name(item.disposition)},
            {"reserved_internal", item.reserved_internal},
            {"matched_rule", item.matched_rule},
            {"rule_line",
             item.matched_rule ? json(item.rule_line) : json(nullptr)},
            {"rule_text",
             item.matched_rule ? json(item.rule_text) : json(nullptr)},
        });
    }
    auto doc =
        make_envelope("ignore check", report.profile_name, true, 0, duration);
    doc["data"] = json{
        {"summary", std::format("evaluated {} path(s)", report.items.size())},
        {"ignore_file", platform::path::to_utf8(report.ignore_file)},
        {"ignore_file_present", report.ignore_file_present},
        {"items", std::move(items)},
    };
    emit_json(doc);
    return 0;
}

int present_json_ignore_init(const application::IgnoreInitReport& report,
                             std::chrono::nanoseconds duration) {
    const auto preset = application::to_string(report.preset);
    auto doc =
        make_envelope("ignore init", report.profile_name, true, 0, duration);
    const std::string summary =
        report.dry_run
            ? std::format("previewed .kasumiignore (preset={})", preset)
            : std::format("{} .kasumiignore (preset={})",
                          report.overwritten ? "overwrote" : "created",
                          preset);
    doc["data"] = json{
        {"summary", summary},
        {"ignore_file", platform::path::to_utf8(report.ignore_file)},
        {"preset", preset},
        {"created", report.created},
        {"overwritten", report.overwritten},
        {"dry_run", report.dry_run},
        {"content", report.content},
    };
    emit_json(doc);
    return 0;
}

int present_json_credentials_required(std::string_view command,
                                      std::string_view profile_name,
                                      std::string_view detail,
                                      std::chrono::nanoseconds duration) {
    return emit_json_error(
        command, profile_name, 1, "credentials_required", detail, duration);
}

int present_json_profile_error(
    std::string_view command,
    std::string_view profile_name,
    const application::ProfileError& error,
    std::optional<std::chrono::nanoseconds> duration) {
    return emit_json_error(command,
                           profile_name,
                           1,
                           profile_error_code_string(error.code),
                           error.detail,
                           duration);
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
                    {"candidate_expired_commits",
                     payload.candidate_expired_commits},
                    {"candidate_activities", payload.candidate_activities},
                    {"deferred_recent_objects",
                     payload.deferred_recent_objects},
                    {"candidate_bytes", payload.candidate_bytes},
                    {"removed_objects", payload.removed_objects},
                    {"removed_bytes", payload.removed_bytes},
                    {"min_age_hours", payload.min_age_hours},
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
            } else if constexpr (std::is_same_v<T,
                                                application::FsckCompleted>) {
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
            } else if constexpr (
                std::is_same_v<T, application::ManualBarrierRemovalCompleted>) {
                data = json{
                    {"identifier", payload.identifier},
                    {"outcome",
                     payload.outcome ==
                             application::BarrierRemovalOutcome::Removed
                         ? "removed"
                         : "already_absent"},
                    {"active_writers_count", payload.active_writers_count},
                    {"remaining_barriers_count",
                     payload.remaining_barriers_count},
                };
            } else {
                data = json::object();
            }
        },
        response.data);

    auto doc =
        make_envelope(cmd, profile_name, exit_code == 0, exit_code, duration);
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
    } else if (const auto* writers_report =
                   std::get_if<application::RemoteWritersReport>(
                       &response.payload)) {
        json barriers = json::array();
        for (const auto& barrier : writers_report->barriers) {
            json item{
                {"identifier", barrier.identifier},
                {"legacy", barrier.legacy},
                {"structurally_valid", barrier.structurally_valid},
            };
            if (barrier.machine_name.has_value()) {
                item["machine_name"] = *barrier.machine_name;
            }
            if (barrier.pid.has_value()) {
                item["pid"] = *barrier.pid;
            }
            if (barrier.started_at_unix.has_value()) {
                item["started_at_unix"] = *barrier.started_at_unix;
            }
            barriers.push_back(std::move(item));
        }
        json writers = json::array();
        for (const auto& writer : writers_report->writers) {
            json item{
                {"identifier", writer.identifier},
                {"state",
                 writer.state == application::RemoteWriterState::Invalid
                     ? "invalid"
                     : "indeterminate"},
            };
            if (writer.machine_name.has_value()) {
                item["machine_name"] = *writer.machine_name;
            }
            if (writer.pid.has_value()) {
                item["pid"] = *writer.pid;
            }
            if (writer.started_at_unix.has_value()) {
                item["started_at_unix"] = *writer.started_at_unix;
            }
            writers.push_back(std::move(item));
        }
        doc["data"] = json{
            {"barrier_present", writers_report->barrier_present},
            {"barrier_identifier",
             writers_report->barrier_identifier
                 ? json(*writers_report->barrier_identifier)
                 : json(nullptr)},
            {"maintenance_blocked", writers_report->maintenance_blocked},
            {"protocol_consistent", writers_report->protocol_consistent},
            {"barriers", std::move(barriers)},
            {"writers", std::move(writers)},
        };
    } else if (const auto* stat_report =
                   std::get_if<application::RemoteStatReport>(
                       &response.payload)) {
        doc["data"] = json{
            {"commit_id",
             stat_report->commit_id ? json(*stat_report->commit_id)
                                    : json(nullptr)},
            {"observed_height", stat_report->observed_height},
            {"has_conflicts", stat_report->has_conflicts},
            {"path", stat_report->path},
            {"type",
             stat_report->type == application::RemoteTreeEntryType::Directory
                 ? "directory"
                 : "file"},
            {"logical_hash", stat_report->logical_hash},
            {"size", stat_report->size},
            {"modified_at_unix_nanoseconds",
             stat_report->modified_at_unix_nanoseconds},
        };
    } else if (const auto* file_report =
                   std::get_if<application::RemoteFileReport>(
                       &response.payload)) {
        doc["data"] = json{
            {"commit_id",
             file_report->commit_id ? json(*file_report->commit_id)
                                    : json(nullptr)},
            {"path", file_report->path},
            {"destination_path", file_report->destination_path},
            {"logical_hash", file_report->logical_hash},
            {"content_id", file_report->content_id},
            {"size", file_report->size},
        };
    } else if (const auto* log_report =
                   std::get_if<application::RemoteLogReport>(
                       &response.payload)) {
        const auto change_name =
            [](application::RemotePathChangeKind kind) -> std::string_view {
            using K = application::RemotePathChangeKind;
            switch (kind) {
                case K::Added:
                    return "added";
                case K::Modified:
                    return "modified";
                case K::Deleted:
                    return "deleted";
                case K::Observed:
                    return "observed";
            }
            return "observed";
        };
        const auto origin_name =
            [](application::RemoteCommitOrigin op) -> std::string_view {
            using O = application::RemoteCommitOrigin;
            switch (op) {
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
        };
        json entries = json::array();
        for (const auto& entry : log_report->entries) {
            json item{
                {"commit_id", entry.commit_id},
                {"height", entry.height},
                {"created_at", entry.created_at},
                {"logical_head", entry.logical_head},
                {"change", change_name(entry.change)},
                {"type",
                 entry.type
                     ? json(*entry.type ==
                                    application::RemoteTreeEntryType::Directory
                                ? "directory"
                                : "file")
                     : json(nullptr)},
                {"logical_hash", entry.logical_hash},
                {"size", entry.size},
                {"modified_at_unix_nanoseconds",
                 entry.modified_at_unix_nanoseconds},
            };
            if (entry.authorship) {
                item["authorship"] = json{
                    {"operation", origin_name(entry.authorship->operation)},
                    {"machine_id", entry.authorship->machine_id_hex},
                    {"machine_name", entry.authorship->machine_name},
                };
            } else {
                item["authorship"] = nullptr;
            }
            entries.push_back(std::move(item));
        }
        doc["data"] = json{
            {"path", log_report->path},
            {"observed_height", log_report->observed_height},
            {"present_in_current_tree", log_report->present_in_current_tree},
            {"entry_count", log_report->entries.size()},
            {"entries", std::move(entries)},
        };
    } else if (const auto* restore_report =
                   std::get_if<application::RemoteRestoreReport>(
                       &response.payload)) {
        doc["data"] = json{
            {"dry_run", restore_report->dry_run},
            {"commit_id",
             restore_report->commit_id ? json(*restore_report->commit_id)
                                       : json(nullptr)},
            {"observed_height", restore_report->observed_height},
            {"source_prefix", restore_report->source_prefix},
            {"destination_path", restore_report->destination_path},
            {"file_count", restore_report->file_count},
            {"directory_count", restore_report->directory_count},
            {"total_bytes", restore_report->total_bytes},
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

namespace {

json serialize_daemon_autostart(const application::DaemonAutostartStatus& s) {
    return json{
        {"supported", s.supported},
        {"installed", s.installed},
        {"systemd_enabled", s.systemd_enabled},
        {"method", s.method},
        {"location", s.location},
        {"command", s.command},
        {"detail", s.detail},
    };
}

} // namespace

int present_json_daemon_status(std::string_view command,
                               const application::DaemonStatusReport& report,
                               std::chrono::nanoseconds duration,
                               std::optional<std::string_view> profile_name) {
    auto doc = make_envelope(
        command, profile_name.value_or(std::string_view{}), true, 0, duration);
    json profiles = json::array();
    for (const auto& p : report.profiles) {
        profiles.push_back(json{
            {"name", p.name},
            {"local_dir", p.local_dir},
            {"remote_dir", p.remote_dir},
            {"key_storage", application::to_string(p.key_storage)},
            {"state", application::to_string(p.state)},
            {"paused", p.paused},
            {"locked", p.locked},
            {"watch_enabled", p.watch_enabled},
            {"watcher_active", p.watcher_active},
            {"watcher_degraded", p.watcher_degraded},
            {"dirty_paths_count", p.dirty_paths_count},
            {"warm_transport_active", p.warm_transport_active},
            {"warm_cache_entries", p.warm_cache_entries},
            {"sync_interval_seconds", p.sync_interval_seconds},
            {"gc_interval_hours", p.gc_interval_hours},
            {"active_stage", p.active_stage},
            {"active_objects", p.active_objects},
            {"active_total_objects",
             p.active_total_objects ? json(*p.active_total_objects)
                                    : json(nullptr)},
            {"active_bytes", p.active_bytes},
            {"active_total_bytes",
             p.active_total_bytes ? json(*p.active_total_bytes)
                                  : json(nullptr)},
            {"last_sync_started_at",
             p.last_sync_started_at ? json(*p.last_sync_started_at)
                                    : json(nullptr)},
            {"last_sync_finished_at",
             p.last_sync_finished_at ? json(*p.last_sync_finished_at)
                                     : json(nullptr)},
            {"last_checked_at",
             p.last_checked_at ? json(*p.last_checked_at) : json(nullptr)},
            {"next_sync_at",
             p.next_sync_at ? json(*p.next_sync_at) : json(nullptr)},
            {"next_gc_at", p.next_gc_at ? json(*p.next_gc_at) : json(nullptr)},
            {"backoff_seconds", p.backoff_seconds},
            {"backoff_until_unix",
             p.backoff_until_unix ? json(*p.backoff_until_unix)
                                  : json(nullptr)},
            {"consecutive_failures", p.consecutive_failures},
            {"sync_runs", p.sync_runs},
            {"fast_noop_polls", p.fast_noop_polls},
            {"gc_runs", p.gc_runs},
            {"last_outcome", p.last_outcome},
            {"last_error", p.last_error},
        });
    }
    doc["data"] = json{
        {"summary", format_compact_summary(report)},
        {"api_version", report.api_version},
        {"kasumi_version", report.kasumi_version},
        {"running", report.running},
        {"pid", report.pid},
        {"started_at_unix", report.started_at_unix},
        {"uptime_seconds", report.uptime_seconds},
        {"ipc_port", report.ipc_port},
        {"secure_pages_locked", report.secure_pages_locked},
        {"autostart", serialize_daemon_autostart(report.autostart)},
        {"profiles", std::move(profiles)},
    };
    emit_json(doc);
    return 0;
}

int present_json_daemon_sync(const application::DaemonSyncTriggerReport& report,
                             std::optional<std::string_view> profile_name,
                             bool wait,
                             std::chrono::nanoseconds duration) {
    const bool ok = report.failures.empty();
    const int code = ok ? 0 : 1;
    auto doc = make_envelope("daemon sync",
                             profile_name.value_or(std::string_view{}),
                             ok,
                             code,
                             duration);
    json failures = json::array();
    for (const auto& [pname, err] : report.failures) {
        failures.push_back(json{{"profile", pname}, {"detail", err}});
    }
    doc["data"] = json{
        {"summary",
         std::format("profiles={}, completed={}, failures={}",
                     report.profiles.size(),
                     report.completed ? "yes" : "no",
                     report.failures.size())},
        {"wait", wait},
        {"completed", report.completed},
        {"profiles", report.profiles},
        {"failures", std::move(failures)},
    };
    if (!ok) {
        doc["error"] = json{
            {"code", "sync_failed"},
            {"message", report.failures.front().second},
        };
    }
    emit_json(doc);
    return code;
}

int present_json_daemon_autostart(
    std::string_view command,
    const application::DaemonAutostartStatus& status,
    std::chrono::nanoseconds duration) {
    auto doc = make_envelope(command, {}, true, 0, duration);
    auto data = serialize_daemon_autostart(status);
    data["summary"] = format_compact_summary(status);
    doc["data"] = std::move(data);
    emit_json(doc);
    return 0;
}

int present_json_daemon_action(std::string_view command,
                               std::string_view profile_name,
                               std::string_view summary,
                               std::chrono::nanoseconds duration) {
    auto doc = make_envelope(command, profile_name, true, 0, duration);
    doc["data"] = json{
        {"summary", summary},
    };
    emit_json(doc);
    return 0;
}

int present_json_daemon_logs(const application::DaemonLogsReport& report,
                             std::optional<std::string_view> profile_name,
                             std::chrono::nanoseconds duration,
                             std::string_view command,
                             bool full) {
    auto doc = make_envelope(command,
                             profile_name.value_or(std::string_view{}),
                             true,
                             0,
                             duration);
    json events = json::array();
    for (const auto& ev : report.events) {
        if (!full && is_noisy_daemon_event(ev)) {
            continue;
        }
        events.push_back(json{
            {"seq", ev.seq},
            {"timestamp_unix", ev.timestamp_unix},
            {"profile", ev.profile_name},
            {"kind", ev.kind},
            {"detail", ev.detail},
        });
    }
    const std::size_t event_count = events.size();
    doc["data"] = json{
        {"summary",
         std::format("events={}, latest_seq={}",
                     event_count,
                     report.latest_seq)},
        {"log_path", report.log_path},
        {"latest_seq", report.latest_seq},
        {"events", std::move(events)},
    };
    emit_json(doc);
    return 0;
}

void present_json_daemon_stream_event(const application::DaemonEvent& ev) {
    json doc{
        {"schema_version", 1},
        {"command", "logs"},
        {"event",
         json{
             {"seq", ev.seq},
             {"timestamp_unix", ev.timestamp_unix},
             {"profile", ev.profile_name},
             {"kind", ev.kind},
             {"detail", ev.detail},
         }},
    };
    emit_json(doc);
}

int present_json_overview(const application::DaemonStatusReport& daemon,
                          const std::vector<OverviewProfileRow>& rows,
                          std::chrono::nanoseconds duration,
                          bool full) {
    auto doc = make_envelope("status", {}, true, 0, duration);
    json profiles = json::array();
    for (const auto& row : rows) {
        const application::ProfileExecutionSummary* chosen =
            row.activity.last_complete_sync ? &*row.activity.last_complete_sync
                                            : (row.activity.last_attempt
                                                   ? &*row.activity.last_attempt
                                                   : nullptr);
        std::string last_machine =
            chosen ? chosen->machine_name
                   : (row.activity.accepted_commit
                          ? row.activity.accepted_commit->machine_name
                          : std::string{});
        std::optional<std::int64_t> last_sync_at;
        if (chosen) {
            last_sync_at = chosen->finished_at.value_or(chosen->started_at);
        } else if (row.activity.accepted_commit) {
            last_sync_at = row.activity.accepted_commit->accepted_at;
        }
        json entry{
            {"name", row.profile.name},
            {"local_state", profile_local_state_name(row.local_state)},
            {"paused", row.profile.paused},
            {"conflicts", row.conflict_count},
            {"daemon_state",
             row.daemon_profile
                 ? json(application::to_string(row.daemon_profile->state))
                 : json(nullptr)},
            {"active_stage",
             row.daemon_profile ? json(row.daemon_profile->active_stage)
                                : json(nullptr)},
            {"dirty_paths_count",
             row.daemon_profile ? row.daemon_profile->dirty_paths_count
                                : std::size_t{0}},
            {"last_sync_at",
             last_sync_at ? json(*last_sync_at) : json(nullptr)},
            {"last_sync_status",
             chosen ? json(profile_status_name(chosen->status))
                    : json(nullptr)},
            {"last_sync_machine",
             last_machine.empty() ? json(nullptr) : json(last_machine)},
            {"last_error",
             row.daemon_profile && !row.daemon_profile->last_error.empty()
                 ? json(row.daemon_profile->last_error)
                 : json(nullptr)},
        };
        if (full) {
            entry["local_dir"] =
                platform::path::to_utf8(row.profile.local_dir);
            entry["remote_dir"] = row.profile.remote_dir;
            entry["watch_enabled"] = row.profile.watch_enabled.value_or(true);
            entry["sync_interval_seconds"] =
                row.profile.sync_interval_seconds.value_or(300U);
            entry["gc_interval_hours"] =
                row.profile.gc_interval_hours.value_or(0U);
            if (row.daemon_profile) {
                entry["sync_runs"] = row.daemon_profile->sync_runs;
                entry["fast_noop_polls"] = row.daemon_profile->fast_noop_polls;
                entry["warm_transport_active"] =
                    row.daemon_profile->warm_transport_active;
            }
        }
        profiles.push_back(std::move(entry));
    }
    json daemon_json{
        {"running", daemon.running},
        {"uptime_seconds", daemon.uptime_seconds},
        {"autostart_supported", daemon.autostart.supported},
        {"autostart_installed", daemon.autostart.installed},
    };
    if (full) {
        daemon_json["pid"] = daemon.pid;
        daemon_json["ipc_port"] = daemon.ipc_port;
        daemon_json["kasumi_version"] = daemon.kasumi_version;
        daemon_json["api_version"] = daemon.api_version;
    }
    doc["data"] = json{
        {"summary",
         std::format("running={}, profiles={}",
                     daemon.running ? "yes" : "no",
                     rows.size())},
        {"daemon", std::move(daemon_json)},
        {"profiles", std::move(profiles)},
    };
    emit_json(doc);
    return 0;
}

void append_json_daemon_event(const std::filesystem::path& path,
                              const application::DaemonEvent& event) {
    auto doc =
        make_envelope("daemon run", event.profile_name, true, 0, std::nullopt);
    doc["event"] = json{
        {"seq", event.seq},
        {"timestamp_unix", event.timestamp_unix},
        {"profile", event.profile_name},
        {"kind", event.kind},
        {"detail", event.detail},
    };
    (void)append_log_line(
        path, doc.dump(-1, ' ', false, json::error_handler_t::replace));
}

int present_json_daemon_error(std::string_view command,
                              std::string_view profile_name,
                              const application::DaemonError& error,
                              std::chrono::nanoseconds duration) {
    return emit_json_error(command,
                           profile_name,
                           1,
                           json_error_code(error.code),
                           error.detail,
                           duration);
}

} // namespace kasumi::cli
