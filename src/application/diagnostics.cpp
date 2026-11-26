#include "application/daemon.hpp"
#include "application/detail.hpp"
#include "application/profile.hpp"
#include "core/ignore.hpp"
#include "platform/path.hpp"
#include "platform/profile_lock.hpp"
#include "runtime/paths.hpp"
#include "runtime/profile.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace kasumi::application {
namespace {

std::string host_os_name() {
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#elif defined(__linux__)
    return "linux";
#else
    return "unknown";
#endif
}

bool is_rclone_location(std::string_view location) noexcept {
    if (location.empty()) {
        return false;
    }
    const bool windows_drive =
        location.size() >= 3 &&
        std::isalpha(static_cast<unsigned char>(location[0])) != 0 &&
        location[1] == ':' && (location[2] == '/' || location[2] == '\\');
    if (windows_drive || location.starts_with("\\\\") ||
        location.find(':') == std::string_view::npos) {
        return false;
    }
    return true;
}

bool check_directory_writable(const std::filesystem::path& dir) noexcept {
#if defined(_WIN32)
    const HANDLE handle =
        CreateFileW(dir.c_str(),
                    FILE_ADD_FILE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    CloseHandle(handle);
    return true;
#else
    return ::access(dir.c_str(), W_OK | X_OK) == 0;
#endif
}

std::optional<std::filesystem::space_info>
safe_space_info(const std::filesystem::path& path) noexcept {
    if (path.empty()) {
        return std::nullopt;
    }
    std::error_code error;
    const auto status = std::filesystem::symlink_status(path, error);
    if (error || status.type() == std::filesystem::file_type::not_found) {
        return std::nullopt;
    }
    const auto info = std::filesystem::space(path, error);
    if (error) {
        return std::nullopt;
    }
    return info;
}

std::optional<std::uint64_t> to_space_u64(std::uintmax_t value) noexcept {
    if (value == static_cast<std::uintmax_t>(-1)) {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(value);
}

void append_reason(std::string& detail, std::string_view reason) {
    if (reason.empty()) {
        return;
    }
    if (!detail.empty()) {
        detail += "; ";
    }
    detail.append(reason);
}

} // namespace

std::expected<DiagnosticsReport, ProfileError>
collect_diagnostics(const ExecutionEnvironment& environment,
                    std::string_view profile_name,
                    const DaemonStatusReport* live) {
    if (!profile_name.empty() &&
        !runtime::is_valid_profile_name(profile_name)) {
        return std::unexpected(ProfileError{
            .code = ProfileErrorCode::InvalidName,
            .detail = "invalid profile name",
        });
    }

    auto profiles = list_profiles(environment);
    if (!profiles) {
        return std::unexpected(profiles.error());
    }

    std::vector<Profile> selected;
    if (!profile_name.empty()) {
        const auto it =
            std::ranges::find(*profiles, profile_name, &Profile::name);
        if (it == profiles->end()) {
            return std::unexpected(ProfileError{
                .code = ProfileErrorCode::NotFound,
                .detail = "profile not found",
            });
        }
        selected.push_back(*it);
    } else {
        selected = std::move(*profiles);
    }

    DiagnosticsReport report;
    report.os_name = host_os_name();
    report.app_data_dir = environment.app_data_dir;
    report.config_path = environment.app_data_dir / "config.toml";
    {
        std::error_code error;
        const auto status =
            std::filesystem::symlink_status(report.config_path, error);
        report.config_exists =
            !error && std::filesystem::is_regular_file(status);
    }
    if (const auto space = safe_space_info(report.app_data_dir)) {
        report.app_data_free_bytes = to_space_u64(space->available);
    } else if (const auto parent_space =
                   safe_space_info(report.app_data_dir.parent_path())) {
        report.app_data_free_bytes = to_space_u64(parent_space->available);
    }

    const auto probed_rclone = transport::probe_rclone_installation();
    report.rclone = DiagnosticsRcloneInfo{
        .found = probed_rclone.found,
        .executable = probed_rclone.executable,
        .version = probed_rclone.version ? probed_rclone.version->raw : "",
        .minimum_version = std::format("v{}.{}.{}",
                                       transport::minimum_rclone_major,
                                       transport::minimum_rclone_minor,
                                       transport::minimum_rclone_patch),
        .meets_minimum = probed_rclone.meets_minimum,
        .detail = probed_rclone.detail,
    };

    const bool daemon_lock_held = live || is_daemon_running(environment);
    report.daemon.running = daemon_lock_held;
    std::optional<DaemonStatusReport> daemon_status;
    if (daemon_lock_held) {
        if (auto st =
                live ? std::expected<DaemonStatusReport, DaemonError>(*live)
                     : query_daemon_status(environment);
            st && st->running) {
            daemon_status = std::move(*st);
            report.daemon.pid = daemon_status->pid;
            report.daemon.ipc_port = daemon_status->ipc_port;
            report.daemon.control_metadata_valid = true;
            report.daemon.secure_pages_locked =
                daemon_status->secure_pages_locked;
            report.daemon.autostart_supported =
                daemon_status->autostart.supported;
            report.daemon.autostart_installed =
                daemon_status->autostart.installed;
            report.daemon.autostart_method = daemon_status->autostart.method;
            report.daemon.detail = std::format("running (PID {}, port {})",
                                               report.daemon.pid,
                                               report.daemon.ipc_port);
        } else {
            report.daemon.control_metadata_valid = false;
            report.daemon.detail =
                st ? "daemon offline during query" : st.error().detail;
            report.overall_ok = false;
        }
    } else {
        if (const auto as = query_daemon_autostart(); as) {
            report.daemon.autostart_supported = as->supported;
            report.daemon.autostart_installed = as->installed;
            report.daemon.autostart_method = as->method;
        }
        report.daemon.detail = "not running";
    }

    report.profiles.reserve(selected.size());
    for (const auto& profile : selected) {
        ProfileDiagnostic diag;
        diag.profile = profile;
        diag.uses_rclone = is_rclone_location(profile.remote_dir);
        diag.local_state = inspect_profile_local_state(
            environment, profile.name, &diag.local_problem);
        diag.activity = inspect_profile_activity(environment, profile.name);

        std::error_code error;
        const auto local_status =
            std::filesystem::symlink_status(profile.local_dir, error);
        diag.local_dir_exists = !error &&
                                !std::filesystem::is_symlink(local_status) &&
                                std::filesystem::is_directory(local_status);
        if (diag.local_dir_exists) {
            diag.local_dir_writable =
                check_directory_writable(profile.local_dir);
            if (const auto space = safe_space_info(profile.local_dir)) {
                diag.local_free_bytes = to_space_u64(space->available);
                diag.local_capacity_bytes = to_space_u64(space->capacity);
            }
            const auto ignore_path = profile.local_dir / ".kasumiignore";
            std::error_code ignore_ec;
            const auto ignore_status =
                std::filesystem::symlink_status(ignore_path, ignore_ec);
            diag.ignore_file_present =
                !ignore_ec &&
                ignore_status.type() != std::filesystem::file_type::not_found;
            const auto ignore_list = ignore::load_ignore_list(ignore_path);
            if (ignore_list.parse_error) {
                diag.ignore_file_valid = false;
                diag.ignore_error_line = ignore_list.parse_error->line;
                diag.ignore_error_detail = ignore_list.parse_error->detail;
            }
        }

        const auto lock_path =
            environment.app_data_dir / ("profile-" + profile.name + ".lock");
        diag.lock_active = (diag.local_state == ProfileLocalState::Running) ||
                           platform::is_profile_lock_held(lock_path);

        const auto profile_paths = runtime::resolve_profile_paths(
            environment.app_data_dir, profile.name);
        if (profile_paths) {
            std::error_code journal_error;
            const auto journal_status = std::filesystem::symlink_status(
                profile_paths->profile_dir / "transaction.bin.enc",
                journal_error);
            diag.journal_present =
                diag.local_problem == ProfileLocalProblem::Journal ||
                (!journal_error && journal_status.type() !=
                                       std::filesystem::file_type::not_found);
        } else {
            diag.journal_present =
                diag.local_problem == ProfileLocalProblem::Journal;
        }

        diag.key_accessible =
            profile.key_storage == KeyStorage::Memory ||
            (diag.local_problem != ProfileLocalProblem::Key &&
             diag.local_problem != ProfileLocalProblem::Directory &&
             diag.local_problem != ProfileLocalProblem::Paths);

        std::string issues;
        if (!diag.local_dir_exists) {
            append_reason(issues, "local directory missing or invalid");
        } else if (!diag.local_dir_writable) {
            append_reason(issues, "local directory not writable");
        }
        if (diag.local_problem == ProfileLocalProblem::Lock) {
            append_reason(
                issues,
                "local profile lock is invalid or cannot be safely inspected");
        }
        if (diag.journal_present && !diag.lock_active) {
            append_reason(issues, "pending local transaction journal");
        }
        if (!diag.key_accessible) {
            append_reason(issues, "profile cryptographic key is unavailable");
        }
        if (diag.local_state == ProfileLocalState::Pending) {
            append_reason(issues, "pending materializations");
        } else if (diag.local_state == ProfileLocalState::Problem &&
                   issues.empty()) {
            append_reason(issues, "local profile state problem");
        }
        if (diag.uses_rclone &&
            (!report.rclone.found || !report.rclone.meets_minimum)) {
            append_reason(issues,
                          report.rclone.detail.empty()
                              ? "rclone toolchain unavailable"
                              : report.rclone.detail);
        }
        if (!diag.ignore_file_valid) {
            append_reason(
                issues,
                diag.ignore_error_line && *diag.ignore_error_line > 0
                    ? std::format(".kasumiignore invalid on line {}: {}",
                                  *diag.ignore_error_line,
                                  diag.ignore_error_detail)
                    : std::format(".kasumiignore invalid: {}",
                                  diag.ignore_error_detail));
        }

        if (daemon_status) {
            for (const auto& dp : daemon_status->profiles) {
                if (dp.name == profile.name) {
                    diag.daemon_state = std::string{to_string(dp.state)};
                    diag.daemon_active_stage = dp.active_stage;
                    diag.daemon_watcher_active = dp.watcher_active;
                    diag.daemon_error = dp.last_error;
                    if (dp.state == DaemonProfileState::NeedsAttention) {
                        append_reason(
                            issues,
                            dp.last_error.empty()
                                ? "daemon marked profile as needs_attention"
                                : "daemon needs attention: " + dp.last_error);
                    }
                    break;
                }
            }
        }

        diag.healthy = issues.empty() &&
                       (diag.local_state == ProfileLocalState::Ready ||
                        diag.local_state == ProfileLocalState::Initialized ||
                        diag.local_state == ProfileLocalState::Running);
        if (diag.healthy) {
            if (diag.local_state == ProfileLocalState::Running) {
                if (diag.daemon_state &&
                    (*diag.daemon_state == "running_sync" ||
                     *diag.daemon_state == "running_gc")) {
                    diag.detail = diag.daemon_active_stage.empty()
                                      ? std::format("running (daemon: {})",
                                                    *diag.daemon_state)
                                      : std::format("running (daemon: {} - {})",
                                                    *diag.daemon_state,
                                                    diag.daemon_active_stage);
                } else {
                    const auto active_op =
                        active_profile_operation(diag.activity);
                    diag.detail = active_op
                                      ? std::format("running ({})", *active_op)
                                      : "running";
                }
            } else {
                diag.detail = "ok";
            }
        } else {
            diag.detail = std::move(issues);
        }
        report.overall_ok = report.overall_ok && diag.healthy;
        report.profiles.push_back(std::move(diag));
    }

    return report;
}

RcloneRemotesInfo discover_rclone_remotes(
    const std::filesystem::path& forbidden_executable_root) {
    const auto result =
        transport::list_rclone_remotes(forbidden_executable_root);
    return RcloneRemotesInfo{
        .available = result.available,
        .remotes = result.remotes,
        .detail = result.detail,
    };
}

} // namespace kasumi::application
