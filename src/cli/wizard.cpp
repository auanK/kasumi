#include "cli/wizard.hpp"

#include "application/daemon.hpp"
#include "application/profile.hpp"
#include "cli/credentials.hpp"
#include "cli/i18n.hpp"
#include "cli/json_presenter.hpp"
#include "cli/presenter.hpp"
#include "platform/cancellation.hpp"
#include "platform/clock.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <iostream>
#include <map>
#include <optional>
#include <print>
#include <set>
#include <string>
#include <variant>

#if !defined(_WIN32)
#include <cerrno>
#include <poll.h>
#include <unistd.h>
#endif

namespace kasumi::cli {
namespace {

#if !defined(_WIN32)
const std::streambuf* const default_cin_buffer = std::cin.rdbuf();

bool read_tty_line(std::string& value) {
    value.clear();
    while (!platform::cancellation::requested()) {
        pollfd input{.fd = STDIN_FILENO, .events = POLLIN, .revents = 0};
        const auto ready = ::poll(&input, 1, 50);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            platform::cancellation::request();
            return false;
        }
        if (ready == 0) {
            continue;
        }
        if ((input.revents & (POLLERR | POLLNVAL)) != 0) {
            platform::cancellation::request();
            return false;
        }
        char ch = '\0';
        const auto count = ::read(STDIN_FILENO, &ch, 1);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            platform::cancellation::request();
            return false;
        }
        if (count == 0) {
            if (value.empty()) {
                platform::cancellation::request();
                return false;
            }
            if (!value.empty() && value.back() == '\r') {
                value.pop_back();
            }
            return !platform::cancellation::requested();
        }
        if (ch == '\n') {
            if (!value.empty() && value.back() == '\r') {
                value.pop_back();
            }
            return !platform::cancellation::requested();
        }
        value.push_back(ch);
    }
    return false;
}
#endif

std::string_view profile_operation_label(application::ProfileOperationKind op) {
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
        default:
            return i18n::tr(i18n::Key::LabelUnknown);
    }
}

std::string
format_execution_metrics(const application::ProfileExecutionSummary& e) {
    using K = application::ProfileOperationKind;
    switch (e.operation) {
        case K::Sync: {
            std::string parts;
            const auto add = [&](std::string part) {
                if (!parts.empty()) {
                    parts += ", ";
                }
                parts += std::move(part);
            };
            if (e.summary_a > 0) {
                add(i18n::format(i18n::Key::LabelMetricSyncUploaded,
                                 e.summary_a));
            }
            if (e.summary_b > 0) {
                add(i18n::format(i18n::Key::LabelMetricSyncDownloaded,
                                 e.summary_b));
            }
            if (e.summary_c > 0) {
                add(i18n::format(i18n::Key::LabelMetricSyncRemoved,
                                 e.summary_c));
            }
            return parts;
        }
        case K::Fsck:
            if (e.summary_a > 0 || e.summary_bytes > 0) {
                return format_activity_metrics(
                    static_cast<std::uint8_t>(
                        application::RemoteActivityOperation::Fsck),
                    e.summary_a,
                    e.summary_b,
                    e.summary_bytes,
                    e.flags);
            }
            return {};
        case K::GarbageCollect:
            if (e.summary_a > 0 || e.summary_b > 0 ||
                (e.flags & application::remote_activity_flag_analysis_only) !=
                    0U) {
                return format_activity_metrics(
                    static_cast<std::uint8_t>(
                        application::RemoteActivityOperation::GarbageCollect),
                    e.summary_a,
                    e.summary_b,
                    e.summary_bytes,
                    e.flags);
            }
            return {};
        case K::Repack:
            if (e.summary_a > 0 || e.summary_b > 0) {
                return i18n::format(i18n::Key::LabelMetricRepack,
                                    e.summary_a,
                                    e.summary_b,
                                    format_size(e.summary_bytes));
            }
            return {};
        case K::ResolveMissing:
            if (e.summary_a > 0) {
                return i18n::format(i18n::Key::LabelMetricResolveMissing,
                                    e.summary_a);
            }
            return {};
        default:
            return {};
    }
}

std::string
format_execution_extra(const application::ProfileExecutionSummary& e,
                       bool include_stage) {
    std::string extra = format_execution_metrics(e);
    const auto append = [&](std::string_view part) {
        if (part.empty()) {
            return;
        }
        if (!extra.empty()) {
            extra += ", ";
        }
        extra += part;
    };
    if ((e.flags & application::profile_execution_flag_origin_daemon) != 0U) {
        append(i18n::tr(i18n::Key::LabelFlagOriginDaemon));
    }
    if (e.recovered) {
        append(i18n::tr(i18n::Key::LabelFlagRecovered));
    }
    if ((e.flags &
         application::profile_execution_flag_audit_failed_after_sync) != 0U) {
        append(i18n::tr(i18n::Key::LabelFlagAuditFailedAfterSync));
    }
    if (e.remote_publish_state ==
        application::ProfileRemotePublishState::Pending) {
        append(i18n::tr(i18n::Key::LabelFlagRemotePublishPending));
    }
    if (e.operation == application::ProfileOperationKind::Fsck ||
        e.operation == application::ProfileOperationKind::GarbageCollect ||
        e.operation == application::ProfileOperationKind::RemoveWriter ||
        e.operation == application::ProfileOperationKind::RemoveBarrier) {
        append(format_activity_flags(e.flags));
    }
    if (include_stage && !e.stage.empty()) {
        append(sanitize_terminal_text(e.stage));
    }
    return extra;
}

std::string
format_local_state_label(application::ProfileLocalState state,
                         const application::ProfileActivityReport& activity) {
    if (state == application::ProfileLocalState::Running) {
        if (const auto op = application::active_profile_operation(activity)) {
            return std::format("Running ({})", *op);
        }
    }
    return std::string{application::to_string(state)};
}

std::string
format_config_last_sync(const application::ProfileActivityReport& activity) {
    if (!activity.database_present) {
        return "-";
    }
    const application::ProfileExecutionSummary* chosen = nullptr;
    if (activity.last_attempt &&
        activity.last_attempt->operation ==
            application::ProfileOperationKind::Sync &&
        (!activity.last_complete_sync ||
         activity.last_attempt->started_at >
             activity.last_complete_sync->started_at)) {
        chosen = &*activity.last_attempt;
    } else if (activity.last_complete_sync) {
        chosen = &*activity.last_complete_sync;
    }
    if (chosen == nullptr) {
        return "-";
    }
    const auto ts = platform::clock::format_local_timestamp(
        chosen->finished_at.value_or(chosen->started_at), false);
    return std::format("{} ({})", ts, execution_status_label(chosen->status));
}

std::string format_compact_automation(const application::Profile& profile) {
    const bool watch_on = profile.watch_enabled.value_or(true);
    const std::string_view watch_str =
        watch_on ? i18n::tr(i18n::Key::LabelYes)
                 : i18n::tr(i18n::Key::LabelNo);
    const std::uint32_t sync_sec = profile.sync_interval_seconds.value_or(300U);
    std::string sync_str;
    if (sync_sec == 0U) {
        sync_str = std::string{i18n::tr(i18n::Key::LabelDisabled)};
    } else if (sync_sec % 60U == 0U) {
        sync_str = std::format("{}m", sync_sec / 60U);
    } else {
        sync_str = std::format("{}s", sync_sec);
    }
    std::string line =
        i18n::format(i18n::Key::WizardShowAutomationLine, watch_str, sync_str);
    if (profile.paused) {
        line += " [";
        line += i18n::tr(i18n::Key::OverviewBadgePaused);
        line += "]";
    }
    return line;
}

void present_profile_activity(std::string_view profile_name,
                              const application::ProfileActivityReport& report,
                              bool full) {
    if (report.accepted_commit) {
        const auto& c = *report.accepted_commit;
        const std::string_view cid =
            (!full && c.commit_id.size() > 16)
                ? std::string_view{c.commit_id}.substr(0, 16)
                : std::string_view{c.commit_id};
        i18n::println(
            i18n::Key::WizardShowAcceptedCommit,
            sanitize_terminal_text(cid),
            c.height,
            platform::clock::format_local_timestamp(c.created_at),
            commit_origin_label(c.origin_operation),
            format_machine_label(c.machine_name, c.machine_id_hex, full, full),
            platform::clock::format_local_timestamp(c.accepted_at));
    } else {
        i18n::println(i18n::Key::WizardShowNoAcceptedCommit);
    }

    if (report.last_complete_sync) {
        const auto& s = *report.last_complete_sync;
        const auto ts = platform::clock::format_local_timestamp(
            s.finished_at.value_or(s.started_at));
        const auto status = execution_status_label(s.status);
        const auto machine =
            format_machine_label(s.machine_name, s.machine_id_hex, full, full);
        i18n::println(
            i18n::Key::WizardShowLastCompleteSync, ts, status, machine);
    } else {
        i18n::println(i18n::Key::WizardShowNoCompleteSync);
    }

    if (report.last_attempt) {
        const auto& a = *report.last_attempt;
        const auto ts = platform::clock::format_local_timestamp(
            a.finished_at.value_or(a.started_at));
        std::string status{execution_status_label(a.status)};
        if (a.recovered) {
            status +=
                std::format(" ({})", i18n::tr(i18n::Key::LabelFlagRecovered));
        }
        i18n::println(
            i18n::Key::WizardShowLastAttempt,
            profile_operation_label(a.operation),
            ts,
            status,
            format_machine_label(a.machine_name, a.machine_id_hex, full, full));
        const bool is_ok =
            a.status == application::ProfileExecutionStatus::Succeeded ||
            a.status ==
                application::ProfileExecutionStatus::SucceededNoChanges ||
            a.status ==
                application::ProfileExecutionStatus::SucceededDownloadedOnly;
        if (!a.stage.empty() && (!is_ok || full)) {
            i18n::println(i18n::Key::WizardShowAttemptStage,
                          sanitize_terminal_text(a.stage));
        }
        if (!a.detail.empty() && (!is_ok || full)) {
            i18n::println(i18n::Key::WizardShowAttemptDetail,
                          sanitize_terminal_text(a.detail));
        }
        if ((a.flags &
             application::profile_execution_flag_audit_failed_after_sync) !=
            0U) {
            i18n::println(i18n::Key::WizardShowAttemptAuditWarning);
        }
        if (a.remote_publish_state ==
            application::ProfileRemotePublishState::Pending) {
            i18n::println(i18n::Key::WizardShowAttemptPendingPublish);
        }
    } else {
        i18n::println(i18n::Key::WizardShowNoAttempts);
    }

    if (!report.recent_executions.empty()) {
        std::vector<const application::ProfileExecutionSummary*> sorted;
        sorted.reserve(report.recent_executions.size());
        for (const auto& item : report.recent_executions) {
            sorted.push_back(&item);
        }
        std::ranges::sort(sorted, [](const auto* a, const auto* b) {
            const auto ta = a->finished_at.value_or(a->started_at);
            const auto tb = b->finished_at.value_or(b->started_at);
            if (ta != tb) {
                return ta > tb;
            }
            return a->started_at > b->started_at;
        });

        if (full) {
            i18n::println(i18n::Key::WizardShowRecentExecutionsHeader,
                          sorted.size());
            for (const auto* item : sorted) {
                const auto ts = platform::clock::format_local_timestamp(
                    item->finished_at.value_or(item->started_at));
                const auto op = profile_operation_label(item->operation);
                const auto status = execution_status_label(item->status);
                const auto dur = format_duration(
                    std::chrono::milliseconds(item->duration_ms));
                const auto machine = format_machine_label(
                    item->machine_name, item->machine_id_hex, true, true);
                const auto extra = format_execution_extra(*item, false);
                if (extra.empty()) {
                    std::println("  {} | {:<17} | {} | {} | {}",
                                 ts,
                                 op,
                                 status,
                                 dur,
                                 machine);
                } else {
                    std::println("  {} | {:<17} | {} | {} | {} ({})",
                                 ts,
                                 op,
                                 status,
                                 dur,
                                 machine,
                                 extra);
                }
                if (!item->stage.empty() || !item->detail.empty()) {
                    std::string note;
                    if (!item->stage.empty()) {
                        note = sanitize_terminal_text(item->stage);
                    }
                    if (!item->detail.empty()) {
                        if (!note.empty()) {
                            note += ": ";
                        }
                        note += sanitize_terminal_text(item->detail);
                    }
                    std::println("    {}", note);
                }
            }
        } else {
            std::set<application::ProfileOperationKind> seen_ops;
            std::vector<const application::ProfileExecutionSummary*> maint;
            for (const auto* item : sorted) {
                if (item->operation !=
                        application::ProfileOperationKind::Sync &&
                    seen_ops.insert(item->operation).second) {
                    maint.push_back(item);
                }
            }
            if (!maint.empty()) {
                i18n::println(i18n::Key::WizardShowLocalMaintenanceHeader);
                for (const auto* item : maint) {
                    const auto ts = platform::clock::format_local_timestamp(
                        item->finished_at.value_or(item->started_at));
                    const auto op = profile_operation_label(item->operation);
                    const auto status = execution_status_label(item->status);
                    const auto extra = format_execution_extra(*item, true);
                    if (extra.empty()) {
                        std::println("  {:<17} {} | {}", op, ts, status);
                    } else {
                        std::println(
                            "  {:<17} {} | {} ({})", op, ts, status, extra);
                    }
                }
            }
            if (sorted.size() > 1) {
                i18n::println(i18n::Key::WizardShowExecutionsMoreHint,
                              sorted.size(),
                              profile_name);
            }
        }
    }

    if (!report.cached_remote_activities.empty()) {
        i18n::println(i18n::Key::WizardShowCachedRemoteHeader, profile_name);
        std::vector<const application::ProfileCachedRemoteActivity*> sorted;
        sorted.reserve(report.cached_remote_activities.size());
        for (const auto& item : report.cached_remote_activities) {
            sorted.push_back(&item);
        }
        std::ranges::sort(sorted, [](const auto* a, const auto* b) {
            if (a->finished_at != b->finished_at) {
                return a->finished_at > b->finished_at;
            }
            return a->started_at > b->started_at;
        });

        std::map<std::string, std::set<std::string>> ids_by_name;
        for (const auto* item : sorted) {
            if (!item->machine_name.empty() && !item->machine_id_hex.empty()) {
                ids_by_name[item->machine_name].insert(item->machine_id_hex);
            }
        }

        std::vector<const application::ProfileCachedRemoteActivity*> shown;
        if (full) {
            shown = sorted;
        } else {
            std::set<std::uint8_t> seen_ops;
            for (const auto* item : sorted) {
                if (seen_ops.insert(item->operation).second) {
                    shown.push_back(item);
                }
            }
        }
        for (const auto* item : shown) {
            const auto ts =
                platform::clock::format_local_timestamp(item->finished_at);
            const auto op = activity_operation_label(item->operation);
            const auto outcome = activity_outcome_label(item->outcome);
            const bool collide = ids_by_name.contains(item->machine_name) &&
                                 ids_by_name.at(item->machine_name).size() > 1;
            const auto machine = format_machine_label(item->machine_name,
                                                      item->machine_id_hex,
                                                      full || collide,
                                                      full);
            const auto metrics = format_activity_metrics(item->operation,
                                                         item->metric_primary,
                                                         item->metric_secondary,
                                                         item->metric_bytes,
                                                         item->flags);
            const auto flags = format_activity_flags(item->flags);
            std::string extra;
            if (!metrics.empty()) {
                extra += metrics;
            }
            if (!flags.empty()) {
                if (!extra.empty()) {
                    extra += ", ";
                }
                extra += flags;
            }
            if (full) {
                const auto dur = format_duration(
                    std::chrono::milliseconds(item->duration_ms));
                const auto cached_note = i18n::format(
                    i18n::Key::WizardShowCachedAt,
                    platform::clock::format_local_timestamp(item->cached_at));
                if (!extra.empty()) {
                    extra += ", ";
                }
                extra += cached_note;
                std::println("  {} | {:<17} | {} | {} | {} ({})",
                             ts,
                             op,
                             outcome,
                             dur,
                             machine,
                             extra);
                if (!item->stage.empty() || !item->detail.empty()) {
                    std::string note;
                    if (!item->stage.empty()) {
                        note = sanitize_terminal_text(item->stage);
                    }
                    if (!item->detail.empty()) {
                        if (!note.empty()) {
                            note += ": ";
                        }
                        note += sanitize_terminal_text(item->detail);
                    }
                    std::println("    {}", note);
                }
            } else {
                if (extra.empty()) {
                    std::println(
                        "  {:<17} {} | {} | {}", op, ts, outcome, machine);
                } else {
                    std::println("  {:<17} {} | {} | {} ({})",
                                 op,
                                 ts,
                                 outcome,
                                 machine,
                                 extra);
                }
            }
        }
        if (!full && sorted.size() > shown.size()) {
            i18n::println(i18n::Key::WizardShowCachedRemoteMoreHint,
                          sorted.size());
        }
    }
}

bool prompt_line(std::string_view label, std::string& value) {
    std::print("{}", label);
    std::fflush(stdout);
    if (platform::cancellation::requested()) {
        return false;
    }
#if !defined(_WIN32)
    if (std::cin.rdbuf() == default_cin_buffer && ::isatty(STDIN_FILENO) != 0) {
        return read_tty_line(value);
    }
#endif
    if (!std::getline(std::cin, value)) {
        platform::cancellation::request();
        return false;
    }
    return !platform::cancellation::requested();
}

bool confirm_change(std::string_view message) {
    std::string confirmation;
    if (!prompt_line(message, confirmation)) {
        return false;
    }
    std::ranges::transform(
        confirmation, confirmation.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
    return confirmation == "y" || confirmation == "yes" ||
           confirmation == "s" || confirmation == "sim";
}

int apply_profile_key_update(
    const application::ExecutionEnvironment& environment,
    std::string_view profile_name,
    application::ProfileCredentials& creds,
    bool print_decline_error) {
    struct CredentialsGuard {
        application::ProfileCredentials& value;
        ~CredentialsGuard() noexcept {
            application::wipe_credentials(value);
        }
    } guard{creds};

    application::ProfileCredentials attempt = creds;
    auto res = application::set_profile_key(
        environment, profile_name, std::move(attempt), false);
    application::wipe_credentials(attempt);
    if (!res &&
        res.error().code == application::ProfileErrorCode::AlreadyExists) {
        if (!confirm_change(i18n::format(i18n::Key::WizardConfirmReplaceKey,
                                         profile_name))) {
            if (platform::cancellation::requested()) {
                return 130;
            }
            if (print_decline_error) {
                print_error_line(
                    i18n::tr(i18n::Key::WizardKeyReplaceCancelled));
            }
            return 1;
        }
        res = application::set_profile_key(
            environment, profile_name, std::move(creds), true);
    }
    if (!res) {
        print_error_line(res.error().detail);
        return 1;
    }
    print_ok_line(
        i18n::format(i18n::Key::WizardProfileKeyUpdated, profile_name));
    return 0;
}

application::RcloneRemotesInfo
show_rclone_discovery_hint(const std::filesystem::path& local_dir) {
    auto info = application::discover_rclone_remotes(local_dir);
    if (info.available && !info.remotes.empty()) {
        std::string joined;
        for (std::size_t i = 0; i < info.remotes.size(); ++i) {
            if (i > 0) {
                joined += ", ";
            }
            joined += info.remotes[i];
            joined.push_back(':');
        }
        i18n::println(i18n::Key::WizardRcloneRemotesHint,
                      sanitize_terminal_text(joined));
    }
    return info;
}

void warn_if_unknown_rclone_remote(std::string_view destination,
                                   const application::RcloneRemotesInfo& info) {
    if (!info.available || destination.empty() ||
        destination.starts_with("\\\\")) {
        return;
    }
    const bool windows_drive =
        destination.size() >= 3U &&
        std::isalpha(static_cast<unsigned char>(destination[0])) != 0 &&
        destination[1] == ':' &&
        (destination[2] == '/' || destination[2] == '\\');
    if (windows_drive) {
        return;
    }
    const auto colon = destination.find(':');
    if (colon == std::string_view::npos || colon == 0U) {
        return;
    }
    const auto remote_name = destination.substr(0U, colon);
    if (std::ranges::find(info.remotes, remote_name) == info.remotes.end()) {
        print_warning_line(i18n::format(i18n::Key::WizardRcloneRemoteUnknown,
                                        sanitize_terminal_text(remote_name)));
    }
}

std::optional<application::ProfileCredentials> read_profile_env_credentials() {
    if (const char* hex = std::getenv("KASUMI_MASTER_KEY");
        hex != nullptr && hex[0] != '\0') {
        return application::ProfileCredentials{
            application::MasterKeyHex{std::string(hex)}};
    }
    const char* pw = std::getenv("KASUMI_PASSWORD");
    const char* salt = std::getenv("KASUMI_PASSWORD2");
    if (pw != nullptr && salt != nullptr) {
        return application::ProfileCredentials{
            application::PasswordPair{std::string(pw), std::string(salt)}};
    }
    return std::nullopt;
}

application::Credentials
to_runtime_credentials(const application::ProfileCredentials& creds) {
    return std::visit(
        [](const auto& value) -> application::Credentials {
            return application::Credentials{value};
        },
        creds);
}

struct ProfileCredsWipeGuard {
    application::ProfileCredentials& value;
    ~ProfileCredsWipeGuard() noexcept {
        application::wipe_credentials(value);
    }
};

struct CredsWipeGuard {
    application::Credentials& value;
    ~CredsWipeGuard() noexcept {
        application::wipe_credentials(value);
    }
};

} // namespace

int run_profile_command(const application::ExecutionEnvironment& environment,
                        const ProfileInvocation& invocation,
                        bool quiet,
                        bool json,
                        std::string* log_summary) {
    const auto started = std::chrono::steady_clock::now();
    const auto elapsed = [&] {
        return std::chrono::steady_clock::now() - started;
    };

    auto command_name = [&]() -> std::string_view {
        switch (invocation.action) {
            case ProfileAction::Create:
                return "profile create";
            case ProfileAction::Edit:
                return "profile edit";
            case ProfileAction::Clone:
                return "profile clone";
            case ProfileAction::Storage:
                return "profile storage";
            case ProfileAction::Rename:
                return "profile rename";
            case ProfileAction::Delete:
                return "profile delete";
            case ProfileAction::Test:
                return "profile test";
        }
        return "profile";
    };
    const std::string_view cmd = command_name();

    const auto fail_error = [&](const application::ProfileError& err) -> int {
        if (log_summary != nullptr) {
            *log_summary =
                std::format("[{}] {}", json_error_code(err.code), err.detail);
        }
        if (json) {
            return present_json_profile_error(
                cmd, invocation.profile_name, err, elapsed());
        }
        print_error_line(err.detail);
        return 1;
    };

    const auto finish_success = [&](const application::Profile* profile,
                                    std::string_view target_name,
                                    std::string_view message,
                                    std::string_view summary,
                                    bool needs_key = false) -> int {
        if (log_summary != nullptr) {
            *log_summary = std::string{summary};
        }
        if (json) {
            return present_json_profile_action(
                cmd, profile, target_name, summary, needs_key, elapsed());
        }
        if (!quiet) {
            print_ok_line(message);
        }
        return 0;
    };

    switch (invocation.action) {
        case ProfileAction::Create: {
            const auto env_creds = read_profile_env_credentials();
            if (!env_creds.has_value() && json) {
                const auto msg =
                    i18n::tr(i18n::Key::WizardProfileCredentialsRequired);
                if (log_summary != nullptr) {
                    *log_summary =
                        std::format("[credentials_required] {}", msg);
                }
                return present_json_credentials_required(
                    cmd, invocation.profile_name, msg, elapsed());
            }
            const auto requested_storage = invocation.key_storage.value_or(
                application::KeyStorage::Vault);
            if (requested_storage == application::KeyStorage::Vault) {
                if (const auto avail = application::check_os_vault_available();
                    !avail) {
                    return fail_error(avail.error());
                }
            }
            application::ProfileCredentials creds =
                env_creds ? *env_creds
                          : application::ProfileCredentials{
                                credentials::read_password_pair()};
            ProfileCredsWipeGuard guard{creds};
            if (platform::cancellation::requested()) {
                return 130;
            }

            application::Profile profile{
                .name = invocation.profile_name,
                .local_dir = platform::path::from_utf8(
                    invocation.local_dir.value_or("")),
                .remote_dir = invocation.remote_dir.value_or(""),
                .min_history_depth = invocation.min_history_depth.value_or(5U),
                .min_history_age_hours =
                    invocation.min_history_age_hours.value_or(6U),
                .key_storage = invocation.key_storage.value_or(
                    application::KeyStorage::Vault),
                .bandwidth_limit = invocation.bandwidth_limit,
                .transfer_concurrency = invocation.transfer_concurrency,
                .rclone_config =
                    invocation.rclone_config
                        ? std::optional<
                              std::filesystem::path>{platform::path::from_utf8(
                              *invocation.rclone_config)}
                        : std::nullopt,
                .watch_enabled = invocation.watch_enabled,
                .sync_interval_seconds = invocation.sync_interval_seconds,
                .paused = invocation.paused.value_or(false),
            };
            application::Credentials verify_creds{application::NoCredentials{}};
            CredsWipeGuard verify_guard{verify_creds};
            if (invocation.verify &&
                profile.key_storage == application::KeyStorage::Memory) {
                verify_creds = to_runtime_credentials(creds);
            }
            auto res = application::create_profile(
                environment, profile, std::move(creds));
            if (!res) {
                return fail_error(res.error());
            }
            if (invocation.verify) {
                auto conn = application::test_profile_connection(
                    environment, profile.name, std::move(verify_creds));
                if (platform::cancellation::requested()) {
                    (void)application::delete_profile(environment,
                                                      profile.name);
                    return 130;
                }
                if (!conn || !conn->ready) {
                    (void)application::delete_profile(environment,
                                                      profile.name);
                    if (!json) {
                        print_warning_line(i18n::format(
                            i18n::Key::WizardProfileCreatedVerifyFailed,
                            profile.name));
                    }
                    if (!conn) {
                        return fail_error(conn.error());
                    }
                    const auto code =
                        conn->vault_state == application::RemoteVaultState::
                                                 KeyMismatchOrInvalidHistory
                            ? application::ProfileErrorCode::CredentialFailure
                            : application::ProfileErrorCode::StorageFailure;
                    return fail_error(application::ProfileError{
                        .code = code,
                        .detail = conn->detail,
                    });
                }
            }
            return finish_success(
                &profile,
                profile.name,
                i18n::tr(i18n::Key::WizardProfileCreated),
                std::format("created profile '{}'", profile.name));
        }
        case ProfileAction::Edit: {
            auto profiles = application::list_profiles(environment);
            if (!profiles) {
                return fail_error(profiles.error());
            }
            const auto it = std::ranges::find(*profiles,
                                              invocation.profile_name,
                                              &application::Profile::name);
            if (it == profiles->end()) {
                return fail_error(application::ProfileError{
                    .code = application::ProfileErrorCode::NotFound,
                    .detail = "profile not found"});
            }
            application::Profile updated = *it;
            if (invocation.local_dir) {
                updated.local_dir =
                    platform::path::from_utf8(*invocation.local_dir);
            }
            if (invocation.remote_dir) {
                updated.remote_dir = *invocation.remote_dir;
            }
            if (invocation.min_history_depth) {
                updated.min_history_depth = *invocation.min_history_depth;
            }
            if (invocation.min_history_age_hours) {
                updated.min_history_age_hours =
                    *invocation.min_history_age_hours;
            }
            if (invocation.bandwidth_limit) {
                updated.bandwidth_limit = *invocation.bandwidth_limit;
            } else if (invocation.clear_bandwidth_limit) {
                updated.bandwidth_limit.reset();
            }
            if (invocation.transfer_concurrency) {
                updated.transfer_concurrency = *invocation.transfer_concurrency;
            } else if (invocation.clear_transfer_concurrency) {
                updated.transfer_concurrency.reset();
            }
            if (invocation.rclone_config) {
                updated.rclone_config =
                    platform::path::from_utf8(*invocation.rclone_config);
            } else if (invocation.clear_rclone_config) {
                updated.rclone_config.reset();
            }
            if (invocation.watch_enabled.has_value()) {
                updated.watch_enabled = *invocation.watch_enabled;
            } else if (invocation.clear_watch_enabled) {
                updated.watch_enabled.reset();
            }
            if (invocation.sync_interval_seconds.has_value()) {
                updated.sync_interval_seconds =
                    *invocation.sync_interval_seconds;
            } else if (invocation.clear_sync_interval_seconds) {
                updated.sync_interval_seconds.reset();
            }
            if (invocation.paused.has_value()) {
                updated.paused = *invocation.paused;
            }
            auto res = application::update_profile(
                environment, updated, invocation.allow_empty_local);
            if (!res) {
                return fail_error(res.error());
            }
            return finish_success(
                &updated,
                updated.name,
                i18n::format(i18n::Key::WizardProfileEdited, updated.name),
                std::format("edited profile '{}'", updated.name));
        }
        case ProfileAction::Clone: {
            const std::string target = invocation.target_name.value_or("");
            auto res = application::clone_profile(
                environment, invocation.profile_name, target);
            if (!res) {
                return fail_error(res.error());
            }
            std::optional<application::Profile> cloned;
            if (auto profiles = application::list_profiles(environment)) {
                if (const auto it = std::ranges::find(
                        *profiles, target, &application::Profile::name);
                    it != profiles->end()) {
                    cloned = *it;
                }
            }
            return finish_success(cloned ? &*cloned : nullptr,
                                  target,
                                  i18n::format(i18n::Key::WizardProfileCloned,
                                               target,
                                               invocation.profile_name),
                                  std::format("cloned '{}' -> '{}'",
                                              invocation.profile_name,
                                              target));
        }
        case ProfileAction::Storage: {
            auto profiles = application::list_profiles(environment);
            if (!profiles) {
                return fail_error(profiles.error());
            }
            const auto it = std::ranges::find(*profiles,
                                              invocation.profile_name,
                                              &application::Profile::name);
            if (it == profiles->end()) {
                return fail_error(application::ProfileError{
                    .code = application::ProfileErrorCode::NotFound,
                    .detail = "profile not found"});
            }
            const auto target_storage =
                invocation.key_storage.value_or(it->key_storage);
            if (target_storage == application::KeyStorage::Vault &&
                target_storage != it->key_storage) {
                if (const auto avail = application::check_os_vault_available();
                    !avail) {
                    return fail_error(avail.error());
                }
            }
            const bool needs_key =
                target_storage != application::KeyStorage::Memory &&
                target_storage != it->key_storage;
            application::Profile updated = *it;
            updated.key_storage = target_storage;
            auto res = application::update_profile(environment, updated);
            if (!res) {
                return fail_error(res.error());
            }
            const auto msg =
                needs_key
                    ? i18n::format(
                          i18n::Key::WizardProfileKeyStorageUpdatedNeedKey,
                          updated.name,
                          application::to_string(target_storage))
                    : i18n::format(i18n::Key::WizardProfileKeyStorageUpdated,
                                   updated.name,
                                   application::to_string(target_storage));
            return finish_success(
                &updated,
                updated.name,
                msg,
                std::format("key_storage={} ({})",
                            application::to_string(target_storage),
                            updated.name),
                needs_key);
        }
        case ProfileAction::Rename: {
            const std::string target = invocation.target_name.value_or("");
            auto res = application::rename_profile(
                environment, invocation.profile_name, target);
            if (!res) {
                return fail_error(res.error());
            }
            std::optional<application::Profile> renamed;
            if (auto profiles = application::list_profiles(environment)) {
                if (const auto it = std::ranges::find(
                        *profiles, target, &application::Profile::name);
                    it != profiles->end()) {
                    renamed = *it;
                }
            }
            return finish_success(
                renamed ? &*renamed : nullptr,
                target,
                i18n::format(i18n::Key::WizardProfileRenamed, target),
                std::format(
                    "renamed '{}' -> '{}'", invocation.profile_name, target));
        }
        case ProfileAction::Delete: {
            auto res = application::delete_profile(environment,
                                                   invocation.profile_name);
            if (!res) {
                return fail_error(res.error());
            }
            return finish_success(
                nullptr,
                invocation.profile_name,
                i18n::format(i18n::Key::WizardProfileDeleted,
                             invocation.profile_name),
                std::format("deleted profile '{}'", invocation.profile_name));
        }
        case ProfileAction::Test: {
            auto profiles = application::list_profiles(environment);
            if (!profiles) {
                return fail_error(profiles.error());
            }
            const auto it = std::ranges::find(*profiles,
                                              invocation.profile_name,
                                              &application::Profile::name);
            if (it == profiles->end()) {
                return fail_error(application::ProfileError{
                    .code = application::ProfileErrorCode::NotFound,
                    .detail = "profile not found"});
            }
            if (json && it->key_storage == application::KeyStorage::Memory &&
                !read_profile_env_credentials().has_value()) {
                const auto msg =
                    i18n::tr(i18n::Key::WizardProfileCredentialsRequired);
                if (log_summary != nullptr) {
                    *log_summary =
                        std::format("[credentials_required] {}", msg);
                }
                return present_json_credentials_required(
                    cmd, invocation.profile_name, msg, elapsed());
            }
            auto creds =
                credentials::for_profile(environment, invocation.profile_name);
            CredsWipeGuard guard{creds};
            if (platform::cancellation::requested()) {
                return 130;
            }
            auto report = application::test_profile_connection(
                environment, invocation.profile_name, std::move(creds));
            if (platform::cancellation::requested()) {
                return 130;
            }
            if (!report) {
                return fail_error(report.error());
            }
            if (log_summary != nullptr) {
                *log_summary = report->detail;
            }
            if (json) {
                return present_json_profile_test(*report, elapsed());
            }
            if (report->ready) {
                if (!quiet) {
                    print_ok_line(i18n::format(
                        i18n::Key::WizardProfileTestReady,
                        sanitize_terminal_text(report->profile_name),
                        sanitize_terminal_text(report->detail)));
                }
                return 0;
            }
            print_error_line(
                i18n::format(i18n::Key::WizardProfileTestFailed,
                             sanitize_terminal_text(report->profile_name),
                             sanitize_terminal_text(report->detail)));
            return 1;
        }
    }
    return 1;
}

int run_ignore_command(const application::ExecutionEnvironment& environment,
                       const IgnoreInvocation& invocation,
                       bool quiet,
                       bool json,
                       std::string* log_summary) {
    const auto started = std::chrono::steady_clock::now();
    const auto elapsed = [&] {
        return std::chrono::steady_clock::now() - started;
    };
    const std::string_view cmd = invocation.action == IgnoreAction::Check
                                     ? "ignore check"
                                     : "ignore init";
    const auto fail_error = [&](const application::ProfileError& err) -> int {
        if (log_summary != nullptr) {
            *log_summary =
                std::format("[{}] {}", json_error_code(err.code), err.detail);
        }
        if (json) {
            return present_json_profile_error(
                cmd, invocation.profile_name, err, elapsed());
        }
        print_error_line(err.detail);
        return 1;
    };

    if (invocation.action == IgnoreAction::Check) {
        auto report = application::check_profile_ignore(
            environment, invocation.profile_name, invocation.paths);
        if (!report) {
            return fail_error(report.error());
        }
        if (log_summary != nullptr) {
            *log_summary =
                std::format("evaluated {} path(s)", report->items.size());
        }
        if (json) {
            return present_json_ignore_check(*report, elapsed());
        }
        return present(*report, quiet);
    }

    auto report = application::init_profile_ignore(environment,
                                                   invocation.profile_name,
                                                   invocation.preset,
                                                   invocation.force,
                                                   invocation.dry_run);
    if (!report) {
        return fail_error(report.error());
    }
    if (log_summary != nullptr) {
        *log_summary = std::format(
            "preset={}{}",
            application::to_string(report->preset),
            report->dry_run
                ? " (dry-run)"
                : (report->overwritten ? " (overwritten)" : " (created)"));
    }
    if (json) {
        return present_json_ignore_init(*report, elapsed());
    }
    return present(*report, quiet);
}

bool prompt_confirmation(std::string_view message) {
    return confirm_change(message);
}

int run_profile_query(const application::ExecutionEnvironment& environment,
                      std::string_view profile_name,
                      bool full,
                      bool json) {
    const auto fail_query = [&](std::string_view message) {
        std::println(stderr, "{} {}", i18n::tr(i18n::Key::LabelError), message);
        return 1;
    };
    auto profiles = application::list_profiles(environment);
    if (!profiles) {
        if (json) {
            return present_json_profile_error(profile_name.empty() ? "list"
                                                                   : "show",
                                              profile_name,
                                              profiles.error());
        }
        return fail_query(profiles.error().detail);
    }
    if (json && profile_name.empty()) {
        return present_json_list(*profiles);
    }
    if (profile_name.empty() && full) {
        if (profiles->empty()) {
            i18n::println(i18n::Key::WizardNoProfiles);
            return 0;
        }
        for (std::size_t idx = 0; idx < profiles->size(); ++idx) {
            const auto& prof = (*profiles)[idx];
            const auto state = application::inspect_profile_local_state(
                environment, prof.name);
            const auto activity =
                application::inspect_profile_activity(environment, prof.name);
            if (idx > 0U) {
                std::println("");
            }
            std::println("{} [{}]",
                         sanitize_terminal_text(prof.name),
                         format_local_state_label(state, activity));
            i18n::println(i18n::Key::OverviewLineLocal,
                          sanitize_terminal_text(
                              platform::path::to_utf8(prof.local_dir)));
            i18n::println(i18n::Key::OverviewLineRemote,
                          sanitize_terminal_text(prof.remote_dir));
            const auto last_sync = format_config_last_sync(activity);
            i18n::println(
                i18n::Key::OverviewLineLastSync,
                last_sync == "-"
                    ? std::string{i18n::tr(i18n::Key::OverviewDetailNeverSynced)}
                    : last_sync);
        }
        return 0;
    }
    for (const auto& profile : *profiles) {
        if (profile_name.empty()) {
            std::println("{}", profile.name);
        } else if (profile.name == profile_name) {
            application::ProfileLocalProblem problem;
            const auto state = application::inspect_profile_local_state(
                environment, profile.name, &problem);
            const auto activity = application::inspect_profile_activity(
                environment, profile.name);
            std::optional<application::DaemonProfileStatus> daemon_prof;
            if (application::is_daemon_running(environment)) {
                if (const auto ds = application::query_daemon_status(
                        environment, profile.name);
                    ds && !ds->profiles.empty()) {
                    for (const auto& candidate : ds->profiles) {
                        if (candidate.name == profile.name) {
                            daemon_prof = candidate;
                            break;
                        }
                    }
                }
            }
            if (json) {
                return present_json_show(
                    profile, state, problem, activity, full, daemon_prof);
            }
            if (!full) {
                i18n::println(
                    i18n::Key::WizardShowProfileCompact,
                    profile.name,
                    sanitize_terminal_text(
                        platform::path::to_utf8(profile.local_dir)),
                    sanitize_terminal_text(profile.remote_dir),
                    format_local_state_label(state, activity));
                std::println("{}", format_compact_automation(profile));
                if (daemon_prof.has_value()) {
                    i18n::println(i18n::Key::WizardShowDaemonStatus,
                                  sanitize_terminal_text(
                                      application::to_string(daemon_prof->state)));
                    if (!daemon_prof->active_stage.empty()) {
                        i18n::println(
                            i18n::Key::WizardShowDaemonStage,
                            sanitize_terminal_text(daemon_prof->active_stage));
                    }
                    if (daemon_prof->dirty_paths_count > 0) {
                        i18n::println(i18n::Key::WizardShowDaemonDirty,
                                      daemon_prof->dirty_paths_count);
                    }
                    if (!daemon_prof->last_error.empty()) {
                        i18n::println(
                            i18n::Key::DaemonStatusProfileError,
                            sanitize_terminal_text(daemon_prof->last_error));
                    }
                }
                if (state == application::ProfileLocalState::Problem) {
                    i18n::println(i18n::Key::WizardProblemReason,
                                  overview_problem_message(problem));
                }
                if (const auto conflicts = application::list_local_conflicts(
                        environment, profile.name);
                    conflicts && conflicts->total_artifacts > 0) {
                    i18n::println(i18n::Key::WizardShowConflictsCount,
                                  conflicts->total_artifacts,
                                  sanitize_terminal_text(profile.name));
                }
                if (activity.database_present) {
                    if (activity.last_complete_sync) {
                        const auto& s = *activity.last_complete_sync;
                        const auto ts = platform::clock::format_local_timestamp(
                            s.finished_at.value_or(s.started_at));
                        const auto status = execution_status_label(s.status);
                        const auto machine = format_machine_label(
                            s.machine_name, s.machine_id_hex, false, false);
                        i18n::println(i18n::Key::WizardShowLastCompleteSync,
                                      ts,
                                      status,
                                      machine);
                    } else {
                        i18n::println(i18n::Key::WizardShowNoCompleteSync);
                    }
                    if (activity.accepted_commit) {
                        const auto& c = *activity.accepted_commit;
                        const auto ts = platform::clock::format_local_timestamp(
                            c.created_at > 0 ? c.created_at : c.accepted_at);
                        const auto machine = format_machine_label(
                            c.machine_name, c.machine_id_hex, false, false);
                        i18n::println(i18n::Key::WizardShowLastChangeHead,
                                      ts,
                                      machine,
                                      c.height);
                    }
                }
                if (const auto logs = application::query_daemon_events(
                        environment,
                        application::DaemonLogQuery{
                            .profile_name = profile.name,
                            .max_lines = 30U,
                        });
                    logs && !logs->events.empty()) {
                    std::vector<const application::DaemonEvent*> recent;
                    for (const auto& ev : logs->events) {
                        if (!is_noisy_daemon_event(ev)) {
                            recent.push_back(&ev);
                        }
                    }
                    if (!recent.empty()) {
                        i18n::println(i18n::Key::WizardShowRecentEventsHeader);
                        const std::size_t start =
                            recent.size() > 5U ? recent.size() - 5U : 0U;
                        for (std::size_t idx = start; idx < recent.size();
                             ++idx) {
                            print_daemon_event_line(*recent[idx]);
                        }
                    }
                }
                i18n::println(i18n::Key::WizardShowFullHint,
                              sanitize_terminal_text(profile.name));
                return 0;
            }
            i18n::println(i18n::Key::WizardProfileDetails,
                          profile.name,
                          platform::path::to_utf8(profile.local_dir),
                          profile.remote_dir,
                          format_local_state_label(state, activity),
                          application::to_string(profile.key_storage),
                          profile.min_history_depth,
                          profile.min_history_age_hours);
            if (profile.bandwidth_limit) {
                i18n::println(i18n::Key::WizardShowBandwidthLimit,
                              sanitize_terminal_text(*profile.bandwidth_limit));
            }
            if (profile.transfer_concurrency) {
                i18n::println(i18n::Key::WizardShowTransferConcurrency,
                              *profile.transfer_concurrency);
            }
            if (profile.rclone_config) {
                i18n::println(i18n::Key::WizardShowRcloneConfig,
                              sanitize_terminal_text(platform::path::to_utf8(
                                  *profile.rclone_config)));
            }
            if (profile.watch_enabled.has_value()) {
                i18n::println(i18n::Key::WizardShowWatch,
                              *profile.watch_enabled
                                  ? i18n::tr(i18n::Key::LabelYes)
                                  : i18n::tr(i18n::Key::LabelNo));
            }
            if (profile.sync_interval_seconds.has_value()) {
                if (*profile.sync_interval_seconds == 0) {
                    i18n::println(i18n::Key::WizardShowSyncIntervalDisabled);
                } else {
                    i18n::println(i18n::Key::WizardShowSyncInterval,
                                  *profile.sync_interval_seconds);
                }
            }
            if (profile.paused) {
                i18n::println(i18n::Key::WizardShowPaused,
                              i18n::tr(i18n::Key::LabelYes));
            }
            if (daemon_prof.has_value()) {
                i18n::println(i18n::Key::WizardShowDaemonStatus,
                              sanitize_terminal_text(
                                  application::to_string(daemon_prof->state)));
                if (!daemon_prof->active_stage.empty()) {
                    i18n::println(
                        i18n::Key::WizardShowDaemonStage,
                        sanitize_terminal_text(daemon_prof->active_stage));
                }
                if (daemon_prof->dirty_paths_count > 0) {
                    i18n::println(i18n::Key::WizardShowDaemonDirty,
                                  daemon_prof->dirty_paths_count);
                }
            }
            if (state == application::ProfileLocalState::Problem) {
                static constexpr auto problem_keys = std::to_array<i18n::Key>({
                    i18n::Key::WizardProblemUnspecified,
                    i18n::Key::WizardProblemName,
                    i18n::Key::WizardProblemPaths,
                    i18n::Key::WizardProblemDirectory,
                    i18n::Key::WizardProblemKey,
                    i18n::Key::WizardProblemDatabase,
                    i18n::Key::WizardProblemLock,
                    i18n::Key::WizardProblemSidecar,
                    i18n::Key::WizardProblemJournal,
                    i18n::Key::WizardProblemWorkspace,
                    i18n::Key::WizardProblemSnapshot,
                    i18n::Key::WizardProblemCleanup,
                });
                static_assert(problem_keys.size() ==
                              static_cast<std::size_t>(
                                  application::ProfileLocalProblem::Count));
                i18n::println(
                    i18n::Key::WizardProblemReason,
                    i18n::tr(problem_keys[static_cast<std::size_t>(problem)]));
            }
            if (activity.database_present) {
                present_profile_activity(profile.name, activity, full);
            }
            return 0;
        }
    }
    if (!profile_name.empty()) {
        if (json) {
            return present_json_profile_error(
                "show",
                profile_name,
                application::ProfileError{
                    .code = application::ProfileErrorCode::NotFound,
                    .detail = "profile not found"});
        }
        return fail_query(i18n::tr(i18n::Key::WizardProfileNotFound));
    }
    return 0;
}

int run_profile_key(const application::ExecutionEnvironment& environment,
                    std::string_view profile_name,
                    bool replace,
                    bool quiet,
                    bool json,
                    std::string* log_summary) {
    const auto started = std::chrono::steady_clock::now();
    const auto elapsed = [&] {
        return std::chrono::steady_clock::now() - started;
    };
    const auto fail_error = [&](const application::ProfileError& err) -> int {
        if (log_summary != nullptr) {
            *log_summary =
                std::format("[{}] {}", json_error_code(err.code), err.detail);
        }
        if (json) {
            return present_json_profile_error(
                "key", profile_name, err, elapsed());
        }
        print_error_line(err.detail);
        return 1;
    };

    auto profiles = application::list_profiles(environment);
    if (!profiles) {
        return fail_error(profiles.error());
    }
    const auto it =
        std::ranges::find(*profiles, profile_name, &application::Profile::name);
    if (it == profiles->end()) {
        return fail_error(application::ProfileError{
            .code = application::ProfileErrorCode::NotFound,
            .detail = std::string{i18n::tr(i18n::Key::WizardProfileNotFound)}});
    }
    if (it->key_storage == application::KeyStorage::Memory) {
        return fail_error(application::ProfileError{
            .code = application::ProfileErrorCode::ConfigFailure,
            .detail = i18n::format(i18n::Key::WizardKeyStorageMemoryNoPersist,
                                   profile_name)});
    }
    if (it->key_storage == application::KeyStorage::Vault) {
        if (const auto avail = application::check_os_vault_available();
            !avail) {
            return fail_error(avail.error());
        }
    }
    const auto env_creds = read_profile_env_credentials();
    if (!env_creds.has_value() && json) {
        const auto msg = i18n::tr(i18n::Key::WizardProfileCredentialsRequired);
        if (log_summary != nullptr) {
            *log_summary = std::format("[credentials_required] {}", msg);
        }
        return present_json_credentials_required(
            "key", profile_name, msg, elapsed());
    }
    application::ProfileCredentials creds =
        env_creds ? *env_creds
                  : application::ProfileCredentials{
                        credentials::read_password_pair()};
    ProfileCredsWipeGuard guard{creds};
    if (platform::cancellation::requested()) {
        return 130;
    }

    application::ProfileCredentials attempt = creds;
    ProfileCredsWipeGuard attempt_guard{attempt};
    auto res = application::set_profile_key(
        environment, profile_name, std::move(attempt), false);
    if (res) {
        if (log_summary != nullptr) {
            *log_summary = std::format("saved key for '{}'", profile_name);
        }
        if (json) {
            return present_json_key_updated(
                profile_name, false, false, elapsed());
        }
        if (!quiet) {
            print_ok_line(
                i18n::format(i18n::Key::WizardProfileKeyUpdated, profile_name));
        }
        return 0;
    }
    if (res.error().code != application::ProfileErrorCode::AlreadyExists) {
        return fail_error(res.error());
    }
    if (!replace) {
        if (json) {
            return fail_error(application::ProfileError{
                .code = application::ProfileErrorCode::AlreadyExists,
                .detail = i18n::format(
                    i18n::Key::WizardKeyDifferentNeedsReplace, profile_name)});
        }
        if (!confirm_change(i18n::format(i18n::Key::WizardConfirmReplaceKey,
                                         profile_name))) {
            if (platform::cancellation::requested()) {
                return 130;
            }
            print_error_line(i18n::tr(i18n::Key::WizardKeyReplaceCancelled));
            if (log_summary != nullptr) {
                *log_summary = "key replacement declined";
            }
            return 1;
        }
    }
    res = application::set_profile_key(
        environment, profile_name, std::move(creds), true);
    if (!res) {
        return fail_error(res.error());
    }
    if (log_summary != nullptr) {
        *log_summary = std::format("replaced key for '{}'", profile_name);
    }
    if (json) {
        return present_json_key_updated(profile_name, true, false, elapsed());
    }
    if (!quiet) {
        print_ok_line(i18n::format(replace ? i18n::Key::WizardKeyReplaced
                                           : i18n::Key::WizardProfileKeyUpdated,
                                   profile_name));
    }
    return 0;
}

int run_config_wizard(const application::ExecutionEnvironment& environment) {
    bool back_hint_shown = false;
    const auto prompt_form_line = [&](std::string_view label,
                                      std::string& value) {
        if (!back_hint_shown) {
            back_hint_shown = true;
            return prompt_line(
                       i18n::format(i18n::Key::WizardPromptWithBack, label),
                       value) &&
                   value != ":back";
        }
        return prompt_line(label, value) && value != ":back";
    };
    const auto prompt_key_storage = [&](application::KeyStorage default_mode)
        -> std::optional<application::KeyStorage> {
        const std::string prompt =
            i18n::format(i18n::Key::WizardPromptKeyStorage,
                         application::to_string(default_mode));
        std::string mode;
        while (prompt_form_line(prompt, mode)) {
            const auto first = mode.find_first_not_of(" \t\r\n");
            std::optional<application::KeyStorage> chosen;
            if (first == std::string::npos) {
                chosen = default_mode;
            } else {
                const auto last = mode.find_last_not_of(" \t\r\n");
                mode = mode.substr(first, last - first + 1);
                std::ranges::transform(mode, mode.begin(), [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
                for (const auto storage : {application::KeyStorage::Vault,
                                           application::KeyStorage::File,
                                           application::KeyStorage::Memory}) {
                    if (mode == application::to_string(storage)) {
                        chosen = storage;
                        break;
                    }
                }
            }
            if (!chosen) {
                print_error_line(i18n::tr(i18n::Key::WizardInvalidKeyStorage));
                continue;
            }
            if (*chosen == application::KeyStorage::Vault) {
                if (const auto avail = application::check_os_vault_available();
                    !avail) {
                    print_error_line(avail.error().detail);
                    continue;
                }
            }
            return *chosen;
        }
        return std::nullopt;
    };
    const auto report_result =
        [&](const std::expected<void, application::ProfileError>& result,
            std::string_view ok_message) {
            if (result) {
                print_ok_line(ok_message);
            } else {
                print_error_line(result.error().detail);
            }
        };

    while (!platform::cancellation::requested()) {
        auto profiles_res = application::list_profiles(environment);
        if (!profiles_res) {
            print_error_line(
                std::string{i18n::tr(i18n::Key::WizardConfigReadFailed)} +
                profiles_res.error().detail);
            return 1;
        }
        std::vector<application::Profile> profiles = std::move(*profiles_res);

        i18n::println(i18n::Key::WizardHeader);
        if (profiles.empty()) {
            i18n::println(i18n::Key::WizardNoProfiles);
        } else {
            i18n::println(i18n::Key::WizardProfileListHeader);
            for (const auto& prof : profiles) {
                const auto state = application::inspect_profile_local_state(
                    environment, prof.name);
                const auto activity = application::inspect_profile_activity(
                    environment, prof.name);
                i18n::println(i18n::Key::WizardProfileListEntry,
                              prof.name,
                              format_local_state_label(state, activity),
                              format_config_last_sync(activity));
            }
        }

        std::string choice;
        const auto menu = profiles.empty() ? i18n::Key::WizardMenuEmpty
                                           : i18n::Key::WizardMenu;
        const auto valid_choice = [&](std::string_view value) {
            if (value == "q" || value == "n") {
                return true;
            }
            return !profiles.empty() &&
                   (value == "c" || value == "d" || value == "e" ||
                    value == "k" || value == "s" || value == "r");
        };
        std::string_view prompt_text = i18n::tr(menu);
        bool cancelled = false;
        while (true) {
            if (!prompt_line(prompt_text, choice)) {
                cancelled = true;
                break;
            }
            if (choice.size() == 1) {
                choice[0] = static_cast<char>(
                    std::tolower(static_cast<unsigned char>(choice[0])));
            }
            if (valid_choice(choice)) {
                break;
            }
            print_error_line(i18n::tr(i18n::Key::WizardInvalidOption));
            prompt_text = "\n> ";
        }
        if (cancelled) {
            break;
        }
        std::println();
        back_hint_shown = false;

        const auto prompt_field = [&](std::string_view label,
                                      application::ProfileField field,
                                      std::string& value,
                                      std::string_view fallback = {}) {
            while (prompt_form_line(label, value)) {
                if (value.empty() && !fallback.empty()) {
                    value = fallback;
                }
                if (auto valid =
                        application::validate_profile_field(field, value);
                    !valid) {
                    const auto key =
                        field == application::ProfileField::Name
                            ? i18n::Key::WizardInvalidProfileName
                        : field == application::ProfileField::LocalPath
                            ? i18n::Key::WizardLocalPathMustBeAbsolute
                            : i18n::Key::WizardInvalidRemotePath;
                    print_error_line(i18n::tr(key));
                    continue;
                }
                if (field == application::ProfileField::Name &&
                    std::ranges::any_of(profiles, [&](const auto& profile) {
                        return profile.name == value;
                    })) {
                    print_error_line(i18n::format(
                        i18n::Key::WizardProfileAlreadyExists, value));
                    continue;
                }
                return true;
            }
            return false;
        };

        const auto prompt_existing = [&](i18n::Key key, std::string& name) {
            if (profiles.empty()) {
                return false;
            }
            while (prompt_form_line(i18n::tr(key), name)) {
                if (std::ranges::find(
                        profiles, name, &application::Profile::name) !=
                    profiles.end()) {
                    return true;
                }
                print_error_line(i18n::tr(i18n::Key::WizardProfileNotFound));
            }
            return false;
        };

        const auto prompt_pair = [&](i18n::Key first_key,
                                     std::string& first,
                                     std::string& second) {
            return prompt_existing(first_key, first) &&
                   prompt_field(i18n::tr(i18n::Key::WizardPromptNewProfileName),
                                application::ProfileField::Name,
                                second);
        };

        if (choice == "q") {
            break;
        } else if (choice == "n") {
            std::string new_profile, new_local, new_remote;
            if (!prompt_field(i18n::tr(i18n::Key::WizardPromptProfileName),
                              application::ProfileField::Name,
                              new_profile)) {
                continue;
            }
            std::println();
            if (!prompt_field(i18n::tr(i18n::Key::WizardPromptLocalPath),
                              application::ProfileField::LocalPath,
                              new_local)) {
                continue;
            }
            const auto rclone_info = show_rclone_discovery_hint(
                platform::path::from_utf8(new_local));
            if (!prompt_field(i18n::tr(i18n::Key::WizardPromptRemotePath),
                              application::ProfileField::RemotePath,
                              new_remote)) {
                continue;
            }
            warn_if_unknown_rclone_remote(new_remote, rclone_info);
            const auto key_storage =
                prompt_key_storage(application::KeyStorage::Vault);
            if (!key_storage) {
                continue;
            }
            std::println();
            application::ProfileCredentials creds =
                credentials::read_password_pair();
            if (platform::cancellation::requested()) {
                application::wipe_credentials(creds);
                break;
            }

            application::Profile p{.name = new_profile,
                                   .local_dir =
                                       platform::path::from_utf8(new_local),
                                   .remote_dir = new_remote,
                                   .key_storage = *key_storage};
            auto res =
                application::create_profile(environment, p, std::move(creds));
            application::wipe_credentials(creds);
            report_result(res, i18n::tr(i18n::Key::WizardProfileCreated));
        } else if (choice == "c") {
            std::string source, new_name;
            if (!prompt_pair(
                    i18n::Key::WizardPromptSourceProfile, source, new_name)) {
                continue;
            }
            report_result(
                application::clone_profile(environment, source, new_name),
                i18n::format(i18n::Key::WizardProfileCloned, new_name, source));

        } else if (choice == "d") {
            std::string target;
            if (!prompt_existing(i18n::Key::WizardPromptProfileToDelete,
                                 target)) {
                continue;
            }
            const auto selected = std::ranges::find(
                profiles, target, &application::Profile::name);
            if (selected == profiles.end()) {
                print_error_line(i18n::tr(i18n::Key::WizardProfileNotFound));
                continue;
            }
            if (!confirm_change(
                    i18n::format(i18n::Key::WizardConfirmDelete,
                                 selected->name,
                                 platform::path::to_utf8(selected->local_dir),
                                 selected->remote_dir))) {
                continue;
            }
            report_result(
                application::delete_profile(environment, target),
                i18n::format(i18n::Key::WizardProfileDeleted, target));

        } else if (choice == "e") {
            std::string target;
            if (!prompt_existing(i18n::Key::WizardPromptProfileToEdit,
                                 target)) {
                continue;
            }

            auto it =
                std::ranges::find_if(profiles, [&](const auto& candidate) {
                    return candidate.name == target;
                });
            if (it != profiles.end()) {
                const auto prompt_default = [&](i18n::Key key,
                                                const std::string& fallback,
                                                std::string& out) {
                    return prompt_field(
                        i18n::format(key, fallback),
                        key == i18n::Key::WizardPromptNewLocalPath
                            ? application::ProfileField::LocalPath
                            : application::ProfileField::RemotePath,
                        out,
                        fallback);
                };
                std::string edit_local, edit_remote;
                if (!prompt_default(i18n::Key::WizardPromptNewLocalPath,
                                    platform::path::to_utf8(it->local_dir),
                                    edit_local)) {
                    continue;
                }
                const auto rclone_info = show_rclone_discovery_hint(
                    platform::path::from_utf8(edit_local));
                if (!prompt_default(i18n::Key::WizardPromptNewRemotePath,
                                    it->remote_dir,
                                    edit_remote)) {
                    continue;
                }
                warn_if_unknown_rclone_remote(edit_remote, rclone_info);

                application::Profile updated = *it;
                updated.local_dir = platform::path::from_utf8(edit_local);
                updated.remote_dir = edit_remote;

                const std::string cur_watch =
                    updated.watch_enabled.value_or(true) ? "on" : "off";
                std::string watch_val;
                if (!prompt_form_line(
                        i18n::format(i18n::Key::WizardAutoPromptWatch,
                                     cur_watch),
                        watch_val)) {
                    continue;
                }
                if (!watch_val.empty()) {
                    std::ranges::transform(
                        watch_val, watch_val.begin(), [](unsigned char c) {
                            return static_cast<char>(std::tolower(c));
                        });
                    if (watch_val == "on" || watch_val == "true" ||
                        watch_val == "1" || watch_val == "yes" ||
                        watch_val == "y" || watch_val == "sim" ||
                        watch_val == "s") {
                        updated.watch_enabled = true;
                    } else if (watch_val == "off" || watch_val == "false" ||
                               watch_val == "0" || watch_val == "no" ||
                               watch_val == "n" || watch_val == "nao") {
                        updated.watch_enabled = false;
                    } else {
                        print_error_line(
                            i18n::tr(i18n::Key::WizardInvalidOption));
                        continue;
                    }
                }

                const std::uint32_t cur_sync =
                    updated.sync_interval_seconds.value_or(300U);
                std::string sync_val;
                if (!prompt_form_line(
                        i18n::format(i18n::Key::WizardAutoPromptSyncInterval,
                                     cur_sync),
                        sync_val)) {
                    continue;
                }
                if (!sync_val.empty()) {
                    try {
                        const auto parsed = std::stoul(sync_val);
                        if (parsed > 86400UL ||
                            (parsed != 0UL && parsed < 10UL)) {
                            print_error_line(i18n::format(
                                i18n::Key::WizardAutoInvalidInterval,
                                10U,
                                86400U));
                            continue;
                        }
                        updated.sync_interval_seconds =
                            static_cast<std::uint32_t>(parsed);
                    } catch (...) {
                        print_error_line(i18n::format(
                            i18n::Key::WizardAutoInvalidInterval,
                            10U,
                            86400U));
                        continue;
                    }
                }

                const bool paths_changed = updated.local_dir != it->local_dir ||
                                           updated.remote_dir != it->remote_dir;
                const bool auto_changed =
                    updated.watch_enabled != it->watch_enabled ||
                    updated.sync_interval_seconds !=
                        it->sync_interval_seconds;
                if (!paths_changed && !auto_changed) {
                    continue;
                }
                if (paths_changed &&
                    !confirm_change(
                        i18n::format(i18n::Key::WizardConfirmEdit,
                                     target,
                                     platform::path::to_utf8(it->local_dir),
                                     edit_local,
                                     it->remote_dir,
                                     edit_remote))) {
                    continue;
                }
                // WizardConfirmEdit already warns explicitly about empty local
                // directories before asking for [y/N] confirmation.
                report_result(
                    application::update_profile(environment, updated, true),
                    i18n::format(i18n::Key::WizardProfileEdited, target));
            } else {
                print_error_line(i18n::tr(i18n::Key::WizardProfileNotFound));
            }

        } else if (choice == "k") {
            std::string target;
            if (!prompt_existing(i18n::Key::WizardPromptProfileToKey, target)) {
                continue;
            }
            const auto selected = std::ranges::find(
                profiles, target, &application::Profile::name);
            if (selected == profiles.end()) {
                print_error_line(i18n::tr(i18n::Key::WizardProfileNotFound));
                continue;
            }
            if (selected->key_storage == application::KeyStorage::Memory) {
                print_error_line(i18n::format(
                    i18n::Key::WizardKeyStorageMemoryNoPersist, target));
                continue;
            }
            if (selected->key_storage == application::KeyStorage::Vault) {
                if (const auto avail = application::check_os_vault_available();
                    !avail) {
                    print_error_line(avail.error().detail);
                    continue;
                }
            }
            application::ProfileCredentials creds =
                credentials::read_password_pair();
            if (platform::cancellation::requested()) {
                application::wipe_credentials(creds);
                break;
            }
            if (apply_profile_key_update(environment, target, creds, false) ==
                130) {
                break;
            }

        } else if (choice == "s") {
            std::string target;
            if (!prompt_existing(i18n::Key::WizardPromptProfileToStorage,
                                 target)) {
                continue;
            }
            const auto selected = std::ranges::find(
                profiles, target, &application::Profile::name);
            if (selected == profiles.end()) {
                print_error_line(i18n::tr(i18n::Key::WizardProfileNotFound));
                continue;
            }
            const auto chosen = prompt_key_storage(selected->key_storage);
            if (!chosen) {
                continue;
            }
            if (*chosen == selected->key_storage) {
                continue;
            }
            application::Profile updated = *selected;
            updated.key_storage = *chosen;
            auto res = application::update_profile(environment, updated);
            if (!res) {
                print_error_line(res.error().detail);
            } else if (*chosen == application::KeyStorage::Memory) {
                print_ok_line(
                    i18n::format(i18n::Key::WizardProfileKeyStorageUpdated,
                                 target,
                                 application::to_string(*chosen)));
            } else {
                print_ok_line(i18n::format(
                    i18n::Key::WizardProfileKeyStorageUpdatedNeedKey,
                    target,
                    application::to_string(*chosen)));
            }

        } else if (choice == "r") {
            std::string target, new_name;
            if (!prompt_pair(
                    i18n::Key::WizardPromptProfileToRename, target, new_name)) {
                continue;
            }
            report_result(
                application::rename_profile(environment, target, new_name),
                i18n::format(i18n::Key::WizardProfileRenamed, new_name));
        } else {
            print_error_line(i18n::tr(i18n::Key::WizardInvalidOption));
        }
    }
    return platform::cancellation::requested() ? 130 : 0;
}

int run_overview_command(const application::ExecutionEnvironment& environment,
                         bool full,
                         bool quiet,
                         bool json) {
    const auto started = std::chrono::steady_clock::now();
    const auto elapsed = [&] {
        return std::chrono::steady_clock::now() - started;
    };
    auto profiles = application::list_profiles(environment);
    if (!profiles) {
        if (json) {
            return present_json_profile_error(
                "status", {}, profiles.error(), elapsed());
        }
        print_error_line(profiles.error().detail);
        return 1;
    }

    application::DaemonStatusReport daemon_report;
    if (const auto ds = application::query_daemon_status(environment)) {
        daemon_report = *ds;
    }

    std::vector<OverviewProfileRow> rows;
    rows.reserve(profiles->size());
    for (const auto& profile : *profiles) {
        OverviewProfileRow row{.profile = profile};
        row.local_state = application::inspect_profile_local_state(
            environment, profile.name, &row.local_problem);
        row.activity =
            application::inspect_profile_activity(environment, profile.name);
        if (const auto conflicts =
                application::list_local_conflicts(environment, profile.name)) {
            row.conflict_count = conflicts->total_artifacts;
        }
        if (daemon_report.running) {
            for (const auto& dp : daemon_report.profiles) {
                if (dp.name == profile.name) {
                    row.daemon_profile = dp;
                    break;
                }
            }
        }
        rows.push_back(std::move(row));
    }

    if (json) {
        return present_json_overview(daemon_report, rows, elapsed(), full);
    }
    return present_overview(daemon_report, rows, full, quiet);
}

int run_profile_toggle_command(
    const application::ExecutionEnvironment& environment,
    const ProfileToggleInvocation& invocation,
    bool quiet,
    bool json,
    std::string* log_summary) {
    const auto started = std::chrono::steady_clock::now();
    const auto elapsed = [&] {
        return std::chrono::steady_clock::now() - started;
    };
    const std::string_view cmd = invocation.pause ? "pause" : "resume";
    const std::string target_label =
        invocation.all ? std::string{"--all"}
                       : invocation.profile_name.value_or("");

    const auto fail_daemon = [&](const application::DaemonError& err) -> int {
        if (log_summary != nullptr) {
            *log_summary = std::format(
                "[{}] {}", json_error_code(err.code), err.detail);
        }
        if (json) {
            return present_json_daemon_error(
                cmd, target_label, err, elapsed());
        }
        return present(err);
    };

    auto profiles = application::list_profiles(environment);
    if (!profiles) {
        const application::DaemonError err{
            .code = application::DaemonErrorCode::ConfigFailure,
            .detail = profiles.error().detail,
        };
        return fail_daemon(err);
    }
    if (profiles->empty()) {
        return fail_daemon(application::DaemonError{
            .code = application::DaemonErrorCode::ProfileNotFound,
            .detail = std::string{i18n::tr(i18n::Key::WizardNoProfiles)},
        });
    }

    std::vector<std::string> targets;
    if (invocation.all) {
        targets.reserve(profiles->size());
        for (const auto& p : *profiles) {
            targets.push_back(p.name);
        }
    } else {
        const std::string target = invocation.profile_name.value_or("");
        const auto it = std::ranges::find(
            *profiles, target, &application::Profile::name);
        if (it == profiles->end()) {
            return fail_daemon(application::DaemonError{
                .code = application::DaemonErrorCode::ProfileNotFound,
                .detail =
                    std::string{i18n::tr(i18n::Key::WizardProfileNotFound)},
            });
        }
        targets.push_back(target);
    }

    for (const auto& name : targets) {
        const auto res =
            invocation.pause
                ? application::pause_daemon_profile(environment, name)
                : application::resume_daemon_profile(environment, name);
        if (!res) {
            return fail_daemon(res.error());
        }
    }

    const std::string summary =
        invocation.all
            ? std::format("{} {} profile(s)",
                          invocation.pause ? "paused" : "resumed",
                          targets.size())
            : std::format("{} profile '{}'",
                          invocation.pause ? "paused" : "resumed",
                          targets.front());
    if (log_summary != nullptr) {
        *log_summary = summary;
    }
    if (json) {
        return present_json_daemon_action(cmd, target_label, summary, elapsed());
    }
    if (!quiet) {
        if (invocation.all) {
            print_ok_line(i18n::format(invocation.pause
                                           ? i18n::Key::DaemonAllPaused
                                           : i18n::Key::DaemonAllResumed,
                                       targets.size()));
        } else {
            print_ok_line(i18n::format(invocation.pause
                                           ? i18n::Key::DaemonProfilePaused
                                           : i18n::Key::DaemonProfileResumed,
                                       sanitize_terminal_text(targets.front())));
        }
    }
    return 0;
}

} // namespace kasumi::cli
