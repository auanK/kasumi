#include "cli/wizard.hpp"

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
#include <format>
#include <iostream>
#include <map>
#include <optional>
#include <print>
#include <set>
#include <string>

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

std::string_view
profile_operation_label(application::ProfileOperationKind op) {
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

std::string_view
execution_status_label(application::ProfileExecutionStatus status) {
    using S = application::ProfileExecutionStatus;
    static constexpr std::array<std::pair<S, i18n::Key>, 11> kTable{{
        {S::InProgress, i18n::Key::LabelStatusInProgress},
        {S::Succeeded, i18n::Key::LabelStatusOk},
        {S::SucceededNoChanges, i18n::Key::LabelStatusNoChanges},
        {S::SucceededDownloadedOnly, i18n::Key::LabelStatusDownloadedOnly},
        {S::SucceededPartial, i18n::Key::LabelStatusPartial},
        {S::IssuesFound, i18n::Key::LabelStatusIssuesFound},
        {S::Blocked, i18n::Key::LabelStatusBlocked},
        {S::Cancelled, i18n::Key::LabelStatusCancelled},
        {S::Failed, i18n::Key::LabelStatusFailed},
        {S::Uncertain, i18n::Key::LabelStatusUncertain},
        {S::Interrupted, i18n::Key::LabelStatusInterrupted},
    }};
    for (const auto& [candidate, key] : kTable) {
        if (candidate == status) {
            return i18n::tr(key);
        }
    }
    return i18n::tr(i18n::Key::LabelUnknown);
}

std::string format_execution_metrics(const application::ProfileExecutionSummary& e) {
    using K = application::ProfileOperationKind;
    switch (e.operation) {
    case K::Sync:
        if (e.summary_a > 0 && e.summary_c > 0) {
            return i18n::format(i18n::Key::LabelMetricSyncChanged, e.summary_a) +
                   ", " +
                   i18n::format(i18n::Key::LabelMetricSyncPending, e.summary_c);
        }
        if (e.summary_a > 0) {
            return i18n::format(i18n::Key::LabelMetricSyncChanged, e.summary_a);
        }
        if (e.summary_c > 0) {
            return i18n::format(i18n::Key::LabelMetricSyncPending, e.summary_c);
        }
        return {};
    case K::Fsck:
        if (e.summary_a > 0 || e.summary_bytes > 0) {
            return format_activity_metrics(
                static_cast<std::uint8_t>(application::RemoteActivityOperation::Fsck),
                e.summary_a,
                e.summary_b,
                e.summary_bytes,
                e.flags);
        }
        return {};
    case K::GarbageCollect:
        if (e.summary_a > 0 || e.summary_b > 0 ||
            (e.flags & application::remote_activity_flag_analysis_only) != 0U) {
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

std::string format_execution_extra(const application::ProfileExecutionSummary& e,
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
    if (e.recovered) {
        append(i18n::tr(i18n::Key::LabelFlagRecovered));
    }
    if ((e.flags & application::profile_execution_flag_audit_failed_after_sync) !=
        0U) {
        append(i18n::tr(i18n::Key::LabelFlagAuditFailedAfterSync));
    }
    if (e.remote_publish_state == application::ProfileRemotePublishState::Pending) {
        append(i18n::tr(i18n::Key::LabelFlagRemotePublishPending));
    }
    append(format_activity_flags(e.flags));
    if (include_stage && !e.stage.empty()) {
        append(sanitize_terminal_text(e.stage));
    }
    return extra;
}

std::string format_local_state_label(
    application::ProfileLocalState state,
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
            a.status == application::ProfileExecutionStatus::SucceededNoChanges ||
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
                if (item->operation != application::ProfileOperationKind::Sync &&
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
            const bool collide =
                ids_by_name.contains(item->machine_name) &&
                ids_by_name.at(item->machine_name).size() > 1;
            const auto machine = format_machine_label(
                item->machine_name, item->machine_id_hex, full || collide, full);
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
    if (std::cin.rdbuf() == default_cin_buffer &&
        ::isatty(STDIN_FILENO) != 0) {
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
        if (!confirm_change(
                i18n::format(i18n::Key::WizardConfirmReplaceKey,
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

} // namespace

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
            return present_json_profile_error(
                profile_name.empty() ? "list" : "show",
                profile_name,
                profiles.error());
        }
        return fail_query(profiles.error().detail);
    }
    if (json && profile_name.empty()) {
        return present_json_list(*profiles);
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
            if (json) {
                return present_json_show(
                    profile, state, problem, activity, full);
            }
            i18n::println(i18n::Key::WizardProfileDetails,
                          profile.name,
                          platform::path::to_utf8(profile.local_dir),
                          profile.remote_dir,
                          format_local_state_label(state, activity),
                          application::to_string(profile.key_storage),
                          profile.min_history_depth,
                          profile.min_history_age_hours);
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
                    std::string_view profile_name) {
    auto profiles = application::list_profiles(environment);
    if (!profiles) {
        print_error_line(profiles.error().detail);
        return 1;
    }
    const auto it =
        std::ranges::find(*profiles, profile_name, &application::Profile::name);
    if (it == profiles->end()) {
        print_error_line(i18n::tr(i18n::Key::WizardProfileNotFound));
        return 1;
    }
    if (it->key_storage == application::KeyStorage::Memory) {
        print_error_line(i18n::format(
            i18n::Key::WizardKeyStorageMemoryNoPersist, profile_name));
        return 1;
    }
    application::ProfileCredentials creds =
        [&]() -> application::ProfileCredentials {
        if (const char* env = std::getenv("KASUMI_MASTER_KEY")) {
            return application::MasterKeyHex{std::string(env)};
        }
        return credentials::read_password_pair();
    }();
    if (platform::cancellation::requested()) {
        application::wipe_credentials(creds);
        return 130;
    }
    return apply_profile_key_update(environment, profile_name, creds, true);
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
            if (first == std::string::npos) {
                return default_mode;
            }
            const auto last = mode.find_last_not_of(" \t\r\n");
            mode = mode.substr(first, last - first + 1);
            std::ranges::transform(mode, mode.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            for (const auto storage : {application::KeyStorage::Vault,
                                       application::KeyStorage::File,
                                       application::KeyStorage::Memory}) {
                if (mode == application::to_string(storage)) {
                    return storage;
                }
            }
            print_error_line(i18n::tr(i18n::Key::WizardInvalidKeyStorage));
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
                              new_local) ||
                !prompt_field(i18n::tr(i18n::Key::WizardPromptRemotePath),
                              application::ProfileField::RemotePath,
                              new_remote)) {
                continue;
            }
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
                                    edit_local) ||
                    !prompt_default(i18n::Key::WizardPromptNewRemotePath,
                                    it->remote_dir,
                                    edit_remote)) {
                    continue;
                }

                application::Profile updated{
                    target,
                    platform::path::from_utf8(edit_local),
                    edit_remote,
                    it->min_history_depth,
                    it->min_history_age_hours,
                    it->key_storage};
                if (updated.local_dir == it->local_dir &&
                    updated.remote_dir == it->remote_dir) {
                    continue;
                }
                if (!confirm_change(
                        i18n::format(i18n::Key::WizardConfirmEdit,
                                     target,
                                     platform::path::to_utf8(it->local_dir),
                                     edit_local,
                                     it->remote_dir,
                                     edit_remote))) {
                    continue;
                }
                report_result(
                    application::update_profile(environment, updated),
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

} // namespace kasumi::cli
