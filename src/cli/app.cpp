#include "cli/app.hpp"

#include "application/daemon.hpp"
#include "application/environment.hpp"
#include "application/execute.hpp"
#include "application/inspection/inspect.hpp"
#include "cli/completion.hpp"
#include "cli/credentials.hpp"
#include "cli/i18n.hpp"
#include "cli/json_presenter.hpp"
#include "cli/log_file.hpp"
#include "cli/parser.hpp"
#include "cli/presenter.hpp"
#include "cli/wizard.hpp"
#include "platform/cancellation.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <mutex>
#include <optional>
#include <print>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <atomic>
#include <windows.h>
#else
#include <signal.h>
#endif

namespace {

struct CommandProgress {
    explicit CommandProgress(bool full = false,
                             kasumi::platform::Terminal terminal =
                                 kasumi::platform::stdout_terminal())
        : display(terminal, full) {
        if (!terminal.interactive) {
            return;
        }
        try {
            ticker = std::jthread([this](std::stop_token stop) {
                std::unique_lock lock(mutex);
                while (!stop.stop_requested()) {
                    wake.wait_for(lock, stop, std::chrono::seconds(1), [] {
                        return false;
                    });
                    if (!stop.stop_requested()) {
                        kasumi::cli::heartbeat_progress_display(display);
                    }
                }
            });
        } catch (...) {
        }
    }

    kasumi::cli::ProgressDisplay display;
    std::mutex mutex;
    std::condition_variable_any wake;
    std::jthread ticker;
};

void update_command_progress(
    CommandProgress& cmd,
    const kasumi::application::ExecutionProgress& progress,
    kasumi::application::Operation operation =
        kasumi::application::Operation::Sync) {
    std::lock_guard lock(cmd.mutex);
    kasumi::cli::update_progress_display(cmd.display, progress, operation);
}

void finish_command_progress(CommandProgress& cmd, bool keep) noexcept {
    cmd.ticker = {};
    kasumi::cli::finish_progress_display(cmd.display, keep);
}

void request_cancellation(int signal_number) {
    kasumi::platform::cancellation::request();
#ifdef _WIN32
    std::signal(signal_number, request_cancellation);
#else
    static_cast<void>(signal_number);
#endif
}

#ifdef _WIN32
std::atomic<DWORD> console_thread_id{};

BOOL WINAPI handle_console_control(DWORD event) noexcept {
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT &&
        event != CTRL_CLOSE_EVENT) {
        return FALSE;
    }
    kasumi::platform::cancellation::request();
    // Wake an interactive prompt without interrupting writes to other handles.
    const auto input = GetStdHandle(STD_INPUT_HANDLE);
    if (input != nullptr && input != INVALID_HANDLE_VALUE) {
        CancelIoEx(input, nullptr);
    }
    if (event == CTRL_CLOSE_EVENT) {
        // Windows terminates the process once the close handler returns.
        const auto thread =
            OpenThread(SYNCHRONIZE,
                       FALSE,
                       console_thread_id.load(std::memory_order_relaxed));
        if (thread != nullptr) {
            WaitForSingleObject(thread, 4000);
            CloseHandle(thread);
        }
    }
    return TRUE;
}

struct ConsoleCancellation {
    bool installed = false;

    ConsoleCancellation() noexcept {
        console_thread_id.store(GetCurrentThreadId(),
                                std::memory_order_relaxed);
        installed = SetConsoleCtrlHandler(handle_console_control, TRUE) != 0;
        if (installed) {
            SetConsoleCtrlHandler(nullptr, FALSE);
        }
        std::signal(SIGINT, request_cancellation);
    }

    ~ConsoleCancellation() {
        if (installed) {
            SetConsoleCtrlHandler(handle_console_control, FALSE);
        }
    }
};
#endif

} // namespace

namespace kasumi::cli {

int run(int argc, char* argv[]) {
    if (argc < 1 || argv == nullptr) {
        i18n::set_language(i18n::Language::English);
        return present_parse_error({});
    }
    for (int index = 0; index < argc; ++index) {
        if (argv[index] == nullptr) {
            i18n::init_language(0, nullptr);
            return present_parse_error({});
        }
    }
    i18n::init_language(argc, argv);
    const auto sanitized = i18n::extract_language_argument(argc, argv);
    bool is_bare_overview = false;
    {
        bool only_overview_flags = true;
        for (std::size_t idx = 1; idx < sanitized.size(); ++idx) {
            const std::string_view a = sanitized[idx];
            if (a == "--") {
                only_overview_flags = false;
                break;
            }
            if (a == "--full" || a == "--quiet" || a == "--json") {
                continue;
            }
            if (a.starts_with("--log-file=")) {
                continue;
            }
            if (a == "--log-file" && idx + 1 < sanitized.size()) {
                ++idx;
                continue;
            }
            only_overview_flags = false;
            break;
        }
        is_bare_overview = only_overview_flags;
    }
    const std::string_view cmd = sanitized.size() > 1
                                     ? std::string_view{sanitized[1]}
                                     : std::string_view{};
    const bool has_profile_arg = sanitized.size() > 2 &&
                                 !sanitized[2].empty() &&
                                 sanitized[2].front() != '-';
    const bool is_bare_status = cmd == "status" && !has_profile_arg;
    const bool is_logs_cmd = cmd == "logs";
    const bool is_start_cmd = cmd == "start";
    const bool is_stop_cmd = cmd == "stop";
    const bool is_toggle_cmd = cmd == "pause" || cmd == "resume";
    const bool is_gc_sub_kw =
        cmd == "gc" && sanitized.size() > 2 &&
        (sanitized[2] == "remove-writer" || sanitized[2] == "remove-barrier");
    const bool is_gc_subcommand = is_gc_sub_kw && sanitized.size() > 3 &&
                                  !sanitized[3].empty() &&
                                  sanitized[3].front() != '-';
    const bool is_profile_sub_kw =
        cmd == "profile" && sanitized.size() > 2 &&
        (sanitized[2] == "create" || sanitized[2] == "edit" ||
         sanitized[2] == "clone" || sanitized[2] == "storage" ||
         sanitized[2] == "rename" || sanitized[2] == "delete" ||
         sanitized[2] == "test");
    const bool is_profile_subcommand =
        is_profile_sub_kw && sanitized.size() > 3 && !sanitized[3].empty() &&
        sanitized[3].front() != '-';
    const bool is_ignore_sub_kw =
        cmd == "ignore" && sanitized.size() > 2 &&
        (sanitized[2] == "check" || sanitized[2] == "init");
    const bool is_ignore_subcommand =
        is_ignore_sub_kw && sanitized.size() > 3 && !sanitized[3].empty() &&
        sanitized[3].front() != '-';
    const bool is_conflicts_sub_kw =
        cmd == "conflicts" && sanitized.size() > 2 && sanitized[2] == "resolve";
    const bool is_conflicts_subcommand =
        is_conflicts_sub_kw && sanitized.size() > 3 && !sanitized[3].empty() &&
        sanitized[3].front() != '-';
    const bool is_remote_sub = cmd == "remote" && sanitized.size() > 3 &&
                               !sanitized[3].empty() &&
                               sanitized[3].front() != '-';
    const bool is_daemon_sub =
        cmd == "daemon" && sanitized.size() > 2 && !sanitized[2].empty() &&
        sanitized[2].front() != '-' &&
        !(sanitized[2] == "autostart" && sanitized.size() < 4);
    const bool is_daemon_profile_arg =
        is_daemon_sub && sanitized.size() > 3 && !sanitized[3].empty() &&
        sanitized[3].front() != '-' && sanitized[2] != "autostart" &&
        sanitized[2] != "run";
    const bool supports_daemon_full =
        is_daemon_sub &&
        (sanitized[2] == "status" || sanitized[2] == "logs");
    const bool supports_command_full =
        (has_profile_arg &&
         (cmd == "sync" || cmd == "status" || cmd == "repack" ||
          cmd == "show")) ||
        cmd == "list" || is_bare_overview || is_bare_status || is_logs_cmd ||
        is_start_cmd;
    const bool supports_remote_full =
        is_remote_sub && (sanitized[2] == "summary" || sanitized[2] == "log");
    const bool supports_full =
        supports_command_full || supports_remote_full || supports_daemon_full;
    const std::size_t full_start_index =
        is_bare_overview
            ? 1U
            : ((cmd == "list" || is_bare_status || is_logs_cmd ||
                is_start_cmd)
                   ? 2U
                   : (supports_remote_full ? 4U : 3U));

    const bool supports_quiet =
        is_bare_overview || is_bare_status || is_logs_cmd || is_start_cmd ||
        is_stop_cmd || is_toggle_cmd || cmd == "list" ||
        cmd == "diagnostics" ||
        (has_profile_arg &&
         (cmd == "show" || cmd == "key" || cmd == "sync" || cmd == "status" ||
          cmd == "fsck" || cmd == "repack" || cmd == "resolve-missing" ||
          (cmd == "conflicts" && !is_conflicts_sub_kw) ||
          (cmd == "gc" && !is_gc_sub_kw))) ||
        is_gc_subcommand || is_profile_subcommand || is_ignore_subcommand ||
        is_conflicts_subcommand || is_remote_sub || is_daemon_sub;
    const std::size_t quiet_start_index =
        is_bare_overview
            ? 1U
            : ((cmd == "list" || (cmd == "diagnostics" && !has_profile_arg) ||
                is_bare_status || is_logs_cmd || is_start_cmd || is_stop_cmd)
                   ? 2U
                   : ((is_gc_subcommand || is_profile_subcommand ||
                       is_ignore_subcommand || is_conflicts_subcommand ||
                       is_remote_sub)
                          ? 4U
                          : 3U));

    const bool supports_remote_summary_or_writers =
        is_remote_sub &&
        (sanitized[2] == "summary" || sanitized[2] == "writers" ||
         sanitized[2] == "stat" || sanitized[2] == "get" ||
         sanitized[2] == "log" || sanitized[2] == "restore");
    const bool supports_gc_remove_barrier =
        is_gc_subcommand && sanitized[2] == "remove-barrier";

    const bool supports_json =
        is_bare_overview || is_bare_status || is_logs_cmd || is_start_cmd ||
        is_stop_cmd || is_toggle_cmd || cmd == "list" ||
        cmd == "diagnostics" ||
        (has_profile_arg &&
         (cmd == "show" || cmd == "key" || cmd == "sync" || cmd == "status" ||
          cmd == "fsck" || cmd == "repack" || cmd == "resolve-missing" ||
          (cmd == "conflicts" && !is_conflicts_sub_kw) ||
          (cmd == "gc" && !is_gc_sub_kw))) ||
        is_profile_subcommand || is_ignore_subcommand ||
        is_conflicts_subcommand || supports_remote_summary_or_writers ||
        supports_gc_remove_barrier || is_daemon_sub;
    const std::size_t json_start_index =
        is_bare_overview
            ? 1U
            : ((cmd == "list" || (cmd == "diagnostics" && !has_profile_arg) ||
                is_bare_status || is_logs_cmd || is_start_cmd || is_stop_cmd)
                   ? 2U
                   : ((is_profile_subcommand || is_ignore_subcommand ||
                       is_conflicts_subcommand ||
                       supports_remote_summary_or_writers ||
                       supports_gc_remove_barrier)
                          ? 4U
                          : 3U));

    std::size_t delimiter_index = sanitized.size();
    for (std::size_t index = 1; index < sanitized.size(); ++index) {
        if (sanitized[index] == "--") {
            delimiter_index = index;
            break;
        }
    }

    bool saw_json_flag = false;
    for (std::size_t index = 1; index < delimiter_index; ++index) {
        if (sanitized[index] == "--json") {
            saw_json_flag = true;
            break;
        }
    }

    bool full = false;
    bool quiet = false;
    bool json = false;
    bool invalid_options = false;
    std::optional<std::filesystem::path> log_file;
    std::vector<std::string> without_cli_flags;
    for (std::size_t index = 0; index < sanitized.size(); ++index) {
        const auto& argument = sanitized[index];
        if (index < delimiter_index && supports_full &&
            index >= full_start_index && argument == "--full") {
            invalid_options |= full;
            full = true;
        } else if (index < delimiter_index && supports_quiet &&
                   index >= quiet_start_index && argument == "--quiet") {
            invalid_options |= quiet;
            quiet = true;
        } else if (index < delimiter_index && supports_json &&
                   index >= json_start_index && argument == "--json") {
            invalid_options |= json;
            json = true;
        } else if (index < delimiter_index && supports_quiet &&
                   index >= quiet_start_index &&
                   (argument == "--log-file" ||
                    argument.starts_with("--log-file="))) {
            if (log_file.has_value()) {
                invalid_options = true;
                continue;
            }
            std::string_view value;
            if (argument == "--log-file") {
                if (index + 1 >= delimiter_index) {
                    invalid_options = true;
                    continue;
                }
                value = sanitized[index + 1];
                if (value == "--help" || value == "-h") {
                    invalid_options = true;
                    continue;
                }
                ++index;
            } else {
                value = std::string_view{argument}.substr(
                    std::string_view{"--log-file="}.size());
            }
            if (value.empty()) {
                invalid_options = true;
            } else {
                log_file = platform::path::from_utf8(value);
            }
        } else {
            without_cli_flags.push_back(argument);
        }
    }
    std::vector<char*> sanitized_ptrs;
    sanitized_ptrs.reserve(without_cli_flags.size());
    for (const auto& s : without_cli_flags) {
        sanitized_ptrs.push_back(const_cast<char*>(s.c_str()));
    }
    const int effective_argc = static_cast<int>(sanitized_ptrs.size());
    char** effective_argv = sanitized_ptrs.data();
    const auto topic_on_error = [&] {
        return help_topic(effective_argc, effective_argv);
    };
    const auto json_cmd_on_error = [&]() -> std::string_view {
        const auto topic = topic_on_error();
        return topic.empty() ? cmd : std::string_view{};
    };
    if (invalid_options) {
        if (saw_json_flag) {
            const auto topic = topic_on_error();
            return present_json_parse_error(
                topic.empty() ? cmd : std::string_view{topic},
                "invalid arguments or duplicate options");
        }
        return present_parse_error(topic_on_error());
    }

    const bool no_args = effective_argc == 1;
    const bool is_version =
        effective_argc == 2 && effective_argv != nullptr &&
        effective_argv[1] != nullptr &&
        (std::string_view{effective_argv[1]} == "--version" ||
         std::string_view{effective_argv[1]} == "-v");

    if (is_version) {
        std::print("kasumi version {}\n", KASUMI_VERSION);
        return 0;
    }
    std::expected<Invocation, ParseError> parse_result =
        no_args ? std::expected<Invocation, ParseError>{OverviewInvocation{}}
                : parse(effective_argc, effective_argv);
    if (!parse_result) {
        if (saw_json_flag) {
            const auto topic = topic_on_error();
            const std::string_view err_cmd =
                !topic.empty() ? std::string_view{topic} : json_cmd_on_error();
            const std::string_view detail =
                parse_result.error().unsupported_sync_audit_combination
                    ? "--audit-inventory cannot be combined with --dry-run or "
                      "--initial"
                : parse_result.error().unsupported_sync_repair_combination
                    ? "--repair cannot be combined with --dry-run or --initial"
                    : "invalid arguments or options";
            return present_json_parse_error(err_cmd, detail);
        }
        if (parse_result.error().unsupported_sync_audit_combination) {
            std::println(
                stderr, "{}", i18n::tr(i18n::Key::ErrorSyncAuditCombination));
        } else if (parse_result.error().unsupported_sync_repair_combination) {
            std::println(
                stderr, "{}", i18n::tr(i18n::Key::ErrorSyncRepairCombination));
        }
        present_parse_error(topic_on_error());
        return parse_result.error().exit_code;
    }
    if (const auto* help = std::get_if<HelpInvocation>(&*parse_result)) {
        return present_help(help->topic, help->all);
    }
    if (const auto* completion =
            std::get_if<CompletionInvocation>(&*parse_result)) {
        std::print("{}", generate_completion_script(completion->shell));
        return 0;
    }

    std::string log_command_storage;
    if (is_daemon_sub) {
        if (sanitized[2] == "autostart" && sanitized.size() > 3 &&
            !sanitized[3].empty() && sanitized[3].front() != '-') {
            log_command_storage =
                std::format("daemon autostart {}", sanitized[3]);
        } else {
            log_command_storage = std::format("daemon {}", sanitized[2]);
        }
    }
    const std::string_view log_command_label =
        !log_command_storage.empty()
            ? std::string_view{log_command_storage}
            : (cmd.empty() ? std::string_view{"kasumi"} : cmd);
    if (log_file.has_value()) {
        if (const auto valid = validate_log_file_path(*log_file); !valid) {
            if (json) {
                const std::string_view err_profile =
                    (is_gc_subcommand || is_profile_subcommand ||
                     is_ignore_subcommand || is_conflicts_subcommand ||
                     is_remote_sub || is_daemon_profile_arg)
                        ? std::string_view{sanitized[3]}
                        : ((!is_daemon_sub && has_profile_arg)
                               ? std::string_view{sanitized[2]}
                               : std::string_view{});
                return present_json_io_error(
                    log_command_label, err_profile, valid.error());
            }
            std::println(stderr,
                         "{} {}",
                         i18n::tr(i18n::Key::LabelError),
                         valid.error());
            return 1;
        }
    }
    const ScopedJsonLogFile scoped_json_log(json ? log_file : std::nullopt);
    const auto log_text_entry = [&](const TextLogEntry& entry,
                                    int exit_code) -> int {
        if (!json && log_file.has_value()) {
            (void)append_text_log_entry(*log_file, entry);
        }
        return exit_code;
    };

    const auto started = std::chrono::steady_clock::now();
    const auto elapsed = [&] {
        return std::chrono::steady_clock::now() - started;
    };
    const auto finish = [&](int code) {
        if (!quiet && !json) {
            present_duration(elapsed());
        }
        return code;
    };
    platform::cancellation::reset();
#ifdef _WIN32
    const ConsoleCancellation console_cancellation;
    std::signal(SIGTERM, request_cancellation);
#else
    struct sigaction action{};
    action.sa_handler = request_cancellation;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGINT, &action, nullptr);
    sigaction(SIGTERM, &action, nullptr);
#endif

    const auto environment = application::default_execution_environment();

    if (std::holds_alternative<OverviewInvocation>(*parse_result)) {
        const int code =
            run_overview_command(environment, full, quiet, json);
        return json ? code
                    : log_text_entry(
                          {.status = code == 0 ? "OK" : "ERROR",
                           .command = "status",
                           .summary = code == 0 ? "completed" : "failed"},
                          code);
    }

    const auto run_logs_common =
        [&](std::string_view log_cmd_name,
            const std::optional<std::string>& profile_name,
            std::size_t log_lines,
            bool follow) -> int {
        const std::size_t query_limit =
            full ? log_lines
                 : (std::min<std::size_t>)(log_lines * 5U, std::size_t{1000});
        const auto initial = application::query_daemon_events(
            environment,
            application::DaemonLogQuery{
                .profile_name = profile_name,
                .max_lines = query_limit,
            });
        if (!initial) {
            if (json) {
                return present_json_daemon_error(
                    log_cmd_name,
                    profile_name.value_or(std::string{}),
                    initial.error(),
                    elapsed());
            }
            return log_text_entry(
                {.status = "ERROR",
                 .command = log_cmd_name,
                 .profile = profile_name.value_or(std::string{}),
                 .summary = std::format("[{}] {}",
                                        json_error_code(initial.error().code),
                                        initial.error().detail),
                 .duration = elapsed()},
                finish(present(initial.error())));
        }

        application::DaemonLogsReport trimmed = *initial;
        if (!full) {
            std::vector<application::DaemonEvent> filtered;
            filtered.reserve(trimmed.events.size());
            for (const auto& ev : trimmed.events) {
                if (!is_noisy_daemon_event(ev)) {
                    filtered.push_back(ev);
                }
            }
            if (filtered.size() > log_lines) {
                filtered.erase(
                    filtered.begin(),
                    filtered.begin() +
                        static_cast<std::ptrdiff_t>(filtered.size() -
                                                    log_lines));
            }
            trimmed.events = std::move(filtered);
        }

        if (!follow) {
            if (json) {
                return present_json_daemon_logs(
                    trimmed, profile_name, elapsed(), log_cmd_name, full);
            }
            const int code = finish(present(trimmed, full, quiet));
            return log_text_entry(
                {.status = "OK",
                 .command = log_cmd_name,
                 .profile = profile_name.value_or(std::string{}),
                 .summary = std::format("events={}, latest_seq={}",
                                        trimmed.events.size(),
                                        trimmed.latest_seq),
                 .duration = elapsed()},
                code);
        }

        if (json) {
            for (const auto& ev : trimmed.events) {
                present_json_daemon_stream_event(ev);
            }
            std::fflush(stdout);
        } else if (!quiet) {
            present(trimmed, full, quiet);
        }

        if (!application::is_daemon_running(environment)) {
            if (!quiet && !json) {
                i18n::println(i18n::Key::DaemonLogsStoppedFollowHint);
            }
            return 0;
        }
        if (!quiet && !json) {
            i18n::println(i18n::Key::DaemonLogsFollowing);
            std::fflush(stdout);
        }

        std::uint64_t last_seq = initial->latest_seq;
        while (!platform::cancellation::requested()) {
            for (int tick = 0;
                 tick < 7 && !platform::cancellation::requested();
                 ++tick) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            if (platform::cancellation::requested()) {
                break;
            }
            if (!application::is_daemon_running(environment)) {
                if (!quiet && !json) {
                    i18n::println(i18n::Key::DaemonLogsStoppedDuringFollow);
                }
                return 0;
            }
            const auto next = application::query_daemon_events(
                environment,
                application::DaemonLogQuery{
                    .profile_name = profile_name,
                    .max_lines = 200U,
                    .since_seq = last_seq,
                });
            if (!next) {
                if (!application::is_daemon_running(environment)) {
                    if (!quiet && !json) {
                        i18n::println(i18n::Key::DaemonLogsStoppedDuringFollow);
                    }
                    return 0;
                }
                if (json) {
                    return present_json_daemon_error(
                        log_cmd_name,
                        profile_name.value_or(std::string{}),
                        next.error(),
                        elapsed());
                }
                return present(next.error());
            }
            last_seq = (std::max)(last_seq, next->latest_seq);
            for (const auto& ev : next->events) {
                if (!full && is_noisy_daemon_event(ev)) {
                    continue;
                }
                if (json) {
                    present_json_daemon_stream_event(ev);
                } else if (!quiet) {
                    print_daemon_event_line(ev);
                }
                std::fflush(stdout);
            }
        }
        return platform::cancellation::requested() ? 130 : 0;
    };

    if (const auto* logs_inv = std::get_if<LogsInvocation>(&*parse_result)) {
        return run_logs_common("logs",
                               logs_inv->profile_name,
                               logs_inv->log_lines,
                               logs_inv->follow);
    }
    if (const auto* start_inv = std::get_if<StartInvocation>(&*parse_result)) {
        if (start_inv->autostart) {
            const auto auto_res = application::install_daemon_autostart();
            if (!auto_res) {
                if (json) {
                    return present_json_daemon_error(
                        "start", "", auto_res.error(), elapsed());
                }
                return finish(present(auto_res.error()));
            }
            if (!quiet && !json && auto_res->supported) {
                print_ok_line(
                    i18n::format(i18n::Key::DaemonAutostartInstalled,
                                 sanitize_terminal_text(auto_res->method),
                                 sanitize_terminal_text(auto_res->location)));
            }
        }
        const bool already_running =
            application::is_daemon_running(environment);
        application::DaemonStatusReport report;
        if (already_running) {
            const auto st = application::query_daemon_status(environment);
            if (!st) {
                if (json) {
                    return present_json_daemon_error(
                        "start", "", st.error(), elapsed());
                }
                return finish(present(st.error()));
            }
            report = *st;
            if (json) {
                return present_json_daemon_status("start", report, elapsed());
            }
            if (!quiet) {
                print_ok_line(i18n::tr(i18n::Key::DaemonAlreadyRunning));
            }
        } else {
            const auto bg =
                application::spawn_background_daemon(environment, log_file);
            if (!bg) {
                if (json) {
                    return present_json_daemon_error(
                        "start", "", bg.error(), elapsed());
                }
                return finish(present(bg.error()));
            }
            report = *bg;
            if (json) {
                return present_json_daemon_status("start", report, elapsed());
            }
            if (!quiet) {
                if (full) {
                    print_ok_line(i18n::format(
                        i18n::Key::DaemonBackgroundStarted,
                        report.pid,
                        report.ipc_port));
                } else {
                    print_ok_line(i18n::tr(i18n::Key::DaemonStartedCompact));
                }
            }
        }
        if (!quiet && !json && !report.profiles.empty() &&
            std::ranges::all_of(report.profiles,
                                &application::DaemonProfileStatus::paused)) {
            i18n::println(i18n::Key::DaemonAllPausedHint);
        }
        return log_text_entry(
            {.status = "OK",
             .command = "start",
             .summary = format_compact_summary(report),
             .duration = elapsed()},
            finish(0));
    }
    if (std::holds_alternative<StopInvocation>(*parse_result)) {
        if (!application::is_daemon_running(environment)) {
            if (json) {
                return present_json_daemon_action(
                    "stop", "", "daemon already stopped", elapsed());
            }
            if (!quiet) {
                print_ok_line(i18n::tr(i18n::Key::DaemonAlreadyStopped));
            }
            return log_text_entry({.status = "OK",
                                   .command = "stop",
                                   .summary = "daemon already stopped",
                                   .duration = elapsed()},
                                  finish(0));
        }
        const auto stopped = application::stop_running_daemon(environment);
        if (!stopped) {
            if (json) {
                return present_json_daemon_error(
                    "stop", "", stopped.error(), elapsed());
            }
            return finish(present(stopped.error()));
        }
        if (json) {
            return present_json_daemon_action(
                "stop", "", "daemon stopped", elapsed());
        }
        if (!quiet) {
            print_ok_line(i18n::tr(i18n::Key::DaemonStopped));
        }
        return log_text_entry({.status = "OK",
                               .command = "stop",
                               .summary = "daemon stopped",
                               .duration = elapsed()},
                              finish(0));
    }
    if (const auto* toggle_inv =
            std::get_if<ProfileToggleInvocation>(&*parse_result)) {
        std::string summary;
        const int code = run_profile_toggle_command(
            environment, *toggle_inv, quiet, json, &summary);
        const std::string_view cmd_lbl =
            toggle_inv->pause ? "pause" : "resume";
        const std::string prof_lbl =
            toggle_inv->all ? std::string{"--all"}
                            : toggle_inv->profile_name.value_or("");
        return json ? code
                    : log_text_entry(
                          {.status = code == 0 ? "OK" : "ERROR",
                           .command = cmd_lbl,
                           .profile = prof_lbl,
                           .summary = summary,
                           .duration = elapsed()},
                          finish(code));
    }

    if (std::holds_alternative<ListInvocation>(*parse_result)) {
        const int code = run_profile_query(environment, {}, full, json);
        return json ? code
                    : log_text_entry(
                          {.status = code == 0 ? "OK" : "ERROR",
                           .command = "list",
                           .summary = code == 0 ? "completed" : "failed"},
                          code);
    }
    if (const auto* show = std::get_if<ShowInvocation>(&*parse_result)) {
        const int code =
            run_profile_query(environment, show->profile_name, full, json);
        return json ? code
                    : log_text_entry(
                          {.status = code == 0 ? "OK" : "ERROR",
                           .command = "show",
                           .profile = show->profile_name,
                           .summary = code == 0 ? "completed" : "failed"},
                          code);
    }
    if (const auto* diag = std::get_if<DiagnosticsInvocation>(&*parse_result)) {
        auto report =
            application::collect_diagnostics(environment, diag->profile_name);
        if (!report) {
            if (json) {
                return present_json_profile_error(
                    "diagnostics", diag->profile_name, report.error());
            }
            print_error_line(report.error().detail);
            const auto summary =
                std::format("[{}] {}",
                            json_error_code(report.error().code),
                            report.error().detail);
            return log_text_entry({.status = "ERROR",
                                   .command = "diagnostics",
                                   .profile = diag->profile_name,
                                   .summary = summary},
                                  1);
        }
        if (json) {
            return present_json_diagnostics(
                *report, KASUMI_VERSION, diag->profile_name, elapsed());
        }
        const int code = finish(present(*report, KASUMI_VERSION, quiet));
        const auto summary = format_compact_summary(*report);
        std::vector<std::string> details;
        for (const auto& entry : report->profiles) {
            if (!entry.healthy && !entry.detail.empty()) {
                details.push_back(
                    std::format("{}: {}", entry.profile.name, entry.detail));
            }
        }
        return log_text_entry({.status = report->overall_ok ? "OK" : "WARN",
                               .command = "diagnostics",
                               .profile = diag->profile_name,
                               .summary = summary,
                               .duration = elapsed(),
                               .detail_lines = std::move(details)},
                              code);
    }

    if (std::holds_alternative<ConfigureInvocation>(*parse_result)) {
        const int code = run_config_wizard(environment);
        return code == 130
                   ? present_cancellation(application::Operation::Preview)
                   : code;
    }
    const auto complete_wizard_command = [&](std::string_view command_label,
                                             std::string_view profile_name,
                                             std::string_view summary,
                                             int code) -> int {
        if (code == 130) {
            if (json) {
                return present_json_cancellation(command_label, profile_name);
            }
            const int exit_code =
                finish(present_cancellation(application::Operation::Preview));
            return log_text_entry({.status = "CANCELLED",
                                   .command = command_label,
                                   .profile = profile_name,
                                   .summary = "cancelled",
                                   .duration = elapsed()},
                                  exit_code);
        }
        if (json) {
            return code;
        }
        const int exit_code = finish(code);
        return log_text_entry(
            {.status = exit_code == 0 ? "OK" : "ERROR",
             .command = command_label,
             .profile = profile_name,
             .summary = summary.empty()
                            ? (exit_code == 0 ? "completed" : "failed")
                            : summary,
             .duration = elapsed()},
            exit_code);
    };

    if (const auto* key_inv = std::get_if<KeyInvocation>(&*parse_result)) {
        std::string summary;
        const int code = run_profile_key(environment,
                                         key_inv->profile_name,
                                         key_inv->replace,
                                         quiet,
                                         json,
                                         &summary);
        return complete_wizard_command(
            "key", key_inv->profile_name, summary, code);
    }
    if (const auto* prof_inv = std::get_if<ProfileInvocation>(&*parse_result)) {
        std::string summary;
        const int code =
            run_profile_command(environment, *prof_inv, quiet, json, &summary);
        const std::string prof_cmd =
            is_profile_subcommand ? std::format("profile {}", sanitized[2])
                                  : std::string{"profile"};
        return complete_wizard_command(
            prof_cmd, prof_inv->profile_name, summary, code);
    }
    if (const auto* daemon_inv =
            std::get_if<DaemonInvocation>(&*parse_result)) {
        const auto daemon_cmd_label = [&]() -> std::string {
            switch (daemon_inv->action) {
                case DaemonAction::Run:
                    return "daemon run";
                case DaemonAction::Stop:
                    return "daemon stop";
                case DaemonAction::Status:
                    return "daemon status";
                case DaemonAction::Sync:
                    return "daemon sync";
                case DaemonAction::Pause:
                    return "daemon pause";
                case DaemonAction::Resume:
                    return "daemon resume";
                case DaemonAction::Unlock:
                    return "daemon unlock";
                case DaemonAction::Lock:
                    return "daemon lock";
                case DaemonAction::Reload:
                    return "daemon reload";
                case DaemonAction::Logs:
                    return "daemon logs";
                case DaemonAction::AutostartInstall:
                    return "daemon autostart install";
                case DaemonAction::AutostartUninstall:
                    return "daemon autostart uninstall";
                case DaemonAction::AutostartStatus:
                    return "daemon autostart status";
            }
            return "daemon";
        };
        const std::string cmd_str = daemon_cmd_label();
        const std::string prof_str = daemon_inv->profile_name.value_or("");
        const auto fail_daemon = [&](const application::DaemonError& err) {
            if (json) {
                return present_json_daemon_error(
                    cmd_str, prof_str, err, elapsed());
            }
            return log_text_entry(
                {.status = "ERROR",
                 .command = cmd_str,
                 .profile = prof_str,
                 .summary = std::format(
                     "[{}] {}", json_error_code(err.code), err.detail),
                 .duration = elapsed()},
                finish(present(err)));
        };
        const auto ok_action = [&](i18n::Key msg_key, std::string summary) {
            if (json) {
                return present_json_daemon_action(
                    cmd_str, prof_str, summary, elapsed());
            }
            if (!quiet) {
                if (prof_str.empty()) {
                    print_ok_line(i18n::tr(msg_key));
                } else {
                    print_ok_line(i18n::format(
                        msg_key, sanitize_terminal_text(prof_str)));
                }
            }
            return log_text_entry({.status = "OK",
                                   .command = cmd_str,
                                   .profile = prof_str,
                                   .summary = std::move(summary),
                                   .duration = elapsed()},
                                  finish(0));
        };

        switch (daemon_inv->action) {
            case DaemonAction::Run: {
                if (daemon_inv->background) {
                    const auto bg = application::spawn_background_daemon(
                        environment, log_file);
                    if (!bg) {
                        return fail_daemon(bg.error());
                    }
                    if (json) {
                        return present_json_daemon_status(
                            cmd_str, *bg, elapsed());
                    }
                    if (!quiet) {
                        print_ok_line(
                            i18n::format(i18n::Key::DaemonBackgroundStarted,
                                         bg->pid,
                                         bg->ipc_port));
                    }
                    return log_text_entry(
                        {.status = "OK",
                         .command = cmd_str,
                         .profile = "",
                         .summary = format_compact_summary(*bg),
                         .duration = elapsed()},
                        finish(0));
                }
                application::DaemonOptions opts;
                std::mutex event_mu;
                opts.on_event = [&](const application::DaemonEvent& ev) {
                    std::lock_guard lock(event_mu);
                    const std::string line =
                        ev.profile_name.empty()
                            ? std::format("[daemon] {}: {}", ev.kind, ev.detail)
                            : std::format("[{}] {}: {}",
                                          ev.profile_name,
                                          ev.kind,
                                          ev.detail);
                    if (log_file.has_value()) {
                        if (json) {
                            append_json_daemon_event(*log_file, ev);
                        } else {
                            (void)append_text_log_entry(
                                *log_file,
                                {.status = "INFO",
                                 .command = cmd_str,
                                 .profile = ev.profile_name,
                                 .summary = line,
                                 .duration = elapsed()});
                        }
                    }
                    if (!quiet && !json) {
                        std::println("{}", sanitize_terminal_text(line));
                    }
                };
                if (!quiet && !json) {
                    print_ok_line(i18n::tr(i18n::Key::DaemonStarting));
                }
                std::stop_source stop_source;
                std::jthread cancel_bridge([&](std::stop_token token) {
                    while (!token.stop_requested()) {
                        if (platform::cancellation::requested()) {
                            stop_source.request_stop();
                            break;
                        }
                        std::this_thread::sleep_for(
                            std::chrono::milliseconds(50));
                    }
                });
                const auto run_res = application::run_daemon(
                    environment, std::move(opts), stop_source.get_token());
                cancel_bridge.request_stop();
                cancel_bridge = {};
                if (!run_res) {
                    return fail_daemon(run_res.error());
                }
                return ok_action(i18n::Key::DaemonStopped, "daemon stopped");
            }
            case DaemonAction::Stop: {
                const auto stopped =
                    application::stop_running_daemon(environment);
                if (!stopped) {
                    return fail_daemon(stopped.error());
                }
                return ok_action(i18n::Key::DaemonStopped, "daemon stopped");
            }
            case DaemonAction::Reload: {
                const auto reloaded =
                    application::reload_running_daemon(environment);
                if (!reloaded) {
                    return fail_daemon(reloaded.error());
                }
                return ok_action(i18n::Key::DaemonReloaded, "daemon reloaded");
            }
            case DaemonAction::Status: {
                const std::optional<std::string_view> filter =
                    daemon_inv->profile_name
                        ? std::optional<std::string_view>{*daemon_inv
                                                               ->profile_name}
                        : std::nullopt;
                const auto st =
                    application::query_daemon_status(environment, filter);
                if (!st) {
                    return fail_daemon(st.error());
                }
                if (json) {
                    return present_json_daemon_status(
                        cmd_str, *st, elapsed(), filter);
                }
                const int code = finish(present(*st, full, quiet));
                return log_text_entry({.status = "OK",
                                       .command = cmd_str,
                                       .profile = prof_str,
                                       .summary = format_compact_summary(*st),
                                       .duration = elapsed()},
                                      code);
            }
            case DaemonAction::Sync: {
                const std::optional<std::string_view> filter =
                    daemon_inv->profile_name
                        ? std::optional<std::string_view>{*daemon_inv
                                                               ->profile_name}
                        : std::nullopt;
                const auto triggered = application::trigger_daemon_sync(
                    environment, filter, daemon_inv->wait);
                if (!triggered) {
                    return fail_daemon(triggered.error());
                }
                if (json) {
                    return present_json_daemon_sync(
                        *triggered, filter, daemon_inv->wait, elapsed());
                }
                const int code =
                    finish(present(*triggered, daemon_inv->wait, quiet));
                return log_text_entry(
                    {.status = code == 0 ? "OK" : "ERROR",
                     .command = cmd_str,
                     .profile = prof_str,
                     .summary = std::format("profiles={}, failures={}",
                                            triggered->profiles.size(),
                                            triggered->failures.size()),
                     .duration = elapsed()},
                    code);
            }
            case DaemonAction::Pause: {
                const auto res =
                    application::pause_daemon_profile(environment, prof_str);
                if (!res) {
                    return fail_daemon(res.error());
                }
                return ok_action(i18n::Key::DaemonProfilePaused,
                                 std::format("paused profile '{}'", prof_str));
            }
            case DaemonAction::Resume: {
                const auto res =
                    application::resume_daemon_profile(environment, prof_str);
                if (!res) {
                    return fail_daemon(res.error());
                }
                return ok_action(i18n::Key::DaemonProfileResumed,
                                 std::format("resumed profile '{}'", prof_str));
            }
            case DaemonAction::Lock: {
                const auto res =
                    application::lock_daemon_profile(environment, prof_str);
                if (!res) {
                    return fail_daemon(res.error());
                }
                return ok_action(i18n::Key::DaemonProfileLocked,
                                 std::format("locked profile '{}'", prof_str));
            }
            case DaemonAction::Unlock: {
                std::optional<application::ProfileCredentials> profile_creds;
                const char* master_env = std::getenv("KASUMI_MASTER_KEY");
                const char* pw_env = std::getenv("KASUMI_PASSWORD");
                const char* salt_env = std::getenv("KASUMI_PASSWORD2");
                if (master_env != nullptr && master_env[0] != '\0') {
                    profile_creds =
                        application::MasterKeyHex{std::string{master_env}};
                } else if (pw_env != nullptr && salt_env != nullptr) {
                    profile_creds = application::PasswordPair{
                        std::string{pw_env}, std::string{salt_env}};
                } else if (json || quiet) {
                    if (json) {
                        return present_json_credentials_required(
                            cmd_str,
                            prof_str,
                            i18n::tr(
                                i18n::Key::WizardProfileCredentialsRequired),
                            elapsed());
                    }
                    print_error_line(
                        i18n::tr(i18n::Key::WizardProfileCredentialsRequired));
                    return log_text_entry(
                        {.status = "ERROR",
                         .command = cmd_str,
                         .profile = prof_str,
                         .summary = "[credentials_required] missing env",
                         .duration = elapsed()},
                        finish(1));
                } else {
                    auto pw = credentials::read_secret(
                        "KASUMI_PASSWORD",
                        std::string{i18n::tr(i18n::Key::PromptPassword)});
                    auto salt =
                        platform::cancellation::requested()
                            ? std::string{}
                            : credentials::read_secret(
                                  "KASUMI_PASSWORD2",
                                  std::string{i18n::tr(i18n::Key::PromptSalt)});
                    if (platform::cancellation::requested()) {
                        application::ProfileCredentials cancelled_creds =
                            application::PasswordPair{std::move(pw),
                                                      std::move(salt)};
                        application::wipe_credentials(cancelled_creds);
                        const int code =
                            json ? present_json_cancellation(cmd_str, prof_str)
                                 : present_cancellation(
                                       application::Operation::Sync);
                        return log_text_entry(
                            {.status = "CANCELLED",
                             .command = cmd_str,
                             .profile = prof_str,
                             .summary = "operation cancelled by user",
                             .duration = elapsed()},
                            code);
                    }
                    profile_creds = application::PasswordPair{std::move(pw),
                                                              std::move(salt)};
                }
                const auto unlocked = application::unlock_daemon_profile(
                    environment, prof_str, std::move(*profile_creds));
                application::wipe_credentials(*profile_creds);
                if (!unlocked) {
                    return fail_daemon(unlocked.error());
                }
                return ok_action(
                    i18n::Key::DaemonProfileUnlocked,
                    std::format("unlocked profile '{}'", prof_str));
            }
            case DaemonAction::Logs: {
                return run_logs_common(cmd_str,
                                       daemon_inv->profile_name,
                                       daemon_inv->log_lines,
                                       daemon_inv->follow);
            }
            case DaemonAction::AutostartInstall:
            case DaemonAction::AutostartUninstall:
            case DaemonAction::AutostartStatus: {
                const auto res =
                    daemon_inv->action == DaemonAction::AutostartInstall
                        ? application::install_daemon_autostart()
                    : daemon_inv->action == DaemonAction::AutostartUninstall
                        ? application::uninstall_daemon_autostart()
                        : application::query_daemon_autostart();
                if (!res) {
                    return fail_daemon(res.error());
                }
                if (json) {
                    return present_json_daemon_autostart(
                        cmd_str, *res, elapsed());
                }
                int code = 0;
                if (daemon_inv->action == DaemonAction::AutostartInstall &&
                    res->supported && !quiet) {
                    print_ok_line(
                        i18n::format(i18n::Key::DaemonAutostartInstalled,
                                     sanitize_terminal_text(res->method),
                                     sanitize_terminal_text(res->location)));
                    code = finish(0);
                } else if (daemon_inv->action ==
                               DaemonAction::AutostartUninstall &&
                           res->supported && !quiet) {
                    print_ok_line(
                        i18n::format(i18n::Key::DaemonAutostartUninstalled,
                                     sanitize_terminal_text(res->method)));
                    code = finish(0);
                } else {
                    code = finish(present(*res, quiet));
                }
                return log_text_entry({.status = "OK",
                                       .command = cmd_str,
                                       .profile = "",
                                       .summary = format_compact_summary(*res),
                                       .duration = elapsed()},
                                      code);
            }
        }
        return 1;
    }
    if (const auto* ign_inv = std::get_if<IgnoreInvocation>(&*parse_result)) {
        std::string summary;
        const int code =
            run_ignore_command(environment, *ign_inv, quiet, json, &summary);
        const std::string ign_cmd = is_ignore_subcommand
                                        ? std::format("ignore {}", sanitized[2])
                                        : std::string{"ignore"};
        return complete_wizard_command(
            ign_cmd, ign_inv->profile_name, summary, code);
    }
    if (const auto* conflicts =
            std::get_if<ConflictsInvocation>(&*parse_result)) {
        if (conflicts->resolve) {
            const application::ResolveConflictRequest req{
                .profile_name = conflicts->profile_name,
                .canonical_path = conflicts->canonical_path,
                .choice = conflicts->choice,
                .artifact_selector = conflicts->artifact_selector,
                .dry_run = conflicts->dry_run,
            };
            auto resolved =
                application::resolve_local_conflict(environment, req);
            if (!resolved) {
                if (json) {
                    return present_json_profile_error("conflicts resolve",
                                                      conflicts->profile_name,
                                                      resolved.error(),
                                                      elapsed());
                }
                print_error_line(resolved.error().detail);
                const auto summary =
                    std::format("[{}] {}",
                                json_error_code(resolved.error().code),
                                resolved.error().detail);
                const std::string_view status =
                    resolved.error().code ==
                            application::ProfileErrorCode::LockFailure
                        ? "LOCKED"
                        : "ERROR";
                return log_text_entry({.status = status,
                                       .command = "conflicts resolve",
                                       .profile = conflicts->profile_name,
                                       .summary = summary,
                                       .duration = elapsed()},
                                      finish(1));
            }
            if (json) {
                return present_json_conflict_resolved(*resolved, elapsed());
            }
            const int code = finish(present(*resolved, quiet));
            const auto summary = format_compact_summary(*resolved);
            return log_text_entry({.status = "OK",
                                   .command = "conflicts resolve",
                                   .profile = conflicts->profile_name,
                                   .summary = summary,
                                   .duration = elapsed()},
                                  code);
        }
        auto report = application::list_local_conflicts(
            environment, conflicts->profile_name);
        if (!report) {
            if (json) {
                return present_json_profile_error("conflicts",
                                                  conflicts->profile_name,
                                                  report.error(),
                                                  elapsed());
            }
            print_error_line(report.error().detail);
            const auto summary =
                std::format("[{}] {}",
                            json_error_code(report.error().code),
                            report.error().detail);
            return log_text_entry({.status = "ERROR",
                                   .command = "conflicts",
                                   .profile = conflicts->profile_name,
                                   .summary = summary,
                                   .duration = elapsed()},
                                  finish(1));
        }
        if (json) {
            return present_json_conflicts(*report, elapsed());
        }
        const int code = finish(present(*report, quiet));
        const auto summary = format_compact_summary(*report);
        return log_text_entry({.status = "OK",
                               .command = "conflicts",
                               .profile = conflicts->profile_name,
                               .summary = summary,
                               .duration = elapsed()},
                              code);
    }
    if (std::holds_alternative<application::InspectionRequest>(*parse_result)) {
        auto request = std::get<application::InspectionRequest>(*parse_result);
        const std::string remote_cmd =
            sanitized.size() > 2 ? std::format("remote {}", sanitized[2])
                                 : std::string{"remote"};
        auto creds =
            credentials::for_profile(environment, request.profile_name);
        if (platform::cancellation::requested()) {
            application::wipe_credentials(creds);
            if (json) {
                return present_json_cancellation(remote_cmd,
                                                 request.profile_name);
            }
            const int code =
                finish(present_cancellation(application::Operation::Preview));
            return log_text_entry({.status = "CANCELLED",
                                   .command = remote_cmd,
                                   .profile = request.profile_name,
                                   .summary = "cancelled",
                                   .duration = elapsed()},
                                  code);
        }
        std::optional<CommandProgress> display;
        application::ProgressCallback on_progress;
        if (!quiet && !json) {
            display.emplace(full);
            on_progress = [&](const auto& progress) {
                update_command_progress(*display, progress);
            };
        }
        auto result = application::inspect({
            .request = request,
            .credentials = std::move(creds),
            .environment = environment,
            .on_progress = std::move(on_progress),
        });
        if (display) {
            finish_command_progress(*display,
                                    result.has_value() &&
                                        !platform::cancellation::requested());
        }
        application::wipe_credentials(creds);

        if (platform::cancellation::requested()) {
            if (json) {
                return present_json_cancellation(remote_cmd,
                                                 request.profile_name);
            }
            const int code =
                finish(present_cancellation(application::Operation::Preview));
            return log_text_entry({.status = "CANCELLED",
                                   .command = remote_cmd,
                                   .profile = request.profile_name,
                                   .summary = "cancelled",
                                   .duration = elapsed()},
                                  code);
        }

        if (result) {
            if (json) {
                return present_json(
                    request.profile_name, *result, elapsed(), full);
            }
            const int code = finish(present(*result, full));
            const auto summary = format_compact_summary(*result);
            return log_text_entry({.status = "OK",
                                   .command = remote_cmd,
                                   .profile = request.profile_name,
                                   .summary = summary,
                                   .duration = elapsed()},
                                  code);
        }
        if (json) {
            return present_json(
                request.profile_name, result.error(), elapsed());
        }
        const int code = finish(present(result.error()));
        const auto summary = std::format(
            "[{}] {}", json_error_code(result.error()), result.error().detail);
        return log_text_entry({.status = "ERROR",
                               .command = remote_cmd,
                               .profile = request.profile_name,
                               .summary = summary,
                               .duration = elapsed()},
                              code);
    }

    auto request = std::get<application::Request>(*parse_result);
    if (!quiet && !json &&
        (request.operation == application::Operation::RemoveWriter ||
         request.operation == application::Operation::RemoveBarrier)) {
        std::println(
            "{} {}",
            i18n::tr(i18n::Key::LabelWarning),
            i18n::tr(request.operation == application::Operation::RemoveWriter
                         ? i18n::Key::ManualWriterRemovalWarning
                         : i18n::Key::ManualBarrierRemovalWarning));
    }

    constexpr std::array<std::pair<application::Operation, i18n::Key>, 7>
        starting_keys{{
            {application::Operation::Sync, i18n::Key::SyncStarting},
            {application::Operation::Preview, i18n::Key::PreviewStarting},
            {application::Operation::Status, i18n::Key::StatusStarting},
            {application::Operation::Fsck, i18n::Key::FsckStarting},
            {application::Operation::GarbageCollect, i18n::Key::GcStarting},
            {application::Operation::ResolveMissing, i18n::Key::SyncStarting},
            {application::Operation::Repack, i18n::Key::RepackStarting},
        }};
    bool reports_progress = false;
    for (const auto& [op, key] : starting_keys) {
        if (op != request.operation) {
            continue;
        }
        if (!quiet && !json) {
            const auto display_key =
                (op == application::Operation::Repack && request.dry_run)
                    ? i18n::Key::RepackDryRunStarting
                : (op == application::Operation::GarbageCollect &&
                   request.dry_run)
                    ? i18n::Key::GcDryRunStarting
                : (op == application::Operation::ResolveMissing &&
                   request.dry_run)
                    ? i18n::Key::ResolveMissingDryRunStarting
                    : key;
            std::println("{}", i18n::format(display_key, request.profile_name));
        }
        reports_progress = !quiet && !json;
        break;
    }

    const std::string request_cmd = is_gc_subcommand
                                        ? std::format("gc {}", sanitized[2])
                                        : std::string{log_command_label};
    const auto log_request_cancelled = [&](std::string_view reason,
                                           int code) -> int {
        return log_text_entry({.status = "CANCELLED",
                               .command = request_cmd,
                               .profile = request.profile_name,
                               .summary = reason,
                               .duration = elapsed()},
                              code);
    };
    const auto log_request_error = [&](const application::Error& err,
                                       int code) -> int {
        const auto summary =
            std::format("[{}] {}", json_error_code(err), err.detail);
        return log_text_entry(
            {.status = err.lock_busy ? "LOCKED"
                                     : (err.remote_busy ? "BUSY" : "ERROR"),
             .command = request_cmd,
             .profile = request.profile_name,
             .summary = summary,
             .duration = elapsed()},
            code);
    };
    const auto log_request_response = [&](const application::Response& res,
                                          int code) -> int {
        std::vector<std::string> details;
        if (const auto* sync =
                std::get_if<application::SyncCompleted>(&res.data)) {
            for (const auto& p : sync->pending_paths) {
                details.push_back(platform::path::to_utf8(p));
            }
        } else if (const auto* plan =
                       std::get_if<application::PlanReport>(&res.data)) {
            for (const auto& p : plan->pending_paths) {
                details.push_back(platform::path::to_utf8(p));
            }
        }
        if (res.activity_publish_warning &&
            !res.activity_publish_warning->empty()) {
            details.push_back("warning: " + *res.activity_publish_warning);
        }
        const std::string_view status =
            code == 2 ? "PARTIAL"
                      : ((res.activity_publish_warning &&
                          !res.activity_publish_warning->empty())
                             ? "WARN"
                             : "OK");
        const auto summary = format_compact_summary(res);
        return log_text_entry({.status = status,
                               .command = request_cmd,
                               .profile = request.profile_name,
                               .summary = summary,
                               .duration = elapsed(),
                               .detail_lines = std::move(details)},
                              code);
    };

    const auto cancel_json = [&]() -> int {
        return present_json_cancellation(
            cmd.empty() ? std::string_view{"kasumi"} : cmd,
            request.profile_name);
    };

    auto creds = credentials::for_profile(environment, request.profile_name);
    struct CredentialsGuard {
        application::Credentials& value;
        ~CredentialsGuard() noexcept {
            application::wipe_credentials(value);
        }
    } creds_guard{creds};
    if (platform::cancellation::requested()) {
        return json ? cancel_json()
                    : log_request_cancelled(
                          "cancelled",
                          finish(present_cancellation(request.operation)));
    }

    if (request.operation == application::Operation::ResolveMissing &&
        !request.dry_run && !request.confirm) {
        auto preview_request = request;
        preview_request.dry_run = true;
        auto preview_creds = creds;
        std::optional<CommandProgress> preview_display;
        application::ProgressCallback on_preview_progress;
        if (reports_progress) {
            preview_display.emplace(full);
            on_preview_progress = [operation = request.operation,
                                   &preview_display](const auto& progress) {
                update_command_progress(*preview_display, progress, operation);
            };
        }
        auto preview_res = application::execute({
            .request = preview_request,
            .credentials = std::move(preview_creds),
            .environment = environment,
            .on_progress = std::move(on_preview_progress),
        });
        if (preview_display) {
            finish_command_progress(*preview_display,
                                    preview_res.has_value() &&
                                        !platform::cancellation::requested());
        }
        application::wipe_credentials(preview_creds);

        if (platform::cancellation::requested()) {
            return json ? cancel_json()
                        : log_request_cancelled(
                              "cancelled",
                              finish(present_cancellation(request.operation)));
        }
        if (!preview_res) {
            return json ? present_json(request.profile_name,
                                       preview_res.error(),
                                       elapsed())
                        : log_request_error(
                              preview_res.error(),
                              finish(present(preview_res.error())));
        }
        const auto* preview_data =
            std::get_if<application::ResolveMissingCompleted>(
                &preview_res->data);
        if (preview_data == nullptr || preview_data->resolved_paths.empty()) {
            return json ? present_json(request.profile_name,
                                       *preview_res,
                                       elapsed(),
                                       full)
                        : log_request_response(
                              *preview_res,
                              finish(present(*preview_res, full, quiet)));
        }
        if (json) {
            return present_json_confirmation_required(
                request.profile_name, *preview_data, elapsed());
        }
        i18n::println(i18n::Key::ResolveMissingConfirmHeader,
                      preview_data->resolved_paths.size());
        for (const auto& path : preview_data->resolved_paths) {
            std::println("  {}", sanitize_terminal_text(path));
        }
        if (!prompt_confirmation(
                i18n::format(i18n::Key::ResolveMissingConfirmPrompt,
                             preview_data->resolved_paths.size()))) {
            if (platform::cancellation::requested()) {
                return log_request_cancelled(
                    "cancelled",
                    finish(present_cancellation(request.operation)));
            }
            print_error_line(i18n::tr(i18n::Key::ResolveMissingCancelled));
            return log_request_cancelled("declined by user", finish(1));
        }
    }

    std::optional<CommandProgress> display;
    application::ProgressCallback on_progress;
    if (reports_progress) {
        display.emplace(full);
        on_progress = [operation = request.operation,
                       &display](const auto& progress) {
            update_command_progress(*display, progress, operation);
        };
    }
    auto result = application::execute({.request = request,
                                        .credentials = std::move(creds),
                                        .environment = environment,
                                        .on_progress = std::move(on_progress)});
    if (display) {
        finish_command_progress(*display,
                                result.has_value() &&
                                    !platform::cancellation::requested());
    }

    if (platform::cancellation::requested()) {
        return json ? cancel_json()
                    : log_request_cancelled(
                          "cancelled",
                          finish(present_cancellation(request.operation)));
    }

    if (result) {
        if (json) {
            return present_json(request.profile_name, *result, elapsed(), full);
        }
        return log_request_response(*result,
                                    finish(present(*result, full, quiet)));
    } else {
        if (json) {
            return present_json(
                request.profile_name, result.error(), elapsed());
        }
        return log_request_error(result.error(),
                                 finish(present(result.error())));
    }
}

} // namespace kasumi::cli
