#include "cli/app.hpp"

#include "application/environment.hpp"
#include "application/execute.hpp"
#include "application/inspection/inspect.hpp"
#include "cli/credentials.hpp"
#include "cli/i18n.hpp"
#include "cli/json_presenter.hpp"
#include "cli/log_file.hpp"
#include "cli/parser.hpp"
#include "cli/presenter.hpp"
#include "cli/wizard.hpp"
#include "platform/cancellation.hpp"
#include "platform/path.hpp"

#include <array>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <filesystem>
#include <format>
#include <mutex>
#include <optional>
#include <print>
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

class CommandProgress {
public:
    explicit CommandProgress(bool full = false,
                             kasumi::platform::Terminal terminal =
                                 kasumi::platform::stdout_terminal())
        : display_(terminal, full) {
        if (!terminal.interactive) {
            return;
        }
        try {
            ticker_ = std::jthread([this](std::stop_token stop) {
                std::unique_lock lock(mutex_);
                while (!stop.stop_requested()) {
                    wake_.wait_for(lock, stop, std::chrono::seconds(1), [] {
                        return false;
                    });
                    if (!stop.stop_requested()) {
                        display_.heartbeat();
                    }
                }
            });
        } catch (...) {
        }
    }

    void update(const kasumi::application::ExecutionProgress& progress,
                kasumi::application::Operation operation =
                    kasumi::application::Operation::Sync) {
        std::lock_guard lock(mutex_);
        display_.update(progress, operation);
    }

    void finish(bool keep) noexcept {
        ticker_ = {};
        display_.finish(keep);
    }

private:
    kasumi::cli::ProgressDisplay display_;
    std::mutex mutex_;
    std::condition_variable_any wake_;
    std::jthread ticker_;
};

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
    const std::string_view cmd =
        sanitized.size() > 1 ? std::string_view{sanitized[1]}
                             : std::string_view{};
    const bool has_profile_arg = sanitized.size() > 2 &&
                                 !sanitized[2].empty() &&
                                 sanitized[2].front() != '-';
    const bool is_gc_sub_kw =
        cmd == "gc" && sanitized.size() > 2 &&
        (sanitized[2] == "remove-writer" || sanitized[2] == "remove-barrier");
    const bool is_gc_subcommand = is_gc_sub_kw && sanitized.size() > 3 &&
                                  !sanitized[3].empty() &&
                                  sanitized[3].front() != '-';
    const bool is_remote_sub = cmd == "remote" && sanitized.size() > 3 &&
                               !sanitized[3].empty() &&
                               sanitized[3].front() != '-';
    const bool supports_command_full =
        has_profile_arg && (cmd == "sync" || cmd == "status" ||
                            cmd == "repack" || cmd == "show");
    const bool supports_remote_summary_full =
        is_remote_sub && sanitized[2] == "summary";
    const bool supports_full =
        supports_command_full || supports_remote_summary_full;
    const std::size_t full_start_index =
        supports_remote_summary_full ? 4U : 3U;

    const bool supports_quiet =
        cmd == "list" || cmd == "diagnostics" ||
        (has_profile_arg &&
         (cmd == "show" || cmd == "sync" || cmd == "status" ||
          cmd == "fsck" || cmd == "repack" || cmd == "resolve-missing" ||
          (cmd == "gc" && !is_gc_sub_kw))) ||
        is_gc_subcommand || is_remote_sub;
    const std::size_t quiet_start_index =
        (cmd == "list" || (cmd == "diagnostics" && !has_profile_arg))
            ? 2U
            : ((is_gc_subcommand || is_remote_sub) ? 4U : 3U);

    const bool supports_json =
        cmd == "list" || cmd == "diagnostics" ||
        (has_profile_arg &&
         (cmd == "show" || cmd == "sync" || cmd == "status" ||
          cmd == "fsck" || cmd == "repack" || cmd == "resolve-missing" ||
          (cmd == "gc" && !is_gc_sub_kw))) ||
        supports_remote_summary_full;
    const std::size_t json_start_index =
        (cmd == "list" || (cmd == "diagnostics" && !has_profile_arg))
            ? 2U
            : (supports_remote_summary_full ? 4U : 3U);

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

    if (no_args) {
        present_help({});
        return 1;
    }

    if (is_version) {
        std::print("kasumi version {}\n", KASUMI_VERSION);
        return 0;
    }
    auto parse_result = parse(effective_argc, effective_argv);
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
        return present_help(help->topic);
    }

    const std::string_view log_command_label =
        cmd.empty() ? std::string_view{"kasumi"} : cmd;
    if (log_file.has_value()) {
        if (const auto valid = validate_log_file_path(*log_file); !valid) {
            if (json) {
                const std::string_view err_profile =
                    (is_gc_subcommand || is_remote_sub)
                        ? std::string_view{sanitized[3]}
                        : (has_profile_arg ? std::string_view{sanitized[2]}
                                           : std::string_view{});
                return present_json_io_error(
                    log_command_label, err_profile, valid.error());
            }
            std::println(
                stderr, "{} {}", i18n::tr(i18n::Key::LabelError), valid.error());
            return 1;
        }
    }
    const ScopedJsonLogFile scoped_json_log(json ? log_file : std::nullopt);
    const auto log_text_result = [&](std::string_view command_name,
                                     int exit_code,
                                     std::string_view summary) -> int {
        if (!json && log_file.has_value()) {
            (void)append_text_log_entry(
                *log_file, command_name, exit_code, summary);
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

    if (std::holds_alternative<ListInvocation>(*parse_result)) {
        const int code = run_profile_query(environment, {}, false, json);
        return json ? code
                    : log_text_result(
                          "list", code, code == 0 ? "completed" : "failed");
    }
    if (const auto* show = std::get_if<ShowInvocation>(&*parse_result)) {
        const int code =
            run_profile_query(environment, show->profile_name, full, json);
        return json ? code
                    : log_text_result("show", code, show->profile_name);
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
            return log_text_result("diagnostics", 1, report.error().detail);
        }
        if (json) {
            return present_json_diagnostics(
                *report, KASUMI_VERSION, diag->profile_name, elapsed());
        }
        const int code = finish(present(*report, KASUMI_VERSION, quiet));
        return log_text_result(
            "diagnostics",
            code,
            report->overall_ok ? "overall=ok" : "overall=issues");
    }

    if (std::holds_alternative<ConfigureInvocation>(*parse_result)) {
        const int code = run_config_wizard(environment);
        return code == 130
                   ? present_cancellation(application::Operation::Preview)
                   : code;
    }
    if (const auto* key_inv = std::get_if<KeyInvocation>(&*parse_result)) {
        const int code = run_profile_key(environment, key_inv->profile_name);
        return code == 130
                   ? present_cancellation(application::Operation::Preview)
                   : code;
    }
    if (std::holds_alternative<application::InspectionRequest>(*parse_result)) {
        auto request = std::get<application::InspectionRequest>(*parse_result);
        auto creds =
            credentials::for_profile(environment, request.profile_name);
        if (platform::cancellation::requested()) {
            application::wipe_credentials(creds);
            if (json) {
                return present_json_cancellation("remote summary",
                                                 request.profile_name);
            }
            return log_text_result(
                "remote",
                finish(present_cancellation(application::Operation::Preview)),
                "cancelled");
        }
        std::optional<CommandProgress> display;
        application::ProgressCallback on_progress;
        if (!quiet && !json) {
            display.emplace(full);
            on_progress = [&](const auto& progress) {
                display->update(progress);
            };
        }
        auto result = application::inspect({
            .request = request,
            .credentials = std::move(creds),
            .environment = environment,
            .on_progress = std::move(on_progress),
        });
        if (display) {
            display->finish(result.has_value() &&
                            !platform::cancellation::requested());
        }
        application::wipe_credentials(creds);

        if (platform::cancellation::requested()) {
            if (json) {
                return present_json_cancellation("remote summary",
                                                 request.profile_name);
            }
            return log_text_result(
                "remote",
                finish(present_cancellation(application::Operation::Preview)),
                "cancelled");
        }

        if (result) {
            if (json) {
                return present_json(
                    request.profile_name, *result, elapsed(), full);
            }
            return log_text_result(
                "remote", finish(present(*result, full)), request.profile_name);
        }
        if (json) {
            return present_json(
                request.profile_name, result.error(), elapsed());
        }
        return log_text_result(
            "remote", finish(present(result.error())), result.error().detail);
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
                    : log_text_result(
                          log_command_label,
                          finish(present_cancellation(request.operation)),
                          "cancelled");
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
                preview_display->update(progress, operation);
            };
        }
        auto preview_res = application::execute({
            .request = preview_request,
            .credentials = std::move(preview_creds),
            .environment = environment,
            .on_progress = std::move(on_preview_progress),
        });
        if (preview_display) {
            preview_display->finish(preview_res.has_value() &&
                                    !platform::cancellation::requested());
        }
        application::wipe_credentials(preview_creds);

        if (platform::cancellation::requested()) {
            return json ? cancel_json()
                        : log_text_result(
                              "resolve-missing",
                              finish(present_cancellation(request.operation)),
                              "cancelled");
        }
        if (!preview_res) {
            return json
                       ? present_json(
                             request.profile_name, preview_res.error(), elapsed())
                       : log_text_result(
                             "resolve-missing",
                             finish(present(preview_res.error())),
                             preview_res.error().detail);
        }
        const auto* preview_data =
            std::get_if<application::ResolveMissingCompleted>(&preview_res->data);
        if (preview_data == nullptr || preview_data->resolved_paths.empty()) {
            return json
                       ? present_json(
                             request.profile_name, *preview_res, elapsed(), full)
                       : log_text_result(
                             "resolve-missing",
                             finish(present(*preview_res, full, quiet)),
                             request.profile_name);
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
        if (!prompt_confirmation(i18n::format(
                i18n::Key::ResolveMissingConfirmPrompt,
                preview_data->resolved_paths.size()))) {
            if (platform::cancellation::requested()) {
                return log_text_result(
                    "resolve-missing",
                    finish(present_cancellation(request.operation)),
                    "cancelled");
            }
            print_error_line(i18n::tr(i18n::Key::ResolveMissingCancelled));
            return log_text_result(
                "resolve-missing", finish(1), "cancelled");
        }
    }

    std::optional<CommandProgress> display;
    application::ProgressCallback on_progress;
    if (reports_progress) {
        display.emplace(full);
        on_progress = [operation = request.operation,
                       &display](const auto& progress) {
            display->update(progress, operation);
        };
    }
    auto result = application::execute({.request = request,
                                        .credentials = std::move(creds),
                                        .environment = environment,
                                        .on_progress = std::move(on_progress)});
    if (display) {
        display->finish(result.has_value() &&
                        !platform::cancellation::requested());
    }

    if (platform::cancellation::requested()) {
        return json ? cancel_json()
                    : log_text_result(
                          log_command_label,
                          finish(present_cancellation(request.operation)),
                          "cancelled");
    }

    if (result) {
        if (json) {
            return present_json(
                request.profile_name, *result, elapsed(), full);
        }
        const int code = finish(present(*result, full, quiet));
        const std::string summary = std::format(
            "profile={} {}",
            request.profile_name,
            code == 0 ? "ok" : "partial");
        return log_text_result(log_command_label, code, summary);
    } else {
        if (json) {
            return present_json(
                request.profile_name, result.error(), elapsed());
        }
        const int code = finish(present(result.error()));
        const std::string summary = std::format(
            "profile={} error={}",
            request.profile_name,
            result.error().detail);
        return log_text_result(log_command_label, code, summary);
    }
}

} // namespace kasumi::cli
