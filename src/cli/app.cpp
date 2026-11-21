#include "cli/app.hpp"

#include "application/environment.hpp"
#include "application/execute.hpp"
#include "application/inspection/inspect.hpp"
#include "cli/credentials.hpp"
#include "cli/i18n.hpp"
#include "cli/parser.hpp"
#include "cli/presenter.hpp"
#include "cli/wizard.hpp"
#include "platform/cancellation.hpp"

#include <array>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <mutex>
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
    const bool supports_command_full =
        sanitized.size() > 2 && !sanitized[2].empty() &&
        sanitized[2].front() != '-' &&
        (sanitized[1] == "sync" || sanitized[1] == "status" ||
         sanitized[1] == "repack" || sanitized[1] == "show");
    const bool supports_remote_summary_full =
        sanitized.size() > 3 && sanitized[1] == "remote" &&
        sanitized[2] == "summary" && !sanitized[3].empty() &&
        sanitized[3].front() != '-';
    const bool supports_full =
        supports_command_full || supports_remote_summary_full;
    const std::size_t full_start_index =
        supports_remote_summary_full ? 4U : 3U;
    bool full = false;
    bool invalid_options = false;
    std::vector<std::string> without_full;
    for (std::size_t index = 0; index < sanitized.size(); ++index) {
        const auto& argument = sanitized[index];
        if (supports_full && index >= full_start_index &&
            argument == "--full") {
            invalid_options |= full;
            full = true;
        } else {
            without_full.push_back(argument);
        }
    }
    std::vector<char*> sanitized_ptrs;
    sanitized_ptrs.reserve(without_full.size());
    for (const auto& s : without_full) {
        sanitized_ptrs.push_back(const_cast<char*>(s.c_str()));
    }
    const int effective_argc = static_cast<int>(sanitized_ptrs.size());
    char** effective_argv = sanitized_ptrs.data();
    if (invalid_options) {
        return present_parse_error(help_topic(effective_argc, effective_argv));
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
        if (parse_result.error().unsupported_sync_audit_combination) {
            std::println(
                stderr, "{}", i18n::tr(i18n::Key::ErrorSyncAuditCombination));
        }
        present_parse_error(help_topic(effective_argc, effective_argv));
        return parse_result.error().exit_code;
    }
    if (const auto* help = std::get_if<HelpInvocation>(&*parse_result)) {
        return present_help(help->topic);
    }

    const auto started = std::chrono::steady_clock::now();
    const auto finish = [&](int code) {
        present_duration(std::chrono::steady_clock::now() - started);
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
        return run_profile_query(environment);
    }
    if (const auto* show = std::get_if<ShowInvocation>(&*parse_result)) {
        return run_profile_query(environment, show->profile_name, full);
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
            return finish(
                present_cancellation(application::Operation::Preview));
        }
        CommandProgress display;
        auto result = application::inspect({
            .request = request,
            .credentials = std::move(creds),
            .environment = environment,
            .on_progress =
                [&](const auto& progress) {
                    display.update(progress);
                },
        });
        display.finish(result.has_value() &&
                       !platform::cancellation::requested());
        application::wipe_credentials(creds);

        if (platform::cancellation::requested()) {
            return finish(
                present_cancellation(application::Operation::Preview));
        }

        if (result) {
            return finish(present(*result, full));
        }
        return finish(present(result.error()));
    }

    auto request = std::get<application::Request>(*parse_result);
    if (request.operation == application::Operation::RemoveWriter ||
        request.operation == application::Operation::RemoveBarrier) {
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
        const auto display_key =
            (op == application::Operation::Repack && request.dry_run)
                ? i18n::Key::RepackDryRunStarting
                : key;
        std::println("{}", i18n::format(display_key, request.profile_name));
        reports_progress = true;
        break;
    }

    auto creds = credentials::for_profile(environment, request.profile_name);
    if (platform::cancellation::requested()) {
        application::wipe_credentials(creds);
        return finish(present_cancellation(request.operation));
    }

    CommandProgress display(full);
    application::ProgressCallback on_progress;
    if (reports_progress) {
        on_progress = [operation = request.operation,
                       &display](const auto& progress) {
            display.update(progress, operation);
        };
    }
    auto result = application::execute({.request = request,
                                        .credentials = std::move(creds),
                                        .environment = environment,
                                        .on_progress = std::move(on_progress)});
    display.finish(result.has_value() && !platform::cancellation::requested());
    application::wipe_credentials(creds);

    if (platform::cancellation::requested()) {
        return finish(present_cancellation(request.operation));
    }

    if (result) {
        return finish(present(*result, full));
    } else {
        return finish(present(result.error()));
    }
}

} // namespace kasumi::cli
