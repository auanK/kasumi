#include "cli/app.hpp"

#include "application/environment.hpp"
#include "application/execute.hpp"
#include "application/inspection/inspect.hpp"
#include "cli/credentials.hpp"
#include "cli/i18n.hpp"
#include "cli/parser.hpp"
#include "cli/presenter.hpp"
#include "cli/update.hpp"
#include "cli/wizard.hpp"
#include "platform/cancellation.hpp"

#include <csignal>
#include <print>
#include <string>
#include <string_view>
#include <vector>

namespace {

void request_cancellation(int) {
    kasumi::platform::cancellation::request();
}

} // namespace

namespace kasumi::cli {

int run(int argc, char* argv[]) {
    if (argc >= 2 && argv != nullptr && argv[1] != nullptr &&
        std::string_view{argv[1]}.starts_with("--kasumi-update-")) {
        return update::run(argc, argv);
    }
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
    const bool supports_full =
        sanitized.size() > 2 && !sanitized[2].empty() &&
        sanitized[2].front() != '-' &&
        (sanitized[1] == "sync" || sanitized[1] == "status");
    bool full = false;
    bool invalid_options = false;
    std::vector<std::string> without_full;
    for (std::size_t index = 0; index < sanitized.size(); ++index) {
        const auto& argument = sanitized[index];
        if (supports_full && index >= 3 && argument == "--full") {
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
        i18n::init_language(argc, argv);
        return present_parse_error(help_topic(effective_argc, effective_argv));
    }

    const bool no_args = argc == 1;
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

    platform::cancellation::reset();
    std::signal(SIGINT, request_cancellation);
    std::signal(SIGTERM, request_cancellation);

    if (std::holds_alternative<UpdateInvocation>(*parse_result)) {
        return update::run(effective_argc, effective_argv);
    }

    const auto environment = application::default_execution_environment();

    if (std::holds_alternative<ConfigureInvocation>(*parse_result)) {
        run_config_wizard(environment);
        return platform::cancellation::requested() ? 130 : 0;
    }
    if (std::holds_alternative<application::InspectionRequest>(*parse_result)) {
        auto request = std::get<application::InspectionRequest>(*parse_result);
        const auto run_remote = [&](application::Credentials credentials) {
            application::InspectionInput input{
                .request = request,
                .credentials = std::move(credentials),
                .environment = environment,
            };
            return request.operation ==
                           application::InspectionOperation::RemoteGet
                       ? application::read_remote_file(std::move(input))
                       : application::inspect(std::move(input));
        };
        auto initial_credentials = credentials::from_environment();
        auto result = run_remote(std::move(initial_credentials));
        application::wipe_credentials(initial_credentials);

        if (platform::cancellation::requested()) {
            return present_cancellation(application::Operation::Preview);
        }

        if (result) {
            return present(*result);
        }
        return present(result.error());
    }

    auto request = std::get<application::Request>(*parse_result);
    if (request.operation == application::Operation::RemoveWriter) {
        std::println("{} {}",
                     i18n::tr(i18n::Key::LabelWarning),
                     i18n::tr(i18n::Key::ManualWriterRemovalWarning));
    }
    if (request.operation == application::Operation::RemoveBarrier) {
        std::println("{} {}",
                     i18n::tr(i18n::Key::LabelWarning),
                     i18n::tr(i18n::Key::ManualBarrierRemovalWarning));
    }
    auto initial_credentials = credentials::from_environment();

    application::ProgressCallback on_progress{};
    FsckProgressDisplayState fsck_display_state;
    GarbageCollectProgressDisplayState gc_display_state;
    if (request.operation == application::Operation::Sync) {
        std::println(
            "{}", i18n::format(i18n::Key::SyncStarting, request.profile_name));
        on_progress = [](const application::ExecutionProgress& progress) {
            if (const auto* sync =
                    std::get_if<application::SyncProgress>(&progress)) {
                present(*sync, application::Operation::Sync);
            }
        };
    } else if (request.operation == application::Operation::Preview) {
        std::println(
            "{}",
            i18n::format(i18n::Key::PreviewStarting, request.profile_name));
        on_progress = [](const application::ExecutionProgress& progress) {
            if (const auto* sync =
                    std::get_if<application::SyncProgress>(&progress)) {
                present(*sync, application::Operation::Preview);
            }
        };
    } else if (request.operation == application::Operation::Status) {
        std::println(
            "{}",
            i18n::format(i18n::Key::StatusStarting, request.profile_name));
        on_progress = [](const application::ExecutionProgress& progress) {
            if (const auto* sync =
                    std::get_if<application::SyncProgress>(&progress)) {
                present(*sync, application::Operation::Status);
            }
        };
    } else if (request.operation == application::Operation::Fsck) {
        std::println(
            "{}", i18n::format(i18n::Key::FsckStarting, request.profile_name));
        on_progress = [&fsck_display_state](
                          const application::ExecutionProgress& progress) {
            if (const auto* fsck =
                    std::get_if<application::FsckProgress>(&progress)) {
                present(*fsck, fsck_display_state);
            }
        };
    } else if (request.operation == application::Operation::GarbageCollect) {
        std::println("{}",
                     i18n::format(i18n::Key::GcStarting, request.profile_name));
        on_progress = [&gc_display_state](
                          const application::ExecutionProgress& progress) {
            if (const auto* gc =
                    std::get_if<application::GarbageCollectProgress>(
                        &progress)) {
                present(*gc, gc_display_state);
            }
        };
    }

    auto result =
        application::execute({.request = request,
                              .credentials = std::move(initial_credentials),
                              .environment = environment,
                              .on_progress = std::move(on_progress)});
    application::wipe_credentials(initial_credentials);

    if (platform::cancellation::requested()) {
        return present_cancellation(request.operation);
    }

    if (result) {
        return present(*result, full);
    } else {
        return present(result.error());
    }
}

} // namespace kasumi::cli
