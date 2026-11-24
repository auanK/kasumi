#ifndef KASUMI_CLI_PARSER_HPP
#define KASUMI_CLI_PARSER_HPP

#include "application/inspection/request.hpp"
#include "application/profile.hpp"
#include "application/request.hpp"
#include "cli/completion.hpp"

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace kasumi::cli {

// Requests opening the interactive configuration wizard.
struct ConfigureInvocation {};
struct OverviewInvocation {};
struct ListInvocation {};
struct ShowInvocation {
    std::string profile_name;
};
struct LogsInvocation {
    std::optional<std::string> profile_name;
    std::size_t log_lines = 50;
    bool follow = false;
};
struct StartInvocation {
    bool autostart = false;
};
struct StopInvocation {};
struct ProfileToggleInvocation {
    bool pause = true;
    bool all = false;
    std::optional<std::string> profile_name;
};
struct DiagnosticsInvocation {
    std::string profile_name;
};
struct KeyInvocation {
    std::string profile_name;
    bool replace = false;
};
struct ConflictsInvocation {
    std::string profile_name;
    bool resolve = false;
    std::string canonical_path;
    application::ConflictResolutionChoice choice =
        application::ConflictResolutionChoice::KeepCanonical;
    std::string artifact_selector;
    bool dry_run = false;
};
struct CompletionInvocation {
    CompletionShell shell = CompletionShell::Bash;
};
enum class ProfileAction {
    Create,
    Edit,
    Clone,
    Storage,
    Rename,
    Delete,
    Test,
};
struct ProfileInvocation {
    ProfileAction action = ProfileAction::Create;
    std::string profile_name;
    std::optional<std::string> target_name;
    std::optional<std::string> local_dir;
    std::optional<std::string> remote_dir;
    std::optional<application::KeyStorage> key_storage;
    std::optional<std::uint32_t> min_history_depth;
    std::optional<std::uint32_t> min_history_age_hours;
    std::optional<std::string> bandwidth_limit;
    bool clear_bandwidth_limit = false;
    std::optional<std::uint32_t> transfer_concurrency;
    bool clear_transfer_concurrency = false;
    std::optional<std::string> rclone_config;
    bool clear_rclone_config = false;
    std::optional<bool> watch_enabled;
    bool clear_watch_enabled = false;
    std::optional<std::uint32_t> sync_interval_seconds;
    bool clear_sync_interval_seconds = false;
    std::optional<std::uint32_t> gc_interval_hours;
    bool clear_gc_interval_hours = false;
    std::optional<bool> paused;
    bool verify = false;
    bool allow_empty_local = false;
    bool confirm = false;
};
enum class DaemonAction {
    Run,
    Stop,
    Status,
    Sync,
    Pause,
    Resume,
    Unlock,
    Lock,
    Reload,
    Logs,
    AutostartInstall,
    AutostartUninstall,
    AutostartStatus,
};
struct DaemonInvocation {
    DaemonAction action = DaemonAction::Status;
    std::optional<std::string> profile_name;
    bool background = false;
    bool wait = false;
    bool follow = false;
    std::size_t log_lines = 50;
};
enum class IgnoreAction {
    Check,
    Init,
};
struct IgnoreInvocation {
    IgnoreAction action = IgnoreAction::Check;
    std::string profile_name;
    std::vector<std::string> paths;
    application::IgnorePreset preset = application::IgnorePreset::Default;
    bool force = false;
    bool dry_run = false;
};
struct HelpInvocation {
    std::string topic;
    bool all = false;
};

// Valid command-line parsing result.
using Invocation = std::variant<application::Request,
                                application::InspectionRequest,
                                OverviewInvocation,
                                ConfigureInvocation,
                                ListInvocation,
                                ShowInvocation,
                                LogsInvocation,
                                StartInvocation,
                                StopInvocation,
                                ProfileToggleInvocation,
                                DiagnosticsInvocation,
                                KeyInvocation,
                                ConflictsInvocation,
                                CompletionInvocation,
                                ProfileInvocation,
                                DaemonInvocation,
                                IgnoreInvocation,
                                HelpInvocation>;

// Command-line argument parsing failure.
struct ParseError {
    // Exit code returned to the operating system.
    int exit_code = 1;
    bool unsupported_sync_audit_combination = false;
    bool unsupported_sync_repair_combination = false;
};

// Parses command-line arguments into an application invocation.
std::expected<Invocation, ParseError> parse(int argc, char* argv[]);

// Closest recognized command for Help and parse-error guidance.
std::string help_topic(int argc, char* argv[]);

} // namespace kasumi::cli

#endif
