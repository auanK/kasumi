#include "cli/parser.hpp"

#include "application/history_storage/remote_layout.hpp"
#include "cli/help_topics.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string_view>
#include <utility>

namespace kasumi::cli {
namespace {

bool operand(const char* value) {
    return value != nullptr && value[0] != '\0' && value[0] != '-';
}

bool literal_operand(const char* value) noexcept {
    return value != nullptr && value[0] != '\0';
}

struct PositionalsWithCommit {
    std::vector<std::string_view> positionals;
    std::optional<std::string> commit_id;
};

std::optional<std::uint32_t>
parse_bounded_u32(std::string_view value,
                  std::uint32_t min_value,
                  std::uint32_t max_value) noexcept {
    if (value.empty() || !std::ranges::all_of(value, [](char ch) {
            return ch >= '0' && ch <= '9';
        })) {
        return std::nullopt;
    }
    std::uint32_t parsed = 0;
    const auto [ptr, ec] =
        std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (ec != std::errc{} || ptr != value.data() + value.size() ||
        parsed < min_value || parsed > max_value) {
        return std::nullopt;
    }
    return parsed;
}

std::optional<application::KeyStorage>
parse_key_storage(std::string_view value) noexcept {
    if (value == "vault") {
        return application::KeyStorage::Vault;
    }
    if (value == "file") {
        return application::KeyStorage::File;
    }
    if (value == "memory") {
        return application::KeyStorage::Memory;
    }
    return std::nullopt;
}

struct FlagValue {
    std::string_view value;
    bool consumed_next = false;
};

std::optional<FlagValue>
read_flag_value(int index, int argc, char* argv[], std::string_view flag_name) {
    const std::string_view arg{argv[index]};
    if (arg == flag_name) {
        if (index + 1 >= argc || argv[index + 1] == nullptr ||
            argv[index + 1][0] == '\0') {
            return std::nullopt;
        }
        return FlagValue{.value = argv[index + 1], .consumed_next = true};
    }
    if (arg.starts_with(flag_name) && arg.size() > flag_name.size() &&
        arg[flag_name.size()] == '=') {
        const auto val = arg.substr(flag_name.size() + 1U);
        if (val.empty()) {
            return std::nullopt;
        }
        return FlagValue{.value = val, .consumed_next = false};
    }
    return std::nullopt;
}

enum class NetworkFlagMatch {
    NotMatched,
    Matched,
    Error,
};

NetworkFlagMatch
try_parse_network_flag(int& index,
                       int argc,
                       char* argv[],
                       std::optional<std::string>& bandwidth_limit,
                       bool& clear_bandwidth_limit,
                       std::optional<std::uint32_t>& transfer_concurrency,
                       bool& clear_transfer_concurrency,
                       bool allow_clear) {
    const std::string_view arg{argv[index]};
    if (arg == "--bwlimit" || arg.starts_with("--bwlimit=")) {
        if (bandwidth_limit.has_value() || clear_bandwidth_limit) {
            return NetworkFlagMatch::Error;
        }
        const auto val = read_flag_value(index, argc, argv, "--bwlimit");
        if (!val) {
            return NetworkFlagMatch::Error;
        }
        bandwidth_limit = std::string{val->value};
        if (val->consumed_next) {
            ++index;
        }
        return NetworkFlagMatch::Matched;
    }
    if (allow_clear && arg == "--clear-bwlimit") {
        if (bandwidth_limit.has_value() || clear_bandwidth_limit) {
            return NetworkFlagMatch::Error;
        }
        clear_bandwidth_limit = true;
        return NetworkFlagMatch::Matched;
    }
    if (arg == "--concurrency" || arg.starts_with("--concurrency=")) {
        if (transfer_concurrency.has_value() || clear_transfer_concurrency) {
            return NetworkFlagMatch::Error;
        }
        const auto val = read_flag_value(index, argc, argv, "--concurrency");
        if (!val) {
            return NetworkFlagMatch::Error;
        }
        const auto parsed = parse_bounded_u32(val->value, 1U, 16U);
        if (!parsed) {
            return NetworkFlagMatch::Error;
        }
        transfer_concurrency = *parsed;
        if (val->consumed_next) {
            ++index;
        }
        return NetworkFlagMatch::Matched;
    }
    if (allow_clear && arg == "--clear-concurrency") {
        if (transfer_concurrency.has_value() || clear_transfer_concurrency) {
            return NetworkFlagMatch::Error;
        }
        clear_transfer_concurrency = true;
        return NetworkFlagMatch::Matched;
    }
    return NetworkFlagMatch::NotMatched;
}

std::optional<bool> parse_on_off(std::string_view value) noexcept {
    if (value == "on" || value == "true" || value == "1") {
        return true;
    }
    if (value == "off" || value == "false" || value == "0") {
        return false;
    }
    return std::nullopt;
}

std::optional<application::IgnorePreset>
parse_ignore_preset(std::string_view value) noexcept {
    if (value == "default") {
        return application::IgnorePreset::Default;
    }
    if (value == "dev") {
        return application::IgnorePreset::Dev;
    }
    if (value == "office") {
        return application::IgnorePreset::Office;
    }
    if (value == "minimal") {
        return application::IgnorePreset::Minimal;
    }
    return std::nullopt;
}

std::optional<PositionalsWithCommit>
parse_positionals_with_commit(int start_index, int argc, char* argv[]) {
    PositionalsWithCommit parsed;
    bool after_delimiter = false;
    for (int i = start_index; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (!after_delimiter && arg == "--") {
            after_delimiter = true;
            continue;
        }
        if (!after_delimiter &&
            (arg == "--commit" || arg.starts_with("--commit="))) {
            if (parsed.commit_id.has_value()) {
                return std::nullopt;
            }
            std::string_view value;
            if (arg == "--commit") {
                if (i + 1 >= argc) {
                    return std::nullopt;
                }
                value = argv[++i];
            } else {
                value = arg.substr(std::string_view{"--commit="}.size());
            }
            if (!application::history_storage::valid_hex_hash(value)) {
                return std::nullopt;
            }
            parsed.commit_id = std::string{value};
            continue;
        }
        if (after_delimiter ? literal_operand(argv[i]) : operand(argv[i])) {
            parsed.positionals.push_back(arg);
            continue;
        }
        return std::nullopt;
    }
    return parsed;
}

std::expected<Invocation, ParseError>
request(application::Operation operation, int argc, char* argv[]) {
    if (argc < 3 || !operand(argv[2])) {
        return std::unexpected(ParseError{});
    }
    std::optional<std::string> bandwidth_limit;
    std::optional<std::uint32_t> transfer_concurrency;
    bool unused_clear_bw = false;
    bool unused_clear_cc = false;
    for (int i = 3; i < argc; ++i) {
        const auto net = try_parse_network_flag(i,
                                                argc,
                                                argv,
                                                bandwidth_limit,
                                                unused_clear_bw,
                                                transfer_concurrency,
                                                unused_clear_cc,
                                                false);
        if (net != NetworkFlagMatch::Matched) {
            return std::unexpected(ParseError{});
        }
    }
    return application::Request{.operation = operation,
                                .profile_name = argv[2],
                                .bandwidth_limit = std::move(bandwidth_limit),
                                .transfer_concurrency = transfer_concurrency};
}

bool parse_logs_args(int start_index,
                     int argc,
                     char* argv[],
                     std::optional<std::string>& profile_name,
                     std::size_t& log_lines,
                     bool& follow) {
    bool saw_lines = false;
    bool saw_follow = false;
    for (int i = start_index; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if (arg == "--lines" || arg.starts_with("--lines=")) {
            if (saw_lines) {
                return false;
            }
            const auto val = read_flag_value(i, argc, argv, "--lines");
            if (!val) {
                return false;
            }
            const auto parsed = parse_bounded_u32(val->value, 1U, 1000U);
            if (!parsed) {
                return false;
            }
            log_lines = *parsed;
            saw_lines = true;
            if (val->consumed_next) {
                ++i;
            }
        } else if (arg == "--follow" || arg == "-f") {
            if (saw_follow) {
                return false;
            }
            saw_follow = true;
            follow = true;
        } else if (operand(argv[i]) && !profile_name.has_value()) {
            profile_name = std::string{arg};
        } else {
            return false;
        }
    }
    return true;
}

constexpr std::
    array<std::pair<std::string_view, application::InspectionOperation>, 11>
        simple_remote_inspections{
            {{"heads", application::InspectionOperation::RemoteHeads},
             {"tree", application::InspectionOperation::RemoteTree},
             {"commits", application::InspectionOperation::RemoteCommits},
             {"summary", application::InspectionOperation::RemoteSummary},
             {"epochs", application::InspectionOperation::RemoteEpochs},
             {"contents", application::InspectionOperation::RemoteContents},
             {"markers", application::InspectionOperation::RemoteMarkers},
             {"objects", application::InspectionOperation::RemoteObjects},
             {"orphans", application::InspectionOperation::RemoteOrphans},
             {"writers", application::InspectionOperation::RemoteWriters},
             {"health", application::InspectionOperation::RemoteHealth}}};

} // namespace

std::string help_topic(int argc, char* argv[]) {
    if (argc < 2 || argv == nullptr || argv[1] == nullptr)
        return {};
    const std::string command{argv[1]};
    if (std::ranges::find(help_topics, command, &HelpTopic::name) ==
        help_topics.end())
        return {};
    if ((command == "remote" || command == "gc" || command == "profile" ||
         command == "conflicts" || command == "ignore" ||
         command == "daemon") &&
        argc > 2 && argv[2] != nullptr) {
        const auto topic = command + " " + argv[2];
        if (std::ranges::find(help_topics, topic, &HelpTopic::name) !=
            help_topics.end())
            return topic;
    }
    return command;
}

std::expected<Invocation, ParseError> parse(int argc, char* argv[]) {
    if (argc < 2 || argv == nullptr || argv[1] == nullptr) {
        return std::unexpected(ParseError{});
    }
    for (int index = 1; index < argc; ++index) {
        if (argv[index] == nullptr)
            return std::unexpected(ParseError{});
    }
    const std::string_view command{argv[1]};
    if (argc == 2 && (command == "--help" || command == "-h")) {
        return HelpInvocation{};
    }
    if (argc == 3 && argv[2] != nullptr) {
        const std::string_view second{argv[2]};
        if (((command == "--help" || command == "-h") && second == "--all") ||
            (command == "--all" && (second == "--help" || second == "-h"))) {
            return HelpInvocation{.topic = {}, .all = true};
        }
    }
    bool has_delimiter = false;
    for (int index = 1; index < argc - 1; ++index) {
        if (std::string_view{argv[index]} == "--") {
            has_delimiter = true;
            break;
        }
    }
    const std::string_view last{argv[argc - 1]};
    if (!has_delimiter && (last == "--help" || last == "-h")) {
        const auto topic = help_topic(argc - 1, argv);
        const int topic_arguments =
            topic.find(' ') == std::string::npos ? 1 : 2;
        if (!topic.empty() && argc == topic_arguments + 2)
            return HelpInvocation{topic};
        const auto invocation = parse(argc - 1, argv);
        if (invocation &&
            !std::holds_alternative<HelpInvocation>(*invocation)) {
            return HelpInvocation{topic};
        }
        return std::unexpected(ParseError{});
    }
    if (command == "list") {
        return argc == 2
                   ? std::expected<Invocation, ParseError>{ListInvocation{}}
                   : std::unexpected(ParseError{});
    }
    if (command == "show") {
        return argc == 3 && operand(argv[2])
                   ? std::expected<Invocation, ParseError>{ShowInvocation{
                         argv[2]}}
                   : std::unexpected(ParseError{});
    }
    if (command == "diagnostics") {
        if (argc == 2) {
            return DiagnosticsInvocation{};
        }
        if (argc == 3 && operand(argv[2])) {
            return DiagnosticsInvocation{.profile_name = argv[2]};
        }
        return std::unexpected(ParseError{});
    }
    if (command == "key") {
        if (argc < 3 || argc > 4 || !operand(argv[2])) {
            return std::unexpected(ParseError{});
        }
        bool replace = false;
        if (argc == 4) {
            if (std::string_view{argv[3]} != "--replace") {
                return std::unexpected(ParseError{});
            }
            replace = true;
        }
        return KeyInvocation{.profile_name = argv[2], .replace = replace};
    }
    if (command == "config") {
        return argc == 2 ? std::expected<Invocation,
                                         ParseError>{ConfigureInvocation{}}
                         : std::unexpected(ParseError{});
    }
    if (command == "conflicts") {
        if (argc == 3 && operand(argv[2]) &&
            std::string_view{argv[2]} != "resolve") {
            return ConflictsInvocation{.profile_name = argv[2]};
        }
        if (argc >= 4 && argv[2] != nullptr &&
            std::string_view{argv[2]} == "resolve" && operand(argv[3])) {
            ConflictsInvocation inv{
                .profile_name = argv[3],
                .resolve = true,
            };
            bool saw_keep_canonical = false;
            bool saw_keep_artifact = false;
            bool after_delimiter = false;
            std::vector<std::string_view> positionals;
            for (int i = 4; i < argc; ++i) {
                const std::string_view arg{argv[i]};
                if (!after_delimiter && arg == "--") {
                    after_delimiter = true;
                    continue;
                }
                if (!after_delimiter && arg == "--keep-canonical") {
                    if (saw_keep_canonical || saw_keep_artifact) {
                        return std::unexpected(ParseError{});
                    }
                    saw_keep_canonical = true;
                    inv.choice =
                        application::ConflictResolutionChoice::KeepCanonical;
                    continue;
                }
                if (!after_delimiter &&
                    (arg == "--keep" || arg.starts_with("--keep="))) {
                    if (saw_keep_canonical || saw_keep_artifact) {
                        return std::unexpected(ParseError{});
                    }
                    const auto val = read_flag_value(i, argc, argv, "--keep");
                    if (!val) {
                        return std::unexpected(ParseError{});
                    }
                    saw_keep_artifact = true;
                    inv.choice =
                        application::ConflictResolutionChoice::KeepArtifact;
                    inv.artifact_selector = std::string{val->value};
                    if (val->consumed_next) {
                        ++i;
                    }
                    continue;
                }
                if (!after_delimiter && arg == "--dry-run") {
                    if (inv.dry_run) {
                        return std::unexpected(ParseError{});
                    }
                    inv.dry_run = true;
                    continue;
                }
                if (after_delimiter ? literal_operand(argv[i])
                                    : operand(argv[i])) {
                    positionals.push_back(arg);
                    continue;
                }
                return std::unexpected(ParseError{});
            }
            if (positionals.size() != 1U ||
                (!saw_keep_canonical && !saw_keep_artifact)) {
                return std::unexpected(ParseError{});
            }
            inv.canonical_path = std::string{positionals[0]};
            return inv;
        }
        return std::unexpected(ParseError{});
    }
    if (command == "daemon") {
        if (argc < 3 || argv[2] == nullptr) {
            return std::unexpected(ParseError{});
        }
        const std::string_view sub{argv[2]};
        if (sub == "run") {
            DaemonInvocation inv{.action = DaemonAction::Run};
            bool saw_foreground = false;
            for (int i = 3; i < argc; ++i) {
                const std::string_view arg{argv[i]};
                if (arg == "--background") {
                    if (inv.background || saw_foreground) {
                        return std::unexpected(ParseError{});
                    }
                    inv.background = true;
                } else if (arg == "--foreground") {
                    if (saw_foreground || inv.background) {
                        return std::unexpected(ParseError{});
                    }
                    saw_foreground = true;
                } else {
                    return std::unexpected(ParseError{});
                }
            }
            return inv;
        }
        if (sub == "stop") {
            return argc == 3
                       ? std::expected<Invocation, ParseError>{DaemonInvocation{
                             .action = DaemonAction::Stop}}
                       : std::unexpected(ParseError{});
        }
        if (sub == "reload") {
            return argc == 3
                       ? std::expected<Invocation, ParseError>{DaemonInvocation{
                             .action = DaemonAction::Reload}}
                       : std::unexpected(ParseError{});
        }
        if (sub == "status") {
            if (argc == 3) {
                return DaemonInvocation{.action = DaemonAction::Status};
            }
            if (argc == 4 && operand(argv[3])) {
                return DaemonInvocation{
                    .action = DaemonAction::Status,
                    .profile_name = std::string{argv[3]},
                };
            }
            return std::unexpected(ParseError{});
        }
        if (sub == "sync") {
            DaemonInvocation inv{.action = DaemonAction::Sync};
            for (int i = 3; i < argc; ++i) {
                const std::string_view arg{argv[i]};
                if (arg == "--wait") {
                    if (inv.wait) {
                        return std::unexpected(ParseError{});
                    }
                    inv.wait = true;
                } else if (operand(argv[i]) && !inv.profile_name.has_value()) {
                    inv.profile_name = std::string{arg};
                } else {
                    return std::unexpected(ParseError{});
                }
            }
            return inv;
        }
        if (sub == "pause" || sub == "resume" || sub == "unlock" ||
            sub == "lock") {
            if (argc != 4 || !operand(argv[3])) {
                return std::unexpected(ParseError{});
            }
            const DaemonAction act = sub == "pause"    ? DaemonAction::Pause
                                     : sub == "resume" ? DaemonAction::Resume
                                     : sub == "unlock" ? DaemonAction::Unlock
                                                       : DaemonAction::Lock;
            return DaemonInvocation{
                .action = act,
                .profile_name = std::string{argv[3]},
            };
        }
        if (sub == "logs") {
            DaemonInvocation inv{.action = DaemonAction::Logs};
            if (!parse_logs_args(3,
                                 argc,
                                 argv,
                                 inv.profile_name,
                                 inv.log_lines,
                                 inv.follow)) {
                return std::unexpected(ParseError{});
            }
            return inv;
        }
        if (sub == "autostart") {
            if (argc != 4 || argv[3] == nullptr) {
                return std::unexpected(ParseError{});
            }
            const std::string_view act_str{argv[3]};
            if (act_str == "install") {
                return DaemonInvocation{.action =
                                            DaemonAction::AutostartInstall};
            }
            if (act_str == "uninstall") {
                return DaemonInvocation{.action =
                                            DaemonAction::AutostartUninstall};
            }
            if (act_str == "status") {
                return DaemonInvocation{.action =
                                            DaemonAction::AutostartStatus};
            }
            return std::unexpected(ParseError{});
        }
        return std::unexpected(ParseError{});
    }
    if (command == "completion") {
        if (argc != 3 || argv[2] == nullptr) {
            return std::unexpected(ParseError{});
        }
        const std::string_view shell{argv[2]};
        if (shell == "bash") {
            return CompletionInvocation{CompletionShell::Bash};
        }
        if (shell == "zsh") {
            return CompletionInvocation{CompletionShell::Zsh};
        }
        if (shell == "fish") {
            return CompletionInvocation{CompletionShell::Fish};
        }
        if (shell == "powershell") {
            return CompletionInvocation{CompletionShell::PowerShell};
        }
        return std::unexpected(ParseError{});
    }
    if (command == "profile") {
        if (argc < 4 || argv[2] == nullptr || !operand(argv[3])) {
            return std::unexpected(ParseError{});
        }
        const std::string_view sub{argv[2]};
        const std::string profile_name{argv[3]};
        if (sub == "create" || sub == "edit") {
            const bool is_create = sub == "create";
            ProfileInvocation inv{
                .action =
                    is_create ? ProfileAction::Create : ProfileAction::Edit,
                .profile_name = profile_name,
            };
            for (int i = 4; i < argc; ++i) {
                const auto net =
                    try_parse_network_flag(i,
                                           argc,
                                           argv,
                                           inv.bandwidth_limit,
                                           inv.clear_bandwidth_limit,
                                           inv.transfer_concurrency,
                                           inv.clear_transfer_concurrency,
                                           !is_create);
                if (net == NetworkFlagMatch::Error) {
                    return std::unexpected(ParseError{});
                }
                if (net == NetworkFlagMatch::Matched) {
                    continue;
                }
                const std::string_view arg{argv[i]};
                if (arg == "--local" || arg.starts_with("--local=")) {
                    if (inv.local_dir.has_value()) {
                        return std::unexpected(ParseError{});
                    }
                    const auto val = read_flag_value(i, argc, argv, "--local");
                    if (!val) {
                        return std::unexpected(ParseError{});
                    }
                    inv.local_dir = std::string{val->value};
                    if (val->consumed_next) {
                        ++i;
                    }
                } else if (arg == "--remote" || arg.starts_with("--remote=")) {
                    if (inv.remote_dir.has_value()) {
                        return std::unexpected(ParseError{});
                    }
                    const auto val = read_flag_value(i, argc, argv, "--remote");
                    if (!val) {
                        return std::unexpected(ParseError{});
                    }
                    inv.remote_dir = std::string{val->value};
                    if (val->consumed_next) {
                        ++i;
                    }
                } else if (is_create && (arg == "--key-storage" ||
                                         arg.starts_with("--key-storage="))) {
                    if (inv.key_storage.has_value()) {
                        return std::unexpected(ParseError{});
                    }
                    const auto val =
                        read_flag_value(i, argc, argv, "--key-storage");
                    if (!val) {
                        return std::unexpected(ParseError{});
                    }
                    const auto storage = parse_key_storage(val->value);
                    if (!storage) {
                        return std::unexpected(ParseError{});
                    }
                    inv.key_storage = *storage;
                    if (val->consumed_next) {
                        ++i;
                    }
                } else if (arg == "--min-depth" ||
                           arg.starts_with("--min-depth=")) {
                    if (inv.min_history_depth.has_value()) {
                        return std::unexpected(ParseError{});
                    }
                    const auto val =
                        read_flag_value(i, argc, argv, "--min-depth");
                    if (!val) {
                        return std::unexpected(ParseError{});
                    }
                    const auto depth = parse_bounded_u32(val->value, 1U, 4096U);
                    if (!depth) {
                        return std::unexpected(ParseError{});
                    }
                    inv.min_history_depth = *depth;
                    if (val->consumed_next) {
                        ++i;
                    }
                } else if (arg == "--min-age" ||
                           arg.starts_with("--min-age=")) {
                    if (inv.min_history_age_hours.has_value()) {
                        return std::unexpected(ParseError{});
                    }
                    const auto val =
                        read_flag_value(i, argc, argv, "--min-age");
                    if (!val) {
                        return std::unexpected(ParseError{});
                    }
                    const auto age = parse_bounded_u32(val->value, 1U, 8760U);
                    if (!age) {
                        return std::unexpected(ParseError{});
                    }
                    inv.min_history_age_hours = *age;
                    if (val->consumed_next) {
                        ++i;
                    }
                } else if (arg == "--rclone-config" ||
                           arg.starts_with("--rclone-config=")) {
                    if (inv.rclone_config.has_value() ||
                        inv.clear_rclone_config) {
                        return std::unexpected(ParseError{});
                    }
                    const auto val =
                        read_flag_value(i, argc, argv, "--rclone-config");
                    if (!val) {
                        return std::unexpected(ParseError{});
                    }
                    inv.rclone_config = std::string{val->value};
                    if (val->consumed_next) {
                        ++i;
                    }
                } else if (!is_create && arg == "--clear-rclone-config") {
                    if (inv.rclone_config.has_value() ||
                        inv.clear_rclone_config) {
                        return std::unexpected(ParseError{});
                    }
                    inv.clear_rclone_config = true;
                } else if (arg == "--watch" || arg.starts_with("--watch=")) {
                    if (inv.watch_enabled.has_value() ||
                        inv.clear_watch_enabled) {
                        return std::unexpected(ParseError{});
                    }
                    const auto val = read_flag_value(i, argc, argv, "--watch");
                    if (!val) {
                        return std::unexpected(ParseError{});
                    }
                    const auto parsed_watch = parse_on_off(val->value);
                    if (!parsed_watch) {
                        return std::unexpected(ParseError{});
                    }
                    inv.watch_enabled = *parsed_watch;
                    if (val->consumed_next) {
                        ++i;
                    }
                } else if (!is_create && arg == "--clear-watch") {
                    if (inv.watch_enabled.has_value() ||
                        inv.clear_watch_enabled) {
                        return std::unexpected(ParseError{});
                    }
                    inv.clear_watch_enabled = true;
                } else if (arg == "--sync-interval" ||
                           arg.starts_with("--sync-interval=")) {
                    if (inv.sync_interval_seconds.has_value() ||
                        inv.clear_sync_interval_seconds) {
                        return std::unexpected(ParseError{});
                    }
                    const auto val =
                        read_flag_value(i, argc, argv, "--sync-interval");
                    if (!val) {
                        return std::unexpected(ParseError{});
                    }
                    const auto parsed_sec =
                        parse_bounded_u32(val->value, 0U, 86400U);
                    if (!parsed_sec ||
                        (*parsed_sec != 0U && *parsed_sec < 10U)) {
                        return std::unexpected(ParseError{});
                    }
                    inv.sync_interval_seconds = *parsed_sec;
                    if (val->consumed_next) {
                        ++i;
                    }
                } else if (!is_create && arg == "--clear-sync-interval") {
                    if (inv.sync_interval_seconds.has_value() ||
                        inv.clear_sync_interval_seconds) {
                        return std::unexpected(ParseError{});
                    }
                    inv.clear_sync_interval_seconds = true;
                } else if (arg == "--gc-interval" ||
                           arg.starts_with("--gc-interval=")) {
                    if (inv.gc_interval_hours.has_value() ||
                        inv.clear_gc_interval_hours) {
                        return std::unexpected(ParseError{});
                    }
                    const auto val =
                        read_flag_value(i, argc, argv, "--gc-interval");
                    if (!val) {
                        return std::unexpected(ParseError{});
                    }
                    const auto parsed_hrs =
                        parse_bounded_u32(val->value, 0U, 8760U);
                    if (!parsed_hrs) {
                        return std::unexpected(ParseError{});
                    }
                    inv.gc_interval_hours = *parsed_hrs;
                    if (val->consumed_next) {
                        ++i;
                    }
                } else if (!is_create && arg == "--clear-gc-interval") {
                    if (inv.gc_interval_hours.has_value() ||
                        inv.clear_gc_interval_hours) {
                        return std::unexpected(ParseError{});
                    }
                    inv.clear_gc_interval_hours = true;
                } else if (arg == "--paused" || arg.starts_with("--paused=")) {
                    if (inv.paused.has_value()) {
                        return std::unexpected(ParseError{});
                    }
                    const auto val = read_flag_value(i, argc, argv, "--paused");
                    if (!val) {
                        return std::unexpected(ParseError{});
                    }
                    const auto parsed_paused = parse_on_off(val->value);
                    if (!parsed_paused) {
                        return std::unexpected(ParseError{});
                    }
                    inv.paused = *parsed_paused;
                    if (val->consumed_next) {
                        ++i;
                    }
                } else if (is_create && arg == "--verify") {
                    if (inv.verify) {
                        return std::unexpected(ParseError{});
                    }
                    inv.verify = true;
                } else if (!is_create && arg == "--allow-empty-local") {
                    if (inv.allow_empty_local) {
                        return std::unexpected(ParseError{});
                    }
                    inv.allow_empty_local = true;
                } else {
                    return std::unexpected(ParseError{});
                }
            }
            if (is_create && (!inv.local_dir || !inv.remote_dir)) {
                return std::unexpected(ParseError{});
            }
            if (!is_create && !inv.local_dir && !inv.remote_dir &&
                !inv.min_history_depth && !inv.min_history_age_hours &&
                !inv.bandwidth_limit && !inv.clear_bandwidth_limit &&
                !inv.transfer_concurrency && !inv.clear_transfer_concurrency &&
                !inv.rclone_config && !inv.clear_rclone_config &&
                !inv.watch_enabled && !inv.clear_watch_enabled &&
                !inv.sync_interval_seconds &&
                !inv.clear_sync_interval_seconds && !inv.gc_interval_hours &&
                !inv.clear_gc_interval_hours && !inv.paused) {
                return std::unexpected(ParseError{});
            }
            return inv;
        }
        if (sub == "test") {
            if (argc != 4) {
                return std::unexpected(ParseError{});
            }
            return ProfileInvocation{
                .action = ProfileAction::Test,
                .profile_name = profile_name,
            };
        }
        if (sub == "clone" || sub == "rename") {
            if (argc != 5 || !operand(argv[4])) {
                return std::unexpected(ParseError{});
            }
            return ProfileInvocation{
                .action = sub == "clone" ? ProfileAction::Clone
                                         : ProfileAction::Rename,
                .profile_name = profile_name,
                .target_name = std::string{argv[4]},
            };
        }
        if (sub == "storage") {
            if (argc != 5 || argv[4] == nullptr) {
                return std::unexpected(ParseError{});
            }
            const auto storage = parse_key_storage(argv[4]);
            if (!storage) {
                return std::unexpected(ParseError{});
            }
            return ProfileInvocation{
                .action = ProfileAction::Storage,
                .profile_name = profile_name,
                .key_storage = *storage,
            };
        }
        if (sub == "delete") {
            if (argc != 5 || std::string_view{argv[4]} != "--confirm") {
                return std::unexpected(ParseError{});
            }
            return ProfileInvocation{
                .action = ProfileAction::Delete,
                .profile_name = profile_name,
                .confirm = true,
            };
        }
        return std::unexpected(ParseError{});
    }
    if (command == "ignore") {
        if (argc < 4 || argv[2] == nullptr || !operand(argv[3])) {
            return std::unexpected(ParseError{});
        }
        const std::string_view sub{argv[2]};
        const std::string profile_name{argv[3]};
        if (sub == "check") {
            IgnoreInvocation inv{
                .action = IgnoreAction::Check,
                .profile_name = profile_name,
            };
            bool after_delimiter = false;
            for (int i = 4; i < argc; ++i) {
                const std::string_view arg{argv[i]};
                if (!after_delimiter && arg == "--") {
                    after_delimiter = true;
                    continue;
                }
                if (after_delimiter ? literal_operand(argv[i])
                                    : operand(argv[i])) {
                    inv.paths.emplace_back(arg);
                    continue;
                }
                return std::unexpected(ParseError{});
            }
            if (inv.paths.empty()) {
                return std::unexpected(ParseError{});
            }
            return inv;
        }
        if (sub == "init") {
            IgnoreInvocation inv{
                .action = IgnoreAction::Init,
                .profile_name = profile_name,
            };
            bool saw_preset = false;
            for (int i = 4; i < argc; ++i) {
                const std::string_view arg{argv[i]};
                if (arg == "--preset" || arg.starts_with("--preset=")) {
                    if (saw_preset) {
                        return std::unexpected(ParseError{});
                    }
                    const auto val = read_flag_value(i, argc, argv, "--preset");
                    if (!val) {
                        return std::unexpected(ParseError{});
                    }
                    const auto preset = parse_ignore_preset(val->value);
                    if (!preset) {
                        return std::unexpected(ParseError{});
                    }
                    saw_preset = true;
                    inv.preset = *preset;
                    if (val->consumed_next) {
                        ++i;
                    }
                } else if (arg == "--force") {
                    if (inv.force) {
                        return std::unexpected(ParseError{});
                    }
                    inv.force = true;
                } else if (arg == "--dry-run") {
                    if (inv.dry_run) {
                        return std::unexpected(ParseError{});
                    }
                    inv.dry_run = true;
                } else {
                    return std::unexpected(ParseError{});
                }
            }
            return inv;
        }
        return std::unexpected(ParseError{});
    }
    if (command == "sync") {
        if (argc < 3 || !operand(argv[2])) {
            return std::unexpected(ParseError{});
        }
        bool dry_run = false;
        bool initial = false;
        bool audit_inventory = false;
        bool repair = false;
        bool allow_empty_local = false;
        std::optional<std::string> bandwidth_limit;
        std::optional<std::uint32_t> transfer_concurrency;
        bool unused_clear_bw = false;
        bool unused_clear_cc = false;
        const std::array<std::pair<std::string_view, bool*>, 5> sync_flags{{
            {"--dry-run", &dry_run},
            {"--initial", &initial},
            {"--audit-inventory", &audit_inventory},
            {"--repair", &repair},
            {"--allow-empty-local", &allow_empty_local},
        }};
        for (int i = 3; i < argc; ++i) {
            const auto net = try_parse_network_flag(i,
                                                    argc,
                                                    argv,
                                                    bandwidth_limit,
                                                    unused_clear_bw,
                                                    transfer_concurrency,
                                                    unused_clear_cc,
                                                    false);
            if (net == NetworkFlagMatch::Error) {
                return std::unexpected(ParseError{});
            }
            if (net == NetworkFlagMatch::Matched) {
                continue;
            }
            const std::string_view flag{argv[i]};
            const auto found = std::ranges::find(
                sync_flags, flag, &std::pair<std::string_view, bool*>::first);
            if (found == sync_flags.end() || *found->second) {
                return std::unexpected(ParseError{});
            }
            *found->second = true;
        }
        if (audit_inventory && (dry_run || initial)) {
            return std::unexpected(
                ParseError{.unsupported_sync_audit_combination = true});
        }
        if (repair && (dry_run || initial)) {
            return std::unexpected(
                ParseError{.unsupported_sync_repair_combination = true});
        }
        if (dry_run && initial) {
            return std::unexpected(ParseError{});
        }
        return application::Request{
            .operation = dry_run ? application::Operation::Preview
                                 : application::Operation::Sync,
            .profile_name = argv[2],
            .initial = initial,
            .audit_inventory = audit_inventory,
            .repair = repair,
            .allow_empty_local = allow_empty_local,
            .bandwidth_limit = std::move(bandwidth_limit),
            .transfer_concurrency = transfer_concurrency};
    }
    if (command == "logs") {
        LogsInvocation inv;
        if (!parse_logs_args(
                2, argc, argv, inv.profile_name, inv.log_lines, inv.follow)) {
            return std::unexpected(ParseError{});
        }
        return inv;
    }
    if (command == "start") {
        if (argc == 2) {
            return StartInvocation{};
        }
        if (argc == 3 && std::string_view{argv[2]} == "--autostart") {
            return StartInvocation{.autostart = true};
        }
        return std::unexpected(ParseError{});
    }
    if (command == "stop") {
        return argc == 2 ? std::expected<Invocation, ParseError>{StopInvocation{}}
                         : std::unexpected(ParseError{});
    }
    if (command == "pause" || command == "resume") {
        if (argc != 3) {
            return std::unexpected(ParseError{});
        }
        const bool is_pause = command == "pause";
        const std::string_view target{argv[2]};
        if (target == "--all") {
            return ProfileToggleInvocation{.pause = is_pause, .all = true};
        }
        if (operand(argv[2])) {
            return ProfileToggleInvocation{
                .pause = is_pause,
                .all = false,
                .profile_name = std::string{target},
            };
        }
        return std::unexpected(ParseError{});
    }
    if (command == "status") {
        if (argc == 2) {
            return OverviewInvocation{};
        }
        return request(application::Operation::Status, argc, argv);
    }
    if (command == "fsck") {
        return request(application::Operation::Fsck, argc, argv);
    }
    if (command == "gc") {
        if (argc >= 3 && std::string_view{argv[2]} == "remove-writer") {
            if (argc != 5 || !operand(argv[3]) ||
                !application::history_storage::valid_writer_identifier(
                    argv[4])) {
                return std::unexpected(ParseError{});
            }
            return application::Request{
                .operation = application::Operation::RemoveWriter,
                .profile_name = argv[3],
                .writer_identifier = argv[4]};
        }
        if (argc >= 3 && std::string_view{argv[2]} == "remove-barrier") {
            if (argc < 5 || argc > 6 || !operand(argv[3])) {
                return std::unexpected(ParseError{});
            }
            bool confirm_abandoned = false;
            std::optional<std::string> barrier_identifier;
            for (int i = 4; i < argc; ++i) {
                const std::string_view arg{argv[i]};
                if (arg == "--confirm-abandoned") {
                    if (confirm_abandoned) {
                        return std::unexpected(ParseError{});
                    }
                    confirm_abandoned = true;
                } else if (operand(argv[i]) &&
                           !barrier_identifier.has_value()) {
                    barrier_identifier = std::string{arg};
                } else {
                    return std::unexpected(ParseError{});
                }
            }
            if (!confirm_abandoned) {
                return std::unexpected(ParseError{});
            }
            return application::Request{
                .operation = application::Operation::RemoveBarrier,
                .profile_name = argv[3],
                .barrier_identifier = std::move(barrier_identifier),
                .confirm_abandoned = true};
        }
        if (argc < 3 || !operand(argv[2])) {
            return std::unexpected(ParseError{});
        }
        bool dry_run = false;
        std::optional<std::uint32_t> min_age_hours;
        std::optional<std::string> bandwidth_limit;
        std::optional<std::uint32_t> transfer_concurrency;
        bool unused_clear_bw = false;
        bool unused_clear_cc = false;
        const auto parse_hours =
            [](std::string_view value) -> std::optional<std::uint32_t> {
            if (value.empty() || !std::ranges::all_of(value, [](char ch) {
                    return ch >= '0' && ch <= '9';
                })) {
                return std::nullopt;
            }
            std::uint32_t hours = 0;
            const auto [ptr, ec] = std::from_chars(
                value.data(), value.data() + value.size(), hours);
            if (ec != std::errc{} || ptr != value.data() + value.size() ||
                hours > 8760U) {
                return std::nullopt;
            }
            return hours;
        };
        for (int i = 3; i < argc; ++i) {
            const auto net = try_parse_network_flag(i,
                                                    argc,
                                                    argv,
                                                    bandwidth_limit,
                                                    unused_clear_bw,
                                                    transfer_concurrency,
                                                    unused_clear_cc,
                                                    false);
            if (net == NetworkFlagMatch::Error) {
                return std::unexpected(ParseError{});
            }
            if (net == NetworkFlagMatch::Matched) {
                continue;
            }
            const std::string_view flag{argv[i]};
            if (flag == "--dry-run") {
                if (dry_run) {
                    return std::unexpected(ParseError{});
                }
                dry_run = true;
            } else if (flag == "--min-age" || flag.starts_with("--min-age=")) {
                if (min_age_hours.has_value()) {
                    return std::unexpected(ParseError{});
                }
                std::string_view value;
                if (flag == "--min-age") {
                    if (i + 1 >= argc) {
                        return std::unexpected(ParseError{});
                    }
                    value = argv[++i];
                } else {
                    value = flag.substr(std::string_view{"--min-age="}.size());
                }
                const auto parsed = parse_hours(value);
                if (!parsed.has_value()) {
                    return std::unexpected(ParseError{});
                }
                min_age_hours = *parsed;
            } else {
                return std::unexpected(ParseError{});
            }
        }
        return application::Request{
            .operation = application::Operation::GarbageCollect,
            .profile_name = argv[2],
            .dry_run = dry_run,
            .gc_min_age_hours = min_age_hours,
            .bandwidth_limit = std::move(bandwidth_limit),
            .transfer_concurrency = transfer_concurrency};
    }
    if (command == "repack") {
        if (argc < 3 || !operand(argv[2])) {
            return std::unexpected(ParseError{});
        }
        bool dry_run = false;
        bool reclaim_dirty = false;
        std::optional<std::string> bandwidth_limit;
        std::optional<std::uint32_t> transfer_concurrency;
        bool unused_clear_bw = false;
        bool unused_clear_cc = false;
        const std::array<std::pair<std::string_view, bool*>, 2> repack_flags{{
            {"--dry-run", &dry_run},
            {"--reclaim-dirty", &reclaim_dirty},
        }};
        for (int i = 3; i < argc; ++i) {
            const auto net = try_parse_network_flag(i,
                                                    argc,
                                                    argv,
                                                    bandwidth_limit,
                                                    unused_clear_bw,
                                                    transfer_concurrency,
                                                    unused_clear_cc,
                                                    false);
            if (net == NetworkFlagMatch::Error) {
                return std::unexpected(ParseError{});
            }
            if (net == NetworkFlagMatch::Matched) {
                continue;
            }
            const std::string_view flag{argv[i]};
            const auto found = std::ranges::find(
                repack_flags, flag, &std::pair<std::string_view, bool*>::first);
            if (found == repack_flags.end() || *found->second) {
                return std::unexpected(ParseError{});
            }
            *found->second = true;
        }
        return application::Request{
            .operation = application::Operation::Repack,
            .profile_name = argv[2],
            .dry_run = dry_run,
            .reclaim_dirty = reclaim_dirty,
            .bandwidth_limit = std::move(bandwidth_limit),
            .transfer_concurrency = transfer_concurrency};
    }
    if (command == "resolve-missing") {
        if (argc == 3 && operand(argv[2])) {
            return application::Request{
                .operation = application::Operation::ResolveMissing,
                .profile_name = argv[2]};
        }
        if (argc == 4 && operand(argv[2])) {
            const std::string_view flag{argv[3]};
            if (flag == "--confirm") {
                return application::Request{
                    .operation = application::Operation::ResolveMissing,
                    .profile_name = argv[2],
                    .confirm = true};
            }
            if (flag == "--dry-run") {
                return application::Request{
                    .operation = application::Operation::ResolveMissing,
                    .profile_name = argv[2],
                    .dry_run = true};
            }
        }
        return std::unexpected(ParseError{});
    }
    if (command == "remote") {
        if (argc < 4 || !operand(argv[3])) {
            return std::unexpected(ParseError{});
        }
        std::optional<std::string> bandwidth_limit;
        std::optional<std::uint32_t> transfer_concurrency;
        bool unused_clear_bw = false;
        bool unused_clear_cc = false;
        std::vector<char*> filtered;
        filtered.reserve(static_cast<std::size_t>(argc));
        for (int i = 0; i < 4; ++i) {
            filtered.push_back(argv[i]);
        }
        bool after_delimiter = false;
        for (int i = 4; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (!after_delimiter && arg == "--") {
                after_delimiter = true;
                filtered.push_back(argv[i]);
                continue;
            }
            if (!after_delimiter) {
                const auto net = try_parse_network_flag(i,
                                                        argc,
                                                        argv,
                                                        bandwidth_limit,
                                                        unused_clear_bw,
                                                        transfer_concurrency,
                                                        unused_clear_cc,
                                                        false);
                if (net == NetworkFlagMatch::Error) {
                    return std::unexpected(ParseError{});
                }
                if (net == NetworkFlagMatch::Matched) {
                    continue;
                }
            }
            filtered.push_back(argv[i]);
        }
        const int rargc = static_cast<int>(filtered.size());
        char** rargv = filtered.data();
        const std::string_view inspection{rargv[2]};
        const auto parse_remote =
            [&]() -> std::optional<application::InspectionRequest> {
            if (rargc == 4) {
                const auto found = std::ranges::find(
                    simple_remote_inspections,
                    inspection,
                    &std::pair<std::string_view,
                               application::InspectionOperation>::first);
                if (found != simple_remote_inspections.end()) {
                    return application::InspectionRequest{
                        .operation = found->second, .profile_name = rargv[3]};
                }
                return std::nullopt;
            }
            if (inspection == "tree" && rargc == 6 &&
                std::string_view{rargv[4]} == "--head" && operand(rargv[5])) {
                return application::InspectionRequest{
                    .operation = application::InspectionOperation::RemoteTree,
                    .profile_name = rargv[3],
                    .head_commit_id = std::string{rargv[5]}};
            }
            if (inspection == "stat") {
                const auto parsed =
                    parse_positionals_with_commit(4, rargc, rargv);
                if (!parsed || parsed->positionals.size() != 1) {
                    return std::nullopt;
                }
                return application::InspectionRequest{
                    .operation = application::InspectionOperation::RemoteStat,
                    .profile_name = rargv[3],
                    .logical_path = std::string{parsed->positionals[0]},
                    .commit_id = parsed->commit_id};
            }
            if (inspection == "log") {
                std::vector<std::string_view> positionals;
                bool log_after_delimiter = false;
                for (int i = 4; i < rargc; ++i) {
                    const std::string_view arg{rargv[i]};
                    if (!log_after_delimiter && arg == "--") {
                        log_after_delimiter = true;
                        continue;
                    }
                    if (log_after_delimiter ? literal_operand(rargv[i])
                                            : operand(rargv[i])) {
                        positionals.push_back(arg);
                        continue;
                    }
                    return std::nullopt;
                }
                if (positionals.size() != 1U) {
                    return std::nullopt;
                }
                return application::InspectionRequest{
                    .operation = application::InspectionOperation::RemoteLog,
                    .profile_name = rargv[3],
                    .logical_path = std::string{positionals[0]}};
            }
            if (inspection == "commit" && rargc == 5 &&
                application::history_storage::valid_hex_hash(rargv[4])) {
                return application::InspectionRequest{
                    .operation = application::InspectionOperation::RemoteCommit,
                    .profile_name = rargv[3],
                    .commit_id = std::string{rargv[4]}};
            }
            if (inspection == "get") {
                const auto parsed =
                    parse_positionals_with_commit(4, rargc, rargv);
                if (!parsed || parsed->positionals.size() != 2) {
                    return std::nullopt;
                }
                return application::InspectionRequest{
                    .operation = application::InspectionOperation::RemoteGet,
                    .profile_name = rargv[3],
                    .logical_path = std::string{parsed->positionals[0]},
                    .commit_id = parsed->commit_id,
                    .destination_path = std::string{parsed->positionals[1]}};
            }
            if (inspection == "restore") {
                std::vector<std::string_view> positionals;
                std::optional<std::string> commit_id;
                bool dry_run = false;
                bool restore_after_delimiter = false;
                for (int i = 4; i < rargc; ++i) {
                    const std::string_view arg{rargv[i]};
                    if (!restore_after_delimiter && arg == "--") {
                        restore_after_delimiter = true;
                        continue;
                    }
                    if (!restore_after_delimiter &&
                        (arg == "--commit" || arg.starts_with("--commit="))) {
                        if (commit_id.has_value()) {
                            return std::nullopt;
                        }
                        const auto val =
                            read_flag_value(i, rargc, rargv, "--commit");
                        if (!val ||
                            !application::history_storage::valid_hex_hash(
                                val->value)) {
                            return std::nullopt;
                        }
                        commit_id = std::string{val->value};
                        if (val->consumed_next) {
                            ++i;
                        }
                        continue;
                    }
                    if (!restore_after_delimiter && arg == "--dry-run") {
                        if (dry_run) {
                            return std::nullopt;
                        }
                        dry_run = true;
                        continue;
                    }
                    if (restore_after_delimiter ? literal_operand(rargv[i])
                                                : operand(rargv[i])) {
                        positionals.push_back(arg);
                        continue;
                    }
                    return std::nullopt;
                }
                if (positionals.size() == 1U) {
                    return application::InspectionRequest{
                        .operation =
                            application::InspectionOperation::RemoteRestore,
                        .profile_name = rargv[3],
                        .commit_id = commit_id,
                        .destination_path = std::string{positionals[0]},
                        .dry_run = dry_run};
                }
                if (positionals.size() == 2U) {
                    return application::InspectionRequest{
                        .operation =
                            application::InspectionOperation::RemoteRestore,
                        .profile_name = rargv[3],
                        .logical_path = std::string{positionals[0]},
                        .commit_id = commit_id,
                        .destination_path = std::string{positionals[1]},
                        .dry_run = dry_run};
                }
                return std::nullopt;
            }
            if (inspection == "epoch" && rargc == 5 && operand(rargv[4])) {
                return application::InspectionRequest{
                    .operation = application::InspectionOperation::RemoteEpoch,
                    .profile_name = rargv[3],
                    .epoch_selector = std::string{rargv[4]}};
            }
            if (inspection == "contents" && rargc == 5 &&
                std::string_view{rargv[4]} == "--audit") {
                return application::InspectionRequest{
                    .operation =
                        application::InspectionOperation::RemoteContentsAudit,
                    .profile_name = rargv[3]};
            }
            if (inspection == "content" && rargc == 5 &&
                application::history_storage::valid_hex_hash(rargv[4])) {
                return application::InspectionRequest{
                    .operation =
                        application::InspectionOperation::RemoteContent,
                    .profile_name = rargv[3],
                    .content_id = std::string{rargv[4]}};
            }
            return std::nullopt;
        };
        auto parsed_remote = parse_remote();
        if (!parsed_remote) {
            return std::unexpected(ParseError{});
        }
        parsed_remote->bandwidth_limit = std::move(bandwidth_limit);
        parsed_remote->transfer_concurrency = transfer_concurrency;
        return *parsed_remote;
    }
    return std::unexpected(ParseError{});
}

} // namespace kasumi::cli
