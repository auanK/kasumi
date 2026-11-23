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
    if (argc != 3 || !operand(argv[2])) {
        return std::unexpected(ParseError{});
    }
    return application::Request{.operation = operation,
                                .profile_name = argv[2]};
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
         command == "conflicts") &&
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
        return argc == 3 && operand(argv[2])
                   ? std::expected<Invocation, ParseError>{KeyInvocation{
                         argv[2]}}
                   : std::unexpected(ParseError{});
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
                } else {
                    return std::unexpected(ParseError{});
                }
            }
            if (is_create && (!inv.local_dir || !inv.remote_dir)) {
                return std::unexpected(ParseError{});
            }
            if (!is_create && !inv.local_dir && !inv.remote_dir &&
                !inv.min_history_depth && !inv.min_history_age_hours) {
                return std::unexpected(ParseError{});
            }
            return inv;
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
    if (command == "sync") {
        if (argc < 3 || argc > 5 || !operand(argv[2])) {
            return std::unexpected(ParseError{});
        }
        bool dry_run = false;
        bool initial = false;
        bool audit_inventory = false;
        bool repair = false;
        const std::array<std::pair<std::string_view, bool*>, 4> sync_flags{{
            {"--dry-run", &dry_run},
            {"--initial", &initial},
            {"--audit-inventory", &audit_inventory},
            {"--repair", &repair},
        }};
        for (int i = 3; i < argc; ++i) {
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
            .repair = repair};
    }
    if (command == "status") {
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
        return application::Request{.operation =
                                        application::Operation::GarbageCollect,
                                    .profile_name = argv[2],
                                    .dry_run = dry_run,
                                    .gc_min_age_hours = min_age_hours};
    }
    if (command == "repack") {
        if (argc < 3 || argc > 5 || !operand(argv[2])) {
            return std::unexpected(ParseError{});
        }
        bool dry_run = false;
        bool reclaim_dirty = false;
        const std::array<std::pair<std::string_view, bool*>, 2> repack_flags{{
            {"--dry-run", &dry_run},
            {"--reclaim-dirty", &reclaim_dirty},
        }};
        for (int i = 3; i < argc; ++i) {
            const std::string_view flag{argv[i]};
            const auto found = std::ranges::find(
                repack_flags, flag, &std::pair<std::string_view, bool*>::first);
            if (found == repack_flags.end() || *found->second) {
                return std::unexpected(ParseError{});
            }
            *found->second = true;
        }
        return application::Request{.operation = application::Operation::Repack,
                                    .profile_name = argv[2],
                                    .dry_run = dry_run,
                                    .reclaim_dirty = reclaim_dirty};
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
        const std::string_view inspection{argv[2]};
        if (argc == 4) {
            const auto found = std::ranges::find(
                simple_remote_inspections,
                inspection,
                &std::pair<std::string_view,
                           application::InspectionOperation>::first);
            if (found != simple_remote_inspections.end()) {
                return application::InspectionRequest{
                    .operation = found->second, .profile_name = argv[3]};
            }
            return std::unexpected(ParseError{});
        }
        if (inspection == "tree" && argc == 6 &&
            std::string_view{argv[4]} == "--head" && operand(argv[5])) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteTree,
                .profile_name = argv[3],
                .head_commit_id = std::string{argv[5]}};
        }
        if (inspection == "stat") {
            const auto parsed = parse_positionals_with_commit(4, argc, argv);
            if (!parsed || parsed->positionals.size() != 1) {
                return std::unexpected(ParseError{});
            }
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteStat,
                .profile_name = argv[3],
                .logical_path = std::string{parsed->positionals[0]},
                .commit_id = parsed->commit_id};
        }
        if (inspection == "log") {
            std::vector<std::string_view> positionals;
            bool after_delimiter = false;
            for (int i = 4; i < argc; ++i) {
                const std::string_view arg{argv[i]};
                if (!after_delimiter && arg == "--") {
                    after_delimiter = true;
                    continue;
                }
                if (after_delimiter ? literal_operand(argv[i])
                                    : operand(argv[i])) {
                    positionals.push_back(arg);
                    continue;
                }
                return std::unexpected(ParseError{});
            }
            if (positionals.size() != 1U) {
                return std::unexpected(ParseError{});
            }
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteLog,
                .profile_name = argv[3],
                .logical_path = std::string{positionals[0]}};
        }
        if (inspection == "commit" && argc == 5 &&
            application::history_storage::valid_hex_hash(argv[4])) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteCommit,
                .profile_name = argv[3],
                .commit_id = std::string{argv[4]}};
        }
        if (inspection == "get") {
            const auto parsed = parse_positionals_with_commit(4, argc, argv);
            if (!parsed || parsed->positionals.size() != 2) {
                return std::unexpected(ParseError{});
            }
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteGet,
                .profile_name = argv[3],
                .logical_path = std::string{parsed->positionals[0]},
                .commit_id = parsed->commit_id,
                .destination_path = std::string{parsed->positionals[1]}};
        }
        if (inspection == "restore") {
            std::vector<std::string_view> positionals;
            std::optional<std::string> commit_id;
            bool dry_run = false;
            bool after_delimiter = false;
            for (int i = 4; i < argc; ++i) {
                const std::string_view arg{argv[i]};
                if (!after_delimiter && arg == "--") {
                    after_delimiter = true;
                    continue;
                }
                if (!after_delimiter &&
                    (arg == "--commit" || arg.starts_with("--commit="))) {
                    if (commit_id.has_value()) {
                        return std::unexpected(ParseError{});
                    }
                    const auto val = read_flag_value(i, argc, argv, "--commit");
                    if (!val || !application::history_storage::valid_hex_hash(
                                    val->value)) {
                        return std::unexpected(ParseError{});
                    }
                    commit_id = std::string{val->value};
                    if (val->consumed_next) {
                        ++i;
                    }
                    continue;
                }
                if (!after_delimiter && arg == "--dry-run") {
                    if (dry_run) {
                        return std::unexpected(ParseError{});
                    }
                    dry_run = true;
                    continue;
                }
                if (after_delimiter ? literal_operand(argv[i])
                                    : operand(argv[i])) {
                    positionals.push_back(arg);
                    continue;
                }
                return std::unexpected(ParseError{});
            }
            if (positionals.size() == 1U) {
                return application::InspectionRequest{
                    .operation =
                        application::InspectionOperation::RemoteRestore,
                    .profile_name = argv[3],
                    .commit_id = commit_id,
                    .destination_path = std::string{positionals[0]},
                    .dry_run = dry_run};
            }
            if (positionals.size() == 2U) {
                return application::InspectionRequest{
                    .operation =
                        application::InspectionOperation::RemoteRestore,
                    .profile_name = argv[3],
                    .logical_path = std::string{positionals[0]},
                    .commit_id = commit_id,
                    .destination_path = std::string{positionals[1]},
                    .dry_run = dry_run};
            }
            return std::unexpected(ParseError{});
        }
        if (inspection == "epoch" && argc == 5 && operand(argv[4])) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteEpoch,
                .profile_name = argv[3],
                .epoch_selector = std::string{argv[4]}};
        }
        if (inspection == "contents" && argc == 5 &&
            std::string_view{argv[4]} == "--audit") {
            return application::InspectionRequest{
                .operation =
                    application::InspectionOperation::RemoteContentsAudit,
                .profile_name = argv[3]};
        }
        if (inspection == "content" && argc == 5 &&
            application::history_storage::valid_hex_hash(argv[4])) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteContent,
                .profile_name = argv[3],
                .content_id = std::string{argv[4]}};
        }
        return std::unexpected(ParseError{});
    }
    return std::unexpected(ParseError{});
}

} // namespace kasumi::cli
