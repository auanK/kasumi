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
    if ((command == "remote" || command == "gc") && argc > 2 &&
        argv[2] != nullptr) {
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
        const auto return_stat = [&](const char* logical) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteStat,
                .profile_name = argv[3],
                .logical_path = std::string{logical}};
        };
        const auto return_get = [&](const char* logical, const char* dst) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteGet,
                .profile_name = argv[3],
                .logical_path = std::string{logical},
                .destination_path = std::string{dst}};
        };
        if (inspection == "stat") {
            if (argc == 5 && operand(argv[4])) {
                return return_stat(argv[4]);
            }
            if (argc == 6 && std::string_view{argv[4]} == "--" &&
                literal_operand(argv[5])) {
                return return_stat(argv[5]);
            }
            return std::unexpected(ParseError{});
        }
        if (inspection == "commit" && argc == 5 &&
            application::history_storage::valid_hex_hash(argv[4])) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteCommit,
                .profile_name = argv[3],
                .commit_id = std::string{argv[4]}};
        }
        if (inspection == "get") {
            if (argc == 6 && operand(argv[4]) && operand(argv[5])) {
                return return_get(argv[4], argv[5]);
            }
            if (argc == 7) {
                if (std::string_view{argv[4]} == "--" &&
                    literal_operand(argv[5]) && literal_operand(argv[6])) {
                    return return_get(argv[5], argv[6]);
                }
                if (operand(argv[4]) && std::string_view{argv[5]} == "--" &&
                    literal_operand(argv[6])) {
                    return return_get(argv[4], argv[6]);
                }
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
