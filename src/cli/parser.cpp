#include "cli/parser.hpp"

#include "application/history_storage/remote_layout.hpp"

#include <algorithm>
#include <array>
#include <string_view>

namespace kasumi::cli {
namespace {

constexpr std::array<std::string_view, 26> help_topics{"sync",
                                                       "status",
                                                       "fsck",
                                                       "gc",
                                                       "gc remove-writer",
                                                       "gc remove-barrier",
                                                       "resolve-missing",
                                                       "remote",
                                                       "config",
                                                       "update",
                                                       "remote heads",
                                                       "remote tree",
                                                       "remote commits",
                                                       "remote summary",
                                                       "remote stat",
                                                       "remote commit",
                                                       "remote get",
                                                       "remote epochs",
                                                       "remote epoch",
                                                       "remote contents",
                                                       "remote content",
                                                       "remote markers",
                                                       "remote objects",
                                                       "remote orphans",
                                                       "remote writers",
                                                       "remote health"};

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

bool valid_commit_id(std::string_view id) {
    if (id.size() != 64) {
        return false;
    }
    for (const char character : id) {
        const auto value = static_cast<unsigned char>(character);
        if (!(value >= '0' && value <= '9') &&
            !(value >= 'a' && value <= 'f')) {
            return false;
        }
    }
    return true;
}

} // namespace

std::string help_topic(int argc, char* argv[]) {
    if (argc < 2 || argv == nullptr || argv[1] == nullptr)
        return {};
    const std::string command{argv[1]};
    if (std::ranges::find(help_topics, command) == help_topics.end())
        return {};
    if ((command == "remote" || command == "gc") && argc > 2 &&
        argv[2] != nullptr) {
        const auto topic = command + " " + argv[2];
        if (std::ranges::find(help_topics, topic) != help_topics.end())
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
        if (argv[index] != nullptr && std::string_view{argv[index]} == "--") {
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
    if (command == "update") {
        return argc == 2
                   ? std::expected<Invocation, ParseError>{UpdateInvocation{}}
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
        bool trust_existing_content = false;
        for (int i = 3; i < argc; ++i) {
            if (argv[i] == nullptr) {
                return std::unexpected(ParseError{});
            }
            const std::string_view flag{argv[i]};
            if (flag == "--dry-run") {
                if (dry_run)
                    return std::unexpected(ParseError{});
                dry_run = true;
            } else if (flag == "--initial") {
                if (initial)
                    return std::unexpected(ParseError{});
                initial = true;
            } else if (flag == "--audit-inventory") {
                if (audit_inventory)
                    return std::unexpected(ParseError{});
                audit_inventory = true;
            } else if (flag == "--trust-existing-content") {
                if (trust_existing_content)
                    return std::unexpected(ParseError{});
                trust_existing_content = true;
            } else {
                return std::unexpected(ParseError{});
            }
        }
        if (audit_inventory && (dry_run || initial || trust_existing_content)) {
            return std::unexpected(
                ParseError{.unsupported_sync_audit_combination = true});
        }
        if (trust_existing_content && (!initial || dry_run)) {
            return std::unexpected(ParseError{});
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
            .trust_existing_content = trust_existing_content};
    }
    if (command == "status") {
        return request(application::Operation::Status, argc, argv);
    }
    if (command == "fsck") {
        return request(application::Operation::Fsck, argc, argv);
    }
    if (command == "gc") {
        if (argc >= 3 && argv[2] != nullptr &&
            std::string_view{argv[2]} == "remove-writer") {
            if (argc != 5 || !operand(argv[3]) || argv[4] == nullptr ||
                !application::history_storage::valid_writer_identifier(
                    argv[4])) {
                return std::unexpected(ParseError{});
            }
            return application::Request{
                .operation = application::Operation::RemoveWriter,
                .profile_name = argv[3],
                .writer_identifier = argv[4]};
        }
        if (argc >= 3 && argv[2] != nullptr &&
            std::string_view{argv[2]} == "remove-barrier") {
            if (argc != 5 || !operand(argv[3]) || argv[4] == nullptr ||
                std::string_view{argv[4]} != "--confirm-abandoned") {
                return std::unexpected(ParseError{});
            }
            return application::Request{
                .operation = application::Operation::RemoveBarrier,
                .profile_name = argv[3],
                .confirm_abandoned = true};
        }
        return request(application::Operation::GarbageCollect, argc, argv);
    }
    if (command == "resolve-missing") {
        return request(application::Operation::ResolveMissing, argc, argv);
    }
    if (command == "remote") {
        if (argc < 4 || argv[2] == nullptr || argv[3] == nullptr ||
            std::string_view{argv[3]}.empty()) {
            return std::unexpected(ParseError{});
        }
        const std::string_view inspection{argv[2]};
        if (!operand(argv[3]))
            return std::unexpected(ParseError{});
        if (inspection == "heads" && argc == 4) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteHeads,
                .profile_name = argv[3]};
        }
        if (inspection == "tree" && argc == 4) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteTree,
                .profile_name = argv[3]};
        }
        if (inspection == "tree" && argc == 6 && argv[4] != nullptr &&
            argv[5] != nullptr && std::string_view{argv[4]} == "--head" &&
            operand(argv[5])) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteTree,
                .profile_name = argv[3],
                .head_commit_id = std::string{argv[5]}};
        }
        if (inspection == "commits" && argc == 4) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteCommits,
                .profile_name = argv[3]};
        }
        if (inspection == "summary" && argc == 4) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteSummary,
                .profile_name = argv[3]};
        }
        if (inspection == "stat") {
            if (argc == 5 && argv[4] != nullptr && operand(argv[4])) {
                return application::InspectionRequest{
                    .operation = application::InspectionOperation::RemoteStat,
                    .profile_name = argv[3],
                    .logical_path = std::string{argv[4]}};
            }
            if (argc == 6 && argv[4] != nullptr && argv[5] != nullptr &&
                std::string_view{argv[4]} == "--" && literal_operand(argv[5])) {
                return application::InspectionRequest{
                    .operation = application::InspectionOperation::RemoteStat,
                    .profile_name = argv[3],
                    .logical_path = std::string{argv[5]}};
            }
            return std::unexpected(ParseError{});
        }
        if (inspection == "commit" && argc == 5 && argv[4] != nullptr &&
            valid_commit_id(argv[4])) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteCommit,
                .profile_name = argv[3],
                .commit_id = std::string{argv[4]}};
        }
        if (inspection == "get") {
            if (argc == 6 && argv[4] != nullptr && argv[5] != nullptr &&
                operand(argv[4]) && operand(argv[5])) {
                return application::InspectionRequest{
                    .operation = application::InspectionOperation::RemoteGet,
                    .profile_name = argv[3],
                    .logical_path = std::string{argv[4]},
                    .destination_path = std::string{argv[5]}};
            }
            if (argc == 7 && argv[4] != nullptr && argv[5] != nullptr &&
                argv[6] != nullptr) {
                if (std::string_view{argv[4]} == "--" &&
                    literal_operand(argv[5]) && literal_operand(argv[6])) {
                    return application::InspectionRequest{
                        .operation = application::InspectionOperation::RemoteGet,
                        .profile_name = argv[3],
                        .logical_path = std::string{argv[5]},
                        .destination_path = std::string{argv[6]}};
                }
                if (operand(argv[4]) && std::string_view{argv[5]} == "--" &&
                    literal_operand(argv[6])) {
                    return application::InspectionRequest{
                        .operation = application::InspectionOperation::RemoteGet,
                        .profile_name = argv[3],
                        .logical_path = std::string{argv[4]},
                        .destination_path = std::string{argv[6]}};
                }
            }
            return std::unexpected(ParseError{});
        }
        if (inspection == "epochs" && argc == 4) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteEpochs,
                .profile_name = argv[3]};
        }
        if (inspection == "epoch" && argc == 5 && argv[4] != nullptr &&
            operand(argv[4])) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteEpoch,
                .profile_name = argv[3],
                .epoch_selector = std::string{argv[4]}};
        }
        if (inspection == "contents" && argc == 4) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteContents,
                .profile_name = argv[3]};
        }
        if (inspection == "contents" && argc == 5 && argv[4] != nullptr &&
            std::string_view{argv[4]} == "--audit") {
            return application::InspectionRequest{
                .operation =
                    application::InspectionOperation::RemoteContentsAudit,
                .profile_name = argv[3]};
        }
        if (inspection == "content" && argc == 5 && argv[4] != nullptr &&
            valid_commit_id(argv[4])) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteContent,
                .profile_name = argv[3],
                .content_id = std::string{argv[4]}};
        }
        if (inspection == "markers" && argc == 4) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteMarkers,
                .profile_name = argv[3]};
        }
        if (inspection == "objects" && argc == 4) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteObjects,
                .profile_name = argv[3]};
        }
        if (inspection == "orphans" && argc == 4) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteOrphans,
                .profile_name = argv[3]};
        }
        if (inspection == "writers" && argc == 4) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteWriters,
                .profile_name = argv[3]};
        }
        if (inspection == "health" && argc == 4) {
            return application::InspectionRequest{
                .operation = application::InspectionOperation::RemoteHealth,
                .profile_name = argv[3]};
        }
        return std::unexpected(ParseError{});
    }
    return std::unexpected(ParseError{});
}

} // namespace kasumi::cli
