#include "cli/parser.hpp"

#include <gtest/gtest.h>
#include <string>
#include <variant>
#include <vector>

namespace {
using namespace kasumi::application;

auto parse(std::vector<std::string> arguments) {
    arguments.insert(arguments.begin(), "kasumi");
    std::vector<char*> argv;
    for (auto& argument : arguments)
        argv.push_back(argument.data());
    return kasumi::cli::parse(static_cast<int>(argv.size()), argv.data());
}
const std::string id(64, 'a');
const std::string writer =
    "2796e9c1/99b74a57/8973/0e7f7095/f51c45986e4bf1accbf45b9e2a14c8ab";
struct ApplicationCase {
    const char* name;
    std::vector<std::string> arguments;
    Request expected;
};
class ApplicationGrammarTest : public testing::TestWithParam<ApplicationCase> {
};
TEST_P(ApplicationGrammarTest, ParsesOperationAndArguments) {
    const auto& test = GetParam();
    const auto result = parse(test.arguments);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(std::holds_alternative<Request>(*result));
    const auto& actual = std::get<Request>(*result);
    EXPECT_EQ(actual.operation, test.expected.operation);
    EXPECT_EQ(actual.profile_name, test.expected.profile_name);
    EXPECT_EQ(actual.initial, test.expected.initial);
    EXPECT_EQ(actual.audit_inventory, test.expected.audit_inventory);
    EXPECT_EQ(actual.trust_existing_content,
              test.expected.trust_existing_content);
    EXPECT_EQ(actual.writer_identifier, test.expected.writer_identifier);
    EXPECT_EQ(actual.confirm_abandoned, test.expected.confirm_abandoned);
}
INSTANTIATE_TEST_SUITE_P(
    Canonical,
    ApplicationGrammarTest,
    testing::Values(
        ApplicationCase{"Sync",
                        {"sync", "demo"},
                        {.operation = Operation::Sync, .profile_name = "demo"}},
        ApplicationCase{
            "Preview",
            {"sync", "demo", "--dry-run"},
            {.operation = Operation::Preview, .profile_name = "demo"}},
        ApplicationCase{"InitialSync",
                        {"sync", "demo", "--initial"},
                        {.operation = Operation::Sync,
                         .profile_name = "demo",
                         .initial = true}},
        ApplicationCase{
            "TrustedBootstrap",
            {"sync", "demo", "--initial", "--trust-existing-content"},
            {.operation = Operation::Sync,
             .profile_name = "demo",
             .initial = true,
             .trust_existing_content = true}},
        ApplicationCase{"InventoryAudit",
                        {"sync", "demo", "--audit-inventory"},
                        {.operation = Operation::Sync,
                         .profile_name = "demo",
                         .audit_inventory = true}},
        ApplicationCase{
            "Status",
            {"status", "demo"},
            {.operation = Operation::Status, .profile_name = "demo"}},
        ApplicationCase{"Fsck",
                        {"fsck", "demo"},
                        {.operation = Operation::Fsck, .profile_name = "demo"}},
        ApplicationCase{
            "Gc",
            {"gc", "demo"},
            {.operation = Operation::GarbageCollect, .profile_name = "demo"}},
        ApplicationCase{"RemoveWriter",
                        {"gc", "remove-writer", "demo", writer},
                        {.operation = Operation::RemoveWriter,
                         .profile_name = "demo",
                         .writer_identifier = writer}},
        ApplicationCase{"RemoveBarrier",
                        {"gc", "remove-barrier", "demo", "--confirm-abandoned"},
                        {.operation = Operation::RemoveBarrier,
                         .profile_name = "demo",
                         .confirm_abandoned = true}},
        ApplicationCase{
            "ResolveMissing",
            {"resolve-missing", "demo"},
            {.operation = Operation::ResolveMissing, .profile_name = "demo"}},
        ApplicationCase{"UnicodeProfile",
                        {"status", "Programação-日本 com espaço"},
                        {.operation = Operation::Status,
                         .profile_name = "Programação-日本 com espaço"}}),
    [](const auto& case_info) {
        return case_info.param.name;
    });
struct InspectionCase {
    const char* name;
    std::vector<std::string> arguments;
    InspectionRequest expected;
};
class InspectionGrammarTest : public testing::TestWithParam<InspectionCase> {};
TEST_P(InspectionGrammarTest, ParsesOperationAndSelectors) {
    const auto& test = GetParam();
    const auto result = parse(test.arguments);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(std::holds_alternative<InspectionRequest>(*result));
    const auto& actual = std::get<InspectionRequest>(*result);
    EXPECT_EQ(actual.operation, test.expected.operation);
    EXPECT_EQ(actual.profile_name, test.expected.profile_name);
    EXPECT_EQ(actual.head_commit_id, test.expected.head_commit_id);
    EXPECT_EQ(actual.logical_path, test.expected.logical_path);
    EXPECT_EQ(actual.commit_id, test.expected.commit_id);
    EXPECT_EQ(actual.destination_path, test.expected.destination_path);
    EXPECT_EQ(actual.epoch_selector, test.expected.epoch_selector);
    EXPECT_EQ(actual.content_id, test.expected.content_id);
}
INSTANTIATE_TEST_SUITE_P(
    Canonical,
    InspectionGrammarTest,
    testing::Values(
        InspectionCase{"Heads",
                       {"remote", "heads", "demo"},
                       {.operation = InspectionOperation::RemoteHeads,
                        .profile_name = "demo"}},
        InspectionCase{"Tree",
                       {"remote", "tree", "demo"},
                       {.operation = InspectionOperation::RemoteTree,
                        .profile_name = "demo"}},
        InspectionCase{"SelectedTree",
                       {"remote", "tree", "demo", "--head", id},
                       {.operation = InspectionOperation::RemoteTree,
                        .profile_name = "demo",
                        .head_commit_id = id}},
        InspectionCase{"Commits",
                       {"remote", "commits", "demo"},
                       {.operation = InspectionOperation::RemoteCommits,
                        .profile_name = "demo"}},
        InspectionCase{"Summary",
                       {"remote", "summary", "demo"},
                       {.operation = InspectionOperation::RemoteSummary,
                        .profile_name = "demo"}},
        InspectionCase{"Stat",
                       {"remote", "stat", "demo", "álbum/foto 日本.jpg"},
                       {.operation = InspectionOperation::RemoteStat,
                        .profile_name = "demo",
                        .logical_path = "álbum/foto 日本.jpg"}},
        InspectionCase{"RootStat",
                       {"remote", "stat", "demo", "/"},
                       {.operation = InspectionOperation::RemoteStat,
                        .profile_name = "demo",
                        .logical_path = "/"}},
        InspectionCase{"StatHyphenPath",
                       {"remote", "stat", "demo", "--", "--notes.txt"},
                       {.operation = InspectionOperation::RemoteStat,
                        .profile_name = "demo",
                        .logical_path = "--notes.txt"}},
        InspectionCase{"StatHyphenSingleDash",
                       {"remote", "stat", "demo", "--", "-draft.txt"},
                       {.operation = InspectionOperation::RemoteStat,
                        .profile_name = "demo",
                        .logical_path = "-draft.txt"}},
        InspectionCase{"StatHelpAsLiteralPath",
                       {"remote", "stat", "demo", "--", "--help"},
                       {.operation = InspectionOperation::RemoteStat,
                        .profile_name = "demo",
                        .logical_path = "--help"}},
        InspectionCase{"Commit",
                       {"remote", "commit", "demo", id},
                       {.operation = InspectionOperation::RemoteCommit,
                        .profile_name = "demo",
                        .commit_id = id}},
        InspectionCase{"Get",
                       {"remote",
                        "get",
                        "demo",
                        "álbum/foto 日本.jpg",
                        "downloads/foto 日本.jpg"},
                       {.operation = InspectionOperation::RemoteGet,
                        .profile_name = "demo",
                        .logical_path = "álbum/foto 日本.jpg",
                        .destination_path = "downloads/foto 日本.jpg"}},
        InspectionCase{"GetHyphenSource",
                       {"remote",
                        "get",
                        "demo",
                        "--",
                        "--notes.txt",
                        "output.txt"},
                       {.operation = InspectionOperation::RemoteGet,
                        .profile_name = "demo",
                        .logical_path = "--notes.txt",
                        .destination_path = "output.txt"}},
        InspectionCase{"GetHyphenDestination",
                       {"remote",
                        "get",
                        "demo",
                        "notes.txt",
                        "--",
                        "-output.txt"},
                       {.operation = InspectionOperation::RemoteGet,
                        .profile_name = "demo",
                        .logical_path = "notes.txt",
                        .destination_path = "-output.txt"}},
        InspectionCase{"GetBothHyphen",
                       {"remote",
                        "get",
                        "demo",
                        "--",
                        "--notes.txt",
                        "-output.txt"},
                       {.operation = InspectionOperation::RemoteGet,
                        .profile_name = "demo",
                        .logical_path = "--notes.txt",
                        .destination_path = "-output.txt"}},
        InspectionCase{"Epochs",
                       {"remote", "epochs", "demo"},
                       {.operation = InspectionOperation::RemoteEpochs,
                        .profile_name = "demo"}},
        InspectionCase{"EpochId",
                       {"remote", "epoch", "demo", id},
                       {.operation = InspectionOperation::RemoteEpoch,
                        .profile_name = "demo",
                        .epoch_selector = id}},
        InspectionCase{"EpochSequence",
                       {"remote", "epoch", "demo", "42"},
                       {.operation = InspectionOperation::RemoteEpoch,
                        .profile_name = "demo",
                        .epoch_selector = "42"}},
        InspectionCase{"Contents",
                       {"remote", "contents", "demo"},
                       {.operation = InspectionOperation::RemoteContents,
                        .profile_name = "demo"}},
        InspectionCase{"ContentAudit",
                       {"remote", "contents", "demo", "--audit"},
                       {.operation = InspectionOperation::RemoteContentsAudit,
                        .profile_name = "demo"}},
        InspectionCase{"Content",
                       {"remote", "content", "demo", id},
                       {.operation = InspectionOperation::RemoteContent,
                        .profile_name = "demo",
                        .content_id = id}},
        InspectionCase{"Markers",
                       {"remote", "markers", "demo"},
                       {.operation = InspectionOperation::RemoteMarkers,
                        .profile_name = "demo"}},
        InspectionCase{"Objects",
                       {"remote", "objects", "demo"},
                       {.operation = InspectionOperation::RemoteObjects,
                        .profile_name = "demo"}},
        InspectionCase{"Orphans",
                       {"remote", "orphans", "demo"},
                       {.operation = InspectionOperation::RemoteOrphans,
                        .profile_name = "demo"}},
        InspectionCase{"Writers",
                       {"remote", "writers", "demo"},
                       {.operation = InspectionOperation::RemoteWriters,
                        .profile_name = "demo"}},
        InspectionCase{"Health",
                       {"remote", "health", "demo"},
                       {.operation = InspectionOperation::RemoteHealth,
                        .profile_name = "demo"}}),
    [](const auto& case_info) {
        return case_info.param.name;
    });
struct InvalidCase {
    const char* name;
    std::vector<std::string> arguments;
};
class InvalidGrammarTest : public testing::TestWithParam<InvalidCase> {};
TEST_P(InvalidGrammarTest, RejectsInvalidInput) {
    const auto result = parse(GetParam().arguments);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().exit_code, 1);
}
INSTANTIATE_TEST_SUITE_P(
    EquivalenceClasses,
    InvalidGrammarTest,
    testing::Values(
        InvalidCase{"MissingCommand", {}},
        InvalidCase{"UnknownCommand", {"unknown"}},
        InvalidCase{"MissingProfile", {"sync"}},
        InvalidCase{"EmptyOperand", {"status", ""}},
        InvalidCase{"OptionInOperandSlot", {"status", "--unknown"}},
        InvalidCase{"ExtraOperand", {"status", "demo", "extra"}},
        InvalidCase{"UnknownSubcommand", {"remote", "unknown", "demo"}},
        InvalidCase{"MissingRemoteOperand", {"remote", "get", "demo", "file"}},
        InvalidCase{"StatMissingDelimiterOperand", {"remote", "stat", "demo", "--"}},
        InvalidCase{"StatDelimiterExtraOperand",
                    {"remote", "stat", "demo", "--", "--notes.txt", "extra"}},
        InvalidCase{"StatHyphenWithoutDelimiter",
                    {"remote", "stat", "demo", "--notes.txt"}},
        InvalidCase{"GetMissingDelimiterOperand",
                    {"remote", "get", "demo", "--", "--notes.txt"}},
        InvalidCase{"GetDelimiterExtraOperand",
                    {"remote", "get", "demo", "--", "--notes.txt", "dest", "extra"}},
        InvalidCase{"UnknownOption", {"sync", "demo", "--unknown"}},
        InvalidCase{"DuplicateSwitch",
                    {"sync", "demo", "--dry-run", "--dry-run"}},
        InvalidCase{"DuplicateValueOption",
                    {"remote", "tree", "demo", "--head", id, "--head", id}},
        InvalidCase{"MissingOptionValue", {"remote", "tree", "demo", "--head"}},
        InvalidCase{"OptionAsValue",
                    {"remote", "tree", "demo", "--head", "--unknown"}},
        InvalidCase{"WrongCommandOption",
                    {"remote", "heads", "demo", "--audit"}},
        InvalidCase{"MutuallyExclusiveModes",
                    {"sync", "demo", "--dry-run", "--initial"}},
        InvalidCase{"AuditIncompatibleMode",
                    {"sync", "demo", "--audit-inventory", "--initial"}},
        InvalidCase{"TrustRequiresInitial",
                    {"sync", "demo", "--trust-existing-content"}},
        InvalidCase{"RequiredConfirmation", {"gc", "remove-barrier", "demo"}},
        InvalidCase{"InvalidWriterIdentity",
                    {"gc", "remove-writer", "demo", "../writer"}}),
    [](const auto& case_info) {
        return case_info.param.name;
    });
class IdentifierGrammarTest : public testing::TestWithParam<std::string> {};
TEST_P(IdentifierGrammarTest, RejectsIdsOutsideTheLowercaseHexBoundary) {
    for (const auto* command : {"commit", "content"}) {
        EXPECT_FALSE(
            parse({"remote", command, "demo", GetParam()}).has_value());
    }
}
INSTANTIATE_TEST_SUITE_P(Boundaries,
                         IdentifierGrammarTest,
                         testing::Values(std::string(63, 'a'),
                                         std::string(65, 'a'),
                                         std::string(64, 'A'),
                                         std::string(64, 'z')));
TEST(CliParserTest, ParsesInteractiveConfiguration) {
    const auto result = parse({"config"});
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(
        std::holds_alternative<kasumi::cli::ConfigureInvocation>(*result));
}
} // namespace
