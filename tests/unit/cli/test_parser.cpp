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
    EXPECT_EQ(actual.repair, test.expected.repair);
    EXPECT_EQ(actual.writer_identifier, test.expected.writer_identifier);
    EXPECT_EQ(actual.confirm_abandoned, test.expected.confirm_abandoned);
    EXPECT_EQ(actual.confirm, test.expected.confirm);
    EXPECT_EQ(actual.dry_run, test.expected.dry_run);
    EXPECT_EQ(actual.reclaim_dirty, test.expected.reclaim_dirty);
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
        ApplicationCase{"InventoryAudit",
                        {"sync", "demo", "--audit-inventory"},
                        {.operation = Operation::Sync,
                         .profile_name = "demo",
                         .audit_inventory = true}},
        ApplicationCase{"SyncRepair",
                        {"sync", "demo", "--repair"},
                        {.operation = Operation::Sync,
                         .profile_name = "demo",
                         .repair = true}},
        ApplicationCase{"SyncRepairWithAudit",
                        {"sync", "demo", "--repair", "--audit-inventory"},
                        {.operation = Operation::Sync,
                         .profile_name = "demo",
                         .audit_inventory = true,
                         .repair = true}},
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
        ApplicationCase{"GcDryRun",
                        {"gc", "demo", "--dry-run"},
                        {.operation = Operation::GarbageCollect,
                         .profile_name = "demo",
                         .dry_run = true}},
        ApplicationCase{"GcMinAgeZero",
                        {"gc", "demo", "--min-age", "0"},
                        {.operation = Operation::GarbageCollect,
                         .profile_name = "demo",
                         .gc_min_age_hours = 0}},
        ApplicationCase{"GcMinAgeEquals",
                        {"gc", "demo", "--min-age=48", "--dry-run"},
                        {.operation = Operation::GarbageCollect,
                         .profile_name = "demo",
                         .dry_run = true,
                         .gc_min_age_hours = 48}},
        ApplicationCase{"GcDryRunBeforeMinAge",
                        {"gc", "demo", "--dry-run", "--min-age", "8760"},
                        {.operation = Operation::GarbageCollect,
                         .profile_name = "demo",
                         .dry_run = true,
                         .gc_min_age_hours = 8760}},
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
            "RemoveBarrierWithIdBeforeFlag",
            {"gc", "remove-barrier", "demo", "deadbeef", "--confirm-abandoned"},
            {.operation = Operation::RemoveBarrier,
             .profile_name = "demo",
             .barrier_identifier = "deadbeef",
             .confirm_abandoned = true}},
        ApplicationCase{
            "RemoveBarrierWithIdAfterFlag",
            {"gc", "remove-barrier", "demo", "--confirm-abandoned", "deadbeef"},
            {.operation = Operation::RemoveBarrier,
             .profile_name = "demo",
             .barrier_identifier = "deadbeef",
             .confirm_abandoned = true}},
        ApplicationCase{
            "Repack",
            {"repack", "demo"},
            {.operation = Operation::Repack, .profile_name = "demo"}},
        ApplicationCase{"RepackDryRun",
                        {"repack", "demo", "--dry-run"},
                        {.operation = Operation::Repack,
                         .profile_name = "demo",
                         .dry_run = true}},
        ApplicationCase{"RepackReclaimDirty",
                        {"repack", "demo", "--reclaim-dirty"},
                        {.operation = Operation::Repack,
                         .profile_name = "demo",
                         .reclaim_dirty = true}},
        ApplicationCase{"RepackDryRunAndReclaimDirty",
                        {"repack", "demo", "--reclaim-dirty", "--dry-run"},
                        {.operation = Operation::Repack,
                         .profile_name = "demo",
                         .dry_run = true,
                         .reclaim_dirty = true}},
        ApplicationCase{
            "ResolveMissing",
            {"resolve-missing", "demo"},
            {.operation = Operation::ResolveMissing, .profile_name = "demo"}},
        ApplicationCase{"ResolveMissingConfirm",
                        {"resolve-missing", "demo", "--confirm"},
                        {.operation = Operation::ResolveMissing,
                         .profile_name = "demo",
                         .confirm = true}},
        ApplicationCase{"ResolveMissingDryRun",
                        {"resolve-missing", "demo", "--dry-run"},
                        {.operation = Operation::ResolveMissing,
                         .profile_name = "demo",
                         .dry_run = true}},
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
        InspectionCase{
            "GetHyphenSource",
            {"remote", "get", "demo", "--", "--notes.txt", "output.txt"},
            {.operation = InspectionOperation::RemoteGet,
             .profile_name = "demo",
             .logical_path = "--notes.txt",
             .destination_path = "output.txt"}},
        InspectionCase{
            "GetHyphenDestination",
            {"remote", "get", "demo", "notes.txt", "--", "-output.txt"},
            {.operation = InspectionOperation::RemoteGet,
             .profile_name = "demo",
             .logical_path = "notes.txt",
             .destination_path = "-output.txt"}},
        InspectionCase{
            "GetBothHyphen",
            {"remote", "get", "demo", "--", "--notes.txt", "-output.txt"},
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
        InvalidCase{"StatMissingDelimiterOperand",
                    {"remote", "stat", "demo", "--"}},
        InvalidCase{"StatDelimiterExtraOperand",
                    {"remote", "stat", "demo", "--", "--notes.txt", "extra"}},
        InvalidCase{"StatHyphenWithoutDelimiter",
                    {"remote", "stat", "demo", "--notes.txt"}},
        InvalidCase{"GetMissingDelimiterOperand",
                    {"remote", "get", "demo", "--", "--notes.txt"}},
        InvalidCase{
            "GetDelimiterExtraOperand",
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
        InvalidCase{"RepairDuplicate",
                    {"sync", "demo", "--repair", "--repair"}},
        InvalidCase{"RepairWithDryRun",
                    {"sync", "demo", "--repair", "--dry-run"}},
        InvalidCase{"RepairWithInitial",
                    {"sync", "demo", "--repair", "--initial"}},
        InvalidCase{"RequiredConfirmation", {"gc", "remove-barrier", "demo"}},
        InvalidCase{"GcDuplicateDryRun",
                    {"gc", "demo", "--dry-run", "--dry-run"}},
        InvalidCase{"GcMinAgeMissingValue", {"gc", "demo", "--min-age"}},
        InvalidCase{"GcMinAgeEmptyEquals", {"gc", "demo", "--min-age="}},
        InvalidCase{"GcMinAgeNegative", {"gc", "demo", "--min-age", "-1"}},
        InvalidCase{"GcMinAgeNonNumeric", {"gc", "demo", "--min-age", "12h"}},
        InvalidCase{"GcMinAgeOutOfRange", {"gc", "demo", "--min-age", "8761"}},
        InvalidCase{"GcDuplicateMinAge",
                    {"gc", "demo", "--min-age", "6", "--min-age=12"}},
        InvalidCase{"GcMinAgeOnRemoveWriter",
                    {"gc", "remove-writer", "demo", writer, "--min-age", "0"}},
        InvalidCase{"GcMinAgeOnRemoveBarrier",
                    {"gc",
                     "remove-barrier",
                     "demo",
                     "--confirm-abandoned",
                     "--min-age",
                     "0"}},
        InvalidCase{"GcDryRunOnSubcommand",
                    {"gc", "remove-writer", "demo", writer, "--dry-run"}},
        InvalidCase{"GcUnknownOption", {"gc", "demo", "--initial"}},
        InvalidCase{"InvalidWriterIdentity",
                    {"gc", "remove-writer", "demo", "../writer"}},
        InvalidCase{"RepackMissingProfile", {"repack"}},
        InvalidCase{"RepackDuplicateDryRun",
                    {"repack", "demo", "--dry-run", "--dry-run"}},
        InvalidCase{"RepackDuplicateReclaimDirty",
                    {"repack", "demo", "--reclaim-dirty", "--reclaim-dirty"}},
        InvalidCase{"RepackUnknownOption", {"repack", "demo", "--initial"}},
        InvalidCase{"RepackExtraOperand", {"repack", "demo", "extra"}},
        InvalidCase{"ResolveMissingDuplicateConfirm",
                    {"resolve-missing", "demo", "--confirm", "--confirm"}},
        InvalidCase{"ResolveMissingConfirmWithDryRun",
                    {"resolve-missing", "demo", "--confirm", "--dry-run"}},
        InvalidCase{"ResolveMissingUnknownOption",
                    {"resolve-missing", "demo", "--initial"}}),
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

TEST(CliParserTest, ParsesRepackHelpTopic) {
    for (const auto& args : std::vector<std::vector<std::string>>{
             {"repack", "--help"},
             {"repack", "demo", "--dry-run", "--help"},
         }) {
        const auto result = parse(args);
        ASSERT_TRUE(result.has_value());
        ASSERT_TRUE(
            std::holds_alternative<kasumi::cli::HelpInvocation>(*result));
        EXPECT_EQ(std::get<kasumi::cli::HelpInvocation>(*result).topic,
                  "repack");
    }
}

TEST(CliParserTest,
     ParsesDiagnosticsWithOptionalProfileAndRejectsExtraOperands) {
    const auto bare = parse({"diagnostics"});
    ASSERT_TRUE(bare.has_value());
    ASSERT_TRUE(
        std::holds_alternative<kasumi::cli::DiagnosticsInvocation>(*bare));
    EXPECT_TRUE(std::get<kasumi::cli::DiagnosticsInvocation>(*bare)
                    .profile_name.empty());

    const auto single = parse({"diagnostics", "demo"});
    ASSERT_TRUE(single.has_value());
    ASSERT_TRUE(
        std::holds_alternative<kasumi::cli::DiagnosticsInvocation>(*single));
    EXPECT_EQ(
        std::get<kasumi::cli::DiagnosticsInvocation>(*single).profile_name,
        "demo");

    const auto help = parse({"diagnostics", "--help"});
    ASSERT_TRUE(help.has_value());
    ASSERT_TRUE(std::holds_alternative<kasumi::cli::HelpInvocation>(*help));
    EXPECT_EQ(std::get<kasumi::cli::HelpInvocation>(*help).topic,
              "diagnostics");

    EXPECT_FALSE(parse({"diagnostics", "--unknown"}).has_value());
    EXPECT_FALSE(parse({"diagnostics", "demo", "extra"}).has_value());
    EXPECT_FALSE(
        parse({"gc", "remove-barrier", "demo", "deadbeef"}).has_value());
    EXPECT_FALSE(parse({"gc",
                        "remove-barrier",
                        "demo",
                        "id1",
                        "id2",
                        "--confirm-abandoned"})
                     .has_value());
}

TEST(CliParserTest, ParsesRemoteStatAndGetWithCommitSelector) {
    const auto stat_res =
        parse({"remote", "stat", "demo", "a.txt", "--commit", id});
    ASSERT_TRUE(stat_res.has_value());
    ASSERT_TRUE(std::holds_alternative<InspectionRequest>(*stat_res));
    const auto& stat_req = std::get<InspectionRequest>(*stat_res);
    EXPECT_EQ(stat_req.operation, InspectionOperation::RemoteStat);
    EXPECT_EQ(stat_req.logical_path, "a.txt");
    EXPECT_EQ(stat_req.commit_id, id);

    const auto get_res = parse({"remote",
                                "get",
                                "demo",
                                "--commit=" + id,
                                "--",
                                "-src.txt",
                                "-dst.txt"});
    ASSERT_TRUE(get_res.has_value());
    ASSERT_TRUE(std::holds_alternative<InspectionRequest>(*get_res));
    const auto& get_req = std::get<InspectionRequest>(*get_res);
    EXPECT_EQ(get_req.operation, InspectionOperation::RemoteGet);
    EXPECT_EQ(get_req.logical_path, "-src.txt");
    EXPECT_EQ(get_req.destination_path, "-dst.txt");
    EXPECT_EQ(get_req.commit_id, id);

    EXPECT_FALSE(
        parse({"remote", "stat", "demo", "a.txt", "--commit", "badhex"})
            .has_value());
    EXPECT_FALSE(parse({"remote",
                        "get",
                        "demo",
                        "a.txt",
                        "b.txt",
                        "--commit",
                        id,
                        "--commit=" + id})
                     .has_value());
}

TEST(CliParserTest, ParsesProfileConflictsAndCompletionCommands) {
    const auto conflicts = parse({"conflicts", "demo"});
    ASSERT_TRUE(conflicts.has_value());
    ASSERT_TRUE(
        std::holds_alternative<kasumi::cli::ConflictsInvocation>(*conflicts));
    EXPECT_EQ(
        std::get<kasumi::cli::ConflictsInvocation>(*conflicts).profile_name,
        "demo");
    EXPECT_FALSE(parse({"conflicts"}).has_value());

    for (const auto& [name, expected_shell] :
         std::vector<std::pair<std::string, kasumi::cli::CompletionShell>>{
             {"bash", kasumi::cli::CompletionShell::Bash},
             {"zsh", kasumi::cli::CompletionShell::Zsh},
             {"fish", kasumi::cli::CompletionShell::Fish},
             {"powershell", kasumi::cli::CompletionShell::PowerShell},
         }) {
        const auto comp = parse({"completion", name});
        ASSERT_TRUE(comp.has_value());
        ASSERT_TRUE(
            std::holds_alternative<kasumi::cli::CompletionInvocation>(*comp));
        EXPECT_EQ(std::get<kasumi::cli::CompletionInvocation>(*comp).shell,
                  expected_shell);
        const auto script =
            kasumi::cli::generate_completion_script(expected_shell);
        EXPECT_NE(script.find("kasumi"), std::string::npos);
        EXPECT_NE(script.find("profile"), std::string::npos);
    }
    EXPECT_FALSE(parse({"completion", "tcsh"}).has_value());

    const auto create = parse({"profile",
                               "create",
                               "work",
                               "--local",
                               "/data/work",
                               "--remote=drive:work",
                               "--key-storage",
                               "file",
                               "--min-depth",
                               "10",
                               "--min-age=24"});
    ASSERT_TRUE(create.has_value());
    ASSERT_TRUE(
        std::holds_alternative<kasumi::cli::ProfileInvocation>(*create));
    const auto& create_inv = std::get<kasumi::cli::ProfileInvocation>(*create);
    EXPECT_EQ(create_inv.action, kasumi::cli::ProfileAction::Create);
    EXPECT_EQ(create_inv.profile_name, "work");
    EXPECT_EQ(create_inv.local_dir, "/data/work");
    EXPECT_EQ(create_inv.remote_dir, "drive:work");
    EXPECT_EQ(create_inv.key_storage, kasumi::application::KeyStorage::File);
    EXPECT_EQ(create_inv.min_history_depth, 10U);
    EXPECT_EQ(create_inv.min_history_age_hours, 24U);

    EXPECT_FALSE(
        parse({"profile", "create", "work", "--local", "/data"}).has_value());
    EXPECT_FALSE(parse({"profile", "edit", "work"}).has_value());
    EXPECT_FALSE(parse({"profile", "delete", "work"}).has_value());

    const auto del = parse({"profile", "delete", "work", "--confirm"});
    ASSERT_TRUE(del.has_value());
    EXPECT_EQ(std::get<kasumi::cli::ProfileInvocation>(*del).action,
              kasumi::cli::ProfileAction::Delete);
    EXPECT_TRUE(std::get<kasumi::cli::ProfileInvocation>(*del).confirm);

    // remote log & remote restore
    const auto rlog = parse({"remote", "log", "demo", "docs/a.txt"});
    ASSERT_TRUE(rlog.has_value());
    const auto& rlog_req =
        std::get<kasumi::application::InspectionRequest>(*rlog);
    EXPECT_EQ(rlog_req.operation,
              kasumi::application::InspectionOperation::RemoteLog);
    EXPECT_EQ(rlog_req.logical_path, "docs/a.txt");
    EXPECT_FALSE(parse({"remote",
                        "log",
                        "demo",
                        "docs/a.txt",
                        "--commit",
                        std::string(64, 'a')})
                     .has_value());

    const auto rrestore_root =
        parse({"remote", "restore", "demo", "/tmp/restore", "--dry-run"});
    ASSERT_TRUE(rrestore_root.has_value());
    const auto& rr_req =
        std::get<kasumi::application::InspectionRequest>(*rrestore_root);
    EXPECT_EQ(rr_req.operation,
              kasumi::application::InspectionOperation::RemoteRestore);
    EXPECT_FALSE(rr_req.logical_path.has_value());
    EXPECT_EQ(rr_req.destination_path, "/tmp/restore");
    EXPECT_TRUE(rr_req.dry_run);

    const std::string cid(64, 'a');
    const auto rrestore_sub = parse(
        {"remote", "restore", "demo", "docs", "/tmp/out", "--commit", cid});
    ASSERT_TRUE(rrestore_sub.has_value());
    const auto& rrs_req =
        std::get<kasumi::application::InspectionRequest>(*rrestore_sub);
    EXPECT_EQ(rrs_req.logical_path, "docs");
    EXPECT_EQ(rrs_req.destination_path, "/tmp/out");
    EXPECT_EQ(rrs_req.commit_id, cid);

    // conflicts resolve
    const auto cres_can =
        parse({"conflicts", "resolve", "demo", "a.txt", "--keep-canonical"});
    ASSERT_TRUE(cres_can.has_value());
    const auto& cres_inv =
        std::get<kasumi::cli::ConflictsInvocation>(*cres_can);
    EXPECT_TRUE(cres_inv.resolve);
    EXPECT_EQ(cres_inv.profile_name, "demo");
    EXPECT_EQ(cres_inv.canonical_path, "a.txt");
    EXPECT_EQ(cres_inv.choice,
              kasumi::application::ConflictResolutionChoice::KeepCanonical);

    const auto cres_art = parse(
        {"conflicts", "resolve", "demo", "a.txt", "--keep=local", "--dry-run"});
    ASSERT_TRUE(cres_art.has_value());
    const auto& cres_art_inv =
        std::get<kasumi::cli::ConflictsInvocation>(*cres_art);
    EXPECT_EQ(cres_art_inv.choice,
              kasumi::application::ConflictResolutionChoice::KeepArtifact);
    EXPECT_EQ(cres_art_inv.artifact_selector, "local");
    EXPECT_TRUE(cres_art_inv.dry_run);

    EXPECT_FALSE(parse({"conflicts", "resolve"}).has_value());
    EXPECT_FALSE(parse({"conflicts", "resolve", "demo", "a.txt"}).has_value());
    EXPECT_FALSE(parse({"conflicts",
                        "resolve",
                        "demo",
                        "a.txt",
                        "--keep-canonical",
                        "--keep",
                        "local"})
                     .has_value());

    // v0.26.0 flags and subcommands
    const auto key_rep = parse({"key", "demo", "--replace"});
    ASSERT_TRUE(key_rep.has_value());
    EXPECT_TRUE(std::get<kasumi::cli::KeyInvocation>(*key_rep).replace);
    EXPECT_FALSE(parse({"key", "demo", "--unknown"}).has_value());

    const auto pcreate_net = parse({"profile",
                                    "create",
                                    "net",
                                    "--local",
                                    "/data/net",
                                    "--remote",
                                    "drive:net",
                                    "--bwlimit",
                                    "10M:5M",
                                    "--concurrency=4",
                                    "--rclone-config",
                                    "/etc/rclone.conf",
                                    "--verify"});
    ASSERT_TRUE(pcreate_net.has_value());
    const auto& pcreate_inv =
        std::get<kasumi::cli::ProfileInvocation>(*pcreate_net);
    EXPECT_EQ(pcreate_inv.bandwidth_limit, "10M:5M");
    EXPECT_EQ(pcreate_inv.transfer_concurrency, 4U);
    EXPECT_EQ(pcreate_inv.rclone_config, "/etc/rclone.conf");
    EXPECT_TRUE(pcreate_inv.verify);
    EXPECT_FALSE(parse({"profile",
                        "create",
                        "net",
                        "--local",
                        "/data/net",
                        "--remote",
                        "drive:net",
                        "--clear-bwlimit"})
                     .has_value());

    const auto pedit_clear = parse({"profile",
                                    "edit",
                                    "net",
                                    "--clear-bwlimit",
                                    "--clear-concurrency",
                                    "--clear-rclone-config",
                                    "--allow-empty-local"});
    ASSERT_TRUE(pedit_clear.has_value());
    const auto& pedit_inv =
        std::get<kasumi::cli::ProfileInvocation>(*pedit_clear);
    EXPECT_TRUE(pedit_inv.clear_bandwidth_limit);
    EXPECT_TRUE(pedit_inv.clear_transfer_concurrency);
    EXPECT_TRUE(pedit_inv.clear_rclone_config);
    EXPECT_TRUE(pedit_inv.allow_empty_local);
    EXPECT_FALSE(
        parse({"profile", "edit", "net", "--allow-empty-local"}).has_value());
    EXPECT_FALSE(
        parse({"profile", "edit", "net", "--bwlimit", "5M", "--clear-bwlimit"})
            .has_value());

    const auto ptest = parse({"profile", "test", "net"});
    ASSERT_TRUE(ptest.has_value());
    EXPECT_EQ(std::get<kasumi::cli::ProfileInvocation>(*ptest).action,
              kasumi::cli::ProfileAction::Test);

    const auto sync_net = parse({"sync",
                                 "net",
                                 "--allow-empty-local",
                                 "--bwlimit",
                                 "2M",
                                 "--concurrency",
                                 "12"});
    ASSERT_TRUE(sync_net.has_value());
    const auto& sync_req = std::get<kasumi::application::Request>(*sync_net);
    EXPECT_TRUE(sync_req.allow_empty_local);
    EXPECT_EQ(sync_req.bandwidth_limit, "2M");
    EXPECT_EQ(sync_req.transfer_concurrency, 12U);
    EXPECT_FALSE(parse({"sync", "net", "--concurrency", "0"}).has_value());
    EXPECT_FALSE(parse({"sync", "net", "--concurrency", "17"}).has_value());

    const auto remote_net = parse({"remote",
                                   "stat",
                                   "net",
                                   "--bwlimit",
                                   "4M",
                                   "--concurrency",
                                   "3",
                                   "--",
                                   "-leading-dash.txt"});
    ASSERT_TRUE(remote_net.has_value());
    const auto& rem_req =
        std::get<kasumi::application::InspectionRequest>(*remote_net);
    EXPECT_EQ(rem_req.bandwidth_limit, "4M");
    EXPECT_EQ(rem_req.transfer_concurrency, 3U);
    EXPECT_EQ(rem_req.logical_path, "-leading-dash.txt");

    const auto ign_chk =
        parse({"ignore", "check", "net", "build/app.o", "--", "-odd.log"});
    ASSERT_TRUE(ign_chk.has_value());
    const auto& ign_chk_inv = std::get<kasumi::cli::IgnoreInvocation>(*ign_chk);
    EXPECT_EQ(ign_chk_inv.action, kasumi::cli::IgnoreAction::Check);
    EXPECT_EQ(ign_chk_inv.paths.size(), 2U);
    EXPECT_FALSE(parse({"ignore", "check", "net"}).has_value());

    const auto ign_init = parse(
        {"ignore", "init", "net", "--preset", "dev", "--force", "--dry-run"});
    ASSERT_TRUE(ign_init.has_value());
    const auto& ign_init_inv =
        std::get<kasumi::cli::IgnoreInvocation>(*ign_init);
    EXPECT_EQ(ign_init_inv.action, kasumi::cli::IgnoreAction::Init);
    EXPECT_EQ(ign_init_inv.preset, kasumi::application::IgnorePreset::Dev);
    EXPECT_TRUE(ign_init_inv.force);
    EXPECT_TRUE(ign_init_inv.dry_run);
    EXPECT_FALSE(
        parse({"ignore", "init", "net", "--preset", "bogus"}).has_value());

    // Profile create/edit daemon automation options.
    const auto p_auto = parse({"profile",
                               "create",
                               "auto_p",
                               "--local",
                               "/data/auto",
                               "--remote",
                               "drive:auto",
                               "--watch",
                               "off",
                               "--sync-interval",
                               "120",
                               "--gc-interval",
                               "12",
                               "--paused",
                               "on"});
    ASSERT_TRUE(p_auto.has_value());
    const auto& p_auto_inv = std::get<kasumi::cli::ProfileInvocation>(*p_auto);
    EXPECT_EQ(p_auto_inv.watch_enabled, false);
    EXPECT_EQ(p_auto_inv.sync_interval_seconds, 120U);
    EXPECT_EQ(p_auto_inv.gc_interval_hours, 12U);
    EXPECT_EQ(p_auto_inv.paused, true);

    const auto p_edit_auto = parse({"profile",
                                    "edit",
                                    "auto_p",
                                    "--clear-watch",
                                    "--clear-sync-interval",
                                    "--clear-gc-interval",
                                    "--paused=off"});
    ASSERT_TRUE(p_edit_auto.has_value());
    const auto& p_edit_auto_inv =
        std::get<kasumi::cli::ProfileInvocation>(*p_edit_auto);
    EXPECT_TRUE(p_edit_auto_inv.clear_watch_enabled);
    EXPECT_TRUE(p_edit_auto_inv.clear_sync_interval_seconds);
    EXPECT_TRUE(p_edit_auto_inv.clear_gc_interval_hours);
    EXPECT_EQ(p_edit_auto_inv.paused, false);

    EXPECT_FALSE(parse({"profile",
                        "create",
                        "auto_p",
                        "--local",
                        "/data/auto",
                        "--remote",
                        "drive:auto",
                        "--sync-interval",
                        "5"})
                     .has_value());
    EXPECT_FALSE(
        parse({"profile", "edit", "auto_p", "--watch", "on", "--clear-watch"})
            .has_value());

    // Daemon subcommands.
    const auto d_run = parse({"daemon", "run", "--background"});
    ASSERT_TRUE(d_run.has_value());
    EXPECT_EQ(std::get<kasumi::cli::DaemonInvocation>(*d_run).action,
              kasumi::cli::DaemonAction::Run);
    EXPECT_TRUE(std::get<kasumi::cli::DaemonInvocation>(*d_run).background);

    const auto d_run_fg = parse({"daemon", "run", "--foreground"});
    ASSERT_TRUE(d_run_fg.has_value());
    EXPECT_FALSE(std::get<kasumi::cli::DaemonInvocation>(*d_run_fg).background);
    EXPECT_FALSE(
        parse({"daemon", "run", "--background", "--foreground"}).has_value());

    const auto d_sync = parse({"daemon", "sync", "auto_p", "--wait"});
    ASSERT_TRUE(d_sync.has_value());
    const auto& d_sync_inv = std::get<kasumi::cli::DaemonInvocation>(*d_sync);
    EXPECT_EQ(d_sync_inv.action, kasumi::cli::DaemonAction::Sync);
    EXPECT_EQ(d_sync_inv.profile_name, "auto_p");
    EXPECT_TRUE(d_sync_inv.wait);

    const auto d_sync_all = parse({"daemon", "sync"});
    ASSERT_TRUE(d_sync_all.has_value());
    EXPECT_FALSE(std::get<kasumi::cli::DaemonInvocation>(*d_sync_all)
                     .profile_name.has_value());

    const auto d_status = parse({"daemon", "status", "auto_p"});
    ASSERT_TRUE(d_status.has_value());
    EXPECT_EQ(std::get<kasumi::cli::DaemonInvocation>(*d_status).action,
              kasumi::cli::DaemonAction::Status);
    EXPECT_EQ(std::get<kasumi::cli::DaemonInvocation>(*d_status).profile_name,
              "auto_p");

    EXPECT_EQ(
        std::get<kasumi::cli::DaemonInvocation>(*parse({"daemon", "stop"}))
            .action,
        kasumi::cli::DaemonAction::Stop);
    EXPECT_EQ(
        std::get<kasumi::cli::DaemonInvocation>(*parse({"daemon", "reload"}))
            .action,
        kasumi::cli::DaemonAction::Reload);
    EXPECT_EQ(std::get<kasumi::cli::DaemonInvocation>(
                  *parse({"daemon", "pause", "auto_p"}))
                  .action,
              kasumi::cli::DaemonAction::Pause);
    EXPECT_EQ(std::get<kasumi::cli::DaemonInvocation>(
                  *parse({"daemon", "resume", "auto_p"}))
                  .action,
              kasumi::cli::DaemonAction::Resume);
    EXPECT_EQ(std::get<kasumi::cli::DaemonInvocation>(
                  *parse({"daemon", "unlock", "auto_p"}))
                  .action,
              kasumi::cli::DaemonAction::Unlock);
    EXPECT_EQ(std::get<kasumi::cli::DaemonInvocation>(
                  *parse({"daemon", "lock", "auto_p"}))
                  .action,
              kasumi::cli::DaemonAction::Lock);
    EXPECT_EQ(std::get<kasumi::cli::DaemonInvocation>(
                  *parse({"daemon", "autostart", "install"}))
                  .action,
              kasumi::cli::DaemonAction::AutostartInstall);
    EXPECT_EQ(std::get<kasumi::cli::DaemonInvocation>(
                  *parse({"daemon", "autostart", "uninstall"}))
                  .action,
              kasumi::cli::DaemonAction::AutostartUninstall);
    EXPECT_EQ(std::get<kasumi::cli::DaemonInvocation>(
                  *parse({"daemon", "autostart", "status"}))
                  .action,
              kasumi::cli::DaemonAction::AutostartStatus);

    const auto d_logs = parse({"daemon", "logs"});
    ASSERT_TRUE(d_logs.has_value());
    EXPECT_EQ(std::get<kasumi::cli::DaemonInvocation>(*d_logs).action,
              kasumi::cli::DaemonAction::Logs);
    EXPECT_EQ(std::get<kasumi::cli::DaemonInvocation>(*d_logs).log_lines, 50U);

    const auto d_logs_prof =
        parse({"daemon", "logs", "auto_p", "--lines", "25"});
    ASSERT_TRUE(d_logs_prof.has_value());
    const auto& d_logs_inv =
        std::get<kasumi::cli::DaemonInvocation>(*d_logs_prof);
    EXPECT_EQ(d_logs_inv.action, kasumi::cli::DaemonAction::Logs);
    EXPECT_EQ(d_logs_inv.profile_name, "auto_p");
    EXPECT_EQ(d_logs_inv.log_lines, 25U);

    const auto d_logs_eq = parse({"daemon", "logs", "--lines=100", "auto_p"});
    ASSERT_TRUE(d_logs_eq.has_value());
    EXPECT_EQ(std::get<kasumi::cli::DaemonInvocation>(*d_logs_eq).log_lines,
              100U);
    EXPECT_EQ(std::get<kasumi::cli::DaemonInvocation>(*d_logs_eq).profile_name,
              "auto_p");

    EXPECT_FALSE(parse({"daemon", "logs", "--lines", "0"}).has_value());
    EXPECT_FALSE(parse({"daemon", "logs", "--lines", "1001"}).has_value());
    EXPECT_FALSE(parse({"daemon", "logs", "--lines", "10", "--lines", "20"})
                     .has_value());

    EXPECT_FALSE(parse({"daemon"}).has_value());
    EXPECT_FALSE(parse({"daemon", "pause"}).has_value());
    EXPECT_FALSE(parse({"daemon", "autostart", "bogus"}).has_value());
    EXPECT_FALSE(parse({"daemon", "stop", "--wait"}).has_value());
}
} // namespace
