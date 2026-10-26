#include "application/profile.hpp"
#include "cli/app.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/scoped_environment.hpp"
#include "kasumi/test/temp_workspace.hpp"

#include <gtest/gtest.h>
#include <string>
#include <vector>
namespace {
struct Output {
    int code;
    std::string out;
    std::string err;
};
Output run(std::vector<std::string> arguments) {
    std::vector<char*> argv;
    for (auto& argument : arguments)
        argv.push_back(argument.data());
    testing::internal::CaptureStdout();
    testing::internal::CaptureStderr();
    const int code =
        kasumi::cli::run(static_cast<int>(argv.size()), argv.data());
    return {code,
            testing::internal::GetCapturedStdout(),
            testing::internal::GetCapturedStderr()};
}
class CliInterfaceTest : public testing::Test {
protected:
    kasumi::test::TempWorkspace workspace =
        kasumi::test::make_temp_workspace("cli-interface");
    kasumi::test::ScopedEnvironmentVariable appdata =
        kasumi::test::scoped_environment_variable(
            "APPDATA", kasumi::test::workspace_root(workspace).string());
    kasumi::test::ScopedEnvironmentVariable xdg =
        kasumi::test::scoped_environment_variable(
            "XDG_CONFIG_HOME",
            kasumi::test::workspace_root(workspace).string());
    kasumi::test::ScopedEnvironmentVariable language =
        kasumi::test::scoped_environment_variable("KASUMI_LANG", "en");
};
class ContextualHelpTest
    : public CliInterfaceTest,
      public testing::WithParamInterface<std::vector<std::string>> {};
TEST_P(ContextualHelpTest, DescribesTheCommandWithoutExecution) {
    std::vector<std::string> arguments{"kasumi"};
    std::string topic;
    for (const auto& part : GetParam()) {
        arguments.push_back(part);
        if (!topic.empty())
            topic += ' ';
        topic += part;
    }
    arguments.push_back("--help");
    const auto output = run(arguments);
    EXPECT_EQ(output.code, 0);
    EXPECT_NE(output.out.find("Usage: kasumi " + topic), std::string::npos);
    EXPECT_NE(output.out.find("--lang"), std::string::npos);
    EXPECT_TRUE(output.err.empty());
    EXPECT_EQ(output.out.find("Password:"), std::string::npos);
    EXPECT_EQ(output.out.find("Duration:"), std::string::npos);
    EXPECT_TRUE(
        std::filesystem::is_empty(kasumi::test::workspace_root(workspace)));
}
INSTANTIATE_TEST_SUITE_P(
    Commands,
    ContextualHelpTest,
    testing::ValuesIn(std::vector<std::vector<std::string>>{
        std::vector<std::string>{"sync"},
        {"status"},
        {"fsck"},
        {"gc"},
        {"gc", "remove-writer"},
        {"gc", "remove-barrier"},
        {"resolve-missing"},
        {"config"},
        {"update"},
        {"remote"},
        {"remote", "heads"},
        {"remote", "tree"},
        {"remote", "commits"},
        {"remote", "summary"},
        {"remote", "stat"},
        {"remote", "commit"},
        {"remote", "get"},
        {"remote", "epochs"},
        {"remote", "epoch"},
        {"remote", "contents"},
        {"remote", "content"},
        {"remote", "markers"},
        {"remote", "objects"},
        {"remote", "orphans"},
        {"remote", "writers"},
        {"remote", "health"}}));
TEST_F(CliInterfaceTest, GlobalLanguageAppliesToContextualHelpAndDiagnostics) {
    const auto help =
        run({"kasumi", "--lang", "pt-BR", "remote", "tree", "--help"});
    EXPECT_EQ(help.code, 0);
    EXPECT_NE(help.out.find("Uso: kasumi remote tree <perfil>"),
              std::string::npos);
    EXPECT_NE(help.out.find("--head"), std::string::npos);
    EXPECT_NE(help.out.find("Exemplo"), std::string::npos);
    const auto error = run({"kasumi", "--lang", "pt-BR", "status"});
    EXPECT_EQ(error.code, 1);
    EXPECT_NE(error.err.find("[ERRO]"), std::string::npos);
    EXPECT_NE(error.err.find("Argumentos inválidos"), std::string::npos);
    EXPECT_TRUE(
        std::filesystem::is_empty(kasumi::test::workspace_root(workspace)));
}
TEST_F(CliInterfaceTest, HelpOnAValidInvocationDoesNotExecuteIt) {
    const auto output =
        run({"kasumi", "sync", "Programação-日本", "--dry-run", "-h"});
    EXPECT_EQ(output.code, 0);
    EXPECT_NE(output.out.find("Usage: kasumi sync"), std::string::npos);
    EXPECT_EQ(output.out.find("Simulating"), std::string::npos);
    EXPECT_TRUE(
        std::filesystem::is_empty(kasumi::test::workspace_root(workspace)));
}
struct InvalidCommandLine {
    const char* name;
    std::vector<std::string> arguments;
    std::string topic;
};
class CommandLineGrammarTest
    : public CliInterfaceTest,
      public testing::WithParamInterface<InvalidCommandLine> {};
TEST_P(CommandLineGrammarTest, InvalidInputHasDiagnosticsAndNoExecution) {
    std::vector<std::string> arguments{"kasumi"};
    const auto& test = GetParam();
    arguments.insert(
        arguments.end(), test.arguments.begin(), test.arguments.end());
    const auto output = run(arguments);
    EXPECT_EQ(output.code, 1);
    EXPECT_NE(output.err.find("[ERROR]"), std::string::npos);
    EXPECT_NE(output.err.find("kasumi" +
                              (test.topic.empty() ? "" : " " + test.topic) +
                              " --help"),
              std::string::npos);
    EXPECT_TRUE(output.out.empty());
    EXPECT_TRUE(
        std::filesystem::is_empty(kasumi::test::workspace_root(workspace)));
}
INSTANTIATE_TEST_SUITE_P(
    EquivalenceClasses,
    CommandLineGrammarTest,
    testing::Values(
        InvalidCommandLine{"GlobalOptionInCommandScope",
                           {"status", "demo", "--lang", "en"},
                           "status"},
        InvalidCommandLine{
            "CommandOptionInGlobalScope", {"--full", "status", "demo"}, ""},
        InvalidCommandLine{
            "WrongCommandOption", {"fsck", "demo", "--full"}, "fsck"},
        InvalidCommandLine{"MissingGlobalValue", {"--lang"}, ""},
        InvalidCommandLine{"MissingCommandValue",
                           {"remote", "tree", "demo", "--head"},
                           "remote tree"},
        InvalidCommandLine{"DuplicateOption",
                           {"status", "demo", "--full", "--full"},
                           "status"},
        InvalidCommandLine{
            "UnknownOption", {"sync", "demo", "--unknown"}, "sync"},
        InvalidCommandLine{"IncompatibleOptions",
                           {"sync", "demo", "--dry-run", "--initial"},
                           "sync"},
        InvalidCommandLine{
            "MissingOperand", {"remote", "get", "demo", "file"}, "remote get"},
        InvalidCommandLine{"UnknownCommand", {"unknown"}, ""}),
    [](const auto& case_info) {
        return case_info.param.name;
    });
class FullOutputGrammarTest
    : public CliInterfaceTest,
      public testing::WithParamInterface<std::vector<std::string>> {};
TEST_P(FullOutputGrammarTest, CommandScopedFullOptionReachesExecution) {
    std::vector<std::string> arguments{"kasumi"};
    arguments.insert(arguments.end(), GetParam().begin(), GetParam().end());
    const auto output = run(arguments);
    EXPECT_EQ(output.code, 1); // The isolated profile does not exist.
    EXPECT_TRUE(output.err.empty());
    EXPECT_NE(output.out.find("[ERROR]"), std::string::npos);
}
INSTANTIATE_TEST_SUITE_P(
    Commands,
    FullOutputGrammarTest,
    testing::ValuesIn(std::vector<std::vector<std::string>>{
        std::vector<std::string>{"sync", "demo", "--full"},
        {"sync", "demo", "--dry-run", "--full"},
        {"status", "demo", "--full"}}));
class GeneralOptionTest : public CliInterfaceTest,
                          public testing::WithParamInterface<const char*> {};
TEST_P(GeneralOptionTest, ConventionalOptionsSucceedWithoutExecution) {
    const auto output = run({"kasumi", GetParam()});
    EXPECT_EQ(output.code, 0);
    EXPECT_TRUE(output.err.empty());
    EXPECT_EQ(output.out.find("Duration:"), std::string::npos);
    EXPECT_TRUE(
        std::filesystem::is_empty(kasumi::test::workspace_root(workspace)));
}
INSTANTIATE_TEST_SUITE_P(Conventional,
                         GeneralOptionTest,
                         testing::Values("--help", "-h", "--version", "-v"));
TEST_F(CliInterfaceTest, MissingCommandPrintsHelpAndFails) {
    const auto output = run({"kasumi"});
    EXPECT_EQ(output.code, 1);
    EXPECT_NE(output.out.find("Usage:"), std::string::npos);
}

TEST_F(CliInterfaceTest, InspectsLogicalPathsStartingWithHyphenUsingDelimiter) {
    const auto root = kasumi::test::workspace_root(workspace);
    const kasumi::application::ExecutionEnvironment environment{root / "kasumi"};
    const kasumi::application::Profile profile{
        "demo", root / "local", (root / "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment,
        profile,
        kasumi::application::MasterKeyHex{std::string(64, '7')}));
    std::filesystem::create_directories(profile.local_dir);
    kasumi::test::write_text(profile.local_dir / "--notes.txt", "hyphen content");
    kasumi::test::write_text(profile.local_dir / "notes.txt", "normal content");

    const auto sync_output = run({"kasumi", "sync", "demo"});
    ASSERT_EQ(sync_output.code, 0) << sync_output.err << sync_output.out;

    const auto stat_output =
        run({"kasumi", "remote", "stat", "demo", "--", "--notes.txt"});
    EXPECT_EQ(stat_output.code, 0) << stat_output.err;
    EXPECT_NE(stat_output.out.find("--notes.txt"), std::string::npos);

    const auto destination = root / "downloaded-notes.txt";
    const auto get_output =
        run({"kasumi", "remote", "get", "demo", "--", "--notes.txt", destination.string()});
    EXPECT_EQ(get_output.code, 0) << get_output.err;
    EXPECT_TRUE(std::filesystem::exists(destination));
    if (std::filesystem::exists(destination)) {
        EXPECT_EQ(kasumi::test::read_text(destination), "hyphen content");
    }

    const auto hyphen_dst = root / "-notes-copy.txt";
    const auto get_hyphen_dst =
        run({"kasumi", "remote", "get", "demo", "notes.txt", "--", hyphen_dst.string()});
    EXPECT_EQ(get_hyphen_dst.code, 0) << get_hyphen_dst.err;
    EXPECT_TRUE(std::filesystem::exists(hyphen_dst));
    if (std::filesystem::exists(hyphen_dst)) {
        EXPECT_EQ(kasumi::test::read_text(hyphen_dst), "normal content");
    }

    const auto both_dst = root / "-both-copy.txt";
    const auto get_both_hyphen =
        run({"kasumi", "remote", "get", "demo", "--", "--notes.txt", both_dst.string()});
    EXPECT_EQ(get_both_hyphen.code, 0) << get_both_hyphen.err;
    EXPECT_TRUE(std::filesystem::exists(both_dst));
    if (std::filesystem::exists(both_dst)) {
        EXPECT_EQ(kasumi::test::read_text(both_dst), "hyphen content");
    }
}

TEST_F(CliInterfaceTest,
       PortugueseRemoteHelpUsesTranslatedArgumentAndOptionPlaceholders) {
    const auto output = run({"kasumi", "--lang", "pt-BR", "remote", "--help"});
    EXPECT_EQ(output.code, 0);
    EXPECT_NE(
        output.out.find(
            "Uso: kasumi remote <subcomando> <perfil> [argumentos] [opções]"),
        std::string::npos);
    EXPECT_EQ(output.out.find("[arguments]"), std::string::npos);
    EXPECT_EQ(output.out.find("[options]"), std::string::npos);
}

} // namespace
