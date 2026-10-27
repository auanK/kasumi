#include "application/profile.hpp"
#include "cli/app.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/scoped_environment.hpp"
#include "kasumi/test/temp_workspace.hpp"

#include <csignal>
#include <future>
#include <gtest/gtest.h>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#ifndef _WIN32
#include <pthread.h>
#include <unistd.h>
#endif
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
TEST_F(CliInterfaceTest, ConfigHelpIncludesCloneInBothLanguages) {
    const auto english = run({"kasumi", "config", "--help"});
    EXPECT_NE(english.out.find("clone"), std::string::npos);

    const auto portuguese =
        run({"kasumi", "--lang", "pt-BR", "config", "--help"});
    EXPECT_NE(portuguese.out.find("clonar"), std::string::npos);
}
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

TEST_F(CliInterfaceTest,
       WizardSuccessAndTerminalFailureHaveDurationAndCorrectExitCodes) {
    std::istringstream input{"q\n"};
    auto* previous = std::cin.rdbuf(input.rdbuf());
    const auto success = run({"kasumi", "config"});
    std::cin.rdbuf(previous);
    std::cin.clear();
    EXPECT_EQ(success.code, 0);
    EXPECT_NE(success.out.find("Duration:"), std::string::npos);

    kasumi::test::write_text(
        kasumi::test::workspace_path(workspace, "kasumi/config.toml"),
        "[invalid toml");
    const auto failure = run({"kasumi", "config"});
    EXPECT_EQ(failure.code, 1);
    EXPECT_NE(failure.out.find("[ERROR]"), std::string::npos);
    EXPECT_NE(failure.out.find("Duration:"), std::string::npos);
}

TEST_F(CliInterfaceTest, WizardCancellationHasDurationAndExit130) {
    struct CancelInput : std::streambuf {
        int_type underflow() override {
            std::raise(SIGINT);
            return traits_type::eof();
        }
    } input;
    auto* previous = std::cin.rdbuf(&input);
    const auto output = run({"kasumi", "config"});
    std::cin.rdbuf(previous);
    std::cin.clear();
    EXPECT_EQ(output.code, 130);
    EXPECT_NE(output.out.find("cancelled"), std::string::npos);
    EXPECT_NE(output.out.find("Duration:"), std::string::npos);
}

TEST_F(CliInterfaceTest, WizardEndOfInputIsCancellation) {
    std::istringstream input;
    auto* previous = std::cin.rdbuf(input.rdbuf());
    const auto output = run({"kasumi", "config"});
    std::cin.rdbuf(previous);
    std::cin.clear();
    EXPECT_EQ(output.code, 130);
    EXPECT_NE(output.out.find("Operation cancelled"), std::string::npos);
    EXPECT_NE(output.out.find("Duration:"), std::string::npos);
    EXPECT_TRUE(
        std::filesystem::is_empty(kasumi::test::workspace_root(workspace)));
}

TEST_F(CliInterfaceTest,
       CancellationDuringDeletePromptDoesNotDeleteTheProfile) {
    const kasumi::application::ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "kasumi")};
    const kasumi::application::Profile profile{
        "existing",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment,
        profile,
        kasumi::application::MasterKeyHex{std::string(64, '1')}));
    struct CancelAtEof : std::stringbuf {
        CancelAtEof() : std::stringbuf("d\nexisting") {
        }
        int_type underflow() override {
            if (!raised) {
                raised = true;
                std::raise(SIGINT);
            }
            return traits_type::eof();
        }
        bool raised = false;
    } input;
    auto* previous = std::cin.rdbuf(&input);
    const auto output = run({"kasumi", "config"});
    std::cin.rdbuf(previous);
    std::cin.clear();
    EXPECT_EQ(output.code, 130);
    const auto profiles = kasumi::application::list_profiles(environment);
    ASSERT_TRUE(profiles.has_value());
    ASSERT_EQ(profiles->size(), 1u);
    EXPECT_EQ(profiles->front().name, "existing");
}

TEST_F(CliInterfaceTest,
       CancellationWhileReadingDeleteTargetDoesNotDeleteTheProfile) {
    const kasumi::application::ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "kasumi")};
    const kasumi::application::Profile profile{
        "existing",
        kasumi::test::workspace_path(workspace, "local"),
        kasumi::test::workspace_path(workspace, "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment,
        profile,
        kasumi::application::MasterKeyHex{std::string(64, '1')}));
    struct CancelWhileReadingTarget : std::streambuf {
        int_type underflow() override {
            if (position == 2)
                std::raise(SIGINT);
            if (position == input.size())
                return traits_type::eof();
            current = input[position++];
            setg(&current, &current, &current + 1);
            return traits_type::to_int_type(current);
        }
        std::string input{"d\nexisting\n"};
        std::size_t position = 0;
        char current = '\0';
    } input;
    auto* previous = std::cin.rdbuf(&input);
    const auto output = run({"kasumi", "config"});
    std::cin.rdbuf(previous);
    std::cin.clear();
    EXPECT_EQ(output.code, 130);
    const auto profiles = kasumi::application::list_profiles(environment);
    ASSERT_TRUE(profiles.has_value());
    ASSERT_EQ(profiles->size(), 1u);
    EXPECT_EQ(profiles->front().name, "existing");
}

#ifndef _WIN32
TEST_F(CliInterfaceTest, SignalCancelsBlockedWizardInput) {
    int descriptors[2];
    ASSERT_EQ(::pipe(descriptors), 0);
    std::promise<void> input_started;
    auto input_started_future = input_started.get_future();
    struct BlockingInput : std::streambuf {
        BlockingInput(int input_descriptor,
                      std::promise<void>& input_started)
            : descriptor(input_descriptor), started(input_started) {}
        int_type underflow() override {
            if (!announced) {
                announced = true;
                started.set_value();
            }
            if (::read(descriptor, &current, 1) != 1)
                return traits_type::eof();
            setg(&current, &current, &current + 1);
            return traits_type::to_int_type(current);
        }
        int descriptor;
        std::promise<void>& started;
        bool announced = false;
        char current = '\0';
    } input{descriptors[0], input_started};
    auto* previous = std::cin.rdbuf(&input);
    std::promise<Output> completion;
    auto completion_future = completion.get_future();
    std::thread cli([&] {
        completion.set_value(run({"kasumi", "config"}));
    });

    const bool input_started_in_time =
        input_started_future.wait_for(std::chrono::seconds(5)) ==
        std::future_status::ready;
    bool interrupted = false;
    if (input_started_in_time) {
        for (int attempt = 0; attempt < 20; ++attempt) {
            if (completion_future.wait_for(std::chrono::milliseconds(0)) ==
                std::future_status::ready) {
                interrupted = true;
                break;
            }
            EXPECT_EQ(::pthread_kill(cli.native_handle(), SIGINT), 0);
            interrupted =
                completion_future.wait_for(std::chrono::milliseconds(50)) ==
                std::future_status::ready;
            if (interrupted)
                break;
        }
    }
    if (!interrupted) {
        const char quit[] = "q\n";
        EXPECT_EQ(::write(descriptors[1], quit, sizeof(quit) - 1),
                  static_cast<ssize_t>(sizeof(quit) - 1));
    }
    cli.join();
    std::cin.rdbuf(previous);
    std::cin.clear();
    ::close(descriptors[0]);
    ::close(descriptors[1]);

    EXPECT_TRUE(input_started_in_time);
    EXPECT_TRUE(interrupted);
    const auto output = completion_future.get();
    EXPECT_EQ(output.code, 130);
    EXPECT_TRUE(
        std::filesystem::is_empty(kasumi::test::workspace_root(workspace)));
}
#endif

} // namespace
