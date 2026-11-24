#include "application/profile.hpp"
#include "cli/app.hpp"
#include "cli/log_file.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/scoped_environment.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/cancellation.hpp"
#include "platform/profile_lock.hpp"

#include <csignal>
#include <fstream>
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

    void TearDown() override {
        kasumi::platform::cancellation::reset();
    }
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
        {"show"},
        {"diagnostics"},
        {"fsck"},
        {"gc"},
        {"gc", "remove-writer"},
        {"gc", "remove-barrier"},
        {"resolve-missing"},
        {"config"},
        {"profile", "test"},
        {"ignore"},
        {"ignore", "check"},
        {"ignore", "init"},
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
        {"remote", "health"},
        {"daemon"}}));
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
    const auto error = run({"kasumi", "--lang", "pt-BR", "sync"});
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
        {"status", "demo", "--full"},
        {"remote", "summary", "demo", "--full"}}));

TEST_F(CliInterfaceTest, ShowAndRemoteSummaryFullGrammarValidation) {
    const auto show_full_missing = run({"kasumi", "show", "demo", "--full"});
    EXPECT_EQ(show_full_missing.code, 1);
    EXPECT_TRUE(show_full_missing.out.empty());
    EXPECT_NE(show_full_missing.err.find("[ERROR]"), std::string::npos);
    EXPECT_EQ(show_full_missing.err.find("Usage:"), std::string::npos);

    for (const auto& args : std::vector<std::vector<std::string>>{
             {"kasumi", "show", "--full"},
             {"kasumi", "show", "demo", "--full", "--full"},
             {"kasumi", "remote", "summary", "--full"},
             {"kasumi", "remote", "summary", "demo", "--full", "--full"},
             {"kasumi", "remote", "heads", "demo", "--full"},
         }) {
        const auto invalid = run(args);
        EXPECT_EQ(invalid.code, 1);
        EXPECT_TRUE(invalid.out.empty());
        EXPECT_NE(invalid.err.find("[ERROR]"), std::string::npos);
        EXPECT_NE(invalid.err.find("--help"), std::string::npos);
    }
}

TEST_F(CliInterfaceTest, ShowOfflineRemoteSummaryAndConfigReflectTraceability) {
    const auto root = kasumi::test::workspace_root(workspace);
    const kasumi::application::ExecutionEnvironment environment{root /
                                                                "kasumi"};
    const auto remote = root / "remote";
    const kasumi::application::Profile profile{
        "demo", root / "local", remote.string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment,
        profile,
        kasumi::application::MasterKeyHex{std::string(64, '7')}));
    std::filesystem::create_directories(profile.local_dir);
    kasumi::test::write_text(profile.local_dir / "doc.txt", "hello world");

    const auto synced = run({"kasumi", "sync", "demo"});
    ASSERT_EQ(synced.code, 0) << synced.err << synced.out;
    const auto fscked = run({"kasumi", "fsck", "demo"});
    ASSERT_EQ(fscked.code, 0) << fscked.err << fscked.out;

    // Move remote away to verify show remains completely offline.
    const auto parked_remote = root / "remote-offline";
    std::filesystem::rename(remote, parked_remote);
    const auto shown = run({"kasumi", "show", "demo"});
    const auto shown_full = run({"kasumi", "show", "demo", "--full"});
    std::filesystem::rename(parked_remote, remote);

    EXPECT_EQ(shown.code, 0) << shown.err;
    EXPECT_NE(shown.out.find("Last complete sync:"), std::string::npos);
    EXPECT_NE(shown.out.find("Last change (HEAD):"), std::string::npos);
    EXPECT_NE(shown.out.find("--full"), std::string::npos);
    EXPECT_EQ(shown.out.find("Accepted state:"), std::string::npos);
    EXPECT_EQ(shown.out.find("Recent local executions (2):"), std::string::npos);

    EXPECT_EQ(shown_full.code, 0) << shown_full.err;
    EXPECT_NE(shown_full.out.find("Accepted state:"), std::string::npos);
    EXPECT_NE(shown_full.out.find("Commit origin: sync"), std::string::npos);
    EXPECT_NE(shown_full.out.find("Last complete sync:"), std::string::npos);
    EXPECT_NE(shown_full.out.find("Last local attempt:"), std::string::npos);
    EXPECT_NE(shown_full.out.find("fsck"), std::string::npos);
    EXPECT_NE(shown_full.out.find("Recent local executions (2):"),
              std::string::npos);

    const auto heads = run({"kasumi", "remote", "heads", "demo"});
    EXPECT_EQ(heads.code, 0) << heads.err;
    EXPECT_NE(heads.out.find("Origin: sync"), std::string::npos);

    const auto summary_full =
        run({"kasumi", "remote", "summary", "demo", "--full"});
    EXPECT_EQ(summary_full.code, 0) << summary_full.err;
    EXPECT_NE(summary_full.out.find("Recent operational activity (1):"),
              std::string::npos);
    EXPECT_NE(summary_full.out.find("fsck"), std::string::npos);

    std::istringstream input{"q\n"};
    auto* previous = std::cin.rdbuf(input.rdbuf());
    const auto config = run({"kasumi", "config"});
    std::cin.rdbuf(previous);
    std::cin.clear();
    EXPECT_EQ(config.code, 0);
    EXPECT_NE(config.out.find("Last sync"), std::string::npos);
    EXPECT_NE(config.out.find("Ready"), std::string::npos);
    EXPECT_NE(config.out.find("(ok)"), std::string::npos);
}

TEST_F(CliInterfaceTest,
       QuietSuppressesProgressAndSuccessOutputButPreservesErrors) {
    const auto root = kasumi::test::workspace_root(workspace);
    const kasumi::application::ExecutionEnvironment environment{root /
                                                                "kasumi"};
    const kasumi::application::Profile profile{
        "demo", root / "local", (root / "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment,
        profile,
        kasumi::application::MasterKeyHex{std::string(64, '7')}));
    std::filesystem::create_directories(profile.local_dir);
    kasumi::test::write_text(profile.local_dir / "doc.txt", "quiet payload");

    const auto synced = run({"kasumi", "sync", "demo", "--quiet"});
    EXPECT_EQ(synced.code, 0) << synced.err << synced.out;
    EXPECT_TRUE(synced.out.empty()) << synced.out;
    EXPECT_TRUE(synced.err.empty()) << synced.err;

    const auto status_ok = run({"kasumi", "status", "demo", "--quiet"});
    EXPECT_EQ(status_ok.code, 0) << status_ok.err << status_ok.out;
    EXPECT_TRUE(status_ok.out.empty());
    EXPECT_TRUE(status_ok.err.empty());

    const auto gc_dry = run({"kasumi", "gc", "demo", "--dry-run", "--quiet"});
    EXPECT_EQ(gc_dry.code, 0) << gc_dry.err << gc_dry.out;
    EXPECT_TRUE(gc_dry.out.empty());
    EXPECT_TRUE(gc_dry.err.empty());

    const auto summary =
        run({"kasumi", "remote", "summary", "demo", "--quiet"});
    EXPECT_EQ(summary.code, 0) << summary.err;
    EXPECT_TRUE(summary.err.empty());
    EXPECT_NE(summary.out.find("Remote summary"), std::string::npos);
    EXPECT_EQ(summary.out.find("Listing remote storage"), std::string::npos);
    EXPECT_EQ(summary.out.find("Duration:"), std::string::npos);

    const auto missing = run({"kasumi", "sync", "missing", "--quiet"});
    EXPECT_EQ(missing.code, 1);
    EXPECT_TRUE(missing.err.empty());
    EXPECT_NE(missing.out.find("[ERROR]"), std::string::npos);
    EXPECT_EQ(missing.out.find("Duration:"), std::string::npos);

    for (const auto& invalid_args : std::vector<std::vector<std::string>>{
             {"kasumi", "sync", "demo", "--quiet", "--quiet"},
             {"kasumi", "config", "--quiet"},
             {"kasumi", "completion", "bash", "--quiet"},
             {"kasumi", "--quiet", "status", "demo"},
         }) {
        const auto bad = run(invalid_args);
        EXPECT_EQ(bad.code, 1);
        EXPECT_NE(bad.err.find("[ERROR]"), std::string::npos);
    }
}

TEST_F(CliInterfaceTest, JsonOutputsStructuredSchemaLockBusyAndErrorCodes) {
    const auto root = kasumi::test::workspace_root(workspace);
    const kasumi::application::ExecutionEnvironment environment{root /
                                                                "kasumi"};
    const kasumi::application::Profile profile{
        "demo", root / "local", (root / "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment,
        profile,
        kasumi::application::MasterKeyHex{std::string(64, '7')}));
    std::filesystem::create_directories(profile.local_dir);
    kasumi::test::write_text(profile.local_dir / "item.txt", "json payload");

    const auto invalid = run({"kasumi", "config", "--json"});
    EXPECT_EQ(invalid.code, 1);
    EXPECT_TRUE(invalid.err.empty());
    EXPECT_NE(invalid.out.find("\"schema_version\":1"), std::string::npos);
    EXPECT_NE(invalid.out.find("\"code\":\"invalid_arguments\""),
              std::string::npos);

    const auto missing =
        run({"kasumi", "--lang", "pt-BR", "show", "absent", "--json"});
    EXPECT_EQ(missing.code, 1);
    EXPECT_TRUE(missing.err.empty());
    EXPECT_NE(missing.out.find("\"code\":\"profile_not_found\""),
              std::string::npos);

    const auto lock_path = environment.app_data_dir / "profile-demo.lock";
    auto lock = kasumi::platform::acquire_profile_lock(lock_path);
    ASSERT_TRUE(lock.has_value()) << lock.error();
    const auto locked = run({"kasumi", "status", "demo", "--json"});
    kasumi::platform::release_profile_lock(*lock);
    EXPECT_EQ(locked.code, 1);
    EXPECT_TRUE(locked.err.empty());
    EXPECT_NE(locked.out.find("\"code\":\"lock_busy\""), std::string::npos);

    const auto sync_dry = run(
        {"kasumi", "--lang", "pt-BR", "sync", "demo", "--dry-run", "--json"});
    EXPECT_EQ(sync_dry.code, 0) << sync_dry.out;
    EXPECT_TRUE(sync_dry.err.empty());
    EXPECT_NE(sync_dry.out.find("\"command\":\"sync\""), std::string::npos);
    EXPECT_NE(sync_dry.out.find("\"dry_run\":true"), std::string::npos);
    EXPECT_NE(sync_dry.out.find("\"upload\":1"), std::string::npos);

    const auto diag_all = run({"kasumi", "diagnostics", "--json"});
    EXPECT_EQ(diag_all.code, 0) << diag_all.out;
    EXPECT_TRUE(diag_all.err.empty());
    EXPECT_NE(diag_all.out.find("\"command\":\"diagnostics\""),
              std::string::npos);
    EXPECT_NE(diag_all.out.find("\"overall_ok\":true"), std::string::npos);
    EXPECT_EQ(diag_all.out.find(std::string(64, '7')), std::string::npos);

    const auto diag_missing =
        run({"kasumi", "diagnostics", "absent", "--json"});
    EXPECT_EQ(diag_missing.code, 1);
    EXPECT_TRUE(diag_missing.err.empty());
    EXPECT_NE(diag_missing.out.find("\"code\":\"profile_not_found\""),
              std::string::npos);

    const auto diag_quiet = run({"kasumi", "diagnostics", "--quiet"});
    EXPECT_EQ(diag_quiet.code, 0);
    EXPECT_TRUE(diag_quiet.out.empty());
    EXPECT_TRUE(diag_quiet.err.empty());
}

TEST_F(CliInterfaceTest,
       LogFileWritesCleanTextAndAppendsNdjsonWithoutCreatingOnHelp) {
    const auto root = kasumi::test::workspace_root(workspace);
    const kasumi::application::ExecutionEnvironment environment{root /
                                                                "kasumi"};
    const std::string master_key(64, '8');
    const kasumi::application::Profile profile{
        "demo", root / "local", (root / "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, profile, kasumi::application::MasterKeyHex{master_key}));
    std::filesystem::create_directories(profile.local_dir);
    kasumi::test::write_text(profile.local_dir / "item.txt", "log payload");

    const auto help_log = root / "logs" / "help-unused.log";
    const auto help_out =
        run({"kasumi", "list", "--log-file", help_log.string(), "--help"});
    EXPECT_EQ(help_out.code, 0);
    EXPECT_FALSE(std::filesystem::exists(help_log));

    const auto missing_val = run({"kasumi", "list", "--log-file"});
    EXPECT_EQ(missing_val.code, 1);

    const auto dir_target = root / "dir-as-log";
    std::filesystem::create_directories(dir_target);
    const auto dir_json =
        run({"kasumi", "list", "--json", "--log-file", dir_target.string()});
    EXPECT_EQ(dir_json.code, 1);
    EXPECT_TRUE(dir_json.err.empty());
    EXPECT_NE(dir_json.out.find("\"code\":\"io_error\""), std::string::npos);

    const auto dir_text =
        run({"kasumi", "list", "--log-file", dir_target.string()});
    EXPECT_EQ(dir_text.code, 1);
    EXPECT_FALSE(dir_text.err.empty());

    const auto ndjson_log = root / "logs" / "events.ndjson";
    const auto json_list =
        run({"kasumi", "list", "--json", "--log-file", ndjson_log.string()});
    ASSERT_EQ(json_list.code, 0) << json_list.err;
    const auto json_sync = run({"kasumi",
                                "sync",
                                "demo",
                                "--json",
                                "--log-file=" + ndjson_log.string()});
    ASSERT_EQ(json_sync.code, 0) << json_sync.err;
    const auto json_diag = run({"kasumi",
                                "diagnostics",
                                "demo",
                                "--json",
                                "--log-file=" + ndjson_log.string()});
    ASSERT_EQ(json_diag.code, 0) << json_diag.err;

    std::vector<std::string> ndjson_lines;
    {
        std::ifstream in(ndjson_log, std::ios::binary);
        ASSERT_TRUE(in.is_open());
        std::string line;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            if (!line.empty()) {
                ndjson_lines.push_back(line);
            }
        }
    }
    ASSERT_EQ(ndjson_lines.size(), 3u);
    EXPECT_NE(ndjson_lines[0].find("\"command\":\"list\""), std::string::npos);
    EXPECT_NE(ndjson_lines[0].find("\"timestamp\":\""), std::string::npos);
    EXPECT_NE(ndjson_lines[1].find("\"command\":\"sync\""), std::string::npos);
    EXPECT_NE(ndjson_lines[1].find("\"summary\":\"1 change | ↑ 1"),
              std::string::npos);
    EXPECT_NE(ndjson_lines[2].find("\"command\":\"diagnostics\""),
              std::string::npos);
    EXPECT_NE(ndjson_lines[2].find("\"summary\":\"1 profile"),
              std::string::npos);
    EXPECT_EQ(ndjson_lines[2].find(master_key), std::string::npos);

    const auto text_log = root / "logs" / "text.log";
    const auto text_sync_noop = run(
        {"kasumi", "sync", "demo", "--quiet", "--log-file", text_log.string()});
    ASSERT_EQ(text_sync_noop.code, 0) << text_sync_noop.err;

    const auto lock_path = environment.app_data_dir / "profile-demo.lock";
    auto held_lock = kasumi::platform::acquire_profile_lock(lock_path);
    ASSERT_TRUE(held_lock.has_value()) << held_lock.error();
    const auto text_locked = run(
        {"kasumi", "sync", "demo", "--quiet", "--log-file", text_log.string()});
    kasumi::platform::release_profile_lock(*held_lock);
    EXPECT_EQ(text_locked.code, 1);

    const auto text_diag = run(
        {"kasumi", "diagnostics", "absent", "--log-file=" + text_log.string()});
    EXPECT_EQ(text_diag.code, 1);

    std::string text_content;
    {
        std::ifstream in(text_log, std::ios::binary);
        ASSERT_TRUE(in.is_open());
        text_content.assign(std::istreambuf_iterator<char>(in), {});
    }
    EXPECT_EQ(text_content.find('\x1b'), std::string::npos);
    EXPECT_NE(text_content.find("] [OK] sync demo | Everything in sync ("),
              std::string::npos);
    EXPECT_NE(text_content.find("] [LOCKED] sync demo | [lock_busy] "),
              std::string::npos);
    EXPECT_NE(text_content.find(
                  "] [ERROR] diagnostics absent | [profile_not_found] "),
              std::string::npos);
    EXPECT_EQ(text_content.find(master_key), std::string::npos);

    EXPECT_EQ(
        kasumi::cli::strip_ansi_sequences("\x1b[32m[OK]\x1b[0m\tOl\xC3\xA1\n"),
        "[OK] Ol\xC3\xA1");
}

TEST_F(CliInterfaceTest, ActiveLockShowsRunningAcrossShowConfigAndDiagnostics) {
    const auto root = kasumi::test::workspace_root(workspace);
    const kasumi::application::ExecutionEnvironment environment{root /
                                                                "kasumi"};
    const kasumi::application::Profile profile{
        "demo", root / "local", (root / "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment,
        profile,
        kasumi::application::MasterKeyHex{std::string(64, '5')}));
    std::filesystem::create_directories(profile.local_dir);

    auto held = kasumi::platform::acquire_profile_lock(
        environment.app_data_dir / "profile-demo.lock");
    ASSERT_TRUE(held.has_value()) << held.error();

    const auto show_text = run({"kasumi", "show", "demo"});
    EXPECT_EQ(show_text.code, 0) << show_text.err;
    EXPECT_NE(show_text.out.find("State: Running"), std::string::npos);
    EXPECT_EQ(show_text.out.find("State: Problem"), std::string::npos);
    EXPECT_EQ(show_text.out.find("Reason:"), std::string::npos);

    const auto show_json = run({"kasumi", "show", "demo", "--json"});
    EXPECT_EQ(show_json.code, 0) << show_json.err;
    EXPECT_NE(show_json.out.find("\"state\":\"running\""), std::string::npos);
    EXPECT_NE(show_json.out.find("\"problem\":\"none\""), std::string::npos);
    EXPECT_NE(show_json.out.find("\"lock_active\":true"), std::string::npos);

    const auto diag_json = run({"kasumi", "diagnostics", "demo", "--json"});
    EXPECT_EQ(diag_json.code, 0) << diag_json.err;
    EXPECT_NE(diag_json.out.find("\"state\":\"running\""), std::string::npos);
    EXPECT_NE(diag_json.out.find("\"lock_active\":true"), std::string::npos);
    EXPECT_NE(diag_json.out.find("\"healthy\":true"), std::string::npos);
    EXPECT_NE(diag_json.out.find("\"overall_ok\":true"), std::string::npos);

    const auto diag_quiet = run({"kasumi", "diagnostics", "demo", "--quiet"});
    EXPECT_EQ(diag_quiet.code, 0);
    EXPECT_TRUE(diag_quiet.out.empty());

    std::istringstream quit_input("q\n");
    auto* previous = std::cin.rdbuf(quit_input.rdbuf());
    const auto config_out = run({"kasumi", "config"});
    std::cin.rdbuf(previous);
    std::cin.clear();
    kasumi::platform::release_profile_lock(*held);

    EXPECT_EQ(config_out.code, 0) << config_out.err;
    EXPECT_NE(config_out.out.find("Running"), std::string::npos);
    EXPECT_EQ(config_out.out.find("Problem"), std::string::npos);
}
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
TEST_F(CliInterfaceTest, BareCommandShowsQuickstartAndUnknownCommandFails) {
    const auto bare = run({"kasumi"});
    EXPECT_EQ(bare.code, 0) << bare.err;
    EXPECT_NE(bare.out.find("kasumi config"), std::string::npos);
    EXPECT_NE(bare.out.find("kasumi start"), std::string::npos);

    const auto unknown = run({"kasumi", "unknowncmd"});
    EXPECT_EQ(unknown.code, 1);
    EXPECT_NE(unknown.err.find("[ERROR]"), std::string::npos);
}

TEST_F(CliInterfaceTest, InspectsLogicalPathsStartingWithHyphenUsingDelimiter) {
    const auto root = kasumi::test::workspace_root(workspace);
    const kasumi::application::ExecutionEnvironment environment{root /
                                                                "kasumi"};
    const kasumi::application::Profile profile{
        "demo", root / "local", (root / "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment,
        profile,
        kasumi::application::MasterKeyHex{std::string(64, '7')}));
    std::filesystem::create_directories(profile.local_dir);
    kasumi::test::write_text(profile.local_dir / "--notes.txt",
                             "hyphen content");
    kasumi::test::write_text(profile.local_dir / "notes.txt", "normal content");

    const auto sync_output = run({"kasumi", "sync", "demo"});
    ASSERT_EQ(sync_output.code, 0) << sync_output.err << sync_output.out;

    const auto stat_output =
        run({"kasumi", "remote", "stat", "demo", "--", "--notes.txt"});
    EXPECT_EQ(stat_output.code, 0) << stat_output.err;
    EXPECT_NE(stat_output.out.find("--notes.txt"), std::string::npos);

    const auto destination = root / "downloaded-notes.txt";
    const auto get_output = run({"kasumi",
                                 "remote",
                                 "get",
                                 "demo",
                                 "--",
                                 "--notes.txt",
                                 destination.string()});
    EXPECT_EQ(get_output.code, 0) << get_output.err;
    EXPECT_TRUE(std::filesystem::exists(destination));
    if (std::filesystem::exists(destination)) {
        EXPECT_EQ(kasumi::test::read_text(destination), "hyphen content");
    }

    const auto hyphen_dst = root / "-notes-copy.txt";
    const auto get_hyphen_dst = run({"kasumi",
                                     "remote",
                                     "get",
                                     "demo",
                                     "notes.txt",
                                     "--",
                                     hyphen_dst.string()});
    EXPECT_EQ(get_hyphen_dst.code, 0) << get_hyphen_dst.err;
    EXPECT_TRUE(std::filesystem::exists(hyphen_dst));
    if (std::filesystem::exists(hyphen_dst)) {
        EXPECT_EQ(kasumi::test::read_text(hyphen_dst), "normal content");
    }

    const auto both_dst = root / "-both-copy.txt";
    const auto get_both_hyphen = run({"kasumi",
                                      "remote",
                                      "get",
                                      "demo",
                                      "--",
                                      "--notes.txt",
                                      both_dst.string()});
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

TEST_F(CliInterfaceTest, WizardSuccessAndTerminalFailureKeepExitCodes) {
    std::istringstream input{"q\n"};
    auto* previous = std::cin.rdbuf(input.rdbuf());
    const auto success = run({"kasumi", "config"});
    std::cin.rdbuf(previous);
    std::cin.clear();
    EXPECT_EQ(success.code, 0);

    kasumi::test::write_text(
        kasumi::test::workspace_path(workspace, "kasumi/config.toml"),
        "[invalid toml");
    const auto failure = run({"kasumi", "config"});
    EXPECT_EQ(failure.code, 1);
    EXPECT_NE(failure.out.find("[ERROR]"), std::string::npos);
}

TEST_F(CliInterfaceTest, WizardCancellationReturnsExit130) {
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
}

TEST_F(CliInterfaceTest, WizardEndOfInputIsCancellation) {
    std::istringstream input;
    auto* previous = std::cin.rdbuf(input.rdbuf());
    const auto output = run({"kasumi", "config"});
    std::cin.rdbuf(previous);
    std::cin.clear();
    EXPECT_EQ(output.code, 130);
    EXPECT_NE(output.out.find("Operation cancelled"), std::string::npos);
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
        CancelAtEof() : std::stringbuf("d\nexisting\n") {
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
        BlockingInput(int input_descriptor, std::promise<void>& input_started)
            : descriptor(input_descriptor), started(input_started) {
        }
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
    kasumi::platform::cancellation::reset();
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

TEST_F(CliInterfaceTest, DaemonStatusJsonOfflineDoesNotCreateWorkspace) {
    const auto output = run({"kasumi", "daemon", "status", "--json"});
    EXPECT_EQ(output.code, 0);
    EXPECT_TRUE(output.err.empty());
    EXPECT_NE(output.out.find("\"running\":false"), std::string::npos);
    EXPECT_NE(output.out.find("\"command\":\"daemon status\""),
              std::string::npos);
    EXPECT_TRUE(
        std::filesystem::is_empty(kasumi::test::workspace_root(workspace)));
}

TEST_F(CliInterfaceTest, DaemonAutostartStatusJsonUsesScopedEnv) {
    const auto autostart_dir =
        kasumi::test::workspace_path(workspace, "autostart");
    auto scoped_autostart = kasumi::test::scoped_environment_variable(
        "KASUMI_AUTOSTART_DIR", autostart_dir.string());
    const auto output =
        run({"kasumi", "daemon", "autostart", "status", "--json"});
    EXPECT_EQ(output.code, 0);
    EXPECT_TRUE(output.err.empty());
    EXPECT_NE(output.out.find("\"installed\":false"), std::string::npos);
    EXPECT_NE(output.out.find("\"command\":\"daemon autostart status\""),
              std::string::npos);
}

TEST_F(CliInterfaceTest, ShowJsonIncludesAutomationFields) {
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(remote);
    const std::string hex_key(64, '2');
    auto scoped_key =
        kasumi::test::scoped_environment_variable("KASUMI_MASTER_KEY", hex_key);

    const auto create_out = run({"kasumi",
                                 "profile",
                                 "create",
                                 "auto_prof",
                                 "--local",
                                 local.string(),
                                 "--remote",
                                 remote.string(),
                                 "--key-storage",
                                 "file",
                                 "--watch",
                                 "off",
                                 "--sync-interval",
                                 "120",
                                 "--gc-interval",
                                 "48",
                                 "--paused",
                                 "on",
                                 "--json"});
    ASSERT_EQ(create_out.code, 0) << create_out.out << create_out.err;

    const auto show_out = run({"kasumi", "show", "auto_prof", "--json"});
    ASSERT_EQ(show_out.code, 0) << show_out.out << show_out.err;
    EXPECT_NE(show_out.out.find("\"watch_enabled\":false"), std::string::npos);
    EXPECT_NE(show_out.out.find("\"sync_interval_seconds\":120"),
              std::string::npos);
    EXPECT_NE(show_out.out.find("\"gc_interval_hours\":48"), std::string::npos);
    EXPECT_NE(show_out.out.find("\"paused\":true"), std::string::npos);
    EXPECT_NE(show_out.out.find("\"daemon\":null"), std::string::npos);
}

TEST_F(CliInterfaceTest, DaemonHelpLogsAndErrorContractsWork) {
    for (const char* sub : {"run",
                            "stop",
                            "reload",
                            "status",
                            "sync",
                            "pause",
                            "resume",
                            "unlock",
                            "lock",
                            "logs",
                            "autostart"}) {
        const auto help_out = run({"kasumi", "daemon", sub, "--help"});
        EXPECT_EQ(help_out.code, 0) << "sub=" << sub << "\n" << help_out.err;
        EXPECT_NE(help_out.out.find("kasumi daemon"), std::string::npos);
    }

    const auto logs_out = run({"kasumi", "daemon", "logs", "--json"});
    ASSERT_EQ(logs_out.code, 0) << logs_out.out << logs_out.err;
    EXPECT_NE(logs_out.out.find("\"command\":\"daemon logs\""),
              std::string::npos);
    EXPECT_NE(logs_out.out.find("\"events\":[]"), std::string::npos);

    const auto diag_out = run({"kasumi", "diagnostics", "--json"});
    ASSERT_EQ(diag_out.code, 0) << diag_out.out << diag_out.err;
    EXPECT_NE(diag_out.out.find("\"daemon\":{"), std::string::npos);

    const auto bad_log_dir = kasumi::test::workspace_path(workspace, "badlog");
    std::filesystem::create_directories(bad_log_dir);
    const auto err_log = run({"kasumi",
                              "daemon",
                              "autostart",
                              "status",
                              "--json",
                              "--log-file",
                              bad_log_dir.string()});
    EXPECT_EQ(err_log.code, 1);
    EXPECT_NE(err_log.out.find("\"command\":\"daemon autostart status\""),
              std::string::npos);
    EXPECT_EQ(err_log.out.find("\"profile\":"), std::string::npos);

    const auto unlock_quiet =
        run({"kasumi", "daemon", "unlock", "demo", "--quiet"});
    EXPECT_EQ(unlock_quiet.code, 1);
    EXPECT_FALSE(unlock_quiet.out.empty());
    EXPECT_TRUE(unlock_quiet.err.empty());
}

TEST_F(CliInterfaceTest, HelpTwoTierEnglishAndPortuguese) {
    const auto compact_en = run({"kasumi", "--help"});
    EXPECT_EQ(compact_en.code, 0);
    EXPECT_NE(compact_en.out.find("kasumi start"), std::string::npos);
    EXPECT_NE(compact_en.out.find("kasumi logs"), std::string::npos);
    EXPECT_NE(compact_en.out.find("--help --all"), std::string::npos);
    EXPECT_EQ(compact_en.out.find("kasumi remote contents <profile> --audit"),
              std::string::npos);

    const auto all_en = run({"kasumi", "--help", "--all"});
    EXPECT_EQ(all_en.code, 0);
    EXPECT_NE(all_en.out.find("kasumi remote contents <profile> --audit"),
              std::string::npos);
    EXPECT_NE(all_en.out.find("kasumi gc <profile>"), std::string::npos);

    const auto all_pt = run({"kasumi", "--lang", "pt-BR", "--help", "--all"});
    EXPECT_EQ(all_pt.code, 0);
    EXPECT_NE(all_pt.out.find("kasumi gc <perfil>"), std::string::npos);
}

TEST_F(CliInterfaceTest, OverviewBareAndStatusFullJsonAndPtBr) {
    const auto empty_en = run({"kasumi"});
    EXPECT_EQ(empty_en.code, 0) << empty_en.err;
    EXPECT_NE(empty_en.out.find("No profiles configured"), std::string::npos);

    const auto empty_status = run({"kasumi", "status"});
    EXPECT_EQ(empty_status.code, 0) << empty_status.err;
    EXPECT_NE(empty_status.out.find("kasumi config"), std::string::npos);

    const auto root = kasumi::test::workspace_root(workspace);
    const kasumi::application::ExecutionEnvironment environment{root /
                                                                "kasumi"};
    const kasumi::application::Profile profile{
        "notes", root / "local", (root / "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment,
        profile,
        kasumi::application::MasterKeyHex{std::string(64, '6')}));
    std::filesystem::create_directories(profile.local_dir);

    const auto overview = run({"kasumi"});
    EXPECT_EQ(overview.code, 0) << overview.err;
    EXPECT_NE(overview.out.find("Daemon: stopped"), std::string::npos);
    EXPECT_NE(overview.out.find("notes"), std::string::npos);
    EXPECT_NE(overview.out.find("--full"), std::string::npos);

    const auto overview_full = run({"kasumi", "status", "--full"});
    EXPECT_EQ(overview_full.code, 0) << overview_full.err;
    EXPECT_NE(overview_full.out.find("Daemon: stopped"), std::string::npos);
    EXPECT_NE(overview_full.out.find("notes"), std::string::npos);
    EXPECT_NE(overview_full.out.find("local="), std::string::npos);

    const auto overview_json = run({"kasumi", "status", "--json"});
    EXPECT_EQ(overview_json.code, 0) << overview_json.err;
    EXPECT_NE(overview_json.out.find("\"schema_version\":1"), std::string::npos);
    EXPECT_NE(overview_json.out.find("\"command\":\"status\""),
              std::string::npos);
    EXPECT_NE(overview_json.out.find("\"profiles\":[{"), std::string::npos);
    EXPECT_NE(overview_json.out.find("\"name\":\"notes\""), std::string::npos);

    const auto overview_pt = run({"kasumi", "--lang", "pt-BR"});
    EXPECT_EQ(overview_pt.code, 0) << overview_pt.err;
    EXPECT_NE(overview_pt.out.find("Daemon: parado"), std::string::npos);
    EXPECT_NE(overview_pt.out.find("notes"), std::string::npos);
}

TEST_F(CliInterfaceTest, LogsFiltersNoisyEventsAndHandlesOfflineFollow) {
    const auto root = kasumi::test::workspace_root(workspace);
    const auto app_dir = root / "kasumi";
    std::filesystem::create_directories(app_dir);
    {
        std::ofstream log_out(app_dir / "daemon.log", std::ios::binary);
        log_out << "{\"seq\":1,\"ts\":1700000000,\"profile\":\"notes\",\"kind\":\"fast_"
                   "noop\",\"detail\":\"Fast poll: no changes\"}\n";
        log_out << "{\"seq\":2,\"ts\":1700000010,\"profile\":\"notes\",\"kind\":\"warm_"
                   "transport_opened\",\"detail\":\"Warm transport opened\"}\n";
        log_out << "{\"seq\":3,\"ts\":1700000020,\"profile\":\"notes\",\"kind\":\"sync_"
                   "completed\",\"detail\":\"Synchronization completed (1.2 s)\"}\n";
    }

    const auto filtered = run({"kasumi", "logs", "--lines", "20"});
    EXPECT_EQ(filtered.code, 0) << filtered.err;
    EXPECT_NE(filtered.out.find("Synchronization completed (1.2 s)"),
              std::string::npos);
    EXPECT_EQ(filtered.out.find("fast_noop"), std::string::npos);
    EXPECT_EQ(filtered.out.find("warm_transport_opened"), std::string::npos);

    const auto unfiltered = run({"kasumi", "logs", "--full", "--lines", "20"});
    EXPECT_EQ(unfiltered.code, 0) << unfiltered.err;
    EXPECT_NE(unfiltered.out.find("fast_noop"), std::string::npos);
    EXPECT_NE(unfiltered.out.find("warm_transport_opened"), std::string::npos);

    const auto logs_json = run({"kasumi", "logs", "--json"});
    EXPECT_EQ(logs_json.code, 0) << logs_json.err;
    EXPECT_NE(logs_json.out.find("\"command\":\"logs\""), std::string::npos);
    EXPECT_NE(logs_json.out.find("Synchronization completed (1.2 s)"),
              std::string::npos);
    EXPECT_EQ(logs_json.out.find("\"kind\":\"fast_noop\""),
              std::string::npos);

    const auto follow_offline = run({"kasumi", "logs", "-f"});
    EXPECT_EQ(follow_offline.code, 0) << follow_offline.err;
    EXPECT_NE(follow_offline.out.find("kasumi start"), std::string::npos);
}

TEST_F(CliInterfaceTest, UnifiedDaemonErrorsAndListFullWorkCleanly) {
    const auto root = kasumi::test::workspace_root(workspace);
    const kasumi::application::ExecutionEnvironment environment{root /
                                                                "kasumi"};
    const kasumi::application::Profile profile{
        "notes", root / "local", (root / "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment,
        profile,
        kasumi::application::MasterKeyHex{std::string(64, '7')}));
    std::filesystem::create_directories(profile.local_dir);

    const auto stop_offline = run({"kasumi", "stop", "--json"});
    EXPECT_EQ(stop_offline.code, 0) << stop_offline.err;
    EXPECT_NE(stop_offline.out.find("\"command\":\"stop\""), std::string::npos);
    EXPECT_NE(stop_offline.out.find("daemon already stopped"),
              std::string::npos);

    const auto pause_one = run({"kasumi", "pause", "notes", "--json"});
    EXPECT_EQ(pause_one.code, 0) << pause_one.err;
    EXPECT_NE(pause_one.out.find("\"command\":\"pause\""), std::string::npos);

    const auto resume_all = run({"kasumi", "resume", "--all", "--json"});
    EXPECT_EQ(resume_all.code, 0) << resume_all.err;
    EXPECT_NE(resume_all.out.find("\"command\":\"resume\""),
              std::string::npos);
    EXPECT_NE(resume_all.out.find("\"profile\":\"--all\""),
              std::string::npos);

    const auto list_compact = run({"kasumi", "list"});
    EXPECT_EQ(list_compact.code, 0);
    EXPECT_NE(list_compact.out.find("notes"), std::string::npos);
    EXPECT_EQ(list_compact.out.find("->"), std::string::npos);

    const auto list_full = run({"kasumi", "list", "--full"});
    EXPECT_EQ(list_full.code, 0);
    EXPECT_NE(list_full.out.find("notes"), std::string::npos);
    EXPECT_NE(list_full.out.find("->"), std::string::npos);
}

TEST_F(CliInterfaceTest, ConfigEditUpdatesProfileAutomationSchedule) {
    const auto root = kasumi::test::workspace_root(workspace);
    const kasumi::application::ExecutionEnvironment environment{root /
                                                                "kasumi"};
    const kasumi::application::Profile profile{
        "notes", root / "local", (root / "remote").string()};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment,
        profile,
        kasumi::application::MasterKeyHex{std::string(64, '8')}));
    std::filesystem::create_directories(profile.local_dir);

    std::istringstream wizard_input("e\nnotes\n\n\noff\n120\n24\nq\n");
    auto* previous = std::cin.rdbuf(wizard_input.rdbuf());
    const auto out = run({"kasumi", "config"});
    std::cin.rdbuf(previous);
    std::cin.clear();
    EXPECT_EQ(out.code, 0) << out.err;
    EXPECT_NE(out.out.find("Profile 'notes' edited successfully."),
              std::string::npos);

    const auto profiles = kasumi::application::list_profiles(environment);
    ASSERT_TRUE(profiles.has_value());
    ASSERT_EQ(profiles->size(), 1U);
    const auto updated = profiles->front();
    ASSERT_TRUE(updated.watch_enabled.has_value());
    EXPECT_FALSE(*updated.watch_enabled);
    ASSERT_TRUE(updated.sync_interval_seconds.has_value());
    EXPECT_EQ(*updated.sync_interval_seconds, 120U);
    ASSERT_TRUE(updated.gc_interval_hours.has_value());
    EXPECT_EQ(*updated.gc_interval_hours, 24U);

    const auto watch_off_overview = run({"kasumi"});
    EXPECT_EQ(watch_off_overview.code, 0);
    EXPECT_NE(watch_off_overview.out.find("[watch off]"), std::string::npos);

    const auto watch_off_json = run({"kasumi", "status", "--json"});
    EXPECT_EQ(watch_off_json.code, 0);
    EXPECT_NE(watch_off_json.out.find("\"watch_enabled\":false"),
              std::string::npos);
    EXPECT_NE(watch_off_json.out.find("\"head_commit_machine\":"),
              std::string::npos);
}

} // namespace
