#include "application/inspection/request.hpp"
#include "application/request.hpp"
#include "cli/parser.hpp"

#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace {

kasumi::cli::Invocation parse(std::vector<std::string> values) {
    std::vector<char*> argv;
    argv.reserve(values.size());
    for (auto& value : values)
        argv.push_back(value.data());
    auto result =
        kasumi::cli::parse(static_cast<int>(argv.size()), argv.data());
    if (!result)
        throw std::runtime_error("parser rejected test input");
    return *result;
}

TEST(CliParserTest, ParsesEveryPublicRequestForm) {
    const auto sync = parse({"kasumi", "sync", "demo"});
    ASSERT_TRUE(std::holds_alternative<kasumi::application::Request>(sync));
    EXPECT_EQ(std::get<kasumi::application::Request>(sync).operation,
              kasumi::application::Operation::Sync);
    const auto preview = parse({"kasumi", "sync", "demo", "--dry-run"});
    EXPECT_EQ(std::get<kasumi::application::Request>(preview).operation,
              kasumi::application::Operation::Preview);
    EXPECT_EQ(std::get<kasumi::application::Request>(
                  parse({"kasumi", "status", "demo"}))
                  .operation,
              kasumi::application::Operation::Status);
    EXPECT_EQ(std::get<kasumi::application::Request>(
                  parse({"kasumi", "fsck", "demo"}))
                  .operation,
              kasumi::application::Operation::Fsck);
    EXPECT_EQ(
        std::get<kasumi::application::Request>(parse({"kasumi", "gc", "demo"}))
            .operation,
        kasumi::application::Operation::GarbageCollect);
    EXPECT_TRUE(std::holds_alternative<kasumi::cli::ConfigureInvocation>(
        parse({"kasumi", "config"})));

    const auto remote = parse({"kasumi", "remote", "heads", "demo"});
    ASSERT_TRUE(
        std::holds_alternative<kasumi::application::InspectionRequest>(remote));
    EXPECT_EQ(
        std::get<kasumi::application::InspectionRequest>(remote).operation,
        kasumi::application::InspectionOperation::RemoteHeads);
    EXPECT_EQ(
        std::get<kasumi::application::InspectionRequest>(remote).profile_name,
        "demo");

    const auto tree = parse({"kasumi", "remote", "tree", "demo"});
    ASSERT_TRUE(
        std::holds_alternative<kasumi::application::InspectionRequest>(tree));
    EXPECT_EQ(std::get<kasumi::application::InspectionRequest>(tree).operation,
              kasumi::application::InspectionOperation::RemoteTree);
    EXPECT_FALSE(std::get<kasumi::application::InspectionRequest>(tree)
                     .head_commit_id.has_value());

    const auto selected =
        parse({"kasumi", "remote", "tree", "demo", "--head", "abc"});
    ASSERT_TRUE(std::holds_alternative<kasumi::application::InspectionRequest>(
        selected));
    const auto& selected_request =
        std::get<kasumi::application::InspectionRequest>(selected);
    ASSERT_TRUE(selected_request.head_commit_id.has_value());
    EXPECT_EQ(*selected_request.head_commit_id, "abc");

    const auto commits = parse({"kasumi", "remote", "commits", "demo"});
    ASSERT_TRUE(std::holds_alternative<kasumi::application::InspectionRequest>(
        commits));
    const auto& commits_request =
        std::get<kasumi::application::InspectionRequest>(commits);
    EXPECT_EQ(commits_request.operation,
              kasumi::application::InspectionOperation::RemoteCommits);
    EXPECT_EQ(commits_request.profile_name, "demo");
    EXPECT_FALSE(commits_request.head_commit_id.has_value());

    const auto summary = parse({"kasumi", "remote", "summary", "demo"});
    EXPECT_EQ(
        std::get<kasumi::application::InspectionRequest>(summary).operation,
        kasumi::application::InspectionOperation::RemoteSummary);

    const auto stat =
        parse({"kasumi", "remote", "stat", "demo", "álbum/foto final.jpg"});
    const auto& stat_request =
        std::get<kasumi::application::InspectionRequest>(stat);
    EXPECT_EQ(stat_request.operation,
              kasumi::application::InspectionOperation::RemoteStat);
    ASSERT_TRUE(stat_request.logical_path.has_value());
    EXPECT_EQ(*stat_request.logical_path, "álbum/foto final.jpg");
    EXPECT_EQ(*std::get<kasumi::application::InspectionRequest>(
                   parse({"kasumi", "remote", "stat", "demo", "/"}))
                   .logical_path,
              "/");

    const std::string commit_id(64, 'a');
    const auto commit =
        parse({"kasumi", "remote", "commit", "demo", commit_id});
    const auto& commit_request =
        std::get<kasumi::application::InspectionRequest>(commit);
    EXPECT_EQ(commit_request.operation,
              kasumi::application::InspectionOperation::RemoteCommit);
    ASSERT_TRUE(commit_request.commit_id.has_value());
    EXPECT_EQ(*commit_request.commit_id, commit_id);

    const auto get = parse({"kasumi",
                            "remote",
                            "get",
                            "demo",
                            "álbum/foto final.jpg",
                            "downloads/foto final.jpg"});
    const auto& get_request =
        std::get<kasumi::application::InspectionRequest>(get);
    EXPECT_EQ(get_request.operation,
              kasumi::application::InspectionOperation::RemoteGet);
    ASSERT_TRUE(get_request.logical_path.has_value());
    ASSERT_TRUE(get_request.destination_path.has_value());
    EXPECT_EQ(*get_request.logical_path, "álbum/foto final.jpg");
    EXPECT_EQ(*get_request.destination_path, "downloads/foto final.jpg");

    const auto epochs = parse({"kasumi", "remote", "epochs", "demo"});
    EXPECT_EQ(
        std::get<kasumi::application::InspectionRequest>(epochs).operation,
        kasumi::application::InspectionOperation::RemoteEpochs);

    const auto epoch = parse({"kasumi", "remote", "epoch", "demo", commit_id});
    const auto& epoch_request =
        std::get<kasumi::application::InspectionRequest>(epoch);
    EXPECT_EQ(epoch_request.operation,
              kasumi::application::InspectionOperation::RemoteEpoch);
    ASSERT_TRUE(epoch_request.epoch_selector.has_value());
    EXPECT_EQ(*epoch_request.epoch_selector, commit_id);
    EXPECT_EQ(*std::get<kasumi::application::InspectionRequest>(
                   parse({"kasumi", "remote", "epoch", "demo", "42"}))
                   .epoch_selector,
              "42");

    const auto contents = parse({"kasumi", "remote", "contents", "demo"});
    EXPECT_EQ(
        std::get<kasumi::application::InspectionRequest>(contents).operation,
        kasumi::application::InspectionOperation::RemoteContents);
    const auto audited =
        parse({"kasumi", "remote", "contents", "--audit", "demo"});
    const auto& audited_request =
        std::get<kasumi::application::InspectionRequest>(audited);
    EXPECT_EQ(audited_request.operation,
              kasumi::application::InspectionOperation::RemoteContentsAudit);
    EXPECT_EQ(audited_request.profile_name, "demo");
    const auto content =
        parse({"kasumi", "remote", "content", "demo", commit_id});
    const auto& content_request =
        std::get<kasumi::application::InspectionRequest>(content);
    EXPECT_EQ(content_request.operation,
              kasumi::application::InspectionOperation::RemoteContent);
    ASSERT_TRUE(content_request.content_id.has_value());
    EXPECT_EQ(*content_request.content_id, commit_id);

    const std::vector physical_commands{
        std::pair{"markers",
                  kasumi::application::InspectionOperation::RemoteMarkers},
        std::pair{"objects",
                  kasumi::application::InspectionOperation::RemoteObjects},
        std::pair{"orphans",
                  kasumi::application::InspectionOperation::RemoteOrphans},
        std::pair{"quarantine",
                  kasumi::application::InspectionOperation::RemoteQuarantine},
        std::pair{"writers",
                  kasumi::application::InspectionOperation::RemoteWriters},
        std::pair{"health",
                  kasumi::application::InspectionOperation::RemoteHealth}};
    for (const auto& [command, operation] : physical_commands) {
        const auto invocation = parse({"kasumi", "remote", command, "demo"});
        const auto& request =
            std::get<kasumi::application::InspectionRequest>(invocation);
        EXPECT_EQ(request.operation, operation);
        EXPECT_EQ(request.profile_name, "demo");
    }
}

TEST(CliParserTest,
     RejectsMissingArgumentsUnknownCommandsAndInvalidCombinations) {
    const auto check_error = [](std::vector<std::string> values) {
        std::vector<char*> argv;
        for (auto& value : values)
            argv.push_back(value.data());
        const auto result =
            kasumi::cli::parse(static_cast<int>(argv.size()), argv.data());
        EXPECT_FALSE(result.has_value());
        if (!result) {
            EXPECT_NE(result.error().exit_code, 0);
        }
    };
    check_error({"kasumi"});
    check_error({"kasumi", "unknown"});
    check_error({"kasumi", "sync"});
    check_error({"kasumi", "status"});
    check_error({"kasumi", "fsck"});
    check_error({"kasumi", "gc"});
    check_error({"kasumi", "sync", "demo", "--unknown"});
    check_error({"kasumi", "sync", "demo", "--dry-run", "extra"});
    check_error({"kasumi", "status", "demo", "extra"});
    check_error({"kasumi", "config", "extra"});
    check_error({"kasumi", "lock", "demo"});
    check_error({"kasumi", "lock", "status", "demo"});
    check_error({"kasumi", "remote"});
    check_error({"kasumi", "remote", "heads"});
    check_error({"kasumi", "remote", "heads", "demo", "extra"});
    check_error({"kasumi", "remote", "unknown", "demo"});
    check_error({"kasumi", "heads", "demo"});
    check_error({"kasumi", "remote", "heads", ""});
    check_error({"kasumi", "remote", "tree"});
    check_error({"kasumi", "remote", "tree", "demo", "--head"});
    check_error({"kasumi", "remote", "tree", "demo", "--head", ""});
    check_error({"kasumi", "remote", "tree", "demo", "--unknown"});
    check_error({"kasumi", "remote", "tree", "demo", "extra"});
    check_error({"kasumi", "remote", "tree", "demo", "--head", "id", "extra"});
    check_error({"kasumi",
                 "remote",
                 "tree",
                 "demo",
                 "--head",
                 "id",
                 "--head",
                 "other"});
    check_error({"kasumi", "remote", "commits"});
    check_error({"kasumi", "remote", "commits", "demo", "extra"});
    check_error({"kasumi", "remote", "commits", "demo", "--head", "id"});
    check_error({"kasumi", "remote", "commits", "demo", "--limit", "10"});
    check_error({"kasumi", "commits", "demo"});
    check_error({"kasumi", "remote", "commit", "demo"});
    check_error({"kasumi", "remote", "summary"});
    check_error({"kasumi", "remote", "summary", "demo", "extra"});
    check_error({"kasumi", "remote", "stat", "demo"});
    check_error({"kasumi", "remote", "stat", "demo", ""});
    check_error({"kasumi", "remote", "stat", "demo", "path", "extra"});
    check_error({"kasumi", "remote", "commit", "demo", "short"});
    check_error({"kasumi", "remote", "commit", "demo", std::string(64, 'A')});
    check_error({"kasumi", "remote", "commit", "demo", std::string(63, 'a')});
    check_error({"kasumi", "remote", "commit", "demo", std::string(65, 'a')});
    check_error({"kasumi", "remote", "commit", "demo", std::string(64, 'z')});
    check_error(
        {"kasumi", "remote", "commit", "demo", std::string(64, 'a'), "extra"});
    check_error({"kasumi", "remote", "get", "demo"});
    check_error({"kasumi", "remote", "get", "demo", "file"});
    check_error({"kasumi", "remote", "get", "demo", "", "destination"});
    check_error({"kasumi", "remote", "get", "demo", "file", ""});
    check_error(
        {"kasumi", "remote", "get", "demo", "file", "destination", "extra"});
    check_error({"kasumi", "remote", "epochs"});
    check_error({"kasumi", "remote", "epochs", "demo", "extra"});
    check_error({"kasumi", "remote", "epoch", "demo"});
    check_error({"kasumi", "remote", "epoch", "demo", ""});
    check_error({"kasumi", "remote", "epoch", "demo", "1", "extra"});
    check_error({"kasumi", "remote", "contents"});
    check_error({"kasumi", "remote", "contents", "--audit"});
    check_error({"kasumi", "remote", "contents", "demo", "--audit"});
    check_error({"kasumi", "remote", "contents", "--audit", ""});
    check_error({"kasumi", "remote", "content", "demo"});
    check_error({"kasumi", "remote", "content", "demo", "short"});
    check_error(
        {"kasumi", "remote", "content", "demo", std::string(64, 'a'), "extra"});
    for (const auto* command :
         {"markers", "objects", "orphans", "quarantine", "writers", "health"}) {
        check_error({"kasumi", "remote", command});
        check_error({"kasumi", "remote", command, ""});
        check_error({"kasumi", "remote", command, "demo", "extra"});
        check_error({"kasumi", "remote", command, "demo", "--audit"});
    }
}

TEST(CliParserTest, ParserAcceptsNamesWhoseRuntimeValidityIsSeparate) {
    const auto invocation = parse({"kasumi", "status", "name with space"});
    ASSERT_TRUE(
        std::holds_alternative<kasumi::application::Request>(invocation));
    EXPECT_EQ(std::get<kasumi::application::Request>(invocation).profile_name,
              "name with space");
}

} // namespace
