#include "application/execute.hpp"
#include "application/inspection/inspect.hpp"
#include "cli/app.hpp"
#include "cli/update.hpp"
#include "kasumi/test/scoped_environment.hpp"
#include "platform/cancellation.hpp"

#include <chrono>
#include <csignal>
#include <cmath>
#include <gtest/gtest.h>
#include <print>
#include <regex>
#include <string>
#include <thread>
#include <vector>

namespace {

enum class Outcome {
    Success,
    Failure,
    Partial,
    AuditFindings,
    Cancelled
};
Outcome outcome = Outcome::Success;
int calls = 0;
std::string profile_received;
double operation_elapsed = 0.0;
constexpr auto delay = std::chrono::milliseconds(25);
constexpr auto transport_detail =
    "timeout: connection reset (native_code=10054)";

void perform() {
    ++calls;
    const auto start = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(delay);
    operation_elapsed =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - start)
            .count();
    if (outcome == Outcome::Cancelled)
        std::raise(SIGINT);
}

struct Output {
    int code;
    std::string out;
    std::string err;
    double elapsed;
};

Output run(std::vector<std::string> arguments) {
    operation_elapsed = 0.0;
    std::vector<char*> argv;
    for (auto& argument : arguments)
        argv.push_back(argument.data());
    testing::internal::CaptureStdout();
    testing::internal::CaptureStderr();
    const auto start = std::chrono::steady_clock::now();
    const int code =
        kasumi::cli::run(static_cast<int>(argv.size()), argv.data());
    const double elapsed =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - start)
            .count();
    return {code,
            testing::internal::GetCapturedStdout(),
            testing::internal::GetCapturedStderr(),
            elapsed};
}

void expect_duration(const Output& output,
                     bool error_stream = false,
                     const std::string& label = "Duration") {
    const auto& text = error_stream ? output.err : output.out;
    std::smatch match;
    ASSERT_TRUE(std::regex_search(
        text, match, std::regex(label + R"(: ([0-9]+\.[0-9]{3}) s\r?\n)")))
        << text;
    const auto reported = std::stod(match[1]);
    EXPECT_TRUE(std::isfinite(reported));
    EXPECT_GE(reported, 0.0);
    EXPECT_GT(operation_elapsed, 0.001);
    EXPECT_GE(reported, operation_elapsed - 0.001);
    EXPECT_LE(reported, output.elapsed + 0.001);
    EXPECT_EQ(
        text.find(label + ":",
                  static_cast<std::size_t>(match.position() + match.length())),
        std::string::npos);
    EXPECT_EQ((error_stream ? output.out : output.err).find(label + ":"),
              std::string::npos);
}

const std::vector<std::vector<std::string>> application_commands{
    {"sync", "Programação-日本"},
    {"sync", "Programação-日本", "--dry-run"},
    {"status", "Programação-日本"},
    {"fsck", "Programação-日本"},
    {"gc", "Programação-日本"},
    {"gc",
     "remove-writer",
     "Programação-日本",
     "2796e9c1/99b74a57/8973/0e7f7095/f51c45986e4bf1accbf45b9e2a14c8ab"},
    {"gc", "remove-barrier", "Programação-日本", "--confirm-abandoned"},
    {"resolve-missing", "Programação-日本"}};

TEST(CliBoundaryTest,
     ApplicationOutcomesHaveOneRealElapsedDurationAndKeepExitCodes) {
    const auto language =
        kasumi::test::scoped_environment_variable("KASUMI_LANG", "en");
    for (const auto selected :
         {Outcome::Success, Outcome::Failure, Outcome::Cancelled}) {
        outcome = selected;
        for (const auto& tail : application_commands) {
            std::vector<std::string> arguments{"kasumi"};
            arguments.insert(arguments.end(), tail.begin(), tail.end());
            calls = 0;
            const auto output = run(arguments);
            SCOPED_TRACE(testing::PrintToString(arguments));
            EXPECT_EQ(output.code,
                      selected == Outcome::Success   ? 0
                      : selected == Outcome::Failure ? 1
                                                     : 130);
            EXPECT_EQ(calls, 1);
            EXPECT_EQ(profile_received, "Programação-日本");
            expect_duration(output);
            EXPECT_EQ(output.out.find("123 s"), std::string::npos);
            if (selected == Outcome::Failure) {
                EXPECT_NE(output.out.find(transport_detail), std::string::npos);
            }
        }
    }
}

TEST(CliBoundaryTest, PartialAndInventoryFindingsRetainExitTwoAndDuration) {
    const auto language =
        kasumi::test::scoped_environment_variable("KASUMI_LANG", "en");
    outcome = Outcome::Partial;
    for (const auto& tail :
         std::vector<std::vector<std::string>>{{"sync", "demo"},
                                               {"sync", "demo", "--dry-run"},
                                               {"status", "demo"}}) {
        std::vector<std::string> arguments{"kasumi"};
        arguments.insert(arguments.end(), tail.begin(), tail.end());
        const auto output = run(arguments);
        EXPECT_EQ(output.code, 2);
        EXPECT_NE(output.out.find("pending.txt"), std::string::npos);
        expect_duration(output);
    }
    outcome = Outcome::AuditFindings;
    const auto audited = run({"kasumi", "sync", "demo", "--audit-inventory"});
    EXPECT_EQ(audited.code, 2);
    EXPECT_NE(audited.out.find("Missing: 1"), std::string::npos);
    expect_duration(audited);
}

TEST(CliBoundaryTest,
     RemoteOutcomesKeepTransportDetailsCancellationAndDuration) {
    const auto language =
        kasumi::test::scoped_environment_variable("KASUMI_LANG", "en");
    for (const auto selected :
         {Outcome::Success, Outcome::Failure, Outcome::Cancelled}) {
        outcome = selected;
        for (const auto& tail : std::vector<std::vector<std::string>>{
                 {"heads", "demo"},
                 {"tree", "demo"},
                 {"contents", "demo", "--audit"},
                 {"get", "demo", "álbum/foto.jpg", "downloads/foto.jpg"}}) {
            std::vector<std::string> arguments{"kasumi", "remote"};
            arguments.insert(arguments.end(), tail.begin(), tail.end());
            const auto output = run(arguments);
            SCOPED_TRACE(testing::PrintToString(arguments));
            EXPECT_EQ(output.code,
                      selected == Outcome::Success   ? 0
                      : selected == Outcome::Failure ? 1
                                                     : 130);
            expect_duration(output);
            if (selected == Outcome::Failure) {
                EXPECT_NE(output.out.find(transport_detail), std::string::npos);
            }
        }
    }
}

TEST(CliBoundaryTest, UpdateOutcomesHaveDurationWithoutRunningAnInstaller) {
    const auto language =
        kasumi::test::scoped_environment_variable("KASUMI_LANG", "en");
    for (const auto selected :
         {Outcome::Success, Outcome::Failure, Outcome::Cancelled}) {
        outcome = selected;
        const auto output = run({"kasumi", "update"});
        EXPECT_EQ(output.code,
                  selected == Outcome::Success   ? 0
                  : selected == Outcome::Failure ? 1
                                                 : 130);
        expect_duration(output);
        if (selected == Outcome::Failure) {
            EXPECT_NE(output.out.find(transport_detail), std::string::npos);
        }
    }
}

TEST(CliBoundaryTest, DurationUsesTheSelectedLanguage) {
    outcome = Outcome::Success;
    const auto output = run({"kasumi", "--lang", "pt-BR", "gc", "demo"});
    EXPECT_EQ(output.code, 0);
    expect_duration(output, false, "Duração");
}

} // namespace

// Link substitutes keep timing/dispatch tests at the public CLI boundary.
namespace kasumi::application {

std::expected<Response, Error> execute(ExecutionInput input) {
    perform();
    profile_received = input.request.profile_name;
    if (outcome == Outcome::Failure || outcome == Outcome::Cancelled) {
        return std::unexpected(Error{.operation = input.request.operation,
                                     .detail = transport_detail});
    }
    Response result{.operation = input.request.operation};
    switch (result.operation) {
        case Operation::Sync:
            result.data = SyncCompleted{
                .pending = outcome == Outcome::Partial ? 1u : 0u,
                .pending_paths =
                    outcome == Outcome::Partial
                        ? std::vector<std::filesystem::path>{"pending.txt"}
                        : std::vector<std::filesystem::path>{},
                .partial = outcome == Outcome::Partial,
                .duration = std::chrono::seconds(123)};
            if (outcome == Outcome::AuditFindings)
                result.inventory_audit =
                    InventoryAuditReport{.missing_content = 1};
            break;
        case Operation::Preview:
        case Operation::Status:
            result.data = PlanReport{
                .pending_paths =
                    outcome == Outcome::Partial
                        ? std::vector<std::filesystem::path>{"pending.txt"}
                        : std::vector<std::filesystem::path>{}};
            break;
        case Operation::Fsck:
            result.data = FsckCompleted{};
            break;
        case Operation::GarbageCollect:
            result.data = GarbageCollectCompleted{};
            break;
        case Operation::RemoveWriter:
            result.data = ManualWriterRemovalCompleted{};
            break;
        case Operation::RemoveBarrier:
            result.data = ManualBarrierRemovalCompleted{};
            break;
        case Operation::ResolveMissing:
            result.data = ResolveMissingCompleted{};
            break;
    }
    return result;
}

std::expected<InspectionResponse, InspectionError>
inspect(InspectionInput input) {
    perform();
    if (outcome == Outcome::Failure || outcome == Outcome::Cancelled) {
        return std::unexpected(InspectionError{
            .operation = input.request.operation, .detail = transport_detail});
    }
    InspectionResponse result{.operation = input.request.operation};
    if (result.operation == InspectionOperation::RemoteTree)
        result.payload = RemoteTreeReport{};
    if (result.operation == InspectionOperation::RemoteContentsAudit)
        result.payload = RemoteContentsReport{};
    if (result.operation == InspectionOperation::RemoteGet)
        result.payload = RemoteFileReport{};
    return result;
}

std::expected<InspectionResponse, InspectionError>
read_remote_file(InspectionInput input) {
    return inspect(std::move(input));
}

} // namespace kasumi::application

namespace kasumi::cli::update {
int run(int, char*[]) {
    perform();
    if (outcome == Outcome::Failure) {
        std::println("[ERROR] {}", transport_detail);
        return 1;
    }
    return outcome == Outcome::Cancelled ? 130 : 0;
}
} // namespace kasumi::cli::update
