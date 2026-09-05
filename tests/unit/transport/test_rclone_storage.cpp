#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/scoped_environment.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/cancellation.hpp"
#include "platform/path.hpp"
#include "transport/rclone/detail.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <gtest/gtest.h>
#include <httplib.h>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <thread>
#include <vector>

TEST(TransportTypesTest, ConnectionLossOrCancellationMakesMutationAmbiguous) {
    using kasumi::transport::Error;
    using kasumi::transport::ErrorCode;
    EXPECT_TRUE(kasumi::transport::mutation_result_is_ambiguous(
        Error{.code = ErrorCode::Io}));
    EXPECT_TRUE(kasumi::transport::mutation_result_is_ambiguous(
        Error{.code = ErrorCode::Timeout}));
    EXPECT_TRUE(kasumi::transport::mutation_result_is_ambiguous(
        Error{.code = ErrorCode::Cancelled}));
    EXPECT_FALSE(kasumi::transport::mutation_result_is_ambiguous(
        Error{.code = ErrorCode::PermissionDenied}));
    EXPECT_FALSE(kasumi::transport::mutation_result_is_ambiguous(
        Error{.code = ErrorCode::InvalidContext}));
    EXPECT_FALSE(kasumi::transport::mutation_result_is_ambiguous(
        Error{.code = ErrorCode::ProtocolFailure}));
}

TEST(RcloneStorageTest, ParsesRelativePathsWithoutRemotePrefix) {
    const auto result = kasumi::transport::rclone_detail::parse_list_response(
        R"({"list":[{"Path":"history/heads/example.head"},{"Path":"history/commits/example/object.kcom"}]})");
    ASSERT_TRUE(result.has_value());
    const std::vector<std::string> expected{
        "history/commits/example/object.kcom", "history/heads/example.head"};
    EXPECT_EQ(*result, expected);
}

TEST(RcloneStorageTest, RejectsUnsafeAndDuplicatePaths) {
    for (const auto path :
         {"/history/object", "history/../object", "history\\object"}) {
        const auto json =
            std::string{"{\"list\":[{\"Path\":\""} + path + "\"}]}";
        const auto result =
            kasumi::transport::rclone_detail::parse_list_response(json);
        ASSERT_FALSE(result.has_value()) << path;
        EXPECT_EQ(result.error().code,
                  kasumi::transport::ErrorCode::ProtocolFailure);
    }

    const auto result = kasumi::transport::rclone_detail::parse_list_response(
        R"({"list":[{"Path":"history/object"},{"Path":"history/object"}]})");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::transport::ErrorCode::ProtocolFailure);
}

namespace {

std::optional<std::string> environment_value(
    const kasumi::transport::rclone_detail::ChildEnvironment& environment,
    std::string_view name) {
    for (const auto& [candidate, value] : environment) {
        if (candidate == name) {
            return value;
        }
    }
    return std::nullopt;
}

TEST(RcloneSessionTest, RemovesKasumiSecretsFromChildEnvironment) {
    auto master = kasumi::test::scoped_environment_variable("KASUMI_MASTER_KEY",
                                                            "master-secret");
    auto password = kasumi::test::scoped_environment_variable(
        "KASUMI_PASSWORD", "password-secret");
    auto salt = kasumi::test::scoped_environment_variable("KASUMI_PASSWORD2",
                                                          "salt-secret");
    auto future = kasumi::test::scoped_environment_variable(
        "KASUMI_FUTURE_SECRET", "future-secret");
    auto inherited_rc = kasumi::test::scoped_environment_variable(
        "RCLONE_RC_PASS", "inherited-rc-secret");

    kasumi::transport::rclone_detail::State state;
    state.port = 4321;
    state.username = "ephemeral-user";
    state.password = "ephemeral-password";
    state.base_url = "/ephemeral-base";
    const auto result =
        kasumi::transport::rclone_detail::make_child_environment(state);

    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(environment_value(*result, "KASUMI_MASTER_KEY"));
    EXPECT_FALSE(environment_value(*result, "KASUMI_PASSWORD"));
    EXPECT_FALSE(environment_value(*result, "KASUMI_PASSWORD2"));
    EXPECT_FALSE(environment_value(*result, "KASUMI_FUTURE_SECRET"));
    EXPECT_EQ(environment_value(*result, "RCLONE_RC_PASS"),
              "ephemeral-password");
    EXPECT_EQ(std::ranges::count_if(*result,
                                    [](const auto& entry) {
                                        return entry.first == "RCLONE_RC_PASS";
                                    }),
              1);
}

TEST(RcloneSessionTest, UnicodeConfigPathIsPreservedInChildEnvironment) {
    kasumi::transport::rclone_detail::State state;
    state.configuration.config_path = kasumi::platform::path::from_utf8(
        "高松灯/千早愛音🌸/rclone.conf");

    const auto result =
        kasumi::transport::rclone_detail::make_child_environment(state);

    ASSERT_TRUE(result) << kasumi::transport::describe(result.error());
    EXPECT_EQ(environment_value(*result, "RCLONE_CONFIG"),
              kasumi::platform::path::to_utf8(*state.configuration.config_path));
}

TEST(RcloneSessionTest, ResolvesExecutableFromUnicodeSearchPath) {
    auto workspace =
        kasumi::test::make_temp_workspace("rclone-unicode-executable");
    const auto trusted = kasumi::test::workspace_root(workspace) /
                         kasumi::platform::path::from_utf8("高松灯/千早愛音🌸");
#if defined(_WIN32)
    const auto expected = trusted / "rclone.exe";
    auto path = kasumi::test::scoped_windows_environment_variable(
        L"PATH", trusted.native());
#else
    const auto expected = trusted / "rclone";
    auto path = kasumi::test::scoped_environment_variable(
        "PATH", kasumi::platform::path::to_utf8(trusted));
#endif
    kasumi::test::write_text(expected, "trusted executable");
#if !defined(_WIN32)
    std::filesystem::permissions(expected,
                                 std::filesystem::perms::owner_exec,
                                 std::filesystem::perm_options::add);
#endif
    const kasumi::transport::detail::RcloneConfiguration configuration{
        .remote_name = "remote",
        .remote_root = "root",
        .executable = "rclone",
    };

    const auto resolved =
        kasumi::transport::rclone_detail::resolve_rclone_executable(
            configuration);

    ASSERT_TRUE(resolved) << kasumi::transport::describe(resolved.error());
    EXPECT_EQ(*resolved, std::filesystem::canonical(expected));
}

TEST(RcloneSessionTest, SkipsExecutableInsideSynchronizedDirectory) {
    auto workspace =
        kasumi::test::make_temp_workspace("rclone-executable-resolution");
    const auto synchronized =
        kasumi::test::workspace_path(workspace, "synchronized");
    const auto trusted = kasumi::test::workspace_path(workspace, "trusted");
    std::filesystem::create_directories(synchronized);
    std::filesystem::create_directories(trusted);
#if defined(_WIN32)
    constexpr std::string_view executable_name = "rclone.exe";
    constexpr char path_separator = ';';
#else
    constexpr std::string_view executable_name = "rclone";
    constexpr char path_separator = ':';
#endif
    const auto trap = synchronized / executable_name;
    const auto expected = trusted / executable_name;
    kasumi::test::write_text(trap, "trap");
    kasumi::test::write_text(expected, "trusted");
#if !defined(_WIN32)
    std::filesystem::permissions(trap,
                                 std::filesystem::perms::owner_exec,
                                 std::filesystem::perm_options::add);
    std::filesystem::permissions(expected,
                                 std::filesystem::perms::owner_exec,
                                 std::filesystem::perm_options::add);
#endif
    const auto search_path =
        synchronized.string() + path_separator + trusted.string();
    auto path = kasumi::test::scoped_environment_variable("PATH", search_path);
    ASSERT_NE(std::getenv("PATH"), nullptr);
    EXPECT_EQ(std::getenv("PATH"), search_path);
    kasumi::transport::detail::RcloneConfiguration configuration{
        .remote_name = "remote",
        .remote_root = "root",
        .executable = "rclone",
        .config_path = std::nullopt,
        .forbidden_executable_root = synchronized,
    };
    auto direct_configuration = configuration;
    direct_configuration.executable = expected;
    const auto direct =
        kasumi::transport::rclone_detail::resolve_rclone_executable(
            direct_configuration);
    ASSERT_TRUE(direct.has_value())
        << kasumi::transport::describe(direct.error());

    const auto resolved =
        kasumi::transport::rclone_detail::resolve_rclone_executable(
            configuration);

    ASSERT_TRUE(resolved.has_value())
        << kasumi::transport::describe(resolved.error());
    EXPECT_EQ(*resolved, std::filesystem::canonical(expected));
}

struct RcServerState {
    httplib::Server server;
    int port = 0;
    std::thread thread;
};

void stop_rc_server(RcServerState& state) {
    state.server.stop();
    if (state.thread.joinable()) {
        state.thread.join();
    }
}

void start_rc_server(RcServerState& state) {
    state.port = state.server.bind_to_any_port("127.0.0.1");
    ASSERT_GT(state.port, 0);
    state.thread = std::thread([&state] {
        state.server.listen_after_bind();
    });
    state.server.wait_until_ready();
}

void configure_state(kasumi::transport::rclone_detail::State& state, int port) {
    state.configuration.remote_name = "test";
    state.configuration.remote_root = "root";
    state.base_url = "/rc";
    state.port = static_cast<std::uint16_t>(port);
    state.ready = true;
}

void close_response_early(httplib::Response& response) {
    response.set_content_provider(
        2,
        "application/json",
        [](std::size_t offset, std::size_t, httplib::DataSink& sink) {
            if (offset == 0) {
                sink.write("{", 1);
                return true;
            }
            return false;
        });
}

TEST(RcloneRcClientTest, RetriesClosedConnectionForIdempotentRead) {
    RcServerState remote;
    std::atomic_int calls = 0;
    remote.server.Post(
        "/rc/operations/list",
        [&](const httplib::Request&, httplib::Response& response) {
            if (++calls == 1) {
                close_response_early(response);
                return;
            }
            response.set_content("{}", "application/json");
        });
    start_rc_server(remote);
    kasumi::transport::rclone_detail::State state;
    configure_state(state, remote.port);

    const auto result = kasumi::transport::rclone_detail::post_rc_read_only(
        state, "operations/list", "{}", 1024, std::chrono::seconds{1});
    stop_rc_server(remote);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "{}");
    EXPECT_EQ(calls, 2);
}

TEST(RcloneRcClientTest, AcceptsVariableReadLatencyWithinEachDeadline) {
    RcServerState remote;
    constexpr std::array delays{
        std::chrono::milliseconds{5},
        std::chrono::milliseconds{90},
        std::chrono::milliseconds{20},
    };
    std::atomic_size_t calls = 0;
    remote.server.Post(
        "/rc/operations/list",
        [&](const httplib::Request&, httplib::Response& response) {
            const auto call = calls.fetch_add(1);
            std::this_thread::sleep_for(delays.at(call));
            response.set_content("{}", "application/json");
        });
    start_rc_server(remote);
    kasumi::transport::rclone_detail::State state;
    configure_state(state, remote.port);

    for (std::size_t call = 0; call < delays.size(); ++call) {
        const auto result = kasumi::transport::rclone_detail::post_rc_read_only(
            state,
            "operations/list",
            "{}",
            1024,
            std::chrono::milliseconds{250});
        EXPECT_TRUE(result.has_value()) << call;
    }
    stop_rc_server(remote);
    EXPECT_EQ(calls, delays.size());
}

TEST(RcloneRcClientTest, TimeoutDoesNotPoisonFollowingSuccessfulRead) {
    RcServerState remote;
    std::atomic_int calls = 0;
    remote.server.Post(
        "/rc/operations/list",
        [&](const httplib::Request&, httplib::Response& response) {
            if (++calls == 1) {
                std::this_thread::sleep_for(std::chrono::milliseconds{100});
            }
            response.set_content("{}", "application/json");
        });
    start_rc_server(remote);
    kasumi::transport::rclone_detail::State state;
    configure_state(state, remote.port);

    const auto timed_out = kasumi::transport::rclone_detail::post_rc_read_only(
        state, "operations/list", "{}", 1024, std::chrono::milliseconds{20});
    const auto recovered = kasumi::transport::rclone_detail::post_rc_read_only(
        state, "operations/list", "{}", 1024, std::chrono::milliseconds{500});
    stop_rc_server(remote);
    ASSERT_FALSE(timed_out.has_value());
    EXPECT_EQ(timed_out.error().code, kasumi::transport::ErrorCode::Timeout);
    EXPECT_TRUE(recovered.has_value());
    EXPECT_EQ(calls, 2);
}

TEST(RcloneRcClientTest, DoesNotRetryTransientFailureForMutation) {
    RcServerState remote;
    std::atomic_int calls = 0;
    remote.server.Post(
        "/rc/operations/deletefile",
        [&](const httplib::Request&, httplib::Response& response) {
            if (++calls == 1) {
                close_response_early(response);
                return;
            }
            response.set_content("{}", "application/json");
        });
    start_rc_server(remote);
    kasumi::transport::rclone_detail::State state;
    configure_state(state, remote.port);

    const auto result = kasumi::transport::rclone_detail::post_rc(
        state, "operations/deletefile", "{}", 1024, std::chrono::seconds{1});
    stop_rc_server(remote);

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(calls, 1);
    const auto diagnostic = kasumi::transport::describe(result.error());
    EXPECT_NE(diagnostic.find("io:"), std::string::npos);
    EXPECT_NE(diagnostic.find("endpoint=operations/deletefile"),
              std::string::npos);
    EXPECT_NE(diagnostic.find("duração="), std::string::npos);
    EXPECT_NE(diagnostic.find("tentativa RC=1/1"), std::string::npos);
}

TEST(RcloneRcClientTest, ReportsSlowListWithCurrentAttempt) {
    RcServerState remote;
    remote.server.Post(
        "/rc/operations/list",
        [](const httplib::Request&, httplib::Response& response) {
            std::this_thread::sleep_for(std::chrono::milliseconds{1100});
            response.set_content("{}", "application/json");
        });
    start_rc_server(remote);
    kasumi::transport::rclone_detail::State state;
    configure_state(state, remote.port);
    std::mutex status_mutex;
    std::vector<std::string> statuses;
    state.report_status = [&](std::string_view status) {
        std::lock_guard lock(status_mutex);
        statuses.emplace_back(status);
    };

    const auto result = kasumi::transport::rclone_detail::post_rc_read_only(
        state, "operations/list", "{}", 1024, std::chrono::seconds{2});
    stop_rc_server(remote);

    ASSERT_TRUE(result.has_value());
    std::lock_guard lock(status_mutex);
    ASSERT_EQ(statuses.size(), 1U);
    EXPECT_NE(statuses.front().find("aguardando LIST remoto"),
              std::string::npos);
    EXPECT_NE(statuses.front().find("tentativa RC 1/2"), std::string::npos);
    EXPECT_NE(statuses.front().find("endpoint=operations/list"),
              std::string::npos);
}

TEST(RcloneRcClientTest, CancellationStopsPendingReadWithoutRetry) {
    RcServerState remote;
    std::atomic_int calls = 0;
    remote.server.Post(
        "/rc/operations/list",
        [&](const httplib::Request&, httplib::Response& response) {
            ++calls;
            std::this_thread::sleep_for(std::chrono::milliseconds{300});
            response.set_content("{}", "application/json");
        });
    start_rc_server(remote);
    kasumi::transport::rclone_detail::State state;
    configure_state(state, remote.port);
    kasumi::platform::cancellation::reset();
    std::jthread cancel([] {
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
        kasumi::platform::cancellation::request();
    });

    const auto result = kasumi::transport::rclone_detail::post_rc_read_only(
        state, "operations/list", "{}", 1024, std::chrono::seconds{2});
    stop_rc_server(remote);
    kasumi::platform::cancellation::reset();

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, kasumi::transport::ErrorCode::Cancelled);
    EXPECT_EQ(calls, 1);
}

TEST(RcloneRcClientTest, FailsAuthenticationImmediately) {
    RcServerState remote;
    std::atomic_int calls = 0;
    remote.server.Post(
        "/rc/operations/list",
        [&](const httplib::Request&, httplib::Response& response) {
            ++calls;
            response.status = 401;
        });
    start_rc_server(remote);
    kasumi::transport::rclone_detail::State state;
    configure_state(state, remote.port);

    const auto result = kasumi::transport::rclone_detail::post_rc_read_only(
        state, "operations/list", "{}", 1024, std::chrono::seconds{1});
    stop_rc_server(remote);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::transport::ErrorCode::PermissionDenied);
    EXPECT_EQ(calls, 1);
}

TEST(RcloneRcClientTest, OmitsArbitraryRemoteErrorBodyAndSecrets) {
    RcServerState remote;
    remote.server.Post(
        "/rc/operations/list",
        [](const httplib::Request&, httplib::Response& response) {
            response.status = 500;
            response.set_content(
                R"({"error":"remote-body-marker rc-user-secret rc-password-secret /rc-secret KASUMI_MASTER_KEY=master-secret"})",
                "application/json");
        });
    start_rc_server(remote);
    kasumi::transport::rclone_detail::State state;
    configure_state(state, remote.port);
    state.username = "rc-user-secret";
    state.password = "rc-password-secret";
    state.base_url = "/rc-secret";
    state.configuration.executable =
        std::filesystem::path{"C:/trusted/rclone.exe"};

    const auto result = kasumi::transport::rclone_detail::post_rc_read_only(
        state, "operations/list", "{}", 1024, std::chrono::seconds{1});
    stop_rc_server(remote);

    ASSERT_FALSE(result.has_value());
    const auto diagnostic = kasumi::transport::describe(result.error());
    EXPECT_EQ(diagnostic.find("remote-body-marker"), std::string::npos);
    EXPECT_EQ(diagnostic.find("rc-user-secret"), std::string::npos);
    EXPECT_EQ(diagnostic.find("rc-password-secret"), std::string::npos);
    EXPECT_EQ(diagnostic.find("master-secret"), std::string::npos);
    EXPECT_NE(diagnostic.find("C:/trusted/rclone.exe"), std::string::npos);
}

TEST(RcloneStorageTest, OmitsJobBatchRemoteErrorText) {
    const kasumi::transport::ControlReadBatchRequest request{
        .list_prefixes = {"history/writers"},
        .presence_identifiers = {"history/gc/barrier"},
    };
    const auto result =
        kasumi::transport::rclone_detail::parse_control_read_batch_response(
            R"({"results":[{"status":500,"error":"remote-secret-marker"},{"item":null}]})",
            request,
            "root");

    ASSERT_FALSE(result.has_value());
    const auto diagnostic = kasumi::transport::describe(result.error());
    EXPECT_EQ(diagnostic.find("remote-secret-marker"), std::string::npos);
}

TEST(RcloneRcClientTest, EnforcesGlobalReadDeadline) {
    RcServerState remote;
    std::atomic_int calls = 0;
    remote.server.Post(
        "/rc/operations/list",
        [&](const httplib::Request&, httplib::Response& response) {
            ++calls;
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
            response.set_content("{}", "application/json");
        });
    start_rc_server(remote);
    kasumi::transport::rclone_detail::State state;
    configure_state(state, remote.port);

    const auto result = kasumi::transport::rclone_detail::post_rc_read_only(
        state, "operations/list", "{}", 1024, std::chrono::milliseconds{20});
    stop_rc_server(remote);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, kasumi::transport::ErrorCode::Timeout);
    EXPECT_EQ(calls, 1);
}

TEST(RcloneRcClientTest, NeverTreatsConnectionFailureAsAbsent) {
    RcServerState remote;
    start_rc_server(remote);
    const auto port = remote.port;
    stop_rc_server(remote);
    kasumi::transport::rclone_detail::State state;
    configure_state(state, port);

    const auto operations =
        kasumi::transport::rclone_detail::make_storage_operations();
    const auto result = operations.presence(&state, "history/head");

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, kasumi::transport::ErrorCode::Io);
}

TEST(RcloneRcClientTest, RejectsInvalidReadResponseWithoutRetry) {
    RcServerState remote;
    std::atomic_int calls = 0;
    remote.server.Post(
        "/rc/operations/list",
        [&](const httplib::Request&, httplib::Response& response) {
            ++calls;
            response.set_content("not-json", "application/json");
        });
    start_rc_server(remote);
    kasumi::transport::rclone_detail::State state;
    configure_state(state, remote.port);

    const auto operations =
        kasumi::transport::rclone_detail::make_storage_operations();
    const auto result = operations.list(&state);
    stop_rc_server(remote);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::transport::ErrorCode::ProtocolFailure);
    EXPECT_EQ(calls, 1);
}

TEST(RcloneStorageTest, PreservesUnicodeLocalPathsInCopyRequests) {
    auto workspace =
        kasumi::test::make_temp_workspace("rclone-unicode-copy");
    const auto source = kasumi::test::workspace_root(workspace) /
                        kasumi::platform::path::from_utf8("高松灯/カード💝.png");
    const auto destination = kasumi::test::workspace_root(workspace) /
                             kasumi::platform::path::from_utf8(
                                 "千早愛音🌸/𝑬𝒎𝒊𝒍𝒊𝒂-𓆩🌸𓆪.txt");
    kasumi::test::write_text(source, "unicode payload");
    RcServerState remote;
    std::vector<nlohmann::json> requests;
    remote.server.Post(
        "/rc/operations/copyfile",
        [&](const httplib::Request& input, httplib::Response& response) {
            const auto request = nlohmann::json::parse(input.body);
            requests.push_back(request);
            if (request.at("srcFs") == "test:") {
                kasumi::test::write_text(
                    kasumi::platform::path::from_utf8(
                        request.at("dstFs").get<std::string>()) /
                        kasumi::platform::path::from_utf8(
                            request.at("dstRemote").get<std::string>()),
                    "unicode payload");
            }
            response.set_content("{}", "application/json");
        });
    start_rc_server(remote);
    kasumi::transport::rclone_detail::State state;
    configure_state(state, remote.port);
    const auto operations =
        kasumi::transport::rclone_detail::make_storage_operations();

    const auto uploaded = operations.put(&state, source, "object");
    const auto downloaded = operations.get(&state, "object", destination);
    stop_rc_server(remote);

    ASSERT_TRUE(uploaded) << kasumi::transport::describe(uploaded.error());
    ASSERT_TRUE(downloaded) << kasumi::transport::describe(downloaded.error());
    ASSERT_EQ(requests.size(), 2U);
    EXPECT_EQ(requests[0].at("srcFs"),
              kasumi::platform::path::to_utf8(source.parent_path()));
    EXPECT_EQ(requests[0].at("srcRemote"), "カード💝.png");
    EXPECT_EQ(requests[0].at("dstRemote"), "root/object");
    EXPECT_EQ(requests[1].at("dstFs"),
              kasumi::platform::path::to_utf8(destination.parent_path()));
    EXPECT_EQ(requests[1].at("dstRemote"), "𝑬𝒎𝒊𝒍𝒊𝒂-𓆩🌸𓆪.txt");
    EXPECT_EQ(kasumi::test::read_text(destination), "unicode payload");
}

TEST(RcloneStorageTest, DownloadsExactBatchWithOneSequentialCopy) {
    RcServerState remote;
    std::string request;
    remote.server.Post(
        "/rc/sync/copy",
        [&](const httplib::Request& input, httplib::Response& response) {
            request = input.body;
            response.set_content("{}", "application/json");
        });
    start_rc_server(remote);

    kasumi::transport::rclone_detail::State state;
    configure_state(state, remote.port);
    auto workspace = kasumi::test::make_temp_workspace("rclone-get-batch");
    const auto destination = kasumi::test::workspace_path(workspace, "batch");
    std::filesystem::create_directories(destination);
    const auto operations =
        kasumi::transport::rclone_detail::make_storage_operations();

    const auto downloaded =
        operations.get_batch(&state,
                             {.source_prefix = "history/commits",
                              .destination_root = destination,
                              .identifiers = {"a/one.kcom", "b/two.kcom"},
                              .max_parallel_transfers = 1});
    stop_rc_server(remote);
    ASSERT_TRUE(downloaded);
    EXPECT_NE(request.find(R"("srcFs":"test:root/history/commits")"),
              std::string::npos);
    EXPECT_NE(request.find(R"("Transfers":1)"), std::string::npos);
    EXPECT_NE(request.find("/a/one.kcom"), std::string::npos);
    EXPECT_NE(request.find("/b/two.kcom"), std::string::npos);
}

kasumi::transport::PhysicalHashBatchRequest batch_request() {
    return {
        .scratch_root = std::filesystem::path{"scratch"},
        .objects = {{"a", std::string(64, 'a')},
                    {"b", std::string(64, 'b')},
                    {"c", std::string(64, 'c')}},
        .algorithm = "sha256",
    };
}

kasumi::transport::ControlReadBatchRequest control_batch_request() {
    return {.list_prefixes = {"history/writers"},
            .presence_identifiers = {"history/gc/barrier"}};
}

auto parse_control_batch(std::string_view response) {
    return kasumi::transport::rclone_detail::parse_control_read_batch_response(
        response, control_batch_request(), "bench");
}

TEST(RcloneStorageTest, BulkCheckAcceptsCompleteAllMatchResponse) {
    const auto result =
        kasumi::transport::rclone_detail::parse_physical_hash_batch_response(
            R"({"differ":[],"error":[],"hashType":"sha256","match":["a","b","c"],"missingOnDst":[],"success":true})",
            batch_request());
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->mismatched.empty());
    EXPECT_TRUE(result->missing.empty());
    EXPECT_TRUE(result->errors.empty());
}

TEST(RcloneStorageTest, BulkCheckAcceptsThousandsOfFilesResponse) {
    kasumi::transport::PhysicalHashBatchRequest request;
    request.scratch_root = std::filesystem::path{"scratch"};
    request.algorithm = "sha256";
    std::string matches;
    constexpr int count = 5000;
    request.objects.reserve(count);
    for (int i = 0; i < count; ++i) {
        const auto id = "file_" + std::to_string(i);
        request.objects.push_back({id, std::string(64, '0')});
        if (!matches.empty()) {
            matches += ",";
        }
        matches += "\"" + id + "\"";
    }
    const auto json = "{\"differ\":[],\"error\":[],\"hashType\":\"sha256\",\"match\":[" + matches + "],\"missingOnDst\":[],\"success\":true}";
    const auto result =
        kasumi::transport::rclone_detail::parse_physical_hash_batch_response(json, request);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->mismatched.empty());
    EXPECT_TRUE(result->missing.empty());
    EXPECT_TRUE(result->errors.empty());
}

TEST(RcloneStorageTest, ParsesBulkCheckMismatchAndMissing) {
    const auto result =
        kasumi::transport::rclone_detail::parse_physical_hash_batch_response(
            R"({"differ":["b"],"error":[],"hashType":"sha256","match":["a"],"missingOnDst":["c"],"success":false})",
            batch_request());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->mismatched, (std::vector<std::string>{"b"}));
    EXPECT_EQ(result->missing, (std::vector<std::string>{"c"}));
    EXPECT_TRUE(result->errors.empty());
}

TEST(RcloneStorageTest, BulkCheckRejectsMissingMatchField) {
    const auto result =
        kasumi::transport::rclone_detail::parse_physical_hash_batch_response(
            R"({"differ":[],"error":[],"hashType":"sha256","missingOnDst":[],"success":true})",
            batch_request());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::transport::ErrorCode::ProtocolFailure);
}

TEST(RcloneStorageTest, BulkCheckRejectsUnexpectedIdentifier) {
    const auto result =
        kasumi::transport::rclone_detail::parse_physical_hash_batch_response(
            R"({"differ":["not-in-request"],"error":[],"hashType":"sha256","match":[],"missingOnDst":[],"success":false})",
            batch_request());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::transport::ErrorCode::ProtocolFailure);
}

TEST(RcloneStorageTest, BulkCheckRejectsMissingExpectedIdentifier) {
    const auto result =
        kasumi::transport::rclone_detail::parse_physical_hash_batch_response(
            R"({"differ":[],"error":[],"hashType":"sha256","match":["a","b"],"missingOnDst":[],"success":true})",
            batch_request());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::transport::ErrorCode::ProtocolFailure);
}

TEST(RcloneStorageTest, BulkCheckRejectsCrossCategoryDuplicate) {
    const auto result =
        kasumi::transport::rclone_detail::parse_physical_hash_batch_response(
            R"({"differ":["b"],"error":[],"hashType":"sha256","match":["a","b"],"missingOnDst":[],"success":false})",
            batch_request());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::transport::ErrorCode::ProtocolFailure);
}

TEST(RcloneStorageTest, BulkCheckRejectsDuplicateWithinCategory) {
    const auto result =
        kasumi::transport::rclone_detail::parse_physical_hash_batch_response(
            R"({"differ":[],"error":[],"hashType":"sha256","match":["a","a","b","c"],"missingOnDst":[],"success":true})",
            batch_request());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::transport::ErrorCode::ProtocolFailure);
}

TEST(RcloneStorageTest, BulkCheckRejectsWrongFieldType) {
    const auto result =
        kasumi::transport::rclone_detail::parse_physical_hash_batch_response(
            R"({"differ":[],"error":[],"hashType":"sha256","match":"a","missingOnDst":[],"success":true})",
            batch_request());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::transport::ErrorCode::ProtocolFailure);
}

TEST(RcloneStorageTest, BulkCheckRejectsSuccessWithFailureEntries) {
    const auto result =
        kasumi::transport::rclone_detail::parse_physical_hash_batch_response(
            R"({"differ":["c"],"error":[],"hashType":"sha256","match":["a","b"],"missingOnDst":[],"success":true})",
            batch_request());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::transport::ErrorCode::ProtocolFailure);
}

TEST(RcloneStorageTest, BulkCheckRejectsFalseSuccessWithoutFailureReason) {
    const auto result =
        kasumi::transport::rclone_detail::parse_physical_hash_batch_response(
            R"({"differ":[],"error":[],"hashType":"sha256","match":["a","b","c"],"missingOnDst":[],"success":false})",
            batch_request());
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              kasumi::transport::ErrorCode::ProtocolFailure);
}

TEST(RcloneStorageTest, ControlBatchParsesPositionalSuccessAndNotFound) {
    const auto result = parse_control_batch(
        R"({"results":[{"list":[{"Path":"bench/history/writers/self.writer"}],"status":200},{"error":"object not found","status":404}]})");
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->listings.size(), 1);
    EXPECT_EQ(result->listings.front(),
              (std::vector<std::string>{"self.writer"}));
    EXPECT_EQ(result->presences,
              (std::vector<kasumi::transport::Presence>{
                  kasumi::transport::Presence::Absent}));
}

TEST(RcloneStorageTest, ControlBatchRejectsMalformedEnvelope) {
    for (const auto response : {"not json",
                                R"({})",
                                R"({"results":{}})",
                                R"({"results":[]})",
                                R"({"results":[{}, {}, {}]})"}) {
        const auto result = parse_control_batch(response);
        ASSERT_FALSE(result.has_value()) << response;
        EXPECT_EQ(result.error().code,
                  kasumi::transport::ErrorCode::ProtocolFailure);
    }
}

TEST(RcloneStorageTest, ControlBatchRejectsFailedStatusWithPlausiblePayload) {
    for (
        const auto response :
        {R"({"results":[{"list":[{"Path":"bench/history/writers/self.writer"}],"status":500},{"item":null,"status":200}]})",
         R"({"results":[{"list":[],"status":200},{"item":null,"status":500}]})"}) {
        const auto result = parse_control_batch(response);
        ASSERT_FALSE(result.has_value()) << response;
        EXPECT_EQ(result.error().code,
                  kasumi::transport::ErrorCode::ProtocolFailure);
    }
}

TEST(RcloneStorageTest, ControlBatchRejectsMalformedOrContradictorySubresults) {
    for (
        const auto response :
        {R"({"results":[{"error":7,"status":404},{"item":null,"status":200}]})",
         R"({"results":[{"list":[],"status":"200"},{"item":null,"status":200}]})",
         R"({"results":[{"error":"not found","list":[{"Path":"bench/history/writers/self.writer"}],"status":404},{"item":null,"status":200}]})",
         R"({"results":[{"list":[],"status":200},{"error":"not found","item":{"IsDir":false},"status":404}]})",
         R"({"results":[{"list":7,"status":200},{"item":null,"status":200}]})",
         R"({"results":[{"list":[],"status":200},{"item":7,"status":200}]})",
         R"({"results":[{"list":[],"status":200},{"item":{"IsDir":"false"},"status":200}]})"}) {
        const auto result = parse_control_batch(response);
        ASSERT_FALSE(result.has_value()) << response;
        EXPECT_EQ(result.error().code,
                  kasumi::transport::ErrorCode::ProtocolFailure);
    }
}

} // namespace
