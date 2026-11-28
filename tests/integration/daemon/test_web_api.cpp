#include "application/concurrency.hpp"
#include "application/daemon.hpp"
#include "application/daemon/web_auth.hpp"
#include "application/execute.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/profile.hpp"
#include "crypto/key_derivation.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/scoped_environment.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/path.hpp"
#include "platform/profile_lock.hpp"
#include "transport/transport.hpp"

#include <atomic>
#include <barrier>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <future>
#include <gtest/gtest.h>
#include <httplib.h>
#include <mutex>
#include <nlohmann/json.hpp>
#include <random>
#include <system_error>
#include <thread>

namespace {
namespace app = kasumi::application;
using Json = nlohmann::json;
using namespace std::chrono_literals;

struct Api {
    kasumi::test::TempWorkspace workspace;
    app::ExecutionEnvironment env;
    app::DaemonSession daemon;
    std::unique_ptr<httplib::Client> client;
    httplib::Headers headers;
};

Api start_api() {
    auto workspace = kasumi::test::make_temp_workspace("kasumi-http-");
    app::ExecutionEnvironment env{.app_data_dir = workspace->root / "app"};
    kasumi::test::write_text(env.app_data_dir / "web.json", R"({"port":0})");
    auto session = app::start_daemon_session(env);
    if (!session)
        throw std::runtime_error(session.error().detail);
    const auto port = app::query_daemon_session_status(*session)->ipc_port;
    auto client = std::make_unique<httplib::Client>("127.0.0.1", port);
    client->set_read_timeout(60, 0);
    auto metadata = Json::parse(
        kasumi::test::read_text(env.app_data_dir / "daemon.control.json"));
    return {.workspace = std::move(workspace),
            .env = env,
            .daemon = std::move(*session),
            .client = std::move(client),
            .headers = {{"X-Kasumi-Daemon-Token",
                         metadata.at("auth_token").get<std::string>()}}};
}

Json response(const httplib::Result& r, int status) {
    if (!r) {
        ADD_FAILURE() << "HTTP transport failed: "
                      << httplib::to_string(r.error());
        return nullptr;
    }
    EXPECT_EQ(r->status, status) << r->body.substr(0, 240);
    return Json::parse(r->body, nullptr, false);
}
Json get(Api& api, const std::string& path, int status = 200) {
    SCOPED_TRACE(path);
    return response(api.client->Get(path, api.headers), status);
}
Json post(Api& api,
          const std::string& path,
          const Json& body,
          int status = 200) {
    SCOPED_TRACE(path);
    return response(
        api.client->Post(path, api.headers, body.dump(), "application/json"),
        status);
}
Json poll_job(Api& api,
              const std::string& path,
              const Json& body,
              std::string_view expected_state = "completed",
              std::optional<bool> expected_dry_run = std::nullopt) {
    SCOPED_TRACE(path);
    const auto accepted =
        api.client->Post(path, api.headers, body.dump(), "application/json");
    const auto job = response(accepted, 202);
    const auto location =
        "/v1/jobs/" + std::to_string(job.at("id").get<std::uint64_t>());
    EXPECT_EQ(accepted->get_header_value("Location"), location);
    if (expected_dry_run) {
        EXPECT_EQ(job.at("dry_run"), *expected_dry_run);
    }
    const auto deadline = std::chrono::steady_clock::now() + 60s;
    Json row;
    do {
        row = get(api, location);
        if (row.at("state") != "running")
            break;
        std::this_thread::sleep_for(30ms);
    } while (std::chrono::steady_clock::now() < deadline);
    EXPECT_EQ(row.at("state").get<std::string>(), expected_state) << row.dump();
    return row;
}
Json job_result(Api& api,
                const std::string& path,
                const Json& body,
                std::string_view expected_state = "completed") {
    return poll_job(api, path, body, expected_state).at("result");
}

std::filesystem::path create(Api& api, std::string name = "demo") {
    auto local = api.workspace->root / name;
    auto remote = api.workspace->root / "remote";
    std::filesystem::create_directories(local);
    std::filesystem::create_directories(remote);
    auto result = post(api,
                       "/v1/profiles",
                       {{"name", name},
                        {"local_dir", kasumi::platform::path::to_utf8(local)},
                        {"remote_dir", kasumi::platform::path::to_utf8(remote)},
                        {"key_storage", "file"},
                        {"paused", true},
                        {"verify", true},
                        {"master_key", std::string(64, '7')}});
    EXPECT_FALSE(result.contains("master_key"));
    return local;
}

TEST(WebApiTest, ChangesAutostartAndRefreshesStatus) {
    auto workspace =
        kasumi::test::make_temp_workspace("kasumi-http-autostart-");
    auto autostart_dir = workspace->root / "startup";
    auto override = kasumi::test::scoped_environment_variable(
        "KASUMI_AUTOSTART_DIR", kasumi::platform::path::to_utf8(autostart_dir));
    auto api = start_api();
    const auto config = autostart_dir / "kasumi-autostart.conf";
    post(api, "/v1/autostart", {{"enabled", "true"}}, 400);
    EXPECT_FALSE(std::filesystem::exists(config));
    EXPECT_EQ(post(api, "/v1/autostart", {{"enabled", true}}).at("installed"),
              true);
    EXPECT_TRUE(std::filesystem::is_regular_file(config));
    EXPECT_EQ(get(api, "/v1/status").at("autostart").at("installed"), true);
    EXPECT_EQ(post(api, "/v1/autostart", {{"enabled", false}}).at("installed"),
              false);
    EXPECT_FALSE(std::filesystem::exists(config));
    EXPECT_EQ(get(api, "/v1/status").at("autostart").at("installed"), false);
}

TEST(WebApiTest, RunsAdvancedSyncAndReturnsInventoryAndRecoveryDetails) {
    auto api = start_api();
    auto local = create(api);
    for (unsigned i = 0; i < 6; ++i) {
        const auto name = "note-" + std::to_string(i) + ".txt";
        kasumi::test::write_text(local / name, "sync inventory " + name);
    }
    const std::string path = "/v1/maintenance/demo/sync";
    const auto initial = job_result(api, path, {{"initial", true}}, "failed");
    EXPECT_NE(initial.at("error").get<std::string>().find(
                  "requires absent local state"),
              std::string::npos);
    auto synchronized = job_result(api, path, Json::object());
    EXPECT_TRUE(synchronized.at("published").get<bool>());
    EXPECT_GE(synchronized.at("total").get<unsigned>(), 1U);
    auto audited = job_result(api,
                              path,
                              {{"audit_inventory", true},
                               {"bandwidth_limit", "8M"},
                               {"transfer_concurrency", 2}});
    EXPECT_GT(
        audited.at("inventory_audit").at("present_content").get<unsigned>(),
        0U);
    EXPECT_EQ(audited.at("inventory_audit").at("missing_content"), 0);
    EXPECT_EQ(job_result(api, path, {{"repair", true}}).at("repaired"), 0);
    const auto incompatible = job_result(
        api, path, {{"initial", true}, {"allow_empty_local", true}}, "failed");
    EXPECT_NE(
        incompatible.at("error").get<std::string>().find("--allow-empty-local"),
        std::string::npos);
    for (unsigned i = 0; i < 6; ++i)
        ASSERT_TRUE(std::filesystem::remove(
            local / ("note-" + std::to_string(i) + ".txt")));
    auto guarded = job_result(api, path, Json::object(), "failed");
    EXPECT_EQ(guarded.at("empty_local_blocked"), true);
    EXPECT_TRUE(job_result(api, path, {{"allow_empty_local", true}})
                    .at("published")
                    .get<bool>());
    post(api, path, {{"transfer_concurrency", -1}}, 400);
}

TEST(WebApiTest,
     RemovesSelectedMaintenanceMarkersWithExplicitBarrierConfirmation) {
    auto api = start_api();
    create(api);
    const auto remote =
        kasumi::platform::path::to_utf8(api.workspace->root / "remote");
    auto storage = kasumi::transport::open_transport(remote);
    ASSERT_TRUE(storage);
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    const auto stage = api.workspace->root / "marker-stage";
    ASSERT_TRUE(std::filesystem::create_directory(stage));
    kasumi::crypto::Key key{};
    key.fill(0x77);
    namespace hs = app::history_storage;
    namespace protocol = hs::maintenance_protocol;
    const auto layout = hs::derive_remote_layout(key);
    auto writer = protocol::register_writer(*storage, layout, stage);
    ASSERT_TRUE(writer) << writer.error().detail;
    const auto writer_id = writer->identifier;
    const std::string writer_route = "/v1/maintenance/demo/remove-writer";
    post(api, writer_route, Json::object(), 400);
    EXPECT_EQ(job_result(api, writer_route, {{"writer_id", writer_id}})
                  .at("identifier"),
              writer_id);
    ASSERT_EQ(kasumi::transport::presence(*storage, writer_id).value(),
              kasumi::transport::Presence::Absent);
    auto barrier = protocol::establish_barrier(*storage, layout, stage);
    ASSERT_TRUE(barrier) << barrier.error().detail;
    const auto barrier_id = barrier->identifier;
    const std::string barrier_route = "/v1/maintenance/demo/remove-barrier";
    post(api, barrier_route, {{"barrier_id", barrier_id}}, 400);
    post(api,
         barrier_route,
         {{"barrier_id", barrier_id}, {"confirm_abandoned", false}},
         400);
    post(api,
         barrier_route,
         {{"barrier_id", barrier_id}, {"confirm_abandoned", "true"}},
         400);
    ASSERT_EQ(kasumi::transport::presence(*storage, barrier_id).value(),
              kasumi::transport::Presence::Present);
    const Json confirmed{{"barrier_id", barrier_id},
                         {"confirm_abandoned", true}};
    const auto removed = job_result(api, barrier_route, confirmed);
    EXPECT_EQ(removed.at("identifier"), barrier_id);
    EXPECT_EQ(removed.at("outcome"), "removed");
    EXPECT_EQ(removed.at("remaining_barriers_count"), 0);
    EXPECT_EQ(kasumi::transport::presence(*storage, barrier_id).value(),
              kasumi::transport::Presence::Absent);
    EXPECT_EQ(job_result(api, barrier_route, confirmed).at("outcome"),
              "already_absent");
    EXPECT_EQ(job_result(api, barrier_route, {{"confirm_abandoned", true}})
                  .at("outcome"),
              "already_absent");
}

TEST(WebApiTest, DefaultBrowserApiUses3137AndKeepsIpcSeparate) {
    auto workspace = kasumi::test::make_temp_workspace("kasumi-http-default-");
    app::ExecutionEnvironment env{.app_data_dir = workspace->root / "app"};
    const auto config = app::read_web_listener_config(env);
    ASSERT_TRUE(config);
    EXPECT_EQ(config->port, 3137);
    auto session = app::start_daemon_session(env);
    if (!session &&
        session.error().detail == "cannot bind web API on 127.0.0.1:3137") {
        GTEST_SKIP() << "the default Web listener is unavailable on this host";
    }
    ASSERT_TRUE(session) << session.error().detail;
    const auto status = app::query_daemon_status(env);
    ASSERT_TRUE(status) << status.error().detail;
    EXPECT_EQ(status->web_port, 3137);
    EXPECT_NE(status->ipc_port, status->web_port);
    httplib::Client browser("127.0.0.1", 3137);
    EXPECT_FALSE(response(browser.Get("/v1/auth/status"), 200)
                     .at("configured")
                     .get<bool>());
    httplib::Client ipc("127.0.0.1", status->ipc_port);
    response(ipc.Get("/v1/auth/status"), 403);
}

TEST(WebApiTest, IndependentDaemonCannotShareAnActiveListener) {
    auto first = start_api();
    const auto status = app::query_daemon_session_status(first.daemon);
    ASSERT_TRUE(status);
    auto other = kasumi::test::make_temp_workspace("kasumi-http-occupied-");
    app::ExecutionEnvironment env{.app_data_dir = other->root / "app"};
    kasumi::test::write_text(env.app_data_dir / "web.json",
                             Json{{"port", status->ipc_port}}.dump());
    const auto second = app::start_daemon_session(env);
    ASSERT_FALSE(second);
    EXPECT_EQ(second.error().code, app::DaemonErrorCode::IpcFailure);
    EXPECT_FALSE(
        std::filesystem::exists(env.app_data_dir / "daemon.control.json"));
    EXPECT_TRUE(app::query_daemon_status(first.env));
}

TEST(WebApiTest, ProfilesDiagnosticsConflictsAndIgnore) {
    auto api = start_api();
    auto local = create(api);
    EXPECT_TRUE(get(api, "/v1/profiles").at("profiles").size() == 1);
    EXPECT_EQ(get(api, "/v1/profiles/demo").at("paused"), true);
    EXPECT_TRUE(get(api, "/v1/rclone/remotes").contains("remotes"));
    for (auto path : {"/v1/diagnostics", "/v1/diagnostics/demo"}) {
        auto diag = get(api, path);
        EXPECT_TRUE(diag.at("daemon").at("running").get<bool>());
        EXPECT_EQ(diag.at("profiles").size(), 1U);
    }
    auto held = kasumi::platform::acquire_profile_lock(api.env.app_data_dir /
                                                       "profile-demo.lock");
    ASSERT_TRUE(held);
    post(api, "/v1/profiles/demo/ignore/init", Json::object(), 409);
    get(api, "/v1/remote/demo/summary");
    get(api, "/v1/local/demo/tree");
    post(api,
         "/v1/remote/demo/restore",
         {{"dst", kasumi::platform::path::to_utf8(api.workspace->root / "out")},
          {"dry_run", false}},
         409);
    kasumi::platform::release_profile_lock(*held);
    auto patch = Json{{"watch_enabled", false},
                      {"sync_interval_seconds", 600},
                      {"transfer_concurrency", 2}};
    auto updated = response(
        api.client->Patch(
            "/v1/profiles/demo", api.headers, patch.dump(), "application/json"),
        200);
    EXPECT_EQ(updated.at("sync_interval_seconds"), 600);
    response(api.client->Patch("/v1/profiles/demo",
                               api.headers,
                               R"({"transfer_concurrency":-1})",
                               "application/json"),
             400);
    EXPECT_TRUE(post(api, "/v1/profiles/demo/test", Json::object())
                    .at("ready")
                    .get<bool>());
    EXPECT_EQ(post(api,
                   "/v1/profiles/demo/ignore/init",
                   {{"preset", "dev"}, {"dry_run", true}})
                  .at("created"),
              false);
    EXPECT_FALSE(std::filesystem::exists(local / ".kasumiignore"));
    EXPECT_EQ(post(api, "/v1/profiles/demo/ignore/init", {{"preset", "dev"}})
                  .at("created"),
              true);
    const auto existing_ignore =
        kasumi::test::read_text(local / ".kasumiignore");
    const auto dry_existing =
        post(api,
             "/v1/profiles/demo/ignore/init",
             {{"preset", "minimal"}, {"dry_run", true}, {"force", false}});
    EXPECT_EQ(dry_existing.at("dry_run"), true);
    EXPECT_EQ(dry_existing.at("created"), false);
    EXPECT_FALSE(dry_existing.at("content").get<std::string>().empty());
    EXPECT_EQ(kasumi::test::read_text(local / ".kasumiignore"),
              existing_ignore);
    auto ignore = post(api,
                       "/v1/profiles/demo/ignore/check",
                       {{"paths", {"notes.txt", "node_modules/test.js"}}});
    EXPECT_EQ(ignore.at("items").size(), 2U);
    kasumi::test::write_text(local / "note.txt", "canonical");
    kasumi::test::write_text(local / "note.txt.kasumiconflict_local",
                             "artifact");
    EXPECT_EQ(get(api, "/v1/conflicts/demo").at("total_artifacts"), 1);
    EXPECT_EQ(get(api,
                  "/v1/conflicts/demo/"
                  "diff?path=note.txt&artifact=note.txt.kasumiconflict_local")
                  .at("artifact")
                  .at("hex"),
              "6172746966616374");
    get(api, "/v1/conflicts/demo/diff?path=note.txt&artifact=unknown", 404);
    get(api,
        "/v1/conflicts/demo/diff?path=&artifact=note.txt.kasumiconflict_local",
        400);
    get(api, "/v1/conflicts/demo/diff?path=note.txt&artifact=.", 400);
    Json resolve{{"path", "note.txt"},
                 {"choice", "keep_artifact"},
                 {"artifact", "local"},
                 {"dry_run", true}};
    EXPECT_EQ(post(api, "/v1/conflicts/demo/resolve", resolve).at("dry_run"),
              true);
    resolve["dry_run"] = false;
    const auto resolved_single = post(api, "/v1/conflicts/demo/resolve", resolve);
    EXPECT_TRUE(resolved_single.at("recovery_directory").is_null());
    EXPECT_EQ(kasumi::test::read_text(local / "note.txt"), "artifact");

    kasumi::test::write_text(local / "keep.txt", "canonical-keep");
    kasumi::test::write_text(local / "keep.txt.kasumiconflict_remote",
                             "remote-retired");
    const auto resolved_keep = post(
        api,
        "/v1/conflicts/demo/resolve",
        {{"path", "keep.txt"}, {"choice", "keep_canonical"}, {"dry_run", false}});
    ASSERT_TRUE(resolved_keep.at("recovery_directory").is_string());
    const auto recovery_dir =
        resolved_keep.at("recovery_directory").get<std::string>();
    EXPECT_EQ(kasumi::test::read_text(local / recovery_dir /
                                      "keep.txt.kasumiconflict_remote"),
              "remote-retired");
    post(api, "/v1/profiles/demo/clone", {{"name", "copy"}});
    EXPECT_EQ(get(api, "/v1/profiles/copy").at("paused"), true);
    post(api, "/v1/profiles/copy/rename", {{"name", "renamed"}});
    get(api, "/v1/profiles/copy", 404);
    post(api, "/v1/profiles/renamed/storage", {{"key_storage", "memory"}});
    post(api, "/v1/profiles/renamed/storage", {{"key_storage", "file"}});
    post(api,
         "/v1/profiles/renamed/key",
         {{"master_key", std::string(64, '7')}});
    response(api.client->Delete(
                 "/v1/profiles/renamed", api.headers, "{}", "application/json"),
             400);
    response(api.client->Delete("/v1/profiles/renamed",
                                api.headers,
                                R"({"confirm":true})",
                                "application/json"),
             200);
    get(api, "/v1/profiles/renamed", 404);
}

void sync(Api& api) {
    auto result = app::execute(
        {.request = {.operation = app::Operation::Sync, .profile_name = "demo"},
         .credentials = app::NoCredentials{},
         .environment = api.env});
    ASSERT_TRUE(result) << result.error().detail;
}

TEST(WebApiTest, HistoricalTreesDiffRangeRestoreAndManualJobs) {
    auto api = start_api();
    auto local = create(api);
    std::filesystem::create_directory(local / "folder");
    kasumi::test::write_text(local / "folder" / "note.txt", "first revision");
    kasumi::test::write_text(local / "old.txt", "same content after rename");
    sync(api);
    const std::string root = "/v1/remote/demo/";
    auto first = get(api, root + "heads")
                     .at("heads")
                     .at(0)
                     .at("commit_id")
                     .get<std::string>();
    kasumi::test::write_text(local / "folder" / "note.txt",
                             "second revision changed");
    std::filesystem::rename(local / "old.txt", local / "new.txt");
    std::string video(18 * 1024 * 1024, ' ');
    std::mt19937 rng(42);
    for (auto& c : video)
        c = static_cast<char>(rng() & 255);
    std::ofstream(local / "clip.mp4", std::ios::binary)
        .write(video.data(), static_cast<std::streamsize>(video.size()));
    sync(api);
    auto second = get(api, root + "heads")
                      .at("heads")
                      .at(0)
                      .at("commit_id")
                      .get<std::string>();
    ASSERT_NE(first, second);
    EXPECT_EQ(get(api, root + "commits").at("commits").size(), 2U);
    EXPECT_EQ(get(api, root + "commits/" + second)
                  .at("commit")
                  .at("parent_ids")
                  .at(0),
              first);
    EXPECT_EQ(get(api, root + "tree?commit=" + first + "&prefix=folder")
                  .at("entries")
                  .size(),
              2U);
    EXPECT_EQ(get(api, root + "tree?head=" + second).at("commit_id"), second);
    EXPECT_EQ(get(api, root + "log?path=folder/note.txt").at("entries").size(),
              2U);
    EXPECT_EQ(
        get(api, root + "stat?path=folder/note.txt&commit=" + first).at("size"),
        14);
    const auto diff = root + "diff?from=" + first + "&to=" + second;
    const auto changes = get(api, diff).at("changes");
    EXPECT_GE(changes.size(), 3U);
    EXPECT_NE(std::find(changes.begin(),
                        changes.end(),
                        Json{{"kind", "renamed"},
                             {"from", "old.txt"},
                             {"path", "new.txt"}}),
              changes.end());
    EXPECT_EQ(get(api, diff + "&path=folder/note.txt").at("from").at("text"),
              "first revision");
    for (const auto& [route, field] : std::map<std::string, std::string>{
             {"summary", "reachable_commit_count"},
             {"objects", "objects"},
             {"orphans", "objects"},
             {"writers", "writers"},
             {"epochs", "epochs"},
             {"health", "state"}}) {
        EXPECT_TRUE(get(api, root + route).contains(field)) << route;
    }
    const auto usage = get(api, root + "summary").at("space_usage");
    EXPECT_GT(usage.at("current_content_bytes").get<std::uint64_t>(), 0U);
    EXPECT_GT(usage.at("retained_content_bytes").get<std::uint64_t>(), 0U);
    auto restore = Json{
        {"prefix", "folder"},
        {"commit", first},
        {"dst",
         kasumi::platform::path::to_utf8(api.workspace->root / "restored")},
        {"dry_run", true}};
    EXPECT_TRUE(post(api, root + "restore", restore).at("dry_run").get<bool>());
    restore["dry_run"] = false;
    EXPECT_FALSE(
        post(api, root + "restore", restore).at("dry_run").get<bool>());
    auto chunks = get(api, root + "stat?path=clip.mp4").at("chunks");
    ASSERT_GE(chunks.size(), 2U);
    const auto boundary = chunks.at(0).at("size").get<size_t>();
    auto range = [&](std::string path, std::string range_header) {
        auto headers = api.headers;
        headers.emplace("Range", std::move(range_header));
        return api.client->Get(root + "download?path=" + path, headers);
    };
    const auto cross = range("clip.mp4",
                             "bytes=" + std::to_string(boundary - 3) + "-" +
                                 std::to_string(boundary + 5));
    ASSERT_TRUE(cross);
    ASSERT_EQ(cross->status, 206);
    EXPECT_EQ(cross->body, video.substr(boundary - 3, 9));
    EXPECT_EQ(cross->get_header_value("Content-Type"), "video/mp4");
    const auto stream = range("clip.mp4", "bytes=0-");
    ASSERT_TRUE(stream);
    EXPECT_EQ(stream->status, 206);
    EXPECT_EQ(stream->body.size(), video.size());
    EXPECT_TRUE(stream->body == video);
    auto suffix = range("folder/note.txt", "bytes=-7");
    ASSERT_TRUE(suffix);
    EXPECT_EQ(suffix->body, "changed");
    EXPECT_EQ(range("folder/note.txt", "bytes=999-")->status, 416);
    auto historical = api.client->Get(
        root + "download?path=folder/note.txt&commit=" + first, api.headers);
    ASSERT_TRUE(historical);
    EXPECT_EQ(historical->body, "first revision");
    const auto run_job = [&](const std::string& route, const Json& body) {
        return job_result(api, "/v1/" + route, body);
    };
    EXPECT_TRUE(run_job("maintenance/demo/fsck", Json::object())
                    .contains("checked_objects"));
    for (const std::string operation : {"gc", "repack", "resolve-missing"}) {
        const auto sim_done = poll_job(api,
                                       "/v1/maintenance/demo/" + operation,
                                       Json::object(),
                                       "completed",
                                       true);
        EXPECT_EQ(sim_done.at("dry_run"), true);
        EXPECT_EQ(sim_done.at("result").at("dry_run"), true);
        EXPECT_GT(sim_done.at("started_at").get<std::int64_t>(), 0);
        EXPECT_GE(sim_done.at("finished_at").get<std::int64_t>(),
                  sim_done.at("started_at").get<std::int64_t>());
        EXPECT_GE(sim_done.at("duration_ms").get<std::int64_t>(), 0);
        EXPECT_EQ(run_job("maintenance/demo/" + operation,
                          {{"dry_run", false}, {"confirm", true}})
                      .at("dry_run"),
                  false);
    }
    post(api, "/v1/maintenance/demo/gc", {{"dry_run", false}}, 400);
    auto hash =
        kasumi::hash_from_hex(chunks.back().at("hash").get<std::string>());
    ASSERT_TRUE(hash);
    kasumi::crypto::Key key;
    key.fill(0x77);
    auto id = kasumi::crypto::content_identifier(key, *hash);
    ASSERT_TRUE(std::filesystem::remove(api.workspace->root / "remote" / id))
        << id;
    auto partial = range("clip.mp4", "bytes=10-17");
    ASSERT_TRUE(partial);
    EXPECT_EQ(partial->status, 206);
    EXPECT_EQ(partial->body, video.substr(10, 8));
    auto unavailable = range("clip.mp4", "bytes=-8");
    ASSERT_TRUE(unavailable);
    EXPECT_EQ(unavailable->status, 404);
}

TEST(WebApiTest,
     PasswordRotationAndRestartRevokeSessionsAndRestrictProxyHosts) {
    auto api = start_api();
    const auto port = app::query_daemon_session_status(api.daemon)->ipc_port;
    auto bootstrap =
        kasumi::test::read_text(api.env.app_data_dir / "web-bootstrap.token");
    post(api,
         "/v1/auth/password",
         {{"bootstrap_token", bootstrap}, {"password", "first test password"}});
    app::stop_daemon_session(api.daemon);
    const auto verifier_path = api.env.app_data_dir / "web-password.json";
    auto legacy = Json::parse(kasumi::test::read_text(verifier_path));
    legacy.erase("username");
    kasumi::test::write_text(verifier_path, legacy.dump());
    kasumi::test::write_text(
        api.env.app_data_dir / "web.json",
        Json{{"port", port}, {"allowed_hosts", {"kasumi.example"}}}.dump());
    auto restarted = app::start_daemon_session(api.env);
    ASSERT_TRUE(restarted) << restarted.error().detail;
    api.daemon = std::move(*restarted);
    const auto status = app::query_daemon_session_status(api.daemon);
    ASSERT_TRUE(status);
    EXPECT_EQ(status->web_port, port);
    auto current_meta = Json::parse(
        kasumi::test::read_text(api.env.app_data_dir / "daemon.control.json"));
    httplib::Headers token{{"X-Kasumi-Daemon-Token",
                            current_meta.at("auth_token").get<std::string>()}};
    EXPECT_EQ(api.client->Get("/v1/status", token)->status, 403);
    httplib::Headers proxy{{"Host", "kasumi.example"},
                           {"Origin", "https://kasumi.example"},
                           {"X-Forwarded-Proto", "https"}};
    const auto login = [&](std::string password) {
        return api.client->Post(
            "/v1/auth/login",
            proxy,
            Json{{"username", "admin"}, {"password", password}}.dump(),
            "application/json");
    };
    auto first = login("first test password");
    ASSERT_TRUE(first);
    ASSERT_EQ(first->status, 200);
    auto second = login("first test password");
    ASSERT_TRUE(second);
    ASSERT_EQ(second->status, 200);
    auto cookie = first->get_header_value("Set-Cookie");
    EXPECT_NE(cookie.find("; Secure"), std::string::npos);
    EXPECT_NE(cookie.find("Max-Age=2592000"), std::string::npos);
    auto auth = proxy;
    auth.emplace("Cookie", cookie.substr(0, cookie.find(';')));
    auto credentials = Json{{"current_password", "first test password"},
                            {"password", "second test password"}};
    EXPECT_EQ(api.client
                  ->Post("/v1/auth/password",
                         auth,
                         credentials.dump(),
                         "application/json")
                  ->status,
              403);
    {
        // Keep-alive ensures each pre-routing-rejected POST receives its full
        // HTTP response, while stopping between calls avoids reusing a socket
        // whose unread request body was left unconsumed by pre_routing_handler.
        api.client->set_keep_alive(true);
        auto invalid = auth;
        invalid.emplace("X-CSRF-Token", std::string(64, '0'));
        response(
            api.client->Post("/v1/reload", invalid, "{}", "application/json"),
            403);
        api.client->stop();
        auth.emplace(
            "X-CSRF-Token",
            Json::parse(first->body).at("csrf_token").get<std::string>());
        httplib::Request without_type;
        without_type.method = "POST";
        without_type.path = "/v1/reload";
        without_type.headers = auth;
        without_type.body = "{}";
        response(api.client->send(without_type), 415);
        api.client->stop();
        response(api.client->Post("/v1/reload", auth, "{}", "text/plain"), 415);
        api.client->stop();
        response(
            api.client->Post(
                "/v1/reload", auth, "{}", "Application/JSON; charset=utf-8"),
            200);
        api.client->stop();
        api.client->set_keep_alive(false);
    }
    EXPECT_EQ(api.client
                  ->Post("/v1/auth/password",
                         auth,
                         credentials.dump(),
                         "application/json")
                  ->status,
              200);
    EXPECT_EQ(api.client->Get("/v1/status", auth)->status, 403);
    cookie = second->get_header_value("Set-Cookie");
    auth.erase("Cookie");
    auth.emplace("Cookie", cookie.substr(0, cookie.find(';')));
    EXPECT_EQ(api.client->Get("/v1/status", auth)->status, 403);
    auto new_session = login("second test password");
    ASSERT_TRUE(new_session);
    ASSERT_EQ(new_session->status, 200);
    cookie = new_session->get_header_value("Set-Cookie");
    auth.erase("Cookie");
    auth.emplace("Cookie", cookie.substr(0, cookie.find(';')));
    auth.erase("X-CSRF-Token");
    auth.emplace(
        "X-CSRF-Token",
        Json::parse(new_session->body).at("csrf_token").get<std::string>());
    ASSERT_EQ(api.client->Get("/v1/status", auth)->status, 200);
    // Persistent session survives a daemon restart until explicit logout.
    app::stop_daemon_session(api.daemon);
    auto again = app::start_daemon_session(api.env);
    ASSERT_TRUE(again) << again.error().detail;
    api.daemon = std::move(*again);
    EXPECT_EQ(api.client->Get("/v1/status", auth)->status, 200);
    EXPECT_EQ(
        api.client->Post("/v1/auth/logout", auth, "{}", "application/json")
            ->status,
        200);
    EXPECT_EQ(api.client->Get("/v1/status", auth)->status, 403);
    app::stop_daemon_session(api.daemon);
    auto third = app::start_daemon_session(api.env);
    ASSERT_TRUE(third) << third.error().detail;
    api.daemon = std::move(*third);
    EXPECT_EQ(api.client->Get("/v1/status", auth)->status, 403);
    EXPECT_FALSE(
        std::filesystem::exists(api.env.app_data_dir / "web-bootstrap.token"));
    const auto stored =
        kasumi::test::read_text(api.env.app_data_dir / "web-password.json");
    EXPECT_EQ(stored.find("second test password"), std::string::npos);
}

TEST(WebApiTest, UsernameChangeKeepsSessionAndRequiresCurrentPassword) {
    auto api = start_api();
    const auto bootstrap =
        kasumi::test::read_text(api.env.app_data_dir / "web-bootstrap.token");
    post(api,
         "/v1/auth/password",
         {{"bootstrap_token", bootstrap},
          {"username", "initial-user"},
          {"password", "kasumi-pw-123"}});

    auto auth_headers = api.headers;
    const auto login_res = api.client->Post(
        "/v1/auth/login",
        api.headers,
        Json{{"username", "initial-user"}, {"password", "kasumi-pw-123"}}
            .dump(),
        "application/json");
    ASSERT_TRUE(login_res);
    ASSERT_EQ(login_res->status, 200);
    const auto set_cookie = login_res->get_header_value("Set-Cookie");
    auth_headers.emplace("Cookie", set_cookie.substr(0, set_cookie.find(';')));
    auth_headers.emplace(
        "X-CSRF-Token",
        Json::parse(login_res->body).at("csrf_token").get<std::string>());

    EXPECT_EQ(api.client
                  ->Post("/v1/auth/username",
                         auth_headers,
                         Json{{"current_password", "wrong-pass"},
                              {"username", "renamed"}}
                             .dump(),
                         "application/json")
                  ->status,
              403);
    EXPECT_EQ(api.client
                  ->Post("/v1/auth/username",
                         auth_headers,
                         Json{{"current_password", "kasumi-pw-123"},
                              {"username", "   "}}
                             .dump(),
                         "application/json")
                  ->status,
              400);

    const auto changed =
        response(api.client->Post("/v1/auth/username",
                                  auth_headers,
                                  Json{{"current_password", "kasumi-pw-123"},
                                       {"username", "kauan-pc"}}
                                      .dump(),
                                  "application/json"),
                 200);
    EXPECT_EQ(changed.at("username"), "kauan-pc");

    // Current session stays authenticated without re-login.
    const auto status =
        response(api.client->Get("/v1/auth/status", auth_headers), 200);
    EXPECT_TRUE(status.at("authenticated").get<bool>());
    EXPECT_EQ(status.at("username"), "kauan-pc");

    // Fresh login works with new username and old password.
    EXPECT_EQ(
        api.client
            ->Post("/v1/auth/login",
                   api.headers,
                   Json{{"username", "kauan-pc"}, {"password", "kasumi-pw-123"}}
                       .dump(),
                   "application/json")
            ->status,
        200);
}

TEST(WebApiTest, WebListenerConfigAndTailscaleIpHostHandling) {
    auto workspace = kasumi::test::make_temp_workspace("kasumi-webui-listen-");
    app::ExecutionEnvironment env{.app_data_dir = workspace->root / "app"};

    // Fail-closed: refuse non-loopback bind before setting a Web UI password.
    app::WebListenerConfig bad{.bind = "0.0.0.0", .port = 3137};
    EXPECT_FALSE(app::write_web_listener_config(env, bad).has_value());

    ASSERT_TRUE(app::set_web_password(env, "tailscale-test-pw").has_value());
    app::WebListenerConfig lan{
        .bind = "0.0.0.0",
        .port = 0,
        .allowed_hosts = {"*.ts.net"},
        .skip_host_check = false,
    };
    ASSERT_TRUE(app::write_web_listener_config(env, lan).has_value());

    auto daemon = app::start_daemon_session(env);
    ASSERT_TRUE(daemon.has_value()) << daemon.error().detail;
    const auto st = app::query_daemon_session_status(*daemon);
    ASSERT_TRUE(st.has_value());
    const int port = st->web_port;
    const std::string port_str = std::to_string(port);

    httplib::Client client("127.0.0.1", port);
    // Tailscale CGNAT / LAN IP literal Host header is accepted on 0.0.0.0.
    EXPECT_EQ(client
                  .Get("/v1/auth/status",
                       httplib::Headers{{"Host", "100.64.0.12:" + port_str}})
                  ->status,
              200);
    // Wildcard domain entry matches cleanly.
    EXPECT_EQ(
        client
            .Get("/v1/auth/status",
                 httplib::Headers{{"Host", "srv.tailnet.ts.net:" + port_str}})
            ->status,
        200);
    // Arbitrary DNS rebinding domains remain blocked when
    // skip_host_check=false.
    EXPECT_EQ(client
                  .Get("/v1/auth/status",
                       httplib::Headers{{"Host", "evil.invalid:" + port_str}})
                  ->status,
              403);
    EXPECT_EQ(client
                  .Get("/v1/auth/status",
                       httplib::Headers{
                           {"Host", "evil.ts.net.attacker.com:" + port_str}})
                  ->status,
              403);

    // Authenticated PATCH /v1/web/config updates web.json cleanly.
    const std::string origin = "http://127.0.0.1:" + port_str;
    const auto logged = client.Post(
        "/v1/auth/login",
        httplib::Headers{{"Host", "127.0.0.1:" + port_str}, {"Origin", origin}},
        Json{{"username", "admin"}, {"password", "tailscale-test-pw"}}.dump(),
        "application/json");
    ASSERT_TRUE(logged);
    ASSERT_EQ(logged->status, 200);
    const auto cookie = logged->get_header_value("Set-Cookie");
    httplib::Headers auth{
        {"Host", "127.0.0.1:" + port_str},
        {"Origin", origin},
        {"Cookie", cookie.substr(0, cookie.find(';'))},
        {"X-CSRF-Token",
         Json::parse(logged->body).at("csrf_token").get<std::string>()},
    };
    const auto get_cfg = client.Get("/v1/web/config", auth);
    ASSERT_TRUE(get_cfg);
    ASSERT_EQ(get_cfg->status, 200);
    EXPECT_EQ(Json::parse(get_cfg->body).at("bind"), "0.0.0.0");

    const auto patch_cfg = client.Patch(
        "/v1/web/config",
        auth,
        Json{{"bind", "0.0.0.0"}, {"port", 3137}, {"skip_host_check", true}}
            .dump(),
        "application/json");
    ASSERT_TRUE(patch_cfg);
    ASSERT_EQ(patch_cfg->status, 200);
    EXPECT_TRUE(
        Json::parse(patch_cfg->body).at("restart_required").get<bool>());
    const auto persisted = app::read_web_listener_config(env);
    ASSERT_TRUE(persisted.has_value());
    EXPECT_EQ(persisted->port, 3137);
    EXPECT_TRUE(persisted->skip_host_check);
}

TEST(WebApiTest, CustomUsernameAndEightDigitsCanBeSetAndRotated) {
    auto api = start_api();
    const auto port = app::query_daemon_session_status(api.daemon)->ipc_port;
    const auto bootstrap =
        kasumi::test::read_text(api.env.app_data_dir / "web-bootstrap.token");
    const std::string username = "Minha Conta ✓";
    post(api,
         "/v1/auth/password",
         {{"bootstrap_token", bootstrap},
          {"username", username},
          {"password", "1234567"}},
         400);
    post(api,
         "/v1/auth/password",
         {{"bootstrap_token", bootstrap},
          {"username", username},
          {"password", "12345678"}});
    httplib::Headers headers{
        {"Origin", "http://127.0.0.1:" + std::to_string(port)}};
    const auto login = [&](std::string_view user, std::string_view password) {
        return api.client->Post(
            "/v1/auth/login",
            headers,
            Json{{"username", user}, {"password", password}}.dump(),
            "application/json");
    };
    const auto logged_in = login(username, "12345678");
    auto session = response(logged_in, 200);
    ASSERT_TRUE(logged_in && session.is_object());
    auto cookie = logged_in->get_header_value("Set-Cookie");
    auto authenticated = headers;
    authenticated.emplace("Cookie", cookie.substr(0, cookie.find(';')));
    authenticated.emplace("X-CSRF-Token",
                          session.at("csrf_token").get<std::string>());
    auto info =
        response(api.client->Get("/v1/auth/status", authenticated), 200);
    EXPECT_EQ(info.at("username"), username);
    const std::string renamed = "Segunda Conta";
    response(api.client->Post("/v1/auth/password",
                              authenticated,
                              Json{{"username", renamed},
                                   {"current_password", "12345678"},
                                   {"password", "87654321"}}
                                  .dump(),
                              "application/json"),
             200);
    response(login(renamed, "87654321"), 200);
    response(login("admin", "87654321"), 401);
    app::stop_daemon_session(api.daemon);
    ASSERT_TRUE(app::set_web_password(api.env, "78901234"));
    auto saved = Json::parse(
        kasumi::test::read_text(api.env.app_data_dir / "web-password.json"));
    EXPECT_EQ(saved.at("username"), renamed);
}

TEST(WebApiTest, ExplorerUsesProfileRcloneConfigAndKeepsRemoteSessionWarm) {
    if (!app::discover_rclone_remotes().available)
        GTEST_SKIP() << "rclone unavailable";
    auto api = start_api();
    auto local = create(api);
    auto config = api.workspace->root / "rclone.conf";
    kasumi::test::write_text(config,
                             "[kasumi-web-test]\ntype = alias\nremote = " +
                                 kasumi::platform::path::to_logical_utf8(
                                     api.workspace->root / "remote") +
                                 "\n");
    Json patch{{"remote_dir", "kasumi-web-test:vault"},
               {"rclone_config", kasumi::platform::path::to_utf8(config)}};
    response(
        api.client->Patch(
            "/v1/profiles/demo", api.headers, patch.dump(), "application/json"),
        200);
    kasumi::test::write_text(local / "note.txt", "rclone content");
    sync(api);
    auto heads = get(api, "/v1/remote/demo/heads");
    ASSERT_EQ(heads.at("heads").size(), 1U);
    EXPECT_EQ(
        get(api, "/v1/profiles/demo").at("daemon").at("warm_transport_active"),
        true);
    auto data =
        api.client->Get("/v1/remote/demo/download?path=note.txt", api.headers);
    ASSERT_TRUE(data);
    EXPECT_EQ(data->body, "rclone content");
}

TEST(WebApiTest, BrowserUnlocksMemoryProfileAndInspectsEncryptedHistory) {
    auto api = start_api();
    auto local = create(api);
    kasumi::test::write_text(local / "note.txt", "private history");
    kasumi::test::write_text(local / "Report.PDF", "%PDF-sample");
    kasumi::test::write_text(local / ".kasumiignore", "obj/\n");
    kasumi::test::write_text(local / "obj" / "hidden.txt", "ignored");
    sync(api);
    post(api, "/v1/profiles/demo/storage", {{"key_storage", "memory"}});
    auto bootstrap =
        kasumi::test::read_text(api.env.app_data_dir / "web-bootstrap.token");
    post(api,
         "/v1/auth/password",
         {{"bootstrap_token", bootstrap}, {"password", "browser memory test"}});
    const auto port = app::query_daemon_session_status(api.daemon)->ipc_port;
    api.headers = httplib::Headers{
        {"Origin", "http://127.0.0.1:" + std::to_string(port)}};
    auto login = api.client->Post(
        "/v1/auth/login",
        api.headers,
        R"({"username":"admin","password":"browser memory test"})",
        "application/json");
    ASSERT_TRUE(login);
    ASSERT_EQ(login->status, 200);
    const auto cookie = login->get_header_value("Set-Cookie");
    api.headers.emplace("Cookie", cookie.substr(0, cookie.find(';')));
    api.headers.emplace(
        "X-CSRF-Token",
        Json::parse(login->body).at("csrf_token").get<std::string>());
    post(api, "/v1/lock", {{"profile", "demo"}});
    get(api, "/v1/remote/demo/heads", 403);
    kasumi::test::write_text(local / "unmapped.txt", "created after sync");
    kasumi::test::write_text(local / "note.txt", "changed on disk after sync");
    const auto local_map = get(api, "/v1/local/demo/tree");
    ASSERT_TRUE(local_map.contains("commit_id"));
    ASSERT_TRUE(local_map.contains("created_at"));
    const auto local_tree = local_map.at("entries");
    EXPECT_EQ(local_tree.size(), 3U);
    EXPECT_TRUE(std::ranges::any_of(local_tree, [](const auto& row) {
        return row.at("path") == ".kasumiignore";
    }));
    get(api, "/v1/local/demo/download?path=obj/hidden.txt", 404);
    get(api, "/v1/local/demo/download?path=unmapped.txt", 404);
    EXPECT_TRUE(std::ranges::any_of(local_tree, [](const auto& row) {
        return row.at("path") == "note.txt" && row.at("size") == 15;
    }));
    const auto changed =
        api.client->Get("/v1/local/demo/download?path=note.txt", api.headers);
    ASSERT_TRUE(changed);
    EXPECT_EQ(changed->body, "changed on disk after sync");
    auto range = api.headers;
    range.emplace("Range", "bytes=0-3");
    auto pdf =
        api.client->Get("/v1/local/demo/download?path=Report.PDF", range);
    ASSERT_TRUE(pdf);
    EXPECT_EQ(pdf->status, 206);
    EXPECT_EQ(pdf->body, "%PDF");
    EXPECT_EQ(pdf->get_header_value("Content-Type"), "application/pdf");
    EXPECT_EQ(pdf->get_header_value("Content-Disposition"), "inline");
    EXPECT_EQ(pdf->get_header_value("Content-Range"), "bytes 0-3/11");
    auto unlocked =
        post(api,
             "/v1/unlock",
             {{"profile", "demo"}, {"master_key", std::string(64, '7')}});
    EXPECT_EQ(unlocked.at("unlocked"), true);
    EXPECT_EQ(get(api, "/v1/remote/demo/heads").at("heads").size(), 1U);
    post(api, "/v1/lock", {{"profile", "demo"}});
    get(api, "/v1/remote/demo/heads", 403);
}

TEST(WebApiTest, ConcurrentLoginsShareTheSameIpBackoff) {
    auto api = start_api();
    const auto bootstrap =
        kasumi::test::read_text(api.env.app_data_dir / "web-bootstrap.token");
    post(api,
         "/v1/auth/password",
         {{"bootstrap_token", bootstrap},
          {"password", "login concurrency test"}});
    const auto port = app::query_daemon_session_status(api.daemon)->web_port;
    const httplib::Headers browser{
        {"Origin", "http://127.0.0.1:" + std::to_string(port)}};
    std::barrier begin(3);
    const auto attempt = [&] {
        httplib::Client client("127.0.0.1", port);
        begin.arrive_and_wait();
        const auto result = client.Post(
            "/v1/auth/login",
            browser,
            R"({"username":"admin","password":"invalid login attempt"})",
            "application/json");
        return result ? result->status : 0;
    };
    auto first = std::async(std::launch::async, attempt);
    auto second = std::async(std::launch::async, attempt);
    begin.arrive_and_wait();
    EXPECT_TRUE(get(api, "/v1/auth/status").at("configured").get<bool>());
    auto results = std::array{first.get(), second.get()};
    std::ranges::sort(results);
    EXPECT_EQ(results, (std::array{401, 429}));
}

TEST(WebApiTest, SessionExpiresAtEitherDeadline) {
    namespace web = app::daemon_detail;
    web::WebAuth auth;
    const auto now = web::WebClock::now();
    auth.sessions.emplace(
        "idle", web::WebSession{.expires = now + 1h, .idle = now - 1s});
    auth.sessions.emplace(
        "absolute", web::WebSession{.expires = now - 1s, .idle = now + 1h});
    EXPECT_FALSE(web::web_session_active(auth, "idle"));
    EXPECT_FALSE(web::web_session_active(auth, "absolute"));
    EXPECT_TRUE(auth.sessions.empty());
}

TEST(WebApiTest, StreamsStatusAndFilteredLogHistory) {
    auto api = start_api();
    auto logs = get(api, "/v1/logs?lines=2&full=false");
    ASSERT_FALSE(logs.at("events").empty());
    EXPECT_FALSE(logs.at("events").back().contains("detail"));
    EXPECT_TRUE(get(api, "/v1/logs?profile=absent").at("events").empty());
    std::string frame;
    (void)api.client->Get(
        "/v1/events/stream", api.headers, [&](const char* data, std::size_t n) {
            frame.append(data, n);
            return frame.find("event: status") == std::string::npos;
        });
    EXPECT_NE(frame.find("event: log"), std::string::npos);
    EXPECT_NE(frame.find("event: status"), std::string::npos);
    EXPECT_NE(frame.find("\"jobs\""), std::string::npos);
}

TEST(WebApiTest, ServesStaticWebUiAndBlocksPathTricksOnApiRoutes) {
    auto workspace = kasumi::test::make_temp_workspace("kasumi-webui-static-");
    app::ExecutionEnvironment env{.app_data_dir = workspace->root / "app"};
    kasumi::test::write_text(env.app_data_dir / "web.json", R"({"port":0})");

    // Verify set_web_password rejects short/oversized secrets and writes
    // verifier.
    const auto too_short = app::set_web_password(env, "short");
    ASSERT_FALSE(too_short.has_value());
    const std::string valid_pw = "kasumi-webui-cli-password-123";
    ASSERT_TRUE(app::set_web_password(env, valid_pw).has_value());
    EXPECT_TRUE(
        std::filesystem::exists(env.app_data_dir / "web-password.json"));
    EXPECT_FALSE(
        std::filesystem::exists(env.app_data_dir / "web-bootstrap.token"));

    auto daemon = app::start_daemon_session(env);
    ASSERT_TRUE(daemon.has_value()) << daemon.error().detail;
    const auto port = app::query_daemon_session_status(*daemon)->web_port;
    httplib::Client client("127.0.0.1", port);

    // DNS rebinding guard must apply to static routes as well as /v1/*.
    auto bad_host = client.Get("/", httplib::Headers{{"Host", "evil.invalid"}});
    ASSERT_TRUE(bad_host);
    EXPECT_EQ(bad_host->status, 403);

    // Malformed / traversal paths must never bypass /v1/* authentication.
    EXPECT_EQ(client.Get("//v1/status")->status, 403);
    EXPECT_EQ(client.Get("/v1/../v1/status")->status, 403);
    EXPECT_EQ(client.Get("/v1/status")->status, 403);

    // Public GET on '/' serves either embedded SPA HTML (200) or 503 if
    // unbundled.
    auto root = client.Get("/");
    ASSERT_TRUE(root);
    EXPECT_TRUE(root->status == 200 || root->status == 503);
    if (root->status == 200) {
        EXPECT_NE(root->body.find("<!doctype html>"), std::string::npos);
        auto spa = client.Get("/explorer/work");
        ASSERT_TRUE(spa);
        EXPECT_EQ(spa->status, 200);
        EXPECT_NE(spa->body.find("<!doctype html>"), std::string::npos);
        auto missing_asset = client.Get("/assets/does-not-exist.js");
        ASSERT_TRUE(missing_asset);
        EXPECT_EQ(missing_asset->status, 404);
        auto missing_icon = client.Get("/favicon.ico");
        ASSERT_TRUE(missing_icon);
        EXPECT_EQ(missing_icon->status, 404);
    }

    // Password configured via set_web_password must work for browser login.
    const std::string origin = "http://127.0.0.1:" + std::to_string(port);
    auto logged =
        client.Post("/v1/auth/login",
                    httplib::Headers{{"Origin", origin}},
                    Json{{"username", "admin"}, {"password", valid_pw}}.dump(),
                    "application/json");
    ASSERT_TRUE(logged);
    EXPECT_EQ(logged->status, 200);
}

TEST(WebApiTest, ProfilesListReportsCoherentStateAndActivityAcrossLock) {
    auto api = start_api();
    auto local = create(api);
    kasumi::test::write_text(local / "item.txt", "hello");
    sync(api);

    const auto list = get(api, "/v1/profiles");
    ASSERT_EQ(list.at("profiles").size(), 1U);
    const auto& prof = list.at("profiles").at(0);
    EXPECT_EQ(prof.at("state"), "ready");
    EXPECT_EQ(prof.at("problem"), "none");
    EXPECT_TRUE(prof.at("activity").at("database_present").get<bool>());
    EXPECT_FALSE(prof.at("activity").at("accepted_commit").is_null());

    auto held = kasumi::platform::acquire_profile_lock(api.env.app_data_dir /
                                                       "profile-demo.lock");
    ASSERT_TRUE(held);
    const auto locked_list = get(api, "/v1/profiles");
    EXPECT_EQ(locked_list.at("profiles").at(0).at("state"), "running");
    EXPECT_EQ(locked_list.at("profiles").at(0).at("problem"), "none");
    kasumi::platform::release_profile_lock(*held);
}

TEST(WebApiTest,
     DiffSingleFileAndMultiWindowStreamingPreserveIntegrityAndRoutes) {
    auto api = start_api();
    auto local = create(api);
    kasumi::test::write_text(local / "note.txt", "line-one\nline-two\n");
    std::string large_body(10U * 1024U * 1024U, 'Z');
    large_body.replace(0, 5, "START");
    large_body.replace(large_body.size() - 3, 3, "END");
    kasumi::test::write_text(local / "blob.bin", large_body);
    sync(api);

    const auto c1 = get(api, "/v1/remote/demo/commits")
                        .at("commits")
                        .at(0)
                        .at("commit_id")
                        .get<std::string>();

    kasumi::test::write_text(local / "note.txt", "line-one\nline-updated\n");
    sync(api);
    const auto c2 = get(api, "/v1/remote/demo/commits")
                        .at("commits")
                        .at(0)
                        .at("commit_id")
                        .get<std::string>();

    const auto file_diff =
        get(api,
            "/v1/remote/demo/diff?from=" + c1 + "&to=" + c2 + "&path=note.txt");
    EXPECT_EQ(file_diff.at("from").at("text"), "line-one\nline-two\n");
    EXPECT_EQ(file_diff.at("to").at("text"), "line-one\nline-updated\n");

    const auto missing_in_both = get(api,
                                     "/v1/remote/demo/diff?from=" + c1 +
                                         "&to=" + c2 + "&path=absent.txt");
    EXPECT_TRUE(missing_in_both.at("from").is_null());
    EXPECT_TRUE(missing_in_both.at("to").is_null());

    auto bad_commit =
        api.client->Get(("/v1/remote/demo/diff?from=" + std::string(64, '0') +
                         "&to=" + c2 + "&path=note.txt")
                            .c_str(),
                        api.headers);
    ASSERT_TRUE(bad_commit);
    EXPECT_EQ(bad_commit->status, 404);

    auto streamed =
        api.client->Get("/v1/remote/demo/download?path=blob.bin", api.headers);
    ASSERT_TRUE(streamed);
    EXPECT_EQ(streamed->status, 200);
    EXPECT_EQ(streamed->body, large_body);
}

TEST(WebApiTest, StatusReportsExternalBusyAndSseStaysQuietWhenIdle) {
    auto api = start_api();
    create(api);

    const auto baseline = get(api, "/v1/status");
    ASSERT_TRUE(baseline.contains("daemon_instance"));
    EXPECT_FALSE(baseline.at("daemon_instance").get<std::string>().empty());
    ASSERT_TRUE(baseline.contains("machine_name"));
    EXPECT_FALSE(baseline.at("machine_name").get<std::string>().empty());
    ASSERT_EQ(baseline.at("profiles").size(), 1U);
    EXPECT_FALSE(baseline.at("profiles").at(0).at("busy").get<bool>());
    EXPECT_EQ(baseline.at("profiles").at(0).at("active_operation"), "");

    auto patched = api.client->Patch("/v1/profiles/demo",
                                     api.headers,
                                     Json{{"icon", "preset:docs"}}.dump(),
                                     "application/json");
    ASSERT_TRUE(patched);
    EXPECT_EQ(patched->status, 200);
    const auto after_patch = get(api, "/v1/status");
    EXPECT_FALSE(after_patch.at("profiles").at(0).at("busy").get<bool>());
    EXPECT_EQ(after_patch.at("profiles").at(0).at("active_operation"), "");

    auto held = kasumi::platform::acquire_profile_lock(api.env.app_data_dir /
                                                       "profile-demo.lock");
    ASSERT_TRUE(held);

    const auto busy_status = get(api, "/v1/status");
    EXPECT_TRUE(busy_status.at("profiles").at(0).at("busy").get<bool>());
    EXPECT_EQ(busy_status.at("profiles").at(0).at("active_operation"),
              "external");

    auto conflict =
        api.client->Patch("/v1/profiles/demo",
                          api.headers,
                          Json{{"sync_interval_seconds", 120}}.dump(),
                          "application/json");
    ASSERT_TRUE(conflict);
    EXPECT_EQ(conflict->status, 409);
    const auto err_json = Json::parse(conflict->body);
    EXPECT_FALSE(err_json.at("error").get<std::string>().empty());
    EXPECT_EQ(err_json.at("code"), "lock_busy");
    EXPECT_EQ(err_json.at("active_operation"), "external");

    kasumi::platform::release_profile_lock(*held);
    const auto free_status = get(api, "/v1/status");
    EXPECT_FALSE(free_status.at("profiles").at(0).at("busy").get<bool>());
}

TEST(WebApiTest, SseTracksExternalCliLockAcquireAndReleaseLive) {
    auto api = start_api();
    create(api);
    const auto port = app::query_daemon_session_status(api.daemon)->ipc_port;

    std::mutex mu;
    std::condition_variable cv;
    std::deque<Json> status_frames;
    std::atomic_bool stop_stream{false};

    std::thread reader([&] {
        httplib::Client stream_client("127.0.0.1", port);
        stream_client.set_read_timeout(8, 0);
        std::string buffer;
        (void)stream_client.Get(
            "/v1/events/stream",
            api.headers,
            [&](const char* data, std::size_t n) {
                buffer.append(data, n);
                for (;;) {
                    const auto sep = buffer.find("\n\n");
                    if (sep == std::string::npos)
                        break;
                    const std::string block = buffer.substr(0, sep);
                    buffer.erase(0, sep + 2);
                    if (block.find("event: status") == std::string::npos)
                        continue;
                    const auto data_pos = block.find("data: ");
                    if (data_pos == std::string::npos)
                        continue;
                    const auto line_end = block.find('\n', data_pos);
                    const auto json_str =
                        block.substr(data_pos + 6,
                                     line_end == std::string::npos
                                         ? std::string::npos
                                         : line_end - (data_pos + 6));
                    auto parsed = Json::parse(json_str, nullptr, false);
                    if (!parsed.is_discarded()) {
                        std::lock_guard lock(mu);
                        status_frames.push_back(std::move(parsed));
                        cv.notify_all();
                    }
                }
                return !stop_stream.load();
            });
    });

    const auto wait_for_profile_state = [&](bool expected_busy,
                                            std::string_view expected_op) {
        std::unique_lock lock(mu);
        return cv.wait_for(lock, 5s, [&] {
            while (!status_frames.empty()) {
                const auto frame = std::move(status_frames.front());
                status_frames.pop_front();
                if (!frame.contains("profiles"))
                    continue;
                for (const auto& p : frame.at("profiles")) {
                    if (p.at("name") == "demo" &&
                        p.at("busy").get<bool>() == expected_busy &&
                        p.at("active_operation").get<std::string>() ==
                            expected_op) {
                        return true;
                    }
                }
            }
            return false;
        });
    };

    ASSERT_TRUE(wait_for_profile_state(false, ""));

    auto held = kasumi::platform::acquire_profile_lock(api.env.app_data_dir /
                                                       "profile-demo.lock");
    ASSERT_TRUE(held);
    ASSERT_TRUE(wait_for_profile_state(true, "external"));

    kasumi::platform::release_profile_lock(*held);
    ASSERT_TRUE(wait_for_profile_state(false, ""));

    stop_stream.store(true);
    app::stop_daemon_session(api.daemon);
    if (reader.joinable())
        reader.join();
}

TEST(WebApiTest, ProfileIconValidationAndSafeFolderIconDetection) {
    auto api = start_api();
    auto local = create(api);

    // Invalid icon rejected with 400.
    auto bad_icon =
        api.client->Patch("/v1/profiles/demo",
                          api.headers,
                          Json{{"icon", "javascript:alert(1)"}}.dump(),
                          "application/json");
    ASSERT_TRUE(bad_icon);
    EXPECT_EQ(bad_icon->status, 400);

    // Valid preset & auto persisted and returned.
    auto ok_preset = api.client->Patch("/v1/profiles/demo",
                                       api.headers,
                                       Json{{"icon", "preset:code"}}.dump(),
                                       "application/json");
    ASSERT_TRUE(ok_preset);
    EXPECT_EQ(ok_preset->status, 200);
    EXPECT_EQ(Json::parse(ok_preset->body).at("icon"), "preset:code");

    auto ok_auto = api.client->Patch("/v1/profiles/demo",
                                     api.headers,
                                     Json{{"icon", "auto"}}.dump(),
                                     "application/json");
    ASSERT_TRUE(ok_auto);
    EXPECT_EQ(ok_auto->status, 200);

    // Absent desktop.ini / .directory -> 204.
    auto empty_icon = api.client->Get("/v1/profiles/demo/icon", api.headers);
    ASSERT_TRUE(empty_icon);
    EXPECT_EQ(empty_icon->status, 204);

    // UTF-16LE desktop.ini pointing to local PNG serves image/png with nosniff.
    const std::string fake_png = "\x89PNG\r\n\x1a\nTESTPNG";
    kasumi::test::write_text(local / ".assets" / "folder.png", fake_png);
    const std::string ini_ascii =
        "[.ShellClassInfo]\r\nIconResource=.\\.assets\\folder.png,0\r\n";
    std::string ini_utf16;
    ini_utf16.push_back(static_cast<char>(0xFF));
    ini_utf16.push_back(static_cast<char>(0xFE));
    for (const char raw_ch : ini_ascii) {
        const auto ch = static_cast<unsigned char>(raw_ch);
        ini_utf16.push_back(static_cast<char>(ch));
        ini_utf16.push_back('\0');
    }
    kasumi::test::write_text(local / "desktop.ini", ini_utf16);
    auto served = api.client->Get("/v1/profiles/demo/icon", api.headers);
    ASSERT_TRUE(served);
    EXPECT_EQ(served->status, 200);
    EXPECT_EQ(served->get_header_value("Content-Type"), "image/png");
    EXPECT_EQ(served->get_header_value("X-Content-Type-Options"), "nosniff");
    EXPECT_EQ(served->get_header_value("Content-Security-Policy"),
              "sandbox; default-src 'none'");
    EXPECT_EQ(served->body, fake_png);

    // UNC and HTML-disguised relative icons fail closed to 204.
    kasumi::test::write_text(
        local / "desktop.ini",
        "[.ShellClassInfo]\nIconResource=\\\\127.0.0.1\\share\\evil.ico,0\n");
    auto unc = api.client->Get("/v1/profiles/demo/icon", api.headers);
    ASSERT_TRUE(unc);
    EXPECT_EQ(unc->status, 204);

    kasumi::test::write_text(local / "fake.png",
                             "<html><script>alert(1)</script></html>");
    kasumi::test::write_text(local / "desktop.ini",
                             "[.ShellClassInfo]\nIconResource=fake.png,0\n");
    auto spoofed = api.client->Get("/v1/profiles/demo/icon", api.headers);
    ASSERT_TRUE(spoofed);
    EXPECT_EQ(spoofed->status, 204);

    // Traversal and unsafe SVG (<script> / onload) fail closed to 204.
    std::filesystem::remove(local / "desktop.ini");
    kasumi::test::write_text(local.parent_path() / "escape.png", fake_png);
    kasumi::test::write_text(
        local / "desktop.ini",
        "[.ShellClassInfo]\nIconResource=../escape.png,0\n");
    auto escaped = api.client->Get("/v1/profiles/demo/icon", api.headers);
    ASSERT_TRUE(escaped);
    EXPECT_EQ(escaped->status, 204);

    kasumi::test::write_text(local / "bad.svg",
                             "<svg><script>alert(1)</script></svg>");
    std::filesystem::remove(local / "desktop.ini");
    kasumi::test::write_text(local / ".directory",
                             "[Desktop Entry]\nIcon=bad.svg\n");
    auto evil_script_svg =
        api.client->Get("/v1/profiles/demo/icon", api.headers);
    ASSERT_TRUE(evil_script_svg);
    EXPECT_EQ(evil_script_svg->status, 204);

    kasumi::test::write_text(local / "onload.svg",
                             "<svg onload=\"alert(1)\"></svg>");
    kasumi::test::write_text(local / ".directory",
                             "[Desktop Entry]\nIcon=onload.svg\n");
    auto evil_onload_svg =
        api.client->Get("/v1/profiles/demo/icon", api.headers);
    ASSERT_TRUE(evil_onload_svg);
    EXPECT_EQ(evil_onload_svg->status, 204);

    // Valid safe SVG in .directory serves image/svg+xml cleanly.
    const std::string valid_svg =
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 16 16\">"
        "<rect width=\"16\" height=\"16\" fill=\"#6b54c8\"/></svg>";
    kasumi::test::write_text(local / "safe.svg", valid_svg);
    kasumi::test::write_text(local / ".directory",
                             "[Desktop Entry]\nIcon=./safe.svg\n");
    auto served_svg = api.client->Get("/v1/profiles/demo/icon", api.headers);
    ASSERT_TRUE(served_svg);
    EXPECT_EQ(served_svg->status, 200);
    EXPECT_EQ(served_svg->get_header_value("Content-Type"), "image/svg+xml");
    EXPECT_EQ(served_svg->get_header_value("Content-Security-Policy"),
              "sandbox; default-src 'none'");
    EXPECT_EQ(served_svg->body, valid_svg);

    // Absolute path and file:// URI in .directory resolve safe external icons.
    const auto abs_icon = api.workspace->root / "external-folder.png";
    kasumi::test::write_text(abs_icon, fake_png);
    kasumi::test::write_text(
        local / ".directory",
        "[Desktop Entry]\nIcon=" +
            kasumi::platform::path::to_logical_utf8(abs_icon) + "\n");
    auto abs_res = api.client->Get("/v1/profiles/demo/icon", api.headers);
    ASSERT_TRUE(abs_res);
    EXPECT_EQ(abs_res->status, 200);
    EXPECT_EQ(abs_res->get_header_value("Content-Type"), "image/png");
    EXPECT_EQ(abs_res->body, fake_png);

    auto uri_path = kasumi::platform::path::to_logical_utf8(abs_icon);
    if (!uri_path.starts_with('/'))
        uri_path.insert(uri_path.begin(), '/');
    kasumi::test::write_text(local / ".directory",
                             "[Desktop Entry]\nIcon=file://" + uri_path + "\n");
    auto uri_res = api.client->Get("/v1/profiles/demo/icon", api.headers);
    ASSERT_TRUE(uri_res);
    EXPECT_EQ(uri_res->status, 200);
    EXPECT_EQ(uri_res->body, fake_png);

    // Freedesktop theme name resolves under KASUMI_ICON_DIRS and falls back
    // even when an unresolvable desktop.ini is also present.
    const auto theme_root = api.workspace->root / "icons";
    kasumi::test::write_text(theme_root / "breeze" / "places" / "64" /
                                 "folder-music.svg",
                             valid_svg);
    auto icon_dirs_env = kasumi::test::scoped_environment_variable(
        "KASUMI_ICON_DIRS", kasumi::platform::path::to_utf8(theme_root));
    auto icon_theme_env = kasumi::test::scoped_environment_variable(
        "KASUMI_ICON_THEME", "breeze");
    kasumi::test::write_text(
        local / "desktop.ini",
        "[.ShellClassInfo]\nIconResource=missing-only-on-other-os.ico,0\n");
    kasumi::test::write_text(local / ".directory",
                             "[Desktop Entry]\nIcon=folder-music\n");
    auto theme_res = api.client->Get("/v1/profiles/demo/icon", api.headers);
    ASSERT_TRUE(theme_res);
    EXPECT_EQ(theme_res->status, 200);
    EXPECT_EQ(theme_res->get_header_value("Content-Type"), "image/svg+xml");
    EXPECT_EQ(theme_res->get_header_value("Cache-Control"),
              "private, no-cache");
    EXPECT_EQ(theme_res->body, valid_svg);

    // Preview mode=auto returns the folder's .directory icon even while
    // preset:code is saved.
    ASSERT_EQ(api.client
                  ->Patch("/v1/profiles/demo",
                          api.headers,
                          Json{{"icon", "preset:code"}}.dump(),
                          "application/json")
                  ->status,
              200);
    auto preview_auto =
        api.client->Get("/v1/profiles/demo/icon?mode=auto", api.headers);
    ASSERT_TRUE(preview_auto);
    EXPECT_EQ(preview_auto->status, 200);
    EXPECT_EQ(preview_auto->body, valid_svg);
    EXPECT_EQ(api.client
                  ->Patch("/v1/profiles/demo",
                          api.headers,
                          Json{{"icon", "auto"}}.dump(),
                          "application/json")
                  ->status,
              200);

    std::filesystem::remove(local / "desktop.ini");
    kasumi::test::write_text(local / "badge.ico",
                             std::string("\x00\x00\x01\x00ICO-BYTES", 13));
    kasumi::test::write_text(local / ".directory",
                             "[Desktop Entry]\nIcon=./badge.ico\n");
    auto ico = api.client->Get("/v1/profiles/demo/icon", api.headers);
    ASSERT_TRUE(ico);
    EXPECT_EQ(ico->status, 200);
    EXPECT_EQ(ico->get_header_value("Content-Type"), "image/x-icon");
    EXPECT_EQ(ico->body, std::string("\x00\x00\x01\x00ICO-BYTES", 13));

#ifdef _WIN32
    // Windows %SystemRoot%\system32\imageres.dll resource extraction -> PNG.
    std::filesystem::remove(local / ".directory");
    kasumi::test::write_text(local / "desktop.ini",
                             "[.ShellClassInfo]\r\nIconResource=%SystemRoot%"
                             "\\system32\\imageres.dll,-112\r\n");
    auto win_ico = api.client->Get("/v1/profiles/demo/icon", api.headers);
    ASSERT_TRUE(win_ico);
    EXPECT_EQ(win_ico->status, 200);
    EXPECT_EQ(win_ico->get_header_value("Content-Type"), "image/png");
    EXPECT_TRUE(win_ico->body.starts_with("\x89PNG\r\n\x1a\n"));
#endif

    // Reject malicious SVG upload (400), accept safe SVG upload (200).
    auto bad_upload = api.client->Post(
        "/v1/profiles/demo/icon",
        api.headers,
        Json{
            {"data_base64", "PHN2Zz48c2NyaXB0PmFsZXJ0KDEpPC9zY3JpcHQ+PC9zdmc+"}}
            .dump(),
        "application/json");
    ASSERT_TRUE(bad_upload);
    EXPECT_EQ(bad_upload->status, 400);

    // Standard 1x1 valid PNG bytes Base64:
    const std::string png_b64 =
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+"
        "M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
    auto good_upload = api.client->Post("/v1/profiles/demo/icon",
                                        api.headers,
                                        Json{{"data_base64", png_b64}}.dump(),
                                        "application/json");
    ASSERT_TRUE(good_upload);
    EXPECT_EQ(good_upload->status, 200);
    const auto uploaded_icon =
        Json::parse(good_upload->body).at("icon").get<std::string>();
    EXPECT_TRUE(uploaded_icon.starts_with("custom:"));

    auto served_custom = api.client->Get(
        "/v1/profiles/demo/icon?v=" + uploaded_icon, api.headers);
    ASSERT_TRUE(served_custom);
    EXPECT_EQ(served_custom->status, 200);
    EXPECT_EQ(served_custom->get_header_value("Content-Type"), "image/png");
    EXPECT_EQ(served_custom->get_header_value("Content-Security-Policy"),
              "sandbox; default-src 'none'");
    EXPECT_TRUE(served_custom->body.starts_with("\x89PNG\r\n\x1a\n"));

    // Cloning preserves custom-icon.* files alongside icon metadata.
    auto cloned_resp = api.client->Post("/v1/profiles/demo/clone",
                                        api.headers,
                                        Json{{"name", "demo_clone"}}.dump(),
                                        "application/json");
    ASSERT_TRUE(cloned_resp);
    EXPECT_EQ(cloned_resp->status, 200);
    auto cloned_icon = api.client->Get(
        "/v1/profiles/demo_clone/icon?v=" + uploaded_icon, api.headers);
    ASSERT_TRUE(cloned_icon);
    EXPECT_EQ(cloned_icon->status, 200);
    EXPECT_EQ(cloned_icon->body, served_custom->body);

    auto deleted_custom = api.client->Delete(
        "/v1/profiles/demo/icon", api.headers, "{}", "application/json");
    ASSERT_TRUE(deleted_custom);
    EXPECT_EQ(deleted_custom->status, 200);
    EXPECT_EQ(Json::parse(deleted_custom->body).at("icon"), "");
}

TEST(WebApiTest, LocalThumbnailScalesRasterImagesAndRejectsUnsafePaths) {
    auto api = start_api();
    auto local = create(api);

    // 200x200 24-bit BMP image (valid uncompressed raster) + plain text file.
    constexpr std::uint32_t w = 200;
    constexpr std::uint32_t h = 200;
    constexpr std::uint32_t pixel_bytes = w * h * 3U;
    constexpr std::uint32_t total_size = 54U + pixel_bytes;
    std::string bmp(total_size, '\0');
    bmp[0] = 'B';
    bmp[1] = 'M';
    auto put_u32 = [&](std::size_t off, std::uint32_t v) {
        bmp[off] = static_cast<char>(v & 0xFFU);
        bmp[off + 1] = static_cast<char>((v >> 8) & 0xFFU);
        bmp[off + 2] = static_cast<char>((v >> 16) & 0xFFU);
        bmp[off + 3] = static_cast<char>((v >> 24) & 0xFFU);
    };
    put_u32(2, total_size);
    put_u32(10, 54);
    put_u32(14, 40);
    put_u32(18, w);
    put_u32(22, h);
    bmp[26] = 1;
    bmp[28] = 24;
    kasumi::test::write_text(local / "photo.bmp", bmp);
    kasumi::test::write_text(local / "note.txt", "plain text");
    sync(api);

    // Traversal rejected with 400; unmapped file rejected with 404; non-image
    // -> 204.
    auto bad = api.client->Get("/v1/local/demo/thumbnail?path=../secret.bmp",
                               api.headers);
    ASSERT_TRUE(bad);
    EXPECT_EQ(bad->status, 400);

    auto missing = api.client->Get("/v1/local/demo/thumbnail?path=missing.bmp",
                                   api.headers);
    ASSERT_TRUE(missing);
    EXPECT_EQ(missing->status, 404);

    auto txt =
        api.client->Get("/v1/local/demo/thumbnail?path=note.txt", api.headers);
    ASSERT_TRUE(txt);
    EXPECT_EQ(txt->status, 204);

#ifdef _WIN32
    auto thumb = api.client->Get(
        "/v1/local/demo/thumbnail?path=photo.bmp&size=160", api.headers);
    ASSERT_TRUE(thumb);
    EXPECT_EQ(thumb->status, 200);
    EXPECT_EQ(thumb->get_header_value("Content-Type"), "image/png");
    EXPECT_EQ(thumb->get_header_value("X-Content-Type-Options"), "nosniff");
    EXPECT_EQ(thumb->get_header_value("Content-Security-Policy"),
              "sandbox; default-src 'none'");
    ASSERT_GE(thumb->body.size(), 24U);
    EXPECT_TRUE(thumb->body.starts_with("\x89PNG\r\n\x1a\n"));
    const auto out_w = (static_cast<std::uint8_t>(thumb->body[16]) << 24) |
                       (static_cast<std::uint8_t>(thumb->body[17]) << 16) |
                       (static_cast<std::uint8_t>(thumb->body[18]) << 8) |
                       static_cast<std::uint8_t>(thumb->body[19]);
    const auto out_h = (static_cast<std::uint8_t>(thumb->body[20]) << 24) |
                       (static_cast<std::uint8_t>(thumb->body[21]) << 16) |
                       (static_cast<std::uint8_t>(thumb->body[22]) << 8) |
                       static_cast<std::uint8_t>(thumb->body[23]);
    EXPECT_EQ(out_w, 160U);
    EXPECT_EQ(out_h, 160U);

    // Large preview size uses JPEG encoding to stay compact.
    auto preview = api.client->Get(
        "/v1/local/demo/thumbnail?path=photo.bmp&size=1280", api.headers);
    ASSERT_TRUE(preview);
    EXPECT_EQ(preview->status, 200);
    EXPECT_EQ(preview->get_header_value("Content-Type"), "image/jpeg");
    ASSERT_GE(preview->body.size(), 3U);
    EXPECT_EQ(static_cast<unsigned char>(preview->body[0]), 0xFFU);
    EXPECT_EQ(static_cast<unsigned char>(preview->body[1]), 0xD8U);

    // Remote hash-matched thumbnail serves locally without remote fetch,
    // while mismatched hash fails cleanly to 204.
    const auto tree = get(api, "/v1/remote/demo/tree");
    std::string photo_hash;
    for (const auto& entry : tree.at("entries")) {
        if (entry.at("path") == "photo.bmp") {
            photo_hash = entry.at("logical_hash").get<std::string>();
            break;
        }
    }
    ASSERT_EQ(photo_hash.size(), 64U);
    auto remote_thumb = api.client->Get(
        "/v1/remote/demo/thumbnail?path=photo.bmp&hash=" + photo_hash +
            "&size=160",
        api.headers);
    ASSERT_TRUE(remote_thumb);
    EXPECT_EQ(remote_thumb->status, 200);
    EXPECT_EQ(remote_thumb->get_header_value("Content-Type"), "image/png");

    auto stale_hash =
        api.client->Get("/v1/remote/demo/thumbnail?path=photo.bmp&hash=" +
                            std::string(64, '0') + "&size=160",
                        api.headers);
    ASSERT_TRUE(stale_hash);
    EXPECT_EQ(stale_hash->status, 204);
#endif
}

TEST(WebApiTest, RemoteThumbnailFallsBackToVaultAndSavesClickedPreviewThumbnail) {
    auto api = start_api();
    auto local = create(api);

    auto make_bmp = [](std::uint32_t w, std::uint32_t h) {
        const std::uint32_t pixel_bytes = w * h * 3U;
        const std::uint32_t total_size = 54U + pixel_bytes;
        std::string bmp(total_size, '\0');
        bmp[0] = 'B';
        bmp[1] = 'M';
        auto put_u32 = [&](std::size_t off, std::uint32_t v) {
            bmp[off] = static_cast<char>(v & 0xFFU);
            bmp[off + 1] = static_cast<char>((v >> 8) & 0xFFU);
            bmp[off + 2] = static_cast<char>((v >> 16) & 0xFFU);
            bmp[off + 3] = static_cast<char>((v >> 24) & 0xFFU);
        };
        put_u32(2, total_size);
        put_u32(10, 54);
        put_u32(14, 40);
        put_u32(18, w);
        put_u32(22, h);
        bmp[26] = 1;
        bmp[28] = 24;
        return bmp;
    };

    kasumi::test::write_text(local / "keep.txt", "anchor");
    kasumi::test::write_text(local / "small.bmp", make_bmp(200, 200));
    // > 5 MiB (1400 * 1300 * 3 + 54 = 5,460,054 bytes): excluded from automatic
    // 160px grid fallback, included up to 32 MiB when previewed.
    kasumi::test::write_text(local / "large.bmp", make_bmp(1400, 1300));
    sync(api);

    const auto tree = get(api, "/v1/remote/demo/tree");
    const auto commit_v0 = tree.at("commit_id").get<std::string>();
    std::string small_hash;
    std::string large_hash;
    for (const auto& entry : tree.at("entries")) {
        const auto p = entry.at("path").get<std::string>();
        if (p == "small.bmp") {
            small_hash = entry.at("logical_hash").get<std::string>();
        } else if (p == "large.bmp") {
            large_hash = entry.at("logical_hash").get<std::string>();
        }
    }
    ASSERT_EQ(commit_v0.size(), 64U);
    ASSERT_EQ(small_hash.size(), 64U);
    ASSERT_EQ(large_hash.size(), 64U);

    // Delete both images locally so neither exists on disk.
    ASSERT_TRUE(std::filesystem::remove(local / "small.bmp"));
    ASSERT_TRUE(std::filesystem::remove(local / "large.bmp"));
    sync(api);

    auto local_gone = api.client->Get(
        "/v1/local/demo/thumbnail?path=small.bmp&size=160", api.headers);
    ASSERT_TRUE(local_gone);
    EXPECT_EQ(local_gone->status, 404);

#ifdef _WIN32
    // 1. Small remote-only image falls back to vault cleanly when commit is
    // provided.
    auto small_grid = api.client->Get(
        "/v1/remote/demo/thumbnail?path=small.bmp&hash=" + small_hash +
            "&commit=" + commit_v0 + "&size=160",
        api.headers);
    ASSERT_TRUE(small_grid);
    EXPECT_EQ(small_grid->status, 200);
    EXPECT_EQ(small_grid->get_header_value("Content-Type"), "image/png");
    EXPECT_EQ(small_grid->get_header_value("Content-Security-Policy"),
              "sandbox; default-src 'none'");

    // 2. Large (> 5 MiB) remote-only image skips automatic 160px grid fallback.
    auto large_grid_before = api.client->Get(
        "/v1/remote/demo/thumbnail?path=large.bmp&hash=" + large_hash +
            "&commit=" + commit_v0 + "&size=160",
        api.headers);
    ASSERT_TRUE(large_grid_before);
    EXPECT_EQ(large_grid_before->status, 204);

    // 3. Clicking to preview (size=1280) fetches up to 32 MiB and also saves
    // the 160px grid thumbnail into RemoteThumbnailCache.
    auto large_preview = api.client->Get(
        "/v1/remote/demo/thumbnail?path=large.bmp&hash=" + large_hash +
            "&commit=" + commit_v0 + "&size=1280",
        api.headers);
    ASSERT_TRUE(large_preview);
    EXPECT_EQ(large_preview->status, 200);
    EXPECT_EQ(large_preview->get_header_value("Content-Type"), "image/jpeg");

    // 4. Subsequent 160px grid request hits the saved cache even without commit.
    auto large_grid_after = api.client->Get(
        "/v1/remote/demo/thumbnail?path=large.bmp&hash=" + large_hash +
            "&size=160",
        api.headers);
    ASSERT_TRUE(large_grid_after);
    EXPECT_EQ(large_grid_after->status, 200);
    EXPECT_EQ(large_grid_after->get_header_value("Content-Type"), "image/png");
#endif
}

TEST(WebApiTest, RemoveWriterBatchRemovesMultipleAndReportsAlreadyAbsent) {
    auto api = start_api();
    create(api);
    const auto remote =
        kasumi::platform::path::to_utf8(api.workspace->root / "remote");
    auto storage = kasumi::transport::open_transport(remote);
    ASSERT_TRUE(storage);
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    const auto stage = api.workspace->root / "writer-batch-stage";
    ASSERT_TRUE(std::filesystem::create_directory(stage));
    kasumi::crypto::Key key{};
    key.fill(0x77);
    namespace hs = app::history_storage;
    namespace protocol = hs::maintenance_protocol;
    const auto layout = hs::derive_remote_layout(key);

    auto w1 = protocol::register_writer(*storage, layout, stage);
    auto w2 = protocol::register_writer(*storage, layout, stage);
    ASSERT_TRUE(w1 && w2);
    const std::string absent_id = layout.writers_prefix + std::string(32, 'e');
    const std::string route = "/v1/maintenance/demo/remove-writer";

    post(api, route, {{"writer_ids", Json::array()}}, 400);
    post(api, route, {{"writer_ids", {"not-valid"}}}, 400);

    const auto batch = job_result(
        api,
        route,
        {{"writer_ids", {w1->identifier, w2->identifier, absent_id}}});
    EXPECT_EQ(batch.at("removed_identifiers"),
              Json({w1->identifier, w2->identifier}));
    EXPECT_EQ(batch.at("already_absent_identifiers"), Json({absent_id}));
    EXPECT_EQ(kasumi::transport::presence(*storage, w1->identifier).value(),
              kasumi::transport::Presence::Absent);
    EXPECT_EQ(kasumi::transport::presence(*storage, w2->identifier).value(),
              kasumi::transport::Presence::Absent);
}

TEST(WebApiTest,
     FsckWorkerSpawnFailureFailsJobCleanlyAndDaemonServesNextRequest) {
    auto api = start_api();
    auto local = create(api);
    kasumi::test::write_text(local / "alpha.txt", "distinct-alpha-payload");
    kasumi::test::write_text(local / "beta.txt", "distinct-beta-payload");
    ASSERT_TRUE(job_result(api, "/v1/maintenance/demo/sync", Json::object())
                    .at("published")
                    .get<bool>());

    {
        std::atomic<bool> fail_once{true};
        app::testing::ScopedWorkerSpawnHook spawn_hook(
            [&](std::size_t worker_index) {
                if (worker_index == 1 && fail_once.exchange(false)) {
                    throw std::system_error(
                        std::make_error_code(
                            std::errc::resource_unavailable_try_again),
                        "injected worker spawn failure");
                }
            });

        const auto failed = job_result(
            api, "/v1/maintenance/demo/fsck", Json::object(), "failed");
        ASSERT_TRUE(failed.contains("error"));
        EXPECT_NE(failed.at("error").get<std::string>().find(
                      "injected worker spawn failure"),
                  std::string::npos);
    }

    const auto next_ok =
        job_result(api, "/v1/maintenance/demo/fsck", Json::object());
    EXPECT_GE(next_ok.at("checked_objects").get<std::size_t>(), 2U);
}

} // namespace
