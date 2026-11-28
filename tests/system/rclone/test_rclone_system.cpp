#include "application/daemon.hpp"
#include "application/execute.hpp"
#include "application/history_storage/content_reachability.hpp"
#include "application/history_storage/detail.hpp"
#include "application/history_storage/history_storage.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/publication.hpp"
#include "application/history_storage/reachability.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/observation/history.hpp"
#include "application/profile.hpp"
#include "application/sync/publication.hpp"
#include "core/hasher.hpp"
#include "core/history.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/scoped_environment.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/clock.hpp"
#include "platform/metadata.hpp"
#include "platform/path.hpp"
#include "platform/workspace.hpp"
#include "runtime/paths.hpp"
#include "runtime/resolver.hpp"
#include "state_storage/database.hpp"
#include "transport/detail.hpp"
#include "transport/rclone/detail.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <future>
#include <gtest/gtest.h>
#include <latch>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <reproc++/run.hpp>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#ifndef KASUMI_SYSTEM_RCLONE_EXECUTABLE
#define KASUMI_SYSTEM_RCLONE_EXECUTABLE "rclone"
#endif

#ifndef KASUMI_SYSTEM_KASUMI_EXECUTABLE
#define KASUMI_SYSTEM_KASUMI_EXECUTABLE "kasumi"
#endif

namespace {

using kasumi::application::Credentials;
using kasumi::application::ExecutionEnvironment;
using kasumi::application::MasterKeyHex;
using kasumi::application::NoCredentials;
using kasumi::application::Operation;
using kasumi::application::Profile;
using kasumi::application::Request;
using kasumi::application::history_storage::HeadReference;
using kasumi::application::history_storage::LoadedHistory;
using kasumi::application::history_storage::RemoteLayout;
constexpr std::string_view remote_name = "kasumi-test";
constexpr std::string_view remote_root = "storage";
constexpr std::string_view remote_backend = "r";
constexpr std::string_view profile_name = "demo";

std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> test_key() {
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    key.fill(0x22U);
    return key;
}

RemoteLayout test_layout() {
    return kasumi::application::history_storage::derive_remote_layout(
        test_key());
}

kasumi::Snapshot tree_with(std::string_view path,
                           std::string_view contents,
                           kasumi::TimestampNs mtime = 0) {
    kasumi::Snapshot tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true},
                 kasumi::NodeRow{.path = std::string{path},
                                 .hash = kasumi::hasher::hash_string(contents),
                                 .size = contents.size(),
                                 .mtime = mtime,
                                 .is_directory = false}}};
    kasumi::finalize_snapshot(tree);
    return tree;
}

kasumi::history::CommitResult make_commit(std::uint64_t height,
                                          std::vector<std::string> parents,
                                          std::string_view path,
                                          std::string_view contents,
                                          kasumi::TimestampNs mtime = 0) {
    return kasumi::history::make_commit(height,
                                        std::move(parents),
                                        tree_with(path, contents, mtime),
                                        2'000'000'000LL);
}

struct CurrentDirectoryData {
    std::filesystem::path previous;
};

void restore_current_directory(CurrentDirectoryData* directory) noexcept {
    if (directory != nullptr) {
        std::error_code ignored;
        std::filesystem::current_path(directory->previous, ignored);
        delete directory;
    }
}

using CurrentDirectory =
    std::unique_ptr<CurrentDirectoryData, void (*)(CurrentDirectoryData*)>;

CurrentDirectory use_current_directory(const std::filesystem::path& path) {
    auto directory = CurrentDirectory{
        new CurrentDirectoryData{.previous = std::filesystem::current_path()},
        restore_current_directory};
    std::filesystem::current_path(path);
    return directory;
}

struct TestClient {
    ExecutionEnvironment environment;
    std::filesystem::path local_dir;
};

void create_system_directory(const std::filesystem::path& path) {
    std::error_code error;
    if (std::filesystem::create_directories(path, error) || !error) {
        return;
    }
    throw std::runtime_error("could not create system test directory: " +
                             kasumi::platform::path::to_utf8(path) + ": " +
                             error.message());
}

std::expected<void, kasumi::application::Error>
sync_client(const TestClient& client) {
    return kasumi::application::execute(
               {Request{Operation::Sync, std::string{profile_name}},
                Credentials{NoCredentials{}},
                client.environment})
        .transform([](const auto&) {
        });
}

struct RcloneHarness {
    kasumi::platform::Workspace workspace;
    CurrentDirectory current_directory{nullptr, restore_current_directory};
    kasumi::test::ScopedEnvironmentVariable rclone_config{
        nullptr, kasumi::test::restore_environment_variable};
    kasumi::test::ScopedEnvironmentVariable rclone_cache{
        nullptr, kasumi::test::restore_environment_variable};

    ~RcloneHarness() {
        if (workspace.root.empty()) {
            return;
        }
        const auto root = workspace.root;
        std::vector<std::filesystem::path> app_dirs{root / "cli-home/kasumi"};
        std::error_code dir_ec;
        for (const auto& entry :
             std::filesystem::directory_iterator(root, dir_ec)) {
            if (entry.is_directory(dir_ec)) {
                app_dirs.push_back(entry.path() / "app-data");
            }
        }
        for (const auto& app_dir : app_dirs) {
            std::error_code cfg_ec;
            if (std::filesystem::exists(app_dir / "config.toml", cfg_ec)) {
                if (const auto profs =
                        kasumi::application::list_profiles({app_dir})) {
                    for (const auto& p : *profs) {
                        static_cast<void>(kasumi::application::delete_profile(
                            {app_dir}, p.name));
                    }
                }
            }
        }
        rclone_cache.reset();
        rclone_config.reset();
        current_directory.reset();
        const auto removed = kasumi::platform::remove_workspace(workspace);
        EXPECT_TRUE(removed) << (removed ? "" : removed.error());
        workspace = {};
        EXPECT_FALSE(std::filesystem::exists(root))
            << kasumi::platform::path::to_utf8(root);
    }
};

const std::filesystem::path&
harness_root(const RcloneHarness& harness) noexcept {
    return harness.workspace.root;
}

std::filesystem::path harness_path(const RcloneHarness& harness,
                                   const std::filesystem::path& relative) {
    return harness.workspace.root / relative;
}

std::filesystem::path storage_root(const RcloneHarness& harness) {
    return harness_path(harness, remote_backend) / remote_root;
}

std::string remote_location(const RcloneHarness&) {
    return std::string{remote_name} + ":" + std::string{remote_root};
}

std::expected<kasumi::transport::Transport, kasumi::transport::Error>
open_transport(const RcloneHarness& harness) {
    kasumi::transport::detail::RcloneConfiguration configuration{
        .remote_name = std::string{remote_name},
        .remote_root = std::string{remote_root},
        .executable = std::filesystem::path{KASUMI_SYSTEM_RCLONE_EXECUTABLE},
        .config_path = harness_path(harness, "rclone.conf")};
    auto opened = kasumi::transport::detail::open_rclone_backend(configuration);
    if (!opened) {
        return std::unexpected(opened.error());
    }
    if (auto initialized = kasumi::transport::initialize(*opened);
        !initialized) {
        return std::unexpected(initialized.error());
    }
    return std::move(*opened);
}

TestClient make_test_client(const RcloneHarness& harness,
                            std::string_view name) {
    const auto base = harness_path(harness, std::string{name});
    create_system_directory(base / "app-data");
    create_system_directory(base / "local");
    return TestClient{
        .environment = ExecutionEnvironment{.app_data_dir = base / "app-data"},
        .local_dir = base / "local"};
}

void create_profile(const RcloneHarness& harness, const TestClient& client) {
    ASSERT_TRUE(kasumi::application::create_profile(
        client.environment,
        Profile{.name = std::string{profile_name},
                .local_dir = client.local_dir,
                .remote_dir = remote_location(harness)},
        MasterKeyHex{std::string(64, '2')}));
}

RcloneHarness make_rclone_harness() {
    auto created = kasumi::platform::create_workspace("system-rclone");
    if (!created) {
        throw std::runtime_error(created.error());
    }
    auto workspace = std::move(*created);
    const auto path = [&](const std::filesystem::path& relative) {
        return workspace.root / relative;
    };

    for (const std::string_view relative : {"cwd-trap",
                                            "r",
                                            "r/storage",
                                            "rclone-cache",
                                            "client-a/app-data",
                                            "client-a/local",
                                            "client-b/app-data",
                                            "client-b/local",
                                            "client-c/app-data",
                                            "client-c/local"}) {
        create_system_directory(workspace.root / relative);
    }

    auto current_directory = use_current_directory(path("cwd-trap"));
    auto rclone_config = kasumi::test::scoped_environment_variable(
        "RCLONE_CONFIG", kasumi::platform::path::to_utf8(path("rclone.conf")));
    auto rclone_cache = kasumi::test::scoped_environment_variable(
        "RCLONE_CACHE_DIR",
        kasumi::platform::path::to_utf8(path("rclone-cache")));

    std::ofstream config(path("rclone.conf"));
    if (!config) {
        throw std::runtime_error("could not create temporary rclone.conf");
    }
    config << "[kasumi-test]\n"
           << "type = alias\n"
           << "remote = "
           << kasumi::platform::path::to_logical_utf8(path(remote_backend))
           << "\n";
    if (!config.good()) {
        throw std::runtime_error("could not write temporary rclone.conf");
    }

    return RcloneHarness{.workspace = std::move(workspace),
                         .current_directory = std::move(current_directory),
                         .rclone_config = std::move(rclone_config),
                         .rclone_cache = std::move(rclone_cache)};
}

std::expected<HeadReference, std::string>
find_reference(kasumi::transport::Transport& storage,
               const RemoteLayout& layout) {
    auto listing = kasumi::transport::list(storage);
    if (!listing) {
        return std::unexpected(kasumi::transport::describe(listing.error()));
    }
    for (const auto& identifier : *listing) {
        if (const auto reference =
                kasumi::application::history_storage::parse_marker_object(
                    layout, identifier)) {
            return *reference;
        }
    }
    return std::unexpected("marker not found");
}

void ensure_workspace(const std::filesystem::path& path) {
    std::error_code error;
    ASSERT_TRUE(std::filesystem::create_directories(path, error) || !error)
        << error.message();
}

LoadedHistory load_history(RcloneHarness& harness,
                           const std::filesystem::path& workspace) {
    ensure_workspace(workspace);
    auto storage = open_transport(harness);
    EXPECT_TRUE(storage.has_value());
    if (!storage) {
        return {};
    }
    auto loaded = kasumi::application::history_storage::load_history(
        *storage, test_key(), workspace);
    EXPECT_TRUE(loaded.has_value()) << (loaded ? "" : loaded.error().detail);
    return loaded ? *loaded : LoadedHistory{};
}

std::expected<kasumi::application::history_storage::PublishedCommitObject,
              std::string>
publish_staged(kasumi::transport::Transport& storage,
               const RemoteLayout& layout,
               const kasumi::history::Commit& commit,
               const std::filesystem::path& workspace) {
    std::error_code directory_error;
    std::filesystem::create_directories(workspace, directory_error);
    if (directory_error) {
        return std::unexpected(directory_error.message());
    }
    auto object = kasumi::application::history_storage::publish_commit_object(
        storage, layout, test_key(), commit, workspace);
    if (!object) {
        return std::unexpected(object.error().detail);
    }
    auto verified = kasumi::application::history_storage::verify_commit_object(
        storage, layout, test_key(), commit, object->head, workspace);
    if (!verified) {
        return std::unexpected(verified.error().detail);
    }
    auto marker = kasumi::application::history_storage::publish_head_marker(
        storage, layout, object->head, workspace);
    if (!marker) {
        return std::unexpected(marker.error().detail);
    }
    auto marker_verified =
        kasumi::application::history_storage::verify_head_marker(
            storage, layout, object->head, workspace);
    if (!marker_verified) {
        return std::unexpected(marker_verified.error().detail);
    }
    return *object;
}

void create_profile_and_file(const RcloneHarness& harness,
                             const TestClient& client,
                             std::string_view contents) {
    create_profile(harness, client);
    kasumi::test::write_text(client.local_dir / "alpha.txt", contents);
}

std::string put_content_blob(kasumi::transport::Transport& storage,
                             const std::filesystem::path& root,
                             std::string_view contents,
                             std::string_view suffix) {
    const auto identifier = kasumi::crypto::content_identifier(
        test_key(), kasumi::hasher::hash_string(contents));
    const auto plain = root / (std::string{suffix} + ".plain");
    const auto encrypted = root / (std::string{suffix} + ".enc");
    kasumi::test::write_text(plain, contents);
    EXPECT_TRUE(kasumi::crypto::encrypt_file(plain, encrypted, test_key()));
    EXPECT_TRUE(kasumi::transport::put(storage, encrypted, identifier));
    return identifier;
}

#if !defined(_WIN32)
TEST(RcloneSystemTest, StartupRetriesAfterChildExitsAndOpensWorkingSession) {
    auto harness = make_rclone_harness();
    const auto shim = harness_path(harness, "rclone-retry");
    const auto failed_attempt = harness_path(harness, "first-attempt");
    auto executable = kasumi::test::scoped_environment_variable(
        "TEST_RCLONE_RETRY_EXECUTABLE", KASUMI_SYSTEM_RCLONE_EXECUTABLE);
    auto marker = kasumi::test::scoped_environment_variable(
        "TEST_RCLONE_RETRY_MARKER",
        kasumi::platform::path::to_utf8(failed_attempt));
    kasumi::test::write_text(shim,
                             "#!/bin/sh\n"
                             "if [ ! -e \"$TEST_RCLONE_RETRY_MARKER\" ]; then\n"
                             "    printf 'temporary startup failure\\n' > "
                             "\"$TEST_RCLONE_RETRY_MARKER\" || exit 2\n"
                             "    exit 1\n"
                             "fi\n"
                             "exec \"$TEST_RCLONE_RETRY_EXECUTABLE\" \"$@\"\n");
    std::filesystem::permissions(shim,
                                 std::filesystem::perms::owner_exec,
                                 std::filesystem::perm_options::add);
    auto storage = kasumi::transport::detail::open_rclone_backend({
        .remote_name = std::string{remote_name},
        .remote_root = std::string{remote_root},
        .executable = shim,
        .config_path = harness_path(harness, "rclone.conf"),
    });
    ASSERT_TRUE(storage) << kasumi::transport::describe(storage.error());
    EXPECT_TRUE(std::filesystem::is_regular_file(failed_attempt));
    ASSERT_TRUE(kasumi::transport::initialize(*storage));
    EXPECT_TRUE(kasumi::transport::list(*storage));
}
#endif

TEST(RcloneSystemTest, RealTransportSmokeUsesAnIsolatedRcProcess) {
    auto harness = make_rclone_harness();
    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());

    const auto source = harness_root(harness) / "source.bin";
    const auto destination = harness_root(harness) / "destination.bin";
    kasumi::test::write_text(source, "rclone smoke");
    ASSERT_TRUE(kasumi::transport::put(*storage, source, "smoke/object"));
    EXPECT_EQ(kasumi::transport::presence(*storage, "smoke/object").value(),
              kasumi::transport::Presence::Present);
    ASSERT_TRUE(kasumi::transport::get(*storage, "smoke/object", destination));
    EXPECT_EQ(kasumi::test::read_text(destination), "rclone smoke");
    ASSERT_TRUE(kasumi::transport::put(*storage, source, "smoke/object"));
    const auto source_time = std::filesystem::last_write_time(source);
    kasumi::test::write_text(source, "rclone retry");
    std::filesystem::last_write_time(source, source_time);
    ASSERT_TRUE(kasumi::transport::put(*storage, source, "smoke/object"));
    ASSERT_TRUE(kasumi::transport::get(*storage, "smoke/object", destination));
    EXPECT_EQ(kasumi::test::read_text(destination), "rclone retry");
    const auto listing = kasumi::transport::list(*storage);
    ASSERT_TRUE(listing.has_value());
    EXPECT_NE(std::ranges::find(*listing, "smoke/object"), listing->end());
    const auto scoped = kasumi::transport::list(*storage, "smoke");
    ASSERT_TRUE(scoped.has_value());
    EXPECT_EQ(*scoped, (std::vector<std::string>{"object"}));
    EXPECT_EQ(kasumi::transport::remove(*storage, "smoke/object").value(),
              kasumi::transport::Removal::Removed);
    EXPECT_EQ(kasumi::transport::presence(*storage, "smoke/object").value(),
              kasumi::transport::Presence::Absent);
    EXPECT_FALSE(kasumi::transport::presence(*storage, "../escape"));
}

TEST(RcloneSystemTest, SpawnedRcUsesRcloneServerTimeoutDefaults) {
    auto read_timeout = kasumi::test::scoped_environment_variable(
        "RCLONE_RC_SERVER_READ_TIMEOUT", std::nullopt);
    auto write_timeout = kasumi::test::scoped_environment_variable(
        "RCLONE_RC_SERVER_WRITE_TIMEOUT", std::nullopt);
    auto harness = make_rclone_harness();
    kasumi::transport::detail::RcloneConfiguration configuration{
        .remote_name = std::string{remote_name},
        .remote_root = std::string{remote_root},
        .executable = std::filesystem::path{KASUMI_SYSTEM_RCLONE_EXECUTABLE},
        .config_path = harness_path(harness, "rclone.conf")};
    auto started = kasumi::transport::rclone_detail::start_state(configuration);
    ASSERT_TRUE(started.has_value())
        << (started ? "" : started.error().message);
    const auto state = std::unique_ptr<kasumi::transport::rclone_detail::State,
                                       void (*)(void*)>{
        *started, kasumi::transport::rclone_detail::destroy_state};
    const auto response =
        kasumi::transport::rclone_detail::post_rc(*state,
                                                  "options/get",
                                                  R"({"blocks":"rc"})",
                                                  64 * 1024,
                                                  std::chrono::seconds{5});
    ASSERT_TRUE(response.has_value())
        << (response ? "" : response.error().message);
    const auto options = nlohmann::json::parse(*response);
    const auto& rc = options.at("rc");
    const auto& http = rc.at(rc.contains("HTTP") ? "HTTP" : "HTTPOptions");
    const auto expected = std::chrono::duration_cast<std::chrono::nanoseconds>(
                              std::chrono::hours{1})
                              .count();
    EXPECT_EQ(http.at("ServerReadTimeout").get<std::int64_t>(), expected);
    EXPECT_EQ(http.at("ServerWriteTimeout").get<std::int64_t>(), expected);
}

TEST(RcloneSystemTest, KilledOwnedRcloneFailsClosedAndCleansUp) {
    auto harness = make_rclone_harness();
    kasumi::transport::detail::RcloneConfiguration configuration{
        .remote_name = std::string{remote_name},
        .remote_root = std::string{remote_root},
        .executable = std::filesystem::path{KASUMI_SYSTEM_RCLONE_EXECUTABLE},
        .config_path = harness_path(harness, "rclone.conf")};
    auto started = kasumi::transport::rclone_detail::start_state(configuration);
    ASSERT_TRUE(started.has_value())
        << (started ? "" : started.error().message);
    const auto state = std::unique_ptr<kasumi::transport::rclone_detail::State,
                                       void (*)(void*)>{
        *started, kasumi::transport::rclone_detail::destroy_state};
    // Stop the polling worker before taking its mutex, as destroy_state does.
    state->stop_drain.store(true);
    state->drain_future.wait();
#if defined(_WIN32)
    const auto [pid, pid_error] = state->process.pid();
    ASSERT_FALSE(pid_error);
    const auto child = OpenProcess(
        PROCESS_TERMINATE | SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
    ASSERT_NE(child, nullptr);
    const auto terminated = TerminateProcess(child, 0xc0000005U);
    const auto exited = WaitForSingleObject(child, 2000);
    CloseHandle(child);
    ASSERT_TRUE(terminated);
    ASSERT_EQ(exited, WAIT_OBJECT_0);
#else
    {
        std::lock_guard lock(state->process_mutex);
        const auto stopped = state->process.stop(reproc::stop_actions{
            {reproc::stop::kill, reproc::milliseconds(2000)}});
        ASSERT_FALSE(stopped.second);
        state->process_started = false;
    }
#endif

    const auto response = kasumi::transport::rclone_detail::post_rc_read_only(
        *state,
        "operations/list",
        R"({"fs":"kasumi-test:","remote":"storage"})",
        64 * 1024,
        std::chrono::milliseconds{500});

    ASSERT_FALSE(response.has_value());
    EXPECT_TRUE(response.error().code == kasumi::transport::ErrorCode::Io ||
                response.error().code == kasumi::transport::ErrorCode::Timeout);
}

TEST(RcloneSystemTest, DirectMissingGetPreservesObjectNotFoundSemantics) {
    auto harness = make_rclone_harness();
    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());

    const auto destination = harness_root(harness) / "missing.bin";
    const auto missing =
        kasumi::transport::get(*storage, "missing/object", destination);
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error().code,
              kasumi::transport::ErrorCode::ObjectNotFound);
}

TEST(RcloneSystemTest, LargeRemovalReportsEveryObjectAgainstRealBackend) {
    auto harness = make_rclone_harness();
    auto storage = open_transport(harness);
    ASSERT_TRUE(storage) << kasumi::transport::describe(storage.error());
    kasumi::transport::RemoveBatch batch{.concurrency = 8};
    for (std::size_t index = 0; index < 600; ++index) {
        auto identifier =
            "content/" + std::string(96, 'a') + std::to_string(index);
        kasumi::test::write_text(storage_root(harness) / identifier, "payload");
        batch.items.push_back({std::move(identifier)});
    }
    const auto removed = kasumi::transport::remove_batch(*storage, batch);
    if (!removed &&
        removed.error().code == kasumi::transport::ErrorCode::Unsupported) {
        GTEST_SKIP() << "installed rclone does not support job/batch";
    }
    ASSERT_TRUE(removed) << kasumi::transport::describe(removed.error());
    ASSERT_EQ(removed->items.size(), batch.items.size());
    for (const auto& item : removed->items) {
        EXPECT_EQ(item.result, kasumi::transport::Removal::Removed)
            << item.identifier;
    }
    EXPECT_TRUE(std::filesystem::is_empty(storage_root(harness) / "content"));
}

TEST(RcloneSystemTest, BootstrapAndSecondClientUseOneImmutableHead) {
    auto harness = make_rclone_harness();
    const auto layout = test_layout();
    auto client_a = make_test_client(harness, "client-a");
    auto client_b = make_test_client(harness, "client-b");
    create_profile_and_file(harness, client_a, "alpha");
    create_profile(harness, client_b);

    ASSERT_TRUE(sync_client(client_a));
    auto before =
        load_history(harness, harness_root(harness) / "client-a/work");
    ASSERT_EQ(before.marked_heads.size(), 1U);
    auto object_listing = open_transport(harness);
    ASSERT_TRUE(object_listing.has_value());
    auto identifiers = kasumi::transport::list(*object_listing);
    ASSERT_TRUE(identifiers.has_value());
    EXPECT_EQ(
        std::ranges::count_if(*identifiers,
                              [&layout](const auto& id) {
                                  return kasumi::application::history_storage::
                                      parse_commit_object(layout, id)
                                          .has_value();
                              }),
        1);
    EXPECT_EQ(
        std::ranges::count_if(*identifiers,
                              [&layout](const auto& id) {
                                  return kasumi::application::history_storage::
                                      parse_marker_object(layout, id)
                                          .has_value();
                              }),
        1);

    ASSERT_TRUE(sync_client(client_b));
    EXPECT_EQ(kasumi::test::read_text(client_b.local_dir / "alpha.txt"),
              "alpha");
    auto after = load_history(harness, harness_root(harness) / "client-b/work");
    EXPECT_EQ(after.marked_heads, before.marked_heads);
    ASSERT_TRUE(sync_client(client_b));
    auto repeated =
        load_history(harness, harness_root(harness) / "client-b/work2");
    EXPECT_EQ(repeated.marked_heads, before.marked_heads);
    EXPECT_TRUE(std::filesystem::exists(
        harness_root(harness) / "client-a/app-data/profiles/demo/db.sqlite"));
}

TEST(RcloneSystemTest, TwoPersistedClientsPropagateRemoteDeletes) {
    auto harness = make_rclone_harness();
    auto client_a = make_test_client(harness, "client-a");
    auto client_b = make_test_client(harness, "client-b");
    create_profile(harness, client_a);
    create_profile(harness, client_b);
    kasumi::test::write_text(client_a.local_dir / "keep.txt", "keep");
    kasumi::test::write_text(client_a.local_dir / "alpha.txt", "alpha");
    kasumi::test::write_text(client_a.local_dir / "beta.txt", "beta");
    kasumi::test::write_text(client_a.local_dir / ".kasumiignore",
                             "ignored.txt\n");
    kasumi::test::write_text(client_a.local_dir / "ignored.txt", "ignored");
    create_system_directory(client_a.local_dir / "dir");
    kasumi::test::write_text(client_a.local_dir / "dir/gamma.txt", "gamma");

    ASSERT_TRUE(sync_client(client_a));
    ASSERT_TRUE(sync_client(client_b));
    ASSERT_TRUE(sync_client(client_a));
    ASSERT_TRUE(sync_client(client_b));

    EXPECT_FALSE(std::filesystem::exists(client_b.local_dir / "ignored.txt"));

    ASSERT_TRUE(std::filesystem::remove(client_b.local_dir / "alpha.txt"));
    ASSERT_TRUE(std::filesystem::remove(client_b.local_dir / "beta.txt"));
    ASSERT_TRUE(std::filesystem::remove(client_b.local_dir / "dir/gamma.txt"));
    ASSERT_TRUE(std::filesystem::remove(client_b.local_dir / "dir"));

    ASSERT_TRUE(sync_client(client_b));

    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());
    ensure_workspace(harness_root(harness) / "delete-observation");
    auto remote = kasumi::application::observation::history::observe(
        *storage,
        test_key(),
        harness_root(harness) / "delete-observation",
        false);
    ASSERT_TRUE(remote.has_value()) << (remote ? "" : remote.error().detail);
    EXPECT_TRUE(kasumi::find_row(remote->effective_tree, "keep.txt"));
    EXPECT_TRUE(kasumi::find_row(remote->effective_tree, ".kasumiignore"));
    EXPECT_FALSE(kasumi::find_row(remote->effective_tree, "alpha.txt"));
    EXPECT_FALSE(kasumi::find_row(remote->effective_tree, "beta.txt"));
    EXPECT_FALSE(kasumi::find_row(remote->effective_tree, "dir/gamma.txt"));

    auto receive_delete = sync_client(client_a);
    EXPECT_TRUE(receive_delete)
        << (receive_delete ? "" : receive_delete.error().detail);
    EXPECT_TRUE(std::filesystem::exists(client_a.local_dir / "keep.txt"));
    EXPECT_FALSE(std::filesystem::exists(client_a.local_dir / "alpha.txt"));
    EXPECT_FALSE(std::filesystem::exists(client_a.local_dir / "beta.txt"));
    EXPECT_FALSE(std::filesystem::exists(client_a.local_dir / "dir"));
    EXPECT_EQ(kasumi::test::read_text(client_a.local_dir / "ignored.txt"),
              "ignored");

    auto runtime_a =
        kasumi::runtime::resolve(client_a.environment.app_data_dir,
                                 profile_name,
                                 kasumi::runtime::AccessMode::ReadOnly);
    ASSERT_TRUE(runtime_a.has_value());
    auto state_a = kasumi::state_storage::load_state(runtime_a->database_path);
    ASSERT_TRUE(state_a && *state_a);
    ASSERT_EQ(remote->logical_heads.size(), 1U);
    EXPECT_EQ((*state_a)->commit_id, remote->logical_heads.front());
    EXPECT_EQ((*state_a)->tree, remote->effective_tree);

    auto repeated = sync_client(client_a);
    EXPECT_TRUE(repeated) << (repeated ? "" : repeated.error().detail);
    EXPECT_FALSE(std::filesystem::exists(client_a.local_dir / "alpha.txt"));
    EXPECT_FALSE(std::filesystem::exists(client_a.local_dir / "beta.txt"));
    EXPECT_FALSE(std::filesystem::exists(client_a.local_dir / "dir"));

    ASSERT_TRUE(sync_client(client_b));
    EXPECT_FALSE(std::filesystem::exists(client_b.local_dir / "alpha.txt"));
    EXPECT_FALSE(std::filesystem::exists(client_b.local_dir / "beta.txt"));
    EXPECT_FALSE(std::filesystem::exists(client_b.local_dir / "dir"));

    ensure_workspace(harness_root(harness) / "delete-final-observation");
    auto final_remote = kasumi::application::observation::history::observe(
        *storage,
        test_key(),
        harness_root(harness) / "delete-final-observation",
        false);
    ASSERT_TRUE(final_remote.has_value());
    EXPECT_EQ(final_remote->logical_heads, remote->logical_heads);
    EXPECT_EQ(final_remote->effective_tree, remote->effective_tree);
}

TEST(RcloneSystemTest, ImmutableHistoryReachabilityInventoryIsReadOnly) {
    auto harness = make_rclone_harness();
    const auto layout = test_layout();
    auto client = make_test_client(harness, "client-a");
    create_profile_and_file(harness, client, "alpha");
    ASSERT_TRUE(sync_client(client));

    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());
    auto loaded =
        load_history(harness, harness_root(harness) / "reachability-base");
    ASSERT_EQ(loaded.marked_heads.size(), 1U);

    auto orphan = make_commit(0, {}, "orphan.txt", "orphan");
    ASSERT_TRUE(orphan.has_value());
    auto published =
        publish_staged(*storage,
                       layout,
                       *orphan,
                       harness_root(harness) / "reachability-orphan");
    ASSERT_TRUE(published.has_value());
    ASSERT_EQ(kasumi::transport::remove(
                  *storage,
                  kasumi::application::history_storage::marker_object(
                      layout, published->head))
                  .value(),
              kasumi::transport::Removal::Removed);

    auto before = kasumi::transport::list(*storage);
    ASSERT_TRUE(before.has_value());
    ensure_workspace(harness_root(harness) / "reachability-inventory");
    auto inventory =
        kasumi::application::history_storage::inventory_reachability(
            *storage,
            test_key(),
            harness_root(harness) / "reachability-inventory");
    ASSERT_TRUE(inventory.has_value()) << inventory.error().detail;
    EXPECT_EQ(inventory->logical_heads,
              std::vector<std::string>{loaded.marked_heads.front()});
    EXPECT_EQ(inventory->reachable_commits,
              std::vector<std::string>{loaded.marked_heads.front()});
    EXPECT_EQ(inventory->orphan_commits,
              std::vector<std::string>{published->head.commit_id});

    auto after = kasumi::transport::list(*storage);
    ASSERT_TRUE(after.has_value());
    std::ranges::sort(*before);
    std::ranges::sort(*after);
    EXPECT_EQ(*after, *before);
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        harness_root(harness) / "reachability-inventory"));
}

TEST(RcloneSystemTest, ImmutableContentReachabilityInventoryIsReadOnly) {
    auto harness = make_rclone_harness();
    auto client = make_test_client(harness, "client-a");
    create_profile_and_file(harness, client, "alpha");
    ASSERT_TRUE(sync_client(client));

    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());
    const auto orphan_id = put_content_blob(
        *storage, harness_root(harness), "orphan", "content-orphan");
    auto before = kasumi::transport::list(*storage);
    ASSERT_TRUE(before.has_value());
    ensure_workspace(harness_root(harness) / "content-history");
    auto history = kasumi::application::history_storage::inventory_reachability(
        *storage, test_key(), harness_root(harness) / "content-history");
    ASSERT_TRUE(history.has_value()) << history.error().detail;
    ensure_workspace(harness_root(harness) / "content-inventory");
    auto inventory =
        kasumi::application::history_storage::inventory_content_reachability(
            *storage,
            test_key(),
            *history,
            harness_root(harness) / "content-inventory");
    ASSERT_TRUE(inventory.has_value()) << inventory.error().detail;

    const auto alpha_id = kasumi::crypto::content_identifier(
        test_key(), kasumi::hasher::hash_string("alpha"));
    EXPECT_EQ(inventory->reachable_content_ids,
              std::vector<std::string>{alpha_id});
    EXPECT_TRUE(inventory->missing_content_ids.empty());
    EXPECT_TRUE(inventory->corrupt_content_ids.empty());
    EXPECT_EQ(inventory->orphan_content_ids,
              std::vector<std::string>{orphan_id});

    auto after = kasumi::transport::list(*storage);
    ASSERT_TRUE(after.has_value());
    std::ranges::sort(*before);
    std::ranges::sort(*after);
    EXPECT_EQ(*after, *before);
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        harness_root(harness) / "content-history"));
    EXPECT_FALSE(kasumi::test::has_temporary_history_workspace(
        harness_root(harness) / "content-inventory"));
}

TEST(RcloneSystemTest, MissingReferencedObjectIsTrustedUntilFsckOrRequiredGet) {
    auto harness = make_rclone_harness();
    const auto layout = test_layout();
    auto client = make_test_client(harness, "client-a");
    create_profile_and_file(harness, client, "alpha");
    ASSERT_TRUE(sync_client(client));

    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());
    auto before = kasumi::transport::list(*storage);
    ASSERT_TRUE(before.has_value());
    const auto reference = find_reference(*storage, layout);
    ASSERT_TRUE(reference.has_value());
    const auto content_id = kasumi::crypto::content_identifier(
        test_key(), kasumi::hasher::hash_string("alpha"));
    ASSERT_EQ(kasumi::transport::presence(*storage, content_id).value(),
              kasumi::transport::Presence::Present);
    ASSERT_EQ(kasumi::transport::remove(*storage, content_id).value(),
              kasumi::transport::Removal::Removed);
    auto trusted = sync_client(client);
    ASSERT_TRUE(trusted) << (trusted ? "" : trusted.error().detail);
    EXPECT_EQ(kasumi::transport::presence(*storage, content_id).value(),
              kasumi::transport::Presence::Absent);
    auto after = kasumi::transport::list(*storage);
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(
        std::ranges::count_if(*before,
                              [&layout](const auto& id) {
                                  return kasumi::application::history_storage::
                                      parse_commit_object(layout, id)
                                          .has_value();
                              }),
        std::ranges::count_if(*after, [&layout](const auto& id) {
            return kasumi::application::history_storage::parse_commit_object(
                       layout, id)
                .has_value();
        }));
    EXPECT_EQ(
        std::ranges::count_if(*before,
                              [&layout](const auto& id) {
                                  return kasumi::application::history_storage::
                                      parse_marker_object(layout, id)
                                          .has_value();
                              }),
        std::ranges::count_if(*after, [&layout](const auto& id) {
            return kasumi::application::history_storage::parse_marker_object(
                       layout, id)
                .has_value();
        }));
    EXPECT_EQ(find_reference(*storage, layout), reference);

    const auto fsck = kasumi::application::execute(
        {Request{Operation::Fsck, std::string{profile_name}},
         Credentials{NoCredentials{}},
         client.environment});
    ASSERT_FALSE(fsck.has_value());
    EXPECT_EQ(fsck.error().code, kasumi::application::ErrorCode::FsckFailure);

    auto receiver = make_test_client(harness, "client-b");
    create_profile(harness, receiver);
    const auto required = kasumi::application::execute(
        {Request{Operation::Sync, std::string{profile_name}},
         Credentials{NoCredentials{}},
         receiver.environment});
    ASSERT_TRUE(required.has_value())
        << (required ? "" : required.error().detail);
    const auto* partial =
        std::get_if<kasumi::application::SyncCompleted>(&required->data);
    ASSERT_NE(partial, nullptr);
    EXPECT_TRUE(partial->partial);
    EXPECT_EQ(partial->pending, 1U);
    EXPECT_EQ(partial->pending_paths,
              std::vector<std::filesystem::path>{"alpha.txt"});
}

TEST(RcloneSystemTest, CommitObjectAndMarkerStagesAreIndependent) {
    auto harness = make_rclone_harness();
    const auto layout = test_layout();
    auto client = make_test_client(harness, "client-a");
    create_profile_and_file(harness, client, "base");
    ASSERT_TRUE(sync_client(client));

    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());
    auto loaded = load_history(harness, harness_root(harness) / "stages-base");
    ASSERT_EQ(loaded.marked_heads.size(), 1U);
    const auto parent = loaded.marked_heads.front();
    const auto parent_commit = std::ranges::find(
        loaded.commits, parent, &kasumi::history::LoadedCommit::id);
    ASSERT_NE(parent_commit, loaded.commits.end());
    auto next = make_commit(
        parent_commit->commit.height + 1, {parent}, "beta.txt", "next");
    ASSERT_TRUE(next.has_value());
    ensure_workspace(harness_root(harness) / "stages");

    auto object = kasumi::application::history_storage::publish_commit_object(
        *storage, layout, test_key(), *next, harness_root(harness) / "stages");
    ASSERT_TRUE(object.has_value());
    ASSERT_TRUE(kasumi::application::history_storage::verify_commit_object(
        *storage,
        layout,
        test_key(),
        *next,
        object->head,
        harness_root(harness) / "stages"));
    auto marker_state =
        kasumi::application::history_storage::inspect_head_marker(
            *storage, layout, object->head, harness_root(harness) / "stages");
    ASSERT_TRUE(marker_state.has_value());
    EXPECT_EQ(*marker_state,
              kasumi::application::history_storage::HeadMarkerState::Absent);

    auto listing_before_marker = kasumi::transport::list(*storage);
    ASSERT_TRUE(listing_before_marker.has_value());
    EXPECT_EQ(
        std::ranges::count_if(*listing_before_marker,
                              [&layout](const auto& id) {
                                  return kasumi::application::history_storage::
                                      parse_marker_object(layout, id)
                                          .has_value();
                              }),
        1);

    ASSERT_TRUE(
        kasumi::application::history_storage::publish_head_marker(
            *storage, layout, object->head, harness_root(harness) / "stages")
            .has_value());
    ASSERT_TRUE(kasumi::application::history_storage::verify_head_marker(
        *storage, layout, object->head, harness_root(harness) / "stages"));

    auto reused = kasumi::application::history_storage::publish_commit_object(
        *storage, layout, test_key(), *next, harness_root(harness) / "stages");
    ASSERT_TRUE(reused.has_value());
    EXPECT_TRUE(reused->reused_existing_ciphertext);
    EXPECT_EQ(reused->head, object->head);
    ASSERT_TRUE(
        kasumi::application::history_storage::publish_head_marker(
            *storage, layout, object->head, harness_root(harness) / "stages")
            .has_value());
}

TEST(RcloneSystemTest, SequentialMutationKeepsThePreviousCommitAsParent) {
    auto harness = make_rclone_harness();
    auto client = make_test_client(harness, "client-a");
    create_profile_and_file(harness, client, "one");
    ASSERT_TRUE(sync_client(client));
    auto before =
        load_history(harness, harness_root(harness) / "sequential-before");
    ASSERT_EQ(before.marked_heads.size(), 1U);
    const auto previous = before.marked_heads.front();

    kasumi::test::write_text(client.local_dir / "alpha.txt", "two");
    ASSERT_TRUE(sync_client(client));
    auto after =
        load_history(harness, harness_root(harness) / "sequential-after");
    ASSERT_EQ(after.marked_heads.size(), 1U);
    ASSERT_NE(after.marked_heads.front(), previous);
    const auto current = std::ranges::find(after.commits,
                                           after.marked_heads.front(),
                                           &kasumi::history::LoadedCommit::id);
    ASSERT_NE(current, after.commits.end());
    EXPECT_EQ(current->commit.parents, std::vector<std::string>{previous});
    EXPECT_TRUE(std::ranges::contains(
        after.commits, previous, &kasumi::history::LoadedCommit::id));
    EXPECT_EQ(kasumi::test::read_text(client.local_dir / "alpha.txt"), "two");
}

TEST(RcloneSystemTest, ThreeConcurrentPublishersConvergeThroughRealTransport) {
    auto harness = make_rclone_harness();
    const auto layout = test_layout();
    auto client_a = make_test_client(harness, "client-a");
    auto reconciler = make_test_client(harness, "client-reconciler");
    create_profile_and_file(harness, client_a, "base");
    create_profile(harness, reconciler);
    ASSERT_TRUE(sync_client(client_a));

    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());
    ensure_workspace(harness_root(harness) / "manual");
    auto loaded = kasumi::application::history_storage::load_history(
        *storage, test_key(), harness_root(harness) / "manual");
    ASSERT_TRUE(loaded.has_value());
    ASSERT_EQ(loaded->marked_heads.size(), 1U);
    const auto base_id = loaded->marked_heads.front();
    const auto base =
        std::ranges::find_if(loaded->commits, [&](const auto& commit) {
            return commit.id == base_id;
        });
    ASSERT_NE(base, loaded->commits.end());

    kasumi::test::write_text(reconciler.local_dir / "alpha.txt", "branch-a");
    kasumi::test::write_text(reconciler.local_dir / "beta.txt", "branch-b");
    kasumi::test::write_text(reconciler.local_dir / "gamma.txt", "branch-c");
    std::error_code mtime_error;
    const auto alpha_file_time = std::filesystem::last_write_time(
        reconciler.local_dir / "alpha.txt", mtime_error);
    ASSERT_FALSE(mtime_error);
    const auto beta_file_time = std::filesystem::last_write_time(
        reconciler.local_dir / "beta.txt", mtime_error);
    ASSERT_FALSE(mtime_error);
    const auto gamma_file_time = std::filesystem::last_write_time(
        reconciler.local_dir / "gamma.txt", mtime_error);
    ASSERT_FALSE(mtime_error);
    const auto alpha_mtime =
        kasumi::platform::metadata::unix_nanoseconds(alpha_file_time);
    const auto beta_mtime =
        kasumi::platform::metadata::unix_nanoseconds(beta_file_time);
    const auto gamma_mtime =
        kasumi::platform::metadata::unix_nanoseconds(gamma_file_time);
    ASSERT_TRUE(alpha_mtime.has_value());
    ASSERT_TRUE(beta_mtime.has_value());
    ASSERT_TRUE(gamma_mtime.has_value());

    auto branch_a = make_commit(base->commit.height + 1,
                                {base_id},
                                "alpha.txt",
                                "branch-a",
                                *alpha_mtime);
    auto branch_b = make_commit(base->commit.height + 1,
                                {base_id},
                                "beta.txt",
                                "branch-b",
                                *beta_mtime);
    auto branch_c = make_commit(base->commit.height + 1,
                                {base_id},
                                "gamma.txt",
                                "branch-c",
                                *gamma_mtime);
    ASSERT_TRUE(branch_a.has_value());
    ASSERT_TRUE(branch_b.has_value());
    ASSERT_TRUE(branch_c.has_value());

    auto storage_b = open_transport(harness);
    auto storage_c = open_transport(harness);
    ASSERT_TRUE(storage_b.has_value());
    ASSERT_TRUE(storage_c.has_value());
    std::latch publishers_ready{3};
    const auto publish = [&](kasumi::transport::Transport& publisher,
                             const kasumi::history::Commit& commit,
                             std::string_view workspace) {
        publishers_ready.count_down();
        publishers_ready.wait();
        return publish_staged(
            publisher, layout, commit, harness_root(harness) / workspace);
    };
    auto publishing_a = std::async(std::launch::async,
                                   publish,
                                   std::ref(*storage),
                                   std::cref(*branch_a),
                                   "manual-a");
    auto publishing_b = std::async(std::launch::async,
                                   publish,
                                   std::ref(*storage_b),
                                   std::cref(*branch_b),
                                   "manual-b");
    auto publishing_c = std::async(std::launch::async,
                                   publish,
                                   std::ref(*storage_c),
                                   std::cref(*branch_c),
                                   "manual-c");
    const auto published_a = publishing_a.get();
    const auto published_b = publishing_b.get();
    const auto published_c = publishing_c.get();
    ASSERT_TRUE(published_a.has_value())
        << (published_a ? "" : published_a.error());
    ASSERT_TRUE(published_b.has_value())
        << (published_b ? "" : published_b.error());
    ASSERT_TRUE(published_c.has_value())
        << (published_c ? "" : published_c.error());

    auto observed = kasumi::application::observation::history::observe(
        *storage, test_key(), harness_root(harness), false);
    ASSERT_TRUE(observed.has_value());
    ASSERT_EQ(observed->logical_heads.size(), 3U);
    auto reconciled = sync_client(reconciler);
    ASSERT_TRUE(reconciled) << (reconciled ? "" : reconciled.error().detail);

    auto converged = load_history(harness, harness_root(harness) / "converged");
    ASSERT_EQ(converged.marked_heads.size(), 1U);
    const auto convergence =
        std::ranges::find_if(converged.commits, [&](const auto& commit) {
            return commit.id == converged.marked_heads.front();
        });
    ASSERT_NE(convergence, converged.commits.end());
    auto expected_parents =
        std::vector<std::string>{published_a->head.commit_id,
                                 published_b->head.commit_id,
                                 published_c->head.commit_id};
    std::ranges::sort(expected_parents);
    EXPECT_EQ(convergence->commit.parents, expected_parents);
    for (const auto& parent : expected_parents) {
        EXPECT_TRUE(std::ranges::contains(
            converged.commits, parent, &kasumi::history::LoadedCommit::id));
    }
}

TEST(RcloneSystemTest, ConcurrentPublishersAndMaterializersRemainSafe) {
    auto harness = make_rclone_harness();
    const auto layout = test_layout();
    auto seed = make_test_client(harness, "seed");
    auto receiver_a = make_test_client(harness, "receiver-a");
    auto receiver_b = make_test_client(harness, "receiver-b");
    create_profile_and_file(harness, seed, "base");
    create_profile(harness, receiver_a);
    create_profile(harness, receiver_b);
    ASSERT_TRUE(sync_client(seed));

    std::latch materializers_ready{2};
    const auto materialize = [&](const TestClient& client) {
        materializers_ready.count_down();
        materializers_ready.wait();
        return sync_client(client);
    };
    auto materialized_a =
        std::async(std::launch::async, materialize, std::cref(receiver_a));
    auto materialized_b =
        std::async(std::launch::async, materialize, std::cref(receiver_b));
    const auto receiver_a_result = materialized_a.get();
    const auto receiver_b_result = materialized_b.get();
    ASSERT_TRUE(receiver_a_result.has_value())
        << receiver_a_result.error().detail;
    ASSERT_TRUE(receiver_b_result.has_value())
        << receiver_b_result.error().detail;
    EXPECT_EQ(kasumi::test::read_text(receiver_a.local_dir / "alpha.txt"),
              "base");
    EXPECT_EQ(kasumi::test::read_text(receiver_b.local_dir / "alpha.txt"),
              "base");

    auto loaded =
        load_history(harness, harness_root(harness) / "concurrent-base");
    ASSERT_EQ(loaded.marked_heads.size(), 1U);
    const auto base_id = loaded.marked_heads.front();
    const auto base = std::ranges::find(
        loaded.commits, base_id, &kasumi::history::LoadedCommit::id);
    ASSERT_NE(base, loaded.commits.end());
    auto left =
        make_commit(base->commit.height + 1, {base_id}, "left.txt", "left");
    auto right =
        make_commit(base->commit.height + 1, {base_id}, "right.txt", "right");
    ASSERT_TRUE(left.has_value());
    ASSERT_TRUE(right.has_value());
    auto storage_a = open_transport(harness);
    auto storage_b = open_transport(harness);
    ASSERT_TRUE(storage_a.has_value());
    ASSERT_TRUE(storage_b.has_value());

    std::latch publishers_ready{2};
    const auto publish = [&](kasumi::transport::Transport& storage,
                             const kasumi::history::Commit& commit,
                             std::string_view workspace) {
        publishers_ready.count_down();
        publishers_ready.wait();
        return publish_staged(
            storage, layout, commit, harness_root(harness) / workspace);
    };
    auto published_a = std::async(std::launch::async,
                                  publish,
                                  std::ref(*storage_a),
                                  std::cref(*left),
                                  "concurrent-left");
    auto published_b = std::async(std::launch::async,
                                  publish,
                                  std::ref(*storage_b),
                                  std::cref(*right),
                                  "concurrent-right");
    const auto left_result = published_a.get();
    const auto right_result = published_b.get();
    ASSERT_TRUE(left_result.has_value())
        << (left_result ? "" : left_result.error());
    ASSERT_TRUE(right_result.has_value())
        << (right_result ? "" : right_result.error());

    ensure_workspace(harness_root(harness) / "concurrent-observe");
    auto observed = kasumi::application::observation::history::observe(
        *storage_a,
        test_key(),
        harness_root(harness) / "concurrent-observe",
        false);
    ASSERT_TRUE(observed.has_value())
        << (observed ? "" : observed.error().detail);
    EXPECT_EQ(observed->logical_heads.size(), 2U);
}

TEST(RcloneSystemTest, CorruptedMarkerAndMissingCommitFailClosed) {
    auto harness = make_rclone_harness();
    const auto layout = test_layout();
    auto client = make_test_client(harness, "client-a");
    create_profile_and_file(harness, client, "valid");
    ASSERT_TRUE(sync_client(client));

    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());
    auto reference = find_reference(*storage, layout);
    ASSERT_TRUE(reference.has_value());
    const auto marker_id =
        kasumi::application::history_storage::marker_object(layout, *reference);
    const auto marker_path = storage_root(harness) / marker_id;
    ASSERT_TRUE(std::filesystem::is_regular_file(marker_path)) << marker_path;
    kasumi::test::write_text(marker_path, "corrupt marker");
    auto marker_observation =
        kasumi::application::observation::history::observe(
            *storage,
            test_key(),
            harness_root(harness) / "corrupt-marker",
            false);
    EXPECT_FALSE(marker_observation.has_value());

    auto fresh = open_transport(harness);
    ASSERT_TRUE(fresh.has_value());
    auto valid_reference = find_reference(*fresh, layout);
    ASSERT_TRUE(valid_reference.has_value());
    ASSERT_EQ(kasumi::transport::remove(
                  *fresh,
                  kasumi::application::history_storage::commit_object(
                      layout, *valid_reference))
                  .value(),
              kasumi::transport::Removal::Removed);
    auto missing_commit = kasumi::application::history_storage::load_history(
        *fresh, test_key(), harness_root(harness));
    EXPECT_FALSE(missing_commit.has_value());
}

TEST(RcloneSystemTest, CorruptedCommitCiphertextFailsClosed) {
    auto harness = make_rclone_harness();
    const auto layout = test_layout();
    auto client = make_test_client(harness, "client-a");
    create_profile_and_file(harness, client, "valid");
    ASSERT_TRUE(sync_client(client));

    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());
    auto reference = find_reference(*storage, layout);
    ASSERT_TRUE(reference.has_value());
    const auto before = kasumi::transport::list(*storage);
    ASSERT_TRUE(before.has_value());
    const auto commit_id =
        kasumi::application::history_storage::commit_object(layout, *reference);
    const auto commit_path = storage_root(harness) / commit_id;
    ASSERT_TRUE(std::filesystem::is_regular_file(commit_path)) << commit_path;
    kasumi::test::write_text(commit_path, "corrupt ciphertext");

    auto observed = kasumi::application::observation::history::observe(
        *storage, test_key(), harness_root(harness) / "corrupt-commit", false);
    EXPECT_FALSE(observed.has_value());
    auto after = kasumi::transport::list(*storage);
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(*after, *before);
}

TEST(RcloneSystemTest, ConflictAndAncestralCleanupPreserveConcurrentHead) {
    auto harness = make_rclone_harness();
    const auto layout = test_layout();
    auto client = make_test_client(harness, "client-a");
    create_profile_and_file(harness, client, "base");
    ASSERT_TRUE(sync_client(client));

    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());
    auto loaded =
        load_history(harness, harness_root(harness) / "conflict-base");
    ASSERT_EQ(loaded.marked_heads.size(), 1U);
    auto parent_reference = find_reference(*storage, layout);
    ASSERT_TRUE(parent_reference.has_value());
    const auto parent = loaded.marked_heads.front();
    const auto parent_commit = std::ranges::find(
        loaded.commits, parent, &kasumi::history::LoadedCommit::id);
    ASSERT_NE(parent_commit, loaded.commits.end());
    auto left = make_commit(
        parent_commit->commit.height + 1, {parent}, "shared.txt", "left");
    auto right = make_commit(
        parent_commit->commit.height + 1, {parent}, "shared.txt", "right");
    ASSERT_TRUE(left.has_value());
    ASSERT_TRUE(right.has_value());
    auto left_object = publish_staged(
        *storage, layout, *left, harness_root(harness) / "conflict-left");
    auto right_object = publish_staged(
        *storage, layout, *right, harness_root(harness) / "conflict-right");
    ASSERT_TRUE(left_object.has_value())
        << (left_object ? "" : left_object.error());
    ASSERT_TRUE(right_object.has_value())
        << (right_object ? "" : right_object.error());

    ensure_workspace(harness_root(harness) / "conflict-observe");
    auto observed = kasumi::application::observation::history::observe(
        *storage,
        test_key(),
        harness_root(harness) / "conflict-observe",
        false);
    ASSERT_TRUE(observed.has_value())
        << (observed ? "" : observed.error().detail);
    ASSERT_EQ(observed->logical_heads.size(), 2U);
    EXPECT_TRUE(observed->has_conflicts);

    ensure_workspace(harness_root(harness) / "conflict-prune");
    auto pruned =
        kasumi::application::sync::publication::prune_current_ancestral_markers(
            *storage, test_key(), harness_root(harness) / "conflict-prune");
    ASSERT_TRUE(pruned.has_value());
    EXPECT_EQ(kasumi::transport::presence(
                  *storage,
                  kasumi::application::history_storage::marker_object(
                      layout, left_object->head)),
              kasumi::transport::Presence::Present);
    EXPECT_EQ(kasumi::transport::presence(
                  *storage,
                  kasumi::application::history_storage::marker_object(
                      layout, right_object->head)),
              kasumi::transport::Presence::Present);
    EXPECT_EQ(kasumi::transport::presence(
                  *storage,
                  kasumi::application::history_storage::marker_object(
                      layout, *parent_reference)),
              kasumi::transport::Presence::Absent);
}

TEST(RcloneSystemTest, RcloneAndClientRestartPreserveHistory) {
    auto harness = make_rclone_harness();
    auto client = make_test_client(harness, "client-a");
    create_profile_and_file(harness, client, "restart");
    ASSERT_TRUE(sync_client(client));
    auto first = load_history(harness, harness_root(harness) / "restart-one");
    ASSERT_EQ(first.marked_heads.size(), 1U);

    {
        auto session = open_transport(harness);
        ASSERT_TRUE(session.has_value());
    }
    auto restarted = open_transport(harness);
    ASSERT_TRUE(restarted.has_value());
    ensure_workspace(harness_root(harness) / "restart-two");
    auto second = kasumi::application::history_storage::load_history(
        *restarted, test_key(), harness_root(harness) / "restart-two");
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second->marked_heads, first.marked_heads);
    ASSERT_TRUE(sync_client(client));
    EXPECT_EQ(kasumi::test::read_text(client.local_dir / "alpha.txt"),
              "restart");
}

TEST(RcloneSystemTest, RealCliUsesOnlyTheTemporaryEnvironment) {
    auto harness = make_rclone_harness();
    const auto xdg = harness_root(harness) / "cli-home";
#if defined(_WIN32)
    auto appdata = kasumi::test::scoped_environment_variable(
        "APPDATA", kasumi::platform::path::to_utf8(xdg));
#else
    auto appdata = kasumi::test::scoped_environment_variable(
        "XDG_CONFIG_HOME", kasumi::platform::path::to_utf8(xdg));
#endif
    const ExecutionEnvironment environment{.app_data_dir = xdg / "kasumi"};
    const auto local = harness_root(harness) / "client-b/cli-local";
    create_system_directory(xdg);
    ASSERT_TRUE(std::filesystem::create_directories(local));
    ASSERT_TRUE(kasumi::application::create_profile(
        environment,
        Profile{.name = std::string{profile_name},
                .local_dir = local,
                .remote_dir = remote_location(harness)},
        MasterKeyHex{std::string(64, '3')}));
    kasumi::test::write_text(local / "alpha.txt", "cli");

    const auto run_cli = [&]() {
        std::string output;
        std::string error;
        reproc::process process;
        reproc::options options;
        options.redirect.in.type = reproc::redirect::discard;
        options.redirect.out.type = reproc::redirect::pipe;
        options.redirect.err.type = reproc::redirect::pipe;
        const std::vector<std::string> arguments{
            kasumi::platform::path::to_utf8(
                std::filesystem::path{KASUMI_SYSTEM_KASUMI_EXECUTABLE}),
            "sync",
            std::string{profile_name}};
        if (const auto start_error =
                process.start(reproc::arguments{arguments}, options)) {
            ADD_FAILURE() << "could not start Kasumi CLI: "
                          << start_error.message();
            return false;
        }

        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds{30};
        std::array<std::uint8_t, 4096> buffer{};
        std::error_code failure;
        bool exited = false;
        int exit_code = -1;
        while (std::chrono::steady_clock::now() < deadline && !exited &&
               !failure) {
            const auto [events, poll_error] = process.poll(
                reproc::event::out | reproc::event::err | reproc::event::exit,
                reproc::milliseconds{100});
            if (poll_error) {
                if (poll_error != std::errc::timed_out) {
                    failure = poll_error;
                }
                continue;
            }

            const auto read_output = [&](reproc::stream stream,
                                         std::string& destination) {
                const auto [size, read_error] =
                    process.read(stream, buffer.data(), buffer.size());
                if (read_error) {
                    if (read_error != reproc::error::broken_pipe &&
                        read_error != std::errc::operation_would_block &&
                        read_error !=
                            std::errc::resource_unavailable_try_again) {
                        failure = read_error;
                    }
                    return;
                }
                destination.append(reinterpret_cast<const char*>(buffer.data()),
                                   size);
            };
            if ((events & reproc::event::out) != 0) {
                read_output(reproc::stream::out, output);
            }
            if ((events & reproc::event::err) != 0 && !failure) {
                read_output(reproc::stream::err, error);
            }
            if ((events & reproc::event::exit) != 0 && !failure) {
                const auto [status, wait_error] =
                    process.wait(reproc::milliseconds{0});
                if (wait_error) {
                    failure = wait_error;
                } else {
                    exit_code = status;
                    exited = true;
                }
            }
        }

        if (!exited || failure) {
            const auto stopped = process.stop(reproc::stop_actions{
                {reproc::stop::wait, reproc::milliseconds{0}},
                {reproc::stop::terminate, reproc::milliseconds{0}},
                {reproc::stop::kill, reproc::milliseconds{2000}}});
            ADD_FAILURE() << (failure ? "Kasumi CLI process failed: " +
                                            failure.message()
                                      : "Kasumi CLI timed out after 30 seconds")
                          << "; stop_error=" << stopped.second.message()
                          << "; stdout=" << output << "; stderr=" << error;
            return false;
        }
        EXPECT_EQ(exit_code, 0) << "stdout=" << output << " stderr=" << error;
        return exit_code == 0;
    };
    ASSERT_TRUE(run_cli());
    ASSERT_TRUE(run_cli());
    EXPECT_TRUE(
        std::filesystem::exists(xdg / "kasumi/profiles/demo/db.sqlite"));
}

TEST(RcloneSystemTest, RcloneBatchUploadPreservesDestinationIsolation) {
    auto harness = make_rclone_harness();
    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());

    const auto source_root = harness_root(harness) / "batch-upload";
    std::filesystem::create_directories(source_root);
    kasumi::transport::PutBatch batch{.source_root = source_root};

    // 1. Criar um objeto remoto preexistente OUTSIDE.
    const auto outside_identifier = "outside-object.txt";
    const auto outside_source = harness_root(harness) / "outside-upload";
    std::filesystem::create_directories(outside_source);
    kasumi::test::write_text(outside_source / outside_identifier,
                             "outside content");
    ASSERT_TRUE(kasumi::transport::put(*storage,
                                       outside_source / outside_identifier,
                                       outside_identifier)
                    .has_value());

    // 2. Criar um batch com dezenas de arquivos.
    for (int i = 0; i < 50; ++i) {
        auto identifier = "batch/file-" + std::to_string(i) + ".txt";
        std::filesystem::create_directories(
            (source_root / identifier).parent_path());
        kasumi::test::write_text(source_root / identifier,
                                 "content " + std::to_string(i));
        batch.identifiers.push_back(identifier);
    }

    // 3. Chamar put_batch().
    auto result = kasumi::transport::put_batch(*storage, batch);
    ASSERT_TRUE(result.has_value()) << result.error().message;

    // 4. Verificar isolamento de destino.
    // O rclone deveria colocar os arquivos no remote, que configuramos como
    // alias para "r". Se dstFs = "storage" incorreto for usado, ele
    // escreveria em "cwd-trap/storage".
    const auto cwd_trap_storage =
        harness_root(harness) / "cwd-trap" / "storage";
    EXPECT_FALSE(
        std::filesystem::exists(cwd_trap_storage / batch.identifiers[0]));

    const auto remote_backend_storage =
        harness_root(harness) / remote_backend / "storage";
    EXPECT_TRUE(
        std::filesystem::exists(remote_backend_storage / batch.identifiers[0]));

    // 5. Confirmar a presença de cada arquivo no storage (via API de
    // transport).
    for (const auto& identifier : batch.identifiers) {
        EXPECT_EQ(kasumi::transport::presence(*storage, identifier).value(),
                  kasumi::transport::Presence::Present);
    }

    // 6. Verificar conteúdo lendo diretamente pelo Transport
    const auto verify_dest = harness_root(harness) / "verify";
    ASSERT_TRUE(
        kasumi::transport::get(*storage, batch.identifiers[0], verify_dest)
            .has_value());
    EXPECT_EQ(kasumi::test::read_text(verify_dest), "content 0");

    // 7. Confirmar não-destruição: OUTSIDE ainda existe
    EXPECT_EQ(kasumi::transport::presence(*storage, outside_identifier).value(),
              kasumi::transport::Presence::Present);

    // 8. Idempotência: rodar de novo
    ASSERT_TRUE(kasumi::transport::put_batch(*storage, batch).has_value());

    const auto changed_source = source_root / batch.identifiers[0];
    const auto source_time = std::filesystem::last_write_time(changed_source);
    kasumi::test::write_text(changed_source, "changed 0");
    std::filesystem::last_write_time(changed_source, source_time);
    batch.max_parallel_transfers = 3;
    const auto replaced = kasumi::transport::put_batch(*storage, batch);
    ASSERT_TRUE(replaced) << kasumi::transport::describe(replaced.error());
    const auto listed = kasumi::transport::list(*storage, "batch");
    ASSERT_TRUE(listed);
    EXPECT_EQ(listed->size(), batch.identifiers.size());

    EXPECT_EQ(kasumi::transport::presence(*storage, outside_identifier).value(),
              kasumi::transport::Presence::Present);
    ASSERT_TRUE(
        kasumi::transport::get(*storage, batch.identifiers[0], verify_dest)
            .has_value());
    EXPECT_EQ(kasumi::test::read_text(verify_dest), "changed 0");
}

TEST(RcloneSystemTest, RcReadinessUsesPidWithoutVersionProbe) {
    auto harness = make_rclone_harness();
    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value()) << storage.error().message;
    storage = {};
}

TEST(RcloneSystemTest, WriterPhysicalHashAvoidsReadback) {
    auto harness = make_rclone_harness();
    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());
    const auto writer_workspace = harness_root(harness) / "writer-workspace";
    ASSERT_TRUE(std::filesystem::create_directories(writer_workspace));

    auto registration = kasumi::application::history_storage::
        maintenance_protocol::register_writer(
            *storage,
            kasumi::application::history_storage::derive_remote_layout(
                test_key()),
            writer_workspace);
    ASSERT_TRUE(registration.has_value()) << registration.error().detail;
    ASSERT_TRUE(kasumi::application::history_storage::maintenance_protocol::
                    release_registration(*registration));
}

// Query the real RC command table independently of the transport's result.
// Older supported releases verify publications with readback instead.
bool advertises_command(kasumi::transport::Transport& storage,
                        std::string_view command) {
    auto& state = *static_cast<kasumi::transport::rclone_detail::State*>(
        storage.state.get());
    const auto reply = kasumi::transport::rclone_detail::post_rc(
        state, "rc/list", "{}", 1024 * 1024, std::chrono::seconds{5});
    if (!reply) {
        throw std::runtime_error(reply.error().message);
    }
    const auto commands = nlohmann::json::parse(*reply).at("commands");
    return std::ranges::any_of(commands, [&](const auto& entry) {
        return entry.at("Path") == command;
    });
}

TEST(RcloneSystemTest, SinglePhysicalHashUsesHashsumfile) {
    auto harness = make_rclone_harness();
    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());

    const auto root = harness_root(harness) / "single-physical-hash";
    const auto source_root = root / "source";
    const auto plain_root = root / "plain";
    ASSERT_TRUE(std::filesystem::create_directories(source_root));
    ASSERT_TRUE(std::filesystem::create_directories(plain_root));
    const auto plain = plain_root / "single.plain";
    const auto identifier =
        kasumi::hash_hex(kasumi::hasher::hash_string("single-content"));
    const auto encrypted = source_root / identifier;
    kasumi::test::write_text(plain, "single-content");
    const auto prepared =
        kasumi::crypto::encrypt_file_with_hashes(plain, encrypted, test_key());
    ASSERT_TRUE(prepared.has_value());
    ASSERT_TRUE(kasumi::transport::put_batch(
        *storage,
        kasumi::transport::PutBatch{.source_root = source_root,
                                    .identifiers = {identifier}}));

    const auto verified =
        kasumi::transport::physical_hash(*storage, identifier, "sha256");
    if (!advertises_command(*storage, "operations/hashsumfile")) {
        ASSERT_FALSE(verified);
        EXPECT_EQ(verified.error().code,
                  kasumi::transport::ErrorCode::Unsupported);
        return;
    }
    ASSERT_TRUE(verified.has_value()) << verified.error().message;
    EXPECT_EQ(*verified, prepared->ciphertext_sha256);
}

TEST(RcloneSystemTest, BulkPhysicalHashUsesOneCheckManifest) {
    auto harness = make_rclone_harness();
    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());

    const auto root = harness_root(harness) / "bulk-physical-hash";
    const auto source_root = root / "source";
    const auto plain_root = root / "plain";
    ASSERT_TRUE(std::filesystem::create_directories(source_root));
    ASSERT_TRUE(std::filesystem::create_directories(plain_root));

    kasumi::transport::PutBatch batch{.source_root = source_root};
    kasumi::transport::PhysicalHashBatchRequest request{
        .scratch_root = source_root,
        .algorithm = "sha256",
    };
    for (std::size_t index = 0; index < 10; ++index) {
        const auto contents = "bulk-content-" + std::to_string(index);
        const auto plain = plain_root / (std::to_string(index) + ".plain");
        kasumi::test::write_text(plain, contents);
        const auto identifier =
            kasumi::hash_hex(kasumi::hasher::hash_string(contents));
        const auto encrypted = source_root / identifier;
        const auto prepared = kasumi::crypto::encrypt_file_with_hashes(
            plain, encrypted, test_key());
        ASSERT_TRUE(prepared.has_value());
        batch.identifiers.push_back(identifier);
        request.objects.push_back({identifier, prepared->ciphertext_sha256});
    }

    ASSERT_TRUE(kasumi::transport::put_batch(*storage, batch));
    const auto verified =
        kasumi::transport::physical_hash_batch(*storage, request);
    if (!advertises_command(*storage, "operations/check")) {
        ASSERT_FALSE(verified);
        EXPECT_EQ(verified.error().code,
                  kasumi::transport::ErrorCode::Unsupported);
        return;
    }
    ASSERT_TRUE(verified.has_value()) << verified.error().message;
    EXPECT_TRUE(verified->mismatched.empty());
    EXPECT_TRUE(verified->missing.empty());
    EXPECT_TRUE(verified->errors.empty());
    EXPECT_FALSE(
        std::filesystem::exists(source_root / ".kasumi-batch-verify.sha256"));
    EXPECT_FALSE(
        std::filesystem::exists(source_root / ".kasumi-batch-verify.files"));

    ASSERT_TRUE(
        kasumi::transport::remove(*storage, request.objects[0].identifier));
    const auto corrupt = plain_root / "corrupt";
    kasumi::test::write_text(corrupt, "corrupted ciphertext");
    ASSERT_TRUE(kasumi::transport::put(
        *storage, corrupt, request.objects[1].identifier));
    const auto damaged =
        kasumi::transport::physical_hash_batch(*storage, request);
    ASSERT_TRUE(damaged.has_value()) << damaged.error().message;
    EXPECT_EQ(damaged->missing,
              (std::vector<std::string>{request.objects[0].identifier}));
    EXPECT_EQ(damaged->mismatched,
              (std::vector<std::string>{request.objects[1].identifier}));
    EXPECT_EQ(damaged->matched.size(), request.objects.size() - 2);
    EXPECT_TRUE(damaged->errors.empty());
}

TEST(RcloneSystemTest,
     RepackConsolidatesLooseFilesOverRealRcloneAndSupportsEnroll) {
    auto harness = make_rclone_harness();
    auto client_a = make_test_client(harness, "client-a");
    auto client_b = make_test_client(harness, "client-b");
    auto client_c = make_test_client(harness, "client-c");
    create_profile(harness, client_a);
    create_profile(harness, client_b);
    create_profile(harness, client_c);

    const auto write_settled = [](const std::filesystem::path& path,
                                  std::string_view text) {
        kasumi::test::write_text(path, text);
        const auto settled = std::filesystem::file_time_type::clock::now() -
                             std::chrono::seconds{2};
        ASSERT_TRUE(
            kasumi::platform::metadata::set_last_write_time(path, settled));
    };

    const std::string payload_one = "first small payload over rclone";
    const std::string payload_two = "second small payload over rclone";
    write_settled(client_a.local_dir / "one.txt", payload_one);
    ASSERT_TRUE(sync_client(client_a));
    write_settled(client_a.local_dir / "two.txt", payload_two);
    ASSERT_TRUE(sync_client(client_a));

    ASSERT_TRUE(sync_client(client_b));
    EXPECT_EQ(kasumi::test::read_text(client_b.local_dir / "one.txt"),
              payload_one);
    EXPECT_EQ(kasumi::test::read_text(client_b.local_dir / "two.txt"),
              payload_two);

    const auto dry_run = kasumi::application::execute(
        {Request{.operation = Operation::Repack,
                 .profile_name = std::string{profile_name},
                 .dry_run = true},
         Credentials{NoCredentials{}},
         client_a.environment});
    ASSERT_TRUE(dry_run.has_value()) << dry_run.error().detail;
    const auto* dry_data =
        std::get_if<kasumi::application::RepackCompleted>(&dry_run->data);
    ASSERT_NE(dry_data, nullptr);
    EXPECT_TRUE(dry_data->dry_run);
    EXPECT_TRUE(dry_data->actionable);
    EXPECT_FALSE(dry_data->published);
    EXPECT_EQ(dry_data->source_loose_blobs, 2U);
    EXPECT_EQ(dry_data->new_packs, 1U);
    EXPECT_EQ(dry_data->wire_upload_bytes, 0U);
    EXPECT_EQ(dry_data->physical_objects_uploaded, 0U);

    const auto repacked = kasumi::application::execute(
        {Request{.operation = Operation::Repack,
                 .profile_name = std::string{profile_name}},
         Credentials{NoCredentials{}},
         client_a.environment});
    ASSERT_TRUE(repacked.has_value()) << repacked.error().detail;
    const auto* repack_data =
        std::get_if<kasumi::application::RepackCompleted>(&repacked->data);
    ASSERT_NE(repack_data, nullptr);
    EXPECT_FALSE(repack_data->dry_run);
    EXPECT_TRUE(repack_data->actionable);
    EXPECT_TRUE(repack_data->published);
    EXPECT_EQ(repack_data->source_loose_blobs, 2U);
    EXPECT_EQ(repack_data->new_packs, 1U);
    EXPECT_EQ(repack_data->repacked_blobs, 2U);
    EXPECT_GT(repack_data->wire_upload_bytes, 0U);
    EXPECT_GT(repack_data->physical_objects_uploaded, 0U);
    EXPECT_FALSE(repack_data->published_commit_id.empty());

    const auto noop = kasumi::application::execute(
        {Request{.operation = Operation::Repack,
                 .profile_name = std::string{profile_name}},
         Credentials{NoCredentials{}},
         client_a.environment});
    ASSERT_TRUE(noop.has_value()) << noop.error().detail;
    const auto* noop_data =
        std::get_if<kasumi::application::RepackCompleted>(&noop->data);
    ASSERT_NE(noop_data, nullptr);
    EXPECT_FALSE(noop_data->actionable);
    EXPECT_FALSE(noop_data->published);

    ASSERT_TRUE(sync_client(client_b));
    EXPECT_EQ(kasumi::test::read_text(client_b.local_dir / "one.txt"),
              payload_one);
    EXPECT_EQ(kasumi::test::read_text(client_b.local_dir / "two.txt"),
              payload_two);

    ASSERT_TRUE(sync_client(client_c));
    EXPECT_EQ(kasumi::test::read_text(client_c.local_dir / "one.txt"),
              payload_one);
    EXPECT_EQ(kasumi::test::read_text(client_c.local_dir / "two.txt"),
              payload_two);

    const auto audited = kasumi::application::execute(
        {Request{.operation = Operation::Fsck,
                 .profile_name = std::string{profile_name}},
         Credentials{NoCredentials{}},
         client_a.environment});
    ASSERT_TRUE(audited.has_value()) << audited.error().detail;
}

TEST(RcloneSystemTest, WarmTransportStaysHealthyAfterIdleAndShutsDownCleanly) {
    auto harness = make_rclone_harness();
    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value()) << storage.error().message;
    ASSERT_TRUE(kasumi::transport::check_health(*storage).has_value());

    const auto src_dir = harness_root(harness) / "warm-idle-src";
    const auto dst_dir = harness_root(harness) / "warm-idle-dst";
    std::filesystem::create_directories(src_dir);
    std::filesystem::create_directories(dst_dir);

    for (int cycle = 0; cycle < 3; ++cycle) {
        std::this_thread::sleep_for(std::chrono::milliseconds{400});
        const auto health = kasumi::transport::check_health(*storage);
        ASSERT_TRUE(health.has_value())
            << "cycle " << cycle << ": " << health.error().message;

        const std::string id =
            "warm-idle/item-" + std::to_string(cycle) + ".txt";
        const std::string payload = "warm-payload-" + std::to_string(cycle);
        kasumi::test::write_text(src_dir / ("in-" + std::to_string(cycle)),
                                 payload);
        const auto put_res = kasumi::transport::put(
            *storage, src_dir / ("in-" + std::to_string(cycle)), id);
        ASSERT_TRUE(put_res.has_value()) << put_res.error().message;

        const auto listed = kasumi::transport::list(*storage);
        ASSERT_TRUE(listed.has_value()) << listed.error().message;
        EXPECT_TRUE(std::ranges::contains(*listed, id));

        const auto pres = kasumi::transport::presence(*storage, id);
        ASSERT_TRUE(pres.has_value()) << pres.error().message;
        EXPECT_EQ(*pres, kasumi::transport::Presence::Present);

        const auto out_file = dst_dir / ("out-" + std::to_string(cycle));
        const auto get_res = kasumi::transport::get(*storage, id, out_file);
        ASSERT_TRUE(get_res.has_value()) << get_res.error().message;
        EXPECT_EQ(kasumi::test::read_text(out_file), payload);

        const auto rm_res = kasumi::transport::remove(*storage, id);
        ASSERT_TRUE(rm_res.has_value()) << rm_res.error().message;
    }

    const auto started_shutdown = std::chrono::steady_clock::now();
    *storage = kasumi::transport::Transport{};
    const auto elapsed = std::chrono::steady_clock::now() - started_shutdown;
    EXPECT_LT(elapsed, std::chrono::seconds{5});
}

TEST(RcloneSystemTest, ShutdownWithoutCoreQuitCompletesBoundedWithoutHanging) {
    auto harness = make_rclone_harness();
    const auto config_path = harness_path(harness, "rclone.conf");

    for (int iteration = 0; iteration < 5; ++iteration) {
        const auto probe = kasumi::transport::probe_rclone_installation();
        EXPECT_TRUE(probe.found) << probe.detail;
        EXPECT_TRUE(probe.meets_minimum) << probe.detail;
        const auto remotes =
            kasumi::transport::list_rclone_remotes({}, config_path);
        EXPECT_TRUE(remotes.available) << remotes.detail;
        EXPECT_TRUE(
            std::ranges::contains(remotes.remotes, std::string{remote_name}));
    }

    kasumi::transport::detail::RcloneConfiguration configuration{
        .remote_name = std::string{remote_name},
        .remote_root = std::string{remote_root},
        .executable = std::filesystem::path{KASUMI_SYSTEM_RCLONE_EXECUTABLE},
        .config_path = config_path};
    auto started = kasumi::transport::rclone_detail::start_state(configuration);
    ASSERT_TRUE(started.has_value()) << started.error().message;
    auto* state = *started;
    ASSERT_NE(state, nullptr);
    ASSERT_TRUE(
        kasumi::transport::rclone_detail::check_rc_health(*state).has_value());

#if defined(_WIN32)
    HANDLE check_handle =
        OpenProcess(SYNCHRONIZE, FALSE, static_cast<DWORD>(state->child_pid));
    ASSERT_NE(check_handle, nullptr);
#endif

    // Simulate a state where core/quit is skipped while rclone is still alive.
    state->ready = false;
    const auto started_shutdown = std::chrono::steady_clock::now();
    kasumi::transport::rclone_detail::destroy_state(state);
    const auto elapsed = std::chrono::steady_clock::now() - started_shutdown;
    EXPECT_LT(elapsed, std::chrono::seconds{5});

#if defined(_WIN32)
    const DWORD wait_result = WaitForSingleObject(check_handle, 2000);
    CloseHandle(check_handle);
    EXPECT_EQ(wait_result, WAIT_OBJECT_0);
#endif
}

TEST(RcloneSystemTest,
     DaemonWarmRcloneSessionSurvivesIdleMutationsAndStopsCleanly) {
    using namespace std::chrono_literals;
    namespace app = kasumi::application;

    auto harness = make_rclone_harness();
    const auto client = make_test_client(harness, "client-a");
    ASSERT_TRUE(
        app::create_profile(client.environment,
                            Profile{.name = std::string{profile_name},
                                    .local_dir = client.local_dir,
                                    .remote_dir = remote_location(harness),
                                    .sync_interval_seconds = 10U},
                            MasterKeyHex{std::string(64, '2')}));
    kasumi::test::write_text(client.local_dir / "seed.md", "seed-content");

    app::DaemonOptions opts;
    opts.watch_debounce = 150ms;
    opts.watch_max_wait = 600ms;
    opts.config_poll_interval = 200ms;
    opts.full_scan_verification_interval = 10min;
    opts.enable_ipc_server = false;

    auto session = app::start_daemon_session(client.environment, opts);
    ASSERT_TRUE(session.has_value()) << session.error().detail;

    const auto wait_for = [&](auto pred, std::chrono::milliseconds timeout) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            if (pred()) {
                return true;
            }
            std::this_thread::sleep_for(50ms);
        }
        return pred();
    };

    const auto profile_status =
        [&]() -> std::optional<app::DaemonProfileStatus> {
        const auto rep =
            app::query_daemon_session_status(*session, profile_name);
        if (!rep || rep->profiles.empty()) {
            return std::nullopt;
        }
        return rep->profiles.front();
    };

    ASSERT_TRUE(wait_for(
        [&] {
            const auto st = profile_status();
            return st && st->state == app::DaemonProfileState::Idle &&
                   st->sync_runs >= 1U && st->warm_transport_active &&
                   st->watcher_active;
        },
        30s));

    // Wait past the 10s sync interval so timer-driven fast_noop executes
    // while keeping warm rclone alive.
    ASSERT_TRUE(wait_for(
        [&] {
            const auto st = profile_status();
            return st && st->fast_noop_polls >= 1U && st->warm_transport_active;
        },
        25s));

    auto wait_sync_delta = [&](std::uint64_t baseline) {
        return wait_for(
            [&] {
                const auto st = profile_status();
                return st && st->sync_runs > baseline &&
                       st->state == app::DaemonProfileState::Idle &&
                       st->dirty_paths_count == 0U;
            },
            30s);
    };

    // Create -> edit -> rename -> delete driven solely by native FS watcher.
    const auto s0 = profile_status()->sync_runs;
    kasumi::test::write_text(client.local_dir / "note-1.md", "v1");
    ASSERT_TRUE(wait_sync_delta(s0));

    const auto s1 = profile_status()->sync_runs;
    kasumi::test::write_text(client.local_dir / "note-1.md", "v2-edited");
    ASSERT_TRUE(wait_sync_delta(s1));

    const auto s2 = profile_status()->sync_runs;
    std::filesystem::rename(client.local_dir / "note-1.md",
                            client.local_dir / "note-2.md");
    ASSERT_TRUE(wait_sync_delta(s2));

    const auto s3 = profile_status()->sync_runs;
    std::filesystem::remove(client.local_dir / "note-2.md");
    ASSERT_TRUE(wait_sync_delta(s3));

    const auto final_st = profile_status();
    ASSERT_TRUE(final_st.has_value());
    EXPECT_TRUE(final_st->warm_transport_active);
    EXPECT_NE(final_st->state, app::DaemonProfileState::NeedsAttention);

    const auto started_stop = std::chrono::steady_clock::now();
    app::stop_daemon_session(*session);
    const auto stop_elapsed = std::chrono::steady_clock::now() - started_stop;
    EXPECT_LT(stop_elapsed, 5s);
    session->state.reset();
}

} // namespace
