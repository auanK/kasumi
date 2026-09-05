#include "application/execute.hpp"
#include "application/history_storage/content_reachability.hpp"
#include "application/history_storage/detail.hpp"
#include "application/history_storage/history_storage.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/publication.hpp"
#include "application/history_storage/reachability.hpp"
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
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "runtime/paths.hpp"
#include "runtime/resolver.hpp"
#include "state_storage/database.hpp"
#include "transport/detail.hpp"
#include "transport/rclone/detail.hpp"
#include "transport/transport.hpp"

#include <array>
#include <chrono>
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
#include <utility>
#include <vector>

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
constexpr std::string_view remote_name = "kasumi-test";
constexpr std::string_view remote_root = "storage";
constexpr std::string_view remote_backend = "r";
constexpr std::string_view profile_name = "demo";

std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> test_key() {
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    key.fill(0x22U);
    return key;
}

kasumi::Snapshot tree_with(std::string_view path,
                           std::string_view contents,
                           std::filesystem::file_time_type mtime = {}) {
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

kasumi::history::CommitResult
make_commit(std::uint64_t height,
            std::vector<std::string> parents,
            std::string_view path,
            std::string_view contents,
            std::filesystem::file_time_type mtime = {}) {
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
    kasumi::test::TempWorkspace workspace;
    CurrentDirectory current_directory{nullptr, restore_current_directory};
    kasumi::test::ScopedEnvironmentVariable rclone_config{
        nullptr, kasumi::test::restore_environment_variable};
    kasumi::test::ScopedEnvironmentVariable rclone_cache{
        nullptr, kasumi::test::restore_environment_variable};
};

const std::filesystem::path&
harness_root(const RcloneHarness& harness) noexcept {
    return kasumi::test::workspace_root(harness.workspace);
}

std::filesystem::path storage_root(const RcloneHarness& harness) {
    return kasumi::test::workspace_path(harness.workspace, remote_backend) /
           remote_root;
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
        .config_path =
            kasumi::test::workspace_path(harness.workspace, "rclone.conf")};
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
    const auto base =
        kasumi::test::workspace_path(harness.workspace, std::string{name});
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
    auto workspace = kasumi::test::make_temp_workspace("system-rclone");

    for (const std::string_view path : {"cwd-trap",
                                        "r",
                                        "r/storage",
                                        "rclone-cache",
                                        "client-a/app-data",
                                        "client-a/local",
                                        "client-b/app-data",
                                        "client-b/local",
                                        "client-c/app-data",
                                        "client-c/local"}) {
        create_system_directory(kasumi::test::workspace_path(workspace, path));
    }

    auto current_directory = use_current_directory(
        kasumi::test::workspace_path(workspace, "cwd-trap"));
    auto rclone_config = kasumi::test::scoped_environment_variable(
        "RCLONE_CONFIG",
        kasumi::platform::path::to_utf8(
            kasumi::test::workspace_path(workspace, "rclone.conf")));
    auto rclone_cache = kasumi::test::scoped_environment_variable(
        "RCLONE_CACHE_DIR",
        kasumi::platform::path::to_utf8(
            kasumi::test::workspace_path(workspace, "rclone-cache")));

    std::ofstream config(
        kasumi::test::workspace_path(workspace, "rclone.conf"));
    if (!config) {
        throw std::runtime_error("could not create temporary rclone.conf");
    }
    config << "[kasumi-test]\n"
           << "type = alias\n"
           << "remote = "
           << kasumi::platform::path::to_logical_utf8(
                  kasumi::test::workspace_path(workspace, remote_backend))
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
find_reference(kasumi::transport::Transport& storage) {
    auto listing = kasumi::transport::list(storage);
    if (!listing) {
        return std::unexpected(kasumi::transport::describe(listing.error()));
    }
    for (const auto& identifier : *listing) {
        if (const auto reference =
                kasumi::application::history_storage::parse_marker_object(
                    identifier)) {
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
               const kasumi::history::Commit& commit,
               const std::filesystem::path& workspace) {
    std::error_code directory_error;
    std::filesystem::create_directories(workspace, directory_error);
    if (directory_error) {
        return std::unexpected(directory_error.message());
    }
    auto object = kasumi::application::history_storage::publish_commit_object(
        storage, test_key(), commit, workspace);
    if (!object) {
        return std::unexpected(object.error().detail);
    }
    auto verified = kasumi::application::history_storage::verify_commit_object(
        storage, test_key(), commit, object->head, workspace);
    if (!verified) {
        return std::unexpected(verified.error().detail);
    }
    auto marker = kasumi::application::history_storage::publish_head_marker(
        storage, object->head, workspace);
    if (!marker) {
        return std::unexpected(marker.error().detail);
    }
    auto marker_verified =
        kasumi::application::history_storage::verify_head_marker(
            storage, object->head, workspace);
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
        .config_path =
            kasumi::test::workspace_path(harness.workspace, "rclone.conf")};
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
    const auto& http = options.at("rc").at("HTTP");
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
        .config_path =
            kasumi::test::workspace_path(harness.workspace, "rclone.conf")};
    auto started = kasumi::transport::rclone_detail::start_state(configuration);
    ASSERT_TRUE(started.has_value())
        << (started ? "" : started.error().message);
    const auto state = std::unique_ptr<kasumi::transport::rclone_detail::State,
                                       void (*)(void*)>{
        *started, kasumi::transport::rclone_detail::destroy_state};
    {
        std::lock_guard lock(state->process_mutex);
        const auto stopped = state->process.stop(reproc::stop_actions{
            {reproc::stop::kill, reproc::milliseconds(2000)}});
        ASSERT_FALSE(stopped.second);
        state->process_started = false;
    }

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

TEST(RcloneSystemTest, BootstrapAndSecondClientUseOneImmutableHead) {
    auto harness = make_rclone_harness();
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
    EXPECT_EQ(std::ranges::count_if(*identifiers,
                                    [](const auto& id) {
                                        return id.starts_with(
                                            "history/commits/");
                                    }),
              1);
    EXPECT_EQ(std::ranges::count_if(*identifiers,
                                    [](const auto& id) {
                                        return id.starts_with("history/heads/");
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
    auto checkpoint_a = kasumi::state_storage::load_observation_checkpoint(
        runtime_a->database_path);
    ASSERT_TRUE(checkpoint_a && *checkpoint_a);
    EXPECT_EQ((*checkpoint_a)->tree_root_hash,
              (*state_a)->tree.rows.front().hash);
    ASSERT_TRUE(sync_client(client_b));

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
    auto published = publish_staged(
        *storage, *orphan, harness_root(harness) / "reachability-orphan");
    ASSERT_TRUE(published.has_value());
    ASSERT_EQ(kasumi::transport::remove(
                  *storage,
                  kasumi::application::history_storage::marker_object(
                      published->head))
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
    auto client = make_test_client(harness, "client-a");
    create_profile_and_file(harness, client, "alpha");
    ASSERT_TRUE(sync_client(client));

    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());
    auto before = kasumi::transport::list(*storage);
    ASSERT_TRUE(before.has_value());
    const auto reference = find_reference(*storage);
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
    EXPECT_EQ(std::ranges::count_if(*before,
                                    [](const auto& id) {
                                        return id.starts_with(
                                            "history/commits/");
                                    }),
              std::ranges::count_if(*after, [](const auto& id) {
                  return id.starts_with("history/commits/");
              }));
    EXPECT_EQ(std::ranges::count_if(*before,
                                    [](const auto& id) {
                                        return id.starts_with("history/heads/");
                                    }),
              std::ranges::count_if(*after, [](const auto& id) {
                  return id.starts_with("history/heads/");
              }));
    EXPECT_EQ(find_reference(*storage), reference);

    const auto fsck = kasumi::application::execute(
        {Request{Operation::Fsck, std::string{profile_name}},
         Credentials{NoCredentials{}},
         client.environment});
    ASSERT_FALSE(fsck.has_value());
    EXPECT_EQ(fsck.error().code, kasumi::application::ErrorCode::FsckFailure);

    auto receiver = make_test_client(harness, "client-b");
    create_profile(harness, receiver);
    const auto required = sync_client(receiver);
    ASSERT_FALSE(required.has_value());
    EXPECT_EQ(required.error().code,
              kasumi::application::ErrorCode::SynchronizationFailure);
}

TEST(RcloneSystemTest, CommitObjectAndMarkerStagesAreIndependent) {
    auto harness = make_rclone_harness();
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
        *storage, test_key(), *next, harness_root(harness) / "stages");
    ASSERT_TRUE(object.has_value());
    ASSERT_TRUE(kasumi::application::history_storage::verify_commit_object(
        *storage,
        test_key(),
        *next,
        object->head,
        harness_root(harness) / "stages"));
    auto marker_state =
        kasumi::application::history_storage::inspect_head_marker(
            *storage, object->head, harness_root(harness) / "stages");
    ASSERT_TRUE(marker_state.has_value());
    EXPECT_EQ(*marker_state,
              kasumi::application::history_storage::HeadMarkerState::Absent);

    auto listing_before_marker = kasumi::transport::list(*storage);
    ASSERT_TRUE(listing_before_marker.has_value());
    EXPECT_EQ(std::ranges::count_if(*listing_before_marker,
                                    [](const auto& id) {
                                        return id.starts_with("history/heads/");
                                    }),
              1);

    ASSERT_TRUE(kasumi::application::history_storage::publish_head_marker(
                    *storage, object->head, harness_root(harness) / "stages")
                    .has_value());
    ASSERT_TRUE(kasumi::application::history_storage::verify_head_marker(
        *storage, object->head, harness_root(harness) / "stages"));

    auto reused = kasumi::application::history_storage::publish_commit_object(
        *storage, test_key(), *next, harness_root(harness) / "stages");
    ASSERT_TRUE(reused.has_value());
    EXPECT_TRUE(reused->reused_existing_ciphertext);
    EXPECT_EQ(reused->head, object->head);
    ASSERT_TRUE(kasumi::application::history_storage::publish_head_marker(
                    *storage, object->head, harness_root(harness) / "stages")
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
    const auto alpha_mtime = std::filesystem::last_write_time(
        reconciler.local_dir / "alpha.txt", mtime_error);
    ASSERT_FALSE(mtime_error);
    const auto beta_mtime = std::filesystem::last_write_time(
        reconciler.local_dir / "beta.txt", mtime_error);
    ASSERT_FALSE(mtime_error);
    const auto gamma_mtime = std::filesystem::last_write_time(
        reconciler.local_dir / "gamma.txt", mtime_error);
    ASSERT_FALSE(mtime_error);

    auto branch_a = make_commit(base->commit.height + 1,
                                {base_id},
                                "alpha.txt",
                                "branch-a",
                                alpha_mtime);
    auto branch_b = make_commit(
        base->commit.height + 1, {base_id}, "beta.txt", "branch-b", beta_mtime);
    auto branch_c = make_commit(base->commit.height + 1,
                                {base_id},
                                "gamma.txt",
                                "branch-c",
                                gamma_mtime);
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
            publisher, commit, harness_root(harness) / workspace);
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

TEST(RcloneSystemTest,
     GarbageCollectionQuarantinesThenPurgesThroughRealTransport) {
    auto harness = make_rclone_harness();
    auto client = make_test_client(harness, "gc-client");
    create_profile_and_file(harness, client, "live");
    ASSERT_TRUE(sync_client(client));

    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());
    const auto orphan = put_content_blob(
        *storage, harness_root(harness), "orphan", "gc-orphan");
    const auto quarantined = kasumi::application::history_storage::
        maintenance_protocol::quarantine_identifier(orphan);
    ASSERT_TRUE(quarantined.has_value());

    auto collected = kasumi::application::execute(
        {Request{Operation::GarbageCollect, std::string{profile_name}},
         Credentials{NoCredentials{}},
         client.environment});
    ASSERT_TRUE(collected.has_value())
        << (collected ? "" : collected.error().detail);
    const auto* first =
        std::get_if<kasumi::application::GarbageCollectCompleted>(
            &collected->data);
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(first->quarantined_objects, 1U);
    EXPECT_EQ(first->purged_objects, 0U);
    EXPECT_EQ(kasumi::transport::presence(*storage, orphan).value(),
              kasumi::transport::Presence::Absent);
    EXPECT_EQ(kasumi::transport::presence(*storage, *quarantined).value(),
              kasumi::transport::Presence::Present);

    const auto now = kasumi::platform::clock::unix_seconds();
    ASSERT_TRUE(now.has_value()) << now.error();
    const auto aged = kasumi::application::history_storage::
        maintenance_protocol::record_quarantine(
            *storage,
            *quarantined,
            *now -
                kasumi::application::history_storage::maintenance_protocol::
                    quarantine_retention_seconds -
                1,
            test_key(),
            harness_root(harness));
    ASSERT_TRUE(aged.has_value()) << (aged ? "" : aged.error().detail);

    auto purged = kasumi::application::execute(
        {Request{Operation::GarbageCollect, std::string{profile_name}},
         Credentials{NoCredentials{}},
         client.environment});
    ASSERT_TRUE(purged.has_value()) << (purged ? "" : purged.error().detail);
    const auto* second =
        std::get_if<kasumi::application::GarbageCollectCompleted>(
            &purged->data);
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(second->quarantined_objects, 0U);
    EXPECT_EQ(second->purged_objects, 1U);
    EXPECT_EQ(kasumi::transport::presence(*storage, *quarantined).value(),
              kasumi::transport::Presence::Absent);
    EXPECT_EQ(kasumi::transport::presence(*storage, aged->metadata_identifier)
                  .value(),
              kasumi::transport::Presence::Absent);
}

TEST(RcloneSystemTest, ReadvertisedHeadRestoresQuarantinedCommitAndContent) {
    auto harness = make_rclone_harness();
    auto publisher = make_test_client(harness, "recovery-publisher");
    auto receiver = make_test_client(harness, "recovery-receiver");
    create_profile_and_file(harness, publisher, "base");
    create_profile(harness, receiver);
    ASSERT_TRUE(sync_client(publisher));

    auto loaded =
        load_history(harness, harness_root(harness) / "recovery-history");
    ASSERT_EQ(loaded.marked_heads.size(), 1U);
    const auto base_id = loaded.marked_heads.front();
    const auto base = std::ranges::find(
        loaded.commits, base_id, &kasumi::history::LoadedCommit::id);
    ASSERT_NE(base, loaded.commits.end());

    const std::string_view recovered_contents = "recovered";
    std::string content_id;
    std::string commit_object;
    HeadReference recovered_head;
    auto recovered_tree = base->commit.tree;
    recovered_tree.rows.push_back(
        kasumi::NodeRow{.path = "recovered.txt",
                        .hash = kasumi::hasher::hash_string(recovered_contents),
                        .size = recovered_contents.size(),
                        .is_directory = false});
    kasumi::finalize_snapshot(recovered_tree);
    auto recovered_commit =
        kasumi::history::make_commit(base->commit.height + 1,
                                     {base_id},
                                     std::move(recovered_tree),
                                     2'000'000'000LL);
    ASSERT_TRUE(recovered_commit.has_value());
    {
        auto storage = open_transport(harness);
        ASSERT_TRUE(storage.has_value());
        content_id = put_content_blob(*storage,
                                      harness_root(harness),
                                      recovered_contents,
                                      "recovery-content");
        const auto published =
            publish_staged(*storage,
                           *recovered_commit,
                           harness_root(harness) / "recovery-publish");
        ASSERT_TRUE(published.has_value())
            << (published ? "" : published.error());
        recovered_head = published->head;
        commit_object =
            kasumi::application::history_storage::detail::commit_object(
                recovered_head);
        const auto marker =
            kasumi::application::history_storage::marker_object(recovered_head);
        ASSERT_EQ(kasumi::transport::remove(*storage, marker).value(),
                  kasumi::transport::Removal::Removed);
    }

    auto collected = kasumi::application::execute(
        {Request{Operation::GarbageCollect, std::string{profile_name}},
         Credentials{NoCredentials{}},
         publisher.environment});
    ASSERT_TRUE(collected.has_value())
        << (collected ? "" : collected.error().detail);
    const auto* first =
        std::get_if<kasumi::application::GarbageCollectCompleted>(
            &collected->data);
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(first->quarantined_objects, 2U);
    {
        auto storage = open_transport(harness);
        ASSERT_TRUE(storage.has_value());
        EXPECT_EQ(kasumi::transport::presence(*storage, commit_object).value(),
                  kasumi::transport::Presence::Absent);
        EXPECT_EQ(kasumi::transport::presence(*storage, content_id).value(),
                  kasumi::transport::Presence::Absent);
        ensure_workspace(harness_root(harness) / "recovery-readvertise");
        const auto advertised =
            kasumi::application::history_storage::publish_head_marker(
                *storage,
                recovered_head,
                harness_root(harness) / "recovery-readvertise");
        ASSERT_TRUE(advertised.has_value())
            << (advertised ? "" : advertised.error().detail);
    }

    auto restored = kasumi::application::execute(
        {Request{Operation::GarbageCollect, std::string{profile_name}},
         Credentials{NoCredentials{}},
         publisher.environment});
    ASSERT_TRUE(restored.has_value())
        << (restored ? "" : restored.error().detail);
    const auto* second =
        std::get_if<kasumi::application::GarbageCollectCompleted>(
            &restored->data);
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(second->restored_objects, 2U);
    EXPECT_EQ(second->purged_objects, 0U);

    auto synchronized = sync_client(receiver);
    ASSERT_TRUE(synchronized)
        << (synchronized ? "" : synchronized.error().detail);
    EXPECT_EQ(kasumi::test::read_text(receiver.local_dir / "recovered.txt"),
              recovered_contents);
}

TEST(RcloneSystemTest, ConcurrentPublishersAndMaterializersRemainSafe) {
    auto harness = make_rclone_harness();
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
            storage, commit, harness_root(harness) / workspace);
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
    auto client = make_test_client(harness, "client-a");
    create_profile_and_file(harness, client, "valid");
    ASSERT_TRUE(sync_client(client));

    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());
    auto reference = find_reference(*storage);
    ASSERT_TRUE(reference.has_value());
    kasumi::test::write_text(
        storage_root(harness) /
            std::filesystem::path{
                kasumi::application::history_storage::marker_object(
                    *reference)},
        "corrupt marker");
    auto marker_observation =
        kasumi::application::observation::history::observe(
            *storage,
            test_key(),
            harness_root(harness) / "corrupt-marker",
            false);
    EXPECT_FALSE(marker_observation.has_value());

    auto fresh = open_transport(harness);
    ASSERT_TRUE(fresh.has_value());
    auto valid_reference = find_reference(*fresh);
    ASSERT_TRUE(valid_reference.has_value());
    ASSERT_EQ(kasumi::transport::remove(
                  *fresh,
                  kasumi::application::history_storage::detail::commit_object(
                      *valid_reference))
                  .value(),
              kasumi::transport::Removal::Removed);
    auto missing_commit = kasumi::application::history_storage::load_history(
        *fresh, test_key(), harness_root(harness));
    EXPECT_FALSE(missing_commit.has_value());
}

TEST(RcloneSystemTest, CorruptedCommitCiphertextFailsClosed) {
    auto harness = make_rclone_harness();
    auto client = make_test_client(harness, "client-a");
    create_profile_and_file(harness, client, "valid");
    ASSERT_TRUE(sync_client(client));

    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());
    auto reference = find_reference(*storage);
    ASSERT_TRUE(reference.has_value());
    const auto before = kasumi::transport::list(*storage);
    ASSERT_TRUE(before.has_value());
    kasumi::test::write_text(
        storage_root(harness) /
            std::filesystem::path{
                kasumi::application::history_storage::detail::commit_object(
                    *reference)},
        "corrupt ciphertext");

    auto observed = kasumi::application::observation::history::observe(
        *storage, test_key(), harness_root(harness) / "corrupt-commit", false);
    EXPECT_FALSE(observed.has_value());
    auto after = kasumi::transport::list(*storage);
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(*after, *before);
}

TEST(RcloneSystemTest, ConflictAndAncestralCleanupPreserveConcurrentHead) {
    auto harness = make_rclone_harness();
    auto client = make_test_client(harness, "client-a");
    create_profile_and_file(harness, client, "base");
    ASSERT_TRUE(sync_client(client));

    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());
    auto loaded =
        load_history(harness, harness_root(harness) / "conflict-base");
    ASSERT_EQ(loaded.marked_heads.size(), 1U);
    auto parent_reference = find_reference(*storage);
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
        *storage, *left, harness_root(harness) / "conflict-left");
    auto right_object = publish_staged(
        *storage, *right, harness_root(harness) / "conflict-right");
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
                      left_object->head)),
              kasumi::transport::Presence::Present);
    EXPECT_EQ(kasumi::transport::presence(
                  *storage,
                  kasumi::application::history_storage::marker_object(
                      right_object->head)),
              kasumi::transport::Presence::Present);
    EXPECT_EQ(kasumi::transport::presence(
                  *storage,
                  kasumi::application::history_storage::marker_object(
                      *parent_reference)),
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
        reproc::options options;
        options.stop = reproc::stop_actions{
            {reproc::stop::wait, reproc::milliseconds(10000)},
            {reproc::stop::terminate, reproc::milliseconds(2000)},
            {reproc::stop::kill, reproc::milliseconds(2000)}};
        const std::vector<std::string> arguments{
            kasumi::platform::path::to_utf8(
                std::filesystem::path{KASUMI_SYSTEM_KASUMI_EXECUTABLE}),
            "sync",
            std::string{profile_name}};
        const auto result = reproc::run(reproc::arguments{arguments},
                                        options,
                                        reproc::sink::string(output),
                                        reproc::sink::string(error));
        EXPECT_FALSE(result.second)
            << "stdout=" << output << " stderr=" << error;
        EXPECT_EQ(result.first, 0)
            << "stdout=" << output << " stderr=" << error;
    };
    run_cli();
    run_cli();
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

    EXPECT_EQ(kasumi::transport::presence(*storage, outside_identifier).value(),
              kasumi::transport::Presence::Present);
    ASSERT_TRUE(
        kasumi::transport::get(*storage, batch.identifiers[0], verify_dest)
            .has_value());
    EXPECT_EQ(kasumi::test::read_text(verify_dest), "content 0");
}

TEST(RcloneSystemTest, RcReadinessUsesPidWithoutVersionProbe) {
    auto perf_trace =
        kasumi::test::scoped_environment_variable("KASUMI_PERF_TRACE", "1");
    kasumi::platform::perf_trace::force_enable(true);
    kasumi::platform::perf_trace::reset();
    auto harness = make_rclone_harness();
    auto storage = open_transport(harness);
    if (!storage) {
        const auto detail = storage.error().message;
        kasumi::platform::perf_trace::force_enable(false);
        FAIL() << detail;
    }

    EXPECT_EQ(kasumi::platform::perf_trace::get_count("rc/core/version"), 0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("rc/core/pid"), 1U);
    storage = {};
    kasumi::platform::perf_trace::reset();
    kasumi::platform::perf_trace::force_enable(false);
}

TEST(RcloneSystemTest, WriterPhysicalHashAvoidsReadback) {
    auto perf_trace =
        kasumi::test::scoped_environment_variable("KASUMI_PERF_TRACE", "1");
    kasumi::platform::perf_trace::force_enable(true);
    auto harness = make_rclone_harness();
    auto storage = open_transport(harness);
    ASSERT_TRUE(storage.has_value());
    kasumi::platform::perf_trace::reset();
    const auto writer_workspace = harness_root(harness) / "writer-workspace";
    ASSERT_TRUE(std::filesystem::create_directories(writer_workspace));

    auto registration = kasumi::application::history_storage::
        maintenance_protocol::register_writer(*storage, writer_workspace);
    ASSERT_TRUE(registration.has_value()) << registration.error().detail;
    ASSERT_TRUE(kasumi::application::history_storage::maintenance_protocol::
                    release_registration(*registration));

    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("rc/operations/hashsumfile"),
        1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("rc/operations/copyfile"),
              1U);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("rclone copyfile download"),
        0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("rc/job/batch"), 1U);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("control batch operations"),
        2U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("rc/operations/list"),
              0U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("rc/operations/stat"),
              0U);
    kasumi::platform::perf_trace::reset();
    kasumi::platform::perf_trace::force_enable(false);
}

TEST(RcloneSystemTest, SinglePhysicalHashUsesHashsumfile) {
    auto perf_trace =
        kasumi::test::scoped_environment_variable("KASUMI_PERF_TRACE", "1");
    kasumi::platform::perf_trace::force_enable(true);
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

    kasumi::platform::perf_trace::reset();
    const auto verified =
        kasumi::transport::physical_hash(*storage, identifier, "sha256");
    ASSERT_TRUE(verified.has_value());
    EXPECT_EQ(*verified, prepared->ciphertext_sha256);
    EXPECT_EQ(
        kasumi::platform::perf_trace::get_count("rc/operations/hashsumfile"),
        1U);
    EXPECT_EQ(kasumi::platform::perf_trace::get_count("rc/operations/check"),
              0U);
    kasumi::platform::perf_trace::reset();
    kasumi::platform::perf_trace::force_enable(false);
}

TEST(RcloneSystemTest, BulkPhysicalHashUsesOneCheckManifest) {
    auto perf_trace =
        kasumi::test::scoped_environment_variable("KASUMI_PERF_TRACE", "1");
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
    ASSERT_TRUE(verified.has_value()) << verified.error().message;
    EXPECT_TRUE(verified->mismatched.empty());
    EXPECT_TRUE(verified->missing.empty());
    EXPECT_TRUE(verified->errors.empty());
    EXPECT_FALSE(
        std::filesystem::exists(source_root / ".kasumi-batch-verify.sha256"));
}

} // namespace
