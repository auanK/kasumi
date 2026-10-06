#include "application/execute.hpp"
#include "application/observation/history.hpp"
#include "application/observation/scanner.hpp"
#include "application/observation/state.hpp"
#include "application/profile.hpp"
#include "application/sync/journal.hpp"
#include "core/reconciliation/plan.hpp"
#include "crypto/key_derivation.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/hash_mutation.hpp"
#include "kasumi/test/provider_scenarios.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/change_journal.hpp"
#include "platform/metadata.hpp"
#include "platform/path.hpp"
#include "runtime/resolver.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <gtest/gtest.h>
#include <initializer_list>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace {

using kasumi::application::Credentials;
using kasumi::application::ExecutionEnvironment;
using kasumi::application::MasterKeyHex;
using kasumi::application::NoCredentials;
using kasumi::application::Operation;
using kasumi::application::Profile;
using kasumi::application::Request;
using kasumi::application::observation::history::StorageView;

constexpr std::string_view key_hex =
    "7777777777777777777777777777777777777777777777777777777777777777";

using Client =
    std::tuple<std::string, ExecutionEnvironment, std::filesystem::path>;
using Scenario = std::
    tuple<kasumi::test::TempWorkspace, std::filesystem::path, std::uint64_t>;

const std::string& client_name(const Client& client) {
    return std::get<0>(client);
}

const ExecutionEnvironment& client_environment(const Client& client) {
    return std::get<1>(client);
}

const std::filesystem::path& client_local_dir(const Client& client) {
    return std::get<2>(client);
}

void make_directory(const std::filesystem::path& path) {
    std::error_code error;
    if (std::filesystem::create_directories(path, error) || !error) {
        return;
    }
    throw std::filesystem::filesystem_error(
        "could not create E2E directory", path, error);
}

Scenario make_scenario() {
    auto workspace = kasumi::test::make_temp_workspace("e2e-local-sync");
    auto remote = kasumi::test::workspace_path(workspace, "remote");
    make_directory(remote);
    return {std::move(workspace), std::move(remote), 0};
}

Client make_client(Scenario& scenario, std::string name) {
    const auto& workspace = std::get<0>(scenario);
    const auto& remote = std::get<1>(scenario);
    const auto root = kasumi::test::workspace_path(workspace, name);
    const auto app_data = root / "app-data";
    const auto local = root / "local";
    make_directory(app_data);
    make_directory(local);

    Client result{std::move(name), ExecutionEnvironment{app_data}, local};
    auto created = kasumi::application::create_profile(
        client_environment(result),
        Profile{.name = client_name(result),
                .local_dir = client_local_dir(result),
                .remote_dir = kasumi::platform::path::to_utf8(remote)},
        MasterKeyHex{std::string{key_hex}});
    if (!created) {
        throw std::runtime_error("could not create E2E profile: " +
                                 created.error().detail);
    }
    return result;
}

kasumi::test::scenarios::TwoClientSyncScenario
shared_scenario(Scenario& scenario,
                const Client& a,
                const Client& b,
                std::string_view name) {
    return {
        .remote_locator = kasumi::platform::path::to_utf8(std::get<1>(scenario)),
        .scratch_root = kasumi::test::workspace_path(
            std::get<0>(scenario), "shared-scenarios/" + std::string{name}),
        .a = {.profile = client_name(a),
              .local_root = client_local_dir(a),
              .environment = client_environment(a)},
        .b = {.profile = client_name(b),
              .local_root = client_local_dir(b),
              .environment = client_environment(b)},
    };
}

std::expected<void, std::string> sync(const Client& client) {
    return kasumi::test::scenarios::sync(client_environment(client),
                                         client_name(client));
}

testing::AssertionResult sync_succeeds(const Client& client) {
    const auto result = sync(client);
    if (!result) {
        return testing::AssertionFailure()
               << client_name(client) << ": " << result.error();
    }
    return testing::AssertionSuccess();
}

std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> decode_key() {
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> result{};
    result.fill(0x77U);
    return result;
}

std::expected<StorageView, std::string> remote(Scenario& scenario) {
    const auto& remote_path = std::get<1>(scenario);
    auto storage = kasumi::transport::open_transport(
        kasumi::platform::path::to_utf8(remote_path));
    if (!storage) {
        return std::unexpected(storage.error().message);
    }
    const auto observer = kasumi::test::workspace_path(
        std::get<0>(scenario),
        "observations/" + std::to_string(std::get<2>(scenario)++));
    make_directory(observer);
    auto observed = kasumi::application::observation::history::observe(
        *storage, decode_key(), observer, false);
    if (!observed) {
        return std::unexpected(observed.error().detail);
    }
    return std::move(*observed);
}

std::expected<std::vector<std::string>, std::string>
remote_identifiers(Scenario& scenario) {
    const auto& remote_path = std::get<1>(scenario);
    auto storage = kasumi::transport::open_transport(
        kasumi::platform::path::to_utf8(remote_path));
    if (!storage) {
        return std::unexpected(storage.error().message);
    }
    auto identifiers = kasumi::transport::list(*storage);
    if (!identifiers) {
        return std::unexpected(identifiers.error().message);
    }
    std::ranges::sort(*identifiers);
    return std::move(*identifiers);
}

std::expected<std::optional<kasumi::state_storage::StoredState>, std::string>
state(const Client& client) {
    auto runtime =
        kasumi::runtime::resolve(client_environment(client).app_data_dir,
                                 client_name(client),
                                 kasumi::runtime::AccessMode::ReadOnly);
    if (!runtime) {
        return std::unexpected(runtime.error().detail);
    }
    return kasumi::state_storage::load_state(runtime->database_path);
}

std::expected<std::optional<kasumi::state_storage::ObservationCheckpoint>,
              std::string>
checkpoint(const Client& client) {
    auto runtime =
        kasumi::runtime::resolve(client_environment(client).app_data_dir,
                                 client_name(client),
                                 kasumi::runtime::AccessMode::ReadOnly);
    if (!runtime) {
        return std::unexpected(runtime.error().detail);
    }
    return kasumi::state_storage::load_observation_checkpoint(
        runtime->database_path);
}

bool supports_observation_checkpoint(const Client& client) {
    return kasumi::platform::capture_change_journal_checkpoint(
               client_local_dir(client))
        .has_value();
}

void expect_converged(Scenario& scenario,
                      std::initializer_list<const Client*> clients) {
    auto observed = remote(scenario);
    ASSERT_TRUE(observed.has_value()) << (observed ? "" : observed.error());
    ASSERT_EQ(observed->logical_heads.size(), 1U);

    for (const auto* client : clients) {
        auto stored = state(*client);
        ASSERT_TRUE(stored.has_value()) << stored.error();
        ASSERT_TRUE(stored->has_value());
        EXPECT_EQ((*stored)->commit_id, observed->logical_heads.front());
        EXPECT_EQ((*stored)->tree, observed->effective_tree);

        auto stored_checkpoint = checkpoint(*client);
        ASSERT_TRUE(stored_checkpoint.has_value()) << stored_checkpoint.error();
        if (supports_observation_checkpoint(*client)) {
            ASSERT_TRUE(stored_checkpoint->has_value());
            ASSERT_FALSE((*stored)->tree.rows.empty());
            EXPECT_EQ((*stored_checkpoint)->tree_root_hash,
                      (*stored)->tree.rows.front().hash);
            EXPECT_EQ((*stored_checkpoint)->row_count,
                      static_cast<std::uint64_t>((*stored)->tree.rows.size()));
        } else {
            EXPECT_FALSE(stored_checkpoint->has_value());
        }
    }
}

void expect_fixed_point(Scenario& scenario, const Client& client) {
    const auto before_files =
        kasumi::test::snapshot_tree(client_local_dir(client));
    auto before_state = state(client);
    ASSERT_TRUE(before_state.has_value()) << before_state.error();
    ASSERT_TRUE(before_state->has_value());
    auto before_checkpoint = checkpoint(client);
    ASSERT_TRUE(before_checkpoint.has_value()) << before_checkpoint.error();
    const bool has_checkpoint = supports_observation_checkpoint(client);
    if (has_checkpoint) {
        ASSERT_TRUE(before_checkpoint->has_value());
    } else {
        EXPECT_FALSE(before_checkpoint->has_value());
    }
    auto before_remote = remote(scenario);
    ASSERT_TRUE(before_remote.has_value()) << before_remote.error();
    auto before_identifiers = remote_identifiers(scenario);
    ASSERT_TRUE(before_identifiers.has_value()) << before_identifiers.error();

    auto synchronized = sync(client);
    ASSERT_TRUE(synchronized.has_value()) << synchronized.error();

    EXPECT_EQ(kasumi::test::snapshot_tree(client_local_dir(client)),
              before_files);
    auto after_state = state(client);
    ASSERT_TRUE(after_state.has_value()) << after_state.error();
    ASSERT_TRUE(after_state->has_value());
    EXPECT_EQ((*after_state)->commit_id, (*before_state)->commit_id);
    EXPECT_EQ((*after_state)->tree, (*before_state)->tree);

    auto after_checkpoint = checkpoint(client);
    ASSERT_TRUE(after_checkpoint.has_value()) << after_checkpoint.error();
    if (has_checkpoint) {
        ASSERT_TRUE(after_checkpoint->has_value());
        EXPECT_EQ((*after_checkpoint)->tree_root_hash,
                  (*before_checkpoint)->tree_root_hash);
        EXPECT_EQ((*after_checkpoint)->row_count,
                  (*before_checkpoint)->row_count);
    } else {
        EXPECT_FALSE(after_checkpoint->has_value());
    }

    auto after_remote = remote(scenario);
    ASSERT_TRUE(after_remote.has_value()) << after_remote.error();
    EXPECT_EQ(after_remote->logical_heads, before_remote->logical_heads);
    EXPECT_EQ(after_remote->effective_tree, before_remote->effective_tree);

    auto after_identifiers = remote_identifiers(scenario);
    ASSERT_TRUE(after_identifiers.has_value()) << after_identifiers.error();
    EXPECT_EQ(*after_identifiers, *before_identifiers);
}

void set_mtime(const Client& client,
               std::string_view path,
               std::filesystem::file_time_type timestamp) {
    const auto target =
        client_local_dir(client) / kasumi::platform::path::from_utf8(path);
    const auto result =
        kasumi::platform::metadata::set_last_write_time(target, timestamp);
    ASSERT_TRUE(result.has_value()) << result.error();
}

void remove_file(const Client& client, std::string_view path) {
    std::error_code error;
    ASSERT_TRUE(std::filesystem::remove(
        client_local_dir(client) / kasumi::platform::path::from_utf8(path),
        error));
    ASSERT_FALSE(error) << error.message();
}

void remove_directory(const Client& client, std::string_view path) {
    std::error_code error;
    ASSERT_TRUE(std::filesystem::remove(
        client_local_dir(client) / kasumi::platform::path::from_utf8(path),
        error));
    ASSERT_FALSE(error) << error.message();
}

void expect_file(const Client& client,
                 std::string_view path,
                 std::string_view contents) {
    const auto file =
        client_local_dir(client) / kasumi::platform::path::from_utf8(path);
    ASSERT_TRUE(std::filesystem::is_regular_file(file));
    EXPECT_EQ(kasumi::test::read_text(file), contents);
}

void expect_absent(const Client& client, std::string_view path) {
    EXPECT_FALSE(std::filesystem::exists(
        client_local_dir(client) / kasumi::platform::path::from_utf8(path)));
}

void expect_remote_present(const StorageView& remote, std::string_view path) {
    EXPECT_NE(kasumi::find_row(remote.effective_tree, path), nullptr);
}

void expect_remote_absent(const StorageView& remote, std::string_view path) {
    EXPECT_EQ(kasumi::find_row(remote.effective_tree, path), nullptr);
}

void seed_remote_ignore_vault(Scenario& scenario, const Client& seed) {
    kasumi::test::write_text(client_local_dir(seed) / ".kasumiignore",
                             "/Screenshots/\n");
    kasumi::test::write_text(client_local_dir(seed) / "Alpha.jpg", "alpha");
    kasumi::test::write_text(client_local_dir(seed) / "Zulu.jpg", "zulu");
    ASSERT_TRUE(sync_succeeds(seed));
    expect_file(seed, ".kasumiignore", "/Screenshots/\n");

    auto observed = remote(scenario);
    ASSERT_TRUE(observed.has_value()) << observed.error();
    ASSERT_FALSE(observed->logical_heads.empty());
    expect_remote_present(*observed, ".kasumiignore");
    expect_remote_present(*observed, "Alpha.jpg");
    expect_remote_present(*observed, "Zulu.jpg");
    expect_remote_absent(*observed, "Screenshots");
}

void expect_no_transaction_artifacts(
    const kasumi::runtime::RuntimeData& runtime) {
    const auto profile = runtime.database_path.parent_path();
    EXPECT_FALSE(std::filesystem::exists(
        profile / kasumi::application::sync::journal::journal_file_name));
    EXPECT_FALSE(std::filesystem::exists(
        profile /
        (std::string{kasumi::application::sync::journal::journal_file_name} +
         std::string{kasumi::application::sync::journal::temporary_suffix})));
    const auto transactions = profile / ".transactions";
    if (std::filesystem::exists(transactions)) {
        EXPECT_TRUE(std::filesystem::is_empty(transactions));
    }
}

TEST(H3LocalSyncTest, BootstrapAndNestedTreeConverge) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");

    const auto unicode_dir = kasumi::platform::path::from_utf8("pasta-日本");
    const auto unicode_file =
        kasumi::platform::path::from_utf8("usuário-☁.txt");
    const auto a_unicode = client_local_dir(a) / unicode_dir / unicode_file;
    const std::string expected_dir_utf8 = "pasta-日本";
    const std::string expected_file_utf8 = "pasta-日本/usuário-☁.txt";

    const std::vector<kasumi::test::scenarios::SeedFile> seed_files{
        {"alpha.txt", "alpha"},
        {"beta.txt", "beta"},
        {"docs/readme.txt", "readme"},
        {"docs/nested/data.txt", "data"},
        {"images/image.bin", "binary"},
        {"pasta-日本/usuário-☁.txt", "unicode-v1"},
    };
    const auto published = kasumi::test::scenarios::publish_seed_files(
        client_environment(a), client_name(a), client_local_dir(a), seed_files);
    ASSERT_TRUE(published.has_value()) << published.error();
    auto observed_remote = remote(scenario);
    ASSERT_TRUE(observed_remote.has_value()) << observed_remote.error();
    expect_remote_present(*observed_remote, "alpha.txt");
    expect_remote_present(*observed_remote, "docs/nested/data.txt");
    expect_remote_present(*observed_remote, expected_dir_utf8);
    expect_remote_present(*observed_remote, expected_file_utf8);

    const auto* r_dir =
        kasumi::find_row(observed_remote->effective_tree, expected_dir_utf8);
    ASSERT_NE(r_dir, nullptr);
    EXPECT_TRUE(r_dir->is_directory);
    const auto* r_file =
        kasumi::find_row(observed_remote->effective_tree, expected_file_utf8);
    ASSERT_NE(r_file, nullptr);
    EXPECT_FALSE(r_file->is_directory);
    EXPECT_EQ(r_file->path, expected_file_utf8);

    const auto materialized = kasumi::test::scenarios::materialize_files(
        client_environment(b), client_name(b), client_local_dir(b), seed_files);
    ASSERT_TRUE(materialized.has_value()) << materialized.error();
    expect_file(b, "alpha.txt", "alpha");
    expect_file(b, "docs/readme.txt", "readme");
    expect_file(b, "docs/nested/data.txt", "data");
    expect_file(b, "images/image.bin", "binary");

    const auto b_unicode = client_local_dir(b) / unicode_dir / unicode_file;
    ASSERT_TRUE(std::filesystem::is_regular_file(b_unicode));
    EXPECT_EQ(kasumi::test::read_text(b_unicode), "unicode-v1");

    // Re-scan client B to confirm: remote logical UTF-8 -> native path ->
    // scanner -> logical UTF-8
    const auto b_scan = kasumi::application::observation::scanner::scan_result(
        client_local_dir(b));
    ASSERT_TRUE(b_scan.has_value())
        << kasumi::application::observation::scanner::describe(b_scan.error());
    const auto* b_scan_dir =
        kasumi::find_row(b_scan->snapshot, expected_dir_utf8);
    ASSERT_NE(b_scan_dir, nullptr);
    EXPECT_TRUE(b_scan_dir->is_directory);
    const auto* b_scan_file =
        kasumi::find_row(b_scan->snapshot, expected_file_utf8);
    ASSERT_NE(b_scan_file, nullptr);
    EXPECT_FALSE(b_scan_file->is_directory);
    EXPECT_EQ(b_scan_file->path, expected_file_utf8);
    EXPECT_EQ(b_scan_file->size, 10U);

    // Reverse path B -> A: modify on B and sync to A
    kasumi::test::write_text(b_unicode, "unicode-v2");

    ASSERT_TRUE(sync_succeeds(b));
    ASSERT_TRUE(sync_succeeds(a));

    ASSERT_TRUE(std::filesystem::is_regular_file(a_unicode));
    EXPECT_EQ(kasumi::test::read_text(a_unicode), "unicode-v2");

    auto remote_after_v2 = remote(scenario);
    ASSERT_TRUE(remote_after_v2.has_value()) << remote_after_v2.error();
    expect_remote_present(*remote_after_v2, expected_dir_utf8);
    expect_remote_present(*remote_after_v2, expected_file_utf8);
    const auto* v2_file =
        kasumi::find_row(remote_after_v2->effective_tree, expected_file_utf8);
    ASSERT_NE(v2_file, nullptr);
    EXPECT_EQ(v2_file->path, expected_file_utf8);

    expect_converged(scenario, {&a, &b});
    expect_fixed_point(scenario, a);
    expect_fixed_point(scenario, b);
}

TEST(H3LocalSyncTest, UnicodeSupplementaryAndExtendedSync) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");
    constexpr std::array<std::pair<std::string_view, std::string_view>, 4>
        files{{
            {"高松灯/カード💝.png", "card from A"},
            {"Icons/Karyl💝.png", "Karyl from A"},
            {"Icons/𝑬𝒎𝒊𝒍𝒊𝒂.txt", "Emilia from A"},
            {"Icons/𓆩🌸𓆪.txt", "flower from A"},
        }};
    for (const auto& [path, contents] : files) {
        kasumi::test::write_text(client_local_dir(a) /
                                     kasumi::platform::path::from_utf8(path),
                                 contents);
    }

    ASSERT_TRUE(sync_succeeds(a));
    ASSERT_TRUE(sync_succeeds(b));
    for (const auto& [path, contents] : files) {
        SCOPED_TRACE(path);
        expect_file(b, path, contents);
    }

    constexpr std::string_view modified = "高松灯/カード💝.png";
    constexpr std::string_view added = "高松灯/千早愛音🌸.txt";
    kasumi::test::write_text(client_local_dir(b) /
                                 kasumi::platform::path::from_utf8(modified),
                             "card updated on B with Unicode path");
    kasumi::test::write_text(client_local_dir(b) /
                                 kasumi::platform::path::from_utf8(added),
                             "new file from B");

    ASSERT_TRUE(sync_succeeds(b));
    ASSERT_TRUE(sync_succeeds(a));
    expect_file(a, modified, "card updated on B with Unicode path");
    expect_file(a, added, "new file from B");
    for (const auto& [path, contents] : files) {
        SCOPED_TRACE(path);
        if (path != modified) {
            expect_file(a, path, contents);
        }
    }
    expect_converged(scenario, {&a, &b});
    expect_fixed_point(scenario, a);
    expect_fixed_point(scenario, b);
}

TEST(H3LocalSyncTest, CreatesSubtreesAndEmptyDirectoriesInBothDirections) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");

    kasumi::test::write_text(client_local_dir(a) / "keep.txt", "keep");
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));

    kasumi::test::write_text(client_local_dir(a) / "new/a.txt", "a");
    kasumi::test::write_text(client_local_dir(a) / "new/nested/b.txt", "b");
    make_directory(client_local_dir(a) / "empty");
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));
    expect_file(b, "new/a.txt", "a");
    expect_file(b, "new/nested/b.txt", "b");
    EXPECT_TRUE(std::filesystem::is_directory(client_local_dir(b) / "empty"));

    kasumi::test::write_text(client_local_dir(b) / "from-b.txt", "from B");
    ASSERT_TRUE(sync(b));
    ASSERT_TRUE(sync(a));
    expect_file(a, "from-b.txt", "from B");
    expect_converged(scenario, {&a, &b});
    expect_fixed_point(scenario, a);
    expect_fixed_point(scenario, b);
}

TEST(H3LocalSyncTest, BidirectionalUpdatesConverge) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");
    const auto result = kasumi::test::scenarios::bidirectional_update(
        shared_scenario(scenario, a, b, "bidirectional-update"));
    ASSERT_TRUE(result.has_value()) << result.error();
}

TEST(H3LocalSyncTest, DeletesRootFilesAndPreservesAnEmptyRoot) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");
    const auto result = kasumi::test::scenarios::logical_delete(
        shared_scenario(scenario, a, b, "logical-delete"));
    ASSERT_TRUE(result.has_value()) << result.error();
    EXPECT_TRUE(std::filesystem::is_directory(client_local_dir(a)));
    EXPECT_TRUE(std::filesystem::is_directory(client_local_dir(b)));
}

TEST(H3LocalSyncTest, DeletesEmptyNestedDeepAndMixedDirectories) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");

    make_directory(client_local_dir(a) / "empty");
    kasumi::test::write_text(client_local_dir(a) / "single/file.txt", "single");
    kasumi::test::write_text(client_local_dir(a) / "nested/b/c.txt", "c");
    kasumi::test::write_text(client_local_dir(a) / "nested/d.txt", "d");
    kasumi::test::write_text(client_local_dir(a) / "deep/a/b/c/file.txt",
                             "deep");
    kasumi::test::write_text(client_local_dir(a) / "mixed/gamma.txt", "gamma");
    kasumi::test::write_text(client_local_dir(a) / "other/keep.txt", "keep");
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));

    remove_directory(b, "empty");
    remove_file(b, "single/file.txt");
    remove_directory(b, "single");
    remove_file(b, "nested/b/c.txt");
    remove_directory(b, "nested/b");
    remove_file(b, "nested/d.txt");
    remove_directory(b, "nested");
    remove_file(b, "deep/a/b/c/file.txt");
    remove_directory(b, "deep/a/b/c");
    remove_directory(b, "deep/a/b");
    remove_directory(b, "deep/a");
    remove_directory(b, "deep");
    remove_file(b, "mixed/gamma.txt");
    remove_directory(b, "mixed");
    ASSERT_TRUE(sync(b));
    ASSERT_TRUE(sync(a));

    auto observed_remote = remote(scenario);
    ASSERT_TRUE(observed_remote.has_value()) << observed_remote.error();
    for (const auto path :
         {"empty", "single", "nested", "deep", "mixed", "mixed/gamma.txt"}) {
        expect_absent(a, path);
        expect_remote_absent(*observed_remote, path);
    }
    expect_file(a, "other/keep.txt", "keep");
    expect_remote_present(*observed_remote, "other/keep.txt");
    expect_converged(scenario, {&a, &b});
    expect_fixed_point(scenario, a);
}

TEST(H3LocalSyncTest, StructuralChangesFailClosedAtTypeBoundary) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");

    kasumi::test::write_text(client_local_dir(a) / "node", "file");
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));

    remove_file(a, "node");
    kasumi::test::write_text(client_local_dir(a) / "node/child.txt", "child");
    ASSERT_TRUE(sync(a));
    auto receive_directory = sync(b);
    ASSERT_FALSE(receive_directory.has_value());
    expect_file(b, "node", "file");

    remove_file(b, "node");
    auto retry_directory = sync(b);
    ASSERT_TRUE(retry_directory.has_value()) << retry_directory.error();
    EXPECT_TRUE(std::filesystem::is_directory(client_local_dir(b) / "node"));
    expect_file(b, "node/child.txt", "child");

    remove_file(b, "node/child.txt");
    remove_directory(b, "node");
    kasumi::test::write_text(client_local_dir(b) / "node", "file again");
    auto publish_file = sync(b);
    ASSERT_FALSE(publish_file.has_value());
    expect_file(b, "node", "file again");
    auto observed_remote = remote(scenario);
    ASSERT_TRUE(observed_remote.has_value()) << observed_remote.error();
    EXPECT_TRUE(std::filesystem::is_directory(client_local_dir(a) / "node"));
    expect_remote_present(*observed_remote, "node/child.txt");
}

TEST(H3LocalSyncTest, IgnoreFilesStayLocalAcrossRemoteDeletes) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");

    kasumi::test::write_text(client_local_dir(a) / ".kasumiignore",
                             "ignored.txt\n");
    kasumi::test::write_text(client_local_dir(a) / "ignored.txt", "local-only");
    kasumi::test::write_text(client_local_dir(a) / "keep.txt", "keep");
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));
    expect_absent(b, "ignored.txt");
    expect_file(b, "keep.txt", "keep");

    remove_file(b, "keep.txt");
    ASSERT_TRUE(sync(b));
    ASSERT_TRUE(sync(a));
    expect_absent(a, "keep.txt");
    expect_file(a, "ignored.txt", "local-only");
    auto observed_remote = remote(scenario);
    ASSERT_TRUE(observed_remote.has_value()) << observed_remote.error();
    expect_remote_absent(*observed_remote, "ignored.txt");
    expect_converged(scenario, {&a, &b});
}

TEST(H3LocalSyncTest,
     IgnoredFileModifiedRemotelyDoesNotCauseCompositionMismatch) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");

    // Initially both sync desktop.ini and file.txt
    kasumi::test::write_text(client_local_dir(a) / "desktop.ini",
                             "initial_desktop_ini");
    kasumi::test::write_text(client_local_dir(a) / "file.txt", "file");
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));
    expect_file(b, "desktop.ini", "initial_desktop_ini");

    // Client A now ignores desktop.ini
    kasumi::test::write_text(client_local_dir(a) / ".kasumiignore",
                             "desktop.ini\n");
    kasumi::test::write_text(client_local_dir(a) / "desktop.ini",
                             "local_a_ini");

    // Client B modifies desktop.ini remotely (c != b)
    kasumi::test::write_text(client_local_dir(b) / "desktop.ini",
                             "modified_remote_desktop_ini_longer");
    ASSERT_TRUE(sync(b));

    // Client A syncs: must succeed without CompositionMismatch!
    ASSERT_TRUE(sync(a));
    // Local file on client A remains intact
    expect_file(a, "desktop.ini", "local_a_ini");

    auto observed_remote = remote(scenario);
    ASSERT_TRUE(observed_remote.has_value()) << observed_remote.error();
    expect_remote_absent(*observed_remote, "desktop.ini");
}

TEST(H3LocalSyncTest,
     FreshClientPreexistingRemoteIgnoredDirectoryConverges) {
    auto scenario = make_scenario();
    const auto seed = make_client(scenario, "seed");
    seed_remote_ignore_vault(scenario, seed);

    const auto fresh = make_client(scenario, "fresh");
    const auto initial_state = state(fresh);
    ASSERT_TRUE(initial_state.has_value()) << initial_state.error();
    ASSERT_FALSE(initial_state->has_value());
    ASSERT_FALSE(std::filesystem::exists(client_local_dir(fresh) /
                                          ".kasumiignore"));

    const auto local_only = client_local_dir(fresh) / "Screenshots" /
                            "local-only.png";
    kasumi::test::write_text(local_only, "keep this ignored file");
    const auto initial_physical_tree =
        kasumi::application::observation::scanner::scan_result(
            client_local_dir(fresh));
    ASSERT_TRUE(initial_physical_tree.has_value());
    EXPECT_NE(kasumi::find_row(initial_physical_tree->snapshot, "Screenshots"),
              nullptr);
    EXPECT_NE(kasumi::find_row(initial_physical_tree->snapshot,
                               "Screenshots/local-only.png"),
              nullptr);

    auto runtime = kasumi::runtime::resolve(
        client_environment(fresh).app_data_dir,
        client_name(fresh),
        kasumi::runtime::AccessMode::ReadOnly);
    ASSERT_TRUE(runtime.has_value()) << runtime.error().detail;
    const auto& remote_path = std::get<1>(scenario);
    auto storage = kasumi::transport::open_transport(
        kasumi::platform::path::to_utf8(remote_path));
    ASSERT_TRUE(storage.has_value()) << storage.error().message;
    const auto key = decode_key();
    const auto input =
        kasumi::application::observation::collect_reconciliation_input(
            *runtime, *storage, key, false);
    ASSERT_TRUE(input.has_value()) << input.error().detail;
    EXPECT_NE(kasumi::find_row(input->storage.tree, ".kasumiignore"), nullptr);
    EXPECT_EQ(kasumi::find_row(input->local_tree, "Screenshots"), nullptr);
    EXPECT_EQ(kasumi::find_row(input->local_tree,
                               "Screenshots/local-only.png"),
              nullptr);
    EXPECT_TRUE(kasumi::ignore::is_ignored(
        "Screenshots/local-only.png", input->ignore_list, false));

    const auto preview = kasumi::reconciliation::reconcile(*input);
    ASSERT_TRUE(preview.has_value()) << preview.error().detail;
    ASSERT_EQ(input->storage.tree.rows.size(), 4U);
    ASSERT_EQ(preview->candidate_shared_tree.rows.size(), 4U);
    EXPECT_FALSE(preview->requires_publication);
    EXPECT_FALSE(std::ranges::any_of(
        preview->plan.operations, [](const kasumi::Operation& operation) {
            return operation.action == kasumi::Action::Upload;
        }));
    EXPECT_EQ(kasumi::find_row(preview->candidate_shared_tree, "Screenshots"),
              nullptr)
        << "candidate contains the pre-existing ignored directory";
    EXPECT_EQ(kasumi::find_row(preview->candidate_shared_tree,
                               "Screenshots/local-only.png"),
              nullptr)
        << "candidate contains local-only ignored content";
    EXPECT_FALSE(std::ranges::any_of(
        preview->plan.operations, [](const kasumi::Operation& operation) {
            return operation.action == kasumi::Action::Upload &&
                   kasumi::platform::path::to_logical_utf8(operation.path) ==
                       "Screenshots/local-only.png";
        })) << "plan uploads local-only ignored content";
    EXPECT_FALSE(std::ranges::any_of(
        preview->pending_materializations, [](const kasumi::NodeRow& row) {
            return row.path == "Screenshots" ||
                   row.path.starts_with("Screenshots/");
        }));

    const auto remote_before = remote(scenario);
    ASSERT_TRUE(remote_before.has_value()) << remote_before.error();
    const auto identifiers_before = remote_identifiers(scenario);
    ASSERT_TRUE(identifiers_before.has_value()) << identifiers_before.error();
    const auto* ignored_row =
        kasumi::find_row(initial_physical_tree->snapshot,
                         "Screenshots/local-only.png");
    ASSERT_NE(ignored_row, nullptr);
    const auto ignored_content_id =
        kasumi::crypto::content_identifier(key, ignored_row->hash);
    EXPECT_EQ(std::ranges::find(*identifiers_before, ignored_content_id),
              identifiers_before->end());
    const auto synchronized = sync(fresh);
    if (!synchronized) {
        ADD_FAILURE() << synchronized.error();
        EXPECT_FALSE(std::filesystem::exists(client_local_dir(fresh) /
                                              ".kasumiignore"))
            << "rollback must restore the pre-sync local namespace";
    }

    expect_file(fresh, "Screenshots/local-only.png", "keep this ignored file");
    auto accepted = state(fresh);
    ASSERT_TRUE(accepted.has_value()) << accepted.error();
    EXPECT_TRUE(accepted->has_value())
        << "successful first sync must persist accepted state";
    if (accepted->has_value()) {
        EXPECT_TRUE((*accepted)->pending_materializations.empty());
        EXPECT_EQ(kasumi::find_row((*accepted)->tree, "Screenshots"), nullptr);
        EXPECT_EQ(kasumi::find_row((*accepted)->tree,
                                   "Screenshots/local-only.png"),
                  nullptr);
    }

    auto observed_after = remote(scenario);
    ASSERT_TRUE(observed_after.has_value()) << observed_after.error();
    EXPECT_EQ(observed_after->logical_heads, remote_before->logical_heads);
    EXPECT_EQ(observed_after->effective_tree, remote_before->effective_tree);
    expect_remote_absent(*observed_after, "Screenshots");
    expect_remote_present(*observed_after, "Alpha.jpg");
    expect_remote_present(*observed_after, "Zulu.jpg");
    const auto identifiers_after = remote_identifiers(scenario);
    ASSERT_TRUE(identifiers_after.has_value()) << identifiers_after.error();
    EXPECT_EQ(*identifiers_after, *identifiers_before)
        << "no remote writes are expected: preview has no Upload or "
           "publication";
    EXPECT_EQ(std::ranges::find(*identifiers_after, ignored_content_id),
              identifiers_after->end())
        << "first sync must not upload local-only ignored content";
    auto materialized =
        kasumi::application::observation::collect_local_tree(
            client_local_dir(fresh), input->ignore_list);
    ASSERT_TRUE(materialized.has_value());
    ASSERT_EQ(materialized->rows.size(),
              preview->candidate_shared_tree.rows.size());
    for (std::size_t index = 0; index < materialized->rows.size(); ++index) {
        const auto& actual = materialized->rows[index];
        const auto& expected = preview->candidate_shared_tree.rows[index];
        EXPECT_EQ(actual.path, expected.path);
        EXPECT_EQ(actual.hash, expected.hash);
        EXPECT_EQ(actual.size, expected.size);
        EXPECT_EQ(actual.is_directory, expected.is_directory);
    }
}

TEST(H3LocalSyncTest,
     FreshClientWithoutPreexistingRemoteIgnoredDirectoryConverges) {
    auto scenario = make_scenario();
    const auto seed = make_client(scenario, "seed");
    seed_remote_ignore_vault(scenario, seed);

    const auto fresh = make_client(scenario, "fresh");
    const auto initial_state = state(fresh);
    ASSERT_TRUE(initial_state.has_value()) << initial_state.error();
    ASSERT_FALSE(initial_state->has_value());
    ASSERT_FALSE(std::filesystem::exists(client_local_dir(fresh) /
                                          "Screenshots"));
    const auto identifiers_before = remote_identifiers(scenario);
    ASSERT_TRUE(identifiers_before.has_value()) << identifiers_before.error();

    ASSERT_TRUE(sync_succeeds(fresh));
    expect_file(fresh, ".kasumiignore", "/Screenshots/\n");
    expect_file(fresh, "Alpha.jpg", "alpha");
    expect_file(fresh, "Zulu.jpg", "zulu");

    auto accepted = state(fresh);
    ASSERT_TRUE(accepted.has_value()) << accepted.error();
    ASSERT_TRUE(accepted->has_value());
    EXPECT_TRUE((*accepted)->pending_materializations.empty());
    EXPECT_EQ(kasumi::find_row((*accepted)->tree, "Screenshots"), nullptr);
    auto observed_after = remote(scenario);
    ASSERT_TRUE(observed_after.has_value()) << observed_after.error();
    expect_remote_absent(*observed_after, "Screenshots");
    EXPECT_EQ((*accepted)->tree, observed_after->effective_tree);
    const auto identifiers_after = remote_identifiers(scenario);
    ASSERT_TRUE(identifiers_after.has_value()) << identifiers_after.error();
    EXPECT_EQ(*identifiers_after, *identifiers_before);
}

TEST(H3LocalSyncTest, RemoteIgnoreChangeOverridesStaleLocalProjection) {
    auto scenario = make_scenario();
    const auto seed = make_client(scenario, "seed");
    seed_remote_ignore_vault(scenario, seed);
    const auto client = make_client(scenario, "stale-ignore");
    ASSERT_TRUE(sync_succeeds(client));

    const auto local_only = client_local_dir(client) / "Cache" / "local.txt";
    kasumi::test::write_text(local_only, "keep while ignored remotely");
    kasumi::test::write_text(client_local_dir(seed) / ".kasumiignore",
                             "/Cache/\n");
    ASSERT_TRUE(sync_succeeds(seed));

    auto runtime = kasumi::runtime::resolve(
        client_environment(client).app_data_dir,
        client_name(client),
        kasumi::runtime::AccessMode::ReadOnly);
    ASSERT_TRUE(runtime.has_value()) << runtime.error().detail;
    auto storage = kasumi::transport::open_transport(
        kasumi::platform::path::to_utf8(std::get<1>(scenario)));
    ASSERT_TRUE(storage.has_value()) << storage.error().message;
    const auto key = decode_key();
    const auto input =
        kasumi::application::observation::collect_reconciliation_input(
            *runtime, *storage, key, false);
    ASSERT_TRUE(input.has_value()) << input.error().detail;
    EXPECT_TRUE(kasumi::ignore::is_ignored("Cache/local.txt",
                                          input->ignore_list,
                                          false));
    EXPECT_EQ(kasumi::find_row(input->local_tree, "Cache"), nullptr);
    EXPECT_EQ(kasumi::find_row(input->local_tree, "Cache/local.txt"), nullptr);
    const auto preview = kasumi::reconciliation::reconcile(*input);
    ASSERT_TRUE(preview.has_value()) << preview.error().detail;
    EXPECT_FALSE(std::ranges::any_of(
        preview->plan.operations, [](const kasumi::Operation& operation) {
            return operation.action == kasumi::Action::Upload &&
                   kasumi::platform::path::to_logical_utf8(operation.path) ==
                       "Cache/local.txt";
        }));
    ASSERT_TRUE(sync_succeeds(client));
    expect_file(client, "Cache/local.txt", "keep while ignored remotely");
    auto observed = remote(scenario);
    ASSERT_TRUE(observed.has_value()) << observed.error();
    expect_remote_absent(*observed, "Cache");
}

TEST(H3LocalSyncTest, MissingAuthenticatedRemoteIgnoreFailsClosed) {
    auto scenario = make_scenario();
    const auto seed = make_client(scenario, "seed");
    seed_remote_ignore_vault(scenario, seed);
    const auto fresh = make_client(scenario, "fresh-missing-ignore");
    kasumi::test::write_text(
        client_local_dir(fresh) / "Screenshots" / "local-only.png",
        "keep this ignored file");

    auto before = remote(scenario);
    ASSERT_TRUE(before.has_value()) << before.error();
    const auto* ignore_row =
        kasumi::find_row(before->effective_tree, ".kasumiignore");
    ASSERT_NE(ignore_row, nullptr);
    const auto key = decode_key();
    const auto ignore_id =
        kasumi::crypto::content_identifier(key, ignore_row->hash);
    auto storage = kasumi::transport::open_transport(
        kasumi::platform::path::to_utf8(std::get<1>(scenario)));
    ASSERT_TRUE(storage.has_value()) << storage.error().message;
    ASSERT_TRUE(kasumi::transport::remove(*storage, ignore_id));

    auto runtime = kasumi::runtime::resolve(
        client_environment(fresh).app_data_dir,
        client_name(fresh),
        kasumi::runtime::AccessMode::ReadOnly);
    ASSERT_TRUE(runtime.has_value()) << runtime.error().detail;
    const auto input =
        kasumi::application::observation::collect_reconciliation_input(
            *runtime, *storage, key, false);
    ASSERT_FALSE(input.has_value());
    EXPECT_NE(input.error().detail.find("authenticated remote .kasumiignore"),
              std::string::npos);
    expect_file(fresh, "Screenshots/local-only.png", "keep this ignored file");
    auto accepted = state(fresh);
    ASSERT_TRUE(accepted.has_value()) << accepted.error();
    EXPECT_FALSE(accepted->has_value());
}

TEST(H3LocalSyncTest,
     IdenticalKasumiIgnoreMtimeDoesNotBlockUnrelatedPublication) {
    auto scenario = make_scenario();
    const auto client = make_client(scenario, "mtime-regression");
    const auto ignore = client_local_dir(client) / ".kasumiignore";
    kasumi::test::write_text(ignore, "ignored.txt\n");

    ASSERT_TRUE(sync_succeeds(client));

    auto before = remote(scenario);
    ASSERT_TRUE(before.has_value()) << before.error();
    const auto* before_ignore =
        kasumi::find_row(before->effective_tree, ".kasumiignore");
    ASSERT_NE(before_ignore, nullptr);
    const auto original_hash = before_ignore->hash;
    const auto original_size = before_ignore->size;
    const auto before_native_mtime =
        kasumi::platform::metadata::file_time_from_unix_nanoseconds(
            before_ignore->mtime);
    ASSERT_TRUE(before_native_mtime.has_value());
    using FileDuration = std::filesystem::file_time_type::duration;
    const auto local_subsecond = *before_native_mtime +
        std::chrono::duration_cast<FileDuration>(
            std::chrono::seconds{1} + std::chrono::nanoseconds{915178000});
    const auto written = kasumi::platform::metadata::set_last_write_time(
        ignore, local_subsecond);
    ASSERT_TRUE(written.has_value()) << written.error();
    std::error_code error;
    const auto observed_local_mtime =
        std::filesystem::last_write_time(ignore, error);
    ASSERT_FALSE(error);
    const auto observed_local_mtime_ns =
        kasumi::platform::metadata::unix_nanoseconds(observed_local_mtime);
    ASSERT_TRUE(observed_local_mtime_ns.has_value());
    ASSERT_NE(*observed_local_mtime_ns, before_ignore->mtime);

    kasumi::test::write_text(client_local_dir(client) / "B.txt", "new");
    ASSERT_TRUE(sync_succeeds(client));

    auto after = remote(scenario);
    ASSERT_TRUE(after.has_value()) << after.error();
    const auto* after_ignore =
        kasumi::find_row(after->effective_tree, ".kasumiignore");
    ASSERT_NE(after_ignore, nullptr);
    EXPECT_EQ(after_ignore->hash, original_hash);
    EXPECT_EQ(after_ignore->size, original_size);
    EXPECT_EQ(after_ignore->mtime, *observed_local_mtime_ns);
    expect_remote_present(*after, "B.txt");
    EXPECT_FALSE(after->has_conflicts);
    expect_file(client, ".kasumiignore", "ignored.txt\n");
    expect_file(client, "B.txt", "new");
    expect_fixed_point(scenario, client);
}

TEST(H3LocalSyncTest, EquivalentFileMtimeDriftSucceedsWithoutPublication) {
    auto scenario = make_scenario();
    const auto client = make_client(scenario, "mtime-drift-no-pub");
    const auto ignore = client_local_dir(client) / ".kasumiignore";
    kasumi::test::write_text(ignore, "ignored.txt\n");

    ASSERT_TRUE(sync_succeeds(client));

    auto before = remote(scenario);
    ASSERT_TRUE(before.has_value()) << before.error();
    const auto* before_ignore =
        kasumi::find_row(before->effective_tree, ".kasumiignore");
    ASSERT_NE(before_ignore, nullptr);
    const auto original_hash = before_ignore->hash;
    const auto original_size = before_ignore->size;

    const auto before_native_mtime =
        kasumi::platform::metadata::file_time_from_unix_nanoseconds(
            before_ignore->mtime);
    ASSERT_TRUE(before_native_mtime.has_value());
    using FileDuration = std::filesystem::file_time_type::duration;
    const auto local_subsecond = *before_native_mtime +
        std::chrono::duration_cast<FileDuration>(
            std::chrono::nanoseconds{685272100});
    const auto written = kasumi::platform::metadata::set_last_write_time(
        ignore, local_subsecond);
    ASSERT_TRUE(written.has_value()) << written.error();

    ASSERT_TRUE(sync_succeeds(client));

    auto after = remote(scenario);
    ASSERT_TRUE(after.has_value()) << after.error();
    const auto* after_ignore =
        kasumi::find_row(after->effective_tree, ".kasumiignore");
    ASSERT_NE(after_ignore, nullptr);
    EXPECT_EQ(after_ignore->hash, original_hash);
    EXPECT_EQ(after_ignore->size, original_size);
    EXPECT_FALSE(after->has_conflicts);
    expect_fixed_point(scenario, client);
}

TEST(ScannerPropagationTest, HybridObservationFailsBeforeRemoteMutation) {
    using namespace kasumi::test;
    auto scenario = make_scenario();
    const auto client = make_client(scenario, "hybrid-first");
    const auto file = client_local_dir(client) / "large.bin";
    write_large_file(file);
    const auto initial_hash = independent_file_hash(file);
    auto runtime =
        kasumi::runtime::resolve(client_environment(client).app_data_dir,
                                 client_name(client),
                                 kasumi::runtime::AccessMode::ReadOnly);
    ASSERT_TRUE(runtime);
    kasumi::Hash hybrid_hash;
    {
        UnavailableFingerprint unavailable(file);
        HashMutation mutation(file, [&] {
            mutate_large_file(file, FileMutation::Overwrite);
        });
        const auto result = sync(client);
        ASSERT_FALSE(result);
        EXPECT_NE(result.error().find("file changed while being read"),
                  std::string::npos);
        ASSERT_EQ(mutation.mutations, 1U);
        ASSERT_EQ(mutation.hashes.size(), 1U);
        hybrid_hash = mutation.hashes.front();
    }

    const auto final_hash = independent_file_hash(file);
    ASSERT_NE(hybrid_hash, initial_hash);
    ASSERT_NE(hybrid_hash, final_hash);
    const auto identifiers = remote_identifiers(scenario);
    ASSERT_TRUE(identifiers);
    EXPECT_TRUE(identifiers->empty());
    const auto stored = state(client);
    ASSERT_TRUE(stored);
    EXPECT_FALSE(stored->has_value());
    expect_no_transaction_artifacts(*runtime);
}

TEST(H3LocalSyncTest, RemoteDeletePreservesLocalConcurrentModification) {
    {
        auto scenario = make_scenario();
        const auto a = make_client(scenario, "a");
        const auto b = make_client(scenario, "b");

        kasumi::test::write_text(client_local_dir(a) / "dir/file.txt", "V1");
        ASSERT_TRUE(sync(a));
        ASSERT_TRUE(sync(b));
        remove_file(b, "dir/file.txt");
        remove_directory(b, "dir");
        ASSERT_TRUE(sync(b));

        kasumi::test::write_text(client_local_dir(a) / "dir/file.txt",
                                 "V2-local");
        auto preserve_local = sync(a);
        ASSERT_TRUE(preserve_local.has_value()) << preserve_local.error();
        ASSERT_TRUE(sync(b));
        expect_file(b, "dir/file.txt", "V2-local");
        auto observed_remote = remote(scenario);
        ASSERT_TRUE(observed_remote.has_value()) << observed_remote.error();
        expect_remote_present(*observed_remote, "dir/file.txt");
        expect_converged(scenario, {&a, &b});
        expect_fixed_point(scenario, a);
    }

    {
        auto scenario = make_scenario();
        const auto a = make_client(scenario, "a");
        const auto b = make_client(scenario, "b");

        kasumi::test::write_text(client_local_dir(a) / "root.txt", "R1");
        ASSERT_TRUE(sync(a));
        ASSERT_TRUE(sync(b));
        remove_file(b, "root.txt");
        ASSERT_TRUE(sync(b));

        kasumi::test::write_text(client_local_dir(a) / "root.txt", "R2-local");
        ASSERT_TRUE(sync(a));
        ASSERT_TRUE(sync(b));
        expect_file(b, "root.txt", "R2-local");
        expect_converged(scenario, {&a, &b});
    }
}

TEST(H3LocalSyncTest, SameFileModifyModifyPreservesBothVersions) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");
    const auto result = kasumi::test::scenarios::two_client_conflict(
        shared_scenario(scenario, a, b, "two-client-conflict"));
    ASSERT_TRUE(result.has_value()) << result.error();
}

TEST(H3LocalSyncTest, IndependentFileChangesConvergeWithoutFalseConflict) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");

    kasumi::test::write_text(client_local_dir(a) / "a.txt", "A1");
    kasumi::test::write_text(client_local_dir(a) / "b.txt", "B1");
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));

    kasumi::test::write_text(client_local_dir(a) / "a.txt", "A2");
    kasumi::test::write_text(client_local_dir(b) / "b.txt", "B2");
    ASSERT_TRUE(sync(a)); // A publica a2.
    ASSERT_TRUE(sync(b)); // B publica o merge de a2 e b2.
    ASSERT_TRUE(sync(a)); // A consome a nova head de B.

    expect_file(a, "a.txt", "A2");
    expect_file(a, "b.txt", "B2");
    expect_file(b, "a.txt", "A2");
    expect_file(b, "b.txt", "B2");
    expect_absent(a, "a.txt.kasumiconflict_local");
    expect_absent(a, "a.txt.kasumiconflict_remote");
    expect_absent(a, "b.txt.kasumiconflict_local");
    expect_absent(a, "b.txt.kasumiconflict_remote");
    expect_absent(b, "a.txt.kasumiconflict_local");
    expect_absent(b, "a.txt.kasumiconflict_remote");
    expect_absent(b, "b.txt.kasumiconflict_local");
    expect_absent(b, "b.txt.kasumiconflict_remote");
    auto observed_remote = remote(scenario);
    ASSERT_TRUE(observed_remote.has_value()) << observed_remote.error();
    expect_remote_present(*observed_remote, "a.txt");
    expect_remote_present(*observed_remote, "b.txt");

    expect_converged(scenario, {&a, &b});
    expect_fixed_point(scenario, a);
    expect_fixed_point(scenario, b);
}

TEST(H3LocalSyncTest, RemoteModifyAndLocalDeletePreservesRemoteContent) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");

    kasumi::test::write_text(client_local_dir(a) / "file.txt", "BASE");
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));

    kasumi::test::write_text(client_local_dir(a) / "file.txt",
                             "REMOTE-MODIFIED");
    const auto base_time = std::filesystem::file_time_type::clock::now();
    set_mtime(a, "file.txt", base_time + std::chrono::hours{2});
    ASSERT_TRUE(sync(a));
    remove_file(b, "file.txt");
    ASSERT_TRUE(sync(b));

    expect_file(a, "file.txt", "REMOTE-MODIFIED");
    expect_file(b, "file.txt", "REMOTE-MODIFIED");
    expect_absent(a, "file.txt.kasumiconflict_local");
    expect_absent(a, "file.txt.kasumiconflict_remote");
    expect_absent(b, "file.txt.kasumiconflict_local");
    expect_absent(b, "file.txt.kasumiconflict_remote");
    auto observed_remote = remote(scenario);
    ASSERT_TRUE(observed_remote.has_value()) << observed_remote.error();
    expect_remote_present(*observed_remote, "file.txt");

    expect_converged(scenario, {&a, &b});
    expect_fixed_point(scenario, a);
    expect_fixed_point(scenario, b);
}

TEST(H3LocalSyncTest, PersistentStateSurvivesIndependentApplicationExecutions) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");

    kasumi::test::write_text(client_local_dir(a) / "before.txt", "before");
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));
    expect_converged(scenario, {&a, &b});
    const auto independent_a = a;
    const auto independent_b = b;
    expect_fixed_point(scenario, independent_a);
    expect_fixed_point(scenario, independent_b);

    kasumi::test::write_text(client_local_dir(independent_a) / "after.txt",
                             "after");
    ASSERT_TRUE(sync(independent_a));
    const auto independent_b_again = independent_b;
    ASSERT_TRUE(sync(independent_b_again));
    expect_converged(scenario, {&independent_a, &independent_b_again});
    expect_file(independent_b_again, "after.txt", "after");
}

TEST(H3LocalSyncTest, StaleClientCatchesUpAcrossMultipleGenerations) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");

    kasumi::test::write_text(client_local_dir(a) / "alpha.txt", "A1");
    kasumi::test::write_text(client_local_dir(a) / "old.txt", "old");
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));

    kasumi::test::write_text(client_local_dir(a) / "alpha.txt", "A2");
    kasumi::test::write_text(client_local_dir(a) / "beta.txt", "B1");
    ASSERT_TRUE(sync(a));
    kasumi::test::write_text(client_local_dir(a) / "alpha.txt", "A3");
    remove_file(a, "old.txt");
    ASSERT_TRUE(sync(a));
    kasumi::test::write_text(client_local_dir(a) / "dir/gamma.txt", "G1");
    ASSERT_TRUE(sync(a));

    ASSERT_TRUE(sync(b));
    expect_file(b, "alpha.txt", "A3");
    expect_file(b, "beta.txt", "B1");
    expect_absent(b, "old.txt");
    expect_file(b, "dir/gamma.txt", "G1");
    expect_converged(scenario, {&a, &b});
    expect_fixed_point(scenario, b);
}

TEST(H3LocalSyncTest, ThreePersistentClientsConvergeBidirectionally) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");
    const auto c = make_client(scenario, "c");

    kasumi::test::write_text(client_local_dir(a) / "base.txt", "base");
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));
    ASSERT_TRUE(sync(c));

    kasumi::test::write_text(client_local_dir(b) / "from-b.txt", "B");
    ASSERT_TRUE(sync(b));
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(c));
    kasumi::test::write_text(client_local_dir(c) / "from-c.txt", "C");
    ASSERT_TRUE(sync(c)); // C publica a segunda alteração.
    ASSERT_TRUE(sync(a)); // A consome a head de C.
    ASSERT_TRUE(sync(b)); // B consome a head de C.

    expect_file(a, "from-b.txt", "B");
    expect_file(a, "from-c.txt", "C");
    expect_file(b, "from-c.txt", "C");
    expect_file(c, "from-b.txt", "B");
    expect_converged(scenario, {&a, &b, &c});
    expect_fixed_point(scenario, a);
}

TEST(H3LocalSyncTest, ConcurrentDirectoryDeletePreservesModifiedDescendant) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");

    kasumi::test::write_text(client_local_dir(a) / "docs/changed.txt",
                             "BASE-CHANGED");
    kasumi::test::write_text(client_local_dir(a) / "docs/obsolete.txt",
                             "BASE-OBSOLETE");
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));

    kasumi::test::write_text(client_local_dir(a) / "docs/changed.txt",
                             "A-MODIFIED");
    ASSERT_TRUE(sync(a));

    remove_file(b, "docs/changed.txt");
    remove_file(b, "docs/obsolete.txt");
    remove_directory(b, "docs");
    expect_absent(b, "docs");

    ASSERT_TRUE(sync(b));

    expect_file(b, "docs/changed.txt", "A-MODIFIED");
    expect_absent(b, "docs/obsolete.txt");

    ASSERT_TRUE(sync(a));

    expect_file(a, "docs/changed.txt", "A-MODIFIED");
    expect_file(b, "docs/changed.txt", "A-MODIFIED");
    expect_absent(a, "docs/obsolete.txt");
    expect_absent(b, "docs/obsolete.txt");

    auto observed_remote = remote(scenario);
    ASSERT_TRUE(observed_remote.has_value()) << observed_remote.error();
    const auto* changed_row =
        kasumi::find_row(observed_remote->effective_tree, "docs/changed.txt");
    ASSERT_NE(changed_row, nullptr);
    EXPECT_EQ(changed_row->hash, kasumi::hasher::hash_string("A-MODIFIED"));
    expect_remote_absent(*observed_remote, "docs/obsolete.txt");

    expect_converged(scenario, {&a, &b});
    expect_fixed_point(scenario, a);
    expect_fixed_point(scenario, b);
}

std::vector<std::pair<std::string, std::string>>
read_local_payloads(const Client& client) {
    std::vector<std::pair<std::string, std::string>> results;
    for (const auto& entry :
         std::filesystem::recursive_directory_iterator(client_local_dir(client))) {
        if (entry.is_regular_file()) {
            const auto rel = std::filesystem::relative(entry.path(),
                                                      client_local_dir(client));
            results.emplace_back(
                kasumi::platform::path::to_logical_utf8(rel),
                kasumi::test::read_text(entry.path()));
        }
    }
    std::ranges::sort(results);
    return results;
}

std::vector<std::string> payload_contents(
    const std::vector<std::pair<std::string, std::string>>& files) {
    std::vector<std::string> contents;
    for (const auto& [path, content] : files) {
        contents.push_back(content);
    }
    std::ranges::sort(contents);
    return contents;
}

TEST(H3LocalSyncTest, ThreeConcurrentModificationsPreserveAllVersions) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");
    const auto c = make_client(scenario, "c");

    // 1. Establish baseline
    kasumi::test::write_text(client_local_dir(a) / "file.txt", "BASE");
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));
    ASSERT_TRUE(sync(c));

    expect_file(a, "file.txt", "BASE");
    expect_file(b, "file.txt", "BASE");
    expect_file(c, "file.txt", "BASE");

    // 2. Create three genuinely concurrent modifications
    kasumi::test::write_text(client_local_dir(a) / "file.txt", "A-V2");
    kasumi::test::write_text(client_local_dir(b) / "file.txt", "B-V2");
    kasumi::test::write_text(client_local_dir(c) / "file.txt", "C-V2");

    const auto base_time = std::filesystem::file_time_type::clock::now();
    set_mtime(a, "file.txt", base_time + std::chrono::hours{1});
    set_mtime(b, "file.txt", base_time + std::chrono::hours{2});
    set_mtime(c, "file.txt", base_time + std::chrono::hours{3});

    // 3. First publication: sync A
    ASSERT_TRUE(sync(a));

    // 4. First conflict reconciliation: sync B
    ASSERT_TRUE(sync(b));

    const auto b_payloads_step4 = read_local_payloads(b);
    EXPECT_EQ(b_payloads_step4.size(), 2U);
    EXPECT_EQ(payload_contents(b_payloads_step4),
              (std::vector<std::string>{"A-V2", "B-V2"}));

    // 5. Third concurrent writer: sync C
    ASSERT_TRUE(sync(c));

    const auto c_payloads_step5 = read_local_payloads(c);
    EXPECT_EQ(c_payloads_step5.size(), 3U);
    EXPECT_EQ(payload_contents(c_payloads_step5),
              (std::vector<std::string>{"A-V2", "B-V2", "C-V2"}));

    // 6. Convergence: sync A and B again until all three consume the final state
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));
    ASSERT_TRUE(sync(c));
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));
    ASSERT_TRUE(sync(c));

    auto observed_remote = remote(scenario);

    // Required assertions on all clients
    const std::vector<std::string> expected_payloads{"A-V2", "B-V2", "C-V2"};
    for (const auto* client : {&a, &b, &c}) {
        const auto payloads = read_local_payloads(*client);
        ASSERT_EQ(payloads.size(), 3U)
            << "Client " << client_name(*client) << " does not have 3 payloads";
        EXPECT_EQ(payload_contents(payloads), expected_payloads);

        std::unordered_set<std::string> distinct_paths;
        for (const auto& [path, content] : payloads) {
            distinct_paths.insert(path);
            EXPECT_NE(content, "BASE");
        }
        EXPECT_EQ(distinct_paths.size(), 3U);
    }

    // Inspect effective remote tree
    ASSERT_TRUE(observed_remote.has_value()) << observed_remote.error();
    EXPECT_EQ(observed_remote->logical_heads.size(), 1U);

    std::vector<kasumi::Hash> remote_file_hashes;
    for (const auto& row : observed_remote->effective_tree.rows) {
        if (!row.is_directory) {
            remote_file_hashes.push_back(row.hash);
        }
    }
    std::ranges::sort(remote_file_hashes);

    std::vector<kasumi::Hash> expected_hashes{
        kasumi::hasher::hash_string("A-V2"),
        kasumi::hasher::hash_string("B-V2"),
        kasumi::hasher::hash_string("C-V2")};
    std::ranges::sort(expected_hashes);

    EXPECT_EQ(remote_file_hashes, expected_hashes);

    expect_converged(scenario, {&a, &b, &c});
    expect_fixed_point(scenario, a);
    expect_fixed_point(scenario, b);
    expect_fixed_point(scenario, c);
}

void verify_file_and_directory_branches_preserved(
    Scenario& scenario,
    const Client& a,
    const Client& b) {
    const std::vector<std::string> expected_contents{
        "CHILD-PAYLOAD", "DEEP-PAYLOAD", "FILE-PAYLOAD"};

    for (const auto* client : {&a, &b}) {
        const auto payloads = read_local_payloads(*client);
        ASSERT_EQ(payloads.size(), 3U)
            << "Client " << client_name(*client)
            << " does not have exactly 3 payloads";
        EXPECT_EQ(payload_contents(payloads), expected_contents);

        std::string file_path;
        std::string child_path;
        std::string deep_path;
        for (const auto& [path, content] : payloads) {
            if (content == "FILE-PAYLOAD") file_path = path;
            else if (content == "CHILD-PAYLOAD") child_path = path;
            else if (content == "DEEP-PAYLOAD") deep_path = path;
        }
        EXPECT_FALSE(file_path.empty());
        EXPECT_FALSE(child_path.empty());
        EXPECT_FALSE(deep_path.empty());

        // File and directory branches occupy non-overlapping logical paths
        EXPECT_NE(file_path, child_path);
        EXPECT_NE(file_path, deep_path);
        EXPECT_FALSE(child_path.starts_with(file_path + "/"));
        EXPECT_FALSE(deep_path.starts_with(file_path + "/"));

        // Ancestor/descendant consistency: child and deep must share parent directory structure
        const auto child_parent =
            std::filesystem::path(child_path).parent_path().lexically_normal();
        const auto deep_parent = std::filesystem::path(deep_path)
                                     .parent_path()
                                     .parent_path()
                                     .lexically_normal();
        EXPECT_EQ(child_parent, deep_parent);
    }

    auto observed_remote = remote(scenario);
    ASSERT_TRUE(observed_remote.has_value()) << observed_remote.error();
    EXPECT_EQ(observed_remote->logical_heads.size(), 1U);

    std::vector<kasumi::Hash> file_hashes;
    for (const auto& row : observed_remote->effective_tree.rows) {
        if (!row.is_directory) {
            file_hashes.push_back(row.hash);
        }
    }
    std::ranges::sort(file_hashes);
    std::vector<kasumi::Hash> expected_hashes{
        kasumi::hasher::hash_string("CHILD-PAYLOAD"),
        kasumi::hasher::hash_string("DEEP-PAYLOAD"),
        kasumi::hasher::hash_string("FILE-PAYLOAD")};
    std::ranges::sort(expected_hashes);
    EXPECT_EQ(file_hashes, expected_hashes);

    EXPECT_TRUE(kasumi::valid_snapshot(observed_remote->effective_tree, false));

    expect_converged(scenario, {&a, &b});
    expect_fixed_point(scenario, a);
    expect_fixed_point(scenario, b);
}

TEST(H3LocalSyncTest, ConcurrentFileDirectoryCreationPreservesBothBranches) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");

    // 1. Establish an empty shared baseline
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));
    expect_absent(a, "node");
    expect_absent(b, "node");

    // 2. Diverge without further sync
    kasumi::test::write_text(client_local_dir(a) / "node", "FILE-PAYLOAD");

    make_directory(client_local_dir(b) / "node" / "nested");
    kasumi::test::write_text(client_local_dir(b) / "node" / "child.txt",
                             "CHILD-PAYLOAD");
    kasumi::test::write_text(
        client_local_dir(b) / "node" / "nested" / "deep.txt", "DEEP-PAYLOAD");

    // 3. Publish A
    ASSERT_TRUE(sync(a));
    auto remote_after_a = remote(scenario);
    ASSERT_TRUE(remote_after_a.has_value()) << remote_after_a.error();
    const auto* remote_node =
        kasumi::find_row(remote_after_a->effective_tree, "node");
    ASSERT_NE(remote_node, nullptr);
    EXPECT_FALSE(remote_node->is_directory);
    EXPECT_EQ(remote_node->hash, kasumi::hasher::hash_string("FILE-PAYLOAD"));

    const auto stored_b_before = state(b);
    ASSERT_TRUE(stored_b_before.has_value());

    // 4. Reconcile B
    const auto sync_b_result = sync(b);
    if (!sync_b_result) {
        // Verify conservative failure properties:
        // - A's published FILE-PAYLOAD remains remotely reachable
        auto observed_remote = remote(scenario);
        ASSERT_TRUE(observed_remote.has_value()) << observed_remote.error();
        const auto* published_node =
            kasumi::find_row(observed_remote->effective_tree, "node");
        ASSERT_NE(published_node, nullptr);
        EXPECT_FALSE(published_node->is_directory);
        EXPECT_EQ(published_node->hash,
                  kasumi::hasher::hash_string("FILE-PAYLOAD"));

        // - B's local directory subtree remains intact
        expect_file(b, "node/child.txt", "CHILD-PAYLOAD");
        expect_file(b, "node/nested/deep.txt", "DEEP-PAYLOAD");

        // - No new remote commit/head was published from B
        EXPECT_EQ(observed_remote->logical_heads.size(), 1U);
        EXPECT_EQ(observed_remote->logical_heads.front(),
                  remote_after_a->logical_heads.front());

        // - B's accepted StoredState was not advanced
        const auto stored_b_after = state(b);
        ASSERT_TRUE(stored_b_after.has_value());
        if (stored_b_before->has_value()) {
            ASSERT_TRUE(stored_b_after->has_value());
            EXPECT_EQ((*stored_b_after)->commit_id,
                      (*stored_b_before)->commit_id);
            EXPECT_EQ((*stored_b_after)->height, (*stored_b_before)->height);
        }
    }

    ASSERT_TRUE(sync_b_result.has_value())
        << "sync(b) failed: " << (sync_b_result ? "" : sync_b_result.error());

    // 5. Consume on A and verify convergence
    ASSERT_TRUE(sync(a));
    verify_file_and_directory_branches_preserved(scenario, a, b);
}

TEST(H3LocalSyncTest, ConcurrentDirectoryFileCreationPreservesBothBranches) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");

    // 1. Establish an empty shared baseline
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));
    expect_absent(a, "node");
    expect_absent(b, "node");

    // 2. Diverge: A creates directory subtree, B creates regular file
    make_directory(client_local_dir(a) / "node" / "nested");
    kasumi::test::write_text(client_local_dir(a) / "node" / "child.txt",
                             "CHILD-PAYLOAD");
    kasumi::test::write_text(
        client_local_dir(a) / "node" / "nested" / "deep.txt", "DEEP-PAYLOAD");

    kasumi::test::write_text(client_local_dir(b) / "node", "FILE-PAYLOAD");

    // 3. Publish A (directory subtree)
    ASSERT_TRUE(sync(a));
    auto remote_after_a = remote(scenario);
    ASSERT_TRUE(remote_after_a.has_value()) << remote_after_a.error();
    const auto* remote_node =
        kasumi::find_row(remote_after_a->effective_tree, "node");
    ASSERT_NE(remote_node, nullptr);
    EXPECT_TRUE(remote_node->is_directory);
    expect_remote_present(*remote_after_a, "node/child.txt");
    expect_remote_present(*remote_after_a, "node/nested/deep.txt");

    const auto stored_b_before = state(b);
    ASSERT_TRUE(stored_b_before.has_value());

    // 4. Reconcile B (regular file)
    const auto sync_b_result = sync(b);
    if (!sync_b_result) {
        // Verify conservative failure properties:
        // - A's published directory subtree remains remotely reachable
        auto observed_remote = remote(scenario);
        ASSERT_TRUE(observed_remote.has_value()) << observed_remote.error();
        const auto* published_node =
            kasumi::find_row(observed_remote->effective_tree, "node");
        ASSERT_NE(published_node, nullptr);
        EXPECT_TRUE(published_node->is_directory);
        expect_remote_present(*observed_remote, "node/child.txt");
        expect_remote_present(*observed_remote, "node/nested/deep.txt");

        // - B's local file remains intact
        expect_file(b, "node", "FILE-PAYLOAD");

        // - No new remote commit/head was published from B
        EXPECT_EQ(observed_remote->logical_heads.size(), 1U);
        EXPECT_EQ(observed_remote->logical_heads.front(),
                  remote_after_a->logical_heads.front());

        // - B's accepted StoredState was not advanced
        const auto stored_b_after = state(b);
        ASSERT_TRUE(stored_b_after.has_value());
        if (stored_b_before->has_value()) {
            ASSERT_TRUE(stored_b_after->has_value());
            EXPECT_EQ((*stored_b_after)->commit_id,
                      (*stored_b_before)->commit_id);
            EXPECT_EQ((*stored_b_after)->height, (*stored_b_before)->height);
        }
    }

    ASSERT_TRUE(sync_b_result.has_value())
        << "sync(b) failed: " << (sync_b_result ? "" : sync_b_result.error());

    // 5. Consume on A and verify convergence
    ASSERT_TRUE(sync(a));
    verify_file_and_directory_branches_preserved(scenario, a, b);
}

} // namespace
