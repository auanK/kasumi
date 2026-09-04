#include "application/execute.hpp"
#include "application/observation/history.hpp"
#include "application/observation/scanner.hpp"
#include "application/profile.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/change_journal.hpp"
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

using Client = std::tuple<std::string, ExecutionEnvironment,
                          std::filesystem::path>;
using Scenario = std::tuple<kasumi::test::TempWorkspace,
                            std::filesystem::path, std::uint64_t>;

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
                .remote_dir = remote.string()},
        MasterKeyHex{std::string{key_hex}});
    if (!created) {
        throw std::runtime_error("could not create E2E profile: " +
                                 created.error().detail);
    }
    return result;
}

std::expected<void, std::string> sync(const Client& client) {
    auto result = kasumi::application::execute(
        {Request{Operation::Sync, client_name(client)},
         Credentials{NoCredentials{}},
         client_environment(client)});
    if (!result) {
        return std::unexpected(result.error().detail);
    }
    return {};
}

std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> decode_key() {
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> result{};
    result.fill(0x77U);
    return result;
}

std::expected<StorageView, std::string> remote(Scenario& scenario) {
    const auto& remote_path = std::get<1>(scenario);
    auto storage = kasumi::transport::open_transport(remote_path.string());
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
    auto storage = kasumi::transport::open_transport(remote_path.string());
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
    auto runtime = kasumi::runtime::resolve(
        client_environment(client).app_data_dir,
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
    auto runtime = kasumi::runtime::resolve(
        client_environment(client).app_data_dir,
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
    ASSERT_TRUE(observed.has_value())
        << (observed ? "" : observed.error());
    ASSERT_EQ(observed->logical_heads.size(), 1U);

    for (const auto* client : clients) {
        auto stored = state(*client);
        ASSERT_TRUE(stored.has_value()) << stored.error();
        ASSERT_TRUE(stored->has_value());
        EXPECT_EQ((*stored)->commit_id, observed->logical_heads.front());
        EXPECT_EQ((*stored)->tree, observed->effective_tree);

        auto stored_checkpoint = checkpoint(*client);
        ASSERT_TRUE(stored_checkpoint.has_value())
            << stored_checkpoint.error();
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
    ASSERT_TRUE(before_checkpoint.has_value())
        << before_checkpoint.error();
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
    ASSERT_TRUE(after_checkpoint.has_value())
        << after_checkpoint.error();
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
    std::error_code error;
    std::filesystem::last_write_time(client_local_dir(client) / path,
                                     timestamp,
                                     error);
    ASSERT_FALSE(error) << error.message();
}

void remove_file(const Client& client, std::string_view path) {
    std::error_code error;
    ASSERT_TRUE(std::filesystem::remove(client_local_dir(client) / path, error));
    ASSERT_FALSE(error) << error.message();
}

void remove_directory(const Client& client, std::string_view path) {
    std::error_code error;
    ASSERT_TRUE(std::filesystem::remove(client_local_dir(client) / path, error));
    ASSERT_FALSE(error) << error.message();
}

void expect_file(const Client& client,
                 std::string_view path,
                 std::string_view contents) {
    ASSERT_TRUE(std::filesystem::is_regular_file(client_local_dir(client) /
                                                 path));
    EXPECT_EQ(kasumi::test::read_text(client_local_dir(client) / path),
              contents);
}

void expect_absent(const Client& client, std::string_view path) {
    EXPECT_FALSE(std::filesystem::exists(client_local_dir(client) / path));
}

void expect_remote_present(const StorageView& remote,
                           std::string_view path) {
    EXPECT_NE(kasumi::find_row(remote.effective_tree, path), nullptr);
}

void expect_remote_absent(const StorageView& remote, std::string_view path) {
    EXPECT_EQ(kasumi::find_row(remote.effective_tree, path), nullptr);
}

TEST(H3LocalSyncTest, BootstrapAndNestedTreeConverge) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");

    const auto unicode_dir =
        std::filesystem::path(
            reinterpret_cast<const char8_t*>(u8"pasta-日本"));
    const auto unicode_file =
        std::filesystem::path(
            reinterpret_cast<const char8_t*>(u8"usuário-☁.txt"));
    const auto a_unicode = client_local_dir(a) / unicode_dir / unicode_file;
    const std::string expected_dir_utf8 = "pasta-日本";
    const std::string expected_file_utf8 = "pasta-日本/usuário-☁.txt";

    kasumi::test::write_text(client_local_dir(a) / "alpha.txt", "alpha");
    kasumi::test::write_text(client_local_dir(a) / "beta.txt", "beta");
    kasumi::test::write_text(client_local_dir(a) / "docs/readme.txt", "readme");
    kasumi::test::write_text(client_local_dir(a) / "docs/nested/data.txt",
                             "data");
    kasumi::test::write_text(client_local_dir(a) / "images/image.bin",
                             "binary");
    kasumi::test::write_text(a_unicode, "unicode-v1");

    ASSERT_TRUE(sync(a));
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

    ASSERT_TRUE(sync(b));
    expect_file(b, "alpha.txt", "alpha");
    expect_file(b, "docs/readme.txt", "readme");
    expect_file(b, "docs/nested/data.txt", "data");
    expect_file(b, "images/image.bin", "binary");

    // Native path on client B constructed independently via char8_t
    const auto b_unicode = client_local_dir(b) / unicode_dir / unicode_file;
    ASSERT_TRUE(std::filesystem::is_regular_file(b_unicode));
    EXPECT_EQ(kasumi::test::read_text(b_unicode), "unicode-v1");

    // Re-scan client B to confirm: remote logical UTF-8 -> native path -> scanner -> logical UTF-8
    const auto b_scan =
        kasumi::application::observation::scanner::scan_result(
            client_local_dir(b));
    ASSERT_TRUE(b_scan.has_value());
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

    ASSERT_TRUE(sync(b));
    ASSERT_TRUE(sync(a));

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

TEST(H3LocalSyncTest, ModifiesFilesAndAppliesCreateModifyDeleteTogether) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");

    kasumi::test::write_text(client_local_dir(a) / "alpha.txt", "A1");
    kasumi::test::write_text(client_local_dir(a) / "beta.txt", "B1");
    kasumi::test::write_text(client_local_dir(a) / "old.txt", "old");
    kasumi::test::write_text(client_local_dir(a) / "keep.txt", "keep");
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));

    kasumi::test::write_text(client_local_dir(a) / "alpha.txt", "A2");
    kasumi::test::write_text(client_local_dir(a) / "beta.txt", "B2");
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));
    expect_file(b, "alpha.txt", "A2");
    expect_file(b, "beta.txt", "B2");

    kasumi::test::write_text(client_local_dir(b) / "alpha.txt", "A3");
    remove_file(b, "old.txt");
    kasumi::test::write_text(client_local_dir(b) / "gamma.txt", "G1");
    ASSERT_TRUE(sync(b));
    ASSERT_TRUE(sync(a));
    expect_file(a, "alpha.txt", "A3");
    expect_file(a, "beta.txt", "B2");
    expect_absent(a, "old.txt");
    expect_file(a, "gamma.txt", "G1");
    expect_file(a, "keep.txt", "keep");
    expect_converged(scenario, {&a, &b});
    expect_fixed_point(scenario, a);
}

TEST(H3LocalSyncTest, DeletesRootFilesAndPreservesAnEmptyRoot) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");

    for (const auto& [path, contents] : {
             std::pair{"alpha.txt", "alpha"},
             std::pair{"beta.txt", "beta"},
             std::pair{"gamma.txt", "gamma"},
             std::pair{"keep.txt", "keep"}}) {
        kasumi::test::write_text(client_local_dir(a) / path, contents);
    }
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));

    remove_file(b, "alpha.txt");
    remove_file(b, "beta.txt");
    ASSERT_TRUE(sync(b));
    auto observed_remote = remote(scenario);
    ASSERT_TRUE(observed_remote.has_value()) << observed_remote.error();
    expect_remote_absent(*observed_remote, "alpha.txt");
    expect_remote_absent(*observed_remote, "beta.txt");
    ASSERT_TRUE(sync(a));
    expect_absent(a, "alpha.txt");
    expect_absent(a, "beta.txt");
    expect_file(a, "keep.txt", "keep");

    remove_file(b, "gamma.txt");
    remove_file(b, "keep.txt");
    ASSERT_TRUE(sync(b));
    ASSERT_TRUE(sync(a));
    EXPECT_TRUE(std::filesystem::is_directory(client_local_dir(a)));
    EXPECT_TRUE(std::filesystem::is_directory(client_local_dir(b)));
    expect_converged(scenario, {&a, &b});
    expect_fixed_point(scenario, a);
}

TEST(H3LocalSyncTest, DeletesEmptyNestedDeepAndMixedDirectories) {
    auto scenario = make_scenario();
    const auto a = make_client(scenario, "a");
    const auto b = make_client(scenario, "b");

    make_directory(client_local_dir(a) / "empty");
    kasumi::test::write_text(client_local_dir(a) / "single/file.txt", "single");
    kasumi::test::write_text(client_local_dir(a) / "nested/b/c.txt", "c");
    kasumi::test::write_text(client_local_dir(a) / "nested/d.txt", "d");
    kasumi::test::write_text(client_local_dir(a) / "deep/a/b/c/file.txt", "deep");
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
    for (const auto path : {"empty", "single", "nested", "deep", "mixed",
                            "mixed/gamma.txt"}) {
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

    kasumi::test::write_text(client_local_dir(a) / ".kasumiignore", "ignored.txt\n");
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

        kasumi::test::write_text(client_local_dir(a) / "dir/file.txt", "V2-local");
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

    kasumi::test::write_text(client_local_dir(a) / "file.txt", "BASE");
    ASSERT_TRUE(sync(a));
    ASSERT_TRUE(sync(b));

    kasumi::test::write_text(client_local_dir(a) / "file.txt", "A-V2");
    kasumi::test::write_text(client_local_dir(b) / "file.txt", "B-V2");
    const auto base_time = std::filesystem::file_time_type::clock::now();
    set_mtime(a, "file.txt", base_time + std::chrono::hours{2});
    set_mtime(b, "file.txt", base_time + std::chrono::hours{1});

    ASSERT_TRUE(sync(a)); // A publica A-V2.
    ASSERT_TRUE(sync(b)); // B publica o merge com o artefato de conflito.
    ASSERT_TRUE(sync(a)); // A consome a nova head de B.

    expect_file(a, "file.txt", "A-V2");
    expect_file(b, "file.txt", "A-V2");
    expect_file(a, "file.txt.kasumiconflict_local", "B-V2");
    expect_file(b, "file.txt.kasumiconflict_local", "B-V2");
    expect_absent(a, "file.txt.kasumiconflict_remote");
    expect_absent(b, "file.txt.kasumiconflict_remote");
    auto observed_remote = remote(scenario);
    ASSERT_TRUE(observed_remote.has_value()) << observed_remote.error();
    expect_remote_present(*observed_remote, "file.txt");
    expect_remote_present(*observed_remote, "file.txt.kasumiconflict_local");

    expect_converged(scenario, {&a, &b});
    expect_fixed_point(scenario, a);
    expect_fixed_point(scenario, b);
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

} // namespace
