#include "application/history_storage/epoch.hpp"
#include "application/history_storage/maintenance_protocol.hpp"
#include "application/history_storage/remote_layout.hpp"
#include "application/inspection/inspect.hpp"
#include "application/profile.hpp"
#include "crypto/content.hpp"
#include "crypto/file_crypto.hpp"
#include "crypto/key_derivation.hpp"
#include "kasumi/test/history_storage.hpp"
#include "platform/path.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using kasumi::application::Credentials;
using kasumi::application::ExecutionEnvironment;
using kasumi::application::InspectionErrorCode;
using kasumi::application::InspectionOperation;
using kasumi::application::InspectionRequest;
using kasumi::application::MasterKeyHex;
using kasumi::application::NoCredentials;
using kasumi::test::TempWorkspace;
using HistoryHeadReference =
    kasumi::application::history_storage::HeadReference;

void write_profile(const TempWorkspace& workspace,
                   const std::filesystem::path& remote) {
    const auto app = kasumi::test::workspace_path(workspace, "app");
    std::filesystem::create_directories(app);
    kasumi::test::write_text(
        app / "config.toml",
        "[profiles.demo]\nlocal_dir = '" +
            kasumi::platform::path::to_utf8(
                kasumi::test::workspace_path(workspace, "local")) +
            "'\nremote_dir = '" + kasumi::platform::path::to_utf8(remote) +
            "'\nmin_history_depth = 5\nmin_history_age_hours = 6\n");
}

auto inspect_request(const TempWorkspace& workspace,
                     InspectionRequest request,
                     Credentials credentials) {
    return kasumi::application::inspect(
        {std::move(request),
         std::move(credentials),
         ExecutionEnvironment{kasumi::test::workspace_path(workspace, "app")}});
}

auto inspect(const TempWorkspace& workspace, InspectionRequest request) {
    return inspect_request(workspace,
                           std::move(request),
                           Credentials{MasterKeyHex{test_key_hex()}});
}

auto inspect(const TempWorkspace& workspace,
             InspectionOperation operation = InspectionOperation::RemoteHeads) {
    return inspect(workspace, InspectionRequest{operation, "demo"});
}

void persist_state(const TempWorkspace& workspace,
                   const kasumi::history::Commit& commit,
                   const HistoryHeadReference& head) {
    const auto database =
        kasumi::test::workspace_path(workspace, "app/profiles/demo/db.sqlite");
    std::filesystem::create_directories(database.parent_path());
    ASSERT_TRUE(kasumi::state_storage::initialize(database));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database,
        kasumi::state_storage::StoredState{
            .tree = commit.tree,
            .height = commit.height,
            .commit_id = head.commit_id,
            .ciphertext_id = head.ciphertext_id,
        }));
}

void expect_same_heads(const kasumi::application::RemoteHeadsReport& actual,
                       const kasumi::application::RemoteHeadsReport& expected) {
    EXPECT_EQ(actual.history_present, expected.history_present);
    EXPECT_EQ(actual.observed_height, expected.observed_height);
    EXPECT_EQ(actual.physical_marker_count, expected.physical_marker_count);
    EXPECT_EQ(actual.ancestral_marker_count, expected.ancestral_marker_count);
    ASSERT_EQ(actual.heads.size(), expected.heads.size());
    for (std::size_t index = 0; index < actual.heads.size(); ++index) {
        const auto& left = actual.heads[index];
        const auto& right = expected.heads[index];
        EXPECT_EQ(left.commit_id, right.commit_id);
        EXPECT_EQ(left.height, right.height);
        EXPECT_EQ(left.created_at, right.created_at);
        EXPECT_EQ(left.root_hash, right.root_hash);
        EXPECT_EQ(left.file_count, right.file_count);
        EXPECT_EQ(left.directory_count, right.directory_count);
        EXPECT_EQ(left.total_bytes, right.total_bytes);
    }
}

void expect_same_tree(const kasumi::application::RemoteTreeReport& actual,
                      const kasumi::application::RemoteTreeReport& expected) {
    EXPECT_EQ(actual.history_present, expected.history_present);
    EXPECT_EQ(actual.commit_id, expected.commit_id);
    EXPECT_EQ(actual.height, expected.height);
    EXPECT_EQ(actual.created_at, expected.created_at);
    EXPECT_EQ(actual.root_hash, expected.root_hash);
    EXPECT_EQ(actual.total_bytes, expected.total_bytes);
    EXPECT_EQ(actual.file_count, expected.file_count);
    EXPECT_EQ(actual.directory_count, expected.directory_count);
    ASSERT_EQ(actual.entries.size(), expected.entries.size());
    for (std::size_t index = 0; index < actual.entries.size(); ++index) {
        EXPECT_EQ(actual.entries[index].path, expected.entries[index].path);
        EXPECT_EQ(actual.entries[index].type, expected.entries[index].type);
        EXPECT_EQ(actual.entries[index].logical_hash,
                  expected.entries[index].logical_hash);
        EXPECT_EQ(actual.entries[index].size, expected.entries[index].size);
    }
}

kasumi::Snapshot statistics_tree() {
    kasumi::Snapshot tree{
        .rows = {
            kasumi::NodeRow{.path = "", .is_directory = true},
            kasumi::NodeRow{.path = "docs", .is_directory = true},
            kasumi::NodeRow{.path = "docs/a.txt",
                            .hash = kasumi::hasher::hash_string("a"),
                            .size = 1},
            kasumi::NodeRow{.path = "docs/b.txt",
                            .hash = kasumi::hasher::hash_string("bb"),
                            .size = 2},
            kasumi::NodeRow{.path = "empty", .is_directory = true},
            kasumi::NodeRow{.path = "root.txt",
                            .hash = kasumi::hasher::hash_string("ccc"),
                            .size = 3},
        }};
    kasumi::finalize_snapshot(tree);
    return tree;
}

kasumi::Snapshot nested_tree() {
    kasumi::Snapshot tree{
        .rows = {
            kasumi::NodeRow{.path = "", .is_directory = true},
            kasumi::NodeRow{.path = "docs", .is_directory = true},
            kasumi::NodeRow{.path = "docs/a.txt",
                            .hash = kasumi::hasher::hash_string("a"),
                            .size = 1},
            kasumi::NodeRow{.path = "docs/nested", .is_directory = true},
            kasumi::NodeRow{.path = "docs/nested/b.txt",
                            .hash = kasumi::hasher::hash_string("bb"),
                            .size = 2},
            kasumi::NodeRow{.path = "empty", .is_directory = true},
            kasumi::NodeRow{.path = "root.txt",
                            .hash = kasumi::hasher::hash_string("ccc"),
                            .size = 3},
        }};
    kasumi::finalize_snapshot(tree);
    return tree;
}

void put_object(LocalStorage& storage,
                std::string_view identifier,
                std::string_view contents = "object") {
    const auto source =
        kasumi::test::workspace_path(storage.workspace, "inspection-object");
    kasumi::test::write_text(source, contents);
    ASSERT_TRUE(kasumi::transport::put(storage.transport, source, identifier));
}

std::string put_content(LocalStorage& storage, std::string_view contents) {
    return ::put_content(
        storage.transport,
        storage.workspace,
        contents,
        "content-" + kasumi::hash_hex(kasumi::hasher::hash_string(contents)));
}

template <typename Report>
std::optional<Report> require_report(
    const std::expected<kasumi::application::InspectionResponse,
                        kasumi::application::InspectionError>& result) {
    if (!result.has_value()) {
        ADD_FAILURE() << result.error().detail;
        return std::nullopt;
    }
    const auto* report = std::get_if<Report>(&result->payload);
    if (report == nullptr) {
        ADD_FAILURE() << "unexpected inspection report variant";
        return std::nullopt;
    }
    return *report;
}

TEST(ApplicationInspectionTest, WarmFrontierPreservesHeadsAndTreeResults) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-inspection-warm");
    write_profile(workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));

    std::optional<HistoryHeadReference> previous;
    kasumi::history::Commit latest;
    for (std::uint64_t height = 0; height <= 10; ++height) {
        const std::vector<std::string> parents =
            previous ? std::vector<std::string>{previous->commit_id}
                     : std::vector<std::string>{};
        latest =
            kasumi::history::make_commit(
                height, parents, make_tree("file.txt", std::to_string(height)))
                .value();
        const auto published = publish(fixture, latest);
        if (previous) {
            ASSERT_TRUE(kasumi::transport::remove(fixture.transport,
                                                  marker_path(*previous)));
        }
        previous = published.head;
    }
    ASSERT_TRUE(previous.has_value());

    const auto cold_heads =
        inspect(workspace, InspectionOperation::RemoteHeads);

    ASSERT_TRUE(cold_heads.has_value()) << cold_heads.error().detail;
    const auto* cold_heads_report =
        std::get_if<kasumi::application::RemoteHeadsReport>(
            &cold_heads->payload);
    ASSERT_NE(cold_heads_report, nullptr);

    const auto cold_tree = inspect(workspace, InspectionOperation::RemoteTree);
    const auto cold_tree_report =
        require_report<kasumi::application::RemoteTreeReport>(cold_tree);
    ASSERT_TRUE(cold_tree_report.has_value());

    persist_state(workspace, latest, *previous);
    const auto database =
        kasumi::test::workspace_path(workspace, "app/profiles/demo/db.sqlite");
    const auto database_before = kasumi::test::read_binary(database);
    const auto config =
        kasumi::test::workspace_path(workspace, "app/config.toml");
    const auto config_before = kasumi::test::read_binary(config);
    const auto remote_before = kasumi::transport::list(fixture.transport);

    const auto warm_heads =
        inspect(workspace, InspectionOperation::RemoteHeads);

    ASSERT_TRUE(warm_heads.has_value()) << warm_heads.error().detail;
    const auto* warm_heads_report =
        std::get_if<kasumi::application::RemoteHeadsReport>(
            &warm_heads->payload);
    ASSERT_NE(warm_heads_report, nullptr);
    expect_same_heads(*warm_heads_report, *cold_heads_report);

    const auto warm_tree = inspect(workspace, InspectionOperation::RemoteTree);

    const auto warm_tree_report =
        require_report<kasumi::application::RemoteTreeReport>(warm_tree);
    ASSERT_TRUE(warm_tree_report.has_value());
    expect_same_tree(*warm_tree_report, *cold_tree_report);
    const auto remote_after = kasumi::transport::list(fixture.transport);
    EXPECT_EQ(kasumi::test::read_binary(database), database_before);
    EXPECT_EQ(kasumi::test::read_binary(config), config_before);
    ASSERT_TRUE(remote_before.has_value());
    ASSERT_TRUE(remote_after.has_value());
    EXPECT_EQ(*remote_after, *remote_before);
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "local")));
}

TEST(ApplicationInspectionTest,
     CorruptPersistedStateFallsBackToColdInspection) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-inspection-corrupt-db");
    write_profile(workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));
    const auto commit = make_commit(0, {}, "file.txt", "contents").value();
    const auto published = publish(fixture, commit);
    persist_state(workspace, commit, published.head);

    const auto database =
        kasumi::test::workspace_path(workspace, "app/profiles/demo/db.sqlite");
    kasumi::test::write_text(database, "corrupt state database");

    const auto result = inspect(workspace);

    const auto report =
        require_report<kasumi::application::RemoteHeadsReport>(result);
    ASSERT_TRUE(report.has_value());
    ASSERT_EQ(report->heads.size(), 1U);
    EXPECT_EQ(report->heads.front().commit_id, published.head.commit_id);
}

TEST(ApplicationInspectionTest,
     RemoteCommitsKeepsFullHistoryWithPersistedState) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-commits-warm");
    write_profile(workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));

    std::optional<HistoryHeadReference> previous;
    kasumi::history::Commit cached;
    for (std::uint64_t height = 0; height <= 6; ++height) {
        const std::vector<std::string> parents =
            previous ? std::vector<std::string>{previous->commit_id}
                     : std::vector<std::string>{};
        cached =
            kasumi::history::make_commit(
                height, parents, make_tree("file.txt", std::to_string(height)))
                .value();
        const auto published = publish(fixture, cached);
        if (previous) {
            ASSERT_TRUE(kasumi::transport::remove(fixture.transport,
                                                  marker_path(*previous)));
        }
        previous = published.head;
    }
    ASSERT_TRUE(previous.has_value());
    persist_state(workspace, cached, *previous);

    const auto at_six = inspect(workspace, InspectionOperation::RemoteCommits);

    const auto at_six_report =
        require_report<kasumi::application::RemoteCommitsReport>(at_six);
    ASSERT_TRUE(at_six_report.has_value());
    EXPECT_EQ(at_six_report->commits.size(), 7U);

    for (std::uint64_t height = 7; height <= 8; ++height) {
        const auto commit = kasumi::history::make_commit(
                                height,
                                {previous->commit_id},
                                make_tree("file.txt", std::to_string(height)))
                                .value();
        const auto published = publish(fixture, commit);
        ASSERT_TRUE(kasumi::transport::remove(fixture.transport,
                                              marker_path(*previous)));
        previous = published.head;
    }

    const auto at_eight =
        inspect(workspace, InspectionOperation::RemoteCommits);

    ASSERT_TRUE(at_eight.has_value()) << at_eight.error().detail;
    const auto* at_eight_report =
        std::get_if<kasumi::application::RemoteCommitsReport>(
            &at_eight->payload);
    ASSERT_NE(at_eight_report, nullptr);
    ASSERT_EQ(at_eight_report->commits.size(), 9U);
    EXPECT_EQ(at_eight_report->commits.front().height, 8U);
    EXPECT_EQ(at_eight_report->commits.back().height, 0U);
}

TEST(ApplicationInspectionTest, EmptyRemoteIsSuccessfulAndUntouched) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-inspection-empty");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    write_profile(workspace, remote);

    const auto result = inspect(workspace);

    const auto report =
        require_report<kasumi::application::RemoteHeadsReport>(result);
    ASSERT_TRUE(report.has_value());
    EXPECT_FALSE(report->history_present);
    EXPECT_TRUE(report->heads.empty());
    EXPECT_FALSE(std::filesystem::exists(remote));
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "local")));
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "app/profiles")));

    const auto requested = inspect_request(
        workspace,
        InspectionRequest{.operation = InspectionOperation::RemoteTree,
                          .profile_name = "demo",
                          .head_commit_id = std::string(64, 'a')},
        Credentials{MasterKeyHex{test_key_hex()}});
    ASSERT_FALSE(requested.has_value());
    EXPECT_EQ(requested.error().code, InspectionErrorCode::RemoteHeadNotFound);
}

TEST(ApplicationInspectionTest, RemoteTreeEmptyHistoryIsSuccessful) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-tree-empty");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    write_profile(workspace, remote);

    const auto result = inspect(workspace, InspectionOperation::RemoteTree);

    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->operation, InspectionOperation::RemoteTree);
    const auto* report =
        std::get_if<kasumi::application::RemoteTreeReport>(&result->payload);
    ASSERT_NE(report, nullptr);
    EXPECT_FALSE(report->history_present);
    EXPECT_TRUE(report->entries.empty());
    EXPECT_FALSE(std::filesystem::exists(remote));
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "local")));
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "app/profiles")));
}

TEST(ApplicationInspectionTest, RemoteTreeUsesExactSnapshotOfSingleHead) {
    auto fixture = make_local_storage();
    const auto app_workspace =
        kasumi::test::make_temp_workspace("application-tree-single");
    write_profile(app_workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));
    const auto tree = nested_tree();
    const auto commit =
        kasumi::history::make_commit(0, {}, tree, 123456).value();
    const auto published = publish(fixture, commit);

    const auto result = inspect_request(
        app_workspace,
        InspectionRequest{InspectionOperation::RemoteTree, "demo"},
        Credentials{MasterKeyHex{test_key_hex()}});

    const auto report =
        require_report<kasumi::application::RemoteTreeReport>(result);
    ASSERT_TRUE(report.has_value());
    ASSERT_TRUE(report->history_present);
    EXPECT_EQ(report->commit_id, published.head.commit_id);
    EXPECT_EQ(report->height, 0U);
    EXPECT_EQ(report->created_at, 123456);
    EXPECT_EQ(report->root_hash,
              kasumi::hash_hex(commit.tree.rows.front().hash));
    EXPECT_EQ(report->total_bytes, 6U);
    EXPECT_EQ(report->file_count, 3U);
    EXPECT_EQ(report->directory_count, 3U);
    ASSERT_EQ(report->entries.size(), commit.tree.rows.size() - 1);
    for (std::size_t index = 1; index < commit.tree.rows.size(); ++index) {
        const auto& row = commit.tree.rows[index];
        const auto& entry = report->entries[index - 1];
        EXPECT_EQ(entry.path, row.path);
        EXPECT_EQ(entry.type,
                  row.is_directory
                      ? kasumi::application::RemoteTreeEntryType::Directory
                      : kasumi::application::RemoteTreeEntryType::File);
        EXPECT_EQ(entry.logical_hash, kasumi::hash_hex(row.hash));
        EXPECT_EQ(entry.size, row.size);
    }
    EXPECT_TRUE(std::ranges::none_of(report->entries, [](const auto& entry) {
        return entry.path.empty();
    }));
}

TEST(ApplicationInspectionTest, RemoteTreeAllowsRootOnlySnapshot) {
    auto fixture = make_local_storage();
    const auto app_workspace =
        kasumi::test::make_temp_workspace("application-tree-root-only");
    write_profile(app_workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));
    kasumi::Snapshot tree{
        .rows = {kasumi::NodeRow{.path = "", .is_directory = true}}};
    kasumi::finalize_snapshot(tree);
    const auto commit = kasumi::history::make_commit(0, {}, tree, 77).value();
    const auto published = publish(fixture, commit);

    const auto result = inspect_request(
        app_workspace,
        InspectionRequest{InspectionOperation::RemoteTree, "demo"},
        Credentials{MasterKeyHex{test_key_hex()}});

    const auto report =
        require_report<kasumi::application::RemoteTreeReport>(result);
    ASSERT_TRUE(report.has_value());
    EXPECT_EQ(report->commit_id, published.head.commit_id);
    EXPECT_EQ(report->file_count, 0U);
    EXPECT_EQ(report->directory_count, 0U);
    EXPECT_EQ(report->total_bytes, 0U);
    EXPECT_TRUE(report->entries.empty());
}

TEST(ApplicationInspectionTest,
     RemoteTreeRequiresSelectionAndUsesOnlySelectedHeadSnapshot) {
    auto fixture = make_local_storage();
    const auto app_workspace =
        kasumi::test::make_temp_workspace("application-tree-multi-head");
    write_profile(app_workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));
    const auto base =
        publish(fixture, make_commit(0, {}, "base.txt", "base").value());
    const auto left = publish(
        fixture, make_commit(1, {base.head.commit_id}, "a.txt", "a").value());
    const auto right = publish(
        fixture, make_commit(1, {base.head.commit_id}, "b.txt", "b").value());

    const auto ambiguous = inspect_request(
        app_workspace,
        InspectionRequest{InspectionOperation::RemoteTree, "demo"},
        Credentials{MasterKeyHex{test_key_hex()}});
    ASSERT_FALSE(ambiguous.has_value());
    EXPECT_EQ(ambiguous.error().code,
              InspectionErrorCode::HeadSelectionRequired);
    ASSERT_EQ(ambiguous.error().candidate_ids.size(), 2U);
    const auto first = std::min(left.head.commit_id, right.head.commit_id);
    const auto second = std::max(left.head.commit_id, right.head.commit_id);
    EXPECT_EQ(ambiguous.error().candidate_ids[0], first);
    EXPECT_EQ(ambiguous.error().candidate_ids[1], second);

    const auto selected_left = inspect_request(
        app_workspace,
        InspectionRequest{.operation = InspectionOperation::RemoteTree,
                          .profile_name = "demo",
                          .head_commit_id = left.head.commit_id},
        Credentials{MasterKeyHex{test_key_hex()}});
    ASSERT_TRUE(selected_left.has_value()) << selected_left.error().detail;
    const auto* left_report =
        std::get_if<kasumi::application::RemoteTreeReport>(
            &selected_left->payload);
    ASSERT_NE(left_report, nullptr);
    EXPECT_EQ(left_report->commit_id, left.head.commit_id);
    ASSERT_EQ(left_report->entries.size(), 1U);
    EXPECT_EQ(left_report->entries.front().path, "a.txt");
    EXPECT_EQ(std::ranges::none_of(left_report->entries,
                                   [](const auto& entry) {
                                       return entry.path == "b.txt";
                                   }),
              true);

    const auto selected_right = inspect_request(
        app_workspace,
        InspectionRequest{.operation = InspectionOperation::RemoteTree,
                          .profile_name = "demo",
                          .head_commit_id = right.head.commit_id},
        Credentials{MasterKeyHex{test_key_hex()}});
    ASSERT_TRUE(selected_right.has_value()) << selected_right.error().detail;
    const auto* right_report =
        std::get_if<kasumi::application::RemoteTreeReport>(
            &selected_right->payload);
    ASSERT_NE(right_report, nullptr);
    EXPECT_EQ(right_report->commit_id, right.head.commit_id);
    ASSERT_EQ(right_report->entries.size(), 1U);
    EXPECT_EQ(right_report->entries.front().path, "b.txt");
    EXPECT_TRUE(
        std::ranges::none_of(right_report->entries, [](const auto& entry) {
            return entry.path == "a.txt";
        }));
}

TEST(ApplicationInspectionTest, RemoteTreeRejectsAncestorAndUnknownHeadIds) {
    auto fixture = make_local_storage();
    const auto app_workspace =
        kasumi::test::make_temp_workspace("application-tree-head-errors");
    write_profile(app_workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));
    const auto ancestor =
        publish(fixture, make_commit(0, {}, "old.txt", "old").value());
    const auto current = publish(
        fixture,
        make_commit(1, {ancestor.head.commit_id}, "new.txt", "new").value());

    const auto old_result = inspect_request(
        app_workspace,
        InspectionRequest{.operation = InspectionOperation::RemoteTree,
                          .profile_name = "demo",
                          .head_commit_id = ancestor.head.commit_id},
        Credentials{MasterKeyHex{test_key_hex()}});
    ASSERT_FALSE(old_result.has_value());
    EXPECT_EQ(old_result.error().code, InspectionErrorCode::RemoteHeadNotFound);
    ASSERT_EQ(old_result.error().candidate_ids.size(), 1U);
    EXPECT_EQ(old_result.error().candidate_ids.front(), current.head.commit_id);

    const auto unknown_result = inspect_request(
        app_workspace,
        InspectionRequest{.operation = InspectionOperation::RemoteTree,
                          .profile_name = "demo",
                          .head_commit_id = std::string(64, 'f')},
        Credentials{MasterKeyHex{test_key_hex()}});
    ASSERT_FALSE(unknown_result.has_value());
    EXPECT_EQ(unknown_result.error().code,
              InspectionErrorCode::RemoteHeadNotFound);
    ASSERT_EQ(unknown_result.error().candidate_ids.size(), 1U);
    EXPECT_EQ(unknown_result.error().candidate_ids.front(),
              current.head.commit_id);
}

TEST(ApplicationInspectionTest, RemoteHeadsRejectsHeadSelector) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-head-selector");
    write_profile(workspace, kasumi::test::workspace_path(workspace, "remote"));

    const auto result = inspect_request(
        workspace,
        InspectionRequest{.operation = InspectionOperation::RemoteHeads,
                          .profile_name = "demo",
                          .head_commit_id = "commit"},
        Credentials{NoCredentials{}});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, InspectionErrorCode::InvalidRequest);
}

TEST(ApplicationInspectionTest,
     RemoteTreeWithPersistedKeyDoesNotMutateProfile) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-tree-real-profile");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto profile = kasumi::application::Profile{
        .name = "demo",
        .local_dir = local,
        .remote_dir = kasumi::platform::path::to_utf8(
            kasumi::test::workspace_path(fixture.workspace, "storage"))};
    ASSERT_TRUE(kasumi::application::create_profile(
        environment, profile, MasterKeyHex{test_key_hex()}));

    const auto config_path = environment.app_data_dir / "config.toml";
    const auto key_path = environment.app_data_dir / "profiles/demo/key.bin";
    const auto database_path =
        environment.app_data_dir / "profiles/demo/db.sqlite";
    const auto config_before = kasumi::test::read_binary(config_path);
    const auto key_before = kasumi::test::read_binary(key_path);
    const auto database_before = kasumi::test::read_binary(database_path);
    const auto published =
        publish(fixture, make_commit(0, {}, "file.txt", "contents").value());
    const auto before = kasumi::transport::list(fixture.transport);

    const auto result = inspect_request(
        workspace,
        InspectionRequest{InspectionOperation::RemoteTree, "demo"},
        Credentials{NoCredentials{}});

    const auto after = kasumi::transport::list(fixture.transport);
    const auto report =
        require_report<kasumi::application::RemoteTreeReport>(result);
    ASSERT_TRUE(report.has_value());
    EXPECT_EQ(report->commit_id, published.head.commit_id);
    ASSERT_TRUE(before.has_value());
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(*before, *after);
    EXPECT_EQ(kasumi::test::read_binary(config_path), config_before);
    EXPECT_EQ(kasumi::test::read_binary(key_path), key_before);
    EXPECT_EQ(kasumi::test::read_binary(database_path), database_before);
    EXPECT_FALSE(std::filesystem::exists(local));
}

TEST(ApplicationInspectionTest, ReportsAuthenticatedHeadMetadataAndStatistics) {
    auto fixture = make_local_storage();
    const auto app_workspace =
        kasumi::test::make_temp_workspace("application-inspection-one");
    write_profile(app_workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));

    const auto commit =
        kasumi::history::make_commit(0, {}, statistics_tree(), 123456).value();
    const auto published = publish(fixture, commit);
    ASSERT_FALSE(published.head.commit_id.empty());

    const auto result = inspect(app_workspace);

    const auto report_ptr =
        require_report<kasumi::application::RemoteHeadsReport>(result);
    ASSERT_TRUE(report_ptr.has_value());
    const auto& report = *report_ptr;
    ASSERT_TRUE(report.history_present);
    ASSERT_EQ(report.heads.size(), 1U);
    const auto& head = report.heads.front();
    EXPECT_EQ(head.commit_id, published.head.commit_id);
    EXPECT_EQ(head.height, 0U);
    EXPECT_EQ(head.created_at, 123456);
    EXPECT_TRUE(head.parent_ids.empty());
    EXPECT_EQ(head.root_hash, kasumi::hash_hex(commit.tree.rows.front().hash));
    EXPECT_EQ(head.file_count, 3U);
    EXPECT_EQ(head.directory_count, 2U);
    EXPECT_EQ(head.total_bytes, 6U);
    EXPECT_EQ(report.observed_height, 0U);
    EXPECT_EQ(report.physical_marker_count, 1U);
}

TEST(ApplicationInspectionTest, ReportsOnlyLogicalHeadsInDeterministicOrder) {
    auto fixture = make_local_storage();
    const auto app_workspace =
        kasumi::test::make_temp_workspace("application-inspection-forks");
    write_profile(app_workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));

    const auto base =
        publish(fixture, make_commit(0, {}, "base.txt", "base").value());
    const auto first = publish(
        fixture, make_commit(1, {base.head.commit_id}, "a.txt", "a").value());
    const auto second = publish(
        fixture, make_commit(1, {base.head.commit_id}, "b.txt", "b").value());

    const auto result = inspect(app_workspace);

    const auto report =
        require_report<kasumi::application::RemoteHeadsReport>(result);
    ASSERT_TRUE(report.has_value());
    const auto& heads = report->heads;
    ASSERT_EQ(heads.size(), 2U);
    const auto expected_first =
        std::min(first.head.commit_id, second.head.commit_id);
    const auto expected_second =
        std::max(first.head.commit_id, second.head.commit_id);
    EXPECT_EQ(heads[0].commit_id, expected_first);
    EXPECT_EQ(heads[1].commit_id, expected_second);
    EXPECT_GE(report->ancestral_marker_count, 1U);
}

TEST(ApplicationInspectionTest, DoesNotMutateRemoteOrRequireMissingKey) {
    auto fixture = make_local_storage();
    const auto app_workspace =
        kasumi::test::make_temp_workspace("application-inspection-ro");
    write_profile(app_workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));
    const auto commit =
        publish(fixture, make_commit(0, {}, "file.txt", "contents").value());
    ASSERT_FALSE(commit.head.commit_id.empty());

    const auto before = kasumi::transport::list(fixture.transport);
    const auto result = inspect(app_workspace);
    const auto after = kasumi::transport::list(fixture.transport);

    ASSERT_TRUE(result.has_value()) << result.error().detail;
    ASSERT_TRUE(before.has_value());
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(*before, *after);
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(app_workspace, "app/profiles")));
}

TEST(ApplicationInspectionTest, UsesPersistedKeyFromProfileCreatedNormally) {
    auto fixture = make_local_storage();
    auto workspace = kasumi::test::make_temp_workspace(
        "application-inspection-real-profile");
    const ExecutionEnvironment environment{
        kasumi::test::workspace_path(workspace, "app")};
    const auto local = kasumi::test::workspace_path(workspace, "local");
    const auto profile = kasumi::application::Profile{
        .name = "demo",
        .local_dir = local,
        .remote_dir = kasumi::platform::path::to_utf8(
            kasumi::test::workspace_path(fixture.workspace, "storage"))};

    ASSERT_TRUE(kasumi::application::create_profile(
        environment, profile, MasterKeyHex{test_key_hex()}));
    const auto key_path =
        kasumi::test::workspace_path(workspace, "app/profiles/demo/key.bin");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "app/profiles/demo/db.sqlite");
    ASSERT_TRUE(std::filesystem::exists(key_path));
    const auto config_path =
        kasumi::test::workspace_path(workspace, "app/config.toml");
    const auto key_before = kasumi::test::read_binary(key_path);
    const auto config_before = kasumi::test::read_binary(config_path);
    const auto database_before = kasumi::test::read_binary(database_path);

    const auto published =
        publish(fixture, make_commit(0, {}, "file.txt", "contents").value());
    ASSERT_FALSE(published.head.commit_id.empty());
    const auto before = kasumi::transport::list(fixture.transport);

    const auto result = kasumi::application::inspect(
        {InspectionRequest{InspectionOperation::RemoteHeads, "demo"},
         Credentials{NoCredentials{}},
         environment});

    const auto after = kasumi::transport::list(fixture.transport);
    const auto report =
        require_report<kasumi::application::RemoteHeadsReport>(result);
    ASSERT_TRUE(report.has_value());
    ASSERT_TRUE(report->history_present);
    ASSERT_EQ(report->heads.size(), 1U);
    EXPECT_EQ(report->heads.front().commit_id, published.head.commit_id);
    ASSERT_TRUE(before.has_value());
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(*before, *after);
    EXPECT_EQ(kasumi::test::read_binary(key_path), key_before);
    EXPECT_EQ(kasumi::test::read_binary(config_path), config_before);
    EXPECT_EQ(kasumi::test::read_binary(database_path), database_before);
    EXPECT_FALSE(std::filesystem::exists(local));
}

TEST(ApplicationInspectionTest, MissingCredentialIsReportedExplicitly) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-inspection-credentials");
    write_profile(workspace, kasumi::test::workspace_path(workspace, "remote"));

    const auto result = kasumi::application::inspect(
        {InspectionRequest{InspectionOperation::RemoteHeads, "demo"},
         Credentials{NoCredentials{}},
         ExecutionEnvironment{kasumi::test::workspace_path(workspace, "app")}});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, InspectionErrorCode::CredentialsRequired);
}

TEST(ApplicationInspectionTest,
     InvalidCredentialNeverReturnsUnauthenticatedHeads) {
    auto fixture = make_local_storage();
    const auto app_workspace =
        kasumi::test::make_temp_workspace("application-inspection-invalid-key");
    write_profile(app_workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));
    const auto published =
        publish(fixture, make_commit(0, {}, "file.txt", "contents").value());
    ASSERT_FALSE(published.head.commit_id.empty());
    const std::array<std::uint8_t, 32> wrong_key{};
    const auto default_layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    const auto wrong_layout =
        kasumi::application::history_storage::derive_remote_layout(wrong_key);
    const auto remote_storage =
        kasumi::test::workspace_path(fixture.workspace, "storage");
    const auto source_identifier =
        kasumi::application::history_storage::marker_object(default_layout,
                                                            published.head);
    const auto target_identifier =
        kasumi::application::history_storage::marker_object(wrong_layout,
                                                            published.head);
    const auto source_path = remote_storage / source_identifier;
    const auto target_path = remote_storage / target_identifier;
    std::filesystem::create_directories(target_path.parent_path());
    std::filesystem::copy_file(source_path, target_path);

    const auto result = kasumi::application::inspect(
        {InspectionRequest{InspectionOperation::RemoteHeads, "demo"},
         Credentials{MasterKeyHex{std::string(64, '0')}},
         ExecutionEnvironment{
             kasumi::test::workspace_path(app_workspace, "app")}});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code,
              InspectionErrorCode::RemoteObservationFailure);
}

TEST(ApplicationInspectionTest, RemoteCommitsEmptyHistoryIsSuccessful) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-commits-empty");
    const auto remote = kasumi::test::workspace_path(workspace, "remote");
    write_profile(workspace, remote);

    const auto result = inspect(workspace, InspectionOperation::RemoteCommits);

    ASSERT_TRUE(result.has_value()) << result.error().detail;
    EXPECT_EQ(result->operation, InspectionOperation::RemoteCommits);
    const auto* report =
        std::get_if<kasumi::application::RemoteCommitsReport>(&result->payload);
    ASSERT_NE(report, nullptr);
    EXPECT_FALSE(report->history_present);
    EXPECT_TRUE(report->logical_head_ids.empty());
    EXPECT_TRUE(report->commits.empty());
    EXPECT_FALSE(std::filesystem::exists(remote));
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "local")));
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "app/profiles")));
}

TEST(ApplicationInspectionTest,
     RemoteCommitsListsLinearHistoryWithMetadataAndFlags) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-commits-linear");
    write_profile(workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));

    const auto c0 =
        kasumi::history::make_commit(0, {}, make_tree("c0.txt", "zero"), 100)
            .value();
    const auto p0 = publish(fixture, c0);
    const auto c1 = kasumi::history::make_commit(
                        1, {p0.head.commit_id}, make_tree("c1.txt", "one"), 200)
                        .value();
    const auto p1 = publish(fixture, c1);
    const auto c2 = kasumi::history::make_commit(
                        2, {p1.head.commit_id}, make_tree("c2.txt", "two"), 300)
                        .value();
    const auto p2 = publish(fixture, c2);
    const auto c3 =
        kasumi::history::make_commit(
            3, {p2.head.commit_id}, make_tree("c3.txt", "three"), 400)
            .value();
    const auto p3 = publish(fixture, c3);

    const auto before = kasumi::transport::list(fixture.transport);
    const auto result = inspect(workspace, InspectionOperation::RemoteCommits);
    const auto after = kasumi::transport::list(fixture.transport);

    const auto report =
        require_report<kasumi::application::RemoteCommitsReport>(result);
    ASSERT_TRUE(report.has_value());
    ASSERT_TRUE(report->history_present);
    ASSERT_EQ(report->commits.size(), 4U);
    ASSERT_EQ(report->logical_head_ids.size(), 1U);
    EXPECT_EQ(report->logical_head_ids.front(), p3.head.commit_id);
    EXPECT_EQ(report->commits[0].commit_id, p3.head.commit_id);
    EXPECT_EQ(report->commits[1].commit_id, p2.head.commit_id);
    EXPECT_EQ(report->commits[2].commit_id, p1.head.commit_id);
    EXPECT_EQ(report->commits[3].commit_id, p0.head.commit_id);

    const auto verify = [](const auto& actual,
                           const auto& commit,
                           const std::string& id,
                           std::uint64_t height,
                           std::int64_t created_at,
                           const std::vector<std::string>& parents) {
        EXPECT_EQ(actual.commit_id, id);
        EXPECT_EQ(actual.height, height);
        EXPECT_EQ(actual.created_at, created_at);
        EXPECT_EQ(actual.parent_ids, parents);
        EXPECT_EQ(actual.root_hash,
                  kasumi::hash_hex(commit.tree.rows.front().hash));
        EXPECT_EQ(actual.total_bytes, commit.tree.rows.front().size);
        EXPECT_EQ(actual.entry_count, commit.tree.rows.size() - 1);
    };
    verify(report->commits[3], c0, p0.head.commit_id, 0, 100, {});
    verify(
        report->commits[2], c1, p1.head.commit_id, 1, 200, {p0.head.commit_id});
    verify(
        report->commits[1], c2, p2.head.commit_id, 2, 300, {p1.head.commit_id});
    verify(
        report->commits[0], c3, p3.head.commit_id, 3, 400, {p2.head.commit_id});
    EXPECT_TRUE(report->commits[0].logical_head);
    EXPECT_FALSE(report->commits[1].logical_head);
    EXPECT_FALSE(report->commits[2].logical_head);
    EXPECT_FALSE(report->commits[3].logical_head);
    EXPECT_TRUE(report->commits[0].physically_marked);
    EXPECT_TRUE(report->commits[1].physically_marked);
    EXPECT_TRUE(report->commits[2].physically_marked);
    EXPECT_TRUE(report->commits[3].physically_marked);
    EXPECT_FALSE(report->commits[0].ancestral_marked);
    EXPECT_TRUE(report->commits[1].ancestral_marked);
    EXPECT_TRUE(report->commits[2].ancestral_marked);
    EXPECT_TRUE(report->commits[3].ancestral_marked);
    ASSERT_TRUE(before.has_value());
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(*before, *after);
}

TEST(ApplicationInspectionTest,
     RemoteCommitsReportsBranchesAndUsesDeterministicOrdering) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-commits-branches");
    write_profile(workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));

    const auto base = publish(
        fixture,
        kasumi::history::make_commit(0, {}, make_tree("base", "base"), 100)
            .value());
    const auto branch_base =
        publish(fixture,
                kasumi::history::make_commit(
                    1, {base.head.commit_id}, make_tree("base-1", "one"), 150)
                    .value());
    const auto older = publish(
        fixture,
        kasumi::history::make_commit(
            2, {branch_base.head.commit_id}, make_tree("older", "older"), 200)
            .value());
    const auto newer = publish(
        fixture,
        kasumi::history::make_commit(
            2, {branch_base.head.commit_id}, make_tree("newer", "newer"), 300)
            .value());

    const auto result = inspect(workspace, InspectionOperation::RemoteCommits);
    const auto report =
        require_report<kasumi::application::RemoteCommitsReport>(result);
    ASSERT_TRUE(report.has_value());
    ASSERT_EQ(report->commits.size(), 4U);
    EXPECT_EQ(report->commits[0].commit_id, newer.head.commit_id);
    EXPECT_EQ(report->commits[1].commit_id, older.head.commit_id);
    EXPECT_EQ(report->commits[2].commit_id, branch_base.head.commit_id);
    EXPECT_EQ(report->commits[3].commit_id, base.head.commit_id);
    ASSERT_EQ(report->logical_head_ids.size(), 2U);
    EXPECT_EQ(report->logical_head_ids[0],
              std::min(older.head.commit_id, newer.head.commit_id));
    EXPECT_EQ(report->logical_head_ids[1],
              std::max(older.head.commit_id, newer.head.commit_id));
    EXPECT_TRUE(report->commits[0].logical_head);
    EXPECT_TRUE(report->commits[1].logical_head);
    EXPECT_FALSE(report->commits[2].logical_head);
    EXPECT_FALSE(report->commits[3].logical_head);
    EXPECT_TRUE(report->commits[2].ancestral_marked);
    EXPECT_TRUE(report->commits[3].ancestral_marked);
}

TEST(ApplicationInspectionTest,
     RemoteCommitsBreaksEqualHeightAndTimestampByCommitId) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-commits-tie");
    write_profile(workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));

    const auto base = publish(
        fixture,
        kasumi::history::make_commit(0, {}, make_tree("base", "base"), 100)
            .value());
    const auto first =
        publish(fixture,
                kasumi::history::make_commit(
                    1, {base.head.commit_id}, make_tree("first", "first"), 200)
                    .value());
    const auto left =
        publish(fixture,
                kasumi::history::make_commit(
                    2, {first.head.commit_id}, make_tree("left", "left"), 300)
                    .value());
    const auto right =
        publish(fixture,
                kasumi::history::make_commit(
                    2, {first.head.commit_id}, make_tree("right", "right"), 300)
                    .value());

    const auto result = inspect(workspace, InspectionOperation::RemoteCommits);
    const auto report =
        require_report<kasumi::application::RemoteCommitsReport>(result);
    ASSERT_TRUE(report.has_value());
    ASSERT_EQ(report->commits.size(), 4U);
    EXPECT_EQ(report->commits[0].commit_id,
              std::min(left.head.commit_id, right.head.commit_id));
    EXPECT_EQ(report->commits[1].commit_id,
              std::max(left.head.commit_id, right.head.commit_id));
}

TEST(ApplicationInspectionTest, RemoteCommitsPreservesMergeParents) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-commits-merge");
    write_profile(workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));

    const auto base = publish(
        fixture,
        kasumi::history::make_commit(0, {}, make_tree("base", "base"), 100)
            .value());
    const auto left =
        publish(fixture,
                kasumi::history::make_commit(
                    1, {base.head.commit_id}, make_tree("left", "left"), 200)
                    .value());
    const auto right =
        publish(fixture,
                kasumi::history::make_commit(
                    1, {base.head.commit_id}, make_tree("right", "right"), 300)
                    .value());
    const auto merge = publish(fixture,
                               kasumi::history::make_commit(
                                   2,
                                   {left.head.commit_id, right.head.commit_id},
                                   make_tree("merge", "merge"),
                                   400)
                                   .value());

    const auto result = inspect(workspace, InspectionOperation::RemoteCommits);
    const auto report =
        require_report<kasumi::application::RemoteCommitsReport>(result);
    ASSERT_TRUE(report.has_value());
    ASSERT_EQ(report->commits.size(), 4U);
    const auto& merge_info = report->commits.front();
    EXPECT_EQ(merge_info.commit_id, merge.head.commit_id);
    EXPECT_TRUE(merge_info.logical_head);
    ASSERT_EQ(merge_info.parent_ids.size(), 2U);
    EXPECT_EQ(merge_info.parent_ids[0], left.head.commit_id);
    EXPECT_EQ(merge_info.parent_ids[1], right.head.commit_id);
    EXPECT_TRUE(
        std::ranges::find(report->logical_head_ids, merge.head.commit_id) !=
        report->logical_head_ids.end());
}

TEST(ApplicationInspectionTest, RemoteCommitsExcludesPhysicalOrphan) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-commits-orphan");
    write_profile(workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));

    const auto base = publish(
        fixture,
        kasumi::history::make_commit(0, {}, make_tree("base", "base"), 100)
            .value());
    const auto current = publish(
        fixture,
        kasumi::history::make_commit(
            1, {base.head.commit_id}, make_tree("current", "current"), 200)
            .value());
    const auto orphan =
        kasumi::history::make_commit(50, {}, make_tree("orphan", "orphan"), 500)
            .value();
    const auto orphan_reference = add_variant(fixture, orphan);
    ASSERT_TRUE(kasumi::transport::remove(fixture.transport,
                                          marker_path(orphan_reference)));

    const auto result = inspect(workspace, InspectionOperation::RemoteCommits);
    const auto report =
        require_report<kasumi::application::RemoteCommitsReport>(result);
    ASSERT_TRUE(report.has_value());
    ASSERT_EQ(report->commits.size(), 2U);
    EXPECT_EQ(report->commits[0].commit_id, current.head.commit_id);
    EXPECT_EQ(report->commits[1].commit_id, base.head.commit_id);
    EXPECT_TRUE(std::ranges::none_of(report->commits, [&](const auto& info) {
        return info.commit_id == orphan_reference.commit_id;
    }));
}

TEST(ApplicationInspectionTest, RemoteCommitsRejectsHeadSelector) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-commits-selector");
    write_profile(workspace, kasumi::test::workspace_path(workspace, "remote"));

    const auto result = inspect_request(
        workspace,
        InspectionRequest{.operation = InspectionOperation::RemoteCommits,
                          .profile_name = "demo",
                          .head_commit_id = "commit"},
        Credentials{NoCredentials{}});

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, InspectionErrorCode::InvalidRequest);
}

TEST(ApplicationInspectionTest,
     RemoteSummaryReportsStructuralContentAndWritersWithoutMutation) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-summary-structural");
    write_profile(workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));

    const auto commit = kasumi::history::make_commit(
                            0, {}, make_tree("missing.txt", "missing"), 100)
                            .value();
    const auto published = publish(fixture, commit);
    ASSERT_FALSE(published.head.commit_id.empty());
    const auto orphan_id = kasumi::crypto::content_identifier(
        test_key(), kasumi::hasher::hash_string("orphan"));
    put_object(fixture, orphan_id, "not authenticated by summary");
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    put_object(fixture,
               layout.writers_prefix + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    const auto before = kasumi::transport::list(fixture.transport);
    const auto result = inspect(workspace, InspectionOperation::RemoteSummary);
    const auto after = kasumi::transport::list(fixture.transport);

    const auto report =
        require_report<kasumi::application::RemoteSummaryReport>(result);
    ASSERT_TRUE(report.has_value());
    EXPECT_TRUE(report->history_present);
    EXPECT_EQ(report->observed_height, 0U);
    EXPECT_EQ(report->reachable_commit_count, 1U);
    EXPECT_EQ(report->logical_head_count, 1U);
    EXPECT_FALSE(report->has_conflicts);
    EXPECT_EQ(report->missing_content_count, 1U);
    EXPECT_EQ(report->orphan_content_count, 1U);
    EXPECT_EQ(report->active_writer_count, 1U);
    ASSERT_TRUE(before.has_value());
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(*before, *after);
}

TEST(ApplicationInspectionTest,
     RemoteSummaryTreatsPresentCorruptContentAsStructurallyPresent) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-summary-present");
    write_profile(workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));
    const auto commit =
        kasumi::history::make_commit(0, {}, make_tree("file.txt", "contents"))
            .value();
    publish(fixture, commit);
    const auto content_id = kasumi::crypto::content_identifier(
        test_key(), commit.tree.rows.back().hash);
    put_object(fixture, content_id, "ciphertext deliberately invalid");

    const auto result = inspect(workspace, InspectionOperation::RemoteSummary);
    const auto report =
        require_report<kasumi::application::RemoteSummaryReport>(result);
    ASSERT_TRUE(report.has_value());
    EXPECT_EQ(report->missing_content_count, 0U);
    EXPECT_EQ(report->orphan_content_count, 0U);
}

TEST(ApplicationInspectionTest,
     RemoteSummaryCountsContentWithoutHistoryAsOrphan) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-summary-empty");
    write_profile(workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));
    const auto content_id = kasumi::crypto::content_identifier(
        test_key(), kasumi::hasher::hash_string("orphan"));
    put_object(fixture, content_id);

    const auto result = inspect(workspace, InspectionOperation::RemoteSummary);
    const auto report =
        require_report<kasumi::application::RemoteSummaryReport>(result);
    ASSERT_TRUE(report.has_value());
    EXPECT_FALSE(report->history_present);
    EXPECT_EQ(report->reachable_commit_count, 0U);
    EXPECT_EQ(report->missing_content_count, 0U);
    EXPECT_EQ(report->orphan_content_count, 1U);
}

TEST(ApplicationInspectionTest, RemoteStatReadsExactEffectiveTreeEntries) {
    auto fixture = make_local_storage();
    auto workspace = kasumi::test::make_temp_workspace("application-stat");
    write_profile(workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));
    const auto commit =
        kasumi::history::make_commit(0, {}, statistics_tree(), 100).value();
    publish(fixture, commit);

    const auto inspect_path = [&](std::string path) {
        return inspect_request(
            workspace,
            InspectionRequest{.operation = InspectionOperation::RemoteStat,
                              .profile_name = "demo",
                              .logical_path = std::move(path)},
            Credentials{MasterKeyHex{test_key_hex()}});
    };
    const auto file = inspect_path("docs/a.txt");
    const auto file_report =
        require_report<kasumi::application::RemoteStatReport>(file);
    ASSERT_TRUE(file_report.has_value());
    EXPECT_EQ(file_report->path, "docs/a.txt");
    EXPECT_EQ(file_report->type,
              kasumi::application::RemoteTreeEntryType::File);
    EXPECT_EQ(file_report->size, 1U);

    const auto directory = inspect_path("docs");
    const auto directory_report =
        require_report<kasumi::application::RemoteStatReport>(directory);
    ASSERT_TRUE(directory_report.has_value());
    EXPECT_EQ(directory_report->type,
              kasumi::application::RemoteTreeEntryType::Directory);
    EXPECT_EQ(directory_report->size, 3U);

    const auto root = inspect_path("/");
    ASSERT_TRUE(root.has_value()) << root.error().detail;
    EXPECT_EQ(
        std::get<kasumi::application::RemoteStatReport>(root->payload).path,
        "/");

    const auto missing = inspect_path("docs/a");
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error().code, InspectionErrorCode::RemotePathNotFound);
}

TEST(ApplicationInspectionTest, RemoteStatRejectsUnsafeLogicalPaths) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-stat-invalid");
    write_profile(workspace, kasumi::test::workspace_path(workspace, "remote"));
    for (const std::string path : {"",
                                   ".",
                                   "./file",
                                   "../file",
                                   "/file",
                                   "a//b",
                                   "a\\b",
                                   "C:/file",
                                   "a/"}) {
        const auto result = inspect_request(
            workspace,
            InspectionRequest{.operation = InspectionOperation::RemoteStat,
                              .profile_name = "demo",
                              .logical_path = path},
            Credentials{NoCredentials{}});
        ASSERT_FALSE(result.has_value()) << path;
        EXPECT_EQ(result.error().code, InspectionErrorCode::InvalidRequest)
            << path;
    }
}

TEST(ApplicationInspectionTest,
     RemoteCommitDetailsReachableCommitAndSelectedPhysicalVariants) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-commit-detail");
    write_profile(workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));
    const auto base = publish(
        fixture,
        kasumi::history::make_commit(0, {}, make_tree("base", "base"), 100)
            .value());
    const auto commit =
        kasumi::history::make_commit(
            1, {base.head.commit_id}, make_tree("current", "current"), 200)
            .value();
    const auto current = publish(fixture, commit);
    add_variant(fixture, commit);
    const HistoryHeadReference invalid{.commit_id = current.head.commit_id,
                                       .ciphertext_id = std::string(64, 'f')};
    put_object(fixture, object_path(invalid), "invalid ciphertext");

    const auto result = inspect_request(
        workspace,
        InspectionRequest{.operation = InspectionOperation::RemoteCommit,
                          .profile_name = "demo",
                          .commit_id = current.head.commit_id},
        Credentials{MasterKeyHex{test_key_hex()}});
    const auto report =
        require_report<kasumi::application::RemoteCommitReport>(result);
    ASSERT_TRUE(report.has_value());
    EXPECT_EQ(report->commit.commit_id, current.head.commit_id);
    EXPECT_EQ(report->commit.parent_ids,
              std::vector<std::string>{base.head.commit_id});
    EXPECT_TRUE(report->commit.logical_head);
    EXPECT_TRUE(report->commit.physically_marked);
    EXPECT_GE(report->variants.size(), 2U);
    EXPECT_TRUE(std::ranges::any_of(report->variants, [](const auto& variant) {
        return variant.state ==
               kasumi::application::RemoteCommitVariantState::Valid;
    }));
    EXPECT_TRUE(std::ranges::any_of(report->variants, [&](const auto& variant) {
        return variant.ciphertext_id == invalid.ciphertext_id &&
               variant.state == kasumi::application::RemoteCommitVariantState::
                                    InvalidCiphertext;
    }));
    EXPECT_TRUE(std::ranges::is_sorted(
        report->variants,
        {},
        &kasumi::application::RemoteCommitVariantInfo::ciphertext_id));
}

TEST(ApplicationInspectionTest,
     RemoteCommitReusesVariantAuthenticatedDuringObservation) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-commit-reuse");
    write_profile(workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));
    const auto published =
        publish(fixture, make_commit(0, {}, "only.txt", "only").value());

    const auto result = inspect_request(
        workspace,
        InspectionRequest{.operation = InspectionOperation::RemoteCommit,
                          .profile_name = "demo",
                          .commit_id = published.head.commit_id},
        Credentials{MasterKeyHex{test_key_hex()}});

    ASSERT_TRUE(result.has_value()) << result.error().detail;
    const auto& report =
        std::get<kasumi::application::RemoteCommitReport>(result->payload);
    ASSERT_EQ(report.variants.size(), 1U);
    EXPECT_EQ(report.variants.front().ciphertext_id,
              published.head.ciphertext_id);
    EXPECT_EQ(report.variants.front().state,
              kasumi::application::RemoteCommitVariantState::Valid);
}

TEST(ApplicationInspectionTest, RemoteCommitRejectsMalformedAndUnreachableIds) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-commit-errors");
    write_profile(workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));
    publish(fixture, make_commit(0, {}, "head", "head").value());
    const auto orphan = make_commit(5, {}, "orphan", "orphan").value();
    const auto orphan_reference = add_variant(fixture, orphan);
    ASSERT_TRUE(kasumi::transport::remove(fixture.transport,
                                          marker_path(orphan_reference)));

    const auto malformed = inspect_request(
        workspace,
        InspectionRequest{.operation = InspectionOperation::RemoteCommit,
                          .profile_name = "demo",
                          .commit_id = "short"},
        Credentials{NoCredentials{}});
    ASSERT_FALSE(malformed.has_value());
    EXPECT_EQ(malformed.error().code, InspectionErrorCode::InvalidRequest);

    const auto unreachable = inspect_request(
        workspace,
        InspectionRequest{.operation = InspectionOperation::RemoteCommit,
                          .profile_name = "demo",
                          .commit_id = orphan_reference.commit_id},
        Credentials{MasterKeyHex{test_key_hex()}});
    ASSERT_FALSE(unreachable.has_value());
    EXPECT_EQ(unreachable.error().code,
              InspectionErrorCode::RemoteCommitNotFound);
}

TEST(ApplicationInspectionTest,
     RemoteEpochsAuthenticatesSelectsAndStaysReadOnly) {
    namespace epoch = kasumi::application::history_storage::epoch;
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-remote-epochs");
    const auto remote_root =
        kasumi::test::workspace_path(fixture.workspace, "storage");
    write_profile(workspace, remote_root);

    epoch::Epoch genesis{
        .vault_id = std::string(64, 'a'),
        .sequence = 0,
        .issued_at = 100,
        .policy = {.min_history_depth = 5, .min_history_age_hours = 6},
        .anchors = {{.commit_id = std::string(64, 'b'), .height = 4}},
    };
    const auto first = epoch::seal(genesis, test_key());
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(
        epoch::publish(fixture.transport,
                       test_key(),
                       *first,
                       kasumi::test::workspace_root(fixture.workspace)));
    auto next = genesis;
    next.sequence = 1;
    next.issued_at = 200;
    next.anchors = {{.commit_id = std::string(64, 'c'), .height = 9}};
    next.previous_epoch_id = first->reference.epoch_id;
    const auto second = epoch::seal(next, test_key());
    ASSERT_TRUE(second.has_value());
    ASSERT_TRUE(
        epoch::publish(fixture.transport,
                       test_key(),
                       *second,
                       kasumi::test::workspace_root(fixture.workspace)));
    const auto remote_before = kasumi::test::snapshot_tree(remote_root);

    const auto list = inspect_request(
        workspace,
        InspectionRequest{.operation = InspectionOperation::RemoteEpochs,
                          .profile_name = "demo"},
        Credentials{MasterKeyHex{test_key_hex()}});
    const auto epochs =
        require_report<kasumi::application::RemoteEpochsReport>(list);
    ASSERT_TRUE(epochs.has_value());
    ASSERT_EQ(epochs->epochs.size(), 2U);
    EXPECT_EQ(epochs->epochs[0].sequence, 0U);
    EXPECT_EQ(epochs->epochs[0].next_epoch_id, second->reference.epoch_id);
    EXPECT_EQ(epochs->epochs[1].previous_epoch_id, first->reference.epoch_id);
    EXPECT_TRUE(epochs->epochs[1].next_epoch_id.empty());
    ASSERT_EQ(epochs->epochs[1].anchors.size(), 1U);
    EXPECT_EQ(epochs->epochs[1].anchors[0].height, 9U);

    for (const auto& selector :
         {std::string{"1"}, second->reference.epoch_id}) {
        const auto detail = inspect_request(
            workspace,
            InspectionRequest{.operation = InspectionOperation::RemoteEpoch,
                              .profile_name = "demo",
                              .epoch_selector = selector},
            Credentials{MasterKeyHex{test_key_hex()}});
        ASSERT_TRUE(detail.has_value()) << detail.error().detail;
        const auto* report =
            std::get_if<kasumi::application::RemoteEpochReport>(
                &detail->payload);
        ASSERT_NE(report, nullptr);
        EXPECT_EQ(report->epoch.epoch_id, second->reference.epoch_id);
        EXPECT_EQ(report->epoch.vault_id, genesis.vault_id);
        EXPECT_EQ(report->epoch.min_history_depth, 5U);
    }
    EXPECT_EQ(kasumi::test::snapshot_tree(remote_root), remote_before);
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "local")));
}

TEST(ApplicationInspectionTest,
     RemoteEpochRejectsInvalidMissingAndBrokenChain) {
    namespace epoch = kasumi::application::history_storage::epoch;
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-remote-epoch-errors");
    write_profile(workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));

    const auto invalid = inspect_request(
        workspace,
        InspectionRequest{.operation = InspectionOperation::RemoteEpoch,
                          .profile_name = "demo",
                          .epoch_selector = "01"},
        Credentials{NoCredentials{}});
    ASSERT_FALSE(invalid.has_value());
    EXPECT_EQ(invalid.error().code, InspectionErrorCode::InvalidRequest);

    const auto missing = inspect_request(
        workspace,
        InspectionRequest{.operation = InspectionOperation::RemoteEpoch,
                          .profile_name = "demo",
                          .epoch_selector = "0"},
        Credentials{MasterKeyHex{test_key_hex()}});
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error().code, InspectionErrorCode::RemoteEpochNotFound);

    epoch::Epoch broken{
        .vault_id = std::string(64, 'a'),
        .sequence = 1,
        .issued_at = 100,
        .anchors = {{.commit_id = std::string(64, 'b'), .height = 0}},
        .previous_epoch_id = std::string(64, 'c'),
    };
    const auto sealed = epoch::seal(broken, test_key());
    ASSERT_TRUE(sealed.has_value());
    ASSERT_TRUE(
        epoch::publish(fixture.transport,
                       test_key(),
                       *sealed,
                       kasumi::test::workspace_root(fixture.workspace)));
    const auto rejected = inspect_request(
        workspace,
        InspectionRequest{.operation = InspectionOperation::RemoteEpochs,
                          .profile_name = "demo"},
        Credentials{MasterKeyHex{test_key_hex()}});
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error().code,
              InspectionErrorCode::RemoteObservationFailure);
}

TEST(ApplicationInspectionTest,
     RemoteContentsInventoryAndAuditClassifyEveryStructuralState) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-remote-contents");
    const auto remote_root =
        kasumi::test::workspace_path(fixture.workspace, "storage");
    write_profile(workspace, remote_root);
    const auto commit =
        kasumi::history::make_commit(0, {}, statistics_tree(), 100).value();
    publish(fixture, commit);
    const auto valid_id = put_content(fixture, "a");
    const auto invalid_id = kasumi::crypto::content_identifier(
        test_key(), kasumi::hasher::hash_string("ccc"));
    put_object(fixture, invalid_id, "invalid ciphertext");
    const auto orphan_id = put_content(fixture, "conteúdo órfão válido");
    const auto remote_before = kasumi::test::snapshot_tree(remote_root);

    const auto list = inspect_request(
        workspace,
        InspectionRequest{.operation = InspectionOperation::RemoteContents,
                          .profile_name = "demo"},
        Credentials{MasterKeyHex{test_key_hex()}});
    const auto inventory =
        require_report<kasumi::application::RemoteContentsReport>(list);
    ASSERT_TRUE(inventory.has_value());
    EXPECT_FALSE(inventory->audited);
    EXPECT_EQ(inventory->referenced_count, 3U);
    EXPECT_EQ(inventory->physical_count, 3U);
    EXPECT_EQ(inventory->missing_count, 1U);
    EXPECT_EQ(inventory->orphan_count, 1U);
    EXPECT_EQ(inventory->valid_count, 0U);
    EXPECT_EQ(inventory->invalid_count, 0U);
    EXPECT_EQ(inventory->contents.size(), 4U);
    const auto listed_valid =
        std::ranges::find(inventory->contents,
                          valid_id,
                          &kasumi::application::RemoteContentInfo::content_id);
    ASSERT_NE(listed_valid, inventory->contents.end());
    EXPECT_EQ(listed_valid->state,
              kasumi::application::RemoteContentState::Present);
    EXPECT_TRUE(listed_valid->current_tree);
    EXPECT_EQ(listed_valid->paths, std::vector<std::string>{"docs/a.txt"});
    const auto listed_orphan =
        std::ranges::find(inventory->contents,
                          orphan_id,
                          &kasumi::application::RemoteContentInfo::content_id);
    ASSERT_NE(listed_orphan, inventory->contents.end());
    EXPECT_EQ(listed_orphan->state,
              kasumi::application::RemoteContentState::Orphan);
    EXPECT_TRUE(listed_orphan->logical_hash.empty());

    const auto audit = inspect_request(
        workspace,
        InspectionRequest{.operation = InspectionOperation::RemoteContentsAudit,
                          .profile_name = "demo"},
        Credentials{MasterKeyHex{test_key_hex()}});
    const auto audited =
        require_report<kasumi::application::RemoteContentsReport>(audit);
    ASSERT_TRUE(audited.has_value());
    EXPECT_TRUE(audited->audited);
    EXPECT_EQ(audited->missing_count, 1U);
    EXPECT_EQ(audited->orphan_count, 1U);
    EXPECT_EQ(audited->valid_count, 2U);
    EXPECT_EQ(audited->invalid_count, 1U);
    const auto audited_invalid =
        std::ranges::find(audited->contents,
                          invalid_id,
                          &kasumi::application::RemoteContentInfo::content_id);
    ASSERT_NE(audited_invalid, audited->contents.end());
    EXPECT_EQ(audited_invalid->state,
              kasumi::application::RemoteContentState::Invalid);
    const auto audited_orphan =
        std::ranges::find(audited->contents,
                          orphan_id,
                          &kasumi::application::RemoteContentInfo::content_id);
    ASSERT_NE(audited_orphan, audited->contents.end());
    EXPECT_EQ(audited_orphan->state,
              kasumi::application::RemoteContentState::Valid);
    EXPECT_FALSE(audited_orphan->logical_hash.empty());
    EXPECT_EQ(audited_orphan->size,
              std::string_view{"conteúdo órfão válido"}.size());

    const auto detail = inspect_request(
        workspace,
        InspectionRequest{.operation = InspectionOperation::RemoteContent,
                          .profile_name = "demo",
                          .content_id = valid_id},
        Credentials{MasterKeyHex{test_key_hex()}});
    const auto content =
        require_report<kasumi::application::RemoteContentReport>(detail);
    ASSERT_TRUE(content.has_value());
    EXPECT_EQ(content->content.content_id, valid_id);
    EXPECT_EQ(content->content.logical_hash,
              kasumi::hash_hex(kasumi::hasher::hash_string("a")));
    EXPECT_EQ(content->content.state,
              kasumi::application::RemoteContentState::Present);

    EXPECT_EQ(kasumi::test::snapshot_tree(remote_root), remote_before);
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "local")));
}

TEST(ApplicationInspectionTest, RemoteContentRejectsInvalidAndUnknownIds) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-remote-content-errors");
    write_profile(workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));

    const auto invalid = inspect_request(
        workspace,
        InspectionRequest{.operation = InspectionOperation::RemoteContent,
                          .profile_name = "demo",
                          .content_id = "short"},
        Credentials{NoCredentials{}});
    ASSERT_FALSE(invalid.has_value());
    EXPECT_EQ(invalid.error().code, InspectionErrorCode::InvalidRequest);

    const auto unknown = inspect_request(
        workspace,
        InspectionRequest{.operation = InspectionOperation::RemoteContent,
                          .profile_name = "demo",
                          .content_id = std::string(64, 'a')},
        Credentials{MasterKeyHex{test_key_hex()}});
    ASSERT_FALSE(unknown.has_value());
    EXPECT_EQ(unknown.error().code, InspectionErrorCode::RemoteContentNotFound);
}

TEST(ApplicationInspectionTest,
     RemoteGetAuthenticatesAndAtomicallySavesWithoutTouchingProfile) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-remote-get");
    const auto remote_root =
        kasumi::test::workspace_path(fixture.workspace, "storage");
    write_profile(workspace, remote_root);
    const auto commit =
        kasumi::history::make_commit(
            0, {}, make_tree("relatório final.txt", "conteúdo remoto"), 100)
            .value();
    publish(fixture, commit);
    const auto content_id = put_content(fixture, "conteúdo remoto");
    const auto destination =
        kasumi::test::workspace_root(workspace) /
        kasumi::platform::path::from_utf8("downloads/relatório final.txt");
    std::filesystem::create_directories(destination.parent_path());
    kasumi::test::write_text(destination, "conteúdo anterior");
    const auto config =
        kasumi::test::workspace_path(workspace, "app/config.toml");
    const auto config_before = kasumi::test::read_binary(config);
    const auto remote_before = kasumi::test::snapshot_tree(remote_root);

    const auto result = kasumi::application::inspect(
        {InspectionRequest{.operation = InspectionOperation::RemoteGet,
                           .profile_name = "demo",
                           .logical_path = "relatório final.txt",
                           .destination_path =
                               kasumi::platform::path::to_utf8(destination)},
         Credentials{MasterKeyHex{test_key_hex()}},
         ExecutionEnvironment{kasumi::test::workspace_path(workspace, "app")}});

    const auto report =
        require_report<kasumi::application::RemoteFileReport>(result);
    ASSERT_TRUE(report.has_value());
    EXPECT_EQ(report->path, "relatório final.txt");
    EXPECT_EQ(report->logical_hash,
              kasumi::hash_hex(commit.tree.rows.back().hash));
    EXPECT_EQ(report->content_id, content_id);
    EXPECT_EQ(report->size, std::string_view{"conteúdo remoto"}.size());
    EXPECT_EQ(kasumi::test::read_text(destination), "conteúdo remoto");
    EXPECT_EQ(kasumi::test::read_binary(config), config_before);
    EXPECT_EQ(kasumi::test::snapshot_tree(remote_root), remote_before);
    EXPECT_FALSE(std::filesystem::exists(
        kasumi::test::workspace_path(workspace, "local")));
    EXPECT_FALSE(std::filesystem::exists(kasumi::test::workspace_path(
        workspace, "app/profiles/demo/db.sqlite")));
}

TEST(ApplicationInspectionTest, RemoteGetInstallsUnicodeDestination) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-remote-get-unicode");
    const auto remote_root =
        kasumi::test::workspace_path(fixture.workspace, "storage");
    write_profile(workspace, remote_root);
    const auto commit = kasumi::history::make_commit(
        0, {}, make_tree("カード💝.png", "unicode remote content"), 100);
    ASSERT_TRUE(commit);
    publish(fixture, *commit);
    const auto content_id = put_content(fixture, "unicode remote content");
    const auto destination =
        (kasumi::test::workspace_root(workspace) /
         kasumi::platform::path::from_utf8(
             "downloads/高松灯/千早愛音🌸-𝑬𝒎𝒊𝒍𝒊𝒂-𓆩🌸𓆪.txt"))
            .lexically_normal();
    kasumi::test::write_text(destination, "previous content");
    const auto remote_before = kasumi::test::snapshot_tree(remote_root);

    const auto result = kasumi::application::inspect(
        {InspectionRequest{.operation = InspectionOperation::RemoteGet,
                           .profile_name = "demo",
                           .logical_path = "カード💝.png",
                           .destination_path =
                               kasumi::platform::path::to_utf8(destination)},
         Credentials{MasterKeyHex{test_key_hex()}},
         ExecutionEnvironment{kasumi::test::workspace_path(workspace, "app")}});

    ASSERT_TRUE(result) << result.error().detail;
    const auto* report =
        std::get_if<kasumi::application::RemoteFileReport>(&result->payload);
    ASSERT_NE(report, nullptr);
    EXPECT_EQ(report->path, "カード💝.png");
    EXPECT_EQ(report->destination_path,
              kasumi::platform::path::to_utf8(destination));
    EXPECT_NE(report->destination_path.find("千早愛音🌸-𝑬𝒎𝒊𝒍𝒊𝒂-𓆩🌸𓆪.txt"),
              std::string::npos);
    EXPECT_EQ(report->content_id, content_id);
    EXPECT_EQ(kasumi::test::read_text(destination), "unicode remote content");
    EXPECT_EQ(kasumi::test::snapshot_tree(remote_root), remote_before);
    const auto installed =
        kasumi::test::snapshot_tree(destination.parent_path());
    ASSERT_EQ(installed.size(), 1U);
    EXPECT_EQ(installed.front().relative_path, "千早愛音🌸-𝑬𝒎𝒊𝒍𝒊𝒂-𓆩🌸𓆪.txt");
}

TEST(
    ApplicationInspectionTest,
    RemoteGetRejectsMissingCorruptAndDirectoryContentWithoutReplacingDestination) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-remote-get-errors");
    write_profile(workspace,
                  kasumi::test::workspace_path(fixture.workspace, "storage"));
    const auto commit =
        kasumi::history::make_commit(0, {}, statistics_tree(), 100).value();
    publish(fixture, commit);
    const auto destination =
        kasumi::test::workspace_path(workspace, "download.txt");
    kasumi::test::write_text(destination, "preservar");
    const auto read = [&](std::string path) {
        return kasumi::application::inspect(
            {InspectionRequest{
                 .operation = InspectionOperation::RemoteGet,
                 .profile_name = "demo",
                 .logical_path = std::move(path),
                 .destination_path =
                     kasumi::platform::path::to_utf8(destination)},
             Credentials{MasterKeyHex{test_key_hex()}},
             ExecutionEnvironment{
                 kasumi::test::workspace_path(workspace, "app")}});
    };

    const auto missing = read("docs/a.txt");
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error().code, InspectionErrorCode::RemoteContentNotFound);
    EXPECT_EQ(kasumi::test::read_text(destination), "preservar");

    const auto content_id = kasumi::crypto::content_identifier(
        test_key(), commit.tree.rows[2].hash);
    put_object(fixture, content_id, "invalid ciphertext");
    const auto corrupt = read("docs/a.txt");
    ASSERT_FALSE(corrupt.has_value());
    EXPECT_EQ(corrupt.error().code, InspectionErrorCode::RemoteContentInvalid);
    EXPECT_EQ(kasumi::test::read_text(destination), "preservar");

    const auto directory = read("docs");
    ASSERT_FALSE(directory.has_value());
    EXPECT_EQ(directory.error().code,
              InspectionErrorCode::RemotePathIsDirectory);
    EXPECT_EQ(kasumi::test::read_text(destination), "preservar");
}

TEST(ApplicationInspectionTest, RemoteGetValidatesItsDedicatedRequest) {
    auto workspace =
        kasumi::test::make_temp_workspace("application-remote-get-invalid");
    write_profile(workspace, kasumi::test::workspace_path(workspace, "remote"));

    for (const auto& request : {
             InspectionRequest{.operation = InspectionOperation::RemoteGet,
                               .profile_name = "demo",
                               .logical_path = "../file",
                               .destination_path = "destination"},
             InspectionRequest{.operation = InspectionOperation::RemoteGet,
                               .profile_name = "demo",
                               .logical_path = "file"},
             InspectionRequest{.operation = InspectionOperation::RemoteStat,
                               .profile_name = "demo",
                               .logical_path = "file",
                               .destination_path = "destination"},
         }) {
        const auto result =
            inspect_request(workspace, request, Credentials{NoCredentials{}});
        ASSERT_FALSE(result.has_value());
        EXPECT_EQ(result.error().code, InspectionErrorCode::InvalidRequest);
    }
}

TEST(ApplicationInspectionTest,
     RemoteMarkersAndObjectsClassifyThePhysicalNamespaceWithoutMutation) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-physical-markers");
    const auto remote_root =
        kasumi::test::workspace_path(fixture.workspace, "storage");
    write_profile(workspace, remote_root);

    const auto base =
        publish(fixture, make_commit(0, {}, "base.txt", "base").value());
    const auto child_commit =
        make_commit(1, {base.head.commit_id}, "child.txt", "child").value();
    const auto child = publish(fixture, child_commit);
    const auto second_variant = add_variant(fixture, child_commit);
    ASSERT_NE(child.head.ciphertext_id, second_variant.ciphertext_id);
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    const auto invalid_marker =
        layout.heads_prefix + std::string(64, 'd') + "-" + std::string(64, 'e');
    put_object(fixture, invalid_marker, "invalid marker");
    put_object(fixture, layout.barrier_identifier);
    put_object(fixture,
               layout.writers_prefix + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    put_object(fixture, "namespace/desconhecido");
    const auto before = kasumi::test::snapshot_tree(remote_root);

    const auto markers = inspect(workspace, InspectionOperation::RemoteMarkers);
    ASSERT_TRUE(markers.has_value()) << markers.error().detail;
    const auto* marker_report =
        std::get_if<kasumi::application::RemoteMarkersReport>(
            &markers->payload);
    ASSERT_NE(marker_report, nullptr);
    EXPECT_EQ(marker_report->logical_count, 2U);
    EXPECT_EQ(marker_report->ancestral_count, 1U);
    EXPECT_EQ(marker_report->invalid_count, 1U);
    EXPECT_TRUE(
        std::ranges::any_of(marker_report->markers, [](const auto& item) {
            return item.state ==
                   kasumi::application::RemoteMarkerState::InvalidMarker;
        }));
    EXPECT_TRUE(
        std::ranges::any_of(marker_report->markers, [&](const auto& item) {
            return item.commit_id == base.head.commit_id &&
                   item.state ==
                       kasumi::application::RemoteMarkerState::Ancestral;
        }));

    const auto objects = inspect(workspace, InspectionOperation::RemoteObjects);
    ASSERT_TRUE(objects.has_value()) << objects.error().detail;
    const auto* object_report =
        std::get_if<kasumi::application::RemoteObjectsReport>(
            &objects->payload);
    ASSERT_NE(object_report, nullptr);
    EXPECT_EQ(object_report->unknown_count, 1U);
    EXPECT_TRUE(
        std::ranges::any_of(object_report->objects, [](const auto& item) {
            return item.category ==
                   kasumi::application::RemoteObjectCategory::Barrier;
        }));
    EXPECT_TRUE(
        std::ranges::any_of(object_report->objects, [](const auto& item) {
            return item.category ==
                   kasumi::application::RemoteObjectCategory::Writer;
        }));
    EXPECT_TRUE(
        std::ranges::any_of(object_report->objects, [](const auto& item) {
            return item.category ==
                       kasumi::application::RemoteObjectCategory::Unknown &&
                   item.relation == "not audited";
        }));
    EXPECT_TRUE(std::ranges::is_sorted(
        object_report->objects,
        {},
        &kasumi::application::RemoteObjectInfo::identifier));
    EXPECT_EQ(kasumi::test::snapshot_tree(remote_root), before);
}

TEST(ApplicationInspectionTest,
     RemoteOrphansIncludesCommitsContentsVariantsAndProtectedEpochs) {
    namespace epoch = kasumi::application::history_storage::epoch;
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-physical-orphans");
    const auto remote_root =
        kasumi::test::workspace_path(fixture.workspace, "storage");
    write_profile(workspace, remote_root);

    const auto head_commit = make_commit(0, {}, "head.txt", "head").value();
    const auto head = publish(fixture, head_commit);
    put_content(fixture, "head");
    const auto redundant = add_variant(fixture, head_commit);
    ASSERT_TRUE(
        kasumi::transport::remove(fixture.transport, marker_path(redundant)));

    const auto orphan_commit =
        make_commit(0, {}, "orphan.txt", "orphan-commit").value();
    const auto orphan = add_variant(fixture, orphan_commit);
    ASSERT_TRUE(
        kasumi::transport::remove(fixture.transport, marker_path(orphan)));
    const auto orphan_content = put_content(fixture, "orphan-content");

    epoch::Epoch first_value{
        .vault_id = std::string(64, 'a'),
        .sequence = 0,
        .issued_at = 100,
        .anchors = {{.commit_id = head.head.commit_id, .height = 0}}};
    const auto first = epoch::seal(first_value, test_key());
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(
        epoch::publish(fixture.transport,
                       test_key(),
                       *first,
                       kasumi::test::workspace_root(fixture.workspace)));
    auto second_value = first_value;
    second_value.sequence = 1;
    second_value.issued_at = 200;
    second_value.previous_epoch_id = first->reference.epoch_id;
    const auto second = epoch::seal(second_value, test_key());
    ASSERT_TRUE(second.has_value());
    ASSERT_TRUE(
        epoch::publish(fixture.transport,
                       test_key(),
                       *second,
                       kasumi::test::workspace_root(fixture.workspace)));
    const auto before = kasumi::test::snapshot_tree(remote_root);

    const auto result = inspect(workspace, InspectionOperation::RemoteOrphans);
    const auto report =
        require_report<kasumi::application::RemoteOrphansReport>(result);
    ASSERT_TRUE(report.has_value());
    const auto has = [&](kasumi::application::RemoteOrphanKind kind,
                         std::string_view identifier,
                         bool candidate) {
        return std::ranges::any_of(report->objects, [&](const auto& item) {
            return item.kind == kind && item.identifier == identifier &&
                   item.removal_candidate == candidate;
        });
    };
    EXPECT_TRUE(has(
        kasumi::application::RemoteOrphanKind::Commit, orphan.commit_id, true));
    EXPECT_TRUE(has(kasumi::application::RemoteOrphanKind::CommitVariant,
                    object_path(orphan),
                    true));
    EXPECT_TRUE(has(kasumi::application::RemoteOrphanKind::RedundantVariant,
                    object_path(redundant),
                    true));
    EXPECT_TRUE(has(
        kasumi::application::RemoteOrphanKind::Content, orphan_content, true));
    const auto inspection_layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    const auto first_epoch_identifier =
        epoch::object_identifier(inspection_layout, first->reference);
    ASSERT_TRUE(first_epoch_identifier.has_value());
    EXPECT_TRUE(has(kasumi::application::RemoteOrphanKind::ProtectedEpoch,
                    *first_epoch_identifier,
                    false));
    EXPECT_EQ(kasumi::test::snapshot_tree(remote_root), before);
}

TEST(ApplicationInspectionTest,
     RemoteWritersAndHealthAuthenticateAndStayReadOnly) {
    namespace epoch = kasumi::application::history_storage::epoch;
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-physical-health");
    const auto remote_root =
        kasumi::test::workspace_path(fixture.workspace, "storage");
    write_profile(workspace, remote_root);
    const auto published =
        publish(fixture, make_commit(0, {}, "ok.txt", "ok").value());
    put_content(fixture, "ok");
    epoch::Epoch first_value{
        .vault_id = std::string(64, 'a'),
        .sequence = 0,
        .issued_at = 100,
        .anchors = {{.commit_id = published.head.commit_id, .height = 0}}};
    const auto first = epoch::seal(first_value, test_key());
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(
        epoch::publish(fixture.transport,
                       test_key(),
                       *first,
                       kasumi::test::workspace_root(fixture.workspace)));
    auto second_value = first_value;
    second_value.sequence = 1;
    second_value.issued_at = 200;
    second_value.previous_epoch_id = first->reference.epoch_id;
    const auto second = epoch::seal(second_value, test_key());
    ASSERT_TRUE(second.has_value());
    ASSERT_TRUE(
        epoch::publish(fixture.transport,
                       test_key(),
                       *second,
                       kasumi::test::workspace_root(fixture.workspace)));

    const auto inspect_health = [&] {
        return inspect(workspace, InspectionOperation::RemoteHealth);
    };

    const auto healthy = inspect_health();
    ASSERT_TRUE(healthy.has_value()) << healthy.error().detail;
    EXPECT_EQ(
        std::get<kasumi::application::RemoteHealthReport>(healthy->payload)
            .state,
        kasumi::application::RemoteHealthState::Healthy);

    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());
    const std::string valid_writer =
        layout.writers_prefix + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    put_object(fixture, valid_writer);
    const auto degraded = inspect_health();
    ASSERT_TRUE(degraded.has_value()) << degraded.error().detail;
    EXPECT_EQ(
        std::get<kasumi::application::RemoteHealthReport>(degraded->payload)
            .state,
        kasumi::application::RemoteHealthState::Degraded);

    const auto invalid_marker =
        layout.heads_prefix + std::string(64, 'd') + "-" + std::string(64, 'e');
    put_object(fixture, invalid_marker, "invalid");
    const auto critical = inspect_health();
    ASSERT_TRUE(critical.has_value()) << critical.error().detail;
    EXPECT_EQ(
        std::get<kasumi::application::RemoteHealthReport>(critical->payload)
            .state,
        kasumi::application::RemoteHealthState::Critical);

    put_object(fixture, layout.barrier_identifier);
    put_object(fixture, layout.writers_prefix + "invalido");
    const auto writers = inspect(workspace, InspectionOperation::RemoteWriters);
    ASSERT_TRUE(writers.has_value()) << writers.error().detail;
    const auto& writer_report =
        std::get<kasumi::application::RemoteWritersReport>(writers->payload);
    EXPECT_TRUE(writer_report.barrier_present);
    EXPECT_EQ(writer_report.barrier_identifier, layout.barrier_identifier);
    EXPECT_TRUE(writer_report.maintenance_blocked);
    EXPECT_FALSE(writer_report.protocol_consistent);
    EXPECT_EQ(writer_report.writers.size(), 2U);
    static_cast<void>(published);
}

TEST(ApplicationInspectionTest,
     PhysicalInspectionRejectsDefensiveLimitsAndTransportFailures) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-physical-errors");
    const auto remote_root =
        kasumi::test::workspace_path(fixture.workspace, "storage");
    write_profile(workspace, remote_root);
    publish(fixture, make_commit(0, {}, "file.txt", "contents").value());
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());

    const auto heads = remote_root / std::filesystem::path{layout.heads_prefix};
    for (std::size_t index = 0;
         index <= kasumi::history::maximum_marked_head_count;
         ++index) {
        auto id = std::string(64, '0');
        const auto suffix = std::to_string(index);
        id.replace(id.size() - suffix.size(), suffix.size(), suffix);
        kasumi::test::write_text(heads / (id + "-" + std::string(64, 'a')),
                                 "x");
    }
    const auto limited = inspect(workspace, InspectionOperation::RemoteMarkers);
    ASSERT_FALSE(limited.has_value());
    EXPECT_EQ(limited.error().code,
              InspectionErrorCode::RemoteObservationFailure);

    const auto blocked =
        kasumi::test::workspace_path(workspace, "blocked-transport");
    kasumi::test::write_text(blocked, "arquivo");
    write_profile(workspace, blocked / "remote");
    const auto transport_failure =
        inspect(workspace, InspectionOperation::RemoteObjects);
    ASSERT_FALSE(transport_failure.has_value());
    EXPECT_EQ(transport_failure.error().code,
              InspectionErrorCode::RuntimeFailure);
}

TEST(
    ApplicationInspectionTest,
    RemoteWritersReportBarrierPresenceAndFullIdentifierWithoutModifyingStorage) {
    auto fixture = make_local_storage();
    auto workspace =
        kasumi::test::make_temp_workspace("application-writers-barrier-id");
    const auto remote_root =
        kasumi::test::workspace_path(fixture.workspace, "storage");
    write_profile(workspace, remote_root);
    publish(fixture, make_commit(0, {}, "file.txt", "contents").value());
    const auto layout =
        kasumi::application::history_storage::derive_remote_layout(test_key());

    // 1. Absent barrier
    auto writers_before =
        inspect(workspace, InspectionOperation::RemoteWriters);
    ASSERT_TRUE(writers_before.has_value()) << writers_before.error().detail;
    const auto& report_before =
        std::get<kasumi::application::RemoteWritersReport>(
            writers_before->payload);
    EXPECT_FALSE(report_before.barrier_present);
    EXPECT_FALSE(report_before.barrier_identifier.has_value());

    // 2. Present barrier
    put_object(fixture, layout.barrier_identifier);
    auto writers_after = inspect(workspace, InspectionOperation::RemoteWriters);
    ASSERT_TRUE(writers_after.has_value()) << writers_after.error().detail;
    const auto& report_after =
        std::get<kasumi::application::RemoteWritersReport>(
            writers_after->payload);
    EXPECT_TRUE(report_after.barrier_present);
    ASSERT_TRUE(report_after.barrier_identifier.has_value());
    EXPECT_EQ(*report_after.barrier_identifier, layout.barrier_identifier);

    // 3. Inspection remains strictly read-only and non-destructive
    EXPECT_TRUE(std::filesystem::exists(
        remote_root / std::filesystem::path{layout.barrier_identifier}));
}
} // namespace
