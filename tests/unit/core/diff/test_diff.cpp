#include "core/diff.hpp"
#include "core/hasher.hpp"
#include "core/node.hpp"
#include "platform/path.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using kasumi::Action;
using kasumi::HashSet;
using kasumi::NodeRow;
using kasumi::Snapshot;

Snapshot tree(std::initializer_list<NodeRow> rows = {}) {
    Snapshot snapshot{{{.path = "", .is_directory = true}}};
    snapshot.rows.insert(snapshot.rows.end(), rows.begin(), rows.end());
    kasumi::finalize_snapshot(snapshot);
    return snapshot;
}

NodeRow file(std::string path,
             std::string_view contents,
             std::filesystem::file_time_type mtime = {},
             std::uint64_t size = 0) {
    if (size == 0)
        size = contents.size();
    return {.path = std::move(path),
            .hash = kasumi::hasher::hash_string(contents),
            .size = size,
            .mtime = mtime,
            .is_directory = false};
}

NodeRow directory(std::string path) {
    return {.path = std::move(path), .is_directory = true};
}

std::string action_name(Action action) {
    switch (action) {
        case Action::RenameLocal:
            return "RenameLocal";
        case Action::Upload:
            return "Upload";
        case Action::CreateLocalDirectory:
            return "CreateLocalDirectory";
        case Action::CreateRemoteDirectory:
            return "CreateRemoteDirectory";
        case Action::Download:
            return "Download";
        case Action::DeleteLocal:
            return "DeleteLocal";
        case Action::DeleteLocalDirectory:
            return "DeleteLocalDirectory";
        case Action::DeleteRemote:
            return "DeleteRemote";
        case Action::DeleteRemoteDirectory:
            return "DeleteRemoteDirectory";
        case Action::Count:
            break;
    }
    return "Invalid";
}

std::string signature(Action action,
                      std::string_view path,
                      std::string_view hash = {},
                      std::string_view alt_path = {},
                      std::uint64_t size = 0,
                      bool exclusive = false) {
    return action_name(action) + "|" + std::string{path} + "|" +
           std::string{hash} + "|" + std::string{alt_path} + "|" +
           std::to_string(size) + "|" + (exclusive ? "1" : "0");
}

std::vector<std::string>
signatures(const std::vector<kasumi::Operation>& operations) {
    std::vector<std::string> result;
    result.reserve(operations.size());
    for (const auto& operation : operations) {
        result.push_back(signature(operation.action,
                                   kasumi::platform::path::to_logical_utf8(operation.path),
                                   operation.hash,
                                   kasumi::platform::path::to_logical_utf8(operation.alt_path),
                                   operation.size,
                                   operation.exclusive_destination));
    }
    std::ranges::sort(result);
    return result;
}

void expect_operations(const std::vector<kasumi::Operation>& actual,
                       std::vector<std::string> expected) {
    std::ranges::sort(expected);
    EXPECT_EQ(signatures(actual), expected);
}

TEST(DiffThreeWayTest, CoversCanonicalCreationChangeDeletionAndNoOpStates) {
    const auto base_file = file("state.txt", "base");
    const auto local_file = file("state.txt", "local");
    const auto cloud_file = file("state.txt", "cloud");

    {
        const auto operations = kasumi::diff::compare_trees(
            tree({file("local.txt", "local")}), tree(), tree());
        expect_operations(
            operations,
            {signature(Action::Upload,
                       "local.txt",
                       kasumi::hash_hex(kasumi::hasher::hash_string("local")),
                       {},
                       5)});
    }
    {
        const auto operations = kasumi::diff::compare_trees(
            tree(), tree(), tree({file("cloud.txt", "cloud")}));
        expect_operations(
            operations,
            {signature(Action::Download,
                       "cloud.txt",
                       kasumi::hash_hex(kasumi::hasher::hash_string("cloud")),
                       {},
                       5)});
    }
    {
        const auto operations = kasumi::diff::compare_trees(
            tree({local_file}), tree({base_file}), tree({base_file}));
        expect_operations(operations,
                          {signature(Action::Upload,
                                     "state.txt",
                                     kasumi::hash_hex(local_file.hash),
                                     {},
                                     local_file.size)});
    }
    {
        const auto operations = kasumi::diff::compare_trees(
            tree({base_file}), tree({base_file}), tree({cloud_file}));
        expect_operations(operations,
                          {signature(Action::Download,
                                     "state.txt",
                                     kasumi::hash_hex(cloud_file.hash),
                                     {},
                                     cloud_file.size)});
    }
    {
        const auto operations = kasumi::diff::compare_trees(
            tree(), tree({base_file}), tree({base_file}));
        expect_operations(operations,
                          {signature(Action::DeleteRemote,
                                     "state.txt",
                                     kasumi::hash_hex(base_file.hash))});
    }
    {
        const auto operations = kasumi::diff::compare_trees(
            tree({base_file}), tree({base_file}), tree());
        expect_operations(operations,
                          {signature(Action::DeleteLocal, "state.txt")});
    }
    {
        auto local = file("same.txt", "same");
        auto cloud = local;
        cloud.mtime = std::filesystem::file_time_type::clock::now() +
                      std::chrono::hours{24};
        const auto operations = kasumi::diff::compare_trees(
            tree({local}), tree({file("same.txt", "base")}), tree({cloud}));
        EXPECT_TRUE(operations.empty());
    }
}

TEST(DiffThreeWayTest, CoversDirectorySubtreesAndTypeChanges) {
    {
        const auto operations = kasumi::diff::compare_trees(
            tree(), tree(), tree({directory("remote-empty")}));
        expect_operations(
            operations,
            {signature(Action::CreateLocalDirectory, "remote-empty")});
    }
    {
        const auto operations = kasumi::diff::compare_trees(
            tree({directory("local-empty")}), tree(), tree());
        expect_operations(
            operations,
            {signature(Action::CreateRemoteDirectory, "local-empty")});
    }
    {
        const auto operations = kasumi::diff::compare_trees(
            tree(),
            tree(),
            tree({directory("docs"), file("docs/readme.txt", "readme")}));
        expect_operations(
            operations,
            {signature(Action::CreateLocalDirectory, "docs"),
             signature(Action::Download,
                       "docs/readme.txt",
                       kasumi::hash_hex(kasumi::hasher::hash_string("readme")),
                       {},
                       6)});
    }
    {
        const auto base =
            tree({directory("docs"), file("docs/readme.txt", "readme")});
        const auto operations = kasumi::diff::compare_trees(tree(), base, base);
        expect_operations(
            operations,
            {signature(
                Action::DeleteRemoteDirectory,
                "docs",
                kasumi::hash_hex(kasumi::find_row(base, "docs")->hash))});
    }

    const auto now = std::filesystem::file_time_type::clock::now();
    auto local_directory = directory("same-path");
    local_directory.mtime = now;
    auto cloud_file =
        file("same-path", "remote-file", now + std::chrono::hours{1});
    const auto operations = kasumi::diff::compare_trees(
        tree({local_directory}), tree(), tree({cloud_file}));
    EXPECT_FALSE(std::ranges::any_of(operations, [](const auto& operation) {
        return operation.action == Action::DeleteLocal;
    }));
}

TEST(DiffThreeWayTest, ExpandsUnchangedLocalSubtreeDeletes) {
    {
        const auto shared = tree(
            {directory("dir"), file("dir/gamma.txt", "gamma")});
        expect_operations(
            kasumi::diff::compare_trees(shared, shared, tree()),
            {signature(Action::DeleteLocal, "dir/gamma.txt"),
             signature(Action::DeleteLocalDirectory, "dir")});
    }
    {
        const auto shared =
            tree({directory("a"),
                  directory("a/b"),
                  file("a/b/c.txt", "c"),
                  file("a/d.txt", "d")});
        expect_operations(
            kasumi::diff::compare_trees(shared, shared, tree()),
            {signature(Action::DeleteLocal, "a/b/c.txt"),
             signature(Action::DeleteLocal, "a/d.txt"),
             signature(Action::DeleteLocalDirectory, "a/b"),
             signature(Action::DeleteLocalDirectory, "a")});
    }
    {
        const auto shared =
            tree({file("alpha.txt", "alpha"),
                  file("beta.txt", "beta"),
                  directory("dir"),
                  file("dir/gamma.txt", "gamma")});
        expect_operations(
            kasumi::diff::compare_trees(shared, shared, tree()),
            {signature(Action::DeleteLocal, "alpha.txt"),
             signature(Action::DeleteLocal, "beta.txt"),
             signature(Action::DeleteLocal, "dir/gamma.txt"),
             signature(Action::DeleteLocalDirectory, "dir")});
    }
}

TEST(DiffThreeWayTest, PreservesRootAndConcurrentLocalSubtreeChanges) {
    {
        const auto shared = tree(
            {file("alpha.txt", "alpha"), file("beta.txt", "beta")});
        expect_operations(
            kasumi::diff::compare_trees(shared, shared, tree()),
            {signature(Action::DeleteLocal, "alpha.txt"),
             signature(Action::DeleteLocal, "beta.txt")});
    }
    {
        const auto base =
            tree({directory("dir"), file("dir/file.txt", "base")});
        const auto local =
            tree({directory("dir"), file("dir/file.txt", "local")});
        expect_operations(
            kasumi::diff::compare_trees(local, base, tree()),
            {signature(Action::CreateRemoteDirectory, "dir", {}, {}, 0),
             signature(Action::Upload,
                       "dir/file.txt",
                       kasumi::hash_hex(
                           kasumi::hasher::hash_string("local")),
                       {},
                       5)});
    }
}

TEST(DiffThreeWayTest, MissingPhysicalBlocksRequestRepairOrRemainPending) {
    const auto local = tree({file("repair.txt", "repair")});
    const auto base = tree({file("repair.txt", "repair")});
    const auto cloud = tree({file("repair.txt", "repair")});
    HashSet missing(0, kasumi::hash_key);
    missing.insert(kasumi::find_row(cloud, "repair.txt")->hash);

    const auto repair =
        kasumi::diff::compare_trees(local, base, cloud, missing);
    expect_operations(
        repair,
        {signature(
            Action::Upload,
            "repair.txt",
            kasumi::hash_hex(kasumi::find_row(local, "repair.txt")->hash),
            {},
            6)});

    const auto pending =
        kasumi::diff::compare_trees(tree(), tree(), cloud, missing);
    EXPECT_TRUE(pending.empty());
}

TEST(DiffThreeWayTest,
     PreservesIndependentFileChangesWithConflictDestinations) {
    const auto now = std::filesystem::file_time_type::clock::now();
    const auto base = file("notes.txt", "base", now);
    const auto local = file("notes.txt", "local", now + std::chrono::hours{2});
    const auto cloud = file("notes.txt", "cloud", now);

    const auto local_newer =
        kasumi::diff::compare_trees(tree({local}), tree({base}), tree({cloud}));
    expect_operations(local_newer,
                      {signature(Action::Upload,
                                 "notes.txt",
                                 kasumi::hash_hex(local.hash),
                                 {},
                                 local.size),
                       signature(Action::Download,
                                 "notes.txt.kasumiconflict_remote",
                                 kasumi::hash_hex(cloud.hash),
                                 {},
                                 cloud.size,
                                 true)});

    const auto local_older =
        file("notes.txt", "local", now - std::chrono::hours{2});
    const auto older = kasumi::diff::compare_trees(
        tree({local_older}), tree({base}), tree({cloud}));
    expect_operations(older,
                      {signature(Action::RenameLocal,
                                 "notes.txt",
                                 {},
                                 "notes.txt.kasumiconflict_local",
                                 0,
                                 true),
                       signature(Action::Download,
                                 "notes.txt",
                                 kasumi::hash_hex(cloud.hash),
                                 {},
                                 cloud.size),
                       signature(Action::Upload,
                                 "notes.txt.kasumiconflict_local",
                                 kasumi::hash_hex(local_older.hash),
                                 {},
                                 local_older.size)});
}

TEST(DiffThreeWayTest, UnicodeConflictPathsPreserveAllConflictBranches) {
    const std::string logical_path = "高松灯/カード💝.png";
    const auto now = std::filesystem::file_time_type::clock::now();
    const auto base = tree({directory("高松灯"), file(logical_path, "base", now)});
    const auto cloud_file = file(logical_path, "cloud", now);
    const auto cloud = tree({directory("高松灯"), cloud_file});
    const auto local_file = file(logical_path, "local", now + std::chrono::hours{1});
    const auto local = tree({directory("高松灯"), local_file});

    expect_operations(kasumi::diff::compare_trees(local, base, cloud),
                      {signature(Action::Upload,
                                 logical_path,
                                 kasumi::hash_hex(local_file.hash),
                                 {},
                                 local_file.size),
                       signature(Action::Download,
                                 logical_path + ".kasumiconflict_remote",
                                 kasumi::hash_hex(cloud_file.hash),
                                 {},
                                 cloud_file.size,
                                 true)});

    const auto older_file = file(logical_path, "local", now - std::chrono::hours{1});
    const auto older = tree({directory("高松灯"), older_file});
    expect_operations(kasumi::diff::compare_trees(older, base, cloud),
                      {signature(Action::RenameLocal,
                                 logical_path,
                                 {},
                                 logical_path + ".kasumiconflict_local",
                                 0,
                                 true),
                       signature(Action::Download,
                                 logical_path,
                                 kasumi::hash_hex(cloud_file.hash),
                                 {},
                                 cloud_file.size),
                       signature(Action::Upload,
                                 logical_path + ".kasumiconflict_local",
                                 kasumi::hash_hex(older_file.hash),
                                 {},
                                 older_file.size)});

    auto local_directory = directory(logical_path);
    local_directory.mtime = now - std::chrono::hours{1};
    expect_operations(kasumi::diff::compare_trees(
                          tree({directory("高松灯"), local_directory}), base, cloud),
                      {signature(Action::Download,
                                 logical_path + ".kasumiconflict_remote",
                                 kasumi::hash_hex(cloud_file.hash),
                                 {},
                                 cloud_file.size,
                                 true)});
}

TEST(DiffThreeWayTest, FileAndDirectoryStatesDoNotBecomeAccidentalDeletes) {
    const auto now = std::filesystem::file_time_type::clock::now();
    auto local_directory = directory("shared");
    local_directory.mtime = now;
    const auto cloud_file =
        file("shared", "cloud", now + std::chrono::hours{1});
    const auto operations = kasumi::diff::compare_trees(
        tree({local_directory}), tree(), tree({cloud_file}));
    EXPECT_FALSE(std::ranges::any_of(operations, [](const auto& operation) {
        return operation.action == Action::DeleteLocal &&
               operation.path == std::filesystem::path{"shared"};
    }));

    auto local_file = file("reverse", "local", now);
    auto cloud_directory = directory("reverse");
    cloud_directory.mtime = now + std::chrono::hours{1};
    const auto reverse = kasumi::diff::compare_trees(
        tree({local_file}), tree(), tree({cloud_directory}));
    expect_operations(reverse,
                      {signature(Action::CreateLocalDirectory, "reverse")});
}

} // namespace
