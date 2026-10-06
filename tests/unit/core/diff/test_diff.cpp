#include "core/diff.hpp"
#include "core/hasher.hpp"
#include "core/node.hpp"
#include "platform/path.hpp"

#include <algorithm>
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

constexpr kasumi::TimestampNs test_mtime = 1'700'000'000'000'000'000LL;

constexpr kasumi::TimestampNs hours_ns(std::int64_t hours) noexcept {
    return hours * 3'600'000'000'000LL;
}

Snapshot tree(std::initializer_list<NodeRow> rows = {}) {
    Snapshot snapshot{{{.path = "", .is_directory = true}}};
    snapshot.rows.insert(snapshot.rows.end(), rows.begin(), rows.end());
    kasumi::finalize_snapshot(snapshot);
    return snapshot;
}

NodeRow file(std::string path,
             std::string_view contents,
             kasumi::TimestampNs mtime = 0,
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
        result.push_back(signature(
            operation.action,
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
        cloud.mtime = test_mtime + hours_ns(24);
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

    constexpr auto now = test_mtime;
    auto local_directory = directory("same-path");
    local_directory.mtime = now;
    auto cloud_file =
        file("same-path", "remote-file", now + hours_ns(1));
    const auto operations = kasumi::diff::compare_trees(
        tree({local_directory}), tree(), tree({cloud_file}));
    EXPECT_FALSE(std::ranges::any_of(operations, [](const auto& operation) {
        return operation.action == Action::DeleteLocal;
    }));
}

TEST(DiffThreeWayTest, ExpandsUnchangedLocalSubtreeDeletes) {
    {
        const auto shared =
            tree({directory("dir"), file("dir/gamma.txt", "gamma")});
        expect_operations(kasumi::diff::compare_trees(shared, shared, tree()),
                          {signature(Action::DeleteLocal, "dir/gamma.txt"),
                           signature(Action::DeleteLocalDirectory, "dir")});
    }
    {
        const auto shared = tree({directory("a"),
                                  directory("a/b"),
                                  file("a/b/c.txt", "c"),
                                  file("a/d.txt", "d")});
        expect_operations(kasumi::diff::compare_trees(shared, shared, tree()),
                          {signature(Action::DeleteLocal, "a/b/c.txt"),
                           signature(Action::DeleteLocal, "a/d.txt"),
                           signature(Action::DeleteLocalDirectory, "a/b"),
                           signature(Action::DeleteLocalDirectory, "a")});
    }
    {
        const auto shared = tree({file("alpha.txt", "alpha"),
                                  file("beta.txt", "beta"),
                                  directory("dir"),
                                  file("dir/gamma.txt", "gamma")});
        expect_operations(kasumi::diff::compare_trees(shared, shared, tree()),
                          {signature(Action::DeleteLocal, "alpha.txt"),
                           signature(Action::DeleteLocal, "beta.txt"),
                           signature(Action::DeleteLocal, "dir/gamma.txt"),
                           signature(Action::DeleteLocalDirectory, "dir")});
    }
}

TEST(DiffThreeWayTest, PreservesRootAndConcurrentLocalSubtreeChanges) {
    {
        const auto shared =
            tree({file("alpha.txt", "alpha"), file("beta.txt", "beta")});
        expect_operations(kasumi::diff::compare_trees(shared, shared, tree()),
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
                       kasumi::hash_hex(kasumi::hasher::hash_string("local")),
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
    constexpr auto now = test_mtime;
    const auto base = file("notes.txt", "base", now);
    const auto local = file("notes.txt", "local", now + hours_ns(2));
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
                                 "notes.txt",
                                 cloud.size,
                                 true)});

    const auto local_older =
        file("notes.txt", "local", now - hours_ns(2));
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

TEST(DiffThreeWayTest, ConflictOrderingUsesCanonicalNanoseconds) {
    constexpr kasumi::TimestampNs older_ns = 123456700;
    constexpr kasumi::TimestampNs newer_ns = 123456789;
    const auto base = file("notes.txt", "base", older_ns);
    const auto local_older = file("notes.txt", "local", older_ns);
    const auto remote_newer = file("notes.txt", "remote", newer_ns);

    expect_operations(
        kasumi::diff::compare_trees(tree({local_older}),
                                    tree({base}),
                                    tree({remote_newer})),
        {signature(Action::RenameLocal,
                   "notes.txt",
                   {},
                   "notes.txt.kasumiconflict_local",
                   0,
                   true),
         signature(Action::Download,
                   "notes.txt",
                   kasumi::hash_hex(remote_newer.hash),
                   {},
                   remote_newer.size),
         signature(Action::Upload,
                   "notes.txt.kasumiconflict_local",
                   kasumi::hash_hex(local_older.hash),
                   {},
                   local_older.size)});

    const auto local_newer = file("notes.txt", "local", newer_ns);
    const auto remote_older = file("notes.txt", "remote", older_ns);
    expect_operations(
        kasumi::diff::compare_trees(tree({local_newer}),
                                    tree({base}),
                                    tree({remote_older})),
        {signature(Action::Upload,
                   "notes.txt",
                   kasumi::hash_hex(local_newer.hash),
                   {},
                   local_newer.size),
         signature(Action::Download,
                   "notes.txt.kasumiconflict_remote",
                   kasumi::hash_hex(remote_older.hash),
                   "notes.txt",
                   remote_older.size,
                   true)});
}

TEST(DiffThreeWayTest, UnicodeConflictPathsPreserveAllConflictBranches) {
    const std::string logical_path = "高松灯/カード💝.png";
    constexpr auto now = test_mtime;
    const auto base =
        tree({directory("高松灯"), file(logical_path, "base", now)});
    const auto cloud_file = file(logical_path, "cloud", now);
    const auto cloud = tree({directory("高松灯"), cloud_file});
    const auto local_file =
        file(logical_path, "local", now + hours_ns(1));
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
                                 logical_path,
                                 cloud_file.size,
                                 true)});

    const auto older_file =
        file(logical_path, "local", now - hours_ns(1));
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
    local_directory.mtime = now - hours_ns(1);
    expect_operations(
        kasumi::diff::compare_trees(
            tree({directory("高松灯"), local_directory}), base, cloud),
        {signature(Action::Download,
                   logical_path + ".kasumiconflict_remote",
                   kasumi::hash_hex(cloud_file.hash),
                   {},
                   cloud_file.size,
                   true)});
}

TEST(DiffThreeWayTest, FileAndDirectoryStatesDoNotBecomeAccidentalDeletes) {
    constexpr auto now = test_mtime;
    auto local_directory = directory("shared");
    local_directory.mtime = now;
    const auto cloud_file =
        file("shared", "cloud", now + hours_ns(1));
    const auto operations = kasumi::diff::compare_trees(
        tree({local_directory}), tree(), tree({cloud_file}));
    EXPECT_FALSE(std::ranges::any_of(operations, [](const auto& operation) {
        return operation.action == Action::DeleteLocal &&
               operation.path == std::filesystem::path{"shared"};
    }));

    auto local_file = file("reverse", "local", now);
    auto cloud_directory = directory("reverse");
    cloud_directory.mtime = now + hours_ns(1);
    const auto reverse = kasumi::diff::compare_trees(
        tree({local_file}), tree(), tree({cloud_directory}));
    expect_operations(
        reverse,
        {signature(Action::CreateLocalDirectory, "reverse"),
         signature(Action::RenameLocal,
                   "reverse",
                   {},
                   "reverse.kasumiconflict_local",
                   0,
                   true),
         signature(Action::Upload,
                   "reverse.kasumiconflict_local",
                   kasumi::hash_hex(local_file.hash),
                   {},
                   local_file.size)});
}

TEST(DiffThreeWayTest, IgnoredFilesOnRemoteArePurgedAndNotDownloaded) {
    constexpr auto now = test_mtime;
    const auto ignore_list =
        kasumi::ignore::parse_ignore_rules("desktop.ini\n");

    const auto normal = file("normal.txt", "content", now);
    const auto base_desktop =
        file("desktop.ini", "base_ini", now - hours_ns(1));
    const auto cloud_desktop = file("desktop.ini", "modified_remote_ini", now);

    const auto local_tree = tree({normal});
    const auto base_tree = tree({normal, base_desktop});
    const auto cloud_tree = tree({normal, cloud_desktop});

    const auto operations = kasumi::diff::compare_trees(
        local_tree, base_tree, cloud_tree, &ignore_list);

    expect_operations(operations,
                      {signature(Action::DeleteRemote,
                                 "desktop.ini",
                                 kasumi::hash_hex(cloud_desktop.hash))});
}

TEST(DiffThreeWayTest, IgnoredWildcardPatternPurgesRemoteMatches) {
    constexpr auto now = test_mtime;
    const auto ignore_list = kasumi::ignore::parse_ignore_rules("*.log\n");

    const auto doc = file("docs/readme.md", "read", now);
    const auto log1 = file("logs/error.log", "err", now);
    const auto log2 = file("logs/debug.log", "dbg", now);

    const auto local_tree = tree({directory("docs"), doc});
    const auto base_tree = tree();
    const auto cloud_tree =
        tree({directory("docs"), doc, directory("logs"), log2, log1});

    const auto operations = kasumi::diff::compare_trees(
        local_tree, base_tree, cloud_tree, &ignore_list);

    EXPECT_FALSE(std::ranges::any_of(operations, [](const auto& op) {
        return op.action == Action::Download &&
               (op.path.string().ends_with(".log"));
    }));
    EXPECT_TRUE(std::ranges::any_of(operations, [&](const auto& op) {
        return op.action == Action::DeleteRemote &&
               op.path == std::filesystem::path{"logs/error.log"};
    }));
    EXPECT_TRUE(std::ranges::any_of(operations, [&](const auto& op) {
        return op.action == Action::DeleteRemote &&
               op.path == std::filesystem::path{"logs/debug.log"};
    }));
}

TEST(DiffThreeWayTest, IgnoredDirectoryPurgesRemoteSubtreeWithoutRecursing) {
    constexpr auto now = test_mtime;
    const auto ignore_list =
        kasumi::ignore::parse_ignore_rules("node_modules/\n");

    const auto pkg = file("package.json", "{}", now);
    const auto mod_dir = directory("node_modules");
    const auto mod_sub = directory("node_modules/lib");
    const auto mod_file = file("node_modules/lib/index.js", "js", now);

    const auto local_tree = tree({pkg});
    const auto base_tree = tree();
    const auto cloud_tree = tree({mod_dir, mod_sub, mod_file, pkg});

    const auto operations = kasumi::diff::compare_trees(
        local_tree, base_tree, cloud_tree, &ignore_list);

    // Only node_modules directory itself should receive DeleteRemoteDirectory.
    // Children inside node_modules must NOT be traversed or scheduled.
    expect_operations(
        operations, {signature(Action::DeleteRemoteDirectory, "node_modules")});
}

TEST(DiffThreeWayTest, NegatedIgnoreRuleReincludesRemoteFile) {
    constexpr auto now = test_mtime;
    const auto ignore_list =
        kasumi::ignore::parse_ignore_rules("*.txt\n!important.txt\n");

    const auto other = file("other.txt", "drop", now);
    const auto important = file("important.txt", "keep", now);

    const auto local_tree = tree();
    const auto base_tree = tree();
    const auto cloud_tree = tree({important, other});

    const auto operations = kasumi::diff::compare_trees(
        local_tree, base_tree, cloud_tree, &ignore_list);

    // other.txt is deleted remotely, important.txt is downloaded.
    EXPECT_TRUE(std::ranges::any_of(operations, [&](const auto& op) {
        return op.action == Action::DeleteRemote &&
               op.path == std::filesystem::path{"other.txt"};
    }));
    EXPECT_TRUE(std::ranges::any_of(operations, [&](const auto& op) {
        return op.action == Action::Download &&
               op.path == std::filesystem::path{"important.txt"};
    }));
}

} // namespace
