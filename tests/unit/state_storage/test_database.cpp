#include "core/hasher.hpp"
#include "kasumi/test/filesystem.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/path.hpp"
#include "state_storage/database.hpp"
#include "state_storage/database_connection.hpp"

#include <algorithm>
#include <array>
#include <barrier>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <future>
#include <gtest/gtest.h>
#include <limits>
#include <memory>
#include <span>
#include <sqlite3.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using Database = std::unique_ptr<sqlite3, int (*)(sqlite3*)>;

Database open_database(const std::filesystem::path& path, int flags) {
    auto database = kasumi::sqlite::open(path, flags);
    if (!database) {
        throw std::runtime_error(database.error());
    }
    return std::move(*database);
}

void execute_sql(const std::filesystem::path& path,
                 std::string_view sql,
                 int flags = SQLITE_OPEN_READWRITE) {
    auto database = open_database(path, flags);
    char* message = nullptr;
    const std::string statement{sql};
    const auto result = sqlite3_exec(
        database.get(), statement.c_str(), nullptr, nullptr, &message);
    if (result != SQLITE_OK) {
        const std::string detail =
            message == nullptr ? sqlite3_errmsg(database.get()) : message;
        sqlite3_free(message);
        throw std::runtime_error(detail);
    }
}

std::vector<std::string> query_text(const std::filesystem::path& path,
                                    std::string_view sql) {
    auto database = open_database(path, SQLITE_OPEN_READONLY);
    sqlite3_stmt* raw = nullptr;
    const std::string statement{sql};
    if (sqlite3_prepare_v2(
            database.get(), statement.c_str(), -1, &raw, nullptr) !=
        SQLITE_OK) {
        throw std::runtime_error(sqlite3_errmsg(database.get()));
    }
    const std::unique_ptr<sqlite3_stmt, int (*)(sqlite3_stmt*)> query{
        raw, sqlite3_finalize};
    std::vector<std::string> result;
    while (sqlite3_step(query.get()) == SQLITE_ROW) {
        const auto* value = sqlite3_column_text(query.get(), 0);
        result.emplace_back(
            value == nullptr ? "" : reinterpret_cast<const char*>(value));
    }
    if (sqlite3_errcode(database.get()) != SQLITE_OK &&
        sqlite3_errcode(database.get()) != SQLITE_DONE) {
        throw std::runtime_error(sqlite3_errmsg(database.get()));
    }
    return result;
}

void update_generation(const std::filesystem::path& path,
                       std::string_view value) {
    auto database = open_database(path, SQLITE_OPEN_READWRITE);
    sqlite3_stmt* raw = nullptr;
    constexpr std::string_view sql =
        "UPDATE metadata SET value = ? WHERE key = 'generation'";
    if (sqlite3_prepare_v2(database.get(), sql.data(), -1, &raw, nullptr) !=
        SQLITE_OK) {
        throw std::runtime_error(sqlite3_errmsg(database.get()));
    }
    const std::unique_ptr<sqlite3_stmt, int (*)(sqlite3_stmt*)> update{
        raw, sqlite3_finalize};
    if (sqlite3_bind_text(update.get(),
                          1,
                          value.data(),
                          static_cast<int>(value.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_step(update.get()) != SQLITE_DONE) {
        throw std::runtime_error(sqlite3_errmsg(database.get()));
    }
}

kasumi::Snapshot make_snapshot(std::string_view file_path,
                               std::string_view contents,
                               std::int64_t time_offset) {
    const auto root_time = std::chrono::duration_cast<std::chrono::nanoseconds>(
                               std::chrono::seconds{time_offset})
                               .count();
    kasumi::Snapshot snapshot{{
        {.path = "", .mtime = root_time, .is_directory = true},
        {.path = "docs",
         .mtime = root_time + 1'000'000'000,
         .is_directory = true},
        {.path = std::string{file_path},
         .hash = kasumi::hasher::hash_string(contents),
         .size = static_cast<std::uint64_t>(contents.size()),
         .mtime = root_time + 2'000'000'000,
         .is_directory = false},
    }};
    kasumi::finalize_snapshot(snapshot);
    return snapshot;
}

struct DbWorkspace {
    kasumi::test::TempWorkspace workspace;
    std::filesystem::path database_path;
};

DbWorkspace make_db(std::string_view name) {
    auto workspace = kasumi::test::make_temp_workspace(name);
    auto database_path = kasumi::test::workspace_path(workspace, "state.db");
    EXPECT_TRUE(kasumi::state_storage::initialize(database_path));
    return {std::move(workspace), std::move(database_path)};
}

TEST(StateStorageDatabaseTest, InitializesFreshDatabaseIdempotently) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-initialize");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    EXPECT_FALSE(std::filesystem::exists(database_path));

    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    EXPECT_TRUE(kasumi::state_storage::initialize(database_path));

    const auto loaded = kasumi::state_storage::load_state(database_path);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_FALSE(*loaded);
}

TEST(StateStorageDatabaseTest,
     ConcurrentInitializationPublishesOneValidDatabase) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-init-concurrent");
    const auto path = kasumi::test::workspace_path(workspace, "state.db");
    std::barrier start{3};
    const auto initialize = [&] {
        start.arrive_and_wait();
        return kasumi::state_storage::initialize(path);
    };
    auto first = std::async(std::launch::async, initialize);
    auto second = std::async(std::launch::async, initialize);
    start.arrive_and_wait();

    EXPECT_TRUE(first.get());
    EXPECT_TRUE(second.get());
    EXPECT_TRUE(kasumi::state_storage::validate(path));
    EXPECT_EQ(query_text(path, "PRAGMA journal_mode"),
              std::vector<std::string>{"wal"});
}

TEST(StateStorageDatabaseTest, FreshInitializationPreservesOrphanedSidecar) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-init-sidecar");
    const auto path = kasumi::test::workspace_path(workspace, "state.db");
    const auto sidecar =
        kasumi::test::workspace_path(workspace, "state.db-wal");
    kasumi::test::write_text(sidecar, "previous state");

    EXPECT_FALSE(kasumi::state_storage::initialize(path));
    EXPECT_FALSE(std::filesystem::exists(path));
    EXPECT_EQ(kasumi::test::read_text(sidecar), "previous state");
    ASSERT_TRUE(std::filesystem::remove(sidecar));
    EXPECT_TRUE(kasumi::state_storage::initialize(path));
}

TEST(StateStorageDatabaseTest,
     CanonicalStateAndCacheDoNotRequireObservationTables) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-no-checkpoint");
    const auto db = kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(db));
    const auto snapshot = make_snapshot("a.txt", "alpha", 9);
    ASSERT_TRUE(kasumi::state_storage::save_state(
        db,
        kasumi::state_storage::StoredState{snapshot, 7, std::string(64, 'a')}));
    execute_sql(
        db,
        "DROP TABLE IF EXISTS observation_checkpoint; DROP TABLE IF EXISTS "
        "directory_lineage; DROP TABLE IF EXISTS directory_lineage_metadata;");
    EXPECT_TRUE(kasumi::state_storage::initialize(db));
    const auto loaded = kasumi::state_storage::load_state(db);
    ASSERT_TRUE(loaded.has_value()) << loaded.error();
    ASSERT_TRUE(loaded->has_value());
    EXPECT_EQ((*loaded)->tree, snapshot);
    EXPECT_EQ((*loaded)->height, 7U);
    EXPECT_TRUE(kasumi::state_storage::load_file_cache(db).has_value());
    EXPECT_TRUE(kasumi::state_storage::save_file_cache_delta(db, {}));
}

TEST(StateStorageDatabaseTest, UnknownAuxiliaryTablesAreIgnoredAndPreserved) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-unknown-auxiliary");
    const auto db = kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(db));
    // Unrecognized auxiliary tables remain outside the current schema contract.
    execute_sql(db, R"(
        CREATE TABLE IF NOT EXISTS observation_checkpoint (
            id INTEGER PRIMARY KEY CHECK(id = 1), kind INTEGER NOT NULL,
            volume_serial TEXT NOT NULL, journal_id TEXT NOT NULL,
            next_usn TEXT NOT NULL, root_file_reference TEXT NOT NULL,
            tree_root_hash TEXT NOT NULL, row_count TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS directory_lineage_metadata (
            id INTEGER PRIMARY KEY CHECK(id = 1), volume_serial TEXT NOT NULL,
            journal_id TEXT NOT NULL, root_file_reference TEXT NOT NULL,
            tree_root_hash TEXT NOT NULL, row_count TEXT NOT NULL,
            directory_count TEXT NOT NULL,
            lineage_complete INTEGER NOT NULL CHECK(lineage_complete IN (0, 1)));
        CREATE TABLE IF NOT EXISTS directory_lineage (
            file_reference TEXT PRIMARY KEY NOT NULL);
        INSERT INTO observation_checkpoint VALUES
            (1, 1, '11', '22', '33', '44',
             'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '3');
        INSERT INTO directory_lineage_metadata VALUES
            (1, '11', '22', '44',
             'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '3', '2', 1);
        INSERT INTO directory_lineage VALUES ('44'), ('55');
    )");
    const auto snapshot = make_snapshot("docs/a.txt", "alpha", 9);
    const kasumi::state_storage::StoredState expected{
        .tree = snapshot,
        .height = 7,
        .commit_id = std::string(64, 'a'),
        .ciphertext_id = std::string(64, 'b'),
        .epoch_id = std::string(64, 'c'),
        .epoch_sequence = 2,
        .pending_materializations = {
            *kasumi::find_row(snapshot, "docs/a.txt")}};
    ASSERT_TRUE(kasumi::state_storage::save_state(db, expected));
    const std::array rows{kasumi::state_storage::FileCacheRow{
        .path = "docs/a.txt",
        .hash = kasumi::hasher::hash_string("alpha"),
        .size = 5,
        .mtime_nanoseconds = 1000,
        .volume = 1,
        .file_low = 2,
        .file_high = 3}};
    ASSERT_TRUE(kasumi::state_storage::save_file_cache_delta(db, rows));
    for (int execution = 0; execution < 2; ++execution) {
        ASSERT_TRUE(kasumi::state_storage::initialize(db));
        const auto loaded = kasumi::state_storage::load_state(db);
        ASSERT_TRUE(loaded.has_value()) << loaded.error();
        ASSERT_TRUE(loaded->has_value());
        EXPECT_EQ((*loaded)->tree, expected.tree);
        EXPECT_EQ((*loaded)->height, expected.height);
        EXPECT_EQ((*loaded)->commit_id, expected.commit_id);
        EXPECT_EQ((*loaded)->ciphertext_id, expected.ciphertext_id);
        EXPECT_EQ((*loaded)->epoch_id, expected.epoch_id);
        EXPECT_EQ((*loaded)->epoch_sequence, expected.epoch_sequence);
        EXPECT_EQ((*loaded)->pending_materializations,
                  expected.pending_materializations);
        const auto cache = kasumi::state_storage::load_file_cache(db);
        ASSERT_TRUE(cache.has_value());
        ASSERT_EQ(cache->size(), 1U);
        EXPECT_EQ(cache->front().hash, rows.front().hash);
        ASSERT_TRUE(kasumi::state_storage::save_file_cache_delta(db, *cache));
        // Even corrupt obsolete data must not participate in schema/state
        // validation.
        execute_sql(db,
                    "UPDATE observation_checkpoint SET next_usn='obsolete';");
    }
    EXPECT_EQ(query_text(db, "SELECT next_usn FROM observation_checkpoint"),
              std::vector<std::string>{"obsolete"});
    EXPECT_EQ(query_text(db,
                         "SELECT file_reference FROM directory_lineage ORDER "
                         "BY file_reference"),
              (std::vector<std::string>{"44", "55"}));
    EXPECT_EQ(query_text(
                  db, "SELECT directory_count FROM directory_lineage_metadata"),
              std::vector<std::string>{"2"});
    EXPECT_EQ(query_text(db, "PRAGMA user_version"),
              std::vector<std::string>{"2"});
}
TEST(StateStorageDatabaseTest, FreshDatabaseCreatesInitialSchemaAndEmptyCache) {
    auto [workspace, database_path] = make_db("persistence-schema");
    EXPECT_EQ(query_text(database_path, "PRAGMA user_version").front(), "2");
    EXPECT_TRUE(
        query_text(database_path,
                   "SELECT name FROM sqlite_master WHERE name='file_cache'")
            .size() == 1);
    EXPECT_EQ(
        query_text(
            database_path,
            "SELECT name FROM sqlite_master WHERE name='local_executions'")
            .size(),
        1U);
    EXPECT_EQ(
        query_text(
            database_path,
            "SELECT name FROM sqlite_master WHERE name='accepted_commit_meta'")
            .size(),
        1U);
    EXPECT_EQ(
        query_text(
            database_path,
            "SELECT name FROM sqlite_master WHERE name='remote_activity_cache'")
            .size(),
        1U);
    EXPECT_TRUE(query_text(database_path,
                           "SELECT name FROM sqlite_master WHERE "
                           "name='observation_checkpoint'")
                    .empty());
    EXPECT_TRUE(
        query_text(
            database_path,
            "SELECT name FROM sqlite_master WHERE name='directory_lineage'")
            .empty());
    EXPECT_EQ(query_text(database_path,
                         "SELECT name FROM sqlite_master WHERE "
                         "name='pending_materializations'")
                  .size(),
              1U);
    EXPECT_TRUE(kasumi::state_storage::load_file_cache(database_path)->empty());
}

TEST(StateStorageDatabaseTest, PendingMaterializationsRoundTrip) {
    auto workspace = kasumi::test::make_temp_workspace("pending-round-trip");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    auto snapshot = make_snapshot("docs/state.txt", "state", 9);
    kasumi::find_row(snapshot, "docs/state.txt")->mtime = 123456789;
    kasumi::finalize_snapshot(snapshot);
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = snapshot,
         .height = 7,
         .commit_id = std::string(64, 'a'),
         .pending_materializations = {
             *kasumi::find_row(snapshot, "docs/state.txt")}}));
    const auto loaded = kasumi::state_storage::load_state(database_path);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_EQ((*loaded)->commit_id, std::string(64, 'a'));
    EXPECT_EQ((*loaded)->tree, snapshot);
    ASSERT_EQ((*loaded)->pending_materializations.size(), 1U);
    EXPECT_EQ((*loaded)->pending_materializations.front(),
              *kasumi::find_row(snapshot, "docs/state.txt"));
}

TEST(StateStorageDatabaseTest, PreservesCanonicalNanosecondSnapshots) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-canonical-mtime");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    auto expected = make_snapshot("docs/readme.txt", "persistence", 0);
    expected.rows[1].mtime = -123456789;
    expected.rows[2].mtime = 123456789;
    kasumi::finalize_snapshot(expected);

    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        kasumi::state_storage::StoredState{
            .tree = expected, .height = 1, .commit_id = std::string(64, 'b')}));
    const auto loaded = kasumi::state_storage::load_state(database_path);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    ASSERT_EQ((*loaded)->tree.rows.size(), expected.rows.size());
    for (std::size_t index = 0; index < expected.rows.size(); ++index) {
        EXPECT_EQ((*loaded)->tree.rows[index].mtime,
                  expected.rows[index].mtime);
    }
}

TEST(StateStorageDatabaseTest, EmptyPendingMaterializationsClearPersistedRows) {
    auto workspace = kasumi::test::make_temp_workspace("pending-clear");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    const auto snapshot = make_snapshot("a.txt", "a", 1);
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = snapshot,
         .height = 1,
         .commit_id = std::string(64, 'a'),
         .pending_materializations = {*kasumi::find_row(snapshot, "a.txt")}}));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = snapshot, .height = 2, .commit_id = std::string(64, 'b')}));
    const auto loaded = kasumi::state_storage::load_state(database_path);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_TRUE((*loaded)->pending_materializations.empty());
}

TEST(StateStorageDatabaseTest, RejectsPendingRowsOutsideAcceptedFileRows) {
    auto workspace = kasumi::test::make_temp_workspace("pending-invalid");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    const auto snapshot = make_snapshot("a.txt", "a", 1);
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    const auto file = *kasumi::find_row(snapshot, "a.txt");
    auto changed = file;
    changed.hash = kasumi::hasher::hash_string("different");
    const kasumi::state_storage::StoredState invalid{
        .tree = snapshot,
        .height = 1,
        .commit_id = std::string(64, 'a'),
        .pending_materializations = {changed}};
    EXPECT_FALSE(kasumi::state_storage::save_state(database_path, invalid));
    EXPECT_FALSE(kasumi::state_storage::save_state(
        database_path,
        {.tree = snapshot,
         .height = 1,
         .commit_id = std::string(64, 'a'),
         .pending_materializations = {file, file}}));
    const auto directory = *kasumi::find_row(snapshot, "docs");
    EXPECT_FALSE(kasumi::state_storage::save_state(
        database_path,
        {.tree = snapshot,
         .height = 1,
         .commit_id = std::string(64, 'a'),
         .pending_materializations = {directory}}));
}

TEST(StateStorageDatabaseTest, StateAndPendingRowsCommitAtomically) {
    auto workspace = kasumi::test::make_temp_workspace("pending-atomic");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    const auto original = make_snapshot("a.txt", "a", 1);
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = original,
         .height = 1,
         .commit_id = std::string(64, 'a'),
         .pending_materializations = {*kasumi::find_row(original, "a.txt")}}));
    execute_sql(database_path,
                "CREATE TRIGGER fail_pending_insert BEFORE INSERT ON "
                "pending_materializations BEGIN SELECT RAISE(ABORT, "
                "'injected pending write failure'); END");

    const auto replacement = make_snapshot("a.txt", "replacement", 2);
    EXPECT_FALSE(kasumi::state_storage::save_state(
        database_path,
        {.tree = replacement,
         .height = 2,
         .commit_id = std::string(64, 'b'),
         .pending_materializations = {
             *kasumi::find_row(replacement, "a.txt")}}));
    const auto loaded = kasumi::state_storage::load_state(database_path);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_EQ((*loaded)->tree, original);
    ASSERT_EQ((*loaded)->pending_materializations.size(), 1U);
    EXPECT_EQ((*loaded)->pending_materializations.front(),
              *kasumi::find_row(original, "a.txt"));
}

TEST(StateStorageDatabaseTest, MissingCanonicalPendingTableFailsClosed) {
    auto [workspace, database_path] = make_db("pending-schema");
    execute_sql(database_path, "DROP TABLE pending_materializations");
    EXPECT_FALSE(kasumi::state_storage::initialize(database_path));
    EXPECT_FALSE(kasumi::state_storage::load_state(database_path).has_value());
}

TEST(StateStorageDatabaseTest, FileCacheDeltaIsNonAuthoritative) {
    auto [workspace, database_path] = make_db("persistence-file-cache");
    const auto snapshot = make_snapshot("a.txt", "a", 10);
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = snapshot, .height = 1, .commit_id = std::string(64, 'a')}));
    const auto row = kasumi::state_storage::FileCacheRow{
        .path = "a.txt",
        .hash = kasumi::hasher::hash_string("a"),
        .size = 1,
        .mtime_nanoseconds = 1000,
        .volume = 1,
        .file_low = 2,
        .file_high = 4};
    ASSERT_TRUE(kasumi::state_storage::save_file_cache_delta(
        database_path,
        std::span<const kasumi::state_storage::FileCacheRow>{&row, 1}));
    const auto loaded_cache =
        kasumi::state_storage::load_file_cache(database_path);
    ASSERT_TRUE(loaded_cache.has_value());
    ASSERT_EQ(loaded_cache->size(), 1U);
    EXPECT_EQ(loaded_cache->front().file_high, 4U);
    ASSERT_TRUE(kasumi::state_storage::save_file_cache_delta(
        database_path, std::span<const kasumi::state_storage::FileCacheRow>{}));
    const auto loaded_state = kasumi::state_storage::load_state(database_path);
    ASSERT_TRUE(loaded_state.has_value() && *loaded_state);
    ASSERT_EQ((*loaded_state)->tree.rows.size(), snapshot.rows.size());
    EXPECT_NE(kasumi::find_row((*loaded_state)->tree, "a.txt"), nullptr);
}

TEST(StateStorageDatabaseTest, PersistsAndPreservesAcceptedEpoch) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-accepted-epoch");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    const auto snapshot = make_snapshot("a.txt", "a", 10);
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    ASSERT_TRUE(
        kasumi::state_storage::save_state(database_path,
                                          {.tree = snapshot,
                                           .height = 0,
                                           .commit_id = std::string(64, 'a'),
                                           .epoch_id = std::string(64, 'e')}));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = snapshot, .height = 1, .commit_id = std::string(64, 'b')}));

    const auto loaded = kasumi::state_storage::load_state(database_path);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_EQ((*loaded)->height, 1U);
    EXPECT_EQ((*loaded)->epoch_id, std::string(64, 'e'));
    EXPECT_EQ((*loaded)->epoch_sequence, 0U);
}

TEST(StateStorageDatabaseTest, EpochReferenceRoundTripsWithNonZeroSequence) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-epoch-sequence");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    const auto snapshot = make_snapshot("a.txt", "a", 11);
    const auto epoch_id = std::string(64, 'e');

    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    ASSERT_TRUE(
        kasumi::state_storage::save_state(database_path,
                                          {.tree = snapshot,
                                           .height = 7,
                                           .commit_id = std::string(64, 'a'),
                                           .epoch_id = epoch_id,
                                           .epoch_sequence = 7}));

    const auto loaded = kasumi::state_storage::load_state(database_path);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_EQ((*loaded)->epoch_id, epoch_id);
    EXPECT_EQ((*loaded)->epoch_sequence, 7U);
}

TEST(StateStorageDatabaseTest, RejectsEpochSequenceWithoutEpochId) {
    auto [workspace, database_path] = make_db("persistence-epoch-invariant");

    EXPECT_FALSE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("a.txt", "a", 12),
         .height = 1,
         .commit_id = std::string(64, 'a'),
         .epoch_sequence = 1}));
}

TEST(StateStorageDatabaseTest, MalformedFileCacheEntryIsDiscarded) {
    auto [workspace, database_path] = make_db("persistence-cache-corrupt");
    execute_sql(database_path,
                "INSERT INTO file_cache VALUES ('bad', 'not-a-hash', 1, 99, "
                "'0', '0', '0', '0')");
    const auto loaded = kasumi::state_storage::load_file_cache(database_path);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_TRUE(loaded->empty());
}

TEST(StateStorageDatabaseTest, RoundTripsSnapshotAndGeneration) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-round-trip");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    const auto expected = make_snapshot("docs/readme.txt", "persistence", 100);

    ASSERT_TRUE(kasumi::valid_snapshot(expected, false));
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    const kasumi::state_storage::StoredState state{
        .tree = expected, .height = 7, .commit_id = std::string(64, 'a')};
    ASSERT_TRUE(kasumi::state_storage::save_state(database_path, state));

    const auto loaded = kasumi::state_storage::load_state(database_path);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_EQ((*loaded)->tree.rows.size(), expected.rows.size());
    for (std::size_t index = 0; index < expected.rows.size(); ++index) {
        EXPECT_EQ((*loaded)->tree.rows[index].path, expected.rows[index].path);
        EXPECT_EQ((*loaded)->tree.rows[index].hash, expected.rows[index].hash);
        EXPECT_EQ((*loaded)->tree.rows[index].size, expected.rows[index].size);
        EXPECT_EQ((*loaded)->tree.rows[index].mtime,
                  expected.rows[index].mtime);
        EXPECT_EQ((*loaded)->tree.rows[index].is_directory,
                  expected.rows[index].is_directory);
    }
    EXPECT_EQ((*loaded)->height, std::uint64_t{7});
    EXPECT_EQ((*loaded)->commit_id, std::string(64, 'a'));
}

TEST(StateStorageDatabaseTest, StateWithoutKnownCiphertextIdRemainsValid) {
    auto [workspace, database_path] = make_db("persistence-unknown-ciphertext");

    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("unknown.txt", "unknown", 110),
         .height = 1,
         .commit_id = std::string(64, 'a')}));

    const auto loaded = kasumi::state_storage::load_state(database_path);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_TRUE((*loaded)->ciphertext_id.empty());
}

TEST(StateStorageDatabaseTest, RejectsInvalidCiphertextId) {
    auto [workspace, database_path] = make_db("persistence-invalid-ciphertext");

    EXPECT_FALSE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("invalid.txt", "invalid", 111),
         .height = 1,
         .commit_id = std::string(64, 'a'),
         .ciphertext_id = "not-a-valid-hash"}));

    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("valid.txt", "valid", 112),
         .height = 1,
         .commit_id = std::string(64, 'a'),
         .ciphertext_id = std::string(64, 'b')}));
    execute_sql(database_path,
                "UPDATE metadata SET value = 'not-a-valid-hash' "
                "WHERE key = 'ciphertext_id'");
    EXPECT_FALSE(kasumi::state_storage::load_state(database_path).has_value());
}

TEST(StateStorageDatabaseTest, ReplacesSnapshotAndGenerationTogether) {
    auto workspace = kasumi::test::make_temp_workspace("persistence-replace");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    const auto first = make_snapshot("docs/old.txt", "old", 200);
    const auto second = make_snapshot("docs/new.txt", "new", 300);

    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = first, .height = 2, .commit_id = std::string(64, 'a')}));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = second, .height = 3, .commit_id = std::string(64, 'b')}));

    const auto loaded = kasumi::state_storage::load_state(database_path);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    ASSERT_EQ((*loaded)->tree.rows.size(), second.rows.size());
    for (std::size_t index = 0; index < second.rows.size(); ++index) {
        EXPECT_EQ((*loaded)->tree.rows[index].path, second.rows[index].path);
        EXPECT_EQ((*loaded)->tree.rows[index].hash, second.rows[index].hash);
        EXPECT_EQ((*loaded)->tree.rows[index].size, second.rows[index].size);
        EXPECT_EQ((*loaded)->tree.rows[index].mtime, second.rows[index].mtime);
        EXPECT_EQ((*loaded)->tree.rows[index].is_directory,
                  second.rows[index].is_directory);
    }
    EXPECT_EQ(kasumi::find_row((*loaded)->tree, "docs/old.txt"), nullptr);
    ASSERT_NE(kasumi::find_row((*loaded)->tree, "docs/new.txt"), nullptr);
    EXPECT_EQ((*loaded)->height, std::uint64_t{3});
    EXPECT_EQ((*loaded)->commit_id, std::string(64, 'b'));
}

TEST(StateStorageDatabaseTest, RejectsUnsupportedSchemaVersion) {
    auto workspace = kasumi::test::make_temp_workspace("persistence-version");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    const auto expected = make_snapshot("docs/version.txt", "version", 400);

    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = expected, .height = 4, .commit_id = std::string(64, 'a')}));
    execute_sql(database_path, "PRAGMA user_version = 99");

    EXPECT_FALSE(kasumi::state_storage::initialize(database_path));
    const auto loaded = kasumi::state_storage::load_state(database_path);
    ASSERT_FALSE(loaded.has_value());
}

TEST(StateStorageDatabaseTest, RejectsMalformedSchema) {
    auto workspace = kasumi::test::make_temp_workspace("persistence-schema");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    execute_sql(database_path,
                "CREATE TABLE nodes (path TEXT PRIMARY KEY)",
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);

    EXPECT_FALSE(kasumi::state_storage::initialize(database_path));
    EXPECT_EQ(query_text(database_path,
                         "SELECT name FROM sqlite_master WHERE type = 'table' "
                         "ORDER BY name"),
              std::vector<std::string>{"nodes"});
}

TEST(StateStorageDatabaseTest,
     RejectsExistingUnversionedDatabaseAndPreservesItsTables) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-unversioned-existing");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    execute_sql(database_path,
                "CREATE TABLE prior_state (value TEXT); "
                "INSERT INTO prior_state VALUES ('keep');",
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);

    EXPECT_FALSE(kasumi::state_storage::initialize(database_path));
    EXPECT_EQ(query_text(database_path, "SELECT value FROM prior_state"),
              std::vector<std::string>{"keep"});
    EXPECT_TRUE(query_text(database_path,
                           "SELECT name FROM sqlite_master WHERE name='nodes'")
                    .empty());
    EXPECT_EQ(query_text(database_path, "PRAGMA user_version"),
              std::vector<std::string>{"0"});
}

TEST(StateStorageDatabaseTest,
     RejectsExistingEmptyDatabaseInsteadOfInitializingIt) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-empty-existing");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    execute_sql(
        database_path, "SELECT 1;", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);

    EXPECT_FALSE(kasumi::state_storage::initialize(database_path));
    EXPECT_TRUE(query_text(database_path,
                           "SELECT name FROM sqlite_master WHERE name='nodes'")
                    .empty());
    EXPECT_EQ(query_text(database_path, "PRAGMA user_version"),
              std::vector<std::string>{"0"});
}

TEST(StateStorageDatabaseTest, ValidationRequiresCurrentExistingSchema) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-validate-current");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    EXPECT_FALSE(kasumi::state_storage::validate(database_path));
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    EXPECT_TRUE(kasumi::state_storage::validate(database_path));
    execute_sql(database_path, "PRAGMA user_version = 99");
    EXPECT_FALSE(kasumi::state_storage::validate(database_path));
    EXPECT_EQ(query_text(database_path, "PRAGMA user_version"),
              std::vector<std::string>{"99"});
}

TEST(StateStorageDatabaseTest, ValidationRecoversSchemaFromUncheckpointedWal) {
    auto [workspace, database] = make_db("persistence-recover-wal");
    execute_sql(database, "PRAGMA user_version = 0");
    auto writer = open_database(database, SQLITE_OPEN_READWRITE);
    ASSERT_EQ(
        sqlite3_exec(
            writer.get(), "PRAGMA user_version = 2", nullptr, nullptr, nullptr),
        SQLITE_OK);

    const auto recovered = database.parent_path() / "recovered.sqlite";
    ASSERT_TRUE(std::filesystem::copy_file(database, recovered));
    const auto wal = [](const auto& path) {
        return kasumi::platform::path::temporary_sibling_path(path, "", "-wal");
    };
    ASSERT_TRUE(std::filesystem::copy_file(wal(database), wal(recovered)));
    EXPECT_TRUE(kasumi::state_storage::validate(recovered));
    EXPECT_EQ(query_text(recovered, "PRAGMA user_version"),
              std::vector<std::string>{"2"});
}

TEST(StateStorageDatabaseTest, RejectsRedirectedDatabaseAndWal) {
    auto [workspace, database] = make_db("persistence-redirected-input");
    const auto alias = database.parent_path() / "alias.sqlite";
    std::error_code error;
    std::filesystem::create_symlink(database, alias, error);
    if (error) {
        GTEST_SKIP() << error.message();
    }
    EXPECT_FALSE(kasumi::state_storage::validate(alias));
    EXPECT_FALSE(kasumi::state_storage::load_state(alias));
    EXPECT_FALSE(kasumi::state_storage::save_file_cache_delta(alias, {}));
    EXPECT_TRUE(std::filesystem::remove(alias));

    const auto wal =
        kasumi::platform::path::temporary_sibling_path(database, "", "-wal");
    const auto untouched = database.parent_path() / "untouched";
    kasumi::test::write_text(untouched, "original");
    std::filesystem::create_symlink(untouched, wal);
    EXPECT_FALSE(kasumi::state_storage::initialize(database));
    EXPECT_FALSE(kasumi::state_storage::validate(database));
    EXPECT_FALSE(kasumi::state_storage::load_file_cache(database));
    EXPECT_EQ(kasumi::test::read_text(untouched), "original");
    EXPECT_TRUE(std::filesystem::remove(wal));
}

TEST(StateStorageDatabaseTest, CorruptHashReturnsControlledError) {
    auto [workspace, database_path] = make_db("persistence-corrupt-hash");
    execute_sql(database_path,
                "INSERT INTO nodes (path, hash, size, mtime, is_dir) VALUES "
                "('docs/bad.txt', 'not-a-hash', 3, 0, 0); "
                "INSERT INTO metadata (key, value) VALUES ('generation', '1'), "
                "('commit_id', '" +
                    std::string(64, 'a') + "')");
    const auto result = kasumi::state_storage::load_state(database_path);
    ASSERT_FALSE(result.has_value());
    EXPECT_FALSE(result.error().empty());
}

TEST(StateStorageDatabaseTest, NegativeIsDirectoryReturnsControlledError) {
    auto [workspace, database_path] = make_db("persistence-negative-is-dir");
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("docs/state.txt", "state", 500),
         .height = 1,
         .commit_id = std::string(64, 'a')}));
    execute_sql(database_path,
                "UPDATE nodes SET is_dir = -1 "
                "WHERE path = 'docs/state.txt'");
    const auto result = kasumi::state_storage::load_state(database_path);
    EXPECT_FALSE(result.has_value());
}

TEST(StateStorageDatabaseTest, OutOfRangeIsDirectoryReturnsControlledError) {
    auto [workspace, database_path] = make_db("persistence-large-is-dir");
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("docs/state.txt", "state", 501),
         .height = 1,
         .commit_id = std::string(64, 'a')}));
    execute_sql(database_path,
                "UPDATE nodes SET is_dir = 2 "
                "WHERE path = 'docs/state.txt'");
    const auto result = kasumi::state_storage::load_state(database_path);
    EXPECT_FALSE(result.has_value());
}

TEST(StateStorageDatabaseTest, NegativeSizeReturnsControlledError) {
    auto [workspace, database_path] = make_db("persistence-negative-size");
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("docs/state.txt", "state", 502),
         .height = 1,
         .commit_id = std::string(64, 'a')}));
    execute_sql(database_path,
                "UPDATE nodes SET size = -1 "
                "WHERE path = 'docs/state.txt'");
    const auto result = kasumi::state_storage::load_state(database_path);
    EXPECT_FALSE(result.has_value());
}

TEST(StateStorageDatabaseTest, RejectsInvalidStoredStateBeforeWriting) {
    auto [workspace, database_path] = make_db("persistence-invalid-state");
    const auto tree = make_snapshot("docs/state.txt", "state", 600);

    EXPECT_FALSE(kasumi::state_storage::save_state(
        database_path, {.tree = tree, .height = 0, .commit_id = "bad"}));
    EXPECT_FALSE(kasumi::state_storage::save_state(
        database_path,
        {.tree = tree,
         .height = std::numeric_limits<std::uint64_t>::max(),
         .commit_id = std::string(64, 'a')}));
    const auto loaded = kasumi::state_storage::load_state(database_path);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_FALSE(*loaded);
}

TEST(StateStorageDatabaseTest, SaveStateCanonicalizesMetadata) {
    auto [workspace, database_path] = make_db("persistence-metadata-canonical");
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("docs/old.txt", "old", 700),
         .height = 1,
         .commit_id = std::string(64, 'a')}));
    execute_sql(database_path,
                "INSERT INTO metadata (key, value) "
                "VALUES ('unknown_key', 'unrecognized')");

    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("docs/new.txt", "new", 701),
         .height = 2,
         .commit_id = std::string(64, 'b')}));
    const auto loaded = kasumi::state_storage::load_state(database_path);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_EQ((*loaded)->height, 2U);
    EXPECT_EQ((*loaded)->commit_id, std::string(64, 'b'));
    EXPECT_NE(kasumi::find_row((*loaded)->tree, "docs/new.txt"), nullptr);

    EXPECT_EQ(
        query_text(database_path, "SELECT key FROM metadata ORDER BY key"),
        (std::vector<std::string>{"commit_id", "generation"}));
}

TEST(StateStorageDatabaseTest, SaveStateFailureKeepsPreviousTuple) {
    auto [workspace, database_path] = make_db("persistence-metadata-rollback");
    const auto previous = kasumi::state_storage::StoredState{
        .tree = make_snapshot("docs/old.txt", "old", 800),
        .height = 3,
        .commit_id = std::string(64, 'a')};
    ASSERT_TRUE(kasumi::state_storage::save_state(database_path, previous));
    execute_sql(database_path,
                "CREATE TRIGGER reject_commit BEFORE INSERT ON metadata "
                "WHEN NEW.key = 'commit_id' BEGIN SELECT RAISE(ABORT, "
                "'test'); END");

    EXPECT_FALSE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("docs/new.txt", "new", 801),
         .height = 4,
         .commit_id = std::string(64, 'b')}));
    const auto loaded = kasumi::state_storage::load_state(database_path);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_EQ((*loaded)->height, previous.height);
    EXPECT_EQ((*loaded)->commit_id, previous.commit_id);
    EXPECT_NE(kasumi::find_row((*loaded)->tree, "docs/old.txt"), nullptr);
    EXPECT_EQ(kasumi::find_row((*loaded)->tree, "docs/new.txt"), nullptr);
}

TEST(StateStorageDatabaseTest, RejectsVersionZeroWithExistingTables) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-version-zero-tables");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    execute_sql(database_path,
                "CREATE TABLE nodes (path TEXT PRIMARY KEY); "
                "CREATE TABLE metadata "
                "(key TEXT PRIMARY KEY, value TEXT)",
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    EXPECT_FALSE(kasumi::state_storage::initialize(database_path));
    EXPECT_FALSE(kasumi::state_storage::load_state(database_path).has_value());
}

TEST(StateStorageDatabaseTest, RejectsPreReleaseSchemaVersion) {
    auto [workspace, database_path] = make_db("persistence-version-prerelease");
    execute_sql(database_path, "PRAGMA user_version = 5");
    EXPECT_FALSE(kasumi::state_storage::initialize(database_path));
    EXPECT_FALSE(kasumi::state_storage::load_state(database_path).has_value());
}

TEST(StateStorageDatabaseTest, RejectsUnknownFutureVersion) {
    auto [workspace, database_path] = make_db("persistence-version-future");
    execute_sql(database_path, "PRAGMA user_version = 99");
    EXPECT_FALSE(kasumi::state_storage::initialize(database_path));
    EXPECT_FALSE(kasumi::state_storage::load_state(database_path).has_value());
}

TEST(StateStorageDatabaseTest, RejectsEmptyMetadataWithNodes) {
    auto [workspace, database_path] = make_db("persistence-empty-metadata");
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("docs/state.txt", "state", 900),
         .height = 1,
         .commit_id = std::string(64, 'a')}));
    execute_sql(database_path, "DELETE FROM metadata");
    EXPECT_FALSE(kasumi::state_storage::load_state(database_path).has_value());
}

TEST(StateStorageDatabaseTest, RejectsMissingGeneration) {
    auto [workspace, database_path] = make_db("persistence-missing-generation");
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("docs/state.txt", "state", 901),
         .height = 1,
         .commit_id = std::string(64, 'a')}));
    execute_sql(database_path, "DELETE FROM metadata WHERE key = 'generation'");
    EXPECT_FALSE(kasumi::state_storage::load_state(database_path).has_value());
}

TEST(StateStorageDatabaseTest, RejectsMissingCommitId) {
    auto [workspace, database_path] = make_db("persistence-missing-commit");
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("docs/state.txt", "state", 902),
         .height = 1,
         .commit_id = std::string(64, 'a')}));
    execute_sql(database_path, "DELETE FROM metadata WHERE key = 'commit_id'");
    EXPECT_FALSE(kasumi::state_storage::load_state(database_path).has_value());
}

TEST(StateStorageDatabaseTest, RejectsNonCanonicalGeneration) {
    auto [workspace, database_path] = make_db("persistence-generation-format");
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("docs/state.txt", "state", 903),
         .height = 7,
         .commit_id = std::string(64, 'a')}));
    const std::array<std::string, 4> invalid_values{"", "+7", "007", " 7"};
    for (const auto& value : invalid_values) {
        update_generation(database_path, value);
        EXPECT_FALSE(
            kasumi::state_storage::load_state(database_path).has_value())
            << value;
        update_generation(database_path, "7");
    }
}

TEST(StateStorageDatabaseTest, RejectsMaximumGeneration) {
    auto [workspace, database_path] = make_db("persistence-generation-maximum");
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("docs/state.txt", "state", 904),
         .height = 1,
         .commit_id = std::string(64, 'a')}));
    execute_sql(database_path,
                "UPDATE metadata SET value = '18446744073709551615' "
                "WHERE key = 'generation'");
    EXPECT_FALSE(kasumi::state_storage::load_state(database_path).has_value());
}

TEST(StateStorageDatabaseTest, RejectsEmptyCommitId) {
    auto [workspace, database_path] = make_db("persistence-empty-commit");
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("docs/state.txt", "state", 905),
         .height = 1,
         .commit_id = std::string(64, 'a')}));
    execute_sql(database_path,
                "UPDATE metadata SET value = '' WHERE key = 'commit_id'");
    EXPECT_FALSE(kasumi::state_storage::load_state(database_path).has_value());
}

TEST(StateStorageDatabaseTest, RejectsMalformedCommitId) {
    auto [workspace, database_path] = make_db("persistence-malformed-commit");
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("docs/state.txt", "state", 906),
         .height = 1,
         .commit_id = std::string(64, 'a')}));
    execute_sql(database_path,
                "UPDATE metadata SET value = 'bad' WHERE key = 'commit_id'");
    EXPECT_FALSE(kasumi::state_storage::load_state(database_path).has_value());
}

TEST(StateStorageDatabaseTest, RejectsUnknownMetadataOnLoad) {
    auto [workspace, database_path] = make_db("persistence-unknown-metadata");
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("docs/state.txt", "state", 907),
         .height = 1,
         .commit_id = std::string(64, 'a')}));
    execute_sql(database_path,
                "INSERT INTO metadata (key, value) VALUES ('unknown', 'x')");
    EXPECT_FALSE(kasumi::state_storage::load_state(database_path).has_value());
}

TEST(StateStorageDatabaseTest, InitializesWithWalJournalMode) {
    auto [workspace, database_path] = make_db("persistence-wal-journal-mode");

    // An independent connection verifies the persistent database header setting
    const auto journal_mode = query_text(database_path, "PRAGMA journal_mode");
    ASSERT_EQ(journal_mode.size(), 1U);
    EXPECT_EQ(journal_mode[0], "wal");
}

TEST(StateStorageDatabaseTest, SaveWaitsForContendingWriter) {
    using namespace std::chrono_literals;
    auto [workspace, path] = make_db("persistence-contending-writer");
    auto writer = open_database(path, SQLITE_OPEN_READWRITE);
    auto lock = kasumi::sqlite::begin(writer.get());
    ASSERT_TRUE(lock) << lock.error();
    const auto tree = make_snapshot("docs/file", "data", 4);
    std::promise<void> started;
    auto ready = started.get_future();
    auto pending = std::async(std::launch::async, [&] {
        started.set_value();
        return kasumi::state_storage::save_state(
            path,
            {.tree = tree, .height = 1, .commit_id = std::string(64, 'a')});
    });
    ready.wait();
    EXPECT_EQ(pending.wait_for(100ms), std::future_status::timeout);
    ASSERT_TRUE(kasumi::sqlite::commit(*lock));
    ASSERT_TRUE(pending.get());
    const auto saved = kasumi::state_storage::load_state(path);
    ASSERT_TRUE(saved && *saved);
    EXPECT_EQ((*saved)->tree, tree);
}

TEST(StateStorageDatabaseTest, SaveRequiresWalAndInitializeRestoresIt) {
    auto [workspace, path] = make_db("persistence-require-wal");
    execute_sql(path, "PRAGMA journal_mode=DELETE");
    const kasumi::state_storage::StoredState state{
        .tree = make_snapshot("docs/file", "data", 4),
        .height = 1,
        .commit_id = std::string(64, 'a')};

    EXPECT_FALSE(kasumi::state_storage::save_state(path, state));
    EXPECT_EQ(query_text(path, "PRAGMA journal_mode"),
              std::vector<std::string>{"delete"});
    ASSERT_TRUE(kasumi::state_storage::initialize(path));
    EXPECT_EQ(query_text(path, "PRAGMA journal_mode"),
              std::vector<std::string>{"wal"});
    EXPECT_TRUE(kasumi::state_storage::save_state(path, state));
}

TEST(StateStorageDatabaseTest, NewReadWriteConnectionAppliesSynchronousNormal) {
    auto [workspace, database_path] =
        make_db("persistence-connection-synchronous");

    // Raw unconfigured SQLite connection defaults to synchronous=FULL (2)
    {
        auto raw_conn = open_database(database_path, SQLITE_OPEN_READWRITE);
        sqlite3_stmt* stmt = nullptr;
        ASSERT_EQ(sqlite3_prepare_v2(
                      raw_conn.get(), "PRAGMA synchronous", -1, &stmt, nullptr),
                  SQLITE_OK);
        ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
        const auto raw_sync = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        EXPECT_EQ(raw_sync, 2);
    }

    // A newly opened connection via StateStorage policy helper applies
    // synchronous=NORMAL (1)
    auto state_conn =
        kasumi::state_storage::detail::open_state_database_readwrite(
            database_path);
    ASSERT_TRUE(state_conn.has_value());
    sqlite3_stmt* stmt = nullptr;
    ASSERT_EQ(sqlite3_prepare_v2(
                  state_conn->get(), "PRAGMA synchronous", -1, &stmt, nullptr),
              SQLITE_OK);
    ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    const auto configured_sync = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    EXPECT_EQ(configured_sync, 1);
}

TEST(StateStorageDatabaseTest, ReadOnlyConnectionDoesNotExecuteWritePragmas) {
    auto [workspace, database_path] =
        make_db("persistence-connection-readonly");

    auto readonly_conn =
        kasumi::state_storage::detail::open_state_database_readonly(
            database_path);
    ASSERT_TRUE(readonly_conn.has_value());

    sqlite3_stmt* stmt = nullptr;
    ASSERT_EQ(sqlite3_prepare_v2(
                  readonly_conn->get(), "SELECT 1", -1, &stmt, nullptr),
              SQLITE_OK);
    ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    EXPECT_EQ(sqlite3_column_int(stmt, 0), 1);
    sqlite3_finalize(stmt);

    // Read-only connection rejects schema modification
    ASSERT_NE(sqlite3_exec(readonly_conn->get(),
                           "CREATE TABLE test_write (x INT)",
                           nullptr,
                           nullptr,
                           nullptr),
              SQLITE_OK);
}

TEST(StateStorageDatabaseTest, UnicodePathRoundTrip) {
    auto workspace = kasumi::test::make_temp_workspace("persistence-unicode");
    const auto unicode_dir =
        kasumi::test::workspace_root(workspace) /
        kasumi::platform::path::from_utf8("usuário-João-日本-☁/高松灯🌸");
    std::filesystem::create_directories(unicode_dir);
    const auto database_path =
        unicode_dir / kasumi::platform::path::from_utf8("千早愛音💝.db");

    // 1. Initialize StateStorage in a Unicode directory (READWRITE + CREATE)
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));

    // 2. Save state via StateStorage READWRITE connection
    constexpr std::string_view logical_path = "docs/𝑬𝒎𝒊𝒍𝒊𝒂-𓆩🌸𓆪.txt";
    const auto snapshot = make_snapshot(logical_path, "conteúdo 日本", 100);
    const std::string commit_hash(64, 'c');
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = snapshot, .height = 1, .commit_id = commit_hash}));

    // 3. Load state via StateStorage READONLY connection
    const auto loaded = kasumi::state_storage::load_state(database_path);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_EQ((*loaded)->commit_id, commit_hash);
    ASSERT_EQ((*loaded)->tree.rows.size(), snapshot.rows.size());
    EXPECT_NE(kasumi::find_row((*loaded)->tree, logical_path), nullptr);
    EXPECT_EQ((*loaded)->tree, snapshot);

    // 4. Query nodes and metadata tables directly via READONLY helper
    const auto node_rows =
        query_text(database_path, "SELECT path FROM nodes ORDER BY path");
    ASSERT_EQ(node_rows.size(), snapshot.rows.size());
    EXPECT_NE(std::find(node_rows.begin(), node_rows.end(), logical_path),
              node_rows.end());

    const auto commit_rows = query_text(
        database_path, "SELECT value FROM metadata WHERE key='commit_id'");
    ASSERT_EQ(commit_rows.size(), 1U);
    EXPECT_EQ(commit_rows[0], commit_hash);
}

TEST(StateStorageDatabaseTest, UnifiedMetadataCachePersistenceFullFidelity) {
    auto [workspace, database_path] = make_db("persistence-unified-metadata");

    const auto row = kasumi::state_storage::FileCacheRow{
        .path = "photos/holiday.jpg",
        .hash = kasumi::hasher::hash_string("blake3_payload_sample"),
        .size = 1048576ULL,
        .mtime_nanoseconds = -123456789LL,
        .volume = 0xdeadbeefcafebabeULL,
        .file_low = 0x0123456789abcdefULL,
        .file_high = 0xfedcba9876543210ULL};

    ASSERT_TRUE(kasumi::state_storage::save_file_cache_delta(
        database_path,
        std::span<const kasumi::state_storage::FileCacheRow>{&row, 1}));

    const auto loaded = kasumi::state_storage::load_file_cache(database_path);
    ASSERT_TRUE(loaded.has_value());
    ASSERT_EQ(loaded->size(), 1U);
    const auto& entry = loaded->front();
    EXPECT_EQ(entry.path, "photos/holiday.jpg");
    EXPECT_EQ(entry.hash, row.hash);
    EXPECT_EQ(entry.size, 1048576ULL);
    EXPECT_EQ(entry.mtime_nanoseconds, -123456789LL);
    EXPECT_EQ(entry.volume, 0xdeadbeefcafebabeULL);
    EXPECT_EQ(entry.file_low, 0x0123456789abcdefULL);
    EXPECT_EQ(entry.file_high, 0xfedcba9876543210ULL);
}

TEST(StateStorageDatabaseTest, ExtremeTimestampsPreservedBitwise) {
    auto [workspace, database_path] = make_db("persistence-extreme-timestamps");

    const std::vector<kasumi::state_storage::FileCacheRow> rows{
        kasumi::state_storage::FileCacheRow{
            .path = "max.bin",
            .hash = kasumi::hasher::hash_string("max"),
            .size = 10,
            .mtime_nanoseconds = std::numeric_limits<std::int64_t>::max(),
            .volume = 1,
            .file_low = 2,
            .file_high = 3},
        kasumi::state_storage::FileCacheRow{
            .path = "min.bin",
            .hash = kasumi::hasher::hash_string("min"),
            .size = 20,
            .mtime_nanoseconds = std::numeric_limits<std::int64_t>::min(),
            .volume = 4,
            .file_low = 5,
            .file_high = 6},
        kasumi::state_storage::FileCacheRow{
            .path = "zero.bin",
            .hash = kasumi::hasher::hash_string("zero"),
            .size = 30,
            .mtime_nanoseconds = 0,
            .volume = 7,
            .file_low = 8,
            .file_high = 9}};

    ASSERT_TRUE(
        kasumi::state_storage::save_file_cache_delta(database_path, rows));
    const auto loaded = kasumi::state_storage::load_file_cache(database_path);
    ASSERT_TRUE(loaded.has_value());
    ASSERT_EQ(loaded->size(), 3U);
    EXPECT_EQ(loaded->at(0).mtime_nanoseconds,
              std::numeric_limits<std::int64_t>::max());
    EXPECT_EQ(loaded->at(1).mtime_nanoseconds,
              std::numeric_limits<std::int64_t>::min());
    EXPECT_EQ(loaded->at(2).mtime_nanoseconds, 0);
}

TEST(StateStorageDatabaseTest,
     LegacyFingerprintsArePrunedAndFutureKindIsPreserved) {
    auto [workspace, database_path] =
        make_db("persistence-unknown-fingerprints");

    const std::string dummy_hash(64, '0');
    execute_sql(database_path,
                "INSERT INTO file_cache (path, hash, size, fingerprint_kind, "
                "fp0, fp1, fp2, fp3) "
                "VALUES ('platform_kind_one.txt', '" +
                    dummy_hash +
                    "', 100, 1, "
                    "'0000000000000001', '0000000000000002', "
                    "'0000000000000003', '0000000000000004')");
    execute_sql(database_path,
                "INSERT INTO file_cache (path, hash, size, fingerprint_kind, "
                "fp0, fp1, fp2, fp3) "
                "VALUES ('platform_kind_two.txt', '" +
                    dummy_hash +
                    "', 200, 2, "
                    "'0000000000000005', '0000000000000006', "
                    "'0000000000000007', '0000000000000008')");

    execute_sql(database_path,
                "INSERT INTO file_cache VALUES ('future.txt', 'hash', 1, 99, "
                "'0', '0', '0', '0')");

    execute_sql(database_path,
                "INSERT INTO file_cache (path, hash, size, fingerprint_kind, "
                "fp0, fp1, fp2, fp3) "
                "VALUES ('unified.txt', '" +
                    dummy_hash +
                    "', 300, 3, "
                    "'0000000000000009', '000000000000000a', "
                    "'000000000000000b', '000000000000000c')");

    const auto loaded = kasumi::state_storage::load_file_cache(database_path);
    ASSERT_TRUE(loaded.has_value());
    ASSERT_EQ(loaded->size(), 1U);
    EXPECT_EQ(loaded->front().path, "unified.txt");

    const auto new_row = kasumi::state_storage::FileCacheRow{
        .path = "unified.txt",
        .hash = kasumi::hasher::hash_string("unified"),
        .size = 300,
        .mtime_nanoseconds = 50,
        .volume = 9,
        .file_low = 10,
        .file_high = 11};

    ASSERT_TRUE(kasumi::state_storage::save_file_cache_delta(
        database_path,
        std::span<const kasumi::state_storage::FileCacheRow>{&new_row, 1}));

    const auto remaining_unknown =
        query_text(database_path,
                   "SELECT path FROM file_cache WHERE fingerprint_kind != 3 "
                   "ORDER BY path");
    EXPECT_EQ(remaining_unknown, (std::vector<std::string>{"future.txt"}));
}

TEST(StateStorageDatabaseTest, CorruptedCacheEntriesIgnoredFailClosed) {
    auto [workspace, database_path] = make_db("persistence-corrupted-cache");

    const std::string dummy_hash(64, 'a');
    execute_sql(database_path,
                "INSERT INTO file_cache (path, hash, size, fingerprint_kind, "
                "fp0, fp1, fp2, fp3) "
                "VALUES ('bad_hex.txt', '" +
                    dummy_hash + "', 10, 3, 'NOT_HEX_VALUE!!', '0', '0', '0')");
    execute_sql(database_path,
                "INSERT INTO file_cache (path, hash, size, fingerprint_kind, "
                "fp0, fp1, fp2, fp3) "
                "VALUES ('bad_hash.txt', 'short_hash', 10, 3, "
                "'0000000000000001', '0', '0', '0')");
    execute_sql(database_path,
                "INSERT INTO file_cache (path, hash, size, fingerprint_kind, "
                "fp0, fp1, fp2, fp3) "
                "VALUES ('neg_size.txt', '" +
                    dummy_hash +
                    "', -5, 3, '0000000000000001', '0', '0', '0')");

    const auto loaded = kasumi::state_storage::load_file_cache(database_path);
    ASSERT_TRUE(loaded.has_value());
    EXPECT_TRUE(loaded->empty());
}

TEST(StateStorageDatabaseTest, UnchangedCacheDeltaAvoidsRedundantWrites) {
    auto [workspace, database_path] = make_db("persistence-unchanged-delta");

    const auto row = kasumi::state_storage::FileCacheRow{
        .path = "steady.txt",
        .hash = kasumi::hasher::hash_string("steady"),
        .size = 100,
        .mtime_nanoseconds = 5000,
        .volume = 1,
        .file_low = 2,
        .file_high = 3};

    ASSERT_TRUE(kasumi::state_storage::save_file_cache_delta(
        database_path,
        std::span<const kasumi::state_storage::FileCacheRow>{&row, 1}));

    ASSERT_TRUE(kasumi::state_storage::save_file_cache_delta(
        database_path,
        std::span<const kasumi::state_storage::FileCacheRow>{&row, 1}));
}

TEST(StateStorageDatabaseTest, ObsoleteEntriesRemovedByDelta) {
    auto [workspace, database_path] = make_db("persistence-obsolete-entries");

    const std::vector<kasumi::state_storage::FileCacheRow> initial{
        kasumi::state_storage::FileCacheRow{
            .path = "keep.txt",
            .hash = kasumi::hasher::hash_string("keep"),
            .size = 10,
            .mtime_nanoseconds = 10,
            .volume = 1,
            .file_low = 1,
            .file_high = 1},
        kasumi::state_storage::FileCacheRow{
            .path = "delete.txt",
            .hash = kasumi::hasher::hash_string("delete"),
            .size = 20,
            .mtime_nanoseconds = 20,
            .volume = 2,
            .file_low = 2,
            .file_high = 2}};

    ASSERT_TRUE(
        kasumi::state_storage::save_file_cache_delta(database_path, initial));
    ASSERT_EQ(kasumi::state_storage::load_file_cache(database_path)->size(),
              2U);

    const auto delta =
        std::span<const kasumi::state_storage::FileCacheRow>{initial.data(), 1};
    ASSERT_TRUE(
        kasumi::state_storage::save_file_cache_delta(database_path, delta));

    const auto loaded = kasumi::state_storage::load_file_cache(database_path);
    ASSERT_TRUE(loaded.has_value());
    ASSERT_EQ(loaded->size(), 1U);
    EXPECT_EQ(loaded->front().path, "keep.txt");
}

TEST(StateStorageDatabaseTest, RejectsLegacySchemaV1WithoutModifyingDatabase) {
    auto workspace = kasumi::test::make_temp_workspace("persistence-reject-v1");
    const auto db = kasumi::test::workspace_path(workspace, "state.db");
    execute_sql(
        db,
        "PRAGMA journal_mode=WAL;"
        "CREATE TABLE nodes (path TEXT PRIMARY KEY, hash TEXT NOT NULL, "
        "size INTEGER NOT NULL, mtime INTEGER NOT NULL, is_dir INTEGER NOT "
        "NULL);"
        "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
        "CREATE TABLE pending_materializations (path TEXT PRIMARY KEY NOT "
        "NULL, "
        "hash TEXT NOT NULL, size INTEGER NOT NULL, mtime INTEGER NOT NULL);"
        "CREATE TABLE file_cache (path TEXT PRIMARY KEY NOT NULL, hash TEXT "
        "NOT NULL, "
        "size INTEGER NOT NULL, fingerprint_kind INTEGER NOT NULL, "
        "fp0 TEXT NOT NULL, fp1 TEXT NOT NULL, fp2 TEXT NOT NULL, fp3 TEXT NOT "
        "NULL);"
        "PRAGMA user_version = 1;",
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);

    EXPECT_FALSE(kasumi::state_storage::validate(db));
    EXPECT_FALSE(kasumi::state_storage::initialize(db));
    EXPECT_FALSE(kasumi::state_storage::load_state(db).has_value());
    EXPECT_FALSE(kasumi::state_storage::load_local_activity(db).has_value());
    EXPECT_FALSE(kasumi::state_storage::save_state(
        db,
        kasumi::state_storage::StoredState{
            make_snapshot("a.txt", "alpha", 1), 1, std::string(64, 'a')}));
    EXPECT_EQ(query_text(db, "PRAGMA user_version"),
              std::vector<std::string>{"1"});
}

TEST(StateStorageDatabaseTest,
     LocalExecutionsAcceptedMetaAndActivityCacheRoundTripAndBoundHistory) {
    auto [workspace, db] = make_db("persistence-v2-activity");

    // Recording an execution on an uninitialized vault keeps
    // load_state()==nullopt.
    kasumi::state_storage::LocalExecutionRecord start_rec{
        .execution_id = "exec-initial",
        .operation = kasumi::state_storage::LocalOperationKind::Fsck,
        .machine_id_hex = std::string(32, 'a'),
        .machine_name = "PC-Casa",
        .started_at = 1700000000,
        .status = kasumi::state_storage::LocalExecutionStatus::InProgress,
    };
    ASSERT_TRUE(kasumi::state_storage::record_execution_start(db, start_rec));
    const auto empty_state = kasumi::state_storage::load_state(db);
    ASSERT_TRUE(empty_state.has_value());
    EXPECT_FALSE(empty_state->has_value());

    start_rec.finished_at = 1700000010;
    start_rec.duration_ms = 10000;
    start_rec.status = kasumi::state_storage::LocalExecutionStatus::Succeeded;
    start_rec.remote_publish_state =
        kasumi::state_storage::RemotePublishState::Published;
    start_rec.summary_a = 42;
    ASSERT_TRUE(kasumi::state_storage::record_execution_finish(db, start_rec));

    // Insert 55 completed sync executions -> capped at
    // max_local_execution_history (50).
    for (int i = 0; i < 55; ++i) {
        kasumi::state_storage::LocalExecutionRecord rec{
            .execution_id = "sync-" + std::to_string(i),
            .operation = kasumi::state_storage::LocalOperationKind::Sync,
            .machine_id_hex = std::string(32, 'a'),
            .machine_name = "PC-Casa",
            .started_at = 1700000100 + i,
            .finished_at = 1700000100 + i,
            .duration_ms = 25,
            .status =
                kasumi::state_storage::LocalExecutionStatus::SucceededNoChanges,
            .commit_id = std::string(64, 'c'),
        };
        ASSERT_TRUE(kasumi::state_storage::record_execution_complete(db, rec));
    }

    const kasumi::state_storage::AcceptedCommitMeta meta{
        .commit_id = std::string(64, 'd'),
        .height = 12,
        .created_at = 1700000500,
        .origin_operation = kasumi::history::CommitOriginOperation::Repack,
        .machine_id_hex = std::string(32, 'b'),
        .machine_name = "Notebook",
        .accepted_at = 1700000550,
    };
    ASSERT_TRUE(kasumi::state_storage::save_accepted_commit_meta(db, meta));

    const std::vector<kasumi::state_storage::CachedRemoteActivity> cached{
        kasumi::state_storage::CachedRemoteActivity{
            .event_id = std::string(32, 'e'),
            .operation = 1,
            .outcome = 1,
            .machine_id_hex = std::string(32, 'b'),
            .machine_name = "Notebook",
            .started_at = 1700000400,
            .finished_at = 1700000410,
            .duration_ms = 10000,
            .metric_primary = 9,
            .cached_at = 1700000600,
        },
    };
    ASSERT_TRUE(kasumi::state_storage::save_remote_activity_cache(db, cached));

    const auto loaded = kasumi::state_storage::load_local_activity(db);
    ASSERT_TRUE(loaded.has_value()) << loaded.error();
    EXPECT_EQ(loaded->executions.size(),
              kasumi::state_storage::max_local_execution_history);
    EXPECT_EQ(loaded->executions.front().execution_id, "sync-54");
    ASSERT_TRUE(loaded->accepted_commit.has_value());
    EXPECT_EQ(*loaded->accepted_commit, meta);
    ASSERT_EQ(loaded->cached_remote_activities.size(), 1U);
    EXPECT_EQ(loaded->cached_remote_activities.front(), cached.front());
}

TEST(StateStorageDatabaseTest,
     SaveStateWithAcceptedCommitMetaIsAtomicAcrossStateAndAuthorship) {
    auto [workspace, db] = make_db("persistence-atomic-state-meta");
    const auto initial_snapshot = make_snapshot("alpha.txt", "alpha", 10);
    const kasumi::state_storage::StoredState initial_state{
        initial_snapshot, 1, std::string(64, 'a')};
    const kasumi::state_storage::AcceptedCommitMeta initial_meta{
        .commit_id = std::string(64, 'a'),
        .height = 1,
        .created_at = 1700000100,
        .origin_operation = kasumi::history::CommitOriginOperation::Sync,
        .machine_id_hex = std::string(32, '1'),
        .machine_name = "Workstation-A",
        .accepted_at = 1700000105,
    };
    ASSERT_TRUE(
        kasumi::state_storage::save_state(db, initial_state, initial_meta));

    const auto bad_snapshot = make_snapshot("beta.txt", "beta", 20);
    const kasumi::state_storage::StoredState next_state{
        bad_snapshot, 2, std::string(64, 'b')};
    kasumi::state_storage::AcceptedCommitMeta bad_meta = initial_meta;
    bad_meta.commit_id = "invalid-commit-id";
    EXPECT_FALSE(kasumi::state_storage::save_state(db, next_state, bad_meta));

    kasumi::state_storage::StoredState invalid_state = next_state;
    invalid_state.epoch_id = "not-a-valid-hex-epoch";
    const kasumi::state_storage::AcceptedCommitMeta valid_meta2{
        .commit_id = std::string(64, 'b'),
        .height = 2,
        .created_at = 1700000200,
        .origin_operation = kasumi::history::CommitOriginOperation::Repack,
        .machine_id_hex = std::string(32, '2'),
        .machine_name = "Workstation-B",
        .accepted_at = 1700000205,
    };
    EXPECT_FALSE(
        kasumi::state_storage::save_state(db, invalid_state, valid_meta2));

    const auto loaded_state = kasumi::state_storage::load_state(db);
    ASSERT_TRUE(loaded_state.has_value()) << loaded_state.error();
    ASSERT_TRUE(loaded_state->has_value());
    EXPECT_EQ((*loaded_state)->commit_id, initial_state.commit_id);
    EXPECT_EQ((*loaded_state)->height, initial_state.height);
    EXPECT_EQ((*loaded_state)->tree, initial_snapshot);

    const auto loaded_activity = kasumi::state_storage::load_local_activity(db);
    ASSERT_TRUE(loaded_activity.has_value()) << loaded_activity.error();
    ASSERT_TRUE(loaded_activity->accepted_commit.has_value());
    EXPECT_EQ(*loaded_activity->accepted_commit, initial_meta);

    ASSERT_TRUE(kasumi::state_storage::save_state(db, next_state, valid_meta2));
    const auto updated_state = kasumi::state_storage::load_state(db);
    ASSERT_TRUE(updated_state.has_value());
    ASSERT_TRUE(updated_state->has_value());
    EXPECT_EQ((*updated_state)->commit_id, next_state.commit_id);
    const auto updated_activity =
        kasumi::state_storage::load_local_activity(db);
    ASSERT_TRUE(updated_activity.has_value());
    ASSERT_TRUE(updated_activity->accepted_commit.has_value());
    EXPECT_EQ(*updated_activity->accepted_commit, valid_meta2);
}

} // namespace
