#include "core/hasher.hpp"
#include "kasumi/test/temp_workspace.hpp"
#include "platform/path.hpp"
#include "state_storage/database.hpp"
#include "state_storage/database_connection.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
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
    const auto epoch = std::chrono::clock_cast<std::chrono::file_clock>(
        std::chrono::system_clock::time_point{});
    const auto root_time = epoch + std::chrono::seconds{time_offset};
    kasumi::Snapshot snapshot{{
        {.path = "", .mtime = root_time, .is_directory = true},
        {.path = "docs",
         .mtime = root_time + std::chrono::seconds{1},
         .is_directory = true},
        {.path = std::string{file_path},
         .hash = kasumi::hasher::hash_string(contents),
         .size = static_cast<std::uint64_t>(contents.size()),
         .mtime = root_time + std::chrono::seconds{2},
         .is_directory = false},
    }};
    kasumi::finalize_snapshot(snapshot);
    return snapshot;
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

TEST(StateStorageDatabaseTest, FreshDatabaseCreatesInitialSchemaAndEmptyCache) {
    auto workspace = kasumi::test::make_temp_workspace("persistence-schema");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    EXPECT_EQ(query_text(database_path, "PRAGMA user_version").front(), "1");
    EXPECT_TRUE(
        query_text(database_path,
                   "SELECT name FROM sqlite_master WHERE name='file_cache'")
            .size() == 1);
    EXPECT_TRUE(query_text(database_path,
                           "SELECT name FROM sqlite_master WHERE "
                           "name='observation_checkpoint'")
                    .size() == 1);
    EXPECT_TRUE(
        query_text(
            database_path,
            "SELECT name FROM sqlite_master WHERE name='directory_lineage'")
            .size() == 1);
    EXPECT_TRUE(kasumi::state_storage::load_file_cache(database_path)->empty());
}

TEST(StateStorageDatabaseTest, FileCacheDeltaIsNonAuthoritative) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-file-cache");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    const auto snapshot = make_snapshot("a.txt", "a", 10);
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = snapshot, .height = 1, .commit_id = std::string(64, 'a')}));
    const auto row = kasumi::state_storage::FileCacheRow{
        .path = "a.txt",
        .hash = kasumi::hasher::hash_string("a"),
        .size = 1,
        .fingerprint = {
            .kind = kasumi::platform::FileFingerprintKind::PosixFileIdentity,
            .value = {1, 2, 3, 4}}};
    ASSERT_TRUE(kasumi::state_storage::save_file_cache_delta(
        database_path,
        std::span<const kasumi::state_storage::FileCacheRow>{&row, 1}));
    const auto loaded_cache =
        kasumi::state_storage::load_file_cache(database_path);
    ASSERT_TRUE(loaded_cache.has_value());
    ASSERT_EQ(loaded_cache->size(), 1U);
    EXPECT_EQ(loaded_cache->front().fingerprint.value[3], 4U);
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
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-epoch-invariant");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));

    EXPECT_FALSE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("a.txt", "a", 12),
         .height = 1,
         .commit_id = std::string(64, 'a'),
         .epoch_sequence = 1}));
}

TEST(StateStorageDatabaseTest, ObservationCheckpointRoundTripsSeparately) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-checkpoint");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    const auto snapshot = make_snapshot("a.txt", "a", 20);
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = snapshot, .height = 1, .commit_id = std::string(64, 'a')}));

    const kasumi::state_storage::ObservationCheckpoint expected{
        .journal = {.kind =
                        kasumi::platform::ChangeJournalKind::WindowsNtfsUsnV1,
                    .volume_serial = 11,
                    .journal_id = 22,
                    .next_usn = 33,
                    .root_file_reference = 44},
        .tree_root_hash = snapshot.rows.front().hash,
        .row_count = snapshot.rows.size(),
        .directory_file_references = {},
        .lineage_complete = false};
    ASSERT_TRUE(kasumi::state_storage::save_observation_checkpoint(
        database_path, expected));
    const auto loaded =
        kasumi::state_storage::load_observation_checkpoint(database_path);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_EQ((*loaded)->journal.volume_serial, 11U);
    EXPECT_EQ((*loaded)->journal.journal_id, 22U);
    EXPECT_EQ((*loaded)->journal.next_usn, 33);
    EXPECT_EQ((*loaded)->journal.root_file_reference, 44U);
    EXPECT_EQ((*loaded)->tree_root_hash, expected.tree_root_hash);
    EXPECT_EQ((*loaded)->row_count, expected.row_count);
}

TEST(StateStorageDatabaseTest, LineageRoundTrip) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-lineage-roundtrip");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    const auto snapshot = make_snapshot("a.txt", "a", 22);
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = snapshot, .height = 1, .commit_id = std::string(64, 'a')}));
    const kasumi::state_storage::ObservationCheckpoint expected{
        .journal = {.kind =
                        kasumi::platform::ChangeJournalKind::WindowsNtfsUsnV1,
                    .volume_serial = 11,
                    .journal_id = 22,
                    .next_usn = 33,
                    .root_file_reference = 44},
        .tree_root_hash = snapshot.rows.front().hash,
        .row_count = snapshot.rows.size(),
        .directory_file_references = {44, 55},
        .lineage_complete = true};
    ASSERT_TRUE(kasumi::state_storage::save_observation_checkpoint(
        database_path, expected));
    const auto loaded =
        kasumi::state_storage::load_observation_checkpoint(database_path);
    ASSERT_TRUE(loaded.has_value() && *loaded);
    EXPECT_TRUE((*loaded)->lineage_complete);
    EXPECT_EQ((*loaded)->directory_file_references,
              (std::vector<std::uint64_t>{44, 55}));
}

TEST(StateStorageDatabaseTest,
     InvalidObservationCheckpointIsRejectedWithoutAffectingState) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-checkpoint-corrupt");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    const auto snapshot = make_snapshot("a.txt", "a", 21);
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = snapshot, .height = 1, .commit_id = std::string(64, 'a')}));
    execute_sql(database_path,
                "INSERT INTO observation_checkpoint VALUES "
                "(1, 99, '1', '2', '3', '4', 'not-a-hash', '1')");

    const auto checkpoint =
        kasumi::state_storage::load_observation_checkpoint(database_path);
    EXPECT_FALSE(checkpoint.has_value());
    const auto state = kasumi::state_storage::load_state(database_path);
    ASSERT_TRUE(state.has_value() && *state);
    EXPECT_EQ((*state)->height, 1U);
    EXPECT_EQ((*state)->tree.rows.size(), snapshot.rows.size());
}

TEST(StateStorageDatabaseTest, MalformedFileCacheEntryIsDiscarded) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-cache-corrupt");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
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
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-unknown-ciphertext");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));

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
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-invalid-ciphertext");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));

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

TEST(StateStorageDatabaseTest, CorruptHashReturnsControlledError) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-corrupt-hash");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");

    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
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
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-negative-is-dir");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
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
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-large-is-dir");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
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
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-negative-size");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
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
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-invalid-state");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
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
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-metadata-canonical");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("docs/old.txt", "old", 700),
         .height = 1,
         .commit_id = std::string(64, 'a')}));
    execute_sql(database_path,
                "INSERT INTO metadata (key, value) "
                "VALUES ('unknown_key', 'legacy')");

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
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-metadata-rollback");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
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
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-version-prerelease");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    execute_sql(database_path, "PRAGMA user_version = 5");
    EXPECT_FALSE(kasumi::state_storage::initialize(database_path));
    EXPECT_FALSE(kasumi::state_storage::load_state(database_path).has_value());
}

TEST(StateStorageDatabaseTest, RejectsUnknownFutureVersion) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-version-future");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    execute_sql(database_path, "PRAGMA user_version = 99");
    EXPECT_FALSE(kasumi::state_storage::initialize(database_path));
    EXPECT_FALSE(kasumi::state_storage::load_state(database_path).has_value());
}

TEST(StateStorageDatabaseTest, RejectsEmptyMetadataWithNodes) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-empty-metadata");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("docs/state.txt", "state", 900),
         .height = 1,
         .commit_id = std::string(64, 'a')}));
    execute_sql(database_path, "DELETE FROM metadata");
    EXPECT_FALSE(kasumi::state_storage::load_state(database_path).has_value());
}

TEST(StateStorageDatabaseTest, RejectsMissingGeneration) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-missing-generation");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("docs/state.txt", "state", 901),
         .height = 1,
         .commit_id = std::string(64, 'a')}));
    execute_sql(database_path, "DELETE FROM metadata WHERE key = 'generation'");
    EXPECT_FALSE(kasumi::state_storage::load_state(database_path).has_value());
}

TEST(StateStorageDatabaseTest, RejectsMissingCommitId) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-missing-commit");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
    ASSERT_TRUE(kasumi::state_storage::save_state(
        database_path,
        {.tree = make_snapshot("docs/state.txt", "state", 902),
         .height = 1,
         .commit_id = std::string(64, 'a')}));
    execute_sql(database_path, "DELETE FROM metadata WHERE key = 'commit_id'");
    EXPECT_FALSE(kasumi::state_storage::load_state(database_path).has_value());
}

TEST(StateStorageDatabaseTest, RejectsNonCanonicalGeneration) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-generation-format");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
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
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-generation-maximum");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
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
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-empty-commit");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
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
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-malformed-commit");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
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
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-unknown-metadata");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));
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
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-wal-journal-mode");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));

    // An independent connection verifies the persistent database header setting
    const auto journal_mode = query_text(database_path, "PRAGMA journal_mode");
    ASSERT_EQ(journal_mode.size(), 1U);
    EXPECT_EQ(journal_mode[0], "wal");
}

TEST(StateStorageDatabaseTest, NewReadWriteConnectionAppliesSynchronousNormal) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-connection-synchronous");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));

    // Raw unconfigured SQLite connection defaults to synchronous=FULL (2)
    {
        auto raw_conn = open_database(database_path, SQLITE_OPEN_READWRITE);
        sqlite3_stmt* stmt = nullptr;
        ASSERT_EQ(sqlite3_prepare_v2(raw_conn.get(), "PRAGMA synchronous", -1,
                                     &stmt, nullptr),
                  SQLITE_OK);
        ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
        const auto raw_sync = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        EXPECT_EQ(raw_sync, 2);
    }

    // A newly opened connection via StateStorage policy helper applies synchronous=NORMAL (1)
    auto state_conn =
        kasumi::state_storage::detail::open_state_database_readwrite(
            database_path);
    ASSERT_TRUE(state_conn.has_value());
    sqlite3_stmt* stmt = nullptr;
    ASSERT_EQ(sqlite3_prepare_v2(state_conn->get(), "PRAGMA synchronous", -1,
                                 &stmt, nullptr),
              SQLITE_OK);
    ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    const auto configured_sync = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    EXPECT_EQ(configured_sync, 1);
}

TEST(StateStorageDatabaseTest, ReadOnlyConnectionDoesNotExecuteWritePragmas) {
    auto workspace =
        kasumi::test::make_temp_workspace("persistence-connection-readonly");
    const auto database_path =
        kasumi::test::workspace_path(workspace, "state.db");
    ASSERT_TRUE(kasumi::state_storage::initialize(database_path));

    auto readonly_conn =
        kasumi::state_storage::detail::open_state_database_readonly(
            database_path);
    ASSERT_TRUE(readonly_conn.has_value());

    sqlite3_stmt* stmt = nullptr;
    ASSERT_EQ(sqlite3_prepare_v2(readonly_conn->get(), "SELECT 1", -1, &stmt,
                                 nullptr),
              SQLITE_OK);
    ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    EXPECT_EQ(sqlite3_column_int(stmt, 0), 1);
    sqlite3_finalize(stmt);

    // Read-only connection rejects schema modification
    ASSERT_NE(sqlite3_exec(readonly_conn->get(),
                           "CREATE TABLE test_write (x INT)", nullptr, nullptr,
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
    EXPECT_NE(
        std::find(node_rows.begin(), node_rows.end(), logical_path),
        node_rows.end());

    const auto commit_rows = query_text(
        database_path, "SELECT value FROM metadata WHERE key='commit_id'");
    ASSERT_EQ(commit_rows.size(), 1U);
    EXPECT_EQ(commit_rows[0], commit_hash);
}

} // namespace
