#include "state_storage/database.hpp"

#include "platform/path.hpp"
#include "core/history.hpp"
#include "platform/perf_trace.hpp"
#include "platform/private_storage.hpp"
#include "sqlite/sqlite.hpp"
#include "state_storage/database_connection.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <limits>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>

namespace kasumi::state_storage {
namespace {

constexpr int schema_version = 1;

struct ColumnDefinition {
    std::string_view name;
    std::string_view type;
    bool requires_not_null;
    int primary_key;
};

constexpr std::array node_columns{
    ColumnDefinition{"path", "TEXT", false, 1},
    ColumnDefinition{"hash", "TEXT", true, 0},
    ColumnDefinition{"size", "INTEGER", true, 0},
    ColumnDefinition{"mtime", "INTEGER", true, 0},
    ColumnDefinition{"is_dir", "INTEGER", true, 0},
};

constexpr std::array metadata_columns{
    ColumnDefinition{"key", "TEXT", false, 1},
    ColumnDefinition{"value", "TEXT", true, 0},
};

constexpr std::array file_cache_columns{
    ColumnDefinition{"path", "TEXT", true, 1},
    ColumnDefinition{"hash", "TEXT", true, 0},
    ColumnDefinition{"size", "INTEGER", true, 0},
    ColumnDefinition{"fingerprint_kind", "INTEGER", true, 0},
    ColumnDefinition{"fp0", "TEXT", true, 0},
    ColumnDefinition{"fp1", "TEXT", true, 0},
    ColumnDefinition{"fp2", "TEXT", true, 0},
    ColumnDefinition{"fp3", "TEXT", true, 0}};

constexpr std::array checkpoint_columns{
    ColumnDefinition{"id", "INTEGER", false, 1},
    ColumnDefinition{"kind", "INTEGER", true, 0},
    ColumnDefinition{"volume_serial", "TEXT", true, 0},
    ColumnDefinition{"journal_id", "TEXT", true, 0},
    ColumnDefinition{"next_usn", "TEXT", true, 0},
    ColumnDefinition{"root_file_reference", "TEXT", true, 0},
    ColumnDefinition{"tree_root_hash", "TEXT", true, 0},
    ColumnDefinition{"row_count", "TEXT", true, 0}};

constexpr std::array lineage_metadata_columns{
    ColumnDefinition{"id", "INTEGER", false, 1},
    ColumnDefinition{"volume_serial", "TEXT", true, 0},
    ColumnDefinition{"journal_id", "TEXT", true, 0},
    ColumnDefinition{"root_file_reference", "TEXT", true, 0},
    ColumnDefinition{"tree_root_hash", "TEXT", true, 0},
    ColumnDefinition{"row_count", "TEXT", true, 0},
    ColumnDefinition{"directory_count", "TEXT", true, 0},
    ColumnDefinition{"lineage_complete", "INTEGER", true, 0}};

constexpr std::array lineage_columns{
    ColumnDefinition{"file_reference", "TEXT", false, 1}};

enum class ObjectKind {
    Missing,
    Table,
    Other,
};

void require(std::expected<void, std::string> result) {
    if (!result) {
        throw std::runtime_error(result.error());
    }
}

sqlite::Statement
require_statement(std::expected<sqlite::Statement, std::string> result) {
    if (!result) {
        throw std::runtime_error(result.error());
    }
    return std::move(*result);
}

bool require_step(sqlite::Statement& statement) {
    auto result = sqlite::step(statement);
    if (!result) {
        throw std::runtime_error(result.error());
    }
    return *result;
}

char ascii_lower(char value) noexcept {
    return value >= 'A' && value <= 'Z' ? static_cast<char>(value + ('a' - 'A'))
                                        : value;
}

bool same_type(std::string_view left, std::string_view right) noexcept {
    return left.size() == right.size() &&
           std::ranges::equal(left, right, {}, ascii_lower, ascii_lower);
}

ObjectKind object_kind(sqlite3* database, std::string_view name) {
    auto query = require_statement(sqlite::prepare(
        database,
        "SELECT type FROM sqlite_master WHERE name = ? COLLATE NOCASE"));
    require(sqlite::bind(query, 1, name));
    if (!require_step(query)) {
        return ObjectKind::Missing;
    }
    return sqlite::text(query, 0) == "table" ? ObjectKind::Table
                                             : ObjectKind::Other;
}

int read_schema_version(sqlite3* database) {
    auto query =
        require_statement(sqlite::prepare(database, "PRAGMA user_version"));
    if (!require_step(query)) {
        throw std::runtime_error("Nao foi possivel ler a versao do schema");
    }
    return static_cast<int>(sqlite::integer(query, 0));
}

template <std::size_t Size>
bool has_columns(sqlite3* database,
                 std::string_view table,
                 const std::array<ColumnDefinition, Size>& expected) {
    auto query = require_statement(sqlite::prepare(
        database, "PRAGMA table_xinfo(" + std::string{table} + ")"));
    std::array<bool, Size> seen{};
    std::size_t count = 0;
    while (require_step(query)) {
        if (count == Size) {
            return false;
        }
        const auto name = sqlite::text(query, 1);
        const auto match =
            std::ranges::find(expected, name, &ColumnDefinition::name);
        if (match == expected.end()) {
            return false;
        }
        const auto index =
            static_cast<std::size_t>(std::distance(expected.begin(), match));
        if (seen[index] || !same_type(sqlite::text(query, 2), match->type) ||
            (match->requires_not_null && sqlite::integer(query, 3) == 0) ||
            sqlite::integer(query, 5) != match->primary_key ||
            sqlite::integer(query, 6) != 0) {
            return false;
        }
        seen[index] = true;
        ++count;
    }
    return count == Size && std::ranges::all_of(seen, [](bool value) {
               return value;
           });
}

bool has_binary_primary_key(sqlite3* database,
                            std::string_view table,
                            std::string_view column) {
    auto indexes = require_statement(sqlite::prepare(
        database, "PRAGMA index_list(" + std::string{table} + ")"));
    std::string primary_key_index;
    while (require_step(indexes)) {
        if (sqlite::text(indexes, 3) != "pk") {
            continue;
        }
        if (!primary_key_index.empty() || sqlite::integer(indexes, 2) != 1 ||
            sqlite::integer(indexes, 4) != 0) {
            return false;
        }
        primary_key_index = sqlite::text(indexes, 1);
    }
    if (primary_key_index.empty()) {
        return false;
    }
    auto columns = require_statement(sqlite::prepare(
        database, "PRAGMA index_xinfo(" + primary_key_index + ")"));
    std::size_t key_columns = 0;
    while (require_step(columns)) {
        if (sqlite::integer(columns, 5) == 0) {
            continue;
        }
        ++key_columns;
        if (key_columns != 1 || sqlite::text(columns, 2) != column ||
            sqlite::integer(columns, 3) != 0 ||
            !same_type(sqlite::text(columns, 4), "BINARY")) {
            return false;
        }
    }
    return key_columns == 1;
}

bool has_expected_schema(sqlite3* database) {
    return object_kind(database, "nodes") == ObjectKind::Table &&
           object_kind(database, "metadata") == ObjectKind::Table &&
           has_columns(database, "nodes", node_columns) &&
           has_columns(database, "metadata", metadata_columns) &&
           object_kind(database, "file_cache") == ObjectKind::Table &&
           has_columns(database, "file_cache", file_cache_columns) &&
           object_kind(database, "observation_checkpoint") ==
               ObjectKind::Table &&
           has_columns(
               database, "observation_checkpoint", checkpoint_columns) &&
           object_kind(database, "directory_lineage_metadata") ==
               ObjectKind::Table &&
           has_columns(database,
                       "directory_lineage_metadata",
                       lineage_metadata_columns) &&
           object_kind(database, "directory_lineage") == ObjectKind::Table &&
           has_columns(database, "directory_lineage", lineage_columns) &&
           has_binary_primary_key(database, "nodes", "path") &&
           has_binary_primary_key(database, "metadata", "key") &&
           has_binary_primary_key(database, "file_cache", "path") &&
           has_binary_primary_key(
               database, "directory_lineage", "file_reference");
}

void create_file_cache(sqlite3* database) {
    if (object_kind(database, "file_cache") != ObjectKind::Missing)
        throw std::runtime_error("state.db file_cache already exists");
    require(sqlite::execute(
        database,
        "CREATE TABLE file_cache (path TEXT PRIMARY KEY NOT NULL, hash TEXT "
        "NOT NULL, size INTEGER NOT NULL, fingerprint_kind INTEGER NOT NULL, "
        "fp0 TEXT NOT NULL, fp1 TEXT NOT NULL, fp2 TEXT NOT NULL, fp3 TEXT NOT "
        "NULL)"));
}

void create_observation_checkpoint(sqlite3* database) {
    if (object_kind(database, "observation_checkpoint") != ObjectKind::Missing)
        throw std::runtime_error(
            "state.db observation_checkpoint already exists");
    require(sqlite::execute(database, R"(
        CREATE TABLE observation_checkpoint (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            kind INTEGER NOT NULL,
            volume_serial TEXT NOT NULL,
            journal_id TEXT NOT NULL,
            next_usn TEXT NOT NULL,
            root_file_reference TEXT NOT NULL,
            tree_root_hash TEXT NOT NULL,
            row_count TEXT NOT NULL
        ))"));
}

void create_directory_lineage(sqlite3* database) {
    if (object_kind(database, "directory_lineage_metadata") !=
            ObjectKind::Missing ||
        object_kind(database, "directory_lineage") != ObjectKind::Missing) {
        throw std::runtime_error("state.db directory lineage already exists");
    }
    require(sqlite::execute(database, R"(
        CREATE TABLE directory_lineage_metadata (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            volume_serial TEXT NOT NULL,
            journal_id TEXT NOT NULL,
            root_file_reference TEXT NOT NULL,
            tree_root_hash TEXT NOT NULL,
            row_count TEXT NOT NULL,
            directory_count TEXT NOT NULL,
            lineage_complete INTEGER NOT NULL CHECK(lineage_complete IN (0, 1))
        ))"));
    require(sqlite::execute(database,
                            "CREATE TABLE directory_lineage ("
                            "file_reference TEXT PRIMARY KEY NOT NULL)"));
}

void create_schema(sqlite3* database) {
    require(sqlite::execute(database, R"(
        CREATE TABLE nodes (
            path TEXT PRIMARY KEY,
            hash TEXT NOT NULL,
            size INTEGER NOT NULL,
            mtime INTEGER NOT NULL,
            is_dir INTEGER NOT NULL
        ))"));
    require(sqlite::execute(database, R"(
        CREATE TABLE metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        ))"));
    create_file_cache(database);
    create_observation_checkpoint(database);
    create_directory_lineage(database);
}

std::int64_t mtime_value(const NodeRow& row) {
    if (row.mtime == std::filesystem::file_time_type{}) {
        return 0;
    }
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::clock_cast<std::chrono::system_clock>(row.mtime)
                   .time_since_epoch())
        .count();
}

bool same_node(const NodeRow& left, const NodeRow& right) {
    return left.path == right.path && left.hash == right.hash &&
           left.size == right.size && left.mtime == right.mtime &&
           left.is_directory == right.is_directory;
}

void bind_node(sqlite::Statement& query, const NodeRow& row) {
    require(sqlite::bind(query, 1, row.path));
    require(sqlite::bind(query, 2, hash_hex(row.hash)));
    require(sqlite::bind(query, 3, static_cast<std::int64_t>(row.size)));
    require(sqlite::bind(query, 4, mtime_value(row)));
    require(sqlite::bind(query, 5, row.is_directory ? 1 : 0));
}

void write_tree_delta(sqlite3* database,
                      const Snapshot& previous,
                      const Snapshot& current) {
    auto insert = require_statement(
        sqlite::prepare(database,
                        "INSERT INTO nodes (path, hash, size, mtime, is_dir) "
                        "VALUES (?, ?, ?, ?, ?)"));
    auto update = require_statement(sqlite::prepare(
        database,
        "UPDATE nodes SET hash = ?, size = ?, mtime = ?, is_dir = ? "
        "WHERE path = ?"));
    auto remove = require_statement(
        sqlite::prepare(database, "DELETE FROM nodes WHERE path = ?"));
    std::unordered_map<std::string_view, const NodeRow*> old;
    old.reserve(previous.rows.size());
    for (const auto& row : previous.rows)
        old.emplace(row.path, &row);
    for (const auto& row : current.rows) {
        const auto found = old.find(row.path);
        if (found == old.end()) {
            bind_node(insert, row);
            require(sqlite::run(insert));
            require(sqlite::reset(insert));
            platform::perf_trace::count("state db node inserts");
        } else if (same_node(*found->second, row)) {
            platform::perf_trace::count("state db node unchanged");
        } else {
            require(sqlite::bind(update, 1, hash_hex(row.hash)));
            require(
                sqlite::bind(update, 2, static_cast<std::int64_t>(row.size)));
            require(sqlite::bind(update, 3, mtime_value(row)));
            require(sqlite::bind(update, 4, row.is_directory ? 1 : 0));
            require(sqlite::bind(update, 5, row.path));
            require(sqlite::run(update));
            require(sqlite::reset(update));
            platform::perf_trace::count("state db node updates");
        }
        old.erase(row.path);
    }
    for (const auto& [path, row] : old) {
        require(sqlite::bind(remove, 1, path));
        require(sqlite::run(remove));
        require(sqlite::reset(remove));
        platform::perf_trace::count("state db node deletes");
    }
}

std::expected<Snapshot, std::string> load_tree(sqlite3* database) {
    try {
        auto query = require_statement(sqlite::prepare(
            database,
            "SELECT path, hash, size, mtime, is_dir FROM nodes ORDER BY path"));
        Snapshot snapshot;
        while (require_step(query)) {
            auto hash = hash_from_hex(sqlite::text(query, 1));
            if (!hash) {
                throw std::runtime_error(hash.error());
            }
            const auto size = sqlite::integer(query, 2);
            const auto is_directory = sqlite::integer(query, 4);
            if (size < 0 || is_directory < 0 || is_directory > 1) {
                throw std::runtime_error("invalid node fields");
            }
            const auto raw_nanos = sqlite::integer(query, 3);
            std::filesystem::file_time_type mtime{};
            if (raw_nanos != 0) {
                const auto sys_dur =
                    std::chrono::duration_cast<std::chrono::system_clock::duration>(
                        std::chrono::nanoseconds{raw_nanos});
                const auto sys_tp =
                    std::chrono::time_point<std::chrono::system_clock>{sys_dur};
                mtime = std::chrono::clock_cast<std::chrono::file_clock>(sys_tp);
            }
            snapshot.rows.push_back(
                {.path = sqlite::text(query, 0),
                 .hash = *hash,
                 .size = static_cast<std::uint64_t>(size),
                 .mtime = mtime,
                 .is_directory = is_directory == 1});
        }
        std::ranges::sort(snapshot.rows, path_less, &NodeRow::path);
        return snapshot;
    } catch (const std::exception& exception) {
        return std::unexpected(std::string{"não foi possível carregar "
                                           "a árvore do banco local: "} +
                               exception.what());
    }
}

std::string word_hex(std::uint64_t value) {
    std::array<char, 16> buffer{};
    constexpr char digits[] = "0123456789abcdef";
    for (std::size_t index = buffer.size(); index > 0; --index)
        buffer[index - 1] = digits[value & 0x0fU], value >>= 4;
    return std::string{buffer.data(), buffer.size()};
}

std::optional<std::uint64_t> parse_word(std::string_view value) {
    if (value.size() != 16)
        return std::nullopt;
    std::uint64_t result = 0;
    const auto parsed =
        std::from_chars(value.data(), value.data() + value.size(), result, 16);
    return parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size()
               ? std::optional<std::uint64_t>{result}
               : std::nullopt;
}

std::optional<std::uint64_t> parse_decimal(std::string_view value) {
    if (value.empty())
        return std::nullopt;
    std::uint64_t result = 0;
    const auto parsed =
        std::from_chars(value.data(), value.data() + value.size(), result, 10);
    return parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size()
               ? std::optional<std::uint64_t>{result}
               : std::nullopt;
}

bool valid_fingerprint_kind(std::int64_t value) noexcept {
    return value == static_cast<std::int64_t>(
                        platform::FileFingerprintKind::WindowsFileIdentity) ||
           value == static_cast<std::int64_t>(
                        platform::FileFingerprintKind::PosixFileIdentity);
}

bool same_cache_row(const FileCacheRow& left, const FileCacheRow& right) {
    return left.hash == right.hash && left.size == right.size &&
           left.fingerprint.kind == right.fingerprint.kind &&
           left.fingerprint.value == right.fingerprint.value;
}

std::vector<FileCacheRow> read_cache_rows(sqlite3* database) {
    auto query = require_statement(sqlite::prepare(
        database,
        "SELECT path, hash, size, fingerprint_kind, fp0, fp1, fp2, fp3 "
        "FROM file_cache ORDER BY path"));
    std::vector<FileCacheRow> rows;
    while (require_step(query)) {
        const auto size = sqlite::integer(query, 2);
        const auto kind = sqlite::integer(query, 3);
        const auto words = std::array{parse_word(sqlite::text(query, 4)),
                                      parse_word(sqlite::text(query, 5)),
                                      parse_word(sqlite::text(query, 6)),
                                      parse_word(sqlite::text(query, 7))};
        const auto hash = hash_from_hex(sqlite::text(query, 1));
        if (size < 0 || !valid_fingerprint_kind(kind) ||
            std::ranges::any_of(
                words,
                [](const auto& word) {
                    return !word;
                }) ||
            !hash) {
            continue;
        }
        rows.push_back(FileCacheRow{
            .path = sqlite::text(query, 0),
            .hash = *hash,
            .size = static_cast<std::uint64_t>(size),
            .fingerprint = platform::FileFingerprint{
                .kind = static_cast<platform::FileFingerprintKind>(kind),
                .value = {*words[0], *words[1], *words[2], *words[3]}}});
    }
    return rows;
}

void write_cache_delta(sqlite3* database,
                       const std::vector<FileCacheRow>& previous,
                       std::span<const FileCacheRow> current) {
    auto upsert = require_statement(sqlite::prepare(
        database,
        "INSERT INTO file_cache "
        "(path, hash, size, fingerprint_kind, fp0, fp1, fp2, fp3) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(path) DO UPDATE SET hash=excluded.hash, "
        "size=excluded.size, fingerprint_kind=excluded.fingerprint_kind, "
        "fp0=excluded.fp0, fp1=excluded.fp1, fp2=excluded.fp2, "
        "fp3=excluded.fp3"));
    auto remove = require_statement(
        sqlite::prepare(database, "DELETE FROM file_cache WHERE path = ?"));
    const auto upsert_row = [&](const FileCacheRow& row) {
        require(sqlite::bind(upsert, 1, row.path));
        require(sqlite::bind(upsert, 2, hash_hex(row.hash)));
        require(sqlite::bind(upsert, 3, static_cast<std::int64_t>(row.size)));
        require(sqlite::bind(
            upsert, 4, static_cast<std::int64_t>(row.fingerprint.kind)));
        for (int index = 0; index < 4; ++index)
            require(sqlite::bind(
                upsert,
                index + 5,
                word_hex(
                    row.fingerprint.value[static_cast<std::size_t>(index)])));
        require(sqlite::run(upsert));
        require(sqlite::reset(upsert));
    };
    std::unordered_map<std::string_view, const FileCacheRow*> old;
    old.reserve(previous.size());
    for (const auto& row : previous)
        old.emplace(row.path, &row);
    for (const auto& row : current) {
        const auto found = old.find(row.path);
        if (found == old.end()) {
            upsert_row(row);
            platform::perf_trace::count("state db cache inserts");
        } else if (same_cache_row(*found->second, row)) {
            platform::perf_trace::count("state db cache unchanged");
        } else {
            upsert_row(row);
            platform::perf_trace::count("state db cache updates");
        }
        old.erase(row.path);
    }
    for (const auto& [path, row] : old) {
        require(sqlite::bind(remove, 1, path));
        require(sqlite::run(remove));
        require(sqlite::reset(remove));
        platform::perf_trace::count("state db cache deletes");
    }
}

} // namespace

bool initialize(const std::filesystem::path& database_path) {
    try {
        std::error_code status_error;
        if (std::filesystem::exists(database_path, status_error)) {
            auto secured =
                platform::private_storage::protect_file(database_path);
            if (!secured) {
                return false;
            }
        } else if (status_error) {
            return false;
        }
        auto opened = detail::open_state_database_readwrite(database_path,
                                                             /*create=*/true);
        if (!opened) {
            return false;
        }
        auto secured = platform::private_storage::protect_file(database_path);
        if (!secured) {
            return false;
        }
        auto transaction = sqlite::begin(opened->get());
        if (!transaction) {
            return false;
        }
        const auto version = read_schema_version(opened->get());
        const auto nodes = object_kind(opened->get(), "nodes");
        const auto metadata = object_kind(opened->get(), "metadata");
        if (version == 0 && nodes == ObjectKind::Missing &&
            metadata == ObjectKind::Missing) {
            create_schema(opened->get());
            require(sqlite::execute(opened->get(), "PRAGMA user_version = 1"));
        } else if (version != schema_version) {
            return false;
        }
        if (!has_expected_schema(opened->get())) {
            return false;
        }
        require(sqlite::commit(*transaction));
        require(sqlite::execute(opened->get(), "PRAGMA journal_mode=WAL"));
        for (const auto& suffix : {"-wal", "-shm"}) {
            const auto sidecar = platform::path::temporary_sibling_path(
                database_path, "", suffix);
            status_error.clear();
            if (std::filesystem::exists(sidecar, status_error)) {
                secured = platform::private_storage::protect_file(sidecar);
                if (!secured) {
                    return false;
                }
            } else if (status_error) {
                return false;
            }
        }
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::expected<std::optional<StoredState>, std::string>
load_state(const std::filesystem::path& database_path) {
    const auto state_trace = platform::perf_trace::begin();
    platform::perf_trace::count("state db load calls");
    try {
        std::error_code filesystem_error;
        if (!std::filesystem::exists(database_path, filesystem_error)) {
            if (filesystem_error) {
                return std::unexpected(filesystem_error.message());
            }
            return std::optional<StoredState>{};
        }
        auto opened = detail::open_state_database_readonly(database_path);
        if (!opened) {
            return std::unexpected(opened.error());
        }
        auto transaction = sqlite::begin(opened->get(), "BEGIN");
        if (!transaction) {
            return std::unexpected(transaction.error());
        }
        if (read_schema_version(opened->get()) != schema_version ||
            !has_expected_schema(opened->get())) {
            return std::unexpected("state.db schema is not version 1");
        }
        auto metadata = require_statement(sqlite::prepare(
            opened->get(), "SELECT key, value FROM metadata ORDER BY key"));
        std::string generation;
        std::string commit_id;
        std::string ciphertext_id;
        std::string epoch_id;
        std::string epoch_sequence;
        std::size_t metadata_count = 0;
        while (require_step(metadata)) {
            const auto key = sqlite::text(metadata, 0);
            ++metadata_count;
            if (key == "generation") {
                if (!generation.empty()) {
                    return std::unexpected("state.db generation is duplicated");
                }
                generation = sqlite::text(metadata, 1);
            } else if (key == "commit_id") {
                if (!commit_id.empty()) {
                    return std::unexpected("state.db commit ID is duplicated");
                }
                commit_id = sqlite::text(metadata, 1);
            } else if (key == "ciphertext_id") {
                if (!ciphertext_id.empty()) {
                    return std::unexpected(
                        "state.db ciphertext ID is duplicated");
                }
                ciphertext_id = sqlite::text(metadata, 1);
            } else if (key == "epoch_id") {
                if (!epoch_id.empty()) {
                    return std::unexpected("state.db Epoch ID is duplicated");
                }
                epoch_id = sqlite::text(metadata, 1);
            } else if (key == "epoch_sequence") {
                if (!epoch_sequence.empty()) {
                    return std::unexpected(
                        "state.db Epoch sequence is duplicated");
                }
                epoch_sequence = sqlite::text(metadata, 1);
            } else {
                return std::unexpected("state.db contains unknown metadata");
            }
        }
        if (metadata_count == 0) {
            auto nodes = require_statement(
                sqlite::prepare(opened->get(), "SELECT 1 FROM nodes LIMIT 1"));
            if (!require_step(nodes)) {
                require(sqlite::commit(*transaction));
                return std::optional<StoredState>{};
            }
            return std::unexpected("state.db state metadata is incomplete");
        }
        if (generation.empty()) {
            return std::unexpected("state.db generation is missing");
        }
        if (commit_id.empty() || !history::valid_commit_id(commit_id)) {
            return std::unexpected("state.db commit ID is invalid");
        }
        if (!ciphertext_id.empty() &&
            !history::valid_commit_id(ciphertext_id)) {
            return std::unexpected("state.db ciphertext ID is invalid");
        }
        if (!epoch_id.empty() && !history::valid_commit_id(epoch_id)) {
            return std::unexpected("state.db Epoch ID is invalid");
        }
        if (epoch_id.empty() != epoch_sequence.empty()) {
            return std::unexpected("state.db Epoch reference is incomplete");
        }
        auto tree = load_tree(opened->get());
        if (!tree) {
            return std::unexpected(tree.error());
        }
        std::size_t consumed = 0;
        const auto height = std::stoull(generation, &consumed);
        if (consumed != generation.size() ||
            std::to_string(height) != generation) {
            return std::unexpected("state.db generation is invalid");
        }
        std::uint64_t parsed_epoch_sequence = 0;
        if (!epoch_sequence.empty()) {
            consumed = 0;
            parsed_epoch_sequence = std::stoull(epoch_sequence, &consumed);
            if (consumed != epoch_sequence.size() ||
                std::to_string(parsed_epoch_sequence) != epoch_sequence) {
                return std::unexpected("state.db Epoch sequence is invalid");
            }
        }
        if (!valid_snapshot(*tree, false) ||
            height == std::numeric_limits<std::uint64_t>::max()) {
            return std::unexpected("state.db state is invalid");
        }
        require(sqlite::commit(*transaction));
        StoredState state{.tree = std::move(*tree),
                          .height = height,
                          .commit_id = std::move(commit_id),
                          .ciphertext_id = std::move(ciphertext_id),
                          .epoch_id = std::move(epoch_id),
                          .epoch_sequence = parsed_epoch_sequence};
        platform::perf_trace::finish("state db load wall", state_trace);
        return state;
    } catch (const std::exception& exception) {
        return std::unexpected(std::string{"não foi possível carregar state.db: "} +
                               exception.what());
    }
}

bool save_state(const std::filesystem::path& database_path,
                const StoredState& state) {
    const auto state_trace = platform::perf_trace::begin();
    platform::perf_trace::count("state db save calls");
    if (!valid_snapshot(state.tree, false) ||
        state.height == std::numeric_limits<std::uint64_t>::max() ||
        !history::valid_commit_id(state.commit_id) ||
        (!state.ciphertext_id.empty() &&
         !history::valid_commit_id(state.ciphertext_id)) ||
        (!state.epoch_id.empty() &&
         !history::valid_commit_id(state.epoch_id)) ||
        (state.epoch_id.empty() && state.epoch_sequence != 0)) {
        return false;
    }
    try {
        auto opened = detail::open_state_database_readwrite(database_path);
        if (!opened) {
            return false;
        }
        auto transaction = sqlite::begin(opened->get());
        if (!transaction ||
            read_schema_version(opened->get()) != schema_version ||
            !has_expected_schema(opened->get())) {
            return false;
        }
        auto previous_tree = load_tree(opened->get());
        if (!previous_tree) {
            return false;
        }
        platform::perf_trace::count("state db existing node rows",
                                    previous_tree->rows.size());
        const auto node_diff_trace = platform::perf_trace::begin();
        write_tree_delta(opened->get(), *previous_tree, state.tree);
        platform::perf_trace::finish("state db node diff wall",
                                     node_diff_trace);
        require(sqlite::execute(opened->get(),
                                "DELETE FROM metadata WHERE key NOT IN "
                                "('epoch_id', 'epoch_sequence')"));
        auto generation = require_statement(
            sqlite::prepare(opened->get(),
                            "INSERT OR REPLACE INTO metadata (key, value) "
                            "VALUES ('generation', ?)"));
        require(sqlite::bind(generation, 1, std::to_string(state.height)));
        require(sqlite::run(generation));
        auto commit = require_statement(
            sqlite::prepare(opened->get(),
                            "INSERT OR REPLACE INTO metadata (key, value) "
                            "VALUES ('commit_id', ?)"));
        require(sqlite::bind(commit, 1, state.commit_id));
        require(sqlite::run(commit));
        if (!state.ciphertext_id.empty()) {
            auto ciphertext = require_statement(
                sqlite::prepare(opened->get(),
                                "INSERT OR REPLACE INTO metadata (key, value) "
                                "VALUES ('ciphertext_id', ?)"));
            require(sqlite::bind(ciphertext, 1, state.ciphertext_id));
            require(sqlite::run(ciphertext));
        }
        if (!state.epoch_id.empty()) {
            auto epoch = require_statement(
                sqlite::prepare(opened->get(),
                                "INSERT OR REPLACE INTO metadata (key, value) "
                                "VALUES ('epoch_id', ?)"));
            require(sqlite::bind(epoch, 1, state.epoch_id));
            require(sqlite::run(epoch));
            auto sequence = require_statement(
                sqlite::prepare(opened->get(),
                                "INSERT OR REPLACE INTO metadata (key, value) "
                                "VALUES ('epoch_sequence', ?)"));
            require(sqlite::bind(
                sequence, 1, std::to_string(state.epoch_sequence)));
            require(sqlite::run(sequence));
        }
        const auto transaction_trace = platform::perf_trace::begin();
        require(sqlite::commit(*transaction));
        platform::perf_trace::finish("state db transaction wall",
                                     transaction_trace);
        platform::perf_trace::finish("state db save wall", state_trace);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::expected<std::vector<FileCacheRow>, std::string>
load_file_cache(const std::filesystem::path& database_path) {
    const auto cache_trace = platform::perf_trace::begin();
    platform::perf_trace::count("file cache load calls");
    try {
        std::error_code error;
        if (!std::filesystem::exists(database_path, error)) {
            if (error)
                return std::unexpected(error.message());
            return std::vector<FileCacheRow>{};
        }
        auto opened = detail::open_state_database_readonly(database_path);
        if (!opened)
            return std::unexpected(opened.error());
        if (read_schema_version(opened->get()) != schema_version ||
            !has_expected_schema(opened->get()))
            return std::vector<FileCacheRow>{};
        auto result = read_cache_rows(opened->get());
        platform::perf_trace::finish("file cache load wall", cache_trace);
        platform::perf_trace::count("file cache rows loaded", result.size());
        return result;
    } catch (const std::exception& exception) {
        return std::unexpected(std::string{"não foi possível carregar o cache de arquivos: "} +
                               exception.what());
    }
}

bool save_file_cache_delta(const std::filesystem::path& database_path,
                           std::span<const FileCacheRow> rows) {
    const auto cache_trace = platform::perf_trace::begin();
    platform::perf_trace::count("file cache save calls");
    try {
        auto opened = detail::open_state_database_readwrite(database_path);
        if (!opened)
            return false;
        auto transaction = sqlite::begin(opened->get());
        if (!transaction ||
            read_schema_version(opened->get()) != schema_version ||
            !has_expected_schema(opened->get()))
            return false;
        const auto previous = read_cache_rows(opened->get());
        const auto diff_trace = platform::perf_trace::begin();
        write_cache_delta(opened->get(), previous, rows);
        platform::perf_trace::finish("state db cache diff wall", diff_trace);
        const auto transaction_trace = platform::perf_trace::begin();
        require(sqlite::commit(*transaction));
        platform::perf_trace::finish("state db transaction wall",
                                     transaction_trace);
        platform::perf_trace::finish("file cache save wall", cache_trace);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::expected<std::optional<ObservationCheckpoint>, std::string>
load_observation_checkpoint(const std::filesystem::path& database_path) {
    const auto checkpoint_trace = platform::perf_trace::begin();
    platform::perf_trace::count("checkpoint load calls");
    try {
        if (!std::filesystem::exists(database_path))
            return std::optional<ObservationCheckpoint>{};
        auto opened = detail::open_state_database_readonly(database_path);
        if (!opened)
            return std::unexpected(opened.error());
        if (read_schema_version(opened->get()) != schema_version ||
            !has_expected_schema(opened->get()))
            return std::unexpected("state.db schema is not version 1");
        auto query = require_statement(
            sqlite::prepare(opened->get(),
                            "SELECT kind, volume_serial, journal_id, next_usn, "
                            "root_file_reference, tree_root_hash, row_count "
                            "FROM observation_checkpoint WHERE id = 1"));
        if (!require_step(query))
            return std::optional<ObservationCheckpoint>{};
        const auto kind = sqlite::integer(query, 0);
        const auto volume = parse_decimal(sqlite::text(query, 1));
        const auto journal = parse_decimal(sqlite::text(query, 2));
        const auto next = parse_decimal(sqlite::text(query, 3));
        const auto root = parse_decimal(sqlite::text(query, 4));
        const auto hash = hash_from_hex(sqlite::text(query, 5));
        const auto rows = parse_decimal(sqlite::text(query, 6));
        if (kind != static_cast<std::int64_t>(
                        platform::ChangeJournalKind::WindowsNtfsUsnV1) ||
            !volume || !journal || !next || !root || !hash || !rows ||
            *next > static_cast<std::uint64_t>(
                        std::numeric_limits<std::int64_t>::max()) ||
            *rows == 0) {
            return std::unexpected(
                "state.db observation checkpoint is invalid");
        }
        ObservationCheckpoint result{
            .journal =
                platform::ChangeJournalCheckpoint{
                    .kind = platform::ChangeJournalKind::WindowsNtfsUsnV1,
                    .volume_serial = *volume,
                    .journal_id = *journal,
                    .next_usn = static_cast<std::int64_t>(*next),
                    .root_file_reference = *root},
            .tree_root_hash = *hash,
            .row_count = *rows,
            .directory_file_references = {},
            .lineage_complete = false};
        if (!platform::valid_change_journal_checkpoint(result.journal))
            return std::unexpected(
                "state.db observation checkpoint is invalid");

        auto lineage_metadata = require_statement(sqlite::prepare(
            opened->get(),
            "SELECT volume_serial, journal_id, root_file_reference, "
            "tree_root_hash, row_count, directory_count, lineage_complete "
            "FROM directory_lineage_metadata WHERE id = 1"));
        if (require_step(lineage_metadata)) {
            const auto metadata_volume =
                parse_decimal(sqlite::text(lineage_metadata, 0));
            const auto metadata_journal =
                parse_decimal(sqlite::text(lineage_metadata, 1));
            const auto metadata_root =
                parse_decimal(sqlite::text(lineage_metadata, 2));
            const auto metadata_hash =
                hash_from_hex(sqlite::text(lineage_metadata, 3));
            const auto metadata_rows =
                parse_decimal(sqlite::text(lineage_metadata, 4));
            const auto directory_count =
                parse_decimal(sqlite::text(lineage_metadata, 5));
            const auto complete = sqlite::integer(lineage_metadata, 6);
            if (!metadata_volume || !metadata_journal || !metadata_root ||
                !metadata_hash || !metadata_rows || !directory_count ||
                (complete != 0 && complete != 1) ||
                *metadata_volume != result.journal.volume_serial ||
                *metadata_journal != result.journal.journal_id ||
                *metadata_root != result.journal.root_file_reference ||
                *metadata_hash != result.tree_root_hash ||
                *metadata_rows != result.row_count) {
                return std::unexpected(
                    "state.db directory lineage binding is invalid");
            }
            auto references = require_statement(
                sqlite::prepare(opened->get(),
                                "SELECT file_reference FROM directory_lineage "
                                "ORDER BY file_reference"));
            while (require_step(references)) {
                const auto reference =
                    parse_decimal(sqlite::text(references, 0));
                if (!reference || *reference == 0)
                    return std::unexpected(
                        "state.db directory lineage is invalid");
                result.directory_file_references.push_back(*reference);
            }
            std::ranges::sort(result.directory_file_references);
            if (std::ranges::adjacent_find(result.directory_file_references) !=
                    result.directory_file_references.end() ||
                *directory_count != result.directory_file_references.size() ||
                (complete == 1 && (result.directory_file_references.empty() ||
                                   !std::ranges::binary_search(
                                       result.directory_file_references,
                                       result.journal.root_file_reference))) ||
                (complete == 0 && !result.directory_file_references.empty())) {
                return std::unexpected(
                    "state.db directory lineage completeness is invalid");
            }
            result.lineage_complete = complete == 1;
        }
        auto loaded = std::optional<ObservationCheckpoint>{std::move(result)};
        platform::perf_trace::finish("checkpoint load wall", checkpoint_trace);
        return loaded;
    } catch (const std::exception& exception) {
        return std::unexpected(
            std::string{"não foi possível carregar o ponto de controle de observação: "} +
            exception.what());
    }
}

bool save_observation_checkpoint(const std::filesystem::path& database_path,
                                 const ObservationCheckpoint& checkpoint) {
    const auto checkpoint_trace = platform::perf_trace::begin();
    platform::perf_trace::count("checkpoint save calls");
    if (!platform::valid_change_journal_checkpoint(checkpoint.journal) ||
        checkpoint.row_count == 0 ||
        (!checkpoint.lineage_complete &&
         !checkpoint.directory_file_references.empty()) ||
        (checkpoint.lineage_complete &&
         (checkpoint.directory_file_references.empty() ||
          std::ranges::find(checkpoint.directory_file_references,
                            checkpoint.journal.root_file_reference) ==
              checkpoint.directory_file_references.end()))) {
        return false;
    }
    try {
        auto opened = detail::open_state_database_readwrite(database_path);
        if (!opened)
            return false;
        auto transaction = sqlite::begin(opened->get());
        if (!transaction ||
            read_schema_version(opened->get()) != schema_version ||
            !has_expected_schema(opened->get())) {
            return false;
        }
        auto insert = require_statement(
            sqlite::prepare(opened->get(),
                            "INSERT OR REPLACE INTO observation_checkpoint "
                            "(id, kind, volume_serial, journal_id, next_usn, "
                            "root_file_reference, tree_root_hash, row_count) "
                            "VALUES (1, ?, ?, ?, ?, ?, ?, ?)"));
        require(sqlite::bind(
            insert, 1, static_cast<std::int64_t>(checkpoint.journal.kind)));
        require(sqlite::bind(
            insert, 2, std::to_string(checkpoint.journal.volume_serial)));
        require(sqlite::bind(
            insert, 3, std::to_string(checkpoint.journal.journal_id)));
        require(sqlite::bind(
            insert, 4, std::to_string(checkpoint.journal.next_usn)));
        require(sqlite::bind(
            insert, 5, std::to_string(checkpoint.journal.root_file_reference)));
        require(sqlite::bind(insert, 6, hash_hex(checkpoint.tree_root_hash)));
        require(sqlite::bind(insert, 7, std::to_string(checkpoint.row_count)));
        require(sqlite::run(insert));
        require(sqlite::execute(opened->get(),
                                "DELETE FROM directory_lineage_metadata"));
        require(
            sqlite::execute(opened->get(), "DELETE FROM directory_lineage"));
        auto lineage = require_statement(sqlite::prepare(
            opened->get(),
            "INSERT INTO directory_lineage_metadata "
            "(id, volume_serial, journal_id, root_file_reference, "
            "tree_root_hash, row_count, directory_count, lineage_complete) "
            "VALUES (1, ?, ?, ?, ?, ?, ?, ?)"));
        require(sqlite::bind(
            lineage, 1, std::to_string(checkpoint.journal.volume_serial)));
        require(sqlite::bind(
            lineage, 2, std::to_string(checkpoint.journal.journal_id)));
        require(sqlite::bind(
            lineage,
            3,
            std::to_string(checkpoint.journal.root_file_reference)));
        require(sqlite::bind(lineage, 4, hash_hex(checkpoint.tree_root_hash)));
        require(sqlite::bind(lineage, 5, std::to_string(checkpoint.row_count)));
        require(sqlite::bind(
            lineage,
            6,
            std::to_string(checkpoint.lineage_complete
                               ? checkpoint.directory_file_references.size()
                               : 0)));
        require(sqlite::bind(lineage, 7, checkpoint.lineage_complete ? 1 : 0));
        require(sqlite::run(lineage));
        if (checkpoint.lineage_complete) {
            auto reference = require_statement(sqlite::prepare(
                opened->get(),
                "INSERT INTO directory_lineage (file_reference) VALUES (?)"));
            for (const auto value : checkpoint.directory_file_references) {
                require(sqlite::bind(reference, 1, std::to_string(value)));
                require(sqlite::run(reference));
                require(sqlite::reset(reference));
            }
        }
        require(sqlite::commit(*transaction));
        platform::perf_trace::finish("checkpoint save wall", checkpoint_trace);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

} // namespace kasumi::state_storage
