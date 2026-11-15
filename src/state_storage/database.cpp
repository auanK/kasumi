#include "state_storage/database.hpp"

#include "core/history.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "sqlite/sqlite.hpp"
#include "state_storage/database_connection.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <optional>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <unordered_map>
#include <utility>

namespace kasumi::state_storage {
namespace {

constexpr int schema_version = 1;
constexpr std::size_t maximum_pending_materializations = 1'000'000;

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

constexpr std::array pending_columns{
    ColumnDefinition{"path", "TEXT", true, 1},
    ColumnDefinition{"hash", "TEXT", true, 0},
    ColumnDefinition{"size", "INTEGER", true, 0},
    ColumnDefinition{"mtime", "INTEGER", true, 0}};

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
        throw std::runtime_error("could not read schema version");
    }
    return static_cast<int>(sqlite::integer(query, 0));
}

template <std::size_t Size>
bool has_columns(sqlite3* database,
                 std::string_view table,
                 const std::array<ColumnDefinition, Size>& expected) {
    std::string pragma{"PRAGMA table_xinfo("};
    pragma.append(table);
    pragma.push_back(')');
    auto query = require_statement(sqlite::prepare(database, pragma));
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

std::string quote_sql_identifier(std::string_view identifier) {
    std::string quoted;
    quoted.reserve(identifier.size() + 2);
    quoted.push_back('"');
    for (const char ch : identifier) {
        if (ch == '"') {
            quoted.push_back('"');
        }
        quoted.push_back(ch);
    }
    quoted.push_back('"');
    return quoted;
}

bool protect_wal_sidecars(const std::filesystem::path& database_path) {
    for (const auto& suffix : {"-wal", "-shm"}) {
        const auto sidecar =
            platform::path::temporary_sibling_path(database_path, "", suffix);
        std::error_code status_error;
        const auto status =
            std::filesystem::symlink_status(sidecar, status_error);
        if (status_error == std::errc::no_such_file_or_directory ||
            (!status_error &&
             status.type() == std::filesystem::file_type::not_found)) {
            continue;
        }
        if (status_error || std::filesystem::is_symlink(status)) {
            return false;
        }
        if (!platform::private_storage::protect_file(sidecar)) {
            return false;
        }
    }
    return true;
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
        database,
        "PRAGMA index_xinfo(" + quote_sql_identifier(primary_key_index) + ")"));
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

template <std::size_t Size>
bool valid_table(sqlite3* database,
                 std::string_view name,
                 std::string_view primary_key,
                 const std::array<ColumnDefinition, Size>& columns) {
    return object_kind(database, name) == ObjectKind::Table &&
           has_columns(database, name, columns) &&
           has_binary_primary_key(database, name, primary_key);
}

bool has_expected_schema(sqlite3* database) {
    return valid_table(database, "nodes", "path", node_columns) &&
           valid_table(
               database, "pending_materializations", "path", pending_columns) &&
           valid_table(database, "metadata", "key", metadata_columns) &&
           valid_table(database, "file_cache", "path", file_cache_columns);
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
    require(sqlite::execute(database, R"(
        CREATE TABLE pending_materializations (
            path TEXT PRIMARY KEY NOT NULL,
            hash TEXT NOT NULL,
            size INTEGER NOT NULL,
            mtime INTEGER NOT NULL
        ))"));
    require(sqlite::execute(
        database,
        "CREATE TABLE file_cache (path TEXT PRIMARY KEY NOT NULL, hash TEXT "
        "NOT NULL, size INTEGER NOT NULL, fingerprint_kind INTEGER NOT NULL, "
        "fp0 TEXT NOT NULL, fp1 TEXT NOT NULL, fp2 TEXT NOT NULL, fp3 TEXT NOT "
        "NULL)"));
}

bool valid_pending_materializations(
    const Snapshot& tree, std::span<const NodeRow> pending_materializations) {
    if (pending_materializations.size() > maximum_pending_materializations) {
        return false;
    }
    const NodeRow* previous = nullptr;
    for (const auto& row : pending_materializations) {
        const auto* accepted = find_row(tree, row.path);
        if (row.is_directory || accepted == nullptr || accepted->is_directory ||
            *accepted != row ||
            row.size > static_cast<std::uint64_t>(
                           std::numeric_limits<std::int64_t>::max()) ||
            (previous != nullptr && !path_less(previous->path, row.path))) {
            return false;
        }
        previous = &row;
    }
    return true;
}

std::vector<NodeRow> load_pending_materializations(sqlite3* database,
                                                   const Snapshot& tree) {
    auto query = require_statement(sqlite::prepare(
        database,
        "SELECT path, hash, size, mtime FROM pending_materializations"));
    std::vector<NodeRow> rows;
    while (require_step(query)) {
        if (rows.size() == maximum_pending_materializations) {
            throw std::runtime_error("too many pending materializations");
        }
        const auto path = sqlite::text(query, 0);
        const auto hash = hash_from_hex(sqlite::text(query, 1));
        const auto size = sqlite::integer(query, 2);
        const auto raw_nanos = sqlite::integer(query, 3);
        if (!hash || size < 0) {
            throw std::runtime_error("invalid pending materialization row");
        }
        rows.push_back(NodeRow{.path = path,
                               .hash = *hash,
                               .size = static_cast<std::uint64_t>(size),
                               .mtime = raw_nanos,
                               .is_directory = false});
    }
    std::ranges::sort(rows, path_less, &NodeRow::path);
    if (!valid_pending_materializations(tree, rows)) {
        throw std::runtime_error(
            "pending materializations do not match accepted state");
    }
    return rows;
}

void write_pending_materializations(
    sqlite3* database, std::span<const NodeRow> pending_materializations) {
    require(sqlite::execute(database, "DELETE FROM pending_materializations"));
    auto insert = require_statement(sqlite::prepare(
        database,
        "INSERT INTO pending_materializations (path, hash, size, mtime) "
        "VALUES (?, ?, ?, ?)"));
    for (const auto& row : pending_materializations) {
        require(sqlite::bind(insert, 1, row.path));
        require(sqlite::bind(insert, 2, hash_hex(row.hash)));
        require(sqlite::bind(insert, 3, static_cast<std::int64_t>(row.size)));
        require(sqlite::bind(insert, 4, row.mtime));
        require(sqlite::run(insert));
        require(sqlite::reset(insert));
    }
}

void bind_node(sqlite::Statement& query, const NodeRow& row) {
    require(sqlite::bind(query, 1, row.path));
    require(sqlite::bind(query, 2, hash_hex(row.hash)));
    require(sqlite::bind(query, 3, static_cast<std::int64_t>(row.size)));
    require(sqlite::bind(query, 4, row.mtime));
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
        } else if (*found->second != row) {
            require(sqlite::bind(update, 1, hash_hex(row.hash)));
            require(
                sqlite::bind(update, 2, static_cast<std::int64_t>(row.size)));
            require(sqlite::bind(update, 3, row.mtime));
            require(sqlite::bind(update, 4, row.is_directory ? 1 : 0));
            require(sqlite::bind(update, 5, row.path));
            require(sqlite::run(update));
            require(sqlite::reset(update));
        }
        old.erase(row.path);
    }
    for (const auto& [path, row] : old) {
        require(sqlite::bind(remove, 1, path));
        require(sqlite::run(remove));
        require(sqlite::reset(remove));
    }
}

std::expected<Snapshot, std::string> load_tree(sqlite3* database) {
    try {
        auto query = require_statement(sqlite::prepare(
            database, "SELECT path, hash, size, mtime, is_dir FROM nodes"));
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
            snapshot.rows.push_back({.path = sqlite::text(query, 0),
                                     .hash = *hash,
                                     .size = static_cast<std::uint64_t>(size),
                                     .mtime = raw_nanos,
                                     .is_directory = is_directory == 1});
        }
        std::ranges::sort(snapshot.rows, path_less, &NodeRow::path);
        return snapshot;
    } catch (const std::exception& exception) {
        return std::unexpected(std::string{"could not load tree "
                                           "from local database: "} +
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

constexpr std::int64_t kUnifiedMetadataKind = 3;

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
        if (size < 0 || kind != kUnifiedMetadataKind ||
            std::ranges::any_of(
                words,
                [](const auto& word) {
                    return !word;
                }) ||
            !hash) {
            continue;
        }
        rows.push_back(FileCacheRow{.path = sqlite::text(query, 0),
                                    .hash = *hash,
                                    .size = static_cast<std::uint64_t>(size),
                                    .mtime_nanoseconds =
                                        static_cast<std::int64_t>(*words[3]),
                                    .volume = *words[0],
                                    .file_low = *words[1],
                                    .file_high = *words[2]});
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
        require(sqlite::bind(upsert, 4, kUnifiedMetadataKind));
        require(sqlite::bind(upsert, 5, word_hex(row.volume)));
        require(sqlite::bind(upsert, 6, word_hex(row.file_low)));
        require(sqlite::bind(upsert, 7, word_hex(row.file_high)));
        require(sqlite::bind(
            upsert,
            8,
            word_hex(static_cast<std::uint64_t>(row.mtime_nanoseconds))));
        require(sqlite::run(upsert));
        require(sqlite::reset(upsert));
    };
    std::unordered_map<std::string_view, const FileCacheRow*> old;
    old.reserve(previous.size());
    for (const auto& row : previous)
        old.emplace(row.path, &row);
    for (const auto& row : current) {
        const auto found = old.find(row.path);
        if (found == old.end() || *found->second != row) {
            upsert_row(row);
        }
        old.erase(row.path);
    }
    for (const auto& [path, row] : old) {
        require(sqlite::bind(remove, 1, path));
        require(sqlite::run(remove));
        require(sqlite::reset(remove));
    }
}

std::optional<std::uint64_t> parse_canonical_u64(std::string_view value) {
    if (value.empty() || (value.size() > 1 && value.front() == '0')) {
        return std::nullopt;
    }
    std::uint64_t result = 0;
    const auto parsed =
        std::from_chars(value.data(), value.data() + value.size(), result, 10);
    return parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size()
               ? std::optional<std::uint64_t>{result}
               : std::nullopt;
}

} // namespace

bool initialize(const std::filesystem::path& database_path) {
    try {
        std::error_code status_error;
        const auto db_status =
            std::filesystem::symlink_status(database_path, status_error);
        const bool database_existed =
            !status_error &&
            db_status.type() != std::filesystem::file_type::not_found;
        if (database_existed) {
            if (std::filesystem::is_symlink(db_status) ||
                !validate(database_path)) {
                return false;
            }
        } else if (status_error &&
                   status_error != std::errc::no_such_file_or_directory) {
            return false;
        } else {
            // Create db.sqlite with restrictive permissions before SQLite
            // opens it so no permissive umask window occurs.
            auto created =
                platform::private_storage::create_private_file(database_path);
            if (!created) {
                return false;
            }
            if (!platform::private_storage::flush_and_close_private_file(
                    *created)) {
                static_cast<void>(
                    platform::private_storage::remove_private_file_if_owned(
                        *created));
                return false;
            }
        }
        auto opened = detail::open_state_database_readwrite(database_path,
                                                            /*create=*/
                                                            !database_existed);
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
            if (database_existed) {
                return false;
            }
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
        return protect_wal_sidecars(database_path);
    } catch (const std::exception&) {
        return false;
    }
}

bool validate(const std::filesystem::path& database_path) {
    try {
        auto opened = detail::open_state_database_readonly(database_path);
        return opened && read_schema_version(opened->get()) == schema_version &&
               has_expected_schema(opened->get());
    } catch (const std::exception&) {
        return false;
    }
}

std::expected<std::optional<StoredState>, std::string>
load_state(const std::filesystem::path& database_path) {
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
        const std::array<
            std::tuple<std::string_view, std::string*, const char*>,
            5>
            fields{{
                {"generation",
                 &generation,
                 "state.db generation is duplicated"},
                {"commit_id", &commit_id, "state.db commit ID is duplicated"},
                {"ciphertext_id",
                 &ciphertext_id,
                 "state.db ciphertext ID is duplicated"},
                {"epoch_id", &epoch_id, "state.db Epoch ID is duplicated"},
                {"epoch_sequence",
                 &epoch_sequence,
                 "state.db Epoch sequence is duplicated"},
            }};
        while (require_step(metadata)) {
            const auto key = sqlite::text(metadata, 0);
            ++metadata_count;
            const auto it =
                std::ranges::find(fields, key, [](const auto& entry) {
                    return std::get<0>(entry);
                });
            if (it == fields.end()) {
                return std::unexpected("state.db contains unknown metadata");
            }
            auto* slot = std::get<1>(*it);
            if (!slot->empty()) {
                return std::unexpected(std::get<2>(*it));
            }
            *slot = sqlite::text(metadata, 1);
        }
        if (metadata_count == 0) {
            auto nodes = require_statement(
                sqlite::prepare(opened->get(), "SELECT 1 FROM nodes LIMIT 1"));
            if (!require_step(nodes)) {
                auto pending = require_statement(sqlite::prepare(
                    opened->get(),
                    "SELECT 1 FROM pending_materializations LIMIT 1"));
                if (require_step(pending)) {
                    return std::unexpected(
                        "state.db has pending rows without accepted state");
                }
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
        auto pending = load_pending_materializations(opened->get(), *tree);
        const auto height = parse_canonical_u64(generation);
        if (!height) {
            return std::unexpected("state.db generation is invalid");
        }
        std::uint64_t parsed_epoch_sequence = 0;
        if (!epoch_sequence.empty()) {
            const auto parsed = parse_canonical_u64(epoch_sequence);
            if (!parsed) {
                return std::unexpected("state.db Epoch sequence is invalid");
            }
            parsed_epoch_sequence = *parsed;
        }
        if (!valid_snapshot(*tree, false) ||
            *height == std::numeric_limits<std::uint64_t>::max()) {
            return std::unexpected("state.db state is invalid");
        }
        require(sqlite::commit(*transaction));
        StoredState state{.tree = std::move(*tree),
                          .height = *height,
                          .commit_id = std::move(commit_id),
                          .ciphertext_id = std::move(ciphertext_id),
                          .epoch_id = std::move(epoch_id),
                          .epoch_sequence = parsed_epoch_sequence,
                          .pending_materializations = std::move(pending)};
        return state;
    } catch (const std::exception& exception) {
        return std::unexpected(std::string{"could not load state.db: "} +
                               exception.what());
    }
}

bool save_state(const std::filesystem::path& database_path,
                const StoredState& state) {
    if (!valid_snapshot(state.tree, false) ||
        !valid_pending_materializations(state.tree,
                                        state.pending_materializations) ||
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
        write_tree_delta(opened->get(), *previous_tree, state.tree);
        write_pending_materializations(opened->get(),
                                       state.pending_materializations);
        require(sqlite::execute(opened->get(),
                                "DELETE FROM metadata WHERE key NOT IN "
                                "('epoch_id', 'epoch_sequence')"));
        auto upsert_meta = require_statement(
            sqlite::prepare(opened->get(),
                            "INSERT OR REPLACE INTO metadata (key, value) "
                            "VALUES (?, ?)"));
        const auto put_meta = [&](std::string_view key,
                                  std::string_view value) {
            require(sqlite::bind(upsert_meta, 1, key));
            require(sqlite::bind(upsert_meta, 2, value));
            require(sqlite::run(upsert_meta));
            require(sqlite::reset(upsert_meta));
        };
        put_meta("generation", std::to_string(state.height));
        put_meta("commit_id", state.commit_id);
        if (!state.ciphertext_id.empty()) {
            put_meta("ciphertext_id", state.ciphertext_id);
        }
        if (!state.epoch_id.empty()) {
            put_meta("epoch_id", state.epoch_id);
            put_meta("epoch_sequence", std::to_string(state.epoch_sequence));
        }
        require(sqlite::commit(*transaction));
        return protect_wal_sidecars(database_path);
    } catch (const std::exception&) {
        return false;
    }
}

std::expected<std::vector<FileCacheRow>, std::string>
load_file_cache(const std::filesystem::path& database_path) {
    try {
        std::error_code error;
        const auto db_status =
            std::filesystem::symlink_status(database_path, error);
        if (error == std::errc::no_such_file_or_directory ||
            (!error &&
             db_status.type() == std::filesystem::file_type::not_found)) {
            return std::vector<FileCacheRow>{};
        }
        if (error || std::filesystem::is_symlink(db_status)) {
            return std::unexpected(error ? error.message()
                                         : "database path is a symlink");
        }
        auto opened = detail::open_state_database_readonly(database_path);
        if (!opened)
            return std::unexpected(opened.error());
        if (read_schema_version(opened->get()) != schema_version ||
            !has_expected_schema(opened->get()))
            return std::vector<FileCacheRow>{};
        return read_cache_rows(opened->get());
    } catch (const std::exception& exception) {
        return std::unexpected(std::string{"could not load file cache: "} +
                               exception.what());
    }
}

bool save_file_cache_delta(const std::filesystem::path& database_path,
                           std::span<const FileCacheRow> rows) {
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
        write_cache_delta(opened->get(), previous, rows);
        require(sqlite::commit(*transaction));
        return protect_wal_sidecars(database_path);
    } catch (const std::exception&) {
        return false;
    }
}

} // namespace kasumi::state_storage
