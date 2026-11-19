#include "state_storage/database.hpp"

#include "core/history.hpp"
#include "platform/durability.hpp"
#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"
#include "sqlite/sqlite.hpp"
#include "state_storage/database_connection.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <unordered_map>
#include <utility>

namespace kasumi::state_storage {
namespace {

constexpr int schema_version = 1;
constexpr std::size_t maximum_pending_materializations = 1'000'000;
constexpr std::int64_t kUnifiedMetadataKind = 3;

struct ColumnDefinition {
    std::string_view name;
    std::string_view type;
    bool requires_not_null;
    int primary_key;
};

constexpr ColumnDefinition node_columns[]{
    {"path", "TEXT", false, 1},
    {"hash", "TEXT", true, 0},
    {"size", "INTEGER", true, 0},
    {"mtime", "INTEGER", true, 0},
    {"is_dir", "INTEGER", true, 0},
};

constexpr ColumnDefinition pending_columns[]{
    {"path", "TEXT", true, 1},
    {"hash", "TEXT", true, 0},
    {"size", "INTEGER", true, 0},
    {"mtime", "INTEGER", true, 0},
};

constexpr ColumnDefinition metadata_columns[]{
    {"key", "TEXT", false, 1},
    {"value", "TEXT", true, 0},
};

constexpr ColumnDefinition file_cache_columns[]{
    {"path", "TEXT", true, 1},
    {"hash", "TEXT", true, 0},
    {"size", "INTEGER", true, 0},
    {"fingerprint_kind", "INTEGER", true, 0},
    {"fp0", "TEXT", true, 0},
    {"fp1", "TEXT", true, 0},
    {"fp2", "TEXT", true, 0},
    {"fp3", "TEXT", true, 0},
};

enum class ObjectKind {
    Missing,
    Table,
    Other
};

void require(std::expected<void, std::string> result) {
    if (!result) {
        throw std::runtime_error(result.error());
    }
}

template <typename T> auto sql_arg(const T& value) {
    if constexpr (std::is_same_v<T, bool>) {
        return std::int64_t{value ? 1 : 0};
    } else if constexpr (std::is_integral_v<T>) {
        if constexpr (std::is_unsigned_v<T>) {
            if (value > static_cast<std::uint64_t>(
                            std::numeric_limits<std::int64_t>::max())) {
                throw std::runtime_error(
                    "integer exceeds signed 64-bit SQLite limit");
            }
        }
        return static_cast<std::int64_t>(value);
    } else {
        return std::string_view{value};
    }
}

template <typename... Args>
sqlite::Statement
prepare_stmt(sqlite3* database, std::string_view sql, const Args&... args) {
    auto stmt = sqlite::prepare(database, sql);
    if (!stmt) {
        throw std::runtime_error(stmt.error());
    }
    if constexpr (sizeof...(Args) > 0) {
        int idx = 0;
        (require(sqlite::bind(*stmt, ++idx, sql_arg(args))), ...);
    }
    return std::move(*stmt);
}

template <typename... Args>
void exec_stmt(sqlite::Statement& stmt, const Args&... args) {
    if constexpr (sizeof...(Args) > 0) {
        int idx = 0;
        (require(sqlite::bind(stmt, ++idx, sql_arg(args))), ...);
    }
    require(sqlite::run(stmt));
    require(sqlite::reset(stmt));
}

bool step_stmt(sqlite::Statement& statement) {
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
    auto query = prepare_stmt(
        database,
        "SELECT type FROM sqlite_master WHERE name = ? COLLATE NOCASE",
        name);
    if (!step_stmt(query)) {
        return ObjectKind::Missing;
    }
    return sqlite::text(query, 0) == "table" ? ObjectKind::Table
                                             : ObjectKind::Other;
}

int read_schema_version(sqlite3* database) {
    auto query = prepare_stmt(database, "PRAGMA user_version");
    if (!step_stmt(query)) {
        throw std::runtime_error("could not read schema version");
    }
    return static_cast<int>(sqlite::integer(query, 0));
}

bool has_columns(sqlite3* database,
                 std::string_view table,
                 std::span<const ColumnDefinition> expected) {
    auto query = prepare_stmt(database,
                              "PRAGMA table_xinfo(" + std::string{table} + ")");
    std::uint32_t seen_mask = 0;
    std::size_t count = 0;
    while (step_stmt(query)) {
        if (count == expected.size()) {
            return false;
        }
        const auto name = sqlite::text(query, 1);
        const auto match =
            std::ranges::find(expected, name, &ColumnDefinition::name);
        if (match == expected.end()) {
            return false;
        }
        const auto bit = std::uint32_t{1}
                         << std::distance(expected.begin(), match);
        if ((seen_mask & bit) != 0 ||
            !same_type(sqlite::text(query, 2), match->type) ||
            (match->requires_not_null && sqlite::integer(query, 3) == 0) ||
            sqlite::integer(query, 5) != match->primary_key ||
            sqlite::integer(query, 6) != 0) {
            return false;
        }
        seen_mask |= bit;
        ++count;
    }
    return count == expected.size();
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
        std::error_code ec;
        const auto status = std::filesystem::symlink_status(sidecar, ec);
        if (detail::missing_file(status, ec)) {
            continue;
        }
        if (ec || !std::filesystem::is_regular_file(status) ||
            platform::private_storage::is_reparse_or_symlink(sidecar)) {
            return false;
        }
        if (!platform::private_storage::protect_file(sidecar)) {
            const auto after = std::filesystem::symlink_status(sidecar, ec);
            if (!detail::missing_file(after, ec)) {
                return false;
            }
        }
    }
    return true;
}

bool sidecars_absent(const std::filesystem::path& path) {
    for (const auto& suffix : {"-wal", "-shm", "-journal"}) {
        const auto sidecar =
            platform::path::temporary_sibling_path(path, "", suffix);
        std::error_code ec;
        const auto status = std::filesystem::symlink_status(sidecar, ec);
        if (!detail::missing_file(status, ec)) {
            return false;
        }
    }
    return true;
}

bool has_binary_primary_key(sqlite3* database,
                            std::string_view table,
                            std::string_view column) {
    auto indexes =
        prepare_stmt(database, "PRAGMA index_list(" + std::string{table} + ")");
    std::string primary_key_index;
    while (step_stmt(indexes)) {
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
    auto columns = prepare_stmt(
        database,
        "PRAGMA index_xinfo(" + quote_sql_identifier(primary_key_index) + ")");
    std::size_t key_columns = 0;
    while (step_stmt(columns)) {
        if (sqlite::integer(columns, 5) == 0) {
            continue;
        }
        if (++key_columns != 1 || sqlite::text(columns, 2) != column ||
            sqlite::integer(columns, 3) != 0 ||
            !same_type(sqlite::text(columns, 4), "BINARY")) {
            return false;
        }
    }
    return key_columns == 1;
}

bool valid_table(sqlite3* database,
                 std::string_view name,
                 std::string_view primary_key,
                 std::span<const ColumnDefinition> columns) {
    return object_kind(database, name) == ObjectKind::Table &&
           has_columns(database, name, columns) &&
           has_binary_primary_key(database, name, primary_key);
}

bool has_unexpected_schema_objects(sqlite3* database) {
    auto query = prepare_stmt(
        database,
        "SELECT 1 FROM sqlite_schema WHERE type = 'view' "
        "OR (type = 'table' AND upper(coalesce(sql, '')) LIKE 'CREATE VIRTUAL TABLE%') "
        "LIMIT 1");
    return step_stmt(query);
}

bool has_expected_schema(sqlite3* database) {
    return !has_unexpected_schema_objects(database) &&
           valid_table(database, "nodes", "path", node_columns) &&
           valid_table(
               database, "pending_materializations", "path", pending_columns) &&
           valid_table(database, "metadata", "key", metadata_columns) &&
           valid_table(database, "file_cache", "path", file_cache_columns);
}

bool valid_schema(sqlite3* database) {
    return read_schema_version(database) == schema_version &&
           has_expected_schema(database);
}

void create_schema(sqlite3* database) {
    require(sqlite::execute(database, R"(
        CREATE TABLE nodes (
            path TEXT PRIMARY KEY,
            hash TEXT NOT NULL,
            size INTEGER NOT NULL,
            mtime INTEGER NOT NULL,
            is_dir INTEGER NOT NULL
        );
        CREATE TABLE metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE pending_materializations (
            path TEXT PRIMARY KEY NOT NULL,
            hash TEXT NOT NULL,
            size INTEGER NOT NULL,
            mtime INTEGER NOT NULL
        );
        CREATE TABLE file_cache (
            path TEXT PRIMARY KEY NOT NULL,
            hash TEXT NOT NULL,
            size INTEGER NOT NULL,
            fingerprint_kind INTEGER NOT NULL,
            fp0 TEXT NOT NULL,
            fp1 TEXT NOT NULL,
            fp2 TEXT NOT NULL,
            fp3 TEXT NOT NULL
        );)"));
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
    auto query = prepare_stmt(
        database,
        "SELECT path, hash, size, mtime FROM pending_materializations");
    std::vector<NodeRow> rows;
    while (step_stmt(query)) {
        if (rows.size() == maximum_pending_materializations) {
            throw std::runtime_error("too many pending materializations");
        }
        if (sqlite::is_null(query, 0) || sqlite::is_null(query, 1) ||
            sqlite::is_null(query, 2) || sqlite::is_null(query, 3)) {
            throw std::runtime_error("pending materialization contains NULL");
        }
        const auto hash = hash_from_hex(sqlite::text(query, 1));
        const auto size = sqlite::integer(query, 2);
        if (!hash || size < 0) {
            throw std::runtime_error("invalid pending materialization row");
        }
        rows.push_back(NodeRow{.path = sqlite::text(query, 0),
                               .hash = *hash,
                               .size = static_cast<std::uint64_t>(size),
                               .mtime = sqlite::integer(query, 3),
                               .is_directory = false});
    }
    std::ranges::sort(rows, path_less, &NodeRow::path);
    if (!valid_pending_materializations(tree, rows)) {
        throw std::runtime_error(
            "pending materializations do not match accepted state");
    }
    return rows;
}

template <typename Row, typename UpsertFn>
void apply_delta(sqlite3* database,
                 std::span<const Row> previous,
                 std::span<const Row> current,
                 std::string_view remove_sql,
                 UpsertFn&& upsert_row) {
    std::unordered_map<std::string_view, const Row*> old;
    old.reserve(previous.size());
    for (const auto& row : previous) {
        old.emplace(row.path, &row);
    }
    for (const auto& row : current) {
        const auto found = old.find(row.path);
        if (found == old.end() || *found->second != row) {
            upsert_row(row);
        }
        old.erase(row.path);
    }
    auto remove = prepare_stmt(database, remove_sql);
    for (const auto& [path, row] : old) {
        exec_stmt(remove, path);
    }
}

void write_pending_materializations(
    sqlite3* database, std::span<const NodeRow> pending_materializations) {
    require(sqlite::execute(database, "DELETE FROM pending_materializations"));
    auto insert = prepare_stmt(
        database,
        "INSERT INTO pending_materializations (path, hash, size, mtime) "
        "VALUES (?, ?, ?, ?)");
    for (const auto& row : pending_materializations) {
        exec_stmt(insert, row.path, hash_hex(row.hash), row.size, row.mtime);
    }
}

void write_tree_delta(sqlite3* database,
                      const Snapshot& previous,
                      const Snapshot& current) {
    auto upsert = prepare_stmt(
        database,
        "INSERT INTO nodes (path, hash, size, mtime, is_dir) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(path) DO UPDATE SET hash=excluded.hash, "
        "size=excluded.size, mtime=excluded.mtime, is_dir=excluded.is_dir");
    apply_delta<NodeRow>(database,
                         previous.rows,
                         current.rows,
                         "DELETE FROM nodes WHERE path = ?",
                         [&](const NodeRow& row) {
                             exec_stmt(upsert,
                                       row.path,
                                       hash_hex(row.hash),
                                       row.size,
                                       row.mtime,
                                       row.is_directory);
                         });
}

std::expected<Snapshot, std::string> load_tree(sqlite3* database) {
    try {
        auto query = prepare_stmt(
            database, "SELECT path, hash, size, mtime, is_dir FROM nodes");
        Snapshot snapshot;
        while (step_stmt(query)) {
            if (sqlite::is_null(query, 0) || sqlite::is_null(query, 1) ||
                sqlite::is_null(query, 2) || sqlite::is_null(query, 3) ||
                sqlite::is_null(query, 4)) {
                throw std::runtime_error("node row contains NULL");
            }
            auto hash = hash_from_hex(sqlite::text(query, 1));
            if (!hash) {
                throw std::runtime_error(hash.error());
            }
            const auto size = sqlite::integer(query, 2);
            const auto is_directory = sqlite::integer(query, 4);
            if (size < 0 || is_directory < 0 || is_directory > 1) {
                throw std::runtime_error("invalid node fields");
            }
            snapshot.rows.push_back({.path = sqlite::text(query, 0),
                                     .hash = *hash,
                                     .size = static_cast<std::uint64_t>(size),
                                     .mtime = sqlite::integer(query, 3),
                                     .is_directory = is_directory == 1});
        }
        std::ranges::sort(snapshot.rows, path_less, &NodeRow::path);
        return snapshot;
    } catch (const std::exception& exception) {
        return std::unexpected(
            std::string{"could not load tree from local database: "} +
            exception.what());
    }
}

std::string word_hex(std::uint64_t value) {
    std::array<char, 16> buffer{};
    constexpr char digits[] = "0123456789abcdef";
    for (std::size_t index = buffer.size(); index > 0; --index) {
        buffer[index - 1] = digits[value & 0x0fU];
        value >>= 4;
    }
    return std::string{buffer.data(), buffer.size()};
}

std::optional<std::uint64_t> parse_word(std::string_view value) {
    if (value.size() != 16) {
        return std::nullopt;
    }
    std::uint64_t result = 0;
    const auto parsed =
        std::from_chars(value.data(), value.data() + value.size(), result, 16);
    return parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size()
               ? std::optional<std::uint64_t>{result}
               : std::nullopt;
}

std::vector<FileCacheRow> read_cache_rows(sqlite3* database) {
    auto query = prepare_stmt(
        database,
        "SELECT path, hash, size, fingerprint_kind, fp0, fp1, fp2, fp3 "
        "FROM file_cache ORDER BY path");
    std::vector<FileCacheRow> rows;
    while (step_stmt(query)) {
        if (sqlite::is_null(query, 0) || sqlite::is_null(query, 1) ||
            sqlite::is_null(query, 2) || sqlite::is_null(query, 3) ||
            sqlite::is_null(query, 4) || sqlite::is_null(query, 5) ||
            sqlite::is_null(query, 6) || sqlite::is_null(query, 7)) {
            continue;
        }
        const auto size = sqlite::integer(query, 2);
        const auto kind = sqlite::integer(query, 3);
        const auto words = std::array{parse_word(sqlite::text(query, 4)),
                                      parse_word(sqlite::text(query, 5)),
                                      parse_word(sqlite::text(query, 6)),
                                      parse_word(sqlite::text(query, 7))};
        const auto hash = hash_from_hex(sqlite::text(query, 1));
        if (size < 0 || kind != kUnifiedMetadataKind || !hash || !words[0] ||
            !words[1] || !words[2] || !words[3]) {
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
    std::ranges::sort(rows, path_less, &FileCacheRow::path);
    return rows;
}

void write_cache_delta(sqlite3* database,
                       const std::vector<FileCacheRow>& previous,
                       std::span<const FileCacheRow> current) {
    auto upsert = prepare_stmt(
        database,
        "INSERT INTO file_cache "
        "(path, hash, size, fingerprint_kind, fp0, fp1, fp2, fp3) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(path) DO UPDATE SET hash=excluded.hash, "
        "size=excluded.size, fingerprint_kind=excluded.fingerprint_kind, "
        "fp0=excluded.fp0, fp1=excluded.fp1, fp2=excluded.fp2, "
        "fp3=excluded.fp3");
    apply_delta<FileCacheRow>(database,
                              previous,
                              current,
                              "DELETE FROM file_cache WHERE path = ?",
                              [&](const FileCacheRow& row) {
                                  exec_stmt(upsert,
                                            row.path,
                                            hash_hex(row.hash),
                                            row.size,
                                            kUnifiedMetadataKind,
                                            word_hex(row.volume),
                                            word_hex(row.file_low),
                                            word_hex(row.file_high),
                                            word_hex(static_cast<std::uint64_t>(
                                                row.mtime_nanoseconds)));
                              });
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

std::string encode_lowercase_hex(std::span<const std::uint8_t> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.resize(bytes.size() * 2);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        out[2 * i] = digits[(bytes[i] >> 4) & 0x0fU];
        out[2 * i + 1] = digits[bytes[i] & 0x0fU];
    }
    return out;
}

std::optional<std::vector<std::uint8_t>>
decode_lowercase_hex(std::string_view text) {
    if (text.size() % 2 != 0 || !kasumi::is_lowercase_hex(text)) {
        return std::nullopt;
    }
    const auto nibble = [](char ch) noexcept -> std::uint8_t {
        return ch >= 'a' ? static_cast<std::uint8_t>(ch - 'a' + 10)
                         : static_cast<std::uint8_t>(ch - '0');
    };
    std::vector<std::uint8_t> out(text.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>((nibble(text[2 * i]) << 4) |
                                           nibble(text[2 * i + 1]));
    }
    return out;
}

bool valid_optional_id(std::string_view id) {
    return id.empty() || history::valid_commit_id(id);
}

bool valid_state_metadata(std::uint64_t height,
                          std::string_view commit_id,
                          std::string_view ciphertext_id,
                          std::string_view epoch_id,
                          std::uint64_t epoch_sequence) {
    return height != std::numeric_limits<std::uint64_t>::max() &&
           history::valid_commit_id(commit_id) &&
           valid_optional_id(ciphertext_id) && valid_optional_id(epoch_id) &&
           (!epoch_id.empty() || epoch_sequence == 0);
}

} // namespace

bool initialize(const std::filesystem::path& database_path) {
    try {
        const auto path = std::filesystem::absolute(database_path);
        std::error_code status_error;
        auto status = std::filesystem::symlink_status(path, status_error);
        if (detail::missing_file(status, status_error) &&
            sidecars_absent(path)) {
            const auto id = platform::random::hex_id();
            if (!id) {
                return false;
            }
            const auto staging = platform::path::temporary_sibling_path(
                path, ".", ".init-" + *id);
            auto created =
                platform::private_storage::create_private_file(staging);
            if (!created) {
                return false;
            }
            struct Cleanup {
                platform::private_storage::PrivateOutputFile& file;
                ~Cleanup() noexcept {
                    static_cast<void>(
                        platform::private_storage::remove_private_file_if_owned(
                            file));
                }
            } cleanup{*created};
            platform::private_storage::close_private_file(*created);
            {
                auto opened =
                    detail::open_state_database(staging, SQLITE_OPEN_READWRITE);
                if (!opened) {
                    return false;
                }
                auto transaction = sqlite::begin(opened->get());
                if (!transaction) {
                    return false;
                }
                create_schema(opened->get());
                require(
                    sqlite::execute(opened->get(), "PRAGMA user_version = 1"));
                if (!valid_schema(opened->get())) {
                    return false;
                }
                require(sqlite::commit(*transaction));
                require(detail::require_wal_mode(opened->get(), true));
            }
            // Publish only a complete database that can be moved on its own.
            if (!sidecars_absent(staging) ||
                !platform::durability::sync_file(staging)) {
                return false;
            }
            const auto installed =
                platform::durability::install_without_overwrite(staging, path);
            if (installed) {
                return platform::durability::sync_parent_directory(path)
                    .has_value();
            }
            if (installed.error() != std::errc::file_exists) {
                return false;
            }
            status = std::filesystem::symlink_status(path, status_error);
        } else if (detail::missing_file(status, status_error)) {
            // A concurrent initializer may have published while we checked
            // sidecars.
            status = std::filesystem::symlink_status(path, status_error);
        }
        if (status_error || !std::filesystem::is_regular_file(status) ||
            platform::private_storage::is_reparse_or_symlink(path) ||
            !validate(path) || !platform::private_storage::protect_file(path)) {
            return false;
        }
        auto opened = detail::open_state_database(path, SQLITE_OPEN_READWRITE);
        return opened && detail::require_wal_mode(opened->get(), true) &&
               protect_wal_sidecars(path);
    } catch (const std::exception&) {
        return false;
    }
}

bool validate(const std::filesystem::path& database_path) {
    try {
        {
            auto opened = detail::open_state_database_readonly(database_path);
            if (!opened) {
                return false;
            }
            try {
                return valid_schema(opened->get());
            } catch (const std::runtime_error&) {
                const auto error = sqlite3_extended_errcode(opened->get());
                if (error != SQLITE_READONLY_RECOVERY &&
                    error != SQLITE_READONLY_CANTINIT &&
                    error != SQLITE_READONLY_CANTLOCK &&
                    error != SQLITE_READONLY_ROLLBACK) {
                    return false;
                }
            }
        }
        auto opened =
            detail::open_state_database(database_path, SQLITE_OPEN_READWRITE);
        return opened && valid_schema(opened->get());
    } catch (const std::exception&) {
        return false;
    }
}

std::expected<std::optional<StoredState>, std::string>
load_state(const std::filesystem::path& database_path) {
    try {
        std::error_code filesystem_error;
        const auto status =
            std::filesystem::symlink_status(database_path, filesystem_error);
        if (detail::missing_file(status, filesystem_error)) {
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
        if (!valid_schema(opened->get())) {
            return std::unexpected("state.db schema is not version 1");
        }
        auto metadata = prepare_stmt(
            opened->get(), "SELECT key, value FROM metadata ORDER BY key");
        std::string generation;
        std::string commit_id;
        std::string ciphertext_id;
        std::string epoch_id;
        std::string epoch_sequence;
        std::string storage_manifest_hex;
        std::size_t metadata_count = 0;
        const std::pair<std::string_view, std::string*> fields[]{
            {"generation", &generation},
            {"commit_id", &commit_id},
            {"ciphertext_id", &ciphertext_id},
            {"epoch_id", &epoch_id},
            {"epoch_sequence", &epoch_sequence},
            {"storage_manifest", &storage_manifest_hex},
        };
        while (step_stmt(metadata)) {
            if (sqlite::is_null(metadata, 0) || sqlite::is_null(metadata, 1)) {
                return std::unexpected("state.db contains NULL metadata");
            }
            const auto key = sqlite::text(metadata, 0);
            ++metadata_count;
            const auto it = std::ranges::find(
                fields, key, &std::pair<std::string_view, std::string*>::first);
            if (it == std::end(fields)) {
                return std::unexpected("state.db contains unknown metadata");
            }
            if (!it->second->empty()) {
                return std::unexpected(
                    "state.db contains duplicate metadata: " +
                    std::string{key});
            }
            *it->second = sqlite::text(metadata, 1);
        }
        if (metadata_count == 0) {
            auto nodes =
                prepare_stmt(opened->get(), "SELECT 1 FROM nodes LIMIT 1");
            if (!step_stmt(nodes)) {
                auto pending = prepare_stmt(
                    opened->get(),
                    "SELECT 1 FROM pending_materializations LIMIT 1");
                if (step_stmt(pending)) {
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
        if (epoch_id.empty() != epoch_sequence.empty()) {
            return std::unexpected("state.db Epoch reference is incomplete");
        }
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
        if (!valid_state_metadata(*height,
                                  commit_id,
                                  ciphertext_id,
                                  epoch_id,
                                  parsed_epoch_sequence)) {
            return std::unexpected("state.db state metadata is invalid");
        }
        auto tree = load_tree(opened->get());
        if (!tree) {
            return std::unexpected(tree.error());
        }
        auto pending = load_pending_materializations(opened->get(), *tree);
        if (!valid_snapshot(*tree, false)) {
            return std::unexpected("state.db state is invalid");
        }
        history::StorageManifest manifest;
        if (!storage_manifest_hex.empty()) {
            auto decoded = decode_lowercase_hex(storage_manifest_hex);
            if (!decoded) {
                return std::unexpected("state.db storage_manifest is invalid");
            }
            auto parsed =
                history::deserialize_storage_manifest(*decoded, *tree);
            if (!parsed || parsed->empty()) {
                return std::unexpected("state.db storage_manifest is invalid");
            }
            manifest = std::move(*parsed);
        }
        require(sqlite::commit(*transaction));
        return StoredState{.tree = std::move(*tree),
                           .height = *height,
                           .commit_id = std::move(commit_id),
                           .ciphertext_id = std::move(ciphertext_id),
                           .epoch_id = std::move(epoch_id),
                           .epoch_sequence = parsed_epoch_sequence,
                           .pending_materializations = std::move(pending),
                           .storage_manifest = std::move(manifest)};
    } catch (const std::exception& exception) {
        return std::unexpected(std::string{"could not load state.db: "} +
                               exception.what());
    }
}

bool save_state(const std::filesystem::path& database_path,
                const StoredState& state) {
    if (!valid_snapshot(state.tree, false) ||
        !history::valid_storage_manifest(state.storage_manifest, state.tree) ||
        !valid_pending_materializations(state.tree,
                                        state.pending_materializations) ||
        !valid_state_metadata(state.height,
                              state.commit_id,
                              state.ciphertext_id,
                              state.epoch_id,
                              state.epoch_sequence)) {
        return false;
    }
    std::string encoded_manifest_hex;
    if (!state.storage_manifest.empty()) {
        auto encoded_manifest =
            history::serialize_storage_manifest(state.storage_manifest);
        if (!encoded_manifest) {
            return false;
        }
        encoded_manifest_hex = encode_lowercase_hex(*encoded_manifest);
    }
    try {
        auto opened = detail::open_state_database_readwrite(database_path);
        if (!opened) {
            return false;
        }
        auto transaction = sqlite::begin(opened->get());
        if (!transaction || !valid_schema(opened->get())) {
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
        auto upsert_meta = prepare_stmt(
            opened->get(),
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)");
        exec_stmt(upsert_meta, "generation", std::to_string(state.height));
        exec_stmt(upsert_meta, "commit_id", state.commit_id);
        if (!state.ciphertext_id.empty()) {
            exec_stmt(upsert_meta, "ciphertext_id", state.ciphertext_id);
        }
        if (!state.epoch_id.empty()) {
            exec_stmt(upsert_meta, "epoch_id", state.epoch_id);
            exec_stmt(upsert_meta,
                      "epoch_sequence",
                      std::to_string(state.epoch_sequence));
        }
        if (!encoded_manifest_hex.empty()) {
            exec_stmt(upsert_meta, "storage_manifest", encoded_manifest_hex);
        }
        return protect_wal_sidecars(database_path) &&
               sqlite::commit(*transaction).has_value();
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
        if (detail::missing_file(db_status, error)) {
            return std::vector<FileCacheRow>{};
        }
        auto opened = detail::open_state_database_readonly(database_path);
        if (!opened) {
            return std::unexpected(opened.error());
        }
        if (!valid_schema(opened->get())) {
            return std::vector<FileCacheRow>{};
        }
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
        if (!opened) {
            return false;
        }
        auto transaction = sqlite::begin(opened->get());
        if (!transaction || !valid_schema(opened->get())) {
            return false;
        }
        const auto previous = read_cache_rows(opened->get());
        require(sqlite::execute(
            opened->get(),
            "DELETE FROM file_cache WHERE fingerprint_kind IN (1, 2)"));
        write_cache_delta(opened->get(), previous, rows);
        return protect_wal_sidecars(database_path) &&
               sqlite::commit(*transaction).has_value();
    } catch (const std::exception&) {
        return false;
    }
}

} // namespace kasumi::state_storage
