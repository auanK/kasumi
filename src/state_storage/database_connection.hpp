#ifndef KASUMI_STATE_STORAGE_DATABASE_CONNECTION_HPP
#define KASUMI_STATE_STORAGE_DATABASE_CONNECTION_HPP

#include "sqlite/sqlite.hpp"

#include <expected>
#include <filesystem>
#include <string>

namespace kasumi::state_storage::detail {

inline std::expected<void, std::string> require_wal_mode(sqlite3* database,
                                                         bool enable = false) {
    auto mode = sqlite::prepare(
        database, enable ? "PRAGMA journal_mode=WAL" : "PRAGMA journal_mode");
    if (!mode) {
        return std::unexpected(mode.error());
    }
    const auto row = sqlite::step(*mode);
    if (!row) {
        return std::unexpected(row.error());
    }
    if (!*row || sqlite::text(*mode, 0) != "wal") {
        return std::unexpected("state database journal mode is not WAL");
    }
    return sqlite::run(*mode);
}

// Opens a StateStorage SQLite database connection in read-only mode.
// Does not execute write PRAGMAs or acquire write locks.
inline std::expected<sqlite::Database, std::string>
open_state_database_readonly(const std::filesystem::path& database_path) {
    auto opened = sqlite::open(database_path, SQLITE_OPEN_READONLY);
    if (opened) {
        static_cast<void>(sqlite::execute(
            opened->get(),
            "PRAGMA temp_store=MEMORY; PRAGMA cache_size=-16384;"));
    }
    return opened;
}

// Opens a StateStorage SQLite database connection in read-write mode and
// applies the required StateStorage durability policy (PRAGMA
// synchronous=NORMAL). Fails closed if the database cannot be opened or if the
// policy cannot be applied.
inline std::expected<sqlite::Database, std::string>
open_state_database_readwrite(const std::filesystem::path& database_path) {
    auto opened = sqlite::open(database_path, SQLITE_OPEN_READWRITE);
    if (!opened) {
        return opened;
    }
    if (auto wal = require_wal_mode(opened->get()); !wal) {
        return std::unexpected(wal.error());
    }
    auto configured =
        sqlite::execute(opened->get(),
                        "PRAGMA synchronous=NORMAL; "
                        "PRAGMA temp_store=MEMORY; "
                        "PRAGMA cache_size=-16384;");
    if (!configured) {
        return std::unexpected(
            std::string{"failed to configure database synchronous PRAGMA: "} +
            configured.error());
    }
    static_cast<void>(
        sqlite::execute(opened->get(), "PRAGMA mmap_size=67108864;"));
    return opened;
}

} // namespace kasumi::state_storage::detail

#endif
