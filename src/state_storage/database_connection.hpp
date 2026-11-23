#ifndef KASUMI_STATE_STORAGE_DATABASE_CONNECTION_HPP
#define KASUMI_STATE_STORAGE_DATABASE_CONNECTION_HPP

#include "platform/path.hpp"
#include "platform/private_storage.hpp"
#include "sqlite/sqlite.hpp"

#include <expected>
#include <filesystem>
#include <string>

namespace kasumi::state_storage::detail {

inline bool missing_file(std::filesystem::file_status status,
                         const std::error_code& error) noexcept {
    return error == std::errc::no_such_file_or_directory ||
           (!error && status.type() == std::filesystem::file_type::not_found);
}

inline std::expected<sqlite::Database, std::string>
open_state_database(const std::filesystem::path& path, int flags) {
    const auto absolute = std::filesystem::absolute(path);
    std::error_code error;
    // Resolve the parent before SQLITE_OPEN_NOFOLLOW so aliases such as macOS
    // /var remain usable. The database and its sidecars must be plain files.
    const auto parent =
        std::filesystem::canonical(absolute.parent_path(), error);
    if (error) {
        return std::unexpected(error.message());
    }
    const auto database = parent / absolute.filename();
    for (const auto suffix : {"", "-wal", "-shm", "-journal"}) {
        const auto entry =
            platform::path::temporary_sibling_path(database, "", suffix);
        const auto status = std::filesystem::symlink_status(entry, error);
        if (*suffix != '\0' && missing_file(status, error)) {
            continue;
        }
        if (error || !std::filesystem::is_regular_file(status) ||
            platform::private_storage::is_reparse_or_symlink(entry)) {
            return std::unexpected(
                error ? error.message()
                      : "database and sidecars must be regular files");
        }
    }
    return sqlite::open(database, flags | SQLITE_OPEN_NOFOLLOW);
}

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
    auto opened = open_state_database(database_path, SQLITE_OPEN_READONLY);
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
    auto opened = open_state_database(database_path, SQLITE_OPEN_READWRITE);
    if (!opened) {
        return opened;
    }
    if (auto wal = require_wal_mode(opened->get()); !wal) {
        return std::unexpected(wal.error());
    }
    auto configured = sqlite::execute(opened->get(),
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
