#ifndef KASUMI_STATE_STORAGE_DATABASE_CONNECTION_HPP
#define KASUMI_STATE_STORAGE_DATABASE_CONNECTION_HPP

#include "sqlite/sqlite.hpp"

#include <expected>
#include <filesystem>
#include <string>

namespace kasumi::state_storage::detail {

// Opens a StateStorage SQLite database connection in read-only mode.
// Does not execute write PRAGMAs or acquire write locks.
inline std::expected<sqlite::Database, std::string>
open_state_database_readonly(const std::filesystem::path& database_path) {
    return sqlite::open(database_path, SQLITE_OPEN_READONLY);
}

// Opens a StateStorage SQLite database connection in read-write mode and applies
// the required StateStorage durability policy (PRAGMA synchronous=NORMAL).
// Fails closed if the database cannot be opened or if the policy cannot be applied.
inline std::expected<sqlite::Database, std::string>
open_state_database_readwrite(const std::filesystem::path& database_path,
                              bool create = false) {
    const int flags = SQLITE_OPEN_READWRITE | (create ? SQLITE_OPEN_CREATE : 0);
    auto opened = sqlite::open(database_path, flags);
    if (!opened) {
        return opened;
    }
    auto configured =
        sqlite::execute(opened->get(), "PRAGMA synchronous=NORMAL");
    if (!configured) {
        return std::unexpected(
            std::string{"não foi possível configurar synchronous no banco: "} +
            configured.error());
    }
    return opened;
}

} // namespace kasumi::state_storage::detail

#endif

