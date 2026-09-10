#ifndef KASUMI_SQLITE_SQLITE_HPP
#define KASUMI_SQLITE_SQLITE_HPP

#include "platform/path.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <limits>
#include <memory>
#include <sqlite3.h>
#include <string>
#include <string_view>

namespace kasumi::sqlite {

// SQLite database handle closed automatically.
using Database = std::unique_ptr<sqlite3, int (*)(sqlite3*)>;
// SQLite statement finalized automatically.
using Statement = std::unique_ptr<sqlite3_stmt, int (*)(sqlite3_stmt*)>;
// Rolls back transaction on scope exit if not committed.
using Rollback = std::unique_ptr<sqlite3, void (*)(sqlite3*)>;

// Returns the last database error message.
inline std::string error(sqlite3* database) {
    return database == nullptr ? "sqlite database is unavailable"
                               : sqlite3_errmsg(database);
}

// Converts a filesystem path to UTF-8 for sqlite3_open_v2.
inline std::expected<std::string, std::string>
sqlite_filename(const std::filesystem::path& path) {
    try {
        return platform::path::to_utf8(path);
    } catch (const std::filesystem::filesystem_error&) {
        return std::unexpected(
            "invalid unicode path cannot be converted to UTF-8 for SQLite");
    }
}

// Opens a database with the specified flags.
inline std::expected<Database, std::string>
open(const std::filesystem::path& path, int flags) {
    auto filename = sqlite_filename(path);
    if (!filename) {
        return std::unexpected(filename.error());
    }
    sqlite3* raw = nullptr;
    const auto result =
        sqlite3_open_v2(filename->c_str(), &raw, flags, nullptr);
    Database database{raw, sqlite3_close};
    if (result != SQLITE_OK) {
        return std::unexpected(error(raw));
    }
    return database;
}

// Executes a parameterless SQL command.
inline std::expected<void, std::string> execute(sqlite3* database,
                                                std::string_view sql) {
    char* message = nullptr;
    const std::string statement{sql};
    const auto result =
        sqlite3_exec(database, statement.c_str(), nullptr, nullptr, &message);
    if (result == SQLITE_OK) {
        return {};
    }
    std::string detail = message == nullptr ? error(database) : message;
    sqlite3_free(message);
    return std::unexpected(std::move(detail));
}

// Prepares a reusable SQL statement.
inline std::expected<Statement, std::string> prepare(sqlite3* database,
                                                     std::string_view sql) {
    sqlite3_stmt* raw = nullptr;
    const std::string statement{sql};
    if (sqlite3_prepare_v2(database, statement.c_str(), -1, &raw, nullptr) !=
        SQLITE_OK) {
        return std::unexpected(error(database));
    }
    return Statement{raw, sqlite3_finalize};
}

// Advances the statement; returns true if a row is available.
inline std::expected<bool, std::string> step(Statement& statement) {
    const auto result = sqlite3_step(statement.get());
    if (result == SQLITE_ROW) {
        return true;
    }
    if (result == SQLITE_DONE) {
        return false;
    }
    return std::unexpected(error(sqlite3_db_handle(statement.get())));
}

// Executes a statement that is expected to return no rows.
inline std::expected<void, std::string> run(Statement& statement) {
    auto result = step(statement);
    if (!result) {
        return std::unexpected(result.error());
    }
    if (*result) {
        return std::unexpected("sqlite statement unexpectedly returned a row");
    }
    return {};
}

// Resets the statement and clears its parameter bindings.
inline std::expected<void, std::string> reset(Statement& statement) {
    if (sqlite3_reset(statement.get()) != SQLITE_OK ||
        sqlite3_clear_bindings(statement.get()) != SQLITE_OK) {
        return std::unexpected(error(sqlite3_db_handle(statement.get())));
    }
    return {};
}

// Binds text to a 1-based positional parameter.
inline std::expected<void, std::string>
bind(Statement& statement, int index, std::string_view value) {
    if (sqlite3_bind_text(statement.get(),
                          index,
                          value.data(),
                          static_cast<int>(value.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK) {
        return std::unexpected(error(sqlite3_db_handle(statement.get())));
    }
    return {};
}

// Binds an integer to a 1-based positional parameter.
inline std::expected<void, std::string>
bind(Statement& statement, int index, std::int64_t value) {
    if (sqlite3_bind_int64(statement.get(), index, value) != SQLITE_OK) {
        return std::unexpected(error(sqlite3_db_handle(statement.get())));
    }
    return {};
}

// Reads text; converts NULL to an empty string.
inline std::string text(const Statement& statement, int column) {
    const auto* value = sqlite3_column_text(statement.get(), column);
    const auto size = sqlite3_column_bytes(statement.get(), column);
    return value == nullptr ? std::string{}
                            : std::string{reinterpret_cast<const char*>(value),
                                          static_cast<std::size_t>(size)};
}

// Reads a column as a 64-bit integer.
inline std::int64_t integer(const Statement& statement, int column) noexcept {
    return sqlite3_column_int64(statement.get(), column);
}

// Attempts to roll back the transaction without propagating errors.
inline void rollback(sqlite3* database) noexcept {
    static_cast<void>(
        sqlite3_exec(database, "ROLLBACK", nullptr, nullptr, nullptr));
}

// Begins a transaction with automatic rollback.
inline std::expected<Rollback, std::string>
begin(sqlite3* database, std::string_view mode = "BEGIN IMMEDIATE") {
    auto started = execute(database, mode);
    if (!started) {
        return std::unexpected(started.error());
    }
    return Rollback{database, rollback};
}

// Commits the transaction and disarms the rollback guard.
inline std::expected<void, std::string> commit(Rollback& rollback_guard) {
    auto committed = execute(rollback_guard.get(), "COMMIT");
    if (!committed) {
        return committed;
    }
    static_cast<void>(rollback_guard.release());
    return {};
}

} // namespace kasumi::sqlite

#endif
