#include "core/hasher.hpp"
#include "platform/path.hpp"
#include "state_storage/database.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sqlite3.h>
#include <string>
#include <thread>

namespace {

bool signal(const std::filesystem::path& path) {
    std::ofstream stream(path, std::ios::binary);
    return static_cast<bool>(stream);
}

std::filesystem::path path_from_utf8(const char* value) {
    return std::filesystem::path{
        std::u8string{reinterpret_cast<const char8_t*>(value)}};
}

bool wait_for(const std::filesystem::path& path) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds{20};
    while (std::chrono::steady_clock::now() < deadline) {
        std::error_code error;
        if (std::filesystem::exists(path, error)) {
            return !error;
        }
        if (error) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    return false;
}

bool save_height(const std::filesystem::path& database_path,
                 std::uint64_t height,
                 bool pending = false) {
    kasumi::Snapshot tree{{
        {.path = "", .is_directory = true},
        {.path = "snapshot.txt",
         .hash = kasumi::hasher::hash_string(std::to_string(height)),
         .size = height,
         .mtime = static_cast<std::int64_t>(height),
         .is_directory = false},
    }};
    kasumi::finalize_snapshot(tree);
    kasumi::state_storage::StoredState state{
        .tree = std::move(tree),
        .height = height,
        .commit_id =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        .ciphertext_id = {},
        .epoch_id = {},
        .epoch_sequence = 0,
        .pending_materializations = {},
    };
    if (pending) {
        state.pending_materializations.push_back(state.tree.rows[1]);
    }
    return kasumi::state_storage::save_state(database_path, state);
}

bool spill_rollback_transaction(sqlite3* database) {
    if (sqlite3_exec(database,
                     "UPDATE metadata SET value='2' WHERE key='generation'",
                     nullptr,
                     nullptr,
                     nullptr) != SQLITE_OK) {
        return false;
    }
    return sqlite3_db_cacheflush(database) == SQLITE_OK;
}

bool signal_status(const std::filesystem::path& path, const char* status) {
    std::ofstream stream(path, std::ios::binary);
    stream << status;
    return static_cast<bool>(stream);
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 7) {
        return 2;
    }
    const std::string mode{argv[1]};
    const auto database = path_from_utf8(argv[2]);
    const auto ready = path_from_utf8(argv[3]);
    const auto trigger = path_from_utf8(argv[4]);
    const auto done = path_from_utf8(argv[5]);
    const auto release = path_from_utf8(argv[6]);
    const bool write_after_trigger =
        mode == "late-write" || mode == "late-pending";
    const bool rollback_spill = mode == "rollback-spill";
    if (mode != "hold" && mode != "write" && !write_after_trigger &&
        !rollback_spill) {
        return 2;
    }
    if ((write_after_trigger || rollback_spill) &&
        (!signal(ready) || !wait_for(trigger))) {
        return 6;
    }

    if (rollback_spill) {
        sqlite3* raw_writer = nullptr;
        const auto database_utf8 = kasumi::platform::path::to_utf8(database);
        if (sqlite3_open_v2(database_utf8.c_str(),
                            &raw_writer,
                            SQLITE_OPEN_READWRITE,
                            nullptr) != SQLITE_OK) {
            if (raw_writer != nullptr) sqlite3_close(raw_writer);
            return 3;
        }
        std::unique_ptr<sqlite3, int (*)(sqlite3*)> writer{raw_writer,
                                                           sqlite3_close};
        const auto begin_result = sqlite3_exec(
            writer.get(),
            "PRAGMA cache_size=1; PRAGMA cache_spill=ON; BEGIN EXCLUSIVE",
            nullptr,
            nullptr,
            nullptr);
        if (begin_result == SQLITE_BUSY || begin_result == SQLITE_LOCKED) {
            if (!signal_status(done, "blocked") || !wait_for(release)) {
                return 7;
            }
            return 0;
        }
        if (begin_result != SQLITE_OK ||
            !spill_rollback_transaction(writer.get()) ||
            !signal_status(done, "spilled") || !wait_for(release) ||
            sqlite3_exec(writer.get(), "ROLLBACK", nullptr, nullptr, nullptr) !=
                SQLITE_OK) {
            return 8;
        }
        return 0;
    }

    sqlite3* raw_reader = nullptr;
    const auto database_utf8 = kasumi::platform::path::to_utf8(database);
    if (sqlite3_open_v2(database_utf8.c_str(),
                        &raw_reader,
                        SQLITE_OPEN_READONLY,
                        nullptr) != SQLITE_OK) {
        if (raw_reader != nullptr) sqlite3_close(raw_reader);
        return 3;
    }
    std::unique_ptr<sqlite3, int (*)(sqlite3*)> reader{raw_reader,
                                                       sqlite3_close};
    if (sqlite3_exec(reader.get(), "BEGIN", nullptr, nullptr, nullptr) !=
        SQLITE_OK) {
        return 4;
    }
    sqlite3_stmt* statement = nullptr;
    if (sqlite3_prepare_v2(reader.get(),
                           "SELECT count(*) FROM metadata",
                           -1,
                           &statement,
                           nullptr) != SQLITE_OK ||
        sqlite3_step(statement) != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return 5;
    }
    sqlite3_finalize(statement);
    if (!save_height(database,
                     write_after_trigger ? 3 : 2,
                     mode == "late-pending") ||
        (!write_after_trigger && !signal(ready))) {
        return 6;
    }
    if (write_after_trigger && !signal(done)) {
        return 6;
    }
    if (mode == "write" &&
        (!wait_for(trigger) || !save_height(database, 3) || !signal(done))) {
        return 7;
    }
    if (!wait_for(release)) {
        return 7;
    }
    return 0;
}
