#include "core/hasher.hpp"
#include "core/history.hpp"
#include "platform/perf_trace.hpp"
#include "state_storage/database.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

using kasumi::Hash;
using kasumi::NodeRow;
using kasumi::Snapshot;
using kasumi::state_storage::FileCacheRow;
using Clock = std::chrono::steady_clock;

std::uint64_t elapsed_us(Clock::time_point started) {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() -
                                                              started)
            .count());
}

std::string file_name(std::size_t index, bool long_path) {
    auto number = std::to_string(index);
    if (number.size() < 6)
        number.insert(0, 6 - number.size(), '0');
    if (!long_path)
        return "file-" + number + ".bin";
    return "file-" + number +
           "-long-path-characterization-padding-0123456789abcdef.bin";
}

Snapshot make_snapshot(std::size_t files, bool long_path) {
    Snapshot snapshot;
    snapshot.rows.reserve(files + 1);
    snapshot.rows.push_back(NodeRow{
        .path = "",
        .mtime = std::filesystem::file_time_type(std::chrono::nanoseconds(1)),
        .is_directory = true});
    for (std::size_t index = 0; index < files; ++index) {
        const auto path = file_name(index, long_path);
        const auto content = std::string{"synthetic-content-"} + path;
        snapshot.rows.push_back(
            NodeRow{.path = path,
                    .hash = kasumi::hasher::hash_string(content),
                    .size = content.size(),
                    .mtime = std::filesystem::file_time_type(
                        std::chrono::nanoseconds(index + 2)),
                    .is_directory = false});
    }
    return snapshot;
}

std::vector<FileCacheRow> make_cache(const Snapshot& snapshot) {
    std::vector<FileCacheRow> cache;
    cache.reserve(snapshot.rows.size());
    for (const auto& row : snapshot.rows) {
        if (row.is_directory)
            continue;
        cache.push_back(FileCacheRow{
            .path = row.path,
            .hash = row.hash,
            .size = row.size,
            .fingerprint = kasumi::platform::FileFingerprint{
                .kind =
                    kasumi::platform::FileFingerprintKind::PosixFileIdentity,
                .value = {
                    1, static_cast<std::uint64_t>(cache.size() + 1), 2, 3}}});
    }
    return cache;
}

Snapshot scenario_snapshot(const Snapshot& base, std::string_view scenario) {
    auto snapshot = base;
    if (scenario == "one_changed") {
        auto& row = snapshot.rows[1];
        row.hash = kasumi::hasher::hash_string("changed-content");
        row.size += 1;
        row.mtime += std::chrono::nanoseconds(7);
    } else if (scenario == "one_added") {
        const auto index = snapshot.rows.size() - 1;
        const auto path = file_name(index, false);
        snapshot.rows.push_back(
            NodeRow{.path = path,
                    .hash = kasumi::hasher::hash_string("added-content"),
                    .size = 13,
                    .mtime = std::filesystem::file_time_type(
                        std::chrono::nanoseconds(index + 2)),
                    .is_directory = false});
    } else if (scenario == "one_deleted") {
        if (snapshot.rows.size() > 1)
            snapshot.rows.pop_back();
    } else if (scenario == "hundred_deleted") {
        const auto remove =
            std::min<std::size_t>(100, snapshot.rows.size() - 1);
        snapshot.rows.resize(snapshot.rows.size() - remove);
    }
    kasumi::finalize_snapshot(snapshot);
    return snapshot;
}

bool same_snapshot(const Snapshot& left, const Snapshot& right) {
    if (left.rows.size() != right.rows.size())
        return false;
    for (std::size_t index = 0; index < left.rows.size(); ++index) {
        const auto& a = left.rows[index];
        const auto& b = right.rows[index];
        if (a.path != b.path || a.hash != b.hash || a.size != b.size ||
            a.mtime != b.mtime || a.is_directory != b.is_directory)
            return false;
    }
    return true;
}

bool same_cache(const std::vector<FileCacheRow>& left,
                const std::vector<FileCacheRow>& right) {
    if (left.size() != right.size())
        return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
        const auto& a = left[index];
        const auto& b = right[index];
        if (a.path != b.path || a.hash != b.hash || a.size != b.size ||
            a.fingerprint.kind != b.fingerprint.kind ||
            a.fingerprint.value != b.fingerprint.value)
            return false;
    }
    return true;
}

std::uintmax_t file_size_or_zero(const std::filesystem::path& path) {
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    return error ? 0 : size;
}

void print_state_row(std::size_t files,
                     std::string_view scenario,
                     std::uint64_t seed_us,
                     std::uint64_t load_state_us,
                     std::uint64_t load_cache_us,
                     std::uint64_t save_state_us,
                     std::uint64_t save_cache_us,
                     std::uint64_t state_valid,
                     std::uint64_t cache_valid,
                     const std::filesystem::path& database) {
    const auto wal = database.string() + "-wal";
    const auto shm = database.string() + "-shm";
    std::cout << "STATE|" << files << "|" << scenario << "|" << seed_us << "|"
              << load_state_us << "|" << load_cache_us << "|" << save_state_us
              << "|" << save_cache_us << "|" << (save_state_us + save_cache_us)
              << "|" << file_size_or_zero(database) << "|"
              << file_size_or_zero(wal) << "|" << file_size_or_zero(shm) << "|"
              << state_valid << "|" << cache_valid << '\n';
}

bool run_state(const std::filesystem::path& root, std::size_t files) {
    std::error_code error;
    std::filesystem::create_directories(root, error);
    if (error) {
        std::cerr << "ERROR|cannot create benchmark directory\n";
        return false;
    }
    auto base = make_snapshot(files, false);
    kasumi::finalize_snapshot(base);
    const auto base_cache = make_cache(base);
    constexpr std::array scenarios{"unchanged",
                                   "one_changed",
                                   "one_added",
                                   "one_deleted",
                                   "hundred_deleted"};
    const auto commit_id = std::string(64, 'a');

    for (const auto scenario : scenarios) {
        const auto database = root / ("state-" + std::to_string(files) + "-" +
                                      std::string{scenario} + ".db");
        std::filesystem::remove(database, error);
        std::filesystem::remove(database.string() + "-wal", error);
        std::filesystem::remove(database.string() + "-shm", error);
        const auto seed_started = Clock::now();
        if (!kasumi::state_storage::initialize(database) ||
            !kasumi::state_storage::save_state(
                database,
                kasumi::state_storage::StoredState{base, 1, commit_id}) ||
            !kasumi::state_storage::save_file_cache_delta(database,
                                                          base_cache)) {
            std::cerr << "ERROR|seed failed|" << scenario << '\n';
            return false;
        }
        const auto seed_us = elapsed_us(seed_started);
        if (std::string_view{scenario} == "unchanged")
            print_state_row(
                files, "initial", seed_us, 0, 0, 0, 0, 1, 1, database);

        const auto current = scenario_snapshot(base, scenario);
        const auto current_cache = make_cache(current);
        const auto load_state_started = Clock::now();
        const auto loaded_state = kasumi::state_storage::load_state(database);
        const auto load_state_us = elapsed_us(load_state_started);
        const auto load_cache_started = Clock::now();
        const auto loaded_cache =
            kasumi::state_storage::load_file_cache(database);
        const auto load_cache_us = elapsed_us(load_cache_started);
        if (!loaded_state || !loaded_state->has_value() || !loaded_cache) {
            std::cerr << "ERROR|load failed|" << scenario << '\n';
            return false;
        }

        kasumi::platform::perf_trace::reset();
        const auto save_state_started = Clock::now();
        const auto state_saved = kasumi::state_storage::save_state(
            database,
            kasumi::state_storage::StoredState{current, 1, commit_id});
        const auto save_state_us = elapsed_us(save_state_started);
        kasumi::platform::perf_trace::report(
            "state-db-" + std::to_string(files) + "-" + std::string{scenario} +
            "-save-state");
        const auto state_after = kasumi::state_storage::load_state(database);
        const auto state_valid =
            state_saved && state_after && state_after->has_value() &&
                    same_snapshot(state_after->value().tree, current)
                ? 1U
                : 0U;

        kasumi::platform::perf_trace::reset();
        const auto save_cache_started = Clock::now();
        const auto cache_saved = kasumi::state_storage::save_file_cache_delta(
            database, current_cache);
        const auto save_cache_us = elapsed_us(save_cache_started);
        kasumi::platform::perf_trace::report(
            "state-db-" + std::to_string(files) + "-" + std::string{scenario} +
            "-save-cache");
        const auto cache_after =
            kasumi::state_storage::load_file_cache(database);
        const auto cache_valid = cache_saved && cache_after &&
                                         same_cache(*cache_after, current_cache)
                                     ? 1U
                                     : 0U;
        if (!state_valid || !cache_valid) {
            std::cerr << "ERROR|validation failed|" << scenario << '\n';
            return false;
        }
        print_state_row(files,
                        scenario,
                        seed_us,
                        load_state_us,
                        load_cache_us,
                        save_state_us,
                        save_cache_us,
                        state_valid,
                        cache_valid,
                        database);
    }
    return true;
}

bool same_commit(const kasumi::history::Commit& left,
                 const kasumi::history::Commit& right) {
    return left.height == right.height && left.parents == right.parents &&
           same_snapshot(left.tree, right.tree);
}

bool run_commit(std::size_t files, bool long_path) {
    const auto construction_started = Clock::now();
    auto snapshot = make_snapshot(files, long_path);
    const auto construction_us = elapsed_us(construction_started);
    const auto finalize_started = Clock::now();
    kasumi::finalize_snapshot(snapshot);
    const auto finalize_us = elapsed_us(finalize_started);

    const auto empty = kasumi::history::make_empty_bootstrap();
    if (!empty)
        return false;
    const auto parent_id = kasumi::history::compute_id(*empty);
    if (!parent_id)
        return false;
    const auto make_started = Clock::now();
    const auto commit = kasumi::history::make_commit(
        1, std::vector<std::string>{*parent_id}, std::move(snapshot));
    const auto make_us = elapsed_us(make_started);
    if (!commit)
        return false;
    const auto serialize_started = Clock::now();
    const auto bytes = kasumi::history::serialize(*commit);
    const auto serialize_us = elapsed_us(serialize_started);
    if (!bytes)
        return false;
    const auto id_started = Clock::now();
    const auto id = kasumi::history::compute_id(*commit);
    const auto id_us = elapsed_us(id_started);
    if (!id)
        return false;
    const auto deserialize_started = Clock::now();
    const auto decoded = kasumi::history::deserialize(*bytes);
    const auto deserialize_us = elapsed_us(deserialize_started);
    const auto roundtrip = decoded && same_commit(*decoded, *commit) ? 1U : 0U;
    std::cout << "COMMIT|" << files << "|" << (long_path ? 1 : 0) << "|"
              << construction_us << "|" << finalize_us << "|" << make_us << "|"
              << serialize_us << "|" << bytes->size() << "|" << id_us << "|"
              << deserialize_us << "|" << roundtrip << "|"
              << kasumi::history::maximum_commit_plaintext_size << '\n';
    return roundtrip != 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 4 || argc > 5) {
        std::cerr << "usage: kasumi_benchmark_structural_scale "
                     "state-db ROOT FILES | commit ROOT FILES [long-path]\n";
        return 2;
    }
    const std::string_view mode = argv[1];
    const auto root = std::filesystem::path{argv[2]};
    const auto files = static_cast<std::size_t>(std::stoull(argv[3]));
    if (mode == "state-db")
        return run_state(root, files) ? 0 : 1;
    if (mode == "commit")
        return run_commit(files,
                          argc == 5 && std::string_view{argv[4]} == "long-path")
                   ? 0
                   : 1;
    std::cerr << "ERROR|unknown mode\n";
    return 2;
}
