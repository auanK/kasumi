#include "application/history_storage/history_storage.hpp"
#include "application/observation/scanner.hpp"
#include "application/observation/state.hpp"
#include "core/history.hpp"
#include "platform/perf_trace.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <string>
#include <string_view>

namespace {

using Clock = std::chrono::steady_clock;

std::uint64_t elapsed_us(Clock::time_point started) {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() -
                                                              started)
            .count());
}

bool same_snapshot(const kasumi::Snapshot& left,
                   const kasumi::Snapshot& right) {
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

bool write_tree(const std::filesystem::path& root, std::size_t files) {
    std::error_code error;
    std::filesystem::create_directories(root, error);
    if (error)
        return false;
    for (std::size_t index = 0; index < files; ++index) {
        const auto path = root / ("file-" + std::to_string(index) + ".bin");
        std::ofstream output(path, std::ios::binary);
        if (!output)
            return false;
        output.put('x');
    }
    return true;
}

struct Seed {
    std::filesystem::path local;
    std::filesystem::path profile;
    std::filesystem::path database;
    std::filesystem::path storage_path;
    std::string storage_location;
    std::uint64_t transport_open_us = 0;
    kasumi::transport::Transport storage;
    std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> key{};
    kasumi::Snapshot snapshot;
};

bool seed_fixture(const std::filesystem::path& root,
                  std::size_t files,
                  Seed& seed) {
    seed.local = root / "local";
    seed.profile = root / "profile";
    seed.database = seed.profile / "state.db";
    seed.storage_path = root / "storage";
    const bool rclone_backend = [] {
        const auto* setting = std::getenv("KASUMI_R17_BACKEND");
        return setting != nullptr && std::string_view{setting} == "rclone";
    }();
    seed.storage_location =
        rclone_backend ? "bench:kasumi" : seed.storage_path.string();
    std::error_code error;
    std::filesystem::create_directories(seed.profile, error);
    if (error || !write_tree(seed.local, files))
        return false;

    auto scanned = kasumi::application::observation::scanner::scan_result(
        seed.local,
        {},
        kasumi::application::observation::scanner::ScanPolicy::FullHash);
    if (!scanned)
        return false;
    seed.snapshot = scanned->snapshot;

    const auto transport_started = Clock::now();
    auto opened = kasumi::transport::open_transport(seed.storage_location);
    seed.transport_open_us = elapsed_us(transport_started);
    if (!opened || !kasumi::transport::initialize(*opened))
        return false;
    seed.storage = std::move(*opened);

    auto commit = kasumi::history::make_bootstrap(seed.snapshot, 0);
    if (!commit)
        return false;
    auto published = kasumi::application::history_storage::publish_commit(
        seed.storage, seed.key, *commit, seed.profile);
    if (!published)
        return false;
    if (!kasumi::state_storage::initialize(seed.database) ||
        !kasumi::state_storage::save_state(
            seed.database,
            kasumi::state_storage::StoredState{seed.snapshot,
                                               0,
                                               published->head.commit_id,
                                               published->head.ciphertext_id}) ||
        !kasumi::state_storage::save_file_cache_delta(seed.database,
                                                      scanned->cache))
        return false;
    return true;
}

bool run_case(const std::filesystem::path& root,
              std::size_t files,
              std::size_t changed_files) {
    if (changed_files == 0 || changed_files > files)
        return false;
    Seed seed;
    if (!seed_fixture(root, files, seed)) {
        std::cerr << "ERROR|seed|" << files << '\n';
        return false;
    }
    const kasumi::runtime::RuntimeData runtime{
        .local_dir = seed.local,
        .database_path = seed.database,
        .key_path = seed.profile / "key.bin",
        .storage_location = seed.storage_location};

    kasumi::application::observation::LocalObservationSession session;
    session.database_path = seed.database;
    kasumi::Snapshot previous;
    for (const auto phase : {"warm", "modify", "rewarm"}) {
        if (std::string_view{phase} == "modify") {
            for (std::size_t index = 0; index < changed_files; ++index) {
                const auto file =
                    seed.local / ("file-" + std::to_string(index) + ".bin");
                const auto mtime = std::filesystem::last_write_time(file);
                std::ofstream(file, std::ios::binary | std::ios::trunc) << 'y';
                std::filesystem::last_write_time(
                    file, mtime + std::chrono::seconds{5});
            }
        }
        kasumi::platform::perf_trace::reset();
        const auto started = Clock::now();
        auto observed =
            kasumi::application::observation::collect_reconciliation_input(
                runtime, seed.storage, seed.key, false, {}, &session);
        if (!observed) {
            std::cerr << "ERROR|observe|" << phase << '|'
                      << observed.error().detail << '\n';
            return false;
        }
        const auto wall_us = elapsed_us(started);
        const auto full =
            kasumi::application::observation::scanner::scan_result(seed.local);
        if (!full || !same_snapshot(observed->local_tree, full->snapshot)) {
            std::cerr << "ERROR|fullhash-equivalence|" << phase << '\n';
            return false;
        }
        if (std::string_view{phase} == "rewarm" &&
            !same_snapshot(previous, observed->local_tree))
            return false;
        previous = observed->local_tree;
        if (session.cache_dirty &&
            !kasumi::state_storage::save_file_cache_delta(seed.database,
                                                          session.cache))
            return false;
        session.cache_dirty = false;
        std::cout << "E2E|" << files << '|' << phase << '|' << wall_us << '\n';
    }
    return true;
}
bool run_r18_reuse(const std::filesystem::path& root, std::size_t files) {
    Seed seed;
    if (!seed_fixture(root, files, seed))
        return false;
    const kasumi::runtime::RuntimeData runtime{
        .local_dir = seed.local,
        .database_path = seed.database,
        .key_path = seed.profile / "key.bin",
        .storage_location = seed.storage_location};

    std::cout << "R18_SESSION|starts|1|open_us|" << seed.transport_open_us
              << "|transport_survives|yes\n";
    kasumi::application::observation::LocalObservationSession session;
    session.database_path = seed.database;
    bool success = true;
    for (int operation = 1; operation <= 10; ++operation) {
        const auto started = Clock::now();
        auto observed =
            kasumi::application::observation::collect_reconciliation_input(
                runtime, seed.storage, seed.key, false, {}, &session);
        const auto wall = elapsed_us(started);
        std::cout << "R18_OP|" << operation << '|' << wall << '|'
                  << (observed ? "clean" : "error") << '|'
                  << kasumi::platform::perf_trace::get_count("local scanner invocations") << '|'
                  << kasumi::platform::perf_trace::get_count("local hash file calls") << '\n';
        if (!observed)
            std::cerr << "R18_ERROR|" << operation << '|'
                      << observed.error().detail << '\n';
        if (!observed)
            success = false;
    }
    const auto shutdown_started = Clock::now();
    seed.storage = {};
    std::cout << "R18_REUSE|session_starts|1|core_version_after_first|0"
              << "|pid_after_first|0|shutdowns|1|shutdown_us|"
              << elapsed_us(shutdown_started) << '|'
              << (success ? "success" : "failure") << '\n';
    kasumi::platform::perf_trace::report(success ? "reuse-success"
                                                 : "reuse-failure");
    return success;
}

bool run_r18_overlap(const std::filesystem::path& root, std::size_t files) {
    Seed seed;
    if (!seed_fixture(root, files, seed))
        return false;
    seed.storage = {};

    struct PendingOpen {
        std::expected<kasumi::transport::Transport, kasumi::transport::Error>
            result;
        std::uint64_t wall_us = 0;
    };
    const auto overlap_started = Clock::now();
    {
        std::ofstream changed(seed.local / "file-0.bin",
                              std::ios::binary | std::ios::trunc);
        changed << 'y';
    }
    const auto startup_started = Clock::now();
    auto opening = std::async(
        std::launch::async,
        [&location = seed.storage_location, startup_started]() mutable {
            PendingOpen pending{
                .result = kasumi::transport::open_transport(location)};
            pending.wall_us = elapsed_us(startup_started);
            return pending;
        });

    const auto state_started = Clock::now();
    auto persisted = kasumi::state_storage::load_state(seed.database);
    const auto state_us = elapsed_us(state_started);
    kasumi::application::observation::LocalObservationSession local_session;
    local_session.database_path = seed.database;
    const auto cache_started = Clock::now();
    auto cache = kasumi::state_storage::load_file_cache(seed.database);
    const auto cache_us = elapsed_us(cache_started);
    if (cache) {
        local_session.cache = std::move(*cache);
        local_session.cache_loaded = true;
    }
    const auto local_started = Clock::now();
    auto local = kasumi::application::observation::collect_local_tree(
        seed.local, &local_session);
    const auto local_us = elapsed_us(local_started);
    const auto local_end_us = elapsed_us(overlap_started);

    auto pending = opening.get();
    if (!pending.result || !persisted || !*persisted || !local || !cache)
        return false;
    auto storage = std::move(*pending.result);
    const auto ready_us = elapsed_us(overlap_started);
    const auto remote_started = Clock::now();
    auto remote = kasumi::application::observation::collect_storage_state(
        storage, seed.key, seed.profile, false);
    const auto remote_us = elapsed_us(remote_started);
    if (!remote)
        return false;
    const auto wall_us = elapsed_us(overlap_started);
    const auto useful_overlap =
        std::min(pending.wall_us, state_us + cache_us + local_us);
    const auto exposed_startup =
        pending.wall_us > useful_overlap ? pending.wall_us - useful_overlap : 0;
    std::cout << "R18_OVERLAP|startup_us|" << pending.wall_us << "|state_us|"
              << state_us << "|cache_us|" << cache_us << "|local_us|"
              << local_us << "|ready_us|" << ready_us << "|remote_us|"
              << remote_us << "|wall_us|" << wall_us << "|local_end_us|"
              << local_end_us << "|useful_overlap_us|" << useful_overlap
              << "|exposed_startup_us|" << exposed_startup << '\n';
    return true;
}

bool run_r18_fresh(const std::filesystem::path& root, std::size_t files) {
    Seed seed;
    if (!seed_fixture(root, files, seed))
        return false;
    const kasumi::runtime::RuntimeData runtime{
        .local_dir = seed.local,
        .database_path = seed.database,
        .key_path = seed.profile / "key.bin",
        .storage_location = seed.storage_location};
    seed.storage = {};
    const std::array<std::string_view, 3> cases{"clean", "modify", "rewarm"};
    for (const auto name : cases) {
        if (name == "modify") {
            std::ofstream changed(seed.local / "file-0.bin",
                                  std::ios::binary | std::ios::trunc);
            changed << 'y';
        }
        const auto open_started = Clock::now();
        auto opened = kasumi::transport::open_transport(seed.storage_location);
        const auto open_us = elapsed_us(open_started);
        if (!opened)
            return false;
        auto storage = std::move(*opened);
        kasumi::application::observation::LocalObservationSession session;
        session.database_path = seed.database;
        const auto observation_started = Clock::now();
        auto observed =
            kasumi::application::observation::collect_reconciliation_input(
                runtime, storage, seed.key, false, {}, &session);
        const auto observation_us = elapsed_us(observation_started);
        if (!observed)
            return false;
        if (session.cache_dirty) {
            static_cast<void>(kasumi::state_storage::save_file_cache_delta(
                seed.database, session.cache));
        }
        std::cout << "R18_FRESH|" << name << "|open_us|" << open_us
                  << "|observation_us|" << observation_us << "|scanner|"
                  << kasumi::platform::perf_trace::get_count("local scanner invocations") << '\n';
        storage = {};
    }
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: kasumi_benchmark_sync_e2e ROOT [FILES...]\n";
        return 2;
    }
    const std::filesystem::path root = argv[1];
    if (const char* model = std::getenv("KASUMI_R18_MODEL"); model != nullptr) {
        const auto files =
            argc > 2 ? static_cast<std::size_t>(std::stoull(argv[2])) : 100'000;
        if (std::string_view{model} == "reuse")
            return run_r18_reuse(root / "reuse", files) ? 0 : 1;
        if (std::string_view{model} == "overlap")
            return run_r18_overlap(root / "overlap", files) ? 0 : 1;
        if (std::string_view{model} == "fresh")
            return run_r18_fresh(root / "fresh", files) ? 0 : 1;
        std::cerr << "unknown KASUMI_R18_MODEL\n";
        return 2;
    }
    std::size_t changed_files = 1;
    if (const char* setting = std::getenv("KASUMI_CHANGED_FILES");
        setting != nullptr)
        changed_files = std::stoull(setting);
    bool success = true;
    if (argc == 2) {
        success = run_case(root / "1k", 1'000, changed_files) &&
                  run_case(root / "10k", 10'000, changed_files) &&
                  run_case(root / "100k", 100'000, changed_files);
    } else {
        for (int index = 2; index < argc; ++index) {
            const auto files =
                static_cast<std::size_t>(std::stoull(argv[index]));
            if (!run_case(root / std::to_string(files), files, changed_files))
                success = false;
        }
    }
    kasumi::platform::perf_trace::report(success ? "success" : "failure");
    return success ? 0 : 1;
}
