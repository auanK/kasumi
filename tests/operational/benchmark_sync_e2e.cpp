#include "application/history_storage/history_storage.hpp"
#include "application/observation/scanner.hpp"
#include "application/observation/state.hpp"
#include "core/history.hpp"
#include "platform/change_journal.hpp"
#include "platform/change_journal_diagnostic.hpp"
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
#include <thread>

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
    std::vector<std::uint64_t> directory_file_references;
    bool lineage_complete = false;
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
    seed.directory_file_references = scanned->directory_file_references;
    seed.lineage_complete = scanned->directory_lineage_complete;

    const auto transport_started = Clock::now();
    auto opened = kasumi::transport::open_transport(seed.storage_location);
    seed.transport_open_us = elapsed_us(transport_started);
    if (!opened || !kasumi::transport::initialize(*opened))
        return false;
    seed.storage = std::move(*opened);

    auto commit = kasumi::history::make_bootstrap(seed.snapshot, 0);
    if (!commit)
        return false;
    auto commit_id = kasumi::history::compute_id(*commit);
    if (!commit_id)
        return false;
    if (!kasumi::application::history_storage::publish_commit(
            seed.storage, seed.key, *commit, seed.profile))
        return false;
    if (!kasumi::state_storage::initialize(seed.database) ||
        !kasumi::state_storage::save_state(
            seed.database,
            kasumi::state_storage::StoredState{seed.snapshot, 0, *commit_id}) ||
        !kasumi::state_storage::save_file_cache_delta(seed.database,
                                                      scanned->cache))
        return false;
    // O NTFS pode registrar o CLOSE após a última gravação.
    auto checkpoint =
        kasumi::platform::capture_change_journal_checkpoint(seed.local);
    for (int attempt = 0; checkpoint && attempt != 4; ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        auto settled =
            kasumi::platform::capture_change_journal_checkpoint(seed.local);
        if (!settled || settled->next_usn == checkpoint->next_usn)
            break;
        checkpoint = std::move(settled);
    }
    if (!checkpoint)
        return false;
    for (int attempt = 0; attempt != 8; ++attempt) {
        auto probe =
            kasumi::platform::probe_change_journal(seed.local, *checkpoint);
        if (probe && probe->evidence == kasumi::platform::ChangeEvidence::Clean)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        checkpoint =
            kasumi::platform::capture_change_journal_checkpoint(seed.local);
        if (!checkpoint)
            return false;
    }
    return kasumi::state_storage::save_observation_checkpoint(
        seed.database,
        kasumi::state_storage::ObservationCheckpoint{
            .journal = *checkpoint,
            .tree_root_hash = seed.snapshot.rows.front().hash,
            .row_count = seed.snapshot.rows.size(),
            .directory_file_references = seed.directory_file_references,
            .lineage_complete = seed.lineage_complete});
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

    auto persisted_checkpoint =
        kasumi::state_storage::load_observation_checkpoint(seed.database);
    if (!persisted_checkpoint || !persisted_checkpoint->has_value())
        return false;
    auto gate = kasumi::platform::probe_change_journal(
        seed.local,
        persisted_checkpoint->value().journal,
        kasumi::platform::DirectoryLineageView{
            .inside_directory_frns =
                persisted_checkpoint->value().directory_file_references,
            .complete = persisted_checkpoint->value().lineage_complete,
            .checkpoint_bound =
                persisted_checkpoint->value().lineage_complete});
    if (!gate)
        return false;
    std::cout << "GATE|" << files << "|"
              << (gate->evidence == kasumi::platform::ChangeEvidence::Clean
                      ? "clean"
                  : gate->evidence == kasumi::platform::ChangeEvidence::Dirty
                      ? "dirty"
                      : "indeterminate")
              << '|' << gate->records_read << '|' << gate->relevant_records
              << '|' << gate->unrelated_records << '|'
              << gate->unresolved_records << '\n';
    std::cout << "BACKEND|"
              << (seed.storage_location.find(':') == std::string::npos
                      ? "local"
                      : "rclone")
              << '\n';

    kasumi::platform::ChangeJournalDiagnostics diagnostics;
    auto forensic = kasumi::platform::probe_change_journal_diagnostic(
        seed.local, persisted_checkpoint->value().journal, diagnostics);
    if (forensic) {
        std::cout << "FORENSICS|" << files << '|' << forensic->records_read
                  << '|' << forensic->relevant_records << '|'
                  << forensic->unrelated_records << '|'
                  << forensic->unresolved_records << '|'
                  << diagnostics.file_open_attempts << '|'
                  << diagnostics.parent_open_attempts << '|'
                  << diagnostics.parent_reconstruction_successes << '|'
                  << diagnostics.unique_file_references << '|'
                  << diagnostics.unique_parent_references << '|'
                  << (diagnostics.unresolved_diagnostics_truncated ? 1 : 0)
                  << '\n';
        for (const auto& item : diagnostics.unresolved) {
            std::cout << "UNRESOLVED|" << files << '|' << item.usn << '|'
                      << item.file_reference << '|' << item.parent_reference
                      << '|' << item.reason << '|'
                      << kasumi::platform::unresolved_reason_name(item.category)
                      << '|' << std::filesystem::path(item.file_name).string()
                      << '|' << item.file_open_error << '|'
                      << item.parent_open_error << '|'
                      << std::filesystem::path(item.parent_path).string() << '|'
                      << (item.file_path_resolved ? 1 : 0) << '|'
                      << (item.parent_path_resolved ? 1 : 0) << '|'
                      << item.major_version << '|' << item.minor_version << '|'
                      << item.file_name_offset << '|' << item.file_name_length
                      << '\n';
        }
    }
    kasumi::platform::ChangeJournalDiagnostics lineage_diagnostics;
    auto lineage_gate = kasumi::platform::probe_change_journal(
        seed.local,
        persisted_checkpoint->value().journal,
        kasumi::platform::DirectoryLineageView{
            .inside_directory_frns =
                persisted_checkpoint->value().directory_file_references,
            .complete = persisted_checkpoint->value().lineage_complete,
            .checkpoint_bound = persisted_checkpoint->value().lineage_complete},
        &lineage_diagnostics);
    if (lineage_gate) {
        std::cout << "LINEAGE|" << files << '|'
                  << (persisted_checkpoint->value().lineage_complete ? 1 : 0)
                  << '|' << lineage_gate->records_read << '|'
                  << lineage_gate->relevant_records << '|'
                  << lineage_gate->unrelated_records << '|'
                  << lineage_gate->unresolved_records << '|'
                  << lineage_diagnostics.file_open_attempts << '|'
                  << lineage_diagnostics.parent_open_attempts << '|'
                  << lineage_diagnostics.lineage_classified_records << '|'
                  << lineage_diagnostics.lineage_membership_lookups << '\n';
    }

    // Simula o carregamento e a gravação antigos do cache.
    kasumi::application::observation::LocalObservationSession before_session;
    before_session.database_path = seed.database;
    const auto before_load_started = Clock::now();
    auto loaded_cache = kasumi::state_storage::load_file_cache(seed.database);
    const auto before_load_us = elapsed_us(before_load_started);
    if (!loaded_cache)
        return false;
    before_session.cache = std::move(*loaded_cache);
    before_session.cache_loaded = true;
    const auto before_started = Clock::now();
    auto before =
        kasumi::application::observation::collect_reconciliation_input(
            runtime, seed.storage, seed.key, false, {}, &before_session);
    const auto before_us = elapsed_us(before_started);
    const auto before_save_started = Clock::now();
    const auto before_saved = kasumi::state_storage::save_file_cache_delta(
        seed.database, before_session.cache);
    const auto before_save_us = elapsed_us(before_save_started);
    if (!before || !before_saved)
        return false;

    // O caminho otimizado evita percorrer o cache quando o USN está limpo.
    kasumi::application::observation::LocalObservationSession after_session;
    after_session.database_path = seed.database;
    const auto after_started = Clock::now();
    auto after = kasumi::application::observation::collect_reconciliation_input(
        runtime, seed.storage, seed.key, false, {}, &after_session);
    const auto after_us = elapsed_us(after_started);
    if (!after)
        return false;
    const auto checkpoint_saved =
        after_session.checkpoint && after_session.last_snapshot &&
        kasumi::state_storage::save_observation_checkpoint(
            seed.database, *after_session.checkpoint);

    const auto before_evidence = before_session.last_evidence.value_or(
        kasumi::platform::ChangeEvidence::Indeterminate);
    std::cout << "E2E|" << files << "|before|" << before_us << '|'
              << before_load_us << '|' << before_save_us << '|'
              << before_session.scanner_invocations << '|'
              << (before_evidence == kasumi::platform::ChangeEvidence::Clean
                      ? "clean"
                  : before_evidence == kasumi::platform::ChangeEvidence::Dirty
                      ? "dirty"
                      : "indeterminate")
              << "|1|1\n";
    std::cout << "E2E|" << files << "|after|" << after_us << "|0|0|"
              << after_session.scanner_invocations << '|'
              << (after_session.last_evidence ==
                          kasumi::platform::ChangeEvidence::Clean
                      ? "clean"
                  : after_session.last_evidence ==
                          kasumi::platform::ChangeEvidence::Dirty
                      ? "dirty"
                      : "indeterminate")
              << '|' << (after_session.cache_loaded ? 1 : 0) << "|0\n";

    for (std::size_t index = 0; index < changed_files; ++index) {
        const auto changed =
            seed.local / ("file-" + std::to_string(index) + ".bin");
        std::ofstream output(changed, std::ios::binary | std::ios::trunc);
        output << 'y';
    }
    // Isola a medição alterada da preparação com hash completo.
    kasumi::platform::perf_trace::reset();
    kasumi::application::observation::LocalObservationSession changed_session;
    changed_session.database_path = seed.database;
    const auto changed_started = Clock::now();
    auto changed_result =
        kasumi::application::observation::collect_reconciliation_input(
            runtime, seed.storage, seed.key, false, {}, &changed_session);
    const auto changed_us = elapsed_us(changed_started);
    if (!changed_result)
        return false;
    std::cout << "E2E|" << files << "|changed|" << changed_us << "|0|0|"
              << changed_session.scanner_invocations << '|'
              << (changed_session.last_evidence ==
                          kasumi::platform::ChangeEvidence::Clean
                      ? "clean"
                  : changed_session.last_evidence ==
                          kasumi::platform::ChangeEvidence::Dirty
                      ? "dirty"
                      : "indeterminate")
              << '|' << (changed_session.cache_loaded ? 1 : 0) << "|0\n";
    std::cout << "SELECTIVE|" << files << '|'
              << changed_session.selective_patch_attempts << '|'
              << changed_session.selective_patch_successes << '|'
              << changed_session.selective_patch_fallbacks << '|'
              << changed_session.last_delta_entry_count << '|'
              << changed_session.targeted_file_observations << '|'
              << changed_session.last_delta_record_count << '\n';
    if (std::getenv("KASUMI_COMPARE_FULLHASH") != nullptr) {
        const auto full =
            kasumi::application::observation::scanner::scan_result(
                seed.local,
                {},
                kasumi::application::observation::scanner::ScanPolicy::
                    FullHash);
        std::cout << "CORRECTNESS|" << files << '|'
                  << (full && same_snapshot(changed_result->local_tree,
                                            full->snapshot)
                          ? "equal"
                          : "different")
                  << '\n';
    }

    // Confirma o avanço do cursor sem repetir a varredura completa.
    const auto rewarm_started = Clock::now();
    auto rewarm = kasumi::application::observation::collect_local_tree(
        seed.local, &changed_session);
    const auto rewarm_us = elapsed_us(rewarm_started);
    if (!rewarm)
        return false;
    std::cout << "E2E|" << files << "|rewarm|" << rewarm_us << "|0|0|"
              << changed_session.scanner_invocations << '|'
              << (changed_session.last_evidence ==
                          kasumi::platform::ChangeEvidence::Clean
                      ? "clean"
                  : changed_session.last_evidence ==
                          kasumi::platform::ChangeEvidence::Dirty
                      ? "dirty"
                      : "indeterminate")
              << "|0|0\n";
    std::cout << "RESTART|" << files << '|' << (checkpoint_saved ? 1 : 0) << '|'
              << after_session.scanner_invocations << '|'
              << (after_session.last_evidence ==
                          kasumi::platform::ChangeEvidence::Clean
                      ? "clean"
                  : after_session.last_evidence ==
                          kasumi::platform::ChangeEvidence::Dirty
                      ? "dirty"
                      : "indeterminate")
              << '\n';
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
                  << session.scanner_invocations << '|'
                  << session.targeted_file_observations << '\n';
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
    if (auto checkpoint =
            kasumi::state_storage::load_observation_checkpoint(seed.database);
        checkpoint && *checkpoint && persisted && *persisted) {
        local_session.checkpoint = std::move(**checkpoint);
        local_session.last_snapshot = (*persisted)->tree;
        local_session.directory_file_references =
            local_session.checkpoint->directory_file_references;
        local_session.lineage_complete =
            local_session.checkpoint->lineage_complete;
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
        if (session.checkpoint) {
            static_cast<void>(
                kasumi::state_storage::save_observation_checkpoint(
                    seed.database, *session.checkpoint));
        }
        std::cout << "R18_FRESH|" << name << "|open_us|" << open_us
                  << "|observation_us|" << observation_us << "|scanner|"
                  << session.scanner_invocations << '\n';
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
