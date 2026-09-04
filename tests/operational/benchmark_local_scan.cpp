#include "application/observation/scanner.hpp"
#include "core/hasher.hpp"
#include "platform/perf_trace.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
// clang-format off
#include <windows.h>
#include <psapi.h>
// clang-format on
#else
#include <sys/resource.h>
#endif

namespace {

using kasumi::Snapshot;
using kasumi::application::observation::scanner::ScanPolicy;
using kasumi::application::observation::scanner::ScanResult;

struct MemorySample {
    std::uint64_t working_set_bytes = 0;
    std::uint64_t peak_working_set_bytes = 0;
    std::uint64_t private_bytes = 0;
};

struct PhaseResult {
    ScanResult scan;
    std::uint64_t wall_us = 0;
};

MemorySample sample_memory() noexcept {
#if defined(_WIN32)
    PROCESS_MEMORY_COUNTERS_EX counters{};
    counters.cb = sizeof(counters);
    if (GetProcessMemoryInfo(
            GetCurrentProcess(),
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),
            sizeof(counters)) != 0) {
        return {.working_set_bytes =
                    static_cast<std::uint64_t>(counters.WorkingSetSize),
                .peak_working_set_bytes =
                    static_cast<std::uint64_t>(counters.PeakWorkingSetSize),
                .private_bytes =
                    static_cast<std::uint64_t>(counters.PrivateUsage)};
    }
    return {};
#else
    struct rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage) != 0)
        return {};
    return {.working_set_bytes = static_cast<std::uint64_t>(usage.ru_maxrss),
            .peak_working_set_bytes =
                static_cast<std::uint64_t>(usage.ru_maxrss),
            .private_bytes = 0};
#endif
}

bool same_semantic_rows(const Snapshot& left, const Snapshot& right) {
    if (left.rows.size() != right.rows.size())
        return false;
    for (std::size_t index = 0; index < left.rows.size(); ++index) {
        const auto& a = left.rows[index];
        const auto& b = right.rows[index];
        if (a.path != b.path || a.hash != b.hash || a.size != b.size ||
            a.is_directory != b.is_directory)
            return false;
    }
    return true;
}

bool exactly_one_file_changed(const Snapshot& before, const Snapshot& after) {
    if (before.rows.size() != after.rows.size())
        return false;
    std::size_t differences = 0;
    bool target_seen = false;
    for (std::size_t index = 0; index < before.rows.size(); ++index) {
        const auto& a = before.rows[index];
        const auto& b = after.rows[index];
        if (a.path == "file-000000.bin") {
            if (a.path != b.path || a.size != b.size ||
                a.is_directory != b.is_directory || a.hash == b.hash)
                return false;
            ++differences;
            target_seen = true;
        } else if (!a.is_directory &&
                   (a.path != b.path || a.hash != b.hash || a.size != b.size ||
                    a.is_directory != b.is_directory)) {
            return false;
        }
    }
    return target_seen && differences == 1;
}

void print_phase(std::string_view name,
                 const PhaseResult& phase,
                 const MemorySample& memory) {
    std::cout << "PHASE|" << name << "|" << phase.wall_us << "|"
              << phase.scan.snapshot.rows.size() << "|"
              << phase.scan.cache.size() << "|" << memory.working_set_bytes
              << "|" << memory.peak_working_set_bytes << "|"
              << memory.private_bytes << '\n';
}

template <typename Previous>
bool run_phase(const std::filesystem::path& root,
               std::string_view name,
               Previous previous,
               ScanPolicy policy,
               PhaseResult& output) {
    kasumi::platform::perf_trace::reset();
    const auto started = std::chrono::steady_clock::now();
    auto result = kasumi::application::observation::scanner::scan_result(
        root, previous, policy);
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                             std::chrono::steady_clock::now() - started)
                             .count();
    if (!result) {
        std::cerr << "SCAN_ERROR|" << name << "|"
                  << kasumi::application::observation::scanner::describe(
                         result.error())
                  << '\n';
        return false;
    }
    output.scan = std::move(*result);
    output.wall_us = static_cast<std::uint64_t>(elapsed);
    kasumi::platform::perf_trace::report(name);
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: kasumi_benchmark_local_scan ROOT\n";
        return 2;
    }
    const std::filesystem::path root = argv[1];
    PhaseResult current;
    if (!run_phase(root,
                   "path-scale-cold",
                   std::span<const kasumi::state_storage::FileCacheRow>{},
                   ScanPolicy::FullHash,
                   current))
        return 1;
    const auto cold_cache_rows = current.scan.cache.size();
    print_phase("path-scale-cold", current, sample_memory());

    PhaseResult next;
    if (!run_phase(root,
                   "path-scale-warm",
                   current.scan.cache,
                   ScanPolicy::ReuseStrongFingerprint,
                   next))
        return 1;
    const bool cold_equals_warm =
        same_semantic_rows(current.scan.snapshot, next.scan.snapshot);
    current = std::move(next);
    print_phase("path-scale-warm", current, sample_memory());

    {
        std::ofstream changed(root / "file-000000.bin",
                              std::ios::binary | std::ios::trunc);
        if (!changed) {
            std::cerr << "SCAN_ERROR|delta|cannot modify file-000000.bin\n";
            return 1;
        }
        changed.write("R13!", 4);
    }

    if (!run_phase(root,
                   "path-scale-delta",
                   current.scan.cache,
                   ScanPolicy::ReuseStrongFingerprint,
                   next))
        return 1;
    const bool delta_changes_one_file =
        exactly_one_file_changed(current.scan.snapshot, next.scan.snapshot);
    current = std::move(next);
    print_phase("path-scale-delta", current, sample_memory());

    if (!run_phase(root,
                   "path-scale-rewarm",
                   current.scan.cache,
                   ScanPolicy::ReuseStrongFingerprint,
                   next))
        return 1;
    const bool rewarm_equals_delta =
        same_semantic_rows(current.scan.snapshot, next.scan.snapshot);
    current = std::move(next);
    print_phase("path-scale-rewarm", current, sample_memory());

    std::cout << "VALIDATION|" << (cold_equals_warm ? 1 : 0) << "|"
              << (delta_changes_one_file ? 1 : 0) << "|"
              << (rewarm_equals_delta ? 1 : 0) << "|"
              << (cold_cache_rows == current.scan.snapshot.rows.size() - 1 ? 1
                                                                           : 0)
              << '\n';
    return 0;
}
