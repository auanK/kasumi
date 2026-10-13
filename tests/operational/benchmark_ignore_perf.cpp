#include "core/ignore.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <string>
#include <vector>

namespace {

// Embedded fallback of representative rules in case external corpus is not present
constexpr std::string_view fallback_rules =
    "desktop.ini\n"
    ".git/\n.svn/\n.hg/\n"
    ".idea/\n.vs/\n.vscode/\n"
    "*.code-workspace/\n"
    "build/\nbuild-*/\nDebug/\nRelease/\nbin/\nobj/\n"
    "node_modules/\n.npm/\n.yarn/\n.next/\n"
    "__pycache__/\n.venv/\nvenv/\n*.egg-info/\n"
    "target/\nvendor/\n"
    "*.log\n*.tmp\n*.bak\n"
    "/PowerShell/\n/My Games/\n"
    "Win32/Debug/\nWin32/Release/\n";

} // namespace

int main(int argc, char* argv[]) {
    std::filesystem::path corpus_dir = "D:/a_corp/Documents";
    if (argc > 1) {
        corpus_dir = argv[1];
    }

    // 1. Load rules
    kasumi::ignore::IgnoreList list;
    const std::filesystem::path ignore_path = corpus_dir / ".kasumiignore";
    if (std::filesystem::exists(ignore_path)) {
        list = kasumi::ignore::load_ignore_list(ignore_path);
        std::cout << "[PERF] Loaded " << list.rules.size() << " rules from " << ignore_path << std::endl;
    } else {
        list = kasumi::ignore::parse_ignore_rules(fallback_rules);
        std::cout << "[PERF] Loaded fallback " << list.rules.size() << " rules" << std::endl;
    }

    // 2. Load paths
    std::vector<std::pair<std::string, bool>> paths;
    if (std::filesystem::exists(corpus_dir)) {
        std::error_code ec;
        for (std::filesystem::recursive_directory_iterator it(corpus_dir, std::filesystem::directory_options::skip_permission_denied, ec), end;
             it != end; it.increment(ec)) {
            if (ec) break;
            auto rel = it->path().lexically_relative(corpus_dir).generic_u8string();
            paths.push_back({std::string(rel.begin(), rel.end()), it->is_directory()});
        }
        std::cout << "[PERF] Loaded " << paths.size() << " paths from corpus" << std::endl;
    }

    if (paths.empty()) {
        // Synthetic fallback of 3000 paths
        for (int i = 0; i < 3000; ++i) {
            paths.push_back({"folder_" + std::to_string(i / 10) + "/sub_" + std::to_string(i / 5) + "/file_" + std::to_string(i) + ".txt", false});
        }
        std::cout << "[PERF] Generated " << paths.size() << " synthetic paths" << std::endl;
    }

    // 3. Performance Budget: 300 ms for matching across the entire tree
    constexpr double budget_ms = 300.0;

    std::cout << "[PERF] Running performance test on " << paths.size() << " paths against " << list.rules.size() << " rules..." << std::endl;
    std::cout << "[PERF] Performance Budget Threshold: " << budget_ms << " ms" << std::endl;

    auto t0 = std::chrono::high_resolution_clock::now();
    std::size_t ignored_count = 0;
    for (const auto& [path, is_dir] : paths) {
        if (kasumi::ignore::is_ignored(path, list, is_dir)) {
            ignored_count++;
        }
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    std::cout << "[PERF] Measured time: " << elapsed_ms << " ms (" 
              << (elapsed_ms * 1000.0 / paths.size()) << " us/path, ignored=" << ignored_count << ")" << std::endl;

    if (elapsed_ms > budget_ms) {
        std::cerr << "[FAIL-RED] Performance test FAILED! Elapsed " << elapsed_ms 
                  << " ms exceeded budget of " << budget_ms << " ms (Over budget by " 
                  << (elapsed_ms - budget_ms) << " ms)" << std::endl;
        return 1;
    }

    std::cout << "[PASS-GREEN] Performance test PASSED! Elapsed " << elapsed_ms 
              << " ms is well within budget of " << budget_ms << " ms." << std::endl;
    return 0;
}

