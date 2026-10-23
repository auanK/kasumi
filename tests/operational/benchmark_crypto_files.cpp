#include "crypto/file_crypto.hpp"
#include "crypto/key_derivation.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cwchar>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
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
#include <unistd.h>
#endif

namespace {

namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

std::uint8_t sink = 0;

constexpr std::size_t no_failure = std::numeric_limits<std::size_t>::max();

struct Sample {
    std::uint64_t wall_us = 0;
};

struct InputFile {
    fs::path source;
    fs::path relative;
};

std::uint64_t elapsed_us(Clock::time_point started) {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(Clock::now() -
                                                              started)
            .count());
}

std::uint64_t peak_working_set() {
#if defined(_WIN32)
    PROCESS_MEMORY_COUNTERS counters{};
    if (::GetProcessMemoryInfo(
            ::GetCurrentProcess(), &counters, sizeof(counters))) {
        return counters.PeakWorkingSetSize;
    }
    return 0;
#else
    rusage usage{};
    if (::getrusage(RUSAGE_SELF, &usage) == 0) {
        return static_cast<std::uint64_t>(usage.ru_maxrss) * 1024U;
    }
    return 0;
#endif
}

std::string path_text(const fs::path& path) {
    return kasumi::platform::path::to_utf8(path);
}

bool is_reparse_point(const fs::file_status& status, const fs::path& path) {
    if (fs::is_symlink(status)) {
        return true;
    }
#if defined(_WIN32)
    const auto attributes = ::GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
    (void)path;
    return false;
#endif
}

bool component_equal(const fs::path& left, const fs::path& right) {
#if defined(_WIN32)
    return ::_wcsicmp(left.native().c_str(), right.native().c_str()) == 0;
#else
    return left == right;
#endif
}

// Component-wise containment; never compare path strings by prefix.
bool path_within(const fs::path& child, const fs::path& parent) {
    auto child_part = child.begin();
    for (auto parent_part = parent.begin(); parent_part != parent.end();
         ++parent_part, ++child_part) {
        if (child_part == child.end() ||
            !component_equal(*child_part, *parent_part)) {
            return false;
        }
    }
    return true;
}

bool path_has_reparse_component(const fs::path& path) {
    fs::path current = path.root_path();
    for (const auto& part : path.relative_path()) {
        current /= part;
        std::error_code error;
        const auto status = fs::symlink_status(current, error);
        if (error || is_reparse_point(status, current)) {
            return true;
        }
    }
    return false;
}

std::vector<fs::path> protected_roots() {
    std::vector<fs::path> roots;
    const auto add = [&roots](const char* value) {
        if (value == nullptr || *value == '\0') {
            return;
        }
        std::error_code error;
        const auto canonical = fs::weakly_canonical(fs::path{value}, error);
        if (!error) {
            roots.push_back(canonical);
        }
    };
#if defined(_WIN32)
    add(std::getenv("SystemRoot"));
    add(std::getenv("windir"));
    add(std::getenv("ProgramFiles"));
    add(std::getenv("ProgramFiles(x86)"));
    add(std::getenv("ProgramData"));
#else
    add("/etc");
    add("/usr");
    add("/bin");
    add("/sbin");
    add("/boot");
    add("/dev");
    add("/proc");
    add("/sys");
    add("/var");
#endif
    return roots;
}

bool is_protected_path(const fs::path& path) {
    if (path.empty() || path == path.root_path() ||
        path.parent_path() == path || path.parent_path() == path.root_path()) {
        return true;
    }
    for (const auto& root : protected_roots()) {
        if (path_within(path, root)) {
            return true;
        }
    }
    return false;
}

bool valid_relative(const fs::path& relative) {
    if (relative.empty() || relative.is_absolute() ||
        relative.has_root_name() || relative.has_root_directory()) {
        return false;
    }
    for (const auto& part : relative) {
        if (part.empty() || part == "." || part == "..") {
            return false;
        }
    }
    return true;
}

bool validate_config(const fs::path& root_argument,
                     std::size_t repetitions,
                     const fs::path& output_argument,
                     fs::path& root,
                     fs::path& output,
                     std::string& error) {
    if (repetitions == 0) {
        error = "repetitions must be at least 1";
        return false;
    }
    if (output_argument.empty()) {
        error = "output directory is empty";
        return false;
    }

    std::error_code status_error;
    const auto root_status = fs::symlink_status(root_argument, status_error);
    if (status_error || !fs::is_directory(root_status)) {
        error = "input root is not an accessible directory: " +
                path_text(root_argument);
        return false;
    }
    if (is_reparse_point(root_status, root_argument)) {
        error = "input root is a symlink or reparse point: " +
                path_text(root_argument);
        return false;
    }

    root = fs::canonical(root_argument, status_error);
    if (status_error) {
        error =
            "could not canonicalize input root: " + path_text(root_argument);
        return false;
    }

    auto absolute_output = fs::absolute(output_argument, status_error);
    if (status_error) {
        error =
            "could not resolve output directory: " + path_text(output_argument);
        return false;
    }
    absolute_output = absolute_output.lexically_normal();
    const auto filename = absolute_output.filename();
    if (filename.empty() || filename == "." || filename == "..") {
        error = "output directory must name a new child directory";
        return false;
    }

    const auto parent = absolute_output.parent_path();
    if (parent.empty()) {
        error = "output directory has no parent";
        return false;
    }
    const auto parent_status = fs::symlink_status(parent, status_error);
    if (status_error || !fs::is_directory(parent_status)) {
        error = "output parent is not an accessible directory: " +
                path_text(parent);
        return false;
    }
    if (is_reparse_point(parent_status, parent) ||
        path_has_reparse_component(parent)) {
        error = "output parent crosses a symlink or reparse point: " +
                path_text(parent);
        return false;
    }
    if (parent == parent.root_path()) {
        error = "refusing to create an output directory at a volume root";
        return false;
    }

    const auto canonical_parent = fs::canonical(parent, status_error);
    if (status_error) {
        error = "could not canonicalize output parent: " + path_text(parent);
        return false;
    }
    output = canonical_parent / filename;

    const auto output_status = fs::symlink_status(output, status_error);
    if (output_status.type() != fs::file_type::not_found) {
        error = "output directory already exists: " + path_text(output);
        return false;
    }
    if (status_error && output_status.type() == fs::file_type::not_found) {
        status_error.clear();
    }
    if (status_error) {
        error = "could not inspect output directory: " + path_text(output);
        return false;
    }

    if (is_protected_path(output)) {
        error = "refusing protected output directory: " + path_text(output);
        return false;
    }
    if (path_within(output, root)) {
        error = "output directory is inside the input root";
        return false;
    }
    if (path_within(root, output)) {
        error = "output directory is an ancestor of the input root";
        return false;
    }
    return true;
}

bool collect_files(const fs::path& root,
                   std::vector<InputFile>& files,
                   std::uint64_t& total_bytes,
                   std::string& error) {
    files.clear();
    total_bytes = 0;

    std::error_code iterator_error;
    fs::recursive_directory_iterator iterator(
        root, fs::directory_options::none, iterator_error);
    if (iterator_error) {
        error = "could not enumerate input root: " + path_text(root);
        return false;
    }

    const fs::recursive_directory_iterator end;
    for (; iterator != end; iterator.increment(iterator_error)) {
        if (iterator_error) {
            error = "input enumeration failed: " + path_text(root);
            return false;
        }
        const auto path = iterator->path();
        std::error_code status_error;
        const auto status = iterator->symlink_status(status_error);
        if (status_error) {
            error = "could not inspect input entry: " + path_text(path);
            return false;
        }
        if (is_reparse_point(status, path)) {
            error =
                "input contains a symlink or reparse point: " + path_text(path);
            return false;
        }
        if (fs::is_directory(status)) {
            continue;
        }
        if (!fs::is_regular_file(status)) {
            error = "input contains an unsupported entry: " + path_text(path);
            return false;
        }

        const auto relative = path.lexically_relative(root);
        if (!valid_relative(relative)) {
            error =
                "input entry cannot be represented safely: " + path_text(path);
            return false;
        }
        std::error_code size_error;
        const auto size = fs::file_size(path, size_error);
        if (size_error) {
            error = "could not read input size: " + path_text(path);
            return false;
        }
        if (size > std::numeric_limits<std::uint64_t>::max() - total_bytes) {
            error = "input size overflows byte counter";
            return false;
        }
        total_bytes += size;
        files.push_back({path, relative});
    }
    if (iterator_error) {
        error = "input enumeration failed: " + path_text(root);
        return false;
    }
    if (files.empty()) {
        error = "no regular files in " + path_text(root);
        return false;
    }

    std::ranges::sort(files, [](const InputFile& left, const InputFile& right) {
        return left.relative.generic_string() < right.relative.generic_string();
    });
    return true;
}

fs::path encrypted_relative(const fs::path& relative) {
    auto result = relative;
    result += ".enc";
    return result;
}

std::string collision_key(const fs::path& relative) {
    std::string key = relative.generic_string();
#if defined(_WIN32)
    for (char& character : key) {
        if (character >= 'A' && character <= 'Z') {
            character = static_cast<char>(character - 'A' + 'a');
        }
    }
#endif
    return key;
}

bool create_new_directory(const fs::path& path, std::string& error) {
    std::error_code create_error;
    if (!fs::create_directory(path, create_error)) {
        error = "could not create new directory: " + path_text(path);
        return false;
    }
    return true;
}

bool ensure_directory(const fs::path& path, std::string& error) {
    std::error_code status_error;
    const auto status = fs::symlink_status(path, status_error);
    if (status.type() != fs::file_type::not_found) {
        if (status_error || !fs::is_directory(status) ||
            is_reparse_point(status, path)) {
            error = "unsafe output path component: " + path_text(path);
            return false;
        }
        return true;
    }

    std::error_code create_error;
    if (fs::create_directory(path, create_error)) {
        return true;
    }
    const auto retry = fs::symlink_status(path, status_error);
    if (!status_error && fs::is_directory(retry) &&
        !is_reparse_point(retry, path)) {
        return true;
    }
    error = "could not create output directory: " + path_text(path);
    return false;
}

bool ensure_directories(const fs::path& run_directory,
                        const fs::path& parent,
                        std::string& error) {
    if (parent == run_directory) {
        return true;
    }
    const auto relative = parent.lexically_relative(run_directory);
    if (!valid_relative(relative)) {
        error = "output parent escapes run directory: " + path_text(parent);
        return false;
    }
    fs::path current = run_directory;
    for (const auto& part : relative) {
        current /= part;
        if (!ensure_directory(current, error)) {
            return false;
        }
    }
    return true;
}

bool prepare_run(const fs::path& run_directory,
                 const std::vector<InputFile>& files,
                 std::vector<fs::path>& outputs,
                 std::string& error) {
    if (!create_new_directory(run_directory, error)) {
        return false;
    }

    outputs.clear();
    outputs.reserve(files.size());
    std::set<std::string> collision_keys;
    for (const auto& file : files) {
        const auto relative = encrypted_relative(file.relative);
        if (!valid_relative(relative)) {
            error = "output path cannot be represented safely: " +
                    path_text(file.relative);
            return false;
        }
        if (!collision_keys.insert(collision_key(relative)).second) {
            error = "output path collision for: " + path_text(file.relative);
            return false;
        }
        const auto output = (run_directory / relative).lexically_normal();
        if (!path_within(output, run_directory)) {
            error = "output path escapes run directory: " +
                    path_text(file.relative);
            return false;
        }
        outputs.push_back(output);
    }

    for (const auto& output : outputs) {
        if (!ensure_directories(run_directory, output.parent_path(), error)) {
            return false;
        }
        std::error_code status_error;
        const auto status = fs::symlink_status(output, status_error);
        if (status.type() != fs::file_type::not_found) {
            error =
                "refusing to overwrite existing output: " + path_text(output);
            return false;
        }
        if (status_error && status.type() == fs::file_type::not_found) {
            status_error.clear();
        }
        if (status_error) {
            error = "could not inspect output path: " + path_text(output);
            return false;
        }
    }
    return true;
}

std::string run_name(std::size_t repetition) {
    std::ostringstream name;
    name << "run-" << std::setw(3) << std::setfill('0') << repetition;
    return name.str();
}

void print_result(std::string_view mode,
                  std::size_t files,
                  std::uint64_t bytes,
                  std::vector<Sample> samples) {
    std::ranges::sort(samples, {}, &Sample::wall_us);
    const auto median = samples[samples.size() / 2].wall_us;
    const auto throughput = median == 0
                                ? 0.0
                                : static_cast<double>(bytes) /
                                      (static_cast<double>(median) / 1e6) / 1e6;
    std::cout << "CRYPTO|" << mode << '|' << files << '|' << bytes << '|'
              << median << '|' << samples.front().wall_us << '|'
              << samples.back().wall_us << '|' << throughput << '\n';
}

bool run_benchmark(const fs::path& root_argument,
                   std::size_t repetitions,
                   const fs::path& output_argument,
                   std::size_t fail_after,
                   bool print,
                   std::string& error) {
    fs::path root;
    fs::path output;
    if (!validate_config(
            root_argument, repetitions, output_argument, root, output, error)) {
        return false;
    }

    std::vector<InputFile> files;
    std::uint64_t bytes = 0;
    if (!collect_files(root, files, bytes, error)) {
        return false;
    }

    if (!create_new_directory(output, error)) {
        return false;
    }
    if (print) {
        std::cout << "OUTPUT|" << path_text(output) << '\n';
    }

    const std::array<std::uint8_t, kasumi::crypto::KEY_SIZE> master_key{};
    std::vector<Sample> full_samples;
    std::vector<Sample> decrypt_samples;
    std::vector<Sample> kdf_samples;
    full_samples.reserve(repetitions);
    decrypt_samples.reserve(repetitions);
    kdf_samples.reserve(repetitions);

    for (std::size_t repetition = 0; repetition < repetitions; ++repetition) {
        const auto run_directory = output / run_name(repetition + 1);
        std::vector<fs::path> outputs;
        if (!prepare_run(run_directory, files, outputs, error)) {
            return false;
        }

        const auto started = Clock::now();
        for (std::size_t index = 0; index < files.size(); ++index) {
            if (index == fail_after) {
                error = "injected failure before file " + std::to_string(index);
                return false;
            }
            const auto encrypted = kasumi::crypto::encrypt_file_with_hashes(
                files[index].source, outputs[index], master_key);
            if (!encrypted) {
                error = "encryption failed: " + path_text(files[index].source);
                return false;
            }
        }
        full_samples.push_back({elapsed_us(started)});

        const auto decrypt_started = Clock::now();
        for (std::size_t index = 0; index < files.size(); ++index) {
            auto decrypted = outputs[index];
            decrypted += ".dec";
            if (!kasumi::crypto::decrypt_file(
                    outputs[index], decrypted, master_key)) {
                error = "decryption failed: " + path_text(outputs[index]);
                return false;
            }
            std::error_code remove_error;
            fs::remove(decrypted, remove_error);
            if (remove_error) {
                error = "could not remove decrypted output: " +
                        path_text(decrypted);
                return false;
            }
        }
        decrypt_samples.push_back({elapsed_us(decrypt_started)});

        const auto kdf_started = Clock::now();
        for (std::size_t index = 0; index < files.size(); ++index) {
            const auto key = kasumi::crypto::derive_key(
                master_key, kasumi::crypto::KeyPurpose::Content);
            sink ^= key.front();
        }
        kdf_samples.push_back({elapsed_us(kdf_started)});
    }

    if (print) {
        std::cout << "TRACE|enabled|"
                  << (kasumi::platform::perf_trace::enabled() ? 1 : 0) << '\n';
        print_result("encrypt_with_hashes", files.size(), bytes, full_samples);
        print_result("decrypt", files.size(), bytes, decrypt_samples);
        print_result("derive_key", files.size(), bytes, kdf_samples);
        std::cout << "MEMORY|peak_working_set_bytes|" << peak_working_set()
                  << '\n';
        std::cout << "SCRATCH|bytes|"
                  << kasumi::platform::perf_trace::get_count(
                         "file encryption scratch bytes")
                  << '\n';
        std::cout << "WIPE|bytes|"
                  << kasumi::platform::perf_trace::get_count(
                         "file encryption wipe bytes")
                  << '\n';
        std::cout << "SCRATCH|decryption|bytes|"
                  << kasumi::platform::perf_trace::get_count(
                         "file decryption scratch bytes")
                  << '\n';
        std::cout << "WIPE|decryption|bytes|"
                  << kasumi::platform::perf_trace::get_count(
                         "file decryption wipe bytes")
                  << '\n';
    }
    return true;
}

std::string read_text(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

bool expect(bool condition, std::string_view label, std::string& failure) {
    if (!condition) {
        failure = std::string(label);
        std::cerr << "FAIL|" << label << '\n';
        return false;
    }
    std::cout << "PASS|" << label << '\n';
    return true;
}

struct TemporaryRoot {
    fs::path path;
    bool ready = false;

    static fs::path candidate() {
        std::error_code error;
        const auto base = fs::temp_directory_path(error);
        if (error) {
            return {};
        }
#if defined(_WIN32)
        const auto process =
            static_cast<unsigned long>(::GetCurrentProcessId());
#else
        const auto process = static_cast<unsigned long>(::getpid());
#endif
        const auto stamp =
            static_cast<std::uint64_t>(Clock::now().time_since_epoch().count());
        return base / ("kasumi-benchmark-selftest-" + std::to_string(process) +
                       "-" + std::to_string(stamp));
    }

    TemporaryRoot() : TemporaryRoot(candidate()) {
    }

    explicit TemporaryRoot(fs::path reserved) : path(std::move(reserved)) {
        std::error_code error;
        ready = fs::create_directory(path, error);
    }

    ~TemporaryRoot() {
        if (path.empty() || !ready) {
            return;
        }
        std::error_code error;
        const auto temp = fs::temp_directory_path(error);
        if (error) {
            return;
        }
        std::error_code equivalent_error;
        const auto same_parent =
            fs::equivalent(path.parent_path(), temp, equivalent_error);
        const auto name = path.filename().string();
        // Cleanup is limited to the unique root this self-test created.
        if (!equivalent_error && same_parent &&
            name.starts_with("kasumi-benchmark-selftest-")) {
            fs::remove_all(path, error);
        }
    }
};

bool create_junction(const fs::path& link, const fs::path& target) {
#if defined(_WIN32)
    const std::string command = "cmd.exe /c mklink /J \"" + path_text(link) +
                                "\" \"" + path_text(target) + "\" >nul 2>nul";
    return std::system(command.c_str()) == 0;
#else
    (void)link;
    (void)target;
    return false;
#endif
}

bool self_test_symlinks(const fs::path& base, std::string& failure) {
    const auto outside = base / "outside";
    if (!fs::create_directories(outside) ||
        !fs::create_directories(base / "link-input")) {
        failure = "could not create symlink test directories";
        return false;
    }
    const auto secret = outside / "secret.bin";
    {
        std::ofstream output(secret, std::ios::binary);
        output << "outside";
    }

    bool tested_link = false;
    std::string error;
    std::error_code link_error;
    fs::create_symlink(secret, base / "link-input" / "link.bin", link_error);
    if (!link_error) {
        tested_link = true;
        if (!expect(!run_benchmark(base / "link-input",
                                   1,
                                   base / "link-output",
                                   no_failure,
                                   false,
                                   error),
                    "symlink input is rejected",
                    failure)) {
            return false;
        }
        if (read_text(secret) != "outside") {
            failure = "symlink target was modified";
            return false;
        }
    } else {
        std::cout << "SKIP|symlink-file|" << link_error.message() << '\n';
    }

    const auto target = base / "link-target";
    if (!fs::create_directories(target)) {
        failure = "could not create output target";
        return false;
    }
    std::error_code directory_link_error;
    fs::create_directory_symlink(
        target, base / "link-parent", directory_link_error);
    bool parent_link = !directory_link_error;
    if (!parent_link) {
        parent_link = create_junction(base / "link-parent", target);
    }
    if (parent_link) {
        tested_link = true;
        if (!fs::create_directories(base / "plain-input")) {
            failure = "could not create plain input";
            return false;
        }
        {
            std::ofstream output(base / "plain-input" / "a.bin",
                                 std::ios::binary);
            output << "plain";
        }
        if (!expect(!run_benchmark(base / "plain-input",
                                   1,
                                   base / "link-parent" / "nested",
                                   no_failure,
                                   false,
                                   error),
                    "symlink or junction output parent is rejected",
                    failure)) {
            return false;
        }
        if (fs::exists(target / "nested")) {
            failure = "symlink or junction output parent was written through";
            return false;
        }
    } else {
        std::cout << "SKIP|junction|" << directory_link_error.message() << '\n';
    }

    const auto outside_root = base / "outside-root";
    if (fs::create_directories(outside_root)) {
        {
            std::ofstream output(outside_root / "a.bin", std::ios::binary);
            output << "outside-root";
        }
        if (create_junction(base / "link-root", outside_root)) {
            tested_link = true;
            if (!expect(!run_benchmark(base / "link-root",
                                       1,
                                       base / "link-root-output",
                                       no_failure,
                                       false,
                                       error),
                        "junction input root is rejected",
                        failure)) {
                return false;
            }
            if (read_text(outside_root / "a.bin") != "outside-root") {
                failure = "junction input root target was modified";
                return false;
            }
        } else {
            std::cout << "SKIP|junction-root|creation unavailable\n";
        }
    } else {
        failure = "could not create junction root target";
        return false;
    }

    if (!tested_link) {
        std::cout << "SKIP|links|no symlink or junction support\n";
    }
    std::error_code cleanup_error;
    fs::remove(base / "link-parent", cleanup_error);
    fs::remove(base / "link-root", cleanup_error);
    return true;
}

bool run_self_test(std::string& failure) {
    TemporaryRoot temporary;
    if (!temporary.ready) {
        failure = "could not create temporary self-test root";
        return false;
    }
    const auto& base = temporary.path;

    auto collision = TemporaryRoot::candidate();
    collision += "-occupied";
    std::error_code collision_error;
    if (!expect(!collision.empty() &&
                    fs::create_directory(collision, collision_error),
                "collision root is prepared",
                failure)) {
        return false;
    }
    {
        std::ofstream sentinel(collision / "sentinel.txt", std::ios::binary);
        sentinel << "keep";
    }
    bool collision_ready = true;
    {
        TemporaryRoot occupied(collision);
        collision_ready = occupied.ready;
    }
    const auto collision_preserved =
        expect(!collision_ready, "occupied root is not owned", failure) &&
        expect(read_text(collision / "sentinel.txt") == "keep",
               "occupied sentinel is preserved",
               failure);
    std::error_code collision_cleanup_error;
    fs::remove(collision / "sentinel.txt", collision_cleanup_error);
    fs::remove(collision, collision_cleanup_error);
    if (!collision_preserved) {
        return false;
    }

    auto owned_path = TemporaryRoot::candidate();
    owned_path += "-owned";
    {
        TemporaryRoot owned(owned_path);
        if (!expect(owned.ready, "owned root is created", failure)) {
            return false;
        }
        std::ofstream sentinel(owned_path / "sentinel.txt", std::ios::binary);
        sentinel << "keep";
    }
    if (!expect(!fs::exists(owned_path), "owned root is cleaned", failure)) {
        return false;
    }

    if (!expect(fs::create_directories(base / "a" / "input") &&
                    fs::create_directories(base / "a" / "output"),
                "scenario A directories",
                failure)) {
        return false;
    }
    {
        std::ofstream input(base / "a" / "input" / "a.bin", std::ios::binary);
        input << "input";
        std::ofstream sentinel(base / "a" / "output" / "sentinel.txt",
                               std::ios::binary);
        sentinel << "keep";
    }
    std::string error;
    if (!expect(!run_benchmark(base / "a" / "input",
                               1,
                               base / "a" / "output",
                               no_failure,
                               false,
                               error),
                "A existing output is rejected",
                failure) ||
        !expect(read_text(base / "a" / "output" / "sentinel.txt") == "keep",
                "A sentinel is preserved",
                failure)) {
        return false;
    }
    if (!expect(fs::create_directories(base / "a-empty"),
                "A empty output directory",
                failure) ||
        !expect(!run_benchmark(base / "a" / "input",
                               1,
                               base / "a-empty",
                               no_failure,
                               false,
                               error),
                "A empty existing output is rejected",
                failure) ||
        !expect(fs::is_empty(base / "a-empty"),
                "A empty output is untouched",
                failure)) {
        return false;
    }

    if (!fs::create_directories(base / "b" / "input")) {
        failure = "scenario B directories";
        return false;
    }
    {
        std::ofstream input(base / "b" / "input" / "a.bin", std::ios::binary);
        input << "input";
    }
    if (!expect(!run_benchmark(base / "b" / "input",
                               1,
                               base / "b" / "input",
                               no_failure,
                               false,
                               error),
                "B input equals output is rejected",
                failure) ||
        !expect(read_text(base / "b" / "input" / "a.bin") == "input",
                "B input is preserved",
                failure)) {
        return false;
    }

    if (!fs::create_directories(base / "c" / "input")) {
        failure = "scenario C directories";
        return false;
    }
    {
        std::ofstream input(base / "c" / "input" / "a.bin", std::ios::binary);
        input << "input";
    }
    if (!expect(
            !run_benchmark(
                base / "c" / "input", 1, base / "c", no_failure, false, error),
            "C output ancestor is rejected",
            failure) ||
        !expect(read_text(base / "c" / "input" / "a.bin") == "input",
                "C input is preserved",
                failure)) {
        return false;
    }

    if (!fs::create_directories(base / "d" / "input")) {
        failure = "scenario D directories";
        return false;
    }
    {
        std::ofstream input(base / "d" / "input" / "a.bin", std::ios::binary);
        input << "input";
    }
    if (!expect(!run_benchmark(base / "d" / "input",
                               1,
                               base / "d" / "input" / "output",
                               no_failure,
                               false,
                               error),
                "D output descendant is rejected",
                failure) ||
        !expect(!fs::exists(base / "d" / "input" / "output"),
                "D no descendant was created",
                failure) ||
        !expect(read_text(base / "d" / "input" / "a.bin") == "input",
                "D input is preserved",
                failure)) {
        return false;
    }

    if (!fs::create_directories(base / "e" / "album-a") ||
        !fs::create_directories(base / "e" / "album-b")) {
        failure = "scenario E directories";
        return false;
    }
    {
        std::ofstream album_a(base / "e" / "album-a" / "photo.jpg",
                              std::ios::binary);
        album_a << "one";
        std::ofstream album_b(base / "e" / "album-b" / "photo.jpg",
                              std::ios::binary);
        album_b << "two";
    }
    if (!expect(run_benchmark(
                    base / "e", 1, base / "e-output", no_failure, false, error),
                "E repeated names run",
                failure)) {
        return false;
    }
    const auto run_e = base / "e-output" / "run-001";
    if (!expect(fs::exists(run_e / "album-a" / "photo.jpg.enc") &&
                    fs::exists(run_e / "album-b" / "photo.jpg.enc"),
                "E both relative ciphertexts exist",
                failure) ||
        !expect(fs::file_size(run_e / "album-a" / "photo.jpg.enc") > 0 &&
                    fs::file_size(run_e / "album-b" / "photo.jpg.enc") > 0,
                "E both ciphertexts are non-empty",
                failure)) {
        return false;
    }

    if (!fs::create_directories(base / "f" / "input")) {
        failure = "scenario F directories";
        return false;
    }
    {
        std::ofstream input(base / "f" / "input" / "a.bin", std::ios::binary);
        input << "repeat";
    }
    if (!expect(run_benchmark(
                    base / "f", 3, base / "f-output", no_failure, false, error),
                "F three repetitions run",
                failure)) {
        return false;
    }
    for (std::size_t index = 1; index <= 3; ++index) {
        const auto run_f =
            base / "f-output" / run_name(index) / "input" / "a.bin.enc";
        if (!expect(fs::exists(run_f) && fs::file_size(run_f) > 0,
                    "F repetition output exists",
                    failure)) {
            return false;
        }
    }

    if (!fs::create_directories(base / "g" / "input")) {
        failure = "scenario G directories";
        return false;
    }
    {
        std::ofstream first(base / "g" / "input" / "one.bin", std::ios::binary);
        first << "one";
        std::ofstream second(base / "g" / "input" / "two.bin",
                             std::ios::binary);
        second << "two";
        std::ofstream external(base / "g" / "external.txt", std::ios::binary);
        external << "keep";
    }
    if (!expect(
            !run_benchmark(
                base / "g" / "input", 1, base / "g-output", 1, false, error),
            "G injected partial failure fails",
            failure) ||
        !expect(fs::exists(base / "g-output" / "run-001" / "one.bin.enc") &&
                    !fs::exists(base / "g-output" / "run-001" / "two.bin.enc"),
                "G partial outputs are preserved",
                failure) ||
        !expect(read_text(base / "g" / "external.txt") == "keep",
                "G external file is preserved",
                failure)) {
        return false;
    }

    if (!self_test_symlinks(base, failure)) {
        return false;
    }

    if (!expect(!run_benchmark(base / "missing",
                               1,
                               base / "missing-output",
                               no_failure,
                               false,
                               error),
                "missing input root is rejected",
                failure) ||
        !expect(!run_benchmark(base / "e",
                               1,
                               base / "missing-parent" / "output",
                               no_failure,
                               false,
                               error),
                "missing output parent is rejected",
                failure)) {
        return false;
    }

    if (!expect(
            !run_benchmark(
                base / "e", 0, base / "zero-output", no_failure, false, error),
            "zero repetitions are rejected",
            failure)) {
        return false;
    }
    {
        std::ofstream parent_file(base / "parent-file", std::ios::binary);
        parent_file << "keep";
    }
    if (!expect(!run_benchmark(base / "e",
                               1,
                               base / "parent-file" / "output",
                               no_failure,
                               false,
                               error),
                "output parent that is a file is rejected",
                failure) ||
        !expect(read_text(base / "parent-file") == "keep",
                "output parent file is preserved",
                failure)) {
        return false;
    }

    std::string protected_root_text;
#if defined(_WIN32)
    if (const char* system_root = std::getenv("SystemRoot")) {
        protected_root_text = system_root;
    }
#else
    protected_root_text = "/etc";
#endif
    if (!protected_root_text.empty()) {
        fs::path validated_root;
        fs::path validated_output;
        if (!expect(!validate_config(base / "e",
                                     1,
                                     fs::path{protected_root_text} /
                                         "kasumi-benchmark-selftest-protected",
                                     validated_root,
                                     validated_output,
                                     error),
                    "protected output is rejected",
                    failure)) {
            return false;
        }
    }
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "--self-test") {
        std::string failure;
        try {
            if (!run_self_test(failure)) {
                std::cerr << "SELFTEST|FAIL|" << failure << '\n';
                return 1;
            }
        } catch (const std::exception& exception) {
            std::cerr << "SELFTEST|FAIL|" << exception.what() << '\n';
            return 1;
        }
        std::cout << "SELFTEST|PASS\n";
        return 0;
    }

    if (argc < 2 || argc > 4) {
        std::cerr << "usage: kasumi_benchmark_crypto_files ROOT [REPS] [OUT]\n"
                  << "       kasumi_benchmark_crypto_files --self-test\n";
        return 2;
    }
    const std::filesystem::path root = argv[1];
    std::size_t repetitions = 5;
    if (argc >= 3) {
        const std::string_view text(argv[2]);
        const auto result = std::from_chars(
            text.data(), text.data() + text.size(), repetitions);
        if (result.ec != std::errc{} ||
            result.ptr != text.data() + text.size() || repetitions == 0) {
            std::cerr << "REPS must be a positive integer\n";
            return 2;
        }
    }
    const std::filesystem::path output =
        argc == 4 ? std::filesystem::path{argv[3]}
                  : root.parent_path() / (root.filename().string() + "-cipher");

    std::string error;
    try {
        if (!run_benchmark(
                root, repetitions, output, no_failure, true, error)) {
            std::cerr << "benchmark failed: " << error << '\n';
            return 1;
        }
    } catch (const std::exception& exception) {
        std::cerr << "benchmark failed: " << exception.what() << '\n';
        return 1;
    }
    return 0;
}
