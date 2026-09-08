#include "kasumi/test/hash_mutation.hpp"

#include "platform/metadata.hpp"

#include <blake3.h>
#include <fstream>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace {

kasumi::test::HashMutation* active_mutation = nullptr;
const std::filesystem::path* unavailable_fingerprint = nullptr;
std::mutex mutation_mutex;
thread_local bool watching_hash = false;
thread_local bool first_chunk = false;

void mutation_blake3_update(blake3_hasher* state,
                            const void* data,
                            std::size_t size) {
    blake3_hasher_update(state, data, size);
    if (watching_hash && !first_chunk) {
        first_chunk = true;
        if (active_mutation->after_first_chunk &&
            active_mutation->mutations < active_mutation->maximum_mutations) {
            auto action = active_mutation->after_first_chunk;
            ++active_mutation->mutations;
            std::exception_ptr error;
            std::thread writer([&] {
                try {
                    action();
                } catch (...) {
                    error = std::current_exception();
                }
            });
            writer.join();
            if (error)
                std::rethrow_exception(error);
        }
    }
}
} // namespace

#define blake3_hasher_update mutation_blake3_update
#define hash_file instrumented_hash_file
#include "../../../src/crypto/content.cpp"
#undef hash_file
#undef blake3_hasher_update

#define regular_file_fingerprint native_regular_file_fingerprint
#include "../../../src/platform/file_fingerprint.cpp"
#undef regular_file_fingerprint

namespace kasumi::crypto::content {
std::expected<Hash, std::string> hash_file(const std::filesystem::path& path) {
    watching_hash = active_mutation && active_mutation->path == path;
    std::unique_lock lock(mutation_mutex, std::defer_lock);
    if (watching_hash)
        lock.lock();
    first_chunk = false;
    auto result = instrumented_hash_file(path);
    if (watching_hash && result)
        active_mutation->hashes.push_back(*result);
    watching_hash = false;
    return result;
}
} // namespace kasumi::crypto::content

namespace kasumi::test {
HashMutation::HashMutation(const std::filesystem::path& target,
                           std::function<void()> action,
                           std::size_t maximum)
    : path(target), after_first_chunk(std::move(action)),
      maximum_mutations(maximum) {
    if (active_mutation)
        throw std::logic_error("nested hash mutation");
    active_mutation = this;
}
HashMutation::~HashMutation() {
    active_mutation = nullptr;
}

UnavailableFingerprint::UnavailableFingerprint(
    const std::filesystem::path& target)
    : path(target) {
    if (unavailable_fingerprint)
        throw std::logic_error("nested unavailable fingerprint");
    unavailable_fingerprint = &path;
}

UnavailableFingerprint::~UnavailableFingerprint() {
    unavailable_fingerprint = nullptr;
}

void write_large_file(const std::filesystem::path& path) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.exceptions(std::ios::badbit | std::ios::failbit);
    const std::string block(mutation_mib, 'A');
    for (int i = 0; i < 32; ++i)
        output.write(block.data(), static_cast<std::streamsize>(block.size()));
}

void mutate_large_file(const std::filesystem::path& path,
                       FileMutation mode,
                       char value) {
    const auto old_time = std::filesystem::last_write_time(path);
    if (mode == FileMutation::Truncate) {
        std::filesystem::resize_file(path, 8 * mutation_mib);
    } else {
        std::fstream output(path,
                            std::ios::binary | std::ios::in | std::ios::out);
        output.exceptions(std::ios::badbit | std::ios::failbit);
        if (mode == FileMutation::Append)
            output.seekp(0, std::ios::end);
        const std::string block(mutation_mib, value);
        const int blocks = mode == FileMutation::Append ? 8 : 32;
        for (int i = 0; i < blocks; ++i)
            output.write(block.data(),
                         static_cast<std::streamsize>(block.size()));
        output.close();
    }
    const auto set = platform::metadata::set_last_write_time(
        path, old_time + std::chrono::seconds{5});
    if (!set)
        throw std::runtime_error(set.error());
}

Hash independent_file_hash(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    input.exceptions(std::ios::badbit | std::ios::failbit);
    if (!input)
        throw std::runtime_error("independent open failed");
    std::string bytes(
        static_cast<std::size_t>(std::filesystem::file_size(path)), '\0');
    input.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    return hasher::hash_bytes(bytes.data(), bytes.size());
}

void print_file_evidence(const char* label, const std::filesystem::path& path) {
    const auto fingerprint = platform::regular_file_fingerprint(path);
    std::cout
        << label << " size=" << std::filesystem::file_size(path)
        << " mtime_ticks="
        << std::filesystem::last_write_time(path).time_since_epoch().count()
        << " hash=" << hash_hex(independent_file_hash(path)) << " fingerprint=";
    if (!fingerprint)
        std::cout << "error:" << fingerprint.error();
    else if (!*fingerprint)
        std::cout << "unavailable";
    else {
        std::cout << static_cast<int>((**fingerprint).kind) << ':';
        for (auto value : (**fingerprint).value)
            std::cout << value << ',';
    }
    std::cout << '\n';
}
} // namespace kasumi::test

namespace kasumi::platform {
FileFingerprintResult
regular_file_fingerprint(const std::filesystem::path& path) {
    if (unavailable_fingerprint && *unavailable_fingerprint == path)
        return std::optional<FileFingerprint>{};
    return native_regular_file_fingerprint(path);
}
} // namespace kasumi::platform
