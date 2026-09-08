#pragma once

#include "crypto/content.hpp"
#include "platform/file_fingerprint.hpp"

#include <filesystem>
#include <functional>
#include <vector>

namespace kasumi::test {
struct HashMutation {
    std::filesystem::path path;
    std::function<void()> after_first_chunk;
    std::vector<Hash> hashes;
    std::size_t mutations = 0;
    std::size_t maximum_mutations = 1;
    HashMutation(const std::filesystem::path& target,
                 std::function<void()> action,
                 std::size_t maximum = 1);
    ~HashMutation();
    HashMutation(const HashMutation&) = delete;
    HashMutation& operator=(const HashMutation&) = delete;
};

struct UnavailableFingerprint {
    std::filesystem::path path;
    explicit UnavailableFingerprint(const std::filesystem::path& target);
    ~UnavailableFingerprint();
    UnavailableFingerprint(const UnavailableFingerprint&) = delete;
    UnavailableFingerprint& operator=(const UnavailableFingerprint&) = delete;
};

inline constexpr std::size_t mutation_mib = 1024U * 1024U;
enum class FileMutation {
    Append,
    Truncate,
    Overwrite
};
void write_large_file(const std::filesystem::path& path);
void mutate_large_file(const std::filesystem::path& path,
                       FileMutation mode,
                       char value = 'B');
Hash independent_file_hash(const std::filesystem::path& path);
void print_file_evidence(const char* label, const std::filesystem::path& path);
} // namespace kasumi::test
