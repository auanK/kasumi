#ifndef KASUMI_APPLICATION_HISTORY_STORAGE_COMMIT_CACHE_HPP
#define KASUMI_APPLICATION_HISTORY_STORAGE_COMMIT_CACHE_HPP

#include "application/history_storage/history_storage.hpp"
#include "core/history.hpp"

#include <cstddef>
#include <filesystem>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace kasumi::application::history_storage {

// Key identifying an immutable, content-addressed remote commit object within a
// repository's keyed commits namespace.
struct CommitCacheKey {
    std::string commits_prefix;
    HeadReference reference;

    bool operator==(const CommitCacheKey&) const noexcept = default;
};

struct CommitCacheKeyHash {
    std::size_t operator()(const CommitCacheKey& key) const noexcept;
};

struct CommitCacheEntry {
    history::LoadedCommit commit;
    std::size_t estimated_bytes = 0;
    std::list<CommitCacheKey>::iterator lru_it;
};

// Two-tier cache for immutable, authenticated commit objects:
// 1) Bounded in-memory LRU of parsed LoadedCommits (daemon warm state)
// 2) Bounded encrypted-ciphertext disk cache under disk_cache_root (cross-run)
// Cached disk ciphertexts are still hash-checked, AEAD-decrypted, and
// commit-ID authenticated before use, and corrupted entries self-evict.
struct CommitCache {
    std::mutex mutex;
    std::filesystem::path disk_cache_root;
    std::size_t max_memory_bytes = 128U * 1024U * 1024U;
    std::size_t max_memory_entries = 1024U;
    std::size_t max_disk_files = 512U;
    std::size_t max_disk_bytes = 256U * 1024U * 1024U;
    std::size_t current_memory_bytes = 0;
    std::list<CommitCacheKey> lru_order;
    std::unordered_map<CommitCacheKey, CommitCacheEntry, CommitCacheKeyHash>
        memory_entries;
};

// Looks up an authenticated commit in memory, promoting it in LRU order and
// returning a copy so callers never mutate cached commits.
std::optional<history::LoadedCommit>
lookup_cached_commit(CommitCache& cache,
                     std::string_view commits_prefix,
                     const HeadReference& reference);

// Returns true if the commit is cached in memory or exists as a bounded regular
// ciphertext file on disk, allowing prefetch_commit_batch to skip re-download.
bool has_cached_commit_or_ciphertext(CommitCache& cache,
                                     std::string_view commits_prefix,
                                     const HeadReference& reference);

// Returns the path to a cached encrypted ciphertext file if present and valid.
std::optional<std::filesystem::path>
lookup_cached_ciphertext_path(CommitCache& cache,
                              std::string_view commits_prefix,
                              const HeadReference& reference);

// Stores an authenticated LoadedCommit into the in-memory LRU and optionally
// copies its validated ciphertext into the disk cache (best-effort).
void store_cached_commit(
    CommitCache& cache,
    std::string_view commits_prefix,
    const HeadReference& reference,
    const history::LoadedCommit& commit,
    const std::filesystem::path* validated_ciphertext_path = nullptr);

// Evicts an entry from both memory and disk cache (used when cached ciphertext
// fails validation or self-heals from remote).
void evict_cached_ciphertext(CommitCache& cache,
                             std::string_view commits_prefix,
                             const HeadReference& reference) noexcept;

// Clears all in-memory cached commits (e.g. on profile lock or key change).
void clear_memory_cache(CommitCache& cache) noexcept;

} // namespace kasumi::application::history_storage

#endif
