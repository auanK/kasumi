#ifndef KASUMI_APPLICATION_HISTORY_STORAGE_COMMIT_CACHE_HPP
#define KASUMI_APPLICATION_HISTORY_STORAGE_COMMIT_CACHE_HPP

#include "application/history_storage/history_storage.hpp"
#include "core/history.hpp"

#include <cstddef>
#include <filesystem>
#include <list>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

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

// Key identifying an authenticated remote epoch object within a repository's
// keyed epochs namespace.
struct EpochCacheKey {
    std::string epochs_prefix;
    epoch::Reference reference;

    bool operator==(const EpochCacheKey&) const noexcept = default;
};

struct EpochCacheKeyHash {
    std::size_t operator()(const EpochCacheKey& key) const noexcept;
};

// Two-tier cache for immutable, authenticated commit and epoch objects, plus
// validated head markers in RAM:
// 1) Bounded in-memory LRU of parsed LoadedCommits + verified epochs/markers
// 2) Bounded encrypted ciphertext / sealed epoch disk cache under
//    disk_cache_root (cross-run)
// Cached disk files are always decrypted and authenticated before use, and
// corrupted entries self-evict.
struct CommitCache {
    std::mutex mutex;
    std::filesystem::path disk_cache_root;
    std::size_t max_memory_bytes = 128U * 1024U * 1024U;
    std::size_t max_memory_entries = 1024U;
    std::size_t max_disk_files = 512U;
    std::size_t max_disk_bytes = 256U * 1024U * 1024U;
    std::size_t max_epoch_entries = 128U;
    std::size_t max_validated_markers = 512U;
    std::size_t current_memory_bytes = 0;
    std::list<CommitCacheKey> lru_order;
    std::unordered_map<CommitCacheKey, CommitCacheEntry, CommitCacheKeyHash>
        memory_entries;
    std::unordered_map<EpochCacheKey, epoch::VerifiedEpoch, EpochCacheKeyHash>
        epoch_entries;
    std::unordered_set<std::string> validated_markers;
};

// Looks up an authenticated commit in memory, promoting it in LRU order and
// returning a copy so callers never mutate cached commits.
std::optional<history::LoadedCommit>
lookup_cached_commit(CommitCache& cache,
                     std::string_view commits_prefix,
                     const HeadReference& reference);

// Looks up any authenticated variant in memory matching commit_id within the
// keyed commits namespace, promoting it in LRU order and returning a copy.
std::optional<history::LoadedCommit>
lookup_cached_commit_by_id(CommitCache& cache,
                           std::string_view commits_prefix,
                           std::string_view commit_id);

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

// Looks up a verified epoch in memory, returning a copy.
std::optional<epoch::VerifiedEpoch>
lookup_cached_epoch(CommitCache& cache,
                    std::string_view epochs_prefix,
                    const epoch::Reference& reference);

// Reads sealed epoch bytes from the disk cache if present and bounded; callers
// must still authenticate and open them via epoch::open.
std::optional<std::vector<std::uint8_t>>
read_cached_sealed_epoch(CommitCache& cache,
                         std::string_view epochs_prefix,
                         const epoch::Reference& reference);

// Stores an authenticated VerifiedEpoch in memory and optionally copies its
// sealed KEPA envelope into the disk cache (best-effort).
void store_cached_epoch(
    CommitCache& cache,
    std::string_view epochs_prefix,
    const epoch::VerifiedEpoch& verified,
    const std::filesystem::path* sealed_epoch_path = nullptr);

// Evicts a cached epoch from both memory and disk cache.
void evict_cached_epoch(CommitCache& cache,
                        std::string_view epochs_prefix,
                        const epoch::Reference& reference) noexcept;

// Returns true if marker_id was already cryptographically validated in this
// cache instance.
bool has_validated_marker(CommitCache& cache, std::string_view marker_id);

// Records marker_id as cryptographically validated up to
// max_validated_markers.
void record_validated_marker(CommitCache& cache, std::string_view marker_id);

// Removes cached commits for commits_prefix from memory when a complete
// commits/ listing shows they no longer exist on the remote.
void prune_unlisted_memory_commits(
    CommitCache& cache,
    std::string_view commits_prefix,
    const std::map<std::string, std::vector<HeadReference>>&
        live_commit_variants) noexcept;

// Clears all in-memory cached commits, epochs, and markers (e.g. on profile
// lock or key change).
void clear_memory_cache(CommitCache& cache) noexcept;

} // namespace kasumi::application::history_storage

#endif
