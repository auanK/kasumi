#include "application/history_storage/commit_cache.hpp"

#include "application/history_storage/detail.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <fstream>
#include <system_error>
#include <utility>
#include <vector>

namespace kasumi::application::history_storage {
namespace {

std::size_t combine_hash(std::size_t seed, std::size_t value) noexcept {
    return seed ^ (value + 0x9e3779b97f4a7c15ULL + (seed << 6U) + (seed >> 2U));
}

bool valid_cache_component_chars(std::string_view prefix) noexcept {
    if (prefix.empty()) {
        return false;
    }
    return std::ranges::all_of(prefix, [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
               ch == '/';
    });
}

std::optional<std::string> derive_namespace_dir(std::string_view commits_prefix) {
    auto trimmed = detail::trim_trailing_slash(commits_prefix);
    if (!valid_cache_component_chars(trimmed)) {
        return std::nullopt;
    }
    std::string name;
    name.reserve(trimmed.size());
    for (const char ch : trimmed) {
        if (ch == '/') {
            if (!name.empty() && name.back() != '_') {
                name.push_back('_');
            }
        } else {
            name.push_back(ch);
        }
    }
    if (name.empty()) {
        return std::nullopt;
    }
    return name;
}

std::optional<std::filesystem::path>
derive_namespace_root(const CommitCache& cache,
                      std::string_view commits_prefix) {
    if (cache.disk_cache_root.empty()) {
        return std::nullopt;
    }
    const auto ns_dir = derive_namespace_dir(commits_prefix);
    if (!ns_dir) {
        return std::nullopt;
    }
    return cache.disk_cache_root / *ns_dir;
}

std::optional<std::filesystem::path>
derive_disk_cache_path(const CommitCache& cache,
                       std::string_view commits_prefix,
                       const HeadReference& reference) {
    if (!valid(reference)) {
        return std::nullopt;
    }
    auto ns_root = derive_namespace_root(cache, commits_prefix);
    if (!ns_root) {
        return std::nullopt;
    }
    return *ns_root / (reference.commit_id + "_" + reference.ciphertext_id);
}

bool is_cached_ciphertext_filename(std::string_view name) noexcept {
    if (name.size() != 129U || name[64] != '_') {
        return false;
    }
    return detail::valid_hex_id(name.substr(0, 64)) &&
           detail::valid_hex_id(name.substr(65));
}

bool is_valid_existing_directory(const std::filesystem::path& path) noexcept {
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(path, ec);
    if (ec || status.type() == std::filesystem::file_type::not_found) {
        return false;
    }
    return !platform::private_storage::is_reparse_or_symlink(path) &&
           std::filesystem::is_directory(status);
}

bool is_valid_cached_file(const std::filesystem::path& path) noexcept {
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(path, ec);
    if (ec || status.type() == std::filesystem::file_type::not_found ||
        platform::private_storage::is_reparse_or_symlink(path) ||
        !std::filesystem::is_regular_file(status)) {
        return false;
    }
    const auto size = std::filesystem::file_size(path, ec);
    return !ec && size > 0 && size <= detail::maximum_commit_ciphertext_size;
}

std::size_t estimate_commit_bytes(const history::LoadedCommit& loaded) noexcept {
    std::size_t total = sizeof(history::LoadedCommit) + loaded.id.capacity();
    for (const auto& parent : loaded.commit.parents) {
        total += sizeof(std::string) + parent.capacity();
    }
    for (const auto& row : loaded.commit.tree.rows) {
        total += sizeof(NodeRow) + row.path.capacity();
    }
    total += loaded.commit.storage.packed_blobs.size() *
             sizeof(history::PackedBlobEntry);
    total += loaded.commit.storage.chunked_files.size() *
             sizeof(history::ChunkedFileEntry);
    for (const auto& chunked : loaded.commit.storage.chunked_files) {
        total += chunked.chunks.size() * sizeof(history::ChunkSlice);
    }
    total += loaded.commit.authorship.machine_name.capacity();
    return total;
}

bool ensure_private_cache_directory(const std::filesystem::path& path) noexcept {
    try {
        std::error_code ec;
        const auto status = std::filesystem::symlink_status(path, ec);
        if (!ec && status.type() != std::filesystem::file_type::not_found) {
            if (platform::private_storage::is_reparse_or_symlink(path) ||
                !std::filesystem::is_directory(status)) {
                return false;
            }
            return true;
        }
        if (ec && ec != std::errc::no_such_file_or_directory) {
            return false;
        }
        std::filesystem::create_directories(path, ec);
        if (ec || platform::private_storage::is_reparse_or_symlink(path)) {
            return false;
        }
        return static_cast<bool>(platform::private_storage::protect_directory(path));
    } catch (...) {
        return false;
    }
}

void prune_disk_cache_locked(const std::filesystem::path& ns_root,
                             std::size_t max_files,
                             std::size_t max_bytes) noexcept {
    try {
        struct CachedFileMeta {
            std::filesystem::path path;
            std::uintmax_t size = 0;
            std::filesystem::file_time_type mtime{};
        };
        std::vector<CachedFileMeta> files;
        std::uintmax_t total_bytes = 0;
        std::error_code ec;
        for (std::filesystem::directory_iterator it(ns_root, ec), end;
             !ec && it != end;
             it.increment(ec)) {
            const auto& entry = *it;
            const auto filename = entry.path().filename().string();
            if (!is_cached_ciphertext_filename(filename)) {
                continue;
            }
            if (platform::private_storage::is_reparse_or_symlink(entry.path())) {
                continue;
            }
            std::error_code file_ec;
            const auto status = entry.symlink_status(file_ec);
            if (file_ec || !std::filesystem::is_regular_file(status)) {
                continue;
            }
            const auto size = entry.file_size(file_ec);
            if (file_ec) {
                continue;
            }
            const auto mtime = entry.last_write_time(file_ec);
            files.push_back(CachedFileMeta{
                .path = entry.path(),
                .size = size,
                .mtime = file_ec ? std::filesystem::file_time_type::min() : mtime,
            });
            total_bytes += size;
        }
        if (files.size() <= max_files && total_bytes <= max_bytes) {
            return;
        }
        std::ranges::sort(files, [](const auto& left, const auto& right) {
            return left.mtime < right.mtime;
        });
        std::size_t remaining_files = files.size();
        for (const auto& file : files) {
            if (remaining_files <= max_files && total_bytes <= max_bytes) {
                break;
            }
            std::error_code rm_ec;
            if (std::filesystem::remove(file.path, rm_ec) && !rm_ec) {
                --remaining_files;
                total_bytes =
                    total_bytes >= file.size ? (total_bytes - file.size) : 0;
            }
        }
    } catch (...) {
    }
}

void write_ciphertext_to_disk(const CommitCache& cache,
                              const std::filesystem::path& ns_root,
                              const std::filesystem::path& target,
                              const std::filesystem::path& source) noexcept {
    try {
        if (is_valid_cached_file(target)) {
            return;
        }
        if (!ensure_private_cache_directory(cache.disk_cache_root) ||
            !ensure_private_cache_directory(ns_root)) {
            return;
        }
        auto random_id = platform::random::hex_id();
        if (!random_id) {
            return;
        }
        const auto tmp = ns_root / (".tmp-" + *random_id);
        {
            auto created = platform::private_storage::create_file(tmp);
            if (!created) {
                return;
            }
            std::ifstream src(source, std::ios::binary);
            std::ofstream dst(tmp, std::ios::binary | std::ios::trunc);
            if (!src || !dst) {
                detail::remove_file(tmp);
                return;
            }
            dst << src.rdbuf();
            dst.flush();
            if (!dst) {
                dst.close();
                detail::remove_file(tmp);
                return;
            }
        }
        if (!platform::private_storage::protect_file(tmp)) {
            detail::remove_file(tmp);
            return;
        }
        std::error_code rename_ec;
        std::filesystem::rename(tmp, target, rename_ec);
        if (rename_ec) {
            detail::remove_file(tmp);
            return;
        }
        prune_disk_cache_locked(
            ns_root, cache.max_disk_files, cache.max_disk_bytes);
    } catch (...) {
    }
}

} // namespace

std::size_t
CommitCacheKeyHash::operator()(const CommitCacheKey& key) const noexcept {
    std::size_t seed = std::hash<std::string>{}(key.commits_prefix);
    seed = combine_hash(seed, std::hash<std::string>{}(key.reference.commit_id));
    seed = combine_hash(seed,
                        std::hash<std::string>{}(key.reference.ciphertext_id));
    return seed;
}

std::optional<history::LoadedCommit>
lookup_cached_commit(CommitCache& cache,
                     std::string_view commits_prefix,
                     const HeadReference& reference) {
    if (!valid(reference) || commits_prefix.empty()) {
        return std::nullopt;
    }
    std::lock_guard lock(cache.mutex);
    const CommitCacheKey key{
        .commits_prefix = std::string{commits_prefix},
        .reference = reference,
    };
    const auto it = cache.memory_entries.find(key);
    if (it == cache.memory_entries.end()) {
        return std::nullopt;
    }
    cache.lru_order.splice(
        cache.lru_order.begin(), cache.lru_order, it->second.lru_it);
    return it->second.commit;
}

std::optional<history::LoadedCommit>
lookup_cached_commit_by_id(CommitCache& cache,
                           std::string_view commits_prefix,
                           std::string_view commit_id) {
    if (commits_prefix.empty() || !detail::valid_hex_id(commit_id)) {
        return std::nullopt;
    }
    std::lock_guard lock(cache.mutex);
    for (auto& [key, entry] : cache.memory_entries) {
        if (key.commits_prefix == commits_prefix &&
            key.reference.commit_id == commit_id) {
            cache.lru_order.splice(
                cache.lru_order.begin(), cache.lru_order, entry.lru_it);
            return entry.commit;
        }
    }
    return std::nullopt;
}

bool has_cached_commit_or_ciphertext(CommitCache& cache,
                                     std::string_view commits_prefix,
                                     const HeadReference& reference) {
    if (!valid(reference) || commits_prefix.empty()) {
        return false;
    }
    {
        std::lock_guard lock(cache.mutex);
        const CommitCacheKey key{
            .commits_prefix = std::string{commits_prefix},
            .reference = reference,
        };
        if (cache.memory_entries.contains(key)) {
            return true;
        }
    }
    return lookup_cached_ciphertext_path(cache, commits_prefix, reference)
        .has_value();
}

std::optional<std::filesystem::path>
lookup_cached_ciphertext_path(CommitCache& cache,
                              std::string_view commits_prefix,
                              const HeadReference& reference) {
    const auto ns_root = derive_namespace_root(cache, commits_prefix);
    const auto target = derive_disk_cache_path(cache, commits_prefix, reference);
    if (!ns_root || !target) {
        return std::nullopt;
    }
    if (!is_valid_existing_directory(cache.disk_cache_root) ||
        !is_valid_existing_directory(*ns_root) ||
        !is_valid_cached_file(*target)) {
        return std::nullopt;
    }
    return target;
}

void store_cached_commit(CommitCache& cache,
                         std::string_view commits_prefix,
                         const HeadReference& reference,
                         const history::LoadedCommit& commit,
                         const std::filesystem::path* validated_ciphertext_path) {
    if (!valid(reference) || commits_prefix.empty()) {
        return;
    }
    try {
        if (cache.max_memory_bytes > 0 && cache.max_memory_entries > 0) {
            const auto estimated = estimate_commit_bytes(commit);
            if (estimated <= cache.max_memory_bytes) {
                std::lock_guard lock(cache.mutex);
                const CommitCacheKey key{
                    .commits_prefix = std::string{commits_prefix},
                    .reference = reference,
                };
                if (const auto existing = cache.memory_entries.find(key);
                    existing != cache.memory_entries.end()) {
                    cache.current_memory_bytes -=
                        existing->second.estimated_bytes;
                    cache.lru_order.erase(existing->second.lru_it);
                    cache.memory_entries.erase(existing);
                }
                while (!cache.lru_order.empty() &&
                       (cache.memory_entries.size() >= cache.max_memory_entries ||
                        cache.current_memory_bytes + estimated >
                            cache.max_memory_bytes)) {
                    const auto victim_key = cache.lru_order.back();
                    cache.lru_order.pop_back();
                    if (const auto victim = cache.memory_entries.find(victim_key);
                        victim != cache.memory_entries.end()) {
                        cache.current_memory_bytes -=
                            victim->second.estimated_bytes;
                        cache.memory_entries.erase(victim);
                    }
                }
                cache.lru_order.push_front(key);
                CommitCacheEntry entry{
                    .commit = commit,
                    .estimated_bytes = estimated,
                    .lru_it = cache.lru_order.begin(),
                };
                cache.current_memory_bytes += estimated;
                cache.memory_entries.emplace(key, std::move(entry));
            }
        }
    } catch (const std::exception&) {
    }

    if (validated_ciphertext_path != nullptr && cache.max_disk_files > 0 &&
        cache.max_disk_bytes > 0) {
        const auto ns_root = derive_namespace_root(cache, commits_prefix);
        const auto target =
            derive_disk_cache_path(cache, commits_prefix, reference);
        if (ns_root && target) {
            write_ciphertext_to_disk(
                cache, *ns_root, *target, *validated_ciphertext_path);
        }
    }
}

void evict_cached_ciphertext(CommitCache& cache,
                             std::string_view commits_prefix,
                             const HeadReference& reference) noexcept {
    try {
        {
            std::lock_guard lock(cache.mutex);
            const CommitCacheKey key{
                .commits_prefix = std::string{commits_prefix},
                .reference = reference,
            };
            if (const auto it = cache.memory_entries.find(key);
                it != cache.memory_entries.end()) {
                cache.current_memory_bytes -= it->second.estimated_bytes;
                cache.lru_order.erase(it->second.lru_it);
                cache.memory_entries.erase(it);
            }
        }
        if (const auto target =
                derive_disk_cache_path(cache, commits_prefix, reference)) {
            detail::remove_file(*target);
        }
    } catch (...) {
    }
}

void clear_memory_cache(CommitCache& cache) noexcept {
    std::lock_guard lock(cache.mutex);
    cache.memory_entries.clear();
    cache.lru_order.clear();
    cache.current_memory_bytes = 0;
}

} // namespace kasumi::application::history_storage
