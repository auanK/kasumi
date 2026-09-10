#ifndef KASUMI_STATE_STORAGE_DATABASE_HPP
#define KASUMI_STATE_STORAGE_DATABASE_HPP

#include "core/node.hpp"
#include "platform/change_journal.hpp"
#include "platform/file_fingerprint.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace kasumi::state_storage {

// Persisted synchronized state for a profile.
struct StoredState {
    Snapshot tree;
    std::uint64_t height = 0;
    std::string commit_id;
    std::string ciphertext_id;
    // Latest Epoch certificate accepted locally.
    std::string epoch_id;
    std::uint64_t epoch_sequence = 0;
};

// Persisted entry for safe reuse of the local hash.
struct FileCacheRow {
    std::string path;
    Hash hash{};
    std::uint64_t size = 0;
    platform::FileFingerprint fingerprint{};
};

// Observation checkpoint linked to the identified tree state.
struct ObservationCheckpoint {
    platform::ChangeJournalCheckpoint journal{};
    // Root hash binding the checkpoint to the tree.
    Hash tree_root_hash{};
    // Row count used to validate the binding.
    std::uint64_t row_count = 0;
    // Ordered references of directories included in the tree.
    std::vector<std::uint64_t> directory_file_references;
    // Indicates whether the list covers the entire observed lineage.
    bool lineage_complete = false;
};

// Creates, migrates, or validates the database schema.
bool initialize(const std::filesystem::path& database_path);

// Loads the state or returns nullopt when it does not exist yet.
std::expected<std::optional<StoredState>, std::string>
load_state(const std::filesystem::path& database_path);

// Validates and replaces the state within a transaction; preserves Epoch if
// omitted.
bool save_state(const std::filesystem::path& database_path,
                const StoredState& state);

// Loads the cache or returns empty when it does not exist yet.
std::expected<std::vector<FileCacheRow>, std::string>
load_file_cache(const std::filesystem::path& database_path);

// Synchronizes the persisted cache with the provided set.
bool save_file_cache_delta(const std::filesystem::path& database_path,
                           std::span<const FileCacheRow> rows);

// Loads the observation checkpoint or returns nullopt when absent.
std::expected<std::optional<ObservationCheckpoint>, std::string>
load_observation_checkpoint(const std::filesystem::path& database_path);

// Validates and replaces the persisted observation checkpoint.
bool save_observation_checkpoint(const std::filesystem::path& database_path,
                                 const ObservationCheckpoint& checkpoint);

} // namespace kasumi::state_storage

#endif
