#ifndef KASUMI_APPLICATION_OBSERVATION_STATE_HPP
#define KASUMI_APPLICATION_OBSERVATION_STATE_HPP

#include "core/reconciliation/types.hpp"
#include "crypto/file_crypto.hpp"
#include "runtime/resolver.hpp"
#include "state_storage/database.hpp"
#include "transport/transport.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace kasumi::application::observation {

// State reused across local observations.
struct LocalObservationSession {
    // Database persisting reusable data and observation checkpoint.
    std::filesystem::path database_path;
    std::vector<state_storage::FileCacheRow> cache;
    bool cache_loaded = false;
    // Indicates that reusable data must be persisted.
    bool cache_dirty = false;
    std::uint64_t scanner_invocations = 0;
    std::optional<platform::ChangeEvidence> last_evidence;
    // Sorted file references of observed directories.
    std::vector<std::uint64_t> directory_file_references;
    // Indicates that all directory file references were obtained.
    bool lineage_complete = false;
    std::uint64_t selective_patch_attempts = 0;
    std::uint64_t selective_patch_successes = 0;
    std::uint64_t selective_patch_fallbacks = 0;
    std::uint64_t last_delta_entry_count = 0;
    std::uint64_t last_delta_record_count = 0;
    std::uint64_t targeted_file_observations = 0;
    // The checkpoint is validated against the last snapshot before reuse.
    std::optional<state_storage::ObservationCheckpoint> checkpoint;
    std::optional<Snapshot> last_snapshot;
};

// Collects the local tree with full hashing.
std::expected<Snapshot, std::string>
collect_local_tree(const std::filesystem::path& local_root);

// Collects the local tree reusing session state when safe.
std::expected<Snapshot, std::string>
collect_local_tree(const std::filesystem::path& local_root,
                   LocalObservationSession* session);

// Collects and validates the observed remote state.
std::expected<reconciliation::StorageState, std::string>
collect_storage_state(transport::Transport& storage,
                      std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                      const std::filesystem::path& workspace_root,
                      bool audit_storage_objects);

// Combines local and remote observations for reconciliation.
std::expected<reconciliation::Input, reconciliation::Error>
collect_reconciliation_input(
    const runtime::RuntimeData& runtime_data,
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    bool audit_storage_objects,
    std::span<const std::string> trusted_marker_identifiers = {},
    LocalObservationSession* session = nullptr,
    const std::function<void()>& on_proven_local_change = {});

} // namespace kasumi::application::observation

#endif
