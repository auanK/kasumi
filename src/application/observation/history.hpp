#ifndef KASUMI_APPLICATION_OBSERVATION_HISTORY_HPP
#define KASUMI_APPLICATION_OBSERVATION_HISTORY_HPP

#include "application/history_storage/history_storage.hpp"
#include "core/history.hpp"
#include "core/node.hpp"
#include "crypto/file_crypto.hpp"
#include "transport/transport.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <unordered_set>
#include <vector>

namespace kasumi::application::observation::history {

// Failure categories when observing remote history.
enum class ErrorCode {
    InvalidInput,
    WorkspaceFailure,
    HistoryStorageFailure,
    ResolutionFailure,
    TransportFailure,
    LimitExceeded,
};

// Detailed failure of remote observation.
struct Error {
    ErrorCode code = ErrorCode::InvalidInput;
    std::string detail;
};

// Validated and resolved remote history.
struct StorageView {
    // Resolved snapshot tree for logical heads.
    Snapshot effective_tree;
    std::uint64_t observed_height = 0;
    std::vector<kasumi::history::LoadedCommit> reachable_commits;
    // Physical variants authenticated during the current observation.
    std::vector<history_storage::HeadReference> authenticated_commit_variants;
    std::vector<std::string> reachable_commit_ids;
    // Commit IDs referenced by observed physical markers.
    std::vector<std::string> marked_heads;
    // Physical identifiers of observed markers.
    std::vector<std::string> marked_head_identifiers;
    // Remaining heads after topology validation.
    std::vector<std::string> logical_heads;
    // Markers pointing to ancestral commits.
    std::vector<std::string> ancestral_marked_heads;
    // Physical IDs observed when content audit is requested.
    std::unordered_set<std::string> content_identifiers;
    // Physical content IDs observed, in canonical order.
    std::vector<std::string> content_object_identifiers;
    // Structural discrepancies between referenced content and physical objects.
    std::size_t missing_content_count = 0;
    std::size_t orphan_content_count = 0;
    bool history_present = false;
    bool has_conflicts = false;
    std::optional<history_storage::epoch::VerifiedEpoch> epoch;
};

// Storage observation result.
using ObserveResult = std::expected<StorageView, Error>;

// Loads, validates, and resolves the observed remote history.
ObserveResult
observe(transport::Transport& storage,
        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
        const std::filesystem::path& workspace_root,
        bool audit_content_objects,
        const history_storage::KnownHistoryFrontier* frontier = nullptr,
        std::span<const std::string> trusted_marker_identifiers = {},
        bool complete_history = false);

} // namespace kasumi::application::observation::history

#endif
