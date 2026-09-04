#ifndef KASUMI_CORE_MAINTENANCE_HPP
#define KASUMI_CORE_MAINTENANCE_HPP

#include "core/node.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace kasumi::maintenance {

// Failure categories when analyzing content references.
enum class ErrorCode {
    InvalidHistoryTree,
    InvalidLocalTree,
    // Same identifier appears with conflicting sizes.
    ConflictingReference
};

// Analysis error, including involved paths when applicable.
struct Error {
    // Failure category.
    ErrorCode code = ErrorCode::InvalidHistoryTree;
    // Human-readable failure description.
    std::string detail;
    // Paths associated with the failure.
    std::vector<std::filesystem::path> paths;
};

// Content object referenced by history.
struct ObjectReference {
    // Hexadecimal hash identifying the object.
    std::string identifier;
    // Expected content size in bytes.
    std::uint64_t size = 0;
    // History paths referencing the object.
    std::vector<std::filesystem::path> referenced_paths;
    // Compatible local copy suitable for object repair.
    std::optional<std::filesystem::path> local_source;
    // Indicates identifier was found in physical listing.
    bool physically_present = false;
};

// Classification of observed references and physical identifiers.
struct Inventory {
    // Objects required by history.
    std::vector<ObjectReference> referenced_objects;
    // Canonical identifiers not referenced in history.
    std::vector<std::string> orphan_identifiers;
    // Physical identifiers outside the canonical format.
    std::vector<std::string> unknown_identifiers;
};

// Result of pure maintenance analysis.
using AnalyzeResult = std::expected<Inventory, Error>;

// Analyzes references without mutating snapshots or storage.
AnalyzeResult analyze(const Snapshot& history_tree,
                      const Snapshot& local_tree,
                      std::span<const std::string> physical_identifiers);

} // namespace kasumi::maintenance

#endif
