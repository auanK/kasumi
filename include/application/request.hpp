#ifndef KASUMI_APPLICATION_REQUEST_HPP
#define KASUMI_APPLICATION_REQUEST_HPP

#include <cstdint>
#include <optional>
#include <string>

namespace kasumi::application {

// Command types supported by the application engine.
enum class Operation {
    // Bidirectionally synchronizes state between local and remote directories.
    Sync,
    // Simulates synchronization and displays execution plan without modifying
    // data (dry-run).
    Preview,
    // Compares differences between local and remote.
    Status,
    // Analyzes cryptographic and structural integrity of remotely stored
    // blocks.
    Fsck,
    // Removes objects unreachable from any logical head.
    GarbageCollect,
    // Resolves unavailable pending materializations as logical deletions.
    ResolveMissing,
    // Explicit manual removal of one remote writer marker.
    RemoveWriter,
    // Explicit manual removal of an abandoned remote maintenance barrier.
    RemoveBarrier,
    // Consolidates fragmented Micro-Packs and loose small files.
    Repack
};

// Request structure defining action to perform and target profile.
struct Request {
    Operation operation = Operation::Sync;
    std::string profile_name;
    std::string writer_identifier;
    std::optional<std::string> barrier_identifier = std::nullopt;
    bool initial = false;
    bool audit_inventory = false;
    bool repair = false;
    bool confirm_abandoned = false;
    bool confirm = false;
    bool dry_run = false;
    bool reclaim_dirty = false;
    std::optional<std::uint32_t> gc_min_age_hours = std::nullopt;
};

} // namespace kasumi::application

#endif
