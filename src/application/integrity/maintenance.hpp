#ifndef KASUMI_APPLICATION_INTEGRITY_MAINTENANCE_HPP
#define KASUMI_APPLICATION_INTEGRITY_MAINTENANCE_HPP

#include "application/execute.hpp"
#include "application/history_storage/activity.hpp"
#include "crypto/file_crypto.hpp"
#include "runtime/resolver.hpp"
#include "transport/transport.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace kasumi::application::history_storage {
struct CommitCache;
}

namespace kasumi::application::integrity {

// Failure categories for integrity routines.
enum class ErrorCode {
    InvalidInput,
    StateFailure,
    WorkspaceFailure,
    TransportFailure,
    CryptoFailure,
    IntegrityFailure,
    Unrecoverable,
    ConcurrentChange
};

// Detailed failure of an integrity routine.
struct Error {
    ErrorCode code = ErrorCode::InvalidInput;
    std::string detail;
    // Object associated with the failure, when applicable.
    std::optional<std::string> object_identifier;
    // Original transport failure, including its native code, when available.
    std::optional<transport::Error> transport_failure;
    // Partial-result and cleanup diagnostics for garbage collection.
    std::optional<GarbageCollectFailure> garbage_collection;
};

// Formats an integrity failure.
std::string describe(const Error& error);

// Counts produced by the integrity audit.
struct FsckResult {
    std::size_t checked_objects = 0;
    std::size_t repaired_objects = 0;
};

using FsckProgressCallback = std::function<void(const FsckProgress&)>;

// Policy options controlling garbage collection safety grace periods and mode.
struct GarbageCollectOptions {
    bool dry_run = false;
    // std::nullopt uses runtime_data.min_history_age_hours (default 6h).
    // Explicit 0s disables the safety grace period (offline maintenance).
    std::optional<std::chrono::seconds> min_orphan_age = std::nullopt;
    // Wait window after publishing a unique barrier marker before confirming
    // exclusivity (0ms default for library/unit callers; CLI uses 2000ms).
    std::chrono::milliseconds barrier_settle_delay{0};
    // Optional override for diagnostic barrier metadata machine name.
    std::optional<std::string> machine_name = std::nullopt;
    // Periodic barrier exclusivity revalidation cadence during Applying.
    std::size_t apply_revalidation_batch_interval = 16;
    std::chrono::seconds apply_revalidation_time_interval{30};
    // Optional commit/epoch cache to avoid re-downloading immutable history
    // objects during GC analysis.
    history_storage::CommitCache* commit_cache = nullptr;
};

// Counts produced by global-plan garbage collection.
struct GarbageCollectResult {
    std::size_t candidate_objects = 0;
    // REMOVE calls acknowledged by the transport. This is not an independent
    // physical audit; no presence read-back is performed after deletion.
    std::size_t removed_objects = 0;
    bool analysis_only = false;
    bool dry_run = false;
    std::size_t candidate_content_objects = 0;
    std::size_t candidate_commit_variants = 0;
    std::size_t candidate_expired_commits = 0;
    std::size_t candidate_activities = 0;
    std::size_t deferred_recent_objects = 0;
    std::uint64_t candidate_bytes = 0;
    std::uint64_t removed_bytes = 0;
    std::uint32_t effective_min_age_hours = 0;
    std::chrono::nanoseconds removal_elapsed{};
    bool epoch_advanced = false;
    bool epoch_advancement_planned = false;
    std::optional<std::uint64_t> target_epoch_sequence = std::nullopt;
    std::optional<std::string> target_epoch_id = std::nullopt;
    std::size_t planned_pruned_commits = 0;
    std::size_t pruned_activities = 0;
    std::vector<history_storage::activity::LoadedActivity> kept_activities;
};

using GarbageCollectProgressCallback =
    std::function<void(const GarbageCollectProgress&)>;

// Removes authenticated, unreachable content, expired commits, and redundant
// commit variants. One authenticated observation builds and validates the
// complete deletion plan; Apply removes planned candidates in bounded batches
// and trusts the transport result. Exclusivity is cooperative: pre-barrier and
// post-barrier writer checks plus the grace period protect in-flight Sync work.
std::expected<GarbageCollectResult, Error>
garbage_collect(const runtime::RuntimeData& runtime_data,
                transport::Transport& storage,
                std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                GarbageCollectOptions options,
                GarbageCollectProgressCallback on_progress = {});

// Default safe collection overload (uses profile's min_history_age_hours).
std::expected<GarbageCollectResult, Error>
garbage_collect(const runtime::RuntimeData& runtime_data,
                transport::Transport& storage,
                std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                GarbageCollectProgressCallback on_progress = {});

// Dry-run overload when dry_run is true; otherwise identical to
// garbage_collect.
std::expected<GarbageCollectResult, Error>
garbage_collect(const runtime::RuntimeData& runtime_data,
                transport::Transport& storage,
                std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                bool dry_run,
                GarbageCollectProgressCallback on_progress = {});

// Compatibility overload retaining the historical maintenance call shape.
// Collection remains sequential; the concurrency hints are validated but the
// direct-removal runner never batches removals.
std::expected<GarbageCollectResult, Error>
garbage_collect(const runtime::RuntimeData& runtime_data,
                transport::Transport& storage,
                std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                std::size_t copy_batch_concurrency,
                std::size_t metadata_batch_concurrency,
                std::size_t source_removal_concurrency,
                GarbageCollectProgressCallback on_progress = {});

// Audits the history and reachable content objects.
std::expected<FsckResult, Error>
fsck(const runtime::RuntimeData& runtime_data,
     transport::Transport& storage,
     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
     std::size_t audit_concurrency = 1,
     FsckProgressCallback on_progress = {});

} // namespace kasumi::application::integrity

#endif
