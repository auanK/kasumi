#ifndef KASUMI_APPLICATION_INTEGRITY_MAINTENANCE_HPP
#define KASUMI_APPLICATION_INTEGRITY_MAINTENANCE_HPP

#include "application/execute.hpp"
#include "crypto/file_crypto.hpp"
#include "runtime/resolver.hpp"
#include "transport/transport.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

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
};

// Formats an integrity failure.
std::string describe(const Error& error);

// Counts produced by the integrity audit.
struct FsckResult {
    std::size_t checked_objects = 0;
    std::size_t repaired_objects = 0;
};

using FsckProgressCallback = std::function<void(const FsckProgress&)>;

enum class GcCandidateKind : std::uint8_t {
    Content,
    CommitVariant
};

struct GcCandidate {
    std::string identifier;
    GcCandidateKind kind = GcCandidateKind::Content;

    bool operator==(const GcCandidate&) const = default;
};

std::expected<std::vector<GcCandidate>, Error>
select_gc_candidates(std::span<const std::string> commit_variant_ids,
                     std::span<const std::string> orphan_content_ids);

bool same_gc_candidates(std::span<const GcCandidate> left,
                        std::span<const GcCandidate> right) noexcept;

// Explicit observation snapshot for garbage collection decision-making.
struct GcSnapshot {
    std::vector<std::string> logical_heads;
    std::vector<std::string> reachable_commits;
    std::vector<std::string> required_commit_objects;
    std::vector<std::string> reachable_content;
    std::vector<std::string> physical_namespace;
    std::vector<GcCandidate> candidates;

    bool operator==(const GcSnapshot&) const = default;
};

// Reconstructs and validates a reachability snapshot from authenticated inventories.
std::expected<GcSnapshot, Error>
collect_gc_snapshot(transport::Transport& storage,
                    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                    const std::filesystem::path& workspace_root);

// Compares all relevant security fields of two snapshots for equivalence.
bool same_gc_snapshot(const GcSnapshot& left,
                      const GcSnapshot& right) noexcept;

enum class GcAnalysisErrorCode {
    Preconditions,
    BarrierAcquisition,
    WriterPresent,
    OwnershipLost,
    Observation,
    SnapshotChanged,
    BarrierRelease,
    Cancelled
};

struct GcAnalysisError {
    GcAnalysisErrorCode code = GcAnalysisErrorCode::Preconditions;
    Error cause;
    std::optional<Error> cleanup_error;
};

// Requires exclusive operation of this vault. The returned report carries no
// deletion authorization: its barrier has already been released.
std::expected<GcSnapshot, GcAnalysisError>
analyze_gc_under_barrier(transport::Transport& storage,
                        std::span<const std::uint8_t, crypto::KEY_SIZE> key,
                        const std::filesystem::path& workspace_root);

struct GcContentRemovalResult {
    std::size_t content_candidates = 0;
    std::size_t removed_content = 0;
    std::size_t already_absent = 0;
    std::size_t pending_commit_variants = 0;

    bool operator==(const GcContentRemovalResult&) const = default;
};

enum class GcContentRemovalErrorCode {
    Preconditions,
    BarrierAcquisition,
    WriterPresent,
    OwnershipLost,
    Observation,
    SnapshotChanged,
    RemovalFailure,
    BarrierRelease,
    Cancelled
};

struct GcContentRemovalError {
    GcContentRemovalErrorCode code = GcContentRemovalErrorCode::Preconditions;
    Error cause;
    std::optional<Error> cleanup_error;
    std::size_t removed_content = 0;
    std::size_t already_absent = 0;
    bool uncertain_mutation = false;
};

// Removes eligible orphan Content objects directly within an active maintenance barrier session.
std::expected<GcContentRemovalResult, GcContentRemovalError>
remove_orphan_content_under_barrier(
    transport::Transport& storage,
    std::span<const std::uint8_t, crypto::KEY_SIZE> key,
    const std::filesystem::path& workspace_root);

// Audits the history and reachable content objects.
std::expected<FsckResult, Error>
fsck(const runtime::RuntimeData& runtime_data,
     transport::Transport& storage,
     std::span<const std::uint8_t, crypto::KEY_SIZE> key,
     std::size_t audit_concurrency = 1,
     FsckProgressCallback on_progress = {});

} // namespace kasumi::application::integrity

#endif
