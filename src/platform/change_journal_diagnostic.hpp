#ifndef KASUMI_PLATFORM_CHANGE_JOURNAL_DIAGNOSTIC_HPP
#define KASUMI_PLATFORM_CHANGE_JOURNAL_DIAGNOSTIC_HPP

#include "platform/change_journal.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <vector>

namespace kasumi::platform {

// Reason why a USN record could not be resolved.
enum class UnresolvedReason : std::uint8_t {
    ObjectMissingParentResolved,
    ObjectMissingParentMissing,
    AccessDeniedObject,
    AccessDeniedParent,
    UnknownReason,
    UnsupportedVersion,
    MalformedRecord,
    RootIdentityProblem,
    OtherWin32Failure,
};

// Preserved evidence of an unresolved USN record.
struct UnresolvedDiagnostic {
    std::int64_t usn = 0;
    std::uint64_t file_reference = 0;
    std::uint64_t parent_reference = 0;
    // Raw USN record reason mask.
    std::uint32_t reason = 0;
    std::uint16_t major_version = 0;
    std::uint16_t minor_version = 0;
    std::uint16_t file_name_offset = 0;
    std::uint16_t file_name_length = 0;
    std::wstring file_name;
    // Category derived from resolution failure.
    UnresolvedReason category = UnresolvedReason::OtherWin32Failure;
    // Win32 error codes when opening the file and its parent.
    std::uint32_t file_open_error = 0;
    std::uint32_t parent_open_error = 0;
    std::wstring parent_path;
    bool file_path_resolved = false;
    bool parent_path_resolved = false;
};

// Metrics and samples from diagnostic USN reading.
struct ChangeJournalDiagnostics {
    std::vector<UnresolvedDiagnostic> unresolved;
    // Indicates that not all unresolved cases were retained.
    bool unresolved_diagnostics_truncated = false;
    std::uint64_t file_open_attempts = 0;
    std::uint64_t parent_open_attempts = 0;
    std::uint64_t file_resolution_failures = 0;
    std::uint64_t parent_resolution_failures = 0;
    std::uint64_t parent_reconstruction_successes = 0;
    std::uint64_t unique_file_references = 0;
    std::uint64_t unique_parent_references = 0;
    std::uint64_t lineage_classified_records = 0;
    std::uint64_t lineage_membership_lookups = 0;
    std::uint64_t delta_unique_files = 0;
    std::uint64_t delta_targeted_resolutions = 0;
};

// Synthetic evidence used to classify a resolution.
struct SyntheticResolutionEvidence {
    bool file_path_resolved = false;
    bool file_inside_root = false;
    bool parent_path_resolved = false;
    bool parent_inside_root = false;
    bool file_missing = false;
    bool parent_missing = false;
    bool filename_valid = false;
    bool parent_history_ambiguous = false;
    bool access_denied = false;
    bool unknown_reason = false;
};

// Classifies the change as internal, external, or indeterminate.
ChangeEvidence classify_resolution_evidence(
    const SyntheticResolutionEvidence& evidence) noexcept;

// Probes the USN journal and populates diagnostics for resolution failures.
std::expected<ChangeJournalProbe, std::string>
probe_change_journal_diagnostic(const std::filesystem::path& local_root,
                                const ChangeJournalCheckpoint& checkpoint,
                                ChangeJournalDiagnostics& diagnostics);

// Returns the stable name of a diagnostic category.
const char* unresolved_reason_name(UnresolvedReason reason) noexcept;

} // namespace kasumi::platform

#endif
