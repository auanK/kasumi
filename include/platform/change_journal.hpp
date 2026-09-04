#ifndef KASUMI_PLATFORM_CHANGE_JOURNAL_HPP
#define KASUMI_PLATFORM_CHANGE_JOURNAL_HPP

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace kasumi::platform {

// Optional diagnostics for change journal reading.
struct ChangeJournalDiagnostics;

// Supported change journal formats.
enum class ChangeJournalKind : std::uint8_t {
    WindowsNtfsUsnV1 = 1
};

// Persistable change journal checkpoint.
struct ChangeJournalCheckpoint {
    ChangeJournalKind kind = ChangeJournalKind::WindowsNtfsUsnV1;
    // Identifies the observed volume.
    std::uint64_t volume_serial = 0;
    // Distinguishes journal recreations on the same volume.
    std::uint64_t journal_id = 0;
    // First unobserved record position.
    std::int64_t next_usn = 0;
    // Volume reference ID of the observed root.
    std::uint64_t root_file_reference = 0;
};

// Conservative change detection outcome.
enum class ChangeEvidence {
    Clean,
    Dirty,
    Indeterminate
};

// Minimal record identity for lineage-based classification.
struct ChangeJournalRecordIdentity {
    std::uint64_t file_reference = 0;
    std::uint64_t parent_reference = 0;
    bool is_directory = false;
};

// Non-owning view of the known root lineage.
struct DirectoryLineageView {
    // Ordered references of known directories.
    std::span<const std::uint64_t> inside_directory_frns;
    // Indicates that all directories under the root were gathered.
    bool complete = false;
    // Indicates binding to the same checkpoint.
    bool checkpoint_bound = false;
};

// Incomplete or unbound lineage yields indeterminate outcome.
ChangeEvidence
classify_record_membership(const ChangeJournalRecordIdentity& record,
                           const DirectoryLineageView& lineage) noexcept;

// Outcome of attempting to produce a safe local delta.
enum class LocalDeltaDisposition {
    Clean,
    Patchable,
    Fallback
};

// Recognized change types in the journal.
enum class LocalDeltaKind {
    ModifyExistingFile,
    CreateFileEntry,
    Unsupported,
};

// Normalized local change derived from a journal record.
struct LocalDeltaEntry {
    LocalDeltaKind kind = LocalDeltaKind::Unsupported;
    std::uint64_t file_reference = 0;
    std::uint64_t parent_reference = 0;
    std::filesystem::path current_relative_path;
};

// Local delta and checkpoint following the probed window.
struct LocalDeltaProbe {
    LocalDeltaDisposition disposition = LocalDeltaDisposition::Fallback;
    // Checkpoint after the probed window.
    ChangeJournalCheckpoint next{};
    std::vector<LocalDeltaEntry> entries;
    std::uint64_t records_read = 0;
    std::uint64_t relevant_records = 0;
    std::uint64_t unrelated_records = 0;
};

// Summary of change detection since a checkpoint.
struct ChangeJournalProbe {
    ChangeEvidence evidence = ChangeEvidence::Indeterminate;
    // Checkpoint after the probed window.
    ChangeJournalCheckpoint next{};
    std::uint64_t records_read = 0;
    std::uint64_t relevant_records = 0;
    std::uint64_t unrelated_records = 0;
    std::uint64_t unresolved_records = 0;
};

// Validates checkpoint fields.
bool valid_change_journal_checkpoint(
    const ChangeJournalCheckpoint& checkpoint) noexcept;

// Captures the current change journal position for the root.
std::expected<ChangeJournalCheckpoint, std::string>
capture_change_journal_checkpoint(const std::filesystem::path& local_root);

// Detects changes since the given checkpoint.
std::expected<ChangeJournalProbe, std::string>
probe_change_journal(const std::filesystem::path& local_root,
                     const ChangeJournalCheckpoint& checkpoint);

// Detects changes using lineage and optional diagnostics.
std::expected<ChangeJournalProbe, std::string>
probe_change_journal(const std::filesystem::path& local_root,
                     const ChangeJournalCheckpoint& checkpoint,
                     DirectoryLineageView lineage,
                     ChangeJournalDiagnostics* diagnostics = nullptr);

// Extracts applicable changes or requests a full scan fallback.
std::expected<LocalDeltaProbe, std::string>
probe_change_journal_delta(const std::filesystem::path& local_root,
                           const ChangeJournalCheckpoint& checkpoint,
                           DirectoryLineageView lineage,
                           ChangeJournalDiagnostics* diagnostics = nullptr);

} // namespace kasumi::platform

#endif
