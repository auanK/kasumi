#include "platform/change_journal.hpp"

#include "change_journal_diagnostic.hpp"
#include "platform/perf_trace.hpp"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <cwctype>
#include <limits>
#include <optional>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#endif

namespace kasumi::platform {

ChangeEvidence
classify_record_membership(const ChangeJournalRecordIdentity& record,
                           const DirectoryLineageView& lineage) noexcept {
    if (!lineage.complete || !lineage.checkpoint_bound)
        return ChangeEvidence::Indeterminate;
    const auto contains = [&](std::uint64_t reference) {
        return std::binary_search(lineage.inside_directory_frns.begin(),
                                  lineage.inside_directory_frns.end(),
                                  reference);
    };
    return contains(record.file_reference) || contains(record.parent_reference)
               ? ChangeEvidence::Dirty
               : ChangeEvidence::Clean;
}

ChangeEvidence classify_resolution_evidence(
    const SyntheticResolutionEvidence& evidence) noexcept {
    if (evidence.access_denied || evidence.unknown_reason)
        return ChangeEvidence::Indeterminate;
    if (evidence.file_path_resolved)
        return evidence.file_inside_root ? ChangeEvidence::Dirty
                                         : ChangeEvidence::Clean;
    if (!evidence.file_missing || !evidence.parent_path_resolved ||
        evidence.parent_missing || !evidence.filename_valid ||
        evidence.parent_history_ambiguous)
        return ChangeEvidence::Indeterminate;
    return evidence.parent_inside_root ? ChangeEvidence::Dirty
                                       : ChangeEvidence::Clean;
}

bool valid_change_journal_checkpoint(
    const ChangeJournalCheckpoint& checkpoint) noexcept {
    return checkpoint.kind == ChangeJournalKind::WindowsNtfsUsnV1 &&
           checkpoint.volume_serial != 0 && checkpoint.journal_id != 0 &&
           checkpoint.next_usn >= 0 && checkpoint.root_file_reference != 0;
}

#if defined(_WIN32)
namespace {

using NativeHandle = HANDLE;

bool valid_handle(NativeHandle handle) noexcept {
    return handle != nullptr && handle != INVALID_HANDLE_VALUE;
}

void close_handle(NativeHandle handle) noexcept {
    if (valid_handle(handle))
        CloseHandle(handle);
}

struct JournalDataV1 {
    DWORDLONG id;
    USN first;
    USN next;
    USN lowest;
    USN max;
    DWORDLONG maximum_size;
    DWORDLONG allocation_delta;
    WORD minimum_version;
    WORD maximum_version;
};

struct ReadJournalDataV1 {
    USN start;
    DWORD reason_mask;
    DWORD return_only_on_close;
    DWORDLONG timeout;
    DWORDLONG bytes_to_wait_for;
    DWORDLONG id;
    WORD minimum_version;
    WORD maximum_version;
};

struct RecordHeader {
    DWORD length;
    WORD major;
    WORD minor;
};

std::string native_error(DWORD code) {
    return std::error_code{static_cast<int>(code), std::system_category()}
        .message();
}

NativeHandle open_volume(const std::filesystem::path& root) {
    WCHAR volume_path[MAX_PATH]{};
    if (!GetVolumePathNameW(root.c_str(),
                            volume_path,
                            static_cast<DWORD>(std::size(volume_path))))
        return {};
    std::wstring volume{volume_path};
    if (volume.size() < 2)
        return {};
    const auto device = L"\\\\." + volume.substr(0, 2);
    for (const auto access : {static_cast<DWORD>(FILE_READ_ATTRIBUTES),
                              static_cast<DWORD>(GENERIC_READ),
                              static_cast<DWORD>(0)}) {
        for (const auto share :
             {static_cast<DWORD>(FILE_SHARE_READ | FILE_SHARE_WRITE |
                                 FILE_SHARE_DELETE),
              static_cast<DWORD>(FILE_SHARE_READ | FILE_SHARE_WRITE)}) {
            const auto handle = CreateFileW(device.c_str(),
                                            access,
                                            share,
                                            nullptr,
                                            OPEN_EXISTING,
                                            0,
                                            nullptr);
            if (valid_handle(handle))
                return handle;
        }
    }
    // Without volume access, try the root for unprivileged USN reading.
    return CreateFileW(root.c_str(),
                       FILE_READ_ATTRIBUTES,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       nullptr,
                       OPEN_EXISTING,
                       FILE_FLAG_BACKUP_SEMANTICS,
                       nullptr);
}

NativeHandle open_root(const std::filesystem::path& root) {
    return CreateFileW(root.c_str(),
                       FILE_READ_ATTRIBUTES,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       nullptr,
                       OPEN_EXISTING,
                       FILE_FLAG_BACKUP_SEMANTICS,
                       nullptr);
}

std::uint64_t file_reference(HANDLE handle) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle, &info))
        return 0;
    return (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) |
           info.nFileIndexLow;
}

std::uint64_t volume_serial(HANDLE handle) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle, &info))
        return 0;
    return info.dwVolumeSerialNumber;
}

std::wstring handle_path(HANDLE handle) {
    std::wstring buffer(32768, L'\0');
    const auto length =
        GetFinalPathNameByHandleW(handle,
                                  buffer.data(),
                                  static_cast<DWORD>(buffer.size()),
                                  FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (length == 0 || length >= buffer.size())
        return {};
    buffer.resize(length);
    return buffer;
}

struct PathResolution {
    std::wstring path;
    DWORD error = ERROR_SUCCESS;
};

std::wstring lower(std::wstring value) {
    std::ranges::transform(value, value.begin(), [](wchar_t character) {
        return static_cast<wchar_t>(towlower(character));
    });
    std::ranges::replace(value, L'/', L'\\');
    return value;
}

bool inside_root(const std::wstring& root, const std::wstring& candidate) {
    const auto base = lower(root);
    const auto path = lower(candidate);
    return path == base ||
           (path.size() > base.size() && path.starts_with(base) &&
            path[base.size()] == L'\\');
}

PathResolution id_path(HANDLE volume,
                       std::uint64_t id,
                       ChangeJournalDiagnostics* diagnostics,
                       bool parent) {
    if (diagnostics != nullptr) {
        if (parent)
            ++diagnostics->parent_open_attempts;
        else
            ++diagnostics->file_open_attempts;
    }
    FILE_ID_DESCRIPTOR descriptor{};
    descriptor.dwSize = sizeof(descriptor);
    descriptor.Type = FileIdType;
    descriptor.FileId.QuadPart = static_cast<LONGLONG>(id);
    const auto object =
        OpenFileById(volume,
                     &descriptor,
                     FILE_READ_ATTRIBUTES,
                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                     nullptr,
                     FILE_FLAG_BACKUP_SEMANTICS);
    if (!valid_handle(object)) {
        const auto error = GetLastError();
        if (diagnostics != nullptr) {
            if (parent)
                ++diagnostics->parent_resolution_failures;
            else
                ++diagnostics->file_resolution_failures;
        }
        return {.path = {}, .error = error};
    }
    auto path = handle_path(object);
    const auto error = path.empty() ? GetLastError() : ERROR_SUCCESS;
    close_handle(object);
    if (path.empty() && diagnostics != nullptr) {
        if (parent)
            ++diagnostics->parent_resolution_failures;
        else
            ++diagnostics->file_resolution_failures;
    }
    return {.path = std::move(path), .error = error};
}

struct JournalInfo {
    JournalDataV1 data{};
    std::wstring root_path;
    std::uint64_t root = 0;
    std::uint64_t volume = 0;
};

std::expected<JournalInfo, std::string>
query(const std::filesystem::path& root_path, HANDLE volume) {
    auto root = open_root(root_path);
    if (!valid_handle(root))
        return std::unexpected("não foi possível abrir a raiz local");
    JournalInfo result{.root_path = handle_path(root),
                       .root = file_reference(root),
                       .volume = volume_serial(root)};
    close_handle(root);
    DWORD returned = 0;
    if (!DeviceIoControl(volume,
                         FSCTL_QUERY_USN_JOURNAL,
                         nullptr,
                         0,
                         &result.data,
                         sizeof(result.data),
                         &returned,
                         nullptr))
        return std::unexpected("não foi possível consultar o USN journal: " +
                               native_error(GetLastError()));
    if (returned < offsetof(JournalDataV1, max) + sizeof(USN) ||
        result.root == 0 || result.volume == 0 || result.root_path.empty())
        return std::unexpected(
            "a consulta ao USN journal retornou dados inválidos");
    return result;
}

constexpr DWORD known_reasons =
    USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_EXTEND |
    USN_REASON_DATA_TRUNCATION | USN_REASON_NAMED_DATA_OVERWRITE |
    USN_REASON_NAMED_DATA_EXTEND | USN_REASON_NAMED_DATA_TRUNCATION |
    USN_REASON_FILE_CREATE | USN_REASON_FILE_DELETE | USN_REASON_EA_CHANGE |
    USN_REASON_SECURITY_CHANGE | USN_REASON_RENAME_OLD_NAME |
    USN_REASON_RENAME_NEW_NAME | USN_REASON_INDEXABLE_CHANGE |
    USN_REASON_BASIC_INFO_CHANGE | USN_REASON_HARD_LINK_CHANGE |
    USN_REASON_COMPRESSION_CHANGE | USN_REASON_ENCRYPTION_CHANGE |
    USN_REASON_OBJECT_ID_CHANGE | USN_REASON_REPARSE_POINT_CHANGE |
    USN_REASON_STREAM_CHANGE | USN_REASON_TRANSACTED_CHANGE | USN_REASON_CLOSE;

constexpr DWORD selective_modify_reasons =
    USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_EXTEND |
    USN_REASON_DATA_TRUNCATION | USN_REASON_NAMED_DATA_OVERWRITE |
    USN_REASON_NAMED_DATA_EXTEND | USN_REASON_NAMED_DATA_TRUNCATION |
    USN_REASON_BASIC_INFO_CHANGE;

constexpr DWORD selective_create_reasons =
    selective_modify_reasons | USN_REASON_FILE_CREATE;

struct DeltaAccumulator {
    LocalDeltaProbe probe;
    std::unordered_map<std::uint64_t, std::size_t> by_file_reference;
    bool fallback = false;
};

void save_unresolved(const USN_RECORD& record,
                     UnresolvedReason category,
                     const PathResolution& file,
                     const PathResolution& parent,
                     ChangeJournalDiagnostics* diagnostics) {
    if (diagnostics == nullptr)
        return;
    if (diagnostics->unresolved.size() >= 64) {
        diagnostics->unresolved_diagnostics_truncated = true;
        return;
    }
    diagnostics->unresolved.push_back(UnresolvedDiagnostic{
        .usn = static_cast<std::int64_t>(record.Usn),
        .file_reference = record.FileReferenceNumber,
        .parent_reference = record.ParentFileReferenceNumber,
        .reason = record.Reason,
        .major_version = record.MajorVersion,
        .minor_version = record.MinorVersion,
        .file_name_offset = record.FileNameOffset,
        .file_name_length = record.FileNameLength,
        .file_name = std::wstring(record.FileName,
                                  record.FileNameLength / sizeof(wchar_t)),
        .category = category,
        .file_open_error = file.error,
        .parent_open_error = parent.error,
        .parent_path = parent.path,
        .file_path_resolved = !file.path.empty(),
        .parent_path_resolved = !parent.path.empty()});
}

void resolve_record(const USN_RECORD& record,
                    HANDLE volume,
                    const JournalInfo& journal,
                    ChangeJournalProbe& probe,
                    ChangeJournalDiagnostics* diagnostics) {
    if ((record.Reason & ~known_reasons) != 0) {
        ++probe.unresolved_records;
        save_unresolved(
            record, UnresolvedReason::UnknownReason, {}, {}, diagnostics);
        return;
    }
    if ((record.Reason & ~USN_REASON_CLOSE) == 0)
        return;
    PathResolution file{};
    if (record.FileReferenceNumber == journal.root)
        file.path = journal.root_path;
    else
        file = id_path(volume, record.FileReferenceNumber, diagnostics, false);
    PathResolution parent{};
    const bool historical_parent_fallback =
        diagnostics == nullptr &&
        (record.Reason &
         (USN_REASON_FILE_DELETE | USN_REASON_RENAME_OLD_NAME)) != 0;
    if (file.path.empty() &&
        (diagnostics != nullptr || historical_parent_fallback)) {
        if (record.ParentFileReferenceNumber == journal.root)
            parent.path = journal.root_path;
        else
            parent = id_path(
                volume, record.ParentFileReferenceNumber, diagnostics, true);
        if (!parent.path.empty()) {
            std::wstring name(record.FileName,
                              record.FileNameLength / sizeof(wchar_t));
            if (diagnostics != nullptr)
                ++diagnostics->parent_reconstruction_successes;
            if (historical_parent_fallback)
                file.path = parent.path + L"\\" + name;
        }
    }
    if (file.path.empty()) {
        ++probe.unresolved_records;
        const auto file_missing = file.error == ERROR_FILE_NOT_FOUND ||
                                  file.error == ERROR_PATH_NOT_FOUND ||
                                  file.error == ERROR_INVALID_HANDLE;
        const auto parent_missing = parent.error == ERROR_FILE_NOT_FOUND ||
                                    parent.error == ERROR_PATH_NOT_FOUND ||
                                    parent.error == ERROR_INVALID_HANDLE;
        const auto category =
            file.error == ERROR_ACCESS_DENIED
                ? UnresolvedReason::AccessDeniedObject
            : parent.error == ERROR_ACCESS_DENIED
                ? UnresolvedReason::AccessDeniedParent
            : file_missing && parent.path.empty() && parent_missing
                ? UnresolvedReason::ObjectMissingParentMissing
            : file_missing && !parent.path.empty()
                ? UnresolvedReason::ObjectMissingParentResolved
                : UnresolvedReason::OtherWin32Failure;
        save_unresolved(record, category, file, parent, diagnostics);
    } else if (inside_root(journal.root_path, file.path)) {
        ++probe.relevant_records;
    } else {
        ++probe.unrelated_records;
    }
}

std::filesystem::path relative_handle_path(const JournalInfo& journal,
                                           const std::wstring& path) {
    if (!inside_root(journal.root_path, path) ||
        path.size() <= journal.root_path.size())
        return {};
    const auto suffix = path.substr(journal.root_path.size() + 1);
    if (suffix.empty())
        return {};
    return std::filesystem::path{suffix};
}

void collect_delta_record(const USN_RECORD& record,
                          HANDLE volume,
                          const JournalInfo& journal,
                          DeltaAccumulator& delta,
                          ChangeJournalDiagnostics* diagnostics) {
    const auto reasons = record.Reason & ~USN_REASON_CLOSE;
    if (reasons == 0)
        return;
    if ((record.Reason & ~known_reasons) != 0 ||
        (reasons & ~selective_create_reasons) != 0 ||
        (record.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        delta.fallback = true;
        return;
    }
    if (record.FileReferenceNumber == journal.root) {
        // The root cannot be treated as a file patch.
        delta.fallback = true;
        return;
    }
    const auto file =
        id_path(volume, record.FileReferenceNumber, diagnostics, false);
    if (file.path.empty()) {
        delta.fallback = true;
        return;
    }
    const auto attributes = GetFileAttributesW(file.path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        delta.fallback = true;
        return;
    }
    const auto relative = relative_handle_path(journal, file.path);
    if (relative.empty() || relative.is_absolute() ||
        relative.has_root_name() || relative.has_root_directory() ||
        std::ranges::find(relative, std::filesystem::path{".."}) !=
            relative.end()) {
        delta.fallback = true;
        return;
    }
    if (const auto found =
            delta.by_file_reference.find(record.FileReferenceNumber);
        found != delta.by_file_reference.end()) {
        if ((reasons & USN_REASON_FILE_CREATE) != 0)
            delta.probe.entries[found->second].kind =
                LocalDeltaKind::CreateFileEntry;
        delta.probe.entries[found->second].current_relative_path = relative;
        return;
    }
    delta.by_file_reference.emplace(record.FileReferenceNumber,
                                    delta.probe.entries.size());
    delta.probe.entries.push_back(
        LocalDeltaEntry{.kind = (reasons & USN_REASON_FILE_CREATE) != 0
                                    ? LocalDeltaKind::CreateFileEntry
                                    : LocalDeltaKind::ModifyExistingFile,
                        .file_reference = record.FileReferenceNumber,
                        .parent_reference = record.ParentFileReferenceNumber,
                        .current_relative_path = relative});
    if (diagnostics != nullptr)
        ++diagnostics->delta_targeted_resolutions;
}

ChangeJournalProbe read(const JournalInfo& journal,
                        HANDLE volume,
                        const ChangeJournalCheckpoint& checkpoint,
                        ChangeJournalDiagnostics* diagnostics,
                        const DirectoryLineageView* lineage,
                        DeltaAccumulator* delta) {
    ChangeJournalProbe result;
    result.next = {.kind = ChangeJournalKind::WindowsNtfsUsnV1,
                   .volume_serial = journal.volume,
                   .journal_id = journal.data.id,
                   .next_usn = journal.data.next,
                   .root_file_reference = journal.root};
    const auto start = static_cast<USN>(checkpoint.next_usn);
    if (checkpoint.volume_serial != journal.volume ||
        checkpoint.journal_id != journal.data.id ||
        checkpoint.root_file_reference != journal.root ||
        start < journal.data.first || start < journal.data.lowest ||
        start > journal.data.next) {
        result.evidence = ChangeEvidence::Indeterminate;
        return result;
    }
    if (lineage != nullptr &&
        (!lineage->complete || !lineage->checkpoint_bound ||
         lineage->inside_directory_frns.empty())) {
        result.evidence = ChangeEvidence::Indeterminate;
        return result;
    }
    if (start == journal.data.next) {
        result.evidence = ChangeEvidence::Clean;
        if (delta != nullptr) {
            delta->probe.next = result.next;
            delta->probe.disposition = LocalDeltaDisposition::Clean;
        }
        return result;
    }

    USN cursor = start;
    std::vector<std::byte> buffer(1024 * 1024);
    std::optional<std::unordered_set<std::uint64_t>> unique_files;
    std::optional<std::unordered_set<std::uint64_t>> unique_parents;
    if (diagnostics != nullptr) {
        unique_files.emplace();
        unique_parents.emplace();
    }
    while (cursor < journal.data.next) {
        ReadJournalDataV1 request{.start = cursor,
                                  .reason_mask =
                                      std::numeric_limits<DWORD>::max(),
                                  .return_only_on_close = FALSE,
                                  .timeout = 0,
                                  .bytes_to_wait_for = 0,
                                  .id = journal.data.id,
                                  .minimum_version = 2,
                                  .maximum_version = 2};
        DWORD returned = 0;
        auto ok = DeviceIoControl(volume,
                                  FSCTL_READ_USN_JOURNAL,
                                  &request,
                                  sizeof(request),
                                  buffer.data(),
                                  static_cast<DWORD>(buffer.size()),
                                  &returned,
                                  nullptr);
        if (!ok && GetLastError() == ERROR_ACCESS_DENIED) {
            ok = DeviceIoControl(volume,
                                 FSCTL_READ_UNPRIVILEGED_USN_JOURNAL,
                                 &request,
                                 sizeof(request),
                                 buffer.data(),
                                 static_cast<DWORD>(buffer.size()),
                                 &returned,
                                 nullptr);
        }
        if (!ok || returned < sizeof(USN)) {
            result.evidence = ChangeEvidence::Indeterminate;
            return result;
        }
        USN next = 0;
        std::memcpy(&next, buffer.data(), sizeof(next));
        if (next <= cursor) {
            result.evidence = ChangeEvidence::Indeterminate;
            return result;
        }
        std::size_t offset = sizeof(USN);
        while (offset < returned) {
            if (returned - offset < sizeof(RecordHeader)) {
                result.evidence = ChangeEvidence::Indeterminate;
                return result;
            }
            const auto* header =
                reinterpret_cast<const RecordHeader*>(buffer.data() + offset);
            if (header->length < sizeof(RecordHeader) ||
                header->length > returned - offset || header->length % 8 != 0 ||
                header->major != 2 ||
                header->length < offsetof(USN_RECORD, FileName) ||
                header->length < sizeof(USN_RECORD) - sizeof(WCHAR)) {
                result.evidence = ChangeEvidence::Indeterminate;
                return result;
            }
            const auto* record =
                reinterpret_cast<const USN_RECORD*>(buffer.data() + offset);
            const auto name_end =
                static_cast<std::size_t>(record->FileNameOffset) +
                record->FileNameLength;
            if (record->FileNameOffset < offsetof(USN_RECORD, FileName) ||
                record->FileNameLength % sizeof(WCHAR) != 0 ||
                name_end > header->length) {
                result.evidence = ChangeEvidence::Indeterminate;
                return result;
            }
            if (record->Usn >= start && record->Usn < journal.data.next) {
                ++result.records_read;
                if (diagnostics != nullptr) {
                    unique_files->insert(record->FileReferenceNumber);
                    unique_parents->insert(record->ParentFileReferenceNumber);
                }
                if (lineage != nullptr) {
                    if (diagnostics != nullptr) {
                        diagnostics->lineage_classified_records++;
                        diagnostics->lineage_membership_lookups += 2;
                    }
                    const auto membership = classify_record_membership(
                        {.file_reference = record->FileReferenceNumber,
                         .parent_reference = record->ParentFileReferenceNumber,
                         .is_directory = (record->FileAttributes &
                                          FILE_ATTRIBUTE_DIRECTORY) != 0},
                        *lineage);
                    if (membership == ChangeEvidence::Indeterminate) {
                        if (delta != nullptr) {
                            delta->fallback = true;
                        } else {
                            result.evidence = ChangeEvidence::Indeterminate;
                            return result;
                        }
                    } else if (membership == ChangeEvidence::Dirty) {
                        ++result.relevant_records;
                        if (delta != nullptr) {
                            collect_delta_record(
                                *record, volume, journal, *delta, diagnostics);
                        } else {
                            result.evidence = ChangeEvidence::Dirty;
                            return result;
                        }
                    } else {
                        ++result.unrelated_records;
                    }
                } else {
                    resolve_record(
                        *record, volume, journal, result, diagnostics);
                }
            }
            offset += header->length;
        }
        cursor = next;
    }
    result.evidence = result.unresolved_records != 0
                          ? ChangeEvidence::Indeterminate
                      : result.relevant_records != 0 ? ChangeEvidence::Dirty
                                                     : ChangeEvidence::Clean;
    if (diagnostics != nullptr) {
        diagnostics->unique_file_references = unique_files->size();
        diagnostics->unique_parent_references = unique_parents->size();
    }
    if (delta != nullptr) {
        delta->probe.next = result.next;
        delta->probe.records_read = result.records_read;
        delta->probe.relevant_records = result.relevant_records;
        delta->probe.unrelated_records = result.unrelated_records;
        delta->probe.disposition =
            delta->fallback                ? LocalDeltaDisposition::Fallback
            : delta->probe.entries.empty() ? LocalDeltaDisposition::Clean
                                           : LocalDeltaDisposition::Patchable;
        if (diagnostics != nullptr)
            diagnostics->delta_unique_files = delta->probe.entries.size();
    }
    return result;
}

} // namespace
#endif

std::expected<ChangeJournalCheckpoint, std::string>
capture_change_journal_checkpoint(const std::filesystem::path& local_root) {
    const auto trace = perf_trace::begin();
    perf_trace::count("USN checkpoint captures");
#if !defined(_WIN32)
    static_cast<void>(local_root);
    static_cast<void>(trace);
    return std::unexpected("o USN journal só está disponível no Windows");
#else
    const auto volume = open_volume(local_root);
    if (!valid_handle(volume))
        return std::unexpected(
            "não foi possível abrir o volume local para o USN journal");
    auto journal = query(local_root, volume);
    close_handle(volume);
    if (!journal)
        return std::unexpected(journal.error());
    const ChangeJournalCheckpoint result{
        .kind = ChangeJournalKind::WindowsNtfsUsnV1,
        .volume_serial = journal->volume,
        .journal_id = journal->data.id,
        .next_usn = journal->data.next,
        .root_file_reference = journal->root};
    if (!valid_change_journal_checkpoint(result))
        return std::unexpected("o ponto de controle do USN é inválido");
    perf_trace::finish("USN checkpoint wall", trace);
    return result;
#endif
}

std::expected<ChangeJournalProbe, std::string>
probe_change_journal(const std::filesystem::path& local_root,
                     const ChangeJournalCheckpoint& checkpoint) {
    const auto trace = perf_trace::begin();
    perf_trace::count("USN probes");
#if !defined(_WIN32)
    static_cast<void>(local_root);
    static_cast<void>(checkpoint);
    static_cast<void>(trace);
    return std::unexpected("o USN journal só está disponível no Windows");
#else
    if (!valid_change_journal_checkpoint(checkpoint))
        return std::unexpected("o ponto de controle do USN é inválido");
    const auto volume = open_volume(local_root);
    if (!valid_handle(volume))
        return std::unexpected(
            "não foi possível abrir o volume local para o USN journal");
    auto journal = query(local_root, volume);
    if (!journal) {
        close_handle(volume);
        return std::unexpected(journal.error());
    }
    auto result = read(*journal, volume, checkpoint, nullptr, nullptr, nullptr);
    close_handle(volume);
    perf_trace::finish("USN probe wall", trace);
    perf_trace::count("USN records read", result.records_read);
    perf_trace::count("USN relevant records", result.relevant_records);
    perf_trace::count("USN unrelated records", result.unrelated_records);
    perf_trace::count("USN unresolved records", result.unresolved_records);
    switch (result.evidence) {
        case ChangeEvidence::Clean:
            perf_trace::count("USN clean evidence");
            break;
        case ChangeEvidence::Dirty:
            perf_trace::count("USN dirty evidence");
            break;
        case ChangeEvidence::Indeterminate:
            perf_trace::count("USN indeterminate evidence");
            break;
    }
    return result;
#endif
}

std::expected<ChangeJournalProbe, std::string>
probe_change_journal(const std::filesystem::path& local_root,
                     const ChangeJournalCheckpoint& checkpoint,
                     DirectoryLineageView lineage,
                     ChangeJournalDiagnostics* diagnostics) {
    const auto trace = perf_trace::begin();
    perf_trace::count("USN lineage probes");
#if !defined(_WIN32)
    static_cast<void>(local_root);
    static_cast<void>(checkpoint);
    static_cast<void>(lineage);
    static_cast<void>(diagnostics);
    static_cast<void>(trace);
    return std::unexpected("o USN journal só está disponível no Windows");
#else
    if (!valid_change_journal_checkpoint(checkpoint))
        return std::unexpected("o ponto de controle do USN é inválido");
    const auto volume = open_volume(local_root);
    if (!valid_handle(volume))
        return std::unexpected(
            "não foi possível abrir o volume local para o USN journal");
    auto journal = query(local_root, volume);
    if (!journal) {
        close_handle(volume);
        return std::unexpected(journal.error());
    }
    auto result =
        read(*journal, volume, checkpoint, diagnostics, &lineage, nullptr);
    close_handle(volume);
    perf_trace::finish("USN lineage probe wall", trace);
    perf_trace::count("USN lineage records read", result.records_read);
    perf_trace::count("USN lineage membership lookups",
                      result.records_read * 2);
    return result;
#endif
}

std::expected<LocalDeltaProbe, std::string>
probe_change_journal_delta(const std::filesystem::path& local_root,
                           const ChangeJournalCheckpoint& checkpoint,
                           DirectoryLineageView lineage,
                           ChangeJournalDiagnostics* diagnostics) {
    const auto trace = perf_trace::begin();
    perf_trace::count("USN delta probes");
#if !defined(_WIN32)
    static_cast<void>(local_root);
    static_cast<void>(checkpoint);
    static_cast<void>(lineage);
    static_cast<void>(diagnostics);
    static_cast<void>(trace);
    return std::unexpected("o USN journal só está disponível no Windows");
#else
    DeltaAccumulator delta;
    if (!valid_change_journal_checkpoint(checkpoint))
        return std::unexpected("o ponto de controle de state.db é inválido");
    const auto volume = open_volume(local_root);
    if (!valid_handle(volume))
        return std::unexpected(
            "não foi possível abrir o volume local para o USN journal");
    auto journal = query(local_root, volume);
    if (!journal) {
        close_handle(volume);
        return std::unexpected(journal.error());
    }
    const auto result =
        read(*journal, volume, checkpoint, diagnostics, &lineage, &delta);
    close_handle(volume);
    delta.probe.next = result.next;
    delta.probe.records_read = result.records_read;
    delta.probe.relevant_records = result.relevant_records;
    delta.probe.unrelated_records = result.unrelated_records;
    if (result.evidence == ChangeEvidence::Indeterminate)
        delta.probe.disposition = LocalDeltaDisposition::Fallback;
    perf_trace::finish("USN delta probe wall", trace);
    perf_trace::count("USN delta records", delta.probe.records_read);
    perf_trace::count("USN delta unique files", delta.probe.entries.size());
    return delta.probe;
#endif
}

std::expected<ChangeJournalProbe, std::string>
probe_change_journal_diagnostic(const std::filesystem::path& local_root,
                                const ChangeJournalCheckpoint& checkpoint,
                                ChangeJournalDiagnostics& diagnostics) {
#if !defined(_WIN32)
    static_cast<void>(local_root);
    static_cast<void>(checkpoint);
    static_cast<void>(diagnostics);
    return std::unexpected("o USN journal só está disponível no Windows");
#else
    if (!valid_change_journal_checkpoint(checkpoint))
        return std::unexpected("o ponto de controle do USN é inválido");
    const auto volume = open_volume(local_root);
    if (!valid_handle(volume))
        return std::unexpected(
            "não foi possível abrir o volume local para o USN journal");
    auto journal = query(local_root, volume);
    if (!journal) {
        close_handle(volume);
        return std::unexpected(journal.error());
    }
    auto result =
        read(*journal, volume, checkpoint, &diagnostics, nullptr, nullptr);
    close_handle(volume);
    return result;
#endif
}

const char* unresolved_reason_name(UnresolvedReason reason) noexcept {
    switch (reason) {
        case UnresolvedReason::ObjectMissingParentResolved:
            return "ObjectMissingParentResolved";
        case UnresolvedReason::ObjectMissingParentMissing:
            return "ObjectMissingParentMissing";
        case UnresolvedReason::AccessDeniedObject:
            return "AccessDeniedObject";
        case UnresolvedReason::AccessDeniedParent:
            return "AccessDeniedParent";
        case UnresolvedReason::UnknownReason:
            return "UnknownReason";
        case UnresolvedReason::UnsupportedVersion:
            return "UnsupportedVersion";
        case UnresolvedReason::MalformedRecord:
            return "MalformedRecord";
        case UnresolvedReason::RootIdentityProblem:
            return "RootIdentityProblem";
        case UnresolvedReason::OtherWin32Failure:
            return "OtherWin32Failure";
    }
    return "OtherWin32Failure";
}

} // namespace kasumi::platform
