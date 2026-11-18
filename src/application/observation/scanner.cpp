#include "application/observation/scanner.hpp"

#include "application/concurrency.hpp"
#include "application/observation/cache_contract.hpp"
#include "application/observation/file_metadata.hpp"
#include "application/progress.hpp"
#include "core/ignore.hpp"
#include "crypto/content.hpp"
#include "platform/metadata.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "platform/private_storage.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace kasumi::application::observation::scanner {
namespace {

using kasumi::ignore::classify_ignore;
using kasumi::ignore::IgnoreDisposition;
using kasumi::ignore::IgnoreList;
using kasumi::ignore::is_ignored;
using kasumi::ignore::load_ignore_list;

struct ScanFrame {
    std::filesystem::directory_iterator iterator;
    std::filesystem::directory_iterator end;
    std::string path;
    std::size_t evidence_index = 0;
};

struct ScanContext {
    ScanPolicy policy = ScanPolicy::FullHash;
    MetadataQuery metadata_query = cache::read_file_metadata;
    std::int64_t scan_start_ns = 0;
    std::unordered_map<std::string_view, const state_storage::FileCacheRow*>
        previous;
    std::vector<state_storage::FileCacheRow> cache;
    ProgressMeter* progress = nullptr;
};

ScanError scan_error(const std::filesystem::path& path,
                     std::string operation,
                     const std::error_code& error,
                     ScanErrorCode fallback) {
    return {error == std::errc::permission_denied
                ? ScanErrorCode::PermissionDenied
                : fallback,
            path,
            std::move(operation),
            error.message()};
}

struct PhysicalEntryType {
    bool directory = false;
    bool regular_file = false;
    bool linklike = false;
};

std::expected<PhysicalEntryType, std::error_code>
classify_entry(const std::filesystem::path& path,
               const std::filesystem::file_status& status) {
#if defined(_WIN32)
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return std::unexpected(std::error_code(static_cast<int>(GetLastError()),
                                               std::system_category()));
    }
    const bool directory = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (std::filesystem::is_symlink(status) ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return PhysicalEntryType{
            .directory = directory, .regular_file = false, .linklike = true};
    }
#else
    static_cast<void>(path);
    if (std::filesystem::is_symlink(status)) {
        return PhysicalEntryType{
            .directory = false, .regular_file = false, .linklike = true};
    }
#endif
    if (status.type() == std::filesystem::file_type::none ||
        status.type() == std::filesystem::file_type::not_found ||
        status.type() == std::filesystem::file_type::unknown) {
        return std::unexpected(std::make_error_code(std::errc::io_error));
    }
    return PhysicalEntryType{.directory = std::filesystem::is_directory(status),
                             .regular_file =
                                 std::filesystem::is_regular_file(status),
                             .linklike = false};
}

std::expected<PhysicalEntryType, ScanError>
classify_path(const std::filesystem::path& path,
              const std::filesystem::file_status& status,
              const std::error_code& error) {
    if (error) {
        return std::unexpected(scan_error(
            path, "query entry type", error, ScanErrorCode::Metadata));
    }
    auto type = classify_entry(path, status);
    if (!type) {
        return std::unexpected(scan_error(
            path, "classify entry", type.error(), ScanErrorCode::Metadata));
    }
    return *type;
}

std::expected<cache::FileMetadata, ScanError>
query_file_metadata(const MetadataQuery& metadata_query,
                    const std::filesystem::path& file_path,
                    std::string_view relative_path,
                    const char* operation,
                    const char* missing_detail) {
    const auto meta_result = metadata_query(file_path, relative_path);
    if (!meta_result) {
        const auto& err = meta_result.error();
        return std::unexpected(ScanError{
            .code = err.code == cache::FileMetadataErrorCode::PermissionDenied
                        ? ScanErrorCode::PermissionDenied
                        : ScanErrorCode::Metadata,
            .path = file_path,
            .operation = operation,
            .detail = err.message});
    }
    if (!meta_result->has_value()) {
        return std::unexpected(ScanError{.code = ScanErrorCode::Metadata,
                                         .path = file_path,
                                         .operation = operation,
                                         .detail = missing_detail});
    }
    return **meta_result;
}

struct ProcessedFile {
    NodeRow row;
    std::optional<state_storage::FileCacheRow> cache_row;
};

struct PendingFile {
    std::filesystem::path physical_path;
    std::string relative;
};

bool is_racy_clean(std::int64_t mtime_ns, std::int64_t scan_start_ns) noexcept {
    constexpr std::int64_t racy_clean_window_ns = 20'000'000LL;
    const std::int64_t mtime_delta = scan_start_ns >= mtime_ns
                                         ? (scan_start_ns - mtime_ns)
                                         : (mtime_ns - scan_start_ns);
    return mtime_delta < racy_clean_window_ns;
}

std::optional<state_storage::FileCacheRow>
try_reuse_cached_row(const ScanContext& context,
                     const cache::FileMetadata& current_meta,
                     NodeRow& row) {
    if (context.policy != ScanPolicy::ReuseStrongFingerprint ||
        !current_meta.identity.has_value()) {
        return std::nullopt;
    }
    const auto cached = context.previous.find(row.path);
    if (cached == context.previous.end()) {
        return std::nullopt;
    }
    const auto& cached_row = *cached->second;
    const cache::FileMetadata cached_meta{
        .path = cached_row.path,
        .kind = cache::EntryKind::RegularFile,
        .size = cached_row.size,
        .mtime_nanoseconds = cached_row.mtime_nanoseconds,
        .identity = cache::FileIdentity{.volume = cached_row.volume,
                                        .file_low = cached_row.file_low,
                                        .file_high = cached_row.file_high},
        .is_valid = true};
    if (is_racy_clean(current_meta.mtime_nanoseconds, context.scan_start_ns) ||
        cache::evaluate_cache_reuse(cached_meta, current_meta) !=
            cache::CacheReuseResult::Reusable) {
        return std::nullopt;
    }
    if (auto* progress = context.progress) {
        ProgressMeter::add(progress->files_seen);
        ProgressMeter::add(progress->files_bytes, current_meta.size);
        ProgressMeter::add(progress->cache_hits);
    }
    row.hash = cached_row.hash;
    platform::perf_trace::count("local hash cache hits");
    return cached_row;
}

std::expected<ProcessedFile, ScanError>
process_file_entry(const std::filesystem::path& file_path,
                   std::string relative,
                   const ScanContext& context) {
    NodeRow row{.path = std::move(relative)};
    auto initial_meta = query_file_metadata(
        context.metadata_query,
        file_path,
        row.path,
        "read metadata",
        "metadata query returned no metadata for a regular file");
    if (!initial_meta) {
        return std::unexpected(initial_meta.error());
    }

    auto current_meta = *initial_meta;
    row.size = current_meta.size;
    row.mtime = current_meta.mtime_nanoseconds;

    if (auto cached_hit = try_reuse_cached_row(context, current_meta, row)) {
        return ProcessedFile{.row = std::move(row),
                             .cache_row = std::move(*cached_hit)};
    }

    if (auto* progress = context.progress) {
        ProgressMeter::add(progress->files_seen);
        ProgressMeter::add(progress->files_bytes, current_meta.size);
    }
    platform::perf_trace::count("local hash cache misses");
    std::expected<Hash, std::string> hash = std::unexpected("unhashed");
    bool stable = false;
    for (int attempt = 0; attempt < 2; ++attempt) {
        const auto before_meta = current_meta;
        hash = crypto::content::hash_file(
            file_path,
            context.progress ? &context.progress->disk_bytes : nullptr);
        platform::perf_trace::count("local hash file calls");
        platform::perf_trace::count("local hash bytes", before_meta.size);
        if (!hash)
            break;

        auto after_result =
            query_file_metadata(context.metadata_query,
                                file_path,
                                row.path,
                                "read metadata after hashing",
                                "file replaced or removed during hash");
        if (!after_result) {
            return std::unexpected(after_result.error());
        }
        const auto after_meta = *after_result;

        if (before_meta.identity == after_meta.identity &&
            before_meta.size == after_meta.size &&
            before_meta.mtime_nanoseconds == after_meta.mtime_nanoseconds) {
            stable = true;
            current_meta = after_meta;
            break;
        }

        if (!before_meta.identity.has_value() ||
            !after_meta.identity.has_value()) {
            break;
        }
        current_meta = after_meta;
        row.size = after_meta.size;
        row.mtime = after_meta.mtime_nanoseconds;
    }

    if (!hash)
        return std::unexpected(ScanError{
            ScanErrorCode::Io, file_path, "compute hash", hash.error()});
    if (!stable)
        return std::unexpected(ScanError{ScanErrorCode::Io,
                                         file_path,
                                         "compute hash",
                                         "file changed while being read"});
    row.hash = *hash;
    if (auto* progress = context.progress) {
        ProgressMeter::add(progress->files_hashed);
    }
    std::optional<state_storage::FileCacheRow> cache_row;
    if (current_meta.is_valid && current_meta.identity.has_value()) {
        cache_row = state_storage::FileCacheRow{
            .path = row.path,
            .hash = row.hash,
            .size = current_meta.size,
            .mtime_nanoseconds = current_meta.mtime_nanoseconds,
            .volume = current_meta.identity->volume,
            .file_low = current_meta.identity->file_low,
            .file_high = current_meta.identity->file_high};
    }
    return ProcessedFile{.row = std::move(row),
                         .cache_row = std::move(cache_row)};
}

std::expected<NodeRow, ScanError>
process_file(const std::filesystem::path& file_path,
             std::string relative,
             ScanContext& context) {
    auto processed =
        process_file_entry(file_path, std::move(relative), context);
    if (!processed) {
        return std::unexpected(processed.error());
    }
    if (processed->cache_row) {
        context.cache.push_back(std::move(*processed->cache_row));
    }
    return std::move(processed->row);
}

std::expected<void, ScanError>
flush_pending_files(std::vector<PendingFile>& pending_files,
                    ScanContext& context,
                    Snapshot& snapshot) {
    if (pending_files.empty()) {
        return {};
    }
    if (pending_files.size() == 1 ||
        context.metadata_query != &cache::read_file_metadata) {
        for (auto& item : pending_files) {
            auto processed = process_file_entry(
                item.physical_path, std::move(item.relative), context);
            if (!processed) {
                return std::unexpected(processed.error());
            }
            snapshot.rows.push_back(std::move(processed->row));
            if (processed->cache_row) {
                context.cache.push_back(std::move(*processed->cache_row));
            }
        }
        return {};
    }

    std::ranges::sort(pending_files, path_less, &PendingFile::relative);
    const auto hw = std::thread::hardware_concurrency();
    const std::size_t workers = std::clamp<std::size_t>(hw == 0 ? 4 : hw, 2, 8);
    std::vector<std::expected<ProcessedFile, ScanError>> outcomes(
        pending_files.size(),
        std::unexpected(ScanError{}));
    application::parallel_for_indexed(
        pending_files.size(), workers, [&](std::size_t index) {
            outcomes[index] = process_file_entry(pending_files[index].physical_path,
                                                 pending_files[index].relative,
                                                 context);
        });
    for (auto& outcome : outcomes) {
        if (!outcome) {
            return std::unexpected(outcome.error());
        }
    }
    snapshot.rows.reserve(snapshot.rows.size() + outcomes.size());
    for (auto& outcome : outcomes) {
        snapshot.rows.push_back(std::move(outcome->row));
        if (outcome->cache_row) {
            context.cache.push_back(std::move(*outcome->cache_row));
        }
    }
    return {};
}

std::expected<void, ScanError>
validate_ignore_list(const std::filesystem::path& local_root,
                     const IgnoreList& ignore_list) {
    if (ignore_list.parse_error) {
        return std::unexpected(ScanError{
            .code = ScanErrorCode::Io,
            .path = local_root / ".kasumiignore",
            .operation =
                ignore_list.parse_error->line == 0
                    ? "read ignore file"
                    : "parse ignore rule at line " +
                          std::to_string(ignore_list.parse_error->line),
            .detail = ignore_list.parse_error->detail,
        });
    }
    return {};
}

std::expected<std::int64_t, ScanError>
read_directory_mtime(const std::filesystem::path& path) {
    const auto modified = platform::metadata::last_write_time(path);
    if (!modified) {
        return std::unexpected(ScanError{ScanErrorCode::Metadata,
                                         path,
                                         "read modification time",
                                         modified.error()});
    }
    const auto mtime_ns = platform::metadata::unix_nanoseconds(*modified);
    if (!mtime_ns) {
        return std::unexpected(ScanError{ScanErrorCode::Metadata,
                                         path,
                                         "convert modification time",
                                         "timestamp is out of range"});
    }
    return *mtime_ns;
}

std::expected<void, ScanError>
verify_disposable_metadata(const std::filesystem::path& current,
                           std::string_view relative,
                           const reconciliation::IgnoredEntryEvidence& found,
                           MetadataQuery metadata_query,
                           const IgnoreList* ignore_list,
                           const char* operation,
                           const char* mismatch_detail) {
    auto metadata = metadata_query(current, relative);
    if (!metadata || !metadata->has_value() ||
        !(**metadata).identity.has_value()) {
        return std::unexpected(ScanError{
            .code = ScanErrorCode::Metadata,
            .path = current,
            .operation = operation,
            .detail = !metadata ? metadata.error().message
                                : "file identity is unavailable",
        });
    }
    const PhysicalFileIdentity observed_identity{
        .volume_or_dev = (**metadata).identity->volume,
        .file_id_low = (**metadata).identity->file_low,
        .file_id_high = (**metadata).identity->file_high,
        .valid = true,
    };
    if (observed_identity != found.identity ||
        (**metadata).size != found.size ||
        (ignore_list != nullptr &&
         classify_ignore(relative, false, *ignore_list) !=
             IgnoreDisposition::IgnoredDisposable)) {
        return std::unexpected(ScanError{
            .code = ScanErrorCode::Metadata,
            .path = current,
            .operation = operation,
            .detail = mismatch_detail,
        });
    }
    return {};
}

std::expected<void, ScanError>
handle_ignored_entry(const std::filesystem::path& physical_path,
                     std::string_view relative,
                     std::string_view entry_name,
                     const PhysicalEntryType& entry_type,
                     IgnoreDisposition disposition,
                     std::optional<cache::FileIdentity> bulk_identity,
                     std::uint64_t bulk_size,
                     MetadataQuery metadata_query,
                     reconciliation::LocalDirectoryEvidence& parent_evidence,
                     reconciliation::LocalPhysicalEvidence& physical_evidence) {
    const auto kind = entry_type.linklike
                          ? reconciliation::PhysicalEntryKind::LinkLike
                      : entry_type.directory
                          ? reconciliation::PhysicalEntryKind::Directory
                      : entry_type.regular_file
                          ? reconciliation::PhysicalEntryKind::RegularFile
                          : reconciliation::PhysicalEntryKind::Unsupported;
    auto effective_disposition =
        entry_type.linklike || !entry_type.regular_file ||
                !valid_logical_path_component(entry_name)
            ? IgnoreDisposition::IgnoredProtected
            : disposition;
    std::uint64_t ignored_size = 0;
    PhysicalFileIdentity identity{};
    if (effective_disposition == IgnoreDisposition::IgnoredDisposable) {
        if (bulk_identity.has_value()) {
            ignored_size = bulk_size;
            identity = {
                .volume_or_dev = bulk_identity->volume,
                .file_id_low = bulk_identity->file_low,
                .file_id_high = bulk_identity->file_high,
                .valid = true,
            };
        } else {
            const auto metadata =
                query_file_metadata(metadata_query,
                                    physical_path,
                                    relative,
                                    "read disposable file metadata",
                                    "");
            if (!metadata) {
                if (!metadata.error().detail.empty()) {
                    return std::unexpected(metadata.error());
                }
                effective_disposition = IgnoreDisposition::IgnoredProtected;
            } else if (!metadata->identity.has_value()) {
                effective_disposition = IgnoreDisposition::IgnoredProtected;
            } else {
                ignored_size = metadata->size;
                identity = {
                    .volume_or_dev = metadata->identity->volume,
                    .file_id_low = metadata->identity->file_low,
                    .file_id_high = metadata->identity->file_high,
                    .valid = true,
                };
            }
        }
    }
    physical_evidence.ignored_entries.push_back(
        {.path = std::string{relative},
         .kind = kind,
         .disposition = effective_disposition,
         .size = ignored_size,
         .identity = identity});
    parent_evidence.has_ignored_descendants = true;
    parent_evidence.has_protected_descendants |=
        effective_disposition == IgnoreDisposition::IgnoredProtected;
    parent_evidence.has_disposable_descendants |=
        effective_disposition == IgnoreDisposition::IgnoredDisposable;
    if (entry_type.directory) {
        physical_evidence.directories.push_back(
            {.path = std::string{relative},
             .ignored_entry = true,
             .has_protected_descendants = true});
    }
    return {};
}

void propagate_directory_evidence(
    reconciliation::LocalPhysicalEvidence& physical_evidence,
    std::size_t parent_index,
    std::size_t completed_index) noexcept {
    auto& parent = physical_evidence.directories[parent_index];
    const auto& completed = physical_evidence.directories[completed_index];
    parent.has_ignored_descendants |= completed.has_ignored_descendants;
    parent.has_unexpected_descendants |= completed.has_unexpected_descendants;
    parent.has_protected_descendants |= completed.has_protected_descendants;
    parent.has_disposable_descendants |= completed.has_disposable_descendants;
}

#if defined(_WIN32)
struct UniqueWin32Handle {
    HANDLE handle = INVALID_HANDLE_VALUE;
    ~UniqueWin32Handle() noexcept {
        if (handle != INVALID_HANDLE_VALUE && handle != nullptr) {
            CloseHandle(handle);
        }
    }
    UniqueWin32Handle() = default;
    explicit UniqueWin32Handle(HANDLE h) noexcept : handle(h) {}
    UniqueWin32Handle(const UniqueWin32Handle&) = delete;
    UniqueWin32Handle& operator=(const UniqueWin32Handle&) = delete;
};

struct Win32BulkEntry {
    std::wstring name;
    std::string name_utf8;
    DWORD attributes = 0;
    std::uint64_t size = 0;
    std::int64_t mtime_ns = 0;
    bool mtime_valid = false;
    bool size_valid = false;
    std::optional<cache::FileIdentity> identity;
};

struct Win32ScanFrame {
    std::filesystem::path dir_path;
    std::string relative;
    std::size_t evidence_index = 0;
    std::vector<Win32BulkEntry> entries;
    std::size_t next_index = 0;
};

enum class Win32BulkStatus : std::uint8_t {
    Ok = 0,
    Unsupported = 1,
    Error = 2
};

bool is_win32_bulk_unsupported(DWORD err) noexcept {
    return err == ERROR_INVALID_PARAMETER || err == ERROR_NOT_SUPPORTED ||
           err == ERROR_INVALID_FUNCTION || err == ERROR_INVALID_LEVEL ||
           err == ERROR_CALL_NOT_IMPLEMENTED;
}

Win32BulkStatus
read_win32_directory_bulk(const std::filesystem::path& dir_path,
                          std::int64_t& out_dir_mtime_ns,
                          std::vector<Win32BulkEntry>& out_entries,
                          ScanError& out_error) {
    out_entries.clear();
    UniqueWin32Handle dir_handle(
        CreateFileW(dir_path.c_str(),
                    FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    nullptr));
    if (dir_handle.handle == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        out_error = scan_error(
            dir_path,
            "list directory",
            std::error_code(static_cast<int>(err), std::system_category()),
            ScanErrorCode::Io);
        return Win32BulkStatus::Error;
    }

    FILE_BASIC_INFO basic_info{};
    if (!GetFileInformationByHandleEx(
            dir_handle.handle, FileBasicInfo, &basic_info, sizeof(basic_info))) {
        const DWORD err = GetLastError();
        if (is_win32_bulk_unsupported(err)) {
            return Win32BulkStatus::Unsupported;
        }
        out_error = scan_error(
            dir_path,
            "read modification time",
            std::error_code(static_cast<int>(err), std::system_category()),
            ScanErrorCode::Metadata);
        return Win32BulkStatus::Error;
    }
    if ((basic_info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        (basic_info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        out_error = ScanError{ScanErrorCode::Metadata,
                              dir_path,
                              "classify entry",
                              "entry is not a regular directory"};
        return Win32BulkStatus::Error;
    }
    const auto dir_mtime = cache::windows_filetime_to_unix_nanoseconds(
        static_cast<std::uint64_t>(basic_info.LastWriteTime.QuadPart));
    if (!dir_mtime) {
        out_error = ScanError{ScanErrorCode::Metadata,
                              dir_path,
                              "convert modification time",
                              "timestamp is out of range"};
        return Win32BulkStatus::Error;
    }
    out_dir_mtime_ns = *dir_mtime;

    FILE_ID_INFO id_info{};
    if (!GetFileInformationByHandleEx(
            dir_handle.handle, FileIdInfo, &id_info, sizeof(id_info))) {
        const DWORD err = GetLastError();
        if (is_win32_bulk_unsupported(err)) {
            return Win32BulkStatus::Unsupported;
        }
        out_error = scan_error(
            dir_path,
            "list directory",
            std::error_code(static_cast<int>(err), std::system_category()),
            ScanErrorCode::Metadata);
        return Win32BulkStatus::Error;
    }
    if (id_info.VolumeSerialNumber == 0) {
        return Win32BulkStatus::Unsupported;
    }
    const auto volume_serial = static_cast<std::uint64_t>(id_info.VolumeSerialNumber);

    alignas(FILE_ID_EXTD_DIR_INFO) std::array<std::byte, 65536> buffer{};
    bool first_batch = true;
    while (true) {
        if (!GetFileInformationByHandleEx(dir_handle.handle,
                                          FileIdExtdDirectoryInfo,
                                          buffer.data(),
                                          static_cast<DWORD>(buffer.size()))) {
            const DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_FILES) {
                break;
            }
            if ((first_batch && is_win32_bulk_unsupported(err)) ||
                err == ERROR_MORE_DATA) {
                return Win32BulkStatus::Unsupported;
            }
            out_error = scan_error(
                dir_path,
                "continue listing",
                std::error_code(static_cast<int>(err), std::system_category()),
                ScanErrorCode::Io);
            return Win32BulkStatus::Error;
        }
        first_batch = false;

        std::size_t offset = 0;
        while (true) {
            const auto* info = reinterpret_cast<const FILE_ID_EXTD_DIR_INFO*>(
                buffer.data() + offset);
            if (info->FileNameLength == 0 ||
                (info->FileNameLength % sizeof(WCHAR)) != 0 ||
                info->FileNameLength >
                    buffer.size() - offset -
                        offsetof(FILE_ID_EXTD_DIR_INFO, FileName)) {
                return Win32BulkStatus::Unsupported;
            }
            const std::wstring_view name_w(
                info->FileName, info->FileNameLength / sizeof(WCHAR));
            if (name_w != L"." && name_w != L"..") {
                Win32BulkEntry entry;
                entry.name.assign(name_w);
                entry.name_utf8 = platform::path::to_logical_utf8(
                    std::filesystem::path(entry.name));
                entry.attributes = info->FileAttributes;
                if (info->EndOfFile.QuadPart >= 0) {
                    entry.size =
                        static_cast<std::uint64_t>(info->EndOfFile.QuadPart);
                    entry.size_valid = true;
                }
                const auto mtime_opt =
                    cache::windows_filetime_to_unix_nanoseconds(
                        static_cast<std::uint64_t>(
                            info->LastWriteTime.QuadPart));
                if (mtime_opt) {
                    entry.mtime_ns = *mtime_opt;
                    entry.mtime_valid = true;
                }
                std::uint64_t file_low = 0;
                std::uint64_t file_high = 0;
                std::memcpy(&file_low,
                            info->FileId.Identifier,
                            sizeof(file_low));
                std::memcpy(&file_high,
                            info->FileId.Identifier + sizeof(file_low),
                            sizeof(file_high));
                const bool valid_id =
                    !(file_low == 0 && file_high == 0) &&
                    !(file_low == std::numeric_limits<std::uint64_t>::max() &&
                      file_high == std::numeric_limits<std::uint64_t>::max());
                if (valid_id) {
                    entry.identity = cache::FileIdentity{.volume = volume_serial,
                                                         .file_low = file_low,
                                                         .file_high = file_high};
                }
                out_entries.push_back(std::move(entry));
            }
            if (info->NextEntryOffset == 0) {
                break;
            }
            if (info->NextEntryOffset > buffer.size() - offset) {
                return Win32BulkStatus::Unsupported;
            }
            offset += info->NextEntryOffset;
        }
    }
    return Win32BulkStatus::Ok;
}
#endif

} // namespace

std::string describe(const ScanError& error) {
    return error.operation + " at '" + platform::path::to_utf8(error.path) +
           "': " + error.detail;
}

std::expected<ScanResult, ScanError>
scan_result(const std::filesystem::path& local_root,
            std::span<const state_storage::FileCacheRow> previous_cache,
            ScanPolicy policy,
            MetadataQuery metadata_query,
            ProgressMeter* progress) {
    const auto ignore_list = load_ignore_list(local_root / ".kasumiignore");
    return scan_result(local_root,
                       previous_cache,
                       policy,
                       metadata_query,
                       ignore_list,
                       progress);
}

std::expected<ScanResult, ScanError>
scan_result(const std::filesystem::path& local_root,
            std::span<const state_storage::FileCacheRow> previous_cache,
            ScanPolicy policy,
            MetadataQuery metadata_query,
            const IgnoreList& ignore_list,
            ProgressMeter* progress) {
    if (auto valid = validate_ignore_list(local_root, ignore_list); !valid) {
        return std::unexpected(valid.error());
    }
    const auto scan_start_ns = static_cast<std::int64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
    ScanContext context{.policy = policy,
                        .metadata_query = metadata_query,
                        .scan_start_ns = scan_start_ns,
                        .previous = {},
                        .cache = {},
                        .progress = progress};
    context.cache.reserve(previous_cache.size());
    context.previous.reserve(previous_cache.size());
    for (const auto& row : previous_cache)
        context.previous.emplace(row.path, &row);
    std::error_code error;
    const auto status = std::filesystem::symlink_status(local_root, error);
    const auto root_type = classify_path(local_root, status, error);
    if (!root_type) {
        return std::unexpected(root_type.error());
    }
    if (root_type->linklike ||
        (!root_type->directory && !root_type->regular_file)) {
        return std::unexpected(
            ScanError{ScanErrorCode::Metadata,
                      local_root,
                      "classify entry",
                      "root is not a regular file or directory"});
    }
    if (root_type->regular_file &&
        is_ignored(platform::path::to_logical_utf8(local_root.filename()),
                   ignore_list,
                   false))
        return ScanResult{};

    if (root_type->regular_file) {
        auto row =
            process_file(local_root,
                         platform::path::to_logical_utf8(local_root.filename()),
                         context);
        if (!row)
            return std::unexpected(row.error());
        return ScanResult{.snapshot = Snapshot{{std::move(*row)}},
                          .cache = std::move(context.cache)};
    }

    Snapshot snapshot;
    snapshot.rows.reserve(previous_cache.size() + 1);
    reconciliation::LocalPhysicalEvidence physical_evidence;
    std::unordered_map<std::string, std::size_t> evidence_indices;
    std::vector<PendingFile> pending_files;

    bool completed_traversal = false;
#if defined(_WIN32)
    if (metadata_query == &cache::read_file_metadata) {
        std::int64_t bulk_root_mtime = 0;
        std::vector<Win32BulkEntry> bulk_root_entries;
        ScanError bulk_error{};
        const auto root_status_win32 = read_win32_directory_bulk(
            local_root, bulk_root_mtime, bulk_root_entries, bulk_error);
        if (root_status_win32 == Win32BulkStatus::Error) {
            return std::unexpected(bulk_error);
        }
        if (root_status_win32 == Win32BulkStatus::Ok) {
            snapshot.rows.push_back(
                {.path = "", .mtime = bulk_root_mtime, .is_directory = true});
            physical_evidence.directories.push_back(
                {.path = "", .physically_empty = true});
            evidence_indices.emplace("", 0);
            std::vector<Win32ScanFrame> win32_stack;
            win32_stack.push_back(Win32ScanFrame{
                .dir_path = local_root,
                .relative = "",
                .evidence_index = 0,
                .entries = std::move(bulk_root_entries),
                .next_index = 0,
            });
            bool fallback_to_portable = false;
            while (!win32_stack.empty()) {
                auto& frame = win32_stack.back();
                if (frame.next_index >= frame.entries.size()) {
                    const auto completed_index = frame.evidence_index;
                    win32_stack.pop_back();
                    if (!win32_stack.empty()) {
                        propagate_directory_evidence(physical_evidence,
                                                     win32_stack.back().evidence_index,
                                                     completed_index);
                    }
                    continue;
                }
                auto entry = std::move(frame.entries[frame.next_index++]);
                const bool linklike =
                    (entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
                const bool has_dir_attr =
                    (entry.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                const auto entry_path = frame.dir_path / entry.name;
                PhysicalEntryType entry_type{
                    .directory = !linklike && has_dir_attr,
                    .regular_file =
                        !linklike && !has_dir_attr && entry.size_valid &&
                        (entry.attributes &
                         (FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_OFFLINE)) == 0,
                    .linklike = linklike};
                if (!linklike && !has_dir_attr && !entry_type.regular_file) {
                    std::error_code status_err;
                    const auto entry_status =
                        std::filesystem::symlink_status(entry_path, status_err);
                    const auto classified =
                        classify_path(entry_path, entry_status, status_err);
                    if (!classified) {
                        return std::unexpected(classified.error());
                    }
                    entry_type = *classified;
                }

                const auto relative = frame.relative.empty()
                                          ? entry.name_utf8
                                          : frame.relative + '/' +
                                                entry.name_utf8;
                const auto disposition = classify_ignore(
                    relative, entry_type.directory, ignore_list);
                const bool ignored = disposition != IgnoreDisposition::Managed;
                auto& parent_evidence =
                    physical_evidence.directories[frame.evidence_index];
                parent_evidence.physically_empty = false;
                if (entry_type.linklike && !ignored) {
                    parent_evidence.has_unexpected_descendants = true;
                    continue;
                }
                if (ignored) {
                    const auto bulk_id =
                        entry_type.regular_file ? entry.identity : std::nullopt;
                    auto ignored_result =
                        handle_ignored_entry(entry_path,
                                             relative,
                                             entry.name_utf8,
                                             entry_type,
                                             disposition,
                                             bulk_id,
                                             entry.size,
                                             metadata_query,
                                             parent_evidence,
                                             physical_evidence);
                    if (!ignored_result) {
                        return std::unexpected(ignored_result.error());
                    }
                    continue;
                }
                if (!valid_logical_path_component(entry.name_utf8)) {
                    return std::unexpected(ScanError{
                        .code = ScanErrorCode::Io,
                        .path = entry_path,
                        .operation = "validate portable name",
                        .detail = "unsupported non-portable path component: '" +
                                  entry.name_utf8 + "'",
                    });
                }
                if (!entry_type.regular_file && !entry_type.directory) {
                    parent_evidence.has_unexpected_descendants = true;
                    return std::unexpected(ScanError{
                        .code = ScanErrorCode::Metadata,
                        .path = entry_path,
                        .operation = "classify entry",
                        .detail = "entry is not a regular file or directory",
                    });
                }
                if (entry_type.regular_file) {
                    if (entry.identity.has_value() && entry.mtime_valid) {
                        NodeRow row{.path = relative,
                                    .size = entry.size,
                                    .mtime = entry.mtime_ns};
                        const cache::FileMetadata current_meta{
                            .path = row.path,
                            .kind = cache::EntryKind::RegularFile,
                            .size = entry.size,
                            .mtime_nanoseconds = entry.mtime_ns,
                            .identity = entry.identity,
                            .is_valid = true};
                        if (auto hit = try_reuse_cached_row(
                                context, current_meta, row)) {
                            snapshot.rows.push_back(std::move(row));
                            context.cache.push_back(std::move(*hit));
                            continue;
                        }
                    }
                    pending_files.push_back(
                        PendingFile{.physical_path = entry_path,
                                    .relative = relative});
                    continue;
                }

                std::int64_t sub_mtime = 0;
                std::vector<Win32BulkEntry> sub_entries;
                const auto sub_status = read_win32_directory_bulk(
                    entry_path, sub_mtime, sub_entries, bulk_error);
                if (sub_status == Win32BulkStatus::Error) {
                    return std::unexpected(bulk_error);
                }
                if (sub_status == Win32BulkStatus::Unsupported) {
                    fallback_to_portable = true;
                    break;
                }
                snapshot.rows.push_back(
                    {.path = relative, .mtime = sub_mtime, .is_directory = true});
                const auto evidence_index =
                    physical_evidence.directories.size();
                physical_evidence.directories.push_back(
                    {.path = relative, .physically_empty = true});
                evidence_indices.emplace(relative, evidence_index);
                win32_stack.push_back(Win32ScanFrame{
                    .dir_path = entry_path,
                    .relative = relative,
                    .evidence_index = evidence_index,
                    .entries = std::move(sub_entries),
                    .next_index = 0,
                });
            }
            if (fallback_to_portable) {
                snapshot.rows.clear();
                physical_evidence = {};
                evidence_indices.clear();
                pending_files.clear();
                context.cache.clear();
            } else {
                completed_traversal = true;
            }
        }
    }
#endif

    if (!completed_traversal) {
        const auto root_mtime = read_directory_mtime(local_root);
        if (!root_mtime) {
            return std::unexpected(root_mtime.error());
        }
        // The parent must precede its descendants.
        snapshot.rows.push_back(
            {.path = "", .mtime = *root_mtime, .is_directory = true});
        physical_evidence.directories.push_back(
            {.path = "", .physically_empty = true});
        evidence_indices.emplace("", 0);

        std::filesystem::directory_iterator iterator(local_root, error);
        if (error)
            return std::unexpected(scan_error(
                local_root, "list directory", error, ScanErrorCode::Io));
        std::vector<ScanFrame> stack;
        stack.push_back({iterator, {}, "", 0});
        while (!stack.empty()) {
            auto& frame = stack.back();
            if (frame.iterator == frame.end) {
                const auto completed_index = frame.evidence_index;
                stack.pop_back();
                if (!stack.empty()) {
                    propagate_directory_evidence(physical_evidence,
                                                 stack.back().evidence_index,
                                                 completed_index);
                }
                continue;
            }
            const auto entry = *frame.iterator;
            frame.iterator.increment(error);
            if (error)
                return std::unexpected(scan_error(entry.path().parent_path(),
                                                  "continue listing",
                                                  error,
                                                  ScanErrorCode::Io));
            const auto entry_status = entry.symlink_status(error);
            const auto entry_type =
                classify_path(entry.path(), entry_status, error);
            if (!entry_type) {
                return std::unexpected(entry_type.error());
            }
            const auto entry_name =
                platform::path::to_logical_utf8(entry.path().filename());
            const auto relative =
                frame.path.empty() ? entry_name : frame.path + '/' + entry_name;
            const auto disposition =
                classify_ignore(relative, entry_type->directory, ignore_list);
            const bool ignored = disposition != IgnoreDisposition::Managed;
            auto& parent_evidence =
                physical_evidence.directories[frame.evidence_index];
            parent_evidence.physically_empty = false;
            if (entry_type->linklike && !ignored) {
                parent_evidence.has_unexpected_descendants = true;
                continue;
            }
            if (ignored) {
                auto ignored_result = handle_ignored_entry(entry.path(),
                                                           relative,
                                                           entry_name,
                                                           *entry_type,
                                                           disposition,
                                                           std::nullopt,
                                                           0,
                                                           metadata_query,
                                                           parent_evidence,
                                                           physical_evidence);
                if (!ignored_result) {
                    return std::unexpected(ignored_result.error());
                }
                continue;
            }
            if (!valid_logical_path_component(entry_name)) {
                return std::unexpected(ScanError{
                    .code = ScanErrorCode::Io,
                    .path = entry.path(),
                    .operation = "validate portable name",
                    .detail = "unsupported non-portable path component: '" +
                              entry_name + "'",
                });
            }
            if (!entry_type->regular_file && !entry_type->directory) {
                parent_evidence.has_unexpected_descendants = true;
                return std::unexpected(ScanError{
                    .code = ScanErrorCode::Metadata,
                    .path = entry.path(),
                    .operation = "classify entry",
                    .detail = "entry is not a regular file or directory",
                });
            }
            if (entry_type->regular_file) {
                if (metadata_query == &cache::read_file_metadata) {
                    pending_files.push_back(
                        PendingFile{.physical_path = entry.path(),
                                    .relative = relative});
                } else {
                    auto row = process_file(entry.path(), relative, context);
                    if (!row)
                        return std::unexpected(row.error());
                    snapshot.rows.push_back(std::move(*row));
                }
                continue;
            }
            const auto mtime_ns = read_directory_mtime(entry.path());
            if (!mtime_ns) {
                return std::unexpected(mtime_ns.error());
            }
            snapshot.rows.push_back(
                {.path = relative, .mtime = *mtime_ns, .is_directory = true});
            const auto evidence_index = physical_evidence.directories.size();
            physical_evidence.directories.push_back(
                {.path = relative, .physically_empty = true});
            evidence_indices.emplace(relative, evidence_index);
            std::filesystem::directory_iterator nested(entry.path(), error);
            if (error)
                return std::unexpected(scan_error(
                    entry.path(), "list directory", error, ScanErrorCode::Io));
            stack.push_back({nested, {}, relative, evidence_index});
        }
    }

    if (auto flushed = flush_pending_files(pending_files, context, snapshot);
        !flushed) {
        return std::unexpected(flushed.error());
    }
    for (const auto& row : snapshot.rows) {
        if (row.is_directory) {
            if (row.path.empty()) {
                continue;
            }
            const auto found = evidence_indices.find(row.path);
            if (found == evidence_indices.end() ||
                !physical_evidence.directories[found->second]
                     .physically_empty) {
                continue;
            }
        }
        auto parent_path = row_parent(row.path);
        while (true) {
            const auto found = evidence_indices.find(std::string{parent_path});
            if (found != evidence_indices.end()) {
                physical_evidence.directories[found->second]
                    .has_managed_descendants = true;
            }
            if (parent_path.empty()) {
                break;
            }
            parent_path = row_parent(parent_path);
        }
    }
    finalize_snapshot(snapshot);
    if (!valid_snapshot(snapshot, false)) {
        return std::unexpected(ScanError{
            .code = ScanErrorCode::Metadata,
            .path = local_root,
            .operation = "validate snapshot",
            .detail =
                "logical snapshot contains case collision or invalid structure",
        });
    }
    std::ranges::sort(
        context.cache, path_less, &state_storage::FileCacheRow::path);
    std::ranges::sort(physical_evidence.directories,
                      path_less,
                      &reconciliation::LocalDirectoryEvidence::path);
    std::ranges::sort(physical_evidence.ignored_entries,
                      path_less,
                      &reconciliation::IgnoredEntryEvidence::path);
    return ScanResult{.snapshot = std::move(snapshot),
                      .cache = std::move(context.cache),
                      .physical_evidence = std::move(physical_evidence)};
}

std::expected<std::vector<reconciliation::DisposableIgnoredContent>, ScanError>
hash_disposable_candidates(
    const std::filesystem::path& local_root,
    const reconciliation::LocalPhysicalEvidence& evidence,
    std::span<const std::filesystem::path> candidate_paths,
    const IgnoreList& ignore_list,
    MetadataQuery metadata_query) {
    if (auto valid = validate_ignore_list(local_root, ignore_list); !valid) {
        return std::unexpected(valid.error());
    }
    std::vector<std::string> paths;
    paths.reserve(candidate_paths.size());
    for (const auto& candidate : candidate_paths) {
        if (candidate.empty() ||
            !kasumi::has_safe_paths(kasumi::Operation{.path = candidate})) {
            return std::unexpected(ScanError{
                .code = ScanErrorCode::Io,
                .path = local_root / candidate,
                .operation = "validate disposable candidate",
                .detail = "candidate path is unsafe",
            });
        }
        paths.push_back(platform::path::to_logical_utf8(candidate));
    }
    std::ranges::sort(paths, path_less);
    if (std::ranges::adjacent_find(paths) != paths.end()) {
        return std::unexpected(ScanError{
            .code = ScanErrorCode::Io,
            .path = local_root,
            .operation = "validate disposable candidates",
            .detail = "duplicate candidate path",
        });
    }

    std::vector<reconciliation::DisposableIgnoredContent> result;
    result.reserve(paths.size());
    ScanContext context{.policy = ScanPolicy::FullHash,
                        .metadata_query = metadata_query,
                        .previous = {},
                        .cache = {}};
    for (const auto& relative : paths) {
        const auto found = std::ranges::lower_bound(
            evidence.ignored_entries,
            relative,
            path_less,
            &reconciliation::IgnoredEntryEvidence::path);
        if (found == evidence.ignored_entries.end() ||
            found->path != relative ||
            found->kind != reconciliation::PhysicalEntryKind::RegularFile ||
            found->disposition != IgnoreDisposition::IgnoredDisposable ||
            !found->identity.valid ||
            classify_ignore(relative, false, ignore_list) !=
                IgnoreDisposition::IgnoredDisposable) {
            return std::unexpected(ScanError{
                .code = ScanErrorCode::Metadata,
                .path = local_root / platform::path::from_utf8(relative),
                .operation = "revalidate disposable candidate",
                .detail = "ignore rules or physical evidence changed",
            });
        }

        std::size_t start = 0;
        auto current = local_root;
        if (platform::private_storage::is_reparse_or_symlink(current)) {
            return std::unexpected(ScanError{
                .code = ScanErrorCode::Metadata,
                .path = current,
                .operation = "validate disposable candidate",
                .detail = "local root is a symlink or reparse point",
            });
        }
        while (start < relative.size()) {
            const auto slash = relative.find('/', start);
            const auto component = std::string_view{relative}.substr(
                start,
                slash == std::string::npos ? relative.size() - start
                                           : slash - start);
            if (!valid_logical_path_component(component)) {
                return std::unexpected(ScanError{
                    .code = ScanErrorCode::Io,
                    .path = local_root / platform::path::from_utf8(relative),
                    .operation = "validate disposable candidate",
                    .detail = "candidate contains an unsafe path component",
                });
            }
            current /= platform::path::from_utf8(component);
            std::error_code error;
            const auto status = std::filesystem::symlink_status(current, error);
            const bool final = slash == std::string::npos;
            if (error || std::filesystem::is_symlink(status) ||
                platform::private_storage::is_reparse_or_symlink(current) ||
                (final ? !std::filesystem::is_regular_file(status)
                       : !std::filesystem::is_directory(status))) {
                return std::unexpected(ScanError{
                    .code = ScanErrorCode::Metadata,
                    .path = current,
                    .operation = "validate disposable candidate",
                    .detail =
                        error
                            ? error.message()
                            : (final
                                   ? "candidate is not a regular file"
                                   : "candidate path contains a non-directory"),
                });
            }
            if (final) {
                break;
            }
            start = slash + 1;
        }

        if (auto before = verify_disposable_metadata(
                current,
                relative,
                *found,
                metadata_query,
                nullptr,
                "verify disposable candidate metadata",
                "physical identity or size changed after observation");
            !before) {
            return std::unexpected(before.error());
        }

        auto row = process_file(current, relative, context);
        if (!row) {
            return std::unexpected(row.error());
        }
        if (auto after = verify_disposable_metadata(
                current,
                relative,
                *found,
                metadata_query,
                &ignore_list,
                "verify disposable candidate after hashing",
                "file or ignore rules changed while hashing");
            !after) {
            return std::unexpected(after.error());
        }
        result.push_back({.path = relative,
                          .hash = hash_hex(row->hash),
                          .size = row->size,
                          .identity = found->identity});
    }
    return result;
}

} // namespace kasumi::application::observation::scanner
