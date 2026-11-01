#include "application/observation/scanner.hpp"

#include "application/observation/cache_contract.hpp"
#include "application/observation/file_metadata.hpp"
#include "core/ignore.hpp"
#include "crypto/content.hpp"
#include "platform/metadata.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"
#include "platform/private_storage.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string_view>
#include <system_error>
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

using kasumi::ignore::IgnoreList;
using kasumi::ignore::IgnoreDisposition;
using kasumi::ignore::classify_ignore;
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
    std::unordered_map<std::string_view, const state_storage::FileCacheRow*>
        previous;
    std::vector<state_storage::FileCacheRow> cache;
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

std::expected<PhysicalEntryType, std::error_code> classify_entry(
    const std::filesystem::path& path,
    const std::filesystem::file_status& status) {
#if defined(_WIN32)
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return std::unexpected(std::error_code(
            static_cast<int>(GetLastError()), std::system_category()));
    }
    const bool directory = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (std::filesystem::is_symlink(status) ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return PhysicalEntryType{.directory = directory,
                                 .regular_file = false,
                                 .linklike = true};
    }
#else
    static_cast<void>(path);
    if (std::filesystem::is_symlink(status)) {
        return PhysicalEntryType{.directory = false,
                                 .regular_file = false,
                                 .linklike = true};
    }
#endif
    if (status.type() == std::filesystem::file_type::none ||
        status.type() == std::filesystem::file_type::not_found ||
        status.type() == std::filesystem::file_type::unknown) {
        return std::unexpected(std::make_error_code(std::errc::io_error));
    }
    return PhysicalEntryType{
        .directory = std::filesystem::is_directory(status),
        .regular_file = std::filesystem::is_regular_file(status),
        .linklike = false};
}

std::expected<NodeRow, ScanError>
process_file(const std::filesystem::path& file_path,
             std::string relative,
             ScanContext& context) {
    NodeRow row{.path = std::move(relative)};
    const auto query_metadata = [&](const std::filesystem::path& path) {
        const auto trace = platform::perf_trace::begin();
        auto result = context.metadata_query(path, row.path);
        platform::perf_trace::finish("local metadata query wall", trace);
        platform::perf_trace::count("local metadata query calls");
        return result;
    };
    const auto meta_result = query_metadata(file_path);
    if (!meta_result) {
        const auto& err = meta_result.error();
        return std::unexpected(ScanError{
            .code = err.code == cache::FileMetadataErrorCode::PermissionDenied
                        ? ScanErrorCode::PermissionDenied
                        : ScanErrorCode::Metadata,
            .path = file_path,
            .operation = "read metadata",
            .detail = err.message});
    }
    if (!meta_result->has_value()) {
        return std::unexpected(ScanError{
            .code = ScanErrorCode::Metadata,
            .path = file_path,
            .operation = "read metadata",
            .detail =
                "metadata query returned no metadata for a regular file"});
    }

    auto current_meta = **meta_result;
    row.size = current_meta.size;
    row.mtime = current_meta.mtime_nanoseconds;
    platform::perf_trace::count("local regular files observed");

    const bool identity_supported = current_meta.identity.has_value();
    if (!identity_supported) {
        platform::perf_trace::count("local hash cache unsupported");
    }

    const auto cached =
        context.policy == ScanPolicy::ReuseStrongFingerprint && identity_supported
            ? context.previous.find(row.path)
            : context.previous.end();

    bool reused = false;
    if (cached != context.previous.end()) {
        const auto& cached_row = *cached->second;
        const cache::FileMetadata cached_meta{
            .path = cached_row.path,
            .kind = cache::EntryKind::RegularFile,
            .size = cached_row.size,
            .mtime_nanoseconds = cached_row.mtime_nanoseconds,
            .identity = cache::FileIdentity{
                .volume = cached_row.volume,
                .file_low = cached_row.file_low,
                .file_high = cached_row.file_high},
            .is_valid = true};

        const auto decision =
            cache::evaluate_cache_reuse(cached_meta, current_meta);
        if (decision == cache::CacheReuseResult::Reusable) {
            row.hash = cached_row.hash;
            context.cache.push_back(cached_row);
            platform::perf_trace::count("local hash cache hits");
            reused = true;
        }
    }

    if (!reused) {
        platform::perf_trace::count("local hash cache misses");
        std::expected<Hash, std::string> hash = std::unexpected("unhashed");
        bool stable = false;
        for (int attempt = 0; attempt < 2; ++attempt) {
            const auto before_meta = current_meta;
            const auto hash_trace = platform::perf_trace::begin();
            hash = crypto::content::hash_file(file_path);
            platform::perf_trace::finish("local content hashing wall",
                                         hash_trace);
            platform::perf_trace::count("local hash file calls");
            platform::perf_trace::count("local hash bytes", before_meta.size);
            if (!hash)
                break;

            const auto after_result = query_metadata(file_path);
            if (!after_result) {
                const auto& err = after_result.error();
                return std::unexpected(ScanError{
                    .code = err.code ==
                                    cache::FileMetadataErrorCode::
                                        PermissionDenied
                                ? ScanErrorCode::PermissionDenied
                                : ScanErrorCode::Metadata,
                    .path = file_path,
                    .operation = "read metadata after hashing",
                    .detail = err.message});
            }
            if (!after_result->has_value()) {
                return std::unexpected(ScanError{
                    .code = ScanErrorCode::Metadata,
                    .path = file_path,
                    .operation = "read metadata after hashing",
                    .detail = "file replaced or removed during hash"});
            }
            const auto after_meta = **after_result;

            const bool same_identity =
                (!before_meta.identity.has_value() &&
                 !after_meta.identity.has_value()) ||
                (before_meta.identity.has_value() &&
                 after_meta.identity.has_value() &&
                 *before_meta.identity == *after_meta.identity);
            const bool same_size = before_meta.size == after_meta.size;
            const bool same_mtime =
                before_meta.mtime_nanoseconds == after_meta.mtime_nanoseconds;

            if (same_identity && same_size && same_mtime) {
                stable = true;
                current_meta = after_meta;
                break;
            }

            platform::perf_trace::count("files changed during hash");
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
        if (current_meta.is_valid && current_meta.identity.has_value()) {
            context.cache.push_back(
                state_storage::FileCacheRow{
                    .path = row.path,
                    .hash = row.hash,
                    .size = current_meta.size,
                    .mtime_nanoseconds = current_meta.mtime_nanoseconds,
                    .volume = current_meta.identity->volume,
                    .file_low = current_meta.identity->file_low,
                    .file_high = current_meta.identity->file_high});
        }
    }
    return row;
}

} // namespace

std::string describe(const ScanError& error) {
    return error.operation + " at '" + platform::path::to_utf8(error.path) +
           "': " + error.detail;
}

std::expected<ScanResult, ScanError>
scan_result(const std::filesystem::path& local_root,
            std::span<const state_storage::FileCacheRow> previous_cache,
            ScanPolicy policy,
            MetadataQuery metadata_query) {
    const auto ignore_list = load_ignore_list(local_root / ".kasumiignore");
    return scan_result(
        local_root, previous_cache, policy, metadata_query, ignore_list);
}

std::expected<ScanResult, ScanError>
scan_result(const std::filesystem::path& local_root,
            std::span<const state_storage::FileCacheRow> previous_cache,
            ScanPolicy policy,
            MetadataQuery metadata_query,
            const IgnoreList& ignore_list) {
    if (ignore_list.parse_error) {
        return std::unexpected(ScanError{
            .code = ScanErrorCode::Io,
            .path = local_root / ".kasumiignore",
            .operation = ignore_list.parse_error->line == 0
                             ? "read ignore file"
                             : "parse ignore rule at line " +
                                   std::to_string(ignore_list.parse_error->line),
            .detail = ignore_list.parse_error->detail,
        });
    }
    const auto scan_trace = platform::perf_trace::begin();
    ScanContext context{.policy = policy,
                        .metadata_query = metadata_query,
                        .previous = {},
                        .cache = {}};
    context.cache.reserve(previous_cache.size());
    context.previous.reserve(previous_cache.size());
    for (const auto& row : previous_cache)
        context.previous.emplace(row.path, &row);
    std::error_code error;
    const auto status = std::filesystem::symlink_status(local_root, error);
    if (error)
        return std::unexpected(scan_error(
            local_root, "query entry type", error, ScanErrorCode::Metadata));
    const auto root_type = classify_entry(local_root, status);
    if (!root_type) {
        return std::unexpected(scan_error(local_root,
                                          "classify entry",
                                          root_type.error(),
                                          ScanErrorCode::Metadata));
    }
    if (root_type->linklike ||
        (!root_type->directory && !root_type->regular_file)) {
        return std::unexpected(ScanError{ScanErrorCode::Metadata,
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
        ScanResult result{.snapshot = Snapshot{{std::move(*row)}},
                          .cache = std::move(context.cache)};
        platform::perf_trace::finish("local filesystem scan wall", scan_trace);
        return result;
    }

    Snapshot snapshot;
    snapshot.rows.reserve(previous_cache.size() + 1);
    const auto modified = platform::metadata::last_write_time(local_root);
    if (!modified)
        return std::unexpected(ScanError{ScanErrorCode::Metadata,
                                          local_root,
                                          "read modification time",
                                          modified.error()});
    const auto root_mtime = platform::metadata::unix_nanoseconds(*modified);
    if (!root_mtime) {
        return std::unexpected(ScanError{ScanErrorCode::Metadata,
                                         local_root,
                                         "convert modification time",
                                         "timestamp is out of range"});
    }
    // The parent must precede its descendants.
    snapshot.rows.push_back(
        {.path = "", .mtime = *root_mtime, .is_directory = true});
    reconciliation::LocalPhysicalEvidence physical_evidence;
    physical_evidence.directories.push_back(
        {.path = "", .physically_empty = true});
    std::unordered_map<std::string, std::size_t> evidence_indices;
    evidence_indices.emplace("", 0);

    std::filesystem::directory_iterator iterator(local_root, error);
    if (error)
        return std::unexpected(
            scan_error(local_root, "list directory", error, ScanErrorCode::Io));
    std::vector<ScanFrame> stack;
    stack.push_back({iterator, {}, "", 0});
    while (!stack.empty()) {
        auto& frame = stack.back();
        if (frame.iterator == frame.end) {
            const auto completed_index = frame.evidence_index;
            stack.pop_back();
            if (!stack.empty()) {
                auto& parent = physical_evidence.directories[
                    stack.back().evidence_index];
                const auto& completed =
                    physical_evidence.directories[completed_index];
                parent.has_ignored_descendants |=
                    completed.has_ignored_descendants;
                parent.has_unexpected_descendants |=
                    completed.has_unexpected_descendants;
                parent.has_protected_descendants |=
                    completed.has_protected_descendants;
                parent.has_disposable_descendants |=
                    completed.has_disposable_descendants;
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
        if (error)
            return std::unexpected(scan_error(entry.path(),
                                              "query entry type",
                                              error,
                                              ScanErrorCode::Metadata));
        const auto entry_type = classify_entry(entry.path(), entry_status);
        if (!entry_type) {
            return std::unexpected(scan_error(entry.path(),
                                              "classify entry",
                                              entry_type.error(),
                                              ScanErrorCode::Metadata));
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
        if (entry_type->linklike) {
            if (ignored) {
                physical_evidence.ignored_entries.push_back(
                    {.path = relative,
                     .kind = reconciliation::PhysicalEntryKind::LinkLike,
                     .disposition = IgnoreDisposition::IgnoredProtected});
                parent_evidence.has_ignored_descendants = true;
                parent_evidence.has_protected_descendants = true;
                if (entry_type->directory) {
                    physical_evidence.directories.push_back(
                        {.path = relative,
                         .ignored_entry = true,
                         .has_protected_descendants = true});
                }
            } else {
                parent_evidence.has_unexpected_descendants = true;
            }
            continue;
        }
        if (ignored) {
            const auto kind = entry_type->directory
                                  ? reconciliation::PhysicalEntryKind::Directory
                                  : (entry_type->regular_file
                                         ? reconciliation::PhysicalEntryKind::RegularFile
                                         : reconciliation::PhysicalEntryKind::Unsupported);
            auto effective_disposition = disposition;
            std::uint64_t ignored_size = 0;
            PhysicalFileIdentity identity{};
            if (!entry_type->regular_file ||
                !valid_logical_path_component(entry_name)) {
                effective_disposition = IgnoreDisposition::IgnoredProtected;
            } else if (disposition == IgnoreDisposition::IgnoredDisposable) {
                const auto metadata = metadata_query(entry.path(), relative);
                if (!metadata) {
                    return std::unexpected(ScanError{
                        .code = metadata.error().code ==
                                        cache::FileMetadataErrorCode::PermissionDenied
                                    ? ScanErrorCode::PermissionDenied
                                    : ScanErrorCode::Metadata,
                        .path = entry.path(),
                        .operation = "read disposable file metadata",
                        .detail = metadata.error().message,
                    });
                }
                if (!metadata->has_value() ||
                    !(**metadata).identity.has_value()) {
                    effective_disposition = IgnoreDisposition::IgnoredProtected;
                } else {
                    const auto& file_metadata = **metadata;
                    ignored_size = file_metadata.size;
                    identity = {
                        .volume_or_dev = file_metadata.identity->volume,
                        .file_id_low = file_metadata.identity->file_low,
                        .file_id_high = file_metadata.identity->file_high,
                        .valid = true,
                    };
                }
            }
            physical_evidence.ignored_entries.push_back(
                {.path = relative,
                 .kind = kind,
                 .disposition = effective_disposition,
                 .size = ignored_size,
                 .identity = identity});
            parent_evidence.has_ignored_descendants = true;
            parent_evidence.has_protected_descendants |=
                effective_disposition == IgnoreDisposition::IgnoredProtected;
            parent_evidence.has_disposable_descendants |=
                effective_disposition == IgnoreDisposition::IgnoredDisposable;
            if (entry_type->directory) {
                physical_evidence.directories.push_back(
                    {.path = relative,
                     .ignored_entry = true,
                     .has_protected_descendants = true});
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
            auto row = process_file(entry.path(), relative, context);
            if (!row)
                return std::unexpected(row.error());
            snapshot.rows.push_back(std::move(*row));
            continue;
        }
        const auto mtime = platform::metadata::last_write_time(entry.path());
        if (!mtime)
            return std::unexpected(ScanError{ScanErrorCode::Metadata,
                                              entry.path(),
                                              "read modification time",
                                              mtime.error()});
        const auto mtime_ns = platform::metadata::unix_nanoseconds(*mtime);
        if (!mtime_ns) {
            return std::unexpected(ScanError{ScanErrorCode::Metadata,
                                             entry.path(),
                                             "convert modification time",
                                             "timestamp is out of range"});
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
    for (const auto& row : snapshot.rows) {
        if (row.is_directory) {
            if (row.path.empty()) {
                continue;
            }
            const auto found = evidence_indices.find(row.path);
            if (found == evidence_indices.end() ||
                !physical_evidence.directories[found->second].physically_empty) {
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
    platform::perf_trace::finish("local filesystem scan wall", scan_trace);
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
    if (ignore_list.parse_error) {
        return std::unexpected(ScanError{
            .code = ScanErrorCode::Io,
            .path = local_root / ".kasumiignore",
            .operation = ignore_list.parse_error->line == 0
                             ? "read ignore file"
                             : "parse ignore rule at line " +
                                   std::to_string(ignore_list.parse_error->line),
            .detail = ignore_list.parse_error->detail,
        });
    }
    std::vector<std::string> paths;
    paths.reserve(candidate_paths.size());
    for (const auto& candidate : candidate_paths) {
        if (candidate.empty() ||
            !kasumi::has_safe_paths(Operation{.path = candidate})) {
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
        if (found == evidence.ignored_entries.end() || found->path != relative ||
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
                (final ? !std::filesystem::is_regular_file(status)
                       : !std::filesystem::is_directory(status))) {
                return std::unexpected(ScanError{
                    .code = ScanErrorCode::Metadata,
                    .path = current,
                    .operation = "validate disposable candidate",
                    .detail = error ? error.message()
                                    : (final ? "candidate is not a regular file"
                                             : "candidate path contains a non-directory"),
                });
            }
            if (final) {
                break;
            }
            start = slash + 1;
        }

        auto metadata = metadata_query(current, relative);
        if (!metadata || !metadata->has_value() ||
            !(**metadata).identity.has_value()) {
            return std::unexpected(ScanError{
                .code = ScanErrorCode::Metadata,
                .path = current,
                .operation = "verify disposable candidate metadata",
                .detail = !metadata ? metadata.error().message
                                    : "file identity is unavailable",
            });
        }
        const auto before_identity = PhysicalFileIdentity{
            .volume_or_dev = (**metadata).identity->volume,
            .file_id_low = (**metadata).identity->file_low,
            .file_id_high = (**metadata).identity->file_high,
            .valid = true,
        };
        if (before_identity != found->identity ||
            (**metadata).size != found->size) {
            return std::unexpected(ScanError{
                .code = ScanErrorCode::Metadata,
                .path = current,
                .operation = "verify disposable candidate metadata",
                .detail = "physical identity or size changed after observation",
            });
        }

        auto row = process_file(current, relative, context);
        if (!row) {
            return std::unexpected(row.error());
        }
        auto after = metadata_query(current, relative);
        if (!after || !after->has_value() || !(**after).identity.has_value()) {
            return std::unexpected(ScanError{
                .code = ScanErrorCode::Metadata,
                .path = current,
                .operation = "verify disposable candidate after hashing",
                .detail = !after ? after.error().message
                                 : "file identity is unavailable",
            });
        }
        const PhysicalFileIdentity after_identity{
            .volume_or_dev = (**after).identity->volume,
            .file_id_low = (**after).identity->file_low,
            .file_id_high = (**after).identity->file_high,
            .valid = true,
        };
        if (after_identity != found->identity ||
            (**after).size != found->size ||
            classify_ignore(relative, false, ignore_list) !=
                IgnoreDisposition::IgnoredDisposable) {
            return std::unexpected(ScanError{
                .code = ScanErrorCode::Metadata,
                .path = current,
                .operation = "verify disposable candidate after hashing",
                .detail = "file or ignore rules changed while hashing",
            });
        }
        result.push_back({.path = relative,
                          .hash = hash_hex(row->hash),
                          .size = row->size,
                          .identity = found->identity});
    }
    return result;
}

} // namespace kasumi::application::observation::scanner
