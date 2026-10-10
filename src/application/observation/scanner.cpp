#include "application/observation/scanner.hpp"

#include "application/observation/cache_contract.hpp"
#include "application/observation/file_metadata.hpp"
#include "core/ignore.hpp"
#include "crypto/content.hpp"
#include "platform/metadata.hpp"
#include "platform/path.hpp"
#include "platform/perf_trace.hpp"

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

namespace kasumi::application::observation::scanner {
namespace {

using kasumi::ignore::IgnoreList;
using kasumi::ignore::is_ignored;
using kasumi::ignore::load_ignore_list;

struct ScanFrame {
    std::filesystem::directory_iterator iterator;
    std::filesystem::directory_iterator end;
    std::string path;
};

struct ScanContext {
    ScanPolicy policy = ScanPolicy::FullHash;
    MetadataQuery metadata_query = cache::read_file_metadata;
    std::unordered_map<std::string_view, const state_storage::FileCacheRow*>
        previous;
    std::vector<state_storage::FileCacheRow> cache;
    std::vector<std::uint64_t> directory_file_references;
    bool directory_lineage_complete = true;
    bool targeted = false;
};

void remember_directory(const std::filesystem::path& path,
                        ScanContext& context) {
    platform::perf_trace::count("local directory identity queries");
    const auto reference = platform::directory_file_reference(path);
    if (!reference || !*reference) {
        context.directory_lineage_complete = false;
        platform::perf_trace::count("local directory identity failures");
        return;
    }
    context.directory_file_references.push_back(**reference);
}

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

std::expected<NodeRow, ScanError>
process_file(const std::filesystem::path& file_path,
             std::string relative,
             ScanContext& context) {
    NodeRow row{.path = std::move(relative)};
    const auto meta_result = context.metadata_query(file_path, row.path);
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
            .detail = "entry is not an eligible regular file"});
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
            if (context.targeted) {
                platform::perf_trace::count("targeted hash calls");
                platform::perf_trace::count("targeted hash bytes",
                                            before_meta.size);
            }
            if (!hash)
                break;

            const auto after_result =
                context.metadata_query(file_path, row.path);
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
    const auto scan_trace = platform::perf_trace::begin();
    ScanContext context{.policy = policy,
                        .metadata_query = metadata_query,
                        .previous = {},
                        .cache = {},
                        .directory_file_references = {},
                        .directory_lineage_complete = true,
                        .targeted = false};
    context.cache.reserve(previous_cache.size());
    context.previous.reserve(previous_cache.size());
    for (const auto& row : previous_cache)
        context.previous.emplace(row.path, &row);
    std::error_code error;
    const auto status = std::filesystem::symlink_status(local_root, error);
    if (error)
        return std::unexpected(scan_error(
            local_root, "query entry type", error, ScanErrorCode::Metadata));
    const bool directory = std::filesystem::is_directory(status);
    if (std::filesystem::is_symlink(status) ||
        is_ignored(".", ignore_list, directory))
        return ScanResult{};

    if (!directory) {
        auto row =
            process_file(local_root,
                         platform::path::to_logical_utf8(local_root.filename()),
                         context);
        if (!row)
            return std::unexpected(row.error());
        ScanResult result{.snapshot = Snapshot{{std::move(*row)}},
                          .cache = std::move(context.cache),
                          .directory_file_references = {},
                          .directory_lineage_complete = false};
        platform::perf_trace::finish("local filesystem scan wall", scan_trace);
        return result;
    }

    Snapshot snapshot;
    snapshot.rows.reserve(previous_cache.size() + 1);
    remember_directory(local_root, context);
    const auto modified = std::filesystem::last_write_time(local_root, error);
    if (error)
        return std::unexpected(scan_error(local_root,
                                          "read modification time",
                                          error,
                                          ScanErrorCode::Metadata));
    const auto root_mtime = platform::metadata::unix_nanoseconds(modified);
    if (!root_mtime) {
        return std::unexpected(ScanError{ScanErrorCode::Metadata,
                                         local_root,
                                         "convert modification time",
                                         "timestamp is out of range"});
    }
    // The parent must precede its descendants.
    snapshot.rows.push_back(
        {.path = "", .mtime = *root_mtime, .is_directory = true});

    std::filesystem::directory_iterator iterator(local_root, error);
    if (error)
        return std::unexpected(
            scan_error(local_root, "list directory", error, ScanErrorCode::Io));
    std::vector<ScanFrame> stack;
    stack.push_back({iterator, {}, ""});
    while (!stack.empty()) {
        auto& frame = stack.back();
        if (frame.iterator == frame.end) {
            stack.pop_back();
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
        const bool entry_directory =
            std::filesystem::is_directory(entry_status);
        if (std::filesystem::is_symlink(entry_status))
            continue;
        const auto entry_name =
            platform::path::to_logical_utf8(entry.path().filename());
        const auto relative =
            frame.path.empty() ? entry_name : frame.path + '/' + entry_name;
        if (is_ignored(relative, ignore_list, entry_directory))
            continue;
        if (!valid_logical_path_component(entry_name)) {
            return std::unexpected(ScanError{
                .code = ScanErrorCode::Io,
                .path = entry.path(),
                .operation = "validate portable name",
                .detail = "unsupported non-portable path component: '" +
                          entry_name + "'",
            });
        }
        if (!entry_directory) {
            auto row = process_file(entry.path(), relative, context);
            if (!row)
                return std::unexpected(row.error());
            snapshot.rows.push_back(std::move(*row));
            continue;
        }
        const auto mtime = entry.last_write_time(error);
        if (error)
            return std::unexpected(scan_error(entry.path(),
                                              "read modification time",
                                              error,
                                              ScanErrorCode::Metadata));
        const auto mtime_ns = platform::metadata::unix_nanoseconds(mtime);
        if (!mtime_ns) {
            return std::unexpected(ScanError{ScanErrorCode::Metadata,
                                             entry.path(),
                                             "convert modification time",
                                             "timestamp is out of range"});
        }
        snapshot.rows.push_back(
            {.path = relative, .mtime = *mtime_ns, .is_directory = true});
        remember_directory(entry.path(), context);
        std::filesystem::directory_iterator nested(entry.path(), error);
        if (error)
            return std::unexpected(scan_error(
                entry.path(), "list directory", error, ScanErrorCode::Io));
        stack.push_back({nested, {}, relative});
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
    std::sort(context.directory_file_references.begin(),
              context.directory_file_references.end());
    context.directory_file_references.erase(
        std::unique(context.directory_file_references.begin(),
                    context.directory_file_references.end()),
        context.directory_file_references.end());
    platform::perf_trace::finish("local filesystem scan wall", scan_trace);
    return ScanResult{.snapshot = std::move(snapshot),
                      .cache = std::move(context.cache),
                      .directory_file_references =
                          std::move(context.directory_file_references),
                      .directory_lineage_complete =
                          context.directory_lineage_complete};
}

std::expected<TargetedFileObservation, ScanError>
observe_file(const std::filesystem::path& local_root,
             std::string_view relative_path,
             std::optional<state_storage::FileCacheRow> cached,
             MetadataQuery metadata_query) {
    if (relative_path.empty() || relative_path.front() == '/' ||
        relative_path.back() == '/') {
        return std::unexpected(
            ScanError{ScanErrorCode::Metadata,
                      platform::path::from_utf8(relative_path),
                      "observe targeted file",
                      "invalid relative path"});
    }

    std::size_t comp_start = 0;
    while (comp_start < relative_path.size()) {
        const auto slash = relative_path.find('/', comp_start);
        const auto component =
            slash == std::string_view::npos
                ? relative_path.substr(comp_start)
                : relative_path.substr(comp_start, slash - comp_start);
        if (!valid_logical_path_component(component)) {
            return std::unexpected(
                ScanError{ScanErrorCode::Metadata,
                          platform::path::from_utf8(relative_path),
                          "observe targeted file",
                          "unsupported non-portable path component: '" +
                              std::string(component) + "'"});
        }
        if (slash == std::string_view::npos) {
            break;
        }
        comp_start = slash + 1;
    }

    const auto relative = platform::path::from_utf8(relative_path);
    if (relative.is_absolute() || relative.has_root_name() ||
        relative.has_root_directory() ||
        std::ranges::find(relative, std::filesystem::path{".."}) !=
            relative.end()) {
        return std::unexpected(ScanError{ScanErrorCode::Metadata,
                                         relative,
                                         "observe targeted file",
                                         "invalid relative path"});
    }
    const auto file_path = local_root / relative;
    std::error_code error;
    const auto status = std::filesystem::symlink_status(file_path, error);
    if (error || std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        return std::unexpected(scan_error(file_path,
                                          "observe targeted file",
                                          error,
                                          ScanErrorCode::Metadata));
    }
    const auto ignore_list = load_ignore_list(local_root / ".kasumiignore");
    const auto normalized = platform::path::to_logical_utf8(relative);
    if (is_ignored(normalized, ignore_list, false)) {
        return std::unexpected(ScanError{ScanErrorCode::Metadata,
                                         file_path,
                                         "observe targeted file",
                                         "ignored file"});
    }

    std::vector<state_storage::FileCacheRow> previous;
    if (cached) {
        cached->path = normalized;
        previous.push_back(*cached);
    }
    ScanContext context{.policy = ScanPolicy::ReuseStrongFingerprint,
                        .metadata_query = metadata_query,
                        .previous = {},
                        .cache = {},
                        .directory_file_references = {},
                        .directory_lineage_complete = false,
                        .targeted = true};
    if (!previous.empty())
        context.previous.emplace(previous.front().path, &previous.front());
    auto row = process_file(file_path, normalized, context);
    if (!row)
        return std::unexpected(std::move(row.error()));
    TargetedFileObservation result{.row = std::move(*row),
                                   .cache = std::nullopt};
    if (!context.cache.empty())
        result.cache = std::move(context.cache.front());
    return result;
}

} // namespace kasumi::application::observation::scanner
