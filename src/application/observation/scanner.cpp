#include "application/observation/scanner.hpp"

#include "core/ignore.hpp"
#include "crypto/content.hpp"
#include "platform/file_fingerprint.hpp"
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
    FingerprintQuery fingerprint_query = platform::regular_file_fingerprint;
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
    std::error_code error;
    const auto modified = std::filesystem::last_write_time(file_path, error);
    if (error) {
        return std::unexpected(scan_error(file_path,
                                          "ler data de modificação",
                                          error,
                                          ScanErrorCode::Metadata));
    }
    row.mtime = modified;
    row.size = std::filesystem::file_size(file_path, error);
    if (error) {
        return std::unexpected(scan_error(
            file_path, "ler tamanho", error, ScanErrorCode::Metadata));
    }
    platform::perf_trace::count("local regular files observed");
    const auto fingerprint_trace = platform::perf_trace::begin();
    auto fingerprint = context.fingerprint_query(file_path);
    platform::perf_trace::finish("local fingerprint query wall",
                                 fingerprint_trace);
    platform::perf_trace::count("local fingerprint queries");
    if (context.targeted)
        platform::perf_trace::count("targeted fingerprint queries");
    if (!fingerprint) {
        return std::unexpected(ScanError{ScanErrorCode::Metadata,
                                         file_path,
                                         "obter identidade do arquivo",
                                         fingerprint.error()});
    }
    if (!*fingerprint)
        platform::perf_trace::count("local hash cache unsupported");

    const auto cached =
        context.policy == ScanPolicy::ReuseStrongFingerprint && *fingerprint
            ? context.previous.find(row.path)
            : context.previous.end();
    if (cached != context.previous.end() && cached->second->size == row.size &&
        cached->second->fingerprint.kind == (**fingerprint).kind &&
        cached->second->fingerprint.value == (**fingerprint).value) {
        row.hash = cached->second->hash;
        context.cache.push_back(*cached->second);
        platform::perf_trace::count("local hash cache hits");
    } else {
        platform::perf_trace::count("local hash cache misses");
        std::expected<Hash, std::string> hash = std::unexpected("unhashed");
        bool cache_allowed = fingerprint->has_value();
        bool stable = false;
        for (int attempt = 0; attempt < 2; ++attempt) {
            const auto before_fingerprint = fingerprint;
            const auto before_size = row.size;
            const auto before_mtime = row.mtime;
            const auto hash_trace = platform::perf_trace::begin();
            hash = crypto::content::hash_file(file_path);
            platform::perf_trace::finish("local content hashing wall",
                                         hash_trace);
            platform::perf_trace::count("local hash file calls");
            platform::perf_trace::count("local hash bytes", before_size);
            if (context.targeted) {
                platform::perf_trace::count("targeted hash calls");
                platform::perf_trace::count("targeted hash bytes", before_size);
            }
            if (!hash)
                break;
            std::error_code after_error;
            const auto after_size =
                std::filesystem::file_size(file_path, after_error);
            if (after_error)
                return std::unexpected(scan_error(file_path,
                                                  "read size after hashing",
                                                  after_error,
                                                  ScanErrorCode::Metadata));
            const auto after_mtime =
                std::filesystem::last_write_time(file_path, after_error);
            if (after_error)
                return std::unexpected(
                    scan_error(file_path,
                               "read modification time after hashing",
                               after_error,
                               ScanErrorCode::Metadata));
            const auto after_fingerprint_trace = platform::perf_trace::begin();
            auto after_fingerprint = context.fingerprint_query(file_path);
            platform::perf_trace::finish("local fingerprint query wall",
                                         after_fingerprint_trace);
            platform::perf_trace::count("local fingerprint queries");
            if (context.targeted)
                platform::perf_trace::count("targeted fingerprint queries");
            if (!after_fingerprint)
                return std::unexpected(ScanError{ScanErrorCode::Metadata,
                                                 file_path,
                                                 "obter identidade após hash",
                                                 after_fingerprint.error()});
            if (!*after_fingerprint)
                cache_allowed = false;
            const bool same_fingerprint =
                (!*before_fingerprint && !*after_fingerprint) ||
                (*before_fingerprint && *after_fingerprint &&
                 (**before_fingerprint).kind == (**after_fingerprint).kind &&
                 (**before_fingerprint).value == (**after_fingerprint).value);
            if (same_fingerprint &&
                before_size == static_cast<std::uint64_t>(after_size) &&
                before_mtime == after_mtime) {
                stable = true;
                fingerprint = std::move(after_fingerprint);
                break;
            }
            platform::perf_trace::count("files changed during hash");
            if (!*before_fingerprint || !*after_fingerprint)
                break;
            row.size = static_cast<std::uint64_t>(after_size);
            row.mtime = after_mtime;
            fingerprint = std::move(after_fingerprint);
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
        if (cache_allowed && fingerprint && fingerprint->has_value()) {
            context.cache.push_back(
                state_storage::FileCacheRow{.path = row.path,
                                            .hash = row.hash,
                                            .size = row.size,
                                            .fingerprint = **fingerprint});
        }
    }
    return row;
}

} // namespace

std::string describe(const ScanError& error) {
    return error.operation + " em '" + platform::path::to_utf8(error.path) +
           "': " + error.detail;
}

std::expected<ScanResult, ScanError>
scan_result(const std::filesystem::path& local_root,
            std::span<const state_storage::FileCacheRow> previous_cache,
            ScanPolicy policy,
            FingerprintQuery fingerprint_query) {
    const auto scan_trace = platform::perf_trace::begin();
    ScanContext context{.policy = policy,
                        .fingerprint_query = fingerprint_query,
                        .previous = {},
                        .cache = {},
                        .directory_file_references = {},
                        .directory_lineage_complete = true,
                        .targeted = false};
    context.cache.reserve(previous_cache.size());
    context.previous.reserve(previous_cache.size());
    for (const auto& row : previous_cache)
        context.previous.emplace(row.path, &row);
    const auto ignore_list = load_ignore_list(local_root / ".kasumiignore");
    std::error_code error;
    const auto status = std::filesystem::symlink_status(local_root, error);
    if (error)
        return std::unexpected(scan_error(local_root,
                                          "consultar tipo da entrada",
                                          error,
                                          ScanErrorCode::Metadata));
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
                                          "ler data de modificação",
                                          error,
                                          ScanErrorCode::Metadata));
    // The parent must precede its descendants.
    snapshot.rows.push_back(
        {.path = "", .mtime = modified, .is_directory = true});

    std::filesystem::directory_iterator iterator(local_root, error);
    if (error)
        return std::unexpected(scan_error(
            local_root, "listar diretório", error, ScanErrorCode::Io));
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
                                              "continuar listagem",
                                              error,
                                              ScanErrorCode::Io));
        const auto entry_status = entry.symlink_status(error);
        if (error)
            return std::unexpected(scan_error(entry.path(),
                                              "consultar tipo da entrada",
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
                .operation = "validar nome portável",
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
                                              "ler data de modificação",
                                              error,
                                              ScanErrorCode::Metadata));
        snapshot.rows.push_back(
            {.path = relative, .mtime = mtime, .is_directory = true});
        remember_directory(entry.path(), context);
        std::filesystem::directory_iterator nested(entry.path(), error);
        if (error)
            return std::unexpected(scan_error(
                entry.path(), "listar diretório", error, ScanErrorCode::Io));
        stack.push_back({nested, {}, relative});
    }
    finalize_snapshot(snapshot);
    if (!valid_snapshot(snapshot, false)) {
        return std::unexpected(ScanError{
            .code = ScanErrorCode::Metadata,
            .path = local_root,
            .operation = "validar snapshot",
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
             FingerprintQuery fingerprint_query) {
    if (relative_path.empty() || relative_path.front() == '/' ||
        relative_path.back() == '/') {
        return std::unexpected(
            ScanError{ScanErrorCode::Metadata,
                      platform::path::from_utf8(relative_path),
                      "observar arquivo direcionado",
                      "caminho relativo inválido"});
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
                          "observar arquivo direcionado",
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
                                         "observar arquivo direcionado",
                                         "caminho relativo inválido"});
    }
    const auto file_path = local_root / relative;
    std::error_code error;
    const auto status = std::filesystem::symlink_status(file_path, error);
    if (error || std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        return std::unexpected(scan_error(file_path,
                                          "observar arquivo direcionado",
                                          error,
                                          ScanErrorCode::Metadata));
    }
    const auto ignore_list = load_ignore_list(local_root / ".kasumiignore");
    const auto normalized = platform::path::to_logical_utf8(relative);
    if (is_ignored(normalized, ignore_list, false)) {
        return std::unexpected(ScanError{ScanErrorCode::Metadata,
                                         file_path,
                                         "observar arquivo direcionado",
                                         "arquivo ignorado"});
    }

    std::vector<state_storage::FileCacheRow> previous;
    if (cached) {
        cached->path = normalized;
        previous.push_back(*cached);
    }
    ScanContext context{.policy = ScanPolicy::ReuseStrongFingerprint,
                        .fingerprint_query = fingerprint_query,
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
