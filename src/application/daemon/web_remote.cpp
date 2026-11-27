#include "application/daemon/web_file.hpp"
#include "application/daemon/web_remote_json.hpp"
#include "application/daemon/web_routes.hpp"
#include "application/daemon/web_thumbnails.hpp"
#include "core/diff.hpp"
#include "platform/path.hpp"
#include "platform/workspace.hpp"

#include <algorithm>
#include <map>

namespace kasumi::application::daemon_detail {
namespace {
using Op = InspectionOperation;

[[noreturn]] void throw_inspection_error(const InspectionError& err) {
    using E = InspectionErrorCode;
    switch (err.code) {
        case E::RemoteHeadNotFound:
        case E::RemoteCommitNotFound:
        case E::RemotePathNotFound:
        case E::RemoteContentNotFound:
        case E::ProfileNotFound:
            throw HttpError{404, err.detail};
        case E::HeadSelectionRequired:
            throw HttpError{409, err.detail};
        case E::CredentialsRequired:
        case E::CredentialFailure:
            throw HttpError{403, err.detail};
        case E::InvalidRequest:
        case E::InvalidProfile:
        case E::RemotePathIsDirectory:
            throw HttpError{400, err.detail};
        default:
            throw HttpError{422, err.detail};
    }
}

InspectionResponse run(const WebContext& ctx, InspectionRequest request) {
    auto response = ctx.inspect(std::move(request));
    if (!response)
        throw_inspection_error(response.error());
    return std::move(*response);
}

std::shared_ptr<RemoteDownloadSession>
open_download_session(const WebContext& ctx, InspectionRequest request) {
    auto session = ctx.open_download(std::move(request));
    if (!session)
        throw_inspection_error(session.error());
    return std::move(*session);
}

std::shared_ptr<platform::Workspace> temporary_download() {
    auto workspace = platform::create_workspace("http-download");
    if (!workspace)
        throw HttpError{500, "cannot create private download directory"};
    return {new platform::Workspace(std::move(*workspace)),
            [](platform::Workspace* p) {
                platform::cleanup_workspace(*p);
                delete p;
            }};
}

using platform::private_storage::FileSlice;
using platform::private_storage::RegularFileInput;

std::shared_ptr<RegularFileInput>
stage_session_slice(const WebContext& ctx,
                    std::string_view profile_name,
                    RemoteDownloadSession& session,
                    const RemoteStatReport& info,
                    std::optional<FileSlice> slice) {
    std::optional<DownloadSlice> req_slice;
    if (slice)
        req_slice = DownloadSlice{slice->offset, slice->size};
    auto workspace = temporary_download();
    const auto file = workspace->root / "content";
    auto result =
        read_remote_download_slice(session, file, req_slice, ctx.stop);
    if (!result)
        throw_inspection_error(result.error());
    if (result->logical_hash != info.logical_hash || result->size != info.size)
        throw HttpError{409, "remote file changed during download"};
    auto input = platform::private_storage::open_regular_file(file);
    if (!input || input->size != (slice ? slice->size : info.size))
        throw HttpError{500, "download file is unavailable"};
    if (!slice && ctx.thumbnail_cache) {
        if (auto cache = ctx.thumbnail_cache(profile_name)) {
            try_cache_grid_thumbnail_from_file(
                *cache, info.path, info.logical_hash, file, info.size);
        }
    }
    return {new RegularFileInput(std::move(*input)),
            [workspace](RegularFileInput* handle) {
                delete handle;
            }};
}

// Group immutable, individually authenticated chunks. Align adjacent reads
// with chunk boundaries so a seek or large response never re-fetches a chunk.
std::vector<FileSlice> download_windows(const RemoteStatReport& info,
                                        FileSlice requested) {
    constexpr std::uint64_t target = 8 * 1024 * 1024;
    const auto end = requested.offset + requested.size;
    auto start = requested.offset;
    std::uint64_t chunk_end = 0;
    std::vector<FileSlice> windows;
    for (const auto& chunk : info.chunks) {
        chunk_end += chunk.size;
        if (chunk_end >= end)
            break;
        if (chunk_end >= start && chunk_end - start >= target) {
            windows.push_back({start, chunk_end - start});
            start = chunk_end;
        }
    }
    windows.push_back({start, end - start});
    return windows;
}

void download(const WebContext& ctx,
              const httplib::Request& req,
              httplib::Response& res) {
    InspectionRequest query{.operation = Op::RemoteGet,
                            .profile_name = req.matches[1].str()};
    query.logical_path = req.get_param_value("path");
    if (req.has_param("commit"))
        query.commit_id = req.get_param_value("commit");
    const auto profile_name = query.profile_name;
    auto session = open_download_session(ctx, std::move(query));
    const auto info = remote_download_stat(*session);
    std::optional<FileSlice> slice;
    if (!prepare_file_range(req, res, info.size, slice))
        return;
    if (req.method == "HEAD" || !info.size) {
        set_file_stream(res, info.path, info.size, nullptr);
        return;
    }
    auto windows =
        download_windows(info, slice.value_or(FileSlice{0, info.size}));
    if (windows.size() == 1) {
        auto input =
            stage_session_slice(ctx, profile_name, *session, info, slice);
        session.reset();
        set_file_stream(res,
                        info.path,
                        info.size,
                        std::move(input),
                        slice ? slice->offset : 0);
        return;
    }
    // Authenticate the first window before sending headers. Remaining windows
    // reuse the validated commit/manifest session without re-observing history.
    auto input = stage_session_slice(
        ctx, profile_name, *session, info, windows.front());
    set_file_provider(
        res,
        info.path,
        info.size,
        [ctx,
         profile_name,
         session = std::move(session),
         info,
         windows = std::move(windows),
         input = std::move(input),
         index = std::size_t{0}](std::size_t offset,
                                 std::size_t length,
                                 httplib::DataSink& sink) mutable {
            try {
                while (length && index < windows.size()) {
                    const auto window = windows[index];
                    if (offset < window.offset ||
                        offset >= window.offset + window.size)
                        return false;
                    if (!input) {
                        if (ctx.stop.stop_requested() || !sink.is_writable() ||
                            !session)
                            return false;
                        input = stage_session_slice(
                            ctx, profile_name, *session, info, window);
                        if (index + 1 == windows.size())
                            session.reset();
                    }
                    const auto relative = offset - window.offset;
                    const auto amount = (std::min)(length,
                                                   static_cast<std::size_t>(
                                                       window.size - relative));
                    if (!write_file_stream(*input, relative, amount, sink))
                        return false;
                    offset += amount;
                    length -= amount;
                    if (relative + amount == window.size) {
                        input.reset();
                        ++index;
                    }
                }
                return length == 0;
            } catch (...) {
                return false;
            }
        });
}

Json text_revision(const WebContext& ctx, InspectionRequest query) {
    query.operation = Op::RemoteGet;
    auto opened = ctx.open_download(std::move(query));
    if (!opened) {
        if (opened.error().code == InspectionErrorCode::RemotePathNotFound)
            return nullptr;
        throw_inspection_error(opened.error());
    }
    auto session = std::move(*opened);
    const auto stat = remote_download_stat(*session);
    constexpr std::size_t limit = 1024 * 1024;
    if (stat.size > limit)
        throw HttpError{413,
                        "text comparison is limited to 1 MiB per revision"};
    if (stat.size == 0)
        return {{"path", stat.path},
                {"hash", stat.logical_hash},
                {"text", std::string{}}};
    auto workspace = temporary_download();
    auto file = workspace->root / "revision";
    auto slice_res =
        read_remote_download_slice(*session, file, std::nullopt, ctx.stop);
    if (!slice_res)
        throw_inspection_error(slice_res.error());
    session.reset();
    auto input = platform::private_storage::open_regular_file(file);
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(stat.size));
    if (!input || input->size != stat.size ||
        !platform::private_storage::read_regular_file_exact(*input, bytes))
        throw HttpError{500, "cannot read revision"};
    return {{"path", stat.path},
            {"hash", stat.logical_hash},
            {"text", std::string(bytes.begin(), bytes.end())}};
}

Snapshot tree_report_to_snapshot(const RemoteTreeReport& report) {
    Snapshot tree;
    tree.rows.push_back(NodeRow{.path = "",
                                .hash = hash_from_hex(report.root_hash).value(),
                                .size = report.total_bytes,
                                .is_directory = true});
    for (const auto& entry : report.entries)
        tree.rows.push_back(NodeRow{
            .path = entry.path,
            .hash = hash_from_hex(entry.logical_hash).value(),
            .size = entry.size,
            .is_directory = entry.type == RemoteTreeEntryType::Directory});
    return tree;
}

Snapshot revision_tree(const WebContext& ctx, const InspectionRequest& query) {
    const auto report = std::get<RemoteTreeReport>(run(ctx, query).payload);
    return tree_report_to_snapshot(report);
}

Json revision_diff(const WebContext& ctx, const httplib::Request& req) {
    const bool bypass_commit_cache = req.has_param("refresh");
    InspectionRequest query{.operation = Op::RemoteTree,
                            .profile_name = req.matches[1].str(),
                            .bypass_commit_cache = bypass_commit_cache};
    query.commit_id = req.get_param_value("from");
    auto other = query;
    other.commit_id = req.get_param_value("to");
    if (req.has_param("path")) {
        query.logical_path = other.logical_path = req.get_param_value("path");
        return {{"from", text_revision(ctx, query)},
                {"to", text_revision(ctx, other)}};
    }
    Snapshot from;
    Snapshot to;
    if (ctx.inspect_commit_pair) {
        auto pair = ctx.inspect_commit_pair(query.profile_name,
                                            *query.commit_id,
                                            *other.commit_id,
                                            bypass_commit_cache);
        if (!pair) {
            throw_inspection_error(pair.error());
        }
        from = tree_report_to_snapshot(pair->from);
        to = tree_report_to_snapshot(pair->to);
    } else {
        from = revision_tree(ctx, query);
        to = revision_tree(ctx, other);
    }
    Json changes = Json::array();
    std::map<std::string, std::vector<std::size_t>> removed, added;
    for (const auto& op : diff::compare_trees(from, from, to)) {
        auto path = platform::path::to_utf8(op.path);
        const auto* before = find_row(from, path);
        const auto* after = find_row(to, path);
        std::string kind = before && after ? "modified"
                           : after         ? "added"
                                           : "deleted";
        if (before && !after && !before->is_directory)
            removed[hash_hex(before->hash)].push_back(changes.size());
        if (after && !before && !after->is_directory)
            added[hash_hex(after->hash)].push_back(changes.size());
        changes.push_back({{"kind", kind}, {"path", path}});
    }
    for (const auto& [hash, indices] : removed) {
        const auto it = added.find(hash);
        if (indices.size() == 1 && it != added.end() &&
            it->second.size() == 1) {
            auto& entry = changes[it->second.front()];
            entry["kind"] = "renamed";
            entry["from"] = changes[indices.front()]["path"];
            changes[indices.front()] = nullptr;
        }
    }
    auto& rows = changes.get_ref<Json::array_t&>();
    std::erase_if(rows, [](const Json& row) {
        return row.is_null();
    });
    return {{"from", *query.commit_id},
            {"to", *other.commit_id},
            {"changes", std::move(changes)}};
}

} // namespace

void register_remote_routes(httplib::Server& server, const WebContext& ctx) {
    server.Get("/v1/remote/([^/]+)/download",
               [ctx](const auto& req, auto& res) {
                   download(ctx, req, res);
               });
    server.Get("/v1/remote/([^/]+)/diff", json_route([ctx](const auto& req) {
                   return revision_diff(ctx, req);
               }));
    server.Get(
        "/v1/remote/([^/]+)/"
        "(summary|heads|commits|tree|stat|log|objects|orphans|writers|epochs|"
        "health)(?:/([^/]+))?",
        json_route([ctx](const auto& req) -> Json {
            static const std::map<std::string, Op> operations{
                {"summary", Op::RemoteSummary},
                {"heads", Op::RemoteHeads},
                {"commits", Op::RemoteCommits},
                {"tree", Op::RemoteTree},
                {"stat", Op::RemoteStat},
                {"log", Op::RemoteLog},
                {"objects", Op::RemoteObjects},
                {"orphans", Op::RemoteOrphans},
                {"writers", Op::RemoteWriters},
                {"epochs", Op::RemoteEpochs},
                {"health", Op::RemoteHealth}};
            InspectionRequest query{.operation =
                                        operations.at(req.matches[2].str()),
                                    .profile_name = req.matches[1].str()};
            query.include_space_usage = query.operation == Op::RemoteSummary;
            if (req.matches[3].matched) {
                if (query.operation != Op::RemoteCommits)
                    throw HttpError{404, "unknown route"};
                query.operation = Op::RemoteCommit;
                query.commit_id = req.matches[3].str();
            } else if (req.has_param("commit"))
                query.commit_id = req.get_param_value("commit");
            if (req.has_param("head"))
                query.head_commit_id = req.get_param_value("head");
            if (req.has_param("path"))
                query.logical_path = req.get_param_value("path");
            if (req.has_param("refresh"))
                query.bypass_commit_cache = true;
            auto report = run(ctx, std::move(query));
            if (auto* tree = std::get_if<RemoteTreeReport>(&report.payload);
                tree && req.has_param("prefix")) {
                auto prefix = req.get_param_value("prefix");
                if (!prefix.empty() && prefix != "/") {
                    if (!valid_logical_path(prefix))
                        throw HttpError{400, "invalid prefix"};
                    std::erase_if(tree->entries, [&](const auto& row) {
                        return row.path != prefix &&
                               !is_descendant(row.path, prefix);
                    });
                }
            }
            return std::visit(
                [](const auto& data) -> Json {
                    if constexpr (std::is_constructible_v<Json, decltype(data)>)
                        return Json(data);
                    else
                        throw HttpError{500, "unsupported inspection report"};
                },
                report.payload);
        }));
    server.Post(
        "/v1/remote/([^/]+)/restore", json_route([ctx](const auto& req) {
            auto body = parse_body(req);
            InspectionRequest query{.operation = Op::RemoteRestore,
                                    .profile_name = req.matches[1].str()};
            query.destination_path =
                body->at("dst").template get<std::string>();
            if (body->contains("commit"))
                query.commit_id =
                    body->at("commit").template get<std::string>();
            if (body->contains("prefix"))
                query.logical_path =
                    body->at("prefix").template get<std::string>();
            query.dry_run = body->value("dry_run", true);
            return std::get<RemoteRestoreReport>(
                run(ctx, std::move(query)).payload);
        }));
}
} // namespace kasumi::application::daemon_detail
